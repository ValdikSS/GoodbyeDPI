/*
 * GoodbyeDPI TUI launcher
 *
 * A small menu in front of goodbyedpi.exe: pick a preset, DNS and a few
 * switches with the keyboard, then start. It builds a command line and
 * runs goodbyedpi.exe from the same folder.
 *
 * With "Minimize to tray" on, goodbyedpi.exe runs hidden as a child of this
 * program, the console closes and a notification-area icon stays. Exiting
 * from the icon's menu stops goodbyedpi.exe; it is also stopped if this
 * program dies (the child lives in a kill-on-close job object).
 *
 * Needs Windows 10+ (ANSI escape sequences in the console).
 *
 *   goodbyedpi-tui.exe               interactive menu
 *   goodbyedpi-tui.exe --tray [name] start straight into the tray with preset
 *                                    "name" (default if omitted)
 *   goodbyedpi-tui.exe --print       print the command line for the default
 *                                    selection and exit (for scripts/testing)
 */
#include <windows.h>
#include <shellapi.h>
#include <conio.h>
#include <stdio.h>
#include <string.h>

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

#define ESC "\x1b"
#define CLEAR   ESC "[2J" ESC "[H"
#define REVERSE ESC "[7m"
#define DIM     ESC "[2m"
#define BOLD    ESC "[1m"
#define RESET   ESC "[0m"

/* goodbyedpi.exe prints this once all filters are open */
#define READY_MARKER "is now running"

#define WM_TRAY    (WM_APP + 1)
#define ID_EXIT    1
#define TRAY_MUTEX "Local\\GoodbyeDPI-TUI-tray"

enum item_e {
    ITEM_PRESET, ITEM_DNS, ITEM_QUIC, ITEM_VERBOSE, ITEM_TRAY, ITEM_START, ITEM_QUIT,
    ITEM_COUNT
};

/* Index 0 means "no --preset": goodbyedpi's default mode -9 is used instead. */
static const char *const preset_names[] = { "default", "viettel", "fpt", "vnpt", "steam" };
static const char *const preset_info[] = {
    "Mode -9 for any ISP, all traffic",
    "Viettel: mode -9 + DNS 1.1.1.1",
    "FPT Telecom: mode -5 (auto TTL) + DNS 8.8.8.8",
    "VNPT: mode -6 (wrong SEQ) + DNS 1.1.1.1",
    "Steam domains only, other traffic untouched. DNS 1.1.1.1",
};
#define PRESET_COUNT (sizeof(preset_names) / sizeof(preset_names[0]))

/* Index 0 means "whatever the preset says" (default mode: no DNS redirect). */
static const char *const dns_names[] = { "preset default", "1.1.1.1", "8.8.8.8", "9.9.9.9" };
static const char *const dns_addrs[] = { NULL,             "1.1.1.1", "8.8.8.8", "9.9.9.9" };
#define DNS_COUNT (sizeof(dns_names) / sizeof(dns_names[0]))

struct state {
    int selected;
    int preset;
    int dns;
    int quic;
    int verbose;
    int tray;
};

static void build_args(const struct state *st, char *out, size_t size) {
    int n;

    if (st->preset == 0)
        n = snprintf(out, size, "-9");
    else
        n = snprintf(out, size, "--preset %s", preset_names[st->preset]);

    if (n < 0 || (size_t)n >= size)
        return;
    if (dns_addrs[st->dns])
        n += snprintf(out + n, size - (size_t)n, " --dns-addr %s", dns_addrs[st->dns]);
    if (n >= 0 && (size_t)n < size && st->quic)
        n += snprintf(out + n, size - (size_t)n, " -q");
    if (n >= 0 && (size_t)n < size && st->verbose)
        snprintf(out + n, size - (size_t)n, " --dns-verb");
}

static void get_exe_path(char *out, size_t size) {
    char self[MAX_PATH];
    char *slash;

    out[0] = '\0';
    if (!GetModuleFileNameA(NULL, self, sizeof(self)))
        return;
    slash = strrchr(self, '\\');
    if (!slash)
        return;
    *slash = '\0';
    snprintf(out, size, "%s\\goodbyedpi.exe", self);
}

static void pause_for_key(void) {
    printf("\nPress any key to return to the menu...");
    fflush(stdout);
    _getch();
}

/* Builds the full command line. Returns 0 on success, -1 (message printed) otherwise. */
static int prepare_cmdline(const struct state *st, char *cmdline, size_t size) {
    char exe[MAX_PATH + 16];
    char args[256];

    get_exe_path(exe, sizeof(exe));
    if (!exe[0] || GetFileAttributesA(exe) == INVALID_FILE_ATTRIBUTES) {
        printf(CLEAR "  goodbyedpi.exe was not found next to this program:\n  %s\n",
               exe[0] ? exe : "(unknown path)");
        return -1;
    }
    build_args(st, args, sizeof(args));
    snprintf(cmdline, size, "\"%s\" %s", exe, args);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Menu                                                                */
/* ------------------------------------------------------------------ */

static void draw_row(int row, int selected, const char *label, const char *value,
                     int is_choice) {
    printf("  %s %-18s", row == selected ? REVERSE ">" : " ", label);
    if (is_choice && value)
        printf(" %s< %s >%s", row == selected ? "" : DIM, value, RESET);
    else if (value)
        printf(" %s", value);
    printf(RESET "\n");
}

static void draw(const struct state *st) {
    char args[256];

    build_args(st, args, sizeof(args));

    printf(CLEAR);
    printf(BOLD "  GoodbyeDPI" RESET "  -  Vietnam presets\n\n");

    draw_row(ITEM_PRESET, st->selected, "Preset", preset_names[st->preset], 1);
    printf("      " DIM "%s" RESET "\n", preset_info[st->preset]);
    draw_row(ITEM_DNS, st->selected, "DNS redirect", dns_names[st->dns], 1);
    draw_row(ITEM_QUIC, st->selected, "Block QUIC (-q)", st->quic ? "[x]" : "[ ]", 0);
    draw_row(ITEM_VERBOSE, st->selected, "Verbose DNS log", st->verbose ? "[x]" : "[ ]", 0);
    draw_row(ITEM_TRAY, st->selected, "Minimize to tray", st->tray ? "[x]" : "[ ]", 0);
    printf("\n");
    draw_row(ITEM_START, st->selected, "Start", NULL, 0);
    draw_row(ITEM_QUIT, st->selected, "Quit", NULL, 0);

    printf("\n  " DIM "Command:" RESET " goodbyedpi.exe %s\n", args);
    printf("\n  " DIM "Up/Down: move   Left/Right: change   Space/Enter: select   Q: quit" RESET "\n");
    printf("  " DIM "DNS redirect only affects plain UDP DNS, not DNS-over-HTTPS." RESET "\n");
}

static int wrap(int value, int delta, int count) {
    return (value + delta + count) % count;
}

static void change(struct state *st, int delta) {
    switch (st->selected) {
        case ITEM_PRESET:  st->preset = wrap(st->preset, delta, (int)PRESET_COUNT); break;
        case ITEM_DNS:     st->dns = wrap(st->dns, delta, (int)DNS_COUNT); break;
        case ITEM_QUIC:    st->quic = !st->quic; break;
        case ITEM_VERBOSE: st->verbose = !st->verbose; break;
        case ITEM_TRAY:    st->tray = !st->tray; break;
        default: break;
    }
}

/* ------------------------------------------------------------------ */
/* Run in the foreground                                               */
/* ------------------------------------------------------------------ */

/*
 * The WinDivert kernel driver can stay loaded after goodbyedpi.exe is gone and
 * keeps WinDivert64.sys locked ("file in use"). Stop and remove its service;
 * WinDivert installs it again the next time goodbyedpi.exe starts.
 * Best effort: if something else still uses the driver, stopping fails and
 * the service is left alone.
 */
static void stop_windivert_driver(void) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE svc;
    SERVICE_STATUS ss;
    int stopped = 0;
    int i;

    if (!scm)
        return;
    svc = OpenServiceA(scm, "WinDivert", SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (svc) {
        if (ControlService(svc, SERVICE_CONTROL_STOP, &ss) ||
            GetLastError() == ERROR_SERVICE_NOT_ACTIVE) {
            for (i = 0; i < 30; i++) {
                if (!QueryServiceStatus(svc, &ss))
                    break;
                if (ss.dwCurrentState == SERVICE_STOPPED) {
                    stopped = 1;
                    break;
                }
                Sleep(100);
            }
        }
        if (stopped)
            DeleteService(svc);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

static BOOL WINAPI ignore_ctrl_c(DWORD type) {
    /* While goodbyedpi runs, Ctrl+C is meant for it, not for this launcher. */
    return type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT;
}

static void run(const struct state *st) {
    char cmdline[MAX_PATH + 300];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD code = 0;

    if (prepare_cmdline(st, cmdline, sizeof(cmdline)) != 0) {
        pause_for_key();
        return;
    }

    printf(CLEAR "  Running: %s\n  Press Ctrl+C to stop.\n\n", cmdline);
    fflush(stdout);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    SetConsoleCtrlHandler(ignore_ctrl_c, TRUE);
    if (CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        printf("\n  goodbyedpi.exe exited with code %lu\n", (unsigned long)code);
        stop_windivert_driver();
    } else {
        printf("\n  Could not start goodbyedpi.exe (error %lu)\n", (unsigned long)GetLastError());
    }
    SetConsoleCtrlHandler(ignore_ctrl_c, FALSE);
    pause_for_key();
}

/* ------------------------------------------------------------------ */
/* Run hidden, with a notification-area icon                           */
/* ------------------------------------------------------------------ */

static NOTIFYICONDATAA g_nid;
static UINT g_taskbar_created;
static int g_alive = 1;
static DWORD g_exit_code;

static void show_menu(HWND hwnd) {
    char status[64];
    POINT pt;
    HMENU menu = CreatePopupMenu();

    if (!menu)
        return;
    if (g_alive)
        snprintf(status, sizeof(status), "GoodbyeDPI: running");
    else
        snprintf(status, sizeof(status), "GoodbyeDPI: stopped (exit code %lu)",
                 (unsigned long)g_exit_code);

    AppendMenuA(menu, MF_STRING | MF_GRAYED, 0, status);
    AppendMenuA(menu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(menu, MF_STRING, ID_EXIT, "Exit and stop GoodbyeDPI");

    GetCursorPos(&pt);
    SetForegroundWindow(hwnd); /* required, otherwise the menu does not close on outside click */
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
    PostMessageA(hwnd, WM_NULL, 0, 0);
    DestroyMenu(menu);
}

static LRESULT CALLBACK tray_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_TRAY) {
        if (lp == WM_RBUTTONUP || lp == WM_LBUTTONUP || lp == WM_CONTEXTMENU)
            show_menu(hwnd);
        return 0;
    }
    if (msg == WM_COMMAND && LOWORD(wp) == ID_EXIT) {
        DestroyWindow(hwnd);
        return 0;
    }
    if (msg == WM_DESTROY) {
        Shell_NotifyIconA(NIM_DELETE, &g_nid);
        PostQuitMessage(0);
        return 0;
    }
    if (g_taskbar_created && msg == g_taskbar_created) {
        /* Explorer restarted, the icon has to be added again */
        Shell_NotifyIconA(NIM_ADD, &g_nid);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

static void tray_notify_stopped(void) {
    g_nid.uFlags = NIF_TIP | NIF_INFO;
    snprintf(g_nid.szTip, sizeof(g_nid.szTip), "GoodbyeDPI - stopped");
    snprintf(g_nid.szInfoTitle, sizeof(g_nid.szInfoTitle), "GoodbyeDPI stopped");
    snprintf(g_nid.szInfo, sizeof(g_nid.szInfo),
             "goodbyedpi.exe exited with code %lu.", (unsigned long)g_exit_code);
    g_nid.dwInfoFlags = NIIF_WARNING;
    Shell_NotifyIconA(NIM_MODIFY, &g_nid);
}

/* Runs the icon and its message loop until the user chooses Exit. */
static void tray_loop(HANDLE proc, const char *args) {
    HINSTANCE inst = GetModuleHandleA(NULL);
    WNDCLASSA wc;
    HWND hwnd;
    char self[MAX_PATH];
    HICON icon;
    HANDLE wait_handle = proc;
    DWORD wait_count = 1;
    MSG msg;

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = tray_wndproc;
    wc.hInstance = inst;
    wc.lpszClassName = "GoodbyeDPITray";
    RegisterClassA(&wc);
    g_taskbar_created = RegisterWindowMessageA("TaskbarCreated");

    /* A hidden top-level window that only receives the icon's messages */
    hwnd = CreateWindowExA(0, wc.lpszClassName, "GoodbyeDPI", WS_OVERLAPPED,
                           0, 0, 0, 0, NULL, NULL, inst, NULL);
    if (!hwnd)
        return;

    /* First icon in our own exe resources */
    icon = NULL;
    if (GetModuleFileNameA(NULL, self, sizeof(self)))
        icon = ExtractIconA(inst, self, 0);
    if ((UINT_PTR)icon <= 1)
        icon = LoadIconA(NULL, IDI_APPLICATION);

    memset(&g_nid, 0, sizeof(g_nid));
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAY;
    g_nid.hIcon = icon;
    snprintf(g_nid.szTip, sizeof(g_nid.szTip), "GoodbyeDPI - running (%.90s)", args);
    Shell_NotifyIconA(NIM_ADD, &g_nid);

    for (;;) {
        DWORD r = MsgWaitForMultipleObjects(wait_count, &wait_handle, FALSE, INFINITE, QS_ALLINPUT);

        if (wait_count && r == WAIT_OBJECT_0) {
            /* goodbyedpi.exe died on its own. Stop waiting on a signaled handle. */
            g_alive = 0;
            GetExitCodeProcess(proc, &g_exit_code);
            wait_count = 0;
            tray_notify_stopped();
        }
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT)
                return;
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }
}

/* Keeps reading goodbyedpi's output so it never blocks on a full pipe */
static DWORD WINAPI drain_pipe(LPVOID param) {
    char buf[1024];
    DWORD n;

    while (ReadFile((HANDLE)param, buf, sizeof(buf), &n, NULL) && n)
        ;
    return 0;
}

/*
 * Starts goodbyedpi.exe hidden, waits until it reports that it is running,
 * then closes the console and lives in the tray.
 * Returns 1 when a tray session ran and has ended (the caller should exit),
 * 0 when starting failed (a message was shown, back to the menu).
 */
static int run_in_tray(const struct state *st) {
    char cmdline[MAX_PATH + 300];
    char args[256];
    char log[8192];
    char buf[512];
    size_t log_len = 0;
    int ready = 0;
    DWORD n;
    HANDLE mutex, job, rd = NULL, wr = NULL, nul;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;

    if (prepare_cmdline(st, cmdline, sizeof(cmdline)) != 0) {
        pause_for_key();
        return 0;
    }

    /* Two copies would both divert the same packets */
    mutex = CreateMutexA(NULL, FALSE, TRAY_MUTEX);
    if (mutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        printf(CLEAR "  GoodbyeDPI is already running in the system tray.\n"
               "  Exit it from the tray icon first.\n");
        CloseHandle(mutex);
        pause_for_key();
        return 0;
    }

    printf(CLEAR "  Starting: %s\n\n", cmdline);
    fflush(stdout);

    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        printf("  Could not create a pipe (error %lu)\n", (unsigned long)GetLastError());
        pause_for_key();
        return 0;
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0); /* only the write end goes to the child */
    nul = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nul;
    si.hStdOutput = wr;
    si.hStdError = wr;
    memset(&pi, 0, sizeof(pi));

    /* No console of its own: this program's console is the only one to close later */
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("  Could not start goodbyedpi.exe (error %lu)\n", (unsigned long)GetLastError());
        CloseHandle(rd);
        CloseHandle(wr);
        if (nul != INVALID_HANDLE_VALUE)
            CloseHandle(nul);
        pause_for_key();
        return 0;
    }
    CloseHandle(wr); /* otherwise the pipe never reports that the child is gone */
    if (nul != INVALID_HANDLE_VALUE)
        CloseHandle(nul);

    /* If this program ends for any reason, goodbyedpi.exe goes with it */
    job = CreateJobObjectA(NULL, NULL);
    if (job) {
        memset(&jeli, 0, sizeof(jeli));
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
        AssignProcessToJobObject(job, pi.hProcess);
    }

    /* Show its output until it says it is running, or exits */
    log[0] = '\0';
    while (ReadFile(rd, buf, sizeof(buf) - 1, &n, NULL) && n) {
        buf[n] = '\0';
        fputs(buf, stdout);
        fflush(stdout);
        if (log_len + n < sizeof(log)) {
            memcpy(log + log_len, buf, n + 1);
            log_len += n;
        }
        if (strstr(log, READY_MARKER)) {
            ready = 1;
            break;
        }
    }

    if (!ready) {
        DWORD code = 0;
        WaitForSingleObject(pi.hProcess, 2000);
        GetExitCodeProcess(pi.hProcess, &code);
        printf("\n  goodbyedpi.exe exited with code %lu\n", (unsigned long)code);
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 3000);
        stop_windivert_driver();
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(rd);
        if (job)
            CloseHandle(job);
        CloseHandle(mutex);
        pause_for_key();
        return 0;
    }

    CloseHandle(CreateThread(NULL, 0, drain_pipe, rd, 0, NULL));
    build_args(st, args, sizeof(args));
    printf("\n  Running in the system tray.\n");
    fflush(stdout);
    Sleep(800);
    FreeConsole();

    tray_loop(pi.hProcess, args);

    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 3000); /* its handles must be closed before the driver can stop */
    stop_windivert_driver();
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (job)
        CloseHandle(job);
    CloseHandle(mutex);
    return 1;
}

/* ------------------------------------------------------------------ */

int main(int argc, char *argv[]) {
    struct state st = { ITEM_START, 0, 0, 0, 0, 0 };
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;

    if (argc > 1 && strcmp(argv[1], "--print") == 0) {
        char args[256];
        build_args(&st, args, sizeof(args));
        printf("goodbyedpi.exe %s\n", args);
        return 0;
    }

    if (argc > 1 && strcmp(argv[1], "--tray") == 0) {
        st.tray = 1;
        if (argc > 2) {
            size_t i;
            for (i = 0; i < PRESET_COUNT; i++)
                if (strcmp(argv[2], preset_names[i]) == 0)
                    st.preset = (int)i;
            if (st.preset == 0 && strcmp(argv[2], preset_names[0]) != 0) {
                fprintf(stderr, "Unknown preset: %s\n", argv[2]);
                return 1;
            }
        }
        return run_in_tray(&st) ? 0 : 1;
    }

    if (!GetConsoleMode(out, &mode) ||
        !SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        fprintf(stderr, "This program needs a Windows 10+ console (ANSI escape support).\n");
        return 1;
    }

    printf(ESC "[?25l"); /* hide cursor */

    for (;;) {
        int key;

        draw(&st);
        key = _getch();

        if (key == 0 || key == 0xE0) {
            switch (_getch()) {
                case 72: st.selected = wrap(st.selected, -1, ITEM_COUNT); break; /* up */
                case 80: st.selected = wrap(st.selected, 1, ITEM_COUNT); break;  /* down */
                case 75: change(&st, -1); break;                                 /* left */
                case 77: change(&st, 1); break;                                  /* right */
                default: break;
            }
            continue;
        }

        switch (key) {
            case 'k': st.selected = wrap(st.selected, -1, ITEM_COUNT); break;
            case 'j': st.selected = wrap(st.selected, 1, ITEM_COUNT); break;
            case 'h': change(&st, -1); break;
            case 'l': change(&st, 1); break;
            case ' ':
            case '\r':
                if (st.selected == ITEM_START) {
                    if (st.tray) {
                        if (run_in_tray(&st))
                            return 0;
                    } else {
                        run(&st);
                    }
                } else if (st.selected == ITEM_QUIT) {
                    goto done;
                } else {
                    change(&st, 1);
                }
                break;
            case 'q':
            case 'Q':
            case 27:
                goto done;
            default:
                break;
        }
    }

done:
    printf(ESC "[?25h" CLEAR);
    return 0;
}
