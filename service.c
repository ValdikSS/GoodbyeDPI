#include <windows.h>
#include <stdio.h>
#include "goodbyedpi.h"
#include "service.h"

#define SERVICE_NAME "GoodbyeDPI"

static SERVICE_STATUS ServiceStatus;
static SERVICE_STATUS_HANDLE hStatus;
static int service_argc;
static char **service_argv;

int service_register(int argc, char *argv[])
{
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)service_main},
        {NULL, NULL}
    };
    /*
     * Save argc & argv as service_main is called with different
     * arguments, which are passed from "start" command, not
     * from the program command line.
     * We don't need this behaviour.
     */
    service_argc = argc;
    service_argv = malloc(sizeof(void*) * argc);
    for (int i = 0; i < argc; i++) {
        service_argv[i] = strdup(argv[i]);
    }
    return StartServiceCtrlDispatcher(ServiceTable);
}

void service_main(int argc __attribute__((unused)),
                  char *argv[] __attribute__((unused)))
{
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS; 
    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 1;
    ServiceStatus.dwWaitHint = 0;

    hStatus = RegisterServiceCtrlHandler(
        SERVICE_NAME,
        (LPHANDLER_FUNCTION)service_controlhandler);
    if (hStatus == (SERVICE_STATUS_HANDLE)0)
    {
        // Registering Control Handler failed
        return;
    }

    SetServiceStatus(hStatus, &ServiceStatus);

    // Calling main with saved argc & argv
    main(service_argc, service_argv);

    if (ServiceStatus.dwCurrentState != SERVICE_STOPPED) {
        // If terminated with error
        ServiceStatus.dwWin32ExitCode = 1;
        ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
        SetServiceStatus (hStatus, &ServiceStatus);
    }
    return;
}

// Control handler function
void service_controlhandler(DWORD request)
{
    switch(request)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            deinit_all();
            ServiceStatus.dwWin32ExitCode = 0;
            ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
        default:
            break;
    }
    // Report current status
    SetServiceStatus (hStatus, &ServiceStatus);
    return;
}
