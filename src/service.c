#include <windows.h>
#include <stdio.h>
#include "goodbyedpi.h"
#include "service.h"

#define SERVICE_NAME "GoodbyeDPI"

static SERVICE_STATUS ServiceStatus;
static SERVICE_STATUS_HANDLE hStatus;
static int service_argc = 0;
static char **service_argv = NULL;

int service_register(int argc, char *argv[])
{
    int i, ret;
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)service_main},
        {NULL, NULL}
    };
    /*
     * Save argc & argv as service_main is called with different
     * arguments, which are passed from "start" command, not
     * from the program command line.
     * We don't need this behaviour.
     *
     * Note that if StartServiceCtrlDispatcher() succeedes
     * it does not return until the service is stopped,
     * so we should copy all arguments first and then
     * handle the failure.
     */
    if (!service_argc && !service_argv) {
        service_argc = argc;
        service_argv = calloc((size_t)(argc + 1), sizeof(void*));
        for (i = 0; i < argc; i++) {
            service_argv[i] = strdup(argv[i]);
        }
    }

    ret = StartServiceCtrlDispatcher(ServiceTable);

    if (service_argc && service_argv) {
        for (i = 0; i < service_argc; i++) {
            free(service_argv[i]);
        }
        free(service_argv);
    }

    return ret;
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
    ServiceStatus.dwWin32ExitCode = (DWORD)main(service_argc, service_argv);
    ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
    SetServiceStatus(hStatus, &ServiceStatus);
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
    SetServiceStatus(hStatus, &ServiceStatus);
    return;
}
