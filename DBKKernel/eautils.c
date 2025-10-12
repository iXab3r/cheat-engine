#include "eautils.h"
#include "logging.h"
#include "blackbone/Private.h"
#include "DBKDrvr.h"

BOOLEAN gIsEyeAurasService;

static HANDLE gMonitoredPidHandle = NULL; // stores PID value as handle
static BOOLEAN gMonitorActive = FALSE;
static HANDLE gMonitorThreadHandle = NULL;
static PETHREAD gMonitorThreadObject = NULL;
static KEVENT gMonitorStopEvent;
static UNICODE_STRING gSavedRegistryPath = {0};
static BOOLEAN g_DriverDisabled = FALSE;

BOOLEAN IsDriverDisabled(void)
{
    return g_DriverDisabled;
}

NTSTATUS DisableDriverFunctionality(void)
{
    if (g_DriverDisabled)
    {
        LogInfo("Driver functionality is already disabled");
        return STATUS_SUCCESS;
    }

    LogInfo("Disabling driver functionality (without unload)");
    g_DriverDisabled = TRUE;
    return STATUS_SUCCESS;
}

BOOLEAN isEyeAurasService(void)
{
    return gIsEyeAurasService;
}

void setIsEyeAurasService(BOOLEAN value)
{
    gIsEyeAurasService = value;
}

HANDLE getMonitoringPID(void)
{
    return gMonitoredPidHandle;
}

void setMonitoringPID(HANDLE processId)
{
    gMonitoredPidHandle = processId;
    LogInfo("Monitoring PID = %p", gMonitoredPidHandle);
}

void stopMonitoring(void)
{
    if (gMonitorActive)
    {
        LogInfo("Signaling monitor thread to stop");
        gMonitorActive = FALSE;
        KeSetEvent(&gMonitorStopEvent, IO_NO_INCREMENT, FALSE);
        if (gMonitorThreadObject)
        {
            LogInfo("Awaiting monitor thread termination");
            PETHREAD currentThread = PsGetCurrentThread();
            if (currentThread != gMonitorThreadObject)
            {
                KeWaitForSingleObject(gMonitorThreadObject, Executive, KernelMode, FALSE, NULL);
            }
            else
            {
                LogInfo("Stop requested from within the monitor thread; skipping wait to avoid deadlock");
            }
            ObDereferenceObject(gMonitorThreadObject);
            gMonitorThreadObject = NULL;
        }

        if (gMonitorThreadHandle)
        {
            LogInfo("Closing Monitor thread");
            ZwClose(gMonitorThreadHandle);
            gMonitorThreadHandle = NULL;
        }

        if (gSavedRegistryPath.Buffer)
        {
            LogInfo("Cleaning up Monitor thread memory");
            ExFreePool(gSavedRegistryPath.Buffer);
            RtlZeroMemory(&gSavedRegistryPath, sizeof(gSavedRegistryPath));
        }
        gMonitoredPidHandle = NULL;
        LogInfo("Monitoring has been fully stopped");
    }
    else
    {
        LogInfo("Monitoring is not active anyways - can't stop it");
    }
}

void initializeMonitoring(IN PUNICODE_STRING RegistryPath)
{
    gSavedRegistryPath.Length = RegistryPath->Length;
    gSavedRegistryPath.MaximumLength = RegistryPath->Length + sizeof(WCHAR);
    gSavedRegistryPath.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, gSavedRegistryPath.MaximumLength, BB_POOL_TAG);
    if (gSavedRegistryPath.Buffer)
    {
        RtlCopyMemory(gSavedRegistryPath.Buffer, RegistryPath->Buffer, RegistryPath->Length);
        gSavedRegistryPath.Buffer[RegistryPath->Length / sizeof(WCHAR)] = L'\0';
    }
    else
    {
        LogInfo("Failed to allocate memory for saved RegistryPath");
    }
}

// Dedicated unloader thread that initiates self-unload safely after monitor thread exits
static VOID UnloaderThreadProc(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    LogInfo("Unloader thread started");

    if (gSavedRegistryPath.Buffer && gSavedRegistryPath.Length)
    {
        UNICODE_STRING us = { 0 };
        us.Length = gSavedRegistryPath.Length;
        us.MaximumLength = gSavedRegistryPath.Length + sizeof(WCHAR);
        us.Buffer = (PWSTR)ExAllocatePool2(POOL_FLAG_PAGED, us.MaximumLength, BB_POOL_TAG);
        if (us.Buffer)
        {
            RtlCopyMemory(us.Buffer, gSavedRegistryPath.Buffer, gSavedRegistryPath.Length);
            us.Buffer[gSavedRegistryPath.Length / sizeof(WCHAR)] = L'\0';
            NTSTATUS st = ZwUnloadDriver(&us);
            LogInfo("ZwUnloadDriver returned: 0x%08X", st);
            // Intentionally leaking 'us.Buffer' since the driver may be gone after unload
        }
        else
        {
            LogInfo("Unloader thread: allocation for registry path copy failed");
        }
    }
    else
    {
        LogInfo("Unloader thread: saved registry path is not available");
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID monitorThreadProc(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    LogInfo("Monitor thread started (PID=%p)", gMonitoredPidHandle);
    LARGE_INTEGER interval;
    // 5 seconds periodic check
    interval.QuadPart = -(LONGLONG)5 * 1000 * 1000 * 10; // relative 5s

    for (;;)
    {
        NTSTATUS waitStatus = KeWaitForSingleObject(&gMonitorStopEvent, Executive, KernelMode, FALSE, &interval);
        if (waitStatus == STATUS_SUCCESS)
        {
            LogInfo("Monitor thread stop signaled");
            break;
        }

        // Periodic check
        if (gMonitoredPidHandle)
        {
            PEPROCESS Process = NULL;
            NTSTATUS st = PsLookupProcessByProcessId(gMonitoredPidHandle, &Process);
            if (NT_SUCCESS(st))
            {
                // Process exists
                ObDereferenceObject(Process);
            }
            else
            {
                LogInfo("Monitored process no longer exists. Disabling driver functionality.");
                DisableDriverFunctionality();
                break; // exit monitor thread
            }
        }
        else
        {
            LogInfo("Process handle was cleared, stopping monitoring process");
            break;
        }
    }

    LogInfo("Monitor thread exiting");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID startProcessMonitoring(void)
{
    if (!gMonitoredPidHandle)
    {
        LogWarn("Monitoring could not be started - PID is not set");
        return;
    }
    
    LogInfo("Initializing monitoring for PID=%p", gMonitoredPidHandle);

    KeInitializeEvent(&gMonitorStopEvent, NotificationEvent, FALSE);
    gMonitorActive = TRUE;
    NTSTATUS th = PsCreateSystemThread(&gMonitorThreadHandle,
                                       THREAD_ALL_ACCESS,
                                       NULL,
                                       NULL,
                                       NULL,
                                       monitorThreadProc,
                                       NULL);
    if (NT_SUCCESS(th))
    {
        LogInfo("Monitoring thread was started: %p", gMonitoredPidHandle);
        NTSTATUS orh = ObReferenceObjectByHandle(gMonitorThreadHandle, SYNCHRONIZE, PsThreadType, KernelMode,
                                                 (PVOID*)&gMonitorThreadObject, NULL);
        if (!NT_SUCCESS(orh))
        {
            LogInfo("Failed to reference monitor thread object: 0x%08X", orh);
        }
    }
    else
    {
        LogInfo("Failed to create monitor thread: 0x%08X", th);
    }
}
