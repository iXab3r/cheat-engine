#include "eautils.h"
#include "logging.h"
#include "blackbone/Private.h"

BOOLEAN gIsEyeAurasService;

// Monitoring additions
static HANDLE gMonitoredPidHandle = NULL; // stores PID value as handle
static BOOLEAN gMonitorActive = FALSE;
static HANDLE gMonitorThreadHandle = NULL;
static PETHREAD gMonitorThreadObject = NULL;
static KEVENT gMonitorStopEvent;
static UNICODE_STRING gSavedRegistryPath = {0};

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
            LogInfo("Awaiting for Monitor thread object");
            //KeWaitForSingleObject(gMonitorThreadObject, Executive, KernelMode, FALSE, NULL);
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
                LogInfo("Monitored process no longer exists. Attempting to unload the driver.");
                if (gSavedRegistryPath.Buffer && gSavedRegistryPath.Length)
                {
                    NTSTATUS us = ZwUnloadDriver(&gSavedRegistryPath);
                    LogInfo("ZwUnloadDriver returned: 0x%08X", us);
                }
                break; // exit thread either way
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
    if (gMonitoredPidHandle)
    {
        LogInfo("Initializing monitoring for PID=%p", gMonitoredPidHandle);

        LogWarn("Monitoring is temporarily disabled");
        return;


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
            NTSTATUS orh = ObReferenceObjectByHandle(gMonitorThreadHandle, SYNCHRONIZE, *PsThreadType, KernelMode,
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
    else
    {
        LogWarn("Monitoring could not be started - PID is not set");
    }
}
