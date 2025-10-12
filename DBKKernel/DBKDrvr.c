#pragma warning( disable: 4100 4101 4103 4189)

#include "DBKFunc.h"
#include <ntifs.h>
#include <windef.h>
#include "DBKDrvr.h"

#include "deepkernel.h"
#include "processlist.h"
#include "memscan.h"
#include "threads.h"
#include "vmxhelper.h"
#include "debugger.h"
#include "eautils.h"
#include "vmxoffload.h"

#include "IOPLDispatcher.h"
#include "interruptHook.h"
#include "ultimap.h"
#include "ultimap2.h"
#include "noexceptions.h"
#include "blackbone/BlackBoneDrv.h"

#include "ultimap2\apic.h"

#if (AMD64 && TOBESIGNED)
#include "sigcheck.h"
#endif


#ifdef CETC
#include "cetc.h"
#endif

void UnloadDriver(PDRIVER_OBJECT DriverObject);

NTSTATUS DispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS DispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

enum
{
    DEFAULT_BUFFER_SIZE = 100
};

typedef NTSTATUS (*PSRCTNR)(__in PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine);
PSRCTNR PsRemoveCreateThreadNotifyRoutine2;

typedef NTSTATUS (*PSRLINR)(__in PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine);
PSRLINR PsRemoveLoadImageNotifyRoutine2;

UNICODE_STRING uszDeviceString;
PVOID BufDeviceString = NULL, BufDeviceStringFormat = NULL;

void* functionlist[1];
char paramsizes[1];
int registered = 0;

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS tls = DBKTraceLoggingRegister();
    if (NT_SUCCESS(tls))
    {
        TraceLoggingWrite(g_DBKProvider, "ProviderRegistered", TraceLoggingLevel(TRACE_LEVEL_INFORMATION));
    }

    LogInfo("DBK: %s: Loading BB", __FUNCTION__);
    NTSTATUS bbStatus = BBInitDriver(DriverObject);
    if (!NT_SUCCESS(bbStatus))
    {
        LogError("DBK: %s: Failed to load BB: 0x%08X", __FUNCTION__, bbStatus);
        return bbStatus;
    }
    LogInfo("DBK: %s: BB loaded successfully", __FUNCTION__);

    NTSTATUS ntStatus;
    PVOID BufDriverString = NULL, BufDriverStringFormat = NULL, BufProcessEventString = NULL, BufThreadEventString =
              NULL;
    UNICODE_STRING uszDriverString;

    UNICODE_STRING uszProcessEventString;
    UNICODE_STRING uszThreadEventString;
    PDEVICE_OBJECT pDeviceObject;
    HANDLE reg = 0;
    OBJECT_ATTRIBUTES oa;

    UNICODE_STRING temp;
    char wbuf[DEFAULT_BUFFER_SIZE];
    WORD this_cs, this_ss, this_ds, this_es, this_fs, this_gs;
    ULONG cr4reg;

    criticalSection csTest;

    HANDLE Ultimap2Handle;

    KernelCodeStepping = 0;
    KernelWritesIgnoreWP = 0;

    this_cs = getCS();
    this_ss = getSS();
    this_ds = getDS();
    this_es = getES();
    this_fs = getFS();
    this_gs = getGS();

    temp.Buffer = (PWCH)wbuf;
    temp.Length = 0;
    temp.MaximumLength = DEFAULT_BUFFER_SIZE;

    LogInfo("DBK: %s: Loading driver", __FUNCTION__);
    if (RegistryPath)
    {
        LogInfo("DBK: %s: Registry path = %S", __FUNCTION__, RegistryPath->Buffer);

        UNICODE_STRING serviceName;
        if (ExtractServiceNameFromRegistryPath(RegistryPath, &serviceName))
        {
            LogInfo("DBK: %s: Driver loaded for service @ %wZ, service name: %wZ", __FUNCTION__, RegistryPath,
                    &serviceName);
            UNICODE_STRING easvc;
            RtlInitUnicodeString(&easvc, L"EASVC73");
            BOOLEAN isCheatEngineService = RtlEqualUnicodeString(&serviceName, &easvc, TRUE);
            setIsEyeAurasService(!isCheatEngineService);

            LogInfo("DBK: %s: Service mode: %s", __FUNCTION__,
                    isEyeAurasService() ? "Generic (with PID monitoring)" : "Persistent (No PID monitoring)");

            if (isEyeAurasService())
            {
                initializeMonitoring(RegistryPath);
            }
        }
        else
        {
            LogInfo("DBK: %s: Failed to extract service name from RegistryPath: %wZ", __FUNCTION__, RegistryPath);
            return STATUS_UNSUCCESSFUL;
        }

        InitializeObjectAttributes(&oa, RegistryPath, OBJ_KERNEL_HANDLE, NULL, NULL);
        ntStatus = ZwOpenKey(&reg, KEY_QUERY_VALUE, &oa);
        if (ntStatus == STATUS_SUCCESS)
        {
            UNICODE_STRING A, B, C, D, P;
            PKEY_VALUE_PARTIAL_INFORMATION bufDriverString, bufDeviceString, bufProcessEventString, bugThreadEventString
                                           , bufPid;
            ULONG ActualSize;

            LogInfo("DBK: %s: Opened the key", __FUNCTION__);

            BufDriverString = ExAllocatePool(PagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + DEFAULT_BUFFER_SIZE);
            BufDriverStringFormat = ExAllocatePool(PagedPool, DEFAULT_BUFFER_SIZE);
            BufDeviceString = ExAllocatePool(PagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + DEFAULT_BUFFER_SIZE);
            BufDeviceStringFormat = ExAllocatePool(PagedPool, DEFAULT_BUFFER_SIZE);
            BufProcessEventString = ExAllocatePool(
                PagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + DEFAULT_BUFFER_SIZE);
            BufThreadEventString = ExAllocatePool(
                PagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + DEFAULT_BUFFER_SIZE);

            bufDriverString = BufDriverString;
            bufDeviceString = BufDeviceString;
            bufProcessEventString = BufProcessEventString;
            bugThreadEventString = BufThreadEventString;

            RtlInitUnicodeString(&A, L"A");
            RtlInitUnicodeString(&B, L"B");
            RtlInitUnicodeString(&C, L"C");
            RtlInitUnicodeString(&D, L"D");
            RtlInitUnicodeString(&P, L"P");

            if (ntStatus == STATUS_SUCCESS)
            {
                if (NT_SUCCESS(
                    ZwQueryValueKey(reg, &A, KeyValuePartialInformation, bufDriverString, sizeof(
                            KEY_VALUE_PARTIAL_INFORMATION) +
                        100, &ActualSize)))
                {
                    RtlInitUnicodeString(&uszDriverString, (PCWSTR)bufDriverString->Data);
                }
                else
                {
                    ntStatus = RtlStringCbPrintfW(
                        BufDriverStringFormat,
                        DEFAULT_BUFFER_SIZE,
                        L"\\Device\\%wZ",
                        &serviceName
                    );
                    if (NT_SUCCESS(ntStatus))
                    {
                        RtlInitUnicodeString(&uszDriverString, BufDriverStringFormat);
                    }
                }
            }

            if (ntStatus == STATUS_SUCCESS)
            {
                if (NT_SUCCESS(
                    ZwQueryValueKey(reg, &B, KeyValuePartialInformation, bufDeviceString, sizeof(
                            KEY_VALUE_PARTIAL_INFORMATION) +
                        100, &ActualSize)))
                {
                    RtlInitUnicodeString(&uszDeviceString, (PCWSTR)bufDeviceString->Data);
                }
                else
                {
                    ntStatus = RtlStringCbPrintfW(
                        BufDeviceStringFormat,
                        DEFAULT_BUFFER_SIZE,
                        L"\\DosDevices\\%wZ",
                        &serviceName
                    );
                    if (NT_SUCCESS(ntStatus))
                    {
                        RtlInitUnicodeString(&uszDeviceString, BufDeviceStringFormat);
                    }
                }
            }

            if (ntStatus == STATUS_SUCCESS)
            {
                if (NT_SUCCESS(
                    ZwQueryValueKey(reg, &C, KeyValuePartialInformation, bufProcessEventString, sizeof(
                            KEY_VALUE_PARTIAL_INFORMATION) +
                        100, &ActualSize)))
                {
                    RtlInitUnicodeString(&uszProcessEventString, (PCWSTR)bufProcessEventString->Data);
                }
                else
                {
                    RtlInitUnicodeString(&uszProcessEventString, (PCWSTR)L"\\BaseNamedObjects\\DBKProcList60");
                }
            }
            if (ntStatus == STATUS_SUCCESS)
            {
                if (NT_SUCCESS(
                    ZwQueryValueKey(reg, &D, KeyValuePartialInformation, bugThreadEventString, sizeof(
                            KEY_VALUE_PARTIAL_INFORMATION) +
                        100, &ActualSize)))
                {
                    RtlInitUnicodeString(&uszThreadEventString, (PCWSTR)bugThreadEventString->Data);
                }
                else
                {
                    RtlInitUnicodeString(&uszThreadEventString, (PCWSTR)L"\\BaseNamedObjects\\DBKThreadList60");
                }
            }

            ULONGLONG pid64 = 0;
            if (ntStatus == STATUS_SUCCESS && isEyeAurasService())
            {
                bufPid = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool(
                    PagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONGLONG));
                if (bufPid)
                {
                    if (NT_SUCCESS(
                        ZwQueryValueKey(reg, &P, KeyValuePartialInformation, bufPid, sizeof(
                                KEY_VALUE_PARTIAL_INFORMATION)
                            + sizeof(ULONGLONG), &ActualSize)))
                    {
                        if (bufPid->Type == REG_DWORD && bufPid->DataLength >= sizeof(ULONG))
                        {
                            pid64 = *(ULONG*)bufPid->Data;
                        }
                        else if (bufPid->Type == REG_QWORD && bufPid->DataLength >= sizeof(ULONGLONG))
                        {
                            pid64 = *(ULONGLONG*)bufPid->Data;
                        }
                        else
                        {
                            LogInfo("Unsupported registry type for P: %u", bufPid->Type);
                        }
                    }
                    ExFreePool(bufPid);
                }
                else
                {
                    LogInfo("Failed to allocate buffer for reading 'P'");
                }
            }

            LogInfo("DBK: %s: DriverString=%S", __FUNCTION__, uszDriverString.Buffer);
            LogInfo("DBK: %s: DeviceString=%S", __FUNCTION__, uszDeviceString.Buffer);
            LogInfo("DBK: %s: ProcessEventString=%S", __FUNCTION__, uszProcessEventString.Buffer);
            LogInfo("DBK: %s: ThreadEventString=%S", __FUNCTION__, uszThreadEventString.Buffer);
            LogInfo("DBK: %s: PID=%p", __FUNCTION__, (HANDLE)pid64);

            if (pid64)
            {
                setMonitoringPID((HANDLE)pid64);
            }

            if (ntStatus == STATUS_SUCCESS)
            {
                LogInfo("DBK: %s: Read settings successfully", __FUNCTION__);
            }
            else
            {
                ExFreePool(bufDriverString);
                ExFreePool(bufDeviceString);
                ExFreePool(bufProcessEventString);
                ExFreePool(bugThreadEventString);

                LogInfo("DBK: %s: Failed reading the value", __FUNCTION__);
                if (!NT_SUCCESS(ZwClose(reg)))
                {
                    LogInfo("DBK: %s: Failed close registry", __FUNCTION__);
                }
                return STATUS_UNSUCCESSFUL;
            }
        }
        else
        {
            LogInfo("DBK: %s: Failed opening the key", __FUNCTION__);
            return STATUS_UNSUCCESSFUL;
        }
    }
    else
    {
        LogInfo("DBK: %s: Registry path is not set - loaded by DBVM", __FUNCTION__);
        loadedbydbvm = TRUE;
    }

    ntStatus = STATUS_SUCCESS;

    if (!loadedbydbvm)
    {
        LogInfo("DBK: %s: Creating the device %S", __FUNCTION__, uszDriverString.Buffer);
        ntStatus = IoCreateDevice(DriverObject,
                                  0,
                                  &uszDriverString,
                                  FILE_DEVICE_UNKNOWN,
                                  0,
                                  FALSE,
                                  &pDeviceObject);

        if (ntStatus == STATUS_SUCCESS)
        {
            LogInfo("DBK: %s: IoCreateDevice succeeded", __FUNCTION__);
        }
        else
        {
            LogError("DBK: %s: IoCreateDevice failed", __FUNCTION__);
            ExFreePool(BufDriverString);
            ExFreePool(BufDriverStringFormat);
            ExFreePool(BufDeviceString);
            ExFreePool(BufDeviceStringFormat);
            ExFreePool(BufProcessEventString);
            ExFreePool(BufThreadEventString);

            if (reg)
            {
                ZwClose(reg);
            }

            return ntStatus;
        }

        // Point uszDeviceString at the device name
        // Create symbolic link to the user-visible name
        LogInfo("DBK: %s: Creating symbolic link, deviceString: %S, driverString: %S", __FUNCTION__,
                uszDeviceString.Buffer,
                uszDriverString.Buffer);
        ntStatus = IoCreateSymbolicLink(&uszDeviceString, &uszDriverString);

        if (ntStatus != STATUS_SUCCESS)
        {
            LogError("DBK: %s: IoCreateSymbolicLink failed: %x", __FUNCTION__, ntStatus);
            // Delete device object if not successful
            IoDeleteDevice(pDeviceObject);

            ExFreePool(BufDriverString);
            ExFreePool(BufDriverStringFormat);
            ExFreePool(BufDeviceString);
            ExFreePool(BufDeviceStringFormat);
            ExFreePool(BufProcessEventString);
            ExFreePool(BufThreadEventString);

            if (reg)
            {
                ZwClose(reg);
            }

            return ntStatus;
        }
    }

    //when loaded by dbvm driver object is 'valid' so store the function addresses
    LogInfo("DBK: %s: DriverObject=%p", __FUNCTION__, DriverObject);

    // Load structure to point to IRP handlers...
    DriverObject->DriverUnload = UnloadDriver;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;

    if (loadedbydbvm)
    {
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)DispatchIoctlDBVM;
    }
    else
    {
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
    }

    startProcessMonitoring();

    ProcessEventCount = 0;
    ExInitializeResourceLite(&ProcesslistR);
    CreateProcessNotifyRoutineEnabled = FALSE;
    ThreadEventCount = 0;
    processlist = NULL;

#ifndef AMD64
    //determine if PAE is used
    cr4reg = (ULONG)getCR4();

    if ((cr4reg & 0x20) == 0x20)
    {
        PTESize = 8; //pae
        PAGE_SIZE_LARGE = 0x200000;
        MAX_PDE_POS = 0xC0604000;
        MAX_PTE_POS = 0xC07FFFF8;
    }
    else
    {
        PTESize = 4;
        PAGE_SIZE_LARGE = 0x400000;
        MAX_PDE_POS = 0xC0301000;
        MAX_PTE_POS = 0xC03FFFFC;
    }
#else
    PTESize = 8; //pae
    PAGE_SIZE_LARGE = 0x200000;
    //base was 0xfffff68000000000ULL

    //to 
    MAX_PTE_POS = 0xFFFFF6FFFFFFFFF8ULL; // base + 0x7FFFFFFFF8
    MAX_PDE_POS = 0xFFFFF6FB7FFFFFF8ULL; // base + 0x7B7FFFFFF8
#endif

    LogInfo("DBK: %s: Initializing debugger", __FUNCTION__);
    debugger_initialize();

    // Return success (don't do the devicestring, I need it for unload)
    LogInfo("DBK: %s: Cleaning up initialization buffers", __FUNCTION__);
    if (BufDriverString)
    {
        ExFreePool(BufDriverString);
        BufDriverString = NULL;
    }

    if (BufDriverStringFormat)
    {
        ExFreePool(BufDriverStringFormat);
        BufDriverStringFormat = NULL;
    }

    if (BufProcessEventString)
    {
        ExFreePool(BufProcessEventString);
        BufProcessEventString = NULL;
    }

    if (BufThreadEventString)
    {
        ExFreePool(BufThreadEventString);
        BufThreadEventString = NULL;
    }

    if (reg)
    {
        ZwClose(reg);
        reg = 0;
    }


    //fetch cpu info
    {
        DWORD r[4];
        DWORD a;

        __cpuid(r, 0);
        LogInfo("DBK: %s: cpuid.0: r[1]=%x", __FUNCTION__, r[1]);
        if (r[1] == 0x756e6547) //GenuineIntel
        {
            __cpuid(r, 1);

            a = r[0];

            cpu_stepping = a & 0xf;
            cpu_model = (a >> 4) & 0xf;
            cpu_familyID = (a >> 8) & 0xf;
            cpu_type = (a >> 12) & 0x3;
            cpu_ext_modelID = (a >> 16) & 0xf;
            cpu_ext_familyID = (a >> 20) & 0xff;

            cpu_model = cpu_model + (cpu_ext_modelID << 4);
            cpu_familyID = cpu_familyID + (cpu_ext_familyID << 4);

            vmx_init_dovmcall(1);
            setup_APIC_BASE(); //for ultimap
        }
        else
        {
            LogInfo("DBK: %s: Not an intel cpu", __FUNCTION__);
            if (r[1] == 0x68747541)
            {
                LogInfo("DBK: %s: This is an AMD", __FUNCTION__);
                vmx_init_dovmcall(0);
            }
        }
    }

    RtlInitUnicodeString(&temp, L"PsSuspendProcess");
    PsSuspendProcess = (PSSUSPENDPROCESS)MmGetSystemRoutineAddress(&temp);

    RtlInitUnicodeString(&temp, L"PsResumeProcess");
    PsResumeProcess = (PSSUSPENDPROCESS)MmGetSystemRoutineAddress(&temp);

    return STATUS_SUCCESS;
}


NTSTATUS DispatchCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    LogInfo("DBK: %s: Creating Dispatch", __FUNCTION__);
    if (IsDriverDisabled())
    {
        LogInfo("DBK: %s: Ignoring DispatchCreate request - driver is disabled", __FUNCTION__);
        Irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Irp->IoStatus.Status;
    }

    // Check for SeDebugPrivilege. (So only processes with admin rights can use it)
    LUID sedebugprivUID;
    sedebugprivUID.LowPart = SE_DEBUG_PRIVILEGE;
    sedebugprivUID.HighPart = 0;

    Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;

    if (SeSinglePrivilegeCheck(sedebugprivUID, UserMode))
    {
        Irp->IoStatus.Status = STATUS_SUCCESS;
#ifdef AMD64
#ifdef TOBESIGNED
        {
            NTSTATUS s = SecurityCheck();
            Irp->IoStatus.Status = s;
        }
        //	LogInfo("Returning %x (and %x)", Irp->IoStatus.Status, s);
#endif
#endif
    }
    else
    {
        LogInfo("DBK: %s: A process without SeDebugPrivilege tried to open the dbk driver", __FUNCTION__);
        Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
    }

    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}


NTSTATUS DispatchClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    LogInfo("DBK: %s: Closing Dispatch", __FUNCTION__);

    if (IsDriverDisabled())
    {
        LogInfo("DBK: %s: Ignoring DispatchClose request - driver is disabled", __FUNCTION__);
        Irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return Irp->IoStatus.Status;
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

void UnloadDriver(PDRIVER_OBJECT DriverObject)
{
    LogInfo("DBK: %s: Unloading the driver", __FUNCTION__);
    stopMonitoring();
    cleanupDBVM();

    if (!debugger_stopDebugging())
    {
        LogInfo("DBK: %s: Can not unload the driver because of debugger", __FUNCTION__);
        return;
    }

    debugger_shutdown();

    ultimap_disable();
    DisableUltimap2();
    UnregisterUltimapPMI();

    clean_APIC_BASE();

    NoExceptions_Cleanup();

    if (CreateProcessNotifyRoutineEnabled || ImageNotifyRoutineLoaded)
    {
        PVOID x;
        UNICODE_STRING temp;

        RtlInitUnicodeString(&temp, L"PsRemoveCreateThreadNotifyRoutine");
        PsRemoveCreateThreadNotifyRoutine2 = (PSRCTNR)MmGetSystemRoutineAddress(&temp);

        RtlInitUnicodeString(&temp, L"PsRemoveCreateThreadNotifyRoutine");
        PsRemoveLoadImageNotifyRoutine2 = (PSRLINR)MmGetSystemRoutineAddress(&temp);

        RtlInitUnicodeString(&temp, L"ObOpenObjectByName");
        x = MmGetSystemRoutineAddress(&temp);

        LogInfo("DBK: %s: ObOpenObjectByName=%p", __FUNCTION__, x);


        if ((PsRemoveCreateThreadNotifyRoutine2) && (PsRemoveLoadImageNotifyRoutine2))
        {
            LogInfo("DBK: %s: Stopping processwatch", __FUNCTION__);

            if (CreateProcessNotifyRoutineEnabled)
            {
                LogInfo("DBK: %s: Removing process watch", __FUNCTION__);
#if (NTDDI_VERSION >= NTDDI_VISTASP1)
                PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutineEx,TRUE);
#else
                PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);
#endif


                LogInfo("DBK: %s: Removing thread watch", __FUNCTION__);
                PsRemoveCreateThreadNotifyRoutine2(CreateThreadNotifyRoutine);
            }

            if (ImageNotifyRoutineLoaded)
                PsRemoveLoadImageNotifyRoutine2(LoadImageNotifyRoutine);
        }
        else return; //leave now!!!!!		
    }

    LogInfo("DBK: %s: Driver unloading", __FUNCTION__);
    IoDeleteDevice(DriverObject->DeviceObject);

    LogInfo("DBK: %s: Deleting symbolic link DeviceString=%S", __FUNCTION__, uszDeviceString.Buffer);
    NTSTATUS status = IoDeleteSymbolicLink(&uszDeviceString);
    if (!NT_SUCCESS(status))
    {
        LogWarn("DBK: %s: Failed to delete symbolic link: %x", __FUNCTION__, status);
    }
    ExFreePool(BufDeviceString);

    CleanProcessList();

    LogInfo("DBK: %s: Releasing resource list", __FUNCTION__);
    status = ExDeleteResourceLite(&ProcesslistR);
    if (!NT_SUCCESS(status))
    {
        LogWarn("DBK: %s: Failed delete process resource list: %x", __FUNCTION__, status);
    }
    RtlZeroMemory(&ProcesslistR, sizeof(ProcesslistR));

    if (DRMHandle)
    {
        LogInfo("DBK: %s: Unregistering DRM handle", __FUNCTION__);
        ObUnRegisterCallbacks(DRMHandle);
        DRMHandle = NULL;
    }

    LogInfo("DBK: %s: Driver unloaded, unregistering TraceProvider", __FUNCTION__);
    DBKTraceLoggingUnregister();
}
