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

    LogInfo("Loading BB");
    NTSTATUS bbStatus = BBInitDriver(DriverObject);
    if (!NT_SUCCESS(bbStatus))
    {
        LogError("Failed to load BB: 0x%08X", bbStatus);
        return bbStatus;
    }
    LogInfo("BB loaded successfully");

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

    LogInfo("Loading driver");
    if (RegistryPath)
    {
        LogInfo("Registry path = %S", RegistryPath->Buffer);

        UNICODE_STRING serviceName;
        if (ExtractServiceNameFromRegistryPath(RegistryPath, &serviceName))
        {
            LogInfo("Driver loaded for service @ %wZ, service name: %wZ", RegistryPath, &serviceName);
            UNICODE_STRING easvc;
            RtlInitUnicodeString(&easvc, L"EASVC73");
            BOOLEAN isCheatEngineService = RtlEqualUnicodeString(&serviceName, &easvc, TRUE);
            setIsEyeAurasService(!isCheatEngineService);

            LogInfo("Service mode: %s",
                    isEyeAurasService() ? "Generic (with PID monitoring)" : "Persistent (No PID monitoring)");

            if (isEyeAurasService())
            {
                initializeMonitoring(RegistryPath);
            }
        }
        else
        {
            LogInfo("Failed to extract service name from RegistryPath: %wZ", RegistryPath);
            return STATUS_UNSUCCESSFUL;
        }

        InitializeObjectAttributes(&oa, RegistryPath, OBJ_KERNEL_HANDLE, NULL, NULL);
        ntStatus = ZwOpenKey(&reg, KEY_QUERY_VALUE, &oa);
        if (ntStatus == STATUS_SUCCESS)
        {
            UNICODE_STRING A, B, C, D, P;
            PKEY_VALUE_PARTIAL_INFORMATION bufA, bufB, bufC, bufD, bufP;
            ULONG ActualSize;

            LogInfo("Opened the key");

            BufDriverString = ExAllocatePool(PagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + DEFAULT_BUFFER_SIZE);
            BufDriverStringFormat = ExAllocatePool(PagedPool, DEFAULT_BUFFER_SIZE);
            BufDeviceString = ExAllocatePool(PagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + DEFAULT_BUFFER_SIZE);
            BufDeviceStringFormat = ExAllocatePool(PagedPool, DEFAULT_BUFFER_SIZE);
            BufProcessEventString = ExAllocatePool(
                PagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + DEFAULT_BUFFER_SIZE);
            BufThreadEventString = ExAllocatePool(
                PagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + DEFAULT_BUFFER_SIZE);

            bufA = BufDriverString;
            bufB = BufDeviceString;
            bufC = BufProcessEventString;
            bufD = BufThreadEventString;

            RtlInitUnicodeString(&A, L"A");
            RtlInitUnicodeString(&B, L"B");
            RtlInitUnicodeString(&C, L"C");
            RtlInitUnicodeString(&D, L"D");

            if (isEyeAurasService())
            {
                RtlInitUnicodeString(&P, L"P");
            }

            if (ntStatus == STATUS_SUCCESS)
            {
                if (NT_SUCCESS(
                    ZwQueryValueKey(reg, &A, KeyValuePartialInformation, bufA, sizeof(KEY_VALUE_PARTIAL_INFORMATION) +
                        100, &ActualSize)))
                {
                    RtlInitUnicodeString(&uszDriverString, (PCWSTR)bufA->Data);
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
                    ZwQueryValueKey(reg, &B, KeyValuePartialInformation, bufB, sizeof(KEY_VALUE_PARTIAL_INFORMATION) +
                        100, &ActualSize)))
                {
                    RtlInitUnicodeString(&uszDeviceString, (PCWSTR)bufB->Data);
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
                    ZwQueryValueKey(reg, &C, KeyValuePartialInformation, bufC, sizeof(KEY_VALUE_PARTIAL_INFORMATION) +
                        100, &ActualSize)))
                {
                    RtlInitUnicodeString(&uszProcessEventString, (PCWSTR)bufC->Data);
                }
                else
                {
                    RtlInitUnicodeString(&uszProcessEventString, (PCWSTR)L"\\BaseNamedObjects\\DBKProcList60");
                }
            }
            if (ntStatus == STATUS_SUCCESS)
            {
                if (NT_SUCCESS(
                    ZwQueryValueKey(reg, &D, KeyValuePartialInformation, bufD, sizeof(KEY_VALUE_PARTIAL_INFORMATION) +
                        100, &ActualSize)))
                {
                    RtlInitUnicodeString(&uszThreadEventString, (PCWSTR)bufD->Data);
                }
                else
                {
                    RtlInitUnicodeString(&uszThreadEventString, (PCWSTR)L"\\BaseNamedObjects\\DBKThreadList60");
                }
            }

            if (ntStatus == STATUS_SUCCESS && isEyeAurasService())
            {
                bufP = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool(
                    PagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONGLONG));
                if (bufP)
                {
                    if (NT_SUCCESS(
                        ZwQueryValueKey(reg, &P, KeyValuePartialInformation, bufP, sizeof(KEY_VALUE_PARTIAL_INFORMATION)
                            + sizeof(ULONGLONG), &ActualSize)))
                    {
                        ULONGLONG pid64 = 0;
                        if (bufP->Type == REG_DWORD && bufP->DataLength >= sizeof(ULONG))
                        {
                            pid64 = *(ULONG*)bufP->Data;
                        }
                        else if (bufP->Type == REG_QWORD && bufP->DataLength >= sizeof(ULONGLONG))
                        {
                            pid64 = *(ULONGLONG*)bufP->Data;
                        }
                        else
                        {
                            LogInfo("Unsupported registry type for P: %u", bufP->Type);
                        }
                        setMonitoringPID((HANDLE)pid64);
                    }
                    else
                    {
                        LogInfo("Registry value 'P' not found or unreadable; monitoring disabled");
                    }
                    ExFreePool(bufP);
                }
                else
                {
                    LogInfo("Failed to allocate buffer for reading 'P'");
                }
            }

            LogInfo("DriverString=%S", uszDriverString.Buffer);
            LogInfo("DeviceString=%S", uszDeviceString.Buffer);
            LogInfo("ProcessEventString=%S", uszProcessEventString.Buffer);
            LogInfo("ThreadEventString=%S", uszThreadEventString.Buffer);

            if (ntStatus == STATUS_SUCCESS)
            {
                LogInfo("Read settings successfully");
            }
            else
            {
                ExFreePool(bufA);
                ExFreePool(bufB);
                ExFreePool(bufC);
                ExFreePool(bufD);

                LogInfo("Failed reading the value");
                ZwClose(reg);
                return STATUS_UNSUCCESSFUL;
            }
        }
        else
        {
            LogInfo("Failed opening the key");
            return STATUS_UNSUCCESSFUL;
        }
    }
    else
    {
        loadedbydbvm = TRUE;
    }

    ntStatus = STATUS_SUCCESS;

    if (!loadedbydbvm)
    {
        // Point uszDriverString at the driver name
#ifndef CETC


        // Create and initialize device object
        ntStatus = IoCreateDevice(DriverObject,
                                  0,
                                  &uszDriverString,
                                  FILE_DEVICE_UNKNOWN,
                                  0,
                                  FALSE,
                                  &pDeviceObject);

        if (ntStatus != STATUS_SUCCESS)
        {
            //LogInfo("IoCreateDevice failed");
            ExFreePool(BufDriverString);
            ExFreePool(BufDriverStringFormat);
            ExFreePool(BufDeviceString);
            ExFreePool(BufDeviceStringFormat);
            ExFreePool(BufProcessEventString);
            ExFreePool(BufThreadEventString);


            if (reg)
                ZwClose(reg);

            return ntStatus;
        }

        // Point uszDeviceString at the device name

        // Create symbolic link to the user-visible name
        LogInfo("Creating symbolic link, deviceString: %S, driverString: %S", uszDeviceString.Buffer,
                uszDriverString.Buffer);
        ntStatus = IoCreateSymbolicLink(&uszDeviceString, &uszDriverString);

        if (ntStatus != STATUS_SUCCESS)
        {
            LogInfo("IoCreateSymbolicLink failed: %x", ntStatus);
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

#endif
    }

    //when loaded by dbvm driver object is 'valid' so store the function addresses


    LogInfo("DriverObject=%p", DriverObject);

    // Load structure to point to IRP handlers...
    DriverObject->DriverUnload = UnloadDriver;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;

    if (loadedbydbvm)
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)DispatchIoctlDBVM;
    else
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    startProcessMonitoring();

    //Processlist init
#ifndef CETC
    ProcessEventCount = 0;
    ExInitializeResourceLite(&ProcesslistR);
#endif

    CreateProcessNotifyRoutineEnabled = FALSE;

    //threadlist init
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


#ifdef CETC
    LogInfo("Going to initialice CETC");
    InitializeCETC();
#endif


    //hideme(DriverObject); //ok, for those that see this, enabling this WILL fuck up try except routines, even in usermode you'll get a blue sreen

    LogInfo("Initializing debugger");
    debugger_initialize();


    // Return success (don't do the devicestring, I need it for unload)
    LogInfo("Cleaning up initialization buffers");
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
        LogInfo("cpuid.0: r[1]=%x", r[1]);
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
            LogInfo("Not an intel cpu");
            if (r[1] == 0x68747541)
            {
                LogInfo("This is an AMD");
                vmx_init_dovmcall(0);
            }
        }
    }

#ifdef DEBUG1
    {
        APIC y;

        DebugStackState x;
        LogInfo("offset of LBR_Count=%d", (UINT_PTR)&x.LBR_Count - (UINT_PTR)&x);


        LogInfo("Testing forEachCpu(...)");
        forEachCpu(TestDPC, NULL, NULL, NULL, NULL);

        LogInfo("Testing forEachCpuAsync(...)");
        forEachCpuAsync(TestDPC, NULL, NULL, NULL, NULL);

        LogInfo("Testing forEachCpuPassive(...)");
        forEachCpuPassive(TestPassive, 0);

        LogInfo("LVT_Performance_Monitor=%x", (UINT_PTR)&y.LVT_Performance_Monitor - (UINT_PTR)&y);
    }
#endif

#ifdef DEBUG2
    LogInfo("No exceptions test:");
    if (NoExceptions_Enter())
    {
        int o = 45678;
        int x = 0, r = 0;
        //r=NoExceptions_CopyMemory(&x, &o, sizeof(x));

        r = NoExceptions_CopyMemory(&x, (PVOID)0, sizeof(x));

        LogInfo("o=%d x=%d r=%d", o, x, r);


        LogInfo("Leaving NoExceptions mode");
        NoExceptions_Leave();
    }
#endif


    RtlInitUnicodeString(&temp, L"PsSuspendProcess");
    PsSuspendProcess = (PSSUSPENDPROCESS)MmGetSystemRoutineAddress(&temp);

    RtlInitUnicodeString(&temp, L"PsResumeProcess");
    PsResumeProcess = (PSSUSPENDPROCESS)MmGetSystemRoutineAddress(&temp);


    return STATUS_SUCCESS;
}


NTSTATUS DispatchCreate(IN PDEVICE_OBJECT DeviceObject,
                        IN PIRP Irp)
{
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
        LogInfo("A process without SeDebugPrivilege tried to open the dbk driver");
        Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
    }

    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}


NTSTATUS DispatchClose(IN PDEVICE_OBJECT DeviceObject,
                       IN PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

void UnloadDriver(PDRIVER_OBJECT DriverObject)
{
    stopMonitoring();
    cleanupDBVM();

    if (!debugger_stopDebugging())
    {
        LogInfo("Can not unload the driver because of debugger");
        return; //
    }

    debugger_shutdown();

    ultimap_disable();
    DisableUltimap2();
    UnregisterUltimapPMI();

    clean_APIC_BASE();

    NoExceptions_Cleanup();

    if ((CreateProcessNotifyRoutineEnabled) || (ImageNotifyRoutineLoaded))
    {
        PVOID x;
        UNICODE_STRING temp;

        RtlInitUnicodeString(&temp, L"PsRemoveCreateThreadNotifyRoutine");
        PsRemoveCreateThreadNotifyRoutine2 = (PSRCTNR)MmGetSystemRoutineAddress(&temp);

        RtlInitUnicodeString(&temp, L"PsRemoveCreateThreadNotifyRoutine");
        PsRemoveLoadImageNotifyRoutine2 = (PSRLINR)MmGetSystemRoutineAddress(&temp);

        RtlInitUnicodeString(&temp, L"ObOpenObjectByName");
        x = MmGetSystemRoutineAddress(&temp);

        LogInfo("ObOpenObjectByName=%p", x);


        if ((PsRemoveCreateThreadNotifyRoutine2) && (PsRemoveLoadImageNotifyRoutine2))
        {
            LogInfo("Stopping processwatch");

            if (CreateProcessNotifyRoutineEnabled)
            {
                LogInfo("Removing process watch");
#if (NTDDI_VERSION >= NTDDI_VISTASP1)
                PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutineEx,TRUE);
#else
                PsSetCreateProcessNotifyRoutine(CreateProcessNotifyRoutine, TRUE);
#endif


                LogInfo("Removing thread watch");
                PsRemoveCreateThreadNotifyRoutine2(CreateThreadNotifyRoutine);
            }

            if (ImageNotifyRoutineLoaded)
                PsRemoveLoadImageNotifyRoutine2(LoadImageNotifyRoutine);
        }
        else return; //leave now!!!!!		
    }


    LogInfo("Driver unloading");

    IoDeleteDevice(DriverObject->DeviceObject);

    // Unregister TraceLogging provider on unload
    DBKTraceLoggingUnregister();

#ifdef CETC
#ifndef CETC_RELEASE
    UnloadCETC(); //not possible in the final build
#endif
#endif

#ifndef CETC_RELEASE
    LogInfo("DeviceString=%S", uszDeviceString.Buffer);
    {
        NTSTATUS r = IoDeleteSymbolicLink(&uszDeviceString);
        LogInfo("IoDeleteSymbolicLink: %x", r);
    }
    ExFreePool(BufDeviceString);
#endif

    CleanProcessList();

    ExDeleteResourceLite(&ProcesslistR);

    RtlZeroMemory(&ProcesslistR, sizeof(ProcesslistR));

#if (NTDDI_VERSION >= NTDDI_VISTA)
    if (DRMHandle)
    {
        LogInfo("Unregistering DRM handle");
        ObUnRegisterCallbacks(DRMHandle);
        DRMHandle = NULL;
    }
#endif
}
