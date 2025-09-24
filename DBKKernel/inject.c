#include <ntifs.h>
#include "inject.h"

// Dynamically resolve ZwCreateThreadEx to support WDK/OS variants where the
// prototype may not be available at compile-time or the export may be absent.
typedef NTSTATUS (*PFN_ZwCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList);

static PFN_ZwCreateThreadEx g_pZwCreateThreadEx = NULL;

#ifndef THREAD_CREATE_FLAGS_CREATE_SUSPENDED
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001UL
#endif

#define PROCESS_TERMINATE                  (0x0001)
#define PROCESS_CREATE_THREAD              (0x0002)
#define PROCESS_SET_SESSIONID              (0x0004)
#define PROCESS_VM_OPERATION               (0x0008)
#define PROCESS_VM_READ                    (0x0010)
#define PROCESS_VM_WRITE                   (0x0020)
#define PROCESS_DUP_HANDLE                 (0x0040)
#define PROCESS_CREATE_PROCESS             (0x0080)
#define PROCESS_SET_QUOTA                  (0x0100)
#define PROCESS_SET_INFORMATION            (0x0200)
#define PROCESS_QUERY_INFORMATION          (0x0400)
#define PROCESS_SUSPEND_RESUME             (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)

static NTSTATUS ResolveZwCreateThreadEx()
{
    if (g_pZwCreateThreadEx)
        return STATUS_SUCCESS;

    
    static const UNICODE_STRING name = RTL_CONSTANT_STRING(L"ZwCreateThreadEx");

    g_pZwCreateThreadEx = (PFN_ZwCreateThreadEx)MmGetSystemRoutineAddress((PUNICODE_STRING)&name);

    if (!g_pZwCreateThreadEx)
        return STATUS_PROCEDURE_NOT_FOUND;

    return STATUS_SUCCESS;
}

static NTSTATUS CheckUserStartAddrExecutable(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID Start)
{
    if (Start == NULL || Start > MmHighestUserAddress)
        return STATUS_INVALID_ADDRESS;

    MEMORY_BASIC_INFORMATION mbi = {0};
    SIZE_T out = 0;
    NTSTATUS st = ZwQueryVirtualMemory(ProcessHandle, Start,
                                       MemoryBasicInformation, &mbi, sizeof(mbi), &out);
    if (!NT_SUCCESS(st)) return st;

    if (mbi.State != MEM_COMMIT) return STATUS_INVALID_ADDRESS;
    if (mbi.Protect & PAGE_NOACCESS) return STATUS_ACCESS_DENIED;

    const ULONG p = mbi.Protect & 0xFF;
    const BOOLEAN exec =
        p == PAGE_EXECUTE ||
        p == PAGE_EXECUTE_READ ||
        p == PAGE_EXECUTE_READWRITE ||
        p == PAGE_EXECUTE_WRITECOPY;

    return exec ? STATUS_SUCCESS : STATUS_PROCEDURE_NOT_FOUND; // “not executable”
}

NTSTATUS Inject_CreateRemoteThread(
    _In_ DWORD pid,
    _In_ PVOID startAddress,
    _In_opt_ PVOID parameter,
    _In_ BOOLEAN createSuspended,
    _Out_opt_ PHANDLE outThreadHandle,
    _Out_opt_ PCLIENT_ID outClientId)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    CLIENT_ID cid = {0};

    PEPROCESS selectedprocess;
		
    LogTrace("[INJECT-CRT] Getting PEPROCESS for %d", pid);
    if (!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)(UINT_PTR)pid,&selectedprocess)))
    {
        LogWarn("[INJECT-CRT] Could not get PEPROCESS for %d", pid);
        return FALSE;
    }
    LogTrace("[INJECT-CRT] Retrieved peprocess"); 

    const KIRQL irql = KeGetCurrentIrql();

    LogTrace("[INJECT-CRT] Enter: EPROCESS=%p Start=%p Param=%p Susp=%d IRQL=%u",
             selectedprocess, startAddress, parameter, (int)createSuspended, (unsigned)irql);

    if (outThreadHandle)
    {
        *outThreadHandle = NULL;
    }
    if (outClientId)
    {
        RtlZeroMemory(outClientId, sizeof(CLIENT_ID));
    }

    if (!selectedprocess || !startAddress)
    {
        LogWarn("[INJECT-CRT] Invalid parameter: TP=%p Start=%p", selectedprocess, startAddress);
        return STATUS_INVALID_PARAMETER;
    }

    if (irql != PASSIVE_LEVEL)
    {
        LogWarn("[INJECT-CRT] Must be called at PASSIVE_LEVEL (irql=%u)", (unsigned)irql);
        return STATUS_INVALID_DEVICE_STATE;
    }

    // Open a kernel handle for the already referenced EPROCESS
    status = ObOpenObjectByPointer(selectedprocess,
                                   OBJ_KERNEL_HANDLE,
                                   NULL,
                                   PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION |
                                   PROCESS_VM_WRITE | PROCESS_VM_READ,
                                   *PsProcessType,
                                   KernelMode,
                                   &hProcess);
    LogTrace("[INJECT-CRT] ObOpenObjectByPointer -> 0x%08X, hProcess=%p", status, hProcess);
    if (!NT_SUCCESS(status))
    {
        LogError("[INJECT-CRT] Failed to open process handle: 0x%08X", status);
        return status;
    }

    __try
    {
        status = CheckUserStartAddrExecutable(hProcess, startAddress);
        if (!NT_SUCCESS(status)) {
            LogError("[INJECT-CRT] Start %p not executable in target: 0x%08X", startAddress, status);
            __leave;
        }
        
        ULONG createFlags = createSuspended ? THREAD_CREATE_FLAGS_CREATE_SUSPENDED : 0;

        status = ResolveZwCreateThreadEx();
        if (!NT_SUCCESS(status))
        {
            LogError("[INJECT-CRT] ZwCreateThreadEx not available (status=0x%08X)", status);
            __leave;
        }

        LogTrace("[INJECT-CRT] ZwCreateThreadEx(Process=%p, Start=%p, Param=%p, Flags=0x%X)",
                 hProcess, startAddress, parameter, createFlags);

        status = g_pZwCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                                     startAddress, parameter, createFlags,
                                     0, 0, 0, NULL);

        LogTrace("[INJECT-CRT] ZwCreateThreadEx -> 0x%08X, hThread=%p", status, hThread);
        if (!NT_SUCCESS(status))
        {
            __leave;
        }

        // Optionally return thread handle to caller
        if (outThreadHandle)
        {
            *outThreadHandle = hThread; // transfer ownership to caller
        }

        // Fill ClientId if requested
        if (outClientId)
        {
            PETHREAD threadObj = NULL;
            NTSTATUS st2 = ObReferenceObjectByHandle(hThread, THREAD_QUERY_LIMITED_INFORMATION, *PsThreadType,
                                                     KernelMode, (PVOID*)&threadObj, NULL);
            if (NT_SUCCESS(st2))
            {
                HANDLE tpid = PsGetThreadProcessId(threadObj);
                HANDLE tid = PsGetThreadId(threadObj);
                cid.UniqueProcess = tpid;
                cid.UniqueThread = tid;
                *outClientId = cid;
                ObDereferenceObject(threadObj);
                LogTrace("[INJECT-CRT] ClientId: PID=%p TID=%p", tpid, tid);
            }
            else
            {
                LogWarn("[INJECT-CRT] ObReferenceObjectByHandle(thread) failed: 0x%08X", st2);
            }
        }
    }
    __finally
    {
        if (!NT_SUCCESS(status))
        {
            if (hThread)
            {
                ZwClose(hThread);
                hThread = NULL;
            }
        }

        if (hProcess)
        {
            ZwClose(hProcess);
            hProcess = NULL;
        }
    }

    LogTrace("[INJECT-CRT] Exit: status=0x%08X", status);
    return status;
}
