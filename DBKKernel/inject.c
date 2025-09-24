#include <ntifs.h>
#include "inject.h"

#include "blackbone/Loader.h"
#include "blackbone/Utils.h"

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
    _In_opt_ PVOID parameter)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        LogInfo("[INJECT-CRT] Must be at a passive level");
        return STATUS_INVALID_DEVICE_STATE;
    }

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PEPROCESS pProcess = NULL; 

    status = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
    if (NT_SUCCESS(status))
    {
        KAPC_STATE apc; // APC state structure for attaching to the target process.

        KeStackAttachProcess(pProcess, &apc);

        // Process in signaled state, abort any operations
        if (BBCheckProcessTermination(PsGetCurrentProcess()))
        {
            LogInfo("[INJECT-CRT] Process %u is terminating. Abort", pid);
            if (pProcess)
            {
                ObDereferenceObject(pProcess);
            }

            return STATUS_PROCESS_IS_TERMINATING;
        }

        NTSTATUS threadStatus = STATUS_SUCCESS; 
        status = BBExecuteInNewThread(startAddress, parameter, 0, FALSE, &threadStatus);
        
        // Detach from the target process's address space.
        KeUnstackDetachProcess(&apc);
    }
    else
    {
        LogInfo("[INJECT-CRT] PsLookupProcessByProcessId failed with status 0x%X", status);
    }

    // Dereference the EPROCESS object to release the reference.
    if (pProcess)
    {
        ObDereferenceObject(pProcess);
    }

    return status;
}
