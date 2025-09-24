#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include "logging.h"

#ifdef __cplusplus
extern "C" {
#endif

// Minimal remote thread creation helper
// Creates a user-mode thread in the given process using ZwCreateThreadEx under the hood
// Returns NTSTATUS and can optionally return a thread handle and the created ClientId
    NTSTATUS Inject_CreateRemoteThread(
        _In_ DWORD pid,
        _In_ PVOID startAddress,
        _In_opt_ PVOID parameter);

#ifdef __cplusplus
}
#endif
