#pragma warning( disable: 4103)
#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <evntrace.h>
#include <TraceLoggingProvider.h>
#include <ntstrsafe.h>
#include <stdarg.h>
#include <excpt.h>

TRACELOGGING_DECLARE_PROVIDER(g_DBKProvider);

NTSTATUS DBKTraceLoggingRegister(void);
VOID DBKTraceLoggingUnregister(void);

#ifdef RELEASE
    #define LogInfo(...)
    #define LogWarn(...)
    #define LogError(...)
    #define LogTrace(...)
#else
    // Fallback definitions if TRACE_LEVEL_* are not provided by headers
    #ifndef TRACE_LEVEL_CRITICAL
    #define TRACE_LEVEL_CRITICAL   1
    #define TRACE_LEVEL_ERROR      2
    #define TRACE_LEVEL_WARNING    3
    #define TRACE_LEVEL_INFORMATION 4
    #define TRACE_LEVEL_VERBOSE    5
    #endif

    _IRQL_requires_max_(DISPATCH_LEVEL)
    VOID DBKTraceLog(_In_ UCHAR level, _In_z_ _Printf_format_string_ PCSTR fmt, ...);

    #define LogInfo(...)  DBKTraceLog(TRACE_LEVEL_INFORMATION, __VA_ARGS__)
    #define LogWarn(...)  DBKTraceLog(TRACE_LEVEL_WARNING, __VA_ARGS__)
    #define LogError(...) DBKTraceLog(TRACE_LEVEL_ERROR, __VA_ARGS__)
    #define LogTrace(...) DBKTraceLog(TRACE_LEVEL_VERBOSE, __VA_ARGS__)
#endif

static __inline NTSTATUS DBKTraceLoggingRegister(void)
{
    NTSTATUS status = TraceLoggingRegister(g_DBKProvider);
    return status;
}

static __inline VOID DBKTraceLoggingUnregister(void)
{
    TraceLoggingUnregister(g_DBKProvider);
}

static __inline VOID DBKTraceLog(_In_ UCHAR level, _In_z_ _Printf_format_string_ PCSTR fmt, ...)
{
#ifndef RELEASE
    // Check if provider is enabled at any level/keyword to avoid formatting cost
    if (!TraceLoggingProviderEnabled(g_DBKProvider, 0, 0))
    {
        return;
    }
	if (!TraceLoggingProviderEnabled(g_DBKProvider, 0 /* keywords */, level))
	{
		return;
	}

	// Format message into a temporary buffer
    CHAR buffer[512];
    buffer[0] = '\0';

    va_list ap;
    va_start(ap, fmt);
    RtlStringCbVPrintfA(buffer, sizeof(buffer), fmt, ap);
    va_end(ap);

    // Emit with a compile-time constant TraceLoggingLevel to satisfy SDK requirements
    switch (level)
    {
    case TRACE_LEVEL_CRITICAL:
        TraceLoggingWrite(g_DBKProvider, "LogLine", TraceLoggingLevel(TRACE_LEVEL_CRITICAL), TraceLoggingString(buffer, "Message"));
        break;
    case TRACE_LEVEL_ERROR:
        TraceLoggingWrite(g_DBKProvider, "LogLine", TraceLoggingLevel(TRACE_LEVEL_ERROR), TraceLoggingString(buffer, "Message"));
        break;
    case TRACE_LEVEL_WARNING:
        TraceLoggingWrite(g_DBKProvider, "LogLine", TraceLoggingLevel(TRACE_LEVEL_WARNING), TraceLoggingString(buffer, "Message"));
        break;
    case TRACE_LEVEL_INFORMATION:
        TraceLoggingWrite(g_DBKProvider, "LogLine", TraceLoggingLevel(TRACE_LEVEL_INFORMATION), TraceLoggingString(buffer, "Message"));
        break;
    case TRACE_LEVEL_VERBOSE:
    default:
        TraceLoggingWrite(g_DBKProvider, "LogLine", TraceLoggingLevel(TRACE_LEVEL_VERBOSE), TraceLoggingString(buffer, "Message"));
        break;
    }
#else
    UNREFERENCED_PARAMETER(level);
    UNREFERENCED_PARAMETER(fmt);
#endif
}

static LONG WpmSehLogFilter(_In_ EXCEPTION_POINTERS* ep)
{
    const EXCEPTION_RECORD* er = ep ? ep->ExceptionRecord : NULL;
    const CONTEXT*          cx = ep ? ep->ContextRecord   : NULL;

    ULONG  code  = er ? er->ExceptionCode : 0;
    PVOID  addr  = er ? er->ExceptionAddress : NULL;
    ULONG  flags = er ? er->ExceptionFlags : 0;
    ULONG  numOfParams = er ? er->NumberParameters : 0;

    if (numOfParams > EXCEPTION_MAXIMUM_PARAMETERS)
    {
        numOfParams = EXCEPTION_MAXIMUM_PARAMETERS;
    }

    ULONG_PTR pid = (ULONG_PTR)PsGetCurrentProcessId();
    ULONG_PTR tid = (ULONG_PTR)PsGetCurrentThreadId();
    KIRQL irql = KeGetCurrentIrql();

    ULONG cpuNumber = KeGetCurrentProcessorNumber();

#if defined(_M_AMD64)
    ULONGLONG cr2 = __readcr2(); // faulting VA for #PF/AV
    ULONGLONG rip = cx ? cx->Rip : 0, rsp = cx ? cx->Rsp : 0, rfl = cx ? cx->EFlags : 0;
#else
    ULONGLONG cr2 = 0, rip = 0, rsp = 0, rfl = 0;
#endif

    ULONGLONG addr64 = (ULONGLONG)(ULONG_PTR)addr;
    ULONGLONG pid64  = (ULONGLONG)(ULONG_PTR)pid;
    ULONGLONG tid64  = (ULONGLONG)(ULONG_PTR)tid;

    // Prepare hex strings to ensure consumers display hex, not negative decimal
    CHAR codeHexStr[11];    // 0x + 8 digits + NUL
    CHAR addrHexStr[19];    // 0x + 16 digits + NUL
    CHAR flagsHexStr[11];
    CHAR cr2HexStr[19];
    CHAR ripHexStr[19];
    CHAR rspHexStr[19];
    CHAR rflHexStr[19];
    CHAR pidHexStr[19];
    CHAR tidHexStr[19];

    RtlStringCbPrintfA(codeHexStr, sizeof(codeHexStr), "0x%08X", code);
    RtlStringCbPrintfA(addrHexStr, sizeof(addrHexStr), "0x%016I64X", addr64);
    RtlStringCbPrintfA(flagsHexStr, sizeof(flagsHexStr), "0x%08X", flags);
    RtlStringCbPrintfA(cr2HexStr, sizeof(cr2HexStr), "0x%016I64X", cr2);
    RtlStringCbPrintfA(ripHexStr, sizeof(ripHexStr), "0x%016I64X", rip);
    RtlStringCbPrintfA(rspHexStr, sizeof(rspHexStr), "0x%016I64X", rsp);
    RtlStringCbPrintfA(rflHexStr, sizeof(rflHexStr), "0x%016I64X", rfl);
    RtlStringCbPrintfA(pidHexStr, sizeof(pidHexStr), "0x%016I64X", pid64);
    RtlStringCbPrintfA(tidHexStr, sizeof(tidHexStr), "0x%016I64X", tid64);

    // Base event with rich context (both hex and decimal where it makes sense)
    TraceLoggingWrite(
        g_DBKProvider,
        "SEH",
        TraceLoggingLevel(TRACE_LEVEL_CRITICAL),
        TraceLoggingString(codeHexStr, "CodeHex"),
        TraceLoggingUInt32(code,    "CodeDec"),
        TraceLoggingPointer(addr,   "ExceptAddrPtr"),
        TraceLoggingString(addrHexStr, "ExceptAddrHex"),
        TraceLoggingString(flagsHexStr, "FlagsHex"),
        TraceLoggingUInt32(flags,    "FlagsDec"),
        TraceLoggingUInt8((UCHAR)numOfParams, "NumParams"),
        TraceLoggingUInt32(cpuNumber, "CpuNumber"),
        TraceLoggingUInt8(irql,      "IRQL"),
        TraceLoggingString(cr2HexStr,   "CR2"),
        TraceLoggingString(ripHexStr,   "RIP"),
        TraceLoggingString(rspHexStr,   "RSP"),
        TraceLoggingString(rflHexStr,   "RFLAGS"),
        TraceLoggingString(pidHexStr, "PIDHex"),
        TraceLoggingUInt64(pid64,    "PIDDec"),
        TraceLoggingString(tidHexStr, "TIDHex"),
        TraceLoggingUInt64(tid64,    "TIDDec"));

    // Log each exception parameter as a separate event with index and both hex and decimal forms
    for (ULONG i = 0; i < numOfParams; ++i)
    {
        ULONGLONG val64 = er ? (ULONGLONG)(ULONG_PTR)er->ExceptionInformation[i] : 0;
        CHAR valHexStr[19];
        RtlStringCbPrintfA(valHexStr, sizeof(valHexStr), "0x%016I64X", val64);
        TraceLoggingWrite(
            g_DBKProvider,
            "SEHParam",
            TraceLoggingLevel(TRACE_LEVEL_CRITICAL),
            TraceLoggingUInt8((UCHAR)i,        "Index"),
            TraceLoggingString(valHexStr,       "ValueHex"),
            TraceLoggingUInt64(val64,          "ValueDec"));
    }

    return EXCEPTION_EXECUTE_HANDLER;
}