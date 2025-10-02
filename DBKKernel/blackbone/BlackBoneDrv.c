#include "BlackBoneDrv.h"
#include "Remap.h"
#include "Loader.h"
#include "Utils.h"
#include <Ntstrsafe.h>
#include "Hooks.h"

// OS Dependant data
DYNAMIC_DATA dynData;
BOOLEAN g_ntQueryHookInstalled;

NTSTATUS BBInitDynamicData(IN OUT PDYNAMIC_DATA pData);
NTSTATUS BBGetBuildNO(OUT PULONG pBuildNo);
NTSTATUS BBScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound);
VOID BBUnload(IN PDRIVER_OBJECT DriverObject);
NTSTATUS BbInstallNtQueryDirectoryFileHook(); // Declare the function

#pragma alloc_text(INIT, BBInitDynamicData)
#pragma alloc_text(INIT, BBGetBuildNO)
#pragma alloc_text(INIT, BBScanSection)

NTSTATUS BBInitDriver(IN PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status = STATUS_SUCCESS;
    InitializeDebuggerBlock();
    status = BBInitDynamicData(&dynData);
    if (!NT_SUCCESS(status))
    {
        if (status == STATUS_NOT_SUPPORTED)
        {
            DPRINT("BlackBone: %s: Unsupported OS version. Aborting", __FUNCTION__);
        } else
        {
            DPRINT("BlackBone: %s: Failed to initialize OS data. Aborting", __FUNCTION__);
        }
        return status;
    }
    BBPrintDynamicData(&dynData);

    status = BBInitLdrData((PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection);
    if (!NT_SUCCESS(status))
    {
        DPRINT("BlackBone: %s: Failed to initialize Ldr data", __FUNCTION__);
        return status;
    }
    return status;
}

/// <summary>
/// Find pattern in kernel PE section
/// </summary>
/// <param name="section">Section name</param>
/// <param name="pattern">Pattern data</param>
/// <param name="wildcard">Pattern wildcard symbol</param>
/// <param name="len">Pattern length</param>
/// <param name="ppFound">Found address</param>
/// <returns>Status code</returns>
NTSTATUS BBScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound)
{
    ASSERT(ppFound != NULL);
    if (ppFound == NULL)
        return STATUS_INVALID_PARAMETER;

    PVOID base = GetKernelBase(NULL);
    if (!base)
        return STATUS_NOT_FOUND;

    PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
    if (!pHdr)
        return STATUS_INVALID_IMAGE_FORMAT;

    PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
    for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections;
         pSection++)
    {
        ANSI_STRING s1, s2;
        RtlInitAnsiString(&s1, section);
        RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
        if (RtlCompareString(&s1, &s2, TRUE) == 0)
        {
            PVOID ptr = NULL;
            NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress,
                                              pSection->Misc.VirtualSize, &ptr);
            if (NT_SUCCESS(status))
                *(PULONG)ppFound = (ULONG)((PUCHAR)ptr - (PUCHAR)base);

            return status;
        }
    }

    return STATUS_NOT_FOUND;
}

/// <summary>
/// Get kernel build number
/// </summary>
/// <param name="pBuildNO">Build number.</param>
/// <returns>Status code</returns>
NTSTATUS BBGetBuildNO(OUT PULONG pBuildNo)
{
    ASSERT(pBuildNo != NULL);
    if (pBuildNo == NULL)
        return STATUS_INVALID_PARAMETER;

    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING strRegKey = RTL_CONSTANT_STRING(
        L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion");
    UNICODE_STRING strRegValue = RTL_CONSTANT_STRING(L"BuildLabEx");
    UNICODE_STRING strRegValue10 = RTL_CONSTANT_STRING(L"UBR");
    UNICODE_STRING strVerVal = {0};
    HANDLE hKey = NULL;
    OBJECT_ATTRIBUTES keyAttr = {0};

    InitializeObjectAttributes(&keyAttr, &strRegKey, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenKey(&hKey, KEY_READ, &keyAttr);
    if (NT_SUCCESS(status))
    {
        PKEY_VALUE_FULL_INFORMATION pValueInfo = ExAllocatePool2(POOL_FLAG_PAGED, PAGE_SIZE, BB_POOL_TAG);
        ULONG bytes = 0;

        if (pValueInfo)
        {
            // Try query UBR value
            status = ZwQueryValueKey(hKey, &strRegValue10, KeyValueFullInformation, pValueInfo, PAGE_SIZE, &bytes);
            if (NT_SUCCESS(status))
            {
                *pBuildNo = *(PULONG)((PUCHAR)pValueInfo + pValueInfo->DataOffset);
                goto skip1;
            }

            status = ZwQueryValueKey(hKey, &strRegValue, KeyValueFullInformation, pValueInfo, PAGE_SIZE, &bytes);
            if (NT_SUCCESS(status))
            {
                PWCHAR pData = (PWCHAR)((PUCHAR)pValueInfo->Name + pValueInfo->NameLength);
                for (ULONG i = 0; i < pValueInfo->DataLength; i++)
                {
                    if (pData[i] == L'.')
                    {
                        for (ULONG j = i + 1; j < pValueInfo->DataLength; j++)
                        {
                            if (pData[j] == L'.')
                            {
                                strVerVal.Buffer = &pData[i] + 1;
                                strVerVal.Length = strVerVal.MaximumLength = (USHORT)((j - i) * sizeof(WCHAR));
                                status = RtlUnicodeStringToInteger(&strVerVal, 10, pBuildNo);

                                goto skip1;
                            }
                        }
                    }
                }

            skip1:;
            }

            ExFreePoolWithTag(pValueInfo, BB_POOL_TAG);
        }
        else
            status = STATUS_NO_MEMORY;

        ZwClose(hKey);
    }
    else
        DPRINT("BlackBone: %s: ZwOpenKey failed with status 0x%X", __FUNCTION__, status);

    return status;
}

/// <summary>
/// Initialize dynamic data.
/// </summary>
/// <param name="pData">Data to initialize</param>
/// <returns>Status code</returns>
NTSTATUS BBInitDynamicData(IN OUT PDYNAMIC_DATA pData)
{
    NTSTATUS status = STATUS_SUCCESS;
    RTL_OSVERSIONINFOEXW verInfo = {0};

    DPRINT("BlackBone: Initializing OS-specific data");
    if (pData == NULL)
    {
        return STATUS_INVALID_ADDRESS;
    }

    NTSTATUS syscallsStatus = InitializeNtSyscalls();
    if (!NT_SUCCESS(syscallsStatus))
    {
        DPRINT("BlackBone: InitializeNtSyscalls failed with status 0x%X", syscallsStatus);
        return syscallsStatus;
    }

    RtlZeroMemory(pData, sizeof(DYNAMIC_DATA));
    pData->DYN_PDE_BASE = PDE_BASE;
    pData->DYN_PTE_BASE = PTE_BASE;

    verInfo.dwOSVersionInfoSize = sizeof(verInfo);
    status = RtlGetVersion((PRTL_OSVERSIONINFOW)&verInfo);

    if (status == STATUS_SUCCESS)
    {
        ULONG ver_short = (verInfo.dwMajorVersion << 8) | (verInfo.dwMinorVersion << 4) | verInfo.wServicePackMajor;
        pData->ver = (WinVer)ver_short;

        // Get kernel build number
        status = BBGetBuildNO(&pData->buildNo);

        // Validate current driver version
        pData->correctBuild = TRUE;
#if defined(_WIN7_)
        if (ver_short != WINVER_7 && ver_short != WINVER_7_SP1)
            return STATUS_NOT_SUPPORTED;
#elif defined(_WIN8_)
        if (ver_short != WINVER_8)
            return STATUS_NOT_SUPPORTED;
#elif defined (_WIN81_)
        if (ver_short != WINVER_81)
            return STATUS_NOT_SUPPORTED;
#elif defined (_WIN10_)
        if (ver_short < WINVER_10 || WINVER_10_24H2 < ver_short)
            return STATUS_NOT_SUPPORTED;
#endif

        DPRINT(
            "BlackBone: OS version %d.%d.%d.%d.%d - 0x%x",
            verInfo.dwMajorVersion,
            verInfo.dwMinorVersion,
            verInfo.dwBuildNumber,
            verInfo.wServicePackMajor,
            pData->buildNo,
            ver_short
        );

        switch (ver_short)
        {
        // Windows 7
        // Windows 7 SP1
        case WINVER_7:
        case WINVER_7_SP1:
            pData->KExecOpt = 0x0D2;
            pData->Protection = 0x43C; // Bitfield, bit index - 0xB
            pData->ObjectTable = 0x200;
            pData->VadRoot = 0x448;
            pData->NtProtectIndex = 0x04D;
            pData->NtCreateThdExIndex = 0x0A5;
            pData->NtTermThdIndex = 0x50;
            pData->PrevMode = 0x1F6;
            pData->ExitStatus = 0x380;
            pData->MiAllocPage = (ver_short == WINVER_7_SP1) ? 0 : 0;
            if (ver_short == WINVER_7_SP1)
            {
                if (NT_SUCCESS(
                    BBScanSection("PAGE", (PCUCHAR)"\x48\x8D\x56\x20\x48\x8B\x42\x08", 0xCC, 8, (PVOID)&pData->
                        ExRemoveTable)))
                    pData->ExRemoveTable -= 0x36;
            }
            else
                pData->ExRemoveTable = 0x32D404;
            break;

        // Windows 8
        case WINVER_8:
            pData->KExecOpt = 0x1B7;
            pData->Protection = 0x648;
            pData->ObjectTable = 0x408;
            pData->VadRoot = 0x590;
            pData->NtProtectIndex = 0x04E;
            pData->NtCreateThdExIndex = 0x0AF;
            pData->NtTermThdIndex = 0x51;
            pData->PrevMode = 0x232;
            pData->ExitStatus = 0x450;
            pData->MiAllocPage = 0x3AF374;
            pData->ExRemoveTable = 0x487518;
            break;

        // Windows 8.1
        case WINVER_81:
            pData->KExecOpt = 0x1B7;
            pData->Protection = 0x67A;
            pData->EProcessFlags2 = 0x2F8;
            pData->ObjectTable = 0x408;
            pData->VadRoot = 0x5D8;
            pData->NtCreateThdExIndex = 0xB0;
            pData->NtTermThdIndex = 0x52;
            pData->PrevMode = 0x232;
            pData->ExitStatus = 0x6D8;
            pData->MiAllocPage = 0;
            pData->ExRemoveTable = 0x432A88; // 0x38E320;
            if (NT_SUCCESS(
                BBScanSection("PAGE", (PCUCHAR)"\x48\x8D\x7D\x18\x48\x8B", 0xCC, 6, (PVOID)&pData->ExRemoveTable)))
                pData->ExRemoveTable -= 0x5E;
            break;

        // Windows 10, build 16299/15063/14393/10586
        case WINVER_10:
            if (verInfo.dwBuildNumber == 10586)
            {
                pData->KExecOpt = 0x1BF;
                pData->Protection = 0x6B2;
                pData->EProcessFlags2 = 0x300;
                pData->ObjectTable = 0x418;
                pData->VadRoot = 0x610;
                pData->NtCreateThdExIndex = 0xB4;
                pData->NtTermThdIndex = 0x53;
                pData->PrevMode = 0x232;
                pData->ExitStatus = 0x6E0;
                pData->MiAllocPage = 0;
                if (NT_SUCCESS(
                    BBScanSection("PAGE", (PCUCHAR)"\x48\x8D\x7D\x18\x48\x8B", 0xCC, 6, (PVOID)&pData->ExRemoveTable)))
                    pData->ExRemoveTable -= 0x5C;
                break;
            }
            else if (verInfo.dwBuildNumber == 14393)
            {
                pData->ver = WINVER_10_RS1;
                pData->KExecOpt = 0x1BF;
                pData->Protection = pData->buildNo >= 447 ? 0x6CA : 0x6C2;
                pData->EProcessFlags2 = 0x300;
                pData->ObjectTable = 0x418;
                pData->VadRoot = 0x620;
                pData->NtCreateThdExIndex = 0xB6;
                pData->NtTermThdIndex = 0x53;
                pData->PrevMode = 0x232;
                pData->ExitStatus = 0x6F0;
                pData->MiAllocPage = 0;
                if (NT_SUCCESS(
                    BBScanSection("PAGE", (PCUCHAR)"\x48\x8D\x7D\x18\x48\x8B", 0xCC, 6, (PVOID)&pData->ExRemoveTable)))
                    pData->ExRemoveTable -= 0x60;
                break;
            }
            else if (verInfo.dwBuildNumber == 15063)
            {
                pData->ver = WINVER_10_RS2;
                pData->KExecOpt = 0x1BF;
                pData->Protection = 0x6CA;
                pData->EProcessFlags2 = 0x300;
                pData->ObjectTable = 0x418;
                pData->VadRoot = 0x628;
                pData->NtCreateThdExIndex = 0xB9;
                pData->NtTermThdIndex = 0x53;
                pData->PrevMode = 0x232;
                pData->ExitStatus = 0x6F8;
                pData->MiAllocPage = 0;
                if (NT_SUCCESS(
                    BBScanSection("PAGE", (PCUCHAR)"\x48\x8B\x47\x20\x48\x83\xC7\x18", 0xCC, 8, (PVOID)&pData->
                        ExRemoveTable)))
                    pData->ExRemoveTable -= 0x34;
                break;
            }
            else if (verInfo.dwBuildNumber == 16299)
            {
                pData->ver = WINVER_10_RS3;
                pData->KExecOpt = 0x1BF;
                pData->Protection = 0x6CA;
                pData->EProcessFlags2 = 0x828; // MitigationFlags offset
                pData->ObjectTable = 0x418;
                pData->VadRoot = 0x628;
                pData->NtCreateThdExIndex = 0xBA;
                pData->NtTermThdIndex = 0x53;
                pData->PrevMode = 0x232;
                pData->ExitStatus = 0x700;
                pData->MiAllocPage = 0;
                if (NT_SUCCESS(
                    BBScanSection("PAGE", (PCUCHAR)"\x48\x83\xC7\x18\x48\x8B\x17", 0xCC, 7, (PVOID)&pData->ExRemoveTable
                    )))
                    pData->ExRemoveTable -= 0x34;
                break;
            }
            else if (verInfo.dwBuildNumber == 17134)
            {
                pData->ver = WINVER_10_RS4;
                pData->KExecOpt = 0x1BF;
                pData->Protection = 0x6CA;
                pData->EProcessFlags2 = 0x828; // MitigationFlags offset
                pData->ObjectTable = 0x418;
                pData->VadRoot = 0x628;
                pData->NtCreateThdExIndex = 0xBB;
                pData->NtTermThdIndex = 0x53;
                pData->PrevMode = 0x232;
                pData->ExitStatus = 0x700;
                pData->MiAllocPage = 0;
                if (NT_SUCCESS(
                    BBScanSection("PAGE", (PCUCHAR)"\x48\x83\xC7\x18\x48\x8B\x17", 0xCC, 7, (PVOID)&pData->ExRemoveTable
                    )))
                    pData->ExRemoveTable -= 0x34;
                break;
            }
            else if (verInfo.dwBuildNumber == 17763)
            {
                pData->ver = WINVER_10_RS5;
                pData->KExecOpt = 0x1BF;
                pData->Protection = 0x6CA;
                pData->EProcessFlags2 = 0x820; // MitigationFlags offset
                pData->ObjectTable = 0x418;
                pData->VadRoot = 0x628;
                pData->PrevMode = 0x232;
                pData->ExitStatus = 0x700;
                pData->MiAllocPage = 0;
                if (NT_SUCCESS(
                    BBScanSection("PAGE", (PCUCHAR)"\x48\x83\xC7\x18\x48\x8B\x17", 0xCC, 7, (PVOID)&pData->ExRemoveTable
                    )))
                    pData->ExRemoveTable -= 0x34;
                break;
            }
            else if (verInfo.dwBuildNumber == 18362 || verInfo.dwBuildNumber == 18363)
            {
                pData->ver = verInfo.dwBuildNumber == 18362 ? WINVER_10_19H1 : WINVER_10_19H2;
                pData->KExecOpt = 0x1C3;
                pData->Protection = 0x6FA;
                pData->EProcessFlags2 = 0x850; // MitigationFlags offset
                pData->ObjectTable = 0x418;
                pData->VadRoot = 0x658;
                pData->PrevMode = 0x232;
                pData->ExitStatus = 0x710;
                pData->MiAllocPage = 0;
                if (NT_SUCCESS(
                    BBScanSection("PAGE", (PCUCHAR)"\x48\x83\xC7\x18\x48\x8B\x17", 0xCC, 7, (PVOID)&pData->ExRemoveTable
                    )))
                    pData->ExRemoveTable -= 0x34;
                break;
            }
            else if (verInfo.dwBuildNumber == 19041)
            {
                pData->ver = WINVER_10_20H1;

                //family: Windows 10, arch: x64, osname: 2004 (May 2020 Update, Vibranium R1), buildnumber: 10.0.19041.264
                pData->KExecOpt = 0x283; //_KPROCESS.Flags
                pData->Protection = 0x87A; //_EPROCESS.Protection
                pData->EProcessFlags2 = 0x9D4; //_EPROCESS.MitigationFlags2
                pData->ObjectTable = 0x570; //_EPROCESS.ObjectTable
                pData->VadRoot = 0x7D8; //_EPROCESS.VadRoot
                pData->PrevMode = 0x232; //_KTHREAD.PreviousMode
                pData->ExitStatus = 0x548; //_ETHREAD.ExitStatus
                ///////////////////////////////////////////////

                pData->MiAllocPage = 0;
                if (NT_SUCCESS(
                    BBScanSection("PAGE", (PCUCHAR)"\x48\x83\xC7\x18\x48\x8B\x17", 0xCC, 7, (PVOID)&pData->ExRemoveTable
                    )))
                    pData->ExRemoveTable -= 0x34;
                break;
            }
            else if (verInfo.dwBuildNumber == 19042)
            {
                pData->ver = WINVER_10_20H2;

                //family: Windows 10, arch: x64, osname: 20H2 (October 2020 Update, Vibranium R2), buildnumber: 10.0.19042.508
                pData->KExecOpt = 0x283; //_KPROCESS.Flags
                pData->Protection = 0x87A; //_EPROCESS.Protection
                pData->EProcessFlags2 = 0x9D4; //_EPROCESS.MitigationFlags2
                pData->ObjectTable = 0x570; //_EPROCESS.ObjectTable
                pData->VadRoot = 0x7D8; //_EPROCESS.VadRoot
                pData->PrevMode = 0x232; //_KTHREAD.PreviousMode
                pData->ExitStatus = 0x548; //_ETHREAD.ExitStatus
                ///////////////////////////////////////////////

                pData->MiAllocPage = 0;
                if (NT_SUCCESS(
                    BBScanSection("PAGE", (PCUCHAR)"\x48\x83\xC7\x18\x48\x8B\x17", 0xCC, 7, (PVOID)&pData->ExRemoveTable
                    )))
                    pData->ExRemoveTable -= 0x34;
                break;
            }
            else if (verInfo.dwBuildNumber == 19044)
            {
                pData->ver = WINVER_10_21H2;

                //family: Windows 10, arch: x64, osname: 21H2 (November 2021 Update, Vibranium R4), buildnumber: 10.0.19044.1288
                pData->KExecOpt = 0x283; //_KPROCESS.Flags
                pData->Protection = 0x87A; //_EPROCESS.Protection
                pData->EProcessFlags2 = 0x9D4; //_EPROCESS.MitigationFlags2
                pData->ObjectTable = 0x570; //_EPROCESS.ObjectTable
                pData->VadRoot = 0x7D8; //_EPROCESS.VadRoot
                pData->PrevMode = 0x232; //_KTHREAD.PreviousMode
                pData->ExitStatus = 0x548; //_ETHREAD.ExitStatus
                ///////////////////////////////////////////////

                pData->MiAllocPage = 0;
                if (NT_SUCCESS(
                    BBScanSection("PAGE", (PCUCHAR)"\x48\x83\xC7\x18\x48\x8B\x17", 0xCC, 7, (PVOID)&pData->ExRemoveTable
                    )))
                    pData->ExRemoveTable -= 0x34;
                break;
            }
            else if (verInfo.dwBuildNumber == 19045)
            {
                pData->ver = WINVER_10_22H2;

                //family: Windows 10, arch: x64, osname: 22H2 (2022 Update, Vibranium R5), buildnumber: 10.0.19045.2965
                pData->KExecOpt = 0x283; //_KPROCESS.Flags
                pData->Protection = 0x87A; //_EPROCESS.Protection
                pData->EProcessFlags2 = 0x9D4; //_EPROCESS.MitigationFlags2
                pData->ObjectTable = 0x570; //_EPROCESS.ObjectTable
                pData->VadRoot = 0x7D8; //_EPROCESS.VadRoot
                pData->PrevMode = 0x232; //_KTHREAD.PreviousMode
                pData->ExitStatus = 0x548; //_ETHREAD.ExitStatus
                ///////////////////////////////////////////////

                pData->ExitStatus = 0x548;
                if (NT_SUCCESS(
                    BBScanSection("PAGE", (PCUCHAR)"\x48\x83\xC7\x18\x48\x8B\x17", 0xCC, 7, (PVOID)&pData->ExRemoveTable
                    )))
                    pData->ExRemoveTable -= 0x34;
                break;
            }

            // Windows 11
            else if (verInfo.dwBuildNumber == 22621)
            {
                pData->ver = WINVER_10_23H2;

                //family: Windows 11, arch: x64, osname: 22H2 (2022 Update, Nickel R1), buildnumber: 10.0.22621.382
                pData->KExecOpt = 0x283; //_KPROCESS.Flags
                pData->Protection = 0x87A; //_EPROCESS.Protection
                pData->EProcessFlags2 = 0x9D4; //_EPROCESS.MitigationFlags2
                pData->ObjectTable = 0x570; //_EPROCESS.ObjectTable
                pData->VadRoot = 0x7D8; //_EPROCESS.VadRoot
                pData->PrevMode = 0x232; //_KTHREAD.PreviousMode
                pData->ExitStatus = 0x598; //_ETHREAD.ExitStatus
                ///////////////////////////////////////////////

                pData->MiAllocPage = 0;
                if (NT_SUCCESS(
                    BBScanSection("PAGE", (PCUCHAR)"\x48\x83\xC7\x18\x48\x8B\x17", 0xCC, 7, (PVOID)&pData->ExRemoveTable
                    )))
                    pData->ExRemoveTable -= 0x34;
                break;
            }
            else if (verInfo.dwBuildNumber == 22631)
            {
                pData->ver = WINVER_10_23H2;

                //family: Windows 11, arch: x64, osname: 23H2 (2023 Update, Nickel R2), buildnumber: 10.0.22631.2428
                pData->KExecOpt = 0x283; //_KPROCESS.Flags
                pData->Protection = 0x87A; //_EPROCESS.Protection
                pData->EProcessFlags2 = 0x9D4; //_EPROCESS.MitigationFlags2
                pData->ObjectTable = 0x570; //_EPROCESS.ObjectTable
                pData->VadRoot = 0x7D8; //_EPROCESS.VadRoot
                pData->PrevMode = 0x232; //_KTHREAD.PreviousMode
                pData->ExitStatus = 0x598; //_ETHREAD.ExitStatus
                ///////////////////////////////////////////////

                pData->MiAllocPage = 0;
                if (NT_SUCCESS(
                    BBScanSection("PAGE", (PCUCHAR)"\x48\x83\xC7\x18\x48\x8B\x17", 0xCC, 7, (PVOID)&pData->ExRemoveTable
                    )))
                    pData->ExRemoveTable -= 0x34;
                break;
            }
            else if (verInfo.dwBuildNumber == 26100)
            {
                pData->ver = WINVER_10_24H2;

                //Generated on 9/25/2025 12:50:02 AM +00:00 from 10.0.26100.1742-x64.yml
                //family: Windows 11, arch: x64, osname: 24H2 (2024 Update, Germanium), buildnumber: 10.0.26100.1742
                pData->KExecOpt = 0x93; //_KPROCESS.Flags
                pData->Protection = 0x5FA; //_EPROCESS.Protection
                pData->EProcessFlags2 = 0x754; //_EPROCESS.MitigationFlags2
                pData->ObjectTable = 0x300; //_EPROCESS.ObjectTable
                pData->VadRoot = 0x558; //_EPROCESS.VadRoot
                pData->PrevMode = 0x232; //_KTHREAD.PreviousMode
                pData->ExitStatus = 0x5D8; //_ETHREAD.ExitStatus
                ///////////////////////////////////////////////

                pData->MiAllocPage = 0;
                if (NT_SUCCESS(
                    BBScanSection("PAGE", (PCUCHAR)"\x48\x83\xC7\x18\x48\x8B\x17", 0xCC, 7, (PVOID)&pData->ExRemoveTable
                    )))
                {
                    pData->ExRemoveTable -= 0x34;
                }
                break;
            }
            else
            {
                return STATUS_NOT_SUPPORTED;
            }
        default:
            break;
        }

        // SSDT
        pData->NtCreateThdExIndex = GetNtSyscallIndex("ZwCreateThreadEx");
        if (pData->NtCreateThdExIndex == MAXULONG)
        {
            DPRINT("BlackBone: Could not find ZwCreateThreadEx syscall");
            return STATUS_RESOURCE_TYPE_NOT_FOUND;
        }
        pData->NtTermThdIndex = GetNtSyscallIndex("ZwTerminateThread");
        if (pData->NtTermThdIndex == MAXULONG)
        {
            DPRINT("BlackBone: Could not find ZwTerminateThread syscall");
            return STATUS_RESOURCE_TYPE_NOT_FOUND;
        }
        pData->NtProtectIndex = GetNtSyscallIndex("ZwProtectVirtualMemory");
        if (pData->NtProtectIndex == MAXULONG)
        {
            DPRINT("BlackBone: Could not find ZwProtectVirtualMemory syscall");
            return STATUS_RESOURCE_TYPE_NOT_FOUND;
        }

        if (pData->ExRemoveTable != 0)
            pData->correctBuild = TRUE;

        DPRINT(
            "BlackBone: Dynamic search status: SSDT - %s, ExRemoveTable - %s",
            GetSSDTBase() != NULL ? "SUCCESS" : "FAIL",
            pData->ExRemoveTable != 0 ? "SUCCESS" : "FAIL"
        );

        if (pData->ver >= WINVER_10_RS1)
        {
            DPRINT(
                "BlackBone: %s: g_KdBlock->KernBase: %p, GetKernelBase() = 0x%p ",
                __FUNCTION__, g_KdBlock.KernBase, GetKernelBase(NULL)
            );

            ULONGLONG mask = (1ll << (PHYSICAL_ADDRESS_BITS - 1)) - 1;
            dynData.DYN_PTE_BASE = (ULONG_PTR)g_KdBlock.PteBase;
            dynData.DYN_PDE_BASE = (ULONG_PTR)((g_KdBlock.PteBase & ~mask) | ((g_KdBlock.PteBase >> 9) & mask));
        }

        DPRINT("BlackBone: PDE_BASE: %p, PTE_BASE: %p", pData->DYN_PDE_BASE, pData->DYN_PTE_BASE);
        if (pData->DYN_PDE_BASE < MI_SYSTEM_RANGE_START || pData->DYN_PTE_BASE < MI_SYSTEM_RANGE_START)
        {
            DPRINT("BlackBone: Invalid PDE/PTE base, aborting");
            return STATUS_UNSUCCESSFUL;
        }

        return (pData->VadRoot != 0 ? status : STATUS_INVALID_KERNEL_INFO_VERSION);
    }

    return status;
}
