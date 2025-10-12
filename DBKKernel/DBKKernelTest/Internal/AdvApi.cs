using System;
using System.Runtime.InteropServices;

namespace DBKKernelTest;

internal static class AdvApi
{
    public const int ERROR_SERVICE_EXISTS = 1073;
    public const int ERROR_SERVICE_ALREADY_RUNNING = 1056;
    public const int ERROR_SERVICE_NOT_ACTIVE = 1062;
    public const int ERROR_SERVICE_MARKED_FOR_DELETE = 1072;

    [Flags]
    public enum SCM_ACCESS : uint
    {
        SC_MANAGER_ALL_ACCESS = 0xF003F
    }

    [Flags]
    public enum SERVICE_ACCESS : uint
    {
        SERVICE_ALL_ACCESS = 0xF01FF,
        SERVICE_QUERY_CONFIG = 0x0001,
    }

    public enum SERVICE_TYPE : uint
    {
        SERVICE_KERNEL_DRIVER = 0x00000001
    }

    public enum SERVICE_START : uint
    {
        SERVICE_DEMAND_START = 0x00000003
    }

    public enum SERVICE_ERROR : uint
    {
        SERVICE_ERROR_NORMAL = 0x00000001
    }

    public enum SERVICE_CONTROL : uint
    {
        STOP = 0x00000001
    }

    public enum SC_STATUS_TYPE : int
    {
        SC_STATUS_PROCESS_INFO = 0
    }

    public enum SERVICE_STATE : uint
    {
        SERVICE_STOPPED = 0x00000001,
        SERVICE_START_PENDING = 0x00000002,
        SERVICE_STOP_PENDING = 0x00000003,
        SERVICE_RUNNING = 0x00000004,
        SERVICE_CONTINUE_PENDING = 0x00000005,
        SERVICE_PAUSE_PENDING = 0x00000006,
        SERVICE_PAUSED = 0x00000007
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SERVICE_STATUS
    {
        public SERVICE_TYPE dwServiceType;
        public SERVICE_STATE dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SERVICE_STATUS_PROCESS
    {
        public SERVICE_TYPE dwServiceType;
        public SERVICE_STATE dwCurrentState;
        public uint dwControlsAccepted;
        public uint dwWin32ExitCode;
        public uint dwServiceSpecificExitCode;
        public uint dwCheckPoint;
        public uint dwWaitHint;
        public uint dwProcessId;
        public uint dwServiceFlags;
    }

    // TOKEN privilege related
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_QUERY = 0x0008;

    public const int SE_PRIVILEGE_ENABLED = 0x2;

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public int Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    // Service control manager
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern SafeServiceHandle OpenSCManager(string lpMachineName, string lpDatabaseName, SCM_ACCESS dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern SafeServiceHandle CreateService(
        SafeServiceHandle hSCManager,
        string lpServiceName,
        string lpDisplayName,
        SERVICE_ACCESS dwDesiredAccess,
        SERVICE_TYPE dwServiceType,
        SERVICE_START dwStartType,
        SERVICE_ERROR dwErrorControl,
        string lpBinaryPathName,
        string lpLoadOrderGroup,
        IntPtr lpdwTagId,
        string lpDependencies,
        string lpServiceStartName,
        string lpPassword);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern SafeServiceHandle OpenService(SafeServiceHandle hSCManager, string lpServiceName, SERVICE_ACCESS dwDesiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool StartService(SafeServiceHandle hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ControlService(SafeServiceHandle hService, SERVICE_CONTROL dwControl, out SERVICE_STATUS lpServiceStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeleteService(SafeServiceHandle hService);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool QueryServiceStatusEx(
        SafeServiceHandle hService,
        SC_STATUS_TYPE InfoLevel,
        out SERVICE_STATUS_PROCESS lpBuffer,
        int cbBufSize,
        out int pcbBytesNeeded);

    // QueryServiceConfig to get binary path
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool QueryServiceConfig(
        SafeServiceHandle hService,
        IntPtr lpServiceConfig,
        int cbBufSize,
        out int pcbBytesNeeded);
}