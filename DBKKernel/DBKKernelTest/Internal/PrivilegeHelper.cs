using System;

namespace DBKKernelTest;

internal static class PrivilegeHelper
{
    public static void TryEnableSeDebugPrivilege(Logger log)
    {
        try
        {
            IntPtr token;
            if (!AdvApi.OpenProcessToken(Kernel32.GetCurrentProcess(), AdvApi.TOKEN_ADJUST_PRIVILEGES | AdvApi.TOKEN_QUERY, out token))
            {
                ThrowLastError(log, "OpenProcessToken failed");
            }

            AdvApi.LUID luid;
            if (!AdvApi.LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
            {
                ThrowLastError(log, "LookupPrivilegeValue(SeDebugPrivilege) failed");
            }

            AdvApi.TOKEN_PRIVILEGES tp = new AdvApi.TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Privileges = new AdvApi.LUID_AND_ATTRIBUTES
                {
                    Luid = luid,
                    Attributes = AdvApi.SE_PRIVILEGE_ENABLED
                }
            };

            if (!AdvApi.AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
            {
                ThrowLastError(log, "AdjustTokenPrivileges failed");
            }

            log.Info("SeDebugPrivilege enabled");
        }
        catch (Exception ex)
        {
            log.Warn("Could not enable SeDebugPrivilege: {0}", ex.Message);
        }
    }

    private static void ThrowLastError(Logger log, string message)
    {
        int err = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
        var ex = new System.ComponentModel.Win32Exception(err);
        throw new InvalidOperationException(string.Format("{0}. Win32Error=0x{1:X8} ({1}) '{2}'", message, err, ex.Message));
    }
}
