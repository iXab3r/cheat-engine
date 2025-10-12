using System;
using System.Runtime.InteropServices;
using EyeAuras.Memory.KD.Internal;
using Microsoft.Win32.SafeHandles;

namespace DBKKernelTest;

internal static class DriverComm
{
    // IOCTL helpers
    private const uint FILE_DEVICE_UNKNOWN = 0x00000022;
    private const uint METHOD_BUFFERED = 0x0;
    private const uint FILE_READ_ACCESS = 0x0001;
    private const uint FILE_WRITE_ACCESS = 0x0002;

    private static uint CTL_CODE(uint deviceType, uint function, uint method, uint access)
    {
        return (deviceType << 16) | (access << 14) | (function << 2) | (method);
    }

    public static uint GetDriverVersion(string deviceDosName, Logger log)
    {
        log.Info("Opening device '{0}'", deviceDosName);
        using (SafeFileHandle h = Kernel32.CreateFile(deviceDosName,
                   Kernel32.GENERIC_READ | Kernel32.GENERIC_WRITE,
                   Kernel32.FILE_SHARE_READ | Kernel32.FILE_SHARE_WRITE,
                   IntPtr.Zero,
                   Kernel32.OPEN_EXISTING,
                   0,
                   IntPtr.Zero))
        {
            if (h.IsInvalid)
            {
                // Try to wait a bit for device creation
                const int retries = 20;
                for (int i = 0; i < retries; i++)
                {
                    System.Threading.Thread.Sleep(200);
                    using (SafeFileHandle h2 = Kernel32.CreateFile(deviceDosName,
                               Kernel32.GENERIC_READ | Kernel32.GENERIC_WRITE,
                               Kernel32.FILE_SHARE_READ | Kernel32.FILE_SHARE_WRITE,
                               IntPtr.Zero,
                               Kernel32.OPEN_EXISTING,
                               0,
                               IntPtr.Zero))
                    {
                        if (!h2.IsInvalid)
                        {
                            log.Info("Device opened after retry {0}", i + 1);
                            return IoctlGetVersion(h2, log);
                        }
                    }
                }

                ThrowLastError("CreateFile failed - device not available");
            }

            return IoctlGetVersion(h, log);
        }
    }

    private static uint IoctlGetVersion(SafeHandle h, Logger log)
    {
        uint version = 0;
        int outBytes = 0;
        log.Info("Calling IOCTL_CE_GETVERSION (0x{0:X8})", DBKIoctlCodes.IOCTL_CE_GETVERSION);
        bool ok = Kernel32.DeviceIoControl(h,
            DBKIoctlCodes.IOCTL_CE_GETVERSION,
            IntPtr.Zero, 0,
            ref version, Marshal.SizeOf(typeof(uint)),
            ref outBytes,
            IntPtr.Zero);

        if (!ok)
        {
            ThrowLastError("DeviceIoControl(IOCTL_CE_GETVERSION) failed");
        }

        log.Info("IOCTL returned {0} bytes", outBytes);
        return version;
    }

    private static void ThrowLastError(string message)
    {
        int err = Marshal.GetLastWin32Error();
        var ex = new System.ComponentModel.Win32Exception(err);
        throw new InvalidOperationException(string.Format("{0}. Win32Error=0x{1:X8} ({1}) '{2}'", message, err, ex.Message));
    }
}
