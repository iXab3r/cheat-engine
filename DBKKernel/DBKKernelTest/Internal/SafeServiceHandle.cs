using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace DBKKernelTest;

internal sealed class SafeServiceHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeServiceHandle() : base(true) { }

    protected override bool ReleaseHandle()
    {
        return CloseServiceHandle(handle);
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr hSCObject);
}