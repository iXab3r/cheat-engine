using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace DBKKernelTest;

internal sealed class ServiceManager
{
    private readonly Logger _log;

    public ServiceManager(Logger log)
    {
        _log = log;
    }

    public void PrintStatus(string serviceName)
    {
        using (SafeServiceHandle scm = AdvApi.OpenSCManager(null, null, AdvApi.SCM_ACCESS.SC_MANAGER_ALL_ACCESS))
        {
            if (scm.IsInvalid)
                ThrowLastError("OpenSCManager failed. Are you running elevated?");

            using (SafeServiceHandle svc = AdvApi.OpenService(scm, serviceName, AdvApi.SERVICE_ACCESS.SERVICE_ALL_ACCESS))
            {
                if (svc.IsInvalid)
                {
                    int err = Marshal.GetLastWin32Error();
                    _log.Info("Service '{0}' not installed. (Win32: {1})", serviceName, err);
                    return;
                }

                var ssp = QueryStatus(svc);
                _log.Info("Service '{0}' state: {1}", serviceName, ssp.dwCurrentState);

                string bin = GetServiceBinaryPath(svc);
                _log.Info("Binary path: {0}", bin);
                try
                {
                    string normalized = NormalizeBinaryPath(bin);
                    if (File.Exists(normalized))
                    {
                        var fi = new FileInfo(normalized);
                        _log.Info("File exists. Size={0} bytes, Created={1}, Modified={2}", fi.Length, fi.CreationTime, fi.LastWriteTime);
                    }
                    else
                    {
                        _log.Warn("Binary file not found at '{0}'", normalized);
                    }
                }
                catch (Exception ex)
                {
                    _log.Warn("Could not read file info: {0}", ex.Message);
                }
            }
        }
    }

    public void Load(string serviceName, string driverPath)
    {
        using (SafeServiceHandle scm = AdvApi.OpenSCManager(null, null, AdvApi.SCM_ACCESS.SC_MANAGER_ALL_ACCESS))
        {
            if (scm.IsInvalid)
                ThrowLastError("OpenSCManager failed. Are you running elevated?");

            using (SafeServiceHandle svc = CreateOrOpenDriverService(scm, serviceName, driverPath))
            {
                StartServiceAndWaitRunning(serviceName, svc);
                _log.Info("Driver loaded");
            }
        }
    }

    public void Unload(string serviceName)
    {
        using (SafeServiceHandle scm = AdvApi.OpenSCManager(null, null, AdvApi.SCM_ACCESS.SC_MANAGER_ALL_ACCESS))
        {
            if (scm.IsInvalid)
                ThrowLastError("OpenSCManager failed. Are you running elevated?");

            using (SafeServiceHandle svc = AdvApi.OpenService(scm, serviceName, AdvApi.SERVICE_ACCESS.SERVICE_ALL_ACCESS))
            {
                if (svc.IsInvalid)
                {
                    int err = Marshal.GetLastWin32Error();
                    ThrowWin32("OpenService failed", err);
                }

                StopAndDeleteService(serviceName, svc);
                _log.Info("Driver unloaded and service removed");
            }
        }
    }

    private SafeServiceHandle CreateOrOpenDriverService(SafeServiceHandle scm, string name, string binPath)
    {
        _log.Info("Creating service '{0}' for driver '{1}'", name, binPath);

        SafeServiceHandle svc = AdvApi.CreateService(
            scm,
            name,
            name,
            AdvApi.SERVICE_ACCESS.SERVICE_ALL_ACCESS,
            AdvApi.SERVICE_TYPE.SERVICE_KERNEL_DRIVER,
            AdvApi.SERVICE_START.SERVICE_DEMAND_START,
            AdvApi.SERVICE_ERROR.SERVICE_ERROR_NORMAL,
            binPath,
            null,
            IntPtr.Zero,
            null,
            null,
            null);

        if (!svc.IsInvalid)
        {
            _log.Info("Service '{0}' created", name);
            return svc;
        }

        int err = Marshal.GetLastWin32Error();
        if (err != AdvApi.ERROR_SERVICE_EXISTS)
        {
            ThrowWin32("CreateService failed", err);
        }

        _log.Warn("Service already exists. Recreating to ensure correct binary path");
        // Open existing
        svc = AdvApi.OpenService(scm, name, AdvApi.SERVICE_ACCESS.SERVICE_ALL_ACCESS);
        if (svc.IsInvalid)
            ThrowLastError(string.Format("OpenService('{0}') failed", name));

        // Try to delete existing service so we can recreate with desired path
        try
        {
            AdvApi.SERVICE_STATUS s;
            AdvApi.ControlService(svc, AdvApi.SERVICE_CONTROL.STOP, out s);
        }
        catch
        {
        }

        if (!AdvApi.DeleteService(svc))
        {
            int derr = Marshal.GetLastWin32Error();
            if (derr != AdvApi.ERROR_SERVICE_MARKED_FOR_DELETE)
            {
                _log.Warn("DeleteService failed: {0} ({1}). Will attempt to recreate anyway.", new Win32Exception(derr).Message, derr);
            }
        }

        svc.Dispose();

        // Recreate with correct path
        svc = AdvApi.CreateService(
            scm,
            name,
            name,
            AdvApi.SERVICE_ACCESS.SERVICE_ALL_ACCESS,
            AdvApi.SERVICE_TYPE.SERVICE_KERNEL_DRIVER,
            AdvApi.SERVICE_START.SERVICE_DEMAND_START,
            AdvApi.SERVICE_ERROR.SERVICE_ERROR_NORMAL,
            binPath,
            null,
            IntPtr.Zero,
            null,
            null,
            null);
        if (svc.IsInvalid)
            ThrowLastError("Re-create service failed");

        _log.Info("Service '{0}' recreated with binary '{1}'", name, binPath);
        return svc;
    }

    private void StartServiceAndWaitRunning(string serviceName, SafeServiceHandle svc)
    {
        _log.Info("Starting service '{0}'", serviceName);
        if (!AdvApi.StartService(svc, 0, null))
        {
            int err = Marshal.GetLastWin32Error();
            if (err != AdvApi.ERROR_SERVICE_ALREADY_RUNNING)
            {
                ThrowWin32("StartService failed", err);
            }

            _log.Warn("Service was already running");
        }
        else
        {
            _log.Info("StartService issued successfully");
        }

        // Wait until running
        AdvApi.SERVICE_STATUS_PROCESS status = QueryStatus(svc);
        const int maxWaitMs = 15000;
        int waited = 0;
        while (status.dwCurrentState != AdvApi.SERVICE_STATE.SERVICE_RUNNING && waited < maxWaitMs)
        {
            int wait = (int)Math.Min(500, Math.Max(200, status.dwWaitHint / 10));
            System.Threading.Thread.Sleep(wait);
            waited += wait;
            status = QueryStatus(svc);
            _log.Trace("Waiting for service to run... state={0}", status.dwCurrentState);
        }

        if (status.dwCurrentState != AdvApi.SERVICE_STATE.SERVICE_RUNNING)
        {
            throw new TimeoutException("Service did not reach RUNNING state in time");
        }

        _log.Info("Service is RUNNING");
    }

    private void StopAndDeleteService(string serviceName, SafeServiceHandle svc)
    {
        _log.Info("Stopping service '{0}'", serviceName);

        AdvApi.SERVICE_STATUS_PROCESS status = QueryStatus(svc);
        if (status.dwCurrentState != AdvApi.SERVICE_STATE.SERVICE_STOPPED)
        {
            AdvApi.SERVICE_STATUS s;
            if (!AdvApi.ControlService(svc, AdvApi.SERVICE_CONTROL.STOP, out s))
            {
                int err = Marshal.GetLastWin32Error();
                if (err != AdvApi.ERROR_SERVICE_NOT_ACTIVE)
                {
                    ThrowWin32("ControlService(STOP) failed", err);
                }

                _log.Warn("Service already stopped");
            }

            // Wait for stopped
            const int maxWaitMs = 10000;
            int waited = 0;
            status = QueryStatus(svc);
            while (status.dwCurrentState != AdvApi.SERVICE_STATE.SERVICE_STOPPED && waited < maxWaitMs)
            {
                int wait = (int)Math.Min(500, Math.Max(200, status.dwWaitHint / 10));
                System.Threading.Thread.Sleep(wait);
                waited += wait;
                status = QueryStatus(svc);
                _log.Trace("Waiting for service to stop... state={0}", status.dwCurrentState);
            }

            if (status.dwCurrentState != AdvApi.SERVICE_STATE.SERVICE_STOPPED)
            {
                throw new TimeoutException("Service did not reach STOPPED state in time");
            }
        }

        _log.Info("Service is STOPPED");

        // Delete service
        if (!AdvApi.DeleteService(svc))
        {
            int err = Marshal.GetLastWin32Error();
            if (err != AdvApi.ERROR_SERVICE_MARKED_FOR_DELETE)
            {
                ThrowWin32("DeleteService failed", err);
            }

            _log.Warn("Service is already marked for delete");
        }
    }

    private AdvApi.SERVICE_STATUS_PROCESS QueryStatus(SafeServiceHandle svc)
    {
        AdvApi.SERVICE_STATUS_PROCESS ssp;
        int bytesNeeded;
        int size = Marshal.SizeOf(typeof(AdvApi.SERVICE_STATUS_PROCESS));
        if (!AdvApi.QueryServiceStatusEx(svc, AdvApi.SC_STATUS_TYPE.SC_STATUS_PROCESS_INFO, out ssp, size, out bytesNeeded))
        {
            ThrowLastError("QueryServiceStatusEx failed");
        }

        return ssp;
    }

    private void ThrowLastError(string message)
    {
        int err = Marshal.GetLastWin32Error();
        ThrowWin32(message, err);
    }

    private void ThrowWin32(string message, int err)
    {
        var ex = new Win32Exception(err);
        throw new InvalidOperationException(string.Format("{0}. Win32Error=0x{1:X8} ({1}) '{2}'", message, err, ex.Message));
    }

    // QueryServiceConfig helpers
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct QUERY_SERVICE_CONFIGW
    {
        public AdvApi.SERVICE_TYPE dwServiceType;
        public AdvApi.SERVICE_START dwStartType;
        public AdvApi.SERVICE_ERROR dwErrorControl;
        public IntPtr lpBinaryPathName;
        public IntPtr lpLoadOrderGroup;
        public uint dwTagId;
        public IntPtr lpDependencies;
        public IntPtr lpServiceStartName;
        public IntPtr lpDisplayName;
    }

    private string GetServiceBinaryPath(SafeServiceHandle svc)
    {
        int needed;
        // First call to get needed size
        AdvApi.QueryServiceConfig(svc, IntPtr.Zero, 0, out needed);
        int err = Marshal.GetLastWin32Error();
        if (needed <= 0)
        {
            ThrowWin32("QueryServiceConfig(size) failed", err);
        }

        IntPtr buf = Marshal.AllocHGlobal(needed);
        try
        {
            if (!AdvApi.QueryServiceConfig(svc, buf, needed, out needed))
            {
                ThrowLastError("QueryServiceConfig failed");
            }

            QUERY_SERVICE_CONFIGW cfg = (QUERY_SERVICE_CONFIGW)Marshal.PtrToStructure(buf, typeof(QUERY_SERVICE_CONFIGW));
            string path = Marshal.PtrToStringUni(cfg.lpBinaryPathName);
            return path ?? string.Empty;
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    private string NormalizeBinaryPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return path;
        // Remove quotes
        path = path.Trim();
        if (path.Length >= 2 && path[0] == '"' && path[path.Length - 1] == '"')
            path = path.Substring(1, path.Length - 2);
        // Expand environment variables
        path = Environment.ExpandEnvironmentVariables(path);
        return path;
    }
}
