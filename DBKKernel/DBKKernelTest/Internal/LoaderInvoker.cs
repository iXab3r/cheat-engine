using System;
using System.Diagnostics;
using System.IO;

namespace DBKKernelTest;

internal static class LoaderInvoker
{
    public static void LoadWithLoader(string exeDirectory, string driverPath, string serviceName, Logger log)
    {
        if (string.IsNullOrWhiteSpace(exeDirectory))
            exeDirectory = AppDomain.CurrentDomain.BaseDirectory;

        driverPath = Path.GetFullPath(driverPath);
        if (!File.Exists(driverPath))
            throw new FileNotFoundException("Driver file not found", driverPath);

        string loaderPath = Path.Combine(exeDirectory, "dLoader.exe");
        if (!File.Exists(loaderPath))
            throw new FileNotFoundException("dLoader.exe not found next to executable", loaderPath);

        var psi = new ProcessStartInfo
        {
            FileName = loaderPath,
            Arguments = $"\"{driverPath}\" load {serviceName}",
            WorkingDirectory = exeDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        log.Info("Starting: {0} {1}", psi.FileName, psi.Arguments);

        using (var proc = new Process())
        {
            proc.StartInfo = psi;
            proc.OutputDataReceived += (s, e) => { if (e.Data != null) log.Info("[dLoader] {0}", e.Data); };
            proc.ErrorDataReceived += (s, e) => { if (e.Data != null) log.Warn("[dLoader] {0}", e.Data); };
            if (!proc.Start())
                throw new InvalidOperationException("Failed to start dLoader.exe");

            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();
            proc.WaitForExit();

            log.Info("dLoader exited with code {0}", proc.ExitCode);
            if (proc.ExitCode != 0)
                throw new InvalidOperationException("dLoader failed with exit code " + proc.ExitCode);
        }
    }
}
