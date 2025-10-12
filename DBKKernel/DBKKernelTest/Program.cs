using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Runtime.InteropServices;
using EyeAuras.Memory.KD.Internal;
using Spectre.Console;

namespace DBKKernelTest
{
    internal static class Program
    {
        private static string CurrentServiceName = "EADBKSVC73";

        private static string GetDeviceDosName() => $"\\\\.\\{CurrentServiceName}"; // maps to \\DosDevices\\dea64

        // Driver expected to be next to this executable
        private const string LocalDriverFileName = "dea64.sys";

        private static Logger Log;

        public static void Main(string[] args)
        {
            // Initialize logger
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            string logPath = Path.Combine(exeDir, "DBKKernelTest.log");
            Log = new Logger(logPath);

            try
            {
                Log.Info("DBKKernelTest started at {0}", DateTime.Now);

                DumpEnvironment();

                // Always try to enable SeDebugPrivilege first as requested
                TryEnableSeDebugPrivilege();

                RunTuiLoop();
                return;
            }
            catch (Exception ex)
            {
                Log.Error("FAILED: {0}", ex);
                Environment.ExitCode = unchecked((int) 0x80004005); // E_FAIL
            }
        }

        private static void TryEnableSeDebugPrivilege()
        {
            PrivilegeHelper.TryEnableSeDebugPrivilege(Log);
        }

        private static void DoStatus()
        {
            var sm = new ServiceManager(Log);
            sm.PrintStatus(CurrentServiceName);
        }

        private static void DoLoad(string pathArg)
        {
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            string driverPath = pathArg;
            if (string.IsNullOrWhiteSpace(driverPath))
                driverPath = Path.Combine(exeDir, LocalDriverFileName);
            driverPath = Path.GetFullPath(driverPath);

            if (!File.Exists(driverPath))
                throw new FileNotFoundException("Driver file not found", driverPath);

            var sm = new ServiceManager(Log);
            sm.Load(CurrentServiceName, driverPath);
        }

        private static void DoLoadWithLoader(string pathArg)
        {
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            string driverPath = pathArg;
            if (string.IsNullOrWhiteSpace(driverPath))
                driverPath = Path.Combine(exeDir, LocalDriverFileName);
            driverPath = Path.GetFullPath(driverPath);

            LoaderInvoker.LoadWithLoader(exeDir, driverPath, CurrentServiceName, Log);
        }

        private static void DoUnload()
        {
            var sm = new ServiceManager(Log);
            sm.Unload(CurrentServiceName);
        }

        private static void DoVersion()
        {
            using (var driver = new DBKDriver(GetDeviceDosName()))
            {
                driver.Open();
                int version = driver.GetVersion();
                Log.Info("Driver version: {0}", version);
            }
        }

        private static void DoInject(bool isX64, string dllPath, DBKDriver.InjectType injectType)
        {
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            string agentExe = GetAgentExe(isX64);

            if (!File.Exists(agentExe))
            {
                throw new FileNotFoundException("Agent executable not found", agentExe);
            }

            if (!File.Exists(dllPath))
            {
                throw new FileNotFoundException("Payload DLL not found", dllPath);
            }

            Log.Info("Starting agent: {0}", agentExe);
            var psi = new ProcessStartInfo
            {
                FileName = agentExe,
                UseShellExecute = true,
                WorkingDirectory = exeDir,
            };

            using (var proc = Process.Start(psi))
            {
                if (proc == null)
                {
                    throw new InvalidOperationException("Failed to start agent process");
                }

                // Give it a moment to initialize
                Thread.Sleep(500);
                proc.Refresh();
                Log.Info("Agent started: PID={0}", proc.Id);

                using (var driver = new DBKDriver(GetDeviceDosName()))
                {
                    driver.Open();
                    Log.Info($"Injecting {{0}} into PID {{1}} via {injectType}", Path.GetFileName(dllPath), proc.Id);
                    driver.InjectDll(proc.Id, dllPath, injectType);
                    Log.Info("Injection request sent successfully");
                }

                Log.Info("Leaving agent running. Close it manually if desired.");
            }
        }

        private static string GetAgentExe(bool isX64)
        {
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            string agentExe = Path.Combine(exeDir, isX64 ? "EyeAuras.Agent.NetHost.x64.exe" : "EyeAuras.Agent.NetHost.x86.exe");
            return agentExe;
        }

        private static string GetHelloWorldDll(bool isX64)
        {
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            string dllPath = Path.Combine(exeDir, isX64 ? "hello-world-x64.dll" : "hello-world-x86.dll");
            return dllPath;
        }

        private static string GetFridaDll(bool isX64)
        {
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            string dllPath = Path.Combine(exeDir, isX64 ? "frida-gadget-17.3.2-windows-x86_64.dll" : "frida-gadget-17.3.2-windows-x86.dll");
            return dllPath;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

        private static bool IsProcess64Bit(Process p)
        {
            try
            {
                if (!Environment.Is64BitOperatingSystem)
                    return false;
                if (p == null || p.HasExited)
                    return false;
                if (!IsWow64Process(p.Handle, out bool isWow64))
                    return Environment.Is64BitOperatingSystem; // fallback
                return !isWow64;
            }
            catch
            {
                return Environment.Is64BitOperatingSystem;
            }
        }

        private static void DoCustomInject(int pid, string dllPath, DBKDriver.InjectType type)
        {
            var proc = GetProcessSafe(pid);
            if (proc == null)
            {
                throw new ArgumentException($"Process with PID {pid} was not found");
            }

            string effectiveDll = dllPath;
            if (string.IsNullOrWhiteSpace(effectiveDll) || !File.Exists(effectiveDll))
            {
                bool is64 = IsProcess64Bit(proc);
                effectiveDll = GetHelloWorldDll(is64);
                Log.Warn("DLL path was empty or invalid, falling back to hello-world ({0})", Path.GetFileName(effectiveDll));
            }

            if (!Path.IsPathRooted(effectiveDll))
            {
                effectiveDll = Path.GetFullPath(effectiveDll);
            }

            if (!File.Exists(effectiveDll))
            {
                throw new FileNotFoundException("Payload DLL not found", effectiveDll);
            }

            using (var driver = new DBKDriver(GetDeviceDosName()))
            {
                driver.Open();
                Log.Info("Injecting {0} into PID {1} via {2}", Path.GetFileName(effectiveDll), proc.Id, type == DBKDriver.InjectType.IT_MMap ? "MMap" : "Thread");
                driver.InjectDll(proc.Id, effectiveDll, type);
                Log.Info("Injection request sent successfully");
            }
        }

        private static void DoSetServiceName()
        {
            var newName = AnsiConsole.Prompt(
                new TextPrompt<string>("Enter new service name:")
                    .DefaultValue(CurrentServiceName)
                    .Validate(name =>
                    {
                        if (string.IsNullOrWhiteSpace(name))
                            return ValidationResult.Error("Service name cannot be empty");
                        return ValidationResult.Success();
                    }));
            if (!string.Equals(newName, CurrentServiceName, StringComparison.Ordinal))
            {
                Log.Info("Service name changed: {0} -> {1}", CurrentServiceName, newName);
                CurrentServiceName = newName;
            }
            else
            {
                Log.Info("Service name unchanged: {0}", CurrentServiceName);
            }
        }

        private static void RunTuiLoop()
        {
            while (true)
            {
                var choice = AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title($"[green]DBKKernelTest[/] — service [yellow]{CurrentServiceName}[/] — select an action:")
                        .PageSize(16)
                        .AddChoices(new[]
                        {
                            "Status",
                            "Set service name",
                            "Load driver",
                            "Load via loader",
                            "Unload driver",
                            "Get version",
                            "Custom inject (Thread)",
                            "Custom inject (MMap)",
                            "Custom inject (Apc)",
                            "Inject hello-world x86 (Thread)",
                            "Inject hello-world x64 (Thread)",
                            "Inject hello-world x86 (MMap)",
                            "Inject hello-world x64 (MMap)", 
                            "Inject hello-world x86 (Apc)",
                            "Inject hello-world x64 (Apc)",
                            "Inject Frida x86 (Thread)",
                            "Inject Frida x64 (Thread)",
                            "Inject Frida x86 (MMap)",
                            "Inject Frida x64 (MMap)",
                            "Inject Frida x86 (Apc)",
                            "Inject Frida x64 (Apc)",
                            "Exit"
                        }));

                switch (choice)
                {
                    case "Status":
                        ExecuteWithStatus("Checking service status", DoStatus);
                        break;
                    case "Set service name":
                        DoSetServiceName();
                        AnsiConsole.MarkupLine("[green]✔ Service name updated[/]");
                        break;
                    case "Load driver":
                    {
                        var path = AnsiConsole.Prompt(
                            new TextPrompt<string>("Driver path (leave empty to use local 'dea64.sys'):")
                                .AllowEmpty());
                        ExecuteWithStatus("Loading driver", () => DoLoad(string.IsNullOrWhiteSpace(path) ? null : path));
                        break;
                    }
                    case "Load via loader":
                    {
                        var path = AnsiConsole.Prompt(
                            new TextPrompt<string>("Driver path (leave empty to use local 'dea64.sys'):")
                                .AllowEmpty());
                        ExecuteWithStatus("Loading driver via loader", () => DoLoadWithLoader(string.IsNullOrWhiteSpace(path) ? null : path));
                        break;
                    }
                    case "Unload driver":
                        ExecuteWithStatus("Unloading driver", DoUnload);
                        break;
                    case "Get version":
                        ExecuteWithStatus("Querying version", DoVersion);
                        break;
                    case "Custom inject (Thread)":
                    {
                        int pid = AnsiConsole.Prompt(new TextPrompt<int>("Target PID:").Validate(p => p > 0 ? ValidationResult.Success() : ValidationResult.Error("PID must be > 0")));
                        var path = AnsiConsole.Prompt(new TextPrompt<string>("DLL path (leave empty to auto-pick hello-world):").AllowEmpty());
                        ExecuteWithStatus("Custom inject via Thread", () => DoCustomInject(pid, string.IsNullOrWhiteSpace(path) ? null : path, DBKDriver.InjectType.IT_Thread));
                        break;
                    }
                    case "Custom inject (MMap)":
                    {
                        int pid = AnsiConsole.Prompt(new TextPrompt<int>("Target PID:").Validate(p => p > 0 ? ValidationResult.Success() : ValidationResult.Error("PID must be > 0")));
                        var path = AnsiConsole.Prompt(new TextPrompt<string>("DLL path (leave empty to auto-pick hello-world):").AllowEmpty());
                        ExecuteWithStatus("Custom inject via MMap", () => DoCustomInject(pid, string.IsNullOrWhiteSpace(path) ? null : path, DBKDriver.InjectType.IT_MMap));
                        break;
                    }
                    case "Custom inject (Apc)":
                    {
                        int pid = AnsiConsole.Prompt(new TextPrompt<int>("Target PID:").Validate(p => p > 0 ? ValidationResult.Success() : ValidationResult.Error("PID must be > 0")));
                        var path = AnsiConsole.Prompt(new TextPrompt<string>("DLL path (leave empty to auto-pick hello-world):").AllowEmpty());
                        ExecuteWithStatus("Custom inject via Apc", () => DoCustomInject(pid, string.IsNullOrWhiteSpace(path) ? null : path, DBKDriver.InjectType.IT_Apc));
                        break;
                    }
                    case "Inject hello-world x86 (Thread)":
                        ExecuteWithStatus("Inject hello-world x86 via Thread", () => DoInject(false, GetHelloWorldDll(false), DBKDriver.InjectType.IT_Thread));
                        break;
                    case "Inject hello-world x64 (Thread)":
                        ExecuteWithStatus("Inject hello-world x64 via Thread", () => DoInject(true, GetHelloWorldDll(true), DBKDriver.InjectType.IT_Thread));
                        break;
                    case "Inject hello-world x86 (MMap)":
                        ExecuteWithStatus("Inject hello-world x86 via MMap", () => DoInject(false, GetHelloWorldDll(false), DBKDriver.InjectType.IT_MMap));
                        break;
                    case "Inject hello-world x64 (MMap)":
                        ExecuteWithStatus("Inject hello-world x64 via MMap", () => DoInject(true, GetHelloWorldDll(true), DBKDriver.InjectType.IT_MMap));
                        break;
                    case "Inject hello-world x86 (Apc)":
                        ExecuteWithStatus("Inject hello-world x86 via Apc", () => DoInject(false, GetHelloWorldDll(false), DBKDriver.InjectType.IT_Apc));
                        break;
                    case "Inject hello-world x64 (Apc)":
                        ExecuteWithStatus("Inject hello-world x64 via Apc", () => DoInject(true, GetHelloWorldDll(true), DBKDriver.InjectType.IT_Apc));
                        break;
                    case "Inject Frida x86 (Thread)":
                        ExecuteWithStatus("Inject Frida x86 via Thread", () => DoInject(false, GetFridaDll(false), DBKDriver.InjectType.IT_Thread));
                        break;
                    case "Inject Frida x64 (Thread)":
                        ExecuteWithStatus("Inject Frida x64 via Thread", () => DoInject(true, GetFridaDll(true), DBKDriver.InjectType.IT_Thread));
                        break;
                    case "Inject Frida x86 (MMap)":
                        ExecuteWithStatus("Inject Frida x86 via MMap", () => DoInject(false, GetFridaDll(false), DBKDriver.InjectType.IT_MMap));
                        break;
                    case "Inject Frida x64 (MMap)":
                        ExecuteWithStatus("Inject Frida x64 via MMap", () => DoInject(true, GetFridaDll(true), DBKDriver.InjectType.IT_MMap));
                        break;
                    case "Inject Frida x86 (Apc)":
                        ExecuteWithStatus("Inject Frida x86 via Apc", () => DoInject(false, GetFridaDll(false), DBKDriver.InjectType.IT_Apc));
                        break;
                    case "Inject Frida x64 (Apc)":
                        ExecuteWithStatus("Inject Frida x64 via Apc", () => DoInject(true, GetFridaDll(true), DBKDriver.InjectType.IT_Apc));
                        break;
                    case "Exit":
                        AnsiConsole.MarkupLine("[yellow]Bye![/]");
                        return;
                }
            }
        }

        private static void ExecuteWithStatus(string description, Action action)
        {
            try
            {
                AnsiConsole.Status()
                    .Spinner(Spinner.Known.Dots)
                    .Start(description, _ => { action(); });
                AnsiConsole.MarkupLine($"[green]✔ {description}[/]");
            }
            catch (Exception ex)
            {
                Log.Error("Operation failed: {0}", ex.Message);
                AnsiConsole.MarkupLine($"[red]✖ {description}: {Markup.Escape(ex.Message)}[/]");
            }
        }

        private static void DumpEnvironment()
        {
            var proc = Process.GetCurrentProcess();
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);

            var table = new Table().Border(TableBorder.Rounded).Title("[yellow]Runtime / Process Info[/]");
            table.AddColumn("Key");
            table.AddColumn("Value");
            table.AddRow("PID", proc.Id.ToString());
            table.AddRow("ProcessName", SafeProcessName(proc));
            table.AddRow("StartTime", Safe(() => proc.StartTime.ToString("u")) ?? "");
            table.AddRow("ExePath", Safe(() => proc.MainModule?.FileName) ?? "");
            table.AddRow("CmdLine", Environment.CommandLine);
            table.AddRow("Args", string.Join(", ", Environment.GetCommandLineArgs().Select(QuoteIfNeeded)));
            table.AddRow("MachineName", Environment.MachineName);
            table.AddRow("User", $"{Environment.UserDomainName}\\{Environment.UserName}");
            table.AddRow("WindowsIdentity", identity.Name);
            table.AddRow("IsAdmin", principal.IsInRole(WindowsBuiltInRole.Administrator).ToString());
            table.AddRow("IsSystem", identity.IsSystem.ToString());
            table.AddRow("OSVersion", Environment.OSVersion.ToString());
            table.AddRow("64bitOS", Environment.Is64BitOperatingSystem.ToString());
            table.AddRow("64bitProcess", Environment.Is64BitProcess.ToString());
            table.AddRow("CLRVersion", Environment.Version.ToString());
            table.AddRow("CurrentDirectory", Environment.CurrentDirectory);
            table.AddRow("BaseDirectory", AppDomain.CurrentDomain.BaseDirectory);
            table.AddRow("ProcessorCount", Environment.ProcessorCount.ToString());
            table.AddRow("SystemPageSize", Environment.SystemPageSize.ToString());
            table.AddRow("Culture", CultureInfo.CurrentCulture.ToString());
            table.AddRow("UICulture", CultureInfo.CurrentUICulture.ToString());
            table.AddRow("ServiceName", CurrentServiceName);
            table.AddRow("DevicePath", GetDeviceDosName());
            table.AddRow("Time", $"{DateTime.Now:O} (Local), {DateTime.UtcNow:O} (UTC)");
            AnsiConsole.Write(table);

            Log.Info("-- Runtime/Process Info --");
            Log.Info($"PID={proc.Id}");
            Log.Info($"ProcessName='{SafeProcessName(proc)}', StartTime={Safe(() => proc.StartTime.ToString("u"))}");
            Log.Info($"ExePath='{Safe(() => proc.MainModule?.FileName)}'");
            Log.Info($"CmdLine='{Environment.CommandLine}'");
            Log.Info($"Args=[{string.Join(", ", Environment.GetCommandLineArgs().Select(QuoteIfNeeded))}]");
            Log.Info($"MachineName='{Environment.MachineName}', User='{Environment.UserDomainName}\\{Environment.UserName}'");
            Log.Info($"WindowsIdentity='{identity.Name}', IsAdmin={principal.IsInRole(WindowsBuiltInRole.Administrator)}, IsSystem={identity.IsSystem}");
            Log.Info($"OSVersion='{Environment.OSVersion}', 64bitOS={Environment.Is64BitOperatingSystem}, 64bitProcess={Environment.Is64BitProcess}");
            Log.Info($"CLRVersion={Environment.Version}");
            Log.Info($"CurrentDirectory='{Environment.CurrentDirectory}', BaseDirectory='{AppDomain.CurrentDomain.BaseDirectory}'");
            Log.Info($"ProcessorCount={Environment.ProcessorCount}, SystemPageSize={Environment.SystemPageSize}");
            Log.Info($"Culture={CultureInfo.CurrentCulture} UI={CultureInfo.CurrentUICulture}");
            Log.Info($"Time={DateTime.Now:O} (Local), {DateTime.UtcNow:O} (UTC)");
        }

        private static T Safe<T>(Func<T> getter)
        {
            try
            {
                return getter();
            }
            catch
            {
                return default!;
            }
        }

        private static string QuoteIfNeeded(string s)
        {
            if (string.IsNullOrEmpty(s)) return "\"\"";
            return s.Contains(' ') || s.Contains('\"') ? '"' + s.Replace("\"", "\\\"") + '"' : s;
        }

        private static string SafeProcessName(Process? p)
        {
            if (p == null) return "";
            try
            {
                return p.ProcessName;
            }
            catch
            {
                return "?";
            }
        }

        private static Process? GetProcessSafe(int pid)
        {
            try
            {
                return Process.GetProcessById(pid);
            }
            catch
            {
                return null;
            }
        }
    }
}