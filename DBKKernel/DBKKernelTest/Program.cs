using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using EyeAuras.Memory.KD.Internal;

namespace DBKKernelTest
{
    internal static class Program
    {
        private const string ServiceName = "EADBKSVC73";

        private const string DeviceDosName = $"\\\\.\\{ServiceName}"; // maps to \DosDevices\dea64

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

                // Option-driven interface
                string option = args != null && args.Length > 0 ? (args[0] ?? string.Empty) : string.Empty;
                option = option.Trim().ToLowerInvariant();

                switch (option)
                {
                    case "b":
                    case "load":
                        DoLoad(args.Length > 1 ? args[1] : null);
                        break;
                    case "c":
                    case "loader":
                    case "loadwithloader":
                        DoLoadWithLoader(args.Length > 1 ? args[1] : null);
                        break;
                    case "unload":
                        DoUnload();
                        break;
                    case "d":
                    case "version":
                        DoVersion();
                        break;
                    case "2":
                    case "injectx86":
                        DoInject(isX64:false);
                        break;
                    case "3":
                    case "injectx64":
                        DoInject(isX64:true);
                        break;
                    case "a":
                    case "status":
                        DoStatus();
                        break;
                    case "":
                        // Interactive menu
                        while (true)
                        {
                            PrintUsage();
                            Console.Write("Select option: ");
                            string input = (Console.ReadLine() ?? string.Empty).Trim();
                            if (string.IsNullOrEmpty(input)) continue;
                            string cmd;
                            string arg = null;
                            int sp = input.IndexOf(' ');
                            if (sp >= 0)
                            {
                                cmd = input.Substring(0, sp).Trim().ToLowerInvariant();
                                arg = input.Substring(sp + 1).Trim();
                            }
                            else
                            {
                                cmd = input.ToLowerInvariant();
                            }

                            try
                            {
                                switch (cmd)
                                {
                                    case "a":
                                    case "status":
                                        DoStatus();
                                        break;
                                    case "b":
                                    case "load":
                                        DoLoad(arg);
                                        break;
                                    case "c":
                                    case "loader":
                                    case "loadwithloader":
                                        DoLoadWithLoader(arg);
                                        break;
                                    case "d":
                                    case "unload":
                                        DoUnload();
                                        break;
                                    case "1":
                                    case "version":
                                        DoVersion();
                                        break;
                                    case "2":
                                    case "injectx86":
                                        DoInject(isX64:false);
                                        break;
                                    case "3":
                                    case "injectx64":
                                        DoInject(isX64:true);
                                        break; 
                                    case "4":
                                        DoInjectViaManualMap(isX64:false);
                                        break;
                                    case "5":
                                        DoInjectViaManualMap(isX64:true);
                                        break;
                                    case "x":
                                    case "q":
                                    case "quit":
                                    case "exit":
                                        return;
                                    default:
                                        PrintUsage();
                                        break;
                                }
                            }
                            catch (Exception ex)
                            {
                                Log.Error("Operation failed: {0}", ex.Message);
                            }
                        }

                        break;
                    default:
                        PrintUsage();
                        Environment.ExitCode = 1;
                        break;
                }

                Log.Info("DBKKernelTest finished successfully");
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
            sm.PrintStatus(ServiceName);
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
            sm.Load(ServiceName, driverPath);
        }

        private static void DoLoadWithLoader(string pathArg)
        {
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            string driverPath = pathArg;
            if (string.IsNullOrWhiteSpace(driverPath))
                driverPath = Path.Combine(exeDir, LocalDriverFileName);
            driverPath = Path.GetFullPath(driverPath);

            LoaderInvoker.LoadWithLoader(exeDir, driverPath, ServiceName, Log);
        }

        private static void DoUnload()
        {
            var sm = new ServiceManager(Log);
            sm.Unload(ServiceName);
        }

        private static void DoVersion()
        {
            using (var driver = new DBKDriver(DeviceDosName))
            {
                driver.Open();
                int version = driver.GetVersion();
                Log.Info("Driver version: {0}", version);
            }
        }
        
        private static void DoInject(bool isX64)
        {
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            string agentExe = Path.Combine(exeDir, isX64 ? "EyeAuras.Agent.NetHost.x64.exe" : "EyeAuras.Agent.NetHost.x86.exe");
            string dllPath = Path.Combine(exeDir, isX64 ? "hello-world-x64.dll" : "hello-world-x86.dll");

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

                using (var driver = new DBKDriver(DeviceDosName))
                {
                    driver.Open();
                    Log.Info("Injecting {0} into PID {1} via Thread", Path.GetFileName(dllPath), proc.Id);
                    driver.InjectDll(proc.Id, dllPath);
                    Log.Info("Injection request sent successfully");
                }

                Log.Info("Leaving agent running. Close it manually if desired.");
            }
        }
        
        private static void DoInjectViaManualMap(bool isX64)
        {
            string exeDir = AppDomain.CurrentDomain.BaseDirectory;
            string agentExe = Path.Combine(exeDir, isX64 ? "EyeAuras.Agent.NetHost.x64.exe" : "EyeAuras.Agent.NetHost.x86.exe");
            string dllPath = Path.Combine(exeDir, isX64 ? "hello-world-x64.dll" : "hello-world-x86.dll");

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

                using (var driver = new DBKDriver(DeviceDosName))
                {
                    driver.Open();
                    Log.Info("Injecting {0} into PID {1} via MMap", Path.GetFileName(dllPath), proc.Id);
                    driver.InjectDll(proc.Id, dllPath, DBKDriver.InjectType.IT_MMap);
                    Log.Info("Injection request sent successfully");
                }

                Log.Info("Leaving agent running. Close it manually if desired.");
            }
        }
        
        private static void PrintUsage()
        {
            Log.Info("DBKKernelTest options:");
            Log.Info("  (Run without arguments to open interactive menu)");
            Log.Info("  a | status           - Print service status and driver file info");
            Log.Info("  b | load [path]      - Create/Update service with driver and start it");
            Log.Info("  c | loader           - Load using loader");
            Log.Info("  d | unload           - Stop service and delete it");
            Log.Info("  1 | version          - Query version via DBKDriver");
            Log.Info("  2 | injectx86          - Launch x86 Agent and inject hello-world-x86.dll via Thread");
            Log.Info("  3 | injectx64          - Launch x64 Agent and inject hello-world-x64.dll via Thread");
            Log.Info("  4                      - Launch x86 Agent and inject hello-world-x64.dll via MMap");
            Log.Info("  5                      - Launch x64 Agent and inject hello-world-x64.dll via MMap");
        }
        
        private static void DumpEnvironment()
        {
            var proc = Process.GetCurrentProcess();
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);

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