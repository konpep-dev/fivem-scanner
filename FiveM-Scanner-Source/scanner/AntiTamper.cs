using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Reflection;
using System.Linq;

namespace FiveMScanner
{
    public static class AntiTamper
    {
        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, ref int returnLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebBaseAddress;
            public IntPtr Reserved2_0;
            public IntPtr Reserved2_1;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        private static bool _isMonitoring = false;

        public static void Initialize()
        {
            // Only check for active debuggers, not cracking tools
            // (cracking tools might be running for legitimate reasons)
            if (DetectDebugger())
            {
                Environment.FailFast("Security violation detected.");
            }

            // Start continuous monitoring (only for debuggers)
            StartMonitoring();
        }

        private static bool DetectDebugger()
        {
            // Check 1: IsDebuggerPresent
            if (IsDebuggerPresent())
                return true;

            // Check 2: CheckRemoteDebuggerPresent
            bool isDebuggerPresent = false;
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
            if (isDebuggerPresent)
                return true;

            // Check 3: Debugger.IsAttached
            if (Debugger.IsAttached)
                return true;

            // Check 4: NtQueryInformationProcess
            try
            {
                PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
                int returnLength = 0;
                int status = NtQueryInformationProcess(Process.GetCurrentProcess().Handle, 0, ref pbi, Marshal.SizeOf(pbi), ref returnLength);
                
                if (status == 0 && pbi.PebBaseAddress != IntPtr.Zero)
                {
                    byte[] data = new byte[1];
                    // Additional PEB checks could be done here
                }
            }
            catch { }

            return false;
        }

        private static bool DetectCrackingTools()
        {
            string[] blacklistedProcesses = new[]
            {
                "ollydbg", "x64dbg", "x32dbg", "windbg", "ida", "ida64",
                "idaq", "idaq64", "idaw", "idaw64", "idag", "idag64",
                "scylla", "scylla_x64", "scylla_x86", "protection_id",
                "importrec", "lordpe", "pestudio", "pe-bear", "hxd",
                "cheatengine", "cheatengine-x86_64", "cheatengine-i386",
                "processhacker", "procexp", "procexp64", "procmon", "procmon64",
                "fiddler", "wireshark", "httpdebugger", "dnspy", "ilspy",
                "dotpeek", "reflector", "de4dot", "megadumper", "extremedumper"
            };

            try
            {
                var processes = Process.GetProcesses();
                foreach (var process in processes)
                {
                    try
                    {
                        string processName = process.ProcessName.ToLower();
                        if (blacklistedProcesses.Any(bp => processName.Contains(bp)))
                        {
                            return true;
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return false;
        }

        private static void StartMonitoring()
        {
            if (_isMonitoring)
                return;

            _isMonitoring = true;

            // Start background thread for continuous monitoring
            Thread monitorThread = new Thread(() =>
            {
                while (_isMonitoring)
                {
                    try
                    {
                        // Only check for active debuggers
                        if (DetectDebugger())
                        {
                            Environment.FailFast("Security violation detected.");
                        }

                        // Check every 5 seconds (less aggressive)
                        Thread.Sleep(5000);
                    }
                    catch { }
                }
            })
            {
                IsBackground = true,
                Priority = ThreadPriority.BelowNormal
            };

            monitorThread.Start();
        }

        public static void StopMonitoring()
        {
            _isMonitoring = false;
        }

        // Integrity check for the assembly
        public static bool VerifyIntegrity()
        {
            try
            {
                var assembly = Assembly.GetExecutingAssembly();
                var assemblyName = assembly.GetName();
                
                // Check if assembly has been tampered with
                if (assemblyName.Name != "AsyncScanner")
                    return false;

                // Additional integrity checks can be added here
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
