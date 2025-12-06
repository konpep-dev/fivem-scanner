using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using System.Management;

namespace FiveMScanner
{
    public class AntiDebug
    {
        // P/Invoke declarations
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern bool IsDebuggerPresent();

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

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

        // Known debugger and analysis tool process names
        private static readonly string[] ForbiddenProcesses = new[]
        {
            // Debuggers
            "x64dbg", "x32dbg", "ollydbg", "windbg", "ida", "ida64", "idaq", "idaq64", "idaw", "idaw64",
            "immunitydebugger", "debugview", "procmon", "procmon64", "procexp", "procexp64",
            
            // Disassemblers
            "ghidra", "binaryninja", "hopper", "radare2", "cutter",
            
            // .NET Tools
            "dnspy", "ilspy", "dotpeek", "dotpeek64", "dotpeek32", "justdecompile",
            
            // Memory Editors
            "cheatengine-x86_64", "cheatengine-i386", "cheatengine", "artmoney", "scanmem",
            
            // Process Tools
            "processhacker", "processhacker2", "systemexplorer", "processexplorer",
            
            // Network Analyzers
            "fiddler", "wireshark", "charles", "burpsuite", "mitmproxy",
            
            // Sandboxes & VMs
            "vboxservice", "vmtoolsd", "vmwaretray", "vmwareuser", "vmsrvc", "vmusrvc",
            "xenservice", "qemu-ga", "prl_tools", "prl_cc",
            
            // API Monitors
            "apimonitor", "apimonitor-x64", "apimonitor-x86", "rohitab",
            
            // Injection Tools
            "xenos", "extreme injector", "dll injector", "process hacker",
            
            // Reverse Engineering
            "pe-bear", "pestudio", "exeinfope", "die", "detect it easy", "cff explorer"
        };

        // Known debugger window titles
        private static readonly string[] ForbiddenWindowTitles = new[]
        {
            "x64dbg", "x32dbg", "ollydbg", "immunity debugger", "windbg", "ida",
            "ghidra", "binary ninja", "dnspy", "ilspy", "dotpeek", "cheat engine",
            "process hacker", "fiddler", "wireshark", "apimonitor"
        };

        private static bool _isRunning = false;
        private static CancellationTokenSource _cancellationTokenSource;

        public static void StartMonitoring()
        {
            if (_isRunning)
                return;

            _isRunning = true;
            _cancellationTokenSource = new CancellationTokenSource();

            // Start continuous monitoring in background
            Task.Run(() => MonitoringLoop(_cancellationTokenSource.Token));
        }

        public static void StopMonitoring()
        {
            _isRunning = false;
            _cancellationTokenSource?.Cancel();
        }

        private static async Task MonitoringLoop(CancellationToken cancellationToken)
        {
            Console.WriteLine("🛡️  Anti-Debug protection activated");
            
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    // Check 1: IsDebuggerPresent
                    if (IsDebuggerPresent())
                    {
                        OnDebuggerDetected("IsDebuggerPresent() returned true");
                        return;
                    }

                    // Check 2: CheckRemoteDebuggerPresent
                    bool isDebuggerPresent = false;
                    CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
                    if (isDebuggerPresent)
                    {
                        OnDebuggerDetected("Remote debugger detected");
                        return;
                    }

                    // Check 3: NtQueryInformationProcess (check for debug port)
                    if (CheckDebugPort())
                    {
                        OnDebuggerDetected("Debug port detected via NtQueryInformationProcess");
                        return;
                    }

                    // Check 4: Forbidden processes
                    if (CheckForbiddenProcesses())
                    {
                        return; // Already handled in method
                    }

                    // Check 5: Parent process check (detect if launched from debugger)
                    if (CheckParentProcess())
                    {
                        OnDebuggerDetected("Suspicious parent process detected");
                        return;
                    }

                    // Check 6: Timing check (debuggers slow down execution)
                    if (CheckTiming())
                    {
                        OnDebuggerDetected("Timing anomaly detected (possible debugger)");
                        return;
                    }

                    // Check 7: Hardware breakpoints
                    if (CheckHardwareBreakpoints())
                    {
                        OnDebuggerDetected("Hardware breakpoints detected");
                        return;
                    }

                    // Check 8: Window titles
                    if (CheckWindowTitles())
                    {
                        return; // Already handled in method
                    }

                    // Wait before next check (randomized to avoid pattern detection)
                    var delay = new Random().Next(2000, 5000); // 2-5 seconds
                    await Task.Delay(delay, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠️  Anti-Debug monitoring error: {ex.Message}");
                    await Task.Delay(5000, cancellationToken);
                }
            }

            Console.WriteLine("🛡️  Anti-Debug protection stopped");
        }

        private static bool CheckDebugPort()
        {
            try
            {
                var pbi = new PROCESS_BASIC_INFORMATION();
                int returnLength;
                int status = NtQueryInformationProcess(
                    Process.GetCurrentProcess().Handle,
                    7, // ProcessDebugPort
                    ref pbi,
                    Marshal.SizeOf(pbi),
                    out returnLength
                );

                return pbi.Reserved1 != IntPtr.Zero;
            }
            catch
            {
                return false;
            }
        }

        private static bool CheckForbiddenProcesses()
        {
            try
            {
                var runningProcesses = Process.GetProcesses();
                
                foreach (var process in runningProcesses)
                {
                    try
                    {
                        var processName = process.ProcessName.ToLower();
                        
                        foreach (var forbidden in ForbiddenProcesses)
                        {
                            if (processName.Contains(forbidden.ToLower()))
                            {
                                OnDebuggerDetected($"Forbidden process detected: {process.ProcessName}");
                                return true;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return false;
        }

        private static bool CheckParentProcess()
        {
            try
            {
                var currentProcess = Process.GetCurrentProcess();
                var parentProcessId = GetParentProcessId(currentProcess.Id);
                
                if (parentProcessId > 0)
                {
                    var parentProcess = Process.GetProcessById(parentProcessId);
                    var parentName = parentProcess.ProcessName.ToLower();
                    
                    // Check if parent is a debugger
                    var suspiciousParents = new[] { "x64dbg", "x32dbg", "ollydbg", "windbg", "ida", "dnspy", "ilspy" };
                    
                    if (suspiciousParents.Any(s => parentName.Contains(s)))
                    {
                        return true;
                    }
                }
            }
            catch { }

            return false;
        }

        private static int GetParentProcessId(int processId)
        {
            try
            {
                using (var query = new ManagementObjectSearcher($"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {processId}"))
                {
                    foreach (ManagementObject obj in query.Get())
                    {
                        return Convert.ToInt32(obj["ParentProcessId"]);
                    }
                }
            }
            catch { }

            return -1;
        }

        private static bool CheckTiming()
        {
            try
            {
                var sw = Stopwatch.StartNew();
                
                // Simple operation that should be very fast
                var dummy = 0;
                for (int i = 0; i < 100; i++)
                {
                    dummy += i;
                }
                
                sw.Stop();
                
                // If this takes more than 10ms, something is slowing us down (likely a debugger)
                if (sw.ElapsedMilliseconds > 10)
                {
                    return true;
                }
            }
            catch { }

            return false;
        }

        private static bool CheckHardwareBreakpoints()
        {
            try
            {
                // Check debug registers (DR0-DR3, DR6, DR7)
                // This is a simplified check - full implementation would use GetThreadContext
                var context = new CONTEXT();
                context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                
                if (GetThreadContext(GetCurrentThread(), ref context))
                {
                    // Check if any debug registers are set
                    if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0)
                    {
                        return true;
                    }
                }
            }
            catch { }

            return false;
        }

        private static bool CheckWindowTitles()
        {
            try
            {
                var currentProcess = Process.GetCurrentProcess();
                var allProcesses = Process.GetProcesses();

                foreach (var process in allProcesses)
                {
                    try
                    {
                        if (process.Id == currentProcess.Id)
                            continue;

                        var windowTitle = process.MainWindowTitle.ToLower();
                        
                        if (string.IsNullOrEmpty(windowTitle))
                            continue;

                        foreach (var forbidden in ForbiddenWindowTitles)
                        {
                            if (windowTitle.Contains(forbidden.ToLower()))
                            {
                                OnDebuggerDetected($"Forbidden window detected: {process.MainWindowTitle}");
                                return true;
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return false;
        }

        private static void OnDebuggerDetected(string reason)
        {
            Console.WriteLine($"🚨 DEBUGGER DETECTED: {reason}");
            Console.WriteLine("🚨 The scanner cannot run while debugging tools are active.");
            Console.WriteLine("🚨 Please close all debugging/analysis tools and try again.");
            Console.WriteLine();
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
            Environment.Exit(1);
        }

        // Additional P/Invoke for hardware breakpoint detection
        private const uint CONTEXT_DEBUG_REGISTERS = 0x00010010;

        [StructLayout(LayoutKind.Sequential)]
        private struct CONTEXT
        {
            public uint ContextFlags;
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
            // ... other fields omitted for brevity
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

        // Quick check method for one-time validation
        public static bool QuickCheck()
        {
            // Quick checks without continuous monitoring
            if (IsDebuggerPresent())
                return true;

            bool isDebuggerPresent = false;
            CheckRemoteDebuggerPresent(Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
            if (isDebuggerPresent)
                return true;

            if (CheckDebugPort())
                return true;

            if (CheckForbiddenProcesses())
                return true;

            return false;
        }
    }
}
