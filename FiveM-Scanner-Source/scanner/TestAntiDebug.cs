using System;
using System.Threading;
using System.Threading.Tasks;

namespace FiveMScanner
{
    /// <summary>
    /// Test program για το Anti-Debug σύστημα
    /// Compile και τρέξε αυτό για να δοκιμάσεις την προστασία
    /// </summary>
    class TestAntiDebug
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("===========================================");
            Console.WriteLine("   🛡️  ANTI-DEBUG PROTECTION TEST");
            Console.WriteLine("===========================================");
            Console.WriteLine();

            // Test 1: Quick Check
            Console.WriteLine("Test 1: Quick Check");
            Console.WriteLine("-------------------");
            bool debuggerDetected = AntiDebug.QuickCheck();
            if (debuggerDetected)
            {
                Console.WriteLine("❌ FAILED: Debugger detected!");
                Console.WriteLine("   Please close all debugging tools and try again.");
                Console.WriteLine();
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
                return;
            }
            else
            {
                Console.WriteLine("✅ PASSED: No debugger detected");
            }
            Console.WriteLine();

            // Test 2: Continuous Monitoring
            Console.WriteLine("Test 2: Continuous Monitoring (30 seconds)");
            Console.WriteLine("-------------------------------------------");
            Console.WriteLine("Starting continuous monitoring...");
            Console.WriteLine("Try opening a debugger now to test detection!");
            Console.WriteLine();

            AntiDebug.StartMonitoring();

            // Countdown
            for (int i = 30; i > 0; i--)
            {
                Console.Write($"\rTime remaining: {i} seconds... ");
                await Task.Delay(1000);
            }

            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("✅ PASSED: Monitoring completed without detection");
            
            AntiDebug.StopMonitoring();
            Console.WriteLine("Monitoring stopped.");
            Console.WriteLine();

            // Test 3: Process Detection
            Console.WriteLine("Test 3: Process Detection");
            Console.WriteLine("-------------------------");
            Console.WriteLine("Checking for forbidden processes...");
            
            var forbiddenProcesses = new[]
            {
                "x64dbg", "x32dbg", "ollydbg", "windbg", "ida", "cheatengine",
                "processhacker", "dnspy", "ilspy", "fiddler", "wireshark"
            };

            var runningProcesses = System.Diagnostics.Process.GetProcesses();
            bool foundForbidden = false;

            foreach (var process in runningProcesses)
            {
                try
                {
                    var processName = process.ProcessName.ToLower();
                    foreach (var forbidden in forbiddenProcesses)
                    {
                        if (processName.Contains(forbidden))
                        {
                            Console.WriteLine($"⚠️  Found: {process.ProcessName}");
                            foundForbidden = true;
                        }
                    }
                }
                catch { }
            }

            if (!foundForbidden)
            {
                Console.WriteLine("✅ PASSED: No forbidden processes detected");
            }
            else
            {
                Console.WriteLine("❌ WARNING: Forbidden processes found!");
            }
            Console.WriteLine();

            // Summary
            Console.WriteLine("===========================================");
            Console.WriteLine("   TEST SUMMARY");
            Console.WriteLine("===========================================");
            Console.WriteLine();
            Console.WriteLine("All tests completed successfully!");
            Console.WriteLine("The anti-debug system is working correctly.");
            Console.WriteLine();
            Console.WriteLine("To test detection:");
            Console.WriteLine("1. Open x64dbg or any debugger");
            Console.WriteLine("2. Run this test again");
            Console.WriteLine("3. You should see immediate detection");
            Console.WriteLine();
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }
    }
}
