using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Linq;

namespace FiveMScanner
{
    public class CheatSignature
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        // New metadata fields to support scoring & modular rules
        public string RuleId { get; set; } = string.Empty;
        public int Weight { get; set; } = 50; // relative importance (0-100)
        public int Confidence { get; set; } = 50; // expected confidence (0-100)
        public Dictionary<string, string> Metadata { get; set; } = new Dictionary<string, string>();
        public List<string> FileNames { get; set; } = new List<string>();
        public List<string> FileSizes { get; set; } = new List<string>();
        public List<string> MD5Hashes { get; set; } = new List<string>();
        public List<string> SHA1Hashes { get; set; } = new List<string>();
        public List<string> SHA256Hashes { get; set; } = new List<string>();
        public List<string> Strings { get; set; } = new List<string>();
        public List<string> APIs { get; set; } = new List<string>();
        public List<string> DNS { get; set; } = new List<string>();
        public List<string> RegistryKeys { get; set; } = new List<string>();
        public List<string> ProcessNames { get; set; } = new List<string>();
        public List<string> FilePatterns { get; set; } = new List<string>();
        public string Severity { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
    }

    public static class CheatDatabase
    {
        // Legitimate FiveM Files (Whitelist) - Expanded to reduce false positives
        public static readonly HashSet<string> LegitimateFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            // FiveM Core Files
            "FiveM.exe",
            "FiveM_b2699_GTAProcess.exe",
            "FiveM_GTAProcess.exe",
            "FiveM_DumpServer.exe",
            "FiveM_SteamChild.exe",
            "FiveM_ChromeBrowser.exe",
            
            // FiveM DLLs
            "citizen-devtools.dll",
            "citizen-server-fxdk.dll",
            "citizen-resources-metadata-lua.dll",
            "citizen-scripting-core.dll",
            "citizen-scripting-lua.dll",
            "citizen-scripting-mono.dll",
            "citizen-scripting-v8.dll",
            "citizen-resources-client.dll",
            "citizen-resources-core.dll",
            "citizen-resources-gta.dll",
            "citizenfx-subprocess.exe",
            "fxcode.exe",
            
            // FiveM Launcher
            "FiveM_ChromeBrowser.exe",
            "FiveM_DumpServer.exe",
            "FiveM_SteamChild.exe",
            
            "TEKLauncher.exe",
            
            // GTA V Files
            "GTA5.exe",
            "GTAVLauncher.exe",
            "PlayGTAV.exe",
            
            // Rockstar Launcher
            "Launcher.exe",
            "LauncherPatcher.exe",
            "RockstarService.exe",
            "RockstarSteamHelper.exe",
            
            // Steam
            "steam.exe",
            "steamservice.exe",
            "steamerrorreporter.exe",
            "steamerrorreporter64.exe",
            "steamwebhelper.exe",
            
            // Epic Games
            "EpicGamesLauncher.exe",
            "EpicWebHelper.exe",
            
            // Common legitimate tools that might trigger false positives
            "node.exe",
            "python.exe",
            "pythonw.exe",
            "code.exe",
            "devenv.exe",
            "msbuild.exe",
            "dotnet.exe",
            "git.exe",
            "chrome.exe",
            "firefox.exe",
            "discord.exe",
            "obs64.exe",
            "obs32.exe",
            "nvidia-smi.exe",
            "nvcontainer.exe"
        };

        // Anti-Debug Processes
        public static readonly HashSet<string> ForbiddenProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "cheatengine-x86_64.exe", "cheatengine-i386.exe", "processhacker.exe",
            "x64dbg.exe", "x32dbg.exe", "ida64.exe", "ida.exe", "ghidrarun.bat",
            "dotpeek64.exe", "dotpeek32.exe", "dnspy.exe", "fiddler.exe"
        };

        // Suspicious Keywords (For FILE and PROCESS scanning ONLY - NOT for URLs/domains)
        public static readonly List<string> SuspiciousKeywords = new List<string>
        {
            // Loaders & Injectors
            "dll inject", "process inject", "xenos injector", "extreme injector", "manual map injector",
            
            // Bypass & Spoofers
            "hwid spoof", "eac bypass", "be bypass", "vac bypass", "anticheat bypass",
            
            // Cheat Types (specific terms only)
            "aimbot", "triggerbot", "wallhack esp", "norecoil", "nospread",
            
            // Known Cheat Executables (specific names)
            "eulencheats", "420cheats", "cherax.exe", "stand.exe", "midnight.exe",
            "2take1", "paragon.exe", "disturbed.exe", "ozark.exe", "kiddions",
            "keyser.exe", "skript.gg", "hxcheats", "tzproject", "testo.exe",
            "gosth.exe", "redengine.exe", "susano.re", "anonhax", "desudo",
            
            // Tools
            "cheatengine", "x64dbg", "dnspy", "processhacker",
            
            // Generic (very specific)
            "fivem cheat", "gta cheat", "mod menu", "cheat loader"
        };

        // Suspicious Domains (Expanded)
        public static readonly List<string> SuspiciousDomains = new List<string>
        {
            // Known Cheat Sites
            "420-services.net", "420cheats.com", "eulencheats.com", "redengine.net",
            "skript.gg", "keyser.gg", "hxcheats.com", "tzproject.com", "susano.re",
            
            // Cheat Forums & Marketplaces
            "unknowncheats.me", "mpgh.net", "elitepvpers.com", "cheatengine.org",
            "wemod.com", "fling-trainer.com",
            
            // GTA/FiveM Specific
            "gta5-mods.com/tools", "fivem-cheats.com", "gtacheats.com",
            
            // Generic Cheat Sites
            "aimbot.net", "wallhacks.com", "esp-cheats.com", "game-hacks.com",
            "cheat-happens.com", "cheatautomation.com"
        };

        // DPS Suspicious Strings
        public static readonly List<string> DPSSuspiciousStrings = new List<string>
        {
            "!Manuelen pc check!", "0x1256000", "0xf15000", "420 spoofer",
            "88cheats test", "Anti-SS Tool", "Asgard", "Astaroth Bypass",
            "Cheat #1", "Cutie External", "Degeo", "Eulen Cracked",
            "Eulen FiveM Cheat", "External Cheat FiveM", "Gosth", "HXHider",
            "HXSoftwares", "Katana", "Monster FiveM Cheat", "Red Engine FiveM Cheat",
            "Redengine", "Skript", "Skript FiveM Cheat", "Skript.gg",
            "Susano.re", "TZX", "Testo", "VPN FOUND", "eulen new",
            "https://hxcheats.com/usercp/loader.exe", "https://tzproject.com",
            "loader.exe", "sicario", "skrippt.gg", "taskhostw tzx", "testo"
        };

        // PCASVC Suspicious Strings Map
        public static readonly Dictionary<string, string> PCASVCSuspiciousStringsMap = new Dictionary<string, string>
        {
            { "Asgard", "0x73c8000" },
            { "Bionic", "0x364000" },
            { "Cheats.cx", "0xd7000" },
            { "DegeoPremium", "0x9a000" },
            { "Eulen", "0x2b78000" },
            { "Gosth", "0x2e1f000" },
            { "RedEngine", "0x27ed000" },
            { "TestoGG", "0x2e1f000" },
            { "TZProject", "0x1c9000" }
        };

        // Journal and MFT Scan Paths
        public static readonly List<string> JournalScanPaths = new List<string>
        {
            "Downloads",
            "Desktop",
            "Windows\\Temp",
            "ProgramData"
        };

        // Critical Functions to Check for Hooks
        public static readonly Dictionary<string, List<string>> CriticalFunctionsToCheck = new Dictionary<string, List<string>>
        {
            { "ntdll.dll", new List<string> { "NtReadVirtualMemory", "NtWriteVirtualMemory", "NtProtectVirtualMemory", "NtQuerySystemInformation", "NtOpenProcess" } },
            { "kernel32.dll", new List<string> { "ReadProcessMemory", "WriteProcessMemory", "VirtualProtectEx", "CreateRemoteThread", "OpenProcess" } },
            { "win32u.dll", new List<string> { "NtUserSendInput", "NtUserBlockInput" } },
            { "d3d11.dll", new List<string> { "D3D11CreateDeviceAndSwapChain" } }
        };

        public static List<CheatSignature> CheatSignatures = new List<CheatSignature>
        {
            // Susano Cheat
            new CheatSignature
            {
                Name = "Susano",
                Description = "Advanced FiveM cheat with HWID linking and self-deleting DLLs",
                FileNames = new List<string> { "hwid.exe", "Loader.exe" },
                FileSizes = new List<string> { "3016988" },
                MD5Hashes = new List<string> { "bd4cbadd5171915ed4a2384c92194c13" },
                SHA1Hashes = new List<string> { "f9fb86ec4b89d4e3c53260359eaa8317cdee8dd8" },
                SHA256Hashes = new List<string> { "ec27eadace5eb14daf23a567fe988db7d68234ea878563e5cf73b954b15cc6ec" },
                FilePatterns = new List<string> { "C:\\*[0-9a-zA-Z]*" },
                ProcessNames = new List<string> { "Tomato.exe" },
                Strings = new List<string> { "susano loader", "susano.re" },
                DNS = new List<string> { "susano.re" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Five Sharp Cheat
            new CheatSignature
            {
                Name = "Five Sharp",
                Description = "FiveM cheat with specific file size and strings",
                FileNames = new List<string> { "FS Update.exe" },
                FileSizes = new List<string> { "140800" },
                MD5Hashes = new List<string> { "bc21075501da1bdf1b4f96f2c73c2e44" },
                Strings = new List<string> { "DPS !2023/10/31:13:24:16", "PCASVC:  0x29000" },
                Severity = "High",
                Category = "Cheat Detection"
            },

            // HX Softwares Cheat
            new CheatSignature
            {
                Name = "HX Softwares",
                Description = "FiveM cheat with specific domains and DLL injection",
                FileNames = new List<string> { "loader.exe" },
                FileSizes = new List<string> { "2372459" },
                MD5Hashes = new List<string> { "9A976BE39AF68795A0447BF6E7C9EAA8" },
                SHA1Hashes = new List<string> { "37734057CAAE8191FF0E3CF81C6B3E3B9640748D" },
                SHA256Hashes = new List<string> { "F444E74BA61C8A95E6E241458506300B9533DD85176EBF99DE59C90164A441DE" },
                Strings = new List<string> { "LSASS.EXE: kzoem.hxcheats.com", "api.hxcheats.com" },
                DNS = new List<string> { "kzoem.hxcheats.com", "api.hxcheats.com" },
                FilePatterns = new List<string> { "Local/Temp", "imgui.ini" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Eulen Cheat
            new CheatSignature
            {
                Name = "Eulen",
                Description = "FiveM cheat with AWS API endpoints",
                FileNames = new List<string> { "loader_prod.exe" },
                FileSizes = new List<string> { "27669504" },
                MD5Hashes = new List<string> { "ba41431c69cb3a3a558b7d363ad5160c" },
                SHA1Hashes = new List<string> { "c981e506dd06d254c456b64fb01de3e5a73ee178" },
                SHA256Hashes = new List<string> { "ade6b6e09ec807df13e6128b48461ff279967f72bd12cfc777d7114e44b1219c" },
                APIs = new List<string> 
                { 
                    "ec2-3-235-182-72.compute-1.amazonaws.com",
                    "ec2-3-235-182-75.compute-1.amazonaws.com",
                    "ec2-3-235-182-71.compute-1.amazonaws.com",
                    "ec2-3-235-182-74.compute-1.amazonaws.com",
                    "ec2-3-235-182-76.compute-1.amazonaws.com",
                    "ec2-3-235-182-73.compute-1.amazonaws.com"
                },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // TZX/Tzproject Cheat
            new CheatSignature
            {
                Name = "TZX/Tzproject",
                Description = "FiveM cheat with specific domains and crash dumps",
                FileNames = new List<string> { "svchost.exe", "packages.json" },
                FileSizes = new List<string> { "6927872" },
                MD5Hashes = new List<string> { "241128850eff9fb7a3a846817bcc0e1e" },
                SHA1Hashes = new List<string> { "57d43aad8bd6144620b6398b3743e8fa03c6cfb2" },
                SHA256Hashes = new List<string> { "b0194498853f8ff587edaff8371ee221baec4c358b16db5316f3e40e786e0813" },
                Strings = new List<string> { "LSASS.EXE: api.tzproject.com", "tzproject.com", "taskhostw.exe" },
                DNS = new List<string> { "api.tzproject.com", "tzproject.com" },
                FilePatterns = new List<string> { "tzx", "crashdump" },
                Severity = "High",
                Category = "Cheat Detection"
            },

            // Red Engine Cheat
            new CheatSignature
            {
                Name = "Red Engine",
                Description = "FiveM cheat with dynamic file renaming and specific patterns",
                FileNames = new List<string> { "SuperNatural.exe", "settings.cock" },
                FileSizes = new List<string> { "19910656" },
                MD5Hashes = new List<string> { "d626cecd048187ee580a09c13636bd94" },
                SHA1Hashes = new List<string> { "fa988331bf2e8b9d932dc8992963e944f90a18f1" },
                SHA256Hashes = new List<string> { "92930068e9108a3099e4eaf56352e9ddb72b709783c78e3490b6167d7d5d4f8f" },
                Strings = new List<string> { "Settings.cock", "imgui.ini" },
                FilePatterns = new List<string> 
                { 
                    "seventiepresentmultiply.exe",
                    "hairsoftbluetrycottonbring.exe", 
                    "natureanylawrecordfewtie.exe",
                    "imgui.ini"
                },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Cheat/Bypass Scripts - Generic Free Cheat 1
            new CheatSignature
            {
                Name = "Generic Free Cheat 1",
                Description = "Generic free cheat with VMProtect protection",
                FileNames = new List<string> { "bypass_kom.exe" },
                FileSizes = new List<string> { "16914432" },
                MD5Hashes = new List<string> { "3aad217ebea2be75ba99ef28347a396b" },
                SHA1Hashes = new List<string> { "7aa59d606d41d01f1035dfc9fb057f1859d150f7" },
                SHA256Hashes = new List<string> { "f86f638ab81409a8fc4798bd8a025ddd2196dc6ec231d3b7f86b916e76996f00" },
                Strings = new List<string> { "VMProtect", "bypass", "cheat" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Cheat/Bypass Scripts - Generic Free Cheat 2
            new CheatSignature
            {
                Name = "Generic Free Cheat 2",
                Description = "Generic free cheat with VMProtect protection",
                FileNames = new List<string> { "generic_free_cheat_1.exe" },
                FileSizes = new List<string> { "16971264" },
                MD5Hashes = new List<string> { "26f1a7039ba43c8e1b1b0bd5677c7bee" },
                SHA1Hashes = new List<string> { "d6a7a2e49016a246ebdd507b9356433c41c4f07f" },
                SHA256Hashes = new List<string> { "d3ed9013eecfe118b2ead85c704a82c19f66e543fdbfd713de43a964f2d1aefd" },
                Strings = new List<string> { "VMProtect", "generic", "free", "cheat" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Cheat/Bypass Scripts - Generic Free Cheat 3
            new CheatSignature
            {
                Name = "Generic Free Cheat 3",
                Description = "Generic free cheat with VMProtect protection",
                FileNames = new List<string> { "generic_free_cheat_2.exe" },
                FileSizes = new List<string> { "20797952" },
                MD5Hashes = new List<string> { "754cb7c3b0f5b71845f27f8b8d900dea" },
                SHA1Hashes = new List<string> { "c7cfc3965caa1079629bce008d62ff3b2235bfa6" },
                SHA256Hashes = new List<string> { "65cd632f8245c54eabe0feb72bf66b593a0a47a72001c75324971507821b10a9" },
                Strings = new List<string> { "VMProtect", "generic", "free", "cheat" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Cheat/Bypass Scripts - InstallShield Setup
            new CheatSignature
            {
                Name = "Cheat/Bypass Scripts",
                Description = "Cheat/bypass scripts with InstallShield setup",
                FileNames = new List<string> { "cheat_bypass_scripts.exe" },
                FileSizes = new List<string> { "42387473" },
                MD5Hashes = new List<string> { "44fa3b7f9d1d22abf75f87f660b80d83" },
                SHA1Hashes = new List<string> { "09eba148fe71c9ec1758f5583e8fdcc20746dc7a" },
                SHA256Hashes = new List<string> { "fe0159687f4eff089e26b5079581b7e12072470e7042122814610457b0f6752d" },
                Strings = new List<string> { "InstallShield", "bypass", "cheat", "scripts" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // AnonHax Free Cheat
            new CheatSignature
            {
                Name = "AnonHax Free",
                Description = "AnonHax free cheat with interception library",
                FileNames = new List<string> { "anonhax_free.exe", "anonhax_free (1).exe", "anonhax_free _1_.exe" },
                FileSizes = new List<string> { "1142784" },
                MD5Hashes = new List<string> { "2122e1d201e9b1b6b3684d16f9e94ed4" },
                SHA1Hashes = new List<string> { "e74728677b15863e7339ed163ba5ccd983dd26d9" },
                SHA256Hashes = new List<string> { "9919a9e938468fcdc2d762dd5c68fde003b0dde933cdefd800a6abfc09243f01" },
                Strings = new List<string> { "interception_create_context", "interception_destroy_context", "interception_get_filter", "interception_get_hardware_id", "interception_get_precedence", "interception_is_invalid", "interception_is_keyboard", "interception_is_mouse", "interception_receive", "interception_send" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // 420 Services Cheat Archive
            new CheatSignature
            {
                Name = "420 Services Cheat",
                Description = "420 Services cheat archive with multiple variants",
                FileNames = new List<string> { "420services.rar", "420services (2).rar", "420services (1).rar", "ciganymodmenu.rar", "420services-1.rar", "Blue-FPS (2).rar" },
                FileSizes = new List<string> { "1784028" },
                MD5Hashes = new List<string> { "27a4d427dbd43c81d633835aadb08c75" },
                SHA1Hashes = new List<string> { "6eb03576dd0bf0df0c62a17b7af8aa83359dc8d3" },
                SHA256Hashes = new List<string> { "bfe7ed7db7a77389bcf4701a6ec41308abc9b1b22a91354ff4a3bccddf93a23b" },
                Strings = new List<string> { "420services", "ciganymodmenu", "Blue-FPS" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Additional Cheat Files
            new CheatSignature
            {
                Name = "Additional Cheat Files",
                Description = "Various cheat files and executables",
                FileNames = new List<string> { "fn cheat.exe", "trpup.exe", "9919a9e938468fcdc2d762dd5c68fde003b0dde933cdefd800a6abfc09243f01-dropped.bin" },
                FileSizes = new List<string> { "1142784" },
                MD5Hashes = new List<string> { "2122e1d201e9b1b6b3684d16f9e94ed4" },
                SHA1Hashes = new List<string> { "e74728677b15863e7339ed163ba5ccd983dd26d9" },
                SHA256Hashes = new List<string> { "9919a9e938468fcdc2d762dd5c68fde003b0dde933cdefd800a6abfc09243f01" },
                Strings = new List<string> { "fn cheat", "trpup", "dropped.bin" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Keyser.exe - Famous Cheat
            new CheatSignature
            {
                Name = "Keyser.exe",
                Description = "Famous cheat with VMProtect protection and DirectX integration",
                FileNames = new List<string> { "keyser.exe", "loader.exe", "loader (1).exe", "SpotifyTask.exe", "loader (2).exe", "updated_yn61.exe", "updated_7xk2.exe", "updated_2a77.exe", "loader (3).exe", "ahm.exe", "oVky1Tu.exe", "loader (4).exe", "loader (5).exe" },
                FileSizes = new List<string> { "12283904" },
                MD5Hashes = new List<string> { "80111b3d79a5f87df4b77554ba69348f", "3aad217ebea2be75ba99ef28347a396b" },
                SHA1Hashes = new List<string> { "d4310e90104844482fdfc647a5d62117f6ea875d", "7aa59d606d41d01f1035dfc9fb057f1859d150f7" },
                SHA256Hashes = new List<string> { "eba3ffbab0d338f7aeac72ae41785cebac3b6371f517c5dd4c506f8121db1850", "f86f638ab81409a8fc4798bd8a025ddd2196dc6ec231d3b7f86b916e76996f00" },
                Strings = new List<string> { "VMProtect", "d3d9.dll", "d3dx9_43.dll", "dwmapi.dll", "dxcore.dll" },
                DNS = new List<string> { "keyser.gg" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Skript Cheat
            new CheatSignature
            {
                Name = "Skript",
                Description = "FiveM cheat with specific PDB path",
                FileNames = new List<string> { "sk_launcher.exe" },
                Strings = new List<string> { "C:\\Users\\dev\\Desktop\\projects\\Skript\\sk_launcher\\x64\\Release\\sk_launcher.pdb", "skript.gg", "sk_launcher" },
                DNS = new List<string> { "skript.gg" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Testo Cheat
            new CheatSignature
            {
                Name = "Testo",
                Description = "FiveM cheat with Oreans protection",
                FileNames = new List<string> { "testo.exe" },
                FileSizes = new List<string> { "24000" },
                Strings = new List<string> { "VCRUNTIME140_1.dll", "d3dx11_43.dll", "Oreans Technologies", "deactiv" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Gosth Cheat
            new CheatSignature
            {
                Name = "Gosth",
                Description = "FiveM cheat with pedrin signatures",
                FileNames = new List<string> { "gosth.exe" },
                FileSizes = new List<string> { "25000" },
                Strings = new List<string> { ".pedrin0", ".pedrin1", ".pedrin2" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // HX Cheat
            new CheatSignature
            {
                Name = "HX",
                Description = "FiveM cheat with specific DLL patterns",
                FileNames = new List<string> { "hx.exe" },
                FileSizes = new List<string> { "20000" },
                Strings = new List<string> { "GDI32.dll", "mcmd7is" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // BypassFun Cheat
            new CheatSignature
            {
                Name = "BypassFun",
                Description = "FiveM bypass cheat",
                FileNames = new List<string> { "bypass.exe" },
                FileSizes = new List<string> { "22000" },
                Strings = new List<string> { "mxxngac", "rFCoMNldh" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // CCleaner - Evidence Cleaner
            new CheatSignature
            {
                Name = "CCleaner",
                Description = "Evidence cleaning tool",
                FileNames = new List<string> { "Ccleaner.exe", "Ccleaner64.exe" },
                Strings = new List<string> { "CCleaner.Windows.IPC.NamedPipes", "CCleanerDU.dll" },
                DNS = new List<string> { "ccleaner.com", "dlc.ccleaner.com" },
                Severity = "High",
                Category = "Evidence Cleaner"
            },

            // PrivaZer - Evidence Cleaner
            new CheatSignature
            {
                Name = "PrivaZer",
                Description = "Evidence cleaning tool",
                FileNames = new List<string> { "PrivaZer.exe", "PrivaZer_Pro.new.exe" },
                Strings = new List<string> { "PrivaZer.ini", "support@privazer.com" },
                DNS = new List<string> { "privazer.com" },
                Severity = "High",
                Category = "Evidence Cleaner"
            },

            // RevoUninstaller - Evidence Cleaner
            new CheatSignature
            {
                Name = "RevoUninstaller",
                Description = "Evidence cleaning tool",
                FileNames = new List<string> { "RevoUnin.exe" },
                Strings = new List<string> { "Revo Uninstaller", "Revo Uninstaller Pro" },
                DNS = new List<string> { "revouninstaller.com" },
                Severity = "High",
                Category = "Evidence Cleaner"
            },

            // ImGui Generic Detection
            new CheatSignature
            {
                Name = "ImGui",
                Description = "Generic ImGui detection (may have false positives)",
                Strings = new List<string> { "ImGui" },
                Severity = "Medium",
                Category = "Generic Detection"
            },

            // Windows Credential Editor
            new CheatSignature
            {
                Name = "WindowsCredentialEditor",
                Description = "Password dumping tool",
                Strings = new List<string> { "extract the TGT session key", "Windows Credentials Editor" },
                Severity = "Critical",
                Category = "Credential Dumper"
            },

            // Mimikatz
            new CheatSignature
            {
                Name = "Mimikatz",
                Description = "Password dumping tool",
                Strings = new List<string> { "sekurlsa::msv", "sekurlsa::wdigest", "sekurlsa::kerberos", "sekurlsa::logonPasswords", "sekurlsa::tickets" },
                Severity = "Critical",
                Category = "Credential Dumper"
            },

            // Generic Port Scanner
            new CheatSignature
            {
                Name = "PortScanner",
                Description = "Network port scanning tool",
                FileNames = new List<string> { "portscan.exe", "pscan.exe", "nmap.exe", "superscan.exe" },
                Strings = new List<string> { "Scan Ports", "port scanner", "TCP scan", "SYN scan" },
                Severity = "Medium",
                Category = "Network Tool"
            },

            // Ammyy Admin
            new CheatSignature
            {
                Name = "AmmyyAdmin",
                Description = "Remote admin tool used by APT groups",
                FileNames = new List<string> { "AA_v3.4.exe", "AA_v3.5.exe" },
                Strings = new List<string> { "Global\\Ammyy.Target.IncomePort", "Please enter password for accessing remote computer" },
                Severity = "High",
                Category = "Remote Admin Tool"
            },

            // ==================== ADDITIONAL CHEATS ====================

            // Midnight Cheat
            new CheatSignature
            {
                Name = "Midnight",
                Description = "FiveM cheat with advanced features",
                FileNames = new List<string> { "midnight.exe", "midnight_loader.exe" },
                Strings = new List<string> { "midnight", "midnight cheat", "midnight.gg" },
                DNS = new List<string> { "midnight.gg", "api.midnight.gg" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Stand Cheat
            new CheatSignature
            {
                Name = "Stand",
                Description = "Popular GTA/FiveM mod menu",
                FileNames = new List<string> { "stand.exe", "stand_loader.exe", "Launchpad.exe" },
                Strings = new List<string> { "stand", "stand.gg", "stand mod menu" },
                DNS = new List<string> { "stand.gg", "api.stand.gg" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Cherax Cheat
            new CheatSignature
            {
                Name = "Cherax",
                Description = "GTA/FiveM mod menu with protections",
                FileNames = new List<string> { "cherax.exe", "cherax_loader.exe" },
                Strings = new List<string> { "cherax", "cherax.vip", "cherax mod menu" },
                DNS = new List<string> { "cherax.vip", "api.cherax.vip" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // 2Take1 Cheat
            new CheatSignature
            {
                Name = "2Take1",
                Description = "Premium GTA mod menu",
                FileNames = new List<string> { "2take1.exe", "2t1.exe", "2take1menu.exe" },
                Strings = new List<string> { "2take1", "2t1", "2take1menu" },
                DNS = new List<string> { "2take1.menu", "api.2take1.menu" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Impulse Cheat
            new CheatSignature
            {
                Name = "Impulse",
                Description = "GTA mod menu (discontinued but still used)",
                FileNames = new List<string> { "impulse.exe", "impulse_loader.exe" },
                Strings = new List<string> { "impulse", "impulse.one", "impulse mod menu" },
                DNS = new List<string> { "impulse.one", "impulsecheats.com" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Phantom-X Cheat
            new CheatSignature
            {
                Name = "Phantom-X",
                Description = "GTA/FiveM mod menu",
                FileNames = new List<string> { "phantom.exe", "phantomx.exe", "phantom_loader.exe" },
                Strings = new List<string> { "phantom-x", "phantomx", "phantom mod menu" },
                DNS = new List<string> { "phantom-x.com", "phantomx.com" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Paragon Cheat
            new CheatSignature
            {
                Name = "Paragon",
                Description = "GTA mod menu (discontinued)",
                FileNames = new List<string> { "paragon.exe", "paragon_loader.exe" },
                Strings = new List<string> { "paragon", "paragon mod menu", "paragonmenu" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Disturbed Cheat
            new CheatSignature
            {
                Name = "Disturbed",
                Description = "GTA mod menu (discontinued)",
                FileNames = new List<string> { "disturbed.exe", "disturbed_loader.exe" },
                Strings = new List<string> { "disturbed", "disturbed mod menu", "disturbedmenu" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Ozark Cheat
            new CheatSignature
            {
                Name = "Ozark",
                Description = "GTA mod menu (discontinued)",
                FileNames = new List<string> { "ozark.exe", "ozark_loader.exe" },
                Strings = new List<string> { "ozark", "ozark mod menu", "ozarkmenu" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Luna Cheat
            new CheatSignature
            {
                Name = "Luna",
                Description = "GTA mod menu (discontinued)",
                FileNames = new List<string> { "luna.exe", "luna_loader.exe" },
                Strings = new List<string> { "luna", "luna mod menu", "lunamenu" },
                Severity = "Critical",
                Category = "Cheat Detection"
            },

            // Kiddions Modest Menu
            new CheatSignature
            {
                Name = "Kiddions",
                Description = "Free GTA mod menu (very popular)",
                FileNames = new List<string> { "Kiddions.exe", "Modest Menu.exe", "modest-menu.exe" },
                Strings = new List<string> { "kiddions", "modest menu", "modestmenu" },
                Severity = "High",
                Category = "Cheat Detection"
            },

            // Cheat Engine
            new CheatSignature
            {
                Name = "CheatEngine",
                Description = "Memory editing tool",
                FileNames = new List<string> { "cheatengine-x86_64.exe", "cheatengine-i386.exe", "cheatengine.exe" },
                Strings = new List<string> { "Cheat Engine", "cheatengine.org", "Dark Byte" },
                DNS = new List<string> { "cheatengine.org" },
                Severity = "High",
                Category = "Memory Editor"
            },

            // Process Hacker
            new CheatSignature
            {
                Name = "ProcessHacker",
                Description = "Advanced process viewer (can be used for cheating)",
                FileNames = new List<string> { "ProcessHacker.exe", "ProcessHacker2.exe" },
                Strings = new List<string> { "Process Hacker", "processhacker.sourceforge.net" },
                Severity = "Medium",
                Category = "Process Tool"
            },

            // x64dbg / x32dbg
            new CheatSignature
            {
                Name = "x64dbg",
                Description = "Debugger tool (can be used for reverse engineering)",
                FileNames = new List<string> { "x64dbg.exe", "x32dbg.exe" },
                Strings = new List<string> { "x64dbg", "x32dbg", "mrexodia" },
                Severity = "Medium",
                Category = "Debugger"
            },

            // dnSpy
            new CheatSignature
            {
                Name = "dnSpy",
                Description = ".NET debugger and assembly editor",
                FileNames = new List<string> { "dnSpy.exe", "dnSpy-x86.exe" },
                Strings = new List<string> { "dnSpy", "0xd4d" },
                Severity = "Medium",
                Category = "Debugger"
            },

            // Xenos Injector
            new CheatSignature
            {
                Name = "Xenos",
                Description = "DLL injector tool",
                FileNames = new List<string> { "Xenos.exe", "Xenos64.exe", "Xenos Injector.exe" },
                Strings = new List<string> { "Xenos", "DarthTon", "Manual map", "Thread hijack" },
                Severity = "High",
                Category = "Injector"
            },

            // Extreme Injector
            new CheatSignature
            {
                Name = "ExtremeInjector",
                Description = "DLL injector tool",
                FileNames = new List<string> { "Extreme Injector.exe", "Extreme Injector v3.exe" },
                Strings = new List<string> { "Extreme Injector", "master131" },
                Severity = "High",
                Category = "Injector"
            },

            // ReClass.NET
            new CheatSignature
            {
                Name = "ReClass",
                Description = "Memory analysis tool",
                FileNames = new List<string> { "ReClass.NET.exe", "ReClass.exe" },
                Strings = new List<string> { "ReClass.NET", "KN4CK3R" },
                Severity = "Medium",
                Category = "Memory Editor"
            },

            // BleachBit - Evidence Cleaner
            new CheatSignature
            {
                Name = "BleachBit",
                Description = "Evidence cleaning tool",
                FileNames = new List<string> { "bleachbit.exe", "bleachbit_console.exe" },
                Strings = new List<string> { "BleachBit", "bleachbit.org" },
                DNS = new List<string> { "bleachbit.org" },
                Severity = "High",
                Category = "Evidence Cleaner"
            },

            // Wise Care 365 - Evidence Cleaner
            new CheatSignature
            {
                Name = "WiseCare365",
                Description = "System cleaner (can delete evidence)",
                FileNames = new List<string> { "WiseCare365.exe", "WiseRegCleaner.exe" },
                Strings = new List<string> { "Wise Care 365", "WiseCleaner" },
                DNS = new List<string> { "wisecleaner.com" },
                Severity = "Medium",
                Category = "Evidence Cleaner"
            },

            // Advanced SystemCare - Evidence Cleaner
            new CheatSignature
            {
                Name = "AdvancedSystemCare",
                Description = "System cleaner (can delete evidence)",
                FileNames = new List<string> { "ASC.exe", "ASCService.exe", "ASCTray.exe" },
                Strings = new List<string> { "Advanced SystemCare", "IObit" },
                DNS = new List<string> { "iobit.com" },
                Severity = "Medium",
                Category = "Evidence Cleaner"
            },

            // Glary Utilities - Evidence Cleaner
            new CheatSignature
            {
                Name = "GlaryUtilities",
                Description = "System cleaner (can delete evidence)",
                FileNames = new List<string> { "Integrator.exe", "GUBootSpeedTray.exe" },
                Strings = new List<string> { "Glary Utilities", "Glarysoft" },
                DNS = new List<string> { "glarysoft.com" },
                Severity = "Medium",
                Category = "Evidence Cleaner"
            }
        };

        public static string CalculateMD5(string filePath)
        {
            try
            {
                using (var md5 = MD5.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = md5.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        public static string CalculateSHA1(string filePath)
        {
            try
            {
                using (var sha1 = SHA1.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = sha1.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        public static string CalculateSHA256(string filePath)
        {
            try
            {
                using (var sha256 = SHA256.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        public static bool CheckFileSize(string filePath, string expectedSize)
        {
            try
            {
                var fileInfo = new FileInfo(filePath);
                return fileInfo.Length.ToString() == expectedSize;
            }
            catch
            {
                return false;
            }
        }

        public static bool CheckFileContent(string filePath, List<string> searchStrings)
        {
            try
            {
                var content = File.ReadAllText(filePath);
                return searchStrings.Any(s => content.Contains(s, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
        }
    }
}
