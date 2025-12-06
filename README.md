# FiveM Anti-Cheat Scanner

<p align="center">
  <img src="c# scanner/logo.ico" alt="Scanner Logo" width="120"/>
</p>

<p align="center">
  <b>Advanced FiveM Anti-Cheat Scanner</b><br>
  <i>Professional forensic analysis tool for FiveM server administrators</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue" alt="Version"/>
  <img src="https://img.shields.io/badge/platform-Windows-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/.NET-6.0-purple" alt=".NET"/>
  <a href="https://github.com/konpep-dev/fivem-scanner/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-green" alt="License"/>
  </a>
</p>

---

## 📸 Screenshots

<p align="center">
  <img src="images/screenshot1.png" width="700"/>
</p>

<p align="center">
  <img src="images/screenshot2.png" width="700"/>
</p>

<p align="center">
  <img src="images/screenshot3.png" width="700"/>
</p>

---

## 📋 What is this?

This is a professional **cheat detection scanner** for FiveM servers. It performs deep forensic analysis on a player's system and reports findings to your admin panel.

Designed for server administrators who want to maintain clean and fair gameplay for all players.

---

## ⚡ Key Features

### 🔍 Forensic Scanning
- **File System Analysis** - Scans for cheat files, loaders, injectors
- **MFT Scanning** - Master File Table analysis for deleted files
- **USN Journal** - Detection of recent file changes
- **Prefetch Analysis** - Identification of executed programs
- **ShimCache Analysis** - Application execution history

### 🧠 Memory Analysis
- **Process Memory Scanning** - Detection of suspicious strings in memory
- **DLL Injection Detection** - Identification of injected modules
- **Memory Hook Detection** - API hook detection (ntdll, kernel32, d3d11)
- **Unbacked Executable Memory** - Hidden injection detection

### 🌐 Network & Browser
- **Browser History Scanning** - Chrome, Firefox, Edge, Opera, Brave
- **Cheat Site Detection** - Detection of visits to known cheat sites
- **Network Connection Analysis** - Active connection analysis
- **DNS Query Monitoring** - Suspicious domain monitoring

### 🎮 Game-Specific
- **FiveM Cache Analysis** - FiveM cache folder scanning
- **GTA V File Integrity** - Game file verification
- **Mod Detection** - Unauthorized modification detection
- **Script Hook Detection** - Script hook identification

### 🛡️ Anti-Tamper
- **Anti-Debug Protection** - Protection against debugging tools
- **Process Integrity Checks** - Integrity verification
- **Evidence Cleaner Detection** - CCleaner, PrivaZer detection, etc.

### 📊 Reporting
- **Real-time Screen Recording** - 30 seconds video capture
- **Hardware Fingerprinting** - Hardware ID collection
- **Discord/Steam Account Detection** - Linked account identification
- **Detailed JSON Reports** - Comprehensive server reports

---

## 🎯 Supported Cheats

The scanner detects **100+ known cheats** including:

| Cheat | Severity | Detection Method |
|-------|----------|------------------|
| Eulen | 🔴 Critical | Hash, Strings, DNS |
| Susano | 🔴 Critical | Hash, Process, DNS |
| Red Engine | 🔴 Critical | Hash, File Patterns |
| TZProject | 🔴 Critical | Hash, DNS, Strings |
| HX Softwares | 🔴 Critical | Hash, API Endpoints |
| Keyser | 🔴 Critical | Hash, VMProtect |
| Skript | 🔴 Critical | PDB Path, DNS |
| Gosth | 🔴 Critical | Signatures |
| 420 Services | 🔴 Critical | Hash, Strings |
| Midnight | 🔴 Critical | DNS, Strings |
| Stand | 🔴 Critical | Process, DNS |
| Testo | 🔴 Critical | Oreans Protection |
| + many more... | | |

---

## 🖥️ System Requirements

### Scanner Client (Windows)
- **OS:** Windows 10/11 (64-bit)
- **RAM:** 4GB minimum
- **Disk:** 100MB free space
- **.NET:** Embedded (self-contained build)
- **Admin Rights:** Required for full scanning

### Server (Backend)
- **OS:** Linux (Ubuntu 20.04+) or Windows Server
- **Python:** 3.8 or higher
- **RAM:** 2GB minimum (4GB recommended)
- **Database:** SQLite (default) or MySQL/MariaDB
- **Ports:** 5000 (default) or custom
- **SSL:** Required for production (use Cloudflare or nginx)
- **Domain:** Required for Discord OAuth2

---

## 🚀 How It Works

```
1. Player downloads the scanner
2. Enters the 6-digit PIN provided by the admin
3. Scanner performs full forensic analysis (~2-3 minutes)
4. Results are sent to the admin panel
5. Admin views detailed report with all findings
```

---

## � APIv Documentation

### Configuration

Before running the server, you need to configure the `.env` file:

```env
# Server Settings
APP_BASE_URL='https://your-domain.com'
FLASK_SECRET_KEY='your-secret-key-here'
FLASK_RUN_HOST='0.0.0.0'
FLASK_RUN_PORT=5000

# Database (SQLite or MySQL)
DATABASE_URL='sqlite:///scanner.db'
# Or for MySQL:
# DATABASE_URL='mysql+pymysql://user:pass@host/database'

# Discord OAuth2 (Required)
DISCORD_CLIENT_ID='your-client-id'
DISCORD_CLIENT_SECRET='your-client-secret'
DISCORD_BOT_TOKEN='your-bot-token'
DISCORD_GUILD_ID='your-server-id'
ADMIN_ROLE_ID='your-admin-role-id'

# Webhooks (Optional - for notifications)
PINS_CREATED_WEBHOOK_URL='webhook-url'
SUS_RESULTS_WEBHOOK_URL='webhook-url'
BAN_LOGS_WEBHOOK_URL='webhook-url'

# AI Features (Optional)
GEMINI_API_KEY='your-gemini-api-key'

# Security
RATE_LIMIT_DEFAULT='200 per minute;30 per second'
AI_GUARDIAN_ENABLED=True
```

### Scanner → Server API Endpoints

These endpoints are used by the scanner client:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/submit/<pin>` | POST | Submit scan results |
| `/api/custom-rules/download/<pin>` | GET | Download custom detection rules |
| `/api/download-scanner/<pin>` | GET | Download scanner executable |
| `/api/verify` | POST | Verify PIN validity |

### Admin Panel API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/user` | GET | Get current user info |
| `/api/scans` | GET | List all scans |
| `/api/scans` | POST | Create new scan PIN |
| `/api/scans/<id>/details` | GET | Get scan details |
| `/api/scans/<id>` | DELETE | Delete scan |
| `/api/dashboard-stats` | GET | Dashboard statistics |

### Admin-Only Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/admin/users` | GET | List all users |
| `/api/admin/users/<id>/ban` | POST | Ban user |
| `/api/admin/users/<id>/unban` | POST | Unban user |
| `/api/admin/users/<id>/grant-license` | POST | Grant license |
| `/api/admin/hardware-fingerprints` | GET | List hardware bans |
| `/api/admin/system-stats` | GET | Server statistics |
| `/api/admin/logs` | GET | API logs |
| `/api/admin/database-stats` | GET | Database statistics |

### Enterprise Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/enterprise/details` | GET | Enterprise info |
| `/api/enterprise/add_member` | POST | Add team member |
| `/api/enterprise/remove_member` | POST | Remove team member |

### AI Guardian (DDoS Protection)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/admin/ai-guardian/status` | GET | Protection status |
| `/api/admin/ai-guardian/config` | POST | Update config |
| `/api/admin/ai-guardian/blocked-ips` | GET | List blocked IPs |
| `/api/admin/ai-guardian/clear-blocked-ips` | POST | Clear blocks |

---

## 🔧 What You Need to Change

### 1. Scanner Client (`c# scanner/`)

Edit `Scanner.cs` - Change the server URL:
```csharp
var serverUrl = "https://YOUR-DOMAIN.com";
```

### 2. Server (`server/`)

1. Rename `.env.example` to `.env`
2. Fill in all required values:
   - `APP_BASE_URL` - Your domain
   - `DISCORD_CLIENT_ID` - From Discord Developer Portal
   - `DISCORD_CLIENT_SECRET` - From Discord Developer Portal
   - `DISCORD_BOT_TOKEN` - Your bot token
   - `DISCORD_GUILD_ID` - Your Discord server ID
   - `ADMIN_ROLE_ID` - Admin role ID

### 3. Discord Developer Portal Setup

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create new application
3. Go to OAuth2 → Add redirect URL: `https://YOUR-DOMAIN.com/callback`
4. Go to Bot → Create bot and copy token
5. Enable required intents: Server Members, Message Content

---

## ⚠️ Important: CheatDatabase.cs

The `CheatDatabase.cs` file contains **SAMPLE/DEMO signatures only**. You MUST customize it with your own detection rules!

### What you need to add:

1. **File Hashes** - MD5, SHA1, SHA256 of known cheat executables
2. **Suspicious Strings** - Unique strings found in cheat files
3. **Process Names** - Known cheat process names
4. **DNS/Domains** - Cheat API endpoints and websites
5. **File Patterns** - Regex patterns for cheat file names
6. **YARA Rules** - Advanced pattern matching rules

### Example - Adding a new cheat signature:

```csharp
new CheatSignature
{
    Name = "Your Cheat Name",
    Description = "Description of the cheat",
    FileNames = new List<string> { "cheat.exe", "loader.exe" },
    MD5Hashes = new List<string> { "abc123..." },
    SHA256Hashes = new List<string> { "def456..." },
    Strings = new List<string> { "unique_string_in_cheat", "api.cheats.com" },
    DNS = new List<string> { "api.cheatsite.com" },
    ProcessNames = new List<string> { "cheat_process.exe" },
    Severity = "Critical",
    Category = "Cheat Detection"
}
```

### Where to find cheat signatures:
- Analyze cheat samples with tools like PE Studio, DIE, x64dbg
- Extract unique strings with `strings` command
- Calculate file hashes
- Monitor network traffic for API calls
- Check cheat forums for file names and patterns

---

## 📁 Project Structure

```
├── c# scanner/              # Main scanner application (WPF)
│   ├── Scanner.cs           # Core scanning engine
│   ├── CheatDatabase.cs     # ⚠️ SAMPLE signatures - ADD YOUR OWN!
│   ├── ApiClient.cs         # Server communication
│   ├── BehaviorEngine.cs    # Behavioral analysis
│   ├── HybridScanner.cs     # Hybrid detection
│   ├── HardwareScanner.cs   # Hardware fingerprinting
│   ├── JournalScanner.cs    # USN Journal analysis
│   ├── ScoringEngine.cs     # Risk scoring system
│   ├── TelemetryClient.cs   # Telemetry & reporting
│   ├── Capture.cs           # Screen recording
│   ├── AntiDebug.cs         # Anti-debugging protection
│   ├── AntiTamper.cs        # Anti-tamper checks
│   ├── MainWindow.xaml      # Main UI
│   ├── TosWindow.xaml       # Terms of Service
│   └── FaqWindow.xaml       # FAQ window
│
├── server/                  # Admin panel & API
│   ├── server.py            # Flask backend API
│   ├── server.sql           # Database schema
│   ├── index.html           # Landing page
│   ├── dashboard.html       # Admin dashboard
│   ├── results.html         # Scan results viewer
│   ├── scans.html           # Scan history
│   ├── rules.html           # Custom rules manager
│   ├── report.html          # Detailed reports
│   ├── admin.html           # Admin management
│   ├── server-admin.html    # Server administration
│   ├── discord-panel.html   # Discord integration
│   ├── enterprise.html      # Enterprise features
│   ├── settings.html        # Settings page
│   ├── notifications.js     # Notification system
│   ├── security.js          # Security utilities
│   ├── rulepacks.json       # Detection rule packs
│   ├── testscan.html        # Test scan page
│   ├── tos.html             # Terms of Service
│   ├── faq.html             # FAQ page
│   └── unlicensed.html      # License error page
│
└── db cheats/               # Cheat database files
    └── db.txt               # Known cheat signatures
```

---

## 🛠️ Build & Run

### Scanner (C#)
```powershell
# Full production build with embedded .NET runtime
dotnet publish "c# scanner/FiveMScanner.csproj" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true
```

Output: `c# scanner/bin/Release/net6.0-windows/win-x64/publish/Scanner.exe`

### Server (Python)
```bash
# Install dependencies
pip install -r server/requirements.txt

# Run server
python server/server.py
```

The server will auto-install missing dependencies on first run.

---

## 🔧 Custom Rules

Supports custom detection rules through the admin panel:

- **Keywords** - Add custom suspicious keywords
- **File Hashes** - MD5/SHA1/SHA256 hashes
- **YARA Rules** - Advanced pattern matching

---

## ⚠️ Disclaimer

This tool is intended **exclusively** for use by authorized server administrators to protect their FiveM servers. Use for other purposes is prohibited.

---

## 📞 Support

- **Discord:** konpep1
- **Discord ID:** 926572380409712660

---

<p align="center">
  <b>Made with ❤️ by 𝓴𝓸𝓷𝓹𝓮𝓹ᵗᵐ</b><br>
  <i>Keeping FiveM servers clean since 2025</i>
</p>
