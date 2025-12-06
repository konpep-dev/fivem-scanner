-- </async> Scanner Database Schema
-- This schema defines the structure for the SQLite database.

--
-- Table structure for `enterprise`
-- Stores information about enterprise groups.
--
CREATE TABLE enterprise (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL UNIQUE,
    admin_user_id VARCHAR(20) NOT NULL,
    license_expires_at DATETIME,
    has_custom_loader BOOLEAN NOT NULL DEFAULT 0,
    loader_path VARCHAR(255),
    warnings INTEGER NOT NULL DEFAULT 0,
    game VARCHAR(50) NOT NULL DEFAULT 'fivem',
    FOREIGN KEY (admin_user_id) REFERENCES user(id)
);

--
-- Table structure for `user`
-- Stores information about users who log in via Discord.
--
CREATE TABLE user (
    id VARCHAR(20) PRIMARY KEY NOT NULL,         -- Discord User ID
    username VARCHAR(80) NOT NULL,               -- Discord username
    avatar VARCHAR(120),                         -- URL to the user's Discord avatar
    role VARCHAR(10) NOT NULL DEFAULT 'user',    -- User role, can be 'user' or 'admin'
    has_license BOOLEAN NOT NULL DEFAULT 0,      -- Whether the user has a license to use the service
    is_banned BOOLEAN NOT NULL DEFAULT 0,        -- Whether the user is banned from the service
    ban_reason TEXT,                             -- Reason for the ban, if any
    ban_expires_at DATETIME,                     -- When the ban expires (NULL for permanent)
    responsible_admin_id VARCHAR(20),            -- ID of the admin who banned the user
    license_expires_at DATETIME,                 -- When the user's license expires
    enterprise_id INTEGER,                       -- Foreign key to the enterprise this user belongs to
    tos_accepted BOOLEAN NOT NULL DEFAULT 0,     -- Whether the user has accepted the terms of service
    FOREIGN KEY (enterprise_id) REFERENCES enterprise(id) ON DELETE SET NULL
);

--
-- Table structure for `scan`
-- Stores metadata for each scan initiated by a user.
--
CREATE TABLE scan (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pin INTEGER NOT NULL UNIQUE,                                -- 6-digit PIN for the scanner client to submit results
    url VARCHAR(120) NOT NULL,                                  -- A unique identifier string for the scan
    status VARCHAR(50) NOT NULL DEFAULT 'Pending',              -- Current status: Pending, Scanning, Cheats Detected, No threats found
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,      -- The time the scan was created or completed
    is_public BOOLEAN NOT NULL DEFAULT 0,                       -- Whether the scan report is publicly viewable
    user_id VARCHAR(20) NOT NULL,                               -- Foreign key linking to the user who initiated the scan
    game VARCHAR(50) NOT NULL DEFAULT 'fivem',
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

--
-- Table structure for `finding`
-- Stores details about each specific threat or cheat detected in a scan.
--
CREATE TABLE finding (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category VARCHAR(100) NOT NULL,                             -- The category of the finding (e.g., 'External Injectors')
    name VARCHAR(255) NOT NULL,                                 -- The name of the detected cheat/threat
    severity VARCHAR(20) NOT NULL,                              -- The risk level: Critical, High, Medium
    path VARCHAR(1024) NOT NULL,                                -- File path or source of the threat
    action VARCHAR(50) NOT NULL,                                -- Action taken by the scanner (e.g., 'Quarantined')
    file_hash VARCHAR(64),                                      -- SHA256 hash of the file, if available
    yara_rule VARCHAR(100),                                     -- YARA rule that was matched, if any
    source_type VARCHAR(50),                                    -- The source of the detection (e.g., File, Memory, Browser)
    score INTEGER,                                              -- Numeric score indicating severity/confidence
    score_contributors TEXT,                                    -- JSON field storing factors contributing to the score
    last_execution_time VARCHAR(50),                            -- Last execution time of the cheat file (format: yyyy-MM-dd HH:mm:ss)
    scan_id INTEGER NOT NULL,                                   -- Foreign key linking to the parent scan
    FOREIGN KEY (scan_id) REFERENCES scan(id) ON DELETE CASCADE
);

--
-- Table structure for `system_info`
-- Stores system information for a scan.
--
CREATE TABLE system_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL UNIQUE,
    os_version VARCHAR(255),
    cpu_info VARCHAR(255),
    ram_total VARCHAR(50),
    hardware_id VARCHAR(255),
    antivirus VARCHAR(255),
    uptime VARCHAR(100),
    FOREIGN KEY (scan_id) REFERENCES scan(id) ON DELETE CASCADE
);

--
-- Table structure for `user_identity`
-- Stores user identities found during a scan.
--
CREATE TABLE user_identity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    identity_type VARCHAR(50) NOT NULL, -- e.g., 'Discord', 'Steam', 'Windows'
    username VARCHAR(255),
    user_id VARCHAR(255),
    additional_info TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan(id) ON DELETE CASCADE
);

--
-- Table structure for `browser_history`
-- Stores suspicious browser history entries.
--
CREATE TABLE browser_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    browser VARCHAR(50),
    url TEXT,
    title TEXT,
    visit_count INTEGER,
    FOREIGN KEY (scan_id) REFERENCES scan(id) ON DELETE CASCADE
);

--
-- Table structure for `command_history`
-- Stores suspicious command line history.
--
CREATE TABLE command_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    type VARCHAR(50), -- e.g., 'PowerShell', 'RunMRU'
    command TEXT,
    is_suspicious BOOLEAN,
    keywords_found TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan(id) ON DELETE CASCADE
);

--
-- Table structure for `game_analysis`
-- Stores game-specific analysis results (e.g., FiveM, DayZ, Minecraft).
--
CREATE TABLE game_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    installation_path TEXT,
    mod_detected BOOLEAN,
    mod_name VARCHAR(255),
    mod_path TEXT,
    mod_details TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan(id) ON DELETE CASCADE
);

--
-- Table structure for `artifact`
-- A generic table to store all other artifacts.
--
CREATE TABLE artifact (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    category VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    details TEXT,
    status VARCHAR(20), -- e.g., 'info', 'warning', 'threat', 'critical'
    FOREIGN KEY (scan_id) REFERENCES scan(id) ON DELETE CASCADE
);

--
-- Table structure for `recent_executable`
-- Stores recently executed applications found during a scan.
--
CREATE TABLE recent_executable (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    process_name VARCHAR(255) NOT NULL,
    last_executed DATETIME,
    risk_level VARCHAR(20) NOT NULL, -- e.g., 'safe', 'suspicious', 'dangerous'
    details TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan(id) ON DELETE CASCADE
);

--
-- Table structure for `hardware_info`
-- Stores information about hardware and peripherals.
--
CREATE TABLE hardware_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    name VARCHAR(255) NOT NULL,
    details TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan(id) ON DELETE CASCADE
);

--
-- Table structure for `system_service`
-- Stores status of important system services.
--
CREATE TABLE system_service (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL,
    details TEXT,
    FOREIGN KEY (scan_id) REFERENCES scan(id) ON DELETE CASCADE
);


-- Create indexes for faster lookups
CREATE INDEX idx_user_enterprise_id ON user (enterprise_id);
CREATE INDEX idx_scan_user_id ON scan (user_id);
CREATE INDEX idx_finding_scan_id ON finding (scan_id);
CREATE INDEX idx_system_info_scan_id ON system_info (scan_id);
CREATE INDEX idx_user_identity_scan_id ON user_identity (scan_id);
CREATE INDEX idx_browser_history_scan_id ON browser_history (scan_id);
CREATE INDEX idx_command_history_scan_id ON command_history (scan_id);
CREATE INDEX idx_game_analysis_scan_id ON game_analysis (scan_id);
CREATE INDEX idx_artifact_scan_id_category ON artifact (scan_id, category);
CREATE INDEX idx_recent_executable_scan_id ON recent_executable (scan_id);
CREATE INDEX idx_hardware_info_scan_id ON hardware_info (scan_id);
CREATE INDEX idx_system_service_scan_id ON system_service (scan_id);