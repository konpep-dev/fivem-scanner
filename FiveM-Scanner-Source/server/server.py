# </async> Scanner Backend
#
# This Flask application provides the backend services for the </async> scanner dashboard.
# It handles user authentication via Discord, stores scan data, and provides API endpoints
# for the frontend and the scanner client.
#
# --- Setup Instructions ---
#
# 1. Ensure you have Python 3.8+ installed.
#
# 2. Run the script directly from your terminal:
#    python flask.py.txt
#
#    - The first time you run it, it will automatically install all required dependencies.
#      After installation, you may be prompted to run the command again.
#
#    - If a `.env` file is not found, it will create a `.env.example` file for you.
#      Rename this file to `.env` and fill in your Discord application details and other settings.
#      Then, run the script again.
#
# 3. The application will start and be running at http://localhost:5000

import os
import sys
import subprocess
import importlib

def setup_check():
    """
    Performs a pre-flight check to ensure dependencies are installed and the .env file exists.
    This function is designed to run before any external modules are imported.
    """
    
    # 1. Check for required packages
    # Tuple format: (module_name_for_importlib, package_name_for_pip)
    dependencies = [
        ('flask', 'Flask'),
        ('flask_sqlalchemy', 'Flask-SQLAlchemy'),
        ('flask_login', 'Flask-Login'),
        ('flask_wtf', 'Flask-WTF'),  # CSRF Protection
        ('requests_oauthlib', 'requests_oauthlib'),
        ('dotenv', 'python-dotenv'),
        ('discord', 'discord.py'),
        ('pymysql', 'PyMySQL'),
        ('flask_limiter', 'Flask-Limiter'),
        ('flask_talisman', 'Flask-Talisman'),
        ('waitress', 'waitress'),
        ('werkzeug', 'Werkzeug'), # Werkzeug is a dependency of Flask but we ensure it's here for ProxyFix
        ('psutil', 'psutil'),
        ('google.generativeai', 'google-generativeai') # For Gemini API
    ]
    
    missing_modules = False
    try:
        for module_name, _ in dependencies:
            importlib.import_module(module_name)
    except ImportError:
        missing_modules = True

    if missing_modules:
        print("--- </async> Initial Setup ---")
        print("One or more required Python packages not found. Attempting to install all dependencies...")
        
        pip_packages = [pkg_name for _, pkg_name in dependencies]
        
        try:
            for package in pip_packages:
                print(f"Installing {package}...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", package],
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.STDOUT)
            print("\n✅ All dependencies installed successfully.")
            print("➡️ Please run the script again to start the server.")
        except subprocess.CalledProcessError:
            print(f"\n❌ Error installing packages. Please install them manually:")
            print(f"pip install {' '.join(pip_packages)}")
        except Exception as e:
            print(f"\n❌ An unexpected error occurred: {e}")
        
        sys.exit(0) # Exit after attempting installation

    # 2. Check for the .env or env.txt file
    env_file_found = False
    if os.path.exists('.env'):
        env_file_found = True
    elif os.path.exists('env.txt'):
        env_file_found = True
    
    if not env_file_found:
        print("--- </async> Configuration Setup ---")
        print("`.env` or `env.txt` file not found. Creating a template for you...")

        env_template = """
# --- FLASK APPLICATION SETTINGS ---
# The public-facing URL of your application. This is CRITICAL for Discord OAuth2 to work behind Cloudflare.
# Do NOT include a trailing slash.
APP_BASE_URL='http://your_domain.com'

# A long, random string used for session security.
FLASK_SECRET_KEY='a_very_long_and_random_string_here'
FLASK_RUN_HOST='0.0.0.0'
FLASK_RUN_PORT=5000

# --- GEMINI AI SETTINGS ---
# Optional: Your Google Gemini API Key for intelligent DDoS analysis.
# Get one from Google AI Studio: https://aistudio.google.com/
GEMINI_API_KEY=''

# --- SECURITY SETTINGS ---
# Flask-Limiter default rate limit. Use a semicolon (;) to separate multiple limits.
RATE_LIMIT_DEFAULT='200 per minute;30 per second'

# Content Security Policy (CSP) for Flask-Talisman. Values are space-separated.
# Use 'self' for the origin, 'unsafe-inline', 'unsafe-eval', or specific domains.
CSP_DEFAULT_SRC="'self'"
CSP_SCRIPT_SRC="'self' 'unsafe-inline' 'unsafe-eval'"
CSP_STYLE_SRC="'self' 'unsafe-inline' https://fonts.googleapis.com"
CSP_FONT_SRC="'self' https://fonts.gstatic.com"
CSP_IMG_SRC="'self' data: https://cdn.discordapp.com"

# --- AI TRAFFIC GUARDIAN (DDoS Protection) ---
# Enable or disable the AI-powered traffic anomaly detection.
AI_GUARDIAN_ENABLED=True
# Global requests-per-second (RPS) threshold. If total server traffic exceeds this, Mitigation Mode is activated.
AI_GUARDIAN_RPS_THRESHOLD=100
# Per-IP RPS limit when in Mitigation Mode. Any single IP exceeding this will be temporarily blocked.
AI_GUARDIAN_IP_RPS_LIMIT=20
# Duration in seconds to block a suspicious IP address.
AI_GUARDIAN_BLOCK_DURATION=300


# --- DATABASE CONFIGURATION ---
# Choose ONE of the following database URLs.
# For local testing (file-based database):
DATABASE_URL='sqlite:///async_scanner.db'
# For a remote MySQL/MariaDB server (recommended):
# DATABASE_URL='mysql+pymysql://USERNAME:PASSWORD@HOST_ADDRESS/DATABASE_NAME'

# --- DISCORD APPLICATION & BOT SETTINGS ---
# Find these in your Discord Developer Portal under your application's "General Information" and "OAuth2" settings.
DISCORD_CLIENT_ID='your_discord_client_id_from_developer_portal'
DISCORD_CLIENT_SECRET='your_discord_client_secret_from_developer_portal'

# Find this in the "Bot" tab in your Discord Developer Portal.
DISCORD_BOT_TOKEN='your_discord_bot_token_from_developer_portal'

# The ID of the Discord server (Guild) where slash commands will be registered.
DISCORD_GUILD_ID='your_discord_server_id'

# The Role ID that has permission to use the bot's admin commands.
ADMIN_ROLE_ID='your_admin_role_id_from_discord'

# --- LOGGING WEBHOOKS ---
# Create these webhooks in your Discord server settings.
# Each webhook can be for a different channel for better organization.
PINS_CREATED_WEBHOOK_URL='your_webhook_url_for_new_pins'
SELF_SCAN_WEBHOOK_URL='your_webhook_url_for_clean_self-scans'
SCREENSHARE_WEBHOOK_URL='your_webhook_url_for_clean_screenshare_scans'
SUS_RESULTS_WEBHOOK_URL='your_webhook_url_for_suspicious_scan_results'
SECURITY_ALERTS_WEBHOOK_URL='your_webhook_url_for_security_alerts'
SITE_LOGIN_WEBHOOK_URL='your_webhook_url_for_site_logins'
BAN_LOGS_WEBHOOK_URL='your_webhook_url_for_ban_logs'
TOS_ACCEPT_WEBHOOK_URL='your_webhook_url_for_tos_acceptances'
LICENSE_LOGS_WEBHOOK_URL='your_webhook_url_for_license_actions'
"""
        with open('.env.example', 'w') as f:
            f.write(env_template.strip())
            
        print("\n✅ `.env.example` has been created.")
        print("➡️ Please rename it to `.env` or `env.txt`, fill in your details, and then run this script again.")
        sys.exit(0)

# Run the setup check before importing anything else
setup_check()

import random
import threading
import asyncio
import time
import requests
import uuid
import discord
import re
import psutil
import platform
import traceback
import json
import google.generativeai as genai
from discord.ext import commands, tasks
from datetime import datetime, timedelta, timezone
import pytz  # For additional timezone support if needed
from dotenv import load_dotenv
from flask import Flask, request, redirect, url_for, jsonify, session, send_from_directory, render_template_string, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect as sqlalchemy_inspect, text
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from requests_oauthlib import OAuth2Session
from functools import wraps
from collections import defaultdict, deque
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from sqlalchemy.exc import IntegrityError, OperationalError
from werkzeug.middleware.proxy_fix import ProxyFix
from waitress import serve

# --- 1. Initialization and Configuration ---

# Load from env.txt if .env is not found
if os.path.exists('env.txt'):
    load_dotenv(dotenv_path='env.txt')
else:
    load_dotenv()
    
APP_ROOT = os.path.dirname(os.path.abspath(__file__))

# Allow OAuth2 over HTTP for local development. This MUST be set before creating the OAuth2Session.
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)

# CSRF Protection - Import after Flask app creation
try:
    from flask_wtf.csrf import CSRFProtect, generate_csrf, CSRFError
    csrf = CSRFProtect()
    CSRF_ENABLED = True
    print("✅ CSRF Protection will be enabled")
except ImportError:
    csrf = None
    CSRF_ENABLED = False
    print("⚠️  WARNING: Flask-WTF not installed. CSRF protection disabled. Install with: pip install Flask-WTF")
    # Create dummy functions if not available
    def generate_csrf():
        return "csrf-disabled"
    class CSRFError(Exception):
        pass

# Add ProxyFix middleware to make the app aware of being behind a proxy (like Cloudflare)
# This is crucial for correct URL generation and security features.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///async_scanner.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session Security Configuration
# Only require HTTPS cookies in production (not in local development)
app.config['SESSION_COOKIE_SECURE'] = not app.debug  # HTTPS only in production
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection - Lax allows OAuth redirects
app.config['SESSION_COOKIE_NAME'] = 'async_session'  # Custom cookie name
app.config['SESSION_COOKIE_PATH'] = '/'  # Available on all paths
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)  # Extended session - 30 days
app.config['SESSION_REFRESH_EACH_REQUEST'] = False  # Don't refresh on every request (reduces load)
app.config['SESSION_COOKIE_DOMAIN'] = None  # Use default domain (current domain only)
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)  # Remember me duration
app.config['REMEMBER_COOKIE_SECURE'] = not app.debug  # HTTPS only in production
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_SAMESITE'] = 'Lax'
app.config['REMEMBER_COOKIE_NAME'] = 'async_remember'  # Custom remember cookie name

# --- Gemini AI Initialization ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
gemini_model = None
if GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        gemini_model = genai.GenerativeModel('gemini-2.5-flash')
        print("✅ Gemini AI model initialized successfully.")
    except Exception as e:
        print(f"❌ WARNING: Gemini API key provided, but failed to initialize model: {e}", file=sys.stderr)
else:
    print("ℹ️ Gemini API key not found. AI DDoS analysis will be disabled.")


# --- Security Initializations ---

# Rate Limiting
rate_limit_string = os.environ.get("RATE_LIMIT_DEFAULT", "200 per minute;30 per second")
default_limits = [limit.strip() for limit in rate_limit_string.split(';')]
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=default_limits,
    storage_uri="memory://",
)

# AI Traffic Guardian (DDoS Protection) Configuration
AI_GUARDIAN_ENABLED = os.environ.get("AI_GUARDIAN_ENABLED", "True").lower() == 'true'
AI_GUARDIAN_RPS_THRESHOLD = int(os.environ.get("AI_GUARDIAN_RPS_THRESHOLD", 100))
AI_GUARDIAN_IP_RPS_LIMIT = int(os.environ.get("AI_GUARDIAN_IP_RPS_LIMIT", 20))
AI_GUARDIAN_BLOCK_DURATION = int(os.environ.get("AI_GUARDIAN_BLOCK_DURATION", 300))

AI_GUARDIAN_STATE = {
    "mitigation_mode_active": False,
    "manual_mode": "auto",  # 'auto', 'on', 'off'
    "last_alert_time": 0,
    "last_gemini_analysis_time": 0,
    "global_requests": deque(maxlen=AI_GUARDIAN_RPS_THRESHOLD * 2),
    "ip_requests": defaultdict(lambda: deque(maxlen=AI_GUARDIAN_IP_RPS_LIMIT * 5)), # Increased buffer
    "blocked_ips": {},
    "lock": threading.Lock()
}

# Security Headers (CSP)
# The `force_https=False` is important. Cloudflare handles HTTPS; the server runs on HTTP.
talisman = Talisman(app, content_security_policy=None, force_https=False)


db = SQLAlchemy(app)
# SQLAlchemy's ORM automatically uses parameterized queries, which is the primary defense against SQL injection.
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize CSRF Protection
if CSRF_ENABLED and csrf:
    csrf.init_app(app)
    # Disable CSRF by default - we use session-based authentication
    app.config['WTF_CSRF_CHECK_DEFAULT'] = False
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['WTF_CSRF_TIME_LIMIT'] = None  # Tokens don't expire (session-based)
    print("✅ CSRF Protection initialized (disabled by default, session-based auth)")
else:
    # Create a dummy decorator if CSRF is not available
    class DummyCSRF:
        def exempt(self, f):
            return f
    if not csrf:
        csrf = DummyCSRF()

# User Activity Tracking
ACTIVE_SESSIONS = {}
SESSION_TIMEOUT = 300 # 5 minutes in seconds

# In-memory log storage for the admin panel
api_logs = deque(maxlen=200)
ddos_logs = deque(maxlen=100)

# For calculating network speed
app.last_net_stats = None

# Discord OAuth2 configuration
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")
# The APP_BASE_URL is now the single source of truth for public URLs.
APP_BASE_URL = os.environ.get("APP_BASE_URL", "").rstrip('/')
if not APP_BASE_URL:
    raise ValueError("APP_BASE_URL is not set in the environment file. This is required.")

REDIRECT_URI = f'{APP_BASE_URL}/callback'
API_BASE_URL = 'https://discord.com/api'
AUTHORIZATION_BASE_URL = API_BASE_URL + '/oauth2/authorize'
TOKEN_URL = API_BASE_URL + '/oauth2/token'

# Discord Bot configuration
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN")
DISCORD_GUILD_ID = int(os.environ.get("DISCORD_GUILD_ID", 0))
ADMIN_ROLE_ID = int(os.environ.get("ADMIN_ROLE_ID", 0))

# Role IDs for automatic assignment
ENTERPRISE_ROLE_IDS = {1429509593452773447, 1429092701344628860}
PERSONAL_ROLE_IDS = {1434643718362763364, 1429092701344628860}

# Webhook URLs from environment variables
PINS_CREATED_WEBHOOK_URL = os.environ.get("PINS_CREATED_WEBHOOK_URL")
SELF_SCAN_WEBHOOK_URL = os.environ.get("SELF_SCAN_WEBHOOK_URL")
SCREENSHARE_WEBHOOK_URL = os.environ.get("SCREENSHARE_WEBHOOK_URL")
SUS_RESULTS_WEBHOOK_URL = os.environ.get("SUS_RESULTS_WEBHOOK_URL")
SECURITY_ALERTS_WEBHOOK_URL = os.environ.get("SECURITY_ALERTS_WEBHOOK_URL")
SITE_LOGIN_WEBHOOK_URL = os.environ.get("SITE_LOGIN_WEBHOOK_URL")
BAN_LOGS_WEBHOOK_URL = os.environ.get("BAN_LOGS_WEBHOOK_URL")
TOS_ACCEPT_WEBHOOK_URL = os.environ.get("TOS_ACCEPT_WEBHOOK_URL")
LICENSE_LOGS_WEBHOOK_URL = os.environ.get("LICENSE_LOGS_WEBHOOK_URL")

# Security Improvements Webhook
SECURITY_IMPROVEMENTS_WEBHOOK_URL = "https://discord.com/api/webhooks/1429531880734064820/GQ_Q_OhNtkGSGef52p8fheQs487gCzFsunNHsnxO2pHsJ2c2QMMHzpZuneokrsdUKNg8"


# Admin configuration
ADMIN_DISCORD_IDS = {
    "926572380409712660",
    "497725390480211978",
    "1355578401494274212"
}

# Licensed Users configuration (Admins are automatically licensed)
LICENSED_DISCORD_IDS = set()

# --- 2. Database Models ---

class Enterprise(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    admin_user_id = db.Column(db.String(20), db.ForeignKey('user.id'), nullable=False)
    license_expires_at = db.Column(db.DateTime, nullable=True)
    has_custom_loader = db.Column(db.Boolean, default=False, nullable=False)
    loader_path = db.Column(db.String(255), nullable=True)
    warnings = db.Column(db.Integer, default=0, nullable=False)
    game = db.Column(db.String(50), nullable=False, server_default='fivem')
    members = db.relationship('User', foreign_keys='User.enterprise_id', backref='enterprise', lazy='dynamic')
    admin = db.relationship('User', foreign_keys=[admin_user_id])

class User(db.Model, UserMixin):
    id = db.Column(db.String(20), primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    avatar = db.Column(db.String(120))
    role = db.Column(db.String(10), default='user', nullable=False)
    has_license = db.Column(db.Boolean, default=False, nullable=False)
    is_banned = db.Column(db.Boolean, default=False, nullable=False)
    ban_reason = db.Column(db.Text, nullable=True)
    ban_expires_at = db.Column(db.DateTime, nullable=True)
    responsible_admin_id = db.Column(db.String(20), nullable=True)
    license_expires_at = db.Column(db.DateTime, nullable=True)
    enterprise_id = db.Column(db.Integer, db.ForeignKey('enterprise.id'), nullable=True)
    tos_accepted = db.Column(db.Boolean, default=False, nullable=False)
    browser_fingerprint = db.Column(db.String(100), nullable=True)  # Store browser fingerprint
    scans = db.relationship('Scan', backref='user', lazy=True, cascade="all, delete-orphan")

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pin = db.Column(db.Integer, unique=True, nullable=False)
    url = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(50), default='Pending', nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    is_public = db.Column(db.Boolean, default=False, nullable=False)
    user_id = db.Column(db.String(20), db.ForeignKey('user.id'), nullable=False)
    game = db.Column(db.String(50), nullable=False, server_default='fivem')
    findings = db.relationship('Finding', backref='scan', lazy=True, cascade="all, delete-orphan")
    system_info = db.relationship('SystemInfo', backref='scan', uselist=False, lazy=True, cascade="all, delete-orphan")
    user_identities = db.relationship('UserIdentity', backref='scan', lazy=True, cascade="all, delete-orphan")
    browser_histories = db.relationship('BrowserHistory', backref='scan', lazy=True, cascade="all, delete-orphan")
    command_histories = db.relationship('CommandHistory', backref='scan', lazy=True, cascade="all, delete-orphan")
    game_analyses = db.relationship('GameAnalysis', backref='scan', lazy=True, cascade="all, delete-orphan")
    artifacts = db.relationship('Artifact', backref='scan', lazy=True, cascade="all, delete-orphan")
    recent_executables = db.relationship('RecentExecutable', backref='scan', lazy=True, cascade="all, delete-orphan")
    hardware_info = db.relationship('HardwareInfo', backref='scan', lazy=True, cascade="all, delete-orphan")
    system_services = db.relationship('SystemService', backref='scan', lazy=True, cascade="all, delete-orphan")

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    path = db.Column(db.String(1024), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    file_hash = db.Column(db.String(64))
    yara_rule = db.Column(db.String(100))
    source_type = db.Column(db.String(50))
    score = db.Column(db.Integer, nullable=True)
    score_contributors = db.Column(db.Text, nullable=True)  # JSON field for storing score contributors
    last_execution_time = db.Column(db.String(50), nullable=True)  # Last execution time of the cheat file
    match_count = db.Column(db.Integer, nullable=True)  # Number of indicators matched
    confidence_score = db.Column(db.Integer, nullable=True)  # Confidence score (0-100)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)

class SystemInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False, unique=True)
    os_version = db.Column(db.String(255))
    cpu_info = db.Column(db.String(255))
    ram_total = db.Column(db.String(50))
    hardware_id = db.Column(db.String(255))
    antivirus = db.Column(db.String(255))
    uptime = db.Column(db.String(100))

class UserIdentity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    identity_type = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(255))
    user_id = db.Column(db.String(255))
    additional_info = db.Column(db.Text)

class BrowserHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    browser = db.Column(db.String(50))
    url = db.Column(db.Text)
    title = db.Column(db.Text)
    visit_count = db.Column(db.Integer)

class CommandHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    type = db.Column(db.String(50))
    command = db.Column(db.Text)
    is_suspicious = db.Column(db.Boolean)
    keywords_found = db.Column(db.Text)

class GameAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    installation_path = db.Column(db.Text)
    mod_detected = db.Column(db.Boolean)
    mod_name = db.Column(db.String(255))
    mod_path = db.Column(db.Text)
    mod_details = db.Column(db.Text)

class Artifact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    details = db.Column(db.Text)
    status = db.Column(db.String(20))

class RecentExecutable(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    process_name = db.Column(db.String(255), nullable=False)
    last_executed = db.Column(db.DateTime)
    risk_level = db.Column(db.String(20), nullable=False) # 'safe', 'suspicious', 'dangerous'
    details = db.Column(db.Text)

class HardwareInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    details = db.Column(db.Text)

class SystemService(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text)

class CustomRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(20), db.ForeignKey('user.id'), nullable=False)
    rule_type = db.Column(db.String(20), nullable=False)  # 'yara', 'keyword', 'hash'
    name = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)  # YARA rule content, keyword, or hash
    severity = db.Column(db.String(20), nullable=False)  # 'Low', 'Medium', 'High', 'Critical'
    category = db.Column(db.String(100), nullable=True)  # For keywords: 'File Path', 'Process Name', etc.
    description = db.Column(db.String(500), nullable=True)  # For hashes
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    user = db.relationship('User', backref='custom_rules')

class CustomRuleFinding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    rule_id = db.Column(db.Integer, db.ForeignKey('custom_rule.id'), nullable=True)
    rule_name = db.Column(db.String(255), nullable=False)
    rule_type = db.Column(db.String(20), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    matched_content = db.Column(db.Text, nullable=False)
    location = db.Column(db.Text, nullable=False)
    scan = db.relationship('Scan', backref='custom_rule_findings')
    rule = db.relationship('CustomRule', backref='findings')

class HardwareFingerprint(db.Model):
    """Hardware-based device fingerprinting for ban enforcement"""
    id = db.Column(db.Integer, primary_key=True)
    fingerprint_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    is_banned = db.Column(db.Boolean, default=False, nullable=False, index=True)
    ban_reason = db.Column(db.Text, nullable=True)
    banned_at = db.Column(db.DateTime, nullable=True)
    banned_by_admin_id = db.Column(db.String(20), nullable=True)
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    visit_count = db.Column(db.Integer, default=1, nullable=False)
    # Store hardware info for identification in admin panel
    hardware_info = db.Column(db.Text, nullable=True)  # JSON with GPU, CPU, screen, etc.
    associated_ips = db.Column(db.Text, nullable=True)  # JSON array of IPs
    associated_user_ids = db.Column(db.Text, nullable=True)  # JSON array of Discord IDs

# --- 2a. Database Migration Logic ---

def migrate_db():
    """
    Checks the database schema against the SQLAlchemy models and applies
    missing columns to existing tables without deleting data.
    
    SECURITY: Uses whitelist validation to prevent SQL injection.
    """
    print("🔄 Checking database schema...")
    inspector = sqlalchemy_inspect(db.engine)
    db_tables = inspector.get_table_names()
    
    total_added = 0
    
    # Security: Whitelist of valid SQL types to prevent injection
    VALID_SQL_TYPES = {
        'INTEGER', 'VARCHAR', 'TEXT', 'BOOLEAN', 'DATETIME', 
        'FLOAT', 'DECIMAL', 'DATE', 'TIME', 'BLOB'
    }

    for table_name, table in db.metadata.tables.items():
        if table_name not in db_tables:
            continue
        
        try:
            # Security: Validate table name (only alphanumeric and underscore)
            if not re.match(r'^[a-zA-Z0-9_]+$', table_name):
                send_security_improvement_log(
                    "SQL Injection Prevention",
                    f"Blocked invalid table name during migration: `{table_name}`",
                    15158332  # Red
                )
                print(f"⚠️  Skipping invalid table name: {table_name}", file=sys.stderr)
                continue
            
            db_columns = {c['name'] for c in inspector.get_columns(table_name)}
            model_columns = {c.name for c in table.columns}
            
            missing_columns = model_columns - db_columns
            
            if not missing_columns:
                continue

            print(f"📊 Table '{table_name}': Found {len(missing_columns)} missing column(s)")

            with db.engine.connect() as connection:
                trans = connection.begin()
                try:
                    for column_name in missing_columns:
                        # Security: Validate column name (only alphanumeric and underscore)
                        if not re.match(r'^[a-zA-Z0-9_]+$', column_name):
                            send_security_improvement_log(
                                "SQL Injection Prevention",
                                f"Blocked invalid column name during migration: `{column_name}` in table `{table_name}`",
                                15158332  # Red
                            )
                            print(f"  ⚠️  Skipping invalid column name: {column_name}", file=sys.stderr)
                            continue
                        
                        column_obj = table.c[column_name]
                        col_type = str(column_obj.type)
                        
                        # Security: Validate column type
                        col_type_base = col_type.split('(')[0].upper()
                        if col_type_base not in VALID_SQL_TYPES:
                            send_security_improvement_log(
                                "SQL Injection Prevention",
                                f"Blocked invalid column type during migration: `{col_type}` for column `{column_name}`",
                                15158332  # Red
                            )
                            print(f"  ⚠️  Skipping invalid column type: {col_type}", file=sys.stderr)
                            continue
                        
                        nullable = "NULL" if column_obj.nullable else "NOT NULL"
                        
                        # Use parameterized identifiers (SQLAlchemy handles escaping)
                        if 'sqlite' in str(db.engine.url).lower():
                            alter_sql = f'ALTER TABLE {table_name} ADD COLUMN {column_name} {col_type}'
                        else:
                            alter_sql = f'ALTER TABLE {table_name} ADD COLUMN {column_name} {col_type} {nullable}'

                        try:
                            connection.execute(text(alter_sql))
                            print(f"  ✅ Added: {column_name} ({col_type})")
                            total_added += 1
                        except OperationalError as e:
                            print(f"  ⚠️  Could not add '{column_name}': {e}", file=sys.stderr)
                    
                    trans.commit()
                    print(f"  💾 Changes committed for table '{table_name}'")
                    
                except Exception as e:
                    trans.rollback()
                    print(f"  ❌ Rollback: {e}", file=sys.stderr)
                    raise

        except Exception as e:
            print(f"❌ Failed to migrate table '{table_name}': {e}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
    
    if total_added > 0:
        print(f"✅ Database migration complete! Added {total_added} column(s)")
    else:
        print("✅ Database schema is up to date")
    print()

# --- 3. User Session Management ---

@login_manager.user_loader
def load_user(user_id):
    with app.app_context():
        return db.session.get(User, user_id)

# --- 3a. User Activity Tracking & Caching ---

# Global cache for Discord members
discord_members_cache = {
    'data': None,
    'timestamp': 0
}
DISCORD_MEMBERS_CACHE_DURATION = 300 # 5 minutes

@app.before_request
def before_request_handler():
    """
    Handles tasks before each request: 
    - Session validation and security checks
    - Verification check for new visitors
    - AI Traffic Guardian DDoS check.
    - Enforcing a canonical URL for production.
    - Tracking user activity for the active user count.
    - Logging request start time for performance monitoring.
    """
    # Store start time for logging AT THE VERY BEGINNING to prevent errors on redirect.
    g.start_time = time.time()
    
    # Session Security: Validate session integrity for authenticated users
    # DISABLED: Too aggressive with Cloudflare/proxies causing false positives
    # if current_user.is_authenticated:
    #     # Just update session metadata silently without alerts
    #     if 'login_timestamp' in session:
    #         session['ip_address'] = get_remote_address()
    #         session['user_agent'] = request.headers.get('User-Agent', '')[:200]
    
    # Paths that bypass ALL security checks (scanner client, downloads, etc.)
    # MUST BE FIRST - before any other checks
    security_bypass_paths = (
        '/api/submit/',           # Scanner result submission
        '/api/download-scanner/', # Scanner download
        '/api/telemetry',         # Telemetry uploads
        '/callback',              # OAuth callback
        '/static/',               # Static files
        '/favicon',               # Favicon
    )
    
    # Skip all security checks for bypass paths
    if any(request.path.startswith(path) for path in security_bypass_paths):
        # Don't even try to use session for scanner client - it doesn't support cookies
        # Just return immediately and let the request through
        return None
    
    # Check hardware fingerprint ban (disabled for localhost)
    # if 'hardware_fingerprint' in session:
    #     hw_fingerprint_id = session['hardware_fingerprint']
    #     hw_record = HardwareFingerprint.query.filter_by(fingerprint_id=hw_fingerprint_id).first()
    #     
    #     if hw_record and hw_record.is_banned:
    #         # Hardware is banned - redirect to ban page
    #         if request.path != '/hardware-banned':
    #             return redirect(url_for('hardware_banned_page', reason=hw_record.ban_reason or 'Violation of Terms of Service'))
    
    # Paths that don't require verification (but still check hardware ban)
    verification_exempt_paths = (
        '/verify', '/api/verify', '/security.js', '/notifications.js',
        '/hardware-banned', '/login', '/logout'
    )
    
    # Check if user needs verification (disabled for localhost)
    # if not any(request.path.startswith(path) for path in verification_exempt_paths):
    #     if 'verified' not in session and not current_user.is_authenticated:
    #         # Store the original URL they wanted to visit
    #         session['verification_redirect'] = request.url
    #         return redirect(url_for('verify_page'))
    
    # AI Traffic Guardian DDoS check (disabled for localhost)
    # Define paths that are critical for scanner functionality and should not be blocked.
    # guardian_exempt_paths = ('/api/submit/', '/api/download-scanner/')
    # 
    # if AI_GUARDIAN_ENABLED and not request.path.startswith(guardian_exempt_paths):
    #     guardian_response = ai_guardian_check()
    #     if guardian_response is not None:
    #         return guardian_response
    
    # Enforce canonical URL (disabled for localhost)
    # canonical_host = "www.asyncac.cc"
    # Skip enforcement for localhost, static assets, and API calls to avoid issues
    # if (not app.debug and 
    #     request.host != canonical_host and
    #     not request.path.startswith('/api/') and
    #     not any(request.path.endswith(ext) for ext in ['.js', '.css', '.svg', '.png', '.jpg', '.ico'])):
    #     
    #     new_url = f"https://{canonical_host}{request.full_path}"
    #     return redirect(new_url, code=301)

    # Track user activity (skip for API endpoints that don't use sessions)
    if not request.path.startswith('/api/submit/'):
        try:
            if 'session_id' not in session:
                session['session_id'] = str(uuid.uuid4())
                ACTIVE_SESSIONS[session['session_id']] = time.time()
            elif session['session_id'] not in ACTIVE_SESSIONS:
                ACTIVE_SESSIONS[session['session_id']] = time.time()
        except:
            # If session fails (e.g., scanner client), just skip tracking
            pass


@app.after_request
def after_request_handler(response):
    """Log request details after the request has been processed."""
    # Exclude non-essential endpoints from logging to keep the log clean.
    excluded_paths = ['/api/admin/logs', '/api/admin/system-stats', '/api/admin/ddos-logs', '/api/admin/ai-guardian-status']
    if request.path in excluded_paths:
        return response

    # Check if start_time was set (it might not be if there was an early redirect)
    if hasattr(g, 'start_time'):
        response_time_ms = (time.time() - g.start_time) * 1000
    else:
        response_time_ms = 0.0
    
    log_entry = {
        'time': datetime.now(timezone.utc).isoformat(),
        'ip': get_remote_address(),
        'method': request.method,
        'path': request.path,
        'status': response.status_code,
        'response_time': f"{response_time_ms:.2f}ms"
    }
    
    # Prepend to deque so newest logs are first
    api_logs.appendleft(log_entry)
    
    return response

def get_active_user_count():
    """Cleans up old sessions and returns the count of active users."""
    global ACTIVE_SESSIONS
    now = time.time()
    # Create a new dictionary with only active users
    active_sessions = {sid: ts for sid, ts in ACTIVE_SESSIONS.items() if now - ts < SESSION_TIMEOUT}
    # Atomically update the global dictionary
    ACTIVE_SESSIONS = active_sessions
    return len(active_sessions)

# --- 4. Helper Functions & Decorators ---

# Hardware Fingerprinting Functions
def generate_hardware_fingerprint(fingerprint_data):
    """Generate a unique hardware fingerprint ID from client data"""
    import hashlib
    
    if not fingerprint_data or not isinstance(fingerprint_data, dict):
        # Fallback to random if no data
        return hashlib.sha256(str(time.time()).encode()).hexdigest()
    
    # Combine stable hardware characteristics
    components = []
    
    # Screen resolution (stable)
    screen = fingerprint_data.get('screen', {})
    if screen:
        components.append(f"{screen.get('width')}x{screen.get('height')}x{screen.get('colorDepth')}")
    
    # Hardware concurrency (CPU cores - stable)
    if fingerprint_data.get('hardwareConcurrency'):
        components.append(str(fingerprint_data.get('hardwareConcurrency')))
    
    # Device memory (stable)
    if fingerprint_data.get('deviceMemory'):
        components.append(str(fingerprint_data.get('deviceMemory')))
    
    # WebGL renderer (GPU - very stable)
    webgl = fingerprint_data.get('webgl', {})
    if isinstance(webgl, dict):
        if webgl.get('vendor'):
            components.append(webgl.get('vendor'))
        if webgl.get('renderer'):
            components.append(webgl.get('renderer'))
    
    # Canvas fingerprint (stable)
    if fingerprint_data.get('canvas'):
        components.append(str(fingerprint_data.get('canvas')))
    
    # Platform (stable)
    if fingerprint_data.get('platform'):
        components.append(fingerprint_data.get('platform'))
    
    # Timezone (relatively stable)
    if fingerprint_data.get('timezone'):
        components.append(fingerprint_data.get('timezone'))
    
    # Create hash from combined components
    fingerprint_string = '|'.join(components)
    fingerprint_id = hashlib.sha256(fingerprint_string.encode()).hexdigest()
    
    return fingerprint_id

# Input Validation & Sanitization Functions
def sanitize_text_input(text, max_length=500):
    """Sanitize user text input to prevent XSS and injection attacks"""
    if not text or not isinstance(text, str):
        return ""
    
    # Remove any HTML tags and dangerous characters
    import html
    cleaned = html.escape(text.strip())
    
    # Limit length
    return cleaned[:max_length]

def validate_discord_id(discord_id):
    """Validate Discord ID format (17-19 digits)"""
    if not isinstance(discord_id, str):
        return False
    return bool(re.match(r'^\d{17,19}$', discord_id))

def validate_pin(pin):
    """Validate scan PIN format (4-6 digits)"""
    if isinstance(pin, int):
        return 1000 <= pin <= 999999  # Support 4-6 digit PINs
    if isinstance(pin, str):
        return pin.isdigit() and 4 <= len(pin) <= 6 and 1000 <= int(pin) <= 999999
    return False

def validate_duration(duration):
    """Validate ban/license duration"""
    if not isinstance(duration, (int, str)):
        return False
    try:
        dur = int(duration)
        return 0 <= dur <= 365  # Max 1 year or permanent (0)
    except:
        return False

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

def internal_or_admin_required(f):
    """
    Decorator that allows access if the request is from localhost (internal)
    OR if the user is a logged-in admin.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Case 1: Internal request from the bot on the same machine
        # get_remote_address() correctly handles proxies.
        if get_remote_address() == '127.0.0.1':
            return f(*args, **kwargs)

        # Case 2: Logged-in admin user via the web UI
        if current_user.is_authenticated and current_user.role == 'admin':
            return f(*args, **kwargs)
        
        # If neither, deny access with a JSON error.
        # This is appropriate for API endpoints.
        return jsonify({'error': 'Admin access or internal request required'}), 403
    return decorated_function

def enterprise_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
            
        # Re-fetch the user to ensure data is fresh and session-bound
        user = db.session.get(User, current_user.id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        is_admin = (
            user.enterprise_id and
            user.enterprise and
            user.enterprise.admin_user_id == user.id
        )
        if not is_admin:
            return jsonify({'error': 'Enterprise admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Super Admin IDs (for Discord Management and Messaging)
SUPER_ADMIN_IDS = {'926572380409712660', '1355578401494274212'}

def super_admin_required(f):
    """Decorator to restrict access to super admins only"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
        if current_user.id not in SUPER_ADMIN_IDS:
            return jsonify({'error': 'Super admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function


def to_dict(obj, relationships_to_expand=None):
    if relationships_to_expand is None:
        relationships_to_expand = []
    d = {}
    for column in obj.__table__.columns:
        val = getattr(obj, column.name)
        if isinstance(val, datetime):
            d[column.name] = val.isoformat()
        else:
            d[column.name] = val

    for rel in relationships_to_expand:
        related_obj = getattr(obj, rel)
        if related_obj:
            if isinstance(related_obj, list):
                d[rel] = [to_dict(o) for o in related_obj]
            else:
                d[rel] = to_dict(related_obj)
    return d

def generate_unique_pin():
    while True:
        pin = random.randint(100000, 999999)
        if not Scan.query.filter_by(pin=pin).first():
            return pin

async def get_user_voice_state_info(user_id):
    """Fetches voice state information for a given user ID from the Discord bot."""
    if not bot.is_ready():
        return None
    
    try:
        user_id_int = int(user_id)
        guild = bot.get_guild(DISCORD_GUILD_ID)
        if not guild:
            return None
        
        member = guild.get_member(user_id_int)
        if not member or not member.voice:
            return None

        voice_state = member.voice
        channel = voice_state.channel
        
        viewers = []
        for viewer_member in channel.members:
            if viewer_member.id != user_id_int:
                viewers.append(f"<@{viewer_member.id}>")
        
        info = {
            "channel_name": channel.name,
            "is_streaming": voice_state.self_stream,
            "viewers": viewers,
            "viewer_count": len(viewers)
        }
        
        return info

    except (ValueError, AttributeError) as e:
        print(f"Error fetching voice state for user {user_id}: {e}", file=sys.stderr)
        return None

def send_pin_creation_notification(user_id, username, pin):
    """Sends a Discord notification when a new scan PIN is created."""
    if not PINS_CREATED_WEBHOOK_URL: return
    
    embed = {
        "title": "🔑 New Scan PIN Generated",
        "description": f"User **{username}** has generated a new scan PIN.",
        "color": 3447003, # Blue
        "fields": [
            {"name": "User", "value": f"<@{user_id}>", "inline": True},
            {"name": "Generated PIN", "value": f"`{pin}`", "inline": True}
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {"text": f"</async> Scanner | User ID: {user_id}"}
    }
    
    try:
        requests.post(PINS_CREATED_WEBHOOK_URL, json={"embeds": [embed]}, timeout=15)
    except requests.exceptions.RequestException as e:
        print(f"Error sending PIN creation notification: {e}", file=sys.stderr)

def send_scan_submission_notification(user, hwid, scan_pin, scan_id, findings_count, scanned_user_discord_id=None):
    """Sends a differentiated Discord notification based on scan results and context."""
    report_url = f"{APP_BASE_URL}/report?id={scan_id}"
    
    # Get user's browser fingerprint
    fingerprint_id = user.browser_fingerprint if hasattr(user, 'browser_fingerprint') and user.browser_fingerprint else 'Unknown'
    
    # Determine which user to check for screensharing. Prioritize the scanned user if their ID was found.
    user_id_to_check_for_stream = scanned_user_discord_id if scanned_user_discord_id else user.id
    is_checking_scanned_user = bool(scanned_user_discord_id)

    voice_info = None
    if bot.is_ready() and bot.loop.is_running():
        try:
            future = asyncio.run_coroutine_threadsafe(get_user_voice_state_info(user_id_to_check_for_stream), bot.loop)
            voice_info = future.result(timeout=3)  # Reduced timeout to 3s
        except TimeoutError:
            print(f"⏱️ Timeout fetching voice state for user {user_id_to_check_for_stream}", file=sys.stderr)
        except Exception as e:
            print(f"Could not fetch voice state for user {user_id_to_check_for_stream}: {e}", file=sys.stderr)
    
    is_screenshare_scan = voice_info and voice_info.get('is_streaming')

    webhook_url = None
    embed = None

    # More robust display name for the scanned user
    scanned_user_display = f"<@{scanned_user_discord_id}>" if scanned_user_discord_id else "An unidentified user"
    streamer_mention = f"<@{user_id_to_check_for_stream}>"

    if findings_count > 0:
        webhook_url = SUS_RESULTS_WEBHOOK_URL
        if webhook_url:
            description = f"**{findings_count} threat(s)** were detected for {scanned_user_display}."
            if is_screenshare_scan:
                description += f"\nThe scan was performed while **{streamer_mention}** was screen sharing."
            
            embed = {
                "title": "🚨 Suspicious Scan Result Submitted",
                "description": description,
                "color": 15158332, # Red
                "thumbnail": {"url": user.avatar},
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "footer": {"text": f"</async> Scanner | Staff ID: {user.id}"}
            }
            fields = [
                {"name": "Scanned User", "value": scanned_user_display, "inline": True},
                {"name": "Scan PIN", "value": f"`{scan_pin}`", "inline": True},
                {"name": "Threats Found", "value": f"**{findings_count}**", "inline": True},
            ]
            if is_screenshare_scan:
                embed["title"] = "🚨 Suspicious SCREENSHARE Scan Result"
                fields.extend([
                    {"name": "Voice Channel", "value": f"`{voice_info.get('channel_name', 'N/A')}`", "inline": True},
                    {"name": "Viewer Count", "value": str(voice_info.get('viewer_count', 0)), "inline": True},
                    {"name": "Streaming User", "value": streamer_mention, "inline": True},
                ])
                viewers_value = ", ".join(voice_info.get('viewers', [])) if voice_info.get('viewers') else "None"
                if len(viewers_value) > 1024: viewers_value = viewers_value[:1020] + "..."
                fields.append({"name": "Viewers in Call", "value": viewers_value, "inline": False})
            fields.append({"name": "Hardware ID (UUID)", "value": f"```{hwid}```", "inline": False})
            
            # Add fingerprint ID if available
            if fingerprint_id and fingerprint_id != 'Unknown':
                fields.append({"name": "🔍 Fingerprint ID", "value": f"`{fingerprint_id}`", "inline": False})
            
            fields.append({"name": "View Full Report", "value": f"[Click here to view the detailed report]({report_url})", "inline": False})
            embed["fields"] = fields

    elif is_screenshare_scan:
        webhook_url = SCREENSHARE_WEBHOOK_URL
        if webhook_url:
            viewers_value = ", ".join(voice_info.get('viewers', [])) if voice_info.get('viewers') else "None"
            if len(viewers_value) > 1024: viewers_value = viewers_value[:1020] + "..."
            
            description = f"A clean scan was completed for {scanned_user_display} while they were screen sharing."

            fields = [
                {"name": "Scanned User", "value": scanned_user_display, "inline": True},
                {"name": "Scan PIN", "value": f"`{scan_pin}`", "inline": True},
                {"name": "Scan Initiated By", "value": f"<@{user.id}>", "inline": True},
                {"name": "Voice Channel", "value": f"`{voice_info.get('channel_name', 'N/A')}`", "inline": True},
                {"name": "Viewer Count", "value": str(voice_info.get('viewer_count', 0)), "inline": True},
                {"name": "Streaming User", "value": streamer_mention, "inline": True},
                {"name": "Viewers in Call", "value": viewers_value, "inline": False},
            ]
            
            # Add fingerprint ID if available
            if fingerprint_id and fingerprint_id != 'Unknown':
                fields.append({"name": "🔍 Fingerprint ID", "value": f"`{fingerprint_id}`", "inline": False})
            
            fields.append({"name": "View Full Report", "value": f"[Click here to view the detailed report]({report_url})", "inline": False})
            
            embed = {
                "title": "🖥️ Clean Screen Share Scan Submitted",
                "description": description,
                "color": 5811378, # Discord Blurple
                "fields": fields,
                "thumbnail": {"url": user.avatar},
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "footer": {"text": f"</async> Scanner | Staff ID: {user.id}"}
            }

    else: # Clean, non-screenshare scan
        webhook_url = SELF_SCAN_WEBHOOK_URL
        if webhook_url:
            fields = [
                {"name": "Scanned User", "value": scanned_user_display, "inline": True},
                {"name": "Scan PIN", "value": f"`{scan_pin}`", "inline": True},
                {"name": "Scan Initiated By", "value": f"<@{user.id}>", "inline": True},
            ]
            
            # Add fingerprint ID if available
            if fingerprint_id and fingerprint_id != 'Unknown':
                fields.append({"name": "🔍 Fingerprint ID", "value": f"`{fingerprint_id}`", "inline": False})
            
            fields.append({"name": "View Full Report", "value": f"[Click here to view the detailed report]({report_url})", "inline": False})
            
            embed = {
                "title": "📄 Clean Scan Submitted",
                "description": f"A clean scan has been completed for {scanned_user_display}.",
                "color": 3066993,  # Green
                "fields": fields,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "footer": {"text": f"</async> Scanner | Staff ID: {user.id}"}
            }
            
    # Centralized sending logic
    if webhook_url and embed:
        try:
            print(f"📤 Sending Discord notification: {findings_count} findings, webhook configured: {bool(webhook_url)}")
            response = requests.post(webhook_url, json={"embeds": [embed]}, timeout=15)
            print(f"✅ Discord notification sent: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"❌ Error sending Discord notification: {e}", file=sys.stderr)
    else:
        if not webhook_url:
            print(f"⚠️ No webhook URL configured for this scan type (findings: {findings_count})", file=sys.stderr)
        if findings_count == 0:
            print(f"Warning: Webhook URL for clean scans is not configured. Clean scan for user {user.id} was not logged.", file=sys.stderr)


def send_security_alert(title, description, color=16776960, fields=None): # Default to yellow
    """Sends a security alert to a dedicated webhook."""
    if not SECURITY_ALERTS_WEBHOOK_URL: return
    
    embed = {
        "title": f"🛡️ Security Alert: {title}",
        "description": description,
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {"text": "</async> Security Monitor"}
    }

    # Automatically add request context if available
    auto_fields = []
    try:
        if request:
            auto_fields.extend([
                {"name": "IP Address", "value": f"`{get_remote_address()}`", "inline": True},
                {"name": "Endpoint", "value": f"`{request.path}`", "inline": True},
            ])
            user_info = f"<@{current_user.id}> ({current_user.username})" if current_user.is_authenticated else "Not Logged In"
            auto_fields.append({"name": "User", "value": user_info, "inline": True})
            auto_fields.append({"name": "User-Agent", "value": f"```{request.user_agent.string}```", "inline": False})
    except RuntimeError: # Not in a request context
        pass
        
    if fields:
        # Prepend auto_fields to the custom fields
        embed["fields"] = auto_fields + fields
    else:
        embed["fields"] = auto_fields
    
    try:
        requests.post(SECURITY_ALERTS_WEBHOOK_URL, json={"embeds": [embed]}, timeout=15)
    except requests.exceptions.RequestException as e:
        print(f"Error sending security alert: {e}", file=sys.stderr)

def send_verification_with_screenshot(log_fields, screenshot_data, ip_address):
    """Send verification log with screenshot attachment to Discord"""
    if not SECURITY_IMPROVEMENTS_WEBHOOK_URL:
        return
    
    try:
        import base64
        import io
        
        # Decode base64 screenshot
        if screenshot_data and screenshot_data.startswith('data:image/png;base64,'):
            screenshot_data = screenshot_data.split(',')[1]
        elif not screenshot_data:
            # No screenshot data, send normal log
            send_security_improvement_log(
                "✅ User Verification Complete",
                "New visitor successfully verified and granted access to the site.",
                3066993,
                fields=log_fields
            )
            return
        
        image_bytes = base64.b64decode(screenshot_data)
        
        # Create embed
        embed = {
            "title": "✅ User Verification Complete",
            "description": f"New visitor successfully verified and granted access to the site.\n📸 **Screenshot attached below**",
            "color": 3066993,  # Green
            "fields": log_fields,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "footer": {"text": "</async> Security System"}
        }
        
        # Prepare multipart form data with proper format
        filename = f'verification_{ip_address.replace(".", "_")}_{int(time.time())}.png'
        
        files = {
            'file': (filename, io.BytesIO(image_bytes), 'image/png')
        }
        
        payload = {
            'embeds': [embed]
        }
        
        # Send to Discord with file attachment
        response = requests.post(
            SECURITY_IMPROVEMENTS_WEBHOOK_URL,
            data={'payload_json': json.dumps(payload)},
            files=files,
            timeout=10
        )
        
        if response.status_code not in [200, 204]:
            print(f"Failed to send verification screenshot: {response.status_code} - {response.text}", file=sys.stderr)
            # Fallback to normal log without screenshot
            send_security_improvement_log(
                "✅ User Verification Complete",
                "New visitor successfully verified (screenshot upload failed).",
                3066993,
                fields=log_fields
            )
        else:
            print(f"✅ Verification screenshot sent successfully for IP: {ip_address}")
            
    except Exception as e:
        print(f"Error sending verification screenshot: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        # Fallback to normal log
        send_security_improvement_log(
            "✅ User Verification Complete",
            "New visitor successfully verified (screenshot processing failed).",
            3066993,
            fields=log_fields
        )

def send_security_improvement_log(title, description, color=3066993, fields=None): # Default to green
    """Sends security improvement logs to a dedicated webhook for monitoring security enhancements."""
    if not SECURITY_IMPROVEMENTS_WEBHOOK_URL: return
    
    embed = {
        "title": f"🔒 Security Improvement: {title}",
        "description": description,
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {"text": "</async> Security Improvements Monitor"}
    }

    # Automatically add request context if available
    auto_fields = []
    try:
        if request:
            auto_fields.extend([
                {"name": "IP Address", "value": f"`{get_remote_address()}`", "inline": True},
                {"name": "Endpoint", "value": f"`{request.path}`", "inline": True},
            ])
            user_info = f"<@{current_user.id}> ({current_user.username})" if current_user.is_authenticated else "Not Logged In"
            auto_fields.append({"name": "User", "value": user_info, "inline": True})
    except RuntimeError: # Not in a request context
        pass
        
    if fields:
        embed["fields"] = auto_fields + fields
    else:
        embed["fields"] = auto_fields
    
    try:
        requests.post(SECURITY_IMPROVEMENTS_WEBHOOK_URL, json={"embeds": [embed]}, timeout=15)
    except requests.exceptions.RequestException as e:
        print(f"Error sending security improvement log: {e}", file=sys.stderr)

def sanitized_error_response(error_exception, user_message="An error occurred", status_code=500, log_to_webhook=True):
    """
    Returns a sanitized error response that doesn't expose sensitive information.
    Logs the actual error server-side and optionally to webhook.
    
    SECURITY: Prevents information disclosure through error messages.
    """
    # Generate a unique error ID for tracking
    error_id = str(uuid.uuid4())[:8]
    
    # Log the actual error server-side with full details
    error_details = f"Error ID: {error_id} | {type(error_exception).__name__}: {str(error_exception)}"
    print(f"SECURITY: Sanitized Error - {error_details}", file=sys.stderr)
    
    # Log to security improvements webhook
    if log_to_webhook:
        try:
            endpoint = request.path if request else "Unknown"
            send_security_improvement_log(
                "Error Sanitization",
                f"Prevented information disclosure through error message sanitization.",
                16776960,  # Yellow
                fields=[
                    {"name": "Error ID", "value": f"`{error_id}`", "inline": True},
                    {"name": "Error Type", "value": f"`{type(error_exception).__name__}`", "inline": True},
                    {"name": "Endpoint", "value": f"`{endpoint}`", "inline": False},
                    {"name": "Actual Error (Server-Side Only)", "value": f"```{str(error_exception)[:500]}```", "inline": False}
                ]
            )
        except Exception as log_error:
            print(f"Failed to log sanitized error to webhook: {log_error}", file=sys.stderr)
    
    # Return generic error to client
    return jsonify({
        'error': user_message,
        'error_id': error_id,
        'message': 'Please contact support with this error ID if the problem persists.'
    }), status_code

def send_login_notification(user_id, username, avatar_url, fingerprint_id=None):
    """Sends a Discord notification when a user logs in."""
    if not SITE_LOGIN_WEBHOOK_URL: return
    
    fields = [
        {"name": "User", "value": f"<@{user_id}>", "inline": True},
        {"name": "User ID", "value": f"`{user_id}`", "inline": True}
    ]
    
    # Add fingerprint ID if available
    if fingerprint_id and fingerprint_id != 'Unknown':
        fields.append({"name": "🔍 Fingerprint ID", "value": f"`{fingerprint_id}`", "inline": False})
    
    embed = {
        "title": "💻 User Logged In",
        "description": f"User **{username}** has successfully logged into the website.",
        "color": 3553599, # Aqua
        "fields": fields,
        "thumbnail": {"url": avatar_url},
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {"text": f"</async> Scanner | Site Login Logs"}
    }
    
    try:
        requests.post(SITE_LOGIN_WEBHOOK_URL, json={"embeds": [embed]}, timeout=15)
    except requests.exceptions.RequestException as e:
        print(f"Error sending login notification: {e}", file=sys.stderr)

def send_ban_notification(banned_user_id, banned_username, admin_user_id, admin_username, reason, duration_days):
    """Sends a Discord notification when a user is banned."""
    if not BAN_LOGS_WEBHOOK_URL: return
    
    if duration_days is not None and duration_days > 0:
        duration_text = f"{duration_days} Day(s)"
        expiration_date = datetime.now(timezone.utc) + timedelta(days=duration_days)
        expiration_text = f"Expires on {expiration_date.strftime('%Y-%m-%d')}"
    else:
        duration_text = "Permanent"
        expiration_text = "This ban does not expire."

    embed = {
        "title": "🚫 User Banned",
        "description": f"**{banned_username}** has been banned by **{admin_username}**.",
        "color": 15158332, # Red
        "fields": [
            {"name": "Banned User", "value": f"<@{banned_user_id}> (`{banned_user_id}`)", "inline": False},
            {"name": "Banned By (Admin)", "value": f"<@{admin_user_id}> (`{admin_user_id}`)", "inline": False},
            {"name": "Reason", "value": f"```{reason}```", "inline": False},
            {"name": "Duration", "value": duration_text, "inline": True},
            {"name": "Expiration", "value": expiration_text, "inline": True},
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {"text": f"</async> Scanner | Ban Logs"}
    }
    
    try:
        requests.post(BAN_LOGS_WEBHOOK_URL, json={"embeds": [embed]}, timeout=15)
    except requests.exceptions.RequestException as e:
        print(f"Error sending ban notification: {e}", file=sys.stderr)

async def update_user_roles(user_id: str, license_type: str):
    """
    Updates a user's roles in Discord based on their license type.
    license_type can be 'enterprise', 'personal', or 'none'.
    """
    if not bot.is_ready():
        print(f"Role Update Skipped: Bot not ready for user {user_id}")
        return

    try:
        guild = bot.get_guild(DISCORD_GUILD_ID)
        if not guild:
            print(f"Role Update Failed: Guild {DISCORD_GUILD_ID} not found.")
            return

        member = guild.get_member(int(user_id))
        if not member:
            # User might not be in the server, which is fine.
            print(f"Role Update Skipped: User {user_id} not found in guild {DISCORD_GUILD_ID}.")
            return

        # Get Role objects from IDs
        all_license_roles_ids = ENTERPRISE_ROLE_IDS.union(PERSONAL_ROLE_IDS)
        all_license_roles = {guild.get_role(role_id) for role_id in all_license_roles_ids}
        all_license_roles.discard(None) # Remove any roles not found

        roles_to_add = set()
        if license_type == 'enterprise':
            roles_to_add = {guild.get_role(role_id) for role_id in ENTERPRISE_ROLE_IDS}
        elif license_type == 'personal':
            roles_to_add = {guild.get_role(role_id) for role_id in PERSONAL_ROLE_IDS}
        
        roles_to_add.discard(None) # Remove any roles not found

        current_roles = set(member.roles)
        roles_to_remove = (current_roles & all_license_roles) - roles_to_add
        
        final_roles_to_add = list(roles_to_add - current_roles)
        final_roles_to_remove = list(roles_to_remove)

        if final_roles_to_add:
            await member.add_roles(*final_roles_to_add, reason="Automatic license role assignment.")
            print(f"Added roles {[r.name for r in final_roles_to_add]} to user {user_id}.")
        
        if final_roles_to_remove:
            await member.remove_roles(*final_roles_to_remove, reason="Automatic license role update/revocation.")
            print(f"Removed roles {[r.name for r in final_roles_to_remove]} from user {user_id}.")

    except (ValueError, AttributeError, discord.Forbidden, discord.HTTPException) as e:
        print(f"CRITICAL: Failed to update roles for user {user_id}: {e}", file=sys.stderr)

def send_unban_notification(unbanned_user_id, unbanned_username, admin_user_id, admin_username):
    """Sends a Discord notification when a user is unbanned."""
    if not BAN_LOGS_WEBHOOK_URL: return
    
    embed = {
        "title": "🕊️ User Unbanned",
        "description": f"**{unbanned_username}** has been unbanned by **{admin_username}**.",
        "color": 3066993, # Green
        "fields": [
            {"name": "Unbanned User", "value": f"<@{unbanned_user_id}> (`{unbanned_user_id}`)", "inline": False},
            {"name": "Unbanned By (Admin)", "value": f"<@{admin_user_id}> (`{admin_user_id}`)", "inline": False},
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {"text": f"</async> Scanner | Ban Logs"}
    }
    
    try:
        requests.post(BAN_LOGS_WEBHOOK_URL, json={"embeds": [embed]}, timeout=15)
    except requests.exceptions.RequestException as e:
        print(f"Error sending unban notification: {e}", file=sys.stderr)

def send_tos_acceptance_notification(user_id, username):
    """Sends a Discord notification when a user accepts the ToS."""
    if not TOS_ACCEPT_WEBHOOK_URL: return
    
    embed = {
        "title": "📜 Terms of Service Accepted",
        "description": f"User **{username}** has accepted the Terms of Service.",
        "color": 3066993, # Green
        "fields": [
            {"name": "User", "value": f"<@{user_id}>", "inline": True},
            {"name": "User ID", "value": f"`{user_id}`", "inline": True}
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {"text": f"</async> Scanner | ToS Accept Logs"}
    }
    
    try:
        requests.post(TOS_ACCEPT_WEBHOOK_URL, json={"embeds": [embed]}, timeout=15)
    except requests.exceptions.RequestException as e:
        print(f"Error sending ToS acceptance notification: {e}", file=sys.stderr)

def send_license_grant_notification(granter_id, granter_name, target_id, target_name, duration_text, enterprise_name=None):
    """Sends a Discord notification when a license is granted."""
    if not LICENSE_LOGS_WEBHOOK_URL: return
    
    embed = {
        "title": "✅ License Granted",
        "description": f"**{target_name}** has been granted a license by **{granter_name}**.",
        "color": 3066993, # Green
        "fields": [
            {"name": "Granted To", "value": f"<@{target_id}> (`{target_id}`)", "inline": False},
            {"name": "Granted By", "value": f"<@{granter_id}> (`{granter_id}`)", "inline": False},
            {"name": "Duration", "value": duration_text, "inline": True},
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {"text": f"</async> Scanner | License Logs"}
    }
    if enterprise_name:
        embed["fields"].append({"name": "Enterprise", "value": enterprise_name, "inline": True})
    
    try:
        requests.post(LICENSE_LOGS_WEBHOOK_URL, json={"embeds": [embed]}, timeout=15)
    except requests.exceptions.RequestException as e:
        print(f"Error sending license grant notification: {e}", file=sys.stderr)

def send_license_revoke_notification(revoker_id, revoker_name, target_id, target_name, enterprise_name=None):
    """Sends a Discord notification when a license is revoked."""
    if not LICENSE_LOGS_WEBHOOK_URL: return
    
    embed = {
        "title": "❌ License Revoked",
        "description": f"The license for **{target_name}** has been revoked by **{revoker_name}**.",
        "color": 15158332, # Red
        "fields": [
            {"name": "Revoked From", "value": f"<@{target_id}> (`{target_id}`)", "inline": False},
            {"name": "Revoked By", "value": f"<@{revoker_id}> (`{revoker_id}`)", "inline": False},
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {"text": f"</async> Scanner | License Logs"}
    }
    if enterprise_name:
         embed["fields"].append({"name": "Enterprise", "value": enterprise_name, "inline": True})

    try:
        requests.post(LICENSE_LOGS_WEBHOOK_URL, json={"embeds": [embed]}, timeout=15)
    except requests.exceptions.RequestException as e:
        print(f"Error sending license revoke notification: {e}", file=sys.stderr)

def send_enterprise_deletion_notification(revoker_id, revoker_name, enterprise_name, member_count):
    """Sends a Discord notification when an enterprise is deleted."""
    if not LICENSE_LOGS_WEBHOOK_URL: return
    
    embed = {
        "title": "🏢 Enterprise Deleted",
        "description": f"The enterprise **{enterprise_name}** has been deleted by **{revoker_name}**.",
        "color": 15158332, # Red
        "fields": [
            {"name": "Deleted By", "value": f"<@{revoker_id}> (`{revoker_id}`)", "inline": False},
            {"name": "Affected Members", "value": f"{member_count} user(s) had their licenses revoked.", "inline": False},
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "footer": {"text": f"</async> Scanner | License Logs"}
    }
    
    try:
        requests.post(LICENSE_LOGS_WEBHOOK_URL, json={"embeds": [embed]}, timeout=15)
    except requests.exceptions.RequestException as e:
        print(f"Error sending enterprise deletion notification: {e}", file=sys.stderr)

STRUCTURED_ARTIFACT_MAP = {
    'SYSTEM_INFORMATION': SystemInfo,
    'USER_IDENTITIES': UserIdentity,
    'BROWSER_HISTORY': BrowserHistory,
    'COMMAND_HISTORY': CommandHistory,
    'RECENT_EXECUTABLES': RecentExecutable
}

def serialize_details(data):
    """
    Safely serializes data (including complex types) into a string for database storage.
    - Dictionaries/lists are converted to a JSON string.
    - Other types are converted to their standard string representation.
    - Returns None if input is None.
    """
    if data is None:
        return None
    if isinstance(data, (dict, list, tuple)):
        try:
            return json.dumps(data)
        except TypeError:
            # Fallback for complex, non-serializable objects (e.g., class instances)
            return str(data)
    return str(data)

# --- 4a. AI Traffic Guardian (DDoS Mitigation) ---
def trigger_gemini_analysis(current_global_rps, top_ips):
    """Formats data and calls Gemini for analysis in a separate thread."""
    if not gemini_model:
        return

    now = time.time()
    if now - AI_GUARDIAN_STATE.get("last_gemini_analysis_time", 0) < 60:
        return # Avoid spamming Gemini on rapid fluctuations

    AI_GUARDIAN_STATE["last_gemini_analysis_time"] = now
    
    def analysis_thread():
        try:
            top_ips_formatted = "\n".join([f"- `{ip}`: {rps} RPS" for ip, rps in top_ips])

            prompt = f"""
You are a senior cybersecurity analyst specializing in DDoS mitigation. I will provide you with a snapshot of server traffic during a suspected attack. Your task is to analyze the data and provide a concise, markdown-formatted summary suitable for a Discord embed.

**Context:**
- My server's normal traffic is under {AI_GUARDIAN_RPS_THRESHOLD} requests/second (RPS).
- Mitigation mode was triggered when traffic spiked to {current_global_rps} RPS.
- When in mitigation mode, any single IP exceeding {AI_GUARDIAN_IP_RPS_LIMIT} RPS is blocked for {AI_GUARDIAN_BLOCK_DURATION} seconds.

**Incident Data:**
- **Timestamp:** {datetime.now(timezone.utc).isoformat()}
- **Global RPS at trigger:** {current_global_rps}
- **Top 5 suspicious IP addresses (and their RPS):**
{top_ips_formatted}

**Your Task:**
Provide a brief analysis and recommendation. Your entire response must be 2-3 short paragraphs.
- **Analysis:** What kind of attack does this look like (e.g., volumetric, application-layer, distributed, single-source)? Is it a low-level or a sophisticated attack?
- **Recommendation:** Are the current thresholds appropriate? Should I adjust the IP RPS limit or the global threshold? Is there anything else I should do?
"""
            response = gemini_model.generate_content(prompt)
            analysis_text = response.text

            log_entry = {
                'time': datetime.now(timezone.utc).isoformat(),
                'type': 'GEMINI_ANALYSIS',
                'ip': 'N/A',
                'message': f"Gemini Analysis received for traffic spike."
            }
            ddos_logs.appendleft(log_entry)
            
            send_security_alert(
                "Gemini DDoS Analysis", 
                f"AI Guardian detected a traffic anomaly and requested an analysis from Gemini.",
                16729344, # Orange
                fields=[{"name": "Gemini's Report", "value": analysis_text}]
            )

        except Exception as e:
            print(f"CRITICAL: Gemini analysis failed: {e}", file=sys.stderr)
            log_entry = {
                'time': datetime.now(timezone.utc).isoformat(),
                'type': 'GEMINI_ERROR',
                'ip': 'N/A',
                'message': f"Gemini analysis failed: {e}"
            }
            ddos_logs.appendleft(log_entry)

    threading.Thread(target=analysis_thread).start()


def ai_guardian_check():
    """
    Inspects incoming traffic for anomalies. This function must be extremely fast.
    Returns a Flask response if the request should be blocked, otherwise returns None.
    """
    remote_ip = get_remote_address()
    now = time.time()
    
    with AI_GUARDIAN_STATE["lock"]:
        # 1. Check if IP is currently blocked
        unblock_time = AI_GUARDIAN_STATE["blocked_ips"].get(remote_ip)
        if unblock_time and now < unblock_time:
            return jsonify({"error": "Too Many Requests", "message": "Your IP is temporarily blocked due to high traffic."}), 429
        elif unblock_time:
            del AI_GUARDIAN_STATE["blocked_ips"][remote_ip] # Clean up expired block

        # --- Handle Manual Overrides ---
        if AI_GUARDIAN_STATE["manual_mode"] == 'off':
            if AI_GUARDIAN_STATE["mitigation_mode_active"]:
                 AI_GUARDIAN_STATE["mitigation_mode_active"] = False
                 # Log deactivation due to manual override if it was active
                 log_entry = { 'time': datetime.now(timezone.utc).isoformat(), 'type': 'MITIGATION_DEACTIVATED', 'ip': 'N/A', 'message': "AI Guardian mitigation disabled by manual override."}
                 ddos_logs.appendleft(log_entry)
            return None # Skip all checks if manually off
        
        # 2. Global traffic monitoring
        AI_GUARDIAN_STATE["global_requests"].append(now)
        while AI_GUARDIAN_STATE["global_requests"] and AI_GUARDIAN_STATE["global_requests"][0] < now - 2:
            AI_GUARDIAN_STATE["global_requests"].popleft()
        
        current_global_rps = len([t for t in AI_GUARDIAN_STATE["global_requests"] if t > now - 1])
        
        # 3. Check mitigation mode activation/deactivation
        mitigation_active_before = AI_GUARDIAN_STATE["mitigation_mode_active"]
        
        if AI_GUARDIAN_STATE["manual_mode"] == 'on':
             AI_GUARDIAN_STATE["mitigation_mode_active"] = True
        elif AI_GUARDIAN_STATE["manual_mode"] == 'auto':
            if current_global_rps > AI_GUARDIAN_RPS_THRESHOLD:
                AI_GUARDIAN_STATE["mitigation_mode_active"] = True
            elif current_global_rps < (AI_GUARDIAN_RPS_THRESHOLD * 0.8):
                 AI_GUARDIAN_STATE["mitigation_mode_active"] = False
        
        # Log state changes
        if not mitigation_active_before and AI_GUARDIAN_STATE["mitigation_mode_active"]:
            mode_reason = "manual override" if AI_GUARDIAN_STATE["manual_mode"] == 'on' else f"global traffic spike ({current_global_rps} RPS)"
            log_entry = {'time': datetime.now(timezone.utc).isoformat(), 'type': 'MITIGATION_ACTIVATED', 'ip': 'N/A', 'message': f"Mitigation enabled due to {mode_reason}."}
            ddos_logs.appendleft(log_entry)
            send_security_alert("DDoS Mitigation Activated", log_entry['message'], 16729344) # Orange

            # Get top IPs for Gemini Analysis
            top_ips = sorted(AI_GUARDIAN_STATE["ip_requests"].items(), key=lambda item: len(item[1]), reverse=True)[:5]
            top_ips_with_rps = [(ip, len([t for t in queue if t > now - 1])) for ip, queue in top_ips]
            trigger_gemini_analysis(current_global_rps, top_ips_with_rps)

        elif mitigation_active_before and not AI_GUARDIAN_STATE["mitigation_mode_active"]:
            mode_reason = "manual override" if AI_GUARDIAN_STATE["manual_mode"] == 'off' else f"global traffic returned to normal ({current_global_rps} RPS)"
            log_entry = {'time': datetime.now(timezone.utc).isoformat(), 'type': 'MITIGATION_DEACTIVATED', 'ip': 'N/A', 'message': f"Mitigation disabled as {mode_reason}."}
            ddos_logs.appendleft(log_entry)
            send_security_alert("DDoS Mitigation Deactivated", log_entry['message'], 3066993) # Green
            AI_GUARDIAN_STATE["ip_requests"].clear() # Clear per-IP tracking when mode deactivates

        # 4. Per-IP monitoring if in mitigation mode
        if AI_GUARDIAN_STATE["mitigation_mode_active"]:
            ip_queue = AI_GUARDIAN_STATE["ip_requests"][remote_ip]
            ip_queue.append(now)
            while ip_queue and ip_queue[0] < now - 2:
                ip_queue.popleft()
            
            current_ip_rps = len([t for t in ip_queue if t > now - 1])
            
            if current_ip_rps > AI_GUARDIAN_IP_RPS_LIMIT:
                AI_GUARDIAN_STATE["blocked_ips"][remote_ip] = now + AI_GUARDIAN_BLOCK_DURATION
                log_entry = {'time': datetime.now(timezone.utc).isoformat(), 'type': 'IP_BLOCKED', 'ip': remote_ip, 'message': f"IP exceeded rate limit ({current_ip_rps} RPS). Blocked for {AI_GUARDIAN_BLOCK_DURATION}s."}
                ddos_logs.appendleft(log_entry)
                
                if now - AI_GUARDIAN_STATE.get("last_alert_time", 0) > 60:
                    send_security_alert(
                        "AI Guardian: IP Blocked", 
                        "An IP has been temporarily blocked by the AI Guardian for exceeding the per-IP request limit during mitigation mode.",
                        15158332, # Red
                        fields=[
                            {"name": "Details", "value": f"`{current_ip_rps}` RPS > `{AI_GUARDIAN_IP_RPS_LIMIT}` limit", "inline": False},
                            {"name": "Block Duration", "value": f"{AI_GUARDIAN_BLOCK_DURATION} seconds", "inline": False}
                        ]
                    )
                    AI_GUARDIAN_STATE["last_alert_time"] = now
                
                return jsonify({"error": "Too Many Requests", "message": "Your IP has been temporarily blocked."}), 429

    return None # Continue with the request

# --- 5. Frontend Serving Routes ---

# Custom error page templates
FORBIDDEN_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>Access Denied</title>
    <script src="security.js"></script>
    <style>
        :root { --bg: #0A0A0A; --fg: #E0E0E0; --red: #EF4444; --glow: rgba(239, 68, 68, 0.5); }
        body { background-color: var(--bg); color: var(--fg); font-family: 'Courier New', monospace; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; text-align: center; }
        .container { border: 1px solid var(--red); padding: 40px; box-shadow: 0 0 20px var(--glow); animation: fadeIn 1s ease-out; }
        h1 { font-size: 2.5em; color: var(--red); text-shadow: 0 0 10px var(--red); margin: 0; }
        p { margin: 15px 0 0; font-size: 1.2em; }
        .glitch { position: relative; }
        .glitch::before, .glitch::after { content: '403 FORBIDDEN'; position: absolute; top: 0; left: 0; right: 0; background: var(--bg); overflow: hidden; clip: rect(0, 900px, 0, 0); }
        .glitch::before { left: 2px; text-shadow: -2px 0 var(--red); animation: glitch-anim-1 2s infinite linear alternate-reverse; }
        .glitch::after { left: -2px; text-shadow: 2px 0 var(--glow); animation: glitch-anim-2 2s infinite linear alternate-reverse; }
        @keyframes fadeIn { from { opacity: 0; transform: scale(0.9); } to { opacity: 1; transform: scale(1); } }
        @keyframes glitch-anim-1 { 0% { clip: rect(42px, 9999px, 44px, 0); } 10% { clip: rect(17px, 9999px, 60px, 0); } 20% { clip: rect(50px, 9999px, 52px, 0); } 30% { clip: rect(5px, 9999px, 80px, 0); } 40% { clip: rect(27px, 9999px, 54px, 0); } 50% { clip: rect(40px, 9999px, 10px, 0); } 60% { clip: rect(33px, 9999px, 75px, 0); } 70% { clip: rect(63px, 9999px, 43px, 0); } 80% { clip: rect(23px, 9999px, 88px, 0); } 90% { clip: rect(57px, 9999px, 3px, 0); } 100% { clip: rect(14px, 9999px, 68px, 0); } }
        @keyframes glitch-anim-2 { 0% { clip: rect(65px, 9999px, 12px, 0); } 10% { clip: rect(53px, 9999px, 99px, 0); } 20% { clip: rect(22px, 9999px, 7px, 0); } 30% { clip: rect(91px, 9999px, 48px, 0); } 40% { clip: rect(13px, 9999px, 62px, 0); } 50% { clip: rect(78px, 9999px, 33px, 0); } 60% { clip: rect(42px, 9999px, 91px, 0); } 70% { clip: rect(7px, 9999px, 50px, 0); } 80% { clip: rect(83px, 9999px, 37px, 0); } 90% { clip: rect(39px, 9999px, 73px, 0); } 100% { clip: rect(68px, 9999px, 59px, 0); } }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="glitch">403 FORBIDDEN</h1>
        <p>// ACCESS TO THIS RESOURCE IS RESTRICTED.</p>
        <p>// Your attempt has been logged.</p>
    </div>
</body>
</html>
"""

TOO_MANY_REQUESTS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><title>Too Many Requests</title>
    <script src="security.js"></script>
    <style>
        :root { --bg: #0A0A0A; --fg: #E0E0E0; --accent: #F59E0B; --glow: rgba(245, 158, 11, 0.5); }
        body { background-color: var(--bg); color: var(--fg); font-family: 'Courier New', monospace; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; text-align: center; }
        .container { border: 1px solid var(--accent); padding: 40px; box-shadow: 0 0 20px var(--glow); animation: fadeIn 1s ease-out; }
        h1 { font-size: 2.5em; color: var(--accent); text-shadow: 0 0 10px var(--accent); margin: 0; }
        p { margin: 15px 0 0; font-size: 1.2em; }
        .glitch { position: relative; }
        .glitch::before, .glitch::after { content: '429 TOO MANY REQUESTS'; position: absolute; top: 0; left: 0; right: 0; background: var(--bg); overflow: hidden; clip: rect(0, 900px, 0, 0); }
        .glitch::before { left: 2px; text-shadow: -2px 0 var(--accent); animation: glitch-anim-1 2s infinite linear alternate-reverse; }
        .glitch::after { left: -2px; text-shadow: 2px 0 var(--glow); animation: glitch-anim-2 2s infinite linear alternate-reverse; }
        @keyframes fadeIn { from { opacity: 0; transform: scale(0.9); } to { opacity: 1; transform: scale(1); } }
        @keyframes glitch-anim-1 { 0% { clip: rect(42px, 9999px, 44px, 0); } 10% { clip: rect(17px, 9999px, 60px, 0); } 20% { clip: rect(50px, 9999px, 52px, 0); } 30% { clip: rect(5px, 9999px, 80px, 0); } 40% { clip: rect(27px, 9999px, 54px, 0); } 50% { clip: rect(40px, 9999px, 10px, 0); } 60% { clip: rect(33px, 9999px, 75px, 0); } 70% { clip: rect(63px, 9999px, 43px, 0); } 80% { clip: rect(23px, 9999px, 88px, 0); } 90% { clip: rect(57px, 9999px, 3px, 0); } 100% { clip: rect(14px, 9999px, 68px, 0); } }
        @keyframes glitch-anim-2 { 0% { clip: rect(65px, 9999px, 12px, 0); } 10% { clip: rect(53px, 9999px, 99px, 0); } 20% { clip: rect(22px, 9999px, 7px, 0); } 30% { clip: rect(91px, 9999px, 48px, 0); } 40% { clip: rect(13px, 9999px, 62px, 0); } 50% { clip: rect(78px, 9999px, 33px, 0); } 60% { clip: rect(42px, 9999px, 91px, 0); } 70% { clip: rect(7px, 9999px, 50px, 0); } 80% { clip: rect(83px, 9999px, 37px, 0); } 90% { clip: rect(39px, 9999px, 73px, 0); } 100% { clip: rect(68px, 9999px, 59px, 0); } }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="glitch">429 TOO MANY REQUESTS</h1>
        <p>// System overload detected. Your connection has been temporarily throttled.</p>
        <p>// Please wait a moment before trying again.</p>
    </div>
</body>
</html>
"""

HARDWARE_BANNED_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied | </async> Scanner</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Orbitron:wght@500;700;900&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --background-color: #0A0A0A;
            --surface-color: #141414;
            --border-color: #2A2A2A;
            --text-primary: #FFFFFF;
            --text-secondary: #A0A0A0;
            --danger: #EF4444;
            --danger-glow: rgba(239, 68, 68, 0.4);
        }
        
        body {
            background-color: var(--background-color);
            color: var(--text-primary);
            font-family: 'Inter', sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            overflow: hidden;
            position: relative;
        }
        
        .orb {
            position: fixed;
            border-radius: 50%;
            filter: blur(80px);
            opacity: 0.3;
            pointer-events: none;
            z-index: 0;
        }
        
        .orb-1 {
            width: 500px;
            height: 500px;
            background: var(--danger);
            top: -250px;
            right: -250px;
            animation: orbFloat1 20s infinite ease-in-out;
        }
        
        @keyframes orbFloat1 {
            0%, 100% { transform: translate(0, 0) scale(1); }
            50% { transform: translate(-100px, 100px) scale(1.2); }
        }
        
        .container {
            position: relative;
            z-index: 10;
            text-align: center;
            padding: 60px 50px;
            background: linear-gradient(135deg, rgba(20, 20, 20, 0.95), rgba(30, 30, 30, 0.9));
            border: 1px solid var(--border-color);
            border-radius: 20px;
            backdrop-filter: blur(20px);
            max-width: 520px;
            width: 90%;
            box-shadow: 
                0 8px 32px rgba(0, 0, 0, 0.8),
                0 0 0 1px rgba(239, 68, 68, 0.2),
                inset 0 1px 0 rgba(255, 255, 255, 0.05);
            animation: fadeInUp 0.8s cubic-bezier(0.16, 1, 0.3, 1);
        }
        
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(40px) scale(0.95); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }
        
        .icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 30px;
            background: linear-gradient(135deg, var(--danger), #dc2626);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 30px var(--danger-glow);
            animation: pulse 2s ease-in-out infinite;
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); box-shadow: 0 0 30px var(--danger-glow); }
            50% { transform: scale(1.05); box-shadow: 0 0 50px var(--danger-glow); }
        }
        
        .icon svg {
            width: 40px;
            height: 40px;
            fill: white;
        }
        
        .logo {
            font-size: 2rem;
            font-weight: 900;
            font-family: 'Orbitron', sans-serif;
            margin-bottom: 20px;
            letter-spacing: -2px;
            background: linear-gradient(135deg, var(--text-primary) 0%, var(--text-secondary) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .logo span {
            color: var(--danger);
            -webkit-text-fill-color: var(--danger);
        }
        
        h1 {
            font-size: 26px;
            font-weight: 700;
            margin-bottom: 12px;
            color: var(--danger);
            letter-spacing: -0.5px;
        }
        
        .subtitle {
            font-size: 15px;
            color: var(--text-secondary);
            margin-bottom: 30px;
            line-height: 1.6;
        }
        
        .reason-box {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 8px;
            padding: 20px;
            margin: 30px 0;
            text-align: left;
        }
        
        .reason-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--danger);
            font-weight: 600;
            margin-bottom: 8px;
        }
        
        .reason-text {
            font-size: 14px;
            color: var(--text-primary);
            line-height: 1.6;
        }
        
        .footer {
            margin-top: 30px;
            padding-top: 24px;
            border-top: 1px solid var(--border-color);
            font-size: 13px;
            color: var(--text-secondary);
            line-height: 1.6;
        }
        
        .footer p:last-child {
            margin-top: 10px;
            font-family: 'Orbitron', sans-serif;
            font-weight: 700;
            font-size: 14px;
            background: linear-gradient(135deg, var(--text-primary), var(--danger));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .footer span {
            color: var(--danger);
            -webkit-text-fill-color: var(--danger);
        }
    </style>
</head>
<body>
    <div class="orb orb-1"></div>
    
    <div class="container">
        <div class="icon">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="white">
                <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/>
                <line x1="7" y1="7" x2="17" y2="17" stroke="#0A0A0A" stroke-width="2.5" stroke-linecap="round"/>
                <line x1="17" y1="7" x2="7" y2="17" stroke="#0A0A0A" stroke-width="2.5" stroke-linecap="round"/>
            </svg>
        </div>
        
        <div class="logo">
            &lt;<span>/</span>async&gt;
        </div>
        
        <h1>Access Denied</h1>
        <p class="subtitle">This device has been banned from accessing the site.</p>
        
        <div class="reason-box">
            <div class="reason-label">Ban Reason</div>
            <div class="reason-text">{{ reason }}</div>
        </div>
        
        <div class="footer">
            <p>If you believe this is an error, please contact support.</p>
            <p>&lt;<span>/</span>async&gt; Security</p>
        </div>
    </div>
</body>
</html>
"""

VERIFICATION_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verifying Your Connection | </async> Scanner</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Orbitron:wght@500;700;900&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --background-color: #0A0A0A;
            --surface-color: #141414;
            --border-color: #2A2A2A;
            --text-primary: #FFFFFF;
            --text-secondary: #A0A0A0;
            --accent: #5865F2;
            --accent-glow: rgba(88, 101, 242, 0.4);
            --success: #10B981;
            --success-glow: rgba(16, 185, 129, 0.4);
        }
        
        body {
            background-color: var(--background-color);
            color: var(--text-primary);
            font-family: 'Inter', sans-serif;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            overflow: hidden;
            position: relative;
        }
        
        /* Animated particles background */
        #particles {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            z-index: 0;
        }
        
        .particle {
            position: absolute;
            width: 2px;
            height: 2px;
            background: var(--accent);
            border-radius: 50%;
            opacity: 0;
            animation: float 8s infinite ease-in-out;
        }
        
        @keyframes float {
            0% { transform: translateY(100vh) translateX(0); opacity: 0; }
            10% { opacity: 0.5; }
            90% { opacity: 0.5; }
            100% { transform: translateY(-100vh) translateX(100px); opacity: 0; }
        }
        
        /* Animated gradient orbs */
        .orb {
            position: fixed;
            border-radius: 50%;
            filter: blur(80px);
            opacity: 0.3;
            pointer-events: none;
            z-index: 0;
        }
        
        .orb-1 {
            width: 500px;
            height: 500px;
            background: var(--accent);
            top: -250px;
            right: -250px;
            animation: orbFloat1 20s infinite ease-in-out;
        }
        
        .orb-2 {
            width: 400px;
            height: 400px;
            background: var(--success);
            bottom: -200px;
            left: -200px;
            animation: orbFloat2 15s infinite ease-in-out;
        }
        
        @keyframes orbFloat1 {
            0%, 100% { transform: translate(0, 0) scale(1); }
            50% { transform: translate(-100px, 100px) scale(1.2); }
        }
        
        @keyframes orbFloat2 {
            0%, 100% { transform: translate(0, 0) scale(1); }
            50% { transform: translate(100px, -100px) scale(1.1); }
        }
        
        /* Grid background */
        .grid-bg {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: 
                linear-gradient(rgba(88, 101, 242, 0.05) 1px, transparent 1px),
                linear-gradient(90deg, rgba(88, 101, 242, 0.05) 1px, transparent 1px);
            background-size: 50px 50px;
            pointer-events: none;
            z-index: 0;
            animation: gridMove 30s linear infinite;
        }
        
        @keyframes gridMove {
            0% { transform: translate(0, 0); }
            100% { transform: translate(50px, 50px); }
        }
        
        .container {
            position: relative;
            z-index: 10;
            text-align: center;
            padding: 60px 50px;
            background: linear-gradient(135deg, rgba(20, 20, 20, 0.95), rgba(30, 30, 30, 0.9));
            border: 1px solid var(--border-color);
            border-radius: 20px;
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            max-width: 520px;
            width: 90%;
            box-shadow: 
                0 8px 32px rgba(0, 0, 0, 0.8),
                0 0 0 1px rgba(88, 101, 242, 0.1),
                inset 0 1px 0 rgba(255, 255, 255, 0.05);
            animation: fadeInUp 0.8s cubic-bezier(0.16, 1, 0.3, 1);
        }
        
        @keyframes fadeInUp {
            from { 
                opacity: 0; 
                transform: translateY(40px) scale(0.95);
            }
            to { 
                opacity: 1; 
                transform: translateY(0) scale(1);
            }
        }
        
        .logo {
            font-size: 3.5rem;
            font-weight: 900;
            font-family: 'Orbitron', sans-serif;
            margin-bottom: 30px;
            letter-spacing: -3px;
            background: linear-gradient(135deg, var(--text-primary) 0%, var(--text-secondary) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            position: relative;
            display: inline-block;
            animation: logoGlow 3s ease-in-out infinite;
        }
        
        @keyframes logoGlow {
            0%, 100% { filter: drop-shadow(0 0 10px var(--accent-glow)); }
            50% { filter: drop-shadow(0 0 20px var(--accent-glow)); }
        }
        
        .logo span {
            color: var(--accent);
            -webkit-text-fill-color: var(--accent);
        }
        
        h1 {
            font-size: 26px;
            font-weight: 700;
            margin-bottom: 12px;
            color: var(--text-primary);
            letter-spacing: -0.5px;
        }
        
        .subtitle {
            font-size: 15px;
            color: var(--text-secondary);
            margin-bottom: 50px;
            line-height: 1.6;
        }
        
        .spinner-container {
            margin: 50px 0;
            height: 100px;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }
        
        /* Advanced spinner with multiple rings */
        .spinner-wrapper {
            position: relative;
            width: 80px;
            height: 80px;
        }
        
        .spinner {
            position: absolute;
            width: 80px;
            height: 80px;
            border: 3px solid transparent;
            border-top: 3px solid var(--accent);
            border-radius: 50%;
            animation: spin 1.2s cubic-bezier(0.5, 0, 0.5, 1) infinite;
        }
        
        .spinner-inner {
            position: absolute;
            width: 60px;
            height: 60px;
            top: 10px;
            left: 10px;
            border: 3px solid transparent;
            border-bottom: 3px solid var(--accent);
            border-radius: 50%;
            animation: spin 1.5s cubic-bezier(0.5, 0, 0.5, 1) infinite reverse;
        }
        
        .spinner-core {
            position: absolute;
            width: 40px;
            height: 40px;
            top: 20px;
            left: 20px;
            background: var(--accent);
            border-radius: 50%;
            opacity: 0.2;
            animation: pulse 2s ease-in-out infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(0.8); opacity: 0.2; }
            50% { transform: scale(1.2); opacity: 0.4; }
        }
        
        /* Success checkmark with animation */
        .checkmark {
            display: none;
            width: 80px;
            height: 80px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--success), #059669);
            position: relative;
            box-shadow: 0 0 30px var(--success-glow);
            animation: successPop 0.6s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        }
        
        @keyframes successPop {
            0% { transform: scale(0) rotate(-180deg); opacity: 0; }
            50% { transform: scale(1.2) rotate(90deg); }
            100% { transform: scale(1) rotate(0deg); opacity: 1; }
        }
        
        .checkmark::before {
            content: '';
            position: absolute;
            width: 100%;
            height: 100%;
            border-radius: 50%;
            background: var(--success);
            animation: ripple 1s ease-out infinite;
        }
        
        @keyframes ripple {
            0% { transform: scale(1); opacity: 0.5; }
            100% { transform: scale(1.5); opacity: 0; }
        }
        
        .checkmark::after {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 20px;
            height: 35px;
            border: solid white;
            border-width: 0 5px 5px 0;
            transform: translate(-50%, -60%) rotate(45deg);
            animation: checkDraw 0.4s 0.2s ease-out forwards;
            opacity: 0;
        }
        
        @keyframes checkDraw {
            to { opacity: 1; }
        }
        
        .status {
            font-size: 15px;
            color: var(--accent);
            margin-top: 30px;
            font-weight: 600;
            min-height: 24px;
            letter-spacing: 0.5px;
            animation: statusPulse 2s ease-in-out infinite;
        }
        
        @keyframes statusPulse {
            0%, 100% { opacity: 0.6; transform: translateY(0); }
            50% { opacity: 1; transform: translateY(-2px); }
        }
        
        /* Progress bar */
        .progress-bar {
            width: 100%;
            height: 3px;
            background: var(--border-color);
            border-radius: 10px;
            margin-top: 30px;
            overflow: hidden;
            position: relative;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--accent), var(--success));
            border-radius: 10px;
            width: 0%;
            animation: progressFill 4s ease-out forwards;
            box-shadow: 0 0 10px var(--accent-glow);
        }
        
        @keyframes progressFill {
            to { width: 100%; }
        }
        
        .footer {
            margin-top: 50px;
            padding-top: 24px;
            border-top: 1px solid var(--border-color);
            font-size: 13px;
            color: var(--text-secondary);
            line-height: 1.8;
        }
        
        .footer p:last-child {
            margin-top: 10px;
            font-family: 'Orbitron', sans-serif;
            font-weight: 700;
            font-size: 14px;
            background: linear-gradient(135deg, var(--text-primary), var(--accent));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .footer span {
            color: var(--accent);
            -webkit-text-fill-color: var(--accent);
        }
        
        /* Verified state */
        .verified .spinner-wrapper { display: none; }
        .verified .checkmark { display: block; }
        .verified .status { 
            color: var(--success); 
            animation: none;
            opacity: 1;
            font-size: 16px;
        }
        .verified .progress-fill {
            background: var(--success);
        }
        
        /* Responsive */
        @media (max-width: 600px) {
            .container {
                padding: 40px 30px;
            }
            .logo {
                font-size: 2.8rem;
            }
            h1 {
                font-size: 22px;
            }
            .spinner-wrapper {
                width: 60px;
                height: 60px;
            }
            .spinner {
                width: 60px;
                height: 60px;
            }
            .checkmark {
                width: 60px;
                height: 60px;
            }
        }
    </style>
</head>
<body>
    <div class="orb orb-1"></div>
    <div class="orb orb-2"></div>
    <div class="grid-bg"></div>
    <div id="particles"></div>
    
    <div class="container" id="verifyContainer">
        <div class="logo">
            &lt;<span>/</span>async&gt;
        </div>
        
        <h1>Verifying Your Connection</h1>
        <p class="subtitle">Please wait while we verify that you're a human visitor...</p>
        
        <div class="spinner-container">
            <div class="spinner-wrapper">
                <div class="spinner"></div>
                <div class="spinner-inner"></div>
                <div class="spinner-core"></div>
            </div>
            <div class="checkmark"></div>
        </div>
        
        <div class="status" id="statusText">Initializing security check...</div>
        
        <div class="progress-bar">
            <div class="progress-fill"></div>
        </div>
        
        <div class="footer">
            <p>This process is automatic. Your browser will redirect shortly.</p>
            <p>&lt;<span>/</span>async&gt; Security</p>
        </div>
    </div>

    <script>
        // Create animated particles
        function createParticles() {
            const particlesContainer = document.getElementById('particles');
            const particleCount = 30;
            
            for (let i = 0; i < particleCount; i++) {
                const particle = document.createElement('div');
                particle.className = 'particle';
                particle.style.left = Math.random() * 100 + '%';
                particle.style.animationDelay = Math.random() * 8 + 's';
                particle.style.animationDuration = (8 + Math.random() * 4) + 's';
                particlesContainer.appendChild(particle);
            }
        }
        
        createParticles();
        
        const statusMessages = [
            'Initializing security check...',
            'Analyzing browser fingerprint...',
            'Verifying connection integrity...',
            'Checking for threats...',
            'Finalizing verification...'
        ];
        let currentMessage = 0;
        const statusText = document.getElementById('statusText');
        const container = document.getElementById('verifyContainer');

        // Collect client fingerprint data
        function collectFingerprint() {
            const fp = {
                screen: {
                    width: screen.width,
                    height: screen.height,
                    colorDepth: screen.colorDepth,
                    pixelRatio: window.devicePixelRatio
                },
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                timezoneOffset: new Date().getTimezoneOffset(),
                language: navigator.language,
                languages: navigator.languages ? navigator.languages.join(',') : navigator.language,
                platform: navigator.platform,
                hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
                deviceMemory: navigator.deviceMemory || 'unknown',
                cookieEnabled: navigator.cookieEnabled,
                doNotTrack: navigator.doNotTrack || 'unknown',
                plugins: Array.from(navigator.plugins || []).map(p => p.name).join(',') || 'none',
                canvas: getCanvasFingerprint(),
                webgl: getWebGLFingerprint(),
                touchSupport: 'ontouchstart' in window || navigator.maxTouchPoints > 0,
                connection: navigator.connection ? {
                    effectiveType: navigator.connection.effectiveType,
                    downlink: navigator.connection.downlink,
                    rtt: navigator.connection.rtt
                } : 'unknown'
            };
            return fp;
        }

        function getCanvasFingerprint() {
            try {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                ctx.textBaseline = 'top';
                ctx.font = '14px Arial';
                ctx.fillText('Browser fingerprint', 2, 2);
                return canvas.toDataURL().slice(-50);
            } catch (e) {
                return 'unavailable';
            }
        }

        async function captureScreenshot() {
            try {
                // Use html2canvas library approach without external dependency
                // Capture the verification container as image
                const container = document.getElementById('verifyContainer');
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                
                // Set canvas size to match viewport
                canvas.width = window.innerWidth;
                canvas.height = window.innerHeight;
                
                // Fill background
                ctx.fillStyle = getComputedStyle(document.body).backgroundColor;
                ctx.fillRect(0, 0, canvas.width, canvas.height);
                
                // Draw text representation (since we can't capture actual DOM without library)
                ctx.fillStyle = '#FFFFFF';
                ctx.font = '20px Inter';
                ctx.textAlign = 'center';
                ctx.fillText('Verification Screenshot', canvas.width / 2, 100);
                ctx.fillText(new Date().toISOString(), canvas.width / 2, 140);
                ctx.fillText('Resolution: ' + window.innerWidth + 'x' + window.innerHeight, canvas.width / 2, 180);
                
                // Convert to base64
                return canvas.toDataURL('image/png');
            } catch (e) {
                console.error('Screenshot capture failed:', e);
                return null;
            }
        }

        async function captureScreenshotAdvanced() {
            try {
                console.log('🎨 Starting screenshot generation...');
                
                // Create a detailed visual report
                const canvas = document.createElement('canvas');
                canvas.width = 1000;
                canvas.height = 800;
                const ctx = canvas.getContext('2d');
                
                if (!ctx) {
                    console.error('Failed to get canvas context');
                    return null;
                }
                
                // Background gradient
                const gradient = ctx.createLinearGradient(0, 0, 0, 800);
                gradient.addColorStop(0, '#0A0A0A');
                gradient.addColorStop(1, '#1A1A2E');
                ctx.fillStyle = gradient;
                ctx.fillRect(0, 0, 1000, 800);
                
                // Border
                ctx.strokeStyle = '#5865F2';
                ctx.lineWidth = 3;
                ctx.strokeRect(10, 10, 980, 780);
                
                // Header - use fallback fonts
                ctx.fillStyle = '#5865F2';
                ctx.font = 'bold 36px Arial, sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText('</async> VERIFICATION REPORT', 500, 70);
                
                // Timestamp
                ctx.fillStyle = '#A0A0A0';
                ctx.font = '14px Arial, sans-serif';
                ctx.fillText(new Date().toISOString(), 500, 100);
                
                // Divider
                ctx.strokeStyle = '#2A2A2A';
                ctx.lineWidth = 1;
                ctx.beginPath();
                ctx.moveTo(50, 120);
                ctx.lineTo(950, 120);
                ctx.stroke();
                
                // Info sections
                let y = 160;
                const leftX = 100;
                const rightX = 550;
                
                // Helper function to draw info
                function drawInfo(label, value, x, yPos) {
                    ctx.fillStyle = '#5865F2';
                    ctx.font = 'bold 14px Arial';
                    ctx.textAlign = 'left';
                    ctx.fillText(label + ':', x, yPos);
                    
                    ctx.fillStyle = '#FFFFFF';
                    ctx.font = '13px monospace';
                    const maxWidth = 400;
                    const lines = wrapText(ctx, String(value), maxWidth);
                    lines.forEach((line, i) => {
                        ctx.fillText(line, x, yPos + 20 + (i * 18));
                    });
                    return yPos + 20 + (lines.length * 18) + 15;
                }
                
                function wrapText(context, text, maxWidth) {
                    const words = text.split(' ');
                    const lines = [];
                    let currentLine = words[0] || '';
                    
                    for (let i = 1; i < words.length; i++) {
                        const word = words[i];
                        const width = context.measureText(currentLine + ' ' + word).width;
                        if (width < maxWidth) {
                            currentLine += ' ' + word;
                        } else {
                            lines.push(currentLine);
                            currentLine = word;
                        }
                    }
                    lines.push(currentLine);
                    return lines;
                }
                
                // Left column
                y = drawInfo('Screen Resolution', window.screen.width + 'x' + window.screen.height + ' @ ' + window.screen.colorDepth + 'bit', leftX, y);
                y = drawInfo('Viewport Size', window.innerWidth + 'x' + window.innerHeight, leftX, y);
                y = drawInfo('Device Pixel Ratio', window.devicePixelRatio.toString(), leftX, y);
                y = drawInfo('Platform', navigator.platform, leftX, y);
                y = drawInfo('Language', navigator.language + ' (' + (navigator.languages || [navigator.language]).join(', ') + ')', leftX, y);
                
                // Right column
                let yRight = 160;
                yRight = drawInfo('CPU Cores', (navigator.hardwareConcurrency || 'Unknown').toString(), rightX, yRight);
                yRight = drawInfo('Device Memory', (navigator.deviceMemory ? navigator.deviceMemory + ' GB' : 'Unknown'), rightX, yRight);
                yRight = drawInfo('Timezone', Intl.DateTimeFormat().resolvedOptions().timeZone, rightX, yRight);
                yRight = drawInfo('Cookie Enabled', navigator.cookieEnabled ? 'Yes' : 'No', rightX, yRight);
                yRight = drawInfo('Touch Support', ('ontouchstart' in window) ? 'Yes' : 'No', rightX, yRight);
                
                // User Agent (full width)
                y = Math.max(y, yRight) + 20;
                y = drawInfo('User Agent', navigator.userAgent, leftX, y);
                
                // Connection info if available
                if (navigator.connection) {
                    y = drawInfo('Connection', 
                        (navigator.connection.effectiveType || 'unknown') + ' (' + 
                        (navigator.connection.downlink || '?') + ' Mbps, ' +
                        (navigator.connection.rtt || '?') + 'ms RTT)',
                        leftX, y);
                }
                
                // Bottom status
                ctx.fillStyle = '#10B981';
                ctx.font = 'bold 28px Arial';
                ctx.textAlign = 'center';
                ctx.fillText('✓ VERIFICATION SUCCESSFUL', 500, 750);
                
                const dataUrl = canvas.toDataURL('image/png');
                console.log('✅ Screenshot generated successfully, size:', Math.round(dataUrl.length / 1024), 'KB');
                return dataUrl;
                
            } catch (e) {
                console.error('❌ Screenshot generation failed:', e);
                return null;
            }
        }

        function getWebGLFingerprint() {
            try {
                const canvas = document.createElement('canvas');
                const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                if (!gl) return 'unavailable';
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                return debugInfo ? {
                    vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL),
                    renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
                } : 'limited';
            } catch (e) {
                return 'unavailable';
            }
        }

        // Rotate status messages
        const messageInterval = setInterval(() => {
            currentMessage = (currentMessage + 1) % statusMessages.length;
            statusText.textContent = statusMessages[currentMessage];
        }, 1500);

        // Complete verification after 3-5 seconds
        const verifyDelay = 3000 + Math.random() * 2000;
        setTimeout(() => {
            clearInterval(messageInterval);
            container.classList.add('verified');
            statusText.textContent = 'Verification complete!';
            
            // Collect fingerprint and screenshot, then send verification
            setTimeout(async () => {
                const fingerprint = collectFingerprint();
                const screenshot = await captureScreenshotAdvanced();
                
                // Prepare data
                const verificationData = { 
                    fingerprint,
                    screenshot: screenshot || null
                };
                
                // Log for debugging
                console.log('Sending verification with screenshot:', screenshot ? 'Yes (' + Math.round(screenshot.length / 1024) + ' KB)' : 'No');
                
                fetch('/api/verify', { 
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(verificationData)
                })
                    .then(async response => {
                        if (response.status === 403) {
                            // Hardware banned - check if it's hardware ban
                            try {
                                const data = await response.json();
                                if (data.error === 'hardware_banned') {
                                    console.log('🚫 Hardware banned:', data.reason);
                                    // Redirect to banned page
                                    window.location.href = '/hardware-banned?reason=' + encodeURIComponent(data.reason || 'Violation of Terms of Service');
                                    return;
                                }
                            } catch (e) {
                                console.error('Error parsing ban response:', e);
                            }
                        }
                        
                        if (response.ok) {
                            console.log('✅ Verification successful');
                            window.location.href = '{{ redirect_url }}';
                        } else {
                            console.error('Verification failed:', response.status);
                            // Still redirect on other errors
                            window.location.href = '{{ redirect_url }}';
                        }
                    })
                    .catch(error => {
                        console.error('Verification error:', error);
                        // Fallback redirect even if API fails
                        window.location.href = '{{ redirect_url }}';
                    });
            }, 1000);
        }, verifyDelay);
    </script>
</body>
</html>
"""

@app.route('/forbidden')
def forbidden_page():
    return render_template_string(FORBIDDEN_PAGE_TEMPLATE), 403

@app.route('/verify')
def verify_page():
    """Display the verification page"""
    redirect_url = session.get('verification_redirect', url_for('index'))
    return render_template_string(VERIFICATION_PAGE_TEMPLATE, redirect_url=redirect_url)

@app.route('/hardware-banned')
def hardware_banned_page():
    """Display hardware ban page"""
    reason = request.args.get('reason', 'Violation of Terms of Service')
    return render_template_string(HARDWARE_BANNED_TEMPLATE, reason=reason)

@app.route('/api/csrf-token')
def get_csrf_token():
    """Provide CSRF token to frontend"""
    return jsonify({'csrf_token': generate_csrf()})

@app.route('/api/verify', methods=['POST'])
@csrf.exempt  # Exempt from CSRF - verification happens before user has session/token
@limiter.limit("3 per minute")
def verify_user():
    """Mark user as verified and set cookie"""
    session['verified'] = True
    session.permanent = True
    
    # Collect detailed visitor information
    visitor_ip = get_remote_address()
    
    # Get all possible IP headers (for proper IP detection behind proxies/Cloudflare)
    real_ip = request.headers.get('X-Real-IP', visitor_ip)
    forwarded_for = request.headers.get('X-Forwarded-For', visitor_ip)
    cf_connecting_ip = request.headers.get('CF-Connecting-IP', visitor_ip)
    
    # Use Cloudflare IP if available, otherwise fallback
    actual_ip = cf_connecting_ip or real_ip or forwarded_for.split(',')[0] if forwarded_for else visitor_ip
    
    # Browser and system information
    user_agent = request.headers.get('User-Agent', 'Unknown')
    accept_language = request.headers.get('Accept-Language', 'Unknown')
    accept_encoding = request.headers.get('Accept-Encoding', 'Unknown')
    
    # Connection information
    referer = request.headers.get('Referer', 'Direct')
    origin = request.headers.get('Origin', 'Unknown')
    
    # Cloudflare specific headers (if behind Cloudflare)
    cf_ray = request.headers.get('CF-RAY', 'N/A')
    cf_ipcountry = request.headers.get('CF-IPCountry', 'Unknown')
    
    # Try to get client hints if available
    sec_ch_ua = request.headers.get('Sec-CH-UA', 'N/A')
    sec_ch_ua_platform = request.headers.get('Sec-CH-UA-Platform', 'N/A')
    sec_ch_ua_mobile = request.headers.get('Sec-CH-UA-Mobile', 'N/A')
    
    # Get client fingerprint and screenshot from request body
    fingerprint = {}
    screenshot_data = None
    try:
        data = request.get_json(silent=True)
        if data:
            if 'fingerprint' in data:
                fingerprint = data['fingerprint']
            if 'screenshot' in data:
                screenshot_data = data['screenshot']
                if screenshot_data:
                    print(f"📸 Received screenshot data: {len(screenshot_data)} bytes")
                else:
                    print("⚠️  Screenshot data is None or empty")
            else:
                print("⚠️  No screenshot field in request data")
        else:
            print("⚠️  No JSON data in verification request")
    except Exception as e:
        print(f"❌ Error parsing verification data: {e}", file=sys.stderr)
    
    # Generate hardware fingerprint ID
    hardware_fingerprint_id = generate_hardware_fingerprint(fingerprint)
    print(f"🔑 Hardware Fingerprint ID: {hardware_fingerprint_id}")
    
    # Check if this hardware is banned
    hw_record = HardwareFingerprint.query.filter_by(fingerprint_id=hardware_fingerprint_id).first()
    
    if hw_record and hw_record.is_banned:
        # Hardware is banned - return error
        print(f"🚫 Banned hardware attempted access: {hardware_fingerprint_id}")
        return jsonify({
            'error': 'hardware_banned',
            'message': 'This device has been banned from accessing the site.',
            'reason': hw_record.ban_reason or 'Violation of Terms of Service',
            'banned_at': hw_record.banned_at.isoformat() if hw_record.banned_at else None
        }), 403
    
    # Update or create hardware fingerprint record
    if hw_record:
        # Update existing record
        hw_record.last_seen = datetime.now(timezone.utc)
        hw_record.visit_count += 1
        
        # Update associated IPs
        ips = json.loads(hw_record.associated_ips) if hw_record.associated_ips else []
        if actual_ip not in ips:
            ips.append(actual_ip)
            hw_record.associated_ips = json.dumps(ips[-10:])  # Keep last 10 IPs
        
        # Update hardware info
        hw_record.hardware_info = json.dumps(fingerprint)
    else:
        # Create new record
        hw_record = HardwareFingerprint(
            fingerprint_id=hardware_fingerprint_id,
            hardware_info=json.dumps(fingerprint),
            associated_ips=json.dumps([actual_ip])
        )
        db.session.add(hw_record)
        print(f"✅ New hardware fingerprint registered: {hardware_fingerprint_id}")
    
    db.session.commit()
    
    # Store fingerprint in session
    session['hardware_fingerprint'] = hardware_fingerprint_id
    
    # Build detailed log fields
    log_fields = [
        {"name": "🌐 IP Address", "value": f"`{actual_ip}`", "inline": True},
        {"name": "🌍 Country", "value": f"`{cf_ipcountry}`", "inline": True},
        {"name": "☁️ CF-RAY", "value": f"`{cf_ray}`", "inline": True},
        {"name": "💻 User Agent", "value": f"`{user_agent[:100]}`", "inline": False},
        {"name": "🖥️ Platform", "value": f"`{sec_ch_ua_platform}`", "inline": True},
        {"name": "📱 Mobile", "value": f"`{sec_ch_ua_mobile}`", "inline": True},
        {"name": "🌐 Browser", "value": f"`{sec_ch_ua[:50]}`", "inline": True},
        {"name": "🗣️ Language", "value": f"`{accept_language[:30]}`", "inline": True},
        {"name": "📦 Encoding", "value": f"`{accept_encoding[:30]}`", "inline": True},
        {"name": "🔗 Referer", "value": f"`{referer[:50]}`", "inline": True},
    ]
    
    # Add proxy information if different from actual IP
    if actual_ip != visitor_ip:
        log_fields.insert(1, {"name": "🔄 Proxy Chain", "value": f"`{forwarded_for[:100]}`", "inline": False})
    
    # Add fingerprint data if available
    if fingerprint:
        screen_info = fingerprint.get('screen', {})
        if screen_info:
            log_fields.append({
                "name": "🖥️ Screen", 
                "value": f"`{screen_info.get('width')}x{screen_info.get('height')} @ {screen_info.get('colorDepth')}bit (x{screen_info.get('pixelRatio')})`", 
                "inline": False
            })
        
        if fingerprint.get('timezone'):
            log_fields.append({
                "name": "🕐 Timezone", 
                "value": f"`{fingerprint.get('timezone')} (UTC{fingerprint.get('timezoneOffset', 0)/-60:+.0f})`", 
                "inline": True
            })
        
        if fingerprint.get('hardwareConcurrency') != 'unknown':
            log_fields.append({
                "name": "⚙️ CPU Cores", 
                "value": f"`{fingerprint.get('hardwareConcurrency')}`", 
                "inline": True
            })
        
        if fingerprint.get('deviceMemory') != 'unknown':
            log_fields.append({
                "name": "💾 RAM", 
                "value": f"`{fingerprint.get('deviceMemory')} GB`", 
                "inline": True
            })
        
        webgl = fingerprint.get('webgl', {})
        if isinstance(webgl, dict) and webgl.get('vendor'):
            log_fields.append({
                "name": "🎮 GPU Vendor", 
                "value": f"`{webgl.get('vendor', 'Unknown')[:50]}`", 
                "inline": False
            })
            log_fields.append({
                "name": "🎮 GPU Renderer", 
                "value": f"`{webgl.get('renderer', 'Unknown')[:50]}`", 
                "inline": False
            })
        
        if fingerprint.get('touchSupport'):
            log_fields.append({
                "name": "👆 Touch", 
                "value": "`Supported`", 
                "inline": True
            })
        
        connection = fingerprint.get('connection')
        if isinstance(connection, dict):
            log_fields.append({
                "name": "📡 Connection", 
                "value": f"`{connection.get('effectiveType', 'unknown')} ({connection.get('downlink', '?')} Mbps, {connection.get('rtt', '?')}ms RTT)`", 
                "inline": False
            })
    
    # Send verification log with screenshot
    if screenshot_data and SECURITY_IMPROVEMENTS_WEBHOOK_URL:
        # Send screenshot as separate message with file attachment
        threading.Thread(
            target=send_verification_with_screenshot,
            args=(log_fields, screenshot_data, actual_ip)
        ).start()
    else:
        # Send normal log without screenshot
        send_security_improvement_log(
            "✅ User Verification Complete",
            f"New visitor successfully verified and granted access to the site.",
            3066993,  # Green
            fields=log_fields
        )
    
    return jsonify({'success': True}), 200

@app.route('/favicon.ico')
def favicon_ico():
    return send_from_directory(APP_ROOT, 'favicon.svg', mimetype='image/svg+xml')

@app.route('/favicon.svg')
def favicon_svg():
    return send_from_directory(APP_ROOT, 'favicon.svg', mimetype='image/svg+xml')

@app.route('/')
@limiter.limit("10 per minute; 2 per 5 seconds")
def index():
    return send_from_directory(APP_ROOT, 'index.html')

# New routes for clean URLs
@app.route('/dashboard')
@limiter.limit("10 per minute; 2 per 5 seconds")
def dashboard(): return send_from_directory(APP_ROOT, 'dashboard.html')

@app.route('/scans')
@limiter.limit("10 per minute; 2 per 5 seconds")
def scans(): return send_from_directory(APP_ROOT, 'scans.html')

@app.route('/results')
@limiter.limit("10 per minute; 2 per 5 seconds")
def results(): return send_from_directory(APP_ROOT, 'results.html')

@app.route('/settings')
@limiter.limit("10 per minute; 2 per 5 seconds")
def settings(): return send_from_directory(APP_ROOT, 'settings.html')

@app.route('/admin')
@login_required
@admin_required
@limiter.limit("10 per minute; 2 per 5 seconds")
def admin(): return send_from_directory(APP_ROOT, 'admin.html')

@app.route('/discord-panel')
@login_required
@super_admin_required
@limiter.limit("10 per minute; 2 per 5 seconds")
def discord_panel(): return send_from_directory(APP_ROOT, 'discord-panel.html')

@app.route('/server-admin')
@login_required
@admin_required
@limiter.limit("10 per minute; 2 per 5 seconds")
def server_admin(): return send_from_directory(APP_ROOT, 'server-admin.html')

@app.route('/enterprise')
@login_required
@enterprise_admin_required
@limiter.limit("10 per minute; 2 per 5 seconds")
def enterprise(): return send_from_directory(APP_ROOT, 'enterprise.html')

@app.route('/report')
@limiter.limit("10 per minute; 2 per 5 seconds")
def report(): return send_from_directory(APP_ROOT, 'report.html')

@app.route('/unlicensed')
@limiter.limit("10 per minute; 2 per 5 seconds")
def unlicensed(): return send_from_directory(APP_ROOT, 'unlicensed.html')

@app.route('/faq')
@limiter.limit("10 per minute; 2 per 5 seconds")
def faq(): return send_from_directory(APP_ROOT, 'faq.html')

@app.route('/tos')
@limiter.limit("10 per minute; 2 per 5 seconds")
def tos(): return send_from_directory(APP_ROOT, 'tos.html')

@app.route('/rules')
@limiter.limit("10 per minute; 2 per 5 seconds")
def rules(): return send_from_directory(APP_ROOT, 'rules.html')

@app.route('/testscan')
@limiter.limit("10 per minute; 2 per 5 seconds")
def testscan(): return send_from_directory(APP_ROOT, 'testscan.html')

# JavaScript files
@app.route('/security.js')
@limiter.limit("20 per minute")
def security_js(): return send_from_directory(APP_ROOT, 'security.js', mimetype='application/javascript')

@app.route('/notifications.js')
@limiter.limit("20 per minute")
def notifications_js(): return send_from_directory(APP_ROOT, 'notifications.js', mimetype='application/javascript')

# New routes to redirect from .html to clean URLs
@app.route('/index.html')
def index_redirect(): return redirect(url_for('index', **request.args), 301)

@app.route('/dashboard.html')
def dashboard_redirect(): return redirect(url_for('dashboard', **request.args), 301)

@app.route('/scans.html')
def scans_redirect(): return redirect(url_for('scans', **request.args), 301)

@app.route('/results.html')
def results_redirect(): return redirect(url_for('results', **request.args), 301)

@app.route('/settings.html')
def settings_redirect(): return redirect(url_for('settings', **request.args), 301)

@app.route('/admin.html')
def admin_redirect(): return redirect(url_for('admin', **request.args), 301)

@app.route('/server-admin.html')
def server_admin_redirect(): return redirect(url_for('server_admin', **request.args), 301)

@app.route('/enterprise.html')
def enterprise_redirect(): return redirect(url_for('enterprise', **request.args), 301)

@app.route('/report.html')
def report_redirect(): return redirect(url_for('report', **request.args), 301)

@app.route('/unlicensed.html')
def unlicensed_redirect(): return redirect(url_for('unlicensed', **request.args), 301)

@app.route('/faq.html')
def faq_redirect(): return redirect(url_for('faq', **request.args), 301)

@app.route('/tos.html')
def tos_redirect(): return redirect(url_for('tos', **request.args), 301)

@app.route('/rules.html')
def rules_redirect(): return redirect(url_for('rules', **request.args), 301)

@app.route('/testscan.html')
def testscan_redirect(): return redirect(url_for('testscan', **request.args), 301)

# --- 6. Authentication Routes (Discord OAuth2) ---

@app.route('/login')
@limiter.limit("5 per minute")
def login():
    scope = ['identify', 'email']
    discord_session = OAuth2Session(DISCORD_CLIENT_ID, redirect_uri=REDIRECT_URI, scope=scope)
    authorization_url, state = discord_session.authorization_url(AUTHORIZATION_BASE_URL)
    session['oauth2_state'] = state
    return redirect(authorization_url)

@app.route('/callback')
@csrf.exempt  # Exempt from CSRF - Discord OAuth has its own CSRF protection via state parameter
@limiter.limit("10 per minute")  # Prevent callback abuse
def callback():
    if request.values.get('error'):
        return request.values['error']

    # If 'code' is not in the response, it's an invalid callback (e.g., user denied auth, bot hit endpoint).
    if 'code' not in request.args:
        return redirect(url_for('index'))
    
    # Ensure state exists to prevent CSRF and errors on expired sessions.
    if 'oauth2_state' not in session:
        return redirect(url_for('login'))
    
    discord_session = OAuth2Session(DISCORD_CLIENT_ID, redirect_uri=REDIRECT_URI, state=session.get('oauth2_state'))
    token = discord_session.fetch_token(
        TOKEN_URL, client_secret=DISCORD_CLIENT_SECRET, authorization_response=request.url)
    
    user_info = discord_session.get(API_BASE_URL + '/users/@me').json()
    user_id_str = user_info['id']

    user = db.session.get(User, user_id_str)
    if not user:
        user = User(id=user_id_str)
        db.session.add(user)
    
    # Check for license expiration
    if user.license_expires_at and user.license_expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        user.has_license = False

    user.username = user_info['username']
    user.avatar = f"https://cdn.discordapp.com/avatars/{user_id_str}/{user_info['avatar']}.png"

    # If user is a super-admin, enforce their role and license.
    if user_id_str in ADMIN_DISCORD_IDS:
        user.role = 'admin'
    # If the user is NEW (doesn't have a role yet), set their role to 'user'.
    # This leaves existing roles (like admins promoted via panel) untouched.
    elif not user.role:
        user.role = 'user'

    # If the user is an admin (from any source), make sure they have a license.
    if user.role == 'admin':
        user.has_license = True
        user.license_expires_at = None
    # For non-admins, check if they are in the secondary license list if they don't have a timed license.
    elif not user.license_expires_at:
        user.has_license = user.has_license or (user_id_str in LICENSED_DISCORD_IDS)

    db.session.commit()
    
    # Clear old session data and create fresh session (prevents session fixation)
    old_verified = session.get('verified', False)
    session.clear()
    
    # Set session as permanent for remember me functionality
    session.permanent = True
    session['verified'] = True  # Mark as verified
    
    # Store session metadata to help Discord recognize legitimate sessions
    session['login_timestamp'] = datetime.now(timezone.utc).isoformat()
    session['user_agent'] = request.headers.get('User-Agent', '')[:200]
    session['ip_address'] = get_remote_address()
    
    # Remember user for 30 days (persistent login)
    login_user(user, remember=True, duration=timedelta(days=30))
    
    # Get and store browser fingerprint
    fingerprint = session.get('browser_fingerprint', 'Unknown')
    if fingerprint and fingerprint != 'Unknown':
        user.browser_fingerprint = fingerprint
        db.session.commit()
    
    # Log successful session creation
    send_security_improvement_log(
        "Session Security",
        f"Secure session created for user {user.username}",
        3066993,  # Green
        fields=[
            {"name": "Session Duration", "value": "30 days", "inline": True},
            {"name": "IP Address", "value": f"`{get_remote_address()}`", "inline": True}
        ]
    )
    
    # --- SITE LOGIN LOG ---
    threading.Thread(target=send_login_notification, args=(user.id, user.username, user.avatar, fingerprint)).start()
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- 7. API Routes ---

@app.errorhandler(429)
def ratelimit_handler(e):
    # --- SECURITY ALERT ---
    send_security_alert(
        "Rate Limit Exceeded", 
        "A user or IP has exceeded a configured rate limit.", 
        16729344, # Yellow
        fields=[{"name": "Limit Exceeded", "value": f"`{e.description}`", "inline": False}]
    )
    return render_template_string(TOO_MANY_REQUESTS_TEMPLATE), 429

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    # --- SECURITY ALERT ---
    send_security_alert(
        "CSRF Attack Detected", 
        "A request was blocked due to missing or invalid CSRF token.", 
        15158332, # Red
        fields=[
            {"name": "Reason", "value": f"`{e.description}`", "inline": False},
            {"name": "Endpoint", "value": f"`{request.path}`", "inline": True},
            {"name": "Method", "value": f"`{request.method}`", "inline": True}
        ]
    )
    return jsonify({
        'error': 'CSRF token missing or invalid',
        'message': 'This request has been blocked for security reasons. Please refresh the page and try again.'
    }), 403

@app.route('/api/security-violation', methods=['POST'])
@limiter.exempt 
def security_violation():
    # --- SECURITY ALERT ---
    send_security_alert(
        "Client-Side Tampering", 
        "A user opened developer tools or performed a similar client-side action.", 
        16729344, # Orange
        fields=[{"name": "Referer", "value": f"`{request.referrer or 'N/A'}`", "inline": False}]
    )
    return '', 204

@app.route('/api/discord-members', methods=['GET'])
def get_discord_members():
    global discord_members_cache
    now = time.time()
    
    if discord_members_cache['data'] and (now - discord_members_cache['timestamp'] < DISCORD_MEMBERS_CACHE_DURATION):
        return jsonify(discord_members_cache['data'])

    if not bot.is_ready():
        return jsonify({'error': 'Bot is not ready, please try again shortly.'}), 503

    async def fetch_members():
        guild = bot.get_guild(DISCORD_GUILD_ID)
        if not guild:
            return []
        
        # Sort members by their top role position, then alphabetically
        sorted_members = sorted(guild.members, key=lambda m: (m.top_role.position, m.display_name.lower()), reverse=True)
        
        members_data = []
        for member in sorted_members:
            if member.bot:
                continue

            roles_data = []
            for role in sorted(member.roles, key=lambda r: r.position, reverse=True):
                if role.is_default():  # Skip @everyone
                    continue
                roles_data.append({
                    'id': str(role.id),
                    'name': role.name,
                    'color': str(role.color),
                    'icon_url': str(role.icon.url) if role.icon else None
                })
            
            members_data.append({
                'id': str(member.id),
                'username': member.display_name,
                'avatar_url': str(member.display_avatar.url),
                'status': str(member.status),
                'roles': roles_data
            })
        return members_data

    future = asyncio.run_coroutine_threadsafe(fetch_members(), bot.loop)
    try:
        result = future.result(timeout=10)
        discord_members_cache['data'] = result
        discord_members_cache['timestamp'] = now
        return jsonify(result)
    except Exception as e:
        return sanitized_error_response(e, "Failed to fetch Discord members", 500)

@app.route('/api/ping', methods=['GET'])
@limiter.exempt
def ping():
    """A lightweight endpoint to check if the server is responsive."""
    return jsonify({'status': 'ok'})

@app.route('/api/download-scanner/<int:pin>')
@limiter.limit("10 per minute")
def download_scanner(pin):
    scan = Scan.query.filter_by(pin=pin).first_or_404()
    user = db.session.get(User, scan.user_id)
    
    # This is the game selected for THIS SPECIFIC SCAN. This is the correct source of truth.
    game_folder = scan.game if scan.game in ['fivem', 'dayz', 'minecraft'] else 'fivem'
    filename = 'scaner.exe'

    # Check for enterprise custom loader first
    if user and user.enterprise and user.enterprise.has_custom_loader and user.enterprise.loader_path:
        enterprise_loader_folder = user.enterprise.loader_path
        
        # The custom loader path is now constructed based on the game of the CURRENT SCAN.
        # Path structure: /app/{scan_game}/{enterprise_loader_folder}/scaner.exe
        custom_app_dir = os.path.join(app.root_path, 'app', game_folder, enterprise_loader_folder)
        
        if os.path.exists(os.path.join(custom_app_dir, filename)):
            # If the custom loader for the selected game exists, send it.
            return send_from_directory(
                custom_app_dir,
                filename,
                as_attachment=True,
                download_name=f'async_{pin}.exe'
            )
        else:
            # If a custom loader doesn't exist for this specific game, log it and fall through to the default loader.
            print(f"INFO: Custom loader for enterprise '{user.enterprise.name}' for game '{game_folder}' not found at '{custom_app_dir}'. Falling back to default scanner.", file=sys.stderr)

    # Default loader logic (also serves as the fallback for enterprise users)
    default_app_dir = os.path.join(app.root_path, 'app', game_folder)
    
    if not os.path.exists(os.path.join(default_app_dir, filename)):
        return jsonify({'error': f"Default scanner client for '{game_folder}' not found on server in '{default_app_dir}'. Please contact support."}), 404

    return send_from_directory(
        default_app_dir,
        filename,
        as_attachment=True,
        download_name=f'async_{pin}.exe'
    )


@app.route('/api/user', methods=['GET'])
def get_user():
    if current_user.is_authenticated:
        user = db.session.get(User, current_user.id)
        if not user:
            logout_user()
            return jsonify({'error': 'Authenticated user not found in database session.'}), 404

        # On-the-fly check for expired bans
        if user.is_banned and user.ban_expires_at and user.ban_expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            user.is_banned = False
            user.ban_reason = None
            user.ban_expires_at = None
            user.responsible_admin_id = None
            db.session.commit()

        # On-the-fly check for expired licenses
        if user.license_expires_at and user.license_expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            if user.has_license:
                user.has_license = False
                db.session.commit()

        is_enterprise_admin = bool(
            user.enterprise_id and
            user.enterprise and
            user.enterprise.admin_user_id == user.id
        )
        return jsonify({
            'id': user.id,
            'username': user.username,
            'avatar': user.avatar,
            'role': user.role,
            'has_license': user.has_license,
            'is_banned': user.is_banned,
            'ban_reason': user.ban_reason,
            'ban_expires_at': user.ban_expires_at.isoformat() if user.ban_expires_at else None,
            'responsible_admin_id': user.responsible_admin_id,
            'is_enterprise_admin': is_enterprise_admin,
            'license_expires_at': user.license_expires_at.isoformat() if user.license_expires_at else None,
            'tos_accepted': user.tos_accepted,
        })
    return jsonify({'error': 'Not authenticated'}), 401

@app.route('/api/accept-tos', methods=['POST'])
@csrf.exempt  # User is already authenticated
@login_required
def accept_tos():
    user = db.session.get(User, current_user.id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if user.tos_accepted:
        return jsonify({'message': 'ToS already accepted.'}), 200

    user.tos_accepted = True
    db.session.commit()
    
    # --- TOS ACCEPT LOG ---
    threading.Thread(target=send_tos_acceptance_notification, args=(user.id, user.username)).start()
    
    return jsonify({'message': 'Terms of Service accepted successfully.'}), 200

@app.route('/api/scans', methods=['GET'])
@login_required
def get_scans():
    target_user_id = request.args.get('user_id')
    # If a user_id is provided, only admins can view other people's scans
    if target_user_id and current_user.role == 'admin':
        user_to_view = db.session.get(User, target_user_id)
        if not user_to_view:
            return jsonify({'error': 'User not found'}), 404
        scans = Scan.query.filter_by(user_id=target_user_id).order_by(Scan.timestamp.desc()).all()
    else:
        # Default behavior: show your own scans
        scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.timestamp.desc()).all()
    
    # Add critical_count to each scan (only count Critical severity findings)
    scans_data = []
    for s in scans:
        scan_dict = to_dict(s, ['findings'])
        # Count only Critical severity findings
        critical_count = sum(1 for f in s.findings if f.severity == 'Critical')
        scan_dict['critical_count'] = critical_count
        scans_data.append(scan_dict)
    
    return jsonify(scans_data)

@app.route('/api/scans/<int:scan_id>/details', methods=['GET'])
@login_required
def get_scan_details(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan: return jsonify({'error': 'Scan not found'}), 404
    
    if scan.user_id != current_user.id and current_user.role != 'admin':
        return jsonify({'error': 'Forbidden'}), 403

    scan_data = to_dict(scan)
    system_info = to_dict(scan.system_info) if scan.system_info else {}
    user_identities = [to_dict(i) for i in scan.user_identities]
    browser_history = [to_dict(b) for b in scan.browser_histories]
    command_history = [to_dict(c) for c in scan.command_histories]
    game_analysis = [to_dict(f) for f in scan.game_analyses]
    recent_executables = [to_dict(e) for e in scan.recent_executables]
    
    # Group findings by category
    findings_list = [to_dict(f) for f in scan.findings]
    grouped_findings = defaultdict(list)
    for f in findings_list:
        grouped_findings[f.get('category', 'Uncategorized')].append(f)

    # Group generic artifacts by category
    artifacts_list = [to_dict(a) for a in scan.artifacts]
    grouped_artifacts = defaultdict(list)
    for a in artifacts_list:
        grouped_artifacts[a.get('category', 'Uncategorized')].append(a)

    # Transform structured hardware_info into the generic artifact format for the frontend
    hardware_artifacts = []
    for hw in scan.hardware_info:
        # Deserialize details if it's a JSON string
        details_value = hw.details
        if isinstance(hw.details, str):
            try:
                details_value = json.loads(hw.details)
            except (json.JSONDecodeError, TypeError):
                details_value = hw.details
        
        hardware_artifacts.append({
            "category": "HARDWARE_AND_PERIPHERALS",
            "key": hw.name,
            "value": details_value,
            "status": "info"
        })
    grouped_artifacts['HARDWARE_AND_PERIPHERALS'] = hardware_artifacts
    
    # Transform structured system_services into the generic artifact format for the frontend
    service_artifacts = []
    status_map = {'running': 'info', 'stopped': 'warning', 'disabled': 'threat'}
    for svc in scan.system_services:
        description = f"Service `{svc.name}` is `{svc.status}`."
        service_artifacts.append({
            "category": "SYSTEM_INTEGRITY_CHECKS",
            "description": description,
            "details": svc.details,
            "status": status_map.get(svc.status.lower(), 'info')
        })
    grouped_artifacts['SYSTEM_INTEGRITY_CHECKS'] = service_artifacts

    return jsonify({
        'scan': scan_data,
        'grouped_findings': grouped_findings,
        'system_info': [system_info] if system_info else [],
        'user_identities': user_identities,
        'browser_history': browser_history,
        'command_history': command_history,
        'game_analysis': game_analysis,
        'grouped_artifacts': grouped_artifacts,
        'recent_executables': recent_executables
    })

@app.route('/api/scans', methods=['POST'])
@csrf.exempt  # Frontend doesn't send CSRF token for this endpoint
@login_required
def create_scan():
    if current_user.is_banned: return jsonify({'error': 'User is banned'}), 403
    
    data = request.get_json() if request.is_json else {}
    game = data.get('game', 'fivem') if isinstance(data, dict) else 'fivem'
    if game not in ['fivem', 'dayz', 'minecraft']:
        game = 'fivem' # Sanitize input

    # Retry logic for handling rare PIN collisions during database insertion.
    for _ in range(5): # Attempts to generate a unique PIN up to 5 times.
        try:
            pin = generate_unique_pin()
            new_scan = Scan(pin=pin, url=f"scanner.{pin}", user_id=current_user.id, game=game)
            db.session.add(new_scan)
            db.session.commit()
            
            # --- PIN CREATION LOG ---
            threading.Thread(target=send_pin_creation_notification, args=(current_user.id, current_user.username, pin)).start()
            
            return jsonify(to_dict(new_scan)), 201
        except IntegrityError:
            db.session.rollback()  # Important: rollback the failed transaction
            # A PIN collision occurred at the database level. Loop will try again.
            continue
        except Exception as e:
            db.session.rollback()
            # Catch any other unexpected errors during the process
            return sanitized_error_response(e, "Failed to create scan", 500)

    # This part is reached only if all retry attempts fail.
    return jsonify({'error': 'Failed to generate a unique scan PIN after multiple attempts. Please try again.'}), 503

@app.route('/api/scans/<int:scan_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return '', 204
    db.session.delete(scan)
    db.session.commit()
    return '', 204

@app.route('/api/scans/<int:scan_id>/public', methods=['PUT'])
@login_required
def toggle_public_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan: return jsonify({'error': 'Not found'}), 404
    if scan.user_id != current_user.id: return jsonify({'error': 'Forbidden'}), 403
    data = request.json
    scan.is_public = data.get('isPublic', scan.is_public)
    db.session.commit()
    return jsonify(to_dict(scan))

@app.route('/api/submit/<int:pin>', methods=['POST'])
@csrf.exempt  # Exempt from CSRF - scanner client doesn't use browser sessions
@limiter.exempt # Exempt this endpoint from standard rate limits
def submit_scan_results(pin):
    print(f"📥 Received scan submission for PIN: {pin}")
    print(f"   IP: {get_remote_address()}")
    print(f"   Content-Type: {request.headers.get('Content-Type')}")
    
    # Validate PIN format
    if not validate_pin(pin):
        print(f"❌ Invalid PIN format: {pin}")
        return jsonify({'error': 'Invalid PIN format'}), 400
    
    scan = Scan.query.filter_by(pin=pin).first_or_404()
    print(f"✅ Found scan: ID={scan.id}, Status={scan.status}")
    
    if scan.status != 'Pending':
        print(f"❌ Scan already submitted: {scan.status}")
        return jsonify({'error': 'Scan results already submitted'}), 409

    try:
        # Parse JSON payload explicitly to avoid relying on request.json property
        # Use get_json to provide clearer error behaviour if payload is missing
        data = request.get_json(force=True)
        if not data:
            print("❌ Empty or invalid JSON payload")
            return jsonify({'error': 'Invalid or empty JSON payload received.'}), 400
        
        print(f"✅ Received data with {len(data.get('results', []))} findings")
        
        # Validate data structure
        if not isinstance(data, dict):
            return jsonify({'error': 'Invalid data format'}), 400
            
        findings_data = data.get('results', [])
        artifacts_data = data.get('artifacts', {})

        # Extract scanned user's Discord ID if available
        scanned_user_discord_id = None
        user_identities_data = artifacts_data.get('USER_IDENTITIES', [])
        if user_identities_data:
            for item in user_identities_data:
                if isinstance(item, dict) and item.get('key') == 'Discord User' and 'value' in item:
                    user_id_match = re.search(r'\(ID: (\d+)\)', item['value'])
                    if user_id_match:
                        scanned_user_discord_id = user_id_match.group(1)
                        break

        # Clear old data for this scan to ensure a clean insert
        Finding.query.filter_by(scan_id=scan.id).delete()
        SystemInfo.query.filter_by(scan_id=scan.id).delete()
        UserIdentity.query.filter_by(scan_id=scan.id).delete()
        BrowserHistory.query.filter_by(scan_id=scan.id).delete()
        CommandHistory.query.filter_by(scan_id=scan.id).delete()
        GameAnalysis.query.filter_by(scan_id=scan.id).delete()
        Artifact.query.filter_by(scan_id=scan.id).delete()
        RecentExecutable.query.filter_by(scan_id=scan.id).delete()
        HardwareInfo.query.filter_by(scan_id=scan.id).delete()
        SystemService.query.filter_by(scan_id=scan.id).delete()
        CustomRuleFinding.query.filter_by(scan_id=scan.id).delete()

        # Process Findings
        for finding_data in findings_data:
            # Correctly serialize 'score_contributors' to a JSON string if it's a list or dict.
            # This fixes a database binding error with SQLite and other dialects that don't auto-serialize.
            if 'score_contributors' in finding_data and isinstance(finding_data.get('score_contributors'), (list, dict)):
                finding_data['score_contributors'] = json.dumps(finding_data['score_contributors'])
            
            # Filter out fields that don't exist in the Finding model
            # This prevents errors when the scanner sends extra fields that aren't in the model yet
            valid_fields = {
                'category', 'name', 'severity', 'path', 'action', 
                'file_hash', 'yara_rule', 'source_type', 'score', 
                'score_contributors', 'last_execution_time', 'match_count', 'confidence_score'
            }
            filtered_data = {k: v for k, v in finding_data.items() if k in valid_fields}
            
            # Debug logging for instance status
            if 'last_execution_time' in filtered_data:
                print(f"🔍 Saving finding with last_execution_time: {filtered_data['last_execution_time']}")
            
            new_finding = Finding(scan_id=scan.id, **filtered_data)
            db.session.add(new_finding)
            
            # If this is a custom rule finding, also save it to CustomRuleFinding table
            if finding_data.get('category') == 'CUSTOM_RULES':
                source_type = finding_data.get('source_type', '')
                rule_name = finding_data.get('name', 'Unknown Rule')
                
                # Determine rule type from source_type
                if 'CustomHash' in source_type:
                    rule_type = 'hash'
                elif 'CustomKeyword' in source_type:
                    rule_type = 'keyword'
                elif 'CustomYARA' in source_type:
                    rule_type = 'yara'
                else:
                    rule_type = 'unknown'
                
                # Try to find the original rule
                rule_id = None
                if rule_type == 'keyword':
                    # Extract keyword from name like "Custom Keyword: something"
                    keyword_match = re.search(r'Custom Keyword:\s*(.+)', rule_name)
                    if keyword_match:
                        keyword = keyword_match.group(1).strip()
                        rule = CustomRule.query.filter_by(
                            user_id=scan.user_id,
                            rule_type='keyword',
                            content=keyword,
                            is_active=True
                        ).first()
                        if rule:
                            rule_id = rule.id
                elif rule_type == 'hash':
                    # Get hash from file_hash field
                    file_hash = finding_data.get('file_hash', '').upper()
                    if file_hash:
                        rule = CustomRule.query.filter_by(
                            user_id=scan.user_id,
                            rule_type='hash',
                            content=file_hash,
                            is_active=True
                        ).first()
                        if rule:
                            rule_id = rule.id
                
                custom_finding = CustomRuleFinding(
                    scan_id=scan.id,
                    rule_id=rule_id,
                    rule_name=rule_name,
                    rule_type=rule_type,
                    severity=finding_data.get('severity', 'Medium'),
                    matched_content=finding_data.get('file_hash') or finding_data.get('name', ''),
                    location=finding_data.get('path', 'Unknown')
                )
                db.session.add(custom_finding)

        # Process Artifacts
        for category, items in artifacts_data.items():
            if not isinstance(items, list): continue

            # SYSTEM_INFORMATION
            if category == 'SYSTEM_INFORMATION' and items:
                info_dict = {item.get('key', '').lower().replace(' ', '_').replace('(', '').replace(')', ''): item.get('value') for item in items if 'key' in item and 'value' in item}
                sys_info = SystemInfo(
                    scan_id=scan.id,
                    os_version=info_dict.get('os_version'),
                    cpu_info=info_dict.get('cpu_info'),
                    ram_total=info_dict.get('ram_total'),
                    hardware_id=info_dict.get('hardware_id'),
                    antivirus=info_dict.get('antivirus'),
                    uptime=info_dict.get('uptime')
                )
                db.session.add(sys_info)
                
                # Extract user identities from SYSTEM_INFORMATION
                for item in items:
                    if 'key' in item and 'value' in item:
                        key = item['key']
                        value = item['value']
                        
                        # Skip empty values
                        if not value or value in ['Unknown', 'N/A', 'None']:
                            continue
                        
                        # Discord
                        if key == 'Discord Username':
                            discord_id = next((i['value'] for i in items if i.get('key') == 'Discord User ID'), None)
                            identity = UserIdentity(
                                scan_id=scan.id,
                                identity_type='Discord',
                                username=value,
                                user_id=discord_id
                            )
                            db.session.add(identity)
                        
                        # Discord User ID (if username not found)
                        elif key == 'Discord User ID':
                            # Check if we already added Discord username
                            has_discord_username = any(i.get('key') == 'Discord Username' for i in items)
                            if not has_discord_username:
                                identity = UserIdentity(
                                    scan_id=scan.id,
                                    identity_type='Discord',
                                    username='Discord User',
                                    user_id=value
                                )
                                db.session.add(identity)
                        
                        # Steam
                        elif key == 'Steam PersonaName':
                            identity = UserIdentity(
                                scan_id=scan.id,
                                identity_type='Steam',
                                username=value,
                                user_id=None
                            )
                            db.session.add(identity)
                        
                        # Windows
                        elif key == 'Windows Username':
                            identity = UserIdentity(
                                scan_id=scan.id,
                                identity_type='Windows',
                                username=value,
                                user_id=None
                            )
                            db.session.add(identity)
            
            # USER_ACCOUNTS (New format from C# Scanner with Discord/Steam)
            elif category == 'USER_ACCOUNTS' and items:
                for item in items:
                    if isinstance(item, dict):
                        platform = item.get('platform', 'Unknown')
                        username = item.get('username', 'Unknown')
                        user_id = item.get('user_id') or item.get('steam_id')
                        email = item.get('email')
                        
                        # Create additional_info JSON with all extra fields
                        additional_info = {}
                        if email:
                            additional_info['email'] = email
                        if item.get('phone'):
                            additional_info['phone'] = item.get('phone')
                        if item.get('avatar_url'):
                            additional_info['avatar_url'] = item.get('avatar_url')
                        if item.get('mfa_enabled') is not None:
                            additional_info['mfa_enabled'] = item.get('mfa_enabled')
                        if item.get('verified') is not None:
                            additional_info['verified'] = item.get('verified')
                        if item.get('locale'):
                            additional_info['locale'] = item.get('locale')
                        if item.get('flags') is not None:
                            additional_info['flags'] = item.get('flags')
                        if item.get('client'):
                            additional_info['client'] = item.get('client')
                        if item.get('persona_name'):
                            additional_info['persona_name'] = item.get('persona_name')
                        if item.get('auto_login') is not None:
                            additional_info['auto_login'] = item.get('auto_login')
                        if item.get('remember_password') is not None:
                            additional_info['remember_password'] = item.get('remember_password')
                        if item.get('steam_path'):
                            additional_info['steam_path'] = item.get('steam_path')
                        if item.get('most_recent') is not None:
                            additional_info['most_recent'] = item.get('most_recent')
                        
                        identity = UserIdentity(
                            scan_id=scan.id,
                            identity_type=platform,
                            username=username,
                            user_id=str(user_id) if user_id else None,
                            additional_info=json.dumps(additional_info) if additional_info else None
                        )
                        db.session.add(identity)
            
            # Legacy USER_IDENTITIES format (keep for backwards compatibility)
            elif category == 'USER_IDENTITIES' and items:
                for item in items:
                    if 'key' in item and 'value' in item:
                        username_part = item['value'].split(' (ID:')[0]
                        user_id_match = re.search(r'\(ID: (\d+)\)', item['value'])
                        user_id = user_id_match.group(1) if user_id_match else None
                        identity = UserIdentity(
                            scan_id=scan.id,
                            identity_type=item['key'].replace(' User', '').replace(' Username', ''),
                            username=username_part,
                            user_id=user_id
                        )
                        db.session.add(identity)
            
            # GAME_ANALYSIS (from C# Scanner - new format)
            elif category == 'GAME_ANALYSIS' and items:
                # Save as generic artifacts for display
                for item in items:
                    if isinstance(item, dict):
                        desc = item.get('description', 'Game file detected')
                        details = item.get('details', '')
                        status = item.get('status', 'info')
                        
                        db.session.add(Artifact(
                            scan_id=scan.id,
                            category='GAME_ANALYSIS',
                            description=serialize_details(desc),
                            details=serialize_details(details),
                            status=serialize_details(status)
                        ))
            
            # GAME_ANALYSIS (Legacy format - Generic handler for FiveM, DayZ, etc.)
            elif category in ['FIVEM_ANALYSIS', 'DAYZ_ANALYSIS', 'MINECRAFT_ANALYSIS'] and items:
                # Check if there is anything to actually save.
                has_meaningful_data = any(
                    'Path Detected' in item.get('key', '') or 'plugin' in item.get('description', '') or
                    'Mods folder is not empty' in item.get('description', '') or
                    'Modifications Detected' in item.get('description', '')
                    for item in items
                )

                if has_meaningful_data:
                    analysis_obj = GameAnalysis(scan_id=scan.id, mod_detected=False)
                    details_list = []
                    for item in items:
                        if 'Path Detected' in item.get('key', ''):
                            analysis_obj.installation_path = item.get('value')
                        if 'plugin' in item.get('description', '') or 'Mods folder is not empty' in item.get('description', '') or 'Modifications Detected' in item.get('description', ''):
                            analysis_obj.mod_detected = True
                            mod_name_match = re.search(r'`([^`]+)`', item.get('description', ''))
                            analysis_obj.mod_name = mod_name_match.group(1) if mod_name_match else 'Unknown Modification'
                            if analysis_obj.installation_path and analysis_obj.mod_name:
                                analysis_obj.mod_path = os.path.join(analysis_obj.installation_path, 'plugins', analysis_obj.mod_name)
                            else:
                                analysis_obj.mod_path = analysis_obj.mod_name
                        if item.get('details'):
                            details_list.append(serialize_details(item.get('details')))
                    analysis_obj.mod_details = "; ".join(details_list) if details_list else None
                    db.session.add(analysis_obj)
                else:
                    # If no meaningful structured data, save them as generic artifacts
                    for item in items:
                         if isinstance(item, dict):
                            desc = item.get('description') or item.get('key')
                            if desc:
                                details = item.get('details') or item.get('value')
                                status = item.get('status')
                                db.session.add(Artifact(
                                    scan_id=scan.id, 
                                    category=category, 
                                    description=serialize_details(desc),
                                    details=serialize_details(details),
                                    status=serialize_details(status)
                                ))

            # BROWSER_ACTIVITY (from C# Scanner)
            elif category == 'BROWSER_ACTIVITY' and items:
                for item in items:
                    if isinstance(item, dict):
                        # Extract URL from item (new format includes url field)
                        url = item.get('url', '')
                        
                        # If no URL field, try to extract from details
                        if not url:
                            details = item.get('details', '')
                            url_match = re.search(r'URL:\s*(https?://[^\s\n]+)', details)
                            url = url_match.group(1) if url_match else ''
                        
                        # Extract site name from description
                        description = item.get('description', '')
                        site_match = re.search(r'site:\s*([^\s]+)', description)
                        site_name = site_match.group(1) if site_match else 'Unknown'
                        
                        # Extract browser from details
                        details = item.get('details', '')
                        browser_match = re.search(r'Browser:\s*(\w+)', details)
                        browser = browser_match.group(1) if browser_match else 'Unknown'
                        
                        # Only add if we have a valid URL
                        if url:
                            bh = BrowserHistory(
                                scan_id=scan.id,
                                browser=browser,
                                url=url,
                                title=description,
                                visit_count=1
                            )
                            db.session.add(bh)
            
            # COMMAND_HISTORY (from C# Scanner)
            elif category == 'COMMAND_HISTORY' and items:
                for item in items:
                    if isinstance(item, dict):
                        # Extract command type (PowerShell or Run Command)
                        description = item.get('description', '')
                        if 'PowerShell' in description:
                            cmd_type = 'PowerShell'
                        elif 'Run command' in description:
                            cmd_type = 'Run Command'
                        else:
                            cmd_type = 'Unknown'
                        
                        # Extract command from details like "Command: some_command"
                        details = item.get('details', '')
                        cmd_match = re.search(r'Command:\s*(.+)', details, re.IGNORECASE)
                        cmd_text = cmd_match.group(1).strip() if cmd_match else details
                        
                        # Extract keyword from description like "containing 'keyword'"
                        keyword_match = re.search(r"containing '([^']+)'", description)
                        keywords = keyword_match.group(1) if keyword_match else None
                        
                        # Only add if we have a valid command
                        if cmd_text and cmd_text != 'Unknown':
                            cmd = CommandHistory(
                                scan_id=scan.id,
                                type=cmd_type,
                                command=cmd_text,
                                is_suspicious=True,
                                keywords_found=keywords
                            )
                            db.session.add(cmd)
            
            # COMMAND_LINE_HISTORY (Legacy format - keep for backwards compatibility)
            elif category == 'COMMAND_LINE_HISTORY' and items:
                for item in items:
                    if 'description' in item and item.get('status') == 'threat':
                        cmd_match = re.search(r'Command: `([^`]+)`', item.get('details', ''))
                        cmd_text = cmd_match.group(1) if cmd_match else 'Unknown'
                        cmd_type_match = re.search(r'in (PowerShell|Run Dialog)', item.get('description', ''))
                        cmd_type = cmd_type_match.group(1) if cmd_type_match else 'Unknown'
                        keywords_match = re.search(r'keyword `([^`]+)`', item.get('description', ''))
                        keywords = keywords_match.group(1) if keywords_match else None
                        cmd = CommandHistory(scan_id=scan.id, type=cmd_type, command=cmd_text, is_suspicious=True, keywords_found=keywords)
                        db.session.add(cmd)
            
            # NETWORK_ACTIVITY (for Browser History)
            elif category == 'NETWORK_ACTIVITY' and items:
                for item in items:
                    if 'Visited suspicious URL' in item.get('description', ''):
                        match = re.search(r'in\s+([\w\s]+):\s*(https?://[^\s`]+)', item.get('description', ''))
                        if match:
                            browser, url = match.groups()
                            title_match = re.search(r'Title: ([^\n]+)', item.get('details', ''))
                            title = title_match.group(1) if title_match else None
                            bh = BrowserHistory(scan_id=scan.id, browser=browser.strip(), url=url.strip(), title=title, visit_count=1)
                            db.session.add(bh)

            # RECENT_EXECUTABLES
            elif category == 'RECENT_EXECUTABLES' and items:
                for item in items:
                    if isinstance(item, dict) and 'process_name' in item:
                        last_executed_dt = None
                        if 'last_executed' in item and item['last_executed']:
                            try:
                                last_executed_dt = datetime.fromisoformat(str(item['last_executed']).replace('Z', '+00:00'))
                            except (ValueError, TypeError):
                                pass
                        new_executable = RecentExecutable(
                            scan_id=scan.id,
                            process_name=item.get('process_name'),
                            last_executed=last_executed_dt,
                            risk_level=item.get('risk_level', 'safe'),
                            details=serialize_details(item.get('details'))
                        )
                        db.session.add(new_executable)
            
            # HARDWARE_AND_PERIPHERALS (New)
            elif category == 'HARDWARE_AND_PERIPHERALS' and items:
                for item in items:
                    if isinstance(item, dict) and 'key' in item and 'value' in item:
                        new_hw = HardwareInfo(
                            scan_id=scan.id,
                            name=item.get('key'),
                            details=serialize_details(item.get('value'))
                        )
                        db.session.add(new_hw)

            # SYSTEM_INTEGRITY_CHECKS (New)
            elif category == 'SYSTEM_INTEGRITY_CHECKS' and items:
                for item in items:
                    if isinstance(item, dict) and 'description' in item:
                        match = re.search(r"Service `([^`]+)`.*? is `([^`]+)`", item['description'])
                        if match:
                            service_name, status = match.groups()
                            new_svc = SystemService(
                                scan_id=scan.id,
                                name=service_name,
                                status=status,
                                details=serialize_details(item.get('details'))
                            )
                            db.session.add(new_svc)
                        else: # Fallback to generic artifact if parsing fails
                            new_artifact = Artifact(scan_id=scan.id, category=category, description=item.get('description', 'N/A'), details=serialize_details(item.get('details')), status=item.get('status'))
                            db.session.add(new_artifact)

            # Generic artifacts - Now handles both description/details and key/value pairs
            else:
                for item in items:
                    if isinstance(item, dict):
                        desc = item.get('description')
                        details = item.get('details')
                        status = item.get('status')
                        
                        if 'key' in item and 'value' in item:
                            desc = item.get('key')
                            details = item.get('value')

                        if desc:
                            new_artifact = Artifact(
                                scan_id=scan.id,
                                category=category,
                                description=serialize_details(desc),
                                details=serialize_details(details),
                                status=serialize_details(status)
                            )
                            db.session.add(new_artifact)

        scan.status = 'Cheats Detected' if findings_data else 'No threats found'
        scan.timestamp = datetime.now(timezone.utc)
        
        # Extract HWID from the submitted artifacts
        hwid = "Not Found"
        system_info_artifacts = artifacts_data.get('SYSTEM_INFORMATION', [])
        if system_info_artifacts:
            # Try multiple possible key names
            hwid = next((item['value'] for item in system_info_artifacts 
                        if item.get('key') in ['Hardware ID', 'Hardware ID (UUID)', 'hardware_id']), "Not Found")
        
        # Spawn a background thread to send the notification without blocking the response
        threading.Thread(target=send_scan_submission_notification, args=(scan.user, hwid, scan.pin, scan.id, len(findings_data), scanned_user_discord_id)).start()

        print(f"💾 Committing {len(findings_data)} findings to database...")
        import time
        commit_start = time.time()
        db.session.commit()
        commit_time = time.time() - commit_start
        print(f"✅ Scan {pin} submitted successfully! {len(findings_data)} findings saved in {commit_time:.2f}s")
        return jsonify({'message': 'Scan results submitted successfully'}), 200




    except Exception as e:
        db.session.rollback()
        error_msg = str(e)
        error_type = type(e).__name__
        print(f"❌ CRITICAL ERROR in /api/submit/{pin}: {error_type}: {error_msg}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        
        # Log additional context for debugging
        try:
            findings_count = len(findings_data) if 'findings_data' in locals() else 0
            print(f"  -> Findings count: {findings_count}", file=sys.stderr)
            print(f"  -> Scan ID: {scan.id if 'scan' in locals() else 'N/A'}", file=sys.stderr)
        except:
            pass
        
        return jsonify({
            'error': 'An internal server error occurred while processing scan data.',
            'error_type': error_type,
            'message': error_msg
        }), 500


# Telemetry endpoint for client uploads (privacy-first; save locally and return 200)
@app.route('/api/telemetry', methods=['POST'])
@csrf.exempt  # Exempt from CSRF - external client uploads
def api_telemetry():
    try:
        payload = request.get_json(force=True)
        reports_dir = os.path.join(APP_ROOT, 'telemetry_reports')
        if not os.path.exists(reports_dir):
            os.makedirs(reports_dir, exist_ok=True)

        fname = os.path.join(reports_dir, f"telemetry_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex}.json")
        with open(fname, 'w', encoding='utf-8') as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)

        api_logs.append({'path': request.path, 'ip': request.remote_addr, 'time': datetime.now(timezone.utc).isoformat()})
        return jsonify({'status': 'ok'}), 200
    except Exception as e:
        print(f"Error saving telemetry: {e}", file=sys.stderr)
        return jsonify({'status': 'error', 'error': str(e)}), 500


# Rulepacks endpoint - serves a rulepack JSON if present, otherwise returns a small sample
@app.route('/api/rulepacks', methods=['GET'])
def api_rulepacks():
    try:
        rp_path = os.path.join(APP_ROOT, 'rulepacks.json')
        if os.path.exists(rp_path):
            with open(rp_path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            return jsonify(data)

        # Fallback sample rulepack
        sample = {
            'version': '1.0',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'rules': [
                {
                    'name': 'ImGui',
                    'rule_id': 'sample-1',
                    'weight': 50,
                    'confidence': 50,
                    'strings': ['ImGui']
                }
            ]
        }
        return jsonify(sample)
    except Exception as e:
        print(f"Error serving rulepacks: {e}", file=sys.stderr)
        return jsonify({'version': '0', 'rules': []}), 500

@app.route('/api/dashboard-stats', methods=['GET'])
@login_required
def get_dashboard_stats():
    user_id = current_user.id
    total_scans = Scan.query.filter_by(user_id=user_id).count()
    threats_detected_scans = Scan.query.filter_by(user_id=user_id, status='Cheats Detected').count()
    recent_scans = Scan.query.filter_by(user_id=user_id).order_by(Scan.timestamp.desc()).limit(5).all()
    recent_activity = []
    for scan in recent_scans:
        # Ensure the timestamp is offset-aware (UTC) before subtraction
        scan_timestamp_utc = scan.timestamp.replace(tzinfo=timezone.utc)
        time_diff = datetime.now(timezone.utc) - scan_timestamp_utc
        if time_diff.total_seconds() < 60: time_ago = f"{int(time_diff.total_seconds())}s ago"
        elif time_diff.total_seconds() < 3600: time_ago = f"{int(time_diff.total_seconds() / 60)}m ago"
        elif time_diff.total_seconds() < 86400: time_ago = f"{int(time_diff.total_seconds() / 3600)}h ago"
        else: time_ago = f"{int(time_diff.total_seconds() / 86400)}d ago"
        activity = {'time': time_ago}
        if scan.status == 'Cheats Detected':
            activity['status'] = 'error'
            activity['message'] = f"Scan PIN {scan.pin} completed - {len(scan.findings)} threats found."
        elif scan.status == 'No threats found':
            activity['status'] = 'success'
            activity['message'] = f"Scan PIN {scan.pin} completed - No threats found."
        else:
            activity['status'] = 'warning'
            activity['message'] = f"New scan PIN {scan.pin} generated."
        recent_activity.append(activity)
    return jsonify({'totalScans': total_scans, 'threatsDetected': threats_detected_scans, 'recentActivity': recent_activity})

# --- 8. Admin API Routes ---
@app.route('/api/admin/users', methods=['GET'])
@login_required
@admin_required
def admin_get_users():
    users = User.query.all()
    users_data = []
    for user in users:
        user_dict = to_dict(user)
        user_dict['scan_count'] = Scan.query.filter_by(user_id=user.id).count()
        users_data.append(user_dict)
    return jsonify(users_data)


@app.route('/api/admin/users/<string:user_id>/ban', methods=['POST'])
@login_required
@admin_required
def admin_ban_user(user_id):
    # Validate user_id format
    if not validate_discord_id(user_id):
        return jsonify({'error': 'Invalid user ID format'}), 400
    
    user_to_update = db.session.get(User, user_id)
    if not user_to_update: return jsonify({'error': 'User not found'}), 404
    if user_to_update.id == current_user.id:
        return jsonify({'error': 'Cannot ban yourself'}), 403
    
    data = request.json
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Validate and sanitize reason
    reason = sanitize_text_input(data.get('reason', 'No reason provided.'), max_length=500)
    if not reason or len(reason.strip()) < 3:
        return jsonify({'error': 'Ban reason must be at least 3 characters'}), 400
    
    # Validate duration
    duration_days = data.get('duration')
    if not validate_duration(duration_days):
        return jsonify({'error': 'Invalid duration. Must be 0-365 days'}), 400
    
    duration_days = int(duration_days)

    user_to_update.is_banned = True
    user_to_update.ban_reason = reason
    user_to_update.responsible_admin_id = current_user.id
    
    if duration_days > 0:
        user_to_update.ban_expires_at = datetime.now(timezone.utc) + timedelta(days=duration_days)
    else: # Permanent ban
        user_to_update.ban_expires_at = None
        
    db.session.commit()
    
    # --- BAN LOG ---
    threading.Thread(target=send_ban_notification, args=(
        user_to_update.id,
        user_to_update.username,
        current_user.id,
        current_user.username,
        reason,
        duration_days
    )).start()

    return jsonify(to_dict(user_to_update))

@app.route('/api/admin/users/<string:user_id>/unban', methods=['POST'])
@login_required
@admin_required
def admin_unban_user(user_id):
    user_to_update = db.session.get(User, user_id)
    if not user_to_update: return jsonify({'error': 'User not found'}), 404
    
    user_to_update.is_banned = False
    user_to_update.ban_reason = None
    user_to_update.ban_expires_at = None
    user_to_update.responsible_admin_id = None
    
    db.session.commit()
    
    # --- UNBAN LOG ---
    threading.Thread(target=send_unban_notification, args=(
        user_to_update.id,
        user_to_update.username,
        current_user.id,
        current_user.username
    )).start()
    
    return jsonify(to_dict(user_to_update))

@app.route('/api/admin/users/<string:user_id>', methods=['PUT'])
@login_required
@admin_required
def admin_update_user(user_id):
    user_to_update = db.session.get(User, user_id)
    if not user_to_update: return jsonify({'error': 'User not found'}), 404
    data = request.json
    new_role = data.get('role')
    if new_role not in ['admin', 'user']: return jsonify({'error': 'Invalid role'}), 400
    if current_user.id == user_to_update.id and user_to_update.role == 'admin' and new_role == 'user':
        return jsonify({'error': 'Cannot remove your own admin status.'}), 403
    user_to_update.role = new_role
    db.session.commit()
    return jsonify(to_dict(user_to_update))

@app.route('/api/admin/users/<string:user_id>/grant-license', methods=['POST'])
@login_required
@admin_required
def admin_grant_license(user_id):
    # Validate user_id format
    if not validate_discord_id(user_id):
        return jsonify({'error': 'Invalid user ID format'}), 400
    
    user_to_update = db.session.get(User, user_id)
    if not user_to_update:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.json
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    duration_days = data.get('duration')
    
    if duration_days is None:
        return jsonify({'error': 'Duration is required'}), 400
    
    # Validate duration
    if not validate_duration(duration_days):
        return jsonify({'error': 'Invalid duration. Must be 0-365 days'}), 400
    
    duration_days = int(duration_days)

    user_to_update.has_license = True
    
    plan_map = { 30: "1 Month Plan", 180: "6 Month Plan", 365: "1 Year Plan", 0: "Lifetime Plan" }
    duration_text = plan_map.get(duration_days, f"{duration_days} Day(s)")

    if duration_days > 0:
        expiration_date = datetime.now(timezone.utc) + timedelta(days=duration_days)
        user_to_update.license_expires_at = expiration_date
    else: # Permanent/Lifetime license
        user_to_update.license_expires_at = None

    db.session.commit()
    
    # --- LICENSE LOG ---
    threading.Thread(target=send_license_grant_notification, args=(
        current_user.id,
        current_user.username,
        user_to_update.id,
        user_to_update.username,
        duration_text,
        None # No enterprise name for personal license
    )).start()

    # --- DISCORD ROLE UPDATE ---
    if bot.is_ready() and bot.loop.is_running():
        # Using call_soon_threadsafe to schedule the coroutine from a synchronous thread
        bot.loop.call_soon_threadsafe(asyncio.create_task, update_user_roles(user_to_update.id, 'personal'))

    return jsonify(to_dict(user_to_update))

@app.route('/api/admin/users/<string:user_id>', methods=['DELETE'])
@login_required
@admin_required
def admin_delete_user(user_id):
    if user_id == current_user.id: return jsonify({'error': 'Cannot delete yourself'}), 403
    user_to_delete = db.session.get(User, user_id)
    if not user_to_delete: return ('', 204)
    db.session.delete(user_to_delete)
    db.session.commit()
    return '', 204

# --- 7b. Hardware Fingerprint Ban Management (Admin Only) ---

@app.route('/api/admin/hardware-fingerprints', methods=['GET'])
@login_required
@admin_required
def get_hardware_fingerprints():
    """Get all hardware fingerprints with pagination"""
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    fingerprints = HardwareFingerprint.query.order_by(
        HardwareFingerprint.last_seen.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'fingerprints': [to_dict(fp) for fp in fingerprints.items],
        'total': fingerprints.total,
        'pages': fingerprints.pages,
        'current_page': page
    })

@app.route('/api/admin/hardware-fingerprints/<string:fingerprint_id>/ban', methods=['POST'])
@login_required
@admin_required
def ban_hardware_fingerprint(fingerprint_id):
    """Ban a hardware fingerprint"""
    hw_record = HardwareFingerprint.query.filter_by(fingerprint_id=fingerprint_id).first()
    
    if not hw_record:
        return jsonify({'error': 'Hardware fingerprint not found'}), 404
    
    data = request.json
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    reason = sanitize_text_input(data.get('reason', 'Violation of Terms of Service'), max_length=500)
    
    hw_record.is_banned = True
    hw_record.ban_reason = reason
    hw_record.banned_at = datetime.now(timezone.utc)
    hw_record.banned_by_admin_id = current_user.id
    
    db.session.commit()
    
    # Log the ban
    send_security_alert(
        "Hardware Fingerprint Banned",
        f"Admin {current_user.username} banned a hardware fingerprint",
        15158332,  # Red
        fields=[
            {"name": "Fingerprint ID", "value": f"`{fingerprint_id[:16]}...`", "inline": True},
            {"name": "Reason", "value": f"`{reason}`", "inline": False},
            {"name": "Admin", "value": f"`{current_user.username}` (`{current_user.id}`)", "inline": True}
        ]
    )
    
    return jsonify(to_dict(hw_record))

@app.route('/api/admin/hardware-fingerprints/<string:fingerprint_id>/unban', methods=['POST'])
@login_required
@admin_required
def unban_hardware_fingerprint(fingerprint_id):
    """Unban a hardware fingerprint"""
    hw_record = HardwareFingerprint.query.filter_by(fingerprint_id=fingerprint_id).first()
    
    if not hw_record:
        return jsonify({'error': 'Hardware fingerprint not found'}), 404
    
    hw_record.is_banned = False
    hw_record.ban_reason = None
    hw_record.banned_at = None
    hw_record.banned_by_admin_id = None
    
    db.session.commit()
    
    # Log the unban
    send_security_improvement_log(
        "Hardware Fingerprint Unbanned",
        f"Admin {current_user.username} unbanned a hardware fingerprint",
        3066993,  # Green
        fields=[
            {"name": "Fingerprint ID", "value": f"`{fingerprint_id[:16]}...`", "inline": True},
            {"name": "Admin", "value": f"`{current_user.username}` (`{current_user.id}`)", "inline": True}
        ]
    )
    
    return jsonify(to_dict(hw_record))

# --- 8a. Admin Messaging API Routes (Super Admins Only) ---

@app.route('/api/admin/messaging/send-dm', methods=['POST'])
@login_required
@super_admin_required
def admin_send_dm():
    """Send a DM to a specific user via Discord bot"""
    data = request.json
    user_id = data.get('user_id')
    message = data.get('message')
    
    if not user_id or not message:
        return jsonify({'error': 'user_id and message are required'}), 400
    
    if len(message) > 2000:
        return jsonify({'error': 'Message too long (max 2000 characters)'}), 400
    
    # Send DM via Discord bot
    async def send_dm_async():
        try:
            user = await bot.fetch_user(int(user_id))
            if user:
                await user.send(message)
                return True
            return False
        except Exception as e:
            print(f"Error sending DM to {user_id}: {e}")
            return False
    
    # Run async function in bot's event loop
    try:
        future = asyncio.run_coroutine_threadsafe(send_dm_async(), bot.loop)
        success = future.result(timeout=10)
        
        if success:
            return jsonify({'success': True, 'message': 'DM sent successfully'})
        else:
            return jsonify({'error': 'Failed to send DM. User may have DMs disabled or bot cannot reach them.'}), 400
    except Exception as e:
        return sanitized_error_response(e, "Failed to send direct message", 500)

@app.route('/api/admin/messaging/send-announcement', methods=['POST'])
@login_required
@super_admin_required
def admin_send_announcement():
    """Send an announcement to all users or specific users via Discord bot"""
    data = request.json
    message = data.get('message')
    target_type = data.get('target_type', 'all')  # 'all' or 'specific'
    user_ids = data.get('user_ids', [])  # List of user IDs for specific targeting
    
    if not message:
        return jsonify({'error': 'message is required'}), 400
    
    if len(message) > 2000:
        return jsonify({'error': 'Message too long (max 2000 characters)'}), 400
    
    # Get target users
    if target_type == 'specific' and user_ids:
        target_users = User.query.filter(User.id.in_(user_ids)).all()
    else:
        # Send to all users
        target_users = User.query.all()
    
    if not target_users:
        return jsonify({'error': 'No users found'}), 404
    
    # Send DMs asynchronously
    async def send_bulk_dms():
        success_count = 0
        fail_count = 0
        
        for user in target_users:
            try:
                discord_user = await bot.fetch_user(int(user.id))
                if discord_user:
                    await discord_user.send(message)
                    success_count += 1
                    await asyncio.sleep(1)  # Rate limiting: 1 second between messages
            except Exception as e:
                print(f"Failed to send DM to {user.id} ({user.username}): {e}")
                fail_count += 1
        
        return success_count, fail_count
    
    # Run async function in bot's event loop
    try:
        future = asyncio.run_coroutine_threadsafe(send_bulk_dms(), bot.loop)
        success_count, fail_count = future.result(timeout=len(target_users) * 2 + 30)
        
        return jsonify({
            'success': True,
            'message': f'Announcement sent to {success_count} users. {fail_count} failed.',
            'success_count': success_count,
            'fail_count': fail_count
        })
    except Exception as e:
        return sanitized_error_response(e, "Failed to send announcement", 500)

# --- 8b. Discord Management API Routes (Super Admins Only) ---

@app.route('/api/admin/discord/status', methods=['GET'])
@login_required
@super_admin_required
def get_discord_status():
    """Check Discord bot status"""
    return jsonify({
        'is_ready': bot.is_ready(),
        'has_loop': hasattr(bot, 'loop') and bot.loop is not None,
        'guild_count': len(bot.guilds) if bot.is_ready() else 0,
        'user': str(bot.user) if bot.user else None
    })

@app.route('/api/admin/discord/guilds', methods=['GET'])
@login_required
@super_admin_required
def get_discord_guilds():
    """Get all Discord guilds the bot is in"""
    print(f"[Discord API] Guilds request - Bot ready: {bot.is_ready()}, Has loop: {hasattr(bot, 'loop')}")
    
    # Check if bot is ready
    if not bot.is_ready():
        return jsonify({'error': 'Discord bot is not ready yet. Please wait a moment and try again.'}), 503
    
    if not hasattr(bot, 'loop') or bot.loop is None:
        return jsonify({'error': 'Discord bot loop is not available'}), 503
    
    async def fetch_guilds():
        guilds = []
        for guild in bot.guilds:
            guilds.append({
                'id': str(guild.id),
                'name': guild.name,
                'icon': str(guild.icon.url) if guild.icon else None,
                'member_count': guild.member_count,
                'owner_id': str(guild.owner_id)
            })
        return guilds
    
    try:
        future = asyncio.run_coroutine_threadsafe(fetch_guilds(), bot.loop)
        guilds = future.result(timeout=10)
        return jsonify({'guilds': guilds})
    except Exception as e:
        return sanitized_error_response(e, "Failed to fetch Discord guilds", 500)

@app.route('/api/admin/discord/channels/<string:guild_id>', methods=['GET'])
@login_required
@super_admin_required
def get_discord_channels(guild_id):
    """Get all channels in a guild"""
    async def fetch_channels():
        guild = bot.get_guild(int(guild_id))
        if not guild:
            return None
        
        channels = []
        for channel in guild.channels:
            channel_data = {
                'id': str(channel.id),
                'name': channel.name,
                'type': str(channel.type),
                'position': channel.position
            }
            
            if hasattr(channel, 'category'):
                channel_data['category'] = channel.category.name if channel.category else None
            
            channels.append(channel_data)
        
        return channels
    
    try:
        future = asyncio.run_coroutine_threadsafe(fetch_channels(), bot.loop)
        channels = future.result(timeout=10)
        
        if channels is None:
            return jsonify({'error': 'Guild not found'}), 404
        
        return jsonify({'channels': channels})
    except Exception as e:
        return sanitized_error_response(e, "Failed to fetch channels", 500)

@app.route('/api/admin/discord/messages/<string:channel_id>', methods=['GET'])
@login_required
@super_admin_required
def get_discord_messages(channel_id):
    """Get recent messages from a channel"""
    limit = request.args.get('limit', 50, type=int)
    
    async def fetch_messages():
        channel = bot.get_channel(int(channel_id))
        if not channel:
            return None
        
        messages = []
        async for message in channel.history(limit=min(limit, 100)):
            messages.append({
                'id': str(message.id),
                'content': message.content,
                'author': {
                    'id': str(message.author.id),
                    'name': message.author.name,
                    'discriminator': message.author.discriminator,
                    'avatar': str(message.author.avatar.url) if message.author.avatar else None,
                    'bot': message.author.bot
                },
                'timestamp': message.created_at.isoformat(),
                'edited_timestamp': message.edited_at.isoformat() if message.edited_at else None,
                'attachments': [{'url': a.url, 'filename': a.filename} for a in message.attachments],
                'embeds': len(message.embeds)
            })
        
        return messages
    
    try:
        future = asyncio.run_coroutine_threadsafe(fetch_messages(), bot.loop)
        messages = future.result(timeout=10)
        
        if messages is None:
            return jsonify({'error': 'Channel not found'}), 404
        
        return jsonify({'messages': messages})
    except Exception as e:
        return sanitized_error_response(e, "Failed to fetch messages", 500)

@app.route('/api/admin/discord/send-message', methods=['POST'])
@login_required
@super_admin_required
def send_discord_message():
    """Send a message to a Discord channel"""
    data = request.json
    channel_id = data.get('channel_id')
    content = data.get('content')
    
    if not channel_id or not content:
        return jsonify({'error': 'channel_id and content are required'}), 400
    
    async def send_message():
        channel = bot.get_channel(int(channel_id))
        if not channel:
            return None
        
        message = await channel.send(content)
        return {
            'id': str(message.id),
            'content': message.content,
            'timestamp': message.created_at.isoformat()
        }
    
    try:
        future = asyncio.run_coroutine_threadsafe(send_message(), bot.loop)
        result = future.result(timeout=10)
        
        if result is None:
            return jsonify({'error': 'Channel not found'}), 404
        
        return jsonify({'success': True, 'message': result})
    except Exception as e:
        return sanitized_error_response(e, "Failed to send message", 500)

@app.route('/api/admin/discord/members/<string:guild_id>', methods=['GET'])
@login_required
@super_admin_required
def get_discord_guild_members(guild_id):
    """Get all members in a guild"""
    async def fetch_members():
        guild = bot.get_guild(int(guild_id))
        if not guild:
            return None
        
        members = []
        for member in guild.members:
            members.append({
                'id': str(member.id),
                'name': member.name,
                'discriminator': member.discriminator,
                'nick': member.nick,
                'avatar': str(member.avatar.url) if member.avatar else None,
                'bot': member.bot,
                'joined_at': member.joined_at.isoformat() if member.joined_at else None,
                'roles': [{'id': str(r.id), 'name': r.name, 'color': str(r.color)} for r in member.roles if r.name != '@everyone'],
                'status': str(member.status)
            })
        
        return members
    
    try:
        future = asyncio.run_coroutine_threadsafe(fetch_members(), bot.loop)
        members = future.result(timeout=15)
        
        if members is None:
            return jsonify({'error': 'Guild not found'}), 404
        
        return jsonify({'members': members})
    except Exception as e:
        return sanitized_error_response(e, "Failed to fetch members", 500)

@app.route('/api/admin/discord/kick/<string:guild_id>/<string:member_id>', methods=['POST'])
@login_required
@super_admin_required
def kick_discord_member(guild_id, member_id):
    """Kick a member from the guild"""
    data = request.json
    reason = data.get('reason', 'No reason provided')
    
    async def kick_member():
        guild = bot.get_guild(int(guild_id))
        if not guild:
            return None
        
        member = guild.get_member(int(member_id))
        if not member:
            return False
        
        await member.kick(reason=reason)
        return True
    
    try:
        future = asyncio.run_coroutine_threadsafe(kick_member(), bot.loop)
        result = future.result(timeout=10)
        
        if result is None:
            return jsonify({'error': 'Guild not found'}), 404
        if not result:
            return jsonify({'error': 'Member not found'}), 404
        
        return jsonify({'success': True, 'message': 'Member kicked successfully'})
    except Exception as e:
        return sanitized_error_response(e, "Failed to kick member", 500)

@app.route('/api/admin/discord/ban/<string:guild_id>/<string:member_id>', methods=['POST'])
@login_required
@super_admin_required
def ban_discord_member(guild_id, member_id):
    """Ban a member from the guild"""
    data = request.json
    reason = data.get('reason', 'No reason provided')
    delete_message_days = data.get('delete_message_days', 0)
    
    async def ban_member():
        guild = bot.get_guild(int(guild_id))
        if not guild:
            return None
        
        member = guild.get_member(int(member_id))
        if member:
            await member.ban(reason=reason, delete_message_days=delete_message_days)
        else:
            # Ban by ID if member not in guild
            await guild.ban(discord.Object(id=int(member_id)), reason=reason, delete_message_days=delete_message_days)
        
        return True
    
    try:
        future = asyncio.run_coroutine_threadsafe(ban_member(), bot.loop)
        result = future.result(timeout=10)
        
        if result is None:
            return jsonify({'error': 'Guild not found'}), 404
        
        return jsonify({'success': True, 'message': 'Member banned successfully'})
    except Exception as e:
        return sanitized_error_response(e, "Failed to ban member", 500)

# --- 8c. Enterprise API Routes ---

@app.route('/api/enterprise/details', methods=['GET'])
@login_required
@enterprise_admin_required
def get_enterprise_details():
    # Re-fetch the user from the current session to ensure relationships can be loaded.
    user = db.session.get(User, current_user.id)
    enterprise = user.enterprise
    if not enterprise:
        return jsonify({'error': 'User not associated with an enterprise'}), 404
    members = enterprise.members.all()
    members_data = [{
        'id': member.id,
        'username': member.username,
        'avatar': member.avatar
    } for member in members]
    
    return jsonify({
        'name': enterprise.name,
        'license_expires_at': enterprise.license_expires_at.isoformat() if enterprise.license_expires_at else None,
        'members': members_data,
        'has_custom_loader': enterprise.has_custom_loader,
        'warnings': enterprise.warnings
    })

@app.route('/api/enterprise/add_member', methods=['POST'])
@login_required
@enterprise_admin_required
def add_enterprise_member():
    data = request.json
    discord_id = data.get('discord_id')
    if not discord_id or not discord_id.isdigit():
        return jsonify({'error': 'Valid Discord User ID is required.'}), 400
    
    user = db.session.get(User, current_user.id)
    enterprise = user.enterprise
    
    member = db.session.get(User, discord_id)
    if not member:
        # Create a placeholder user that will be updated when they log in
        member = User(id=discord_id, username=f"Invited User ({discord_id})")
        db.session.add(member)

    if member.enterprise_id:
        return jsonify({'error': 'User is already in an enterprise.'}), 409

    member.enterprise_id = enterprise.id
    member.has_license = True
    member.license_expires_at = enterprise.license_expires_at
    db.session.commit()
    
    # --- LICENSE LOG ---
    duration_text = "Until Enterprise Expiration"
    if enterprise.license_expires_at:
        try:
            diff_days = (enterprise.license_expires_at.replace(tzinfo=None) - datetime.now(timezone.utc)).days
            duration_text = f"Expires in {diff_days} days"
        except Exception:
            pass # Keep default text if date math fails
    
    threading.Thread(target=send_license_grant_notification, args=(
        current_user.id, current_user.username, member.id, member.username,
        duration_text, enterprise.name
    )).start()
    
    # --- ROLE UPDATE ---
    if bot.is_ready() and bot.loop.is_running():
        bot.loop.call_soon_threadsafe(asyncio.create_task, update_user_roles(member.id, 'enterprise'))

    return jsonify({'message': 'Member added successfully.'}), 201

@app.route('/api/enterprise/remove_member', methods=['POST'])
@login_required
@enterprise_admin_required
def remove_enterprise_member():
    data = request.json
    user_id = data.get('user_id')
    if not user_id: return jsonify({'error': 'User ID is required.'}), 400

    user = db.session.get(User, current_user.id)
    enterprise = user.enterprise
    if user_id == enterprise.admin_user_id:
        return jsonify({'error': 'Cannot remove the enterprise admin.'}), 403

    member = db.session.get(User, user_id)
    if not member or member.enterprise_id != enterprise.id:
        return jsonify({'error': 'User is not a member of this enterprise.'}), 404

    member.enterprise_id = None
    member.has_license = False
    member.license_expires_at = None
    db.session.commit()
    
    # --- LICENSE LOG ---
    threading.Thread(target=send_license_revoke_notification, args=(
        current_user.id, current_user.username, member.id, member.username,
        enterprise.name
    )).start()

    # --- ROLE UPDATE ---
    if bot.is_ready() and bot.loop.is_running():
        bot.loop.call_soon_threadsafe(asyncio.create_task, update_user_roles(member.id, 'none'))
    
    return jsonify({'message': 'Member removed successfully.'}), 200

# --- 8b. Server Admin API Routes ---
MODEL_WHITELIST = {
    'User': User,
    'Scan': Scan,
    'Enterprise': Enterprise,
    'Finding': Finding,
    'SystemInfo': SystemInfo,
    'UserIdentity': UserIdentity,
    'BrowserHistory': BrowserHistory,
    'CommandHistory': CommandHistory,
    'GameAnalysis': GameAnalysis,
    'Artifact': Artifact,
    'RecentExecutable': RecentExecutable,
    'HardwareInfo': HardwareInfo,
    'SystemService': SystemService
}

@app.route('/api/admin/system-stats', methods=['GET'])
@login_required
@admin_required
def get_system_stats():
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        ram = psutil.virtual_memory()
        
        # Network Speed Calculation
        upload_speed = 0
        download_speed = 0
        current_net = psutil.net_io_counters()
        current_time = time.time()

        if app.last_net_stats:
            last_net = app.last_net_stats['counters']
            last_time = app.last_net_stats['timestamp']
            time_delta = current_time - last_time

            if time_delta > 0:
                upload_speed = (current_net.bytes_sent - last_net.bytes_sent) / time_delta
                download_speed = (current_net.bytes_recv - last_net.bytes_recv) / time_delta
        
        app.last_net_stats = {'counters': current_net, 'timestamp': current_time}
        
        cpu_model = "Unknown"
        try:
            cpu_model = platform.processor()
        except Exception:
            try:
                cpu_result = subprocess.run(['wmic', 'cpu', 'get', 'name'], capture_output=True, text=True, check=False, creationflags=0x08000000)
                cpu_model = cpu_result.stdout.strip().split('\n')[-1].strip()
            except Exception:
                pass

        return jsonify({
            'cpu_percent': cpu_percent,
            'ram_percent': ram.percent,
            'upload_speed': upload_speed,
            'download_speed': download_speed,
            'spec_cpu': cpu_model,
            'spec_cores': f"{psutil.cpu_count(logical=False)} / {psutil.cpu_count(logical=True)}",
            'spec_os': platform.system() + " " + platform.release(),
            'spec_ram': f"{round(ram.total / (1024**3), 1)} GB DDR4",
        })
    except Exception as e:
        return sanitized_error_response(e, "Failed to fetch system statistics", 500)

@app.route('/api/admin/logs', methods=['GET'])
@login_required
@admin_required
def get_api_logs():
    return jsonify(list(api_logs))

@app.route('/api/admin/database-stats', methods=['GET'])
@login_required
@admin_required
def get_database_stats():
    """Get comprehensive database statistics"""
    try:
        # User statistics
        total_users = User.query.count()
        licensed_users = User.query.filter_by(has_license=True).count()
        banned_users = User.query.filter_by(is_banned=True).count()
        admin_users = User.query.filter_by(role='admin').count()
        
        # Scan statistics
        total_scans = Scan.query.count()
        public_scans = Scan.query.filter_by(is_public=True).count()
        
        # Scans by game
        fivem_scans = Scan.query.filter_by(game='fivem').count()
        rdr2_scans = Scan.query.filter_by(game='rdr2').count()
        
        # Recent scans (last 24 hours)
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        recent_scans = Scan.query.filter(Scan.timestamp >= yesterday).count()
        
        # Finding statistics
        total_findings = Finding.query.count()
        critical_findings = Finding.query.filter_by(severity='Critical').count()
        high_findings = Finding.query.filter_by(severity='High').count()
        
        # Enterprise statistics
        total_enterprises = Enterprise.query.count()
        
        # Most active users (top 5)
        from sqlalchemy import func
        top_users = db.session.query(
            User.username,
            func.count(Scan.id).label('scan_count')
        ).join(Scan).group_by(User.id).order_by(func.count(Scan.id).desc()).limit(5).all()
        
        # Most detected cheats (top 10)
        top_cheats = db.session.query(
            Finding.name,
            func.count(Finding.id).label('count')
        ).group_by(Finding.name).order_by(func.count(Finding.id).desc()).limit(10).all()
        
        return jsonify({
            'users': {
                'total': total_users,
                'licensed': licensed_users,
                'banned': banned_users,
                'admins': admin_users,
                'active': total_users - banned_users
            },
            'scans': {
                'total': total_scans,
                'public': public_scans,
                'recent_24h': recent_scans,
                'fivem': fivem_scans,
                'rdr2': rdr2_scans
            },
            'findings': {
                'total': total_findings,
                'critical': critical_findings,
                'high': high_findings
            },
            'enterprises': {
                'total': total_enterprises
            },
            'top_users': [{'username': u[0], 'scans': u[1]} for u in top_users],
            'top_cheats': [{'name': c[0], 'count': c[1]} for c in top_cheats]
        })
    except Exception as e:
        return sanitized_error_response(e, "Failed to fetch scan statistics", 500)

@app.route('/api/admin/ddos-logs', methods=['GET'])
@internal_or_admin_required
def get_ddos_logs():
    return jsonify(list(ddos_logs))

@app.route('/api/admin/ai-guardian/status', methods=['GET'])
@internal_or_admin_required
def get_ai_guardian_status():
    global AI_GUARDIAN_ENABLED, AI_GUARDIAN_RPS_THRESHOLD, AI_GUARDIAN_IP_RPS_LIMIT, AI_GUARDIAN_BLOCK_DURATION
    with AI_GUARDIAN_STATE["lock"]:
        now = time.time()
        # Clean up expired blocks before reporting
        AI_GUARDIAN_STATE["blocked_ips"] = {ip: t for ip, t in AI_GUARDIAN_STATE["blocked_ips"].items() if now < t}
        current_global_rps = len([t for t in AI_GUARDIAN_STATE["global_requests"] if t > now - 1])

        return jsonify({
            "enabled": AI_GUARDIAN_ENABLED,
            "mitigation_mode": AI_GUARDIAN_STATE["mitigation_mode_active"],
            "manual_mode": AI_GUARDIAN_STATE["manual_mode"],
            "blocked_ips_count": len(AI_GUARDIAN_STATE["blocked_ips"]),
            "global_rps": current_global_rps,
            "config": {
                "rps_threshold": AI_GUARDIAN_RPS_THRESHOLD,
                "ip_rps_limit": AI_GUARDIAN_IP_RPS_LIMIT,
                "block_duration": AI_GUARDIAN_BLOCK_DURATION,
            }
        })

@app.route('/api/admin/ai-guardian/config', methods=['POST'])
@internal_or_admin_required
def set_ai_guardian_config():
    global AI_GUARDIAN_ENABLED, AI_GUARDIAN_RPS_THRESHOLD, AI_GUARDIAN_IP_RPS_LIMIT
    data = request.json
    with AI_GUARDIAN_STATE["lock"]:
        if 'enabled' in data:
            AI_GUARDIAN_ENABLED = bool(data['enabled'])
        if 'manual_mode' in data and data['manual_mode'] in ['auto', 'on', 'off']:
            AI_GUARDIAN_STATE['manual_mode'] = data['manual_mode']
        if 'rps_threshold' in data:
            AI_GUARDIAN_RPS_THRESHOLD = int(data['rps_threshold'])
        if 'ip_rps_limit' in data:
            AI_GUARDIAN_IP_RPS_LIMIT = int(data['ip_rps_limit'])
    return jsonify({"status": "success", "message": "AI Guardian configuration updated."})

@app.route('/api/admin/ai-guardian/blocked-ips', methods=['GET'])
@internal_or_admin_required
def get_blocked_ips():
    with AI_GUARDIAN_STATE["lock"]:
        now = time.time()
        active_blocks = {ip: round(expiry - now) for ip, expiry in AI_GUARDIAN_STATE["blocked_ips"].items() if expiry > now}
        return jsonify(active_blocks)

@app.route('/api/admin/ai-guardian/clear-blocked-ips', methods=['POST'])
@internal_or_admin_required
def clear_blocked_ips():
    with AI_GUARDIAN_STATE["lock"]:
        cleared_count = len(AI_GUARDIAN_STATE["blocked_ips"])
        AI_GUARDIAN_STATE["blocked_ips"].clear()
    log_entry = {'time': datetime.now(timezone.utc).isoformat(), 'type': 'IP_UNBLOCKED', 'ip': 'ALL', 'message': f"All {cleared_count} blocked IPs were manually cleared by an admin."}
    ddos_logs.appendleft(log_entry)
    return jsonify({"status": "success", "message": f"Cleared {cleared_count} blocked IPs."})


@app.route('/api/admin/db/tables', methods=['GET'])
@login_required
@admin_required
def list_db_tables():
    return jsonify(list(MODEL_WHITELIST.keys()))

@app.route('/api/admin/db/table/<string:table_name>', methods=['GET'])
@login_required
@admin_required
def get_table_data(table_name):
    if table_name not in MODEL_WHITELIST:
        return jsonify({'error': 'Table not found or not accessible'}), 404
    
    Model = MODEL_WHITELIST[table_name]
    page = request.args.get('page', 1, type=int)
    per_page = 15
    
    pagination = Model.query.paginate(page=page, per_page=per_page, error_out=False)
    
    items = [to_dict(item) for item in pagination.items]
    
    mapper = sqlalchemy_inspect(Model)
    columns = [c.key for c in mapper.attrs]

    return jsonify({
        'items': items,
        'columns': columns,
        'total': pagination.total,
        'page': pagination.page,
        'pages': pagination.pages,
        'has_prev': pagination.has_prev,
        'has_next': pagination.has_next
    })
    
@app.route('/api/admin/db/table/<string:table_name>/<string:row_id>', methods=['PUT'])
@login_required
@admin_required
def update_table_row(table_name, row_id):
    if table_name not in MODEL_WHITELIST:
        return jsonify({'error': 'Table not found or not accessible'}), 404
    
    Model = MODEL_WHITELIST[table_name]
    mapper = sqlalchemy_inspect(Model)
    pk_type = mapper.primary_key[0].type.python_type
    try:
        typed_row_id = pk_type(row_id)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid row ID format'}), 400

    row = db.session.get(Model, typed_row_id)
    if not row:
        return jsonify({'error': 'Row not found'}), 404
        
    data = request.json
    for key, value in data.items():
        if hasattr(row, key):
            try:
                column_attr = getattr(Model, key)
                column_type = column_attr.property.columns[0].type.python_type

                if value is None or value == '':
                    setattr(row, key, None)
                    continue
                
                if column_type == bool:
                    value = str(value).lower() in ['true', '1', 'yes', 'on']
                elif column_type == datetime:
                    try:
                        value = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
                    except (ValueError, TypeError):
                         return jsonify({'error': f"Invalid date format for column '{key}'"}), 400
                else:
                    value = column_type(value)

                setattr(row, key, value)
            except Exception:
                return jsonify({'error': f"Invalid value or type for column '{key}'"}), 400
    
    db.session.commit()
    return jsonify({'message': 'Row updated successfully'})

@app.route('/api/admin/db/table/<string:table_name>/<string:row_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_table_row(table_name, row_id):
    if table_name not in MODEL_WHITELIST:
        return jsonify({'error': 'Table not found or not accessible'}), 404
    
    Model = MODEL_WHITELIST[table_name]
    mapper = sqlalchemy_inspect(Model)
    pk_type = mapper.primary_key[0].type.python_type
    try:
        typed_row_id = pk_type(row_id)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid row ID format'}), 400

    row = db.session.get(Model, typed_row_id)
    if not row:
        return jsonify({'error': 'Row not found'}), 404

    db.session.delete(row)
    db.session.commit()
    return jsonify({'message': 'Row deleted successfully'})

# --- 8b. Custom Rules API Routes ---

@app.route('/api/custom-rules', methods=['GET'])
@login_required
def get_custom_rules():
    """Get all custom rules for the current user"""
    rules = CustomRule.query.filter_by(user_id=current_user.id, is_active=True).all()
    return jsonify([{
        'id': r.id,
        'rule_type': r.rule_type,
        'name': r.name,
        'content': r.content,
        'severity': r.severity,
        'category': r.category,
        'description': r.description,
        'created_at': r.created_at.isoformat()
    } for r in rules])

@app.route('/api/custom-rules', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def create_custom_rule():
    """Create a new custom rule"""
    data = request.get_json()
    
    rule_type = data.get('rule_type')
    name = data.get('name')
    content = data.get('content')
    severity = data.get('severity')
    category = data.get('category')
    description = data.get('description')
    
    if not all([rule_type, name, content, severity]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if rule_type not in ['yara', 'keyword', 'hash']:
        return jsonify({'error': 'Invalid rule type'}), 400
    
    if severity not in ['Low', 'Medium', 'High', 'Critical']:
        return jsonify({'error': 'Invalid severity'}), 400
    
    # Check for duplicate names
    existing = CustomRule.query.filter_by(user_id=current_user.id, name=name, is_active=True).first()
    if existing:
        return jsonify({'error': 'A rule with this name already exists'}), 400
    
    new_rule = CustomRule(
        user_id=current_user.id,
        rule_type=rule_type,
        name=name,
        content=content,
        severity=severity,
        category=category,
        description=description
    )
    
    db.session.add(new_rule)
    db.session.commit()
    
    # Send to Discord webhook for admin review
    send_custom_rule_to_discord(
        user=current_user,
        rule_type=rule_type,
        name=name,
        content=content,
        severity=severity,
        category=category
    )
    
    return jsonify({
        'id': new_rule.id,
        'message': 'Custom rule created successfully'
    }), 201

@app.route('/api/custom-rules/<int:rule_id>', methods=['DELETE'])
@login_required
def delete_custom_rule(rule_id):
    """Delete a custom rule"""
    rule = CustomRule.query.filter_by(id=rule_id, user_id=current_user.id).first()
    
    if not rule:
        return jsonify({'error': 'Rule not found'}), 404
    
    rule.is_active = False
    db.session.commit()
    
    return jsonify({'message': 'Rule deleted successfully'}), 200

def send_custom_rule_to_discord(user, rule_type, name, content, severity, category=None):
    """Send custom rule creation to Discord webhook for admin review"""
    import requests
    from datetime import datetime
    
    webhook_url = "https://discord.com/api/webhooks/1440439303271612558/k-irNYfozFHMmRSuM52oKnufz4KRh99zRIBbiWVtUFS7sdeQfqXkit26z6ToTAuVvd45"
    
    try:
        user_info = f"{user.username} (Discord ID: {user.discord_user_id})" if hasattr(user, 'discord_user_id') and user.discord_user_id else user.username
        fingerprint_id = user.browser_fingerprint if hasattr(user, 'browser_fingerprint') and user.browser_fingerprint else None
        
        # Emoji based on rule type
        emoji_map = {
            'yara': '📜',
            'keyword': '🔑',
            'hash': '#️⃣'
        }
        
        # Color based on severity
        color_map = {
            'Critical': 0xEF4444,
            'High': 0xF97316,
            'Medium': 0xF59E0B,
            'Low': 0x6B7280
        }
        
        # Truncate content if too long
        display_content = content[:500] + "..." if len(content) > 500 else content
        
        fields = [
            {
                "name": "👤 User",
                "value": user_info,
                "inline": True
            },
            {
                "name": "⚠️ Severity",
                "value": severity,
                "inline": True
            },
            {
                "name": "📋 Rule Type",
                "value": rule_type.upper(),
                "inline": True
            }
        ]
        
        if category:
            fields.append({
                "name": "📁 Category",
                "value": category,
                "inline": True
            })
        
        # Add fingerprint ID if available
        if fingerprint_id:
            fields.append({
                "name": "🔍 Fingerprint ID",
                "value": f"`{fingerprint_id}`",
                "inline": False
            })
        
        fields.append({
            "name": "📝 Content",
            "value": f"```\n{display_content}\n```",
            "inline": False
        })
        
        embed = {
            "title": f"{emoji_map.get(rule_type, '📌')} New Custom Rule: {name}",
            "color": color_map.get(severity, 0x5865F2),
            "fields": fields,
            "footer": {
                "text": f"User ID: {user.id} • {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        payload = {
            "embeds": [embed],
            "username": "</async> Scanner",
        }
        
        response = requests.post(webhook_url, json=payload, timeout=10)
        
        if response.status_code == 204:
            app.logger.info(f"Successfully sent custom rule to Discord webhook for user {user.id}")
        else:
            app.logger.warning(f"Discord webhook returned status {response.status_code}")
            
    except Exception as e:
        app.logger.error(f"Failed to send custom rule to Discord webhook: {str(e)}")

def send_strings_to_discord_webhook(user, filename, strings, severity, added_count, sha256=None, md5=None, yara_generated=False):
    """Send extracted data to Discord webhook for admin review"""
    import requests
    from datetime import datetime
    
    webhook_url = "https://discord.com/api/webhooks/1440439303271612558/k-irNYfozFHMmRSuM52oKnufz4KRh99zRIBbiWVtUFS7sdeQfqXkit26z6ToTAuVvd45"
    
    try:
        # Get user info
        user_info = f"{user.username} (Discord ID: {user.discord_user_id})" if hasattr(user, 'discord_user_id') and user.discord_user_id else user.username
        fingerprint_id = user.browser_fingerprint if hasattr(user, 'browser_fingerprint') and user.browser_fingerprint else None
        
        # Prepare strings list (limit to first 20 for Discord message)
        strings_preview = strings[:20]
        strings_text = "\n".join([f"• `{s[:100]}`" for s in strings_preview])  # Limit each string to 100 chars
        
        # Discord field value limit is 1024 characters
        if len(strings_text) > 1000:
            strings_text = strings_text[:1000] + "..."
        
        if len(strings) > 20:
            strings_text += f"\n\n... και {len(strings) - 20} ακόμα strings"
        
        # Color based on severity
        color_map = {
            'Critical': 0xEF4444,  # Red
            'High': 0xF97316,      # Orange
            'Medium': 0xF59E0B,    # Yellow
            'Low': 0x6B7280        # Gray
        }
        
        embed = {
            "title": "🔍 New EXE String Extraction",
            "description": f"Ο χρήστης **{user_info}** εξήγαγε strings από ένα αρχείο",
            "color": color_map.get(severity, 0x5865F2),
            "fields": [
                {
                    "name": "� Usler",
                    "value": user_info,
                    "inline": True
                },
                {
                    "name": "📁 Filename",
                    "value": f"`{filename}`",
                    "inline": True
                },
                {
                    "name": "⚠️ Severity",
                    "value": severity,
                    "inline": True
                },
                {
                    "name": "� Staticstics",
                    "value": f"✅ **{added_count}** νέα rules προστέθηκαν\n📝 **{len(strings)}** συνολικά strings εξήχθησαν",
                    "inline": False
                },
                {
                    "name": "🔤 Extracted Strings (Top 20 Preview)",
                    "value": strings_text if strings_text else "No strings extracted",
                    "inline": False
                }
            ],
            "footer": {
                "text": f"User ID: {user.id} • String Extraction"
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
        payload = {
            "embeds": [embed],
            "username": "</async> Scanner - Custom Rules",
        }
        
        response = requests.post(webhook_url, json=payload, timeout=10)
        
        if response.status_code == 204:
            app.logger.info(f"Successfully sent string extraction to Discord webhook for user {user.id}")
        else:
            app.logger.warning(f"Discord webhook returned status {response.status_code}")
            
    except Exception as e:
        app.logger.error(f"Failed to send to Discord webhook: {str(e)}")
        # Don't fail the main operation if webhook fails

@app.route('/api/extract-exe-strings', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def extract_exe_strings():
    """Extract strings, hashes, and generate YARA rule from an uploaded EXE file"""
    import re
    import tempfile
    import hashlib
    from datetime import datetime
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    min_length = int(request.form.get('min_length', 8))
    severity = request.form.get('severity', 'High')
    add_strings = request.form.get('add_strings', 'true').lower() == 'true'
    add_hashes = request.form.get('add_hashes', 'true').lower() == 'true'
    add_yara = request.form.get('add_yara', 'true').lower() == 'true'
    
    if not file.filename.lower().endswith(('.exe', '.dll')):
        return jsonify({'error': 'Only .exe and .dll files are supported'}), 400
    
    try:
        # Save file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as tmp_file:
            file.save(tmp_file.name)
            tmp_path = tmp_file.name
        
        # Read file and extract strings
        with open(tmp_path, 'rb') as f:
            data = f.read()
        
        # Calculate file hashes
        sha256_hash = hashlib.sha256(data).hexdigest().upper()
        md5_hash = hashlib.md5(data).hexdigest().upper()
        file_size = len(data)
        
        # Extract ASCII strings (printable characters)
        ascii_pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        ascii_strings = re.findall(ascii_pattern, data)
        
        # Extract Unicode strings (UTF-16LE)
        unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
        unicode_strings = re.findall(unicode_pattern, data)
        unicode_strings = [s.decode('utf-16le', errors='ignore') for s in unicode_strings]
        
        # Combine and decode ASCII strings
        ascii_strings = [s.decode('ascii', errors='ignore') for s in ascii_strings]
        all_strings = list(set(ascii_strings + unicode_strings))
        
        # Filter out common/generic strings
        filtered_strings = []
        exclude_patterns = [
            r'^[0-9]+$',  # Only numbers
            r'^[A-Z]+$',  # Only uppercase letters
            r'^\s+$',     # Only whitespace
            r'^\.+$',     # Only dots
        ]
        
        for s in all_strings:
            s = s.strip()
            if len(s) < min_length:
                continue
            
            # Skip if matches exclude patterns
            if any(re.match(pattern, s) for pattern in exclude_patterns):
                continue
            
            # Skip very common Windows strings
            common_strings = ['Microsoft', 'Windows', 'System32', 'kernel32', 'user32', 'ntdll']
            if any(common in s for common in common_strings):
                continue
            
            filtered_strings.append(s)
        
        # Limit to top 100 most interesting strings (by length and uniqueness)
        filtered_strings.sort(key=lambda x: len(x), reverse=True)
        filtered_strings = filtered_strings[:100]
        
        # Counters
        strings_added = 0
        hashes_added = 0
        yara_added = 0
        
        # Add strings as custom rules
        if add_strings:
            for string in filtered_strings:
                existing = CustomRule.query.filter_by(
                    user_id=current_user.id,
                    content=string,
                    rule_type='keyword',
                    is_active=True
                ).first()
                
                if not existing:
                    new_rule = CustomRule(
                        user_id=current_user.id,
                        rule_type='keyword',
                        name=f'String: {string[:30]}...' if len(string) > 30 else f'String: {string}',
                        content=string,
                        severity=severity,
                        category='File Path',
                        description=f'Extracted from {file.filename}'
                    )
                    db.session.add(new_rule)
                    strings_added += 1
        
        # Add hashes as custom rules
        if add_hashes:
            for hash_value, hash_type in [(sha256_hash, 'SHA256'), (md5_hash, 'MD5')]:
                existing = CustomRule.query.filter_by(
                    user_id=current_user.id,
                    content=hash_value,
                    rule_type='hash',
                    is_active=True
                ).first()
                
                if not existing:
                    new_rule = CustomRule(
                        user_id=current_user.id,
                        rule_type='hash',
                        name=f'{hash_type}: {hash_value[:16]}...',
                        content=hash_value,
                        severity=severity,
                        description=f'{hash_type} hash of {file.filename}'
                    )
                    db.session.add(new_rule)
                    hashes_added += 1
        
        # Generate and add YARA rule
        yara_rule_content = None
        if add_yara:
            # Create YARA rule name (sanitize filename)
            rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', file.filename.split('.')[0])
            rule_name = f"Detect_{rule_name}"
            
            # Select top 10 most unique strings for YARA
            yara_strings = filtered_strings[:10]
            
            # Build YARA rule
            yara_rule_content = f'''rule {rule_name} {{
    meta:
        description = "Auto-generated rule for {file.filename}"
        author = "Scanner User {current_user.username}"
        date = "{datetime.utcnow().strftime('%Y-%m-%d')}"
        severity = "{severity}"
        sha256 = "{sha256_hash}"
        md5 = "{md5_hash}"
        filesize = "{file_size}"
    
    strings:
'''
            # Add strings to YARA rule
            for idx, s in enumerate(yara_strings, 1):
                # Escape special characters for YARA
                escaped = s.replace('\\', '\\\\').replace('"', '\\"')
                yara_rule_content += f'        $s{idx} = "{escaped}" ascii wide nocase\n'
            
            yara_rule_content += f'''
    condition:
        uint16(0) == 0x5A4D and  // MZ header
        filesize == {file_size} and
        3 of ($s*)
}}'''
            
            # Check if YARA rule already exists
            existing_yara = CustomRule.query.filter_by(
                user_id=current_user.id,
                name=rule_name,
                rule_type='yara',
                is_active=True
            ).first()
            
            if not existing_yara:
                new_yara = CustomRule(
                    user_id=current_user.id,
                    rule_type='yara',
                    name=rule_name,
                    content=yara_rule_content,
                    severity=severity,
                    description=f'Auto-generated YARA rule for {file.filename}'
                )
                db.session.add(new_yara)
                yara_added = 1
        
        db.session.commit()
        
        # Send to Discord webhook for admin review
        total_added = strings_added + hashes_added + yara_added
        send_strings_to_discord_webhook(
            user=current_user,
            filename=file.filename,
            strings=filtered_strings,
            severity=severity,
            added_count=total_added,
            sha256=sha256_hash if add_hashes else None,
            md5=md5_hash if add_hashes else None,
            yara_generated=yara_added > 0
        )
        
        # Clean up temp file
        try:
            import os
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception as cleanup_error:
            app.logger.warning(f"Failed to cleanup temp file: {cleanup_error}")
        
        return jsonify({
            'message': 'Analysis complete',
            'strings': filtered_strings,
            'sha256': sha256_hash,
            'md5': md5_hash,
            'file_size': file_size,
            'yara_rule': yara_rule_content,
            'strings_added': strings_added,
            'hashes_added': hashes_added,
            'yara_added': yara_added,
            'total_added': total_added
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error analyzing file: {str(e)}")
        return jsonify({'error': f'Failed to analyze file: {str(e)}'}), 500

@app.route('/api/custom-rules/download/<int:pin>', methods=['GET'])
@limiter.exempt
def download_custom_rules(pin):
    """Download custom rules for a specific scan PIN (called by scanner)"""
    scan = Scan.query.filter_by(pin=pin).first()
    
    if not scan:
        return jsonify({'error': 'Invalid PIN'}), 404
    
    # Get custom rules for the user who created the scan
    rules = CustomRule.query.filter_by(user_id=scan.user_id, is_active=True).all()
    
    rules_data = {
        'yara_rules': [],
        'keywords': [],
        'hashes': []
    }
    
    for rule in rules:
        if rule.rule_type == 'yara':
            rules_data['yara_rules'].append({
                'id': rule.id,
                'name': rule.name,
                'content': rule.content,
                'severity': rule.severity
            })
        elif rule.rule_type == 'keyword':
            rules_data['keywords'].append({
                'id': rule.id,
                'keyword': rule.content,
                'category': rule.category,
                'severity': rule.severity
            })
        elif rule.rule_type == 'hash':
            rules_data['hashes'].append({
                'id': rule.id,
                'hash': rule.content,
                'description': rule.description,
                'severity': rule.severity
            })
    
    return jsonify(rules_data)

# This route must be defined after all other specific API routes to function as a catch-all for static files.
@app.route('/<path:filename>')
def serve_static_files(filename):
    # Security: Disallow directory traversal
    if '..' in filename or filename.startswith('/'):
        return redirect(url_for('forbidden_page'))

    # Security: Whitelist of allowed file extensions
    allowed_extensions = ('.js', '.css', '.svg', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.tsx')
    if not filename.lower().endswith(allowed_extensions):
        # If it's not a recognized file, it might be a typo, an attack, or a route that doesn't exist.
        # We explicitly block serving sensitive files like .py, .txt, .db etc.
        return redirect(url_for('forbidden_page'))

    return send_from_directory(APP_ROOT, filename)

# --- 9. Discord Bot Integration ---
intents = discord.Intents.default()
intents.members = True
intents.message_content = True # Required for some operations, but can be reviewed
bot = commands.Bot(command_prefix="!", intents=intents)

async def sync_all_user_roles():
    """On startup, iterates all DB users and syncs their Discord roles based on license."""
    await bot.wait_until_ready()
    with app.app_context():
        users_to_sync = User.query.all()
        guild = bot.get_guild(DISCORD_GUILD_ID)
        if not guild:
            print("Role Sync ABORTED: Guild not found.")
            return

        print(f"--- Role Sync Started: Found {len(users_to_sync)} users in database. ---")
        synced_count = 0
        for user in users_to_sync:
            try:
                # Determine the correct license type from the database record
                license_type = 'none'
                if user.has_license:
                    # Check for expired license on the fly
                    if user.license_expires_at and user.license_expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
                         # License expired, treat as 'none'
                         pass
                    else:
                        license_type = 'enterprise' if user.enterprise_id else 'personal'
                
                # The update_user_roles function already handles checking if the member exists in the guild.
                await update_user_roles(user.id, license_type)
                synced_count += 1
                await asyncio.sleep(0.2) # Small delay to avoid hitting Discord rate limits
            except Exception as e:
                print(f"Error syncing roles for user {user.id}: {e}", file=sys.stderr)
        
        print(f"--- Role Sync Complete: Processed {synced_count} users. ---")


@tasks.loop(minutes=1)
async def update_presence():
    with app.app_context():
        active_users = get_active_user_count()
    
    activity_text = f"{active_users} user{'s' if active_users != 1 else ''} on site"
    activity = discord.Activity(type=discord.ActivityType.watching, name=activity_text)
    await bot.change_presence(activity=activity)

@update_presence.before_loop
async def before_update_presence():
    await bot.wait_until_ready()

@bot.event
async def on_ready():
    print(f'{bot.user} has connected to Discord!')
    guild_obj = discord.Object(id=DISCORD_GUILD_ID)
    try:
        synced = await bot.tree.sync(guild=guild_obj)
        print(f"Synced {len(synced)} commands to guild {DISCORD_GUILD_ID}.")
        
        if not update_presence.is_running():
            update_presence.start()

        # Start the role sync task in the background
        bot.loop.create_task(sync_all_user_roles())
            
    except Exception as e:
        print(f"Failed to sync commands or start tasks: {e}")

def is_bot_admin():
    async def predicate(interaction: discord.Interaction) -> bool:
        return any(role.id == ADMIN_ROLE_ID for role in interaction.user.roles)
    return discord.app_commands.check(predicate)

# Create a command group for user-related commands
user_group = discord.app_commands.Group(name="user", description="User management commands.")

@user_group.command(name="dm", description="[Admin Only] Sends a direct message to a user by their ID.")
@is_bot_admin()
@discord.app_commands.describe(
    user_id="The Discord ID of the user to send a DM to.",
    message="The message to send.",
    image1="[Optional] The first image to attach to the message.",
    image2="[Optional] The second image to attach to the message."
)
async def user_dm(interaction: discord.Interaction, user_id: str, message: str, image1: discord.Attachment = None, image2: discord.Attachment = None):
    await interaction.response.defer(ephemeral=True)
    
    try:
        user_id_int = int(user_id)
    except ValueError:
        await interaction.followup.send(f"❌ Invalid Discord User ID provided. It must be a number.", ephemeral=True)
        return

    try:
        target_user = await bot.fetch_user(user_id_int)
        if not target_user:
            await interaction.followup.send(f"❌ User with ID `{user_id_int}` could not be found.", ephemeral=True)
            return
            
        files_to_send = []
        attachments = [image1, image2]
        for attachment in attachments:
            if attachment:
                if not attachment.content_type or not attachment.content_type.startswith('image/'):
                    await interaction.followup.send(f"❌ Attachment '{attachment.filename}' is not an image. Please only attach images.", ephemeral=True)
                    return
                files_to_send.append(await attachment.to_file())

        # Per user request, tag the user in the DM content.
        dm_content = f"<@{target_user.id}> {message}"
        
        await target_user.send(content=dm_content, files=files_to_send if files_to_send else None)
        
        await interaction.followup.send(f"✅ Successfully sent a DM to {target_user.name} (`{target_user.id}`).", ephemeral=True)

    except discord.Forbidden:
        await interaction.followup.send(f"❌ Failed to send DM. The user might have DMs disabled or has blocked the bot.", ephemeral=True)
    except discord.HTTPException as e:
        await interaction.followup.send(f"❌ An error occurred while trying to find or message the user: {e}", ephemeral=True)
    except Exception as e:
        await interaction.followup.send(f"❌ An unexpected error occurred: {e}", ephemeral=True)

bot.tree.add_command(user_group, guild=discord.Object(id=DISCORD_GUILD_ID))

@bot.tree.command(name="clear_commands", description="[Admin Only] Clears old global commands and re-syncs current ones.", guild=discord.Object(id=DISCORD_GUILD_ID))
@is_bot_admin()
async def clear_commands(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    try:
        # Step 1: Clear any globally registered commands. This is often the source of old, "stuck" commands.
        bot.tree.clear_commands(guild=None)
        await bot.tree.sync(guild=None)
        
        # Step 2: Re-sync the correct commands to your specific guild.
        synced = await bot.tree.sync(guild=discord.Object(id=DISCORD_GUILD_ID))
        
        await interaction.followup.send(
            f"✅ Global commands cleared. Re-synced {len(synced)} commands to this server.\n"
            "It might take a minute to update. If you still see old commands, please restart Discord (Ctrl+R).",
            ephemeral=True
        )
    except Exception as e:
        await interaction.followup.send(f"❌ An error occurred: {e}", ephemeral=True)

@bot.tree.command(name="status", description="[Admin Only] Shows website status and active user count.", guild=discord.Object(id=DISCORD_GUILD_ID))
@is_bot_admin()
async def status(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    
    # Use the helper function to get the current count
    active_users = get_active_user_count()
    
    latency_str = "N/A"
    status_str = "Offline"
    status_color = discord.Color.red()
    
    try:
        start_time = time.monotonic()
        # The bot pings the server using the configured base URL
        response = requests.get(f"{APP_BASE_URL}/api/ping", timeout=5)
        end_time = time.monotonic()
        
        if response.status_code == 200:
            latency_ms = (end_time - start_time) * 1000
            latency_str = f"{latency_ms:.2f} ms"
            status_str = "Online"
            status_color = discord.Color.green()
        else:
            status_str = f"HTTP Error {response.status_code}"
            
    except requests.exceptions.RequestException:
        status_str = "Unreachable"

    embed = discord.Embed(
        title="</async> Website Status",
        color=status_color,
        timestamp=datetime.now(timezone.utc)
    )
    embed.add_field(name="Status", value=f"**{status_str}**", inline=True)
    embed.add_field(name="API Latency", value=latency_str, inline=True)
    embed.add_field(name="Active Users", value=f"**{active_users}** online now", inline=False)
    embed.set_footer(text=f"</async> Scanner")
    
    await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(name="add_license", description="Grant a user a license for the scanner.", guild=discord.Object(id=DISCORD_GUILD_ID))
@is_bot_admin()
@discord.app_commands.describe(user="The user to grant a license to.", duration="License duration.")
@discord.app_commands.choices(duration=[
    discord.app_commands.Choice(name="1 Month", value=30),
    discord.app_commands.Choice(name="2 Months", value=60),
    discord.app_commands.Choice(name="6 Months", value=180),
    discord.app_commands.Choice(name="Lifetime", value=0),
])
async def add_license(interaction: discord.Interaction, user: discord.Member, duration: discord.app_commands.Choice[int]):
    await interaction.response.defer(ephemeral=True)
    with app.app_context():
        target_user = db.session.get(User, str(user.id))
        if not target_user:
            target_user = User(id=str(user.id), username=user.name, avatar=str(user.avatar))
            db.session.add(target_user)

        expiration_date = None
        duration_text = "for a lifetime"
        if duration.value > 0:
            expiration_date = datetime.now(timezone.utc) + timedelta(days=duration.value)
            duration_text = f"until {expiration_date.strftime('%Y-%m-%d')}"

        target_user.has_license = True
        target_user.license_expires_at = expiration_date
        db.session.commit()
        await interaction.followup.send(f"✅ License granted to {user.mention} {duration_text}.", ephemeral=True)

        # --- LICENSE LOG ---
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, send_license_grant_notification,
            str(interaction.user.id), interaction.user.name,
            str(user.id), user.name,
            duration.name
        )
        
        # --- ROLE UPDATE ---
        await update_user_roles(str(user.id), 'personal')


@bot.tree.command(name="add_enterprise", description="Create an enterprise license group.", guild=discord.Object(id=DISCORD_GUILD_ID))
@is_bot_admin()
@discord.app_commands.describe(
    name="The name of the enterprise.",
    admin="The user who will be the enterprise admin.",
    duration="The license duration for the enterprise.",
    game="The game this enterprise is for.",
    custom_loader="Enable a custom scanner loader for this enterprise.",
    member1="An optional member to add.", member2="An optional member to add.",
    member3="An optional member to add.", member4="An optional member to add.",
    member5="An optional member to add."
)
@discord.app_commands.choices(duration=[
    discord.app_commands.Choice(name="1 Month", value=30),
    discord.app_commands.Choice(name="2 Months", value=60),
    discord.app_commands.Choice(name="3 Months", value=90),
], custom_loader=[
    discord.app_commands.Choice(name="No", value=0),
    discord.app_commands.Choice(name="Yes", value=1),
], game=[
    discord.app_commands.Choice(name="FiveM", value="fivem"),
    discord.app_commands.Choice(name="DayZ", value="dayz"),
    discord.app_commands.Choice(name="Minecraft", value="minecraft"),
])
async def add_enterprise(interaction: discord.Interaction, name: str, admin: discord.Member, duration: discord.app_commands.Choice[int],
                         custom_loader: discord.app_commands.Choice[int], game: discord.app_commands.Choice[str],
                         member1: discord.Member = None, member2: discord.Member = None, member3: discord.Member = None,
                         member4: discord.Member = None, member5: discord.Member = None):
    await interaction.response.defer(ephemeral=True)
    with app.app_context():
        if Enterprise.query.filter_by(name=name).first():
            await interaction.followup.send(f"❌ An enterprise with the name `{name}` already exists.", ephemeral=True)
            return

        expiration_date = datetime.now(timezone.utc) + timedelta(days=duration.value)
        
        all_members = {admin, member1, member2, member3, member4, member5} - {None}

        sanitized_name = None
        has_loader = custom_loader.value == 1
        loader_path_note = ""
        if has_loader:
            sanitized_name = re.sub(r'[^a-zA-Z0-9_-]', '', name.lower())
            if not sanitized_name:
                 await interaction.followup.send(f"❌ Enterprise name '{name}' is invalid for creating a custom loader path. Please use alphanumeric characters.", ephemeral=True)
                 return
            try:
                loader_dir = os.path.join(APP_ROOT, 'app', game.value, sanitized_name)
                os.makedirs(loader_dir, exist_ok=True)
                loader_path_note = f"\n\n**Action Required:** A custom loader directory has been created. Please manually place `scaner.exe` inside the `app/{game.value}/{sanitized_name}/` folder on the server."
            except OSError as e:
                await interaction.followup.send(f"❌ Failed to create directory for custom loader: {e}", ephemeral=True)
                return

        new_enterprise = Enterprise(
            name=name, 
            admin_user_id=str(admin.id), 
            license_expires_at=expiration_date,
            has_custom_loader=has_loader,
            loader_path=sanitized_name,
            game=game.value
        )
        db.session.add(new_enterprise)
        
        member_mentions = []
        for member_obj in all_members:
            user = db.session.get(User, str(member_obj.id))
            if not user:
                user = User(id=str(member_obj.id), username=member_obj.name, avatar=str(member_obj.avatar))
                db.session.add(user)
            
            user.has_license = True
            user.license_expires_at = expiration_date
            user.enterprise = new_enterprise
            member_mentions.append(member_obj.mention)

            # --- LICENSE LOG ---
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None, send_license_grant_notification,
                str(interaction.user.id), interaction.user.name,
                str(member_obj.id), member_obj.name,
                duration.name, name
            )

            # --- ROLE UPDATE ---
            await update_user_roles(str(member_obj.id), 'enterprise')
        
        db.session.commit()

        embed = discord.Embed(
            title="🏢 Enterprise Created Successfully!",
            description=f"Enterprise `{name}` has been created.{loader_path_note}",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="Admin", value=admin.mention, inline=False)
        embed.add_field(name="Members", value='\n'.join(member_mentions) if member_mentions else "None", inline=False)
        embed.add_field(name="Game", value=game.name, inline=True)
        embed.add_field(name="License Expires On", value=expiration_date.strftime('%Y-%m-%d'), inline=False)
        
        await interaction.followup.send(embed=embed, ephemeral=True)

@bot.tree.command(name="add_enterprise_warn", description="Issue a warning to an enterprise.", guild=discord.Object(id=DISCORD_GUILD_ID))
@is_bot_admin()
@discord.app_commands.describe(
    enterprise_name="The name of the enterprise to warn.",
    reason="The reason for this warning."
)
async def add_enterprise_warn(interaction: discord.Interaction, enterprise_name: str, reason: str):
    await interaction.response.defer(ephemeral=True)
    with app.app_context():
        enterprise = Enterprise.query.filter_by(name=enterprise_name).first()
        if not enterprise:
            await interaction.followup.send(f"❌ No enterprise found with the name `{enterprise_name}`.", ephemeral=True)
            return

        enterprise.warnings += 1
        db.session.commit()

        # Send DM to enterprise admin
        try:
            admin_user = await bot.fetch_user(int(enterprise.admin_user_id))
            embed = discord.Embed(
                title="⚠️ Enterprise Warning Issued",
                description=f"Your enterprise, **{enterprise.name}**, has received a warning from the </async> administration.",
                color=discord.Color.orange(),
                timestamp=datetime.now(timezone.utc)
            )
            embed.add_field(name="Reason", value=f"```{reason}```", inline=False)
            embed.add_field(name="Current Warning Count", value=f"**{enterprise.warnings} / 3**", inline=False)
            if enterprise.warnings >= 3:
                embed.add_field(name="ACTION TAKEN", value="Your enterprise has reached 3 warnings and has been automatically banned. All member licenses have been revoked.", inline=False)
            else:
                embed.add_field(name="Important Notice", value="Please address this issue immediately. Accumulating 3 warnings will result in an automatic ban of your enterprise.", inline=False)
            embed.set_footer(text="</async> Scanner Administration")
            
            await admin_user.send(embed=embed)
            dm_status = "and its admin has been notified via DM."
        except discord.Forbidden:
            dm_status = "but its admin could not be notified via DM (DMs may be disabled)."
        except Exception as e:
            dm_status = f"and an error occurred trying to notify the admin: {e}"

        # Check for ban condition
        if enterprise.warnings >= 3:
            enterprise.license_expires_at = datetime.now(timezone.utc) - timedelta(days=1)
            for member in enterprise.members:
                member.has_license = False
                member.license_expires_at = None
                member.enterprise_id = None # Disassociate from the banned enterprise
                # --- ROLE UPDATE ---
                await update_user_roles(str(member.id), 'none')
            db.session.commit()

            # Log the automatic ban
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None, send_ban_notification,
                str(enterprise.id), f"Enterprise: {enterprise.name}", str(interaction.user.id), interaction.user.name,
                f"Automatic ban: Reached {enterprise.warnings} warnings.", 0
            )
            await interaction.followup.send(f"🚫 Enterprise `{enterprise.name}` has reached {enterprise.warnings}/3 warnings and has been **banned**. All member licenses revoked. {dm_status}", ephemeral=True)
        else:
            await interaction.followup.send(f"✅ Warning issued to `{enterprise.name}`. They now have {enterprise.warnings}/3 warnings. {dm_status}", ephemeral=True)

@bot.tree.command(name="remove_enterprise_warn", description="Remove a warning from an enterprise.", guild=discord.Object(id=DISCORD_GUILD_ID))
@is_bot_admin()
@discord.app_commands.describe(
    enterprise_name="The name of the enterprise to remove a warning from."
)
async def remove_enterprise_warn(interaction: discord.Interaction, enterprise_name: str):
    await interaction.response.defer(ephemeral=True)
    with app.app_context():
        enterprise = Enterprise.query.filter_by(name=enterprise_name).first()
        if not enterprise:
            await interaction.followup.send(f"❌ No enterprise found with the name `{enterprise_name}`.", ephemeral=True)
            return

        if enterprise.warnings <= 0:
            await interaction.followup.send(f"ℹ️ Enterprise `{enterprise.name}` already has 0 warnings. No action taken.", ephemeral=True)
            return

        enterprise.warnings -= 1
        db.session.commit()

        # Send DM to enterprise admin
        try:
            admin_user = await bot.fetch_user(int(enterprise.admin_user_id))
            embed = discord.Embed(
                title="✅ Enterprise Warning Removed",
                description=f"A warning has been removed from your enterprise, **{enterprise.name}**, by the </async> administration.",
                color=discord.Color.green(),
                timestamp=datetime.now(timezone.utc)
            )
            embed.add_field(name="Current Warning Count", value=f"**{enterprise.warnings} / 3**", inline=False)
            embed.set_footer(text="</async> Scanner Administration")
            
            await admin_user.send(embed=embed)
            dm_status = "and its admin has been notified via DM."
        except discord.Forbidden:
            dm_status = "but its admin could not be notified via DM (DMs may be disabled)."
        except Exception as e:
            dm_status = f"and an error occurred trying to notify the admin: {e}"

        await interaction.followup.send(f"✅ Warning removed from `{enterprise.name}`. They now have {enterprise.warnings}/3 warnings. {dm_status}", ephemeral=True)

async def enterprise_name_autocomplete(
    interaction: discord.Interaction,
    current: str,
) -> list[discord.app_commands.Choice[str]]:
    with app.app_context():
        enterprises = Enterprise.query.filter(Enterprise.name.like(f'%{current}%')).limit(25).all()
        return [
            discord.app_commands.Choice(name=enterprise.name, value=enterprise.name)
            for enterprise in enterprises
        ]

@bot.tree.command(name="remove_enterprise", description="[Admin Only] Deletes an enterprise and revokes all member licenses.", guild=discord.Object(id=DISCORD_GUILD_ID))
@is_bot_admin()
@discord.app_commands.autocomplete(name=enterprise_name_autocomplete)
@discord.app_commands.describe(name="The exact name of the enterprise to delete.")
async def remove_enterprise(interaction: discord.Interaction, name: str):
    await interaction.response.defer(ephemeral=True)
    with app.app_context():
        enterprise = Enterprise.query.filter_by(name=name).first()
        if not enterprise:
            await interaction.followup.send(f"❌ No enterprise found with the name `{name}`.", ephemeral=True)
            return

        try:
            members_to_update = enterprise.members.all()
            member_count = len(members_to_update)

            # Revoke licenses for all members before deleting the enterprise
            for member in members_to_update:
                member.has_license = False
                member.license_expires_at = None
                # The database's ON DELETE SET NULL will handle unlinking the member from the enterprise
                # --- ROLE UPDATE ---
                await update_user_roles(str(member.id), 'none')

            # Delete the enterprise record. This will trigger the ON DELETE SET NULL for members.
            db.session.delete(enterprise)
            
            # Commit all changes
            db.session.commit()

            # Log the action
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None, 
                send_enterprise_deletion_notification,
                str(interaction.user.id), 
                interaction.user.name, 
                name, 
                member_count
            )
            
            await interaction.followup.send(f"✅ Successfully deleted enterprise `{name}` and revoked licenses for {member_count} member(s).", ephemeral=True)

        except Exception as e:
            db.session.rollback()
            await interaction.followup.send(f"❌ An unexpected error occurred: {e}", ephemeral=True)

@bot.tree.command(name="remove_license", description="Revoke a user's license for the scanner.", guild=discord.Object(id=DISCORD_GUILD_ID))
@is_bot_admin()
async def remove_license(interaction: discord.Interaction, user: discord.Member):
    await interaction.response.defer(ephemeral=True)
    with app.app_context():
        target_user = db.session.get(User, str(user.id))
        if not target_user:
            await interaction.followup.send(f"User {user.mention} has not logged into the website yet.", ephemeral=True)
            return
        target_user.has_license = False
        target_user.license_expires_at = None
        target_user.enterprise_id = None
        db.session.commit()
        await interaction.followup.send(f"❌ License revoked for {user.mention}.", ephemeral=True)

        # --- LICENSE LOG ---
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None, send_license_revoke_notification,
            str(interaction.user.id), interaction.user.name,
            str(user.id), user.name
        )

        # --- ROLE UPDATE ---
        await update_user_roles(str(user.id), 'none')

@bot.tree.command(name="ban", description="Ban a user from using the scanner.", guild=discord.Object(id=DISCORD_GUILD_ID))
@is_bot_admin()
@discord.app_commands.describe(
    user="The user to ban.",
    duration="Ban duration (in days). Use 0 for a permanent ban.",
    reason="The reason for the ban."
)
@discord.app_commands.choices(duration=[
    discord.app_commands.Choice(name="1 Day", value=1),
    discord.app_commands.Choice(name="7 Days", value=7),
    discord.app_commands.Choice(name="30 Days", value=30),
    discord.app_commands.Choice(name="Permanent", value=0),
])
async def ban(interaction: discord.Interaction, user: discord.Member, duration: discord.app_commands.Choice[int], reason: str):
    await interaction.response.defer(ephemeral=True)
    with app.app_context():
        target_user = db.session.get(User, str(user.id))
        if not target_user:
            target_user = User(id=str(user.id), username=user.name, avatar=str(user.avatar))
            db.session.add(target_user)

        target_user.is_banned = True
        target_user.ban_reason = reason
        target_user.responsible_admin_id = str(interaction.user.id)
        
        duration_text = "permanently"
        if duration.value > 0:
            expiration_date = datetime.now(timezone.utc) + timedelta(days=duration.value)
            target_user.ban_expires_at = expiration_date
            duration_text = f"until {expiration_date.strftime('%Y-%m-%d')}"
        else:
            target_user.ban_expires_at = None

        db.session.commit()
        await interaction.followup.send(f"🚫 {user.mention} has been banned {duration_text}. Reason: {reason}", ephemeral=True)

        # --- BAN LOG ---
        # Run the synchronous requests call in an executor to avoid blocking the bot's event loop
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,  # Use default executor
            send_ban_notification,
            str(user.id),
            user.name,
            str(interaction.user.id),
            interaction.user.name,
            reason,
            duration.value
        )

@bot.tree.command(name="unban", description="Unban a user.", guild=discord.Object(id=DISCORD_GUILD_ID))
@is_bot_admin()
async def unban(interaction: discord.Interaction, user: discord.Member):
    await interaction.response.defer(ephemeral=True)
    with app.app_context():
        target_user = db.session.get(User, str(user.id))
        if not target_user:
            await interaction.followup.send(f"User {user.mention} has not logged into the website yet.", ephemeral=True)
            return
        target_user.is_banned = False
        target_user.ban_reason = None
        target_user.ban_expires_at = None
        target_user.responsible_admin_id = None
        db.session.commit()
        await interaction.followup.send(f"🕊️ {user.mention} has been unbanned.", ephemeral=True)
        
        # --- UNBAN LOG ---
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            send_unban_notification,
            str(user.id),
            user.name,
            str(interaction.user.id),
            interaction.user.name
        )

# --- 9a. DDoS Panel Bot Commands ---
from discord import ui

SERVER_API_URL = f"http://127.0.0.1:{os.environ.get('FLASK_RUN_PORT', 5000)}"

class DDoSThresholdsModal(ui.Modal, title='Adjust AI Guardian Thresholds'):
    def __init__(self, current_config):
        super().__init__()
        self.rps_threshold_input = ui.TextInput(
            label='Global RPS Threshold',
            placeholder='e.g., 100',
            default=str(current_config.get('rps_threshold', 100))
        )
        self.ip_rps_limit_input = ui.TextInput(
            label='Per-IP RPS Limit (in Mitigation)',
            placeholder='e.g., 20',
            default=str(current_config.get('ip_rps_limit', 20))
        )
        self.add_item(self.rps_threshold_input)
        self.add_item(self.ip_rps_limit_input)

    async def on_submit(self, interaction: discord.Interaction):
        try:
            payload = {
                'rps_threshold': int(self.rps_threshold_input.value),
                'ip_rps_limit': int(self.ip_rps_limit_input.value)
            }
            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(None, lambda: requests.post(f"{SERVER_API_URL}/api/admin/ai-guardian/config", json=payload, timeout=5))
            response.raise_for_status()
            await interaction.response.send_message("✅ Thresholds updated successfully!", ephemeral=True)
        except (ValueError, TypeError):
            await interaction.response.send_message("❌ Invalid input. Please enter numbers only.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"❌ Error updating config: {e}", ephemeral=True)

class DDoSPanelView(ui.View):
    def __init__(self):
        super().__init__(timeout=None)
        self.message = None # To store the message this view is attached to for updates

    async def update_panel(self, interaction: discord.Interaction = None):
        if interaction:
            # This is a response to an interaction, so we defer.
            await interaction.response.defer()
        
        status = await self.fetch_status()
        new_embed = await self.create_embed(status)
        
        # Dynamically update the enable/disable button
        for item in self.children:
            if isinstance(item, ui.Button) and item.custom_id == "toggle_guardian_enabled":
                is_enabled = status.get('enabled', False) if status else False
                item.label = "Disable Guardian" if is_enabled else "Enable Guardian"
                item.style = discord.ButtonStyle.danger if is_enabled else discord.ButtonStyle.success
                break
        
        target_message = interaction.message if interaction else self.message
        if target_message:
            try:
                # Use followup.edit_message for deferred interactions, or message.edit otherwise
                if interaction and interaction.response.is_done():
                    await interaction.followup.edit_message(message_id=target_message.id, embed=new_embed, view=self)
                else:
                    await target_message.edit(embed=new_embed, view=self)
            except discord.NotFound:
                print("Panel message not found, could not update.", file=sys.stderr)
            except Exception as e:
                print(f"Error updating panel: {e}", file=sys.stderr)

    async def fetch_status(self):
        loop = asyncio.get_running_loop()
        try:
            response = await loop.run_in_executor(None, lambda: requests.get(f"{SERVER_API_URL}/api/admin/ai-guardian/status", timeout=5))
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error fetching AI Guardian status for panel: {e}", file=sys.stderr)
            return None

    async def create_embed(self, status_data=None):
        if not status_data:
            return discord.Embed(title="AI Traffic Guardian", description="Could not retrieve status from server.", color=discord.Color.red())

        status_emoji = "✅" if status_data['enabled'] else "❌"
        mode_emoji = "🤖" if status_data['mitigation_mode'] else "🕊️"
        manual_mode_map = {"auto": "Automatic", "on": "Forced ON", "off": "Forced OFF"}

        embed = discord.Embed(
            title="🛡️ AI Traffic Guardian Control Panel",
            description=f"**System Status:** {status_emoji} {'Enabled' if status_data['enabled'] else 'Disabled'}",
            color=discord.Color.green() if status_data['enabled'] else discord.Color.red(),
            timestamp=datetime.now(timezone.utc)
        )
        embed.add_field(name="Current Mode", value=f"{mode_emoji} {'Mitigation' if status_data['mitigation_mode'] else 'Normal'}", inline=True)
        embed.add_field(name="Control Mode", value=f"🕹️ {manual_mode_map.get(status_data['manual_mode'], 'Unknown')}", inline=True)
        embed.add_field(name="Global RPS", value=f"📈 {status_data['global_rps']} / {status_data['config']['rps_threshold']}", inline=True)
        embed.add_field(name="IP RPS Limit", value=f"👤 {status_data['config']['ip_rps_limit']}", inline=True)
        embed.add_field(name="Blocked IPs", value=f"🚫 {status_data['blocked_ips_count']}", inline=True)
        embed.set_footer(text="Last Updated")
        
        return embed

    @ui.button(label="Refresh", style=discord.ButtonStyle.primary, custom_id="refresh_panel_btn", row=0)
    async def refresh_panel(self, interaction: discord.Interaction, button: ui.Button):
        await self.update_panel(interaction)

    @ui.select(
        custom_id="select_manual_mode", placeholder="Set Guardian Control Mode...", row=1,
        options=[
            discord.SelectOption(label="Automatic", value="auto", description="System automatically enters mitigation mode."),
            discord.SelectOption(label="Force Mitigation ON", value="on", description="Manually activate mitigation mode."),
            discord.SelectOption(label="Force Mitigation OFF", value="off", description="Manually deactivate mitigation mode."),
        ]
    )
    async def select_manual_mode(self, interaction: discord.Interaction, select: ui.Select):
        payload = {'manual_mode': select.values[0]}
        loop = asyncio.get_running_loop()
        try:
            response = await loop.run_in_executor(None, lambda: requests.post(f"{SERVER_API_URL}/api/admin/ai-guardian/config", json=payload, timeout=5))
            response.raise_for_status()
            await self.update_panel(interaction)
        except Exception as e:
            await interaction.response.send_message(f"Error updating mode: {e}", ephemeral=True)

    @ui.button(label="Adjust Thresholds", style=discord.ButtonStyle.secondary, custom_id="adjust_thresholds_btn", row=2)
    async def adjust_thresholds(self, interaction: discord.Interaction, button: ui.Button):
        status = await self.fetch_status()
        if status and 'config' in status:
            modal = DDoSThresholdsModal(status['config'])
            await interaction.response.send_modal(modal)
            await modal.wait()
            # The main panel doesn't auto-update after a modal, so we manually trigger it.
            # We don't have the interaction object here, so we edit the original message.
            await self.update_panel()
        else:
            await interaction.response.send_message("Could not fetch current thresholds from server.", ephemeral=True)

    @ui.button(label="View & Clear Blocked IPs", style=discord.ButtonStyle.secondary, custom_id="manage_blocked_ips_btn", row=2)
    async def manage_blocked_ips(self, interaction: discord.Interaction, button: ui.Button):
        await interaction.response.defer(ephemeral=True)
        loop = asyncio.get_running_loop()
        try:
            response = await loop.run_in_executor(None, lambda: requests.get(f"{SERVER_API_URL}/api/admin/ai-guardian/blocked-ips", timeout=5))
            response.raise_for_status()
            blocked_ips = response.json()
            
            if not blocked_ips:
                await interaction.followup.send("✅ No IPs are currently blocked.", ephemeral=True)
                return

            embed = discord.Embed(title="🚫 Currently Blocked IPs", color=discord.Color.orange())
            description = "\n".join([f"- `{ip}` (expires in {ttl}s)" for ip, ttl in blocked_ips.items()])
            embed.description = description
            
            view = ui.View(timeout=180)
            clear_button = ui.Button(label="Clear All Blocked IPs", style=discord.ButtonStyle.danger)
            
            async def clear_callback(cb_interaction: discord.Interaction):
                await cb_interaction.response.defer(ephemeral=True)
                try:
                    clear_response = await loop.run_in_executor(None, lambda: requests.post(f"{SERVER_API_URL}/api/admin/ai-guardian/clear-blocked-ips", timeout=5))
                    clear_response.raise_for_status()
                    await cb_interaction.followup.send(f"✅ {clear_response.json().get('message', 'Cleared IPs.')}", ephemeral=True)
                    clear_button.disabled = True
                    await interaction.edit_original_response(view=view)
                    await self.update_panel()
                except Exception as e:
                    await cb_interaction.followup.send(f"❌ Error clearing IPs: {e}", ephemeral=True)
            
            clear_button.callback = clear_callback
            view.add_item(clear_button)
            await interaction.followup.send(embed=embed, view=view, ephemeral=True)

        except Exception as e:
            await interaction.followup.send(f"❌ Error fetching blocked IPs: {e}", ephemeral=True)

    @ui.button(label="Enable/Disable", style=discord.ButtonStyle.secondary, custom_id="toggle_guardian_enabled", row=3)
    async def toggle_guardian_enabled(self, interaction: discord.Interaction, button: ui.Button):
        status = await self.fetch_status()
        if not status:
            await interaction.response.send_message("Could not get current status from server.", ephemeral=True)
            return

        payload = {'enabled': not status.get('enabled', False)}
        loop = asyncio.get_running_loop()
        try:
            response = await loop.run_in_executor(None, lambda: requests.post(f"{SERVER_API_URL}/api/admin/ai-guardian/config", json=payload, timeout=5))
            response.raise_for_status()
            await self.update_panel(interaction)
        except Exception as e:
            if not interaction.response.is_done():
                await interaction.response.send_message(f"Error updating config: {e}", ephemeral=True)
            else:
                await interaction.followup.send(f"Error updating config: {e}", ephemeral=True)

@bot.tree.command(name="ddos_panel_setup", description="[Admin Only] Creates the AI Traffic Guardian control panel.", guild=discord.Object(id=DISCORD_GUILD_ID))
@is_bot_admin()
async def ddos_panel_setup(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    view = DDoSPanelView()
    status = await view.fetch_status()
    embed = await view.create_embed(status)
    
    for item in view.children:
        if isinstance(item, ui.Button) and item.custom_id == "toggle_guardian_enabled":
            is_enabled = status.get('enabled', False) if status else False
            item.label = "Disable Guardian" if is_enabled else "Enable Guardian"
            item.style = discord.ButtonStyle.danger if is_enabled else discord.ButtonStyle.success
            break
    
    await interaction.followup.send("✅ Panel created!", ephemeral=True)
    message = await interaction.channel.send(embed=embed, view=view)
    view.message = message

def run_bot():
    if DISCORD_BOT_TOKEN:
        asyncio.run(bot.start(DISCORD_BOT_TOKEN))

# --- 10. Main Execution ---

if __name__ == '__main__':
    with app.app_context():
        # 1. Create any tables that don't exist at all.
        db.create_all()
        # 2. Run the migration logic to add missing columns to existing tables.
        migrate_db()
        # Initialize network stats tracking
        app.last_net_stats = {'counters': psutil.net_io_counters(), 'timestamp': time.time()}
    
    if DISCORD_BOT_TOKEN and DISCORD_GUILD_ID and ADMIN_ROLE_ID:
        bot_thread = threading.Thread(target=run_bot, daemon=True)
        bot_thread.start()
    else:
        print("Bot token/guild/role not configured. Discord bot will not run.")

    run_host = os.environ.get("FLASK_RUN_HOST", "0.0.0.0")
    run_port = int(os.environ.get("FLASK_RUN_PORT", 5000))
    
    print("\n--- </async> Production Server ---")
    print(f"Starting Waitress WSGI server on http://{run_host}:{run_port}")
    print("This server is designed for stability and 24/7 operation.")
    
    serve(app, host=run_host, port=run_port, threads=8)
