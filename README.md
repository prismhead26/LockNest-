# LockNest Password Manager

A secure, self-hosted password manager designed for Raspberry Pi 4. LockNest provides a modern web interface to manage your passwords with strong encryption, accessible from any device on your local network.

## Table of Contents

- [Features](#features)
- [Security Features](#security-features)
- [System Requirements](#system-requirements)
- [Quick Start](#quick-start)
- [Installation on Raspberry Pi](#installation-on-raspberry-pi)
- [Running the Application](#running-the-application)
- [Running as a System Service](#running-as-a-system-service)
- [Enhanced Security Version](#enhanced-security-version)
- [Usage Guide](#usage-guide)
- [Backup and Restore](#backup-and-restore)
- [Troubleshooting](#troubleshooting)
- [Configuration](#configuration)
- [Raspberry Pi Specific Notes](#raspberry-pi-specific-notes)
- [Security Best Practices](#security-best-practices)
- [Maintenance](#maintenance)
- [Contributing](#contributing)

---

## Features

- **Master Password Encryption**: All passwords encrypted using your master password with industry-standard encryption (Fernet with PBKDF2)
- **Web-Based Interface**: Clean, modern UI accessible from any browser on your network
- **Password Generator**: Generate strong, random passwords or memorable passphrases
- **Categories**: Organize passwords into customizable categories with color coding
- **Search**: Quick search across all your passwords
- **Network Access**: Access your password manager from any device on your local network
- **Secure Storage**: SQLite database with encrypted password fields
- **No Cloud Dependencies**: Everything runs locally on your Raspberry Pi
- **Session Management**: Automatic timeout for security
- **Mobile Responsive**: Works on phones, tablets, and desktop browsers

## Security Features

### Standard Version
- **Argon2 password hashing** for master password (memory-hard, GPU-resistant)
- **PBKDF2 key derivation** with 480,000 iterations
- **Fernet symmetric encryption** (AES-128 in CBC mode)
- **Session management** with configurable timeout
- **No plaintext password storage**

### Enhanced Security Version
All standard features plus:
- **Database encryption at rest** (AES-256-GCM for username, URL, and notes fields)
- **Rate limiting** (5 attempts per 15 minutes)
- **Account lockout** (30-minute lockout after exceeding rate limit)
- **Comprehensive audit logging** (all security events tracked with IP addresses)
- **Security headers** (XSS, clickjacking, MIME sniffing protection)
- **HTTPS/SSL** (TLS 1.2/1.3 with nginx reverse proxy)
- **Systemd hardening** (restricted service permissions and capabilities)
- **IP address tracking** for all requests

## System Requirements

### Hardware
- **Raspberry Pi 4** (2GB+ RAM recommended)
- **MicroSD card** (16GB+ recommended)
- **Power supply** (official Raspberry Pi power supply recommended)
- **Network connection** (Ethernet recommended, WiFi works too)

### Software
- **Raspberry Pi OS** (Debian 11 or newer) or any Debian-based Linux
- **Python 3.7+** (Python 3.9+ recommended)
- **Network connection** to install dependencies

### Network
- Local network with TCP/IP connectivity
- Static IP recommended for easier access (can be configured in router)
- Port 5000 available (or configure different port)

---

## Quick Start

```bash
# 1. Update system
sudo apt update && sudo apt upgrade -y

# 2. Install dependencies
sudo apt install python3 python3-pip python3-venv -y

# 3. Clone repository
cd ~
git clone https://github.com/yourusername/LockNest-.git
cd LockNest-

# 4. Create virtual environment with COPIES (important for systemd)
python3 -m venv --copies venv

# 5. Install Python packages
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 6. Run the app
python app.py

# Access at http://<your-pi-ip>:5000
```

---

## Installation on Raspberry Pi

### Step 1: Update Your System

Always start with a fresh update:

```bash
sudo apt update
sudo apt upgrade -y
sudo reboot  # Recommended after major updates
```

### Step 2: Install System Dependencies

```bash
sudo apt install -y python3 python3-pip python3-venv git sqlite3
```

### Step 3: Clone or Transfer LockNest

**Option A: Clone from GitHub**
```bash
cd ~
git clone https://github.com/yourusername/LockNest-.git
cd LockNest-
```

**Option B: Transfer from another machine (using scp)**
```bash
# From your Mac/PC
scp -r /path/to/LockNest- pi@<pi-ip-address>:/home/pi/
```

**Option C: Transfer via USB drive**
```bash
# Mount USB drive
sudo mount /dev/sda1 /mnt
cp -r /mnt/LockNest- ~/
sudo umount /mnt
```

### Step 4: Create Virtual Environment

**CRITICAL: Use `--copies` flag for systemd compatibility**

```bash
cd ~/LockNest-

# Remove old venv if it exists
rm -rf venv

# Create venv with COPIES (not symlinks)
python3 -m venv --copies venv

# Activate virtual environment
source venv/bin/activate

# Verify Python is a real file, not a symlink
file venv/bin/python
# Should show: "ELF 64-bit LSB executable" (NOT "symbolic link")
```

**Why `--copies`?**
The `--copies` flag creates actual copies of Python binaries instead of symlinks. This is crucial because systemd's `ProtectHome` security feature blocks symlink resolution across directories, which would prevent the service from starting.

### Step 5: Install Python Dependencies

```bash
# Make sure venv is activated (you should see (venv) in prompt)
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install requirements
pip install -r requirements.txt
```

### Step 6: Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit configuration (optional)
nano .env
```

**Important `.env` settings:**
```bash
SECRET_KEY=<auto-generated>      # Will be created automatically if not set
FLASK_ENV=production             # Use production mode
HOST=0.0.0.0                     # Listen on all interfaces (for network access)
PORT=5000                        # Default port
DATABASE_PATH=locknest.db        # SQLite database file
SESSION_TIMEOUT=30               # Session timeout in minutes
```

### Step 7: Find Your Raspberry Pi's IP Address

```bash
hostname -I
```

Example output: `192.168.5.162 172.17.0.1`
The first IP (192.168.5.162) is typically your local network IP.

---

## Running the Application

### Manual Run (Testing/Development)

```bash
cd ~/LockNest-
source venv/bin/activate
python app.py
```

You should see:
```
Starting LockNest Password Manager...
Access the application at: http://0.0.0.0:5000
On your local network, use your Pi's IP address instead of 0.0.0.0
```

Press `Ctrl+C` to stop.

### Access the Application

Open a web browser on any device on your network and navigate to:
```
http://<raspberry-pi-ip>:5000
```

Example: `http://192.168.5.162:5000`

**First Time Setup:**
1. You'll be prompted to create a master password
2. Choose a strong password (minimum 8 characters, 20+ recommended)
3. **CRITICAL**: Write down your master password somewhere safe - it cannot be recovered!
4. After setting master password, you'll be logged in automatically

---

## Running as a System Service

Running LockNest as a systemd service makes it start automatically on boot and restart if it crashes.

### Standard Service Setup

#### Step 1: Choose the Right Service File

LockNest includes two service files:
- `locknest.service` - Basic service configuration
- `locknest-enhanced.service` - Hardened service with security features

For standard setup:
```bash
cd ~/LockNest-
sudo cp locknest.service /etc/systemd/system/locknest.service
```

For enhanced security setup:
```bash
cd ~/LockNest-
sudo cp locknest-enhanced.service /etc/systemd/system/locknest.service
```

#### Step 2: Edit Service File for Your User

If your username is not `overapt`, edit the service file:

```bash
sudo nano /etc/systemd/system/locknest.service
```

Change these lines to match your username and path:
```ini
User=your-username
WorkingDirectory=/home/your-username/LockNest-
Environment="PATH=/home/your-username/LockNest-/venv/bin"
ExecStart=/home/your-username/LockNest-/venv/bin/python /home/your-username/LockNest-/app.py
```

**IMPORTANT:** If using the enhanced service file, ensure `ProtectHome=read-only` (NOT `true`):
```ini
ProtectHome=read-only
```

Using `ProtectHome=true` will prevent systemd from accessing your Python virtual environment, causing the service to fail with "Unable to locate executable" errors.

#### Step 3: Enable and Start Service

```bash
# Reload systemd to recognize new service
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable locknest

# Start the service now
sudo systemctl start locknest

# Check status
sudo systemctl status locknest
```

You should see:
```
● locknest.service - LockNest Password Manager
     Loaded: loaded (/etc/systemd/system/locknest.service; enabled; preset: enabled)
     Active: active (running) since [timestamp]
```

### Service Management Commands

```bash
# Start service
sudo systemctl start locknest

# Stop service
sudo systemctl stop locknest

# Restart service
sudo systemctl restart locknest

# Check status
sudo systemctl status locknest

# View logs (live tail)
sudo journalctl -u locknest -f

# View last 50 log lines
sudo journalctl -u locknest -n 50

# Disable auto-start on boot
sudo systemctl disable locknest

# Enable auto-start on boot
sudo systemctl enable locknest
```

### Verify Auto-Start Works

```bash
# Reboot your Pi
sudo reboot

# After reboot, SSH back in and check service
sudo systemctl status locknest
```

Service should show as `active (running)` and the application should be accessible.

---

## Enhanced Security Version

LockNest includes an enhanced security version with enterprise-grade protection features. This section provides comprehensive documentation for all security enhancements, configuration, backup, and maintenance procedures.

### Quick Deploy Enhanced Security

```bash
cd ~/LockNest-
chmod +x deploy-enhanced-security.sh
./deploy-enhanced-security.sh
```

The script automatically:
- Backs up existing files
- Installs nginx for HTTPS
- Generates SSL certificate
- Deploys enhanced security files
- Configures hardened systemd service
- Sets up firewall rules
- Configures automated encrypted backups

### Manual Enhanced Security Setup

See `DEPLOYMENT_GUIDE.md` for detailed manual setup instructions.

---

### Enhanced Security Features

#### 1. Database Encryption at Rest (AES-256-GCM)
- Encrypts username, URL, and notes fields in the database
- Separate from master password encryption
- Encryption key stored in `.db_key` file
- Transparent encryption/decryption during operations

#### 2. Rate Limiting & Account Lockout
- Maximum 5 login attempts per 15 minutes
- Automatic 30-minute account lockout after threshold exceeded
- IP address tracking for all attempts
- Prevents brute-force attacks

#### 3. Comprehensive Audit Logging
- All security events logged with timestamps
- IP addresses recorded for every action
- Tracks: logins, logouts, password operations, failed attempts
- Stored in `audit_log` table in database

#### 4. Enhanced Password Hashing
- Argon2 for master password (memory-hard, GPU-resistant)
- Automatic rehashing when security parameters improve
- PBKDF2 with 600,000 iterations for password encryption keys

#### 5. Security Headers
- X-Frame-Options: DENY (prevents clickjacking)
- X-Content-Type-Options: nosniff (prevents MIME sniffing)
- X-XSS-Protection: 1; mode=block
- Content-Security-Policy (prevents XSS attacks)
- Strict-Transport-Security (enforces HTTPS)

#### 6. HTTPS/TLS Encryption
- Self-signed certificate for local network use
- TLS 1.2 and 1.3 support
- Strong cipher suites configured
- All traffic encrypted in transit

#### 7. Systemd Service Hardening
- NoNewPrivileges (prevents privilege escalation)
- ProtectSystem=strict (read-only system files)
- ProtectHome=read-only
- PrivateTmp (private /tmp directory)
- Capability restrictions
- System call filtering

#### 8. Automated Encrypted Backups
- Daily backups at 2 AM via cron
- GPG encryption with passphrase
- Automatic old backup cleanup
- Backs up: database, encryption key, configuration files

---

### Configuration Files Modified

#### `.env` Configuration
```bash
SECRET_KEY=                # Auto-generated Flask secret key
FLASK_ENV=production      # Production mode
HOST=0.0.0.0             # Listen on all interfaces
PORT=5000                # Application port
DATABASE_PATH=locknest.db # Database file path
SESSION_TIMEOUT=15       # Session timeout in minutes (reduced for security)
```

#### Enhanced Python Modules

**`app_enhanced.py` (replaces `app.py`):**
- Rate limiting implementation
- Audit logging for all operations
- Account lockout logic
- IP address tracking
- Enhanced error handling

**`crypto_enhanced.py` (replaces `crypto.py`):**
- Database field encryption methods (`encrypt_field`, `decrypt_field`)
- AES-256-GCM encryption for database fields
- Enhanced Argon2 parameters
- Automatic `.db_key` generation

**`database_enhanced.py` (replaces `database.py`):**
- `audit_log` table for security events
- `rate_limits` table for tracking attempts
- Enhanced `master_password` table with lockout fields
- Field encryption integration
- Audit logging methods

#### Nginx Configuration (`nginx-locknest.conf`)
```nginx
# HTTP to HTTPS redirect
server {
    listen 80;
    return 301 https://$host$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl;
    http2 on;

    ssl_certificate /etc/nginx/ssl/locknest.crt;
    ssl_certificate_key /etc/nginx/ssl/locknest.key;

    # Strong SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    # Proxy to Flask application
    location / {
        proxy_pass http://127.0.0.1:5000;
    }
}
```

#### Systemd Service (`locknest-enhanced.service`)
```ini
[Service]
# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
CapabilityBoundingSet=
MemoryDenyWriteExecute=true
RestrictRealtime=true
SystemCallFilter=@system-service
```

---

### Critical Files

#### Files You MUST Backup Together

1. **`locknest.db`** - Your password database
2. **`.db_key`** - Database encryption key ⚠️ **WITHOUT THIS, ENCRYPTED DATA IS UNRECOVERABLE**
3. **`.env`** - Configuration and secret key

**⚠️ WITHOUT THESE FILES, YOUR DATA IS PERMANENTLY LOST!**

#### File Permissions (Critical)
```bash
chmod 600 locknest.db    # Database - owner read/write only
chmod 600 .db_key        # Encryption key - owner read/write only
chmod 600 .env           # Configuration - owner read/write only
chmod 700 .              # Application directory - owner access only
```

---

### Backup & Restore

#### Automated Backups

**Setup (already configured after running enhanced deployment):**
```bash
# View scheduled backups
crontab -l
# Output: 0 2 * * * /home/overapt/LockNest-/backup-locknest.sh >> /home/overapt/backup.log 2>&1
```

**Backup locations:**
- Daily backups: `~/locknest-backups/`
- Encryption key backup: `~/secure-backups/.db_key-backup-YYYYMMDD.gpg`

**Backup script (`backup-locknest.sh`):**
- Creates encrypted `.tar.gz.gpg` file
- Includes: `locknest.db`, `.db_key`, `.env`
- Requires GPG passphrase (you set during setup)
- Automatically cleans up old backups (keeps last 30 days)

#### Manual Backup
```bash
cd ~/LockNest-
./backup-locknest.sh
```

You'll be prompted for a passphrase to encrypt the backup.

#### Restore from Backup
```bash
# Stop service
sudo systemctl stop locknest

# Decrypt and extract backup
cd ~/LockNest-
gpg --decrypt ~/locknest-backups/locknest-backup-YYYYMMDD-HHMMSS.tar.gz.gpg | tar xzf -

# Verify permissions
chmod 600 locknest.db .db_key .env

# Restart service
sudo systemctl start locknest
```

#### External Backup Storage

**USB Drive:**
```bash
# Mount USB
sudo mount /dev/sda1 /mnt

# Copy backups
cp ~/locknest-backups/*.tar.gz.gpg /mnt/
cp ~/secure-backups/.db_key-backup-*.gpg /mnt/

# Unmount safely
sudo umount /mnt
```

**Network Storage (NAS):**
```bash
# Mount NAS
sudo mount -t cifs //nas-ip/backup /mnt/nas -o username=user,password=pass

# Copy backups
cp ~/locknest-backups/*.tar.gz.gpg /mnt/nas/
cp ~/secure-backups/.db_key-backup-*.gpg /mnt/nas/

# Unmount
sudo umount /mnt/nas
```

---

### Security Monitoring

#### View Audit Logs
```bash
# All recent events
sqlite3 ~/LockNest-/locknest.db "SELECT timestamp, event_type, ip_address, success FROM audit_log ORDER BY timestamp DESC LIMIT 20;"

# Failed login attempts
sqlite3 ~/LockNest-/locknest.db "SELECT timestamp, ip_address, details FROM audit_log WHERE event_type='login_failed' ORDER BY timestamp DESC LIMIT 10;"

# Events by type
sqlite3 ~/LockNest-/locknest.db "SELECT event_type, COUNT(*) as count FROM audit_log GROUP BY event_type;"

# Events from specific IP
sqlite3 ~/LockNest-/locknest.db "SELECT timestamp, event_type, success FROM audit_log WHERE ip_address='192.168.5.69' ORDER BY timestamp DESC;"

# Events today
sqlite3 ~/LockNest-/locknest.db "SELECT timestamp, event_type, ip_address FROM audit_log WHERE date(timestamp) = date('now') ORDER BY timestamp DESC;"
```

#### Check Rate Limiting Status
```bash
# Recent failed attempts
sqlite3 ~/LockNest-/locknest.db "SELECT * FROM rate_limits ORDER BY attempt_time DESC LIMIT 10;"

# Check if account is locked
sqlite3 ~/LockNest-/locknest.db "SELECT failed_attempts, locked_until FROM master_password WHERE id=1;"
```

#### Unlock Account Manually

If locked out due to failed attempts:
```bash
cd ~/LockNest-
sqlite3 locknest.db "UPDATE master_password SET locked_until = NULL, failed_attempts = 0 WHERE id = 1;"
sudo systemctl restart locknest
```

---

### Service Management

#### Status & Logs
```bash
# Check service status
sudo systemctl status locknest

# View live logs
sudo journalctl -u locknest -f

# View last 50 log entries
sudo journalctl -u locknest -n 50

# View logs for specific date
sudo journalctl -u locknest --since "2026-01-13" --until "2026-01-14"
```

#### Start/Stop/Restart
```bash
sudo systemctl start locknest      # Start service
sudo systemctl stop locknest       # Stop service
sudo systemctl restart locknest    # Restart service
sudo systemctl status locknest     # Check status
```

#### Check All Security Services
```bash
# Quick status check for all services
sudo systemctl status locknest nginx fail2ban --no-pager | grep Active

# Individual service checks
sudo systemctl status locknest
sudo systemctl status nginx
sudo systemctl status fail2ban
```

---

### Firewall Configuration

#### Current Configuration
```bash
# View firewall status
sudo ufw status verbose

# View numbered rules
sudo ufw status numbered
```

#### Allowed Ports

- **2222/tcp** - SSH (custom port)
- **80/tcp** - HTTP (redirects to HTTPS)
- **443/tcp** - HTTPS (LockNest web interface)

#### Port 5000 (Flask Application)

⚠️ Port 5000 should **NOT** be open externally. This forces all traffic through nginx's HTTPS layer for encryption.

If you need to block it explicitly:
```bash
sudo ufw delete allow 5000/tcp
```

---

### HTTPS/SSL Configuration

#### Certificate Location
```bash
/etc/nginx/ssl/locknest.crt  # SSL Certificate
/etc/nginx/ssl/locknest.key  # Private key
```

#### Regenerate SSL Certificate
```bash
PI_IP=$(hostname -I | awk '{print $1}')

sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/locknest.key \
  -out /etc/nginx/ssl/locknest.crt \
  -subj "/CN=$PI_IP/O=LockNest/C=US"

sudo chmod 600 /etc/nginx/ssl/locknest.key
sudo chmod 644 /etc/nginx/ssl/locknest.crt

sudo systemctl restart nginx
```

#### Nginx Commands
```bash
# Test configuration syntax
sudo nginx -t

# Reload configuration (no downtime)
sudo systemctl reload nginx

# Restart nginx
sudo systemctl restart nginx

# View nginx logs
sudo tail -f /var/log/nginx/locknest_access.log
sudo tail -f /var/log/nginx/locknest_error.log
```

---

### Database Maintenance

#### Database Structure

**Tables:**
- `master_password` - Master password hash and lockout info
- `passwords` - Encrypted password entries
- `categories` - Password categories
- `audit_log` - Security event log
- `rate_limits` - Login attempt tracking

#### Database Commands
```bash
# Connect to database
cd ~/LockNest-
sqlite3 locknest.db

# View all tables
.tables

# View table structure
PRAGMA table_info(passwords);

# Exit
.quit
```

#### Verify Encryption
```bash
# Check if fields are encrypted (should see gibberish, not plaintext)
sqlite3 ~/LockNest-/locknest.db "SELECT id, title, substr(username, 1, 40) as username_sample FROM passwords LIMIT 3;"
```

✓ If you see encrypted data (random characters/base64), encryption is working correctly.

#### Clean Old Data
```bash
# Clean old audit logs (older than 90 days)
sqlite3 ~/LockNest-/locknest.db "DELETE FROM audit_log WHERE datetime(timestamp) < datetime('now', '-90 days');"

# Clean old rate limit records (older than 24 hours)
sqlite3 ~/LockNest-/locknest.db "DELETE FROM rate_limits WHERE datetime(attempt_time) < datetime('now', '-24 hours');"

# Vacuum database (reclaim space and optimize)
sqlite3 ~/LockNest-/locknest.db "VACUUM;"
```

---

### Accessing Enhanced LockNest

#### Access URLs

**Primary (HTTPS - Recommended):**
```
https://192.168.5.162
```

**Browser Certificate Warning:**
You'll see a security warning because the certificate is self-signed. This is **normal and expected** for local network use.

**To proceed:**
- **Chrome/Edge:** Click "Advanced" → "Proceed to 192.168.5.162 (unsafe)"
- **Firefox:** Click "Advanced" → "Accept the Risk and Continue"
- **Safari:** Click "Show Details" → "visit this website"

#### From Different Devices

- **Same network:** Use Pi's IP address (find with `hostname -I` on Pi)
- **Different network:** Set up VPN (WireGuard recommended)
- **⚠️ Do NOT expose directly to internet** - use VPN for remote access

---

### Enhanced Security Best Practices

#### 1. Master Password

- **Minimum 20 characters** recommended (longer is better)
- Use mix of uppercase, lowercase, numbers, symbols
- Consider using a passphrase: `correct-horse-battery-staple-2026!`
- **Cannot be recovered** - store safely in physical location!

#### 2. Regular Backups

- Automated backups run daily at 2 AM
- Copy backups to external storage weekly
- Test restore process quarterly
- Keep `.db_key` backup separate but secure

#### 3. Monitor Security Events

- Review audit logs weekly
- Check for failed login attempts
- Watch for unusual IP addresses
- Monitor system resources and disk space

#### 4. Keep System Updated
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Update Python dependencies (if needed)
cd ~/LockNest-
source venv/bin/activate
pip install --upgrade cryptography argon2-cffi Flask python-dotenv
deactivate

# Restart service after updates
sudo systemctl restart locknest
```

#### 5. Network Security

- Keep on local network only
- Use VPN for remote access (never port forward directly)
- Ensure firewall is enabled: `sudo ufw status`
- Monitor nginx access logs for suspicious activity
- Use strong SSH keys and disable password authentication

---

### Troubleshooting Enhanced Security

#### Service Won't Start
```bash
# Check logs for errors
sudo journalctl -u locknest -n 50

# Check if port is in use
sudo lsof -i :5000

# Test manually
cd ~/LockNest-
source venv/bin/activate
python app.py
```

#### Can't Access via HTTPS
```bash
# Check nginx status
sudo systemctl status nginx

# Check nginx configuration syntax
sudo nginx -t

# Check SSL certificates exist
ls -la /etc/nginx/ssl/

# Check firewall allows HTTPS
sudo ufw status | grep 443
```

#### Database Errors
```bash
# Check file permissions
ls -la ~/LockNest-/locknest.db

# Should be: -rw------- (600)
chmod 600 ~/LockNest-/locknest.db

# Check for database locks
fuser ~/LockNest-/locknest.db

# Restart service
sudo systemctl restart locknest
```

#### Account Locked Out
```bash
# Manually unlock account
sqlite3 ~/LockNest-/locknest.db "UPDATE master_password SET locked_until = NULL, failed_attempts = 0 WHERE id = 1;"
sudo systemctl restart locknest
```

#### Missing .db_key File
⚠️ **CRITICAL:** If `.db_key` is missing, encrypted username/URL/notes fields are **permanently unrecoverable**.

```bash
# Check if backup exists
ls -la ~/secure-backups/.db_key-backup-*.gpg

# Restore from backup
gpg --decrypt ~/secure-backups/.db_key-backup-YYYYMMDD.gpg > ~/LockNest-/.db_key
chmod 600 ~/LockNest-/.db_key
```

---

### Configuration Tuning

#### Rate Limiting Parameters

Edit `~/LockNest-/app.py`:
```python
MAX_LOGIN_ATTEMPTS = 5              # Attempts before lockout
LOCKOUT_DURATION_MINUTES = 30       # Lockout duration
RATE_LIMIT_WINDOW_MINUTES = 15      # Time window for attempts
```

Then restart: `sudo systemctl restart locknest`

#### Session Timeout

Edit `~/LockNest-/.env`:
```
SESSION_TIMEOUT=15  # Minutes (current: 15, can increase to 30 or 60)
```

Then restart: `sudo systemctl restart locknest`

#### Audit Log Retention

Automatically clean old audit logs:
```bash
# Add to crontab
crontab -e

# Add this line to clean logs older than 90 days (runs weekly)
0 3 * * 0 sqlite3 ~/LockNest-/locknest.db "DELETE FROM audit_log WHERE datetime(timestamp) < datetime('now', '-90 days');"
```

---

### Security Audit Commands

Run these periodically to verify security posture:

```bash
# Complete security status check
echo "=== LockNest Security Status ==="
echo ""
echo "Services Status:"
systemctl is-active locknest nginx fail2ban

echo ""
echo "Critical File Permissions:"
ls -la ~/LockNest-/{locknest.db,.db_key,.env}

echo ""
echo "Firewall Rules:"
sudo ufw status | grep ALLOW

echo ""
echo "Failed Logins (Last 7 Days):"
sqlite3 ~/LockNest-/locknest.db "SELECT COUNT(*) FROM audit_log WHERE event_type='login_failed' AND timestamp > datetime('now', '-7 days');"

echo ""
echo "Database Encryption Status:"
sqlite3 ~/LockNest-/locknest.db "SELECT 'Fields encrypted: ' || CASE WHEN length(username) > 20 THEN 'YES' ELSE 'NO' END FROM passwords LIMIT 1;"

echo ""
echo "Recent Backups:"
ls -lht ~/locknest-backups/ | head -5

echo ""
echo "Disk Space:"
df -h /home | tail -1
```

---

### What Changed from Standard Version

#### Files Modified
- `app.py` → Enhanced with rate limiting and audit logging
- `crypto.py` → Added database field encryption (AES-256-GCM)
- `database.py` → Added audit tables and lockout logic
- `.env` → Reduced session timeout to 15 minutes
- Added `nginx-locknest.conf` for HTTPS/TLS
- Added `locknest-enhanced.service` with hardening
- Added `backup-locknest.sh` for automated encrypted backups

#### New Tables in Database
- `audit_log` - Complete security event logging
- `rate_limits` - Login attempt tracking for rate limiting

#### New Fields in Existing Tables
- `master_password.failed_attempts` - Track failed login count
- `master_password.locked_until` - Account lockout timestamp

#### New Files Created
- `.db_key` - Database encryption key (auto-generated on first run)
- `~/secure-backups/.db_key-backup-*.gpg` - Encrypted key backups
- `~/locknest-backups/*.tar.gz.gpg` - Daily encrypted database backups

---

### Important Security Reminders

⚠️ **CRITICAL:**
- **Always backup `.db_key` with your database** - they must stay together
- Without `.db_key`, encrypted username/URL/notes fields are **permanently unrecoverable**
- Master password cannot be recovered if forgotten - no backdoor exists
- Test backup/restore process regularly (quarterly recommended)
- Keep system and dependencies updated for security patches
- Monitor audit logs weekly for suspicious activity
- Never expose directly to internet - use VPN for remote access

🔒 **Your data is protected with:**
- **AES-256-GCM** for database field encryption
- **Argon2** for master password hashing (GPU-resistant)
- **Fernet (AES-128)** for password encryption
- **TLS 1.3** for network traffic encryption
- **Multiple layers** of defense-in-depth security

---

### Additional Security Resources

- **DEPLOYMENT_GUIDE.md** - Complete enhanced security deployment guide
- **SECURITY_FEATURES.md** - Detailed security feature documentation
- **OWASP Top 10** - Review for general web security best practices
- **CIS Benchmarks** - For Raspberry Pi and Linux hardening

---

**Your LockNest installation is now enterprise-grade secure!** 🔒

---

## Usage Guide

### First Time Setup

1. Open LockNest in your browser
2. Create a master password:
   - Minimum 8 characters (20+ recommended)
   - Use uppercase, lowercase, numbers, and symbols
   - Make it memorable but strong
3. **Store your master password safely** - write it down and keep it in a safe place
4. You cannot recover your passwords if you forget the master password

### Adding a Password

1. Click **"Add Password"** button (+ icon)
2. Fill in the details:
   - **Title** (required): Name for this password entry (e.g., "Gmail Account")
   - **Username/Email**: Your login username or email
   - **Password** (required): The password to store
   - **URL**: Website URL (e.g., "https://gmail.com")
   - **Category**: Select or create a category
   - **Notes**: Any additional notes
   - **Master Password** (required): Your master password to encrypt
3. Click **"Save"**

### Generating a Strong Password

1. When adding/editing a password, click the **dice icon** (🎲)
2. Configure password settings:
   - Length (8-64 characters)
   - Include uppercase letters
   - Include lowercase letters
   - Include numbers
   - Include symbols
3. Click **"Generate"**
4. Click **"Use This Password"** to fill the password field
5. Or click **"Generate Passphrase"** for a memorable word-based password

### Viewing/Decrypting a Password

1. Click on any password card in the list
2. Enter your **master password**
3. Click **"Decrypt"** to reveal the password
4. Use the **copy button** (📋) to copy password to clipboard
5. Password is revealed for the current session only

### Editing a Password

1. Click on the password entry
2. Decrypt it with your master password
3. Click **"Edit"** button
4. Modify any fields
5. Enter master password again if changing the password field
6. Click **"Save"**

### Deleting a Password

1. Click on the password entry
2. Click **"Delete"** button
3. Confirm deletion
4. **This action cannot be undone!**

### Managing Categories

1. Click **"Add Category"** in the sidebar
2. Enter a category name (e.g., "Work", "Personal", "Banking")
3. Choose a color
4. Click **"Save"**
5. Click on categories to filter passwords by that category
6. Delete categories by clicking the trash icon (passwords remain, category removed)

### Searching Passwords

1. Use the search bar at the top
2. Search matches: titles, usernames, URLs, and notes
3. Search is case-insensitive
4. Click **"Clear"** to show all passwords

### Logging Out

Click the **"Logout"** button in the top right corner. This clears your session and requires master password to log back in.

---

## Backup and Restore

### What to Backup

**Critical files:**
- `locknest.db` - Your password database
- `.env` - Configuration and secret key
- `.db_key` - Database encryption key (if using enhanced security)

**Without these files, your data is lost!**

### Manual Backup

```bash
# Create backup directory
mkdir -p ~/locknest-backups

# Backup with timestamp
cd ~/LockNest-
cp locknest.db ~/locknest-backups/locknest_$(date +%Y%m%d_%H%M%S).db
cp .env ~/locknest-backups/.env_backup
cp .db_key ~/locknest-backups/.db_key_backup 2>/dev/null || true
```

### Automated Backups

Use the included backup script:

```bash
# Make script executable
chmod +x ~/LockNest-/backup-locknest.sh

# Test manual backup
~/LockNest-/backup-locknest.sh

# Set up daily automated backups at 2 AM
crontab -e

# Add this line:
0 2 * * * /home/your-username/LockNest-/backup-locknest.sh >> /home/your-username/backup.log 2>&1
```

### Restore from Backup

```bash
# Stop the service
sudo systemctl stop locknest

# Restore database
cp ~/locknest-backups/locknest_20260113.db ~/LockNest-/locknest.db

# Restore encryption key (if using enhanced security)
cp ~/locknest-backups/.db_key_backup ~/LockNest-/.db_key

# Set proper permissions
chmod 600 ~/LockNest-/locknest.db
chmod 600 ~/LockNest-/.db_key

# Restart service
sudo systemctl start locknest
```

### Backup to External Drive

```bash
# Mount USB drive
sudo mount /dev/sda1 /mnt

# Copy backups to USB
cp -r ~/locknest-backups /mnt/

# Unmount safely
sudo umount /mnt
```

---

## Troubleshooting

### Common Issues and Solutions

#### Service Won't Start

**Error: "Unable to locate executable"**

This is the most common issue, caused by using symlinks in the virtual environment with `ProtectHome=true` in the systemd service.

**Solution 1: Fix the virtual environment**
```bash
cd ~/LockNest-
deactivate  # If venv is active
rm -rf venv
python3 -m venv --copies venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Verify Python is a real file
file venv/bin/python
# Should show: "ELF 64-bit LSB executable"

sudo systemctl restart locknest
```

**Solution 2: Fix the service file**
```bash
sudo nano /etc/systemd/system/locknest.service

# Change this line:
ProtectHome=true

# To:
ProtectHome=read-only

# Save and exit (Ctrl+X, Y, Enter)

sudo systemctl daemon-reload
sudo systemctl restart locknest
```

**Check logs for details:**
```bash
sudo journalctl -u locknest -n 50 --no-pager
```

#### Can't Access from Other Devices

**Check firewall:**
```bash
# For standard version (port 5000)
sudo ufw allow 5000/tcp

# For enhanced version (ports 80 and 443)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Check firewall status
sudo ufw status
```

**Verify Pi's IP address:**
```bash
hostname -I
```

**Ensure devices are on the same network:**
- Check that both devices are connected to the same WiFi/LAN
- Try pinging the Pi from another device: `ping <pi-ip-address>`

**Check if service is listening:**
```bash
sudo netstat -tulnp | grep 5000
```

Should show Python listening on port 5000.

#### Forgot Master Password

**Unfortunately, there is no way to recover a forgotten master password.** This is by design for security.

Your only options:
1. **If you have a backup** - Restore from backup and try to remember the password
2. **Start fresh** - Delete database and set up new master password:
   ```bash
   sudo systemctl stop locknest
   cd ~/LockNest-
   mv locknest.db locknest.db.old  # Backup old database just in case
   sudo systemctl start locknest
   ```

**Prevention:**
- Write down your master password and store it in a safe place
- Consider keeping a physical copy in a safe or safety deposit box

#### Port Already in Use

**Error: "Address already in use"**

```bash
# Find what's using port 5000
sudo lsof -i :5000

# Kill the process
sudo kill -9 <PID>

# Or change port in .env
cd ~/LockNest-
nano .env
# Change: PORT=5001

# Restart service
sudo systemctl restart locknest
```

#### Database Locked Error

**Error: "database is locked"**

```bash
# Check for leftover lock
cd ~/LockNest-
ls -la locknest.db*

# Remove lock file if it exists
rm -f locknest.db-journal

# Restart service
sudo systemctl restart locknest
```

#### SSL Certificate Issues (Enhanced Version)

**Error: "SSL certificate problem"**

This is normal for self-signed certificates. In your browser:
1. Click "Advanced"
2. Click "Proceed to site" or "Accept Risk and Continue"

**Generate new certificate:**
```bash
sudo rm /etc/nginx/ssl/locknest.*
PI_IP=$(hostname -I | awk '{print $1}')
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/locknest.key \
  -out /etc/nginx/ssl/locknest.crt \
  -subj "/CN=$PI_IP/O=LockNest/C=US"
sudo systemctl restart nginx
```

#### Account Locked (Enhanced Version)

If you exceed the login attempt limit (5 attempts in 15 minutes):

```bash
cd ~/LockNest-
sqlite3 locknest.db "UPDATE master_password SET locked_until = NULL, failed_attempts = 0 WHERE id = 1;"
sudo systemctl restart locknest
```

#### Service Fails After Reboot

Check logs immediately after reboot:
```bash
sudo journalctl -u locknest -b -n 50
```

Common causes:
- Virtual environment uses symlinks (recreate with `--copies`)
- Database file permissions incorrect
- Network not ready before service starts (add `After=network-online.target` to service file)

#### Python Module Not Found

```bash
cd ~/LockNest-
source venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart locknest
```

---

## Configuration

### Environment Variables (.env)

```bash
# Flask secret key (auto-generated if not set)
SECRET_KEY=your-secret-key-here

# Flask environment
FLASK_ENV=production

# Host to bind to (0.0.0.0 = all interfaces, 127.0.0.1 = localhost only)
HOST=0.0.0.0

# Port to listen on
PORT=5000

# Database file path
DATABASE_PATH=locknest.db

# Session timeout in minutes
SESSION_TIMEOUT=30
```

### Changing Port

```bash
nano ~/LockNest-/.env
# Change: PORT=8080
sudo systemctl restart locknest
```

Access at: `http://<pi-ip>:8080`

### Changing Session Timeout

```bash
nano ~/LockNest-/.env
# Change: SESSION_TIMEOUT=60  (in minutes)
sudo systemctl restart locknest
```

### Rate Limiting (Enhanced Version)

Edit `~/LockNest-/app.py`:
```python
MAX_LOGIN_ATTEMPTS = 5              # Attempts allowed
LOCKOUT_DURATION_MINUTES = 30       # Lockout duration
RATE_LIMIT_WINDOW_MINUTES = 15      # Time window
```

Restart after changes:
```bash
sudo systemctl restart locknest
```

---

## Raspberry Pi Specific Notes

### Python Virtual Environment Critical Info

**Always use `--copies` flag when creating venv on Pi for systemd:**
```bash
python3 -m venv --copies venv
```

**Why?**
- Default venv creates symlinks to system Python
- Systemd's `ProtectHome` security feature blocks symlink resolution
- Results in "Unable to locate executable" errors
- Using `--copies` creates actual binary copies instead

**Verify your venv:**
```bash
cd ~/LockNest-
file venv/bin/python
```

Should show: `ELF 64-bit LSB executable` (not "symbolic link")

### Memory Considerations

**Minimum:** 2GB RAM
**Recommended:** 4GB+ RAM

LockNest is lightweight but encryption operations benefit from more RAM.

### Storage Considerations

**Minimum:** 500MB free space
**Recommended:** 2GB+ free space (for logs, backups, database growth)

**Check available space:**
```bash
df -h /home
```

### Performance Tips

1. **Use Ethernet instead of WiFi** for better stability
2. **Use a high-quality SD card** (Class 10 or UHS-I)
3. **Enable boot from USB** (faster than SD card)
4. **Overclock carefully** (can improve performance but generates more heat)
5. **Use active cooling** (heatsink + fan for better stability)

### Network Configuration

**Set Static IP (recommended):**

Option 1: Configure in router (DHCP reservation)
Option 2: Configure on Pi:

```bash
sudo nano /etc/dhcpcd.conf

# Add at the end:
interface eth0
static ip_address=192.168.1.100/24
static routers=192.168.1.1
static domain_name_servers=192.168.1.1 8.8.8.8

sudo reboot
```

### Power Management

**Use official Raspberry Pi power supply!**
- Insufficient power causes instability
- Can corrupt SD card
- Can cause random reboots

**Symptoms of power issues:**
- Random reboots
- Database corruption
- Service failures
- USB devices disconnecting

### SSH Access

**Enable SSH:**
```bash
sudo raspi-config
# Select: Interface Options > SSH > Enable
```

**Change default password:**
```bash
passwd
```

**SSH from Mac/PC:**
```bash
ssh pi@<pi-ip-address>
# Or:
ssh -p 2222 overapt@<pi-ip-address>  # If using custom port
```

### Updating Raspberry Pi OS

```bash
# Update package list
sudo apt update

# Upgrade installed packages
sudo apt upgrade -y

# Full distribution upgrade
sudo apt full-upgrade -y

# Clean up
sudo apt autoremove -y
sudo apt autoclean

# Reboot if kernel updated
sudo reboot
```

### Monitoring System Health

**Check temperature:**
```bash
vcgencmd measure_temp
```

Keep under 80°C for longevity.

**Check memory usage:**
```bash
free -h
```

**Check disk usage:**
```bash
df -h
```

**Check running processes:**
```bash
htop  # Install with: sudo apt install htop
```

---

## Security Best Practices

### Master Password

1. **Length:** Use at least 20 characters (longer is better)
2. **Complexity:** Mix uppercase, lowercase, numbers, and symbols
3. **Uniqueness:** Don't reuse from other accounts
4. **Storage:** Write it down and store physically in a safe place
5. **Never share:** Don't email, text, or share with anyone

**Good master password examples:**
- Passphrase: `correct-horse-battery-staple-2026!`
- Random: `Km9#nP2$vQ8@xL5&wR7*tY3`

### Raspberry Pi Security

1. **Change default password:**
   ```bash
   passwd
   ```

2. **Keep system updated:**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

3. **Enable firewall:**
   ```bash
   sudo apt install ufw
   sudo ufw allow 22/tcp   # SSH
   sudo ufw allow 5000/tcp # LockNest
   sudo ufw enable
   ```

4. **Use SSH keys instead of passwords:**
   ```bash
   # On your Mac/PC:
   ssh-keygen -t ed25519
   ssh-copy-id pi@<pi-ip>
   ```

5. **Disable password SSH login (after setting up keys):**
   ```bash
   sudo nano /etc/ssh/sshd_config
   # Change: PasswordAuthentication no
   sudo systemctl restart ssh
   ```

### Network Security

1. **Keep on local network only** - Don't expose directly to internet
2. **Use VPN for remote access** (WireGuard, OpenVPN)
3. **Don't port forward** unless you know what you're doing
4. **Use enhanced security version** with HTTPS for encrypted traffic
5. **Monitor firewall logs** for suspicious access attempts

### Backup Security

1. **Encrypt backups** before storing off-site
2. **Store backups in multiple locations**
3. **Test restore process** periodically
4. **Keep backup passwords separate** from master password

### Physical Security

1. **Secure physical access to Pi** - Locked room or cabinet
2. **Consider encrypted filesystem** for extra protection (LUKS)
3. **Disable unused USB ports** if possible
4. **Monitor physical access logs**

---

## Maintenance

### Daily Tasks

- Monitor for any service failures: `sudo systemctl status locknest`

### Weekly Tasks

- Review audit logs (if using enhanced security):
  ```bash
  sqlite3 ~/LockNest-/locknest.db "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 20;"
  ```
- Check for failed login attempts
- Verify backups are running

### Monthly Tasks

- **Update system packages:**
  ```bash
  sudo apt update && sudo apt upgrade -y
  sudo reboot
  ```
- **Test backup restore process**
- **Review disk space:** `df -h`
- **Clean old logs:**
  ```bash
  sudo journalctl --vacuum-time=30d
  ```

### Quarterly Tasks

- **Consider changing master password** (recommended but optional)
- **Review and test disaster recovery plan**
- **Update LockNest** if new version available
- **Check Pi temperature and cooling**

### Cleaning Up

**Old rate limit records (enhanced version):**
```bash
sqlite3 ~/LockNest-/locknest.db "DELETE FROM rate_limits WHERE datetime(attempt_time) < datetime('now', '-24 hours');"
```

**Old audit logs (enhanced version):**
```bash
# Keep last 90 days
sqlite3 ~/LockNest-/locknest.db "DELETE FROM audit_log WHERE datetime(timestamp) < datetime('now', '-90 days');"
```

**Journal logs:**
```bash
# Keep last 2 weeks
sudo journalctl --vacuum-time=2weeks
```

---

## Contributing

This is a personal project, but suggestions and improvements are welcome!

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## Additional Documentation

- **DEPLOYMENT_GUIDE.md** - Complete enhanced security deployment guide
- **SECURITY_FEATURES.md** - Detailed security feature documentation
- **.env.example** - Example environment configuration

---

## Uninstall

To completely remove LockNest:

```bash
# Stop and disable service
sudo systemctl stop locknest
sudo systemctl disable locknest
sudo rm /etc/systemd/system/locknest.service
sudo systemctl daemon-reload

# Remove nginx config (if using enhanced security)
sudo rm /etc/nginx/sites-enabled/locknest
sudo rm /etc/nginx/sites-available/locknest
sudo systemctl restart nginx

# Remove application files (BACKUP FIRST!)
cd ~
# Backup database before removing
cp ~/LockNest-/locknest.db ~/locknest-final-backup.db
rm -rf ~/LockNest-

# Remove backups (optional)
rm -rf ~/locknest-backups
```

---

## License

See LICENSE file for details.

---

## Disclaimer

This password manager is provided as-is. While it uses industry-standard encryption and security best practices, please use at your own risk. Always maintain multiple backups of your password database and encryption keys.

**Remember:**
- Your master password cannot be recovered if lost
- Backup your `.db_key` file (enhanced security) - without it, encrypted data is unrecoverable
- Test your backup/restore process regularly
- Keep your Raspberry Pi physically secure
- Keep your system updated

---

## Support and Issues

**For issues or questions:**

1. Check the troubleshooting section above
2. Review logs: `sudo journalctl -u locknest -n 50`
3. Check GitHub issues for similar problems
4. Create a new GitHub issue with:
   - Raspberry Pi model and OS version
   - Python version: `python3 --version`
   - LockNest version/commit
   - Error logs (remove sensitive information)
   - Steps to reproduce

---

**Made with ❤️ for secure, self-hosted password management on Raspberry Pi**
