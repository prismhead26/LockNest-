# LockNest Enhanced Security Features

## Quick Reference

This document provides a quick overview of all security enhancements implemented in LockNest.

## Security Features Overview

### 1. Database Encryption at Rest (AES-256-GCM)

**What it does:**
- Encrypts `username`, `url`, and `notes` fields in the database
- Uses AES-256-GCM (Galois/Counter Mode) encryption
- Separate from master password encryption
- Encryption key stored in `.db_key` file

**Key Benefits:**
- Even if someone gains access to the database file, sensitive fields cannot be read
- Protection against database theft
- Transparent encryption/decryption

**Important:**
- The `.db_key` file must be backed up with your database
- Without this file, encrypted data cannot be recovered
- Keep this file secure with 600 permissions

### 2. Rate Limiting & Account Lockout

**What it does:**
- Tracks login attempts per IP address
- Limits attempts to 5 per 15-minute window
- Locks account for 30 minutes after threshold exceeded
- Prevents brute-force password attacks

**Configuration:**
```python
MAX_LOGIN_ATTEMPTS = 5              # Attempts allowed
LOCKOUT_DURATION_MINUTES = 30       # Lockout duration
RATE_LIMIT_WINDOW_MINUTES = 15      # Time window
```

**Unlock Account:**
```bash
sqlite3 locknest.db "UPDATE master_password SET locked_until = NULL, failed_attempts = 0 WHERE id = 1;"
```

### 3. Comprehensive Audit Logging

**What it does:**
- Logs all security-relevant events
- Records IP addresses
- Tracks timestamps
- Captures success/failure status

**Events Logged:**
- `login_success` - Successful login
- `login_failed` - Failed login attempt
- `logout` - User logout
- `password_added` - New password created
- `password_updated` - Password modified
- `password_deleted` - Password removed
- `password_decrypted` - Password viewed
- `category_added` - Category created
- `category_deleted` - Category removed
- `account_locked_rate_limit` - Account locked
- `rate_limit_exceeded` - Too many attempts

**View Logs:**
```bash
# Last 20 events
sqlite3 locknest.db "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 20;"

# Failed logins
sqlite3 locknest.db "SELECT * FROM audit_log WHERE event_type = 'login_failed';"

# Events by type
sqlite3 locknest.db "SELECT event_type, COUNT(*) FROM audit_log GROUP BY event_type;"
```

### 4. Enhanced Password Hashing

**What it does:**
- Uses Argon2 for master password hashing
- Memory-hard algorithm resistant to GPU attacks
- Industry-standard parameters

**Algorithm Details:**
- Argon2id variant
- Automatic salt generation
- Time-cost and memory-cost parameters optimized for security

### 5. Security Headers

**What it does:**
- Protects against common web vulnerabilities
- Set on every HTTP response

**Headers Implemented:**
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

**Protection Against:**
- Clickjacking (X-Frame-Options)
- MIME type sniffing (X-Content-Type-Options)
- XSS attacks (CSP, X-XSS-Protection)
- Protocol downgrade attacks (HSTS)

### 6. HTTPS/SSL Encryption

**What it does:**
- Encrypts all data in transit
- Uses TLS 1.2 and 1.3
- Self-signed certificate for local network use

**Configuration:**
- Certificate: `/etc/nginx/ssl/locknest.crt`
- Private key: `/etc/nginx/ssl/locknest.key`
- Valid for 365 days
- Can be replaced with real certificate

**Cipher Suites:**
- ECDHE-ECDSA-AES128-GCM-SHA256
- ECDHE-RSA-AES128-GCM-SHA256
- ECDHE-ECDSA-AES256-GCM-SHA384
- ECDHE-RSA-AES256-GCM-SHA384
- ECDHE-ECDSA-CHACHA20-POLY1305
- ECDHE-RSA-CHACHA20-POLY1305

### 7. Systemd Service Hardening

**What it does:**
- Restricts service capabilities and permissions
- Limits what the service can access
- Prevents privilege escalation

**Hardening Features:**
```ini
NoNewPrivileges=true              # No privilege escalation
PrivateTmp=true                   # Private /tmp directory
ProtectSystem=strict              # Read-only system files
ProtectHome=true                  # No access to home dirs
ProtectKernelLogs=true            # No kernel log access
ProtectKernelModules=true         # Can't load kernel modules
RestrictNamespaces=true           # Namespace restrictions
RestrictRealtime=true             # No real-time scheduling
SystemCallFilter=@system-service  # Limited system calls
LockPersonality=true              # Locked personality
PrivateDevices=true               # No device access
CapabilityBoundingSet=            # No capabilities
MemoryDenyWriteExecute=true       # W^X protection
```

### 8. IP Address Tracking

**What it does:**
- Tracks client IP for all requests
- Logs IP with security events
- Used for rate limiting
- Supports proxy headers (X-Forwarded-For)

**Implementation:**
```python
def get_client_ip():
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0]
    return request.environ.get('REMOTE_ADDR', 'unknown')
```

## File Structure

```
LockNest-/
├── app.py                          # Enhanced application (use app_enhanced.py)
├── crypto.py                       # Enhanced crypto (use crypto_enhanced.py)
├── database.py                     # Enhanced database (use database_enhanced.py)
├── app_enhanced.py                 # New enhanced app
├── crypto_enhanced.py              # New enhanced crypto
├── database_enhanced.py            # New enhanced database
├── locknest-enhanced.service       # Hardened systemd service
├── nginx-locknest.conf             # Nginx HTTPS configuration
├── deploy-enhanced-security.sh     # Automated deployment script
├── backup-locknest.sh              # Backup script
├── DEPLOYMENT_GUIDE.md             # Complete deployment instructions
├── SECURITY_FEATURES.md            # This file
├── .db_key                         # Database encryption key (auto-generated)
├── .env                            # Configuration file
└── locknest.db                     # SQLite database
```

## Critical Files (Must Backup)

1. **locknest.db** - Your password database
2. **.db_key** - Database encryption key (CRITICAL!)
3. **.env** - Configuration and secret key

## Database Schema Changes

### New Tables

**audit_log:**
```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    ip_address TEXT,
    details TEXT,
    success INTEGER DEFAULT 1
);
```

**rate_limits:**
```sql
CREATE TABLE rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    attempt_time TEXT NOT NULL,
    event_type TEXT NOT NULL
);
```

### Modified Tables

**master_password:**
- Added `failed_attempts INTEGER DEFAULT 0`
- Added `locked_until TEXT`

**passwords:**
- `username` field is now encrypted with AES-256-GCM
- `url` field is now encrypted with AES-256-GCM
- `notes` field is now encrypted with AES-256-GCM
- `encrypted_password` remains encrypted with master password (Fernet)

## API Changes

### New Endpoints

**GET /api/security/audit-log**
- Returns audit log entries
- Parameters: `limit` (default 100), `event_type` (optional)
- Requires authentication

**POST /api/maintenance/cleanup**
- Cleans up old rate limit records
- Requires authentication

### Modified Endpoints

All endpoints now:
- Track IP addresses
- Log security events
- Include security headers in responses
- Verify rate limits (for auth endpoints)

## Configuration Options

### Environment Variables (.env)

```bash
SECRET_KEY=<auto-generated>        # Flask secret key
FLASK_ENV=production               # Production mode
HOST=127.0.0.1                     # Bind to localhost (nginx proxies)
PORT=5000                          # Application port
DATABASE_PATH=locknest.db          # Database file path
SESSION_TIMEOUT=30                 # Session timeout in minutes
```

### Rate Limiting (app.py)

```python
MAX_LOGIN_ATTEMPTS = 5              # Max attempts per window
LOCKOUT_DURATION_MINUTES = 30       # Lockout duration
RATE_LIMIT_WINDOW_MINUTES = 15      # Time window for counting
```

## Security Checklist

After deployment, verify:

- [ ] All services running (locknest, nginx)
- [ ] HTTPS accessible
- [ ] Database encryption working (fields are encrypted in DB)
- [ ] Rate limiting active (test with wrong password)
- [ ] Audit logging working (check database)
- [ ] Backup script configured (cron job)
- [ ] Firewall enabled (ufw status)
- [ ] File permissions correct (.env=600, .db_key=600, locknest.db=600)
- [ ] SSL certificate valid
- [ ] Security headers present (check browser dev tools)

## Performance Impact

The security enhancements have minimal performance impact:

- **Database encryption:** ~1-2ms per operation
- **Audit logging:** ~0.5ms per event
- **Rate limiting:** ~1ms per login attempt
- **Security headers:** Negligible
- **HTTPS overhead:** ~10-20ms initial handshake

## Backward Compatibility

The enhanced version is backward compatible:

- Existing databases work without modification
- Legacy unencrypted fields remain readable
- New data is automatically encrypted
- Passwords encrypted with old method still decrypt correctly
- No data migration required

## Migration Notes

When upgrading from standard to enhanced version:

1. Existing passwords remain functional
2. Username, URL, and notes fields will be encrypted on next update
3. New audit log tables are created automatically
4. Rate limiting starts immediately
5. `.db_key` is generated on first run if missing

## Troubleshooting

### Common Issues

**Account Locked:**
```bash
sqlite3 locknest.db "UPDATE master_password SET locked_until = NULL, failed_attempts = 0;"
sudo systemctl restart locknest
```

**Lost .db_key:**
- Encrypted fields cannot be recovered
- Restore from backup
- If no backup, encrypted data is lost (but passwords still work)

**HTTPS Not Working:**
- Check SSL certificate exists: `ls -la /etc/nginx/ssl/`
- Check nginx config: `sudo nginx -t`
- Check nginx logs: `sudo tail -f /var/log/nginx/error.log`

**Service Won't Start:**
- Check logs: `sudo journalctl -u locknest -n 50`
- Check file permissions
- Run manually: `cd ~/LockNest- && source venv/bin/activate && python app.py`

## Maintenance Tasks

**Daily:**
- Monitor for failed login attempts in audit log

**Weekly:**
- Review audit logs for suspicious activity
- Test backup script

**Monthly:**
- Update system packages: `sudo apt update && sudo apt upgrade`
- Clean old audit logs (optional)
- Verify backups are working

**Quarterly:**
- Change master password (recommended)
- Review and update firewall rules
- Test disaster recovery process

## Resources

- **Deployment Guide:** See DEPLOYMENT_GUIDE.md
- **Original README:** See README.md
- **Backup Script:** backup-locknest.sh
- **Deploy Script:** deploy-enhanced-security.sh

## Support

For issues or questions:
1. Check DEPLOYMENT_GUIDE.md troubleshooting section
2. Review audit logs for error details
3. Check service logs: `sudo journalctl -u locknest`
4. Create GitHub issue with relevant (non-sensitive) logs

---

**Security is a process, not a destination. Keep your system updated and monitor regularly!**
