# LockNest Enhanced Security Deployment Guide

This guide will walk you through deploying the enhanced security version of LockNest to your Raspberry Pi 4.

## Overview

The enhanced security version includes:
- **Database Encryption at Rest** - AES-256-GCM encryption for username, URL, and notes fields
- **Rate Limiting** - 5 login attempts per 15 minutes
- **Account Lockout** - 30-minute lockout after exceeding rate limit
- **Audit Logging** - Complete logging of all security events
- **Security Headers** - Protection against XSS, clickjacking, and other web attacks
- **HTTPS** - SSL/TLS encryption for all connections
- **Systemd Hardening** - Restricted service permissions and capabilities

## Prerequisites

- Raspberry Pi 4 (2GB+ RAM recommended)
- Raspberry Pi OS (Debian-based)
- Existing LockNest installation (or fresh install)
- SSH access to your Pi
- Network connection

## Deployment Methods

### Method 1: Automated Deployment (Recommended)

This is the easiest method. The script handles everything automatically.

#### Step 1: Transfer Files to Pi

From your Mac, transfer the entire LockNest directory to your Pi:

```bash
# From your Mac terminal
cd /Users/macuser/Coding/Development/Projects/
scp -r LockNest- overapt@<pi-ip-address>:/home/overapt/
```

Replace `<pi-ip-address>` with your Pi's IP address (find it with `hostname -I` on the Pi).

#### Step 2: SSH into Your Pi

```bash
ssh overapt@<pi-ip-address>
```

#### Step 3: Run the Deployment Script

```bash
cd ~/LockNest-
chmod +x deploy-enhanced-security.sh
./deploy-enhanced-security.sh
```

The script will:
1. Backup your existing files
2. Install system dependencies (nginx, python3)
3. Set up Python virtual environment
4. Deploy enhanced security files
5. Set secure file permissions
6. Configure systemd service with hardening
7. Generate SSL certificate
8. Configure nginx for HTTPS
9. Set up firewall rules
10. Verify deployment

#### Step 4: Access LockNest

Open a browser and navigate to: `https://<pi-ip-address>`

You'll see a security warning about the self-signed certificate. This is expected.
Click "Advanced" and "Proceed to site" (the exact wording varies by browser).

### Method 2: Manual Deployment

If you prefer manual control or the script fails:

#### Step 1: Backup Existing Files

```bash
cd ~/LockNest-
mkdir -p ~/locknest-backups/manual-backup-$(date +%Y%m%d)
cp locknest.db .env .db_key ~/locknest-backups/manual-backup-$(date +%Y%m%d)/ 2>/dev/null || true
```

#### Step 2: Update System Packages

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv nginx
```

#### Step 3: Deploy Enhanced Files

```bash
cd ~/LockNest-

# Replace files with enhanced versions
cp app_enhanced.py app.py
cp crypto_enhanced.py crypto.py
cp database_enhanced.py database.py
```

#### Step 4: Install Python Dependencies

```bash
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

#### Step 5: Set File Permissions

```bash
chmod 700 ~/LockNest-
chmod 600 ~/LockNest-/.env
chmod 600 ~/LockNest-/locknest.db
chmod 600 ~/LockNest-/.db_key  # Will be created on first run if not exists
```

#### Step 6: Deploy Systemd Service

```bash
sudo cp locknest-enhanced.service /etc/systemd/system/locknest.service
sudo systemctl daemon-reload
sudo systemctl stop locknest  # Stop old version
sudo systemctl enable locknest
sudo systemctl start locknest
```

#### Step 7: Generate SSL Certificate

```bash
sudo mkdir -p /etc/nginx/ssl
PI_IP=$(hostname -I | awk '{print $1}')

sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/locknest.key \
  -out /etc/nginx/ssl/locknest.crt \
  -subj "/CN=$PI_IP/O=LockNest/C=US"

sudo chmod 600 /etc/nginx/ssl/locknest.key
sudo chmod 644 /etc/nginx/ssl/locknest.crt
```

#### Step 8: Configure Nginx

```bash
sudo cp nginx-locknest.conf /etc/nginx/sites-available/locknest
sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -s /etc/nginx/sites-available/locknest /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# If test passes, restart nginx
sudo systemctl restart nginx
sudo systemctl enable nginx
```

#### Step 9: Configure Firewall

```bash
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP (redirects to HTTPS)
sudo ufw allow 443/tcp  # HTTPS
sudo ufw enable
```

**WARNING:** Make sure SSH (port 22) is allowed before enabling the firewall!

#### Step 10: Verify Deployment

```bash
sudo systemctl status locknest
sudo systemctl status nginx
```

Both services should show as "active (running)".

## Post-Deployment

### 1. Test the Application

1. Open `https://<pi-ip-address>` in your browser
2. Accept the security warning for self-signed certificate
3. Log in with your master password (or set up if new install)
4. Test adding/viewing a password
5. Verify encryption is working

### 2. Set Up Automated Backups

Create a cron job to backup critical files daily:

```bash
# Make backup script executable
chmod +x ~/LockNest-/backup-locknest.sh

# Edit crontab
crontab -e

# Add this line for daily backups at 2 AM:
0 2 * * * /home/overapt/LockNest-/backup-locknest.sh >> /home/overapt/backup.log 2>&1
```

### 3. Review Audit Logs

Check audit logs regularly for suspicious activity:

```bash
cd ~/LockNest-
sqlite3 locknest.db "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 20;"
```

Or via API (while logged in):
```bash
curl -X GET https://<pi-ip>/api/security/audit-log -k -H "Cookie: session=YOUR_SESSION"
```

### 4. Monitor Service Status

Create a simple monitoring script (optional):

```bash
cat > ~/check-locknest.sh << 'EOF'
#!/bin/bash
if ! systemctl is-active --quiet locknest; then
    echo "LockNest service is down!" | mail -s "LockNest Alert" your@email.com
fi
EOF

chmod +x ~/check-locknest.sh

# Add to crontab to check every 15 minutes
crontab -e
# Add: */15 * * * * /home/overapt/check-locknest.sh
```

## Security Verification

### Check Database Encryption

```bash
cd ~/LockNest-
sqlite3 locknest.db "SELECT username, url FROM passwords LIMIT 1;"
```

If encryption is working, you should see gibberish (base64 encoded encrypted data), not plaintext.

### Check Rate Limiting

Try logging in with wrong password 6 times. You should be locked out for 30 minutes.

### Check Audit Logging

```bash
sqlite3 locknest.db "SELECT event_type, COUNT(*) FROM audit_log GROUP BY event_type;"
```

Should show various event types: login_success, password_added, etc.

### Check HTTPS

```bash
curl -I https://<pi-ip> -k | grep -i "Strict-Transport-Security"
```

Should show the HSTS header.

### Check Firewall

```bash
sudo ufw status
```

Should show ports 22, 80, and 443 as allowed.

## Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo journalctl -u locknest -n 50 --no-pager

# Check for errors
cd ~/LockNest-
source venv/bin/activate
python app.py  # Run manually to see errors
```

### Can't Access via HTTPS

```bash
# Check nginx status
sudo systemctl status nginx

# Check nginx error logs
sudo tail -f /var/log/nginx/locknest_error.log

# Verify SSL certificate exists
ls -la /etc/nginx/ssl/
```

### Database Encryption Key Missing

If `.db_key` is missing, it will be automatically generated on first run. However, this means you won't be able to decrypt data encrypted with the old key.

If you have a backup:
```bash
cp ~/locknest-backups/<backup-name>/.db_key ~/LockNest-/
chmod 600 ~/LockNest-/.db_key
sudo systemctl restart locknest
```

### Account Locked Out

If you're locked out due to failed attempts:

```bash
cd ~/LockNest-
sqlite3 locknest.db "UPDATE master_password SET locked_until = NULL, failed_attempts = 0 WHERE id = 1;"
sudo systemctl restart locknest
```

### Port 5000 Already in Use

```bash
# Check what's using port 5000
sudo lsof -i :5000

# Kill the process if needed
sudo kill -9 <PID>

# Or change the port in .env
nano ~/LockNest-/.env
# Change PORT=5000 to PORT=5001 (or any available port)
# Also update nginx-locknest.conf to proxy to the new port

sudo systemctl restart locknest
sudo systemctl restart nginx
```

### Nginx Configuration Test Fails

```bash
sudo nginx -t
```

Check the error message. Common issues:
- SSL certificate files don't exist
- Syntax error in config file
- Port already in use

### Can't Push to GitHub (Permission Denied)

If you want to push changes back to GitHub:

```bash
# On your Mac (not the Pi)
cd /Users/macuser/Coding/Development/Projects/LockNest-
git add .
git commit -m "Add enhanced security features"
git push origin main
```

Then on the Pi:
```bash
cd ~/LockNest-
git pull origin main
./deploy-enhanced-security.sh
```

## Maintenance

### Update LockNest

```bash
cd ~/LockNest-
git pull origin main  # If using git
sudo systemctl restart locknest
```

### View Logs

```bash
# LockNest service logs
sudo journalctl -u locknest -f

# Nginx access logs
sudo tail -f /var/log/nginx/locknest_access.log

# Nginx error logs
sudo tail -f /var/log/nginx/locknest_error.log
```

### Backup Manually

```bash
cd ~/LockNest-
./backup-locknest.sh
```

### Clean Up Old Rate Limit Records

```bash
sqlite3 ~/LockNest-/locknest.db "DELETE FROM rate_limits WHERE datetime(attempt_time) < datetime('now', '-24 hours');"
```

### Clean Up Old Audit Logs

```bash
# Keep last 90 days
sqlite3 ~/LockNest-/locknest.db "DELETE FROM audit_log WHERE datetime(timestamp) < datetime('now', '-90 days');"
```

## Security Best Practices

1. **Strong Master Password**
   - Use at least 20 characters
   - Include uppercase, lowercase, numbers, and symbols
   - Don't reuse passwords
   - Store securely (physical safe, offline backup)

2. **Regular Backups**
   - Backup database, .db_key, and .env files
   - Store backups off-site
   - Test restore process periodically

3. **System Updates**
   ```bash
   sudo apt update && sudo apt upgrade -y
   sudo reboot
   ```

4. **Monitor Audit Logs**
   - Review logs weekly
   - Look for failed login attempts
   - Check for unusual activity

5. **Network Security**
   - Keep LockNest on local network only
   - Use VPN for remote access (don't expose to internet)
   - Keep firewall enabled

6. **Physical Security**
   - Secure physical access to Raspberry Pi
   - Consider encrypted filesystem for extra security

## Advanced Configuration

### Change Rate Limiting Settings

Edit `~/LockNest-/app.py`:

```python
MAX_LOGIN_ATTEMPTS = 5  # Change to desired value
LOCKOUT_DURATION_MINUTES = 30  # Change to desired value
RATE_LIMIT_WINDOW_MINUTES = 15  # Change to desired value
```

Then restart:
```bash
sudo systemctl restart locknest
```

### Change Session Timeout

Edit `~/LockNest-/.env`:
```
SESSION_TIMEOUT=30  # Minutes
```

Restart service:
```bash
sudo systemctl restart locknest
```

### Add Custom SSL Certificate

If you have a real SSL certificate (e.g., from Let's Encrypt):

```bash
sudo cp your-certificate.crt /etc/nginx/ssl/locknest.crt
sudo cp your-private-key.key /etc/nginx/ssl/locknest.key
sudo chmod 600 /etc/nginx/ssl/locknest.key
sudo systemctl restart nginx
```

### Enable HSTS (HTTP Strict Transport Security)

After verifying HTTPS works correctly, edit `/etc/nginx/sites-available/locknest` and uncomment the HSTS line:

```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

Then:
```bash
sudo systemctl restart nginx
```

## Rollback to Previous Version

If you need to rollback:

```bash
# Stop services
sudo systemctl stop locknest
sudo systemctl stop nginx

# Restore backup
cd ~/LockNest-
cp ~/locknest-backups/<backup-name>/* .

# Restore old service file
sudo cp locknest.service /etc/systemd/system/locknest.service
sudo systemctl daemon-reload

# Remove nginx config (if you want to go back to direct access)
sudo rm /etc/nginx/sites-enabled/locknest
sudo systemctl stop nginx

# Start LockNest
sudo systemctl start locknest
```

## Getting Help

If you encounter issues:

1. Check the logs:
   ```bash
   sudo journalctl -u locknest -n 100 --no-pager
   ```

2. Verify file permissions:
   ```bash
   ls -la ~/LockNest-/
   ```

3. Test database connectivity:
   ```bash
   sqlite3 ~/LockNest-/locknest.db "SELECT COUNT(*) FROM passwords;"
   ```

4. Check GitHub issues or create a new one

## Summary Checklist

After deployment, verify:

- [ ] LockNest service is running (`sudo systemctl status locknest`)
- [ ] Nginx is running (`sudo systemctl status nginx`)
- [ ] Can access via HTTPS (`https://<pi-ip>`)
- [ ] Master password login works
- [ ] Can add/view passwords
- [ ] Audit logging is working (check database)
- [ ] Rate limiting is active (test with wrong password)
- [ ] Firewall is enabled (`sudo ufw status`)
- [ ] File permissions are correct (600 for sensitive files)
- [ ] Backup script is working
- [ ] Automated backups are scheduled (crontab)

## Critical Files

**MUST backup regularly:**
- `~/LockNest-/locknest.db` - Your password database
- `~/LockNest-/.db_key` - Database encryption key (WITHOUT THIS, DATA IS LOST!)
- `~/LockNest-/.env` - Configuration file

**Store backups:**
- On a separate device (USB drive, NAS)
- Encrypted (use the backup script which uses GPG)
- In multiple locations for redundancy

---

**Congratulations!** Your LockNest installation now has enterprise-grade security features.
