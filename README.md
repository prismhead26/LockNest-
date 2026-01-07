# LockNest Password Manager

A secure, self-hosted password manager designed for Raspberry Pi 4. LockNest provides a modern web interface to manage your passwords with strong encryption, accessible from any device on your local network.

## Features

- **Master Password Encryption**: All passwords are encrypted using your master password with industry-standard encryption (Fernet with PBKDF2)
- **Web-Based Interface**: Clean, modern UI accessible from any browser on your network
- **Password Generator**: Generate strong, random passwords or memorable passphrases
- **Categories**: Organize passwords into customizable categories
- **Search**: Quick search across all your passwords
- **Network Access**: Access your password manager from any device on your local network
- **Secure Storage**: SQLite database with encrypted password fields
- **No Cloud Dependencies**: Everything runs locally on your Raspberry Pi

## Security Features

- Argon2 password hashing for master password
- PBKDF2 key derivation with 480,000 iterations
- Fernet symmetric encryption (AES-128 in CBC mode)
- Session management with automatic timeout
- No plaintext password storage

## Requirements

- Raspberry Pi 4 (2GB+ RAM recommended)
- Raspberry Pi OS (or any Debian-based Linux)
- Python 3.7 or higher
- Network connection

## Installation on Raspberry Pi

### 1. Update Your System

```bash
sudo apt update
sudo apt upgrade -y
```

### 2. Install Python and pip

```bash
sudo apt install python3 python3-pip python3-venv -y
```

### 3. Clone or Download LockNest

```bash
cd ~
git clone <your-repo-url> LockNest
cd LockNest
```

Or if you transferred files manually:
```bash
cd ~/LockNest
```

### 4. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 5. Install Dependencies

```bash
pip install -r requirements.txt
```

### 6. Configure Environment

```bash
cp .env.example .env
```

Edit the `.env` file to customize settings (optional):
```bash
nano .env
```

Important settings:
- `SECRET_KEY`: Will be auto-generated if not set
- `HOST`: `0.0.0.0` to allow network access (default)
- `PORT`: `5000` (default, change if needed)
- `SESSION_TIMEOUT`: Session timeout in minutes (default: 30)

### 7. Run LockNest

```bash
python app.py
```

You should see output like:
```
Starting LockNest Password Manager...
Access the application at: http://0.0.0.0:5000
```

### 8. Access LockNest

1. Find your Raspberry Pi's IP address:
   ```bash
   hostname -I
   ```

2. On any device on your network, open a web browser and navigate to:
   ```
   http://<raspberry-pi-ip>:5000
   ```
   For example: `http://192.168.1.100:5000`

3. On first visit, you'll be prompted to set up your master password

## Running LockNest as a Service (Auto-start on Boot)

To make LockNest start automatically when your Raspberry Pi boots:

### 1. Create a systemd service file

```bash
sudo nano /etc/systemd/system/locknest.service
```

### 2. Add the following content (adjust paths if needed):

```ini
[Unit]
Description=LockNest Password Manager
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/LockNest
Environment="PATH=/home/pi/LockNest/venv/bin"
ExecStart=/home/pi/LockNest/venv/bin/python /home/pi/LockNest/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 3. Enable and start the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable locknest
sudo systemctl start locknest
```

### 4. Check status

```bash
sudo systemctl status locknest
```

### Useful Service Commands

```bash
# Stop the service
sudo systemctl stop locknest

# Restart the service
sudo systemctl restart locknest

# View logs
sudo journalctl -u locknest -f
```

## Usage

### First Time Setup

1. Open LockNest in your browser
2. Create a strong master password (at least 8 characters)
3. **IMPORTANT**: Store your master password somewhere safe - it cannot be recovered!

### Adding a Password

1. Click "Add Password" button
2. Fill in the details:
   - Title (required): Name for this password entry
   - Username/Email: Your login username
   - Password (required): The password to store
   - URL: Website URL
   - Category: Select a category
   - Notes: Any additional notes
   - Master Password (required): Your master password to encrypt
3. Click "Save"

### Generating a Password

1. When adding/editing a password, click the dice icon (🎲)
2. Adjust settings (length, character types)
3. Click "Generate"
4. Click "Use This Password" to fill the password field

### Viewing a Password

1. Click on any password card
2. Enter your master password
3. Click "Decrypt" to reveal the password
4. Use the copy button (📋) to copy to clipboard

### Managing Categories

1. Click "Add Category" in the sidebar
2. Enter a category name
3. Click on categories to filter passwords

## Security Best Practices

1. **Strong Master Password**: Use a long, unique master password
2. **Keep Your Pi Secure**:
   - Change default Raspberry Pi password
   - Keep system updated
   - Use firewall if exposing to internet (not recommended)
3. **Backup Your Database**: Regularly backup `locknest.db` file
4. **Local Network Only**: Don't expose LockNest directly to the internet
5. **HTTPS (Advanced)**: Consider setting up HTTPS with a reverse proxy for added security

## Backup and Restore

### Backup

The password database is stored in `locknest.db`. To backup:

```bash
cp ~/LockNest/locknest.db ~/LockNest/backups/locknest_$(date +%Y%m%d).db
```

Create automatic backups with cron:
```bash
crontab -e
```

Add this line to backup daily at 2 AM:
```
0 2 * * * cp ~/LockNest/locknest.db ~/LockNest/backups/locknest_$(date +\%Y\%m\%d).db
```

### Restore

```bash
cp ~/LockNest/backups/locknest_YYYYMMDD.db ~/LockNest/locknest.db
sudo systemctl restart locknest
```

## Troubleshooting

### Can't Access from Other Devices

- Check firewall: `sudo ufw allow 5000`
- Verify Pi's IP address: `hostname -I`
- Ensure devices are on the same network

### Forgot Master Password

Unfortunately, if you forget your master password, there is no way to recover your encrypted passwords. This is by design for security. You'll need to:
1. Delete `locknest.db`
2. Restart the application
3. Set up a new master password

### Service Won't Start

Check logs:
```bash
sudo journalctl -u locknest -n 50
```

Check if port is in use:
```bash
sudo lsof -i :5000
```

## Advanced Configuration

### Change Port

Edit `.env` file:
```
PORT=8080
```

Then restart:
```bash
sudo systemctl restart locknest
```

### Session Timeout

Edit `.env` file to change timeout (in minutes):
```
SESSION_TIMEOUT=60
```

## Uninstall

```bash
# Stop and disable service
sudo systemctl stop locknest
sudo systemctl disable locknest
sudo rm /etc/systemd/system/locknest.service
sudo systemctl daemon-reload

# Remove files
rm -rf ~/LockNest
```

## Contributing

This is a personal project, but suggestions and improvements are welcome!

## License

See LICENSE file for details.

## Disclaimer

This password manager is provided as-is. While it uses industry-standard encryption, please use at your own risk. Always maintain backups of your password database.
