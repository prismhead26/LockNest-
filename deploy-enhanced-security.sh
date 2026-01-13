#!/bin/bash

# LockNest Enhanced Security Deployment Script
# This script deploys the enhanced security version with all features

set -e  # Exit on error

echo "================================================="
echo "LockNest Enhanced Security Deployment"
echo "================================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "$1"
}

# Check if running on Raspberry Pi
if [ ! -f /proc/device-tree/model ] || ! grep -q "Raspberry Pi" /proc/device-tree/model 2>/dev/null; then
    print_warning "This script is designed for Raspberry Pi. Continuing anyway..."
fi

# Get current directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
print_info "Step 1: Backing up existing files..."
echo "----------------------------------------"

# Create backup directory
BACKUP_DIR="$HOME/locknest-backups/pre-security-upgrade-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup existing files if they exist
if [ -f "locknest.db" ]; then
    cp locknest.db "$BACKUP_DIR/" 2>/dev/null || true
    print_success "Backed up database"
fi

if [ -f ".env" ]; then
    cp .env "$BACKUP_DIR/" 2>/dev/null || true
    print_success "Backed up .env file"
fi

if [ -f ".db_key" ]; then
    cp .db_key "$BACKUP_DIR/" 2>/dev/null || true
    print_success "Backed up encryption key"
fi

if [ -f "app.py" ]; then
    cp app.py "$BACKUP_DIR/app.py.bak" 2>/dev/null || true
    print_success "Backed up app.py"
fi

print_success "Backup created at: $BACKUP_DIR"

echo ""
print_info "Step 2: Installing/Updating system packages..."
echo "----------------------------------------"

sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv nginx

print_success "System packages installed"

echo ""
print_info "Step 3: Setting up Python virtual environment..."
echo "----------------------------------------"

# Create or update virtual environment
if [ ! -d "venv" ]; then
    python3 -m venv venv
    print_success "Created virtual environment"
else
    print_info "Virtual environment already exists"
fi

# Activate virtual environment and install requirements
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

print_success "Python dependencies installed"

echo ""
print_info "Step 4: Deploying enhanced security files..."
echo "----------------------------------------"

# Replace files with enhanced versions
if [ -f "app_enhanced.py" ]; then
    cp app_enhanced.py app.py
    print_success "Deployed enhanced app.py"
fi

if [ -f "crypto_enhanced.py" ]; then
    cp crypto_enhanced.py crypto.py
    print_success "Deployed enhanced crypto.py"
fi

if [ -f "database_enhanced.py" ]; then
    cp database_enhanced.py database.py
    print_success "Deployed enhanced database.py"
fi

echo ""
print_info "Step 5: Setting file permissions..."
echo "----------------------------------------"

# Set secure permissions
chmod 700 "$SCRIPT_DIR"
print_success "Set directory permissions (700)"

if [ -f ".env" ]; then
    chmod 600 .env
    print_success "Set .env permissions (600)"
fi

if [ -f "locknest.db" ]; then
    chmod 600 locknest.db
    print_success "Set database permissions (600)"
fi

if [ -f ".db_key" ]; then
    chmod 600 .db_key
    print_success "Set encryption key permissions (600)"
fi

echo ""
print_info "Step 6: Setting up systemd service..."
echo "----------------------------------------"

# Stop existing service if running
sudo systemctl stop locknest 2>/dev/null || true

# Copy enhanced service file
if [ -f "locknest-enhanced.service" ]; then
    sudo cp locknest-enhanced.service /etc/systemd/system/locknest.service
    print_success "Deployed hardened systemd service"
fi

# Reload systemd
sudo systemctl daemon-reload

# Enable and start service
sudo systemctl enable locknest
sudo systemctl start locknest

print_success "LockNest service started"

echo ""
print_info "Step 7: Setting up HTTPS with self-signed certificate..."
echo "----------------------------------------"

# Create SSL directory
sudo mkdir -p /etc/nginx/ssl

# Generate self-signed certificate if it doesn't exist
if [ ! -f /etc/nginx/ssl/locknest.crt ]; then
    PI_IP=$(hostname -I | awk '{print $1}')
    print_info "Generating self-signed SSL certificate for IP: $PI_IP"

    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/locknest.key \
        -out /etc/nginx/ssl/locknest.crt \
        -subj "/CN=$PI_IP/O=LockNest/C=US" 2>/dev/null

    sudo chmod 600 /etc/nginx/ssl/locknest.key
    sudo chmod 644 /etc/nginx/ssl/locknest.crt

    print_success "SSL certificate generated"
else
    print_info "SSL certificate already exists"
fi

echo ""
print_info "Step 8: Configuring nginx..."
echo "----------------------------------------"

# Copy nginx configuration
if [ -f "nginx-locknest.conf" ]; then
    sudo cp nginx-locknest.conf /etc/nginx/sites-available/locknest

    # Remove default site if it exists
    sudo rm -f /etc/nginx/sites-enabled/default

    # Enable LockNest site
    sudo ln -sf /etc/nginx/sites-available/locknest /etc/nginx/sites-enabled/

    # Test nginx configuration
    if sudo nginx -t 2>/dev/null; then
        print_success "Nginx configuration valid"
    else
        print_error "Nginx configuration has errors"
        sudo nginx -t
        exit 1
    fi

    # Restart nginx
    sudo systemctl restart nginx
    sudo systemctl enable nginx

    print_success "Nginx configured and started"
fi

echo ""
print_info "Step 9: Configuring firewall..."
echo "----------------------------------------"

# Configure UFW firewall
if command -v ufw >/dev/null 2>&1; then
    # Allow SSH (important!)
    sudo ufw allow 22/tcp >/dev/null 2>&1

    # Allow HTTPS
    sudo ufw allow 443/tcp >/dev/null 2>&1

    # Allow HTTP (for redirect to HTTPS)
    sudo ufw allow 80/tcp >/dev/null 2>&1

    # Enable firewall if not already enabled
    print_info "Firewall rules configured (SSH:22, HTTP:80, HTTPS:443)"

    # Ask before enabling firewall
    if ! sudo ufw status | grep -q "Status: active"; then
        print_warning "Firewall is not active. Enable it? (y/n)"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            echo "y" | sudo ufw enable >/dev/null 2>&1
            print_success "Firewall enabled"
        else
            print_warning "Firewall not enabled. You can enable it later with: sudo ufw enable"
        fi
    else
        print_success "Firewall already active"
    fi
else
    print_warning "UFW not found. Please configure firewall manually."
fi

echo ""
print_info "Step 10: Verifying deployment..."
echo "----------------------------------------"

# Check if service is running
if sudo systemctl is-active --quiet locknest; then
    print_success "LockNest service is running"
else
    print_error "LockNest service is not running"
    print_info "Check logs with: sudo journalctl -u locknest -n 50"
fi

# Check if nginx is running
if sudo systemctl is-active --quiet nginx; then
    print_success "Nginx is running"
else
    print_error "Nginx is not running"
    print_info "Check logs with: sudo journalctl -u nginx -n 50"
fi

# Get Pi IP address
PI_IP=$(hostname -I | awk '{print $1}')

echo ""
echo "================================================="
print_success "Deployment Complete!"
echo "================================================="
echo ""
print_info "Access LockNest at: https://$PI_IP"
print_warning "Note: You'll see a browser warning about the self-signed certificate."
print_warning "This is expected. Click 'Advanced' and proceed to the site."
echo ""
print_info "Security Features Enabled:"
echo "  ✓ Database field encryption (AES-256-GCM)"
echo "  ✓ Rate limiting (5 attempts per 15 minutes)"
echo "  ✓ Account lockout (30 minutes)"
echo "  ✓ Audit logging"
echo "  ✓ Security headers"
echo "  ✓ HTTPS encryption"
echo "  ✓ Systemd hardening"
echo ""
print_info "Backup Location: $BACKUP_DIR"
echo ""
print_info "Useful Commands:"
echo "  sudo systemctl status locknest    - Check service status"
echo "  sudo systemctl restart locknest   - Restart service"
echo "  sudo journalctl -u locknest -f    - View live logs"
echo "  sudo systemctl status nginx       - Check nginx status"
echo ""
print_warning "IMPORTANT: Backup the following files regularly:"
echo "  - $SCRIPT_DIR/locknest.db"
echo "  - $SCRIPT_DIR/.db_key"
echo "  - $SCRIPT_DIR/.env"
echo ""
echo "================================================="
