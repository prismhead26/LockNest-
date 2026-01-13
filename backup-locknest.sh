#!/bin/bash

# LockNest Backup Script
# Automatically backs up critical files with encryption

set -e  # Exit on error

# Configuration
LOCKNEST_DIR="$HOME/LockNest-"
BACKUP_DIR="$HOME/locknest-backups"
DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="locknest-backup-$DATE.tar.gz.gpg"

# Keep only the last N backups (set to 0 to keep all)
KEEP_BACKUPS=30

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

echo "================================================="
echo "LockNest Backup Script"
echo "================================================="
echo ""

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Check if critical files exist
if [ ! -f "$LOCKNEST_DIR/locknest.db" ]; then
    print_error "Database file not found at $LOCKNEST_DIR/locknest.db"
    exit 1
fi

if [ ! -f "$LOCKNEST_DIR/.db_key" ]; then
    print_warning "Database encryption key not found. Backup will continue without it."
fi

if [ ! -f "$LOCKNEST_DIR/.env" ]; then
    print_warning ".env file not found. Backup will continue without it."
fi

echo "Creating backup..."
echo ""

# Change to LockNest directory
cd "$LOCKNEST_DIR"

# List of files to backup
FILES_TO_BACKUP=""
[ -f "locknest.db" ] && FILES_TO_BACKUP="$FILES_TO_BACKUP locknest.db"
[ -f ".db_key" ] && FILES_TO_BACKUP="$FILES_TO_BACKUP .db_key"
[ -f ".env" ] && FILES_TO_BACKUP="$FILES_TO_BACKUP .env"

if [ -z "$FILES_TO_BACKUP" ]; then
    print_error "No files to backup"
    exit 1
fi

# Create encrypted backup
echo "Files to backup: $FILES_TO_BACKUP"
echo ""

# Check if gpg is installed
if ! command -v gpg &> /dev/null; then
    print_warning "GPG not found. Creating unencrypted backup..."
    tar czf "$BACKUP_DIR/locknest-backup-$DATE.tar.gz" $FILES_TO_BACKUP
    print_success "Backup created (unencrypted): $BACKUP_DIR/locknest-backup-$DATE.tar.gz"
else
    # Create encrypted backup with GPG
    print_warning "You will be prompted for a passphrase to encrypt the backup."
    print_warning "Remember this passphrase - you'll need it to restore the backup!"
    echo ""

    tar czf - $FILES_TO_BACKUP | \
        gpg --symmetric --cipher-algo AES256 --output \
        "$BACKUP_DIR/$BACKUP_FILE"

    if [ $? -eq 0 ]; then
        print_success "Encrypted backup created: $BACKUP_DIR/$BACKUP_FILE"
    else
        print_error "Backup failed"
        exit 1
    fi
fi

# Calculate backup size
BACKUP_SIZE=$(du -h "$BACKUP_DIR/$BACKUP_FILE" 2>/dev/null || du -h "$BACKUP_DIR/locknest-backup-$DATE.tar.gz" 2>/dev/null | cut -f1)
print_success "Backup size: $BACKUP_SIZE"

# Clean up old backups if configured
if [ "$KEEP_BACKUPS" -gt 0 ]; then
    echo ""
    echo "Cleaning up old backups (keeping last $KEEP_BACKUPS)..."

    # Count current backups
    BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/locknest-backup-*.tar.gz* 2>/dev/null | wc -l)

    if [ "$BACKUP_COUNT" -gt "$KEEP_BACKUPS" ]; then
        ls -t "$BACKUP_DIR"/locknest-backup-*.tar.gz* | tail -n +$((KEEP_BACKUPS + 1)) | xargs rm -f
        DELETED=$((BACKUP_COUNT - KEEP_BACKUPS))
        print_success "Deleted $DELETED old backup(s)"
    else
        echo "No old backups to delete"
    fi
fi

echo ""
echo "================================================="
print_success "Backup Complete!"
echo "================================================="
echo ""
echo "Backup location: $BACKUP_DIR/$BACKUP_FILE"
echo ""
echo "To restore this backup:"
if command -v gpg &> /dev/null; then
    echo "  1. Decrypt: gpg --decrypt $BACKUP_FILE | tar xzf -"
else
    echo "  1. Extract: tar xzf locknest-backup-$DATE.tar.gz"
fi
echo "  2. Stop service: sudo systemctl stop locknest"
echo "  3. Copy files to $LOCKNEST_DIR"
echo "  4. Start service: sudo systemctl start locknest"
echo ""
print_warning "IMPORTANT: Store this backup in a safe location!"
print_warning "Without the .db_key file, encrypted data cannot be recovered!"
echo ""
