#!/bin/bash

# Installation script for LockNest systemd service

echo "Installing LockNest as a system service..."

# Copy service file to systemd directory
sudo cp locknest.service /etc/systemd/system/

# Reload systemd daemon
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

# Enable the service to start on boot
echo "Enabling LockNest service..."
sudo systemctl enable locknest

# Start the service now
echo "Starting LockNest service..."
sudo systemctl start locknest

# Check status
echo ""
echo "Service status:"
sudo systemctl status locknest --no-pager

echo ""
echo "LockNest has been installed as a service!"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status locknest    - Check service status"
echo "  sudo systemctl stop locknest      - Stop the service"
echo "  sudo systemctl restart locknest   - Restart the service"
echo "  sudo journalctl -u locknest -f    - View live logs"
