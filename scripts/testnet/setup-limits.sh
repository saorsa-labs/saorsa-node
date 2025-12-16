#!/bin/bash
# Configure system limits for running 50 saorsa nodes
# Run this once on each droplet before spawning nodes

set -e

echo "=== Configuring System Limits ==="

# File handle limits
echo "Setting file handle limits..."
if ! grep -q "soft nofile 65535" /etc/security/limits.conf; then
    echo "* soft nofile 65535" >> /etc/security/limits.conf
    echo "* hard nofile 65535" >> /etc/security/limits.conf
fi

if ! grep -q "fs.file-max = 2097152" /etc/sysctl.conf; then
    echo "fs.file-max = 2097152" >> /etc/sysctl.conf
fi

# Apply sysctl changes
sysctl -p

# Create data directories
echo "Creating data directories..."
mkdir -p /var/lib/saorsa/nodes

# Set ulimit for current session
ulimit -n 65535 2>/dev/null || true

echo "=== System limits configured ==="
echo "Current file limit: $(ulimit -n)"
