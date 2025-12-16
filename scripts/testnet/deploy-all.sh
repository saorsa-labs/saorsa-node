#!/bin/bash
# Deploy saorsa-node to all testnet droplets
# Run from local machine with SSH access to droplets

set -e

# Droplet IPs
WORKERS=(
    "142.93.52.129"   # saorsa-worker-1
    "24.199.82.114"   # saorsa-worker-2
    "192.34.62.192"   # saorsa-worker-3
    "159.223.131.196" # saorsa-worker-4
)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_URL="https://github.com/dirvine/saorsa-node/releases/download/v0.2.0/saorsa-node-cli-linux-x64.tar.gz"

echo "=== Saorsa Testnet Deployment ==="
echo "Deploying to ${#WORKERS[@]} droplets"
echo ""

for i in "${!WORKERS[@]}"; do
    IP="${WORKERS[$i]}"
    WORKER_NUM=$((i + 1))

    echo "=== Deploying to saorsa-worker-${WORKER_NUM} ($IP) ==="

    # Copy scripts
    echo "Copying scripts..."
    scp -o StrictHostKeyChecking=no \
        "$SCRIPT_DIR/setup-limits.sh" \
        "$SCRIPT_DIR/spawn-nodes.sh" \
        "$SCRIPT_DIR/start-nodes.sh" \
        "$SCRIPT_DIR/check-health.sh" \
        "root@${IP}:/usr/local/bin/"

    # Make scripts executable
    ssh -o StrictHostKeyChecking=no "root@${IP}" "chmod +x /usr/local/bin/*.sh"

    # Download and install binary
    echo "Downloading and installing saorsa-node..."
    ssh -o StrictHostKeyChecking=no "root@${IP}" "
        cd /tmp
        curl -sL '${BINARY_URL}' -o saorsa-node.tar.gz
        tar xzf saorsa-node.tar.gz
        mv saorsa-node /usr/local/bin/
        mv saorsa-keygen /usr/local/bin/ 2>/dev/null || true
        chmod +x /usr/local/bin/saorsa-node
        rm -f saorsa-node.tar.gz
        /usr/local/bin/saorsa-node --version
    "

    # Configure system limits
    echo "Configuring system limits..."
    ssh -o StrictHostKeyChecking=no "root@${IP}" "/usr/local/bin/setup-limits.sh"

    # Create systemd services
    echo "Creating node services..."
    ssh -o StrictHostKeyChecking=no "root@${IP}" "/usr/local/bin/spawn-nodes.sh $((i * 50))"

    echo "Worker ${WORKER_NUM} ready!"
    echo ""
done

echo "=== Deployment Complete ==="
echo "To start all nodes, run: ./start-all.sh"
