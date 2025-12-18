#!/bin/bash
# Spawn 50 saorsa nodes on a single droplet
# Usage: ./spawn-nodes.sh [start_index]
#
# start_index: Optional starting index for node numbering (default: 0)
#              Use this to avoid port conflicts when running multiple batches

set -e

NODE_COUNT=50
BASE_PORT=12000
METRICS_BASE=9100
# Use worker-1 and worker-2 as bootstrap nodes
BOOTSTRAP1="142.93.52.129:12000"
BOOTSTRAP2="24.199.82.114:12000"
START_INDEX=${1:-0}

echo "=== Saorsa Node Spawner ==="
echo "Creating $NODE_COUNT nodes starting at index $START_INDEX"
echo "Bootstrap nodes: $BOOTSTRAP1, $BOOTSTRAP2"

# Create data directory
mkdir -p /var/lib/saorsa/nodes

for i in $(seq 0 $((NODE_COUNT - 1))); do
    NODE_INDEX=$((START_INDEX + i))
    NODE_DIR="/var/lib/saorsa/nodes/node-${NODE_INDEX}"
    PORT=$((BASE_PORT + i))
    METRICS=$((METRICS_BASE + i))

    mkdir -p "$NODE_DIR"

    echo "Creating systemd service for node-${NODE_INDEX} (port $PORT, metrics $METRICS)"

    # Determine bootstrap flags based on node index
    # Node 0 (worker-1 bootstrap) only connects to BOOTSTRAP2 (worker-2)
    # Node 50 (worker-2 bootstrap) only connects to BOOTSTRAP1 (worker-1)
    # All other nodes connect to both bootstrap nodes
    BOOTSTRAP_FLAGS=""
    if [ "$NODE_INDEX" -eq 0 ]; then
        # Primary bootstrap - only connect to secondary (worker-2)
        BOOTSTRAP_FLAGS="-b ${BOOTSTRAP2}"
    elif [ "$NODE_INDEX" -eq 50 ]; then
        # Secondary bootstrap - only connect to primary (worker-1)
        BOOTSTRAP_FLAGS="-b ${BOOTSTRAP1}"
    else
        # All other nodes connect to both bootstraps
        BOOTSTRAP_FLAGS="-b ${BOOTSTRAP1} -b ${BOOTSTRAP2}"
    fi

    cat > /etc/systemd/system/saorsa-node-${NODE_INDEX}.service <<EOF
[Unit]
Description=Saorsa Node ${NODE_INDEX}
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/saorsa-node \\
    --root-dir ${NODE_DIR} \\
    --port ${PORT} \\
    --ip-version ipv4 \\
    --network-mode testnet \\
    ${BOOTSTRAP_FLAGS} \\
    --metrics-port ${METRICS} \\
    --log-level info \\
    --auto-upgrade \\
    --upgrade-channel stable \\
    --evm-network arbitrum-sepolia \\
    --disable-payment-verification
Restart=on-failure
RestartSec=5
MemoryMax=300M
CPUQuota=15%

[Install]
WantedBy=multi-user.target
EOF
done

echo "Reloading systemd daemon..."
systemctl daemon-reload

echo "=== Done creating ${NODE_COUNT} node services ==="
echo "To start all nodes: ./start-nodes.sh"
