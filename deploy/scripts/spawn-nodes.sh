#!/bin/bash
# Saorsa Node Spawner - Deploy multiple nodes on a single host
# Usage: ./spawn-nodes.sh [count] [bootstrap1] [bootstrap2] ...
set -euo pipefail

# Configuration
NODE_COUNT="${1:-10}"
shift || true
BOOTSTRAP_NODES=("${@:-165.22.4.178:12000 164.92.111.156:12000}")

# Directories
BASE_DIR="/var/lib/saorsa/nodes"
LOG_DIR="/var/log/saorsa"
BINARY_PATH="${SAORSA_BINARY:-/usr/local/bin/saorsa-node}"
METRICS_BASE_PORT="${METRICS_BASE_PORT:-9100}"

# Resource limits per node
MEMORY_LIMIT="350M"
CPU_QUOTA="15%"

echo "=== Saorsa Multi-Node Spawner ==="
echo "Nodes to spawn: $NODE_COUNT"
echo "Bootstrap nodes: ${BOOTSTRAP_NODES[*]}"
echo "Binary: $BINARY_PATH"
echo "Base directory: $BASE_DIR"
echo ""

# Check binary exists
if [[ ! -x "$BINARY_PATH" ]]; then
    echo "ERROR: saorsa-node binary not found at $BINARY_PATH"
    echo "Set SAORSA_BINARY environment variable or install to /usr/local/bin/"
    exit 1
fi

# Create directories
mkdir -p "$BASE_DIR" "$LOG_DIR"

# Create saorsa user if not exists
if ! id -u saorsa &>/dev/null; then
    useradd -r -s /bin/false saorsa || true
fi

# Build bootstrap args
BOOTSTRAP_ARGS=""
for bs in "${BOOTSTRAP_NODES[@]}"; do
    BOOTSTRAP_ARGS="$BOOTSTRAP_ARGS --bootstrap $bs"
done

# Spawn nodes
for i in $(seq 0 $((NODE_COUNT - 1))); do
    NODE_DIR="$BASE_DIR/node-$i"
    METRICS_PORT=$((METRICS_BASE_PORT + i))
    SERVICE_NAME="saorsa-node-$i"

    echo "Creating node $i..."

    # Create node directory
    mkdir -p "$NODE_DIR"
    chown saorsa:saorsa "$NODE_DIR"

    # Create systemd service
    cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=Saorsa Node $i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=saorsa
Group=saorsa
ExecStart=$BINARY_PATH \\
    --root-dir $NODE_DIR \\
    --port 0 \\
    --metrics-port $METRICS_PORT \\
    --log-level info \\
    $BOOTSTRAP_ARGS
Restart=always
RestartSec=10

# Resource limits
MemoryMax=$MEMORY_LIMIT
CPUQuota=$CPU_QUOTA

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$NODE_DIR
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

# Logging
StandardOutput=append:$LOG_DIR/node-$i.log
StandardError=append:$LOG_DIR/node-$i.log

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload

    # Enable and start service
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"

    echo "  Started node $i on metrics port $METRICS_PORT"

    # Stagger starts to avoid overwhelming bootstrap nodes
    sleep 0.5
done

echo ""
echo "=== Deployment Complete ==="
echo "Spawned $NODE_COUNT nodes"
echo ""
echo "Check status with:"
echo "  systemctl status 'saorsa-node-*'"
echo "  ./manage-nodes.sh status"
echo ""
echo "View logs:"
echo "  journalctl -u saorsa-node-0 -f"
echo "  tail -f $LOG_DIR/node-0.log"
