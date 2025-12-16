#!/bin/bash
# Start genesis bootstrap nodes (node-0 on worker-1, node-50 on worker-2)
# These nodes start first and form the initial network

set -e

WORKER1="142.93.52.129"
WORKER2="24.199.82.114"

echo "=== Starting Genesis Bootstrap Nodes ==="

# Create genesis node-0 on worker-1 (no bootstrap peers needed)
echo "Creating genesis node-0 on worker-1..."
ssh -o StrictHostKeyChecking=no root@${WORKER1} "
    mkdir -p /var/lib/saorsa/nodes/node-0
    cat > /etc/systemd/system/saorsa-node-0.service <<'EOF'
[Unit]
Description=Saorsa Genesis Node 0
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/saorsa-node \
    --root-dir /var/lib/saorsa/nodes/node-0 \
    --port 12000 \
    --ip-version ipv4 \
    --metrics-port 9100 \
    --log-level info \
    --auto-upgrade \
    --upgrade-channel stable \
    --evm-network arbitrum-sepolia \
    --disable-payment-verification
Restart=on-failure
RestartSec=5
MemoryMax=300M
CPUQuota=15%

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable saorsa-node-0
    systemctl start saorsa-node-0
"

# Wait for node-0 to start
echo "Waiting for node-0 to initialize..."
sleep 10

# Check if node-0 is running
echo "Checking node-0 status..."
ssh -o StrictHostKeyChecking=no root@${WORKER1} "systemctl is-active saorsa-node-0 && echo 'Node-0 is running!' || echo 'Node-0 failed to start'"

# Create genesis node-50 on worker-2 (bootstrap to node-0)
echo "Creating genesis node-50 on worker-2..."
ssh -o StrictHostKeyChecking=no root@${WORKER2} "
    mkdir -p /var/lib/saorsa/nodes/node-50
    cat > /etc/systemd/system/saorsa-node-50.service <<'EOF'
[Unit]
Description=Saorsa Genesis Node 50
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/saorsa-node \
    --root-dir /var/lib/saorsa/nodes/node-50 \
    --port 12000 \
    --ip-version ipv4 \
    -b 142.93.52.129:12000 \
    --metrics-port 9100 \
    --log-level info \
    --auto-upgrade \
    --upgrade-channel stable \
    --evm-network arbitrum-sepolia \
    --disable-payment-verification
Restart=on-failure
RestartSec=5
MemoryMax=300M
CPUQuota=15%

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable saorsa-node-50
    systemctl start saorsa-node-50
"

# Wait for node-50 to start
echo "Waiting for node-50 to initialize..."
sleep 10

# Check if node-50 is running
echo "Checking node-50 status..."
ssh -o StrictHostKeyChecking=no root@${WORKER2} "systemctl is-active saorsa-node-50 && echo 'Node-50 is running!' || echo 'Node-50 failed to start'"

echo ""
echo "=== Genesis Bootstrap Complete ==="
echo "Genesis nodes:"
echo "  - node-0: ${WORKER1}:12000"
echo "  - node-50: ${WORKER2}:12000"
echo ""
echo "Now run ./start-remaining.sh to start the other 198 nodes"
