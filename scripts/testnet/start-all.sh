#!/bin/bash
# Start all saorsa nodes across all testnet droplets
# Run from local machine

set -e

WORKERS=(
    "142.93.52.129"   # saorsa-worker-1
    "24.199.82.114"   # saorsa-worker-2
    "192.34.62.192"   # saorsa-worker-3
    "159.223.131.196" # saorsa-worker-4
)

echo "=== Starting All Testnet Nodes ==="

for i in "${!WORKERS[@]}"; do
    IP="${WORKERS[$i]}"
    WORKER_NUM=$((i + 1))
    START_INDEX=$((i * 50))

    echo "Starting nodes on saorsa-worker-${WORKER_NUM} ($IP)..."
    ssh -o StrictHostKeyChecking=no "root@${IP}" "/usr/local/bin/start-nodes.sh ${START_INDEX} 50" &
done

# Wait for all SSH commands to complete
wait

echo ""
echo "=== All nodes starting ==="
echo "Wait 5-10 minutes for network stabilization"
echo "Then run: ./check-all.sh"
