#!/bin/bash
# Start remaining 198 nodes (all except genesis nodes 0 and 50)
# Run this after start-genesis.sh

set -e

WORKERS=(
    "142.93.52.129"   # saorsa-worker-1 (nodes 1-49)
    "24.199.82.114"   # saorsa-worker-2 (nodes 51-99)
    "192.34.62.192"   # saorsa-worker-3 (nodes 100-149)
    "159.223.131.196" # saorsa-worker-4 (nodes 150-199)
)

echo "=== Starting Remaining Nodes ==="

# Start nodes on worker-1 (nodes 1-49, skipping genesis node-0)
echo "Starting nodes 1-49 on worker-1..."
ssh -o StrictHostKeyChecking=no root@${WORKERS[0]} "
    for i in \$(seq 1 49); do
        systemctl start saorsa-node-\${i} 2>/dev/null || true
        sleep 0.5
    done
    echo 'Worker-1 nodes started'
" &

# Start nodes on worker-2 (nodes 51-99, skipping genesis node-50)
echo "Starting nodes 51-99 on worker-2..."
ssh -o StrictHostKeyChecking=no root@${WORKERS[1]} "
    for i in \$(seq 51 99); do
        systemctl start saorsa-node-\${i} 2>/dev/null || true
        sleep 0.5
    done
    echo 'Worker-2 nodes started'
" &

# Start nodes on worker-3 (nodes 100-149)
echo "Starting nodes 100-149 on worker-3..."
ssh -o StrictHostKeyChecking=no root@${WORKERS[2]} "
    for i in \$(seq 100 149); do
        systemctl start saorsa-node-\${i} 2>/dev/null || true
        sleep 0.5
    done
    echo 'Worker-3 nodes started'
" &

# Start nodes on worker-4 (nodes 150-199)
echo "Starting nodes 150-199 on worker-4..."
ssh -o StrictHostKeyChecking=no root@${WORKERS[3]} "
    for i in \$(seq 150 199); do
        systemctl start saorsa-node-\${i} 2>/dev/null || true
        sleep 0.5
    done
    echo 'Worker-4 nodes started'
" &

# Wait for all to complete
wait

echo ""
echo "=== All nodes started ==="
echo "Run ./check-all.sh to verify network health"
