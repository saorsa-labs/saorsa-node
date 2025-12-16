#!/bin/bash
# Start all saorsa nodes with staggered timing to avoid thundering herd
# Usage: ./start-nodes.sh [start_index] [count]

set -e

START_INDEX=${1:-0}
COUNT=${2:-50}
END_INDEX=$((START_INDEX + COUNT - 1))

echo "=== Starting Saorsa Nodes ==="
echo "Starting nodes ${START_INDEX} to ${END_INDEX}"

for i in $(seq $START_INDEX $END_INDEX); do
    echo "Starting saorsa-node-${i}..."
    systemctl enable --now saorsa-node-${i}
    sleep 0.5  # Stagger to avoid thundering herd
done

echo "=== All nodes started ==="
echo "Check status with: ./check-health.sh"
