#!/bin/bash
# Check health of all saorsa nodes on this droplet
# Usage: ./check-health.sh [start_index] [count]

START_INDEX=${1:-0}
COUNT=${2:-50}
END_INDEX=$((START_INDEX + COUNT - 1))

HEALTHY=0
UNHEALTHY=0
UNREACHABLE=0

echo "=== Saorsa Node Health Check ==="
echo "Checking nodes ${START_INDEX} to ${END_INDEX}"
echo ""

for i in $(seq $START_INDEX $END_INDEX); do
    PORT=$((9100 + i - START_INDEX))

    # Check if service is running
    if ! systemctl is-active --quiet saorsa-node-${i}; then
        echo "Node $i: SERVICE NOT RUNNING"
        ((UNREACHABLE++))
        continue
    fi

    # Check metrics endpoint
    RESPONSE=$(curl -s --connect-timeout 2 "http://localhost:${PORT}/metrics" 2>/dev/null)

    if [ -z "$RESPONSE" ]; then
        echo "Node $i: METRICS UNREACHABLE (port $PORT)"
        ((UNREACHABLE++))
        continue
    fi

    # Parse key metrics
    HEALTH=$(echo "$RESPONSE" | grep "p2p_health_status" | awk '{print $2}' | head -1)
    PEERS=$(echo "$RESPONSE" | grep "peer_count" | awk '{print $2}' | head -1)
    ROUTING=$(echo "$RESPONSE" | grep "routing_table_size" | awk '{print $2}' | head -1)
    VERSION=$(echo "$RESPONSE" | grep "saorsa_version" | head -1)

    if [ "$HEALTH" = "1" ]; then
        echo "Node $i: HEALTHY (peers: ${PEERS:-?}, routing: ${ROUTING:-?})"
        ((HEALTHY++))
    else
        echo "Node $i: UNHEALTHY (health: ${HEALTH:-?}, peers: ${PEERS:-?})"
        ((UNHEALTHY++))
    fi
done

echo ""
echo "=== Summary ==="
echo "Healthy:     $HEALTHY"
echo "Unhealthy:   $UNHEALTHY"
echo "Unreachable: $UNREACHABLE"
echo "Total:       $COUNT"
echo ""

# Calculate health percentage
if [ $COUNT -gt 0 ]; then
    PERCENT=$((HEALTHY * 100 / COUNT))
    echo "Health Rate: ${PERCENT}%"

    if [ $PERCENT -ge 95 ]; then
        echo "Status: GOOD"
        exit 0
    elif [ $PERCENT -ge 80 ]; then
        echo "Status: ACCEPTABLE"
        exit 0
    else
        echo "Status: DEGRADED"
        exit 1
    fi
fi
