#!/bin/bash
# Check health of all saorsa nodes across all testnet droplets
# Run from local machine

WORKERS=(
    "142.93.52.129"   # saorsa-worker-1
    "24.199.82.114"   # saorsa-worker-2
    "192.34.62.192"   # saorsa-worker-3
    "159.223.131.196" # saorsa-worker-4
)

TOTAL_HEALTHY=0
TOTAL_UNHEALTHY=0
TOTAL_UNREACHABLE=0

echo "=== Saorsa Testnet Health Check ==="
echo ""

for i in "${!WORKERS[@]}"; do
    IP="${WORKERS[$i]}"
    WORKER_NUM=$((i + 1))
    START_INDEX=$((i * 50))

    echo "--- saorsa-worker-${WORKER_NUM} ($IP) ---"

    # Run health check remotely
    RESULT=$(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "root@${IP}" \
        "/usr/local/bin/check-health.sh ${START_INDEX} 50 2>/dev/null" 2>/dev/null)

    if [ -z "$RESULT" ]; then
        echo "DROPLET UNREACHABLE"
        TOTAL_UNREACHABLE=$((TOTAL_UNREACHABLE + 50))
    else
        echo "$RESULT" | tail -10

        # Parse summary
        HEALTHY=$(echo "$RESULT" | grep "^Healthy:" | awk '{print $2}')
        UNHEALTHY=$(echo "$RESULT" | grep "^Unhealthy:" | awk '{print $2}')
        UNREACHABLE=$(echo "$RESULT" | grep "^Unreachable:" | awk '{print $2}')

        TOTAL_HEALTHY=$((TOTAL_HEALTHY + ${HEALTHY:-0}))
        TOTAL_UNHEALTHY=$((TOTAL_UNHEALTHY + ${UNHEALTHY:-0}))
        TOTAL_UNREACHABLE=$((TOTAL_UNREACHABLE + ${UNREACHABLE:-0}))
    fi
    echo ""
done

TOTAL=$((TOTAL_HEALTHY + TOTAL_UNHEALTHY + TOTAL_UNREACHABLE))

echo "=========================================="
echo "=== CLUSTER SUMMARY ==="
echo "=========================================="
echo "Total Healthy:     $TOTAL_HEALTHY"
echo "Total Unhealthy:   $TOTAL_UNHEALTHY"
echo "Total Unreachable: $TOTAL_UNREACHABLE"
echo "Total Nodes:       $TOTAL"
echo ""

if [ $TOTAL -gt 0 ]; then
    PERCENT=$((TOTAL_HEALTHY * 100 / TOTAL))
    echo "Overall Health Rate: ${PERCENT}%"

    if [ $PERCENT -ge 95 ]; then
        echo "Cluster Status: EXCELLENT"
    elif [ $PERCENT -ge 80 ]; then
        echo "Cluster Status: GOOD"
    elif [ $PERCENT -ge 50 ]; then
        echo "Cluster Status: DEGRADED"
    else
        echo "Cluster Status: CRITICAL"
    fi
fi
