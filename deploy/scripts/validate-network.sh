#!/bin/bash
# Saorsa Network Validator - Checks health of entire testnet
# Usage: ./validate-network.sh [worker_ips_file]
set -euo pipefail

WORKERS_FILE="${1:-/etc/saorsa/workers.json}"
NODES_PER_WORKER="${NODES_PER_WORKER:-100}"
METRICS_BASE_PORT="${METRICS_BASE_PORT:-9100}"

# Thresholds
MIN_PEERS=3
MIN_DHT_SIZE=20
HEALTH_THRESHOLD=0.99  # 99% nodes healthy

echo "=== Saorsa Testnet Validator ==="
echo "Nodes per worker: $NODES_PER_WORKER"
echo "Min peers: $MIN_PEERS"
echo "Min DHT size: $MIN_DHT_SIZE"
echo ""

# Check if workers file exists
if [[ ! -f "$WORKERS_FILE" ]]; then
    echo "Workers file not found: $WORKERS_FILE"
    echo "Checking localhost only..."
    WORKERS=("localhost")
else
    # Parse workers file (JSON array of IPs)
    mapfile -t WORKERS < <(jq -r '.[]' "$WORKERS_FILE" 2>/dev/null || echo "localhost")
fi

echo "Workers to check: ${WORKERS[*]}"
echo ""

# Initialize counters
TOTAL_NODES=0
HEALTHY_NODES=0
UNHEALTHY_NODES=0
LOW_PEER_NODES=0
LOW_DHT_NODES=0

# Detailed issues
declare -a ISSUES=()

# Check each worker
for worker in "${WORKERS[@]}"; do
    echo "Checking worker: $worker"
    WORKER_HEALTHY=0
    WORKER_UNHEALTHY=0

    for i in $(seq 0 $((NODES_PER_WORKER - 1))); do
        ((TOTAL_NODES++)) || true
        PORT=$((METRICS_BASE_PORT + i))

        # Fetch metrics
        METRICS=$(curl -s --max-time 5 "http://$worker:$PORT/metrics" 2>/dev/null || echo "")

        if [[ -z "$METRICS" ]]; then
            ((UNHEALTHY_NODES++)) || true
            ((WORKER_UNHEALTHY++)) || true
            ISSUES+=("$worker:$PORT - No response")
            continue
        fi

        # Parse metrics
        HEALTH=$(echo "$METRICS" | grep -E "^p2p_health_status" | awk '{print $2}' || echo "0")
        PEERS=$(echo "$METRICS" | grep -E "^p2p_network_peer_count" | awk '{print $2}' || echo "0")
        DHT_SIZE=$(echo "$METRICS" | grep -E "^p2p_dht_routing_table_size" | awk '{print $2}' || echo "0")
        UPTIME=$(echo "$METRICS" | grep -E "^p2p_uptime_seconds" | awk '{print $2}' || echo "0")

        # Check health
        if [[ "$HEALTH" != "1" ]]; then
            ((UNHEALTHY_NODES++)) || true
            ((WORKER_UNHEALTHY++)) || true
            ISSUES+=("$worker:$PORT - Unhealthy (peers: $PEERS, dht: $DHT_SIZE)")
        else
            ((HEALTHY_NODES++)) || true
            ((WORKER_HEALTHY++)) || true
        fi

        # Check peers
        if (( $(echo "$PEERS < $MIN_PEERS" | bc -l) )); then
            ((LOW_PEER_NODES++)) || true
            ISSUES+=("$worker:$PORT - Low peers: $PEERS < $MIN_PEERS")
        fi

        # Check DHT
        if (( $(echo "$DHT_SIZE < $MIN_DHT_SIZE" | bc -l) )); then
            ((LOW_DHT_NODES++)) || true
            ISSUES+=("$worker:$PORT - Low DHT: $DHT_SIZE < $MIN_DHT_SIZE")
        fi
    done

    echo "  Healthy: $WORKER_HEALTHY/$NODES_PER_WORKER"
    echo "  Unhealthy: $WORKER_UNHEALTHY"
done

echo ""
echo "=== Summary ==="
echo "Total nodes: $TOTAL_NODES"
echo "Healthy: $HEALTHY_NODES"
echo "Unhealthy: $UNHEALTHY_NODES"
echo "Low peer count: $LOW_PEER_NODES"
echo "Low DHT size: $LOW_DHT_NODES"

# Calculate health percentage
if (( TOTAL_NODES > 0 )); then
    HEALTH_PCT=$(echo "scale=4; $HEALTHY_NODES / $TOTAL_NODES" | bc -l)
    echo ""
    echo "Health percentage: $(echo "scale=2; $HEALTH_PCT * 100" | bc -l)%"

    # Check against threshold
    PASS=$(echo "$HEALTH_PCT >= $HEALTH_THRESHOLD" | bc -l)

    if (( PASS )); then
        echo ""
        echo "✅ VALIDATION PASSED"
        EXIT_CODE=0
    else
        echo ""
        echo "❌ VALIDATION FAILED - Below $(($(echo "$HEALTH_THRESHOLD * 100" | bc -l | cut -d'.' -f1)))% threshold"
        EXIT_CODE=1
    fi
else
    echo ""
    echo "❌ VALIDATION FAILED - No nodes found"
    EXIT_CODE=1
fi

# Print issues if any
if (( ${#ISSUES[@]} > 0 )); then
    echo ""
    echo "=== Issues (first 20) ==="
    for issue in "${ISSUES[@]:0:20}"; do
        echo "  - $issue"
    done
    if (( ${#ISSUES[@]} > 20 )); then
        echo "  ... and $((${#ISSUES[@]} - 20)) more issues"
    fi
fi

exit $EXIT_CODE
