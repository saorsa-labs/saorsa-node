#!/bin/bash
# Saorsa Node Manager - Start/stop/status for multiple nodes
# Usage: ./manage-nodes.sh [action] [options]
set -euo pipefail

ACTION="${1:-status}"
NODE_PATTERN="${2:-saorsa-node-*}"
METRICS_BASE_PORT="${METRICS_BASE_PORT:-9100}"

# Count nodes by matching systemd services
get_node_count() {
    systemctl list-units --all --type=service \
        | grep -c "saorsa-node-[0-9]" || echo "0"
}

# Get list of node indices
get_node_indices() {
    systemctl list-units --all --type=service \
        | grep "saorsa-node-[0-9]" \
        | sed 's/.*saorsa-node-\([0-9]*\).*/\1/' \
        | sort -n
}

case "$ACTION" in
    start)
        echo "Starting all saorsa nodes..."
        for i in $(get_node_indices); do
            systemctl start "saorsa-node-$i" 2>/dev/null || true
        done
        echo "Started $(get_node_count) nodes"
        ;;

    stop)
        echo "Stopping all saorsa nodes..."
        for i in $(get_node_indices); do
            systemctl stop "saorsa-node-$i" 2>/dev/null || true
        done
        echo "Stopped all nodes"
        ;;

    restart)
        echo "Restarting all saorsa nodes..."
        for i in $(get_node_indices); do
            systemctl restart "saorsa-node-$i" 2>/dev/null || true
            sleep 0.2  # Stagger restarts
        done
        echo "Restarted $(get_node_count) nodes"
        ;;

    status)
        TOTAL=$(get_node_count)
        RUNNING=0
        FAILED=0
        FAILED_NODES=""

        for i in $(get_node_indices); do
            if systemctl is-active --quiet "saorsa-node-$i"; then
                ((RUNNING++)) || true
            else
                ((FAILED++)) || true
                FAILED_NODES="$FAILED_NODES $i"
            fi
        done

        echo "=== Saorsa Node Status ==="
        echo "Total nodes: $TOTAL"
        echo "Running: $RUNNING"
        echo "Failed: $FAILED"
        if [[ -n "$FAILED_NODES" ]]; then
            echo "Failed nodes:$FAILED_NODES"
        fi
        echo ""
        echo "Use 'systemctl status saorsa-node-N' for individual node details"
        ;;

    health)
        echo "=== Node Health Check ==="
        HEALTHY=0
        UNHEALTHY=0

        for i in $(get_node_indices); do
            PORT=$((METRICS_BASE_PORT + i))
            HEALTH=$(curl -s --max-time 2 "http://localhost:$PORT/metrics" 2>/dev/null \
                | grep -E "^p2p_health_status" | awk '{print $2}' || echo "0")

            if [[ "$HEALTH" == "1" ]]; then
                ((HEALTHY++)) || true
            else
                ((UNHEALTHY++)) || true
                # Get more details for unhealthy nodes
                if systemctl is-active --quiet "saorsa-node-$i"; then
                    PEERS=$(curl -s --max-time 2 "http://localhost:$PORT/metrics" 2>/dev/null \
                        | grep -E "^p2p_network_peer_count" | awk '{print $2}' || echo "?")
                    echo "Node $i (port $PORT): unhealthy (peers: $PEERS)"
                else
                    echo "Node $i (port $PORT): service not running"
                fi
            fi
        done

        echo ""
        echo "Healthy: $HEALTHY"
        echo "Unhealthy: $UNHEALTHY"
        ;;

    peers)
        echo "=== Peer Counts ==="
        for i in $(get_node_indices); do
            PORT=$((METRICS_BASE_PORT + i))
            PEERS=$(curl -s --max-time 2 "http://localhost:$PORT/metrics" 2>/dev/null \
                | grep -E "^p2p_network_peer_count" | awk '{print $2}' || echo "?")
            printf "Node %3d: %s peers\n" "$i" "$PEERS"
        done
        ;;

    dht)
        echo "=== DHT Routing Table Sizes ==="
        for i in $(get_node_indices); do
            PORT=$((METRICS_BASE_PORT + i))
            DHT_SIZE=$(curl -s --max-time 2 "http://localhost:$PORT/metrics" 2>/dev/null \
                | grep -E "^p2p_dht_routing_table_size" | awk '{print $2}' || echo "?")
            printf "Node %3d: %s entries\n" "$i" "$DHT_SIZE"
        done
        ;;

    logs)
        NODE_ID="${2:-0}"
        echo "=== Logs for node $NODE_ID ==="
        journalctl -u "saorsa-node-$NODE_ID" -f --no-pager
        ;;

    cleanup)
        echo "Cleaning up all saorsa nodes..."

        # Stop all nodes
        for i in $(get_node_indices); do
            systemctl stop "saorsa-node-$i" 2>/dev/null || true
            systemctl disable "saorsa-node-$i" 2>/dev/null || true
            rm -f "/etc/systemd/system/saorsa-node-$i.service"
        done

        systemctl daemon-reload

        # Remove data directories
        rm -rf /var/lib/saorsa/nodes
        rm -rf /var/log/saorsa

        echo "Cleanup complete"
        ;;

    *)
        echo "Usage: $0 {start|stop|restart|status|health|peers|dht|logs [node_id]|cleanup}"
        echo ""
        echo "Commands:"
        echo "  start    - Start all nodes"
        echo "  stop     - Stop all nodes"
        echo "  restart  - Restart all nodes (staggered)"
        echo "  status   - Show running/failed counts"
        echo "  health   - Check node health via metrics"
        echo "  peers    - Show peer counts for all nodes"
        echo "  dht      - Show DHT routing table sizes"
        echo "  logs N   - Follow logs for node N"
        echo "  cleanup  - Remove all nodes and data"
        exit 1
        ;;
esac
