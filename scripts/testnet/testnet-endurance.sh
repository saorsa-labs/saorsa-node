#!/bin/bash
# Testnet endurance test - runs data type tests in a loop for 12-24 hours
# Run from the saorsa-node project root
# Usage: ./scripts/testnet/testnet-endurance.sh [duration_hours]

set -e

DURATION_HOURS=${1:-24}
BOOTSTRAP="142.93.52.129:12000,24.199.82.114:12000"
START=$(date +%s)
END=$((START + DURATION_HOURS * 3600))
ITERATION=0
FAILURES=0
SUCCESSES=0

LOG_DIR="testnet-logs"
LOG_FILE="${LOG_DIR}/endurance-$(date +%Y%m%d-%H%M%S).log"

# Ensure we're in the project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

mkdir -p "$LOG_DIR"

echo "=== Saorsa Testnet Endurance Test ===" | tee -a "$LOG_FILE"
echo "Duration: ${DURATION_HOURS} hours" | tee -a "$LOG_FILE"
echo "Bootstrap: ${BOOTSTRAP}" | tee -a "$LOG_FILE"
echo "Log file: ${LOG_FILE}" | tee -a "$LOG_FILE"
echo "Start time: $(date)" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Build the test binary if needed
echo "Building test binary..." | tee -a "$LOG_FILE"
cargo build --release 2>&1 | tee -a "$LOG_FILE"

# Export test configuration
export SAORSA_TEST_BOOTSTRAP="$BOOTSTRAP"
export SAORSA_TEST_EXTERNAL=true
export RUST_LOG=info

while [ $(date +%s) -lt $END ]; do
    ((ITERATION++))
    ITER_START=$(date +%s)

    echo "" | tee -a "$LOG_FILE"
    echo "=============================================" | tee -a "$LOG_FILE"
    echo "=== Iteration $ITERATION at $(date) ===" | tee -a "$LOG_FILE"
    echo "=============================================" | tee -a "$LOG_FILE"

    # Run all data type tests (unit tests as sanity check)
    echo "--- Running data type unit tests ---" | tee -a "$LOG_FILE"
    if cargo test --release data_types -- --nocapture 2>&1 | tee -a "$LOG_FILE"; then
        ((SUCCESSES++))
        echo "✓ Unit tests passed" | tee -a "$LOG_FILE"
    else
        ((FAILURES++))
        echo "✗ Unit tests failed (iteration $ITERATION)" | tee -a "$LOG_FILE"
    fi

    # Collect metrics from first available node
    echo "--- Collecting metrics snapshot ---" | tee -a "$LOG_FILE"
    for PORT in 9100 9101 9102; do
        METRICS=$(curl -s --connect-timeout 5 "http://165.22.4.178:${PORT}/metrics" 2>/dev/null | head -50)
        if [ -n "$METRICS" ]; then
            echo "$METRICS" | grep -E "^(saorsa_|p2p_|peer_|routing_)" >> "$LOG_FILE"
            break
        fi
    done

    # Calculate iteration duration
    ITER_END=$(date +%s)
    ITER_DURATION=$((ITER_END - ITER_START))

    # Calculate progress
    ELAPSED=$((ITER_END - START))
    REMAINING=$((END - ITER_END))
    PERCENT=$((ELAPSED * 100 / (DURATION_HOURS * 3600)))

    echo "" | tee -a "$LOG_FILE"
    echo "--- Iteration $ITERATION Summary ---" | tee -a "$LOG_FILE"
    echo "Duration: ${ITER_DURATION}s" | tee -a "$LOG_FILE"
    echo "Progress: ${PERCENT}% (${REMAINING}s remaining)" | tee -a "$LOG_FILE"
    echo "Success rate: $SUCCESSES / $ITERATION ($((SUCCESSES * 100 / ITERATION))%)" | tee -a "$LOG_FILE"

    # Check cluster health
    echo "--- Cluster Health Check ---" | tee -a "$LOG_FILE"
    ./scripts/testnet/check-all.sh 2>&1 | tee -a "$LOG_FILE" || true

    # Sleep between iterations (5 minutes)
    if [ $(date +%s) -lt $END ]; then
        echo "Sleeping 5 minutes before next iteration..." | tee -a "$LOG_FILE"
        sleep 300
    fi
done

# Final summary
echo "" | tee -a "$LOG_FILE"
echo "=============================================" | tee -a "$LOG_FILE"
echo "=== Endurance Test Complete ===" | tee -a "$LOG_FILE"
echo "=============================================" | tee -a "$LOG_FILE"
echo "End time: $(date)" | tee -a "$LOG_FILE"
echo "Total iterations: $ITERATION" | tee -a "$LOG_FILE"
echo "Successes: $SUCCESSES" | tee -a "$LOG_FILE"
echo "Failures: $FAILURES" | tee -a "$LOG_FILE"
if [ $ITERATION -gt 0 ]; then
    echo "Success rate: $((SUCCESSES * 100 / ITERATION))%" | tee -a "$LOG_FILE"
fi
echo "" | tee -a "$LOG_FILE"

# Final cluster health
echo "=== Final Cluster Status ===" | tee -a "$LOG_FILE"
./scripts/testnet/check-all.sh 2>&1 | tee -a "$LOG_FILE" || true

echo "" | tee -a "$LOG_FILE"
echo "Log file saved to: $LOG_FILE"
