#!/bin/bash
# Run comprehensive data type tests against live testnet
# Usage: ./scripts/testnet/run-data-tests.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

# Testnet bootstrap nodes
export SAORSA_TEST_BOOTSTRAP="142.93.52.129:12000,24.199.82.114:12000"
export SAORSA_TEST_EXTERNAL=true
export RUST_LOG=info

echo "=== Saorsa Testnet Data Type Tests ==="
echo "Bootstrap: $SAORSA_TEST_BOOTSTRAP"
echo ""

# Check cluster health first
echo "--- Checking Cluster Health ---"
for IP in 142.93.52.129 24.199.82.114 192.34.62.192 159.223.131.196; do
    RUNNING=$(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@$IP "pgrep -c saorsa-node 2>/dev/null" 2>/dev/null || echo "0")
    echo "$IP: $RUNNING nodes running"
done
echo ""

# Run the comprehensive tests
echo "--- Running Comprehensive Data Tests ---"
echo ""

cargo test --release --test e2e run_comprehensive_data_tests -- --ignored --nocapture 2>&1 | tee testnet-logs/data-tests-$(date +%Y%m%d-%H%M%S).log

echo ""
echo "=== Test Complete ==="
