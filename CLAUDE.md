# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

saorsa-node is the core P2P network node binary for the Saorsa ecosystem. It provides the decentralized storage and networking foundation using post-quantum cryptography.

## Development Commands

### Building and Testing
```bash
# Build the project
cargo build --release

# Run all tests
cargo test

# Run with verbose output
cargo test -- --nocapture

# Format and lint
cargo fmt --all
cargo clippy --all-features -- -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used
```

### Running the Node
```bash
# Run as bootstrap node (default port)
cargo run --release -- --listen 0.0.0.0:10000 --bootstrap

# Run additional instance (use any port in range 10000-10999)
cargo run --release -- --listen 0.0.0.0:10001

# Run as regular node connecting to bootstrap
cargo run --release -- --listen 0.0.0.0:10000 --connect saorsa-2.saorsalabs.com:10000

# Run with debug logging
RUST_LOG=debug cargo run --release -- --listen 0.0.0.0:10000
```

## Code Standards

### NO PANICS IN PRODUCTION CODE
- No `.unwrap()` - Use `?` operator or `.ok_or()`
- No `.expect()` - Use `.context()` from `anyhow`
- No `panic!()` - Return `Result` instead
- **Exception**: Test code may use these for assertions

---

## 🚨 CRITICAL: Saorsa Network Infrastructure & Port Isolation

### Infrastructure Documentation
Full infrastructure documentation is available at: `docs/infrastructure/INFRASTRUCTURE.md`

This includes:
- All 9 VPS nodes across 3 cloud providers (DigitalOcean, Hetzner, Vultr)
- Bootstrap node endpoints and IP addresses
- Firewall configurations and SSH access
- Systemd service templates

### ⚠️ PORT ISOLATION - MANDATORY

**saorsa-node uses UDP port range 10000-10999 exclusively.**

| Service | UDP Port Range | Default | Description |
|---------|----------------|---------|-------------|
| ant-quic | 9000-9999 | 9000 | QUIC transport layer |
| **saorsa-node** | **10000-10999** | **10000** | Core P2P network nodes (THIS PROJECT) |
| communitas | 11000-11999 | 11000 | Collaboration platform nodes |

### 🛑 DO NOT DISTURB OTHER NETWORKS

When testing or developing saorsa-node:

1. **ONLY use ports 10000-10999** for saorsa-node services
2. **NEVER** kill processes on ports 9000-9999 or 11000-11999
3. **NEVER** restart services outside our port range
4. **NEVER** modify firewall rules for other port ranges

```bash
# ✅ CORRECT - saorsa-node operations (within 10000-10999)
cargo run --release -- --listen 0.0.0.0:10000
cargo run --release -- --listen 0.0.0.0:10001  # Second instance OK
ssh root@saorsa-2.saorsalabs.com "systemctl restart saorsa-node-bootstrap"

# ❌ WRONG - Would disrupt other networks
ssh root@saorsa-2.saorsalabs.com "pkill -f ':9'"    # NEVER - matches ant-quic ports
ssh root@saorsa-2.saorsalabs.com "pkill -f ':11'"   # NEVER - matches communitas ports
ssh root@saorsa-2.saorsalabs.com "systemctl restart ant-quic-bootstrap"  # NOT OUR SERVICE
```

### Bootstrap Endpoints (saorsa-node)
```
saorsa-2.saorsalabs.com:10000  (NYC - 142.93.199.50)
saorsa-3.saorsalabs.com:10000  (SFO - 147.182.234.192)
```

### Before Any VPS Operations
1. Verify you're targeting ports 10000-10999 only
2. Double-check service names contain "saorsa-node"
3. Never run broad `pkill` commands that could affect other services

### Deploy New Binary
```bash
# Build release binary
cargo build --release

# Deploy to bootstrap node
scp target/release/saorsa-node root@saorsa-2.saorsalabs.com:/opt/saorsa-node/
ssh root@saorsa-2.saorsalabs.com "systemctl restart saorsa-node-bootstrap"
```
