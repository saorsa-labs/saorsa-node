# saorsa-node

**The quantum-proof evolution of Autonomi network nodes.**

saorsa-node is the next-generation node software for the Autonomi decentralized network, replacing ant-node with future-proof cryptography and advanced network security.

> **Why Upgrade?** Current ant-node uses Ed25519/X25519 cryptography that will be broken by quantum computers. Data encrypted today can be harvested and decrypted later. saorsa-node uses FIPS-approved post-quantum algorithms to protect your data forever.

---

## Table of Contents

1. [The Quantum Threat](#the-quantum-threat)
2. [Key Advantages Over ant-node](#key-advantages-over-ant-node)
3. [Post-Quantum Cryptography](#post-quantum-cryptography)
4. [NAT Traversal](#nat-traversal)
5. [Network Hardening](#network-hardening)
6. [Dual IPv4/IPv6 DHT](#dual-ipv4ipv6-dht)
7. [Migration from ant-node](#migration-from-ant-node)
8. [Development Status](#development-status)
9. [Auto-Upgrade System](#auto-upgrade-system)
10. [Architecture](#architecture)
11. [Quick Start](#quick-start)
12. [CLI Reference](#cli-reference)
13. [Configuration](#configuration)
14. [Security Considerations](#security-considerations)
15. [Related Projects](#related-projects)

---

## The Quantum Threat

### Harvest Now, Decrypt Later (HNDL)

Nation-state actors and sophisticated adversaries are already collecting encrypted network traffic today. When cryptographically relevant quantum computers (CRQCs) become available, they will decrypt this harvested data. This is known as the **Harvest Now, Decrypt Later (HNDL)** attack.

**Timeline:**
- NIST estimates CRQCs capable of breaking RSA-2048 and ECC in **10-15 years**
- Some researchers suggest it could be sooner
- Data stored today on decentralized networks must remain secure for **decades**

### Why Classical Cryptography Fails

| Algorithm | Type | Quantum Attack | Time to Break |
|-----------|------|----------------|---------------|
| RSA-2048 | Asymmetric | Shor's Algorithm | Hours |
| ECDSA/Ed25519 | Signatures | Shor's Algorithm | Hours |
| X25519/ECDH | Key Exchange | Shor's Algorithm | Hours |
| AES-256 | Symmetric | Grover's Algorithm | Still secure* |

*Symmetric algorithms remain secure with sufficient key sizes (256-bit), but key exchange and signatures are completely broken.

### The Autonomi Network Risk

ant-node uses:
- **BLS signatures** - Quantum vulnerable (elliptic curve based)
- **Ed25519 signatures** - Quantum vulnerable (elliptic curve based)
- **X25519 key exchange** - Quantum vulnerable (elliptic curve based)

Even though the Autonomi nettwork self encrypted data is secure, he Autonomi network has metadata (signatures, encrypted keys) that will be compromised by quantum computers. **The time to act is now.**

---

## Key Advantages Over ant-node

| Feature | ant-node | saorsa-node |
|---------|----------|-------------|
| **Digital Signatures** | BLS/Ed25519 (quantum-vulnerable) | ML-DSA-65 (FIPS 204, quantum-proof) |
| **Key Exchange** | X25519 (quantum-vulnerable) | ML-KEM-768 (FIPS 203, quantum-proof) |
| **NAT Traversal** | None (requires port forwarding) | Native QUIC traversal (100% success, no STUN/ICE) |
| **DHT Architecture** | IPv4-only | Dual IPv4/IPv6 with separate close groups |
| **Sybil Resistance** | Basic per-IP limits | Multi-layer: subnet, ASN, geographic, node age |
| **Node Limiting** | None | Prevents large actors spinning up millions of nodes |
| **Trust System** | Manual metrics | EigenTrust++ with data integrity & replica health |
| **Geographic Routing** | None | 7-region distribution (no entity holds multiple copies) |
| **Eclipse Protection** | Limited | Diversity scoring, ASN limits, detection algorithms |
| **Auto-Upgrade** | Manual | Cross-platform staged rollout with network protection |
| **Rate Limiting** | Basic | 100 req/min per node, 500/min per IP |
| **Node Identity** | Ed25519 pubkey (unused, never signs data) | ML-DSA-65 pubkey (actively signs all operations) |
| **Legacy Data** | N/A | Full support for classical encrypted data |

---

## Post-Quantum Cryptography

saorsa-node implements **pure post-quantum cryptography** with no hybrid fallbacks. All algorithms are NIST FIPS-approved standards.

### ML-DSA-65 (FIPS 204) - Digital Signatures

- **Security Level**: 128-bit quantum security (NIST Level 2)
- **Public Key Size**: 1,952 bytes
- **Signature Size**: 3,309 bytes
- **Use Cases**: Node identity, message authentication, upgrade verification

ML-DSA (Module-Lattice Digital Signature Algorithm), formerly known as CRYSTALS-Dilithium, is based on the hardness of lattice problems that remain intractable for quantum computers.

### ML-KEM-768 (FIPS 203) - Key Encapsulation

- **Security Level**: 128-bit quantum security (NIST Level 2)
- **Public Key Size**: 1,184 bytes
- **Ciphertext Size**: 1,088 bytes
- **Shared Secret**: 32 bytes
- **Use Cases**: Secure key exchange, encrypted communications

ML-KEM (Module-Lattice Key Encapsulation Mechanism), formerly CRYSTALS-Kyber, provides secure key exchange resistant to both classical and quantum attacks.

### ChaCha20-Poly1305 - Symmetric Encryption

- **Security Level**: 256-bit (quantum-resistant with Grover consideration)
- **Use Cases**: Data encryption, authenticated encryption

Symmetric algorithms remain quantum-resistant at sufficient key sizes. ChaCha20-Poly1305 provides high-performance authenticated encryption.

### No Hybrid Mode

Unlike some transitional implementations, saorsa-node uses **pure post-quantum cryptography**:

- No Ed25519 fallback
- No X25519 hybrid key exchange
- No classical signature chains

This ensures maximum security and eliminates the complexity of dual-algorithm systems.

### Backward Compatibility

saorsa-core fully supports **legacy classical encrypted data**:

- **Existing Data**: AES-256-GCM-SIV encrypted content from ant-node remains readable
- **New Signatures**: All new signatures use ML-DSA-65 (quantum-proof)
- **New Key Exchange**: All new key exchanges use ML-KEM-768 (quantum-proof)
- **Gradual Migration**: Network can operate with mixed classical/quantum-proof data

This allows seamless migration without data loss while ensuring all new data is quantum-secure.

---

## NAT Traversal

### Everyone Can Run a Node

One of the most significant advantages of saorsa-node is **full native QUIC NAT traversal**. Unlike ant-node, which requires manual port forwarding, saorsa-core implements NAT traversal directly within the QUIC protocol itself - **no ICE, no STUN, no external protocols**.

> **100% Success Rate**: In our testing, we have successfully traversed 100% of network connections using native QUIC NAT traversal.

### The ant-node Limitation

ant-node has **no native NAT traversal**:
- Requires manual router configuration or UPnP
- Excludes users behind carrier-grade NAT (CGNAT)
- Excludes most mobile and residential users
- Limits network participation to technically savvy operators

### Native QUIC NAT Traversal

Based on **draft-seemann-quic-nat-traversal-02** (Marten Seemann & Eric Kinnear, Apple Inc.), saorsa-core implements NAT traversal as a pure QUIC protocol extension.

**Why Not ICE/STUN?**

| Aspect | ICE/STUN | Native QUIC (saorsa) |
|--------|----------|----------------------|
| **External Dependencies** | Requires STUN/TURN servers | None - 100% within QUIC |
| **Protocol Complexity** | Separate signaling (SDP) | QUIC frames only |
| **Path Validation** | ICE connectivity checks | Native QUIC PATH_CHALLENGE |
| **Connection Migration** | Separate step after ICE | Automatic QUIC feature |
| **Amplification Protection** | STUN fingerprints | QUIC rate limits |

**Three Custom QUIC Frames:**

1. **ADD_ADDRESS** - Server advertises candidate addresses to peer
2. **PUNCH_ME_NOW** - Coordinates simultaneous hole punching
3. **REMOVE_ADDRESS** - Removes stale address candidates

### How It Works

```
1. Node starts → enumerates local interfaces and addresses
2. Peers exchange addresses via ADD_ADDRESS frames
3. Client sends PUNCH_ME_NOW to coordinate timing
4. Both peers simultaneously send QUIC PATH_CHALLENGE packets
5. NAT bindings created → PATH_RESPONSE packets received
6. QUIC connection migrates to direct path automatically
7. Application data flows directly (no relay needed)
```

**Key Innovation**: Uses QUIC's existing path validation mechanism (RFC 9000 Section 8.2) as the actual NAT traversal technique, eliminating external protocol dependencies entirely.

### Benefits

- **Universal Participation**: Anyone can run a node, regardless of network configuration
- **No Port Forwarding**: Works automatically on any network
- **No External Servers**: No STUN/TURN infrastructure required
- **CGNAT Support**: Works on mobile networks and carrier-grade NAT
- **Zero Configuration**: Just start the node - NAT traversal is automatic
- **Increased Decentralization**: More participants = more resilient network

This ensures that **everyone can contribute to the network**, democratizing participation beyond those with favorable network configurations or technical expertise.

---

## Network Hardening

### Multi-Layer Sybil Resistance

Sybil attacks involve creating many fake identities to gain disproportionate influence. saorsa-node implements defense-in-depth:

#### Layer 1: IPv6 Node Identity Binding

```
NodeID = SHA256(IPv6_Address || PublicKey || Salt)
```

Each node's identity is cryptographically bound to its IPv6 address, making identity spoofing detectable.

#### Layer 2: Subnet Limits

Prevents concentration of nodes in single networks:

| Scope | Maximum Nodes |
|-------|---------------|
| Per /64 subnet | 1 |
| Per /48 subnet | 3 |
| Per /32 subnet | 10 |
| Per ASN | 20 |

VPN and hosting providers have **halved limits** to prevent abuse.

#### Layer 3: Node Age & Preference

The network **actively prefers older, more proven nodes**. This creates a natural barrier against attackers who would need to maintain nodes for extended periods before gaining significant influence.

| Status | Age Requirement | Trust Weight | Capabilities |
|--------|-----------------|--------------|--------------|
| **New** | 0-24 hours | 0.25x | Limited routing, no close group membership |
| **Young** | 1-7 days | 0.5x | Standard routing, limited replication |
| **Established** | 7-30 days | 1.0x | Full participation, all operations |
| **Veteran** | 30+ days | 1.5x | Trusted bootstrap, priority in close groups |

**Why Node Age Matters:**
- **Attack Cost**: Attackers must invest months to gain meaningful network influence
- **Proven Reliability**: Older nodes have demonstrated consistent uptime
- **Historical Trust**: Long-running nodes have accumulated positive EigenTrust scores
- **Priority Routing**: Veteran nodes receive routing preference, improving reliability

#### Layer 4: Node Limiting

Prevents **large actors from spinning up millions of nodes at once**:

- **Rate-limited Registration**: New nodes must wait before full participation
- **Resource Proof**: Nodes must demonstrate actual storage/bandwidth capacity
- **Progressive Trust**: Influence grows slowly with proven good behavior
- **Suspicious Pattern Detection**: Rapid node deployment triggers investigation

This makes **hostile takeover economically infeasible** - an attacker would need to:
1. Acquire millions of unique IP addresses across diverse subnets and ASNs
2. Maintain nodes for months to accumulate trust
3. Provide actual storage and bandwidth resources
4. Avoid triggering pattern detection algorithms

#### Layer 5: Geographic Distribution

Ensures close groups aren't dominated by nodes in single datacenters or regions.

### EigenTrust++ Reputation System

Automated reputation scoring based on observable behavior. This is a **foundational system** that we continue to build upon with additional integrity checks.

**Core Scoring Factors:**
- **Response Rate**: Percentage of valid responses to requests
- **Uptime**: Time node has been continuously available
- **Storage Reliability**: Successful data retrievals
- **Bandwidth Contribution**: Network throughput provided

**Advanced Integrity Checks (Building on EigenTrust):**
- **Data Integrity Verification**: Periodic challenges to verify nodes actually store the data they claim
- **Replica Health Monitoring**: Continuous verification that replicas are valid and accessible
- **Proof of Storage**: Cryptographic proofs that data exists without retrieving entire content
- **Cross-Node Validation**: Nodes verify each other's claims through random sampling

**Key Features:**
- **Time Decay**: Trust decays at 0.99x per hour (recent behavior matters more)
- **Pre-trusted Bootstrap**: Initial nodes have verified trust scores
- **Automatic Removal**: Nodes below threshold are automatically excluded
- **Convergence**: Iterative algorithm converges to stable trust values
- **Extensible Framework**: New verification methods can be added as the network evolves

**Trust Score Impact:**
| Trust Level | Multiplier | Effect |
|-------------|------------|--------|
| Very Low | 0.1x | Excluded from routing, data migrated away |
| Low | 0.5x | Reduced routing priority, monitored |
| Normal | 1.0x | Standard participation |
| High | 1.5x | Preferred for routing and storage |
| Very High | 2.0x | Priority close group membership, bootstrap eligible |

The EigenTrust++ system provides the foundation for **continuous network health monitoring**, ensuring that bad actors are detected and isolated before they can cause harm.

### Geographic Routing

7-region latency-aware distribution ensures **no single entity can hold more than one copy of any piece of data**:

1. **North America**
2. **South America**
3. **Europe**
4. **Africa**
5. **Asia Pacific**
6. **Middle East**
7. **Oceania**

**Data Distribution Rules:**
- Close groups are constructed with **geographic diversity requirements**
- Each replica of data is stored in a **different geographic region** where possible
- Nodes from the same ASN/organization cannot hold multiple replicas of the same data
- XorName-based addressing combined with geographic constraints ensures distribution

**Why This Matters:**
- **No Single Point of Failure**: Data survives regional outages or censorship
- **No Entity Concentration**: Even large operators cannot hold multiple copies
- **Regulatory Resilience**: Data exists across multiple legal jurisdictions
- **Attack Resistance**: Compromising data requires attacking nodes worldwide

**Benefits:**
- Prevents datacenter concentration in close groups
- Optimizes latency for data retrieval (nearest geographic replica)
- Ensures regulatory diversity (no single jurisdiction dominance)
- Makes coordinated data destruction practically impossible

---

## Dual IPv4/IPv6 DHT

saorsa-node implements a novel dual-stack DHT architecture that maximizes network connectivity.

### Separate Close Groups

Each XorName has **two** close groups:
- IPv4 close group (K=20 closest IPv4 nodes)
- IPv6 close group (K=20 closest IPv6 nodes)

### Cross-Replication

Data is replicated to **both** close groups:
- IPv4-only nodes can always retrieve IPv4-stored data
- IPv6-only nodes can always retrieve IPv6-stored data
- Dual-stack nodes can retrieve from either

### Happy Eyeballs (RFC 8305)

For connections, saorsa-node implements Happy Eyeballs:
1. Attempt IPv6 connection first
2. Start IPv4 connection after short delay
3. Use whichever completes first
4. Cache successful connection type for peer

### Benefits

- **Maximum Connectivity**: Works on IPv4-only, IPv6-only, or dual-stack networks
- **Future-Proof**: Ready for IPv6-only internet segments
- **Resilient**: Network partition in one IP version doesn't affect the other

---

## Migration from ant-node

saorsa-node provides seamless migration from existing ant-node installations.

### Automatic Detection

```bash
# Auto-detect ant-node data directories
saorsa-node --migrate-ant-data auto
```

Searches common locations:
- `~/.local/share/safe/node/`
- `~/.safe/node/`
- Platform-specific data directories

### Migration Process

1. **Scan**: Enumerate all record files in ant-node `record_store/`
2. **Classify**: Identify record types (Chunk, Register, Scratchpad, GraphEntry)
3. **Decrypt**: Decrypt AES-256-GCM-SIV encrypted records
4. **Upload**: Store on saorsa-network
5. **Track**: Save progress for resume capability

### Progress Tracking

Migration can be interrupted and resumed:

```bash
# Migration continues from last checkpoint
saorsa-node --migrate-ant-data ~/.local/share/safe/node
```

### Payment Model

| Data Type | Payment |
|-----------|---------|
| **Legacy Autonomi data** | FREE (already paid) |
| **New data** | EVM payment (Arbitrum One) |

The three-layer verification:
1. **LRU Cache**: Fast lookup of recently verified XorNames
2. **Autonomi Check**: Query legacy network for existing data
3. **EVM Verification**: Verify on-chain payment for new data

### CRDT Data Migration (Scratchpad, Pointer, GraphEntry)

Mutable data types use CRDT semantics with **owner signatures** for authorization. This creates a dual-key requirement during migration:

#### The Challenge

| Data Type | Signature Required | Why |
|-----------|-------------------|-----|
| **Chunk** | None (content-addressed) | Immutability verified by hash |
| **Scratchpad** | Owner signature | Only owner can update their data |
| **Pointer** | Owner signature | Only owner can change the target |
| **GraphEntry** | Owner signature | Only owner can add to their DAG |

Existing Autonomi CRDT data was signed with **Ed25519** (classical). To update these records, users must provide valid Ed25519 signatures that the Autonomi network can verify.

#### Dual-Key Architecture

Users with existing CRDT data need **two key pairs**:

```
┌─────────────────────────────────────────────────────────────────┐
│                      User's Key Wallet                          │
├─────────────────────────────────────────────────────────────────┤
│  Classical Keys (Ed25519)        │  Quantum Keys (ML-DSA-65)    │
│  ─────────────────────────────   │  ─────────────────────────   │
│  • From existing Autonomi wallet │  • Generated by saorsa       │
│  • Signs updates to OLD data     │  • Signs updates to NEW data │
│  • Required for migration        │  • Future-proof security     │
└─────────────────────────────────────────────────────────────────┘
```

#### How the Hybrid Client Handles This

```rust
// The HybridClient manages both key types
let hybrid = HybridClient::new(config)?;

// Updating EXISTING Autonomi scratchpad (uses Ed25519)
hybrid.update_legacy_scratchpad(
    &classical_keypair,  // Ed25519 - signs for Autonomi network
    owner_address,
    new_content,
    counter + 1,
)?;

// Creating NEW saorsa scratchpad (uses ML-DSA-65)
hybrid.put_scratchpad(
    &quantum_keypair,    // ML-DSA-65 - signs for saorsa network
    content_type,
    payload,
)?;
```

#### Migration Strategy for CRDT Data

**Option 1: Continue Using Legacy Data**
- Keep existing Scratchpads/Pointers on Autonomi
- Use classical keys for updates via HybridClient
- New data goes to saorsa with quantum keys

**Option 2: Full Migration**
1. Read existing CRDT data from Autonomi
2. Create new equivalent on saorsa (new address, quantum-signed)
3. Update any references (Pointers) to point to new addresses
4. Optionally: Create a Pointer on saorsa pointing to legacy data

**Option 3: Gradual Transition**
1. Create new quantum-signed CRDT on saorsa
2. Use Pointer to redirect from old → new location
3. Applications check both locations during transition
4. Eventually deprecate legacy data

#### Key Import

Users can import their existing Autonomi keys:

```bash
# Import classical keys for legacy CRDT access
saorsa-keygen import-legacy ~/.safe/client/key.sk

# This creates a hybrid wallet with both key types
# Output: ~/.saorsa/keys/
#   ├── classical.key    # Ed25519 (imported)
#   └── quantum.key      # ML-DSA-65 (generated)
```

#### Security Considerations

| Aspect | Classical (Legacy) | Quantum (New) |
|--------|-------------------|---------------|
| **Algorithm** | Ed25519 | ML-DSA-65 |
| **Security** | 128-bit classical | 128-bit quantum |
| **Quantum Safe** | ❌ No | ✅ Yes |
| **Key Size** | 32 bytes | 1,952 bytes |
| **Signature Size** | 64 bytes | 3,309 bytes |
| **Use Case** | Update existing Autonomi data | All new data |

**Important**: Classical keys should only be used for updating existing legacy data. All new CRDT records should use quantum-safe ML-DSA-65 signatures.

---

## Development Status

### Current Implementation Status

| Component | Status | Description |
|-----------|--------|-------------|
| **Core Library** | ✅ Complete | Full node implementation with client APIs |
| **Data Types** | ✅ Complete | Chunk, Scratchpad, Pointer, GraphEntry |
| **Payment Verification** | ✅ Complete | Autonomi lookup + EVM verification + LRU cache |
| **Migration Decryption** | ✅ Complete | AES-256-GCM-SIV decryption for ant-node data |
| **Auto-Upgrade** | ✅ Complete | Cross-platform with ML-DSA-65 signature verification |
| **E2E Test Infrastructure** | ✅ Complete | Real P2P testnet with 25+ nodes |

### Test Coverage

```
Library Unit Tests:     104 passing
E2E Unit Tests:          35 passing
E2E Integration Tests:   49 passing (real P2P testnet)
────────────────────────────────────
Total:                  188 tests
```

### Data Types Supported

| Type | Size Limit | Addressing | Mutability | Use Cases |
|------|------------|------------|------------|-----------|
| **Chunk** | 1 MB | Content-addressed (SHA256) | Immutable | Files, documents, media |
| **Scratchpad** | 4 MB | Owner public key | Mutable (CRDT counter) | User profiles, settings |
| **Pointer** | 32 bytes | Owner public key | Mutable (counter) | Mutable references, DNS-like |
| **GraphEntry** | 100 KB | Content + owner + parents | Immutable | Version control, social feeds |

### Migration Capability

The migration system is **fully implemented** and ready for use:

1. **Decryption Module** (`src/migration/decrypt.rs`)
   - AES-256-GCM-SIV decryption with HKDF key derivation
   - Handles embedded nonces from ant-node format
   - Full round-trip encryption/decryption verified

2. **Scanner Module** (`src/migration/scanner.rs`)
   - Auto-detection of ant-node data directories
   - Cross-platform path discovery
   - Record enumeration and classification

3. **Client APIs** (`src/client/`)
   - `QuantumClient`: Pure saorsa-network operations
   - `LegacyClient`: Read-only access to Autonomi network
   - `HybridClient`: Seamless access to both networks

4. **Payment Verification** (`src/payment/`)
   - Three-layer verification: LRU cache → Autonomi lookup → EVM check
   - Legacy data is FREE (already paid on Autonomi)
   - New data requires EVM payment (Arbitrum One)

### E2E Test Infrastructure

The test infrastructure spawns real P2P networks for integration testing:

```rust
// Spawn a 25-node testnet
let harness = TestHarness::setup().await?;

// Store and retrieve data across nodes
let chunk_addr = harness.node(5).store_chunk(&data).await?;
let retrieved = harness.node(20).get_chunk(&chunk_addr).await?;

// With EVM payment verification
let harness = TestHarness::setup_with_evm().await?;
assert!(harness.anvil().is_healthy().await);
```

### Roadmap

| Phase | Target | Status |
|-------|--------|--------|
| **Phase 1** | Core implementation | ✅ Complete |
| **Phase 2** | E2E test infrastructure | ✅ Complete |
| **Phase 3** | Testnet deployment | 🔄 In Progress |
| **Phase 4** | Migration tooling CLI | 📋 Planned |
| **Phase 5** | Mainnet preparation | 📋 Planned |

---

## Auto-Upgrade System

saorsa-node automatically stays up-to-date with secure, verified upgrades across **all platforms** - Windows, macOS, and Linux.

### Cross-Platform Support

| Platform | Architecture | Binary |
|----------|--------------|--------|
| **Linux** | x86_64, aarch64 | `saorsa-node-linux-*` |
| **macOS** | x86_64, aarch64 (Apple Silicon) | `saorsa-node-darwin-*` |
| **Windows** | x86_64 | `saorsa-node-windows-*.exe` |

The auto-upgrade system automatically detects the current platform and downloads the correct binary.

### How It Works

1. **Monitor**: Periodically check GitHub releases for new versions
2. **Download**: Fetch the correct binary for the current platform
3. **Verify**: Validate ML-DSA-65 signature against embedded public key
4. **Stage**: Download completes before any changes are made
5. **Apply**: Replace current binary and restart
6. **Rollback**: Automatic rollback if new version fails health checks

### Network-Safe Staged Rollout

To prevent **network collapse** from simultaneous upgrades, saorsa-node implements **randomized staged rollout**:

**How Staged Rollout Works:**
- Each node adds a **random delay** (0-24 hours) before applying upgrades
- Delay is deterministically derived from node ID (consistent but distributed)
- Critical security updates can override with shorter delay windows
- Network maintains minimum online node threshold during rollout

**Why This Matters:**
- **No Mass Restart**: Nodes don't all restart simultaneously
- **Network Continuity**: DHT maintains routing capability throughout upgrade
- **Data Availability**: Close groups retain quorum during transition
- **Rollback Safety**: Problems detected early before full network deployment

```
Upgrade Timeline (example):
Hour 0:  Release published
Hour 1:  ~4% of nodes upgrade (random delay 0-1h)
Hour 6:  ~25% of nodes upgraded
Hour 12: ~50% of nodes upgraded
Hour 24: ~100% of nodes upgraded
```

### Security Guarantees

**Embedded Public Key:**
The ML-DSA-65 verification key is compiled into the binary at build time. It cannot be changed by:
- Configuration files
- Environment variables
- Network messages
- Remote commands

The only way to change the signing key is a manual upgrade with a new binary.

**Signature Verification:**
- Every release is signed with the project's ML-DSA-65 private key
- Signature size: 3,309 bytes
- Failed verification = upgrade rejected
- Tampered binaries cannot be installed

### Unattended Operation

saorsa-node is designed for **true unattended operation**:

- **Zero Intervention**: Nodes upgrade themselves without human action
- **Self-Healing**: Failed upgrades automatically rollback
- **Health Monitoring**: Post-upgrade health checks verify functionality
- **Notification**: Optional alerts for upgrade events (success/failure)

This enables node operators to deploy and forget, knowing their nodes will stay current and secure.

### Release Channels

| Channel | Description | Rollout Speed |
|---------|-------------|---------------|
| **stable** | Production releases, thoroughly tested | 24-hour staged |
| **beta** | Pre-release versions for early testing | 6-hour staged |

```bash
# Use stable channel (default)
saorsa-node --auto-upgrade --upgrade-channel stable

# Use beta channel for testing
saorsa-node --auto-upgrade --upgrade-channel beta
```

### Configuration

```toml
[upgrade]
enabled = true
channel = "stable"
check_interval_hours = 1
github_repo = "dirvine/saorsa-node"
# max_random_delay_hours = 24  # For staged rollout
```

---

## Architecture

saorsa-node follows a **thin wrapper** design philosophy, adding minimal code on top of saorsa-core.

### Component Responsibilities

| Component | Provider | Description |
|-----------|----------|-------------|
| **P2P Networking** | saorsa-core | QUIC transport, connection management |
| **DHT Routing** | saorsa-core | Trust-weighted Kademlia |
| **Reputation** | saorsa-core | EigenTrust++ engine |
| **Security** | saorsa-core | Rate limiting, blacklisting, diversity scoring |
| **Content Storage** | saorsa-core | Local chunk storage |
| **Replication** | saorsa-core | Data redundancy management |
| **Auto-Upgrade** | saorsa-node | Binary update system |
| **Migration** | saorsa-node | ant-node data import |
| **CLI** | saorsa-node | User interface |

### Code Size

saorsa-node adds approximately **1,000 lines** of new code:
- Easy to audit
- Minimal attack surface
- Clear separation of concerns

### Dependency Chain

```
saorsa-node
    └── saorsa-core
            └── saorsa-pqc (ML-DSA, ML-KEM)
```

---

## Quick Start

### Prerequisites

- Rust 1.75+ (for building from source)
- Linux, macOS, or Windows

### Build from Source

```bash
# Clone the repository
git clone https://github.com/dirvine/saorsa-node
cd saorsa-node

# Build release binary
cargo build --release

# Binary location
./target/release/saorsa-node --version
```

### Run with Defaults

```bash
# Start node with default settings
./target/release/saorsa-node
```

### Join Existing Network

```bash
# Connect to bootstrap peers
./target/release/saorsa-node \
    --bootstrap "/ip4/1.2.3.4/udp/12000/quic-v1" \
    --bootstrap "/ip6/2001:db8::1/udp/12000/quic-v1"
```

### Full Configuration

```bash
./target/release/saorsa-node \
    --root-dir ~/.saorsa \
    --port 12000 \
    --ip-version dual \
    --auto-upgrade \
    --upgrade-channel stable \
    --migrate-ant-data auto \
    --log-level info
```

---

## CLI Reference

```
saorsa-node [OPTIONS]

Options:
    --root-dir <PATH>
        Node data directory
        [default: ~/.saorsa]

    --port <PORT>
        Listening port (0 for automatic selection)
        [default: 0]

    --ip-version <VERSION>
        IP version to use: ipv4, ipv6, or dual
        [default: dual]

    --bootstrap <ADDR>
        Bootstrap peer multiaddresses (can be specified multiple times)
        Example: /ip4/1.2.3.4/udp/12000/quic-v1

    --migrate-ant-data <PATH>
        Path to ant-node data directory to migrate
        Use 'auto' for automatic detection

    --auto-upgrade
        Enable automatic upgrades from GitHub releases

    --upgrade-channel <CHANNEL>
        Release channel: stable, beta
        [default: stable]

    --log-level <LEVEL>
        Log verbosity: trace, debug, info, warn, error
        [default: info]

    -h, --help
        Print help information

    -V, --version
        Print version information
```

---

## Configuration

Configuration sources (highest to lowest priority):

1. **Command-line arguments**
2. **Environment variables** (`SAORSA_*`)
3. **Configuration file** (`~/.saorsa/config.toml`)

### Environment Variables

```bash
export SAORSA_ROOT_DIR=~/.saorsa
export SAORSA_PORT=12000
export SAORSA_IP_VERSION=dual
export SAORSA_LOG_LEVEL=info
export SAORSA_AUTO_UPGRADE=true
export SAORSA_UPGRADE_CHANNEL=stable
```

### Configuration File

`~/.saorsa/config.toml`:

```toml
[node]
root_dir = "~/.saorsa"
port = 0  # Auto-select

[network]
ip_version = "dual"
bootstrap = [
    "/ip4/1.2.3.4/udp/12000/quic-v1",
    "/ip6/2001:db8::1/udp/12000/quic-v1"
]

[upgrade]
enabled = true
channel = "stable"
check_interval_hours = 1
github_repo = "dirvine/saorsa-node"

[migration]
auto_detect = true
# ant_data_path = "~/.local/share/safe/node"  # Explicit path

[payment]
# Autonomi verification for legacy data
autonomi_enabled = true
autonomi_timeout_secs = 30

# EVM verification for new data
evm_enabled = true
evm_network = "arbitrum-one"

# Cache configuration
cache_capacity = 100000
```

---

## Security Considerations

### Rate Limiting

Protects against denial-of-service attacks:

| Limit | Value |
|-------|-------|
| Requests per node per minute | 100 |
| Requests per IP per minute | 500 |
| Concurrent connections per IP | 10 |

### Blacklist Management

Automatically blacklists nodes that:
- Repeatedly violate rate limits
- Fail trust score thresholds
- Exhibit malicious behavior patterns

### Eclipse Attack Detection

Monitors for attempts to isolate nodes:
- Diversity scoring ensures varied peer selection
- ASN limits prevent single-provider dominance
- Geographic distribution prevents regional isolation
- Connection history analysis detects patterns

### Audit Logging

All security-relevant events are logged:
- Connection attempts
- Rate limit violations
- Trust score changes
- Blacklist modifications

Enable detailed logging:

```bash
RUST_LOG=saorsa_node=debug,saorsa_core=debug ./saorsa-node
```

---

## Related Projects

| Project | Description | Repository |
|---------|-------------|------------|
| **saorsa-core** | Core networking and security library | [github.com/dirvine/saorsa-core](https://github.com/dirvine/saorsa-core) |
| **saorsa-pqc** | Post-quantum cryptography primitives | [github.com/dirvine/saorsa-pqc](https://github.com/dirvine/saorsa-pqc) |
| **saorsa-client** | Client library for applications | [github.com/dirvine/saorsa-client](https://github.com/dirvine/saorsa-client) |

---

## License

This project is dual-licensed under MIT and Apache-2.0.

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development

```bash
# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run

# Check for issues
cargo clippy -- -D warnings

# Format code
cargo fmt
```

---

**saorsa-node**: Securing the future of decentralized data, one quantum-proof node at a time.
