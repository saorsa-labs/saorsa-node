# saorsa-node Design Document

## Overview

Build a **pure quantum-proof network node** (`saorsa-node`) that:
1. Uses `saorsa-core` for networking, NAT traversal, and PQC crypto
2. Stays clean - no legacy protocol dependencies
3. Auto-migrates local ant-node data on startup
4. Implements auto-upgrade with ML-DSA signature verification
5. Supports dual IPv4/IPv6 DHT for maximum connectivity
6. Features geographic routing, Sybil resistance, and EigenTrust

## Architecture Philosophy

**Clean separation of concerns:**
- **saorsa-node** = Pure quantum-proof node (no legacy baggage)
- **saorsa-client** = Bridge layer (reads old network, writes new network)
- **Auto-migration** = Nodes discover and upload local ant-node data
- **Dual IP DHT** = IPv4 and IPv6 close groups for resilience

This avoids the complexity of bridge nodes by pushing migration logic to:
1. **Clients** - which naturally access data and can write to new network
2. **Node startup** - which can scan for local ant-node data and migrate it

---

## Migration Strategy: Client-as-Bridge + Node Auto-Migration

### How Migration Works

```
┌─────────────────────────────────────────────────────────────────┐
│                      TRANSITION PERIOD                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────┐         ┌─────────────────┐                  │
│   │ ant-network │ ◄─────► │  saorsa-client  │                  │
│   │ (classical) │  read   │  (bridge layer) │                  │
│   └─────────────┘         └────────┬────────┘                  │
│                                    │ write                      │
│                                    ▼                            │
│                           ┌─────────────────┐                  │
│   ┌─────────────┐        │ saorsa-network  │                   │
│   │ant-node data│ ──────►│ (quantum-proof) │                   │
│   │   on disk   │ migrate │                 │                   │
│   └─────────────┘        └─────────────────┘                   │
│         ▲                         ▲                             │
│         │ scan                    │                             │
│   ┌─────┴─────────────────────────┴─────┐                      │
│   │           saorsa-node               │                      │
│   │    (pure quantum-proof node)        │                      │
│   └─────────────────────────────────────┘                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Client Bridge Behavior

```rust
impl SaorsaClient {
    async fn get_data(&self, address: &DataAddress) -> Result<Data> {
        // 1. Try saorsa-network first (quantum-proof)
        if let Ok(data) = self.saorsa_network.get(address).await {
            return Ok(data);
        }

        // 2. Fall back to ant-network (legacy)
        let data = self.ant_network.get(address).await?;

        // 3. Migrate to saorsa-network (lazy migration)
        self.saorsa_network.put(&data).await?;

        Ok(data)
    }

    async fn put_data(&self, data: &Data) -> Result<DataAddress> {
        // New data goes ONLY to quantum-proof network
        self.saorsa_network.put(data).await
    }
}
```

### Node Auto-Migration on Startup

```rust
impl SaorsaNode {
    async fn startup(&mut self) -> Result<()> {
        // 1. Normal node startup
        self.initialize_network().await?;

        // 2. Scan for local ant-node data directories
        if let Some(ant_data_dir) = self.find_ant_node_data() {
            info!("Found ant-node data at {:?}, starting migration", ant_data_dir);
            self.migrate_local_ant_data(ant_data_dir).await?;
        }

        Ok(())
    }

    async fn migrate_local_ant_data(&self, ant_dir: PathBuf) -> Result<MigrationStats> {
        let reader = AntRecordStoreReader::new(&ant_dir)?;
        let mut stats = MigrationStats::default();

        for record in reader.read_all_records() {
            // Store on saorsa-network
            self.dht_manager.put(record.key, record.value).await?;
            stats.migrated += 1;
        }

        Ok(stats)
    }
}
```

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Migration Strategy | **Client-as-Bridge + Node Auto-Migration** | Clean node, organic migration |
| Node Architecture | **Pure quantum-proof (no libp2p)** | Simpler, more secure |
| Node Identity | Fresh ML-DSA Keypairs | Clean break, better privacy |
| Network Protocol | **Dual IPv4/IPv6 DHT** | Maximum connectivity and resilience |
| Geographic Routing | **Enabled** | No datacenter concentration |
| Sybil Resistance | **Required** | Prevent Sybil attacks |
| Node Reputation | **EigenTrust** | Measure and remove bad nodes |
| Auto-Upgrade | Phase 1 Critical | Essential for network transition |

---

## Architecture

### Project Structure (Thin Wrapper - Leverages saorsa-core)

```
saorsa-node/
├── Cargo.toml
├── src/
│   ├── lib.rs                    # Library exports
│   ├── bin/
│   │   └── saorsa-node/
│   │       ├── main.rs           # CLI entry point
│   │       ├── cli.rs            # Command-line parsing (clap)
│   │       └── rpc_service.rs    # Admin RPC service (optional)
│   │
│   ├── node.rs                   # RunningNode + NodeBuilder
│   │                             # Thin wrapper around NetworkCoordinator
│   ├── config.rs                 # Configuration (wraps saorsa-core configs)
│   ├── event.rs                  # NodeEvent system
│   │
│   ├── ant_protocol/             # ANT wire protocol (chunk messages)
│   │   ├── mod.rs
│   │   └── chunk.rs              # Bincode-serialized PUT/GET/Quote messages
│   │
│   ├── storage/                  # Content-addressed chunk persistence
│   │   ├── mod.rs
│   │   ├── disk.rs               # Sharded directory storage with atomic writes
│   │   └── handler.rs            # AntProtocol handler (routes messages to storage)
│   │
│   ├── client/                   # Quantum-resistant client operations
│   │   ├── mod.rs
│   │   ├── quantum.rs            # QuantumClient (chunk PUT/GET over P2P)
│   │   └── data_types.rs         # DataChunk, XorName
│   │
│   ├── payment/                  # EVM payment verification and quoting
│   │   └── ...
│   │
│   ├── migration/                # ant-node data migration (NEW CODE)
│   │   ├── mod.rs
│   │   ├── scanner.rs            # Find ant-node data directories
│   │   ├── ant_record_reader.rs  # Decrypt AES-256-GCM-SIV records
│   │   └── uploader.rs           # Upload via NetworkCoordinator
│   │
│   └── upgrade/                  # AUTO-UPGRADE (NEW CODE - Critical)
│       ├── mod.rs
│       ├── monitor.rs            # GitHub release polling
│       ├── signature.rs          # ML-DSA binary verification
│       └── executor.rs           # Process replacement + rollback
│
├── tests/                        # Integration tests
│   ├── e2e/
│   │   ├── testnet.rs            # 25-node local testnet infrastructure
│   │   ├── integration_tests.rs  # Network formation and messaging tests
│   │   └── data_types/chunk.rs   # Chunk store/retrieve E2E tests
│   └── ...
│
└── README.md
```

**Delegated to saorsa-core:**
- `network/` - Use P2PNode + DualStackNetworkNode
- `trust/` - Use EigenTrustEngine

**Implemented in saorsa-node** (not provided by saorsa-core):
- `storage/` - Content-addressed chunk persistence with sharded directories, atomic writes, and TOCTOU-safe concurrency. saorsa-core's `ContentStore` operates at the DHT level; saorsa-node needs its own disk storage layer for the ANT chunk protocol.
- `ant_protocol/` - Bincode-serialized wire protocol for chunk PUT/GET/Quote operations. This is the autonomi-compatible protocol layer that sits between P2P transport and disk storage.
- Replication is not yet implemented. saorsa-core provides DHT-level replication via `ReplicationManager`, but chunk-level replication across storage nodes is a future milestone.

### Core Components

**KEY INSIGHT: saorsa-core provides security, networking, and DHT features. saorsa-node adds the application-level chunk storage protocol, disk persistence, and payment integration on top.**

#### 1. SaorsaNode (Thin Wrapper Around saorsa-core)

```rust
use saorsa_core::{
    adaptive::coordinator::NetworkCoordinator,
    adaptive::security::SecurityManager,
    adaptive::trust::EigenTrustEngine,
    bootstrap::BootstrapManager,
    dht::trust_weighted_kademlia::TrustWeightedKademlia,
    messaging::NetworkConfig,
    security::{IPv6NodeID, IPDiversityEnforcer},
};

pub struct RunningNode {
    shutdown_sender: watch::Sender<bool>,
    // USE SAORSA-CORE DIRECTLY - NO REIMPLEMENTATION!
    coordinator: Arc<NetworkCoordinator>,  // Integrates ALL components
    security: Arc<SecurityManager>,         // Rate limiting, blacklist, eclipse detection
    bootstrap: Arc<BootstrapManager>,       // 30,000 peer cache
    // Events
    node_events_channel: NodeEventsChannel,
    root_dir_path: PathBuf,
}

pub struct NodeBuilder {
    network_config: NetworkConfig,          // saorsa-core's config
    identity: saorsa_core::identity::NodeIdentity,
    root_dir: PathBuf,
    auto_migrate_ant_data: bool,
}
```

#### 2. Dual IPv4/IPv6 - ALREADY IN SAORSA-CORE!

**File:** `saorsa-core/src/messaging/network_config.rs`

```rust
// Just configure saorsa-core - it handles everything!
use saorsa_core::messaging::NetworkConfig;

// Option 1: Dual-stack on same port
let config = NetworkConfig::with_dual_stack();

// Option 2: Separate ports per IP version
let config = NetworkConfig::with_dual_stack_separate();

// Option 3: IPv4 only (default, safest)
let config = NetworkConfig::default();

// saorsa-core also implements Happy Eyeballs (RFC 8305)!
```

**DualStackNetworkNode already exists:**
```rust
// From saorsa-core/src/transport/ant_quic_adapter.rs
pub struct DualStackNetworkNode {
    pub v6: Option<P2PNetworkNode>,  // IPv6 stack
    pub v4: Option<P2PNetworkNode>,  // IPv4 stack
}

// Happy Eyeballs - race IPv6 and IPv4, return first success
pub async fn connect_happy_eyeballs(&self, targets: &[SocketAddr]) -> Result<PeerId>
```

#### 3. Sybil Resistance - ALREADY IN SAORSA-CORE!

**File:** `saorsa-core/src/security.rs` (1,245 lines)

```rust
// Just use saorsa-core's existing implementation!
use saorsa_core::security::{IPv6NodeID, IPDiversityEnforcer, IPDiversityConfig};

// Multi-layer subnet enforcement ALREADY IMPLEMENTED:
pub struct IPDiversityConfig {
    pub max_nodes_per_64: usize,   // Default: 1 per /64 subnet
    pub max_nodes_per_48: usize,   // Default: 3 per /48 allocation
    pub max_nodes_per_32: usize,   // Default: 10 per /32 region
    pub max_nodes_per_asn: usize,  // Default: 20 per ASN
    // + GeoIP-based country limits
    // + Halved limits for hosting/VPN providers
}

// IPv6-based node identity binding with ML-DSA signatures
pub struct IPv6NodeID {
    pub node_id: [u8; 32],        // SHA256(IPv6 || pubkey || salt || timestamp)
    pub ipv6_addr: Ipv6Addr,
    pub public_key: MlDsaPublicKey,
    pub signature: MlDsaSignature,
}
```

#### 4. EigenTrust - ALREADY IN SAORSA-CORE!

**File:** `saorsa-core/src/adaptive/trust.rs` (825 lines)

```rust
// Just use saorsa-core's EigenTrust++ engine!
use saorsa_core::adaptive::trust::EigenTrustEngine;

// Multi-factor trust scoring ALREADY IMPLEMENTED:
// - 40% response_rate (correct/total responses)
// - 20% uptime_estimate
// - 15% storage_contributed
// - 15% bandwidth_contributed
// - 10% compute_contributed
// + Time decay (0.99 per hour)
// + Pre-trusted node bootstrap (0.9 initial)
// + Background computation every 5 minutes

let engine = EigenTrustEngine::new(pre_trusted_nodes);
engine.update_local_trust(from, to, success).await;
let score = engine.get_trust_async(node_id).await;
```

#### 5. Geographic Routing - ALREADY IN SAORSA-CORE!

**File:** `saorsa-core/src/dht/geographic_routing.rs`

```rust
// Just use saorsa-core's geographic routing!
use saorsa_core::dht::geographic_routing::{GeographicRegion, LatencyAwareSelection};

// 7 geographic regions with cross-region preference scores
// Expected latency ranges per region (15-200ms)
// Latency-aware peer selection
// ASN diversity enforcement
```

#### 6. Security Manager - ALREADY IN SAORSA-CORE!

**File:** `saorsa-core/src/adaptive/security.rs` (1,326 lines)

```rust
// Comprehensive security - just configure and use!
use saorsa_core::adaptive::security::{SecurityManager, SecurityConfig};

let security = SecurityManager::new(config, identity);

// ALREADY IMPLEMENTED:
// - Rate limiting: 100 req/min per node, 500/min per IP
// - Join rate: 20 new nodes/hour
// - Blacklist with 24-hour TTL
// - Eclipse attack detection via diversity scoring
// - Message integrity verification (ML-DSA)
// - Full audit logging with 30-day retention
```

#### 7. NetworkCoordinator - INTEGRATES EVERYTHING!

**File:** `saorsa-core/src/adaptive/coordinator.rs`

```rust
// The coordinator brings ALL components together
pub struct NetworkCoordinator {
    identity: Arc<NodeIdentity>,
    transport: Arc<TransportManager>,
    dht: Arc<AdaptiveDHT>,                    // Trust-weighted Kademlia
    router: Arc<AdaptiveRouter>,              // Geographic + trust routing
    trust_engine: Arc<EigenTrustEngine>,      // EigenTrust++
    gossip: Arc<AdaptiveGossipSub>,           // Pub/sub messaging
    storage: Arc<ContentStore>,               // DHT storage
    replication: Arc<ReplicationManager>,     // k=8 replication
    churn_handler: Arc<ChurnHandler>,         // Node churn handling
    security: Arc<SecurityManager>,           // All security features
    // + ML optimization components
}
```

#### 8. What saorsa-node Builds

**Components implemented in saorsa-node:**

```rust
/// ANT chunk protocol - wire protocol for chunk operations (not in saorsa-core)
pub struct AntProtocol {
    storage: Arc<DiskStorage>,                // Content-addressed disk persistence
    payment_verifier: Arc<PaymentVerifier>,   // EVM payment verification
    quote_generator: Arc<QuoteGenerator>,     // Storage quote generation
}

/// Content-addressed disk storage (not in saorsa-core)
/// saorsa-core's ContentStore is DHT-level; this is the local persistence layer
pub struct DiskStorage {
    config: DiskStorageConfig,                // Root dir, max_chunks, verify_on_read
    stats: RwLock<StorageStats>,              // Operation counters
    address_locks: Mutex<LruCache<...>>,      // Per-address TOCTOU protection
}

/// Auto-upgrade system (not in saorsa-core)
pub struct UpgradeMonitor {
    github_repo: String,                      // "dirvine/saorsa-node"
    release_signing_key: MlDsaPublicKey,      // Embedded in binary
    check_interval: Duration,                 // Default: 1 hour
    rollback_dir: PathBuf,                    // For failed upgrades
}

/// ant-node data migration (not in saorsa-core)
pub struct AntDataMigrator {
    ant_data_dir: PathBuf,
    // Reads AES-256-GCM-SIV encrypted records
    // Uploads to saorsa-network
}

/// Node lifecycle and CLI (wrapper around saorsa-core)
pub struct NodeLifecycle {
    coordinator: Arc<NetworkCoordinator>,
    upgrade_monitor: UpgradeMonitor,
    migrator: Option<AntDataMigrator>,
}
```

---

## Implementation Phases

**saorsa-core provides:**
- Dual IPv4/IPv6 with DualStackNetworkNode and Happy Eyeballs
- Sybil Resistance with IPv6NodeID and IPDiversityEnforcer
- EigenTrust++ with full trust engine
- Geographic Routing with 7 regions and latency-aware selection
- Security Manager with rate limiting, blacklist, eclipse detection
- P2P transport and message routing via P2PNode
- DHT-level storage via ContentStore (not used for chunk persistence)

**saorsa-node builds on top:**
1. ANT chunk protocol (wire format, message routing, handler)
2. Content-addressed disk storage (sharded directories, atomic writes)
3. EVM payment verification and quoting
4. Auto-upgrade system (Phase 1 Critical)
5. ant-node data migration
6. Node lifecycle/CLI wrapper
7. Configuration/startup glue
8. Chunk replication across storage nodes (future — see below)

### Phase 1: Repository Setup & Core Structure

- [ ] Initialize git repo, push to `dirvine/saorsa-node` on GitHub
- [ ] Create Cargo.toml with saorsa-core, saorsa-pqc dependencies
- [ ] Create project structure
- [ ] Implement NodeBuilder that configures and creates NetworkCoordinator
- [ ] Implement RunningNode as thin wrapper around NetworkCoordinator
- [ ] Basic startup/shutdown lifecycle

### Phase 2: Auto-Upgrade System (CRITICAL)

**This is the one system that doesn't exist in saorsa-core**

- [ ] GitHub release monitor with configurable check interval
- [ ] ML-DSA-65 signature verification for binaries
- [ ] Process replacement with state preservation
- [ ] Rollback functionality (backup current binary)
- [ ] CLI flags: `--auto-upgrade`, `--upgrade-channel`

### Phase 3: ant-node Data Migration

**Read and re-encrypt ant-node records for the new network**

- [ ] Directory scanner for common ant-node paths
- [ ] AES-256-GCM-SIV decryption (read-only, for migration)
- [ ] Upload via coordinator.dht.put() or coordinator.storage.store()
- [ ] Progress tracking and resume capability
- [ ] CLI flag: `--migrate-ant-data <path>`

### Phase 4: CLI & Configuration

- [ ] Create complete CLI with clap
- [ ] Configuration file support (TOML)
- [ ] RPC service for admin commands (optional)

### Phase 5: Integration Testing

- [ ] Single node startup/shutdown test
- [ ] Multi-node network test (local)
- [ ] DHT put/get test via NetworkCoordinator
- [ ] Migration test (mock ant-node data)
- [ ] Auto-upgrade test (mock release)
- [ ] Test IPv4-only, IPv6-only, dual-stack scenarios

### Phase 6: Documentation & Release

- [ ] README.md with quick start
- [ ] API documentation
- [ ] Migration guide from ant-node
- [ ] Release workflow with ML-DSA signing
- [ ] CI/CD pipeline (GitHub Actions)

---

## Key Design Decisions (Finalized)

### 1. Node Architecture: Pure Quantum-Proof (No Legacy)
- **No libp2p** - saorsa-node is clean, uses only ant-quic + saorsa-core
- **Client is the bridge** - saorsa-client handles reading from ant-network
- **Node auto-migrates** - scans local ant-node data and uploads to network
- **Rationale**: Simpler node, cleaner security model, easier maintenance

### 2. Storage Encryption: ChaCha20-Poly1305 (Quantum-Resistant)
- **Disk**: ChaCha20-Poly1305 (new format, not ant-node compatible)
- **Network**: ML-KEM-768 for key exchange, ChaCha20-Poly1305 for symmetric
- **Migration**: ant-node data is read and re-encrypted during upload
- **Rationale**: Full quantum-resistance, clean break from legacy crypto

### 3. Identity: Fresh ML-DSA-65 Keypairs
- Generate completely new quantum-proof identity
- No derivation from legacy ed25519 keys
- **Rationale**: Clean break, better privacy, simpler implementation

### 4. Network: Dual IPv4/IPv6 DHT
- Separate close groups for IPv4 and IPv6
- Data replicated to BOTH for maximum redundancy
- IPv4-only and IPv6-only nodes participate fully in their respective DHTs
- Dual-stack nodes bridge between the two
- **Rationale**: Maximum connectivity, protocol resilience

### 5. Network Hardening
- **Geographic routing**: No datacenter concentration in close groups
- **Sybil resistance**: Join rate limiting, node age, resource verification
- **EigenTrust**: Node reputation and automatic bad node removal
- **Rationale**: Production-grade security

### 6. Migration Strategy: Client-as-Bridge + Node Auto-Migration
- Client reads from both networks, writes to saorsa-network only
- Nodes scan for local ant-node data and upload automatically
- Organic migration through usage
- **Rationale**: No bridge nodes, smooth transition

### 7. Auto-Upgrade: Phase 1 Critical with ML-DSA Verification
- All releases signed with ML-DSA-65 (quantum-proof signatures)
- Public key embedded in binary
- Rollback support for failed upgrades
- **Rationale**: Essential for coordinating network transition

---

## Dependencies

```toml
[dependencies]
# Core (provides networking, DHT, security, trust)
saorsa-core = { path = "../saorsa-core" }
saorsa-pqc = { path = "../saorsa-pqc" }  # ML-DSA for upgrade signature verification

# Migration: Decrypt ant-node data (read-only)
aes-gcm-siv = "0.11"    # Decrypt existing ant-node records
hkdf = "0.12"           # Key derivation for ant-node format

# Async runtime
tokio = { version = "1.35", features = ["full"] }

# CLI
clap = { version = "4", features = ["derive"] }

# Configuration
serde = { version = "1", features = ["derive"] }
toml = "0.8"

# Auto-upgrade
reqwest = { version = "0.12", features = ["json", "rustls-tls"] }
semver = "1"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Error handling
thiserror = "2"

[dev-dependencies]
tempfile = "3"
tokio-test = "0.4"
```

**Note:**
- No libp2p - pure quantum-proof
- No maxminddb - saorsa-core handles GeoIP
- No blake3/chacha20poly1305 - saorsa-core handles encryption
- Only aes-gcm-siv for reading legacy ant-node data

---

## Risk Mitigation

### Migration Speed Risk
- **Risk**: Data migration may be slow if users don't access old data
- **Mitigation**: Node auto-migration uploads local ant-node data proactively
- **Mitigation**: Popular data migrates first through client usage
- **Mitigation**: Optional bulk migration tool for operators

### IPv4/IPv6 Fragmentation Risk
- **Risk**: Networks may diverge if few dual-stack nodes
- **Mitigation**: Incentivize dual-stack node operators
- **Mitigation**: Geographic distribution of dual-stack nodes
- **Mitigation**: Data replicated to BOTH close groups for redundancy

### Sybil Attack Risk
- **Risk**: Attackers may try to dominate close groups
- **Mitigation**: Join rate limiting per subnet
- **Mitigation**: Node age requirements before full participation
- **Mitigation**: Resource verification challenges
- **Mitigation**: Geographic/ASN diversity enforcement

### EigenTrust Gaming Risk
- **Risk**: Nodes may try to game reputation system
- **Mitigation**: Multiple metrics (latency, uptime, success rate)
- **Mitigation**: Cross-validation between nodes
- **Mitigation**: Historical behavior weighting

### Auto-Upgrade Attack Risk
- **Risk**: Compromised release could spread to network
- **Mitigation**: ML-DSA-65 signatures on all binaries
- **Mitigation**: Multiple key holders for release signing
- **Mitigation**: Staged rollout with canary nodes
- **Mitigation**: Rollback functionality
