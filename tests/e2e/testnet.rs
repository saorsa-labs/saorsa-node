//! Test network infrastructure for spawning and managing multiple nodes.
//!
//! This module provides the core infrastructure for creating a local testnet
//! of 25 ant nodes for E2E testing.
//!
//! ## Protocol-Based Testing
//!
//! Each test node includes an `AntProtocol` handler that processes chunk
//! PUT/GET requests using the autonomi protocol messages. This allows E2E
//! tests to validate the complete protocol flow including:
//! - Message encoding/decoding (postcard serialization)
//! - Content address verification
//! - Payment verification (when enabled)
//! - LMDB storage persistence

use ant_node::ant_protocol::{
    ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkMessageBody, ChunkPutRequest,
    ChunkPutResponse, CHUNK_PROTOCOL_ID, MAX_WIRE_MESSAGE_SIZE,
};
use ant_node::client::{send_and_await_chunk_response, DataChunk, XorName};
use ant_node::payment::{
    EvmVerifierConfig, PaymentVerifier, PaymentVerifierConfig, QuoteGenerator,
    QuotingMetricsTracker,
};
use ant_node::replication::config::MAX_REPLICATION_MESSAGE_SIZE;
use ant_node::storage::{AntProtocol, LmdbStorage, LmdbStorageConfig};
use ant_node::{ReplicationConfig, ReplicationEngine};
use bytes::Bytes;
use evmlib::Network as EvmNetwork;
use evmlib::RewardsAddress;
use futures::future::join_all;
use rand::Rng;
use saorsa_core::identity::PeerId;
use saorsa_core::{
    identity::NodeIdentity, IPDiversityConfig as CoreDiversityConfig, MultiAddr,
    NodeConfig as CoreNodeConfig, P2PEvent, P2PNode,
};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

// =============================================================================
// Test Isolation Constants
// =============================================================================
//
// NOTE: E2E tests use a SEPARATE port range from production ant-node.
//
// - Production ant-node: 10000-10999 (see CLAUDE.md)
// - E2E tests: 20000-60000 (this file)
//
// This separation prevents test conflicts with:
// 1. Running local development nodes (which use 10000-10999)
// 2. Parallel test execution (via random port allocation)
// 3. Other Autonomi services (ant-quic: 9000-9999, communitas: 11000-11999)

/// Minimum port for random test allocation.
/// Avoids well-known ports, production ranges, and other Autonomi services.
pub const TEST_PORT_RANGE_MIN: u16 = 20_000;

/// Maximum port for random test allocation.
pub const TEST_PORT_RANGE_MAX: u16 = 60_000;

/// Maximum nodes supported in a test network.
/// Limited to ensure port calculations don't overflow u16.
pub const MAX_TEST_NODE_COUNT: usize = 1000;

// =============================================================================
// Default Timing Constants
// =============================================================================

/// Default delay between spawning nodes (milliseconds).
const DEFAULT_SPAWN_DELAY_MS: u64 = 200;

/// Default timeout for network stabilization (seconds).
const DEFAULT_STABILIZATION_TIMEOUT_SECS: u64 = 120;

/// Default timeout for single node startup (seconds).
const DEFAULT_NODE_STARTUP_TIMEOUT_SECS: u64 = 30;

/// Stabilization timeout for minimal network (seconds).
const MINIMAL_STABILIZATION_TIMEOUT_SECS: u64 = 30;

/// Stabilization timeout for small network (seconds).
const SMALL_STABILIZATION_TIMEOUT_SECS: u64 = 60;

/// Default timeout for chunk operations (seconds).
///
/// Covers the full round-trip: QUIC handshake, up to a 4 MiB payload
/// transfer, and storage confirmation. 30 s was enough on Linux CI but
/// flaked on `macos-latest` runners (nested-virt, roughly half the CPU
/// throughput of the Linux pool) when the 5-node testnet's concurrent
/// QUIC+PQC handshake burst collided with the 4 MiB
/// `test_chunk_store_on_remote_node` fixture. 90 s is deliberately
/// conservative; the happy path completes in well under a second on
/// loopback, so the larger budget only shows up on flakes. Test-only —
/// no production code path reads this constant.
const DEFAULT_CHUNK_OPERATION_TIMEOUT_SECS: u64 = 90;

/// Short node-level network timeout for E2E test harness.
///
/// This bounds DHT leave/request waits during shutdown so tests do not spend
/// most of their runtime in graceful teardown.
const TEST_CORE_CONNECTION_TIMEOUT_SECS: u64 = 2;

// =============================================================================
// AntProtocol Test Configuration
// =============================================================================

/// Payment cache capacity for test nodes.
const TEST_PAYMENT_CACHE_CAPACITY: usize = 1000;

/// Test rewards address (20 bytes, all 0x01).
const TEST_REWARDS_ADDRESS: [u8; 20] = [0x01; 20];

/// Initial records for quoting metrics (test value).
const TEST_INITIAL_RECORDS: usize = 1000;

// =============================================================================
// Default Node Counts
// =============================================================================

/// Default number of nodes in a full test network.
pub const DEFAULT_NODE_COUNT: usize = 25;

/// Default number of bootstrap nodes.
pub const DEFAULT_BOOTSTRAP_COUNT: usize = 3;

/// Number of nodes in a minimal test network.
pub const MINIMAL_NODE_COUNT: usize = 5;

/// Number of bootstrap nodes in a minimal network.
pub const MINIMAL_BOOTSTRAP_COUNT: usize = 2;

/// Number of nodes in a small test network.
pub const SMALL_NODE_COUNT: usize = 10;

/// Error type for testnet operations.
#[derive(Debug, thiserror::Error)]
pub enum TestnetError {
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Node startup error
    #[error("Node startup error: {0}")]
    Startup(String),

    /// Network stabilization error
    #[error("Network stabilization error: {0}")]
    Stabilization(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Core error
    #[error("Core error: {0}")]
    Core(String),

    /// Data storage error
    #[error("Storage error: {0}")]
    Storage(String),

    /// Data retrieval error
    #[error("Retrieval error: {0}")]
    Retrieval(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Node not running error
    #[error("Node not running")]
    NodeNotRunning,
}

/// Result type for testnet operations.
pub type Result<T> = std::result::Result<T, TestnetError>;

/// Configuration for the test network.
///
/// Each configuration is automatically isolated with unique ports and
/// data directories to prevent test pollution when running in parallel.
#[derive(Debug, Clone)]
pub struct TestNetworkConfig {
    /// Number of nodes to spawn (default: 25).
    pub node_count: usize,

    /// Base port for node allocation (auto-generated for isolation).
    pub base_port: u16,

    /// Number of bootstrap nodes (first N nodes, default: 3).
    pub bootstrap_count: usize,

    /// Root directory for test data (auto-generated for isolation).
    pub test_data_dir: PathBuf,

    /// Delay between node spawns (default: 200ms).
    pub spawn_delay: Duration,

    /// Timeout for network stabilization (default: 120s).
    pub stabilization_timeout: Duration,

    /// Timeout for single node startup (default: 30s).
    pub node_startup_timeout: Duration,

    /// Enable verbose logging for test nodes.
    pub enable_node_logging: bool,

    /// Enable payment enforcement (EVM verification) for test nodes.
    /// Default: false (EVM disabled for speed).
    pub payment_enforcement: bool,

    /// Optional EVM network for payment verification.
    /// When `payment_enforcement` is true and this is `Some`, nodes will use
    /// this network (e.g. Anvil testnet) for on-chain verification.
    /// When `None`, defaults to `ArbitrumOne`.
    pub evm_network: Option<EvmNetwork>,

    /// Optional replication-config override applied to every node's
    /// replication engine. `None` uses `ReplicationConfig::default()`. Tests
    /// use this to shorten timers — e.g. the ADR-0003 possession-check delay.
    pub replication_config: Option<ReplicationConfig>,

    /// Optional per-node storage disk-reserve overrides.
    ///
    /// Tests can set a node's reserve above available disk space to make its
    /// capacity pre-check fail deterministically without filling the host disk.
    pub storage_disk_reserve_overrides: HashMap<usize, u64>,
}

impl Default for TestNetworkConfig {
    fn default() -> Self {
        let mut rng = rand::thread_rng();

        // Random port in isolated range to avoid collisions in parallel tests.
        // Ensure we have room for DEFAULT_NODE_COUNT consecutive ports.
        // Calculation: base_port + (DEFAULT_NODE_COUNT - 1) must be < TEST_PORT_RANGE_MAX
        // Safety: DEFAULT_NODE_COUNT (25) fits in u16.
        #[allow(clippy::cast_possible_truncation)]
        let max_base_port = TEST_PORT_RANGE_MAX.saturating_sub(DEFAULT_NODE_COUNT as u16);
        let base_port = if max_base_port > TEST_PORT_RANGE_MIN {
            rng.gen_range(TEST_PORT_RANGE_MIN..max_base_port)
        } else {
            TEST_PORT_RANGE_MIN
        };

        // Random suffix for unique temp directory
        let suffix: u64 = rng.gen();
        let test_data_dir = std::env::temp_dir().join(format!("ant_test_{suffix:x}"));

        Self {
            node_count: DEFAULT_NODE_COUNT,
            base_port,
            bootstrap_count: DEFAULT_BOOTSTRAP_COUNT,
            test_data_dir,
            spawn_delay: Duration::from_millis(DEFAULT_SPAWN_DELAY_MS),
            stabilization_timeout: Duration::from_secs(DEFAULT_STABILIZATION_TIMEOUT_SECS),
            node_startup_timeout: Duration::from_secs(DEFAULT_NODE_STARTUP_TIMEOUT_SECS),
            enable_node_logging: false,
            payment_enforcement: false,
            evm_network: None,
            replication_config: None,
            storage_disk_reserve_overrides: HashMap::new(),
        }
    }
}

impl TestNetworkConfig {
    /// Create a minimal configuration for quick tests (5 nodes).
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            node_count: MINIMAL_NODE_COUNT,
            bootstrap_count: MINIMAL_BOOTSTRAP_COUNT,
            stabilization_timeout: Duration::from_secs(MINIMAL_STABILIZATION_TIMEOUT_SECS),
            ..Default::default()
        }
    }

    /// Create a small configuration for faster tests (10 nodes).
    #[must_use]
    pub fn small() -> Self {
        Self {
            node_count: SMALL_NODE_COUNT,
            bootstrap_count: DEFAULT_BOOTSTRAP_COUNT,
            stabilization_timeout: Duration::from_secs(SMALL_STABILIZATION_TIMEOUT_SECS),
            // The heavy subtree round-1 responder cooldown defaults to 30 min for
            // production rate-limiting; tests audit the same holder repeatedly in
            // quick succession, so drop it to near-zero so audits are not
            // rate-dropped (a dropped round-1 would surface as a timeout).
            replication_config: Some(ReplicationConfig {
                subtree_round1_responder_cooldown: Duration::from_millis(1),
                ..ReplicationConfig::default()
            }),
            ..Default::default()
        }
    }

    /// Enable payment enforcement for this configuration.
    ///
    /// When enabled, nodes will require valid EVM payment proofs
    /// for all chunk storage operations. This allows testing the
    /// full payment enforcement flow.
    #[must_use]
    pub fn with_payment_enforcement(mut self) -> Self {
        self.payment_enforcement = true;
        self
    }

    /// Set the EVM network for payment verification.
    ///
    /// Use this with `with_payment_enforcement()` to wire nodes to
    /// a local Anvil testnet for on-chain payment verification.
    #[must_use]
    pub fn with_evm_network(mut self, network: EvmNetwork) -> Self {
        self.evm_network = Some(network);
        self
    }
}

/// State of the test network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkState {
    /// Network has not been started.
    Uninitialized,
    /// Bootstrap nodes are starting.
    BootstrappingPhase,
    /// Regular nodes are starting.
    NodeSpawningPhase,
    /// Waiting for network stabilization.
    Stabilizing,
    /// Network is fully operational.
    Ready,
    /// Network is shutting down.
    ShuttingDown,
    /// Network has been shut down.
    Stopped,
    /// Network failed to start.
    Failed(String),
}

impl NetworkState {
    /// Check if the network is in a running state.
    #[must_use]
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Ready | Self::Stabilizing)
    }
}

/// State of an individual test node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeState {
    /// Node has not been started.
    Pending,
    /// Node is starting up.
    Starting,
    /// Node is running and healthy.
    Running,
    /// Node is connecting to peers.
    Connecting,
    /// Node is fully connected to the network.
    Connected,
    /// Node is stopping.
    Stopping,
    /// Node has stopped.
    Stopped,
    /// Node has been intentionally shut down (simulated failure).
    ShutDown,
    /// Node encountered an error.
    Failed(String),
}

/// Represents a single test node in the network.
pub struct TestNode {
    /// Node index (0-based).
    pub index: usize,

    /// Unique node ID.
    pub node_id: String,

    /// Port this node listens on.
    pub port: u16,

    /// Root directory for this node's data.
    pub data_dir: PathBuf,

    /// Reference to the running P2P node.
    pub p2p_node: Option<Arc<P2PNode>>,

    /// ANT protocol handler (`AntProtocol`) for processing chunk PUT/GET requests.
    pub ant_protocol: Option<Arc<AntProtocol>>,

    /// Is this a bootstrap node?
    pub is_bootstrap: bool,

    /// Node state.
    pub state: Arc<RwLock<NodeState>>,

    /// Bootstrap addresses this node connects to.
    pub bootstrap_addrs: Vec<MultiAddr>,

    /// ML-DSA-65 identity used for quote signing.
    ///
    /// Stored so that `start_node` can inject the same identity into the
    /// `P2PNode`, ensuring the transport-level peer ID matches the public
    /// key embedded in payment quotes (`BLAKE3(pub_key)` == `peer_id`).
    pub node_identity: Option<Arc<NodeIdentity>>,

    /// Protocol handler background task handle.
    ///
    /// Populated once the node starts and the protocol router is spawned.
    /// Dropped (and aborted) during teardown so tests don't leave tasks behind.
    pub protocol_task: Option<JoinHandle<()>>,

    /// Replication engine for this test node.
    pub replication_engine: Option<ReplicationEngine>,

    /// Shutdown token for the replication engine.
    pub replication_shutdown: Option<CancellationToken>,
}

impl TestNode {
    /// Check if this node is running.
    pub async fn is_running(&self) -> bool {
        matches!(
            &*self.state.read().await,
            NodeState::Running | NodeState::Connected
        )
    }

    /// Shutdown this test node gracefully.
    ///
    /// This simulates a node failure by shutting down the P2P node and
    /// stopping the protocol handler. The node's state is set to `ShutDown`.
    ///
    /// # Errors
    ///
    /// Returns an error if the node is not running or shutdown fails.
    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down test node {}", self.index);

        // Shut down replication engine and await its background tasks so all
        // Arc<LmdbStorage> clones are released before we drop the engine.
        if let Some(ref mut engine) = self.replication_engine {
            engine.shutdown().await;
        }
        self.replication_engine = None;
        self.replication_shutdown = None;

        // Stop protocol handler
        if let Some(handle) = self.protocol_task.take() {
            handle.abort();
        }

        *self.state.write().await = NodeState::Stopping;

        // Shutdown P2P node if running
        if let Some(p2p) = self.p2p_node.take() {
            p2p.shutdown()
                .await
                .map_err(|e| TestnetError::Core(format!("Failed to shutdown node: {e}")))?;
        }

        *self.state.write().await = NodeState::ShutDown;
        info!("Test node {} shut down successfully", self.index);
        Ok(())
    }

    /// Get the number of connected peers.
    pub async fn peer_count(&self) -> usize {
        if let Some(ref node) = self.p2p_node {
            node.peer_count().await
        } else {
            0
        }
    }

    /// Get the list of connected peer IDs.
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        if let Some(ref node) = self.p2p_node {
            node.connected_peers().await
        } else {
            vec![]
        }
    }

    // =========================================================================
    // Chunk Operations (via autonomi protocol messages)
    // =========================================================================

    /// Store a chunk using the autonomi protocol.
    ///
    /// Creates a `ChunkPutRequest` message, sends it to the local `AntProtocol`
    /// handler, and parses the `ChunkPutResponse`.
    ///
    /// Returns the content-addressed `XorName` where the chunk is stored.
    ///
    /// # Errors
    ///
    /// Returns an error if the node is not running, chunk exceeds max size,
    /// protocol handling fails, or the response indicates an error.
    pub async fn store_chunk(&self, data: &[u8]) -> Result<XorName> {
        let protocol = self
            .ant_protocol
            .as_ref()
            .ok_or(TestnetError::NodeNotRunning)?;

        // Compute content address
        let address = Self::compute_chunk_address(data);

        // Pre-populate payment cache so the handler accepts the store
        // without an on-chain proof.
        protocol.payment_verifier().cache_insert(address);

        let request_id: u64 = rand::thread_rng().gen();
        let request = ChunkPutRequest::new(address, Bytes::copy_from_slice(data));
        let message = ChunkMessage {
            request_id,
            body: ChunkMessageBody::PutRequest(request),
        };
        let message_bytes = message.encode().map_err(|e| {
            TestnetError::Serialization(format!("Failed to encode PUT request: {e}"))
        })?;

        // Handle the protocol message
        let timeout = Duration::from_secs(DEFAULT_CHUNK_OPERATION_TIMEOUT_SECS);
        let response_bytes =
            tokio::time::timeout(timeout, protocol.try_handle_request(&message_bytes))
                .await
                .map_err(|_| {
                    TestnetError::Storage(format!(
                        "Timeout storing chunk after {DEFAULT_CHUNK_OPERATION_TIMEOUT_SECS}s"
                    ))
                })?
                .map_err(|e| TestnetError::Storage(format!("Protocol error: {e}")))?
                .ok_or_else(|| {
                    TestnetError::Storage(format!(
                        "Protocol returned no response for PUT request (request_id={request_id}, node_index={})",
                        self.index
                    ))
                })?;

        // Parse response
        let response = ChunkMessage::decode(&response_bytes)
            .map_err(|e| TestnetError::Storage(format!("Failed to decode response: {e}")))?;

        match response.body {
            ChunkMessageBody::PutResponse(ChunkPutResponse::Success { address: addr }) => {
                debug!("Node {} stored chunk at {}", self.index, hex::encode(addr));
                Ok(addr)
            }
            ChunkMessageBody::PutResponse(ChunkPutResponse::AlreadyExists { address: addr }) => {
                debug!(
                    "Node {} chunk already exists at {}",
                    self.index,
                    hex::encode(addr)
                );
                Ok(addr)
            }
            ChunkMessageBody::PutResponse(ChunkPutResponse::PaymentRequired { message }) => Err(
                TestnetError::Storage(format!("Payment required: {message}")),
            ),
            ChunkMessageBody::PutResponse(ChunkPutResponse::Error(e)) => {
                Err(TestnetError::Storage(format!("Protocol error: {e}")))
            }
            _ => Err(TestnetError::Storage(
                "Unexpected response type".to_string(),
            )),
        }
    }

    /// Retrieve a chunk using the autonomi protocol.
    ///
    /// Creates a `ChunkGetRequest` message, sends it to the local `AntProtocol`
    /// handler, and parses the `ChunkGetResponse`.
    ///
    /// # Errors
    ///
    /// Returns an error if the node is not running, protocol handling fails,
    /// or the response indicates an error.
    pub async fn get_chunk(&self, address: &XorName) -> Result<Option<DataChunk>> {
        let protocol = self
            .ant_protocol
            .as_ref()
            .ok_or(TestnetError::NodeNotRunning)?;

        // Create GET request
        let request_id: u64 = rand::thread_rng().gen();
        let request = ChunkGetRequest::new(*address);
        let message = ChunkMessage {
            request_id,
            body: ChunkMessageBody::GetRequest(request),
        };
        let message_bytes = message.encode().map_err(|e| {
            TestnetError::Serialization(format!("Failed to encode GET request: {e}"))
        })?;

        // Handle the protocol message
        let timeout = Duration::from_secs(DEFAULT_CHUNK_OPERATION_TIMEOUT_SECS);
        let response_bytes =
            tokio::time::timeout(timeout, protocol.try_handle_request(&message_bytes))
                .await
                .map_err(|_| {
                    TestnetError::Retrieval(format!(
                        "Timeout retrieving chunk after {DEFAULT_CHUNK_OPERATION_TIMEOUT_SECS}s"
                    ))
                })?
                .map_err(|e| TestnetError::Retrieval(format!("Protocol error: {e}")))?
                .ok_or_else(|| {
                    TestnetError::Retrieval(format!(
                        "Protocol returned no response for GET request (request_id={request_id}, address={address:?})"
                    ))
                })?;

        // Parse response
        let response = ChunkMessage::decode(&response_bytes)
            .map_err(|e| TestnetError::Retrieval(format!("Failed to decode response: {e}")))?;

        match response.body {
            ChunkMessageBody::GetResponse(ChunkGetResponse::Success { address, content }) => {
                debug!(
                    "Node {} retrieved chunk {} ({} bytes)",
                    self.index,
                    hex::encode(address),
                    content.len()
                );
                Ok(Some(DataChunk::new(address, Bytes::from(content))))
            }
            ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound { address }) => {
                debug!(
                    "Node {} chunk not found: {}",
                    self.index,
                    hex::encode(address)
                );
                Ok(None)
            }
            ChunkMessageBody::GetResponse(ChunkGetResponse::Error(e)) => {
                Err(TestnetError::Retrieval(format!("Protocol error: {e}")))
            }
            _ => Err(TestnetError::Retrieval(
                "Unexpected response type".to_string(),
            )),
        }
    }

    // =========================================================================
    // Remote Chunk Operations (via P2P network)
    // =========================================================================

    /// Store a chunk on a remote node via P2P.
    ///
    /// Sends a `ChunkPutRequest` to the target node over the P2P network
    /// and waits for the `ChunkPutResponse`.
    ///
    /// # Errors
    ///
    /// Returns an error if either node is not running, the message cannot be
    /// sent, the response times out, or the remote node reports an error.
    pub async fn store_chunk_on(&self, target: &Self, data: &[u8]) -> Result<XorName> {
        let target_p2p = target
            .p2p_node
            .as_ref()
            .ok_or(TestnetError::NodeNotRunning)?;
        let target_peer_id = target_p2p.peer_id();
        self.store_chunk_on_peer(target_peer_id, data).await
    }

    /// Store a chunk on a remote peer via P2P using the peer's ID directly.
    ///
    /// # Errors
    ///
    /// Returns an error if this node is not running, the message cannot be
    /// sent, the response times out, or the remote peer reports an error.
    pub async fn store_chunk_on_peer(
        &self,
        target_peer_id: &PeerId,
        data: &[u8],
    ) -> Result<XorName> {
        let p2p = self.p2p_node.as_ref().ok_or(TestnetError::NodeNotRunning)?;

        // Create PUT request without payment proof — caller must pre-populate
        // the target node's payment cache via harness.prepopulate_payment_cache_for_peer().
        let address = Self::compute_chunk_address(data);

        let request_id: u64 = rand::thread_rng().gen();
        let request = ChunkPutRequest::new(address, Bytes::copy_from_slice(data));
        let message = ChunkMessage {
            request_id,
            body: ChunkMessageBody::PutRequest(request),
        };
        let message_bytes = message.encode().map_err(|e| {
            TestnetError::Serialization(format!("Failed to encode PUT request: {e}"))
        })?;

        let timeout = Duration::from_secs(DEFAULT_CHUNK_OPERATION_TIMEOUT_SECS);
        let node_index = self.index;

        send_and_await_chunk_response(
            p2p,
            target_peer_id,
            message_bytes,
            request_id,
            timeout,
            &[],
            |body| match body {
                ChunkMessageBody::PutResponse(ChunkPutResponse::Success { address: addr }) => {
                    debug!(
                        "Node {} stored chunk on peer {}: {}",
                        node_index,
                        target_peer_id,
                        hex::encode(addr)
                    );
                    Some(Ok(addr))
                }
                ChunkMessageBody::PutResponse(ChunkPutResponse::AlreadyExists {
                    address: addr,
                }) => {
                    debug!(
                        "Node {} chunk already exists on peer {}: {}",
                        node_index,
                        target_peer_id,
                        hex::encode(addr)
                    );
                    Some(Ok(addr))
                }
                ChunkMessageBody::PutResponse(ChunkPutResponse::PaymentRequired { message }) => {
                    Some(Err(TestnetError::Storage(format!(
                        "Payment required: {message}"
                    ))))
                }
                ChunkMessageBody::PutResponse(ChunkPutResponse::Error(e)) => Some(Err(
                    TestnetError::Storage(format!("Remote protocol error: {e}")),
                )),
                _ => None,
            },
            |e| TestnetError::Storage(format!("Failed to send PUT to remote node: {e}")),
            || {
                TestnetError::Storage(format!(
                    "Timeout waiting for remote store response after {DEFAULT_CHUNK_OPERATION_TIMEOUT_SECS}s"
                ))
            },
        )
        .await
    }

    /// Retrieve a chunk from a remote node via P2P.
    ///
    /// Sends a `ChunkGetRequest` to the target node over the P2P network
    /// and waits for the `ChunkGetResponse`.
    ///
    /// # Errors
    ///
    /// Returns an error if either node is not running, the message cannot be
    /// sent, the response times out, or the remote node reports an error.
    pub async fn get_chunk_from(
        &self,
        target: &Self,
        address: &XorName,
    ) -> Result<Option<DataChunk>> {
        let target_p2p = target
            .p2p_node
            .as_ref()
            .ok_or(TestnetError::NodeNotRunning)?;
        let target_peer_id = target_p2p.peer_id();
        self.get_chunk_from_peer(target_peer_id, address).await
    }

    /// Retrieve a chunk from a remote peer via P2P using the peer's ID directly.
    ///
    /// # Errors
    ///
    /// Returns an error if this node is not running, the message cannot be
    /// sent, the response times out, or the remote peer reports an error.
    pub async fn get_chunk_from_peer(
        &self,
        target_peer_id: &PeerId,
        address: &XorName,
    ) -> Result<Option<DataChunk>> {
        let p2p = self.p2p_node.as_ref().ok_or(TestnetError::NodeNotRunning)?;

        // Create GET request
        let request_id: u64 = rand::thread_rng().gen();
        let request = ChunkGetRequest::new(*address);
        let message = ChunkMessage {
            request_id,
            body: ChunkMessageBody::GetRequest(request),
        };
        let message_bytes = message.encode().map_err(|e| {
            TestnetError::Serialization(format!("Failed to encode GET request: {e}"))
        })?;

        let timeout = Duration::from_secs(DEFAULT_CHUNK_OPERATION_TIMEOUT_SECS);
        let node_index = self.index;

        send_and_await_chunk_response(
            p2p,
            target_peer_id,
            message_bytes,
            request_id,
            timeout,
            &[],
            |body| match body {
                ChunkMessageBody::GetResponse(ChunkGetResponse::Success {
                    address: addr,
                    content,
                }) => {
                    debug!(
                        "Node {} retrieved chunk from peer {}: {} ({} bytes)",
                        node_index,
                        target_peer_id,
                        hex::encode(addr),
                        content.len()
                    );
                    Some(Ok(Some(DataChunk::new(addr, Bytes::from(content)))))
                }
                ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound { address: addr }) => {
                    debug!(
                        "Node {} chunk not found on peer {}: {}",
                        node_index,
                        target_peer_id,
                        hex::encode(addr)
                    );
                    Some(Ok(None))
                }
                ChunkMessageBody::GetResponse(ChunkGetResponse::Error(e)) => Some(Err(
                    TestnetError::Retrieval(format!("Remote protocol error: {e}")),
                )),
                _ => None,
            },
            |e| TestnetError::Retrieval(format!("Failed to send GET to remote node: {e}")),
            || {
                TestnetError::Retrieval(format!(
                    "Timeout waiting for remote get response after {DEFAULT_CHUNK_OPERATION_TIMEOUT_SECS}s"
                ))
            },
        )
        .await
    }

    /// Compute content address for chunk data (BLAKE3 hash).
    #[must_use]
    pub fn compute_chunk_address(data: &[u8]) -> XorName {
        ant_node::compute_address(data)
    }
}

/// Manages a network of test nodes.
pub struct TestNetwork {
    /// Network configuration.
    config: TestNetworkConfig,

    /// All test nodes (index `0..bootstrap_count` are bootstrap nodes).
    nodes: Vec<TestNode>,

    /// Shared shutdown signal.
    shutdown_tx: broadcast::Sender<()>,

    /// Network state.
    state: Arc<RwLock<NetworkState>>,

    /// Health monitor handle.
    health_monitor: Option<JoinHandle<()>>,
}

impl TestNetwork {
    /// Create a new test network with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or the test
    /// data directory cannot be created.
    pub async fn new(config: TestNetworkConfig) -> Result<Self> {
        // Validate configuration
        if config.bootstrap_count >= config.node_count {
            return Err(TestnetError::Config(
                "Bootstrap count must be less than node count".to_string(),
            ));
        }

        if config.bootstrap_count == 0 {
            return Err(TestnetError::Config(
                "At least one bootstrap node is required".to_string(),
            ));
        }

        // Validate node count fits in u16 for port calculations
        if config.node_count > MAX_TEST_NODE_COUNT {
            return Err(TestnetError::Config(format!(
                "Node count {} exceeds maximum {}",
                config.node_count, MAX_TEST_NODE_COUNT
            )));
        }

        // Validate port range doesn't overflow
        let node_count_u16 = u16::try_from(config.node_count).map_err(|_| {
            TestnetError::Config(format!("Node count {} exceeds u16::MAX", config.node_count))
        })?;
        let max_port = config
            .base_port
            .checked_add(node_count_u16)
            .ok_or_else(|| {
                TestnetError::Config(format!(
                    "Port range overflow: base_port {} + node_count {} exceeds u16::MAX",
                    config.base_port, config.node_count
                ))
            })?;
        if max_port > TEST_PORT_RANGE_MAX {
            return Err(TestnetError::Config(format!(
                "Port range overflow: max port {max_port} exceeds TEST_PORT_RANGE_MAX {TEST_PORT_RANGE_MAX}"
            )));
        }

        // Ensure test data directory exists
        tokio::fs::create_dir_all(&config.test_data_dir).await?;

        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            config,
            nodes: Vec::new(),
            shutdown_tx,
            state: Arc::new(RwLock::new(NetworkState::Uninitialized)),
            health_monitor: None,
        })
    }

    /// Create a test network with default configuration (25 nodes).
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub async fn with_defaults() -> Result<Self> {
        Self::new(TestNetworkConfig::default()).await
    }

    /// Create a test network with minimal configuration (5 nodes).
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails.
    pub async fn minimal() -> Result<Self> {
        Self::new(TestNetworkConfig::minimal()).await
    }

    /// Start the entire test network.
    ///
    /// This method:
    /// 1. Starts bootstrap nodes first
    /// 2. Waits for bootstrap nodes to be ready
    /// 3. Starts regular nodes with bootstrap addresses
    /// 4. Waits for network stabilization
    ///
    /// # Errors
    ///
    /// Returns an error if any node fails to start or the network
    /// fails to stabilize within the timeout.
    pub async fn start(&mut self) -> Result<()> {
        info!(
            "Starting test network with {} nodes ({} bootstrap)",
            self.config.node_count, self.config.bootstrap_count
        );

        *self.state.write().await = NetworkState::BootstrappingPhase;

        // Phase 1: Start bootstrap nodes
        self.start_bootstrap_nodes().await?;

        // Phase 2: Start regular nodes
        *self.state.write().await = NetworkState::NodeSpawningPhase;
        self.start_regular_nodes().await?;

        // Phase 3: Wait for network stabilization
        *self.state.write().await = NetworkState::Stabilizing;
        self.wait_for_stabilization().await?;

        // Phase 4: Start health monitor
        self.start_health_monitor();

        *self.state.write().await = NetworkState::Ready;
        info!("Test network is ready");
        Ok(())
    }

    /// Start bootstrap nodes (first N nodes).
    async fn start_bootstrap_nodes(&mut self) -> Result<()> {
        info!("Starting {} bootstrap nodes", self.config.bootstrap_count);

        for i in 0..self.config.bootstrap_count {
            let node = self.create_node(i, true, vec![]).await?;
            self.start_node(node).await?;

            // Delay between spawns to prevent port conflicts
            tokio::time::sleep(self.config.spawn_delay).await;
        }

        // Wait for bootstrap nodes to be ready
        self.wait_for_nodes_ready(0..self.config.bootstrap_count)
            .await?;

        info!("All bootstrap nodes are ready");
        Ok(())
    }

    /// Start regular nodes.
    async fn start_regular_nodes(&mut self) -> Result<()> {
        let regular_count = self.config.node_count - self.config.bootstrap_count;
        info!("Starting {} regular nodes", regular_count);

        let bootstrap_addrs: Vec<MultiAddr> = self
            .nodes
            .get(0..self.config.bootstrap_count)
            .unwrap_or_default()
            .iter()
            .map(|n| MultiAddr::quic(SocketAddr::from((Ipv4Addr::LOCALHOST, n.port))))
            .collect();

        for i in self.config.bootstrap_count..self.config.node_count {
            let node = self.create_node(i, false, bootstrap_addrs.clone()).await?;
            self.start_node(node).await?;

            // Staggered spawns to prevent overwhelming bootstrap nodes
            tokio::time::sleep(self.config.spawn_delay).await;
        }

        info!("All regular nodes started");
        Ok(())
    }

    /// Create a test node (but don't start it yet).
    ///
    /// Initializes the `AntProtocol` handler with:
    /// - LMDB storage in the node's data directory
    /// - Payment verification configured per `TestNetworkConfig`
    /// - Quote generation with a test rewards address
    async fn create_node(
        &self,
        index: usize,
        is_bootstrap: bool,
        bootstrap_addrs: Vec<MultiAddr>,
    ) -> Result<TestNode> {
        // Safe: node_count is validated in TestNetwork::new() to fit in u16
        let index_u16 = u16::try_from(index)
            .map_err(|_| TestnetError::Config(format!("Node index {index} exceeds u16::MAX")))?;
        let port = self.config.base_port + index_u16;
        let node_id = format!("test_node_{index}");
        let data_dir = self.config.test_data_dir.join(&node_id);

        tokio::fs::create_dir_all(&data_dir).await?;

        // Generate an ML-DSA-65 identity for this test node's quote signing
        // AND for the P2PNode so BLAKE3(pub_key) == transport peer_id.
        let identity = Arc::new(NodeIdentity::generate().map_err(|e| {
            TestnetError::Core(format!("Failed to generate test node identity: {e}"))
        })?);

        // Initialize AntProtocol for this node with payment enforcement setting
        let storage_disk_reserve = self
            .config
            .storage_disk_reserve_overrides
            .get(&index)
            .copied()
            .unwrap_or_default();
        let ant_protocol = Self::create_ant_protocol_with_disk_reserve(
            &data_dir,
            self.config.evm_network.clone(),
            storage_disk_reserve,
            &identity,
        )
        .await?;

        Ok(TestNode {
            index,
            node_id,
            port,
            data_dir,
            p2p_node: None,
            ant_protocol: Some(Arc::new(ant_protocol)),
            is_bootstrap,
            state: Arc::new(RwLock::new(NodeState::Pending)),
            bootstrap_addrs,
            node_identity: Some(identity),
            protocol_task: None,
            replication_engine: None,
            replication_shutdown: None,
        })
    }

    /// Create an `AntProtocol` handler for a test node.
    ///
    /// Configures:
    /// - LMDB storage with verification enabled
    /// - Payment verification (enabled/disabled based on `payment_enforcement`)
    /// - Quote generator with a test rewards address
    ///
    /// # Arguments
    ///
    /// * `data_dir` - Directory for LMDB storage
    /// * `payment_enforcement` - Whether to enable EVM payment verification
    ///
    /// # Errors
    ///
    /// Returns an error if LMDB storage initialisation fails.
    pub async fn create_ant_protocol(
        data_dir: &std::path::Path,
        evm_network: Option<EvmNetwork>,
        identity: &saorsa_core::identity::NodeIdentity,
    ) -> Result<AntProtocol> {
        Self::create_ant_protocol_with_disk_reserve(data_dir, evm_network, 0, identity).await
    }

    /// Create an `AntProtocol` handler with an explicit storage disk reserve.
    ///
    /// # Errors
    ///
    /// Returns an error if LMDB storage initialisation fails.
    pub async fn create_ant_protocol_with_disk_reserve(
        data_dir: &std::path::Path,
        evm_network: Option<EvmNetwork>,
        disk_reserve: u64,
        identity: &saorsa_core::identity::NodeIdentity,
    ) -> Result<AntProtocol> {
        // Create LMDB storage
        let storage_config = LmdbStorageConfig {
            root_dir: data_dir.to_path_buf(),
            disk_reserve,
            ..LmdbStorageConfig::test_default()
        };
        let storage = LmdbStorage::new(storage_config)
            .await
            .map_err(|e| TestnetError::Core(format!("Failed to create LMDB storage: {e}")))?;

        // Create payment verifier (EVM is always on).
        // When an EVM network is provided (e.g. Anvil), use it for on-chain verification.
        // Otherwise default to ArbitrumSepoliaTest for test nodes.
        let rewards_address = RewardsAddress::new(TEST_REWARDS_ADDRESS);
        let replication_config = ReplicationConfig::default();
        let payment_config = PaymentVerifierConfig {
            evm: EvmVerifierConfig {
                network: evm_network.unwrap_or(EvmNetwork::ArbitrumSepoliaTest),
            },
            cache_capacity: TEST_PAYMENT_CACHE_CAPACITY,
            close_group_size: replication_config.close_group_size,
            local_rewards_address: rewards_address,
            price_floor: ant_node::payment::PriceFloorConfig::default(),
        };
        let payment_verifier = PaymentVerifier::new(payment_config);

        // Create quote generator with ML-DSA-65 signing from the test node's identity
        let metrics_tracker = QuotingMetricsTracker::new(TEST_INITIAL_RECORDS);
        let mut quote_generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        // Wire ML-DSA-65 signing so quotes are properly signed and verifiable
        let pub_key_bytes = identity.public_key().as_bytes().to_vec();
        let sk_bytes = identity.secret_key_bytes().to_vec();
        let sk = {
            use saorsa_pqc::pqc::types::MlDsaSecretKey;
            match MlDsaSecretKey::from_bytes(&sk_bytes) {
                Ok(sk) => sk,
                Err(e) => {
                    return Err(TestnetError::Core(format!(
                        "Failed to deserialize ML-DSA-65 secret key: {e}"
                    )));
                }
            }
        };
        quote_generator.set_signer(pub_key_bytes, move |msg| {
            use saorsa_pqc::pqc::MlDsaOperations;

            let ml_dsa = saorsa_core::MlDsa65::new();
            ml_dsa
                .sign(&sk, msg)
                .map_or_else(|_| vec![], |sig| sig.as_bytes().to_vec())
        });

        Ok(AntProtocol::new(
            Arc::new(storage),
            Arc::new(payment_verifier),
            Arc::new(quote_generator),
        ))
    }

    /// Start a single node.
    #[allow(clippy::too_many_lines)]
    async fn start_node(&mut self, mut node: TestNode) -> Result<()> {
        debug!("Starting node {} on port {}", node.index, node.port);
        *node.state.write().await = NodeState::Starting;

        // Retry budget for a transient transport/port-bind race at node
        // creation (a `let`, not an item, to avoid clippy's items-after-
        // statements in this scope). See the loop below for the rationale.
        let node_create_attempts: u32 = 4;

        // Build the saorsa-core config (a fresh one per creation attempt, since
        // P2PNode::new consumes it). Factored into a closure so the transient-
        // error retry below can rebuild it.
        // .local(true) auto-enables allow_loopback for test nodes on 127.0.0.1.
        // .ipv6(false) keeps the bind on 127.0.0.1 only; Windows GitHub
        // Actions runners (and some macOS runners) can't bind a dual-stack
        // v6 socket and the whole testnet startup fails with
        // "Failed to create dual-stack network nodes: Failed to create transport".
        // Loopback-only tests don't need v6.
        let build_core_config = || -> Result<CoreNodeConfig> {
            let mut core_config = CoreNodeConfig::builder()
                .port(node.port)
                .ipv6(false)
                .local(true)
                .connection_timeout(Duration::from_secs(TEST_CORE_CONNECTION_TIMEOUT_SECS))
                .max_message_size(MAX_REPLICATION_MESSAGE_SIZE.max(MAX_WIRE_MESSAGE_SIZE))
                .build()
                .map_err(|e| TestnetError::Core(format!("Failed to create core config: {e}")))?;
            core_config
                .bootstrap_peers
                .clone_from(&node.bootstrap_addrs);
            core_config.diversity_config = Some(CoreDiversityConfig::permissive());
            // Inject the ML-DSA identity so the P2PNode's transport peer ID
            // matches the pub_key embedded in payment quotes.
            core_config.node_identity.clone_from(&node.node_identity);
            Ok(core_config)
        };

        // Create the P2P node, retrying a transient transport/port-bind failure.
        // On Windows (and occasionally macOS) GitHub runners, node creation can
        // intermittently fail with "Failed to create transport" when the freshly
        // chosen loopback port is momentarily still held by a just-released
        // socket — a flaky-setup race, not a logic error. A few retries with a
        // short backoff (same port; the race clears in milliseconds) makes the
        // multi-node bring-up deterministic without masking a real transport
        // misconfiguration (which fails every attempt).
        let mut p2p_node = None;
        let mut last_err = String::new();
        for attempt in 1..=node_create_attempts {
            match P2PNode::new(build_core_config()?).await {
                Ok(n) => {
                    p2p_node = Some(n);
                    break;
                }
                Err(e) => {
                    last_err = e.to_string();
                    debug!(
                        "Node {} creation attempt {attempt}/{node_create_attempts} failed \
                         (transient transport/port race?): {last_err}",
                        node.index
                    );
                    tokio::time::sleep(Duration::from_millis(250 * u64::from(attempt))).await;
                }
            }
        }
        let p2p_node = p2p_node.ok_or_else(|| {
            TestnetError::Startup(format!(
                "Failed to create node {} after {node_create_attempts} attempts: {last_err}",
                node.index
            ))
        })?;

        p2p_node.start().await.map_err(|e| {
            TestnetError::Startup(format!("Failed to start node {}: {e}", node.index))
        })?;

        node.p2p_node = Some(Arc::new(p2p_node));
        *node.state.write().await = NodeState::Running;

        // Start protocol handler that routes incoming P2P messages to AntProtocol
        if let (Some(ref p2p), Some(ref protocol)) = (&node.p2p_node, &node.ant_protocol) {
            // Wire P2P into AntProtocol for payment-proof closeness checks.
            protocol.attach_p2p_node(Arc::clone(p2p));

            let mut events = p2p.subscribe_events();
            let p2p_clone = Arc::clone(p2p);
            let protocol_clone = Arc::clone(protocol);
            let node_index = node.index;
            node.protocol_task = Some(tokio::spawn(async move {
                while let Ok(event) = events.recv().await {
                    if let P2PEvent::Message {
                        topic,
                        source: Some(source),
                        data,
                        ..
                    } = event
                    {
                        if topic == CHUNK_PROTOCOL_ID {
                            debug!(
                                "Node {node_index} received chunk protocol message from {source}"
                            );
                            let protocol = Arc::clone(&protocol_clone);
                            let p2p = Arc::clone(&p2p_clone);
                            tokio::spawn(async move {
                                match protocol.try_handle_request(&data).await {
                                    Ok(Some(response)) => {
                                        if let Err(e) = p2p
                                            .send_message(
                                                &source,
                                                CHUNK_PROTOCOL_ID,
                                                response.to_vec(),
                                                &[],
                                            )
                                            .await
                                        {
                                            warn!(
                                                "Node {node_index} failed to send chunk response to {source}: {e}"
                                            );
                                        }
                                    }
                                    Ok(None) => {
                                        // Response message — no reply needed
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Node {node_index} chunk protocol handler error: {e}"
                                        );
                                    }
                                }
                            });
                        }
                    }
                }
            }));
        }

        // Start replication engine for this node. A node without an identity
        // skips ONLY the engine (no early return — the node must still be
        // tracked in `self.nodes` below, or its already-started P2P/protocol
        // tasks would keep running untracked by the harness).
        if let (Some(ref p2p), Some(ref protocol), Some(ref id)) =
            (&node.p2p_node, &node.ant_protocol, &node.node_identity)
        {
            let shutdown = CancellationToken::new();
            let repl_config = self.config.replication_config.clone().unwrap_or_default();
            let (_fresh_tx, fresh_rx) = tokio::sync::mpsc::unbounded_channel();
            let node_identity = Arc::clone(id);
            match ReplicationEngine::new(
                repl_config,
                Arc::clone(p2p),
                protocol.storage(),
                protocol.payment_verifier_arc(),
                node_identity,
                &node.data_dir,
                fresh_rx,
                shutdown.clone(),
            )
            .await
            {
                Ok(mut engine) => {
                    let dht_events = p2p.dht_manager().subscribe_events();
                    engine.start(dht_events);
                    node.replication_engine = Some(engine);
                    node.replication_shutdown = Some(shutdown);
                    debug!("Node {} replication engine started", node.index);
                }
                Err(e) => {
                    warn!(
                        "Node {} failed to start replication engine: {e}",
                        node.index
                    );
                }
            }
        } else if node.node_identity.is_none() {
            warn!(
                "Node {} has no identity; skipping replication engine",
                node.index
            );
        }

        debug!("Node {} started successfully", node.index);
        self.nodes.push(node);
        Ok(())
    }

    /// Wait for specific nodes to reach ready state.
    async fn wait_for_nodes_ready(&self, range: std::ops::Range<usize>) -> Result<()> {
        let deadline = Instant::now() + self.config.node_startup_timeout;

        for i in range {
            while Instant::now() < deadline {
                let node = self
                    .nodes
                    .get(i)
                    .ok_or_else(|| TestnetError::Config(format!("Node index {i} out of range")))?;
                let state = node.state.read().await.clone();
                match state {
                    NodeState::Running | NodeState::Connected => break,
                    NodeState::Failed(ref e) => {
                        return Err(TestnetError::Startup(format!("Node {i} failed: {e}")));
                    }
                    _ => tokio::time::sleep(Duration::from_millis(100)).await,
                }
            }
        }
        Ok(())
    }

    /// Wait for network to stabilize (all nodes connected).
    async fn wait_for_stabilization(&self) -> Result<()> {
        let deadline = Instant::now() + self.config.stabilization_timeout;
        let min_connections = self.config.bootstrap_count.min(3);

        info!(
            "Waiting for network stabilization (min {} connections per node)",
            min_connections
        );

        while Instant::now() < deadline {
            let mut all_connected = true;
            let mut total_connections = 0;

            for node in &self.nodes {
                let peer_count = node.peer_count().await;
                total_connections += peer_count;

                if peer_count < min_connections {
                    all_connected = false;
                }
            }

            if all_connected {
                info!(
                    "Network stabilized: {} total connections",
                    total_connections
                );
                return Ok(());
            }

            debug!(
                "Waiting for stabilization: {} total connections",
                total_connections
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        Err(TestnetError::Stabilization(
            "Network failed to stabilize within timeout".to_string(),
        ))
    }

    /// Warm up DHT routing tables by performing random lookups.
    ///
    /// After network stabilization, nodes are P2P connected but their DHT
    /// routing tables may be sparse. Performing random lookups forces DHT
    /// query traffic that populates and propagates routing information
    /// across the network.
    ///
    /// This is essential for tests that use `get_quotes_from_dht()` which relies
    /// on `find_closest_nodes()` to discover peers.
    ///
    /// # Errors
    ///
    /// Returns an error if DHT lookup fails.
    pub async fn warmup_dht(&self) -> Result<()> {
        info!("Warming up DHT routing tables ({} nodes)", self.nodes.len());

        // Perform DHT queries to populate and propagate routing tables.
        // The permissive diversity config (set in start_node) allows the DHT
        // to accept localhost peers during these find_closest_nodes() calls.
        let num_warmup_queries = 5; // More queries for better DHT coverage
        let mut random_addresses = Vec::new();
        for _ in 0..num_warmup_queries {
            let mut addr = [0u8; 32];
            rand::Rng::fill(&mut rand::thread_rng(), &mut addr);
            random_addresses.push(addr);
        }

        for node in &self.nodes {
            if let Some(ref p2p) = node.p2p_node {
                for addr in &random_addresses {
                    // Perform DHT lookup to populate routing tables
                    let result = p2p.dht().find_closest_nodes(addr, 8).await;
                    if let Ok(peers) = result {
                        if peers.is_empty() {
                            warn!(
                                "Node {} DHT warmup found 0 peers for {} - DHT may not be seeded yet",
                                node.index,
                                hex::encode(addr)
                            );
                        } else {
                            debug!(
                                "Node {} DHT warmup found {} peers for target {}",
                                node.index,
                                peers.len(),
                                hex::encode(addr)
                            );
                        }
                    } else if tracing::enabled!(tracing::Level::WARN) {
                        warn!(
                            "Node {} DHT warmup failed for {}: {:?}",
                            node.index,
                            hex::encode(addr),
                            result
                        );
                    }
                }
            }
        }

        // Give DHT time to propagate discoveries
        tokio::time::sleep(Duration::from_secs(3)).await;

        info!("✅ DHT routing tables warmed up");

        // Wait for all replication engines to exit the bootstrap phase so
        // that audit and neighbor-sync handlers return operational responses
        // instead of `Bootstrapping` / `bootstrapping: true`.
        self.wait_for_replication_bootstrap().await?;

        Ok(())
    }

    /// Wait for every node's replication engine to complete its bootstrap
    /// phase.
    ///
    /// This ensures `is_bootstrapping` is `false` on all nodes before tests
    /// that depend on audit or neighbor-sync responses start running.
    ///
    /// # Errors
    ///
    /// Returns an error if any node's bootstrap does not complete within
    /// the timeout.
    async fn wait_for_replication_bootstrap(&self) -> Result<()> {
        const BOOTSTRAP_TIMEOUT: Duration = Duration::from_mins(2);

        for node in &self.nodes {
            if let Some(ref engine) = node.replication_engine {
                if !engine.wait_for_bootstrap_complete(BOOTSTRAP_TIMEOUT).await {
                    return Err(TestnetError::Stabilization(format!(
                        "Node {} replication bootstrap did not complete within {}s",
                        node.index,
                        BOOTSTRAP_TIMEOUT.as_secs(),
                    )));
                }
                debug!("Node {} replication bootstrap complete", node.index,);
            }
        }

        info!("✅ All replication engines bootstrapped");
        Ok(())
    }

    /// Start background health monitoring.
    fn start_health_monitor(&mut self) {
        let nodes: Vec<Arc<P2PNode>> = self
            .nodes
            .iter()
            .filter_map(|n| n.p2p_node.clone())
            .collect();
        let _state = Arc::clone(&self.state);
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        self.health_monitor = Some(tokio::spawn(async move {
            let check_interval = Duration::from_secs(5);

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => break,
                    () = tokio::time::sleep(check_interval) => {
                        // Check each node's health
                        for (i, node) in nodes.iter().enumerate() {
                            if !node.is_running() {
                                warn!("Node {} appears unhealthy", i);
                            }
                        }
                    }
                }
            }
        }));
    }

    /// Shutdown the entire test network.
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup fails.
    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down test network");
        *self.state.write().await = NetworkState::ShuttingDown;

        // Signal all background tasks to stop
        let _ = self.shutdown_tx.send(());

        // Stop health monitor
        if let Some(handle) = self.health_monitor.take() {
            handle.abort();
        }

        // Stop all nodes in reverse order.
        // We shutdown nodes concurrently to avoid serially accumulating DHT
        // graceful-leave waits across every node.
        // Skip nodes that are already shut down (e.g., via shutdown_node()).
        let mut shutdown_futures = Vec::with_capacity(self.nodes.len());
        for node in self.nodes.iter_mut().rev() {
            let state = node.state.read().await.clone();

            // Skip nodes that are already shut down or stopped
            if matches!(state, NodeState::ShutDown | NodeState::Stopped) {
                debug!("Skipping node {} (already shut down)", node.index);
                continue;
            }

            debug!("Stopping node {}", node.index);
            if let Some(ref mut engine) = node.replication_engine {
                engine.shutdown().await;
            }
            node.replication_engine = None;
            node.replication_shutdown = None;
            if let Some(handle) = node.protocol_task.take() {
                handle.abort();
            }
            *node.state.write().await = NodeState::Stopping;

            if let Some(p2p) = node.p2p_node.clone() {
                let node_index = node.index;
                shutdown_futures.push(async move { (node_index, p2p.shutdown().await) });
            }
        }

        for (node_index, result) in join_all(shutdown_futures).await {
            if let Err(e) = result {
                warn!("Error shutting down node {}: {}", node_index, e);
            }
        }

        for node in &self.nodes {
            let state = node.state.read().await.clone();
            if !matches!(state, NodeState::ShutDown) {
                *node.state.write().await = NodeState::Stopped;
            }
        }

        // Cleanup test data directory
        if let Err(e) = tokio::fs::remove_dir_all(&self.config.test_data_dir).await {
            warn!("Failed to cleanup test data directory: {}", e);
        }

        *self.state.write().await = NetworkState::Stopped;
        info!("Test network shutdown complete");
        Ok(())
    }

    /// Get a reference to a specific node.
    #[must_use]
    pub fn node(&self, index: usize) -> Option<&TestNode> {
        self.nodes.get(index)
    }

    /// Get a mutable reference to a specific node.
    #[must_use]
    pub fn node_mut(&mut self, index: usize) -> Option<&mut TestNode> {
        self.nodes.get_mut(index)
    }

    /// Get all nodes.
    #[must_use]
    pub fn nodes(&self) -> &[TestNode] {
        &self.nodes
    }

    /// Get bootstrap nodes.
    #[must_use]
    pub fn bootstrap_nodes(&self) -> &[TestNode] {
        &self.nodes[0..self.config.bootstrap_count.min(self.nodes.len())]
    }

    /// Get regular (non-bootstrap) nodes.
    #[must_use]
    pub fn regular_nodes(&self) -> &[TestNode] {
        if self.nodes.len() > self.config.bootstrap_count {
            &self.nodes[self.config.bootstrap_count..]
        } else {
            &[]
        }
    }

    /// Get current network state.
    pub async fn state(&self) -> NetworkState {
        self.state.read().await.clone()
    }

    /// Check if network is ready.
    pub async fn is_ready(&self) -> bool {
        matches!(self.state().await, NetworkState::Ready)
    }

    /// Get total peer connections across all nodes.
    pub async fn total_connections(&self) -> usize {
        let mut total = 0;
        for node in &self.nodes {
            total += node.peer_count().await;
        }
        total
    }

    /// Get the number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get the configuration.
    #[must_use]
    pub fn config(&self) -> &TestNetworkConfig {
        &self.config
    }

    /// Add a new node to an already-running network.
    ///
    /// Creates, starts, and bootstraps a fresh node that joins the existing
    /// network. The node's DHT is warmed up and its replication engine is
    /// allowed to complete bootstrap before this method returns.
    ///
    /// Returns the index of the newly added node.
    ///
    /// # Errors
    ///
    /// Returns an error if node creation, startup, or bootstrap fails.
    pub async fn add_node(&mut self) -> Result<usize> {
        const DHT_WARMUP_QUERIES: usize = 10;
        const BOOTSTRAP_TIMEOUT: Duration = Duration::from_mins(2);

        let index = self.nodes.len();

        let bootstrap_addrs: Vec<MultiAddr> = self
            .nodes
            .get(0..self.config.bootstrap_count)
            .unwrap_or_default()
            .iter()
            .map(|n| MultiAddr::quic(SocketAddr::from((Ipv4Addr::LOCALHOST, n.port))))
            .collect();

        let node = self.create_node(index, false, bootstrap_addrs).await?;
        self.start_node(node).await?;

        // Warm the new node's DHT so it discovers existing peers.
        if let Some(ref p2p) = self.nodes[index].p2p_node {
            for _ in 0..DHT_WARMUP_QUERIES {
                let mut addr = [0u8; 32];
                rand::Rng::fill(&mut rand::thread_rng(), &mut addr);
                let _ = p2p.dht().find_closest_nodes(&addr, 8).await;
            }
        }

        // Also warm existing nodes' DHTs so they discover the new peer.
        // Without this, existing nodes may not include the new node in
        // close-group calculations and won't generate replica hints for it.
        for i in 0..index {
            if let Some(ref p2p) = self.nodes[i].p2p_node {
                for _ in 0..DHT_WARMUP_QUERIES {
                    let mut addr = [0u8; 32];
                    rand::Rng::fill(&mut rand::thread_rng(), &mut addr);
                    let _ = p2p.dht().find_closest_nodes(&addr, 8).await;
                }
            }
        }

        // Give DHT time to propagate discoveries bidirectionally.
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Trigger an early neighbor sync on ALL nodes (existing + new) so
        // they exchange hints without waiting for the regular 10-20 minute
        // cadence.  The new node requests hints from its neighbors, and
        // existing nodes push hints to the new peer.
        for node in &self.nodes {
            if let Some(ref engine) = node.replication_engine {
                engine.trigger_neighbor_sync();
            }
        }

        // Wait for replication bootstrap to complete so the node is fully
        // operational (accepting audits, neighbor sync, etc.).
        if let Some(ref engine) = self.nodes[index].replication_engine {
            if !engine.wait_for_bootstrap_complete(BOOTSTRAP_TIMEOUT).await {
                return Err(TestnetError::Stabilization(format!(
                    "New node {index} replication bootstrap did not complete within {}s",
                    BOOTSTRAP_TIMEOUT.as_secs(),
                )));
            }
        }

        info!("New node {index} added and fully bootstrapped");
        Ok(index)
    }

    /// Shutdown a specific node by index.
    ///
    /// This simulates a node failure during testing. The node is gracefully shut down
    /// and its state is set to `ShutDown`. The network continues to operate with the
    /// remaining nodes.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the node to shutdown (0-based)
    ///
    /// # Errors
    ///
    /// Returns an error if the node index is invalid or shutdown fails.
    pub async fn shutdown_node(&mut self, index: usize) -> Result<()> {
        let node = self
            .nodes
            .get_mut(index)
            .ok_or_else(|| TestnetError::Config(format!("Node index {index} out of bounds")))?;

        node.shutdown().await?;

        info!("Node {} has been shut down", index);
        Ok(())
    }

    /// Shutdown multiple nodes by their indices.
    ///
    /// This is a convenience method for simulating multiple node failures at once.
    ///
    /// # Arguments
    ///
    /// * `indices` - Slice of node indices to shutdown
    ///
    /// # Errors
    ///
    /// Returns an error if any node index is invalid or shutdown fails.
    pub async fn shutdown_nodes(&mut self, indices: &[usize]) -> Result<()> {
        for &index in indices {
            self.shutdown_node(index).await?;
        }
        Ok(())
    }

    /// Get the number of currently running nodes.
    pub async fn running_node_count(&self) -> usize {
        let mut count = 0;
        for node in &self.nodes {
            if node.is_running().await {
                count += 1;
            }
        }
        count
    }
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        // Best-effort synchronous cleanup
        // Note: async cleanup should be done via shutdown() before dropping
        let _ = self.shutdown_tx.send(());

        // Cancel replication engine background tasks so they don't outlive
        // the test's tokio runtime.
        for node in &mut self.nodes {
            if let Some(token) = node.replication_shutdown.take() {
                token.cancel();
            }
        }

        // Abort health monitor if still running
        if let Some(handle) = self.health_monitor.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = TestNetworkConfig::default();
        assert_eq!(config.node_count, 25);
        assert_eq!(config.bootstrap_count, 3);
        // Port is randomly generated in range 20000-60000
        assert!(config.base_port >= 20000 && config.base_port < 60000);
        // Data dir has unique suffix
        assert!(config.test_data_dir.to_string_lossy().contains("ant_test_"));
    }

    #[test]
    fn test_config_minimal() {
        let config = TestNetworkConfig::minimal();
        assert_eq!(config.node_count, 5);
        assert_eq!(config.bootstrap_count, 2);
    }

    #[test]
    fn test_config_isolation() {
        // Each config should get unique port and data dir
        let config1 = TestNetworkConfig::default();
        let config2 = TestNetworkConfig::default();

        // Data directories must be unique
        assert_ne!(config1.test_data_dir, config2.test_data_dir);
    }

    #[test]
    fn test_network_state_is_running() {
        assert!(!NetworkState::Uninitialized.is_running());
        assert!(NetworkState::Ready.is_running());
        assert!(NetworkState::Stabilizing.is_running());
        assert!(!NetworkState::Stopped.is_running());
    }

    #[tokio::test]
    async fn test_invalid_bootstrap_count_rejected() {
        let config = TestNetworkConfig {
            node_count: 5,
            bootstrap_count: 5, // Invalid: must be less than node_count
            ..Default::default()
        };

        let result = TestNetwork::new(config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_zero_bootstrap_rejected() {
        let config = TestNetworkConfig {
            node_count: 5,
            bootstrap_count: 0, // Invalid: must have at least one
            ..Default::default()
        };

        let result = TestNetwork::new(config).await;
        assert!(result.is_err());
    }
}
