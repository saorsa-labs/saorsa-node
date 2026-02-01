//! Test network infrastructure for spawning and managing multiple nodes.
//!
//! This module provides the core infrastructure for creating a local testnet
//! of 25 saorsa nodes for E2E testing.
//!
//! ## Protocol-Based Testing
//!
//! Each test node includes a `AntProtocol` handler that processes chunk
//! PUT/GET requests using the autonomi protocol messages. This allows E2E
//! tests to validate the complete protocol flow including:
//! - Message encoding/decoding (bincode serialization)
//! - Content address verification
//! - Payment verification (when enabled)
//! - Disk storage persistence

use ant_evm::RewardsAddress;
use bytes::Bytes;
use rand::Rng;
use saorsa_core::{NodeConfig as CoreNodeConfig, P2PEvent, P2PNode};
use saorsa_node::ant_protocol::{
    ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkMessageBody, ChunkPutRequest,
    ChunkPutResponse, CHUNK_PROTOCOL_ID,
};
use saorsa_node::client::{DataChunk, XorName};
use saorsa_node::payment::{
    EvmVerifierConfig, PaymentVerifier, PaymentVerifierConfig, QuoteGenerator,
    QuotingMetricsTracker,
};
use saorsa_node::storage::{AntProtocol, DiskStorage, DiskStorageConfig};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, warn};

// =============================================================================
// Test Isolation Constants
// =============================================================================
//
// NOTE: E2E tests use a SEPARATE port range from production saorsa-node.
//
// - Production saorsa-node: 10000-10999 (see CLAUDE.md)
// - E2E tests: 20000-60000 (this file)
//
// This separation prevents test conflicts with:
// 1. Running local development nodes (which use 10000-10999)
// 2. Parallel test execution (via random port allocation)
// 3. Other Saorsa services (ant-quic: 9000-9999, communitas: 11000-11999)

/// Minimum port for random test allocation.
/// Avoids well-known ports, production ranges, and other Saorsa services.
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
const DEFAULT_CHUNK_OPERATION_TIMEOUT_SECS: u64 = 30;

// =============================================================================
// AntProtocol Test Configuration
// =============================================================================

/// Payment cache capacity for test nodes.
const TEST_PAYMENT_CACHE_CAPACITY: usize = 1000;

/// Test rewards address (20 bytes, all 0x01).
const TEST_REWARDS_ADDRESS: [u8; 20] = [0x01; 20];

/// Max records for quoting metrics (test value).
const TEST_MAX_RECORDS: usize = 100_000;

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
}

impl Default for TestNetworkConfig {
    fn default() -> Self {
        let mut rng = rand::thread_rng();

        // Random port in isolated range to avoid collisions in parallel tests.
        // Ensure we have room for DEFAULT_NODE_COUNT consecutive ports.
        // Safety: DEFAULT_NODE_COUNT (25) fits in u16.
        #[allow(clippy::cast_possible_truncation)]
        let max_base_port = TEST_PORT_RANGE_MAX.saturating_sub(DEFAULT_NODE_COUNT as u16);
        let base_port = rng.gen_range(TEST_PORT_RANGE_MIN..max_base_port);

        // Random suffix for unique temp directory
        let suffix: u64 = rng.gen();
        let test_data_dir = std::env::temp_dir().join(format!("saorsa_test_{suffix:x}"));

        Self {
            node_count: DEFAULT_NODE_COUNT,
            base_port,
            bootstrap_count: DEFAULT_BOOTSTRAP_COUNT,
            test_data_dir,
            spawn_delay: Duration::from_millis(DEFAULT_SPAWN_DELAY_MS),
            stabilization_timeout: Duration::from_secs(DEFAULT_STABILIZATION_TIMEOUT_SECS),
            node_startup_timeout: Duration::from_secs(DEFAULT_NODE_STARTUP_TIMEOUT_SECS),
            enable_node_logging: false,
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
            ..Default::default()
        }
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

    /// Socket address for this node.
    pub address: SocketAddr,

    /// Root directory for this node's data.
    pub data_dir: PathBuf,

    /// Reference to the running P2P node.
    pub p2p_node: Option<Arc<P2PNode>>,

    /// ANT protocol handler for processing chunk PUT/GET requests.
    pub ant_protocol: Option<Arc<AntProtocol>>,

    /// Is this a bootstrap node?
    pub is_bootstrap: bool,

    /// Node state.
    pub state: Arc<RwLock<NodeState>>,

    /// Bootstrap addresses this node connects to.
    pub bootstrap_addrs: Vec<SocketAddr>,

    /// Protocol handler background task.
    protocol_task: Option<JoinHandle<()>>,
}

impl TestNode {
    /// Check if this node is running.
    pub async fn is_running(&self) -> bool {
        matches!(
            &*self.state.read().await,
            NodeState::Running | NodeState::Connected
        )
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
    pub async fn connected_peers(&self) -> Vec<String> {
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

        // Create PUT request with empty payment proof (EVM disabled in tests)
        let empty_payment = rmp_serde::to_vec(&ant_evm::ProofOfPayment {
            peer_quotes: vec![],
        })
        .map_err(|e| {
            TestnetError::Serialization(format!("Failed to serialize payment proof: {e}"))
        })?;

        let request_id: u64 = rand::thread_rng().gen();
        let request = ChunkPutRequest::with_payment(address, data.to_vec(), empty_payment);
        let message = ChunkMessage {
            request_id,
            body: ChunkMessageBody::PutRequest(request),
        };
        let message_bytes = message.encode().map_err(|e| {
            TestnetError::Serialization(format!("Failed to encode PUT request: {e}"))
        })?;

        // Handle the protocol message
        let timeout = Duration::from_secs(DEFAULT_CHUNK_OPERATION_TIMEOUT_SECS);
        let response_bytes = tokio::time::timeout(timeout, protocol.handle_message(&message_bytes))
            .await
            .map_err(|_| {
                TestnetError::Storage(format!(
                    "Timeout storing chunk after {DEFAULT_CHUNK_OPERATION_TIMEOUT_SECS}s"
                ))
            })?
            .map_err(|e| TestnetError::Storage(format!("Protocol error: {e}")))?;

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
        let response_bytes = tokio::time::timeout(timeout, protocol.handle_message(&message_bytes))
            .await
            .map_err(|_| {
                TestnetError::Retrieval(format!(
                    "Timeout retrieving chunk after {DEFAULT_CHUNK_OPERATION_TIMEOUT_SECS}s"
                ))
            })?
            .map_err(|e| TestnetError::Retrieval(format!("Protocol error: {e}")))?;

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
        let target_peer_id = target_p2p
            .transport_peer_id()
            .ok_or_else(|| TestnetError::Core("No transport peer ID available".to_string()))?;
        self.store_chunk_on_peer(&target_peer_id, data).await
    }

    /// Store a chunk on a remote peer via P2P using the peer's ID directly.
    ///
    /// # Errors
    ///
    /// Returns an error if this node is not running, the message cannot be
    /// sent, the response times out, or the remote peer reports an error.
    pub async fn store_chunk_on_peer(&self, target_peer_id: &str, data: &[u8]) -> Result<XorName> {
        let p2p = self.p2p_node.as_ref().ok_or(TestnetError::NodeNotRunning)?;
        let target_peer_id = target_peer_id.to_string();

        // Subscribe before sending so we don't miss the response
        let mut events = p2p.subscribe_events();

        // Create PUT request
        let address = Self::compute_chunk_address(data);
        let empty_payment = rmp_serde::to_vec(&ant_evm::ProofOfPayment {
            peer_quotes: vec![],
        })
        .map_err(|e| {
            TestnetError::Serialization(format!("Failed to serialize payment proof: {e}"))
        })?;

        let request_id: u64 = rand::thread_rng().gen();
        let request = ChunkPutRequest::with_payment(address, data.to_vec(), empty_payment);
        let message = ChunkMessage {
            request_id,
            body: ChunkMessageBody::PutRequest(request),
        };
        let message_bytes = message.encode().map_err(|e| {
            TestnetError::Serialization(format!("Failed to encode PUT request: {e}"))
        })?;

        // Send to target node
        p2p.send_message(&target_peer_id, CHUNK_PROTOCOL_ID, message_bytes)
            .await
            .map_err(|e| {
                TestnetError::Storage(format!("Failed to send PUT to remote node: {e}"))
            })?;

        // Wait for response matching our request_id
        let timeout = Duration::from_secs(DEFAULT_CHUNK_OPERATION_TIMEOUT_SECS);
        let deadline = Instant::now() + timeout;

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, events.recv()).await {
                Ok(Ok(P2PEvent::Message {
                    topic,
                    data: resp_data,
                    ..
                })) if topic == CHUNK_PROTOCOL_ID => {
                    let response = ChunkMessage::decode(&resp_data).map_err(|e| {
                        TestnetError::Storage(format!("Failed to decode PUT response: {e}"))
                    })?;
                    if response.request_id != request_id {
                        continue; // Not our response, keep waiting
                    }
                    match response.body {
                        ChunkMessageBody::PutResponse(ChunkPutResponse::Success {
                            address: addr,
                        }) => {
                            debug!(
                                "Node {} stored chunk on peer {}: {}",
                                self.index,
                                target_peer_id,
                                hex::encode(addr)
                            );
                            return Ok(addr);
                        }
                        ChunkMessageBody::PutResponse(ChunkPutResponse::AlreadyExists {
                            address: addr,
                        }) => {
                            debug!(
                                "Node {} chunk already exists on peer {}: {}",
                                self.index,
                                target_peer_id,
                                hex::encode(addr)
                            );
                            return Ok(addr);
                        }
                        ChunkMessageBody::PutResponse(ChunkPutResponse::PaymentRequired {
                            message,
                        }) => {
                            return Err(TestnetError::Storage(format!(
                                "Payment required: {message}"
                            )));
                        }
                        ChunkMessageBody::PutResponse(ChunkPutResponse::Error(e)) => {
                            return Err(TestnetError::Storage(format!(
                                "Remote protocol error: {e}"
                            )));
                        }
                        _ => {} // Not a PUT response, keep waiting
                    }
                }
                Ok(Ok(_)) => {} // Different topic, keep waiting
                Ok(Err(_)) | Err(_) => break,
            }
        }

        Err(TestnetError::Storage(format!(
            "Timeout waiting for remote store response after {DEFAULT_CHUNK_OPERATION_TIMEOUT_SECS}s"
        )))
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
        let target_peer_id = target_p2p
            .transport_peer_id()
            .ok_or_else(|| TestnetError::Core("No transport peer ID available".to_string()))?;
        self.get_chunk_from_peer(&target_peer_id, address).await
    }

    /// Retrieve a chunk from a remote peer via P2P using the peer's ID directly.
    ///
    /// # Errors
    ///
    /// Returns an error if this node is not running, the message cannot be
    /// sent, the response times out, or the remote peer reports an error.
    pub async fn get_chunk_from_peer(
        &self,
        target_peer_id: &str,
        address: &XorName,
    ) -> Result<Option<DataChunk>> {
        let p2p = self.p2p_node.as_ref().ok_or(TestnetError::NodeNotRunning)?;
        let target_peer_id = target_peer_id.to_string();

        // Subscribe before sending
        let mut events = p2p.subscribe_events();

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

        // Send to target node
        p2p.send_message(&target_peer_id, CHUNK_PROTOCOL_ID, message_bytes)
            .await
            .map_err(|e| {
                TestnetError::Retrieval(format!("Failed to send GET to remote node: {e}"))
            })?;

        // Wait for response matching our request_id
        let timeout = Duration::from_secs(DEFAULT_CHUNK_OPERATION_TIMEOUT_SECS);
        let deadline = Instant::now() + timeout;

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, events.recv()).await {
                Ok(Ok(P2PEvent::Message {
                    topic,
                    data: resp_data,
                    ..
                })) if topic == CHUNK_PROTOCOL_ID => {
                    let response = ChunkMessage::decode(&resp_data).map_err(|e| {
                        TestnetError::Retrieval(format!("Failed to decode GET response: {e}"))
                    })?;
                    if response.request_id != request_id {
                        continue; // Not our response, keep waiting
                    }
                    match response.body {
                        ChunkMessageBody::GetResponse(ChunkGetResponse::Success {
                            address: addr,
                            content,
                        }) => {
                            debug!(
                                "Node {} retrieved chunk from peer {}: {} ({} bytes)",
                                self.index,
                                target_peer_id,
                                hex::encode(addr),
                                content.len()
                            );
                            return Ok(Some(DataChunk::new(addr, Bytes::from(content))));
                        }
                        ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound {
                            address: addr,
                        }) => {
                            debug!(
                                "Node {} chunk not found on peer {}: {}",
                                self.index,
                                target_peer_id,
                                hex::encode(addr)
                            );
                            return Ok(None);
                        }
                        ChunkMessageBody::GetResponse(ChunkGetResponse::Error(e)) => {
                            return Err(TestnetError::Retrieval(format!(
                                "Remote protocol error: {e}"
                            )));
                        }
                        _ => {} // Not a GET response, keep waiting
                    }
                }
                Ok(Ok(_)) => {} // Different topic, keep waiting
                Ok(Err(_)) | Err(_) => break,
            }
        }

        Err(TestnetError::Retrieval(format!(
            "Timeout waiting for remote get response after {DEFAULT_CHUNK_OPERATION_TIMEOUT_SECS}s"
        )))
    }

    /// Compute content address for chunk data (SHA256 hash).
    #[must_use]
    pub fn compute_chunk_address(data: &[u8]) -> XorName {
        saorsa_node::compute_address(data)
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

        // Get bootstrap addresses
        let bootstrap_addrs: Vec<SocketAddr> = self.nodes[0..self.config.bootstrap_count]
            .iter()
            .map(|n| n.address)
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
    /// - Disk storage in the node's data directory
    /// - Payment verification disabled (for testing)
    /// - Quote generation with a test rewards address
    async fn create_node(
        &self,
        index: usize,
        is_bootstrap: bool,
        bootstrap_addrs: Vec<SocketAddr>,
    ) -> Result<TestNode> {
        // Safe: node_count is validated in TestNetwork::new() to fit in u16
        let index_u16 = u16::try_from(index)
            .map_err(|_| TestnetError::Config(format!("Node index {index} exceeds u16::MAX")))?;
        let port = self.config.base_port + index_u16;
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let node_id = format!("test_node_{index}");
        let data_dir = self.config.test_data_dir.join(&node_id);

        tokio::fs::create_dir_all(&data_dir).await?;

        // Initialize AntProtocol for this node
        let ant_protocol = Self::create_ant_protocol(&data_dir).await?;

        Ok(TestNode {
            index,
            node_id,
            port,
            address,
            data_dir,
            p2p_node: None,
            ant_protocol: Some(Arc::new(ant_protocol)),
            is_bootstrap,
            state: Arc::new(RwLock::new(NodeState::Pending)),
            bootstrap_addrs,
            protocol_task: None,
        })
    }

    /// Create an `AntProtocol` handler for a test node.
    ///
    /// Configures:
    /// - Disk storage with verification enabled
    /// - Payment verification disabled (for testing without Anvil)
    /// - Quote generator with a test rewards address
    async fn create_ant_protocol(data_dir: &std::path::Path) -> Result<AntProtocol> {
        // Create disk storage
        let storage_config = DiskStorageConfig {
            root_dir: data_dir.to_path_buf(),
            verify_on_read: true,
            max_chunks: 0, // Unlimited for tests
        };
        let storage = DiskStorage::new(storage_config)
            .await
            .map_err(|e| TestnetError::Core(format!("Failed to create disk storage: {e}")))?;

        // Create payment verifier with EVM disabled
        let payment_config = PaymentVerifierConfig {
            evm: EvmVerifierConfig {
                enabled: false, // Disable EVM verification for tests
                ..Default::default()
            },
            cache_capacity: TEST_PAYMENT_CACHE_CAPACITY,
        };
        let payment_verifier = PaymentVerifier::new(payment_config);

        // Create quote generator with test rewards address
        let rewards_address = RewardsAddress::new(TEST_REWARDS_ADDRESS);
        let metrics_tracker = QuotingMetricsTracker::new(TEST_MAX_RECORDS, TEST_INITIAL_RECORDS);
        let quote_generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        Ok(AntProtocol::new(
            Arc::new(storage),
            Arc::new(payment_verifier),
            Arc::new(quote_generator),
        ))
    }

    /// Start a single node.
    async fn start_node(&mut self, mut node: TestNode) -> Result<()> {
        debug!("Starting node {} on port {}", node.index, node.port);
        *node.state.write().await = NodeState::Starting;

        // Build configuration for saorsa-core P2PNode
        let mut core_config = CoreNodeConfig::new()
            .map_err(|e| TestnetError::Core(format!("Failed to create core config: {e}")))?;

        core_config.listen_addr = node.address;
        core_config.listen_addrs = vec![node.address];
        core_config.enable_ipv6 = false; // Disable IPv6 for local testing to avoid dual-stack binding issues
        core_config
            .bootstrap_peers
            .clone_from(&node.bootstrap_addrs);

        // Create and start the P2P node
        let p2p_node = P2PNode::new(core_config).await.map_err(|e| {
            TestnetError::Startup(format!("Failed to create node {}: {e}", node.index))
        })?;

        p2p_node.start().await.map_err(|e| {
            TestnetError::Startup(format!("Failed to start node {}: {e}", node.index))
        })?;

        node.p2p_node = Some(Arc::new(p2p_node));
        *node.state.write().await = NodeState::Running;

        // Start protocol handler that routes incoming P2P messages to AntProtocol
        if let (Some(ref p2p), Some(ref protocol)) = (&node.p2p_node, &node.ant_protocol) {
            let mut events = p2p.subscribe_events();
            let p2p_clone = Arc::clone(p2p);
            let protocol_clone = Arc::clone(protocol);
            let node_index = node.index;
            node.protocol_task = Some(tokio::spawn(async move {
                while let Ok(event) = events.recv().await {
                    if let P2PEvent::Message {
                        topic,
                        source,
                        data,
                    } = event
                    {
                        if topic == CHUNK_PROTOCOL_ID {
                            debug!(
                                "Node {} received chunk protocol message from {}",
                                node_index, source
                            );
                            let protocol = Arc::clone(&protocol_clone);
                            let p2p = Arc::clone(&p2p_clone);
                            tokio::spawn(async move {
                                match protocol.handle_message(&data).await {
                                    Ok(response) => {
                                        if let Err(e) = p2p
                                            .send_message(
                                                &source,
                                                CHUNK_PROTOCOL_ID,
                                                response.to_vec(),
                                            )
                                            .await
                                        {
                                            warn!(
                                                "Node {} failed to send response to {}: {}",
                                                node_index, source, e
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Node {} protocol handler error: {}", node_index, e);
                                    }
                                }
                            });
                        }
                    }
                }
            }));
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
                let state = self.nodes[i].state.read().await.clone();
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
                            if !node.is_running().await {
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

        // Stop all nodes in reverse order
        for node in self.nodes.iter_mut().rev() {
            debug!("Stopping node {}", node.index);
            if let Some(handle) = node.protocol_task.take() {
                handle.abort();
            }
            if let Some(ref p2p) = node.p2p_node {
                if let Err(e) = p2p.shutdown().await {
                    warn!("Error shutting down node {}: {}", node.index, e);
                }
            }
            *node.state.write().await = NodeState::Stopped;
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
}

impl Drop for TestNetwork {
    fn drop(&mut self) {
        // Best-effort synchronous cleanup
        // Note: async cleanup should be done via shutdown() before dropping
        let _ = self.shutdown_tx.send(());

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
        assert!(config
            .test_data_dir
            .to_string_lossy()
            .contains("saorsa_test_"));
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
