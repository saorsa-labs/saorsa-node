//! Local devnet infrastructure for spawning and managing multiple nodes.
//!
//! This module provides a local, in-process devnet suitable for running
//! multi-node networks on a single machine.

use crate::ant_protocol::CHUNK_PROTOCOL_ID;
use crate::config::{default_root_dir, NODES_SUBDIR, NODE_IDENTITY_FILENAME};
use crate::logging::{debug, info, warn};
use crate::payment::{
    EvmVerifierConfig, PaymentVerifier, PaymentVerifierConfig, PriceFloorConfig, QuoteGenerator,
    QuotingMetricsTracker,
};
use crate::replication::config::ReplicationConfig;
use crate::storage::{AntProtocol, ChunkRequestContext, ChunkStore, ChunkStoreConfig};
use evmlib::Network as EvmNetwork;
use evmlib::RewardsAddress;
use rand::Rng;
use saorsa_core::identity::NodeIdentity;
use saorsa_core::{
    IPDiversityConfig, MultiAddr, NodeConfig as CoreNodeConfig, P2PEvent, P2PNode, PeerId,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

// =============================================================================
// Devnet Constants
// =============================================================================

/// Minimum port for random devnet allocation.
pub const DEVNET_PORT_RANGE_MIN: u16 = 20_000;

/// Maximum port for random devnet allocation.
pub const DEVNET_PORT_RANGE_MAX: u16 = 60_000;

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

/// Polling interval when waiting for individual nodes to become ready (milliseconds).
const NODE_READY_POLL_INTERVAL_MS: u64 = 100;

/// Polling interval when waiting for network stabilization (seconds).
const STABILIZATION_POLL_INTERVAL_SECS: u64 = 1;

/// Maximum minimum connections required per node during stabilization.
const STABILIZATION_MIN_CONNECTIONS_CAP: usize = 3;

/// Health monitor check interval (seconds).
const HEALTH_CHECK_INTERVAL_SECS: u64 = 5;

// =============================================================================
// AntProtocol Devnet Configuration
// =============================================================================

/// Payment cache capacity for devnet nodes.
const DEVNET_PAYMENT_CACHE_CAPACITY: usize = 1000;

/// Devnet rewards address (20 bytes, all 0x01).
const DEVNET_REWARDS_ADDRESS: [u8; 20] = [0x01; 20];

/// Initial records for quoting metrics (devnet value).
const DEVNET_INITIAL_RECORDS: usize = 1000;

async fn handle_chunk_message(
    protocol: Arc<AntProtocol>,
    p2p: Arc<P2PNode>,
    source: PeerId,
    data: Vec<u8>,
    node_index: usize,
    received_at: Instant,
) {
    let handled = protocol
        .try_handle_request_with_context(
            &data,
            Some(ChunkRequestContext::new(
                source.to_string(),
                received_at.into(),
                Duration::ZERO,
            )),
        )
        .await;
    let telemetry = handled.get_telemetry;
    match handled.response {
        Ok(Some(response)) => {
            let send_started = Instant::now();
            let send_result = p2p
                .send_message(&source, CHUNK_PROTOCOL_ID, response.to_vec(), &[])
                .await;
            if let Some(telemetry) = telemetry {
                telemetry.finish_send(send_started.elapsed(), send_result.is_ok());
            }
            if let Err(e) = send_result {
                warn!("Node {node_index} failed to send response to {source}: {e}");
            }
        }
        Ok(None) => {
            if let Some(telemetry) = telemetry {
                telemetry.finish_without_send("no_response");
            }
        }
        Err(e) => {
            if let Some(telemetry) = telemetry {
                telemetry.finish_without_send("encode_error");
            }
            warn!("Node {node_index} protocol handler error: {e}");
        }
    }
}

// =============================================================================
// Default Node Counts
// =============================================================================

/// Default number of nodes in a full devnet.
pub const DEFAULT_NODE_COUNT: usize = 25;

/// Default number of bootstrap nodes.
pub const DEFAULT_BOOTSTRAP_COUNT: usize = 3;

/// Number of nodes in a minimal devnet.
pub const MINIMAL_NODE_COUNT: usize = 5;

/// Number of bootstrap nodes in a minimal network.
pub const MINIMAL_BOOTSTRAP_COUNT: usize = 2;

/// Number of nodes in a small devnet.
pub const SMALL_NODE_COUNT: usize = 10;

/// Error type for devnet operations.
#[derive(Debug, thiserror::Error)]
pub enum DevnetError {
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
}

/// Result type for devnet operations.
pub type Result<T> = std::result::Result<T, DevnetError>;

/// Configuration for the devnet.
///
/// Each configuration is automatically isolated with unique ports and
/// data directories to prevent collisions when running multiple devnets.
#[derive(Debug, Clone)]
pub struct DevnetConfig {
    /// Number of nodes to spawn (default: 25).
    pub node_count: usize,

    /// Base port for node allocation (0 = auto).
    pub base_port: u16,

    /// Number of bootstrap nodes (first N nodes, default: 3).
    pub bootstrap_count: usize,

    /// Root directory for devnet data.
    pub data_dir: PathBuf,

    /// Delay between node spawns (default: 200ms).
    pub spawn_delay: Duration,

    /// Timeout for network stabilization (default: 120s).
    pub stabilization_timeout: Duration,

    /// Timeout for single node startup (default: 30s).
    pub node_startup_timeout: Duration,

    /// Enable verbose logging for devnet nodes.
    pub enable_node_logging: bool,

    /// Whether to remove the data directory on shutdown.
    pub cleanup_data_dir: bool,

    /// Optional EVM network for payment verification.
    /// When `Some`, nodes will use this network (e.g. Anvil testnet) for
    /// on-chain verification. Defaults to Arbitrum One when `None`.
    pub evm_network: Option<EvmNetwork>,

    /// Optional IPv4 to advertise to peers/clients (LAN devnet). When `Some`,
    /// nodes bind 0.0.0.0 and advertise this IP instead of 127.0.0.1.
    pub advertise_ip: Option<Ipv4Addr>,
}

impl Default for DevnetConfig {
    fn default() -> Self {
        let mut rng = rand::thread_rng();

        #[allow(clippy::cast_possible_truncation)] // DEFAULT_NODE_COUNT is 25, always fits u16
        let max_base_port = DEVNET_PORT_RANGE_MAX.saturating_sub(DEFAULT_NODE_COUNT as u16);
        let base_port = rng.gen_range(DEVNET_PORT_RANGE_MIN..max_base_port);

        Self {
            node_count: DEFAULT_NODE_COUNT,
            base_port,
            bootstrap_count: DEFAULT_BOOTSTRAP_COUNT,
            data_dir: default_root_dir(),
            spawn_delay: Duration::from_millis(DEFAULT_SPAWN_DELAY_MS),
            stabilization_timeout: Duration::from_secs(DEFAULT_STABILIZATION_TIMEOUT_SECS),
            node_startup_timeout: Duration::from_secs(DEFAULT_NODE_STARTUP_TIMEOUT_SECS),
            enable_node_logging: false,
            cleanup_data_dir: true,
            evm_network: None,
            advertise_ip: None,
        }
    }
}

impl DevnetConfig {
    /// Minimal devnet preset (5 nodes).
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            node_count: MINIMAL_NODE_COUNT,
            bootstrap_count: MINIMAL_BOOTSTRAP_COUNT,
            stabilization_timeout: Duration::from_secs(MINIMAL_STABILIZATION_TIMEOUT_SECS),
            ..Self::default()
        }
    }

    /// Small devnet preset (10 nodes).
    #[must_use]
    pub fn small() -> Self {
        Self {
            node_count: SMALL_NODE_COUNT,
            bootstrap_count: MINIMAL_BOOTSTRAP_COUNT,
            stabilization_timeout: Duration::from_secs(SMALL_STABILIZATION_TIMEOUT_SECS),
            ..Self::default()
        }
    }
}

// The manifest types are shared with ant-client (CLI reads them, devnet
// writes them), so they live in ant-protocol. Re-exported here for
// backwards compatibility.
pub use ant_protocol::devnet_manifest::{DevnetEvmInfo, DevnetManifest};

/// Network state for devnet startup lifecycle.
#[derive(Debug, Clone)]
pub enum NetworkState {
    /// Not started.
    Uninitialized,
    /// Bootstrapping nodes are starting.
    BootstrappingPhase,
    /// Regular nodes are starting.
    NodeSpawningPhase,
    /// Waiting for stabilization.
    Stabilizing,
    /// Network is ready.
    Ready,
    /// Shutting down.
    ShuttingDown,
    /// Stopped.
    Stopped,
}

/// Node state for devnet nodes.
#[derive(Debug, Clone)]
pub enum NodeState {
    /// Not started yet.
    Pending,
    /// Starting up.
    Starting,
    /// Running.
    Running,
    /// Connected to peers.
    Connected,
    /// Stopped.
    Stopped,
    /// Failed to start.
    Failed(String),
}

/// A single devnet node instance.
#[allow(dead_code)]
pub struct DevnetNode {
    index: usize,
    label: String,
    peer_id: PeerId,
    port: u16,
    data_dir: PathBuf,
    p2p_node: Option<Arc<P2PNode>>,
    ant_protocol: Option<Arc<AntProtocol>>,
    is_bootstrap: bool,
    state: Arc<RwLock<NodeState>>,
    bootstrap_addrs: Vec<MultiAddr>,
    protocol_task: Option<JoinHandle<()>>,
}

impl DevnetNode {
    /// Get the node's peer count.
    pub async fn peer_count(&self) -> usize {
        if let Some(ref node) = self.p2p_node {
            node.peer_count().await
        } else {
            0
        }
    }
}

/// A local devnet composed of multiple nodes.
pub struct Devnet {
    config: DevnetConfig,
    nodes: Vec<DevnetNode>,
    shutdown: CancellationToken,
    state: Arc<RwLock<NetworkState>>,
    health_monitor: Option<JoinHandle<()>>,
}

impl Devnet {
    /// Create a new devnet with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns `DevnetError::Config` if the configuration is invalid (e.g. bootstrap
    /// count exceeds node count or port range overflow).
    /// Returns `DevnetError::Io` if the data directory cannot be created.
    pub async fn new(mut config: DevnetConfig) -> Result<Self> {
        if config.bootstrap_count >= config.node_count {
            return Err(DevnetError::Config(
                "Bootstrap count must be less than node count".to_string(),
            ));
        }

        if config.bootstrap_count == 0 {
            return Err(DevnetError::Config(
                "At least one bootstrap node is required".to_string(),
            ));
        }

        let node_count = config.node_count;
        let node_count_u16 = u16::try_from(node_count).map_err(|_| {
            DevnetError::Config(format!("Node count {node_count} exceeds u16::MAX"))
        })?;

        if config.base_port == 0 {
            let mut rng = rand::thread_rng();
            let max_base_port = DEVNET_PORT_RANGE_MAX.saturating_sub(node_count_u16);
            config.base_port = rng.gen_range(DEVNET_PORT_RANGE_MIN..max_base_port);
        }

        let base_port = config.base_port;
        let max_port = base_port
            .checked_add(node_count_u16)
            .ok_or_else(|| {
                DevnetError::Config(format!(
                    "Port range overflow: base_port {base_port} + node_count {node_count} exceeds u16::MAX"
                ))
            })?;
        if max_port > DEVNET_PORT_RANGE_MAX {
            return Err(DevnetError::Config(format!(
                "Port range overflow: max port {max_port} exceeds DEVNET_PORT_RANGE_MAX {DEVNET_PORT_RANGE_MAX}"
            )));
        }

        tokio::fs::create_dir_all(&config.data_dir).await?;

        Ok(Self {
            config,
            nodes: Vec::new(),
            shutdown: CancellationToken::new(),
            state: Arc::new(RwLock::new(NetworkState::Uninitialized)),
            health_monitor: None,
        })
    }

    /// Start the devnet.
    ///
    /// # Errors
    ///
    /// Returns `DevnetError::Startup` if any node fails to start, or
    /// `DevnetError::Stabilization` if the network does not stabilize within the timeout.
    pub async fn start(&mut self) -> Result<()> {
        info!(
            "Starting devnet with {} nodes ({} bootstrap)",
            self.config.node_count, self.config.bootstrap_count
        );

        *self.state.write().await = NetworkState::BootstrappingPhase;
        self.start_bootstrap_nodes().await?;

        *self.state.write().await = NetworkState::NodeSpawningPhase;
        self.start_regular_nodes().await?;

        *self.state.write().await = NetworkState::Stabilizing;
        self.wait_for_stabilization().await?;

        self.start_health_monitor();

        *self.state.write().await = NetworkState::Ready;
        info!("Devnet is ready");
        Ok(())
    }

    /// Shutdown the devnet.
    ///
    /// # Errors
    ///
    /// Returns `DevnetError::Io` if the data directory cleanup fails.
    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down devnet");
        *self.state.write().await = NetworkState::ShuttingDown;

        self.shutdown.cancel();

        if let Some(handle) = self.health_monitor.take() {
            handle.abort();
        }

        let mut shutdown_futures = Vec::with_capacity(self.nodes.len());
        for node in self.nodes.iter_mut().rev() {
            debug!("Stopping node {}", node.index);
            if let Some(handle) = node.protocol_task.take() {
                handle.abort();
            }

            let node_index = node.index;
            let node_state = Arc::clone(&node.state);
            let p2p_node = node.p2p_node.take();

            shutdown_futures.push(async move {
                if let Some(p2p) = p2p_node {
                    if let Err(e) = p2p.shutdown().await {
                        warn!("Error shutting down node {node_index}: {e}");
                    }
                }
                *node_state.write().await = NodeState::Stopped;
            });
        }
        futures::future::join_all(shutdown_futures).await;

        if self.config.cleanup_data_dir {
            if let Err(e) = tokio::fs::remove_dir_all(&self.config.data_dir).await {
                warn!("Failed to cleanup devnet data directory: {e}");
            }
        }

        *self.state.write().await = NetworkState::Stopped;
        info!("Devnet shutdown complete");
        Ok(())
    }

    /// Get devnet configuration.
    #[must_use]
    pub fn config(&self) -> &DevnetConfig {
        &self.config
    }

    /// Get bootstrap addresses.
    #[must_use]
    pub fn bootstrap_addrs(&self) -> Vec<MultiAddr> {
        self.nodes
            .iter()
            .take(self.config.bootstrap_count)
            .map(|n| {
                MultiAddr::quic(SocketAddr::from((
                    self.config.advertise_ip.unwrap_or(Ipv4Addr::LOCALHOST),
                    n.port,
                )))
            })
            .collect()
    }

    async fn start_bootstrap_nodes(&mut self) -> Result<()> {
        info!("Starting {} bootstrap nodes", self.config.bootstrap_count);

        for i in 0..self.config.bootstrap_count {
            let node = self.create_node(i, true, vec![]).await?;
            self.start_node(node).await?;
            tokio::time::sleep(self.config.spawn_delay).await;
        }

        self.wait_for_nodes_ready(0..self.config.bootstrap_count)
            .await?;

        info!("All bootstrap nodes are ready");
        Ok(())
    }

    async fn start_regular_nodes(&mut self) -> Result<()> {
        let regular_count = self.config.node_count - self.config.bootstrap_count;
        info!("Starting {} regular nodes", regular_count);

        let bootstrap_addrs: Vec<MultiAddr> = self
            .nodes
            .get(0..self.config.bootstrap_count)
            .ok_or_else(|| {
                DevnetError::Config(format!(
                    "Bootstrap count {} exceeds nodes length {}",
                    self.config.bootstrap_count,
                    self.nodes.len()
                ))
            })?
            .iter()
            .map(|n| {
                MultiAddr::quic(SocketAddr::from((
                    self.config.advertise_ip.unwrap_or(Ipv4Addr::LOCALHOST),
                    n.port,
                )))
            })
            .collect();

        for i in self.config.bootstrap_count..self.config.node_count {
            let node = self.create_node(i, false, bootstrap_addrs.clone()).await?;
            self.start_node(node).await?;
            tokio::time::sleep(self.config.spawn_delay).await;
        }

        info!("All regular nodes started");
        Ok(())
    }

    async fn create_node(
        &self,
        index: usize,
        is_bootstrap: bool,
        bootstrap_addrs: Vec<MultiAddr>,
    ) -> Result<DevnetNode> {
        let index_u16 = u16::try_from(index)
            .map_err(|_| DevnetError::Config(format!("Node index {index} exceeds u16::MAX")))?;
        let port = self.config.base_port + index_u16;

        // Generate identity first so we can use peer_id as the directory name
        let identity = NodeIdentity::generate()
            .map_err(|e| DevnetError::Core(format!("Failed to generate node identity: {e}")))?;
        let peer_id = *identity.peer_id();
        let label = format!("devnet_node_{index}");
        let data_dir = self
            .config
            .data_dir
            .join(NODES_SUBDIR)
            .join(peer_id.to_hex());

        tokio::fs::create_dir_all(&data_dir).await?;

        identity
            .save_to_file(&data_dir.join(NODE_IDENTITY_FILENAME))
            .await
            .map_err(|e| DevnetError::Core(format!("Failed to save node identity: {e}")))?;

        let ant_protocol = Self::create_ant_protocol(&data_dir, &identity, &self.config).await?;

        Ok(DevnetNode {
            index,
            label,
            peer_id,
            port,
            data_dir,
            p2p_node: None,
            ant_protocol: Some(Arc::new(ant_protocol)),
            is_bootstrap,
            state: Arc::new(RwLock::new(NodeState::Pending)),
            bootstrap_addrs,
            protocol_task: None,
        })
    }

    async fn create_ant_protocol(
        data_dir: &std::path::Path,
        identity: &NodeIdentity,
        config: &DevnetConfig,
    ) -> Result<AntProtocol> {
        let storage_config = ChunkStoreConfig {
            root_dir: data_dir.to_path_buf(),
            verify_on_read: true,
            ..ChunkStoreConfig::default()
        };
        let storage = ChunkStore::new(storage_config)
            .await
            .map_err(|e| DevnetError::Core(format!("Failed to create the chunk store: {e}")))?;

        let evm_config = EvmVerifierConfig {
            network: config
                .evm_network
                .clone()
                .unwrap_or(EvmNetwork::ArbitrumOne),
        };

        let rewards_address = RewardsAddress::new(DEVNET_REWARDS_ADDRESS);
        let replication_config = ReplicationConfig::default();
        let payment_config = PaymentVerifierConfig {
            evm: evm_config,
            cache_capacity: DEVNET_PAYMENT_CACHE_CAPACITY,
            close_group_size: replication_config.close_group_size,
            local_rewards_address: rewards_address,
            price_floor: PriceFloorConfig::default(),
        };
        let payment_verifier = PaymentVerifier::new(payment_config);
        let metrics_tracker = QuotingMetricsTracker::new(DEVNET_INITIAL_RECORDS);
        let mut quote_generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        // Wire ML-DSA-65 signing from the devnet node's identity
        crate::payment::wire_ml_dsa_signer(&mut quote_generator, identity)
            .map_err(|e| DevnetError::Startup(format!("Failed to wire ML-DSA-65 signer: {e}")))?;

        let storage = Arc::new(storage);
        let payment_verifier = Arc::new(payment_verifier);

        Ok(AntProtocol::new(
            storage,
            payment_verifier,
            Arc::new(quote_generator),
        ))
    }

    async fn start_node(&mut self, mut node: DevnetNode) -> Result<()> {
        debug!("Starting node {} on port {}", node.index, node.port);
        *node.state.write().await = NodeState::Starting;

        let mut core_config = CoreNodeConfig::builder()
            .port(node.port)
            .local(self.config.advertise_ip.is_none())
            .max_message_size(crate::ant_protocol::MAX_WIRE_MESSAGE_SIZE)
            .build()
            .map_err(|e| DevnetError::Core(format!("Failed to create core config: {e}")))?;

        // Load the node identity for app-level message signing.
        let identity = NodeIdentity::load_from_file(
            &node.data_dir.join(crate::config::NODE_IDENTITY_FILENAME),
        )
        .await
        .map_err(|e| DevnetError::Core(format!("Failed to load node identity: {e}")))?;

        core_config.node_identity = Some(Arc::new(identity));
        core_config
            .bootstrap_peers
            .clone_from(&node.bootstrap_addrs);
        core_config.diversity_config = Some(IPDiversityConfig::permissive());

        let index = node.index;
        let p2p_node = P2PNode::new(core_config)
            .await
            .map_err(|e| DevnetError::Startup(format!("Failed to create node {index}: {e}")))?;

        p2p_node
            .start()
            .await
            .map_err(|e| DevnetError::Startup(format!("Failed to start node {index}: {e}")))?;

        node.p2p_node = Some(Arc::new(p2p_node));
        *node.state.write().await = NodeState::Running;

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
                            let received_at = Instant::now();
                            tokio::spawn(handle_chunk_message(
                                protocol,
                                p2p,
                                source,
                                data,
                                node_index,
                                received_at,
                            ));
                        }
                    }
                }
            }));
        }

        debug!("Node {} started successfully", node.index);
        self.nodes.push(node);
        Ok(())
    }

    async fn wait_for_nodes_ready(&self, range: std::ops::Range<usize>) -> Result<()> {
        let deadline = Instant::now() + self.config.node_startup_timeout;

        for i in range {
            while Instant::now() < deadline {
                let node = self.nodes.get(i).ok_or_else(|| {
                    DevnetError::Config(format!(
                        "Node index {i} out of bounds (len: {})",
                        self.nodes.len()
                    ))
                })?;
                let state = node.state.read().await.clone();
                match state {
                    NodeState::Running | NodeState::Connected => break,
                    NodeState::Failed(ref e) => {
                        return Err(DevnetError::Startup(format!("Node {i} failed: {e}")));
                    }
                    _ => {
                        tokio::time::sleep(Duration::from_millis(NODE_READY_POLL_INTERVAL_MS))
                            .await;
                    }
                }
            }
        }
        Ok(())
    }

    async fn wait_for_stabilization(&self) -> Result<()> {
        let deadline = Instant::now() + self.config.stabilization_timeout;
        let min_connections = self
            .config
            .bootstrap_count
            .min(STABILIZATION_MIN_CONNECTIONS_CAP);

        info!(
            "Waiting for devnet stabilization (min {} connections per node)",
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
                info!("Devnet stabilized: {} total connections", total_connections);
                return Ok(());
            }

            debug!(
                "Waiting for stabilization: {} total connections",
                total_connections
            );
            tokio::time::sleep(Duration::from_secs(STABILIZATION_POLL_INTERVAL_SECS)).await;
        }

        Err(DevnetError::Stabilization(
            "Devnet failed to stabilize within timeout".to_string(),
        ))
    }

    fn start_health_monitor(&mut self) {
        let nodes: Vec<Arc<P2PNode>> = self
            .nodes
            .iter()
            .filter_map(|n| n.p2p_node.clone())
            .collect();
        let shutdown = self.shutdown.clone();

        self.health_monitor = Some(tokio::spawn(async move {
            let check_interval = Duration::from_secs(HEALTH_CHECK_INTERVAL_SECS);

            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(check_interval) => {
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
}

impl Drop for Devnet {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(handle) = self.health_monitor.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Backward-compatibility contract: a default config advertises no LAN IP,
    /// so nodes bind loopback (`.local(advertise_ip.is_none())` → `.local(true)`)
    /// and stamp `127.0.0.1` into the manifest bootstrap addresses — exactly as
    /// before the `--host` flag existed.
    #[test]
    fn default_config_has_no_advertise_ip() {
        assert!(DevnetConfig::default().advertise_ip.is_none());
    }
}
