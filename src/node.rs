//! Node implementation - thin wrapper around saorsa-core's `P2PNode`.

use crate::ant_protocol::CHUNK_PROTOCOL_ID;
use crate::config::{EvmNetworkConfig, IpVersion, NetworkMode, NodeConfig};
use crate::error::{Error, Result};
use crate::event::{create_event_channel, NodeEvent, NodeEventsChannel, NodeEventsSender};
use crate::payment::metrics::QuotingMetricsTracker;
use crate::payment::wallet::parse_rewards_address;
use crate::payment::{PaymentVerifier, PaymentVerifierConfig, QuoteGenerator};
use crate::storage::{AntProtocol, DiskStorage, DiskStorageConfig};
use crate::upgrade::{AutoApplyUpgrader, UpgradeMonitor, UpgradeResult};
use ant_evm::RewardsAddress;
use evmlib::Network as EvmNetwork;
use saorsa_core::{
    BootstrapConfig as CoreBootstrapConfig, BootstrapManager,
    IPDiversityConfig as CoreDiversityConfig, NodeConfig as CoreNodeConfig, P2PEvent, P2PNode,
    ProductionConfig as CoreProductionConfig,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

/// Maximum number of records for quoting metrics.
const DEFAULT_MAX_QUOTING_RECORDS: usize = 100_000;

/// Default rewards address when none is configured (20-byte zero address).
const DEFAULT_REWARDS_ADDRESS: [u8; 20] = [0u8; 20];

#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

/// Builder for constructing a saorsa node.
pub struct NodeBuilder {
    config: NodeConfig,
}

impl NodeBuilder {
    /// Create a new node builder with the given configuration.
    #[must_use]
    pub fn new(config: NodeConfig) -> Self {
        Self { config }
    }

    /// Build and start the node.
    ///
    /// # Errors
    ///
    /// Returns an error if the node fails to start.
    pub async fn build(self) -> Result<RunningNode> {
        info!("Building saorsa-node with config: {:?}", self.config);

        // Ensure root directory exists
        std::fs::create_dir_all(&self.config.root_dir)?;

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Create event channel
        let (events_tx, events_rx) = create_event_channel();

        // Convert our config to saorsa-core's config
        let core_config = Self::build_core_config(&self.config)?;
        debug!("Core config: {:?}", core_config);

        // Initialize saorsa-core's P2PNode
        let p2p_node = P2PNode::new(core_config)
            .await
            .map_err(|e| Error::Startup(format!("Failed to create P2P node: {e}")))?;

        // Create upgrade monitor if enabled
        let upgrade_monitor = if self.config.upgrade.enabled {
            let node_id_seed = p2p_node.peer_id().as_bytes();
            Some(Self::build_upgrade_monitor(&self.config, node_id_seed))
        } else {
            None
        };

        // Initialize bootstrap cache manager if enabled
        let bootstrap_manager = if self.config.bootstrap_cache.enabled {
            Self::build_bootstrap_manager(&self.config).await
        } else {
            info!("Bootstrap cache disabled");
            None
        };

        // Initialize ANT protocol handler for chunk storage
        let ant_protocol = if self.config.storage.enabled {
            Some(Arc::new(Self::build_ant_protocol(&self.config).await?))
        } else {
            info!("Chunk storage disabled");
            None
        };

        let node = RunningNode {
            config: self.config,
            p2p_node: Arc::new(p2p_node),
            shutdown_tx,
            shutdown_rx,
            events_tx,
            events_rx: Some(events_rx),
            upgrade_monitor,
            bootstrap_manager,
            ant_protocol,
            protocol_task: None,
        };

        Ok(node)
    }

    /// Build the saorsa-core `NodeConfig` from our config.
    fn build_core_config(config: &NodeConfig) -> Result<CoreNodeConfig> {
        // Determine listen address based on port and IP version
        let listen_addr: SocketAddr = match config.ip_version {
            IpVersion::Ipv4 | IpVersion::Dual => format!("0.0.0.0:{}", config.port)
                .parse()
                .map_err(|e| Error::Config(format!("Invalid listen address: {e}")))?,
            IpVersion::Ipv6 => format!("[::]:{}", config.port)
                .parse()
                .map_err(|e| Error::Config(format!("Invalid listen address: {e}")))?,
        };

        let mut core_config = CoreNodeConfig::new()
            .map_err(|e| Error::Config(format!("Failed to create core config: {e}")))?;

        // Set listen address
        core_config.listen_addr = listen_addr;
        core_config.listen_addrs = vec![listen_addr];

        // Enable IPv6 if configured
        core_config.enable_ipv6 = matches!(config.ip_version, IpVersion::Ipv6 | IpVersion::Dual);

        // Add bootstrap peers
        core_config.bootstrap_peers.clone_from(&config.bootstrap);

        // Propagate network-mode tuning into saorsa-core where supported.
        match config.network_mode {
            NetworkMode::Production => {
                core_config.production_config = Some(CoreProductionConfig::default());
                core_config.diversity_config = Some(CoreDiversityConfig::default());
            }
            NetworkMode::Testnet => {
                core_config.production_config = Some(CoreProductionConfig::default());
                let mut diversity = CoreDiversityConfig::testnet();
                diversity.max_nodes_per_asn = config.testnet.max_nodes_per_asn;
                diversity.max_nodes_per_64 = config.testnet.max_nodes_per_64;
                diversity.enable_geolocation_check = config.testnet.enable_geo_checks;
                diversity.min_geographic_diversity = if config.testnet.enable_geo_checks {
                    3
                } else {
                    1
                };
                core_config.diversity_config = Some(diversity);

                if config.testnet.enforce_age_requirements {
                    warn!(
                        "testnet.enforce_age_requirements is set but saorsa-core does not yet \
                         expose a knob; age checks may remain relaxed"
                    );
                }
            }
            NetworkMode::Development => {
                core_config.production_config = None;
                core_config.diversity_config = Some(CoreDiversityConfig::permissive());
            }
        }

        Ok(core_config)
    }

    fn build_upgrade_monitor(config: &NodeConfig, node_id_seed: &[u8]) -> Arc<UpgradeMonitor> {
        let monitor = UpgradeMonitor::new(
            config.upgrade.github_repo.clone(),
            config.upgrade.channel,
            config.upgrade.check_interval_hours,
        );

        if config.upgrade.staged_rollout_hours > 0 {
            Arc::new(monitor.with_staged_rollout(node_id_seed, config.upgrade.staged_rollout_hours))
        } else {
            Arc::new(monitor)
        }
    }

    /// Build the ANT protocol handler from config.
    ///
    /// Initializes disk storage, payment verifier, and quote generator.
    async fn build_ant_protocol(config: &NodeConfig) -> Result<AntProtocol> {
        // Create disk storage
        let storage_config = DiskStorageConfig {
            root_dir: config.root_dir.clone(),
            verify_on_read: config.storage.verify_on_read,
            max_chunks: config.storage.max_chunks,
        };
        let storage = DiskStorage::new(storage_config)
            .await
            .map_err(|e| Error::Startup(format!("Failed to create disk storage: {e}")))?;

        // Create payment verifier
        let evm_network = match config.payment.evm_network {
            EvmNetworkConfig::ArbitrumOne => EvmNetwork::ArbitrumOne,
            EvmNetworkConfig::ArbitrumSepolia => EvmNetwork::ArbitrumSepoliaTest,
        };
        let payment_config = PaymentVerifierConfig {
            evm: crate::payment::EvmVerifierConfig {
                enabled: config.payment.enabled,
                network: evm_network,
            },
            cache_capacity: config.payment.cache_capacity,
        };
        let payment_verifier = PaymentVerifier::new(payment_config);

        // Create quote generator
        let rewards_address = match config.payment.rewards_address {
            Some(ref addr) => parse_rewards_address(addr)?,
            None => RewardsAddress::new(DEFAULT_REWARDS_ADDRESS),
        };
        let metrics_tracker = QuotingMetricsTracker::new(DEFAULT_MAX_QUOTING_RECORDS, 0);
        let quote_generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        info!(
            "ANT protocol handler initialized (protocol={})",
            CHUNK_PROTOCOL_ID
        );

        Ok(AntProtocol::new(
            Arc::new(storage),
            Arc::new(payment_verifier),
            Arc::new(quote_generator),
        ))
    }

    /// Build the bootstrap cache manager from config.
    async fn build_bootstrap_manager(config: &NodeConfig) -> Option<BootstrapManager> {
        let cache_dir = config
            .bootstrap_cache
            .cache_dir
            .clone()
            .unwrap_or_else(|| config.root_dir.join("bootstrap_cache"));

        // Create cache directory
        if let Err(e) = std::fs::create_dir_all(&cache_dir) {
            warn!("Failed to create bootstrap cache directory: {}", e);
            return None;
        }

        let bootstrap_config = CoreBootstrapConfig {
            cache_dir,
            max_peers: config.bootstrap_cache.max_contacts,
            ..CoreBootstrapConfig::default()
        };

        match BootstrapManager::with_config(bootstrap_config).await {
            Ok(manager) => {
                info!(
                    "Bootstrap cache initialized with {} max contacts",
                    config.bootstrap_cache.max_contacts
                );
                Some(manager)
            }
            Err(e) => {
                warn!("Failed to initialize bootstrap cache: {}", e);
                None
            }
        }
    }
}

/// A running saorsa node.
pub struct RunningNode {
    config: NodeConfig,
    p2p_node: Arc<P2PNode>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    events_tx: NodeEventsSender,
    events_rx: Option<NodeEventsChannel>,
    upgrade_monitor: Option<Arc<UpgradeMonitor>>,
    /// Bootstrap cache manager for persistent peer storage.
    bootstrap_manager: Option<BootstrapManager>,
    /// ANT protocol handler for chunk storage.
    ant_protocol: Option<Arc<AntProtocol>>,
    /// Protocol message routing background task.
    protocol_task: Option<JoinHandle<()>>,
}

impl RunningNode {
    /// Get the node's root directory.
    #[must_use]
    pub fn root_dir(&self) -> &PathBuf {
        &self.config.root_dir
    }

    /// Get a receiver for node events.
    ///
    /// Note: Can only be called once. Subsequent calls return None.
    pub fn events(&mut self) -> Option<NodeEventsChannel> {
        self.events_rx.take()
    }

    /// Subscribe to node events.
    #[must_use]
    pub fn subscribe_events(&self) -> NodeEventsChannel {
        self.events_tx.subscribe()
    }

    /// Run the node until shutdown is requested.
    ///
    /// # Errors
    ///
    /// Returns an error if the node encounters a fatal error.
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting saorsa-node");

        // Start the P2P node
        self.p2p_node
            .start()
            .await
            .map_err(|e| Error::Startup(format!("Failed to start P2P node: {e}")))?;

        info!(
            "P2P node started, listening on {:?}",
            self.p2p_node.listen_addrs().await
        );

        // Emit started event
        if let Err(e) = self.events_tx.send(NodeEvent::Started) {
            warn!("Failed to send Started event: {e}");
        }

        // Start protocol message routing (P2P → AntProtocol → P2P response)
        self.start_protocol_routing();

        // Start upgrade monitor if enabled
        if let Some(ref monitor) = self.upgrade_monitor {
            let monitor = Arc::clone(monitor);
            let events_tx = self.events_tx.clone();
            let mut shutdown_rx = self.shutdown_rx.clone();

            tokio::spawn(async move {
                let upgrader = AutoApplyUpgrader::new();

                loop {
                    tokio::select! {
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() {
                                break;
                            }
                        }
                        result = monitor.check_for_updates() => {
                            if let Ok(Some(upgrade_info)) = result {
                                info!(
                                    "Upgrade available: {} -> {}",
                                    upgrader.current_version(),
                                    upgrade_info.version
                                );

                                // Send notification event
                                if let Err(e) = events_tx.send(NodeEvent::UpgradeAvailable {
                                    version: upgrade_info.version.to_string(),
                                }) {
                                    warn!("Failed to send UpgradeAvailable event: {e}");
                                }

                                // Auto-apply the upgrade
                                info!("Starting auto-apply upgrade...");
                                match upgrader.apply_upgrade(&upgrade_info).await {
                                    Ok(UpgradeResult::Success { version }) => {
                                        info!("Upgrade to {} successful! Process will restart.", version);
                                        // If we reach here, exec() failed or not supported
                                    }
                                    Ok(UpgradeResult::RolledBack { reason }) => {
                                        warn!("Upgrade rolled back: {}", reason);
                                    }
                                    Ok(UpgradeResult::NoUpgrade) => {
                                        debug!("No upgrade needed");
                                    }
                                    Err(e) => {
                                        error!("Critical upgrade error: {}", e);
                                    }
                                }
                            }
                            // Wait for next check interval
                            tokio::time::sleep(monitor.check_interval()).await;
                        }
                    }
                }
            });
        }

        info!("Node running, waiting for shutdown signal");

        // Run the main event loop with signal handling
        self.run_event_loop().await?;

        // Log bootstrap cache stats before shutdown
        if let Some(ref manager) = self.bootstrap_manager {
            match manager.get_stats().await {
                Ok(stats) => {
                    info!(
                        "Bootstrap cache shutdown: {} contacts, avg quality {:.2}",
                        stats.total_contacts, stats.average_quality_score
                    );
                }
                Err(e) => {
                    debug!("Failed to get bootstrap cache stats: {}", e);
                }
            }
        }

        // Stop protocol routing task
        if let Some(handle) = self.protocol_task.take() {
            handle.abort();
        }

        // Shutdown P2P node
        info!("Shutting down P2P node...");
        if let Err(e) = self.p2p_node.shutdown().await {
            warn!("Error during P2P node shutdown: {e}");
        }

        if let Err(e) = self.events_tx.send(NodeEvent::ShuttingDown) {
            warn!("Failed to send ShuttingDown event: {e}");
        }
        info!("Node shutdown complete");
        Ok(())
    }

    /// Run the main event loop, handling shutdown and signals.
    #[cfg(unix)]
    async fn run_event_loop(&mut self) -> Result<()> {
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sighup = signal(SignalKind::hangup())?;

        loop {
            tokio::select! {
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        info!("Shutdown signal received");
                        break;
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Received SIGINT (Ctrl-C), initiating shutdown");
                    self.shutdown();
                    break;
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, initiating shutdown");
                    self.shutdown();
                    break;
                }
                _ = sighup.recv() => {
                    info!("Received SIGHUP, could reload config here");
                    // TODO: Implement config reload on SIGHUP
                }
            }
        }
        Ok(())
    }

    /// Run the main event loop, handling shutdown signals (non-Unix version).
    #[cfg(not(unix))]
    async fn run_event_loop(&mut self) -> Result<()> {
        loop {
            tokio::select! {
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        info!("Shutdown signal received");
                        break;
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Received Ctrl-C, initiating shutdown");
                    self.shutdown();
                    break;
                }
            }
        }
        Ok(())
    }

    /// Start the protocol message routing background task.
    ///
    /// Subscribes to P2P events and routes incoming chunk protocol messages
    /// to the `AntProtocol` handler, sending responses back to the sender.
    fn start_protocol_routing(&mut self) {
        let protocol = match self.ant_protocol {
            Some(ref p) => Arc::clone(p),
            None => return,
        };

        let mut events = self.p2p_node.subscribe_events();
        let p2p = Arc::clone(&self.p2p_node);

        self.protocol_task = Some(tokio::spawn(async move {
            while let Ok(event) = events.recv().await {
                if let P2PEvent::Message {
                    topic,
                    source,
                    data,
                } = event
                {
                    if topic == CHUNK_PROTOCOL_ID {
                        debug!("Received chunk protocol message from {}", source);
                        let protocol = Arc::clone(&protocol);
                        let p2p = Arc::clone(&p2p);
                        tokio::spawn(async move {
                            match protocol.handle_message(&data).await {
                                Ok(response) => {
                                    if let Err(e) = p2p
                                        .send_message(&source, CHUNK_PROTOCOL_ID, response.to_vec())
                                        .await
                                    {
                                        warn!(
                                            "Failed to send protocol response to {}: {}",
                                            source, e
                                        );
                                    }
                                }
                                Err(e) => {
                                    warn!("Protocol handler error: {}", e);
                                }
                            }
                        });
                    }
                }
            }
        }));
        info!("Protocol message routing started");
    }

    /// Request the node to shut down.
    pub fn shutdown(&self) {
        if let Err(e) = self.shutdown_tx.send(true) {
            warn!("Failed to send shutdown signal: {e}");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_build_upgrade_monitor_staged_rollout_enabled() {
        let config = NodeConfig {
            upgrade: crate::config::UpgradeConfig {
                enabled: true,
                staged_rollout_hours: 24,
                ..Default::default()
            },
            ..Default::default()
        };
        let seed = b"node-seed";

        let monitor = NodeBuilder::build_upgrade_monitor(&config, seed);
        assert!(monitor.has_staged_rollout());
    }

    #[test]
    fn test_build_upgrade_monitor_staged_rollout_disabled() {
        let config = NodeConfig {
            upgrade: crate::config::UpgradeConfig {
                enabled: true,
                staged_rollout_hours: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        let seed = b"node-seed";

        let monitor = NodeBuilder::build_upgrade_monitor(&config, seed);
        assert!(!monitor.has_staged_rollout());
    }

    #[test]
    fn test_build_core_config_sets_production_mode() {
        let config = NodeConfig {
            network_mode: NetworkMode::Production,
            ..Default::default()
        };
        let core = NodeBuilder::build_core_config(&config).expect("core config");
        assert!(core.production_config.is_some());
        assert!(core.diversity_config.is_some());
    }

    #[test]
    fn test_build_core_config_sets_development_mode_relaxed() {
        let config = NodeConfig {
            network_mode: NetworkMode::Development,
            ..Default::default()
        };
        let core = NodeBuilder::build_core_config(&config).expect("core config");
        assert!(core.production_config.is_none());
        let diversity = core.diversity_config.expect("diversity");
        assert!(diversity.is_relaxed());
    }
}
