//! Node implementation - thin wrapper around saorsa-core's `P2PNode`.

use crate::attestation::VerificationLevel;
use crate::config::{AttestationMode, AttestationNodeConfig, IpVersion, NetworkMode, NodeConfig};
use crate::error::{Error, Result};
use crate::event::{create_event_channel, NodeEvent, NodeEventsChannel, NodeEventsSender};
use crate::upgrade::{AutoApplyUpgrader, UpgradeMonitor, UpgradeResult};
use saorsa_core::{
    AttestationConfig as CoreAttestationConfig, BootstrapConfig as CoreBootstrapConfig,
    BootstrapManager, EnforcementMode as CoreEnforcementMode,
    IPDiversityConfig as CoreDiversityConfig, NodeConfig as CoreNodeConfig, P2PNode,
    ProductionConfig as CoreProductionConfig,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

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
    /// Returns an error if the node fails to start, or if attestation is enabled
    /// without a proper verification feature (blocks startup for security).
    pub async fn build(self) -> Result<RunningNode> {
        info!("Building saorsa-node with config: {:?}", self.config);

        // Validate attestation security BEFORE proceeding
        Self::validate_attestation_security(&self.config)?;

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

        let node = RunningNode {
            config: self.config,
            p2p_node: Arc::new(p2p_node),
            shutdown_tx,
            shutdown_rx,
            events_tx,
            events_rx: Some(events_rx),
            upgrade_monitor,
            bootstrap_manager,
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

        // Configure attestation
        core_config.attestation_config = Self::build_attestation_config(&config.attestation)?;

        Ok(core_config)
    }

    /// Validate attestation security configuration.
    ///
    /// **BLOCKS STARTUP** if attestation is enabled without a verification feature.
    fn validate_attestation_security(config: &NodeConfig) -> Result<()> {
        if !config.attestation.enabled {
            return Ok(());
        }

        let level = VerificationLevel::current();
        info!("Attestation verification level: {}", level);

        match level {
            VerificationLevel::None => {
                error!("SECURITY: Attestation enabled without verification feature!");
                error!(
                    "Enable zkvm-prover or zkvm-verifier-groth16 feature for real verification."
                );
                error!("Build with: cargo build --features zkvm-prover");
                return Err(Error::Config(
                    "Attestation requires zkvm-prover or zkvm-verifier-groth16 feature. \
                     Without a verification feature, proofs use mock verification \
                     which provides NO CRYPTOGRAPHIC SECURITY. \
                     Build with: cargo build --features zkvm-prover"
                        .into(),
                ));
            }
            VerificationLevel::Groth16 => {
                if config.attestation.require_pq_secure {
                    error!(
                        "SECURITY: require_pq_secure=true but only Groth16 verification available"
                    );
                    return Err(Error::Config(
                        "require_pq_secure=true but only Groth16 available (not post-quantum secure). \
                         Either enable zkvm-prover feature for STARK verification, \
                         or set require_pq_secure=false in attestation config."
                            .into(),
                    ));
                }
                warn!(
                    "Attestation using Groth16 verification - NOT post-quantum secure. \
                     Consider enabling zkvm-prover feature for production deployments."
                );
            }
            VerificationLevel::Stark => {
                info!("Attestation using STARK verification (post-quantum secure)");
            }
        }

        Ok(())
    }

    /// Build the saorsa-core `AttestationConfig` from our config.
    fn build_attestation_config(config: &AttestationNodeConfig) -> Result<CoreAttestationConfig> {
        let enforcement_mode = match config.mode {
            AttestationMode::Off => CoreEnforcementMode::Off,
            AttestationMode::Soft => CoreEnforcementMode::Soft,
            AttestationMode::Hard => CoreEnforcementMode::Hard,
        };

        // Parse hex-encoded binary hashes
        let allowed_binary_hashes = config
            .allowed_binary_hashes
            .iter()
            .map(|hex_str| {
                let bytes = hex::decode(hex_str).map_err(|e| {
                    Error::Config(format!(
                        "Invalid hex in allowed_binary_hashes '{hex_str}': {e}"
                    ))
                })?;
                if bytes.len() != 32 {
                    let len = bytes.len();
                    return Err(Error::Config(format!(
                        "Binary hash must be 32 bytes (64 hex chars), got {len} bytes for '{hex_str}'"
                    )));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(arr)
            })
            .collect::<Result<Vec<_>>>()?;

        if config.mode == AttestationMode::Hard && config.enabled {
            if allowed_binary_hashes.is_empty() {
                warn!(
                    "Attestation in Hard mode with empty allowed_binary_hashes - \
                     all binaries will be accepted. Consider specifying allowed hashes."
                );
            } else {
                info!(
                    "Attestation in Hard mode with {} allowed binary hash(es)",
                    allowed_binary_hashes.len()
                );
            }
        }

        Ok(CoreAttestationConfig {
            enabled: config.enabled,
            enforcement_mode,
            allowed_binary_hashes,
            sunset_grace_days: config.sunset_grace_days,
        })
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
