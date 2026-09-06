//! Node implementation - thin wrapper around saorsa-core's `P2PNode`.

use crate::ant_protocol::CHUNK_PROTOCOL_ID;
use crate::config::{
    default_nodes_dir, default_root_dir, NetworkMode, NodeConfig, NODE_IDENTITY_FILENAME,
};
use crate::error::{Error, Result};
use crate::event::{create_event_channel, NodeEvent, NodeEventsChannel, NodeEventsSender};
use crate::logging::{debug, error, info, warn};
use crate::payment::metrics::QuotingMetricsTracker;
use crate::payment::wallet::parse_rewards_address;
use crate::payment::{
    EvmVerifierConfig, PaymentVerifier, PaymentVerifierConfig, PriceFloorConfig, QuoteGenerator,
};
use crate::replication::config::ReplicationConfig;
use crate::replication::fresh::FreshWriteEvent;
use crate::replication::ReplicationEngine;
use crate::storage::MIB;
use crate::storage::{AntProtocol, ChunkRequestContext, ChunkStore, ChunkStoreConfig};
use crate::upgrade::{
    upgrade_cache_dir, AutoApplyUpgrader, BinaryCache, ReleaseCache, UpgradeMonitor, UpgradeResult,
};
use rand::Rng;
use saorsa_core::identity::NodeIdentity;
use saorsa_core::{
    IPDiversityConfig as CoreDiversityConfig, MultiAddr, NodeConfig as CoreNodeConfig, P2PEvent,
    P2PNode,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

/// How long shutdown waits for in-flight request handlers to finish.
///
/// Short, because these are single request/response exchanges and the peer will retry.
/// The point is to stop new legacy reads starting, not to see every last one through.
const PROTOCOL_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// Builder for constructing an Ant node.
pub struct NodeBuilder {
    config: NodeConfig,
}

impl NodeBuilder {
    /// Create a new node builder with the given configuration.
    #[must_use]
    pub fn new(config: NodeConfig) -> Self {
        Self { config }
    }

    /// Reject startup in production mode without a usable rewards address.
    ///
    /// A node that cannot receive payment must not silently run on the
    /// production network. The placeholder address shipped in the example
    /// config and an empty string both count as "unconfigured".
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if `network_mode` is `Production` and
    /// `payment.rewards_address` is unset, empty, or the example placeholder.
    fn validate_production_rewards_address(config: &NodeConfig) -> Result<()> {
        if config.network_mode != NetworkMode::Production {
            return Ok(());
        }
        let configured = config
            .payment
            .rewards_address
            .as_deref()
            .is_some_and(|addr| !addr.is_empty() && addr != "0xYOUR_ARBITRUM_ADDRESS_HERE");
        if configured {
            Ok(())
        } else {
            Err(Error::Config(
                "CRITICAL: Rewards address is not configured. \
                 Set payment.rewards_address in config to your Arbitrum wallet address."
                    .to_string(),
            ))
        }
    }

    /// Build and start the node.
    ///
    /// # Errors
    ///
    /// Returns an error if the node fails to start.
    pub async fn build(mut self) -> Result<RunningNode> {
        info!("Building ant-node with config: {:?}", self.config);

        Self::validate_production_rewards_address(&self.config)?;

        // Resolve identity and root_dir (may update self.config.root_dir)
        let identity = Arc::new(Self::resolve_identity(&mut self.config).await?);
        let peer_id = identity.peer_id().to_hex();

        info!(peer_id = %peer_id, root_dir = %self.config.root_dir.display(), "Node identity resolved");

        // Ensure root directory exists
        std::fs::create_dir_all(&self.config.root_dir)?;

        // As soon as the root is known, and before anything is built on top of it. The
        // store's own constructor asks this too, but a node with `storage.enabled = false`
        // never builds a store and would walk straight past it, and turning storage off is
        // not consent to run beside chunks this build cannot read while the commitment that
        // claims them is still live.
        //
        // Ahead of the P2P node specifically. That binds transports and spawns background
        // tasks, so asking afterwards means a bind failure can mask this answer, and a
        // caller that does see the refusal has already been charged for a transport it is
        // about to throw away.
        crate::storage::legacy_artifacts::refuse_if_unmigrated(&self.config.root_dir)
            .map_err(|e| Error::Startup(e.to_string()))?;

        // One release-level decision, applied before anything can audit. It was suspended
        // for two releases while the fleet moved off the old chunk store, because a node
        // that has to give chunks up cannot stop its peers punishing it for that. This
        // release restores it, so a peer is penalised again for failing to hold a chunk it
        // was supposed to be holding. The commitment-bound audit penalised throughout.
        crate::replication::config::apply_close_group_storage_penalty_policy();

        // Create shutdown token
        let shutdown = CancellationToken::new();

        // Create event channel
        let (events_tx, events_rx) = create_event_channel();

        // Convert our config to saorsa-core's config
        let mut core_config = Self::build_core_config(&self.config)?;
        // Inject the ML-DSA identity so the P2PNode's transport peer ID
        // matches the pub_key embedded in payment quotes.
        core_config.node_identity = Some(Arc::clone(&identity));
        debug!("Core config: {:?}", core_config);

        // Initialize saorsa-core's P2PNode
        let p2p_node = P2PNode::new(core_config)
            .await
            .map_err(|e| Error::Startup(format!("Failed to create P2P node: {e}")))?;

        // Create upgrade monitor
        let upgrade_monitor = {
            let node_id_seed = p2p_node.peer_id().as_bytes();
            Some(Self::build_upgrade_monitor(&self.config, node_id_seed))
        };

        let repl_config = ReplicationConfig::default();

        // Initialize ANT protocol handler for chunk storage and
        // wire the fresh-write channel so PUTs trigger replication.
        let (ant_protocol, fresh_write_rx) = if self.config.storage.enabled {
            let (fresh_write_tx, fresh_write_rx) = tokio::sync::mpsc::unbounded_channel();
            let mut protocol =
                Self::build_ant_protocol(&self.config, &identity, repl_config.close_group_size)
                    .await?;
            protocol.set_fresh_write_sender(fresh_write_tx);
            (Some(Arc::new(protocol)), Some(fresh_write_rx))
        } else {
            info!("Chunk storage disabled");
            (None, None)
        };

        let p2p_arc = Arc::new(p2p_node);

        // Wire the P2PNode handle into AntProtocol so payment proofs can query
        // live-DHT closeness.
        if let Some(ref protocol) = ant_protocol {
            protocol.attach_p2p_node(Arc::clone(&p2p_arc));
        }

        let replication_engine = match (&ant_protocol, fresh_write_rx) {
            (Some(protocol), Some(fresh_rx)) => {
                Self::build_replication_engine(
                    protocol,
                    repl_config,
                    &p2p_arc,
                    &identity,
                    &self.config.root_dir,
                    fresh_rx,
                    &shutdown,
                )
                .await?
            }
            _ => None,
        };

        let node = RunningNode {
            config: self.config,
            p2p_node: p2p_arc,
            shutdown,
            events_tx,
            events_rx: Some(events_rx),
            upgrade_monitor,
            ant_protocol,
            replication_engine,
            protocol_task: None,
            protocol_children: TaskTracker::new(),
            upgrade_exit_code: Arc::new(AtomicI32::new(-1)),
        };

        Ok(node)
    }

    /// Start the replication engine.
    ///
    /// # Errors
    ///
    /// Never, currently: an engine that fails to start is logged and the node runs without
    /// one, as it always has. The signature keeps its `Result` because the caller's does,
    /// and because the migration release did have a case that had to refuse.
    async fn build_replication_engine(
        protocol: &Arc<AntProtocol>,
        repl_config: ReplicationConfig,
        p2p: &Arc<P2PNode>,
        identity: &Arc<NodeIdentity>,
        root_dir: &Path,
        fresh_rx: UnboundedReceiver<FreshWriteEvent>,
        shutdown: &CancellationToken,
    ) -> Result<Option<ReplicationEngine>> {
        let engine = match ReplicationEngine::new(
            repl_config,
            Arc::clone(p2p),
            protocol.storage(),
            protocol.payment_verifier_arc(),
            Arc::clone(identity),
            root_dir,
            fresh_rx,
            shutdown.clone(),
        )
        .await
        {
            Ok(engine) => engine,
            Err(e) => {
                warn!("Failed to initialize replication engine: {e}");
                return Ok(None);
            }
        };

        // ADR-0004: wire the engine's commitment state as the quote generator's
        // commitment source so quotes force their price from the live storage
        // commitment. Done here because the engine owns the commitment state and is
        // built after the protocol.
        let concrete = Arc::clone(engine.commitment_state());
        let source: Arc<dyn crate::payment::quote::CommitmentSource> = concrete;
        protocol.attach_commitment_source(source);
        // ADR-0004: share the engine's gossip commitment cache with the verifier so the
        // cross-check can resolve quote pins against neighbours' commitments.
        protocol
            .payment_verifier_arc()
            .attach_commitment_cache(Arc::clone(engine.last_commitment_by_peer()));
        // ADR-0004: give the verifier the monetized-pin sender so commitments that back
        // a payment get a deterministic first audit from the engine's drainer.
        protocol
            .payment_verifier_arc()
            .attach_monetized_pin_sender(engine.monetized_pin_sender());

        Ok(Some(engine))
    }

    /// Build the saorsa-core `NodeConfig` from our config.
    fn build_core_config(config: &NodeConfig) -> Result<CoreNodeConfig> {
        let local = matches!(config.network_mode, NetworkMode::Development);

        let mut core_config = CoreNodeConfig::builder()
            .port(config.port)
            .ipv6(!config.ipv4_only)
            .local(local)
            .max_message_size(config.max_message_size)
            .build()
            .map_err(|e| Error::Config(format!("Failed to create core config: {e}")))?;

        // Add bootstrap peers.
        core_config.bootstrap_peers = config
            .bootstrap
            .iter()
            .map(|addr| MultiAddr::quic(*addr))
            .collect();

        // Propagate network-mode tuning into saorsa-core where supported.
        match config.network_mode {
            NetworkMode::Production => {
                core_config.diversity_config = Some(CoreDiversityConfig::default());
            }
            NetworkMode::Testnet => {
                // Testnet allows loopback so nodes can be co-located on one machine.
                core_config.allow_loopback = true;
                core_config.diversity_config = Some(CoreDiversityConfig {
                    max_per_ip: config.testnet.max_per_ip,
                    max_per_subnet: config.testnet.max_per_subnet,
                });
            }
            NetworkMode::Development => {
                core_config.diversity_config = Some(CoreDiversityConfig::permissive());
            }
        }

        // Persist close group peers + trust scores across restarts.
        // Default to root_dir (alongside node_identity.key) when not explicitly set.
        core_config.close_group_cache_dir = Some(
            config
                .close_group_cache_dir
                .clone()
                .unwrap_or_else(|| config.root_dir.clone()),
        );

        Ok(core_config)
    }

    /// Resolve the node identity from disk or generate a new one.
    ///
    /// **When `root_dir` differs from the platform default** (set via `--root-dir`
    /// or loaded from `config.toml`):
    ///   - Use `root_dir` directly: load existing identity or generate a new one.
    ///
    /// **When `root_dir` is the platform default** (first run, no config file):
    ///   1. Scan `{default_root_dir}/nodes/` for subdirectories containing
    ///      `node_identity.key`.
    ///   2. **None found** — first run: generate identity, create
    ///      `nodes/{full_peer_id}/`, save identity there, update `config.root_dir`.
    ///   3. **Exactly one found** — load it and update `config.root_dir`.
    ///   4. **Multiple found** — return an error asking for `--root-dir`.
    async fn resolve_identity(config: &mut NodeConfig) -> Result<NodeIdentity> {
        if config.root_dir != default_root_dir() {
            return Self::load_or_generate_identity(&config.root_dir).await;
        }

        let nodes_dir = default_nodes_dir();
        let identity_dirs = Self::scan_identity_dirs(&nodes_dir)?;

        match identity_dirs.len() {
            0 => {
                // First run: generate new identity and create a peer-id-scoped subdirectory
                let identity = NodeIdentity::generate().map_err(|e| {
                    Error::Startup(format!("Failed to generate node identity: {e}"))
                })?;
                let peer_id = identity.peer_id().to_hex();
                let peer_dir = nodes_dir.join(&peer_id);
                std::fs::create_dir_all(&peer_dir)?;
                identity
                    .save_to_file(&peer_dir.join(NODE_IDENTITY_FILENAME))
                    .await
                    .map_err(|e| Error::Startup(format!("Failed to save node identity: {e}")))?;
                config.root_dir = peer_dir;
                Ok(identity)
            }
            1 => {
                let dir = identity_dirs
                    .first()
                    .ok_or_else(|| Error::Config("No identity dirs found".to_string()))?;
                let identity = NodeIdentity::load_from_file(&dir.join(NODE_IDENTITY_FILENAME))
                    .await
                    .map_err(|e| Error::Startup(format!("Failed to load node identity: {e}")))?;
                config.root_dir.clone_from(dir);
                Ok(identity)
            }
            _ => {
                let dirs: Vec<String> = identity_dirs
                    .iter()
                    .filter_map(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()))
                    .collect();
                Err(Error::Config(format!(
                    "Multiple node identities found at {}: [{}]. Specify --root-dir to select one.",
                    nodes_dir.display(),
                    dirs.join(", ")
                )))
            }
        }
    }

    /// Load an existing identity from `dir/node_identity.key`, or generate and save a new one.
    async fn load_or_generate_identity(dir: &std::path::Path) -> Result<NodeIdentity> {
        let key_path = dir.join(NODE_IDENTITY_FILENAME);
        if key_path.exists() {
            NodeIdentity::load_from_file(&key_path)
                .await
                .map_err(|e| Error::Startup(format!("Failed to load node identity: {e}")))
        } else {
            let identity = NodeIdentity::generate()
                .map_err(|e| Error::Startup(format!("Failed to generate node identity: {e}")))?;
            std::fs::create_dir_all(dir)?;
            identity
                .save_to_file(&key_path)
                .await
                .map_err(|e| Error::Startup(format!("Failed to save node identity: {e}")))?;
            Ok(identity)
        }
    }

    /// Scan `base_dir` for immediate subdirectories that contain `node_identity.key`.
    fn scan_identity_dirs(base_dir: &std::path::Path) -> Result<Vec<PathBuf>> {
        let mut dirs = Vec::new();
        let read_dir = match std::fs::read_dir(base_dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(dirs),
            Err(e) => return Err(e.into()),
        };
        for entry in read_dir {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && path.join(NODE_IDENTITY_FILENAME).exists() {
                dirs.push(path);
            }
        }
        Ok(dirs)
    }

    fn build_upgrade_monitor(config: &NodeConfig, node_id_seed: &[u8]) -> UpgradeMonitor {
        let mut monitor = UpgradeMonitor::new(
            config.upgrade.github_repo.clone(),
            config.upgrade.channel,
            config.upgrade.check_interval_hours,
        );

        if let Ok(cache_dir) = upgrade_cache_dir() {
            monitor = monitor.with_release_cache(ReleaseCache::new(
                cache_dir,
                std::time::Duration::from_secs(3600),
            ));
        }

        if config.upgrade.staged_rollout_hours > 0 {
            monitor =
                monitor.with_staged_rollout(node_id_seed, config.upgrade.staged_rollout_hours);
        }

        monitor
    }
    /// Build the ANT protocol handler from config.
    ///
    /// Initializes the chunk store, payment verifier, and quote generator.
    /// Wires ML-DSA-65 signing from the node's identity into the quote generator.
    async fn build_ant_protocol(
        config: &NodeConfig,
        identity: &NodeIdentity,
        close_group_size: usize,
    ) -> Result<AntProtocol> {
        let storage_config = ChunkStoreConfig {
            root_dir: config.root_dir.clone(),
            verify_on_read: config.storage.verify_on_read,
            disk_reserve: config.storage.disk_reserve_mb.saturating_mul(MIB),
        };
        let storage = ChunkStore::new(storage_config)
            .await
            .map_err(|e| Error::Startup(format!("Failed to create the chunk store: {e}")))?;

        // Parse rewards address (required — node must know where to receive payments)
        let rewards_address = match config.payment.rewards_address {
            Some(ref addr) => parse_rewards_address(addr)?,
            None => {
                return Err(Error::Startup(
                    "No rewards address configured. Set --rewards-address or payment.rewards_address in config.".to_string(),
                ));
            }
        };

        // Create payment verifier
        let evm_network = config.payment.evm_network.clone().into_evm_network();
        let payment_config = PaymentVerifierConfig {
            evm: EvmVerifierConfig {
                network: evm_network,
            },
            cache_capacity: config.payment.cache_capacity,
            close_group_size,
            local_rewards_address: rewards_address,
            // Shadow mode by default; enforcement is a per-node canary opt-in
            // via ANT_PRICE_FLOOR_ENFORCE (see PriceFloorConfig).
            price_floor: PriceFloorConfig::from_env(),
        };
        if payment_config.price_floor.enforce {
            info!(
                "Price floor ENFORCEMENT enabled (tolerance {}%)",
                payment_config.price_floor.tolerance_percent
            );
        }
        let payment_verifier = PaymentVerifier::new(payment_config);
        let metrics_tracker = QuotingMetricsTracker::new(0);
        let mut quote_generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        // Wire ML-DSA-65 signing from node identity.
        // This same signer is used for both regular quotes and merkle candidate quotes.
        crate::payment::wire_ml_dsa_signer(&mut quote_generator, identity)?;

        let storage = Arc::new(storage);
        let payment_verifier = Arc::new(payment_verifier);

        let protocol = AntProtocol::new(storage, payment_verifier, Arc::new(quote_generator));

        info!(
            "ANT protocol handler initialized with ML-DSA-65 signing (protocol={CHUNK_PROTOCOL_ID})"
        );

        Ok(protocol)
    }
}

/// A running Ant node.
pub struct RunningNode {
    config: NodeConfig,
    p2p_node: Arc<P2PNode>,
    shutdown: CancellationToken,
    events_tx: NodeEventsSender,
    events_rx: Option<NodeEventsChannel>,
    upgrade_monitor: Option<UpgradeMonitor>,
    /// ANT protocol handler for chunk storage.
    ant_protocol: Option<Arc<AntProtocol>>,
    /// Replication engine (manages neighbor sync, verification, audits).
    replication_engine: Option<ReplicationEngine>,
    /// Protocol message routing background task.
    protocol_task: Option<JoinHandle<()>>,
    /// The per-message handler tasks the protocol loop spawns.
    ///
    /// Tracked rather than detached so shutdown can stop accepting work and then wait for
    /// what is already in flight. Aborting only the loop leaves its children running, and
    /// a chunk read that outlives the loop keeps working against a store the shutdown is
    /// about to tear down.
    protocol_children: TaskTracker,
    /// Exit code requested by a successful upgrade (-1 = no upgrade exit pending).
    upgrade_exit_code: Arc<AtomicI32>,
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
    #[allow(clippy::too_many_lines)]
    pub async fn run(&mut self) -> Result<()> {
        info!("Node runtime loop starting");

        // Subscribe to DHT events BEFORE starting the P2P node so the
        // bootstrap-sync task does not miss the BootstrapComplete event
        // emitted during P2PNode::start().
        let dht_events_for_bootstrap = self
            .replication_engine
            .as_ref()
            .map(|_| self.p2p_node.dht_manager().subscribe_events());

        // Start the P2P node
        self.p2p_node
            .start()
            .await
            .map_err(|e| Error::Startup(format!("Failed to start P2P node: {e}")))?;

        let listen_addrs = self.p2p_node.listen_addrs().await;
        info!(listen_addrs = ?listen_addrs, "P2P node started");

        // Extract the actual bound port (config port may be 0 = auto-select)
        let actual_port = listen_addrs
            .first()
            .and_then(MultiAddr::port)
            .unwrap_or(self.config.port);
        info!(
            port = actual_port,
            "Node is running on port: {}", actual_port
        );

        // Emit started event
        if let Err(e) = self.events_tx.send(NodeEvent::Started) {
            warn!("Failed to send Started event: {e}");
        }

        // Start protocol message routing (P2P → AntProtocol → P2P response)
        self.start_protocol_routing();

        // Start replication engine background tasks
        if let Some(ref mut engine) = self.replication_engine {
            // Safety: dht_events_for_bootstrap is Some when replication_engine
            // is Some (both arms use the same condition).
            if let Some(dht_events) = dht_events_for_bootstrap {
                engine.start(dht_events);
            }
            info!("Replication engine started");
        }

        // Start upgrade monitor if enabled
        if let Some(monitor) = self.upgrade_monitor.take() {
            let events_tx = self.events_tx.clone();
            let shutdown = self.shutdown.clone();
            let stop_on_upgrade = self.config.upgrade.stop_on_upgrade;
            let upgrade_exit_code = Arc::clone(&self.upgrade_exit_code);

            tokio::spawn(async move {
                let mut monitor = monitor;
                let mut upgrader = AutoApplyUpgrader::new().with_stop_on_upgrade(stop_on_upgrade);
                if let Ok(cache_dir) = upgrade_cache_dir() {
                    upgrader = upgrader.with_binary_cache(BinaryCache::new(cache_dir));
                }

                // Add randomized jitter before the first upgrade check to prevent all nodes
                // from hitting the GitHub API simultaneously when started together.
                {
                    let jitter_duration = jittered_interval(monitor.check_interval());
                    let first_check_time = chrono::Utc::now()
                        + chrono::Duration::from_std(jitter_duration).unwrap_or_else(|e| {
                            warn!("chrono::Duration::from_std failed for jitter ({e}), defaulting to 1 minute");
                            chrono::Duration::minutes(1)
                        });
                    info!(
                        "First upgrade check scheduled for {} (jitter: {}s)",
                        first_check_time.to_rfc3339(),
                        jitter_duration.as_secs()
                    );
                    tokio::time::sleep(jitter_duration).await;
                }

                loop {
                    tokio::select! {
                        () = shutdown.cancelled() => {
                            break;
                        }
                        result = monitor.check_for_ready_upgrade() => {
                            match result {
                                Ok(Some(upgrade_info)) => {
                                    info!(
                                        current_version = %upgrader.current_version(),
                                        new_version = %upgrade_info.version,
                                        "Upgrade available"
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
                                        Ok(UpgradeResult::Success { version, exit_code }) => {
                                            info!("Upgrade to {} successful, initiating graceful shutdown", version);
                                            upgrade_exit_code.store(exit_code, Ordering::SeqCst);
                                            shutdown.cancel();
                                            break;
                                        }
                                        Ok(UpgradeResult::RolledBack { reason }) => {
                                            warn!("Error during upgrade process: {}", reason);
                                        }
                                        Ok(UpgradeResult::NoUpgrade) => {
                                            info!("Already running latest version");
                                        }
                                        Err(e) => {
                                            error!("Error during upgrade process: {}", e);
                                        }
                                    }
                                }
                                Ok(None) => {
                                    if let Some(remaining) = monitor.time_until_upgrade() {
                                        info!(
                                            "Upgrade pending, rollout delay remaining: {}m {}s",
                                            remaining.as_secs() / 60,
                                            remaining.as_secs() % 60
                                        );
                                    } else {
                                        info!("No upgrade available");
                                    }
                                }
                                Err(e) => {
                                    warn!("Error during upgrade process: {}", e);
                                }
                            }
                            // If an upgrade is pending, sleep for exactly the remaining
                            // rollout delay so the node restarts at its scheduled time
                            // rather than waiting for the next check interval tick.
                            let sleep_duration = monitor.time_until_upgrade().map_or_else(
                                || {
                                    // No pending upgrade - schedule next check with jitter
                                    let jittered_duration =
                                        jittered_interval(monitor.check_interval());
                                    let next_check = chrono::Utc::now()
                                        + chrono::Duration::from_std(jittered_duration).unwrap_or_else(|e| {
                                            warn!("chrono::Duration::from_std failed for interval ({e}), defaulting to 1 hour");
                                            chrono::Duration::hours(1)
                                        });
                                    info!("Next upgrade check scheduled for {}", next_check.to_rfc3339());
                                    jittered_duration
                                },
                                |remaining| {
                                    // If the rollout delay has fully elapsed but the upgrade was
                                    // not successfully applied, avoid a tight loop by backing off
                                    // at least one check interval before retrying.
                                    if remaining.is_zero() {
                                        let backoff = jittered_interval(monitor.check_interval());
                                        let next_check = chrono::Utc::now()
                                            + chrono::Duration::from_std(backoff).unwrap_or_else(|e| {
                                                warn!("chrono::Duration::from_std failed for backoff ({e}), defaulting to 1 hour");
                                                chrono::Duration::hours(1)
                                            });
                                        info!(
                                            "Upgrade rollout delay elapsed but previous apply did not succeed; \
                                             backing off, next check scheduled for {}",
                                            next_check.to_rfc3339()
                                        );
                                        backoff
                                    } else {
                                        let wake_time = chrono::Utc::now()
                                            + chrono::Duration::from_std(remaining).unwrap_or_else(|e| {
                                                warn!("chrono::Duration::from_std failed for rollout delay ({e}), defaulting to 1 minute");
                                                chrono::Duration::minutes(1)
                                            });
                                        info!("Will apply upgrade at {}", wake_time.to_rfc3339());
                                        remaining
                                    }
                                },
                            );
                            // Use select! so shutdown can interrupt long sleeps
                            // (e.g. during a full rollout window delay).
                            tokio::select! {
                                () = shutdown.cancelled() => {
                                    break;
                                }
                                () = tokio::time::sleep(sleep_duration) => {}
                            }
                        }
                    }
                }
            });
        }

        info!("Node running, waiting for shutdown signal");

        // The main event loop, with signal handling. Everything above this starts
        // something; this is where the node waits.
        self.run_event_loop().await?;

        // Protocol routing stops first, loop and children both. The routing loop waits on
        // `events.recv()` and has no cancellation branch of its own, and it holds an `Arc`
        // on the P2P node that keeps the sender it is waiting on alive, so nothing else
        // here will ever wake it. Left running it holds the chunk store and its
        // single-process lock open after the node has returned. Aborting the accept loop
        // alone is not enough either: the requests already in flight run in their own
        // tasks, which is what the drain below is for.
        if let Some(handle) = self.protocol_task.take() {
            handle.abort();
            // Awaited, not just asked to stop. `abort` schedules cancellation; it does not
            // establish that the task is gone, and what matters here is that it has
            // dropped its `Arc` on the protocol and with it the store's single-process
            // lock before this function returns. The join resolves as cancelled.
            let _ = handle.await;
        }
        // Cancelled first, so anything still queued behind the concurrency permits gives
        // up rather than starting fresh storage work, then given a moment to finish what
        // is genuinely in flight.
        self.shutdown.cancel();
        self.protocol_children.close();
        if tokio::time::timeout(PROTOCOL_DRAIN_GRACE, self.protocol_children.wait())
            .await
            .is_err()
        {
            warn!(
                "{} request handler(s) had not finished after {}s; continuing shutdown \
                 without them.",
                self.protocol_children.len(),
                PROTOCOL_DRAIN_GRACE.as_secs()
            );
        }

        // Shutdown replication engine before P2P so background tasks don't
        // use a dead P2P layer, and Arc<ChunkStore> references are released.
        if let Some(ref mut engine) = self.replication_engine {
            engine.shutdown().await;
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

        // If an upgrade triggered the shutdown, exit with the requested code.
        // This happens *after* all cleanup (P2P shutdown, log flush, etc.) so
        // that destructors and async resources are properly torn down.
        let exit_code = self.upgrade_exit_code.load(Ordering::SeqCst);
        if exit_code >= 0 {
            info!("Exiting with code {} for upgrade restart", exit_code);
            std::process::exit(exit_code);
        }

        Ok(())
    }

    /// Run the main event loop, handling shutdown and signals.
    #[cfg(unix)]
    async fn run_event_loop(&self) -> Result<()> {
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sighup = signal(SignalKind::hangup())?;

        loop {
            tokio::select! {
                () = self.shutdown.cancelled() => {
                    info!("Shutdown signal received");
                    break;
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
                    info!("Received SIGHUP (config reload not yet supported)");
                }
            }
        }
        Ok(())
    }

    /// Run the main event loop, handling shutdown signals (non-Unix version).
    #[cfg(not(unix))]
    async fn run_event_loop(&self) -> Result<()> {
        loop {
            tokio::select! {
                () = self.shutdown.cancelled() => {
                    info!("Shutdown signal received");
                    break;
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

    /// Handle one inbound protocol message and send whatever it produced.
    async fn answer_one_request(
        protocol: &Arc<AntProtocol>,
        p2p: &Arc<P2PNode>,
        source: &saorsa_core::identity::PeerId,
        data: &[u8],
        data_type: &str,
        response_topic: &str,
        received_at: Instant,
    ) {
        if data_type != "chunk" {
            return;
        }
        let queue_wait = received_at.elapsed();
        let handled = protocol
            .try_handle_request_with_context(
                data,
                Some(ChunkRequestContext::new(
                    source.to_string(),
                    received_at,
                    queue_wait,
                )),
            )
            .await;
        let telemetry = handled.get_telemetry;
        match handled.response {
            Ok(Some(response)) => {
                let send_started = Instant::now();
                let send_result = p2p
                    .send_message(source, response_topic, response.to_vec(), &[])
                    .await;
                if let Some(telemetry) = telemetry {
                    telemetry.finish_send(send_started.elapsed(), send_result.is_ok());
                }
                if let Err(e) = send_result {
                    warn!("Failed to send {data_type} protocol response to {source}: {e}");
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
                warn!("{data_type} protocol handler error: {e}");
            }
        }
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
        let semaphore = Arc::new(Semaphore::new(64));
        let children = self.protocol_children.clone();
        let stopping = self.shutdown.clone();

        self.protocol_task = Some(tokio::spawn(async move {
            while let Ok(event) = events.recv().await {
                if let P2PEvent::Message {
                    topic,
                    source: Some(source),
                    data,
                    ..
                } = event
                {
                    let handler_info: Option<(&str, &str)> = if topic == CHUNK_PROTOCOL_ID {
                        Some(("chunk", CHUNK_PROTOCOL_ID))
                    } else {
                        None
                    };

                    if let Some((data_type, response_topic)) = handler_info {
                        debug!("Received {data_type} protocol message from {source}");
                        let received_at = Instant::now();
                        let protocol = Arc::clone(&protocol);
                        let p2p = Arc::clone(&p2p);
                        let sem = semaphore.clone();
                        let stopping = stopping.clone();
                        children.spawn(async move {
                            // A queued handler must not start work once shutdown has
                            // begun. With 64 permits and a busy node the queue behind them
                            // can be long, and every one of those would otherwise start
                            // fresh storage reads while the store beneath is being torn
                            // down.
                            let _permit = {
                                let acquired = tokio::select! {
                                    biased;
                                    () = stopping.cancelled() => return,
                                    p = sem.acquire() => p,
                                };
                                match acquired {
                                    Ok(permit) => permit,
                                    Err(_) => return,
                                }
                            };
                            // Checked again: the wait for a permit may have been long.
                            if stopping.is_cancelled() {
                                return;
                            }
                            Self::answer_one_request(
                                &protocol,
                                &p2p,
                                &source,
                                &data,
                                data_type,
                                response_topic,
                                received_at,
                            )
                            .await;
                        });
                    }
                }
            }
        }));
        info!("Protocol message routing started");
    }

    /// Request the node to shut down.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

/// Apply ±5% jitter to a base interval to prevent thundering-herd behaviour
/// when multiple nodes check for upgrades on the same schedule.
fn jittered_interval(base: std::time::Duration) -> std::time::Duration {
    let secs = base.as_secs();
    let variance = secs / 20; // 5%
    if variance == 0 {
        return base;
    }
    let jitter = rand::thread_rng().gen_range(0..=variance * 2);
    std::time::Duration::from_secs(secs.saturating_sub(variance) + jitter)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use rand::Rng;
    use tempfile::TempDir;

    /// The e2e port range, so a test bind never lands on a production or dev instance.
    const TEST_PORT_RANGE: std::ops::Range<u16> = 20000..60000;

    /// How many times a bind is retried before the failure is treated as real.
    const BIND_ATTEMPTS: u32 = 5;

    /// A well-formed address that receives nothing; no chain is contacted in these tests.
    const TEST_REWARDS_ADDRESS: &str = "0x0000000000000000000000000000000000000001";

    /// A node config that builds without touching a chain or a real network.
    fn local_node_config(root: &std::path::Path, port: u16) -> NodeConfig {
        NodeConfig {
            root_dir: root.to_path_buf(),
            port,
            ipv4_only: true,
            network_mode: NetworkMode::Development,
            payment: crate::config::PaymentConfig {
                rewards_address: Some(TEST_REWARDS_ADDRESS.to_string()),
                ..crate::config::PaymentConfig::default()
            },
            ..NodeConfig::default()
        }
    }

    /// A node builds on a root with nothing left over from the old store.
    #[tokio::test]
    async fn a_node_builds_on_a_clean_root() {
        let dir = TempDir::new().expect("temp dir");
        let root = dir.path().join("node");
        std::fs::create_dir_all(&root).expect("mkdir");

        let mut built = None;
        let mut last_err = String::new();
        for _ in 0..BIND_ATTEMPTS {
            let port = rand::thread_rng().gen_range(TEST_PORT_RANGE);
            match NodeBuilder::new(local_node_config(&root, port))
                .build()
                .await
            {
                Ok(node) => {
                    built = Some(node);
                    break;
                }
                Err(e) => {
                    last_err = e.to_string();
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
            }
        }
        let Some(node) = built else {
            panic!("could not build a node after {BIND_ATTEMPTS} attempts: {last_err}");
        };

        node.shutdown.cancel();
    }

    /// A node with chunks in a store this build cannot read does not start, however it is
    /// configured.
    ///
    /// Both ways, because they are different code paths and only one of them was covered.
    /// The store's own constructor asks the question, but a node with `storage.enabled =
    /// false` never builds a store and so never reaches it. Turning storage off is not
    /// consent to run beside chunks that this node's own published commitment still claims
    /// and that this build cannot read, so the question is asked before anything is built.
    ///
    /// Goes through `build()` rather than the check directly. The failure worth catching
    /// here is the call site going missing, which is what happened: the check existed and
    /// one of the two routes into the node walked straight past it.
    #[tokio::test]
    async fn a_node_with_an_unmigrated_store_refuses_to_build_however_it_is_configured() {
        for storage_enabled in [true, false] {
            let dir = TempDir::new().expect("temp dir");
            let root = dir.path().join("node");
            let env = root.join(crate::storage::LEGACY_ENV_DIR);
            std::fs::create_dir_all(&env).expect("mkdir");
            std::fs::write(env.join("data.mdb"), b"chunks that were never copied out")
                .expect("seed");

            let port = rand::thread_rng().gen_range(TEST_PORT_RANGE);
            let mut config = local_node_config(&root, port);
            config.storage.enabled = storage_enabled;

            let err = NodeBuilder::new(config)
                .build()
                .await
                .err()
                .unwrap_or_else(|| {
                    panic!(
                        "a node with an unmigrated store built with storage.enabled = \
                         {storage_enabled}"
                    )
                });
            let said = err.to_string();
            assert!(
                said.contains("chunks.mdb"),
                "the refusal must name the directory (storage.enabled = {storage_enabled}): \
                 {said}"
            );
        }

        // And it answers before the transport is built, not after. Asking afterwards means
        // a bind failure masks this answer, and a caller that does see it has already been
        // charged for a transport it is about to throw away. Staged with a privileged port,
        // which an ordinary user cannot bind, so P2P construction would fail if it were
        // reached: the refusal still has to be the one that comes back.
        let dir = TempDir::new().expect("temp dir");
        let root = dir.path().join("node");
        let env = root.join(crate::storage::LEGACY_ENV_DIR);
        std::fs::create_dir_all(&env).expect("mkdir");
        std::fs::write(env.join("data.mdb"), b"never copied out").expect("seed");

        let said = NodeBuilder::new(local_node_config(&root, 1))
            .build()
            .await
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(
            said.contains("chunks.mdb"),
            "the store answer must come back before the transport is built, got: {said}"
        );
    }
    use super::*;
    use crate::config::NODES_SUBDIR;

    #[test]
    fn test_build_upgrade_monitor_staged_rollout_enabled() {
        let config = NodeConfig {
            upgrade: crate::config::UpgradeConfig {
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
        assert!(core.diversity_config.is_some());
    }

    #[test]
    fn test_build_core_config_ipv4_only() {
        let config = NodeConfig {
            ipv4_only: true,
            ..Default::default()
        };
        let core = NodeBuilder::build_core_config(&config).expect("core config");
        assert!(!core.ipv6, "ipv4_only should disable IPv6");
    }

    #[test]
    fn test_build_core_config_dual_stack_by_default() {
        let config = NodeConfig::default();
        let core = NodeBuilder::build_core_config(&config).expect("core config");
        assert!(core.ipv6, "dual-stack should be the default");
    }

    #[test]
    fn test_build_core_config_sets_development_mode_permissive() {
        let config = NodeConfig {
            network_mode: NetworkMode::Development,
            ..Default::default()
        };
        let core = NodeBuilder::build_core_config(&config).expect("core config");
        let diversity = core.diversity_config.expect("diversity");
        assert_eq!(diversity.max_per_ip, Some(usize::MAX));
        assert_eq!(diversity.max_per_subnet, Some(usize::MAX));
    }

    #[test]
    fn test_scan_identity_dirs_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs = NodeBuilder::scan_identity_dirs(tmp.path()).unwrap();
        assert!(dirs.is_empty());
    }

    #[test]
    fn test_scan_identity_dirs_nonexistent_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nonexistent_identity_dir");
        let dirs = NodeBuilder::scan_identity_dirs(&path).unwrap();
        assert!(dirs.is_empty());
    }

    #[test]
    fn test_scan_identity_dirs_finds_one() {
        let tmp = tempfile::tempdir().unwrap();
        let node_dir = tmp.path().join("abc123");
        std::fs::create_dir_all(&node_dir).unwrap();
        std::fs::write(node_dir.join(NODE_IDENTITY_FILENAME), "{}").unwrap();

        let dirs = NodeBuilder::scan_identity_dirs(tmp.path()).unwrap();
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0], node_dir);
    }

    #[test]
    fn test_scan_identity_dirs_finds_multiple() {
        let tmp = tempfile::tempdir().unwrap();
        for name in &["node_a", "node_b"] {
            let dir = tmp.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(NODE_IDENTITY_FILENAME), "{}").unwrap();
        }
        // A directory without a key file should be ignored
        std::fs::create_dir_all(tmp.path().join("no_key")).unwrap();

        let dirs = NodeBuilder::scan_identity_dirs(tmp.path()).unwrap();
        assert_eq!(dirs.len(), 2);
    }

    #[tokio::test]
    async fn test_resolve_identity_first_run_creates_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = NodeConfig {
            root_dir: tmp.path().to_path_buf(),
            ..Default::default()
        };

        let identity = NodeBuilder::resolve_identity(&mut config).await.unwrap();
        // Key file should exist
        assert!(tmp.path().join(NODE_IDENTITY_FILENAME).exists());
        // peer_id should be derivable from the identity
        let peer_id = identity.peer_id().to_hex();
        assert_eq!(peer_id.len(), 64); // 32 bytes hex-encoded
    }

    #[tokio::test]
    async fn test_resolve_identity_loads_existing() {
        let tmp = tempfile::tempdir().unwrap();

        // Generate and save an identity
        let original = NodeIdentity::generate().unwrap();
        original
            .save_to_file(&tmp.path().join(NODE_IDENTITY_FILENAME))
            .await
            .unwrap();

        let mut config = NodeConfig {
            root_dir: tmp.path().to_path_buf(),
            ..Default::default()
        };

        let loaded = NodeBuilder::resolve_identity(&mut config).await.unwrap();
        assert_eq!(loaded.peer_id(), original.peer_id());
    }

    #[test]
    fn test_peer_id_hex_length() {
        let id = saorsa_core::identity::PeerId::from_bytes([0x42; 32]);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
    }

    /// Simulates a node restart: first run creates identity in a scoped subdir
    /// under `nodes/`, second run discovers and reloads it — `peer_id` must be
    /// identical and the directory name is the full 64-char hex peer ID.
    #[tokio::test]
    async fn test_identity_persisted_across_restarts() {
        let base_dir = tempfile::tempdir().unwrap();
        let nodes_dir = base_dir.path().join(NODES_SUBDIR);

        // First "boot": generate identity, save it in nodes/{peer_id}/
        let identity1 = NodeIdentity::generate().unwrap();
        let peer_id1 = identity1.peer_id().to_hex();
        let peer_dir = nodes_dir.join(&peer_id1);
        std::fs::create_dir_all(&peer_dir).unwrap();
        identity1
            .save_to_file(&peer_dir.join(NODE_IDENTITY_FILENAME))
            .await
            .unwrap();

        // Verify directory name is the full 64-char hex peer ID
        assert_eq!(peer_id1.len(), 64);
        assert_eq!(peer_dir.file_name().unwrap().to_string_lossy(), peer_id1);

        // Second "boot": scan should find and reload the same identity
        let identity_dirs = NodeBuilder::scan_identity_dirs(&nodes_dir).unwrap();
        assert_eq!(identity_dirs.len(), 1);
        let loaded = NodeIdentity::load_from_file(&identity_dirs[0].join(NODE_IDENTITY_FILENAME))
            .await
            .unwrap();
        let peer_id2 = loaded.peer_id().to_hex();

        assert_eq!(peer_id1, peer_id2, "peer_id must survive restart");
        assert_eq!(
            identity_dirs[0], peer_dir,
            "root_dir must be the same directory"
        );
    }

    /// When two identity subdirs exist under `nodes/`, the scan finds multiple
    /// and the resolve path would error asking for `--root-dir`.
    #[tokio::test]
    async fn test_multiple_identities_errors() {
        let base_dir = tempfile::tempdir().unwrap();
        let nodes_dir = base_dir.path().join(NODES_SUBDIR);

        // Create two identity subdirectories under nodes/
        for name in &["aaaa", "bbbb"] {
            let dir = nodes_dir.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            let identity = NodeIdentity::generate().unwrap();
            identity
                .save_to_file(&dir.join(NODE_IDENTITY_FILENAME))
                .await
                .unwrap();
        }

        let identity_dirs = NodeBuilder::scan_identity_dirs(&nodes_dir).unwrap();
        assert_eq!(identity_dirs.len(), 2, "should find both identity dirs");
    }

    /// With a non-default `root_dir` (explicit path), the identity is created on
    /// first run and reloaded on subsequent runs from the same directory.
    #[tokio::test]
    async fn test_explicit_root_dir_persists_across_restarts() {
        let tmp = tempfile::tempdir().unwrap();

        // First boot — non-default root_dir triggers explicit path
        let mut config1 = NodeConfig {
            root_dir: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let identity1 = NodeBuilder::resolve_identity(&mut config1).await.unwrap();

        // Second boot — same dir
        let mut config2 = NodeConfig {
            root_dir: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let identity2 = NodeBuilder::resolve_identity(&mut config2).await.unwrap();

        assert_eq!(
            identity1.peer_id(),
            identity2.peer_id(),
            "explicit --root-dir must yield stable identity"
        );
    }
}
