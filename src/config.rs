//! Configuration for ant-node.

use evmlib::Network as EvmNetwork;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};

/// Filename for the persisted node identity keypair.
pub const NODE_IDENTITY_FILENAME: &str = "node_identity.key";

/// Subdirectory under the root dir that contains per-node data directories.
pub const NODES_SUBDIR: &str = "nodes";

/// Upgrade channel for auto-updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpgradeChannel {
    /// Stable releases only.
    #[default]
    Stable,
    /// Beta releases (includes stable).
    Beta,
}

/// Network mode for different deployment scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    /// Production mode with full anti-Sybil protection.
    #[default]
    Production,
    /// Testnet mode with relaxed diversity requirements.
    /// Suitable for single-provider deployments (e.g., Digital Ocean).
    Testnet,
    /// Development mode with minimal restrictions.
    /// Only use for local testing.
    Development,
}

/// Testnet-specific configuration for relaxed IP diversity limits.
///
/// saorsa-core uses a simple 2-tier model: per-exact-IP and per-subnet
/// (/24 IPv4, /64 IPv6) limits.  Testnet defaults are permissive so
/// nodes co-located on a single provider (e.g. Digital Ocean) can join.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestnetConfig {
    /// Maximum nodes sharing an exact IP address.
    /// Default: `usize::MAX` (effectively unlimited for testnet).
    #[serde(default = "default_testnet_max_per_ip")]
    pub max_per_ip: Option<usize>,

    /// Maximum nodes in the same /24 (IPv4) or /64 (IPv6) subnet.
    /// Default: `usize::MAX` (effectively unlimited for testnet).
    #[serde(default = "default_testnet_max_per_subnet")]
    pub max_per_subnet: Option<usize>,
}

impl Default for TestnetConfig {
    fn default() -> Self {
        Self {
            max_per_ip: default_testnet_max_per_ip(),
            max_per_subnet: default_testnet_max_per_subnet(),
        }
    }
}

// These return `Option` because `serde(default = "...")` requires the function's
// return type to match the field type (`Option<usize>`).
#[allow(clippy::unnecessary_wraps)]
const fn default_testnet_max_per_ip() -> Option<usize> {
    Some(usize::MAX)
}

#[allow(clippy::unnecessary_wraps)]
const fn default_testnet_max_per_subnet() -> Option<usize> {
    Some(usize::MAX)
}

/// Node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Root directory for node data.
    #[serde(default = "default_root_dir")]
    pub root_dir: PathBuf,

    /// Listening port (0 for auto-select).
    #[serde(default)]
    pub port: u16,

    /// Force IPv4-only mode.
    ///
    /// When true, the node binds only on IPv4 instead of dual-stack.
    /// Use this on hosts without working IPv6 to avoid advertising
    /// unreachable addresses to the DHT.
    #[serde(default)]
    pub ipv4_only: bool,

    /// Bootstrap peer addresses.
    #[serde(default)]
    pub bootstrap: Vec<SocketAddr>,

    /// Network mode (production, testnet, or development).
    #[serde(default)]
    pub network_mode: NetworkMode,

    /// Testnet-specific configuration.
    /// Only used when `network_mode` is `Testnet`.
    #[serde(default)]
    pub testnet: TestnetConfig,

    /// Upgrade configuration.
    #[serde(default)]
    pub upgrade: UpgradeConfig,

    /// Payment verification configuration.
    #[serde(default)]
    pub payment: PaymentConfig,

    /// Storage configuration for chunk persistence.
    #[serde(default)]
    pub storage: StorageConfig,

    /// Directory for persisting the close group cache.
    ///
    /// When `None` (default), the node's `root_dir` is used — the cache
    /// file lands alongside `node_identity.key`.
    #[serde(default)]
    pub close_group_cache_dir: Option<PathBuf>,

    /// Maximum application-layer message size in bytes.
    ///
    /// Tunes the QUIC stream receive window and per-stream read buffer.
    /// Default: the larger of
    /// [`MAX_WIRE_MESSAGE_SIZE`](crate::ant_protocol::MAX_WIRE_MESSAGE_SIZE) (5 MiB)
    /// and [`MAX_REPLICATION_MESSAGE_SIZE`](crate::replication::config::MAX_REPLICATION_MESSAGE_SIZE)
    /// (10 MiB), so both chunk and replication traffic fit within the transport
    /// ceiling.
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,

    /// Log level.
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

/// Auto-upgrade configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeConfig {
    /// Release channel.
    #[serde(default)]
    pub channel: UpgradeChannel,

    /// Check interval in hours.
    #[serde(default = "default_check_interval")]
    pub check_interval_hours: u64,

    /// GitHub repository in "owner/repo" format for release monitoring.
    #[serde(default = "default_github_repo")]
    pub github_repo: String,

    /// Staged rollout window in hours.
    ///
    /// When a new version is detected, each node waits a deterministic delay
    /// based on its node ID before applying the upgrade. This prevents mass
    /// restarts and ensures network stability during upgrades.
    ///
    /// Set to 0 to disable staged rollout (apply upgrades immediately).
    #[serde(default = "default_staged_rollout_hours")]
    pub staged_rollout_hours: u64,

    /// Exit cleanly on upgrade instead of spawning a new process.
    ///
    /// When true, the node exits after applying an upgrade and relies on
    /// an external service manager (systemd, launchd, Windows Service) to
    /// restart it. When false (default), the node spawns the new binary
    /// as a child process before exiting.
    #[serde(default)]
    pub stop_on_upgrade: bool,
}

/// EVM network for payment processing.
///
/// `Custom` is used by the local-Anvil testnet flow in
/// `deploy/testnet-v2/`: when an operator stands up a private Anvil
/// instance with the ANT token + payment vault contracts deployed,
/// every node points at the Anvil RPC and the deployed addresses
/// instead of one of the public Arbitrum networks.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum EvmNetworkConfig {
    /// Arbitrum One mainnet.
    #[default]
    ArbitrumOne,
    /// Arbitrum Sepolia testnet.
    ArbitrumSepolia,
    /// Local / private EVM (e.g. Anvil) with operator-supplied
    /// contract addresses.
    Custom {
        /// HTTP RPC URL of the EVM node (e.g. `http://1.2.3.4:8545`).
        rpc_url: String,
        /// Deployed ANT token (ERC-20) contract address.
        payment_token_address: String,
        /// Deployed payment vault contract address.
        payment_vault_address: String,
    },
}

impl EvmNetworkConfig {
    /// Resolve this config into the concrete `evmlib` network used by
    /// the payment verifier and the rewards wallet.
    #[must_use]
    pub fn into_evm_network(self) -> EvmNetwork {
        match self {
            Self::ArbitrumOne => EvmNetwork::ArbitrumOne,
            Self::ArbitrumSepolia => EvmNetwork::ArbitrumSepoliaTest,
            Self::Custom {
                rpc_url,
                payment_token_address,
                payment_vault_address,
            } => EvmNetwork::new_custom(&rpc_url, &payment_token_address, &payment_vault_address),
        }
    }
}

/// Payment verification configuration.
///
/// All new data requires EVM payment on Arbitrum — there is no way to
/// disable payment verification. The cache stores previously verified
/// payments to avoid redundant on-chain lookups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentConfig {
    /// Cache capacity for verified `XorNames`.
    #[serde(default = "default_cache_capacity")]
    pub cache_capacity: usize,

    /// EVM wallet address for receiving payments (e.g., "0x...").
    /// If not set, the node will not be able to receive payments.
    #[serde(default)]
    pub rewards_address: Option<String>,

    /// EVM network for payment processing.
    #[serde(default)]
    pub evm_network: EvmNetworkConfig,

    /// Metrics port for Prometheus scraping.
    /// Set to 0 to disable metrics endpoint.
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
}

impl Default for PaymentConfig {
    fn default() -> Self {
        Self {
            cache_capacity: default_cache_capacity(),
            rewards_address: None,
            evm_network: EvmNetworkConfig::default(),
            metrics_port: default_metrics_port(),
        }
    }
}

const fn default_metrics_port() -> u16 {
    9100
}

const fn default_cache_capacity() -> usize {
    100_000
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            root_dir: default_root_dir(),
            port: 0,
            ipv4_only: false,
            bootstrap: Vec::new(),
            network_mode: NetworkMode::default(),
            testnet: TestnetConfig::default(),
            upgrade: UpgradeConfig::default(),
            payment: PaymentConfig::default(),
            storage: StorageConfig::default(),
            close_group_cache_dir: None,
            max_message_size: default_max_message_size(),
            log_level: default_log_level(),
        }
    }
}

impl NodeConfig {
    /// Create a testnet configuration preset.
    ///
    /// This is a convenience method for setting up a testnet node with
    /// relaxed anti-Sybil protection, suitable for single-provider deployments.
    /// Includes default bootstrap nodes for the Autonomi testnet.
    #[must_use]
    pub fn testnet() -> Self {
        Self {
            network_mode: NetworkMode::Testnet,
            testnet: TestnetConfig::default(),
            bootstrap: default_testnet_bootstrap(),
            ..Self::default()
        }
    }

    /// Create a development configuration preset.
    ///
    /// This has minimal restrictions and is only suitable for local testing.
    #[must_use]
    pub fn development() -> Self {
        Self {
            network_mode: NetworkMode::Development,
            testnet: TestnetConfig {
                max_per_ip: Some(usize::MAX),
                max_per_subnet: Some(usize::MAX),
            },
            ..Self::default()
        }
    }

    /// Check if this configuration is using relaxed security settings.
    #[must_use]
    pub fn is_relaxed(&self) -> bool {
        !matches!(self.network_mode, NetworkMode::Production)
    }

    /// Load configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn from_file(path: &std::path::Path) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        toml::from_str(&content).map_err(|e| crate::Error::Config(e.to_string()))
    }

    /// Save configuration to a TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn to_file(&self, path: &std::path::Path) -> crate::Result<()> {
        let content =
            toml::to_string_pretty(self).map_err(|e| crate::Error::Config(e.to_string()))?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

impl Default for UpgradeConfig {
    fn default() -> Self {
        Self {
            channel: UpgradeChannel::default(),
            check_interval_hours: default_check_interval(),
            github_repo: default_github_repo(),
            staged_rollout_hours: default_staged_rollout_hours(),
            stop_on_upgrade: false,
        }
    }
}

fn default_github_repo() -> String {
    "WithAutonomi/ant-node".to_string()
}

/// Default base directory for node data (platform data dir for "ant").
#[must_use]
pub fn default_root_dir() -> PathBuf {
    directories::ProjectDirs::from("", "", "ant").map_or_else(
        || PathBuf::from(".ant"),
        |dirs| dirs.data_dir().to_path_buf(),
    )
}

/// Default directory containing per-node data subdirectories.
///
/// Each node gets `{default_root_dir}/nodes/{peer_id}/` where `peer_id` is the
/// full 64-character hex-encoded node ID.
#[must_use]
pub fn default_nodes_dir() -> PathBuf {
    default_root_dir().join(NODES_SUBDIR)
}

fn default_max_message_size() -> usize {
    // Use the larger of the chunk protocol and replication protocol ceilings
    // so that replication hint batches (up to 10 MiB) are not silently dropped
    // by the transport layer.
    crate::replication::config::MAX_REPLICATION_MESSAGE_SIZE
        .max(crate::ant_protocol::MAX_WIRE_MESSAGE_SIZE)
}

fn default_log_level() -> String {
    "info".to_string()
}

const fn default_check_interval() -> u64 {
    1 // 1 hour
}

const fn default_staged_rollout_hours() -> u64 {
    24 // 24 hour window for staged rollout
}

// ============================================================================
// Storage Configuration
// ============================================================================

/// Storage configuration for chunk persistence.
///
/// Controls how chunks are stored, including:
/// - Whether storage is enabled
/// - Content verification on read
/// - How much free disk to leave unused
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Enable chunk storage.
    /// Default: true
    #[serde(default = "default_storage_enabled")]
    pub enabled: bool,

    /// Verify content hash matches address on read.
    /// Default: true
    #[serde(default = "default_storage_verify_on_read")]
    pub verify_on_read: bool,

    /// Minimum free disk space (in MiB) to preserve on the storage partition.
    ///
    /// Writes are refused when available space drops below this threshold,
    /// preventing the node from filling the disk completely.  Default: 500 MiB.
    #[serde(default = "default_disk_reserve_mb")]
    pub disk_reserve_mb: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            enabled: default_storage_enabled(),
            verify_on_read: default_storage_verify_on_read(),
            disk_reserve_mb: default_disk_reserve_mb(),
        }
    }
}

/// Default: 500 MiB — matches `DEFAULT_DISK_RESERVE` in `storage`.
const fn default_disk_reserve_mb() -> u64 {
    500
}

const fn default_storage_enabled() -> bool {
    true
}

const fn default_storage_verify_on_read() -> bool {
    true
}

// ============================================================================
// Bootstrap Peers Configuration (shipped config file)
// ============================================================================

/// The filename for the bootstrap peers configuration file.
pub const BOOTSTRAP_PEERS_FILENAME: &str = "bootstrap_peers.toml";

/// Environment variable that overrides the bootstrap peers file search path.
pub const BOOTSTRAP_PEERS_ENV: &str = "ANT_BOOTSTRAP_PEERS_PATH";

/// Bootstrap peers loaded from a shipped configuration file.
///
/// This file provides initial peers for first-time network joins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapPeersConfig {
    /// The bootstrap peer socket addresses.
    #[serde(default)]
    pub peers: Vec<SocketAddr>,
}

/// The source from which bootstrap peers were resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapSource {
    /// Provided via `--bootstrap` CLI argument or `ANT_BOOTSTRAP` env var.
    Cli,
    /// Loaded from an explicit `--config` file.
    ConfigFile,
    /// Auto-discovered from a `bootstrap_peers.toml` file.
    AutoDiscovered(PathBuf),
    /// No bootstrap peers were found from any source.
    None,
}

impl BootstrapPeersConfig {
    /// Load bootstrap peers from a TOML file at the given path.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or contains invalid TOML.
    pub fn from_file(path: &Path) -> crate::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        toml::from_str(&content).map_err(|e| crate::Error::Config(e.to_string()))
    }

    /// Search well-known locations for a `bootstrap_peers.toml` file and load it.
    ///
    /// Search order (first match wins):
    /// 1. `$ANT_BOOTSTRAP_PEERS_PATH` environment variable (path to file)
    /// 2. Same directory as the running executable
    /// 3. Platform config directory (`~/.config/ant/` on Linux,
    ///    `~/Library/Application Support/ant/` on macOS,
    ///    `%APPDATA%\ant\` on Windows)
    /// 4. System config: `/etc/ant/` (Unix only)
    ///
    /// Returns `None` if no file is found in any location.
    #[must_use]
    pub fn discover() -> Option<(Self, PathBuf)> {
        if let Ok(env_path) = std::env::var(BOOTSTRAP_PEERS_ENV) {
            return Self::load_non_empty_candidate(PathBuf::from(env_path));
        }

        for path in Self::search_paths() {
            if let Some(discovered) = Self::load_non_empty_candidate(path) {
                return Some(discovered);
            }
        }

        None
    }

    fn load_non_empty_candidate(path: PathBuf) -> Option<(Self, PathBuf)> {
        if !path.is_file() {
            return None;
        }

        match Self::from_file(&path) {
            Ok(config) if !config.peers.is_empty() => Some((config, path)),
            Ok(_) => None,
            Err(err) => {
                crate::logging::warn!(
                    "Failed to load bootstrap peers from {}: {err}",
                    path.display(),
                );
                None
            }
        }
    }

    /// Build the ordered list of candidate paths to search.
    fn search_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // 1. Environment variable override.
        if let Ok(env_path) = std::env::var(BOOTSTRAP_PEERS_ENV) {
            paths.push(PathBuf::from(env_path));
        }

        // 2. Next to the running executable.
        if let Ok(exe) = std::env::current_exe() {
            if let Some(exe_dir) = exe.parent() {
                paths.push(exe_dir.join(BOOTSTRAP_PEERS_FILENAME));
            }
        }

        // 3. Platform config directory.
        if let Some(proj_dirs) = directories::ProjectDirs::from("", "", "ant") {
            paths.push(proj_dirs.config_dir().join(BOOTSTRAP_PEERS_FILENAME));
        }

        // 4. System config (Unix only).
        #[cfg(unix)]
        {
            paths.push(PathBuf::from("/etc/ant").join(BOOTSTRAP_PEERS_FILENAME));
        }

        paths
    }
}

/// Default testnet bootstrap nodes.
///
/// These are well-known bootstrap nodes for the Autonomi testnet.
/// - ant-bootstrap-1 (NYC): 165.22.4.178:12000
/// - ant-bootstrap-2 (SFO): 164.92.111.156:12000
fn default_testnet_bootstrap() -> Vec<SocketAddr> {
    vec![
        // ant-bootstrap-1 (Digital Ocean NYC1)
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(165, 22, 4, 178), 12000)),
        // ant-bootstrap-2 (Digital Ocean SFO3)
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(164, 92, 111, 156), 12000)),
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    /// A config file written by the previous release still loads.
    ///
    /// The settings that drove the migration off the old chunk store are gone from this
    /// build, and so is the database size cap, which configured a memory map that no longer
    /// exists. Every node on the fleet has a config file on disk carrying them, written by
    /// the release that did the migrating. If those keys made the file unparseable, every
    /// one of those nodes would fail to start on upgrade, all at once.
    ///
    /// Nothing declares `deny_unknown_fields`, so serde ignores them. That is the behaviour
    /// this depends on, which makes it worth a test rather than an assumption: adding that
    /// attribute later would look harmless and would take down the fleet.
    #[test]
    fn a_config_file_from_the_previous_release_still_loads() {
        let previous = r#"
[network]
port = 10000

[storage]
enabled = true
verify_on_read = true
db_size_gb = 32
disk_reserve_mb = 500

[storage.migration]
shed_hold_hours = 72
wave_hours = 24
copier_throttle_mib_per_sec = 32
copier_slack_mb = 2048
retire_delay_hours = 4

[payment]
rewards_address = "0x0000000000000000000000000000000000000001"
"#;
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, previous).expect("write the previous release's config");

        // Through the loader a node actually uses, not a hand-picked table. The whole file
        // has to parse, because that is what a node does with it on start.
        let parsed = NodeConfig::from_file(&path)
            .expect("a config file from the previous release must still load");

        assert!(parsed.storage.enabled);
        assert!(parsed.storage.verify_on_read);
        assert_eq!(
            parsed.storage.disk_reserve_mb, 500,
            "the settings this build still uses must survive the ones it dropped"
        );
    }

    use super::*;
    use serial_test::serial;

    #[test]
    fn test_default_config_has_cache_capacity() {
        let config = PaymentConfig::default();
        assert!(config.cache_capacity > 0, "Cache capacity must be positive");
    }

    #[test]
    fn test_default_evm_network() {
        use crate::payment::EvmVerifierConfig;
        let _config = EvmVerifierConfig::default();
        // EVM verification is always on — no enabled field
    }

    #[test]
    fn test_bootstrap_peers_parse_valid_toml() {
        let toml_str = r#"
            peers = [
                "127.0.0.1:10000",
                "192.168.1.1:10001",
            ]
        "#;
        let config: BootstrapPeersConfig =
            toml::from_str(toml_str).expect("valid TOML should parse");
        assert_eq!(config.peers.len(), 2);
        assert_eq!(config.peers[0].port(), 10000);
        assert_eq!(config.peers[1].port(), 10001);
    }

    #[test]
    fn test_bootstrap_peers_parse_empty_peers() {
        let toml_str = r"peers = []";
        let config: BootstrapPeersConfig =
            toml::from_str(toml_str).expect("empty peers should parse");
        assert!(config.peers.is_empty());
    }

    #[test]
    fn test_bootstrap_peers_parse_missing_peers_field() {
        let toml_str = "";
        let config: BootstrapPeersConfig =
            toml::from_str(toml_str).expect("missing field should use default");
        assert!(config.peers.is_empty());
    }

    #[test]
    fn test_bootstrap_peers_from_file() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("bootstrap_peers.toml");
        std::fs::write(&path, r#"peers = ["10.0.0.1:10000", "10.0.0.2:10000"]"#)
            .expect("write file");

        let config = BootstrapPeersConfig::from_file(&path).expect("load from file");
        assert_eq!(config.peers.len(), 2);
    }

    #[test]
    fn test_bootstrap_peers_from_file_invalid_toml() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("bootstrap_peers.toml");
        std::fs::write(&path, "not valid toml [[[").expect("write file");

        assert!(BootstrapPeersConfig::from_file(&path).is_err());
    }

    /// Env-var-based discovery tests must run serially because they mutate
    /// a shared process-wide environment variable.
    #[test]
    #[serial]
    fn test_bootstrap_peers_discover_env_var() {
        // Sub-test 1: valid file with peers is discovered.
        {
            let dir = tempfile::tempdir().expect("create temp dir");
            let path = dir.path().join("bootstrap_peers.toml");
            std::fs::write(&path, r#"peers = ["10.0.0.1:10000"]"#).expect("write file");

            std::env::set_var(BOOTSTRAP_PEERS_ENV, &path);
            let result = BootstrapPeersConfig::discover();
            std::env::remove_var(BOOTSTRAP_PEERS_ENV);

            let (config, discovered_path) = result.expect("should discover from env var");
            assert_eq!(config.peers.len(), 1);
            assert_eq!(discovered_path, path);
        }

        // Sub-test 2: file with empty peers list is skipped.
        {
            let dir = tempfile::tempdir().expect("create temp dir");
            let path = dir.path().join("bootstrap_peers.toml");
            std::fs::write(&path, r"peers = []").expect("write file");

            std::env::set_var(BOOTSTRAP_PEERS_ENV, &path);
            let result = BootstrapPeersConfig::discover();
            std::env::remove_var(BOOTSTRAP_PEERS_ENV);

            assert!(result.is_none(), "empty peers file should be skipped");
        }
    }

    #[test]
    fn test_bootstrap_peers_search_paths_contains_exe_dir() {
        let paths = BootstrapPeersConfig::search_paths();
        // At minimum, the exe-dir candidate should be present.
        assert!(
            paths
                .iter()
                .any(|p| p.file_name().is_some_and(|f| f == BOOTSTRAP_PEERS_FILENAME)),
            "search paths should include a candidate with the bootstrap peers filename"
        );
    }
}
