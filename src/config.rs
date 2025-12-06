//! Configuration for saorsa-node.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// IP version configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpVersion {
    /// IPv4 only.
    Ipv4,
    /// IPv6 only.
    Ipv6,
    /// Dual-stack (both IPv4 and IPv6).
    #[default]
    Dual,
}

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

/// Testnet-specific configuration for relaxed anti-Sybil protection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestnetConfig {
    /// Maximum nodes allowed per ASN.
    /// Default: 5000 (compared to 20 in production).
    #[serde(default = "default_testnet_max_per_asn")]
    pub max_nodes_per_asn: usize,

    /// Maximum nodes allowed per /64 subnet.
    /// Default: 100 (compared to 1 in production).
    #[serde(default = "default_testnet_max_per_64")]
    pub max_nodes_per_64: usize,

    /// Whether to enforce node age requirements.
    /// Default: false (compared to true in production).
    #[serde(default)]
    pub enforce_age_requirements: bool,

    /// Enable geographic diversity checks.
    /// Default: false (compared to true in production).
    #[serde(default)]
    pub enable_geo_checks: bool,
}

impl Default for TestnetConfig {
    fn default() -> Self {
        Self {
            max_nodes_per_asn: default_testnet_max_per_asn(),
            max_nodes_per_64: default_testnet_max_per_64(),
            enforce_age_requirements: false,
            enable_geo_checks: false,
        }
    }
}

const fn default_testnet_max_per_asn() -> usize {
    5000
}

const fn default_testnet_max_per_64() -> usize {
    100
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

    /// IP version to use.
    #[serde(default)]
    pub ip_version: IpVersion,

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

    /// Migration configuration.
    #[serde(default)]
    pub migration: MigrationConfig,

    /// Payment verification configuration.
    #[serde(default)]
    pub payment: PaymentConfig,

    /// Log level.
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

/// Auto-upgrade configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeConfig {
    /// Enable automatic upgrades.
    #[serde(default)]
    pub enabled: bool,

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
}

/// Migration configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MigrationConfig {
    /// Auto-detect ant-node data directories.
    #[serde(default)]
    pub auto_detect: bool,

    /// Explicit path to ant-node data.
    #[serde(default)]
    pub ant_data_path: Option<PathBuf>,
}

/// EVM network for payment processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvmNetworkConfig {
    /// Arbitrum One mainnet.
    #[default]
    ArbitrumOne,
    /// Arbitrum Sepolia testnet.
    ArbitrumSepolia,
}

/// Payment verification configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentConfig {
    /// Enable autonomi network verification.
    /// When enabled, data that exists on autonomi is stored for free.
    #[serde(default = "default_payment_enabled")]
    pub enabled: bool,

    /// Bootstrap peers for connecting to the autonomi network.
    #[serde(default)]
    pub autonomi_bootstrap: Vec<String>,

    /// Cache capacity for verified `XorNames`.
    #[serde(default = "default_cache_capacity")]
    pub cache_capacity: usize,

    /// Require payment when autonomi lookup fails (fail closed).
    /// If false, allows free storage on network errors (fail open).
    #[serde(default = "default_require_payment_on_error")]
    pub require_payment_on_error: bool,

    /// Query timeout in seconds for autonomi lookups.
    #[serde(default = "default_query_timeout")]
    pub query_timeout_secs: u64,

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
            enabled: default_payment_enabled(),
            autonomi_bootstrap: Vec::new(),
            cache_capacity: default_cache_capacity(),
            require_payment_on_error: default_require_payment_on_error(),
            query_timeout_secs: default_query_timeout(),
            rewards_address: None,
            evm_network: EvmNetworkConfig::default(),
            metrics_port: default_metrics_port(),
        }
    }
}

const fn default_metrics_port() -> u16 {
    9100
}

const fn default_payment_enabled() -> bool {
    true
}

const fn default_cache_capacity() -> usize {
    100_000
}

const fn default_require_payment_on_error() -> bool {
    true
}

const fn default_query_timeout() -> u64 {
    30
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            root_dir: default_root_dir(),
            port: 0,
            ip_version: IpVersion::default(),
            bootstrap: Vec::new(),
            network_mode: NetworkMode::default(),
            testnet: TestnetConfig::default(),
            upgrade: UpgradeConfig::default(),
            migration: MigrationConfig::default(),
            payment: PaymentConfig::default(),
            log_level: default_log_level(),
        }
    }
}

impl NodeConfig {
    /// Create a testnet configuration preset.
    ///
    /// This is a convenience method for setting up a testnet node with
    /// relaxed anti-Sybil protection, suitable for single-provider deployments.
    /// Includes default bootstrap nodes for the Saorsa testnet.
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
                max_nodes_per_asn: usize::MAX,
                max_nodes_per_64: usize::MAX,
                enforce_age_requirements: false,
                enable_geo_checks: false,
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
            enabled: false,
            channel: UpgradeChannel::default(),
            check_interval_hours: default_check_interval(),
            github_repo: default_github_repo(),
            staged_rollout_hours: default_staged_rollout_hours(),
        }
    }
}

fn default_github_repo() -> String {
    "dirvine/saorsa-node".to_string()
}

fn default_root_dir() -> PathBuf {
    directories::ProjectDirs::from("", "", "saorsa").map_or_else(
        || PathBuf::from(".saorsa"),
        |dirs| dirs.data_dir().to_path_buf(),
    )
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

/// Default testnet bootstrap nodes.
///
/// These are well-known bootstrap nodes for the Saorsa testnet.
/// - saorsa-bootstrap-1 (NYC): 165.22.4.178:12000
/// - saorsa-bootstrap-2 (SFO): 164.92.111.156:12000
fn default_testnet_bootstrap() -> Vec<SocketAddr> {
    use std::net::{Ipv4Addr, SocketAddrV4};

    vec![
        // saorsa-bootstrap-1 (Digital Ocean NYC1)
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(165, 22, 4, 178), 12000)),
        // saorsa-bootstrap-2 (Digital Ocean SFO3)
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(164, 92, 111, 156), 12000)),
    ]
}
