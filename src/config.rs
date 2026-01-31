//! Configuration for saorsa-node.

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
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

    /// Payment verification configuration.
    #[serde(default)]
    pub payment: PaymentConfig,

    /// Attestation configuration for software integrity verification.
    #[serde(default)]
    pub attestation: AttestationNodeConfig,

    /// Bootstrap cache configuration for persistent peer storage.
    #[serde(default)]
    pub bootstrap_cache: BootstrapCacheConfig,

    /// Storage configuration for chunk persistence.
    #[serde(default)]
    pub storage: StorageConfig,

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
///
/// All new data requires EVM payment on Arbitrum. The cache stores
/// previously verified payments to avoid redundant lookups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentConfig {
    /// Enable payment verification.
    #[serde(default = "default_payment_enabled")]
    pub enabled: bool,

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
            enabled: default_payment_enabled(),
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

// ============================================================================
// Attestation Configuration
// ============================================================================

/// Attestation enforcement mode.
///
/// Controls how the node responds to attestation verification failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationMode {
    /// Attestation is completely disabled (default).
    /// No verification is performed.
    #[default]
    Off,
    /// Soft enforcement: log warnings but don't reject connections.
    /// Useful for testing and gradual rollout.
    Soft,
    /// Hard enforcement: reject peers with invalid attestations.
    /// Requires `zkvm-prover` or `zkvm-verifier-groth16` feature for security.
    Hard,
}

/// Attestation configuration for software integrity verification.
///
/// # Security Warning
///
/// **Without the `zkvm-prover` feature enabled, attestation proofs are accepted
/// without cryptographic verification (mock prover).** This provides **NO SECURITY**.
///
/// For production deployments:
/// - Enable `zkvm-prover` feature for post-quantum secure STARK verification
/// - Or enable `zkvm-verifier-groth16` for Groth16 verification (NOT post-quantum secure)
///
/// The node will **block startup** if attestation is enabled without a verification feature.
///
/// # Example Configuration
///
/// ```toml
/// [attestation]
/// enabled = true
/// mode = "hard"
/// require_pq_secure = true
/// allowed_binary_hashes = ["a1b2c3..."]
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationNodeConfig {
    /// Enable attestation verification.
    /// Default: false (disabled for backward compatibility)
    #[serde(default)]
    pub enabled: bool,

    /// Enforcement mode for attestation verification.
    /// Default: off
    #[serde(default)]
    pub mode: AttestationMode,

    /// Require post-quantum secure verification.
    /// If true, only STARK proofs (via `zkvm-prover`) are accepted.
    /// If false, Groth16 proofs are also accepted.
    /// Default: true
    #[serde(default = "default_require_pq_secure")]
    pub require_pq_secure: bool,

    /// Allowed binary hashes (hex-encoded, 64 characters each).
    /// Empty list = permissive mode (all binaries allowed).
    /// In production, set specific hashes of authorized binaries.
    #[serde(default)]
    pub allowed_binary_hashes: Vec<String>,

    /// Grace period in days after sunset before hard rejection.
    /// During the grace period, nodes can still connect but with warnings.
    /// Default: 30
    #[serde(default = "default_sunset_grace_days")]
    pub sunset_grace_days: u32,
}

impl Default for AttestationNodeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: AttestationMode::Off,
            require_pq_secure: default_require_pq_secure(),
            allowed_binary_hashes: Vec::new(),
            sunset_grace_days: default_sunset_grace_days(),
        }
    }
}

impl AttestationNodeConfig {
    /// Development configuration: soft enforcement, all binaries allowed.
    #[must_use]
    pub fn development() -> Self {
        Self {
            enabled: true,
            mode: AttestationMode::Soft,
            require_pq_secure: false,
            allowed_binary_hashes: Vec::new(),
            sunset_grace_days: 365,
        }
    }

    /// Production configuration: hard enforcement with specific allowed binaries.
    #[must_use]
    pub fn production(allowed_binary_hashes: Vec<String>) -> Self {
        Self {
            enabled: true,
            mode: AttestationMode::Hard,
            require_pq_secure: true,
            allowed_binary_hashes,
            sunset_grace_days: 30,
        }
    }
}

const fn default_require_pq_secure() -> bool {
    true
}

const fn default_sunset_grace_days() -> u32 {
    30
}

const fn default_payment_enabled() -> bool {
    true
}

const fn default_cache_capacity() -> usize {
    100_000
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
            payment: PaymentConfig::default(),
            attestation: AttestationNodeConfig::default(),
            bootstrap_cache: BootstrapCacheConfig::default(),
            storage: StorageConfig::default(),
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
    1 // 1 hour window for staged rollout (testing)
}

// ============================================================================
// Bootstrap Cache Configuration
// ============================================================================

/// Bootstrap cache configuration for persistent peer storage.
///
/// The bootstrap cache stores discovered peers across node restarts,
/// ranking them by quality metrics (success rate, latency, recency).
/// This reduces dependency on hardcoded bootstrap nodes and enables
/// faster network reconnection after restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapCacheConfig {
    /// Enable persistent bootstrap cache.
    /// Default: true
    #[serde(default = "default_bootstrap_cache_enabled")]
    pub enabled: bool,

    /// Directory for cache files.
    /// Default: `{root_dir}/bootstrap_cache/`
    #[serde(default)]
    pub cache_dir: Option<PathBuf>,

    /// Maximum contacts to store in the cache.
    /// Default: 10,000
    #[serde(default = "default_bootstrap_max_contacts")]
    pub max_contacts: usize,

    /// Stale contact threshold in days.
    /// Contacts older than this are removed during cleanup.
    /// Default: 7 days
    #[serde(default = "default_bootstrap_stale_days")]
    pub stale_threshold_days: u64,
}

impl Default for BootstrapCacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_bootstrap_cache_enabled(),
            cache_dir: None,
            max_contacts: default_bootstrap_max_contacts(),
            stale_threshold_days: default_bootstrap_stale_days(),
        }
    }
}

const fn default_bootstrap_cache_enabled() -> bool {
    true
}

const fn default_bootstrap_max_contacts() -> usize {
    10_000
}

const fn default_bootstrap_stale_days() -> u64 {
    7
}

// ============================================================================
// Storage Configuration
// ============================================================================

/// Storage configuration for chunk persistence.
///
/// Controls how chunks are stored on disk, including:
/// - Whether storage is enabled
/// - Maximum chunks to store (for capacity management)
/// - Content verification on read
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Enable chunk storage.
    /// Default: true
    #[serde(default = "default_storage_enabled")]
    pub enabled: bool,

    /// Maximum number of chunks to store (0 = unlimited).
    /// Default: 0 (unlimited)
    #[serde(default)]
    pub max_chunks: usize,

    /// Verify content hash matches address on read.
    /// Default: true
    #[serde(default = "default_storage_verify_on_read")]
    pub verify_on_read: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            enabled: default_storage_enabled(),
            max_chunks: 0,
            verify_on_read: default_storage_verify_on_read(),
        }
    }
}

const fn default_storage_enabled() -> bool {
    true
}

const fn default_storage_verify_on_read() -> bool {
    true
}

/// Default testnet bootstrap nodes.
///
/// These are well-known bootstrap nodes for the Saorsa testnet.
/// - saorsa-bootstrap-1 (NYC): 165.22.4.178:12000
/// - saorsa-bootstrap-2 (SFO): 164.92.111.156:12000
fn default_testnet_bootstrap() -> Vec<SocketAddr> {
    vec![
        // saorsa-bootstrap-1 (Digital Ocean NYC1)
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(165, 22, 4, 178), 12000)),
        // saorsa-bootstrap-2 (Digital Ocean SFO3)
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(164, 92, 111, 156), 12000)),
    ]
}
