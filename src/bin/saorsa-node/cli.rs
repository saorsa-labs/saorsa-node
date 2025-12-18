//! Command-line interface definition.

use clap::{Parser, ValueEnum};
use saorsa_node::config::{
    BootstrapCacheConfig, EvmNetworkConfig, IpVersion, NetworkMode, NodeConfig, PaymentConfig,
    UpgradeChannel, UpgradeConfig,
};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Pure quantum-proof network node for the Saorsa decentralized network.
#[derive(Parser, Debug)]
#[command(name = "saorsa-node")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Root directory for node data.
    #[arg(long, env = "SAORSA_ROOT_DIR")]
    pub root_dir: Option<PathBuf>,

    /// Listening port (0 for auto-select).
    #[arg(long, short, default_value = "0", env = "SAORSA_PORT")]
    pub port: u16,

    /// IP version to use.
    #[arg(long, value_enum, default_value = "dual", env = "SAORSA_IP_VERSION")]
    pub ip_version: CliIpVersion,

    /// Bootstrap peer addresses.
    #[arg(long, short, env = "SAORSA_BOOTSTRAP")]
    pub bootstrap: Vec<SocketAddr>,

    /// Enable automatic upgrades.
    #[arg(long, env = "SAORSA_AUTO_UPGRADE")]
    pub auto_upgrade: bool,

    /// Release channel for upgrades.
    #[arg(
        long,
        value_enum,
        default_value = "stable",
        env = "SAORSA_UPGRADE_CHANNEL"
    )]
    pub upgrade_channel: CliUpgradeChannel,

    /// Disable payment verification.
    #[arg(long)]
    pub disable_payment_verification: bool,

    /// Cache capacity for verified `XorName` values.
    #[arg(long, default_value = "100000", env = "SAORSA_CACHE_CAPACITY")]
    pub cache_capacity: usize,

    /// EVM wallet address for receiving payments (e.g., "0x...").
    #[arg(long, env = "SAORSA_REWARDS_ADDRESS")]
    pub rewards_address: Option<String>,

    /// EVM network for payment processing.
    #[arg(
        long,
        value_enum,
        default_value = "arbitrum-one",
        env = "SAORSA_EVM_NETWORK"
    )]
    pub evm_network: CliEvmNetwork,

    /// Metrics port for Prometheus scraping (0 to disable).
    #[arg(long, default_value = "9100", env = "SAORSA_METRICS_PORT")]
    pub metrics_port: u16,

    /// Log level.
    #[arg(long, value_enum, default_value = "info", env = "RUST_LOG")]
    pub log_level: CliLogLevel,

    /// Network mode (production, testnet, or development).
    /// Testnet mode uses relaxed IP diversity limits suitable for
    /// single-provider deployments with many nodes per IP.
    #[arg(long, value_enum, default_value = "production", env = "SAORSA_NETWORK_MODE")]
    pub network_mode: CliNetworkMode,

    /// Path to configuration file.
    #[arg(long, short)]
    pub config: Option<PathBuf>,

    /// Disable persistent bootstrap cache.
    #[arg(long)]
    pub disable_bootstrap_cache: bool,

    /// Directory for bootstrap cache files.
    #[arg(long, env = "SAORSA_BOOTSTRAP_CACHE_DIR")]
    pub bootstrap_cache_dir: Option<PathBuf>,

    /// Maximum peers to cache in the bootstrap cache.
    #[arg(long, default_value = "10000", env = "SAORSA_BOOTSTRAP_CACHE_CAPACITY")]
    pub bootstrap_cache_capacity: usize,
}

/// IP version CLI enum.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliIpVersion {
    /// IPv4 only.
    Ipv4,
    /// IPv6 only.
    Ipv6,
    /// Dual-stack (both IPv4 and IPv6).
    Dual,
}

/// Upgrade channel CLI enum.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliUpgradeChannel {
    /// Stable releases only.
    Stable,
    /// Beta releases.
    Beta,
}

/// EVM network CLI enum.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum CliEvmNetwork {
    /// Arbitrum One mainnet.
    #[default]
    #[value(name = "arbitrum-one")]
    ArbitrumOne,
    /// Arbitrum Sepolia testnet.
    #[value(name = "arbitrum-sepolia")]
    ArbitrumSepolia,
}

/// Log level CLI enum.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum CliLogLevel {
    /// Error messages only.
    Error,
    /// Warnings and errors.
    Warn,
    /// Informational messages (default).
    #[default]
    Info,
    /// Debug messages.
    Debug,
    /// Trace messages (verbose).
    Trace,
}

/// Network mode CLI enum.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum CliNetworkMode {
    /// Production mode with full anti-Sybil protection.
    #[default]
    Production,
    /// Testnet mode with relaxed diversity requirements.
    /// Allows many nodes per IP/ASN for single-provider deployments.
    Testnet,
    /// Development mode with minimal restrictions.
    /// Only use for local testing.
    Development,
}

impl Cli {
    /// Convert CLI arguments into a `NodeConfig`.
    ///
    /// # Errors
    ///
    /// Returns an error if a config file is specified but cannot be loaded.
    pub fn into_config(self) -> color_eyre::Result<NodeConfig> {
        // Start with default config or load from file
        let mut config = if let Some(ref path) = self.config {
            NodeConfig::from_file(path)?
        } else {
            NodeConfig::default()
        };

        // Override with CLI arguments
        if let Some(root_dir) = self.root_dir {
            config.root_dir = root_dir;
        }

        config.port = self.port;
        config.ip_version = self.ip_version.into();
        config.bootstrap = self.bootstrap;
        config.log_level = self.log_level.into();
        config.network_mode = self.network_mode.into();

        // Upgrade config
        config.upgrade = UpgradeConfig {
            enabled: self.auto_upgrade,
            channel: self.upgrade_channel.into(),
            ..config.upgrade
        };

        // Payment config
        config.payment = PaymentConfig {
            enabled: !self.disable_payment_verification,
            cache_capacity: self.cache_capacity,
            rewards_address: self.rewards_address,
            evm_network: self.evm_network.into(),
            metrics_port: self.metrics_port,
        };

        // Bootstrap cache config
        config.bootstrap_cache = BootstrapCacheConfig {
            enabled: !self.disable_bootstrap_cache,
            cache_dir: self.bootstrap_cache_dir,
            max_contacts: self.bootstrap_cache_capacity,
            ..config.bootstrap_cache
        };

        Ok(config)
    }
}

impl From<CliIpVersion> for IpVersion {
    fn from(v: CliIpVersion) -> Self {
        match v {
            CliIpVersion::Ipv4 => Self::Ipv4,
            CliIpVersion::Ipv6 => Self::Ipv6,
            CliIpVersion::Dual => Self::Dual,
        }
    }
}

impl From<CliUpgradeChannel> for UpgradeChannel {
    fn from(c: CliUpgradeChannel) -> Self {
        match c {
            CliUpgradeChannel::Stable => Self::Stable,
            CliUpgradeChannel::Beta => Self::Beta,
        }
    }
}

impl From<CliEvmNetwork> for EvmNetworkConfig {
    fn from(n: CliEvmNetwork) -> Self {
        match n {
            CliEvmNetwork::ArbitrumOne => Self::ArbitrumOne,
            CliEvmNetwork::ArbitrumSepolia => Self::ArbitrumSepolia,
        }
    }
}

impl From<CliLogLevel> for String {
    fn from(level: CliLogLevel) -> Self {
        match level {
            CliLogLevel::Error => "error".to_string(),
            CliLogLevel::Warn => "warn".to_string(),
            CliLogLevel::Info => "info".to_string(),
            CliLogLevel::Debug => "debug".to_string(),
            CliLogLevel::Trace => "trace".to_string(),
        }
    }
}

impl From<CliNetworkMode> for NetworkMode {
    fn from(mode: CliNetworkMode) -> Self {
        match mode {
            CliNetworkMode::Production => Self::Production,
            CliNetworkMode::Testnet => Self::Testnet,
            CliNetworkMode::Development => Self::Development,
        }
    }
}
