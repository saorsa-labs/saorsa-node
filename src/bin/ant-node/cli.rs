//! Command-line interface definition.

use ant_node::config::{
    BootstrapPeersConfig, BootstrapSource, EvmNetworkConfig, NetworkMode, NodeConfig,
    PaymentConfig, UpgradeChannel,
};
use clap::{Parser, ValueEnum};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Pure quantum-proof network node for the Autonomi decentralized network.
#[derive(Parser, Debug)]
#[command(name = "ant-node")]
#[command(author, version, about, long_about = None)]
#[allow(clippy::struct_excessive_bools)] // unrelated CLI toggles, not a state machine
pub struct Cli {
    /// Root directory for node data.
    #[arg(long, env = "ANT_ROOT_DIR")]
    pub root_dir: Option<PathBuf>,

    /// Listening port (0 for auto-select).
    #[arg(long, short, default_value = "0", env = "ANT_PORT")]
    pub port: u16,

    /// Force IPv4-only mode (disable dual-stack).
    /// Use on hosts without working IPv6 to avoid advertising
    /// unreachable addresses to the DHT.
    #[arg(long, env = "ANT_IPV4_ONLY")]
    pub ipv4_only: bool,

    /// Override the default ADR-0009 WebRTC Direct UDP bind address.
    ///
    /// Port zero selects the stable automatic port derived from `--port`.
    #[arg(long, env = "ANT_WEBRTC_DIRECT_BIND")]
    pub webrtc_direct_bind: Option<SocketAddr>,

    /// Override the UDP port used by the WebRTC Direct listener.
    ///
    /// This takes precedence over the port in `--webrtc-direct-bind`. Port zero
    /// selects the automatic port derived from the native QUIC listener.
    #[arg(long, visible_alias = "webrtc-port", env = "ANT_WEBRTC_DIRECT_PORT")]
    pub webrtc_direct_port: Option<u16>,

    /// Literal public UDP address to advertise instead of the bind address.
    #[arg(
        long,
        env = "ANT_WEBRTC_DIRECT_ADVERTISED_ADDR",
        requires = "webrtc_direct_bind"
    )]
    pub webrtc_direct_advertised_addr: Option<SocketAddr>,

    /// Bootstrap peer addresses.
    #[arg(long, short, env = "ANT_BOOTSTRAP")]
    pub bootstrap: Vec<SocketAddr>,

    /// Release channel for upgrades.
    #[arg(
        long,
        value_enum,
        default_value = "stable",
        env = "ANT_UPGRADE_CHANNEL"
    )]
    pub upgrade_channel: CliUpgradeChannel,

    /// Cache capacity for verified `XorName` values.
    #[arg(long, default_value = "100000", env = "ANT_CACHE_CAPACITY")]
    pub cache_capacity: usize,

    /// EVM wallet address for receiving payments (e.g., "0x...").
    #[arg(long, env = "ANT_REWARDS_ADDRESS")]
    pub rewards_address: Option<String>,

    /// EVM network for payment processing.
    ///
    /// Ignored when `--evm-rpc-url` is set (which selects a custom EVM
    /// network instead — used by the local-Anvil testnet flow).
    #[arg(
        long,
        value_enum,
        default_value = "arbitrum-one",
        env = "ANT_EVM_NETWORK"
    )]
    pub evm_network: CliEvmNetwork,

    /// HTTP RPC URL of a custom EVM (e.g. a local Anvil instance).
    /// When set, --evm-payment-token and --evm-payment-vault must also
    /// be set, and they together override --evm-network.
    #[arg(long, env = "ANT_EVM_RPC_URL")]
    pub evm_rpc_url: Option<String>,

    /// ANT token contract address on the custom EVM.
    /// Required iff --evm-rpc-url is set.
    #[arg(long, env = "ANT_EVM_PAYMENT_TOKEN")]
    pub evm_payment_token: Option<String>,

    /// Payment vault contract address on the custom EVM.
    /// Required iff --evm-rpc-url is set.
    #[arg(long, env = "ANT_EVM_PAYMENT_VAULT")]
    pub evm_payment_vault: Option<String>,

    /// Metrics port for Prometheus scraping (0 to disable).
    #[arg(long, default_value = "9100", env = "ANT_METRICS_PORT")]
    pub metrics_port: u16,

    /// Enable logging output.
    /// When omitted, the tracing subscriber is not installed and no log
    /// records are emitted, even if the binary was built with the
    /// `logging` feature. The remaining `--log-*` options are ignored
    /// unless this flag is set.
    #[cfg(feature = "logging")]
    #[arg(long, env = "ANT_ENABLE_LOGGING")]
    pub enable_logging: bool,

    /// Log level.
    #[cfg(feature = "logging")]
    #[arg(long, value_enum, default_value = "info", env = "RUST_LOG")]
    pub log_level: CliLogLevel,

    /// Log output format.
    #[cfg(feature = "logging")]
    #[arg(long, value_enum, default_value = "text", env = "ANT_LOG_FORMAT")]
    pub log_format: CliLogFormat,

    /// Directory for log file output.
    /// When set, logs are written to files in this directory instead of stdout.
    /// Files rotate daily and are named ant-node.YYYY-MM-DD.log.
    #[cfg(feature = "logging")]
    #[arg(long, env = "ANT_LOG_DIR")]
    pub log_dir: Option<PathBuf>,

    /// Maximum number of rotated log files to retain (only used with --log-dir).
    /// Oldest files are deleted when this limit is reached. Rotation is daily.
    #[cfg(feature = "logging")]
    #[arg(long, default_value = "7", env = "ANT_LOG_MAX_FILES")]
    pub log_max_files: usize,

    /// Network mode (production, testnet, or development).
    /// Testnet mode uses relaxed IP diversity limits suitable for
    /// single-provider deployments with many nodes per IP.
    #[arg(
        long,
        value_enum,
        default_value = "production",
        env = "ANT_NETWORK_MODE"
    )]
    pub network_mode: CliNetworkMode,

    /// Path to configuration file.
    #[arg(long, short)]
    pub config: Option<PathBuf>,

    /// Exit cleanly on upgrade instead of spawning a new process.
    /// Use when running under a service manager (systemd, launchd, Windows Service)
    /// that will restart the process automatically.
    #[arg(long)]
    pub stop_on_upgrade: bool,
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
#[cfg(feature = "logging")]
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

/// Log format CLI enum.
#[cfg(feature = "logging")]
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum CliLogFormat {
    /// Plain text output (default).
    #[default]
    Text,
    /// Structured JSON output.
    Json,
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
    /// Convert CLI arguments into a `NodeConfig` and the source of bootstrap peers.
    ///
    /// # Bootstrap peer precedence (highest to lowest)
    ///
    /// 1. `--bootstrap` CLI argument (or `ANT_BOOTSTRAP` env var)
    /// 2. `bootstrap` field in a `--config` file
    /// 3. Auto-discovered `bootstrap_peers.toml` from well-known paths
    /// 4. Empty list
    ///
    /// # Errors
    ///
    /// Returns an error if a config file is specified but cannot be loaded.
    pub fn into_config(self) -> color_eyre::Result<(NodeConfig, BootstrapSource)> {
        // Start with default config or load from file
        let has_config_file = self.config.is_some();
        let mut config = if let Some(ref path) = self.config {
            NodeConfig::from_file(path)?
        } else {
            NodeConfig::default()
        };

        // Track whether CLI provided bootstrap peers.
        let cli_bootstrap_provided = !self.bootstrap.is_empty();

        // Override with CLI arguments
        if let Some(root_dir) = self.root_dir {
            config.root_dir = root_dir;
        }

        config.port = self.port;
        config.ipv4_only = self.ipv4_only;
        if let Some(bind) = self.webrtc_direct_bind {
            config.webrtc_direct.enabled = true;
            config.webrtc_direct.bind = bind;
        }
        if let Some(port) = self.webrtc_direct_port {
            config.webrtc_direct.enabled = true;
            config.webrtc_direct.bind.set_port(port);
        }
        if let Some(addr) = self.webrtc_direct_advertised_addr {
            config.webrtc_direct.advertised_addr = Some(addr);
        }
        #[cfg(feature = "logging")]
        {
            config.log_level = self.log_level.into();
        }
        config.network_mode = self.network_mode.into();

        // Apply CLI bootstrap peers if provided; otherwise keep config file value.
        if cli_bootstrap_provided {
            config.bootstrap = self.bootstrap;
        }

        // Upgrade config
        config.upgrade.channel = self.upgrade_channel.into();
        config.upgrade.stop_on_upgrade = self.stop_on_upgrade;

        // Payment config (payment verification is always on)
        // Custom EVM (--evm-rpc-url) overrides the --evm-network preset.
        let evm_network = if let Some(rpc_url) = self.evm_rpc_url {
            let payment_token_address = self.evm_payment_token.ok_or_else(|| {
                color_eyre::eyre::eyre!("--evm-payment-token is required when --evm-rpc-url is set")
            })?;
            let payment_vault_address = self.evm_payment_vault.ok_or_else(|| {
                color_eyre::eyre::eyre!("--evm-payment-vault is required when --evm-rpc-url is set")
            })?;
            EvmNetworkConfig::Custom {
                rpc_url,
                payment_token_address,
                payment_vault_address,
            }
        } else {
            self.evm_network.into()
        };

        config.payment = PaymentConfig {
            cache_capacity: self.cache_capacity,
            rewards_address: self.rewards_address,
            evm_network,
            metrics_port: self.metrics_port,
        };

        // Determine bootstrap source and apply auto-discovery if needed.
        let bootstrap_source = if cli_bootstrap_provided {
            BootstrapSource::Cli
        } else if !config.bootstrap.is_empty() && has_config_file {
            BootstrapSource::ConfigFile
        } else if config.bootstrap.is_empty() {
            // No peers from CLI or config file — try auto-discovery.
            if let Some((peers_config, path)) = BootstrapPeersConfig::discover() {
                config.bootstrap = peers_config.peers;
                BootstrapSource::AutoDiscovered(path)
            } else {
                BootstrapSource::None
            }
        } else {
            // Config had peers from default (e.g., testnet preset) but no --config file.
            BootstrapSource::None
        };

        Ok((config, bootstrap_source))
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

#[cfg(feature = "logging")]
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

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::Parser;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn webrtc_direct_port_overrides_the_default_bind_port() -> Result<(), Box<dyn std::error::Error>>
    {
        let cli = Cli::try_parse_from(["ant-node", "--webrtc-direct-port", "45000"])?;
        let (config, _) = cli.into_config()?;

        assert!(config.webrtc_direct.enabled);
        assert_eq!(config.webrtc_direct.bind.port(), 45_000);
        Ok(())
    }

    #[test]
    fn webrtc_direct_port_overrides_only_the_explicit_bind_port(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from([
            "ant-node",
            "--webrtc-direct-bind",
            "127.0.0.1:40000",
            "--webrtc-direct-port",
            "45000",
        ])?;
        let (config, _) = cli.into_config()?;

        assert_eq!(
            config.webrtc_direct.bind.ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(config.webrtc_direct.bind.port(), 45_000);
        Ok(())
    }

    #[test]
    fn webrtc_port_alias_is_supported() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::try_parse_from(["ant-node", "--webrtc-port", "45000"])?;

        assert_eq!(cli.webrtc_direct_port, Some(45_000));
        Ok(())
    }
}
