//! EVM wallet management for receiving payments.
//!
//! Handles parsing and validation of EVM wallet addresses (rewards addresses)
//! that nodes use to receive payments for storing data.

use crate::config::EvmNetworkConfig;
use crate::error::{Error, Result};
use ant_evm::RewardsAddress;
use evmlib::Network as EvmNetwork;

/// EVM wallet configuration for a node.
#[derive(Debug, Clone)]
pub struct WalletConfig {
    /// The rewards address where payments are received.
    pub rewards_address: Option<RewardsAddress>,
    /// The EVM network (Arbitrum One or Sepolia).
    pub network: EvmNetwork,
}

impl WalletConfig {
    /// Create a new wallet configuration.
    ///
    /// # Arguments
    ///
    /// * `rewards_address` - Optional EVM address string (e.g., "0x...")
    /// * `evm_network` - The EVM network configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the address string is invalid.
    pub fn new(
        rewards_address: Option<&str>,
        evm_network: EvmNetworkConfig,
    ) -> Result<Self> {
        let rewards_address = rewards_address
            .map(parse_rewards_address)
            .transpose()?;

        let network = match evm_network {
            EvmNetworkConfig::ArbitrumOne => EvmNetwork::ArbitrumOne,
            EvmNetworkConfig::ArbitrumSepolia => EvmNetwork::ArbitrumSepoliaTest,
        };

        Ok(Self {
            rewards_address,
            network,
        })
    }

    /// Check if the wallet has a rewards address configured.
    #[must_use]
    pub fn has_rewards_address(&self) -> bool {
        self.rewards_address.is_some()
    }

    /// Get the rewards address if configured.
    #[must_use]
    pub fn get_rewards_address(&self) -> Option<&RewardsAddress> {
        self.rewards_address.as_ref()
    }

    /// Check if this wallet is configured for mainnet.
    #[must_use]
    pub fn is_mainnet(&self) -> bool {
        matches!(self.network, EvmNetwork::ArbitrumOne)
    }
}

/// Parse an EVM address string into a `RewardsAddress`.
///
/// # Arguments
///
/// * `address` - EVM address string (e.g., "0x1234...")
///
/// # Errors
///
/// Returns an error if the address format is invalid.
pub fn parse_rewards_address(address: &str) -> Result<RewardsAddress> {
    // Validate format: should start with 0x and be 42 characters total (0x + 40 hex chars)
    if !address.starts_with("0x") && !address.starts_with("0X") {
        return Err(Error::Payment(format!(
            "Invalid rewards address format: must start with '0x', got: {address}"
        )));
    }

    if address.len() != 42 {
        return Err(Error::Payment(format!(
            "Invalid rewards address length: expected 42 characters, got {}",
            address.len()
        )));
    }

    // Validate hex characters
    let hex_part = &address[2..];
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Payment(format!(
            "Invalid rewards address: contains non-hex characters: {address}"
        )));
    }

    // Parse into bytes
    let bytes = hex::decode(hex_part).map_err(|e| {
        Error::Payment(format!("Failed to decode rewards address: {e}"))
    })?;

    // Convert to fixed-size array
    let mut address_bytes = [0u8; 20];
    address_bytes.copy_from_slice(&bytes);

    Ok(RewardsAddress::new(address_bytes))
}

/// Validate that an EVM address is properly formatted.
///
/// # Arguments
///
/// * `address` - EVM address string to validate
///
/// # Returns
///
/// `true` if the address is valid, `false` otherwise.
#[must_use]
pub fn is_valid_address(address: &str) -> bool {
    parse_rewards_address(address).is_ok()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_address() {
        let address = "0x742d35Cc6634C0532925a3b844Bc9e7595916Da2";
        let result = parse_rewards_address(address);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_lowercase_address() {
        let address = "0x742d35cc6634c0532925a3b844bc9e7595916da2";
        let result = parse_rewards_address(address);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_prefix() {
        let address = "742d35Cc6634C0532925a3b844Bc9e7595916Da2";
        let result = parse_rewards_address(address);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_length() {
        let address = "0x742d35Cc6634C0532925a3b844Bc9e7595916Da";
        let result = parse_rewards_address(address);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_hex_chars() {
        let address = "0x742d35Cc6634C0532925a3b844Bc9e7595916DgZ";
        let result = parse_rewards_address(address);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_valid_address() {
        assert!(is_valid_address("0x742d35Cc6634C0532925a3b844Bc9e7595916Da2"));
        assert!(!is_valid_address("invalid"));
    }

    #[test]
    fn test_wallet_config_new() {
        let config = WalletConfig::new(
            Some("0x742d35Cc6634C0532925a3b844Bc9e7595916Da2"),
            EvmNetworkConfig::ArbitrumSepolia,
        );
        assert!(config.is_ok());
        let config = config.expect("valid config");
        assert!(config.has_rewards_address());
        assert!(!config.is_mainnet());
    }

    #[test]
    fn test_wallet_config_no_address() {
        let config = WalletConfig::new(None, EvmNetworkConfig::ArbitrumOne);
        assert!(config.is_ok());
        let config = config.expect("valid config");
        assert!(!config.has_rewards_address());
        assert!(config.is_mainnet());
    }
}
