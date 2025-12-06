//! Payment quote generation for saorsa-node.
//!
//! Generates `PaymentQuote` values that clients use to pay for data storage.
//! Compatible with the autonomi payment system.
//!
//! NOTE: Quote generation requires integration with the node's signing
//! capabilities from saorsa-core. This module provides the interface
//! and will be fully integrated when the node is initialized.

use crate::error::Result;
use crate::payment::metrics::QuotingMetricsTracker;
use ant_evm::{PaymentQuote, QuotingMetrics, RewardsAddress};
use std::time::SystemTime;
use tracing::debug;

/// Content address type (32-byte `XorName`).
pub type XorName = [u8; 32];

/// Signing function type that takes bytes and returns a signature.
pub type SignFn = Box<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

/// Quote generator for creating payment quotes.
///
/// Uses the node's signing capabilities to sign quotes, which clients
/// use to pay for storage on the Arbitrum network.
pub struct QuoteGenerator {
    /// The rewards address for receiving payments.
    rewards_address: RewardsAddress,
    /// Metrics tracker for quoting.
    metrics_tracker: QuotingMetricsTracker,
    /// Signing function provided by the node.
    /// Takes bytes and returns a signature.
    sign_fn: Option<SignFn>,
    /// Public key bytes for the quote.
    pub_key: Vec<u8>,
}

impl QuoteGenerator {
    /// Create a new quote generator without signing capability.
    ///
    /// Call `set_signer` to enable quote signing.
    ///
    /// # Arguments
    ///
    /// * `rewards_address` - The EVM address for receiving payments
    /// * `metrics_tracker` - Tracker for quoting metrics
    #[must_use]
    pub fn new(rewards_address: RewardsAddress, metrics_tracker: QuotingMetricsTracker) -> Self {
        Self {
            rewards_address,
            metrics_tracker,
            sign_fn: None,
            pub_key: Vec::new(),
        }
    }

    /// Set the signing function for quote generation.
    ///
    /// # Arguments
    ///
    /// * `pub_key` - The node's public key bytes
    /// * `sign_fn` - Function that signs bytes and returns signature
    pub fn set_signer<F>(&mut self, pub_key: Vec<u8>, sign_fn: F)
    where
        F: Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
    {
        self.pub_key = pub_key;
        self.sign_fn = Some(Box::new(sign_fn));
    }

    /// Check if the generator has signing capability.
    #[must_use]
    pub fn can_sign(&self) -> bool {
        self.sign_fn.is_some()
    }

    /// Generate a payment quote for storing data.
    ///
    /// # Arguments
    ///
    /// * `content` - The `XorName` of the content to store
    /// * `data_size` - Size of the data in bytes
    /// * `data_type` - Type index of the data (0 for chunks)
    ///
    /// # Returns
    ///
    /// A signed `PaymentQuote` that the client can use to pay on-chain.
    ///
    /// # Errors
    ///
    /// Returns an error if signing is not configured.
    pub fn create_quote(
        &self,
        content: XorName,
        data_size: usize,
        data_type: u32,
    ) -> Result<PaymentQuote> {
        let sign_fn = self.sign_fn.as_ref().ok_or_else(|| {
            crate::error::Error::Payment("Quote signing not configured".to_string())
        })?;

        let timestamp = SystemTime::now();

        // Get current quoting metrics
        let quoting_metrics = self.metrics_tracker.get_metrics(data_size, data_type);

        // Convert XorName to xor_name::XorName
        let xor_name = xor_name::XorName(content);

        // Create bytes for signing (following autonomi's pattern)
        let bytes = PaymentQuote::bytes_for_signing(
            xor_name,
            timestamp,
            &quoting_metrics,
            &self.rewards_address,
        );

        // Sign the bytes
        let signature = sign_fn(&bytes);

        let quote = PaymentQuote {
            content: xor_name,
            timestamp,
            quoting_metrics,
            pub_key: self.pub_key.clone(),
            rewards_address: self.rewards_address,
            signature,
        };

        debug!(
            "Generated quote for {} (size: {}, type: {})",
            hex::encode(content),
            data_size,
            data_type
        );

        Ok(quote)
    }

    /// Get the rewards address.
    #[must_use]
    pub fn rewards_address(&self) -> &RewardsAddress {
        &self.rewards_address
    }

    /// Get current quoting metrics.
    #[must_use]
    pub fn current_metrics(&self) -> QuotingMetrics {
        self.metrics_tracker.get_metrics(0, 0)
    }

    /// Record a payment received (delegates to metrics tracker).
    pub fn record_payment(&self) {
        self.metrics_tracker.record_payment();
    }

    /// Record data stored (delegates to metrics tracker).
    pub fn record_store(&self, data_type: u32) {
        self.metrics_tracker.record_store(data_type);
    }
}

/// Verify a payment quote signature.
///
/// # Arguments
///
/// * `quote` - The quote to verify
/// * `expected_content` - The expected content `XorName`
///
/// # Returns
///
/// `true` if the content matches (signature verification requires public key).
#[must_use]
pub fn verify_quote_content(quote: &PaymentQuote, expected_content: &XorName) -> bool {
    // Check content matches
    if quote.content.0 != *expected_content {
        debug!(
            "Quote content mismatch: expected {}, got {}",
            hex::encode(expected_content),
            hex::encode(quote.content.0)
        );
        return false;
    }
    true
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::payment::metrics::QuotingMetricsTracker;

    fn create_test_generator() -> QuoteGenerator {
        let rewards_address = RewardsAddress::new([1u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(1000, 100);

        let mut generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        // Set up a dummy signer for testing
        generator.set_signer(vec![0u8; 64], |bytes| {
            // Dummy signature - just return hash of bytes
            let mut sig = vec![0u8; 64];
            for (i, b) in bytes.iter().take(64).enumerate() {
                sig[i] = *b;
            }
            sig
        });

        generator
    }

    #[test]
    fn test_create_quote() {
        let generator = create_test_generator();
        let content = [42u8; 32];

        let quote = generator.create_quote(content, 1024, 0);
        assert!(quote.is_ok());

        let quote = quote.expect("valid quote");
        assert_eq!(quote.content.0, content);
    }

    #[test]
    fn test_verify_quote_content() {
        let generator = create_test_generator();
        let content = [42u8; 32];

        let quote = generator.create_quote(content, 1024, 0).expect("valid quote");
        assert!(verify_quote_content(&quote, &content));

        // Wrong content should fail
        let wrong_content = [99u8; 32];
        assert!(!verify_quote_content(&quote, &wrong_content));
    }

    #[test]
    fn test_generator_without_signer() {
        let rewards_address = RewardsAddress::new([1u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(1000, 100);
        let generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        assert!(!generator.can_sign());

        let content = [42u8; 32];
        let result = generator.create_quote(content, 1024, 0);
        assert!(result.is_err());
    }
}
