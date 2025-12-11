//! Main payment verifier combining autonomi lookup and LRU cache.
//!
//! This is the core payment verification logic for saorsa-node.

use crate::error::{Error, Result};
use crate::payment::autonomi_verifier::{AutonomVerifier, AutonomVerifierConfig};
use crate::payment::cache::{VerifiedCache, XorName};
use ant_evm::ProofOfPayment;
use evmlib::Network as EvmNetwork;
use tracing::{debug, info, warn};

/// Configuration for EVM payment verification.
#[derive(Debug, Clone)]
pub struct EvmVerifierConfig {
    /// EVM network to use (Arbitrum One, Arbitrum Sepolia, etc.)
    pub network: EvmNetwork,
    /// Whether EVM verification is enabled.
    pub enabled: bool,
}

impl Default for EvmVerifierConfig {
    fn default() -> Self {
        Self {
            network: EvmNetwork::ArbitrumOne,
            enabled: true,
        }
    }
}

/// Configuration for the payment verifier.
///
/// ## Security: Fail-Closed Default
///
/// The `require_payment_on_error` field defaults to `true` (fail-closed behavior).
/// This means that if the autonomi network lookup fails (network issues, timeouts, etc.),
/// the node will require payment rather than allowing free storage.
///
/// This is the secure default because:
/// - **Prevents abuse**: Attackers cannot exploit network failures to store data for free
/// - **Economic security**: Ensures payment is always required for new data
/// - **Fail-safe**: Errs on the side of requiring payment when uncertain
///
/// Setting `require_payment_on_error = false` enables fail-open behavior, which is
/// less secure but may be useful during network instability for better user experience.
/// **Use fail-open only in controlled environments.**
#[derive(Debug, Clone)]
pub struct PaymentVerifierConfig {
    /// Autonomi verifier configuration.
    pub autonomi: AutonomVerifierConfig,
    /// EVM verifier configuration.
    pub evm: EvmVerifierConfig,
    /// Cache capacity (number of `XorName` values to cache).
    pub cache_capacity: usize,
    /// Whether to require payment on autonomi lookup failure.
    ///
    /// **Default: `true` (fail-closed)** - This is the secure default.
    /// When `true`: Network errors result in `PaymentRequired` status.
    /// When `false`: Network errors result in `AlreadyPaid` status (less secure).
    pub require_payment_on_error: bool,
}

impl Default for PaymentVerifierConfig {
    fn default() -> Self {
        Self {
            autonomi: AutonomVerifierConfig::default(),
            evm: EvmVerifierConfig::default(),
            cache_capacity: 100_000,
            require_payment_on_error: true,
        }
    }
}

/// Status returned by payment verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentStatus {
    /// Data exists on autonomi - no payment required.
    AlreadyPaid,
    /// Data was found in local cache - no payment required.
    CachedAsVerified,
    /// New data - payment required.
    PaymentRequired,
    /// Payment was provided and verified.
    PaymentVerified,
}

impl PaymentStatus {
    /// Returns true if the data can be stored (either already paid or payment verified).
    #[must_use]
    pub fn can_store(&self) -> bool {
        matches!(
            self,
            Self::AlreadyPaid | Self::CachedAsVerified | Self::PaymentVerified
        )
    }

    /// Returns true if this status indicates the data was already paid for.
    #[must_use]
    pub fn is_free(&self) -> bool {
        matches!(self, Self::AlreadyPaid | Self::CachedAsVerified)
    }
}

/// Main payment verifier for saorsa-node.
///
/// Combines:
/// 1. LRU cache for fast lookups of previously verified `XorName` values
/// 2. Autonomi network verification for checking if data already exists
/// 3. EVM payment verification for new data
pub struct PaymentVerifier {
    /// LRU cache of verified `XorName` values.
    cache: VerifiedCache,
    /// Autonomi network verifier.
    autonomi: AutonomVerifier,
    /// Configuration.
    config: PaymentVerifierConfig,
}

impl PaymentVerifier {
    /// Create a new payment verifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the autonomi verifier fails to initialize.
    pub async fn new(config: PaymentVerifierConfig) -> Result<Self> {
        let cache = VerifiedCache::with_capacity(config.cache_capacity);
        let autonomi = AutonomVerifier::new(config.autonomi.clone()).await?;

        info!(
            "Payment verifier initialized (cache_capacity={}, autonomi_enabled={})",
            config.cache_capacity,
            autonomi.is_enabled()
        );

        Ok(Self {
            cache,
            autonomi,
            config,
        })
    }

    /// Check if payment is required for the given `XorName`.
    ///
    /// This is the main entry point for payment verification:
    /// 1. Check LRU cache (fast path)
    /// 2. Query autonomi network
    /// 3. Return status indicating if payment is needed
    ///
    /// # Arguments
    ///
    /// * `xorname` - The content-addressed name of the data
    ///
    /// # Returns
    ///
    /// * `PaymentStatus::CachedAsVerified` - Found in local cache (no payment)
    /// * `PaymentStatus::AlreadyPaid` - Found on autonomi (no payment)
    /// * `PaymentStatus::PaymentRequired` - Not found (payment required)
    pub async fn check_payment_required(&self, xorname: &XorName) -> PaymentStatus {
        // Step 1: Check LRU cache (fast path)
        if self.cache.contains(xorname) {
            debug!("Data {} found in verified cache", hex::encode(xorname));
            return PaymentStatus::CachedAsVerified;
        }

        // Step 2: Query autonomi network
        match self.autonomi.data_exists(xorname).await {
            Ok(true) => {
                // Data exists on autonomi - cache it and return AlreadyPaid
                self.cache.insert(*xorname);
                info!(
                    "Data {} exists on autonomi - storing free",
                    hex::encode(xorname)
                );
                PaymentStatus::AlreadyPaid
            }
            Ok(false) => {
                // Data not found - payment required
                debug!(
                    "Data {} not found on autonomi - payment required",
                    hex::encode(xorname)
                );
                PaymentStatus::PaymentRequired
            }
            Err(e) => {
                // Network error - decide based on config
                warn!("Autonomi lookup failed for {}: {}", hex::encode(xorname), e);
                if self.config.require_payment_on_error {
                    PaymentStatus::PaymentRequired
                } else {
                    // Fail open - allow free storage on error
                    // This is less secure but more user-friendly during network issues
                    PaymentStatus::AlreadyPaid
                }
            }
        }
    }

    /// Verify that a PUT request has valid payment or data exists on autonomi.
    ///
    /// This is the complete payment verification flow:
    /// 1. Check if data exists (cache or autonomi)
    /// 2. If not, verify the provided payment proof
    ///
    /// # Arguments
    ///
    /// * `xorname` - The content-addressed name of the data
    /// * `payment_proof` - Optional payment proof (required if data doesn't exist)
    ///
    /// # Returns
    ///
    /// * `Ok(PaymentStatus)` - Verification succeeded
    /// * `Err(Error::PaymentRequired)` - No payment and data not found
    /// * `Err(Error::PaymentInvalid)` - Payment provided but invalid
    ///
    /// # Errors
    ///
    /// Returns an error if payment is required but not provided, or if payment is invalid.
    pub async fn verify_payment(
        &self,
        xorname: &XorName,
        payment_proof: Option<&[u8]>,
    ) -> Result<PaymentStatus> {
        // First check if payment is required
        let status = self.check_payment_required(xorname).await;

        match status {
            PaymentStatus::CachedAsVerified | PaymentStatus::AlreadyPaid => {
                // No payment needed
                Ok(status)
            }
            PaymentStatus::PaymentRequired => {
                // Payment is required - verify the proof
                match payment_proof {
                    Some(proof) => {
                        if proof.is_empty() {
                            return Err(Error::Payment("Empty payment proof".to_string()));
                        }

                        // Deserialize the ProofOfPayment
                        let payment: ProofOfPayment =
                            rmp_serde::from_slice(proof).map_err(|e| {
                                Error::Payment(format!("Failed to deserialize payment proof: {e}"))
                            })?;

                        // Verify the payment using EVM
                        self.verify_evm_payment(xorname, &payment).await?;

                        // Cache the verified xorname
                        self.cache.insert(*xorname);

                        Ok(PaymentStatus::PaymentVerified)
                    }
                    None => {
                        // No payment provided
                        Err(Error::Payment(format!(
                            "Payment required for new data {}",
                            hex::encode(xorname)
                        )))
                    }
                }
            }
            PaymentStatus::PaymentVerified => {
                // This shouldn't happen from check_payment_required
                Ok(status)
            }
        }
    }

    /// Get cache statistics.
    #[must_use]
    pub fn cache_stats(&self) -> crate::payment::cache::CacheStats {
        self.cache.stats()
    }

    /// Get the number of cached entries.
    #[must_use]
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the autonomi verifier is enabled.
    #[must_use]
    pub fn autonomi_enabled(&self) -> bool {
        self.autonomi.is_enabled()
    }

    /// Check if EVM verification is enabled.
    #[must_use]
    pub fn evm_enabled(&self) -> bool {
        self.config.evm.enabled
    }

    /// Verify an EVM payment proof.
    ///
    /// This verifies that:
    /// 1. All quote signatures are valid
    /// 2. The payment was made on-chain
    async fn verify_evm_payment(&self, xorname: &XorName, payment: &ProofOfPayment) -> Result<()> {
        debug!(
            "Verifying EVM payment for {} with {} quotes",
            hex::encode(xorname),
            payment.peer_quotes.len()
        );

        // Skip EVM verification if disabled
        if !self.config.evm.enabled {
            warn!("EVM verification disabled - accepting payment without on-chain check");
            return Ok(());
        }

        // Verify quote signatures first (doesn't require network)
        for (encoded_peer_id, quote) in &payment.peer_quotes {
            let peer_id = encoded_peer_id
                .to_peer_id()
                .map_err(|e| Error::Payment(format!("Invalid peer ID in payment proof: {e}")))?;

            if !quote.check_is_signed_by_claimed_peer(peer_id) {
                return Err(Error::Payment(format!(
                    "Quote signature invalid for peer {peer_id}"
                )));
            }
        }

        // Get the payment digest for on-chain verification
        let payment_digest = payment.digest();

        if payment_digest.is_empty() {
            return Err(Error::Payment("Payment has no quotes".to_string()));
        }

        // Verify on-chain payment
        // Note: We pass empty owned_quote_hashes because we're not a node claiming payment,
        // we just want to verify the payment is valid
        let owned_quote_hashes = vec![];
        match evmlib::contract::payment_vault::verify_data_payment(
            &self.config.evm.network,
            owned_quote_hashes,
            payment_digest,
        )
        .await
        {
            Ok(_amount) => {
                info!("EVM payment verified for {}", hex::encode(xorname));
                Ok(())
            }
            Err(evmlib::contract::payment_vault::error::Error::PaymentInvalid) => {
                Err(Error::Payment(format!(
                    "Payment verification failed on-chain for {}",
                    hex::encode(xorname)
                )))
            }
            Err(e) => Err(Error::Payment(format!(
                "EVM verification error for {}: {e}",
                hex::encode(xorname)
            ))),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    async fn create_test_verifier() -> PaymentVerifier {
        let config = PaymentVerifierConfig {
            autonomi: AutonomVerifierConfig {
                enabled: false, // Disabled for tests
                ..Default::default()
            },
            evm: EvmVerifierConfig {
                enabled: false, // Disabled for tests
                ..Default::default()
            },
            cache_capacity: 100,
            require_payment_on_error: true,
        };
        PaymentVerifier::new(config).await.expect("should create")
    }

    #[tokio::test]
    async fn test_payment_required_for_new_data() {
        let verifier = create_test_verifier().await;
        let xorname = [1u8; 32];

        // With autonomi disabled, all data should require payment
        let status = verifier.check_payment_required(&xorname).await;
        assert_eq!(status, PaymentStatus::PaymentRequired);
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let verifier = create_test_verifier().await;
        let xorname = [1u8; 32];

        // Manually add to cache
        verifier.cache.insert(xorname);

        // Should return CachedAsVerified
        let status = verifier.check_payment_required(&xorname).await;
        assert_eq!(status, PaymentStatus::CachedAsVerified);
    }

    #[tokio::test]
    async fn test_verify_payment_without_proof() {
        let verifier = create_test_verifier().await;
        let xorname = [1u8; 32];

        // Should fail without payment proof
        let result = verifier.verify_payment(&xorname, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_payment_with_proof() {
        let verifier = create_test_verifier().await;
        let xorname = [1u8; 32];

        // Create a valid (but empty) ProofOfPayment
        let proof = ProofOfPayment {
            peer_quotes: vec![],
        };
        let proof_bytes = rmp_serde::to_vec(&proof).expect("should serialize");

        // Should succeed with a valid proof when EVM verification is disabled
        // Note: With EVM verification disabled, even empty proofs pass
        let result = verifier.verify_payment(&xorname, Some(&proof_bytes)).await;
        assert!(result.is_ok(), "Expected Ok, got: {result:?}");
        assert_eq!(result.expect("verified"), PaymentStatus::PaymentVerified);
    }

    #[tokio::test]
    async fn test_verify_payment_cached() {
        let verifier = create_test_verifier().await;
        let xorname = [1u8; 32];

        // Add to cache
        verifier.cache.insert(xorname);

        // Should succeed without payment (cached)
        let result = verifier.verify_payment(&xorname, None).await;
        assert!(result.is_ok());
        assert_eq!(result.expect("cached"), PaymentStatus::CachedAsVerified);
    }

    #[test]
    fn test_payment_status_can_store() {
        assert!(PaymentStatus::AlreadyPaid.can_store());
        assert!(PaymentStatus::CachedAsVerified.can_store());
        assert!(PaymentStatus::PaymentVerified.can_store());
        assert!(!PaymentStatus::PaymentRequired.can_store());
    }

    #[test]
    fn test_payment_status_is_free() {
        assert!(PaymentStatus::AlreadyPaid.is_free());
        assert!(PaymentStatus::CachedAsVerified.is_free());
        assert!(!PaymentStatus::PaymentVerified.is_free());
        assert!(!PaymentStatus::PaymentRequired.is_free());
    }
}
