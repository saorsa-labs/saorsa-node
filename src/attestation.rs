//! Attestation security level detection.
//!
//! This module provides compile-time detection of the available attestation
//! verification level based on enabled features.
//!
//! # Security Levels
//!
//! | Level | Feature | Security |
//! |-------|---------|----------|
//! | `Stark` | `zkvm-prover` | Post-quantum secure |
//! | `Groth16` | `zkvm-verifier-groth16` | NOT post-quantum secure |
//! | `None` | (no feature) | **NO CRYPTOGRAPHIC SECURITY** |
//!
//! # Usage
//!
//! ```rust,ignore
//! use saorsa_node::attestation::VerificationLevel;
//!
//! match VerificationLevel::current() {
//!     VerificationLevel::Stark => println!("Post-quantum secure"),
//!     VerificationLevel::Groth16 => println!("WARNING: Not PQ-secure"),
//!     VerificationLevel::None => panic!("NO SECURITY - mock verification only"),
//! }
//! ```

use std::fmt;

/// Attestation verification security level.
///
/// Determined at compile time based on enabled features.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerificationLevel {
    /// No cryptographic verification available.
    ///
    /// **WARNING**: Proofs are accepted without any cryptographic validation.
    /// This provides **ZERO SECURITY** and should never be used in production.
    /// Enable `zkvm-prover` or `zkvm-verifier-groth16` feature for real verification.
    None,

    /// Groth16/PLONK verification via `sp1-verifier`.
    ///
    /// **WARNING**: Groth16 uses BN254 elliptic curves which are **NOT post-quantum secure**.
    /// Suitable for applications where quantum resistance is not required.
    Groth16,

    /// STARK-based verification via `sp1-sdk`.
    ///
    /// Post-quantum secure verification using STARKs.
    /// This is the recommended option for production deployments.
    Stark,
}

impl VerificationLevel {
    /// Get the current verification level based on compile-time features.
    ///
    /// Priority: `zkvm-prover` (Stark) > `zkvm-verifier-groth16` (Groth16) > None
    #[must_use]
    pub const fn current() -> Self {
        #[cfg(feature = "zkvm-prover")]
        {
            Self::Stark
        }

        #[cfg(all(feature = "zkvm-verifier-groth16", not(feature = "zkvm-prover")))]
        {
            Self::Groth16
        }

        #[cfg(not(any(feature = "zkvm-prover", feature = "zkvm-verifier-groth16")))]
        {
            Self::None
        }
    }

    /// Check if any cryptographic verification is available.
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        matches!(self, Self::Groth16 | Self::Stark)
    }

    /// Check if post-quantum secure verification is available.
    #[must_use]
    pub const fn is_pq_secure(&self) -> bool {
        matches!(self, Self::Stark)
    }

    /// Get a human-readable description of the security level.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::None => "NO CRYPTOGRAPHIC SECURITY (mock verification)",
            Self::Groth16 => "Groth16 verification (NOT post-quantum secure)",
            Self::Stark => "STARK verification (post-quantum secure)",
        }
    }

    /// Get the required feature flag name for this level.
    #[must_use]
    pub const fn feature_name(&self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Groth16 => Some("zkvm-verifier-groth16"),
            Self::Stark => Some("zkvm-prover"),
        }
    }
}

impl fmt::Display for VerificationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_level_current() {
        let level = VerificationLevel::current();

        // The level depends on features, but we can verify it's valid
        match level {
            VerificationLevel::None => {
                assert!(!level.is_secure());
                assert!(!level.is_pq_secure());
            }
            VerificationLevel::Groth16 => {
                assert!(level.is_secure());
                assert!(!level.is_pq_secure());
            }
            VerificationLevel::Stark => {
                assert!(level.is_secure());
                assert!(level.is_pq_secure());
            }
        }
    }

    #[test]
    fn test_verification_level_display() {
        assert!(VerificationLevel::None.to_string().contains("NO"));
        assert!(VerificationLevel::Groth16
            .to_string()
            .contains("NOT post-quantum"));
        assert!(VerificationLevel::Stark
            .to_string()
            .contains("post-quantum secure"));
    }

    #[test]
    fn test_feature_names() {
        assert_eq!(VerificationLevel::None.feature_name(), None);
        assert_eq!(
            VerificationLevel::Groth16.feature_name(),
            Some("zkvm-verifier-groth16")
        );
        assert_eq!(VerificationLevel::Stark.feature_name(), Some("zkvm-prover"));
    }
}
