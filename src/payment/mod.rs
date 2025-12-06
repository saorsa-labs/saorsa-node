//! Payment verification system for saorsa-node.
//!
//! This module implements the payment verification strategy:
//! 1. Check if data already exists on the autonomi network (already paid)
//! 2. If not, require and verify EVM/Arbitrum payment for new data
//!
//! # Architecture
//!
//! ```text
//! PUT request received
//!        │
//!        ▼
//! ┌─────────────────────┐
//! │ Check LRU cache     │
//! └─────────┬───────────┘
//!           │
//!    ┌──────┴──────┐
//!    │             │
//!   HIT          MISS
//!    │             │
//!    ▼             ▼
//! Store FREE   Query autonomi
//!                  │
//!           ┌──────┴──────┐
//!           │             │
//!        EXISTS      NOT FOUND
//!           │             │
//!           ▼             ▼
//!      Cache + FREE   Require EVM payment
//! ```
//!
//! # Payment Flow
//!
//! For new data that doesn't exist on autonomi:
//! 1. Client requests a quote from the node
//! 2. Node generates `PaymentQuote` with ML-DSA-65 signature
//! 3. Client pays on Arbitrum via `PaymentVault.payForQuotes()`
//! 4. Client sends PUT with `ProofOfPayment`
//! 5. Node verifies on-chain payment and stores data

mod autonomi_verifier;
mod cache;
pub mod metrics;
pub mod quote;
mod verifier;
pub mod wallet;

pub use autonomi_verifier::AutonomVerifier;
pub use cache::VerifiedCache;
pub use metrics::QuotingMetricsTracker;
pub use quote::{verify_quote_content, QuoteGenerator, XorName};
pub use verifier::{PaymentStatus, PaymentVerifier, PaymentVerifierConfig};
pub use wallet::{is_valid_address, parse_rewards_address, WalletConfig};
