//! # saorsa-node
//!
//! A pure quantum-proof network node for the Saorsa decentralized network.
//!
//! This crate provides a thin wrapper around `saorsa-core` that adds:
//! - Auto-upgrade system with ML-DSA signature verification
//! - CLI interface and configuration
//! - Content-addressed chunk storage with EVM payment
//!
//! ## Architecture
//!
//! `saorsa-node` delegates all core functionality to `saorsa-core`:
//! - Networking via `NetworkCoordinator`
//! - DHT via `TrustWeightedKademlia`
//! - Trust via `EigenTrustEngine`
//! - Security via `SecurityManager`
//!
//! ## Data Types
//!
//! Currently supports a single data type:
//! - **Chunk**: Immutable content-addressed data (hash(value) == key)
//!
//! ## Example
//!
//! ```rust,no_run
//! use saorsa_node::{NodeBuilder, NodeConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = NodeConfig::default();
//!     let mut node = NodeBuilder::new(config).build().await?;
//!     node.run().await?;
//!     Ok(())
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]

pub mod attestation;
pub mod client;
pub mod config;
pub mod error;
pub mod event;
pub mod node;
pub mod payment;
#[cfg(test)]
mod probe;
pub mod upgrade;

pub use client::{DataChunk, QuantumClient, QuantumConfig, XorName};
pub use config::{BootstrapCacheConfig, NodeConfig};
pub use error::{Error, Result};
pub use event::{NodeEvent, NodeEventsChannel};
pub use node::{NodeBuilder, RunningNode};
pub use payment::{PaymentStatus, PaymentVerifier, PaymentVerifierConfig};
