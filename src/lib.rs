//! # ant-node
//!
//! A pure quantum-proof network node for the Autonomi decentralized network.
//!
//! This crate provides a thin wrapper around `saorsa-core` that adds:
//! - Auto-upgrade system with ML-DSA signature verification
//! - CLI interface and configuration
//! - Content-addressed chunk storage with EVM payment
//!
//! ## Architecture
//!
//! `ant-node` delegates all core functionality to `saorsa-core`:
//! - Networking via `P2PNode`
//! - DHT via `AdaptiveDHT`
//! - Trust via `TrustEngine`
//! - Security via `IPDiversityConfig`
//!
//! ## Data Types
//!
//! Currently supports a single data type:
//! - **Chunk**: Immutable content-addressed data (hash(value) == key)
//!
//! ## Example
//!
//! ```rust,no_run
//! use ant_node::{NodeBuilder, NodeConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = NodeConfig::default();
//!     let mut node = NodeBuilder::new(config).build().await?;
//!     node.run().await?;
//!     Ok(())
//! }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
// When the `logging` feature is off, variables used only in log macros become
// unused. These are expected and harmless — the compiler optimises them away.
#![cfg_attr(not(feature = "logging"), allow(unused_variables, unused_assignments))]

pub mod ant_protocol;
pub mod client;
pub mod config;
pub mod devnet;
pub mod error;
pub mod event;
pub mod logging;
pub mod node;
pub mod payment;
pub mod replication;
pub mod storage;
pub mod upgrade;

pub use ant_protocol::{
    ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkMessageBody, ChunkPutRequest,
    ChunkPutResponse, ChunkQuoteRequest, ChunkQuoteResponse, CHUNK_PROTOCOL_ID,
    CLOSE_GROUP_MAJORITY, CLOSE_GROUP_SIZE, MAX_CHUNK_SIZE,
};
pub use client::{
    compute_address, hex_node_id_to_encoded_peer_id, peer_id_to_xor_name, xor_distance, DataChunk,
    XorName,
};
pub use config::{NodeConfig, StorageConfig};
pub use devnet::{Devnet, DevnetConfig, DevnetEvmInfo, DevnetManifest};
pub use error::{Error, Result};
pub use event::{NodeEvent, NodeEventsChannel};
pub use node::{NodeBuilder, RunningNode};
pub use payment::{PaymentStatus, PaymentVerifier, PaymentVerifierConfig};
pub use replication::{config::ReplicationConfig, ReplicationEngine};
pub use storage::{AntProtocol, ChunkStore, ChunkStoreConfig};

/// Re-exports from `saorsa-core` so downstream crates (e.g. `ant-client`)
/// can depend on `ant-node` alone without a direct `saorsa-core` dependency.
pub mod core {
    pub use saorsa_core::identity::{NodeIdentity, PeerId};
    pub use saorsa_core::{
        IPDiversityConfig, MlDsa65, MultiAddr, NodeConfig as CoreNodeConfig, NodeMode, P2PEvent,
        P2PNode,
    };
}
