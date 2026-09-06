//! Storage subsystem for chunk persistence.
//!
//! This module provides content-addressed storage for chunks, one immutable file per
//! chunk, along with a protocol handler that integrates with saorsa-core's `Protocol`
//! trait for automatic message routing.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │        AntProtocol (implements Protocol trait)        │
//! ├─────────────────────────────────────────────────────────┤
//! │  protocol_id() = "autonomi.ant.chunk.v1"                  │
//! │                                                         │
//! │  handle(peer_id, data) ──▶ decode AntProtocolMessage │
//! │                                   │                     │
//! │         ┌─────────────────────────┼─────────────────┐  │
//! │         ▼                         ▼                 ▼  │
//! │   QuoteRequest           ChunkPutRequest    ChunkGetRequest
//! │         │                         │                 │  │
//! │         ▼                         ▼                 ▼  │
//! │   QuoteGenerator          PaymentVerifier    ChunkStore│
//! │         │                         │                 │  │
//! │         └─────────────────────────┴─────────────────┘  │
//! │                           │                             │
//! │                 return Ok(Some(response_bytes))         │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use ant_node::storage::{AntProtocol, ChunkStore, ChunkStoreConfig};
//!
//! // Create storage
//! let config = ChunkStoreConfig::default();
//! let storage = Arc::new(ChunkStore::new(config).await?);
//!
//! // Create protocol handler
//! let protocol = AntProtocol::new(storage, Arc::new(payment_verifier), Arc::new(quote_generator));
//!
//! // Register with saorsa-core
//! listener.register_protocol(protocol).await?;
//! ```

#[cfg(any(test, feature = "test-utils"))]
pub mod chunk_store;
#[cfg(not(any(test, feature = "test-utils")))]
pub(crate) mod chunk_store;
mod handler;
pub mod legacy_artifacts;

pub use crate::ant_protocol::XorName;
pub use chunk_store::{CapacityVerdict, ChunkStore, ChunkStoreConfig, StoreLayout};
pub use handler::AntProtocol;
pub(crate) use handler::ChunkRequestContext;
pub use legacy_artifacts::LEGACY_ENV_DIR;

/// Bytes in one MiB.
pub const MIB: u64 = 1024 * 1024;

/// Bytes in one GiB.
pub const GIB: u64 = 1024 * MIB;

/// Default free disk space to keep unused on the storage partition.
pub const DEFAULT_DISK_RESERVE: u64 = 500 * MIB;

/// Statistics about storage operations.
///
/// Counters other than `current_chunks` are cumulative for the lifetime of the
/// process; `current_chunks` is the live count.
#[derive(Debug, Clone, Default)]
pub struct StorageStats {
    /// Total number of chunks stored.
    pub chunks_stored: u64,
    /// Total number of chunks retrieved.
    pub chunks_retrieved: u64,
    /// Total bytes stored.
    pub bytes_stored: u64,
    /// Total bytes retrieved.
    pub bytes_retrieved: u64,
    /// Number of duplicate writes (already exists).
    pub duplicates: u64,
    /// Number of verification failures on read.
    pub verification_failures: u64,
    /// Number of chunks currently persisted.
    pub current_chunks: u64,
}
