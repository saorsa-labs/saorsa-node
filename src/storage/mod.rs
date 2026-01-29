//! Storage subsystem for chunk persistence.
//!
//! This module provides content-addressed disk storage for chunks,
//! along with a protocol handler that integrates with saorsa-core's
//! `Protocol` trait for automatic message routing.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │        AntProtocol (implements Protocol trait)        │
//! ├─────────────────────────────────────────────────────────┤
//! │  protocol_id() = "saorsa/autonomi/chunk/v1"            │
//! │                                                         │
//! │  handle(peer_id, data) ──▶ decode AntProtocolMessage │
//! │                                   │                     │
//! │         ┌─────────────────────────┼─────────────────┐  │
//! │         ▼                         ▼                 ▼  │
//! │   QuoteRequest           ChunkPutRequest    ChunkGetRequest
//! │         │                         │                 │  │
//! │         ▼                         ▼                 ▼  │
//! │   QuoteGenerator          PaymentVerifier    DiskStorage│
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
//! use saorsa_node::storage::{AntProtocol, DiskStorage, DiskStorageConfig};
//!
//! // Create storage
//! let config = DiskStorageConfig::default();
//! let storage = DiskStorage::new(config).await?;
//!
//! // Create protocol handler
//! let protocol = AntProtocol::new(storage, payment_verifier, quote_generator);
//!
//! // Register with saorsa-core
//! listener.register_protocol(protocol).await?;
//! ```

mod disk;
mod handler;

pub use disk::{DiskStorage, DiskStorageConfig, StorageStats, XorName};
pub use handler::AntProtocol;
