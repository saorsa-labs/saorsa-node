//! Chunk client module for saorsa-node.
//!
//! This module provides a client interface for content-addressed chunk storage
//! on the saorsa network using post-quantum cryptography.
//!
//! # Architecture
//!
//! The chunk client provides:
//!
//! 1. **Content-addressed storage**: Chunk address = SHA256(content)
//! 2. **PQC security**: All data uses ML-KEM-768 and ML-DSA-65
//! 3. **EVM payment**: Chunks are paid for on Arbitrum network
//!
//! # Data Types
//!
//! Currently supports a single data type:
//!
//! - **Chunk**: Immutable content-addressed data (hash(value) == key)
//!
//! Future extensions may include non-content-addressed key-value storage.
//!
//! # Example
//!
//! ```rust,ignore
//! use saorsa_node::client::{ChunkClient, ChunkConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create client with default config
//!     let client = ChunkClient::with_defaults();
//!
//!     // Store new data (content-addressed)
//!     let address = client.put_chunk(bytes::Bytes::from("hello world")).await?;
//!
//!     // Retrieve data by address
//!     let data = client.get_chunk(&address).await?;
//!
//!     // Check statistics
//!     let stats = client.stats();
//!     println!("Chunks stored: {}", stats.chunks_stored);
//!     println!("Chunks retrieved: {}", stats.chunks_retrieved);
//!
//!     Ok(())
//! }
//! ```
//!
//! # Security Model
//!
//! ## Quantum-Resistant Cryptography
//!
//! All data stored through this client uses:
//! - **ML-KEM-768** (NIST FIPS 203): Key encapsulation for encryption
//! - **ML-DSA-65** (NIST FIPS 204): Digital signatures for authentication
//! - **ChaCha20-Poly1305**: Symmetric encryption for data at rest

mod data_types;
mod quantum;

pub use data_types::{compute_address, ChunkStats, DataChunk, XorName};
pub use quantum::{QuantumClient, QuantumConfig};
