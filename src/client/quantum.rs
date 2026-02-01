//! Quantum-resistant client operations for chunk storage.
//!
//! This module provides content-addressed chunk storage operations on the saorsa network
//! using post-quantum cryptography (ML-KEM-768 for key exchange, ML-DSA-65 for signatures).
//!
//! ## Data Model
//!
//! Chunks are the only data type supported:
//! - **Content-addressed**: Address = SHA256(content)
//! - **Immutable**: Once stored, content cannot change
//! - **Paid**: All storage requires EVM payment on Arbitrum
//!
//! ## Security Features
//!
//! - **ML-KEM-768**: NIST FIPS 203 compliant key encapsulation for encryption
//! - **ML-DSA-65**: NIST FIPS 204 compliant signatures for authentication
//! - **ChaCha20-Poly1305**: Symmetric encryption for data at rest

use super::data_types::{DataChunk, XorName};
use crate::ant_protocol::{
    ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkPutRequest, ChunkPutResponse,
    CHUNK_PROTOCOL_ID,
};
use crate::error::{Error, Result};
use bytes::Bytes;
use saorsa_core::{P2PEvent, P2PNode};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tracing::{debug, info};

/// Default timeout for network operations in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Default number of replicas for data redundancy.
const DEFAULT_REPLICA_COUNT: u8 = 4;

/// Configuration for the quantum-resistant client.
#[derive(Debug, Clone)]
pub struct QuantumConfig {
    /// Timeout for network operations in seconds.
    pub timeout_secs: u64,
    /// Number of replicas for data redundancy.
    pub replica_count: u8,
    /// Enable encryption for all stored data.
    pub encrypt_data: bool,
}

impl Default for QuantumConfig {
    fn default() -> Self {
        Self {
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            replica_count: DEFAULT_REPLICA_COUNT,
            encrypt_data: true,
        }
    }
}

/// Client for quantum-resistant chunk operations on the saorsa network.
///
/// This client uses post-quantum cryptography for all operations:
/// - ML-KEM-768 for key encapsulation
/// - ML-DSA-65 for digital signatures
/// - ChaCha20-Poly1305 for symmetric encryption
///
/// ## Chunk Storage Model
///
/// Chunks are content-addressed: the address is the SHA256 hash of the content.
/// This ensures data integrity - if the content matches the address, the data
/// is authentic. All chunk storage requires EVM payment on Arbitrum.
pub struct QuantumClient {
    config: QuantumConfig,
    p2p_node: Option<Arc<P2PNode>>,
}

impl QuantumClient {
    /// Create a new quantum client with the given configuration.
    #[must_use]
    pub fn new(config: QuantumConfig) -> Self {
        debug!("Creating quantum-resistant saorsa client");
        Self {
            config,
            p2p_node: None,
        }
    }

    /// Create a quantum client with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(QuantumConfig::default())
    }

    /// Set the P2P node for network operations.
    #[must_use]
    pub fn with_node(mut self, node: Arc<P2PNode>) -> Self {
        self.p2p_node = Some(node);
        self
    }

    /// Get a chunk from the saorsa network via ANT protocol.
    ///
    /// Sends a `ChunkGetRequest` to a connected peer and waits for the
    /// `ChunkGetResponse`.
    ///
    /// # Arguments
    ///
    /// * `address` - The `XorName` address of the chunk (SHA256 of content)
    ///
    /// # Returns
    ///
    /// The chunk data if found, or None if not present in the network.
    ///
    /// # Errors
    ///
    /// Returns an error if the network operation fails.
    pub async fn get_chunk(&self, address: &XorName) -> Result<Option<DataChunk>> {
        debug!(
            "Querying saorsa network for chunk: {}",
            hex::encode(address)
        );

        let Some(ref node) = self.p2p_node else {
            return Err(Error::Network("P2P node not configured".into()));
        };

        let target_peer = Self::pick_target_peer(node).await?;

        // Subscribe before sending so we don't miss the response
        let mut events = node.subscribe_events();

        // Create and send GET request
        let request = ChunkGetRequest::new(*address);
        let message = ChunkMessage::GetRequest(request);
        let message_bytes = message
            .encode()
            .map_err(|e| Error::Network(format!("Failed to encode GET request: {e}")))?;

        node.send_message(&target_peer, CHUNK_PROTOCOL_ID, message_bytes)
            .await
            .map_err(|e| {
                Error::Network(format!("Failed to send GET to peer {target_peer}: {e}"))
            })?;

        // Wait for response from the target
        let timeout = Duration::from_secs(self.config.timeout_secs);
        let deadline = Instant::now() + timeout;

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, events.recv()).await {
                Ok(Ok(P2PEvent::Message {
                    topic,
                    source,
                    data,
                })) if topic == CHUNK_PROTOCOL_ID && source == target_peer => {
                    let response = ChunkMessage::decode(&data).map_err(|e| {
                        Error::Network(format!("Failed to decode GET response: {e}"))
                    })?;
                    match response {
                        ChunkMessage::GetResponse(ChunkGetResponse::Success {
                            address: addr,
                            content,
                        }) => {
                            debug!(
                                "Found chunk {} on saorsa network ({} bytes)",
                                hex::encode(addr),
                                content.len()
                            );
                            return Ok(Some(DataChunk::new(addr, Bytes::from(content))));
                        }
                        ChunkMessage::GetResponse(ChunkGetResponse::NotFound { .. }) => {
                            debug!("Chunk {} not found on saorsa network", hex::encode(address));
                            return Ok(None);
                        }
                        ChunkMessage::GetResponse(ChunkGetResponse::Error(e)) => {
                            return Err(Error::Network(format!(
                                "Remote GET error for {}: {e}",
                                hex::encode(address)
                            )));
                        }
                        _ => {} // Not a GET response, keep waiting
                    }
                }
                Ok(Ok(_)) => {} // Different topic/source, keep waiting
                Ok(Err(_)) | Err(_) => break,
            }
        }

        Err(Error::Network(format!(
            "Timeout waiting for chunk {} after {}s",
            hex::encode(address),
            self.config.timeout_secs
        )))
    }

    /// Store a chunk on the saorsa network via ANT protocol.
    ///
    /// The chunk address is computed as SHA256(content), ensuring content-addressing.
    /// Sends a `ChunkPutRequest` to a connected peer and waits for the
    /// `ChunkPutResponse`.
    ///
    /// # Arguments
    ///
    /// * `content` - The data to store
    ///
    /// # Returns
    ///
    /// The `XorName` address where the chunk was stored.
    ///
    /// # Errors
    ///
    /// Returns an error if the store operation fails.
    pub async fn put_chunk(&self, content: Bytes) -> Result<XorName> {
        debug!("Storing chunk on saorsa network ({} bytes)", content.len());

        let Some(ref node) = self.p2p_node else {
            return Err(Error::Network("P2P node not configured".into()));
        };

        let target_peer = Self::pick_target_peer(node).await?;

        // Subscribe before sending so we don't miss the response
        let mut events = node.subscribe_events();

        // Compute content address using SHA-256
        let address = crate::client::compute_address(&content);

        // Create PUT request with empty payment proof
        let empty_payment = rmp_serde::to_vec(&ant_evm::ProofOfPayment {
            peer_quotes: vec![],
        })
        .map_err(|e| Error::Network(format!("Failed to serialize payment proof: {e}")))?;

        let request = ChunkPutRequest::with_payment(address, content.to_vec(), empty_payment);
        let message = ChunkMessage::PutRequest(request);
        let message_bytes = message
            .encode()
            .map_err(|e| Error::Network(format!("Failed to encode PUT request: {e}")))?;

        // Send to target peer
        node.send_message(&target_peer, CHUNK_PROTOCOL_ID, message_bytes)
            .await
            .map_err(|e| {
                Error::Network(format!("Failed to send PUT to peer {target_peer}: {e}"))
            })?;

        // Wait for response from the target
        let timeout = Duration::from_secs(self.config.timeout_secs);
        let deadline = Instant::now() + timeout;

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, events.recv()).await {
                Ok(Ok(P2PEvent::Message {
                    topic,
                    source,
                    data,
                })) if topic == CHUNK_PROTOCOL_ID && source == target_peer => {
                    let response = ChunkMessage::decode(&data).map_err(|e| {
                        Error::Network(format!("Failed to decode PUT response: {e}"))
                    })?;
                    match response {
                        ChunkMessage::PutResponse(ChunkPutResponse::Success { address: addr }) => {
                            info!(
                                "Chunk stored at address: {} ({} bytes)",
                                hex::encode(addr),
                                content.len()
                            );
                            return Ok(addr);
                        }
                        ChunkMessage::PutResponse(ChunkPutResponse::AlreadyExists {
                            address: addr,
                        }) => {
                            info!("Chunk already exists at address: {}", hex::encode(addr));
                            return Ok(addr);
                        }
                        ChunkMessage::PutResponse(ChunkPutResponse::PaymentRequired {
                            message,
                        }) => {
                            return Err(Error::Network(format!("Payment required: {message}")));
                        }
                        ChunkMessage::PutResponse(ChunkPutResponse::Error(e)) => {
                            return Err(Error::Network(format!(
                                "Remote PUT error for {}: {e}",
                                hex::encode(address)
                            )));
                        }
                        _ => {} // Not a PUT response, keep waiting
                    }
                }
                Ok(Ok(_)) => {} // Different topic/source, keep waiting
                Ok(Err(_)) | Err(_) => break,
            }
        }

        Err(Error::Network(format!(
            "Timeout waiting for store response for {} after {}s",
            hex::encode(address),
            self.config.timeout_secs
        )))
    }

    /// Check if a chunk exists on the saorsa network.
    ///
    /// Implemented via `get_chunk` — returns `Ok(true)` on success,
    /// `Ok(false)` if not found.
    ///
    /// # Arguments
    ///
    /// * `address` - The `XorName` to check
    ///
    /// # Returns
    ///
    /// True if the chunk exists, false otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the network operation fails.
    pub async fn exists(&self, address: &XorName) -> Result<bool> {
        debug!(
            "Checking existence on saorsa network: {}",
            hex::encode(address)
        );
        self.get_chunk(address).await.map(|opt| opt.is_some())
    }

    /// Pick a target peer from the connected peers list.
    async fn pick_target_peer(node: &P2PNode) -> Result<String> {
        let peers = node.connected_peers().await;
        peers
            .into_iter()
            .next()
            .ok_or_else(|| Error::Network("No connected peers available".into()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_quantum_config_default() {
        let config = QuantumConfig::default();
        assert_eq!(config.timeout_secs, DEFAULT_TIMEOUT_SECS);
        assert_eq!(config.replica_count, DEFAULT_REPLICA_COUNT);
        assert!(config.encrypt_data);
    }

    #[test]
    fn test_quantum_client_creation() {
        let client = QuantumClient::with_defaults();
        assert_eq!(client.config.timeout_secs, DEFAULT_TIMEOUT_SECS);
        assert!(client.p2p_node.is_none());
    }

    #[tokio::test]
    async fn test_get_chunk_without_node_fails() {
        let client = QuantumClient::with_defaults();
        let address = [0; 32];

        let result = client.get_chunk(&address).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_put_chunk_without_node_fails() {
        let client = QuantumClient::with_defaults();
        let content = Bytes::from("test data");

        let result = client.put_chunk(content).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_exists_without_node_fails() {
        let client = QuantumClient::with_defaults();
        let address = [0; 32];

        let result = client.exists(&address).await;
        assert!(result.is_err());
    }
}
