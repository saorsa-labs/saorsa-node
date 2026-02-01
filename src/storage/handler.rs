//! ANT protocol handler for autonomi protocol messages.
//!
//! This handler processes chunk PUT/GET requests with optional payment verification,
//! storing chunks to disk and using the DHT for network-wide retrieval.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    AntProtocol                        │
//! ├─────────────────────────────────────────────────────────┤
//! │  protocol_id() = "saorsa/ant/chunk/v1"                  │
//! │                                                         │
//! │  handle_message(data) ──▶ decode ChunkMessage  │
//! │                                   │                     │
//! │         ┌─────────────────────────┼─────────────────┐  │
//! │         ▼                         ▼                 ▼  │
//! │   ChunkQuoteRequest           ChunkPutRequest    ChunkGetRequest
//! │         │                         │                 │  │
//! │         ▼                         ▼                 ▼  │
//! │   QuoteGenerator          PaymentVerifier    DiskStorage│
//! │         │                         │                 │  │
//! │         └─────────────────────────┴─────────────────┘  │
//! │                           │                             │
//! │                 return Ok(response_bytes)               │
//! └─────────────────────────────────────────────────────────┘
//! ```

use crate::ant_protocol::{
    ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkPutRequest, ChunkPutResponse,
    ChunkQuoteRequest, ChunkQuoteResponse, ProtocolError, CHUNK_PROTOCOL_ID, DATA_TYPE_CHUNK,
    MAX_CHUNK_SIZE,
};
use crate::error::Result;
use crate::payment::{PaymentVerifier, QuoteGenerator};
use crate::storage::disk::DiskStorage;
use bytes::Bytes;
use saorsa_core::{P2PEvent, P2PNode};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// ANT protocol handler.
///
/// Handles chunk PUT/GET/Quote requests using disk storage for persistence
/// and optional payment verification.
pub struct AntProtocol {
    /// Disk storage for chunk persistence.
    storage: Arc<DiskStorage>,
    /// Payment verifier for checking payments.
    payment_verifier: Arc<PaymentVerifier>,
    /// Quote generator for creating storage quotes.
    quote_generator: Arc<QuoteGenerator>,
}

impl AntProtocol {
    /// Create a new ANT protocol handler.
    ///
    /// # Arguments
    ///
    /// * `storage` - Disk storage for chunk persistence
    /// * `payment_verifier` - Payment verifier for validating payments
    /// * `quote_generator` - Quote generator for creating storage quotes
    #[must_use]
    pub fn new(
        storage: Arc<DiskStorage>,
        payment_verifier: Arc<PaymentVerifier>,
        quote_generator: Arc<QuoteGenerator>,
    ) -> Self {
        info!(
            "ANT protocol handler initialized (protocol={})",
            CHUNK_PROTOCOL_ID
        );

        Self {
            storage,
            payment_verifier,
            quote_generator,
        }
    }

    /// Get the protocol identifier.
    #[must_use]
    pub fn protocol_id(&self) -> &'static str {
        CHUNK_PROTOCOL_ID
    }

    /// Handle an incoming protocol message.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw message bytes
    ///
    /// # Returns
    ///
    /// Response bytes, or an error if handling fails.
    ///
    /// # Errors
    ///
    /// Returns an error if message decoding or handling fails.
    pub async fn handle_message(&self, data: &[u8]) -> Result<Bytes> {
        let message = ChunkMessage::decode(data)
            .map_err(|e| crate::error::Error::Protocol(format!("Failed to decode message: {e}")))?;

        let response = match message {
            ChunkMessage::PutRequest(req) => ChunkMessage::PutResponse(self.handle_put(req).await),
            ChunkMessage::GetRequest(req) => ChunkMessage::GetResponse(self.handle_get(req).await),
            ChunkMessage::QuoteRequest(ref req) => {
                ChunkMessage::QuoteResponse(self.handle_quote(req))
            }
            // Response messages shouldn't be received as requests — this
            // indicates a peer routing bug or protocol mismatch.
            other @ (ChunkMessage::PutResponse(_)
            | ChunkMessage::GetResponse(_)
            | ChunkMessage::QuoteResponse(_)) => {
                warn!("Received unexpected response message as request: {other:?}");
                return Err(crate::error::Error::Protocol(
                    "Received response message as request".to_string(),
                ));
            }
        };

        response
            .encode()
            .map(Bytes::from)
            .map_err(|e| crate::error::Error::Protocol(format!("Failed to encode response: {e}")))
    }

    /// Handle a PUT request.
    async fn handle_put(&self, request: ChunkPutRequest) -> ChunkPutResponse {
        let rid = request.request_id;
        let address = request.address;
        debug!("Handling PUT request for {}", hex::encode(address));

        // 1. Validate chunk size
        if request.content.len() > MAX_CHUNK_SIZE {
            return ChunkPutResponse::Error {
                request_id: rid,
                error: ProtocolError::ChunkTooLarge {
                    size: request.content.len(),
                    max_size: MAX_CHUNK_SIZE,
                },
            };
        }

        // 2. Verify payment
        let payment_result = self
            .payment_verifier
            .verify_payment(&address, request.payment_proof.as_deref())
            .await;

        match payment_result {
            Ok(status) if status.can_store() => {
                // Payment verified or cached
            }
            Ok(_) => {
                return ChunkPutResponse::PaymentRequired {
                    request_id: rid,
                    message: "Payment required for new chunk".to_string(),
                };
            }
            Err(e) => {
                return ChunkPutResponse::Error {
                    request_id: rid,
                    error: ProtocolError::PaymentFailed(e.to_string()),
                };
            }
        }

        // 3. Store to disk.
        // DiskStorage::put() is the authoritative check for existence and
        // content-address verification, all under a per-address lock. We rely
        // on its return value to distinguish new stores from duplicates rather
        // than doing a separate exists() call which would be racy (TOCTOU).
        match self.storage.put(&address, &request.content).await {
            Ok(true) => {
                info!(
                    "Stored chunk {} ({} bytes)",
                    hex::encode(address),
                    request.content.len()
                );
                // Record the store in metrics
                self.quote_generator.record_store(DATA_TYPE_CHUNK);
                ChunkPutResponse::Success {
                    request_id: rid,
                    address,
                }
            }
            Ok(false) => {
                debug!("Chunk {} already exists", hex::encode(address));
                ChunkPutResponse::AlreadyExists {
                    request_id: rid,
                    address,
                }
            }
            Err(e) => {
                warn!("Failed to store chunk {}: {}", hex::encode(address), e);
                ChunkPutResponse::Error {
                    request_id: rid,
                    error: ProtocolError::StorageFailed(e.to_string()),
                }
            }
        }
    }

    /// Handle a GET request.
    async fn handle_get(&self, request: ChunkGetRequest) -> ChunkGetResponse {
        let rid = request.request_id;
        let address = request.address;
        debug!("Handling GET request for {}", hex::encode(address));

        match self.storage.get(&address).await {
            Ok(Some(content)) => {
                debug!(
                    "Retrieved chunk {} ({} bytes)",
                    hex::encode(address),
                    content.len()
                );
                ChunkGetResponse::Success {
                    request_id: rid,
                    address,
                    content,
                }
            }
            Ok(None) => {
                debug!("Chunk {} not found", hex::encode(address));
                ChunkGetResponse::NotFound {
                    request_id: rid,
                    address,
                }
            }
            Err(e) => {
                warn!("Failed to retrieve chunk {}: {}", hex::encode(address), e);
                ChunkGetResponse::Error {
                    request_id: rid,
                    error: ProtocolError::StorageFailed(e.to_string()),
                }
            }
        }
    }

    /// Handle a quote request.
    fn handle_quote(&self, request: &ChunkQuoteRequest) -> ChunkQuoteResponse {
        let rid = request.request_id;
        debug!(
            "Handling quote request for {} (size: {})",
            hex::encode(request.address),
            request.data_size
        );

        // Validate data size - data_size is u64, cast carefully
        let data_size_usize = usize::try_from(request.data_size).unwrap_or(usize::MAX);
        if data_size_usize > MAX_CHUNK_SIZE {
            return ChunkQuoteResponse::Error {
                request_id: rid,
                error: ProtocolError::ChunkTooLarge {
                    size: data_size_usize,
                    max_size: MAX_CHUNK_SIZE,
                },
            };
        }

        match self
            .quote_generator
            .create_quote(request.address, data_size_usize, request.data_type)
        {
            Ok(quote) => {
                // Serialize the quote
                match rmp_serde::to_vec(&quote) {
                    Ok(quote_bytes) => ChunkQuoteResponse::Success {
                        request_id: rid,
                        quote: quote_bytes,
                    },
                    Err(e) => ChunkQuoteResponse::Error {
                        request_id: rid,
                        error: ProtocolError::QuoteFailed(format!(
                            "Failed to serialize quote: {e}"
                        )),
                    },
                }
            }
            Err(e) => ChunkQuoteResponse::Error {
                request_id: rid,
                error: ProtocolError::QuoteFailed(e.to_string()),
            },
        }
    }

    /// Get storage statistics.
    #[must_use]
    pub fn storage_stats(&self) -> crate::storage::StorageStats {
        self.storage.stats()
    }

    /// Get payment cache statistics.
    #[must_use]
    pub fn payment_cache_stats(&self) -> crate::payment::CacheStats {
        self.payment_verifier.cache_stats()
    }

    /// Check if a chunk exists locally.
    ///
    /// # Errors
    ///
    /// Returns an error if the filesystem check fails.
    pub async fn exists(&self, address: &[u8; 32]) -> Result<bool> {
        self.storage.exists(address).await
    }

    /// Get a chunk directly from local storage.
    ///
    /// # Errors
    ///
    /// Returns an error if storage access fails.
    pub async fn get_local(&self, address: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        self.storage.get(address).await
    }

    /// Store a chunk directly to local storage (bypasses payment verification).
    ///
    /// This is useful for testing or when payment has been verified elsewhere.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails or content doesn't match address.
    pub async fn put_local(&self, address: &[u8; 32], content: &[u8]) -> Result<bool> {
        self.storage.put(address, content).await
    }

    /// Spawn a background task that routes incoming P2P chunk messages to this
    /// handler and sends responses back to the originating peer.
    ///
    /// This is the shared routing loop used by both the production node and the
    /// E2E test infrastructure.
    ///
    /// Returns a [`JoinHandle`] that should be aborted on shutdown.
    pub fn spawn_routing_task(protocol: Arc<Self>, p2p: Arc<P2PNode>) -> JoinHandle<()> {
        let mut events = p2p.subscribe_events();

        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(P2PEvent::Message {
                        topic,
                        source,
                        data,
                    }) if topic == CHUNK_PROTOCOL_ID => {
                        debug!("Received chunk protocol message from {}", source);
                        let protocol = Arc::clone(&protocol);
                        let p2p = Arc::clone(&p2p);
                        tokio::spawn(async move {
                            match protocol.handle_message(&data).await {
                                Ok(response) => {
                                    if let Err(e) = p2p
                                        .send_message(&source, CHUNK_PROTOCOL_ID, response.to_vec())
                                        .await
                                    {
                                        warn!(
                                            "Failed to send protocol response to {}: {}",
                                            source, e
                                        );
                                    }
                                }
                                Err(e) => {
                                    warn!("Protocol handler error: {}", e);
                                }
                            }
                        });
                    }
                    Ok(_) => {} // Different topic or event type
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(
                            "Protocol routing task lagged, dropped {n} events — \
                             consider increasing broadcast channel capacity"
                        );
                        // Continue processing; lagging is recoverable.
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        debug!("P2P event channel closed, stopping protocol routing");
                        break;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::ant_protocol::compute_address;
    use crate::payment::metrics::QuotingMetricsTracker;
    use crate::payment::{EvmVerifierConfig, PaymentVerifierConfig};
    use crate::storage::DiskStorageConfig;
    use ant_evm::RewardsAddress;
    use tempfile::TempDir;

    async fn create_test_protocol() -> (AntProtocol, TempDir) {
        let temp_dir = TempDir::new().expect("create temp dir");

        let storage_config = DiskStorageConfig {
            root_dir: temp_dir.path().to_path_buf(),
            verify_on_read: true,
            max_chunks: 0,
        };
        let storage = Arc::new(
            DiskStorage::new(storage_config)
                .await
                .expect("create storage"),
        );

        let payment_config = PaymentVerifierConfig {
            evm: EvmVerifierConfig {
                enabled: false, // Disable EVM for tests
                ..Default::default()
            },
            cache_capacity: 100,
        };
        let payment_verifier = Arc::new(PaymentVerifier::new(payment_config));

        let rewards_address = RewardsAddress::new([1u8; 20]);
        let metrics_tracker = QuotingMetricsTracker::new(1000, 100);
        let quote_generator = Arc::new(QuoteGenerator::new(rewards_address, metrics_tracker));

        let protocol = AntProtocol::new(storage, payment_verifier, quote_generator);
        (protocol, temp_dir)
    }

    #[tokio::test]
    async fn test_put_and_get_chunk() {
        let (protocol, _temp) = create_test_protocol().await;

        let content = b"hello world";
        let address = compute_address(content);

        // Create PUT request - with empty payment proof (EVM disabled)
        let put_request = ChunkPutRequest::with_payment(
            address,
            content.to_vec(),
            rmp_serde::to_vec(&ant_evm::ProofOfPayment {
                peer_quotes: vec![],
            })
            .unwrap(),
        );
        let put_msg = ChunkMessage::PutRequest(put_request);
        let put_bytes = put_msg.encode().expect("encode put");

        // Handle PUT
        let response_bytes = protocol
            .handle_message(&put_bytes)
            .await
            .expect("handle put");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        if let ChunkMessage::PutResponse(ChunkPutResponse::Success { address: addr, .. }) = response
        {
            assert_eq!(addr, address);
        } else {
            panic!("expected PutResponse::Success, got: {response:?}");
        }

        // Create GET request
        let get_request = ChunkGetRequest::new(address);
        let get_msg = ChunkMessage::GetRequest(get_request);
        let get_bytes = get_msg.encode().expect("encode get");

        // Handle GET
        let response_bytes = protocol
            .handle_message(&get_bytes)
            .await
            .expect("handle get");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        if let ChunkMessage::GetResponse(ChunkGetResponse::Success {
            address: addr,
            content: data,
            ..
        }) = response
        {
            assert_eq!(addr, address);
            assert_eq!(data, content.to_vec());
        } else {
            panic!("expected GetResponse::Success");
        }
    }

    #[tokio::test]
    async fn test_get_not_found() {
        let (protocol, _temp) = create_test_protocol().await;

        let address = [0xAB; 32];
        let get_request = ChunkGetRequest::new(address);
        let get_msg = ChunkMessage::GetRequest(get_request);
        let get_bytes = get_msg.encode().expect("encode get");

        let response_bytes = protocol
            .handle_message(&get_bytes)
            .await
            .expect("handle get");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        if let ChunkMessage::GetResponse(ChunkGetResponse::NotFound { address: addr, .. }) =
            response
        {
            assert_eq!(addr, address);
        } else {
            panic!("expected GetResponse::NotFound");
        }
    }

    #[tokio::test]
    async fn test_put_address_mismatch() {
        let (protocol, _temp) = create_test_protocol().await;

        let content = b"test content";
        let wrong_address = [0xFF; 32]; // Wrong address

        let put_request = ChunkPutRequest::with_payment(
            wrong_address,
            content.to_vec(),
            rmp_serde::to_vec(&ant_evm::ProofOfPayment {
                peer_quotes: vec![],
            })
            .unwrap(),
        );
        let put_msg = ChunkMessage::PutRequest(put_request);
        let put_bytes = put_msg.encode().expect("encode put");

        let response_bytes = protocol
            .handle_message(&put_bytes)
            .await
            .expect("handle put");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        // Address verification is done by DiskStorage::put(), which returns a
        // StorageFailed error containing "Content address mismatch".
        if let ChunkMessage::PutResponse(ChunkPutResponse::Error {
            error: ProtocolError::StorageFailed(msg),
            ..
        }) = response
        {
            assert!(
                msg.contains("address mismatch"),
                "expected mismatch error, got: {msg}"
            );
        } else {
            panic!("expected StorageFailed error with address mismatch, got: {response:?}");
        }
    }

    #[tokio::test]
    async fn test_put_chunk_too_large() {
        let (protocol, _temp) = create_test_protocol().await;

        // Create oversized content
        let content = vec![0u8; MAX_CHUNK_SIZE + 1];
        let address = compute_address(&content);

        let put_request = ChunkPutRequest::new(address, content);
        let put_msg = ChunkMessage::PutRequest(put_request);
        let put_bytes = put_msg.encode().expect("encode put");

        let response_bytes = protocol
            .handle_message(&put_bytes)
            .await
            .expect("handle put");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        if let ChunkMessage::PutResponse(ChunkPutResponse::Error {
            error: ProtocolError::ChunkTooLarge { .. },
            ..
        }) = response
        {
            // Expected
        } else {
            panic!("expected ChunkTooLarge error");
        }
    }

    #[tokio::test]
    async fn test_put_already_exists() {
        let (protocol, _temp) = create_test_protocol().await;

        let content = b"duplicate content";
        let address = compute_address(content);

        // Store first time
        let put_request = ChunkPutRequest::with_payment(
            address,
            content.to_vec(),
            rmp_serde::to_vec(&ant_evm::ProofOfPayment {
                peer_quotes: vec![],
            })
            .unwrap(),
        );
        let put_msg = ChunkMessage::PutRequest(put_request);
        let put_bytes = put_msg.encode().expect("encode put");

        let _ = protocol
            .handle_message(&put_bytes)
            .await
            .expect("handle put");

        // Store again - should return AlreadyExists
        let response_bytes = protocol
            .handle_message(&put_bytes)
            .await
            .expect("handle put 2");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        if let ChunkMessage::PutResponse(ChunkPutResponse::AlreadyExists {
            address: addr, ..
        }) = response
        {
            assert_eq!(addr, address);
        } else {
            panic!("expected AlreadyExists");
        }
    }

    #[tokio::test]
    async fn test_protocol_id() {
        let (protocol, _temp) = create_test_protocol().await;
        assert_eq!(protocol.protocol_id(), CHUNK_PROTOCOL_ID);
    }

    #[tokio::test]
    async fn test_exists_and_local_access() {
        let (protocol, _temp) = create_test_protocol().await;

        let content = b"local access test";
        let address = compute_address(content);

        assert!(!protocol.exists(&address).await.expect("exists check"));

        protocol
            .put_local(&address, content)
            .await
            .expect("put local");

        assert!(protocol.exists(&address).await.expect("exists check"));

        let retrieved = protocol.get_local(&address).await.expect("get local");
        assert_eq!(retrieved, Some(content.to_vec()));
    }
}
