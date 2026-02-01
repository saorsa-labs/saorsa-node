//! Chunk message types for the ANT protocol.
//!
//! Chunks are immutable, content-addressed data blocks where the address
//! is the SHA256 hash of the content. Maximum size is 4MB.
//!
//! This module defines the wire protocol messages for chunk operations
//! using bincode serialization for compact, fast encoding.

use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Protocol identifier for chunk operations.
pub const CHUNK_PROTOCOL_ID: &str = "saorsa/ant/chunk/v1";

/// Current protocol version.
///
/// This must stay in sync with the version suffix in [`CHUNK_PROTOCOL_ID`].
/// Future version negotiation will include this in the wire header; for now
/// it is used for documentation and assertions only.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum chunk size in bytes (4MB).
pub const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Maximum wire message size: chunk payload + protocol envelope overhead.
///
/// The envelope includes the bincode discriminant, address (32 bytes),
/// optional payment proof, and length prefixes. 64 KiB of headroom is
/// generous enough for any current message variant.
const MAX_WIRE_MESSAGE_SIZE: u64 = MAX_CHUNK_SIZE as u64 + 64 * 1024;

/// Data type identifier for chunks.
pub const DATA_TYPE_CHUNK: u32 = 0;

/// Content-addressed identifier (32 bytes).
pub type XorName = [u8; 32];

/// Compute the content address (SHA256 hash) for the given data.
///
/// This is the canonical address computation used throughout the protocol.
/// A chunk's address is always `SHA256(content)`.
#[must_use]
pub fn compute_address(content: &[u8]) -> XorName {
    let mut hasher = Sha256::new();
    hasher.update(content);
    let result = hasher.finalize();
    let mut address = [0u8; 32];
    address.copy_from_slice(&result);
    address
}

/// Wrapper enum for all chunk protocol messages.
///
/// Uses a single-byte discriminant for efficient wire encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkMessage {
    /// Request to store a chunk.
    PutRequest(ChunkPutRequest),
    /// Response to a PUT request.
    PutResponse(ChunkPutResponse),
    /// Request to retrieve a chunk.
    GetRequest(ChunkGetRequest),
    /// Response to a GET request.
    GetResponse(ChunkGetResponse),
    /// Request a storage quote.
    QuoteRequest(ChunkQuoteRequest),
    /// Response with a storage quote.
    QuoteResponse(ChunkQuoteResponse),
}

/// Return size-limited bincode options to prevent OOM from malicious input.
///
/// Uses the default bincode v1 byte order and int encoding, but caps the
/// maximum allocation at [`MAX_WIRE_MESSAGE_SIZE`].
fn bincode_options() -> impl Options {
    bincode::options()
        .with_limit(MAX_WIRE_MESSAGE_SIZE)
        .allow_trailing_bytes()
}

impl ChunkMessage {
    /// Encode the message to bytes using bincode.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    #[must_use = "encoded bytes must be sent or stored"]
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        bincode_options()
            .serialize(self)
            .map_err(|e| ProtocolError::SerializationFailed(e.to_string()))
    }

    /// Decode a message from bytes using bincode.
    ///
    /// The deserialization is capped at [`MAX_WIRE_MESSAGE_SIZE`] to prevent
    /// out-of-memory attacks from untrusted peers.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails or the message exceeds the
    /// size limit.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        bincode_options()
            .deserialize(data)
            .map_err(|e| ProtocolError::DeserializationFailed(e.to_string()))
    }
}

// =============================================================================
// PUT Request/Response
// =============================================================================

/// Request to store a chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkPutRequest {
    /// Caller-assigned request ID for correlating the response.
    pub request_id: u64,
    /// The content-addressed identifier (SHA256 of content).
    pub address: XorName,
    /// The chunk data.
    pub content: Vec<u8>,
    /// Optional payment proof (serialized `ProofOfPayment`).
    /// Required for new chunks unless already verified.
    pub payment_proof: Option<Vec<u8>>,
}

impl ChunkPutRequest {
    /// Create a new PUT request.
    #[must_use]
    pub fn new(address: XorName, content: Vec<u8>) -> Self {
        Self {
            request_id: rand::random(),
            address,
            content,
            payment_proof: None,
        }
    }

    /// Create a new PUT request with payment proof.
    #[must_use]
    pub fn with_payment(address: XorName, content: Vec<u8>, payment_proof: Vec<u8>) -> Self {
        Self {
            request_id: rand::random(),
            address,
            content,
            payment_proof: Some(payment_proof),
        }
    }
}

/// Response to a PUT request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkPutResponse {
    /// Chunk stored successfully.
    Success {
        /// Echo of the request ID for correlation.
        request_id: u64,
        /// The address where the chunk was stored.
        address: XorName,
    },
    /// Chunk already exists (idempotent success).
    AlreadyExists {
        /// Echo of the request ID for correlation.
        request_id: u64,
        /// The existing chunk address.
        address: XorName,
    },
    /// Payment is required to store this chunk.
    PaymentRequired {
        /// Echo of the request ID for correlation.
        request_id: u64,
        /// Error message.
        message: String,
    },
    /// An error occurred.
    Error {
        /// Echo of the request ID for correlation.
        request_id: u64,
        /// The protocol error.
        error: ProtocolError,
    },
}

// =============================================================================
// GET Request/Response
// =============================================================================

/// Request to retrieve a chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkGetRequest {
    /// Caller-assigned request ID for correlating the response.
    pub request_id: u64,
    /// The content-addressed identifier to retrieve.
    pub address: XorName,
}

impl ChunkGetRequest {
    /// Create a new GET request.
    #[must_use]
    pub fn new(address: XorName) -> Self {
        Self {
            request_id: rand::random(),
            address,
        }
    }
}

/// Response to a GET request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkGetResponse {
    /// Chunk found and returned.
    Success {
        /// Echo of the request ID for correlation.
        request_id: u64,
        /// The chunk address.
        address: XorName,
        /// The chunk data.
        content: Vec<u8>,
    },
    /// Chunk not found.
    NotFound {
        /// Echo of the request ID for correlation.
        request_id: u64,
        /// The requested address.
        address: XorName,
    },
    /// An error occurred.
    Error {
        /// Echo of the request ID for correlation.
        request_id: u64,
        /// The protocol error.
        error: ProtocolError,
    },
}

// =============================================================================
// Quote Request/Response
// =============================================================================

/// Request a storage quote for a chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkQuoteRequest {
    /// Caller-assigned request ID for correlating the response.
    pub request_id: u64,
    /// The content address of the data to store.
    pub address: XorName,
    /// Size of the data in bytes.
    pub data_size: u64,
    /// Data type identifier (0 for chunks).
    pub data_type: u32,
}

impl ChunkQuoteRequest {
    /// Create a new quote request.
    #[must_use]
    pub fn new(address: XorName, data_size: u64) -> Self {
        Self {
            request_id: rand::random(),
            address,
            data_size,
            data_type: DATA_TYPE_CHUNK,
        }
    }
}

/// Response with a storage quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkQuoteResponse {
    /// Quote generated successfully.
    Success {
        /// Echo of the request ID for correlation.
        request_id: u64,
        /// Serialized `PaymentQuote`.
        quote: Vec<u8>,
    },
    /// Quote generation failed.
    Error {
        /// Echo of the request ID for correlation.
        request_id: u64,
        /// The protocol error.
        error: ProtocolError,
    },
}

// =============================================================================
// Protocol Errors
// =============================================================================

/// Errors that can occur during protocol operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtocolError {
    /// Message serialization failed.
    SerializationFailed(String),
    /// Message deserialization failed.
    DeserializationFailed(String),
    /// Chunk exceeds maximum size.
    ChunkTooLarge {
        /// Size of the chunk in bytes.
        size: usize,
        /// Maximum allowed size.
        max_size: usize,
    },
    /// Content address mismatch (hash(content) != address).
    AddressMismatch {
        /// Expected address.
        expected: XorName,
        /// Actual address computed from content.
        actual: XorName,
    },
    /// Storage operation failed.
    StorageFailed(String),
    /// Payment verification failed.
    PaymentFailed(String),
    /// Quote generation failed.
    QuoteFailed(String),
    /// Internal error.
    Internal(String),
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SerializationFailed(msg) => write!(f, "serialization failed: {msg}"),
            Self::DeserializationFailed(msg) => write!(f, "deserialization failed: {msg}"),
            Self::ChunkTooLarge { size, max_size } => {
                write!(f, "chunk size {size} exceeds maximum {max_size}")
            }
            Self::AddressMismatch { expected, actual } => {
                write!(
                    f,
                    "address mismatch: expected {}, got {}",
                    hex::encode(expected),
                    hex::encode(actual)
                )
            }
            Self::StorageFailed(msg) => write!(f, "storage failed: {msg}"),
            Self::PaymentFailed(msg) => write!(f, "payment failed: {msg}"),
            Self::QuoteFailed(msg) => write!(f, "quote failed: {msg}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_put_request_encode_decode() {
        let address = [0xAB; 32];
        let content = vec![1, 2, 3, 4, 5];
        let request = ChunkPutRequest::new(address, content.clone());
        let request_id = request.request_id;
        let msg = ChunkMessage::PutRequest(request);

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        if let ChunkMessage::PutRequest(req) = decoded {
            assert_eq!(req.request_id, request_id);
            assert_eq!(req.address, address);
            assert_eq!(req.content, content);
            assert!(req.payment_proof.is_none());
        } else {
            panic!("expected PutRequest");
        }
    }

    #[test]
    fn test_put_request_with_payment() {
        let address = [0xAB; 32];
        let content = vec![1, 2, 3, 4, 5];
        let payment = vec![10, 20, 30];
        let request = ChunkPutRequest::with_payment(address, content.clone(), payment.clone());

        assert_eq!(request.address, address);
        assert_eq!(request.content, content);
        assert_eq!(request.payment_proof, Some(payment));
        assert_ne!(request.request_id, 0); // random, extremely unlikely to be 0
    }

    #[test]
    fn test_get_request_encode_decode() {
        let address = [0xCD; 32];
        let request = ChunkGetRequest::new(address);
        let request_id = request.request_id;
        let msg = ChunkMessage::GetRequest(request);

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        if let ChunkMessage::GetRequest(req) = decoded {
            assert_eq!(req.request_id, request_id);
            assert_eq!(req.address, address);
        } else {
            panic!("expected GetRequest");
        }
    }

    #[test]
    fn test_put_response_success() {
        let address = [0xEF; 32];
        let response = ChunkPutResponse::Success {
            request_id: 42,
            address,
        };
        let msg = ChunkMessage::PutResponse(response);

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        if let ChunkMessage::PutResponse(ChunkPutResponse::Success {
            request_id,
            address: addr,
        }) = decoded
        {
            assert_eq!(request_id, 42);
            assert_eq!(addr, address);
        } else {
            panic!("expected PutResponse::Success");
        }
    }

    #[test]
    fn test_get_response_not_found() {
        let address = [0x12; 32];
        let response = ChunkGetResponse::NotFound {
            request_id: 99,
            address,
        };
        let msg = ChunkMessage::GetResponse(response);

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        if let ChunkMessage::GetResponse(ChunkGetResponse::NotFound {
            request_id,
            address: addr,
        }) = decoded
        {
            assert_eq!(request_id, 99);
            assert_eq!(addr, address);
        } else {
            panic!("expected GetResponse::NotFound");
        }
    }

    #[test]
    fn test_quote_request_encode_decode() {
        let address = [0x34; 32];
        let request = ChunkQuoteRequest::new(address, 1024);
        let request_id = request.request_id;
        let msg = ChunkMessage::QuoteRequest(request);

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        if let ChunkMessage::QuoteRequest(req) = decoded {
            assert_eq!(req.request_id, request_id);
            assert_eq!(req.address, address);
            assert_eq!(req.data_size, 1024);
            assert_eq!(req.data_type, DATA_TYPE_CHUNK);
        } else {
            panic!("expected QuoteRequest");
        }
    }

    #[test]
    fn test_protocol_error_display() {
        let err = ProtocolError::ChunkTooLarge {
            size: 5_000_000,
            max_size: MAX_CHUNK_SIZE,
        };
        assert!(err.to_string().contains("5000000"));
        assert!(err.to_string().contains(&MAX_CHUNK_SIZE.to_string()));

        let err = ProtocolError::AddressMismatch {
            expected: [0xAA; 32],
            actual: [0xBB; 32],
        };
        let display = err.to_string();
        assert!(display.contains("address mismatch"));
    }

    #[test]
    fn test_invalid_decode() {
        let invalid_data = vec![0xFF, 0xFF, 0xFF];
        let result = ChunkMessage::decode(&invalid_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_constants() {
        assert_eq!(CHUNK_PROTOCOL_ID, "saorsa/ant/chunk/v1");
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(MAX_CHUNK_SIZE, 4 * 1024 * 1024);
        assert_eq!(DATA_TYPE_CHUNK, 0);
    }
}
