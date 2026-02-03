//! Chunk message types for the ANT protocol.
//!
//! Chunks are immutable, content-addressed data blocks where the address
//! is the SHA256 hash of the content. Maximum size is 4MB.
//!
//! This module defines the wire protocol messages for chunk operations
//! using postcard serialization for compact, fast encoding.

use serde::{Deserialize, Serialize};

/// Protocol identifier for chunk operations.
pub const CHUNK_PROTOCOL_ID: &str = "saorsa/ant/chunk/v1";

/// Current protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// Maximum chunk size in bytes (4MB).
pub const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Data type identifier for chunks.
pub const DATA_TYPE_CHUNK: u32 = 0;

/// Content-addressed identifier (32 bytes).
pub type XorName = [u8; 32];

/// Enum of all chunk protocol message types.
///
/// Uses a single-byte discriminant for efficient wire encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkMessageBody {
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

/// Wire-format wrapper that pairs a sender-assigned `request_id` with
/// a [`ChunkMessageBody`].
///
/// The sender picks a unique `request_id`; the handler echoes it back
/// in the response so callers can correlate replies by ID rather than
/// by source peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMessage {
    /// Sender-assigned identifier, echoed back in the response.
    pub request_id: u64,
    /// The protocol message body.
    pub body: ChunkMessageBody,
}

impl ChunkMessage {
    /// Encode the message to bytes using postcard.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        postcard::to_stdvec(self)
            .map_err(|e| ProtocolError::SerializationFailed(e.to_string()))
    }

    /// Decode a message from bytes using postcard.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn decode(data: &[u8]) -> Result<Self, ProtocolError> {
        postcard::from_bytes(data)
            .map_err(|e| ProtocolError::DeserializationFailed(e.to_string()))
    }
}

// =============================================================================
// PUT Request/Response
// =============================================================================

/// Request to store a chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkPutRequest {
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
            address,
            content,
            payment_proof: None,
        }
    }

    /// Create a new PUT request with payment proof.
    #[must_use]
    pub fn with_payment(address: XorName, content: Vec<u8>, payment_proof: Vec<u8>) -> Self {
        Self {
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
        /// The address where the chunk was stored.
        address: XorName,
    },
    /// Chunk already exists (idempotent success).
    AlreadyExists {
        /// The existing chunk address.
        address: XorName,
    },
    /// Payment is required to store this chunk.
    PaymentRequired {
        /// Error message.
        message: String,
    },
    /// An error occurred.
    Error(ProtocolError),
}

// =============================================================================
// GET Request/Response
// =============================================================================

/// Request to retrieve a chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkGetRequest {
    /// The content-addressed identifier to retrieve.
    pub address: XorName,
}

impl ChunkGetRequest {
    /// Create a new GET request.
    #[must_use]
    pub fn new(address: XorName) -> Self {
        Self { address }
    }
}

/// Response to a GET request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChunkGetResponse {
    /// Chunk found and returned.
    Success {
        /// The chunk address.
        address: XorName,
        /// The chunk data.
        content: Vec<u8>,
    },
    /// Chunk not found.
    NotFound {
        /// The requested address.
        address: XorName,
    },
    /// An error occurred.
    Error(ProtocolError),
}

// =============================================================================
// Quote Request/Response
// =============================================================================

/// Request a storage quote for a chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkQuoteRequest {
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
        /// Serialized `PaymentQuote`.
        quote: Vec<u8>,
    },
    /// Quote generation failed.
    Error(ProtocolError),
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
        let msg = ChunkMessage {
            request_id: 42,
            body: ChunkMessageBody::PutRequest(request),
        };

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 42);
        if let ChunkMessageBody::PutRequest(req) = decoded.body {
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
    }

    #[test]
    fn test_get_request_encode_decode() {
        let address = [0xCD; 32];
        let request = ChunkGetRequest::new(address);
        let msg = ChunkMessage {
            request_id: 7,
            body: ChunkMessageBody::GetRequest(request),
        };

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 7);
        if let ChunkMessageBody::GetRequest(req) = decoded.body {
            assert_eq!(req.address, address);
        } else {
            panic!("expected GetRequest");
        }
    }

    #[test]
    fn test_put_response_success() {
        let address = [0xEF; 32];
        let response = ChunkPutResponse::Success { address };
        let msg = ChunkMessage {
            request_id: 99,
            body: ChunkMessageBody::PutResponse(response),
        };

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 99);
        if let ChunkMessageBody::PutResponse(ChunkPutResponse::Success { address: addr }) =
            decoded.body
        {
            assert_eq!(addr, address);
        } else {
            panic!("expected PutResponse::Success");
        }
    }

    #[test]
    fn test_get_response_not_found() {
        let address = [0x12; 32];
        let response = ChunkGetResponse::NotFound { address };
        let msg = ChunkMessage {
            request_id: 0,
            body: ChunkMessageBody::GetResponse(response),
        };

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 0);
        if let ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound { address: addr }) =
            decoded.body
        {
            assert_eq!(addr, address);
        } else {
            panic!("expected GetResponse::NotFound");
        }
    }

    #[test]
    fn test_quote_request_encode_decode() {
        let address = [0x34; 32];
        let request = ChunkQuoteRequest::new(address, 1024);
        let msg = ChunkMessage {
            request_id: 1,
            body: ChunkMessageBody::QuoteRequest(request),
        };

        let encoded = msg.encode().expect("encode should succeed");
        let decoded = ChunkMessage::decode(&encoded).expect("decode should succeed");

        assert_eq!(decoded.request_id, 1);
        if let ChunkMessageBody::QuoteRequest(req) = decoded.body {
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
