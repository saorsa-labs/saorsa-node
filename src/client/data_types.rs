//! Data type definitions for chunk storage.
//!
//! This module provides the core data types for content-addressed chunk storage
//! on the saorsa network. Chunks are immutable, content-addressed blobs where
//! the address is the SHA256 hash of the content.

use bytes::Bytes;

/// Compute the content address (SHA256 hash) for the given data.
///
/// Delegates to [`crate::ant_protocol::compute_address`], the canonical definition.
#[must_use]
pub fn compute_address(content: &[u8]) -> XorName {
    crate::ant_protocol::compute_address(content)
}

/// A content-addressed identifier (32 bytes).
///
/// The address is computed as SHA256(content) for chunks,
/// ensuring content-addressed storage.
pub type XorName = [u8; 32];

/// A chunk of data with its content-addressed identifier.
///
/// Chunks are the fundamental storage unit in saorsa. They are:
/// - **Immutable**: Content cannot be changed after storage
/// - **Content-addressed**: Address = SHA256(content)
/// - **Paid**: Storage requires EVM payment on Arbitrum
#[derive(Debug, Clone)]
pub struct DataChunk {
    /// The content-addressed identifier (SHA256 of content).
    pub address: XorName,
    /// The raw data content.
    pub content: Bytes,
}

impl DataChunk {
    /// Create a new data chunk.
    ///
    /// Note: This does NOT verify that address == SHA256(content).
    /// Use `from_content` for automatic address computation.
    #[must_use]
    pub fn new(address: XorName, content: Bytes) -> Self {
        Self { address, content }
    }

    /// Create a chunk from content, computing the address automatically.
    #[must_use]
    pub fn from_content(content: Bytes) -> Self {
        let address = compute_address(&content);
        Self { address, content }
    }

    /// Get the size of the chunk in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.content.len()
    }

    /// Verify that the address matches SHA256(content).
    #[must_use]
    pub fn verify(&self) -> bool {
        self.address == compute_address(&self.content)
    }
}

/// Statistics about chunk operations.
#[derive(Debug, Default, Clone)]
pub struct ChunkStats {
    /// Number of chunks stored.
    pub chunks_stored: u64,
    /// Number of chunks retrieved.
    pub chunks_retrieved: u64,
    /// Number of cache hits.
    pub cache_hits: u64,
    /// Number of misses (not found).
    pub misses: u64,
    /// Total bytes stored.
    pub bytes_stored: u64,
    /// Total bytes retrieved.
    pub bytes_retrieved: u64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_data_chunk_creation() {
        let address = [0xAB; 32];
        let content = Bytes::from("test data");
        let chunk = DataChunk::new(address, content.clone());

        assert_eq!(chunk.address, address);
        assert_eq!(chunk.content, content);
        assert_eq!(chunk.size(), 9);
    }

    #[test]
    fn test_chunk_from_content() {
        let content = Bytes::from("hello world");
        let chunk = DataChunk::from_content(content.clone());

        // SHA256 of "hello world"
        let expected: [u8; 32] = [
            0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d,
            0xab, 0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac,
            0xe2, 0xef, 0xcd, 0xe9,
        ];

        assert_eq!(chunk.address, expected);
        assert_eq!(chunk.content, content);
        assert!(chunk.verify());
    }

    #[test]
    fn test_chunk_verify() {
        // Valid chunk
        let content = Bytes::from("test");
        let valid = DataChunk::from_content(content);
        assert!(valid.verify());

        // Invalid chunk (wrong address)
        let invalid = DataChunk::new([0; 32], Bytes::from("test"));
        assert!(!invalid.verify());
    }
}
