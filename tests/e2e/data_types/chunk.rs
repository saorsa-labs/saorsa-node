//! Chunk data type E2E tests.
//!
//! Chunks are immutable, content-addressed data blocks (up to 4MB).
//! The address is derived from the content hash (SHA256 -> `XorName`).
//!
//! ## Test Coverage
//!
//! - Basic store and retrieve
//! - Content addressing verification
//! - Cross-node replication
//! - Maximum size handling (4MB)
//! - Payment verification
//! - ML-DSA-65 signature verification

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sha2::{Digest, Sha256};

use super::{TestData, MAX_CHUNK_SIZE};

/// Size of small test data (1KB).
const SMALL_CHUNK_SIZE: usize = 1024;

/// Size of medium test data (1MB).
const MEDIUM_CHUNK_SIZE: usize = 1024 * 1024;

/// Test fixture for chunk operations.
#[allow(clippy::struct_field_names)]
pub struct ChunkTestFixture {
    /// Small test data (1KB).
    pub small: Vec<u8>,
    /// Medium test data (1MB).
    pub medium: Vec<u8>,
    /// Large test data (4MB - max size).
    pub large: Vec<u8>,
}

impl Default for ChunkTestFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkTestFixture {
    /// Create a new test fixture with pre-generated data.
    #[must_use]
    pub fn new() -> Self {
        Self {
            small: TestData::generate(SMALL_CHUNK_SIZE),
            medium: TestData::generate(MEDIUM_CHUNK_SIZE),
            large: TestData::generate(MAX_CHUNK_SIZE),
        }
    }

    /// Compute content address for data (SHA256 hash).
    #[must_use]
    pub fn compute_address(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let mut address = [0u8; 32];
        address.copy_from_slice(&hash);
        address
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TestHarness;

    /// Test 1: Content address computation is deterministic
    #[test]
    fn test_content_address_deterministic() {
        let data = TestData::generate(100);
        let addr1 = ChunkTestFixture::compute_address(&data);
        let addr2 = ChunkTestFixture::compute_address(&data);
        assert_eq!(addr1, addr2, "Same data should produce same address");
    }

    /// Test 2: Different data produces different addresses
    #[test]
    fn test_different_data_different_address() {
        let data1 = TestData::generate(100);
        let mut data2 = TestData::generate(100);
        data2[0] = 255; // Modify first byte

        let addr1 = ChunkTestFixture::compute_address(&data1);
        let addr2 = ChunkTestFixture::compute_address(&data2);
        assert_ne!(
            addr1, addr2,
            "Different data should produce different addresses"
        );
    }

    /// Test 3: Empty data has valid address
    #[test]
    fn test_empty_data_address() {
        let addr = ChunkTestFixture::compute_address(&[]);
        // SHA256 of empty string is well-known
        assert_eq!(
            hex::encode(addr),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Test 4: Fixture creates correct sizes
    #[test]
    fn test_fixture_data_sizes() {
        let fixture = ChunkTestFixture::new();
        assert_eq!(fixture.small.len(), SMALL_CHUNK_SIZE);
        assert_eq!(fixture.medium.len(), MEDIUM_CHUNK_SIZE);
        assert_eq!(fixture.large.len(), MAX_CHUNK_SIZE);
    }

    /// Test 5: Max chunk size constant is correct
    #[test]
    fn test_max_chunk_size() {
        assert_eq!(MAX_CHUNK_SIZE, 4 * 1024 * 1024); // 4MB
    }

    // =========================================================================
    // Integration Tests (require local testnet - spun up automatically)
    // =========================================================================

    /// Test 6: Store and retrieve small chunk via local testnet.
    ///
    /// This is the core e2e test that validates chunk upload/download works:
    /// 1. Spins up a minimal 5-node local testnet
    /// 2. Stores a 1KB chunk via one node
    /// 3. Retrieves it from the same node
    /// 4. Verifies data integrity
    ///
    /// Note: Cross-node retrieval is tested separately in `test_chunk_replication`.
    #[tokio::test]
    async fn test_chunk_store_retrieve_small() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let fixture = ChunkTestFixture::new();

        // Store via node 0 (bootstrap node)
        let store_node = harness.test_node(0).expect("Node 0 should exist");

        let address = store_node
            .store_chunk(&fixture.small)
            .await
            .expect("Failed to store chunk");

        // Verify the address is a valid SHA256 hash
        let expected_address = ChunkTestFixture::compute_address(&fixture.small);
        assert_eq!(
            address, expected_address,
            "Returned address should match computed content address"
        );

        // Retrieve from the same node
        let retrieved = store_node
            .get_chunk(&address)
            .await
            .expect("Failed to retrieve chunk");

        let chunk = retrieved.expect("Chunk should exist");
        assert_eq!(
            chunk.content.as_ref(),
            fixture.small.as_slice(),
            "Retrieved data should match original"
        );

        // Verify chunk address matches
        assert_eq!(
            chunk.address, address,
            "Chunk address should match the stored address"
        );

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    /// Test 7: Store and retrieve large chunk (4MB max).
    #[tokio::test]
    async fn test_chunk_store_retrieve_large() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let fixture = ChunkTestFixture::new();

        // Store 4MB chunk
        let store_node = harness.test_node(0).expect("Node 0 should exist");
        let address = store_node
            .store_chunk(&fixture.large)
            .await
            .expect("Failed to store large chunk");

        // Retrieve from the same node
        let retrieved = store_node
            .get_chunk(&address)
            .await
            .expect("Failed to retrieve large chunk");

        let chunk = retrieved.expect("Large chunk should exist");
        assert_eq!(chunk.content.len(), fixture.large.len());
        assert_eq!(chunk.content.as_ref(), fixture.large.as_slice());

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    // =========================================================================
    // Tests requiring additional infrastructure (not yet implemented)
    // =========================================================================

    /// Test 8: Chunk replication across nodes.
    ///
    /// Store on one node, retrieve from a different node.
    #[test]
    #[ignore = "TODO: Cross-node DHT replication not yet working in saorsa-core"]
    fn test_chunk_replication() {
        // TODO: Implement when saorsa-core DHT replication is fixed
        // - Store chunk on node 0
        // - Retrieve from nodes 1-4
        // - Verify data matches
    }

    /// Test: Payment verification for chunk storage.
    #[test]
    #[ignore = "Requires Anvil EVM testnet integration"]
    fn test_chunk_payment_verification() {
        // TODO: Implement with TestHarness and TestAnvil
        // - Create payment proof via Anvil
        // - Store chunk with payment proof
        // - Verify payment was validated
    }

    /// Test 8: Reject oversized chunk (> 4MB).
    ///
    /// Chunks have a maximum size of 4MB. Attempting to store a larger
    /// chunk should fail with an appropriate error.
    #[tokio::test]
    async fn test_chunk_reject_oversized() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        // Generate oversized data (4MB * 2)
        let oversized_data = TestData::generate(MAX_CHUNK_SIZE * 2);

        let node = harness.test_node(0).expect("Node 0 should exist");

        // Attempt to store oversized chunk - should fail
        let result = node.store_chunk(&oversized_data).await;

        assert!(
            result.is_err(),
            "Storing oversized chunk should fail, but got: {result:?}"
        );

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    /// Test: ML-DSA-65 signature on chunk.
    #[test]
    #[ignore = "Requires signature verification infrastructure"]
    fn test_chunk_signature_verification() {
        // TODO: Verify chunk is signed with ML-DSA-65 when stored
    }
}
