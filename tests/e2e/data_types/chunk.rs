//! Chunk data type E2E tests.
//!
//! Chunks are immutable, content-addressed data blocks (up to 4MB).
//! The address is derived from the content hash (BLAKE3 -> `XorName`).
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

    /// Compute content address for data (BLAKE3 hash).
    #[must_use]
    pub fn compute_address(data: &[u8]) -> [u8; 32] {
        ant_node::compute_address(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::{TestHarness, TestNetwork};
    use ant_node::payment::{
        EvmVerifierConfig, PaymentVerifier, PaymentVerifierConfig, PriceFloorConfig,
        QuoteGenerator, QuotingMetricsTracker,
    };
    use ant_node::storage::{AntProtocol, ChunkStore, ChunkStoreConfig};
    use ant_node::ReplicationConfig;
    use evmlib::testnet::Testnet;
    use evmlib::RewardsAddress;
    use rand::seq::SliceRandom;
    use serial_test::serial;

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
        // BLAKE3 of empty string is well-known
        assert_eq!(
            hex::encode(addr),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
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
    #[tokio::test(flavor = "multi_thread")]
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

        // Verify the address is a valid BLAKE3 hash
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
    #[tokio::test(flavor = "multi_thread")]
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
    // Cross-Node Tests (require P2P network)
    // =========================================================================

    /// Test 8: One node asks another to store a max-size chunk (4 MiB) via P2P.
    ///
    /// This test validates the full cross-node protocol flow with the largest
    /// allowed payload, exercising QUIC stream flow-control limits:
    /// 1. Spins up a minimal 5-node local testnet
    /// 2. A regular node (node 3) discovers connected peers
    /// 3. Picks a random peer and sends a `ChunkPutRequest` with a 4 MiB chunk
    /// 4. The target node stores the chunk and responds with success
    /// 5. The regular node then sends a `ChunkGetRequest` to retrieve it
    /// 6. Verifies the 4 MiB data round-trips correctly
    #[tokio::test(flavor = "multi_thread")]
    async fn test_chunk_store_on_remote_node() {
        let harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let fixture = ChunkTestFixture::new();

        // Node 3 (regular) discovers its connected peers and picks a random one
        let requester = harness.test_node(3).expect("Node 3 should exist");
        let peers = requester.connected_peers().await;
        assert!(
            !peers.is_empty(),
            "Node 3 should have at least one connected peer"
        );

        let mut rng = rand::thread_rng();
        let target_peer_id = peers.choose(&mut rng).expect("peers is non-empty");

        // Pre-populate payment cache on the target node so the store is accepted
        let expected_address = ChunkTestFixture::compute_address(&fixture.large);
        harness.prepopulate_payment_cache_for_peer(target_peer_id, &expected_address);

        // Use the max-size (4 MiB) chunk to exercise QUIC stream limits
        let address = requester
            .store_chunk_on_peer(target_peer_id, &fixture.large)
            .await
            .expect("Failed to store max-size chunk on remote node");

        // Verify the returned address matches the expected content hash
        assert_eq!(
            address, expected_address,
            "Returned address should match computed content address"
        );

        // Retrieve the chunk back from the same remote peer via P2P
        let retrieved = requester
            .get_chunk_from_peer(target_peer_id, &address)
            .await
            .expect("Failed to retrieve max-size chunk from remote node");

        let chunk = retrieved.expect("Max-size chunk should exist on remote storage node");
        assert_eq!(
            chunk.content.len(),
            fixture.large.len(),
            "Retrieved chunk size should match original (4 MiB)"
        );
        assert_eq!(
            chunk.content.as_ref(),
            fixture.large.as_slice(),
            "Retrieved data should match original"
        );
        assert_eq!(
            chunk.address, address,
            "Chunk address should match the stored address"
        );

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    /// Test 8: Reject oversized chunk (> 4MB).
    ///
    /// Chunks have a maximum size of 4MB. Attempting to store a larger
    /// chunk should fail with an appropriate error.
    #[tokio::test(flavor = "multi_thread")]
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

    /// Test: Chunks persist across node restarts.
    ///
    /// Validates the full persistence lifecycle:
    /// 1. Stores multiple chunks on a node via the protocol layer
    /// 2. Drops the node's `AntProtocol` (simulating shutdown)
    /// 3. Recreates it from the same data directory (simulating restart)
    /// 4. Verifies all chunks are still retrievable with correct content
    #[tokio::test(flavor = "multi_thread")]
    async fn test_chunk_persist_across_restart() {
        let mut harness = TestHarness::setup_minimal()
            .await
            .expect("Failed to setup test harness");

        let fixture = ChunkTestFixture::new();
        let chunks: &[(&str, &[u8])] = &[
            ("small", &fixture.small),
            ("medium", &fixture.medium),
            ("large", &fixture.large),
        ];

        // Store all chunks on node 0
        let mut addresses = Vec::new();
        {
            let node = harness.test_node(0).expect("Node 0 should exist");
            for (_label, data) in chunks {
                let addr = node.store_chunk(data).await.expect("Failed to store chunk");
                addresses.push(addr);
            }
        }

        // Shut down node 0 completely (simulates node restart):
        // 1. Shut down the replication engine and await its background tasks
        //    so all Arc<ChunkStore> clones are released.
        // 2. Abort the protocol task that holds an Arc<AntProtocol>.
        // 3. Drop the node's own Arc<AntProtocol>.
        // This ensures the chunk store is fully closed before reopening.
        let data_dir = {
            let node = harness
                .network_mut()
                .node_mut(0)
                .expect("Node 0 should exist");
            if let Some(ref mut engine) = node.replication_engine {
                engine.shutdown().await;
            }
            node.replication_engine = None;
            node.replication_shutdown = None;
            let dir = node.data_dir.clone();
            if let Some(handle) = node.protocol_task.take() {
                handle.abort();
                let _ = handle.await;
            }
            node.ant_protocol = None;
            dir
        };

        // Recreate AntProtocol from the same data directory (simulates restart)
        let restart_identity = saorsa_core::identity::NodeIdentity::generate()
            .expect("Failed to generate identity for restart");
        let new_protocol = TestNetwork::create_ant_protocol(&data_dir, None, &restart_identity)
            .await
            .expect("Failed to recreate AntProtocol");
        {
            let node = harness
                .network_mut()
                .node_mut(0)
                .expect("Node 0 should exist");
            node.ant_protocol = Some(Arc::new(new_protocol));
        }

        // Verify all chunks survived the restart
        let node = harness.test_node(0).expect("Node 0 should exist");
        for (i, (label, data)) in chunks.iter().enumerate() {
            let retrieved = node
                .get_chunk(&addresses[i])
                .await
                .expect("Failed to retrieve chunk after restart");

            let chunk = retrieved.expect("Chunk should still exist after restart");
            assert_eq!(
                chunk.content.as_ref(),
                *data,
                "{label} chunk content should match after restart"
            );
            assert_eq!(
                chunk.address, addresses[i],
                "{label} chunk address should match after restart"
            );
        }

        harness
            .teardown()
            .await
            .expect("Failed to teardown harness");
    }

    /// Create an `AntProtocol` with EVM verification enabled, backed by an Anvil testnet.
    ///
    /// Returns (protocol, `temp_dir`, testnet). The testnet must be kept alive for the
    /// duration of the test so Anvil doesn't shut down.
    async fn create_evm_enabled_protocol(
        test_name: &str,
    ) -> color_eyre::Result<(AntProtocol, std::path::PathBuf, Testnet)> {
        let testnet = Testnet::new()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("Failed to start testnet: {e}"))?;
        let network = testnet.to_network();

        let temp_dir = std::env::temp_dir().join(format!("{test_name}_{}", rand::random::<u64>()));
        tokio::fs::create_dir_all(&temp_dir).await?;

        let storage = ChunkStore::new(ChunkStoreConfig {
            root_dir: temp_dir.clone(),
            ..ChunkStoreConfig::test_default()
        })
        .await?;

        let rewards_address = RewardsAddress::new([0x01; 20]);
        let payment_verifier = PaymentVerifier::new(PaymentVerifierConfig {
            evm: EvmVerifierConfig { network },
            cache_capacity: 100,
            close_group_size: ReplicationConfig::default().close_group_size,
            local_rewards_address: rewards_address,
            price_floor: PriceFloorConfig::default(),
        });
        let metrics_tracker = QuotingMetricsTracker::new(100);
        let quote_generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        let protocol = AntProtocol::new(
            Arc::new(storage),
            Arc::new(payment_verifier),
            Arc::new(quote_generator),
        );

        Ok((protocol, temp_dir, testnet))
    }

    /// Test: Chunk is rejected without payment when EVM verification is enabled.
    ///
    /// This test verifies that payment enforcement actually works by:
    /// 1. Creating a protocol handler with EVM verification enabled
    /// 2. Attempting to store a chunk with an empty payment proof
    /// 3. Verifying the request is rejected with `PaymentRequired`
    /// 4. Confirming the chunk was NOT stored
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_chunk_rejected_without_payment() -> color_eyre::Result<()> {
        use ant_node::ant_protocol::{
            ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkMessageBody, ChunkPutRequest,
            ChunkPutResponse,
        };

        let (protocol, temp_dir, _testnet) =
            create_evm_enabled_protocol("test_payment_rejection").await?;

        // Create test data
        let data = b"test data that should be rejected without payment";
        let address = ChunkTestFixture::compute_address(data);

        // Create empty payment proof
        let empty_payment = rmp_serde::to_vec(&evmlib::ProofOfPayment {
            peer_quotes: vec![],
        })?;

        // Create PUT request with empty payment
        let request_id: u64 = rand::random();
        let request = ChunkPutRequest::with_payment(
            address,
            bytes::Bytes::copy_from_slice(data),
            empty_payment,
        );
        let message = ChunkMessage {
            request_id,
            body: ChunkMessageBody::PutRequest(request),
        };
        let message_bytes = message.encode()?;

        // Send PUT request to protocol handler
        let response_bytes = protocol
            .try_handle_request(&message_bytes)
            .await?
            .ok_or_else(|| color_eyre::eyre::eyre!("expected response"))?;
        let response = ChunkMessage::decode(&response_bytes)?;

        // Verify the response indicates payment is required or an error occurred
        match response.body {
            ChunkMessageBody::PutResponse(ChunkPutResponse::PaymentRequired { message }) => {
                // Success - payment was required as expected
                assert!(
                    !message.is_empty(),
                    "PaymentRequired should include a message"
                );
                eprintln!("✓ Chunk rejected with PaymentRequired: {message}");
            }
            ChunkMessageBody::PutResponse(ChunkPutResponse::Error(err)) => {
                // Also acceptable - payment verification failure can be reported as error
                let err_str = format!("{err:?}");
                assert!(
                    err_str.contains("Payment") || err_str.contains("payment"),
                    "Error should mention payment: {err_str}"
                );
                eprintln!("✓ Chunk rejected with Error: {err:?}");
            }
            other => {
                return Err(color_eyre::eyre::eyre!(
                    "Expected PaymentRequired or Error response, got: {other:?}"
                ));
            }
        }

        // Verify the chunk was NOT stored by attempting to retrieve it
        let get_request_id: u64 = rand::random();
        let get_request = ChunkGetRequest::new(address);
        let get_message = ChunkMessage {
            request_id: get_request_id,
            body: ChunkMessageBody::GetRequest(get_request),
        };
        let get_message_bytes = get_message.encode()?;

        let get_response_bytes = protocol
            .try_handle_request(&get_message_bytes)
            .await?
            .ok_or_else(|| color_eyre::eyre::eyre!("expected response"))?;
        let get_response = ChunkMessage::decode(&get_response_bytes)?;

        match get_response.body {
            ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound { .. }) => {
                // Success - chunk was not stored
                eprintln!("✓ Confirmed chunk was NOT stored (GET returned NotFound)");
            }
            other => {
                return Err(color_eyre::eyre::eyre!(
                    "Expected NotFound response (chunk should not be stored), got: {other:?}"
                ));
            }
        }

        eprintln!("\n✅ Payment enforcement verified: chunks are rejected without valid payment when EVM is enabled");

        // Cleanup
        drop(protocol);
        if let Err(e) = tokio::fs::remove_dir_all(&temp_dir).await {
            eprintln!("Failed to cleanup temp directory: {e}");
        }

        Ok(())
    }
}
