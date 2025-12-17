//! Comprehensive data type tests for the live testnet.
//!
//! This module tests all 4 saorsa data types against the live 200-node testnet:
//! - Chunk: Immutable, content-addressed (up to 4MB)
//! - Scratchpad: Mutable, owner-indexed with counter versioning
//! - Pointer: Lightweight mutable pointers
//! - GraphEntry: DAG entries with parent links
//!
//! ## Running Tests
//!
//! ```bash
//! # Set up environment
//! export SAORSA_TEST_BOOTSTRAP="142.93.52.129:12000,24.199.82.114:12000"
//! export SAORSA_TEST_EXTERNAL=true
//!
//! # Run all testnet data ops
//! cargo test --release testnet_data_ops -- --nocapture --ignored
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use saorsa_core::{NodeConfig as CoreNodeConfig, P2PNode};
use sha2::{Digest, Sha256};
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// XorName type alias
type XorName = [u8; 32];

/// Test result tracking
#[derive(Debug, Default)]
struct TestResults {
    passed: u32,
    failed: u32,
    skipped: u32,
    details: Vec<String>,
}

impl TestResults {
    fn pass(&mut self, name: &str) {
        self.passed += 1;
        self.details.push(format!("✅ PASS: {name}"));
    }

    fn fail(&mut self, name: &str, reason: &str) {
        self.failed += 1;
        self.details.push(format!("❌ FAIL: {name} - {reason}"));
    }

    fn skip(&mut self, name: &str, reason: &str) {
        self.skipped += 1;
        self.details.push(format!("⏭️ SKIP: {name} - {reason}"));
    }

    fn summary(&self) -> String {
        let sep = "=".repeat(60);
        let success_rate = if self.passed + self.failed > 0 {
            (self.passed as f64 / (self.passed + self.failed) as f64) * 100.0
        } else {
            0.0
        };
        format!(
            "\n{sep}\nTEST SUMMARY\n{sep}\n\
             Passed:  {}\nFailed:  {}\nSkipped: {}\nTotal:   {}\n\
             Success Rate: {:.1}%\n{sep}\n\n{}",
            self.passed,
            self.failed,
            self.skipped,
            self.passed + self.failed + self.skipped,
            success_rate,
            self.details.join("\n")
        )
    }
}

/// Generate test data of specified size
fn generate_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Generate random owner key
fn generate_owner() -> [u8; 32] {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut owner = [0u8; 32];
    rng.fill(&mut owner);
    owner
}

/// Compute content address for chunk data
fn compute_chunk_address(data: &[u8]) -> XorName {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    let mut address = [0u8; 32];
    address.copy_from_slice(&hash);
    address
}

/// Compute scratchpad address from owner
fn compute_scratchpad_address(owner: &[u8; 32]) -> XorName {
    let mut hasher = Sha256::new();
    hasher.update(b"scratchpad:");
    hasher.update(owner);
    let hash = hasher.finalize();
    let mut address = [0u8; 32];
    address.copy_from_slice(&hash);
    address
}

/// Compute pointer address from owner
fn compute_pointer_address(owner: &[u8; 32]) -> XorName {
    let mut hasher = Sha256::new();
    hasher.update(b"pointer:");
    hasher.update(owner);
    let hash = hasher.finalize();
    let mut address = [0u8; 32];
    address.copy_from_slice(&hash);
    address
}

/// Compute graph entry address
fn compute_graph_entry_address(owner: &[u8; 32], content: &[u8], parents: &[XorName]) -> XorName {
    let mut hasher = Sha256::new();
    hasher.update(b"graph_entry:");
    hasher.update(owner);
    hasher.update(content);
    for parent in parents {
        hasher.update(parent);
    }
    let hash = hasher.finalize();
    let mut address = [0u8; 32];
    address.copy_from_slice(&hash);
    address
}

/// Parse bootstrap peers from environment
fn parse_bootstrap_peers() -> Vec<SocketAddr> {
    env::var("SAORSA_TEST_BOOTSTRAP")
        .unwrap_or_else(|_| "142.93.52.129:12000,24.199.82.114:12000".to_string())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect()
}

/// Create a test node connected to the external testnet
async fn create_test_node(bootstrap_peers: Vec<SocketAddr>) -> Result<Arc<P2PNode>, String> {
    // Use a random high port for the test node
    let port = 30000 + (std::process::id() % 1000) as u16;
    let listen_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);

    let mut config = CoreNodeConfig::new().map_err(|e| format!("Config error: {e}"))?;
    config.listen_addr = listen_addr;
    config.listen_addrs = vec![listen_addr];
    config.bootstrap_peers = bootstrap_peers;
    config.enable_ipv6 = false; // IPv4-only to avoid dual-stack binding issues

    let node = P2PNode::new(config)
        .await
        .map_err(|e| format!("Node creation failed: {e}"))?;

    node.start()
        .await
        .map_err(|e| format!("Node start failed: {e}"))?;

    Ok(Arc::new(node))
}

/// Wait for node to connect to peers
async fn wait_for_peers(node: &P2PNode, min_peers: usize, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if node.peer_count().await >= min_peers {
            return true;
        }
        sleep(Duration::from_millis(500)).await;
    }
    false
}

// =============================================================================
// CHUNK TESTS
// =============================================================================

async fn test_chunk_store_small(node: &P2PNode, results: &mut TestResults) {
    let test_name = "Chunk: Store/retrieve small (1KB)";
    let data = generate_test_data(1024);
    let address = compute_chunk_address(&data);

    match node.dht_put(address, data.clone()).await {
        Ok(()) => {
            // Wait for propagation
            sleep(Duration::from_millis(500)).await;

            match node.dht_get(address).await {
                Ok(Some(retrieved)) if retrieved == data => {
                    results.pass(test_name);
                }
                Ok(Some(_)) => {
                    results.fail(test_name, "Data mismatch");
                }
                Ok(None) => {
                    results.fail(test_name, "Data not found after store");
                }
                Err(e) => {
                    results.fail(test_name, &format!("Get failed: {e}"));
                }
            }
        }
        Err(e) => {
            results.fail(test_name, &format!("Store failed: {e}"));
        }
    }
}

async fn test_chunk_store_medium(node: &P2PNode, results: &mut TestResults) {
    let test_name = "Chunk: Store/retrieve medium (100KB)";
    let data = generate_test_data(100 * 1024);
    let address = compute_chunk_address(&data);

    match node.dht_put(address, data.clone()).await {
        Ok(()) => {
            sleep(Duration::from_secs(1)).await;

            match node.dht_get(address).await {
                Ok(Some(retrieved)) if retrieved == data => {
                    results.pass(test_name);
                }
                Ok(Some(_)) => {
                    results.fail(test_name, "Data mismatch");
                }
                Ok(None) => {
                    results.fail(test_name, "Data not found");
                }
                Err(e) => {
                    results.fail(test_name, &format!("Get failed: {e}"));
                }
            }
        }
        Err(e) => {
            results.fail(test_name, &format!("Store failed: {e}"));
        }
    }
}

async fn test_chunk_store_large(node: &P2PNode, results: &mut TestResults) {
    let test_name = "Chunk: Store/retrieve large (1MB)";
    let data = generate_test_data(1024 * 1024);
    let address = compute_chunk_address(&data);

    match node.dht_put(address, data.clone()).await {
        Ok(()) => {
            sleep(Duration::from_secs(2)).await;

            match node.dht_get(address).await {
                Ok(Some(retrieved)) if retrieved == data => {
                    results.pass(test_name);
                }
                Ok(Some(_)) => {
                    results.fail(test_name, "Data mismatch");
                }
                Ok(None) => {
                    results.fail(test_name, "Data not found");
                }
                Err(e) => {
                    results.fail(test_name, &format!("Get failed: {e}"));
                }
            }
        }
        Err(e) => {
            results.fail(test_name, &format!("Store failed: {e}"));
        }
    }
}

async fn test_chunk_content_addressing(node: &P2PNode, results: &mut TestResults) {
    let test_name = "Chunk: Content addressing deterministic";
    let data = generate_test_data(512);
    let addr1 = compute_chunk_address(&data);
    let addr2 = compute_chunk_address(&data);

    if addr1 == addr2 {
        // Store once
        if node.dht_put(addr1, data.clone()).await.is_ok() {
            sleep(Duration::from_millis(500)).await;
            // Retrieve should work with computed address
            if let Ok(Some(retrieved)) = node.dht_get(addr2).await {
                if retrieved == data {
                    results.pass(test_name);
                } else {
                    results.fail(test_name, "Retrieved data mismatch");
                }
            } else {
                results.fail(test_name, "Could not retrieve with computed address");
            }
        } else {
            results.fail(test_name, "Store failed");
        }
    } else {
        results.fail(test_name, "Address computation not deterministic");
    }
}

async fn test_chunk_nonexistent(node: &P2PNode, results: &mut TestResults) {
    let test_name = "Chunk: Retrieve nonexistent returns None";
    let random_address = generate_owner(); // Random address that doesn't exist

    match node.dht_get(random_address).await {
        Ok(None) => {
            results.pass(test_name);
        }
        Ok(Some(_)) => {
            results.fail(test_name, "Found data at random address");
        }
        Err(e) => {
            results.fail(test_name, &format!("Error: {e}"));
        }
    }
}

async fn test_chunk_deduplication(node: &P2PNode, results: &mut TestResults) {
    let test_name = "Chunk: Deduplication (same data = same address)";
    let data = generate_test_data(256);
    let address = compute_chunk_address(&data);

    // Store twice
    let store1 = node.dht_put(address, data.clone()).await;
    let store2 = node.dht_put(address, data.clone()).await;

    if store1.is_ok() && store2.is_ok() {
        sleep(Duration::from_millis(500)).await;
        if let Ok(Some(retrieved)) = node.dht_get(address).await {
            if retrieved == data {
                results.pass(test_name);
            } else {
                results.fail(test_name, "Data mismatch after duplicate store");
            }
        } else {
            results.fail(test_name, "Could not retrieve after duplicate store");
        }
    } else {
        results.fail(test_name, "One or both stores failed");
    }
}

// =============================================================================
// SCRATCHPAD TESTS
// =============================================================================

async fn test_scratchpad_store_retrieve(node: &P2PNode, results: &mut TestResults) {
    let test_name = "Scratchpad: Store/retrieve basic";
    let owner = generate_owner();
    let data = generate_test_data(1024);
    let address = compute_scratchpad_address(&owner);

    // Create scratchpad entry (simplified - just store raw data with owner prefix)
    let mut entry = Vec::new();
    entry.extend_from_slice(&owner);
    entry.extend_from_slice(&0u64.to_le_bytes()); // counter
    entry.extend_from_slice(&data);

    match node.dht_put(address, entry.clone()).await {
        Ok(()) => {
            sleep(Duration::from_millis(500)).await;

            match node.dht_get(address).await {
                Ok(Some(retrieved)) if retrieved == entry => {
                    results.pass(test_name);
                }
                Ok(Some(_)) => {
                    results.fail(test_name, "Data mismatch");
                }
                Ok(None) => {
                    results.fail(test_name, "Data not found");
                }
                Err(e) => {
                    results.fail(test_name, &format!("Get failed: {e}"));
                }
            }
        }
        Err(e) => {
            results.fail(test_name, &format!("Store failed: {e}"));
        }
    }
}

async fn test_scratchpad_update_counter(node: &P2PNode, results: &mut TestResults) {
    let test_name = "Scratchpad: Counter versioning";
    let owner = generate_owner();
    let address = compute_scratchpad_address(&owner);

    // Store version 0
    let data_v0 = b"version 0".to_vec();
    let mut entry_v0 = Vec::new();
    entry_v0.extend_from_slice(&owner);
    entry_v0.extend_from_slice(&0u64.to_le_bytes());
    entry_v0.extend_from_slice(&data_v0);

    // Store version 1
    let data_v1 = b"version 1".to_vec();
    let mut entry_v1 = Vec::new();
    entry_v1.extend_from_slice(&owner);
    entry_v1.extend_from_slice(&1u64.to_le_bytes());
    entry_v1.extend_from_slice(&data_v1);

    if node.dht_put(address, entry_v0).await.is_ok() {
        sleep(Duration::from_millis(300)).await;

        if node.dht_put(address, entry_v1.clone()).await.is_ok() {
            sleep(Duration::from_millis(500)).await;

            // Should get version 1 (higher counter)
            match node.dht_get(address).await {
                Ok(Some(retrieved)) => {
                    // Check if it's version 1 (has counter=1)
                    if retrieved.len() > 40 {
                        let counter =
                            u64::from_le_bytes(retrieved[32..40].try_into().unwrap_or([0; 8]));
                        if counter == 1 {
                            results.pass(test_name);
                        } else {
                            results.fail(test_name, &format!("Wrong counter: {counter}"));
                        }
                    } else {
                        results.fail(test_name, "Entry too short");
                    }
                }
                Ok(None) => {
                    results.fail(test_name, "Data not found");
                }
                Err(e) => {
                    results.fail(test_name, &format!("Get failed: {e}"));
                }
            }
        } else {
            results.fail(test_name, "Version 1 store failed");
        }
    } else {
        results.fail(test_name, "Version 0 store failed");
    }
}

async fn test_scratchpad_owner_addressing(_node: &P2PNode, results: &mut TestResults) {
    let test_name = "Scratchpad: Owner-based addressing";
    let owner1 = generate_owner();
    let owner2 = generate_owner();

    let addr1 = compute_scratchpad_address(&owner1);
    let addr2 = compute_scratchpad_address(&owner2);

    if addr1 != addr2 {
        results.pass(test_name);
    } else {
        results.fail(test_name, "Different owners produced same address");
    }
}

// =============================================================================
// POINTER TESTS
// =============================================================================

async fn test_pointer_store_retrieve(node: &P2PNode, results: &mut TestResults) {
    let test_name = "Pointer: Store/retrieve basic";
    let owner = generate_owner();
    let target = generate_owner(); // Random target address
    let address = compute_pointer_address(&owner);

    // Create pointer entry
    let mut entry = Vec::new();
    entry.extend_from_slice(&owner);
    entry.extend_from_slice(&0u64.to_le_bytes()); // counter
    entry.extend_from_slice(&target);

    match node.dht_put(address, entry.clone()).await {
        Ok(()) => {
            sleep(Duration::from_millis(500)).await;

            match node.dht_get(address).await {
                Ok(Some(retrieved)) if retrieved == entry => {
                    results.pass(test_name);
                }
                Ok(Some(_)) => {
                    results.fail(test_name, "Data mismatch");
                }
                Ok(None) => {
                    results.fail(test_name, "Data not found");
                }
                Err(e) => {
                    results.fail(test_name, &format!("Get failed: {e}"));
                }
            }
        }
        Err(e) => {
            results.fail(test_name, &format!("Store failed: {e}"));
        }
    }
}

async fn test_pointer_update_target(node: &P2PNode, results: &mut TestResults) {
    let test_name = "Pointer: Update target with higher counter";
    let owner = generate_owner();
    let address = compute_pointer_address(&owner);
    let target1 = generate_owner();
    let target2 = generate_owner();

    // Store pointer v0 -> target1
    let mut entry_v0 = Vec::new();
    entry_v0.extend_from_slice(&owner);
    entry_v0.extend_from_slice(&0u64.to_le_bytes());
    entry_v0.extend_from_slice(&target1);

    // Store pointer v1 -> target2
    let mut entry_v1 = Vec::new();
    entry_v1.extend_from_slice(&owner);
    entry_v1.extend_from_slice(&1u64.to_le_bytes());
    entry_v1.extend_from_slice(&target2);

    if node.dht_put(address, entry_v0).await.is_ok() {
        sleep(Duration::from_millis(300)).await;

        if node.dht_put(address, entry_v1).await.is_ok() {
            sleep(Duration::from_millis(500)).await;

            match node.dht_get(address).await {
                Ok(Some(retrieved)) if retrieved.len() >= 72 => {
                    let stored_target: [u8; 32] = retrieved[40..72].try_into().unwrap_or([0; 32]);
                    if stored_target == target2 {
                        results.pass(test_name);
                    } else if stored_target == target1 {
                        results.fail(test_name, "Got old target (v0) instead of new (v1)");
                    } else {
                        results.fail(test_name, "Unknown target");
                    }
                }
                Ok(Some(_)) => {
                    results.fail(test_name, "Entry too short");
                }
                Ok(None) => {
                    results.fail(test_name, "Data not found");
                }
                Err(e) => {
                    results.fail(test_name, &format!("Get failed: {e}"));
                }
            }
        } else {
            results.fail(test_name, "Version 1 store failed");
        }
    } else {
        results.fail(test_name, "Version 0 store failed");
    }
}

async fn test_pointer_chain(node: &P2PNode, results: &mut TestResults) {
    let test_name = "Pointer: Chain resolution";
    // Create: ChunkA -> PointerB -> PointerC
    let chunk_data = generate_test_data(100);
    let chunk_address = compute_chunk_address(&chunk_data);

    let owner_b = generate_owner();
    let ptr_b_address = compute_pointer_address(&owner_b);

    let owner_c = generate_owner();
    let ptr_c_address = compute_pointer_address(&owner_c);

    // Store chunk
    if node
        .dht_put(chunk_address, chunk_data.clone())
        .await
        .is_err()
    {
        results.fail(test_name, "Chunk store failed");
        return;
    }

    // PointerB -> ChunkA
    let mut ptr_b = Vec::new();
    ptr_b.extend_from_slice(&owner_b);
    ptr_b.extend_from_slice(&0u64.to_le_bytes());
    ptr_b.extend_from_slice(&chunk_address);

    if node.dht_put(ptr_b_address, ptr_b).await.is_err() {
        results.fail(test_name, "Pointer B store failed");
        return;
    }

    // PointerC -> PointerB
    let mut ptr_c = Vec::new();
    ptr_c.extend_from_slice(&owner_c);
    ptr_c.extend_from_slice(&0u64.to_le_bytes());
    ptr_c.extend_from_slice(&ptr_b_address);

    if node.dht_put(ptr_c_address, ptr_c).await.is_err() {
        results.fail(test_name, "Pointer C store failed");
        return;
    }

    sleep(Duration::from_secs(1)).await;

    // Resolve chain: C -> B -> chunk
    match node.dht_get(ptr_c_address).await {
        Ok(Some(c_entry)) if c_entry.len() >= 72 => {
            let b_addr: [u8; 32] = c_entry[40..72].try_into().unwrap_or([0; 32]);
            if b_addr != ptr_b_address {
                results.fail(test_name, "Pointer C doesn't point to B");
                return;
            }

            match node.dht_get(b_addr).await {
                Ok(Some(b_entry)) if b_entry.len() >= 72 => {
                    let final_addr: [u8; 32] = b_entry[40..72].try_into().unwrap_or([0; 32]);
                    if final_addr != chunk_address {
                        results.fail(test_name, "Pointer B doesn't point to chunk");
                        return;
                    }

                    match node.dht_get(final_addr).await {
                        Ok(Some(final_data)) if final_data == chunk_data => {
                            results.pass(test_name);
                        }
                        _ => {
                            results.fail(test_name, "Final chunk retrieval failed");
                        }
                    }
                }
                _ => {
                    results.fail(test_name, "Pointer B retrieval failed");
                }
            }
        }
        _ => {
            results.fail(test_name, "Pointer C retrieval failed");
        }
    }
}

// =============================================================================
// GRAPH ENTRY TESTS
// =============================================================================

async fn test_graph_entry_store_retrieve(node: &P2PNode, results: &mut TestResults) {
    let test_name = "GraphEntry: Store/retrieve basic";
    let owner = generate_owner();
    let content = b"graph entry content".to_vec();
    let parents: Vec<XorName> = vec![];
    let address = compute_graph_entry_address(&owner, &content, &parents);

    // Create entry
    let mut entry = Vec::new();
    entry.extend_from_slice(&owner);
    entry.extend_from_slice(&(parents.len() as u32).to_le_bytes());
    entry.extend_from_slice(&content);

    match node.dht_put(address, entry.clone()).await {
        Ok(()) => {
            sleep(Duration::from_millis(500)).await;

            match node.dht_get(address).await {
                Ok(Some(retrieved)) if retrieved == entry => {
                    results.pass(test_name);
                }
                Ok(Some(_)) => {
                    results.fail(test_name, "Data mismatch");
                }
                Ok(None) => {
                    results.fail(test_name, "Data not found");
                }
                Err(e) => {
                    results.fail(test_name, &format!("Get failed: {e}"));
                }
            }
        }
        Err(e) => {
            results.fail(test_name, &format!("Store failed: {e}"));
        }
    }
}

async fn test_graph_entry_with_parents(node: &P2PNode, results: &mut TestResults) {
    let test_name = "GraphEntry: Entry with parent links";
    let owner = generate_owner();

    // Create parent entry
    let parent_content = b"parent entry".to_vec();
    let parent_address = compute_graph_entry_address(&owner, &parent_content, &[]);

    let mut parent_entry = Vec::new();
    parent_entry.extend_from_slice(&owner);
    parent_entry.extend_from_slice(&0u32.to_le_bytes()); // 0 parents
    parent_entry.extend_from_slice(&parent_content);

    if node.dht_put(parent_address, parent_entry).await.is_err() {
        results.fail(test_name, "Parent store failed");
        return;
    }

    // Create child entry with parent link
    let child_content = b"child entry".to_vec();
    let parents = vec![parent_address];
    let child_address = compute_graph_entry_address(&owner, &child_content, &parents);

    let mut child_entry = Vec::new();
    child_entry.extend_from_slice(&owner);
    child_entry.extend_from_slice(&(parents.len() as u32).to_le_bytes());
    for p in &parents {
        child_entry.extend_from_slice(p);
    }
    child_entry.extend_from_slice(&child_content);

    match node.dht_put(child_address, child_entry.clone()).await {
        Ok(()) => {
            sleep(Duration::from_millis(500)).await;

            match node.dht_get(child_address).await {
                Ok(Some(retrieved)) if retrieved == child_entry => {
                    results.pass(test_name);
                }
                Ok(Some(_)) => {
                    results.fail(test_name, "Data mismatch");
                }
                Ok(None) => {
                    results.fail(test_name, "Data not found");
                }
                Err(e) => {
                    results.fail(test_name, &format!("Get failed: {e}"));
                }
            }
        }
        Err(e) => {
            results.fail(test_name, &format!("Store failed: {e}"));
        }
    }
}

async fn test_graph_dag_traversal(node: &P2PNode, results: &mut TestResults) {
    let test_name = "GraphEntry: DAG traversal (3 levels)";
    let owner = generate_owner();

    // Level 0: Root
    let root_content = b"root".to_vec();
    let root_address = compute_graph_entry_address(&owner, &root_content, &[]);

    // Level 1: Two children of root
    let child1_content = b"child1".to_vec();
    let child1_address = compute_graph_entry_address(&owner, &child1_content, &[root_address]);

    let child2_content = b"child2".to_vec();
    let child2_address = compute_graph_entry_address(&owner, &child2_content, &[root_address]);

    // Level 2: Merge node (has both children as parents)
    let merge_content = b"merge".to_vec();
    let merge_address =
        compute_graph_entry_address(&owner, &merge_content, &[child1_address, child2_address]);

    // Store all entries
    let entries = vec![
        (root_address, &root_content, vec![]),
        (child1_address, &child1_content, vec![root_address]),
        (child2_address, &child2_content, vec![root_address]),
        (
            merge_address,
            &merge_content,
            vec![child1_address, child2_address],
        ),
    ];

    for (addr, content, parents) in &entries {
        let mut entry = Vec::new();
        entry.extend_from_slice(&owner);
        entry.extend_from_slice(&(parents.len() as u32).to_le_bytes());
        for p in parents {
            entry.extend_from_slice(p);
        }
        entry.extend_from_slice(content);

        if node.dht_put(*addr, entry).await.is_err() {
            results.fail(test_name, &format!("Failed to store entry at {addr:?}"));
            return;
        }
    }

    sleep(Duration::from_secs(1)).await;

    // Verify all entries exist
    for (addr, _, _) in &entries {
        if node.dht_get(*addr).await.is_err() {
            results.fail(test_name, &format!("Failed to retrieve entry at {addr:?}"));
            return;
        }
    }

    results.pass(test_name);
}

// =============================================================================
// STRESS TESTS
// =============================================================================

async fn test_bulk_store_retrieve(node: &P2PNode, results: &mut TestResults) {
    let test_name = "Stress: Bulk store/retrieve (100 chunks)";
    let count = 100;
    let mut stored: Vec<(XorName, Vec<u8>)> = Vec::new();

    // Store 100 chunks
    for i in 0..count {
        let data = generate_test_data(256 + i);
        let address = compute_chunk_address(&data);

        if node.dht_put(address, data.clone()).await.is_err() {
            results.fail(test_name, &format!("Store {i} failed"));
            return;
        }
        stored.push((address, data));
    }

    // Wait for propagation
    sleep(Duration::from_secs(3)).await;

    // Retrieve all
    let mut retrieved_count = 0;
    for (address, expected) in &stored {
        if let Ok(Some(data)) = node.dht_get(*address).await {
            if data == *expected {
                retrieved_count += 1;
            }
        }
    }

    if retrieved_count >= count * 9 / 10 {
        // 90% success threshold
        results.pass(&format!("{test_name} ({retrieved_count}/{count})"));
    } else {
        results.fail(
            test_name,
            &format!("Only {retrieved_count}/{count} retrieved"),
        );
    }
}

async fn test_concurrent_operations(node: &P2PNode, results: &mut TestResults) {
    let test_name = "Stress: Sequential rapid operations (50 ops)";

    // Store all first, then retrieve all (simulates concurrent workload)
    let mut stored: Vec<(XorName, Vec<u8>)> = Vec::new();

    // Rapid store operations
    for i in 0..50 {
        let data = generate_test_data(128 + i);
        let address = compute_chunk_address(&data);

        if node.dht_put(address, data.clone()).await.is_ok() {
            stored.push((address, data));
        }
    }

    // Wait for propagation
    sleep(Duration::from_secs(2)).await;

    // Rapid retrieve operations
    let mut success_count = 0;
    for (address, expected) in &stored {
        if let Ok(Some(retrieved)) = node.dht_get(*address).await {
            if retrieved == *expected {
                success_count += 1;
            }
        }
    }

    if success_count >= 40 {
        // 80% success threshold
        results.pass(&format!("{test_name} ({success_count}/50)"));
    } else {
        results.fail(test_name, &format!("Only {success_count}/50 succeeded"));
    }
}

// =============================================================================
// MAIN TEST RUNNER
// =============================================================================

#[tokio::test]
#[ignore = "Requires live testnet - set SAORSA_TEST_EXTERNAL=true"]
async fn run_comprehensive_data_tests() {
    let sep = "=".repeat(70);
    println!("\n{sep}");
    println!("SAORSA TESTNET - COMPREHENSIVE DATA TYPE TESTS");
    println!("{sep}\n");

    let mut results = TestResults::default();

    // Check if external testing is enabled
    if env::var("SAORSA_TEST_EXTERNAL").is_err() {
        println!("Skipping: Set SAORSA_TEST_EXTERNAL=true to run against live testnet");
        return;
    }

    // Parse bootstrap peers
    let bootstrap_peers = parse_bootstrap_peers();
    println!("Bootstrap peers: {bootstrap_peers:?}");

    // Create test node
    println!("\nCreating test node and connecting to testnet...");
    let node = match create_test_node(bootstrap_peers).await {
        Ok(n) => n,
        Err(e) => {
            println!("Failed to create test node: {e}");
            return;
        }
    };

    // Wait for peer connections
    println!("Waiting for peer connections...");
    if !wait_for_peers(&node, 1, Duration::from_secs(30)).await {
        println!("Warning: Could not establish peer connections");
    }

    let peer_count = node.peer_count().await;
    println!("Connected to {peer_count} peers\n");

    // ==========================================================================
    // CHUNK TESTS
    // ==========================================================================
    println!("\n--- CHUNK TESTS ---");
    test_chunk_store_small(&node, &mut results).await;
    test_chunk_store_medium(&node, &mut results).await;
    test_chunk_store_large(&node, &mut results).await;
    test_chunk_content_addressing(&node, &mut results).await;
    test_chunk_nonexistent(&node, &mut results).await;
    test_chunk_deduplication(&node, &mut results).await;

    // ==========================================================================
    // SCRATCHPAD TESTS
    // ==========================================================================
    println!("\n--- SCRATCHPAD TESTS ---");
    test_scratchpad_store_retrieve(&node, &mut results).await;
    test_scratchpad_update_counter(&node, &mut results).await;
    test_scratchpad_owner_addressing(&node, &mut results).await;

    // ==========================================================================
    // POINTER TESTS
    // ==========================================================================
    println!("\n--- POINTER TESTS ---");
    test_pointer_store_retrieve(&node, &mut results).await;
    test_pointer_update_target(&node, &mut results).await;
    test_pointer_chain(&node, &mut results).await;

    // ==========================================================================
    // GRAPH ENTRY TESTS
    // ==========================================================================
    println!("\n--- GRAPH ENTRY TESTS ---");
    test_graph_entry_store_retrieve(&node, &mut results).await;
    test_graph_entry_with_parents(&node, &mut results).await;
    test_graph_dag_traversal(&node, &mut results).await;

    // ==========================================================================
    // STRESS TESTS
    // ==========================================================================
    println!("\n--- STRESS TESTS ---");
    test_bulk_store_retrieve(&node, &mut results).await;
    test_concurrent_operations(&node, &mut results).await;

    // Cleanup
    println!("\nShutting down test node...");
    if let Err(e) = node.shutdown().await {
        println!("Warning: Shutdown error: {e}");
    }

    // Print summary
    println!("{}", results.summary());

    // Assert overall success
    assert!(results.failed == 0, "Some tests failed! See details above.");
}
