//! Live testnet tests for load testing and data verification.
//!
//! These tests connect to the live 200-node testnet for comprehensive testing.
//! They are designed to be run via shell scripts that set environment variables.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]

use saorsa_core::{NodeConfig as CoreNodeConfig, P2PNode};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

type XorName = [u8; 32];

/// Get bootstrap addresses from environment or use defaults.
fn get_bootstrap_addrs() -> Vec<SocketAddr> {
    let bootstrap_str = env::var("SAORSA_TEST_BOOTSTRAP")
        .unwrap_or_else(|_| "142.93.52.129:12000,24.199.82.114:12000".to_string());

    bootstrap_str
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect()
}

/// Create a P2P node connected to the live testnet.
async fn create_testnet_client() -> P2PNode {
    let bootstrap_addrs = get_bootstrap_addrs();
    println!("Connecting to testnet via: {bootstrap_addrs:?}");

    let mut config = CoreNodeConfig::new().expect("Failed to create config");
    config.bootstrap_peers = bootstrap_addrs;

    // Use a random port for the client
    config.listen_addr = "127.0.0.1:0".parse().unwrap();
    config.listen_addrs = vec![];

    let node = P2PNode::new(config)
        .await
        .expect("Failed to create P2P node");

    node.start().await.expect("Failed to start P2P node");

    // Wait for connection
    tokio::time::sleep(Duration::from_secs(5)).await;

    println!(
        "Connected to testnet with {} peers",
        node.peer_count().await
    );

    node
}

/// Compute content address (SHA256 hash).
fn compute_address(data: &[u8]) -> XorName {
    saorsa_node::compute_address(data)
}

/// Generate random chunk data.
fn generate_chunk(index: usize, size_kb: usize) -> Vec<u8> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let size = size_kb * 1024;
    let mut data = vec![0u8; size];

    // Use index to generate deterministic but unique data
    let mut hasher = DefaultHasher::new();
    index.hash(&mut hasher);
    let seed = hasher.finish();

    for (i, byte) in data.iter_mut().enumerate() {
        *byte = ((seed.wrapping_add(i as u64)) % 256) as u8;
    }

    data
}

/// Load test: store thousands of chunks on the testnet.
///
/// Environment variables:
/// - `SAORSA_TEST_CHUNK_COUNT`: Number of chunks to store (default: 1000)
/// - `SAORSA_TEST_CHUNK_SIZE_KB`: Size of each chunk in KB (default: 1)
/// - `SAORSA_TEST_CONCURRENCY`: Concurrent operations (default: 10)
/// - `SAORSA_TEST_ADDRESSES_FILE`: File to write chunk addresses to
#[tokio::test]
#[ignore = "Live testnet test - run via load-test.sh"]
async fn run_load_test() {
    let chunk_count: usize = env::var("SAORSA_TEST_CHUNK_COUNT")
        .unwrap_or_else(|_| "1000".to_string())
        .parse()
        .expect("Invalid SAORSA_TEST_CHUNK_COUNT");

    let chunk_size_kb: usize = env::var("SAORSA_TEST_CHUNK_SIZE_KB")
        .unwrap_or_else(|_| "1".to_string())
        .parse()
        .expect("Invalid SAORSA_TEST_CHUNK_SIZE_KB");

    let concurrency: usize = env::var("SAORSA_TEST_CONCURRENCY")
        .unwrap_or_else(|_| "10".to_string())
        .parse()
        .expect("Invalid SAORSA_TEST_CONCURRENCY");

    let addresses_file = env::var("SAORSA_TEST_ADDRESSES_FILE")
        .unwrap_or_else(|_| "chunk-addresses.txt".to_string());

    println!("=== Load Test Configuration ===");
    println!("Chunk count: {chunk_count}");
    println!("Chunk size: {chunk_size_kb}KB");
    println!("Concurrency: {concurrency}");
    println!("Addresses file: {addresses_file}");
    println!();

    let node = Arc::new(create_testnet_client().await);
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let stored_count = Arc::new(AtomicUsize::new(0));
    let failed_count = Arc::new(AtomicUsize::new(0));

    // Open file for writing addresses
    let file = Arc::new(std::sync::Mutex::new(
        File::create(&addresses_file).expect("Failed to create addresses file"),
    ));

    let start_time = Instant::now();

    println!("=== Storing {chunk_count} chunks ===");

    let mut handles = vec![];

    for i in 0..chunk_count {
        let node = Arc::clone(&node);
        let semaphore = Arc::clone(&semaphore);
        let stored = Arc::clone(&stored_count);
        let failed = Arc::clone(&failed_count);
        let file = Arc::clone(&file);

        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.expect("Semaphore closed");

            let data = generate_chunk(i, chunk_size_kb);
            let address = compute_address(&data);

            match node.dht_put(address, data).await {
                Ok(()) => {
                    stored.fetch_add(1, Ordering::SeqCst);

                    // Write address to file
                    let hex_addr = hex::encode(address);
                    if let Ok(mut f) = file.lock() {
                        writeln!(f, "{hex_addr}").ok();
                    }

                    if i % 100 == 0 {
                        println!("Stored chunk {} / {chunk_count}", i + 1);
                    }
                }
                Err(e) => {
                    failed.fetch_add(1, Ordering::SeqCst);
                    eprintln!("Failed to store chunk {i}: {e}");
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all operations
    for handle in handles {
        let _ = handle.await;
    }

    let duration = start_time.elapsed();
    let stored = stored_count.load(Ordering::SeqCst);
    let failed = failed_count.load(Ordering::SeqCst);

    println!();
    println!("=== Load Test Results ===");
    println!("Duration: {duration:?}");
    println!("Stored: {stored} / {chunk_count}");
    println!("Failed: {failed}");
    println!(
        "Throughput: {:.2} chunks/sec",
        stored as f64 / duration.as_secs_f64()
    );
    println!("Addresses written to: {addresses_file}");

    // Cleanup
    if let Err(e) = node.shutdown().await {
        eprintln!("Error shutting down node: {e}");
    }

    assert!(
        failed == 0,
        "Some chunks failed to store: {failed} / {chunk_count}"
    );
}

/// Verify chunks: check that all stored chunks are retrievable.
///
/// Environment variables:
/// - `SAORSA_TEST_ADDRESSES_FILE`: File containing chunk addresses to verify
/// - `SAORSA_TEST_SAMPLE_SIZE`: Number of chunks to sample (default: all)
#[tokio::test]
#[ignore = "Live testnet test - run via churn-verify.sh"]
async fn run_verify_chunks() {
    let addresses_file =
        env::var("SAORSA_TEST_ADDRESSES_FILE").expect("SAORSA_TEST_ADDRESSES_FILE not set");

    let sample_size: Option<usize> = env::var("SAORSA_TEST_SAMPLE_SIZE")
        .ok()
        .and_then(|s| s.parse().ok());

    println!("=== Chunk Verification ===");
    println!("Addresses file: {addresses_file}");

    // Read addresses from file
    let file = File::open(&addresses_file).expect("Failed to open addresses file");
    let reader = BufReader::new(file);
    let addresses: Vec<XorName> = reader
        .lines()
        .filter_map(|line| {
            line.ok().and_then(|s| {
                let bytes = hex::decode(s.trim()).ok()?;
                if bytes.len() == 32 {
                    let mut addr = [0u8; 32];
                    addr.copy_from_slice(&bytes);
                    Some(addr)
                } else {
                    None
                }
            })
        })
        .collect();

    let total_addresses = addresses.len();
    println!("Total addresses: {total_addresses}");

    // Sample if requested
    let addresses_to_verify: Vec<XorName> = if let Some(sample) = sample_size {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        let mut sampled = addresses;
        sampled.shuffle(&mut rng);
        sampled.into_iter().take(sample).collect()
    } else {
        addresses
    };

    let addresses_len = addresses_to_verify.len();
    println!("Verifying: {addresses_len} chunks");
    println!();

    let node = Arc::new(create_testnet_client().await);
    let verified_count = Arc::new(AtomicUsize::new(0));
    let missing_count = Arc::new(AtomicUsize::new(0));
    let error_count = Arc::new(AtomicUsize::new(0));

    let semaphore = Arc::new(Semaphore::new(20)); // Higher concurrency for reads
    let start_time = Instant::now();

    let mut handles = vec![];

    for (i, address) in addresses_to_verify.iter().enumerate() {
        let node = Arc::clone(&node);
        let semaphore = Arc::clone(&semaphore);
        let verified = Arc::clone(&verified_count);
        let missing = Arc::clone(&missing_count);
        let errors = Arc::clone(&error_count);
        let addr = *address;
        let total = addresses_to_verify.len();

        let handle = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.expect("Semaphore closed");

            match node.dht_get(addr).await {
                Ok(Some(_data)) => {
                    verified.fetch_add(1, Ordering::SeqCst);
                }
                Ok(None) => {
                    missing.fetch_add(1, Ordering::SeqCst);
                    eprintln!("MISSING: {}", hex::encode(addr));
                }
                Err(e) => {
                    errors.fetch_add(1, Ordering::SeqCst);
                    eprintln!("ERROR retrieving {}: {e}", hex::encode(addr));
                }
            }

            if (i + 1) % 100 == 0 {
                println!("Verified {} / {total}", i + 1);
            }
        });

        handles.push(handle);
    }

    // Wait for all operations
    for handle in handles {
        let _ = handle.await;
    }

    let duration = start_time.elapsed();
    let verified = verified_count.load(Ordering::SeqCst);
    let missing = missing_count.load(Ordering::SeqCst);
    let errors = error_count.load(Ordering::SeqCst);

    println!();
    println!("=== Verification Results ===");
    println!("Duration: {duration:?}");
    println!("verified: {verified}");
    println!("total: {addresses_len}");
    println!("Missing: {missing}");
    println!("Errors: {errors}");
    println!(
        "Availability: {:.2}%",
        (verified as f64 / addresses_len as f64) * 100.0
    );

    // Cleanup
    if let Err(e) = node.shutdown().await {
        eprintln!("Error shutting down node: {e}");
    }

    // Test passes if 100% available
    if missing == 0 && errors == 0 {
        println!("PASSED: All chunks are available!");
    } else {
        panic!("FAILED: {missing} missing, {errors} errors out of {addresses_len} total");
    }
}

/// Comprehensive data test: store, retrieve, and verify.
///
/// This test stores a moderate number of chunks and immediately verifies
/// they can be retrieved from different parts of the network.
#[tokio::test]
#[ignore = "Live testnet test - requires SAORSA_TEST_EXTERNAL=true"]
async fn run_comprehensive_data_tests() {
    if env::var("SAORSA_TEST_EXTERNAL").is_err() {
        println!("Skipping: SAORSA_TEST_EXTERNAL not set");
        return;
    }

    println!("=== Comprehensive Data Tests ===");
    println!();

    let node = Arc::new(create_testnet_client().await);

    // Test 1: Store and retrieve various chunk sizes
    println!("--- Test 1: Various Chunk Sizes ---");
    let sizes_kb = [1, 4, 16, 64, 256];

    for size_kb in sizes_kb {
        let data = generate_chunk(size_kb, size_kb);
        let address = compute_address(&data);

        println!("Storing {size_kb}KB chunk...");
        node.dht_put(address, data.clone())
            .await
            .expect("Failed to store chunk");

        // Small delay to allow replication
        tokio::time::sleep(Duration::from_millis(500)).await;

        println!("Retrieving {size_kb}KB chunk...");
        let retrieved = node
            .dht_get(address)
            .await
            .expect("Failed to retrieve chunk")
            .expect("Chunk not found");

        assert_eq!(data, retrieved, "Data mismatch for {size_kb}KB chunk");
        println!("  OK: {size_kb}KB chunk verified");
    }

    // Test 2: Concurrent storage and retrieval
    println!();
    println!("--- Test 2: Concurrent Operations ---");
    let concurrent_count = 50;

    let mut addresses = vec![];
    let mut handles = vec![];

    for i in 0..concurrent_count {
        let node = Arc::clone(&node);
        let handle = tokio::spawn(async move {
            let data = generate_chunk(1000 + i, 4);
            let address = compute_address(&data);

            node.dht_put(address, data).await.expect("Store failed");
            address
        });
        handles.push(handle);
    }

    for handle in handles {
        let addr = handle.await.expect("Task panicked");
        addresses.push(addr);
    }

    println!("Stored {concurrent_count} chunks concurrently");

    // Verify all can be retrieved
    tokio::time::sleep(Duration::from_secs(2)).await;

    let mut verified = 0;
    for addr in &addresses {
        if node.dht_get(*addr).await.expect("Get failed").is_some() {
            verified += 1;
        }
    }

    let addresses_len = addresses.len();
    println!("Retrieved {verified} / {addresses_len} chunks");
    assert_eq!(verified, addresses_len, "Not all chunks were retrievable");

    // Test 3: Network distribution check
    println!();
    println!("--- Test 3: Network Distribution ---");
    let peer_count = node.peer_count().await;
    println!("Connected to {peer_count} peers");
    assert!(peer_count >= 3, "Should be connected to at least 3 peers");

    // Cleanup
    if let Err(e) = node.shutdown().await {
        eprintln!("Error shutting down node: {e}");
    }

    println!();
    println!("=== All Comprehensive Tests Passed ===");
}
