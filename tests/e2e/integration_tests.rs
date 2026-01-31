//! Integration tests for the E2E test infrastructure.
//!
//! These tests verify that the E2E test infrastructure works correctly.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::testnet::{
    DEFAULT_BOOTSTRAP_COUNT, DEFAULT_NODE_COUNT, MINIMAL_BOOTSTRAP_COUNT, MINIMAL_NODE_COUNT,
    SMALL_NODE_COUNT, TEST_PORT_RANGE_MAX, TEST_PORT_RANGE_MIN,
};
use super::{NetworkState, TestHarness, TestNetwork, TestNetworkConfig};
use saorsa_core::P2PEvent;
use std::time::Duration;

/// Test that a minimal network (5 nodes) can form and stabilize.
#[tokio::test]
#[ignore = "Requires real P2P node spawning - run with --ignored"]
async fn test_minimal_network_formation() {
    // TestNetworkConfig automatically generates unique ports and data dirs
    let harness = TestHarness::setup_minimal()
        .await
        .expect("Failed to setup harness");

    // Verify network is ready
    assert!(harness.is_ready().await);
    assert_eq!(harness.node_count(), MINIMAL_NODE_COUNT);

    // Verify we have connections
    let total_connections = harness.total_connections().await;
    assert!(
        total_connections > 0,
        "Should have at least some connections"
    );

    // Cleanup
    harness.teardown().await.expect("Failed to teardown");
}

/// Test that a small network (10 nodes) can form and stabilize.
#[tokio::test]
#[ignore = "Requires real P2P node spawning - run with --ignored"]
async fn test_small_network_formation() {
    // TestNetworkConfig automatically generates unique ports and data dirs
    let harness = TestHarness::setup_small()
        .await
        .expect("Failed to setup harness");

    // Verify network is ready
    assert!(harness.is_ready().await);
    assert_eq!(harness.node_count(), SMALL_NODE_COUNT);

    // Verify all nodes are accessible
    for i in 0..SMALL_NODE_COUNT {
        assert!(harness.node(i).is_some(), "Node {i} should be accessible");
    }

    // Cleanup
    harness.teardown().await.expect("Failed to teardown");
}

/// Test that the full 25-node network can form.
#[tokio::test]
#[ignore = "Requires real P2P node spawning - run with --ignored"]
async fn test_full_network_formation() {
    let harness = TestHarness::setup().await.expect("Failed to setup harness");

    // Verify network is ready
    assert!(harness.is_ready().await);
    assert_eq!(harness.node_count(), DEFAULT_NODE_COUNT);

    // Verify bootstrap nodes
    let network = harness.network();
    assert_eq!(network.bootstrap_nodes().len(), DEFAULT_BOOTSTRAP_COUNT);

    // Verify regular nodes
    let expected_regular = DEFAULT_NODE_COUNT - DEFAULT_BOOTSTRAP_COUNT;
    assert_eq!(network.regular_nodes().len(), expected_regular);

    // Verify we can get random nodes
    assert!(harness.random_node().is_some());
    assert!(harness.random_bootstrap_node().is_some());

    // Cleanup
    harness.teardown().await.expect("Failed to teardown");
}

/// Test custom network configuration.
#[tokio::test]
#[ignore = "Requires real P2P node spawning - run with --ignored"]
async fn test_custom_network_config() {
    // Override only the settings we care about; ports and data dir are auto-generated
    let config = TestNetworkConfig {
        node_count: 7,
        bootstrap_count: 2,
        spawn_delay: Duration::from_millis(100),
        stabilization_timeout: Duration::from_secs(60),
        ..Default::default()
    };

    let harness = TestHarness::setup_with_config(config)
        .await
        .expect("Failed to setup harness");

    assert_eq!(harness.node_count(), 7);
    assert_eq!(harness.network().bootstrap_nodes().len(), 2);
    assert_eq!(harness.network().regular_nodes().len(), 5);

    harness.teardown().await.expect("Failed to teardown");
}

/// Test network with EVM testnet.
#[tokio::test]
#[ignore = "Requires real P2P node spawning and Anvil - run with --ignored"]
async fn test_network_with_evm() {
    // TestNetworkConfig automatically generates unique ports and data dirs
    let harness = TestHarness::setup_with_evm()
        .await
        .expect("Failed to setup harness with EVM");

    // Verify EVM is available
    assert!(harness.has_evm());

    let anvil = harness.anvil().expect("Anvil should be present");
    assert!(anvil.is_healthy().await);
    assert!(!anvil.rpc_url().is_empty());

    harness.teardown().await.expect("Failed to teardown");
}

/// Test network config validation.
#[tokio::test]
async fn test_network_config_validation() {
    // Invalid: bootstrap_count >= node_count
    let config = TestNetworkConfig {
        node_count: 5,
        bootstrap_count: 5,
        ..Default::default()
    };

    let result = TestNetwork::new(config).await;
    assert!(result.is_err());

    // Invalid: zero bootstrap nodes
    let config = TestNetworkConfig {
        node_count: 5,
        bootstrap_count: 0,
        ..Default::default()
    };

    let result = TestNetwork::new(config).await;
    assert!(result.is_err());
}

/// Test network state enum.
#[test]
fn test_network_state() {
    assert!(!NetworkState::Uninitialized.is_running());
    assert!(!NetworkState::BootstrappingPhase.is_running());
    assert!(!NetworkState::NodeSpawningPhase.is_running());
    assert!(NetworkState::Stabilizing.is_running());
    assert!(NetworkState::Ready.is_running());
    assert!(!NetworkState::ShuttingDown.is_running());
    assert!(!NetworkState::Stopped.is_running());
    assert!(!NetworkState::Failed("error".to_string()).is_running());
}

/// Test `TestNetworkConfig` presets.
#[test]
fn test_config_presets() {
    let default = TestNetworkConfig::default();
    assert_eq!(default.node_count, DEFAULT_NODE_COUNT);
    assert_eq!(default.bootstrap_count, DEFAULT_BOOTSTRAP_COUNT);
    // Ports are randomly generated in a wide range to avoid collisions
    assert!(default.base_port >= TEST_PORT_RANGE_MIN && default.base_port < TEST_PORT_RANGE_MAX);

    let minimal = TestNetworkConfig::minimal();
    assert_eq!(minimal.node_count, MINIMAL_NODE_COUNT);
    assert_eq!(minimal.bootstrap_count, MINIMAL_BOOTSTRAP_COUNT);

    let small = TestNetworkConfig::small();
    assert_eq!(small.node_count, SMALL_NODE_COUNT);
    assert_eq!(small.bootstrap_count, DEFAULT_BOOTSTRAP_COUNT);

    // Each config should have a unique data directory
    assert_ne!(default.test_data_dir, minimal.test_data_dir);
    assert_ne!(minimal.test_data_dir, small.test_data_dir);
}

/// Test that a node can send a message to a connected peer and the peer
/// receives it.
///
/// This validates the fundamental `send_message` / `subscribe_events` layer
/// that all higher-level protocols (chunk, etc.) are built on.
#[tokio::test(flavor = "multi_thread")]
async fn test_node_to_node_messaging() {
    const TEST_TOPIC: &str = "test/ping/v1";
    const PAYLOAD: &[u8] = b"hello from node 3";
    // With the reduced transport recv timeout (2s), messages should arrive
    // within a few seconds. 10s gives ample headroom.
    const DELIVERY_TIMEOUT_SECS: u64 = 10;

    let harness = TestHarness::setup_minimal()
        .await
        .expect("Failed to setup test harness");

    // Subscribe on every node's event stream *before* sending, so we can
    // confirm exactly which node receives the message.
    let all_nodes = harness.all_nodes();
    let mut all_rx: Vec<_> = all_nodes.iter().map(|n| n.subscribe_events()).collect();

    // Pick node 3 (regular) and send to one of its connected peers.
    let sender = harness.test_node(3).expect("Node 3 should exist");
    let peers = sender.connected_peers().await;
    assert!(
        !peers.is_empty(),
        "Node 3 should have at least one connected peer"
    );
    let target_peer_id = peers[0].clone();

    let sender_p2p = sender.p2p_node.as_ref().expect("Node 3 should be running");

    sender_p2p
        .send_message(&target_peer_id, TEST_TOPIC, PAYLOAD.to_vec())
        .await
        .expect("Failed to send message to connected peer");

    // Poll all event streams until the message arrives or we time out.
    // Note: P2PEvent::Message.source is a transport-level peer ID (hex),
    // which differs from P2PNode::peer_id() (app-level "peer_…" format),
    // so we match on topic + payload instead of source identity.
    let mut received = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(DELIVERY_TIMEOUT_SECS);

    // Race all receivers concurrently instead of polling sequentially.
    // Pin the deadline sleep once so it tracks cumulative time across loop
    // iterations — otherwise select_all always wins the race against a
    // freshly-created sleep and the timeout never fires.
    let timeout = tokio::time::sleep_until(deadline);
    tokio::pin!(timeout);

    while !received {
        let futs: Vec<_> = all_rx
            .iter_mut()
            .enumerate()
            .map(|(i, rx)| Box::pin(async move { (i, rx.recv().await) }))
            .collect();

        tokio::select! {
            (result, idx, _remaining) = futures::future::select_all(futs) => {
                if let (_, Ok(P2PEvent::Message { ref topic, ref data, .. })) = (idx, &result.1) {
                    if topic == TEST_TOPIC && data.as_slice() == PAYLOAD {
                        received = true;
                    }
                }
            }
            () = &mut timeout => {
                break;
            }
        }
    }

    assert!(
        received,
        "No node received the message on topic '{TEST_TOPIC}'"
    );

    // Drop event subscribers before teardown — holding broadcast receivers
    // can prevent background tasks from terminating during shutdown.
    drop(all_rx);
    drop(all_nodes);

    harness
        .teardown()
        .await
        .expect("Failed to teardown test harness");
}
