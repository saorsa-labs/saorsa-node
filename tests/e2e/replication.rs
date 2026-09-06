//! Replication E2E tests.
//!
//! Tests the replication subsystem behaviors from Section 18 of
//! `REPLICATION_DESIGN.md` against a live multi-node testnet.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::testnet::TestNetworkConfig;
use super::TestHarness;
use ant_node::client::compute_address;
use ant_node::replication::audit_coordinator::AuditChallengeCoordinator;
use ant_node::replication::commitment_state::{BuiltCommitment, ResponderCommitmentState};
use ant_node::replication::config::{
    storage_admission_width, K_BUCKET_SIZE, REPLICATION_PROTOCOL_ID,
};
use ant_node::replication::protocol::{
    compute_audit_digest, AuditChallenge, AuditResponse, FetchRequest, FetchResponse,
    FreshReplicationOffer, FreshReplicationResponse, NeighborSyncRequest, ReplicationMessage,
    ReplicationMessageBody, VerificationRequest, ABSENT_KEY_DIGEST,
};
use ant_node::replication::pruning;
use ant_node::replication::scheduling::ReplicationQueues;
use ant_node::replication::types::{NeighborSyncState, RepairProofs};
use ant_node::ReplicationConfig;
use saorsa_core::identity::PeerId;
use saorsa_core::{P2PNode, TrustEvent};
use serial_test::serial;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Maximum time to wait for replication propagation in tests.
const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(15);
/// Interval between propagation poll checks.
const PROPAGATION_POLL_INTERVAL: Duration = Duration::from_millis(200);
/// Checker node used by the full-node shunning regression.
const FULL_NODE_SHUN_CHECKER_INDEX: usize = 3;
/// Target node made disk-full by the full-node shunning regression.
const FULL_NODE_SHUN_TARGET_INDEX: usize = 4;
/// Search budget for finding a key whose close group contains the full node.
const FULL_NODE_SHUN_KEY_SEARCH_ATTEMPTS: usize = 10_000;
/// Fast lower bound for the full-node shunning scheduler check.
const FULL_NODE_SHUN_POSSESSION_DELAY_MIN: Duration = Duration::from_millis(200);
/// Fast upper bound for the full-node shunning scheduler check.
const FULL_NODE_SHUN_POSSESSION_DELAY_MAX: Duration = Duration::from_millis(500);
/// Dummy proof length used when a test only needs to reach pre-payment gates.
const DUMMY_PAYMENT_PROOF_LEN: usize = 64;
/// Dummy proof byte used when a test only needs to reach pre-payment gates.
const DUMMY_PAYMENT_PROOF_BYTE: u8 = 0x01;
/// Minimal paid-list repair close group used by the deterministic repair e2e.
const PAID_REPAIR_GROUP_SIZE: usize = 5;
/// Storage threshold configured above majority so one holder is below quorum.
const PAID_REPAIR_STORAGE_THRESHOLD: usize = 4;
/// Paid-list majority for a five-peer group.
const PAID_REPAIR_CONFIRMING_NODES: usize = 3;
/// Single node seeded with the record bytes before repair.
const PAID_REPAIR_SOURCE_INDEX: usize = 0;
/// Missing responsible node that must learn the paid-list entry and fetch.
const PAID_REPAIR_TARGET_INDEX: usize = 4;
/// Expected storage quorum for the five-peer repair group.
const PAID_REPAIR_STORAGE_QUORUM: usize = 3;
/// Timeout used by the repair e2e's verification requests.
const PAID_REPAIR_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(3);
/// Timeout used by the repair e2e's fetch requests.
const PAID_REPAIR_FETCH_TIMEOUT: Duration = Duration::from_secs(3);
/// Wait budget for asynchronous verification plus fetch completion.
const PAID_REPAIR_SETTLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Request-response timeout for seeding the replica hint.
const PAID_REPAIR_HINT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Stable request id for the paid-list repair sync request.
const PAID_REPAIR_HINT_REQUEST_ID: u64 = 2526;

/// Send a replication request via saorsa-core's request-response mechanism
/// and decode the response.
///
/// Uses `send_request` which wraps the payload in a `RequestResponseEnvelope`
/// with the `/rr/` topic prefix. The replication handler recognises this
/// pattern and routes the response back via `send_response`.
async fn send_replication_request(
    sender: &P2PNode,
    target: &PeerId,
    msg: ReplicationMessage,
    timeout: Duration,
) -> ReplicationMessage {
    let encoded = msg.encode().expect("encode replication request");
    let response = sender
        .send_request(target, REPLICATION_PROTOCOL_ID, encoded, timeout)
        .await
        .expect("send_request");
    ReplicationMessage::decode(&response.data).expect("decode replication response")
}

fn prune_test_config(close_group_size: usize) -> ReplicationConfig {
    ReplicationConfig {
        close_group_size,
        quorum_threshold: 1,
        // Keep the width-20 view incomplete in the five-node harness so these
        // tests exercise the remote-audit path rather than the fast path.
        paid_list_close_group_size: 20,
        prune_hysteresis_duration: Duration::ZERO,
        ..ReplicationConfig::default()
    }
}

fn node_index_for_peer(harness: &TestHarness, peer: &PeerId) -> Option<usize> {
    (0..harness.node_count()).find(|idx| {
        harness
            .test_node(*idx)
            .and_then(|node| node.p2p_node.as_ref())
            .is_some_and(|p2p| p2p.peer_id() == peer)
    })
}

async fn find_remote_prune_candidate(
    harness: &TestHarness,
    pruner_idx: usize,
    close_group_size: usize,
    label: &str,
) -> (Vec<u8>, [u8; 32], Vec<PeerId>) {
    let pruner = harness.test_node(pruner_idx).expect("pruner");
    let pruner_p2p = pruner.p2p_node.as_ref().expect("pruner p2p");
    let pruner_peer = *pruner_p2p.peer_id();
    let admission_width = storage_admission_width(close_group_size);

    for attempt in 0..10_000usize {
        let content = format!("prune-confirmation-{label}-{attempt}").into_bytes();
        let address = compute_address(&content);
        let closest = pruner_p2p
            .dht_manager()
            .find_closest_nodes_local_with_self(&address, close_group_size)
            .await;
        if closest.len() != close_group_size {
            continue;
        }

        let target_peers: Vec<PeerId> = closest.iter().map(|node| node.peer_id).collect();
        if target_peers.contains(&pruner_peer) {
            continue;
        }
        let storage_admission_group = pruner_p2p
            .dht_manager()
            .find_closest_nodes_local_with_self(&address, admission_width)
            .await;
        if storage_admission_group
            .iter()
            .any(|node| node.peer_id == pruner_peer)
        {
            continue;
        }
        if target_peers
            .iter()
            .all(|peer| node_index_for_peer(harness, peer).is_some())
        {
            return (content, address, target_peers);
        }
    }

    panic!(
        "failed to find a {close_group_size}-peer prune candidate outside pruner {pruner_idx}'s \
         storage-admission range"
    );
}

async fn store_record_on_peer(
    harness: &TestHarness,
    peer: &PeerId,
    address: &[u8; 32],
    content: &[u8],
) {
    let idx = node_index_for_peer(harness, peer).expect("target peer should be in test harness");
    let protocol = harness
        .test_node(idx)
        .expect("target node")
        .ant_protocol
        .as_ref()
        .expect("target protocol");
    protocol.storage().put(address, content).await.expect("put");
}

async fn store_record_on_peers(
    harness: &TestHarness,
    peers: &[PeerId],
    address: &[u8; 32],
    content: &[u8],
) {
    for peer in peers {
        store_record_on_peer(harness, peer, address, content).await;
    }
}

/// Fresh write happy path (Section 18 #1).
///
/// Store a chunk on a node that has a `ReplicationEngine`, manually call
/// `replicate_fresh`, then check that at least one other node in the
/// close group received it via their storage.
#[tokio::test]
#[serial]
async fn test_fresh_replication_propagates_to_close_group() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    // Pick a non-bootstrap node with replication engine
    let source_idx = 3; // first regular node
    let source = harness.test_node(source_idx).expect("source node");
    let source_protocol = source.ant_protocol.as_ref().expect("protocol");
    let source_storage = source_protocol.storage();

    // Create and store a chunk
    let content = b"hello replication world";
    let address = compute_address(content);
    source_storage.put(&address, content).await.expect("put");

    // Pre-populate payment cache on ALL nodes so receivers accept the offer
    // (bypasses EVM verification, which is unavailable without Anvil).
    for i in 0..harness.node_count() {
        if let Some(node) = harness.test_node(i) {
            if let Some(protocol) = &node.ant_protocol {
                protocol.payment_verifier().cache_insert(address);
            }
        }
    }

    // Trigger fresh replication with a dummy PoP
    let dummy_pop = [0x01u8; 64];
    if let Some(ref engine) = source.replication_engine {
        engine.replicate_fresh(&address, content, &dummy_pop).await;
    }

    // Poll until replication propagates (or timeout).
    let deadline = tokio::time::Instant::now() + PROPAGATION_TIMEOUT;
    let mut found_on_other = false;
    while tokio::time::Instant::now() < deadline {
        for i in 0..harness.node_count() {
            if i == source_idx {
                continue;
            }
            if let Some(node) = harness.test_node(i) {
                if let Some(protocol) = &node.ant_protocol {
                    if protocol.storage().exists(&address).unwrap_or(false) {
                        found_on_other = true;
                    }
                }
            }
        }
        if found_on_other {
            break;
        }
        tokio::time::sleep(PROPAGATION_POLL_INTERVAL).await;
    }
    assert!(
        found_on_other,
        "Chunk should have replicated to at least one other node"
    );

    harness.teardown().await.expect("teardown");
}

/// ADR-0003: the delayed possession check penalises a responsible peer that
/// does NOT hold the chunk, and leaves a peer that DOES hold it unpenalised.
///
/// Drives the check directly (`run_possession_check_now`, bypassing the 5-15
/// minute settle delay) so the detection+penalty path is asserted
/// deterministically over real transport. The penalty is observed as a drop in
/// the checker's trust score for the absent peer (the same signal saorsa-core
/// eviction acts on), via `P2PNode::peer_trust`.
#[tokio::test]
#[serial]
async fn possession_check_penalises_absent_peer_only_and_obeys_the_release_switch() {
    let harness = TestHarness::setup_small().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    // A is the checker; B will be absent, C will hold the chunk. All three are
    // regular nodes (idx >= 3) with running replication engines and storage.
    let a = harness.test_node(3).expect("node a");
    let b = harness.test_node(4).expect("node b");
    let c = harness.test_node(5).expect("node c");

    let p2p_a = a.p2p_node.as_ref().expect("p2p a");
    let engine_a = a.replication_engine.as_ref().expect("engine a");
    let peer_b = *b.p2p_node.as_ref().expect("p2p b").peer_id();
    let peer_c = *c.p2p_node.as_ref().expect("p2p c").peer_id();

    let content = b"adr-0003 possession-check payload";
    let address = compute_address(content);

    // The checker A must hold the chunk it verifies: the possession check
    // recomputes the audit digest from its own canonical copy. In production the
    // PUT handler stores K before fresh-replicating; here we store it on the
    // checker explicitly.
    a.ant_protocol
        .as_ref()
        .expect("proto a")
        .storage()
        .put(&address, content)
        .await
        .expect("put on a (checker)");

    // C holds the chunk; B never stores it.
    c.ant_protocol
        .as_ref()
        .expect("proto c")
        .storage()
        .put(&address, content)
        .await
        .expect("put on c");

    assert!(
        !b.ant_protocol
            .as_ref()
            .expect("proto b")
            .storage()
            .exists(&address)
            .expect("exists b"),
        "precondition: B must not hold the chunk"
    );
    assert!(
        c.ant_protocol
            .as_ref()
            .expect("proto c")
            .storage()
            .exists(&address)
            .expect("exists c"),
        "precondition: C must hold the chunk"
    );

    // Switched on explicitly, so this half keeps testing the possession mechanism rather
    // than whichever release it happens to be compiled against.
    ant_node::replication::config::set_close_group_storage_penalty_suspended(false);

    let trust_b_before = p2p_a.peer_trust(&peer_b);
    let trust_c_before = p2p_a.peer_trust(&peer_c);

    // Probe both peers now (no scheduler delay). B is absent -> penalised; C is
    // present -> untouched.
    engine_a
        .run_possession_check_now(address, vec![peer_b, peer_c])
        .await;

    let trust_b_after = p2p_a.peer_trust(&peer_b);
    let trust_c_after = p2p_a.peer_trust(&peer_c);

    assert!(
        trust_b_after < trust_b_before,
        "absent peer B must be penalised: {trust_b_before} -> {trust_b_after}"
    );
    assert!(
        trust_c_after >= trust_c_before - f64::EPSILON,
        "present peer C must not be penalised: {trust_c_before} -> {trust_c_after}"
    );

    // And the other half of the contract, on the same harness. The release that moves
    // nodes off the legacy chunk store withholds exactly this penalty: a node short of
    // disk cannot avoid answering "absent" while it moves its chunks out of a store that
    // never returns space, and it cannot stop its peers penalising it for that, because
    // the penalty is the auditor's decision. So the auditors stop one release ahead.
    ant_node::replication::config::set_close_group_storage_penalty_suspended(true);
    let trust_b_suspended_before = p2p_a.peer_trust(&peer_b);
    engine_a
        .run_possession_check_now(address, vec![peer_b, peer_c])
        .await;
    let trust_b_suspended_after = p2p_a.peer_trust(&peer_b);
    ant_node::replication::config::set_close_group_storage_penalty_suspended(false);

    assert!(
        trust_b_suspended_after >= trust_b_suspended_before - f64::EPSILON,
        "an absent peer must not be penalised while the release withholds that penalty: \
         {trust_b_suspended_before} -> {trust_b_suspended_after}"
    );

    harness.teardown().await.expect("teardown");
}

/// ADR-0003: the possession-check *scheduler* (not the direct-drive path)
/// fires after the configured delay and penalises an absent close peer.
///
/// Uses a shortened possession delay so the scheduled check runs in well under
/// a second. No payment cache is pre-populated, so the close-group peers reject
/// the fresh offer and are absent when the scheduled check probes them. Proves
/// the `replicate_fresh` -> enqueue -> delayed scheduler -> penalty wiring.
#[tokio::test]
#[serial]
async fn possession_scheduler_penalises_absent_close_peer_after_delay() {
    let mut net_config = TestNetworkConfig::small();
    net_config.replication_config = Some(ReplicationConfig {
        possession_check_delay_min: Duration::from_millis(200),
        possession_check_delay_max: Duration::from_millis(500),
        ..ReplicationConfig::default()
    });
    let harness = TestHarness::setup_with_config(net_config)
        .await
        .expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let a = harness.test_node(3).expect("node a");
    let p2p_a = a.p2p_node.as_ref().expect("p2p a");
    let engine_a = a.replication_engine.as_ref().expect("engine a");
    let self_a = *p2p_a.peer_id();

    let content = b"adr-0003 scheduler-wiring payload";
    let address = compute_address(content);

    // A's close group for this key = exactly the peers the scheduled possession
    // check targets. With no payment cache anywhere, they reject the fresh offer
    // and are absent when probed.
    let close_group_size = ReplicationConfig::default().close_group_size;
    let close_group: Vec<PeerId> = p2p_a
        .dht_manager()
        .find_closest_nodes_local_with_self(&address, close_group_size)
        .await
        .iter()
        .filter(|n| n.peer_id != self_a)
        .map(|n| n.peer_id)
        .collect();
    assert!(!close_group.is_empty(), "expected a non-empty close group");

    // Switched on explicitly. The release that moves nodes off the legacy chunk store
    // withholds this penalty by default, so a test that asserts it must say so, or it
    // silently starts asserting whichever release it is compiled against.
    ant_node::replication::config::set_close_group_storage_penalty_suspended(false);

    let trust_before: Vec<f64> = close_group.iter().map(|p| p2p_a.peer_trust(p)).collect();

    // The checker must hold the chunk it later probes for: the possession check
    // recomputes the audit digest from its own copy. `replicate_fresh` assumes
    // the PUT handler already stored K locally, so store it on the checker here.
    a.ant_protocol
        .as_ref()
        .expect("proto a")
        .storage()
        .put(&address, content)
        .await
        .expect("put on a (checker)");

    // Trigger fresh replication; the engine enqueues the possession check, which
    // fires ~200-500 ms later and penalises the absent close peers.
    let dummy_pop = [0x01u8; 64];
    engine_a
        .replicate_fresh(&address, content, &dummy_pop)
        .await;

    // Poll until at least one absent close peer is penalised (trust drops).
    let deadline = tokio::time::Instant::now() + PROPAGATION_TIMEOUT;
    let mut penalised = false;
    while tokio::time::Instant::now() < deadline {
        penalised = close_group
            .iter()
            .zip(trust_before.iter())
            .any(|(peer, &before)| p2p_a.peer_trust(peer) < before - f64::EPSILON);
        if penalised {
            break;
        }
        tokio::time::sleep(PROPAGATION_POLL_INTERVAL).await;
    }
    assert!(
        penalised,
        "the scheduled possession check should have penalised an absent close peer"
    );

    harness.teardown().await.expect("teardown");
}

/// ADR-0003 full-node shunning: a close-group peer that is disk-full rejects a
/// fresh-replication offer before payment verification, remains absent for the
/// key, and is penalised when the checker probes possession.
///
/// This bridges the two protections that make a full node get shunned by close
/// groups: capacity rejection creates a missing replica, and the delayed
/// possession-check verdict turns that absence into the trust signal that
/// saorsa-core eviction acts on.
#[tokio::test]
#[serial]
async fn full_close_group_node_rejects_replica_and_is_penalised_as_absent() {
    let mut net_config = TestNetworkConfig::small();
    net_config.replication_config = Some(ReplicationConfig {
        possession_check_delay_min: FULL_NODE_SHUN_POSSESSION_DELAY_MIN,
        possession_check_delay_max: FULL_NODE_SHUN_POSSESSION_DELAY_MAX,
        ..ReplicationConfig::default()
    });
    net_config
        .storage_disk_reserve_overrides
        .insert(FULL_NODE_SHUN_TARGET_INDEX, u64::MAX);
    let harness = TestHarness::setup_with_config(net_config)
        .await
        .expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let checker = harness
        .test_node(FULL_NODE_SHUN_CHECKER_INDEX)
        .expect("checker node");
    let full_node = harness
        .test_node(FULL_NODE_SHUN_TARGET_INDEX)
        .expect("full node");
    let checker_p2p = checker.p2p_node.as_ref().expect("checker p2p");
    let checker_engine = checker.replication_engine.as_ref().expect("checker engine");
    let full_p2p = full_node.p2p_node.as_ref().expect("full node p2p");
    let full_peer = *full_p2p.peer_id();

    let close_group_size = ReplicationConfig::default().close_group_size;
    let admission_width = storage_admission_width(close_group_size);
    let mut candidate = None;
    for attempt in 0..FULL_NODE_SHUN_KEY_SEARCH_ATTEMPTS {
        let content = format!("adr-0003 full-node shunning payload {attempt}").into_bytes();
        let address = compute_address(&content);
        let full_node_in_checker_close_group = checker_p2p
            .dht_manager()
            .find_closest_nodes_local_with_self(&address, close_group_size)
            .await
            .iter()
            .any(|node| node.peer_id == full_peer);
        if !full_node_in_checker_close_group {
            continue;
        }

        let full_node_admits_self = full_p2p
            .dht_manager()
            .find_closest_nodes_local_with_self(&address, admission_width)
            .await
            .iter()
            .any(|node| node.peer_id == full_peer);
        if full_node_admits_self {
            candidate = Some((content, address));
            break;
        }
    }
    let (content, address) =
        candidate.expect("find key where full node is a responsible close-group peer");

    for idx in 0..harness.node_count() {
        if let Some(protocol) = harness
            .test_node(idx)
            .and_then(|node| node.ant_protocol.as_ref())
        {
            protocol.payment_verifier().cache_insert(address);
        }
    }

    let dummy_payment_proof = vec![DUMMY_PAYMENT_PROOF_BYTE; DUMMY_PAYMENT_PROOF_LEN];
    let offer = FreshReplicationOffer {
        key: address,
        data: content.clone(),
        proof_of_payment: dummy_payment_proof.clone(),
    };
    let response = send_replication_request(
        checker_p2p,
        &full_peer,
        ReplicationMessage {
            request_id: rand::random(),
            body: ReplicationMessageBody::FreshReplicationOffer(offer),
        },
        PROPAGATION_TIMEOUT,
    )
    .await;

    match response.body {
        ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
            key,
            reason,
        }) => {
            assert_eq!(key, address);
            assert!(
                reason.contains("Insufficient disk space"),
                "expected disk-full rejection, got: {reason}"
            );
        }
        other => panic!("expected disk-full rejection, got: {other:?}"),
    }

    let full_storage = full_node
        .ant_protocol
        .as_ref()
        .expect("full node protocol")
        .storage();
    assert!(
        !full_storage.exists(&address).expect("exists on full node"),
        "full node must not store the rejected replica"
    );

    // The checker must hold the chunk it probes for: the possession check
    // recomputes the audit digest from its own copy. `replicate_fresh` assumes
    // the PUT handler already stored K locally, so store it on the checker here.
    checker
        .ant_protocol
        .as_ref()
        .expect("checker protocol")
        .storage()
        .put(&address, &content)
        .await
        .expect("put on checker");

    // Switched on explicitly. The release that moves nodes off the legacy chunk store
    // withholds this penalty by default, so a test that asserts it must say so, or it
    // silently starts asserting whichever release it is compiled against.
    ant_node::replication::config::set_close_group_storage_penalty_suspended(false);

    let trust_before = checker_p2p.peer_trust(&full_peer);
    checker_engine
        .replicate_fresh(&address, &content, &dummy_payment_proof)
        .await;

    let deadline = tokio::time::Instant::now() + PROPAGATION_TIMEOUT;
    let mut trust_after = trust_before;
    while tokio::time::Instant::now() < deadline {
        trust_after = checker_p2p.peer_trust(&full_peer);
        if trust_after < trust_before - f64::EPSILON {
            break;
        }
        tokio::time::sleep(PROPAGATION_POLL_INTERVAL).await;
    }
    assert!(
        trust_after < trust_before - f64::EPSILON,
        "full close-group peer should be shunned by the scheduled possession check: \
         {trust_before} -> {trust_after}"
    );

    harness.teardown().await.expect("teardown");
}

/// ADR-0003 self-closeness gate: a node accepts a client PUT only when it is
/// within its own local `K_BUCKET_SIZE`-closest to the address.
///
/// Needs more than `K_BUCKET_SIZE` nodes so a far node falls outside its own
/// closest view. The responsible (closest) node accepts and stores; the
/// non-responsible (farthest) node rejects before payment with a closeness
/// error. Guards both the regression risk (gate must not reject responsible
/// puts) and the intended reject behaviour.
#[tokio::test]
#[serial]
async fn self_closeness_gate_accepts_responsible_rejects_far_node() {
    let harness = TestHarness::setup().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let content = b"adr-0003 self-closeness gate payload";
    let address = compute_address(content);

    // Rank all peers by XOR distance to the address (identical from any node's
    // view once routing tables are warm).
    let ranker_p2p = harness
        .test_node(3)
        .expect("ranker")
        .p2p_node
        .as_ref()
        .expect("p2p");
    let ranked: Vec<PeerId> = ranker_p2p
        .dht_manager()
        .find_closest_nodes_local_with_self(&address, harness.node_count())
        .await
        .iter()
        .map(|n| n.peer_id)
        .collect();
    assert!(
        ranked.len() > K_BUCKET_SIZE,
        "need > K_BUCKET_SIZE nodes to exercise the reject path; got {}",
        ranked.len()
    );

    // Only nodes that actually run a protocol handler can serve a client PUT.
    let has_protocol = |peer: &PeerId| {
        node_index_for_peer(&harness, peer)
            .and_then(|idx| harness.test_node(idx))
            .is_some_and(|n| n.ant_protocol.is_some())
    };

    // Closest node with a handler -> within its own K-closest -> gate accepts.
    let close_peer = ranked
        .iter()
        .copied()
        .find(|p| has_protocol(p))
        .expect("a close node with a handler");
    // Farthest node beyond the gate width with a handler -> gate rejects.
    let far_peer = ranked
        .iter()
        .copied()
        .enumerate()
        .rev()
        .find(|(rank, p)| *rank >= K_BUCKET_SIZE && has_protocol(p))
        .map(|(_, p)| p)
        .expect("a far node (rank >= K_BUCKET_SIZE) with a handler");

    let close_idx = node_index_for_peer(&harness, &close_peer).expect("close idx");
    let far_idx = node_index_for_peer(&harness, &far_peer).expect("far idx");

    // Accept path: a responsible node stores the chunk (gate passes).
    let close_result = harness
        .test_node(close_idx)
        .expect("close node")
        .store_chunk(content)
        .await;
    assert!(
        close_result.is_ok(),
        "responsible (closest) node must accept the PUT, got {close_result:?}"
    );

    // Reject path: a non-responsible node rejects before payment with a
    // closeness error.
    let far_result = harness
        .test_node(far_idx)
        .expect("far node")
        .store_chunk(content)
        .await;
    assert!(
        far_result.is_err(),
        "non-responsible (farthest) node must reject the PUT"
    );
    let err = format!("{}", far_result.expect_err("far rejection"));
    assert!(
        err.contains("closest"),
        "rejection should cite closeness, got: {err}"
    );

    harness.teardown().await.expect("teardown");
}

/// `PaidForList` persistence (Section 18 #43).
///
/// Insert a key into the `PaidList`, verify it persists by reopening the
/// list from the same data directory.
#[tokio::test]
#[serial]
async fn test_paid_list_persistence() {
    let mut harness = TestHarness::setup_minimal().await.expect("setup");

    let key = [0xAA; 32];
    let data_dir = {
        let node = harness.test_node(3).expect("node");
        let dir = node.data_dir.clone();

        // Insert into paid list
        if let Some(ref engine) = node.replication_engine {
            engine.paid_list().insert(&key).await.expect("insert");
            assert!(engine.paid_list().contains(&key).expect("contains"));
        }
        dir
    };

    // Shut down the replication engine so the chunk store is released
    {
        let node = harness.network_mut().node_mut(3).expect("node");
        if let Some(ref mut engine) = node.replication_engine {
            engine.shutdown().await;
        }
        node.replication_engine = None;
        node.replication_shutdown = None;
    }

    // Reopen the paid list from the same directory to verify persistence
    let paid_list2 = ant_node::replication::paid_list::PaidList::new(&data_dir)
        .await
        .expect("reopen");
    assert!(paid_list2.contains(&key).expect("contains after reopen"));

    harness.teardown().await.expect("teardown");
}

/// Verification request/response (Section 18 #6, #27).
///
/// Send a verification request to a node and check that it returns proper
/// per-key presence results for both stored and missing keys.
#[tokio::test]
#[serial]
async fn test_verification_request_returns_presence() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_a = node_a.p2p_node.as_ref().expect("p2p_a");
    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol_a");
    let storage_a = protocol_a.storage();

    // Store a chunk on node A
    let content = b"verification test data";
    let address = compute_address(content);
    storage_a.put(&address, content).await.expect("put");

    // Also create a key that doesn't exist
    let missing_key = [0xBB; 32];

    // Build verification request from B to A
    let request = VerificationRequest {
        keys: vec![address, missing_key],
        paid_list_check_indices: vec![],
    };
    let msg = ReplicationMessage {
        request_id: 42,
        body: ReplicationMessageBody::VerificationRequest(request),
    };

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *p2p_a.peer_id();

    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    if let ReplicationMessageBody::VerificationResponse(resp) = resp_msg.body {
        assert_eq!(resp.results.len(), 2);
        assert!(resp.results[0].present, "First key should be present");
        assert!(!resp.results[1].present, "Second key should be absent");
    } else {
        panic!("Expected VerificationResponse");
    }

    harness.teardown().await.expect("teardown");
}

/// Fetch request/response happy path.
///
/// Store a chunk on node A, send a `FetchRequest` from node B, and verify
/// the response contains the correct data.
#[tokio::test]
#[serial]
async fn test_fetch_request_returns_record() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_a = node_a.p2p_node.as_ref().expect("p2p_a");
    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol_a");

    // Store chunk on A
    let content = b"fetch me please";
    let address = compute_address(content);
    protocol_a
        .storage()
        .put(&address, content)
        .await
        .expect("put");

    // Send fetch request from B to A
    let request = FetchRequest { key: address };
    let msg = ReplicationMessage {
        request_id: 99,
        body: ReplicationMessageBody::FetchRequest(request),
    };

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *p2p_a.peer_id();

    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    if let ReplicationMessageBody::FetchResponse(FetchResponse::Success { key, data }) =
        resp_msg.body
    {
        assert_eq!(key, address);
        assert_eq!(data, content);
    } else {
        panic!("Expected FetchResponse::Success");
    }

    harness.teardown().await.expect("teardown");
}

/// Audit challenge/response (Section 18 #54).
///
/// Store a chunk on a node, send an audit challenge, and verify the
/// returned digest matches our local computation.
#[tokio::test]
#[serial]
async fn test_audit_challenge_returns_correct_digest() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_a = node_a.p2p_node.as_ref().expect("p2p_a");
    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol_a");

    // Store chunk on A
    let content = b"audit test data";
    let address = compute_address(content);
    protocol_a
        .storage()
        .put(&address, content)
        .await
        .expect("put");

    let peer_a = *p2p_a.peer_id();
    let nonce = [0x42u8; 32];

    // Send audit challenge from B to A
    // The on-wire `AuditChallenge` is handled by the responsible-chunk audit
    // responder (`audit::handle_audit_challenge`), which answers with per-key
    // `Digests`. The prune-confirmation audit reuses the same message. (The
    // storage-commitment audit uses the separate
    // `SubtreeAuditChallenge`/`SubtreeAuditResponse` path.)
    let challenge = AuditChallenge {
        challenge_id: 1234,
        nonce,
        challenged_peer_id: *peer_a.as_bytes(),
        keys: vec![address],
    };
    let msg = ReplicationMessage {
        request_id: 1234,
        body: ReplicationMessageBody::AuditChallenge(challenge),
    };

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    if let ReplicationMessageBody::AuditResponse(AuditResponse::Digests {
        challenge_id,
        digests,
    }) = resp_msg.body
    {
        assert_eq!(challenge_id, 1234);
        assert_eq!(digests.len(), 1);

        // Verify digest matches our local computation
        let expected = compute_audit_digest(&nonce, peer_a.as_bytes(), &address, content);
        assert_eq!(digests[0], expected);
    } else {
        panic!("Expected AuditResponse::Digests");
    }

    harness.teardown().await.expect("teardown");
}

/// Audit absent key returns sentinel (Section 18 #54 variant).
///
/// Challenge a node with a key it does NOT hold and verify the digest
/// is the [`ABSENT_KEY_DIGEST`] sentinel.
#[tokio::test]
#[serial]
async fn test_audit_absent_key_returns_sentinel() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_a = node_a.p2p_node.as_ref().expect("p2p_a");
    let peer_a = *p2p_a.peer_id();

    // Challenge with a key that A does NOT hold
    let missing_key = [0xDD; 32];
    let nonce = [0x11u8; 32];

    let challenge = AuditChallenge {
        challenge_id: 5678,
        nonce,
        challenged_peer_id: *peer_a.as_bytes(),
        keys: vec![missing_key],
    };
    let msg = ReplicationMessage {
        request_id: 5678,
        body: ReplicationMessageBody::AuditChallenge(challenge),
    };

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    if let ReplicationMessageBody::AuditResponse(AuditResponse::Digests { digests, .. }) =
        resp_msg.body
    {
        assert_eq!(digests.len(), 1);
        assert_eq!(
            digests[0], ABSENT_KEY_DIGEST,
            "Absent key should return sentinel digest"
        );
    } else {
        panic!("Expected AuditResponse::Digests");
    }

    harness.teardown().await.expect("teardown");
}

/// Prune pass requires remote storage proofs before deleting local records.
///
/// This drives `run_prune_pass` against live nodes so prune-confirmation audits
/// travel over the real replication request/response path. The repair-proof
/// table stays EMPTY throughout: prune candidacy and prune-audit target
/// selection must not depend on prior neighbor-sync repair hints.
#[tokio::test]
#[serial]
async fn test_prune_pass_requires_remote_confirmation_before_delete() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let pruner_idx = 3;
    let close_group_size = 2;
    let config = prune_test_config(close_group_size);
    let sync_state = Arc::new(RwLock::new(NeighborSyncState::new_cycle(vec![])));
    let repair_proofs = Arc::new(RwLock::new(RepairProofs::new()));
    let audit_challenge_coordinator = Arc::new(AuditChallengeCoordinator::new());

    let pruner = harness.test_node(pruner_idx).expect("pruner");
    let pruner_p2p = Arc::clone(pruner.p2p_node.as_ref().expect("pruner p2p"));
    let pruner_protocol = pruner.ant_protocol.as_ref().expect("pruner protocol");
    let pruner_storage = pruner_protocol.storage();
    let pruner_paid_list = Arc::clone(
        pruner
            .replication_engine
            .as_ref()
            .expect("pruner replication engine")
            .paid_list(),
    );
    let pruner_peer = *pruner_p2p.peer_id();

    // Even with all target peers storing the record, pruning must be blocked
    // while remote prune audits are not allowed during bootstrap/drain — but
    // the deferral must preserve candidacy and the first-seen timestamp.
    let (gate_content, gate_address, gate_targets) =
        find_remote_prune_candidate(&harness, pruner_idx, close_group_size, "bootstrap-gate").await;
    pruner_storage
        .put(&gate_address, &gate_content)
        .await
        .expect("put gate record on pruner");
    store_record_on_peers(&harness, &gate_targets, &gate_address, &gate_content).await;

    let blocked = pruning::run_prune_pass_with_context(pruning::PrunePassContext {
        self_id: &pruner_peer,
        storage: &pruner_storage,
        paid_list: &pruner_paid_list,
        p2p_node: &pruner_p2p,
        config: &config,
        sync_state: &sync_state,
        repair_proofs: &repair_proofs,
        allow_remote_prune_audits: false,
        commitment_state: None,
        audit_challenge_coordinator: &audit_challenge_coordinator,
    })
    .await;
    assert_eq!(blocked.records_pruned, 0);
    assert_eq!(
        blocked.records_candidates, 1,
        "the bootstrap gate must not remove candidate status"
    );
    assert_eq!(blocked.records_bootstrap_deferred, 1);
    assert!(
        pruner_storage.exists(&gate_address).expect("exists"),
        "record must not be pruned before remote audits are allowed"
    );
    let first_seen = pruner_paid_list
        .record_out_of_range_since(&gate_address)
        .expect("bootstrap-deferred record keeps its out-of-range timestamp");

    // A second blocked pass must not restart the hysteresis clock.
    let blocked_again = pruning::run_prune_pass_with_context(pruning::PrunePassContext {
        self_id: &pruner_peer,
        storage: &pruner_storage,
        paid_list: &pruner_paid_list,
        p2p_node: &pruner_p2p,
        config: &config,
        sync_state: &sync_state,
        repair_proofs: &repair_proofs,
        allow_remote_prune_audits: false,
        commitment_state: None,
        audit_challenge_coordinator: &audit_challenge_coordinator,
    })
    .await;
    assert_eq!(blocked_again.records_pruned, 0);
    assert_eq!(
        pruner_paid_list.record_out_of_range_since(&gate_address),
        Some(first_seen),
        "repeated deferrals must preserve the original first-seen time"
    );

    let confirmed = pruning::run_prune_pass_with_context(pruning::PrunePassContext {
        self_id: &pruner_peer,
        storage: &pruner_storage,
        paid_list: &pruner_paid_list,
        p2p_node: &pruner_p2p,
        config: &config,
        sync_state: &sync_state,
        repair_proofs: &repair_proofs,
        allow_remote_prune_audits: true,
        commitment_state: None,
        audit_challenge_coordinator: &audit_challenge_coordinator,
    })
    .await;
    assert_eq!(confirmed.records_audits_attempted, 1);
    assert_eq!(confirmed.records_pruned, 1);
    assert!(
        !pruner_storage.exists(&gate_address).expect("exists"),
        "record should be pruned after all target peers prove storage"
    );

    // If any current close-group peer lacks the record, the prune pass must
    // retain the local copy until that peer can prove it stores the bytes.
    let (missing_content, missing_address, missing_targets) =
        find_remote_prune_candidate(&harness, pruner_idx, close_group_size, "missing-proof").await;
    pruner_storage
        .put(&missing_address, &missing_content)
        .await
        .expect("put missing-proof record on pruner");
    store_record_on_peer(
        &harness,
        &missing_targets[0],
        &missing_address,
        &missing_content,
    )
    .await;

    let incomplete = pruning::run_prune_pass_with_context(pruning::PrunePassContext {
        self_id: &pruner_peer,
        storage: &pruner_storage,
        paid_list: &pruner_paid_list,
        p2p_node: &pruner_p2p,
        config: &config,
        sync_state: &sync_state,
        repair_proofs: &repair_proofs,
        allow_remote_prune_audits: true,
        commitment_state: None,
        audit_challenge_coordinator: &audit_challenge_coordinator,
    })
    .await;
    assert_eq!(incomplete.records_pruned, 0);
    assert_eq!(
        incomplete.records_audit_below_threshold, 1,
        "a below-threshold audit must be reported as such, not silently dropped"
    );
    assert!(
        pruner_storage.exists(&missing_address).expect("exists"),
        "record must remain local while any target peer lacks proof"
    );

    store_record_on_peers(
        &harness,
        &missing_targets,
        &missing_address,
        &missing_content,
    )
    .await;

    let complete = pruning::run_prune_pass_with_context(pruning::PrunePassContext {
        self_id: &pruner_peer,
        storage: &pruner_storage,
        paid_list: &pruner_paid_list,
        p2p_node: &pruner_p2p,
        config: &config,
        sync_state: &sync_state,
        repair_proofs: &repair_proofs,
        allow_remote_prune_audits: true,
        commitment_state: None,
        audit_challenge_coordinator: &audit_challenge_coordinator,
    })
    .await;
    assert_eq!(complete.records_pruned, 1);
    assert!(
        !pruner_storage.exists(&missing_address).expect("exists"),
        "record should prune once every current target peer proves storage"
    );

    harness.teardown().await.expect("teardown");
}

/// Pruner-retention veto (ADR-0002): a chunk the pruner is no longer responsible
/// for, but which is still committed under a recently-gossiped commitment, must
/// NOT be deleted — the storage-commitment audit's round-2 byte challenge could
/// still demand it, and deleting would turn an honest node's reply into an
/// `Absent` confirmed failure. The veto applies to DELETION only: the
/// out-of-range timer starts immediately even while the key is held. Once it is
/// no longer committed (e.g. it has aged out of the retention window, simulated
/// here by passing `None`), the same out-of-range record becomes prunable.
/// Drives the real `run_prune_pass` against live nodes.
#[tokio::test]
#[serial]
async fn test_prune_veto_for_committed_out_of_range_key() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let pruner_idx = 3;
    let close_group_size = 2;
    let config = prune_test_config(close_group_size);
    let sync_state = Arc::new(RwLock::new(NeighborSyncState::new_cycle(vec![])));
    let repair_proofs = Arc::new(RwLock::new(RepairProofs::new()));
    let audit_challenge_coordinator = Arc::new(AuditChallengeCoordinator::new());

    let pruner = harness.test_node(pruner_idx).expect("pruner");
    let pruner_p2p = Arc::clone(pruner.p2p_node.as_ref().expect("pruner p2p"));
    let pruner_storage = pruner.ant_protocol.as_ref().expect("protocol").storage();
    let pruner_paid_list = Arc::clone(
        pruner
            .replication_engine
            .as_ref()
            .expect("engine")
            .paid_list(),
    );
    let pruner_peer = *pruner_p2p.peer_id();

    // An out-of-range record fully confirmed on its remote close group — so the
    // ONLY thing that can keep it on the pruner is the retention veto.
    let (content, address, targets) =
        find_remote_prune_candidate(&harness, pruner_idx, close_group_size, "veto").await;
    pruner_storage
        .put(&address, &content)
        .await
        .expect("put record on pruner");
    store_record_on_peers(&harness, &targets, &address, &content).await;

    // A retained commitment that COMMITS to the out-of-range key (as if we
    // gossiped it just before the key left our range). A throwaway keypair is
    // fine: the pruner's veto consults only `is_held` (membership), not the
    // signature.
    let committed = ResponderCommitmentState::new();
    {
        let (pk, sk) = saorsa_pqc::api::sig::ml_dsa_65()
            .generate_keypair()
            .expect("keypair");
        let bytes_hash = *blake3::hash(&content).as_bytes();
        let built =
            BuiltCommitment::build(vec![(address, bytes_hash)], &[0; 32], &sk, &pk.to_bytes())
                .expect("build commitment");
        let h = built.hash();
        committed.rotate(built);
        committed.mark_gossiped(h);
    }
    let committed = Arc::new(committed);
    assert!(committed.is_held(&address), "test setup: key must be held");

    // With the key still committed, an otherwise-fully-prunable out-of-range
    // record is VETOED — but the out-of-range timer still starts.
    let vetoed = pruning::run_prune_pass_with_context(pruning::PrunePassContext {
        self_id: &pruner_peer,
        storage: &pruner_storage,
        paid_list: &pruner_paid_list,
        p2p_node: &pruner_p2p,
        config: &config,
        sync_state: &sync_state,
        repair_proofs: &repair_proofs,
        allow_remote_prune_audits: true,
        commitment_state: Some(&committed),
        audit_challenge_coordinator: &audit_challenge_coordinator,
    })
    .await;
    assert_eq!(
        vetoed.records_pruned, 0,
        "a key still committed under a recent commitment must not be pruned"
    );
    assert_eq!(vetoed.records_marked_out_of_range, 1);
    assert_eq!(vetoed.records_held_by_commitment, 1);
    assert!(
        pruner_paid_list
            .record_out_of_range_since(&address)
            .is_some(),
        "a retained commitment must not prevent the out-of-range timer from starting"
    );
    assert!(
        pruner_storage.exists(&address).expect("exists"),
        "the vetoed record must remain on disk"
    );

    // Once it is no longer committed (aged out of the retention window — modelled
    // by `None`), the same out-of-range record is prunable.
    let pruned = pruning::run_prune_pass_with_context(pruning::PrunePassContext {
        self_id: &pruner_peer,
        storage: &pruner_storage,
        paid_list: &pruner_paid_list,
        p2p_node: &pruner_p2p,
        config: &config,
        sync_state: &sync_state,
        repair_proofs: &repair_proofs,
        allow_remote_prune_audits: true,
        commitment_state: None,
        audit_challenge_coordinator: &audit_challenge_coordinator,
    })
    .await;
    assert_eq!(
        pruned.records_pruned, 1,
        "once no longer committed, the out-of-range record prunes normally"
    );
    assert!(
        !pruner_storage.exists(&address).expect("exists"),
        "the no-longer-committed record is reclaimed"
    );

    harness.teardown().await.expect("teardown");
}

/// Production-width prune liveness: close group 7, storage-retention width 9
/// (7 + `STORAGE_ADMISSION_MARGIN`), and a chunk the pruner holds (as if
/// admitted under the wider client-PUT gate) that is now outside width 9.
///
/// The prune-confirmation audit must reach the CURRENT key-nearest close
/// group directly from the routing table, with a completely EMPTY
/// `RepairProofs` table: no overlap between the pruner's neighbor-sync set
/// (self-nearest peers) and the key-nearest close group may be assumed. The
/// old repair-proof gate silently deferred candidacy here forever — the
/// production "pruning is hardly taking place" incident.
///
/// This test also pins both sides of the 6-of-7 possession threshold:
/// - below the threshold (5 of 7 proofs) the record must never be deleted,
///   no matter how many passes run (absent peers answer
///   `ABSENT_KEY_DIGEST`, which never counts positively);
/// - at the threshold (6 of 7 proofs) the record prunes even though one
///   peer still lacks the bytes.
#[tokio::test]
#[serial]
async fn prune_deletes_at_proof_threshold_and_retains_below_it() {
    /// Production close-group size (`CLOSE_GROUP_SIZE` in ant-protocol).
    const PROD_CLOSE_GROUP_SIZE: usize = 7;
    /// Prune proof threshold at production parameters: all but one, 6 of 7.
    const PRUNE_PROOFS_NEEDED: usize = 6;

    let harness = TestHarness::setup_small().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let pruner_idx = 3;
    let config = ReplicationConfig {
        close_group_size: PROD_CLOSE_GROUP_SIZE,
        // The ten-node harness cannot complete width 20, so this test remains
        // specifically about the 6-of-7 remote-proof path.
        paid_list_close_group_size: 20,
        prune_hysteresis_duration: Duration::ZERO,
        ..ReplicationConfig::default()
    };
    let sync_state = Arc::new(RwLock::new(NeighborSyncState::new_cycle(vec![])));
    // Deliberately empty and never populated: candidacy and target selection
    // must not depend on neighbor-sync repair hints.
    let repair_proofs = Arc::new(RwLock::new(RepairProofs::new()));
    let audit_challenge_coordinator = Arc::new(AuditChallengeCoordinator::new());

    let pruner = harness.test_node(pruner_idx).expect("pruner");
    let pruner_p2p = Arc::clone(pruner.p2p_node.as_ref().expect("pruner p2p"));
    let pruner_protocol = pruner.ant_protocol.as_ref().expect("pruner protocol");
    let pruner_storage = pruner_protocol.storage();
    let pruner_paid_list = Arc::clone(
        pruner
            .replication_engine
            .as_ref()
            .expect("pruner replication engine")
            .paid_list(),
    );
    let pruner_peer = *pruner_p2p.peer_id();

    // `find_remote_prune_candidate` guarantees the pruner is outside the
    // width-9 storage-retention group for the key (and outside the strict 7).
    let (content, address, targets) =
        find_remote_prune_candidate(&harness, pruner_idx, PROD_CLOSE_GROUP_SIZE, "quorum-stored")
            .await;
    pruner_storage
        .put(&address, &content)
        .await
        .expect("put record on pruner");

    // Replicate below the threshold: only 5 of 7 peers hold the bytes.
    store_record_on_peers(
        &harness,
        &targets[..PRUNE_PROOFS_NEEDED - 1],
        &address,
        &content,
    )
    .await;

    // Below the threshold the local copy is load-bearing: deleting it would
    // shrink the proven replica set past the prune safety bar, so every
    // pass must retain it — while still ATTEMPTING the audit each pass.
    for pass in 0..3 {
        let result = pruning::run_prune_pass_with_context(pruning::PrunePassContext {
            self_id: &pruner_peer,
            storage: &pruner_storage,
            paid_list: &pruner_paid_list,
            p2p_node: &pruner_p2p,
            config: &config,
            sync_state: &sync_state,
            repair_proofs: &repair_proofs,
            allow_remote_prune_audits: true,
            commitment_state: None,
            audit_challenge_coordinator: &audit_challenge_coordinator,
        })
        .await;
        assert_eq!(
            result.records_audits_attempted, 1,
            "pass {pass}: the candidate must be audited despite the empty repair-proof table",
        );
        assert_eq!(
            result.records_pruned, 0,
            "pass {pass}: a record below the proof threshold must never prune",
        );
        assert_eq!(
            result.records_audit_below_threshold, 1,
            "pass {pass}: the failed confirmation must surface in telemetry",
        );
        assert!(
            pruner_storage.exists(&address).expect("exists"),
            "pass {pass}: record should remain on the out-of-range node",
        );
    }

    // One more holder reaches the threshold (6 of 7). The prune must now
    // proceed even though one close-group peer still lacks the bytes:
    // demanding unanimity left prod fleets unable to prune at all.
    store_record_on_peer(
        &harness,
        targets
            .get(PRUNE_PROOFS_NEEDED - 1)
            .expect("threshold target"),
        &address,
        &content,
    )
    .await;
    let at_threshold = pruning::run_prune_pass_with_context(pruning::PrunePassContext {
        self_id: &pruner_peer,
        storage: &pruner_storage,
        paid_list: &pruner_paid_list,
        p2p_node: &pruner_p2p,
        config: &config,
        sync_state: &sync_state,
        repair_proofs: &repair_proofs,
        allow_remote_prune_audits: true,
        commitment_state: None,
        audit_challenge_coordinator: &audit_challenge_coordinator,
    })
    .await;
    assert_eq!(
        at_threshold.records_pruned, 1,
        "a record proven on all but one of the close group must prune",
    );
    assert!(!pruner_storage.exists(&address).expect("exists"));

    harness.teardown().await.expect("teardown");
}

/// Hysteresis lifecycle against live nodes: a record outside the retention
/// width is marked immediately, is NOT a candidate while the hysteresis is
/// running, and becomes a candidate that prunes — with an empty
/// `RepairProofs` table — once continuously out of range for the full
/// (test-shortened) hysteresis.
#[tokio::test]
#[serial]
async fn prune_marks_immediately_and_candidacy_waits_for_hysteresis() {
    /// Test stand-in for the 3-day production hysteresis. Long enough that the
    /// two pre-maturity prune passes reliably run inside the window, short
    /// enough to keep the test fast.
    const TEST_HYSTERESIS: Duration = Duration::from_secs(2);

    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let pruner_idx = 3;
    let close_group_size = 2;
    let config = ReplicationConfig {
        prune_hysteresis_duration: TEST_HYSTERESIS,
        ..prune_test_config(close_group_size)
    };
    let sync_state = Arc::new(RwLock::new(NeighborSyncState::new_cycle(vec![])));
    let repair_proofs = Arc::new(RwLock::new(RepairProofs::new()));
    let audit_challenge_coordinator = Arc::new(AuditChallengeCoordinator::new());

    let pruner = harness.test_node(pruner_idx).expect("pruner");
    let pruner_p2p = Arc::clone(pruner.p2p_node.as_ref().expect("pruner p2p"));
    let pruner_storage = pruner.ant_protocol.as_ref().expect("protocol").storage();
    let pruner_paid_list = Arc::clone(
        pruner
            .replication_engine
            .as_ref()
            .expect("engine")
            .paid_list(),
    );
    let pruner_peer = *pruner_p2p.peer_id();

    let (content, address, targets) =
        find_remote_prune_candidate(&harness, pruner_idx, close_group_size, "hysteresis").await;
    pruner_storage
        .put(&address, &content)
        .await
        .expect("put record on pruner");
    store_record_on_peers(&harness, &targets, &address, &content).await;

    // Pass 1: the record is marked out-of-range immediately, but the running
    // hysteresis keeps it from candidacy.
    let marked = pruning::run_prune_pass_with_context(pruning::PrunePassContext {
        self_id: &pruner_peer,
        storage: &pruner_storage,
        paid_list: &pruner_paid_list,
        p2p_node: &pruner_p2p,
        config: &config,
        sync_state: &sync_state,
        repair_proofs: &repair_proofs,
        allow_remote_prune_audits: true,
        commitment_state: None,
        audit_challenge_coordinator: &audit_challenge_coordinator,
    })
    .await;
    assert_eq!(marked.records_marked_out_of_range, 1);
    assert_eq!(marked.records_hysteresis_pending, 1);
    assert_eq!(marked.records_candidates, 0);
    assert_eq!(marked.records_pruned, 0);
    let first_seen = pruner_paid_list
        .record_out_of_range_since(&address)
        .expect("out-of-range timestamp set on first observation");

    // Pass 2 (immediately after): still pending, timer NOT restarted.
    let pending = pruning::run_prune_pass_with_context(pruning::PrunePassContext {
        self_id: &pruner_peer,
        storage: &pruner_storage,
        paid_list: &pruner_paid_list,
        p2p_node: &pruner_p2p,
        config: &config,
        sync_state: &sync_state,
        repair_proofs: &repair_proofs,
        allow_remote_prune_audits: true,
        commitment_state: None,
        audit_challenge_coordinator: &audit_challenge_coordinator,
    })
    .await;
    assert_eq!(pending.records_marked_out_of_range, 0);
    assert_eq!(pending.records_hysteresis_pending, 1);
    assert_eq!(pending.records_pruned, 0);
    assert_eq!(
        pruner_paid_list.record_out_of_range_since(&address),
        Some(first_seen),
        "continuously out-of-range records keep their original first-seen time"
    );

    // Pass 3 (after the hysteresis): candidate, audited, and pruned — with an
    // empty repair-proof table.
    tokio::time::sleep(TEST_HYSTERESIS + Duration::from_millis(100)).await;
    let matured = pruning::run_prune_pass_with_context(pruning::PrunePassContext {
        self_id: &pruner_peer,
        storage: &pruner_storage,
        paid_list: &pruner_paid_list,
        p2p_node: &pruner_p2p,
        config: &config,
        sync_state: &sync_state,
        repair_proofs: &repair_proofs,
        allow_remote_prune_audits: true,
        commitment_state: None,
        audit_challenge_coordinator: &audit_challenge_coordinator,
    })
    .await;
    assert_eq!(matured.records_candidates, 1);
    assert_eq!(matured.records_audits_attempted, 1);
    assert_eq!(
        matured.records_pruned, 1,
        "the matured candidate must prune without any repair-hint history"
    );
    assert!(!pruner_storage.exists(&address).expect("exists"));

    harness.teardown().await.expect("teardown");
}

/// Paid-list entry pruning requires confirmations from the current paid
/// close group (three quarters rounded up, 15 of 20 at production
/// parameters), independent of chunk possession.
///
/// An out-of-range `PaidForList` entry used to be removed on local state
/// alone once the hysteresis elapsed. It is now retained until enough of
/// the current paid close group confirm they track the key in their own
/// paid lists, so a node never forgets an authorization the group has not
/// already absorbed. Chunk pruning and paid pruning check their own gates
/// only: this test stores no chunk anywhere.
///
/// Run with a 2-peer paid close group, where the threshold is both peers.
#[tokio::test]
#[serial]
async fn paid_prune_requires_paid_close_group_confirmations() {
    const PAID_GROUP: usize = 2;

    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let pruner_idx = 3;
    let config = ReplicationConfig {
        close_group_size: 2,
        quorum_threshold: 1,
        paid_list_close_group_size: PAID_GROUP,
        prune_hysteresis_duration: Duration::ZERO,
        ..ReplicationConfig::default()
    };
    let sync_state = Arc::new(RwLock::new(NeighborSyncState::new_cycle(vec![])));
    let repair_proofs = Arc::new(RwLock::new(RepairProofs::new()));
    let audit_challenge_coordinator = Arc::new(AuditChallengeCoordinator::new());

    let pruner = harness.test_node(pruner_idx).expect("pruner");
    let pruner_p2p = Arc::clone(pruner.p2p_node.as_ref().expect("pruner p2p"));
    let pruner_protocol = pruner.ant_protocol.as_ref().expect("pruner protocol");
    let pruner_storage = pruner_protocol.storage();
    let pruner_peer = *pruner_p2p.peer_id();

    // Standalone paid list so the engine's own paid state stays untouched.
    let paid_dir = tempfile::tempdir().expect("tempdir");
    let paid_list = Arc::new(
        ant_node::replication::paid_list::PaidList::new(paid_dir.path())
            .await
            .expect("paid list"),
    );

    let (_content, address, targets) =
        find_remote_prune_candidate(&harness, pruner_idx, PAID_GROUP, "paid-prune").await;
    paid_list.insert(&address).await.expect("insert paid key");

    // The paid close group does not track the key yet: the entry must be
    // retained even though it is out of range and past hysteresis.
    let unconfirmed = pruning::run_prune_pass_with_context(pruning::PrunePassContext {
        self_id: &pruner_peer,
        storage: &pruner_storage,
        paid_list: &paid_list,
        p2p_node: &pruner_p2p,
        config: &config,
        sync_state: &sync_state,
        repair_proofs: &repair_proofs,
        allow_remote_prune_audits: true,
        commitment_state: None,
        audit_challenge_coordinator: &audit_challenge_coordinator,
    })
    .await;
    assert_eq!(
        unconfirmed.paid_entries_pruned, 0,
        "a paid entry without paid close-group confirmations must never prune",
    );
    assert!(
        paid_list.contains(&address).expect("contains"),
        "unconfirmed paid entry should remain tracked",
    );

    // Once the whole paid close group confirms the key in their paid lists,
    // the entry prunes.
    for peer in &targets {
        let idx = node_index_for_peer(&harness, peer).expect("target in harness");
        let engine = harness
            .test_node(idx)
            .expect("target node")
            .replication_engine
            .as_ref()
            .expect("target engine");
        engine.paid_list().insert(&address).await.expect("insert");
    }

    let confirmed = pruning::run_prune_pass_with_context(pruning::PrunePassContext {
        self_id: &pruner_peer,
        storage: &pruner_storage,
        paid_list: &paid_list,
        p2p_node: &pruner_p2p,
        config: &config,
        sync_state: &sync_state,
        repair_proofs: &repair_proofs,
        allow_remote_prune_audits: true,
        commitment_state: None,
        audit_challenge_coordinator: &audit_challenge_coordinator,
    })
    .await;
    assert_eq!(
        confirmed.paid_entries_pruned, 1,
        "a paid entry confirmed by the paid close group must prune",
    );
    assert!(
        !paid_list.contains(&address).expect("contains"),
        "confirmed paid entry should be removed",
    );

    harness.teardown().await.expect("teardown");
}

/// Fetch not-found returns `NotFound`.
///
/// Request a key that does not exist on the target node and verify
/// the response is `FetchResponse::NotFound`.
#[tokio::test]
#[serial]
async fn test_fetch_not_found() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_a = node_a.p2p_node.as_ref().expect("p2p_a");
    let peer_a = *p2p_a.peer_id();

    let missing_key = [0xEE; 32];
    let request = FetchRequest { key: missing_key };
    let msg = ReplicationMessage {
        request_id: 77,
        body: ReplicationMessageBody::FetchRequest(request),
    };

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    assert!(
        matches!(
            resp_msg.body,
            ReplicationMessageBody::FetchResponse(FetchResponse::NotFound { .. })
        ),
        "Expected FetchResponse::NotFound"
    );

    harness.teardown().await.expect("teardown");
}

/// Verification with paid-list check.
///
/// Store a chunk AND add it to the paid list on node A, then send a
/// verification request with `paid_list_check_indices` and confirm the
/// response reports both presence and paid status.
#[tokio::test]
#[serial]
async fn test_verification_with_paid_list_check() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_a = node_a.p2p_node.as_ref().expect("p2p_a");

    // Store a chunk AND add to paid list on node A
    let content = b"paid test data";
    let address = compute_address(content);
    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol_a");
    protocol_a
        .storage()
        .put(&address, content)
        .await
        .expect("put");

    if let Some(ref engine) = node_a.replication_engine {
        engine
            .paid_list()
            .insert(&address)
            .await
            .expect("paid_list insert");
    }

    // Send verification with paid-list check for index 0
    let request = VerificationRequest {
        keys: vec![address],
        paid_list_check_indices: vec![0],
    };
    let msg = ReplicationMessage {
        request_id: 55,
        body: ReplicationMessageBody::VerificationRequest(request),
    };

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *p2p_a.peer_id();
    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    if let ReplicationMessageBody::VerificationResponse(resp) = resp_msg.body {
        assert_eq!(resp.results.len(), 1);
        assert!(resp.results[0].present, "Key should be present");
        assert_eq!(
            resp.results[0].paid,
            Some(true),
            "Key should be in PaidForList"
        );
    } else {
        panic!("Expected VerificationResponse");
    }

    harness.teardown().await.expect("teardown");
}

/// Fresh write with empty `PoP` rejected (Section 18 #2).
///
/// Send a `FreshReplicationOffer` with an empty `proof_of_payment` and
/// verify the receiver rejects it without storing the chunk.
#[tokio::test]
#[serial]
async fn test_fresh_offer_with_empty_pop_rejected() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *node_a.p2p_node.as_ref().expect("p2p_a").peer_id();

    let content = b"invalid pop test";
    let address = ant_node::client::compute_address(content);

    // Send fresh offer with EMPTY PoP
    let offer = FreshReplicationOffer {
        key: address,
        data: content.to_vec(),
        proof_of_payment: vec![], // Empty!
    };
    let msg = ReplicationMessage {
        request_id: 1000,
        body: ReplicationMessageBody::FreshReplicationOffer(offer),
    };

    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    match resp_msg.body {
        ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
            reason,
            ..
        }) => {
            assert!(
                reason.contains("proof of payment") || reason.contains("Missing"),
                "Should mention missing PoP, got: {reason}"
            );
        }
        other => panic!("Expected Rejected, got: {other:?}"),
    }

    // Verify chunk was NOT stored
    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol");
    assert!(
        !protocol_a.storage().exists(&address).unwrap_or(false),
        "Chunk should not be stored with empty PoP"
    );

    harness.teardown().await.expect("teardown");
}

/// Fresh write with a key that does not match the supplied bytes is rejected
/// before payment verification.
#[tokio::test]
#[serial]
async fn test_fresh_offer_with_mismatched_content_address_rejected() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *node_a.p2p_node.as_ref().expect("p2p_a").peer_id();

    let content = b"mismatched fresh offer content";
    let actual_address = compute_address(content);
    let mut wrong_address = actual_address;
    wrong_address[0] ^= 0xFF;

    let offer = FreshReplicationOffer {
        key: wrong_address,
        data: content.to_vec(),
        proof_of_payment: vec![0x01; 64],
    };
    let msg = ReplicationMessage {
        request_id: 1001,
        body: ReplicationMessageBody::FreshReplicationOffer(offer),
    };

    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    match resp_msg.body {
        ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
            reason,
            ..
        }) => {
            assert!(
                reason.contains("Content address mismatch"),
                "Should mention content address mismatch, got: {reason}"
            );
        }
        other => panic!("Expected Rejected, got: {other:?}"),
    }

    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol");
    assert!(
        !protocol_a.storage().exists(&wrong_address).unwrap_or(false),
        "Chunk should not be stored under the wrong address"
    );
    assert!(
        !protocol_a
            .storage()
            .exists(&actual_address)
            .unwrap_or(false),
        "Chunk should not be stored under the actual address after rejected offer"
    );

    harness.teardown().await.expect("teardown");
}

/// Neighbor sync request returns a sync response (Section 18 #5/#37).
///
/// Send a `NeighborSyncRequest` from one node to another and verify we
/// receive a well-formed `NeighborSyncResponse`.
#[tokio::test]
#[serial]
async fn test_neighbor_sync_request_returns_hints() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *node_a.p2p_node.as_ref().expect("p2p_a").peer_id();

    // Store something on A so it has hints to share
    let content = b"sync test data";
    let address = ant_node::client::compute_address(content);
    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol");
    protocol_a
        .storage()
        .put(&address, content)
        .await
        .expect("put");

    // Send sync request
    let request = NeighborSyncRequest {
        replica_hints: vec![],
        paid_hints: vec![],
        bootstrapping: false,
        commitment: None,
    };
    let msg = ReplicationMessage {
        request_id: 2000,
        body: ReplicationMessageBody::NeighborSyncRequest(request),
    };

    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    match resp_msg.body {
        ReplicationMessageBody::NeighborSyncResponse(resp) => {
            // Node A should return a sync response (may or may not contain hints
            // depending on whether B is in A's close group for any keys)
            assert!(!resp.bootstrapping, "Node A shouldn't claim bootstrapping");
            // The response is valid -- that's the main assertion
        }
        other => panic!("Expected NeighborSyncResponse, got: {other:?}"),
    }

    harness.teardown().await.expect("teardown");
}

/// Audit challenge with multiple keys, some present and some absent
/// (Section 18 #11).
///
/// Challenge a node with three keys (two stored, one missing) and verify
/// per-key digest correctness.
#[tokio::test]
#[serial]
async fn test_audit_challenge_multi_key() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_a = node_a.p2p_node.as_ref().expect("p2p_a");
    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol_a");

    // Store four chunks on A so the dynamic audit key limit (2 * sqrt(4) = 4)
    // accommodates our 3-key challenge.  Only c1 and c2 are challenged; c3
    // and c4 just raise the stored-chunk count.
    let c1 = b"audit multi key 1";
    let c2 = b"audit multi key 2";
    let c3 = b"audit multi key 3 (padding)";
    let c4 = b"audit multi key 4 (padding)";
    let a1 = ant_node::client::compute_address(c1);
    let a2 = ant_node::client::compute_address(c2);
    let a3 = ant_node::client::compute_address(c3);
    let a4 = ant_node::client::compute_address(c4);
    protocol_a.storage().put(&a1, c1).await.expect("put 1");
    protocol_a.storage().put(&a2, c2).await.expect("put 2");
    protocol_a.storage().put(&a3, c3).await.expect("put 3");
    protocol_a.storage().put(&a4, c4).await.expect("put 4");

    let absent_key = [0xCC; 32];
    let peer_a = *p2p_a.peer_id();
    let nonce = [0x55; 32];

    let challenge = AuditChallenge {
        challenge_id: 3000,
        nonce,
        challenged_peer_id: *peer_a.as_bytes(),
        keys: vec![a1, absent_key, a2],
    };
    let msg = ReplicationMessage {
        request_id: 3000,
        body: ReplicationMessageBody::AuditChallenge(challenge),
    };

    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    if let ReplicationMessageBody::AuditResponse(AuditResponse::Digests {
        challenge_id,
        digests,
    }) = resp_msg.body
    {
        assert_eq!(challenge_id, 3000);
        assert_eq!(digests.len(), 3);

        // Key 1 -- correct digest
        let expected_1 = compute_audit_digest(&nonce, peer_a.as_bytes(), &a1, c1);
        assert_eq!(digests[0], expected_1, "First key digest should match");

        // Key 2 -- absent sentinel
        assert_eq!(
            digests[1], ABSENT_KEY_DIGEST,
            "Absent key should be sentinel"
        );

        // Key 3 -- correct digest
        let expected_2 = compute_audit_digest(&nonce, peer_a.as_bytes(), &a2, c2);
        assert_eq!(digests[2], expected_2, "Third key digest should match");
    } else {
        panic!("Expected AuditResponse::Digests");
    }

    harness.teardown().await.expect("teardown");
}

/// Fetch returns `NotFound` for a zeroed-out key (variant of the basic
/// not-found test).
///
/// Request a key that is all zeros -- not a valid content address -- and
/// verify the response is `FetchResponse::NotFound`.
#[tokio::test]
#[serial]
async fn test_fetch_returns_error_for_corrupt_key() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_a = node_a.p2p_node.as_ref().expect("p2p_a");
    let peer_a = *p2p_a.peer_id();

    let fake_key = [0x00; 32];
    let request = FetchRequest { key: fake_key };
    let msg = ReplicationMessage {
        request_id: 4000,
        body: ReplicationMessageBody::FetchRequest(request),
    };
    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    assert!(
        matches!(
            resp_msg.body,
            ReplicationMessageBody::FetchResponse(FetchResponse::NotFound { .. })
        ),
        "Expected NotFound for non-existent key"
    );

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #1/#24: Fresh replication stores + PaidNotify
// =========================================================================

/// Fresh replication stores chunk on remote peer AND updates their `PaidForList`
/// (Section 18 #1 + #24 combined).
///
/// Store a chunk on node A, call `replicate_fresh`, wait for propagation, then
/// verify at least one remote node has the chunk in both storage and `PaidForList`.
#[tokio::test]
#[serial]
async fn scenario_1_and_24_fresh_replication_stores_and_propagates_paid_list() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let source_idx = 3;
    let source = harness.test_node(source_idx).expect("source");
    let protocol = source.ant_protocol.as_ref().expect("protocol");
    let storage = protocol.storage();

    let content = b"scenario 3 quorum pass test";
    let address = compute_address(content);
    storage.put(&address, content).await.expect("put");

    // Pre-populate payment cache on ALL nodes so receivers accept the offer
    // (bypasses EVM verification, which is unavailable without Anvil).
    for i in 0..harness.node_count() {
        if let Some(node) = harness.test_node(i) {
            if let Some(p) = &node.ant_protocol {
                p.payment_verifier().cache_insert(address);
            }
        }
    }

    // Trigger fresh replication (sends FreshReplicationOffer + PaidNotify)
    let dummy_pop = [0x01u8; 64];
    if let Some(ref engine) = source.replication_engine {
        engine.replicate_fresh(&address, content, &dummy_pop).await;
    }

    // Poll until replication propagates (or timeout).
    let deadline = tokio::time::Instant::now() + PROPAGATION_TIMEOUT;
    let mut stored_elsewhere = false;
    let mut paid_listed_elsewhere = false;
    loop {
        for i in 0..harness.node_count() {
            if i == source_idx {
                continue;
            }
            if let Some(node) = harness.test_node(i) {
                if let Some(p) = &node.ant_protocol {
                    if p.storage().exists(&address).unwrap_or(false) {
                        stored_elsewhere = true;
                    }
                }
                if let Some(ref engine) = node.replication_engine {
                    if engine.paid_list().contains(&address).unwrap_or(false) {
                        paid_listed_elsewhere = true;
                    }
                }
            }
        }
        if (stored_elsewhere && paid_listed_elsewhere) || tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(PROPAGATION_POLL_INTERVAL).await;
    }
    assert!(
        stored_elsewhere,
        "Chunk should be stored on at least one other node"
    );
    assert!(
        paid_listed_elsewhere,
        "Key should be in PaidForList on at least one other node"
    );

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #9: Fetch retry with alternate source
// =========================================================================

/// When a fetch fails, the queue rotates to the next untried source
/// (Section 18 #9).
///
/// Tested via direct `ReplicationQueues` manipulation since we cannot
/// deterministically trigger network failures in e2e.
#[tokio::test]
#[serial]
async fn scenario_9_fetch_retry_uses_alternate_source() {
    let mut queues = ReplicationQueues::new();
    let key = [0x09; 32];
    let distance = [0x01; 32];
    let source_a = PeerId::from_bytes([0xA0; 32]);
    let source_b = PeerId::from_bytes([0xB0; 32]);

    // Enqueue with two sources
    queues.enqueue_fetch(key, distance, vec![source_a, source_b]);
    let candidate = queues.dequeue_fetch().expect("dequeue");

    // Start in-flight with first source
    queues.start_dequeued_fetch(candidate, source_a);

    // First source fails -> retry should give source_b
    let next = queues.retry_fetch(&key);
    assert_eq!(next, Some(source_b), "Should retry with alternate source");

    // Second source fails -> no more sources
    let exhausted = queues.retry_fetch(&key);
    assert!(exhausted.is_none(), "No more sources available");
}

// =========================================================================
// Section 18, Scenario #10: Fetch retry exhaustion
// =========================================================================

/// When all sources fail, the fetch is exhausted and can be completed
/// (Section 18 #10).
#[tokio::test]
#[serial]
async fn scenario_10_fetch_retry_exhaustion() {
    let mut queues = ReplicationQueues::new();
    let key = [0x10; 32];
    let distance = [0x01; 32];
    let source = PeerId::from_bytes([0xC0; 32]);

    // Single source
    queues.enqueue_fetch(key, distance, vec![source]);
    let candidate = queues.dequeue_fetch().expect("dequeue");
    queues.start_dequeued_fetch(candidate, source);

    // Source fails -> no alternates -> exhausted
    let next = queues.retry_fetch(&key);
    assert!(next.is_none(), "Single source exhausted");

    // Complete the fetch (abandon)
    let entry = queues.complete_fetch(&key);
    assert!(entry.is_some(), "Should have in-flight entry to complete");
    assert_eq!(queues.in_flight_count(), 0);
}

// =========================================================================
// Section 18, Scenario #11: Repeated failures -> trust penalty
// =========================================================================

/// Multiple application failures from a peer decrease its trust score
/// (Section 18 #11).
#[tokio::test]
#[serial]
async fn scenario_11_repeated_failures_decrease_trust() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_a = node_a.p2p_node.as_ref().expect("p2p_a");
    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_b = *p2p_b.peer_id();

    // Get initial trust score for node B (should be neutral ~0.5)
    // Switched on explicitly. The release that moves nodes off the legacy chunk store
    // withholds this penalty by default, so a test that asserts it must say so, or it
    // silently starts asserting whichever release it is compiled against.
    ant_node::replication::config::set_close_group_storage_penalty_suspended(false);

    let initial_trust = p2p_a.peer_trust(&peer_b);

    // Report multiple application failures
    let failure_count = 5;
    let failure_weight = 3.0;
    for _ in 0..failure_count {
        p2p_a
            .report_trust_event(&peer_b, TrustEvent::ApplicationFailure(failure_weight))
            .await;
    }

    let final_trust = p2p_a.peer_trust(&peer_b);
    assert!(
        final_trust < initial_trust,
        "Trust should decrease after repeated failures: {initial_trust} -> {final_trust}"
    );

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #12: Bootstrap quorum aggregation
// =========================================================================

/// A bootstrapping node queries multiple peers and discovers that a key
/// meets the multi-peer presence threshold (Section 18 #12).
///
/// Store a chunk on nodes 0-3 (4 holders), then have node 4 send
/// verification requests to all holders. The querying node should receive
/// enough presence confirmations to meet the quorum threshold.
#[tokio::test]
#[serial]
async fn scenario_12_bootstrap_quorum_aggregation() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let content = b"bootstrap quorum test";
    let address = compute_address(content);

    // Store chunk + paid-list entry on nodes 0-3 (4 holders)
    let holder_count = 4;
    for idx in 0..holder_count {
        let node = harness.test_node(idx).expect("node");
        let protocol = node.ant_protocol.as_ref().expect("protocol");
        protocol
            .storage()
            .put(&address, content)
            .await
            .expect("put");
        if let Some(ref engine) = node.replication_engine {
            engine
                .paid_list()
                .insert(&address)
                .await
                .expect("paid insert");
        }
    }

    // Node 4 acts as the bootstrapping node: query each holder for presence
    let querier = harness.test_node(4).expect("querier");
    let p2p_q = querier.p2p_node.as_ref().expect("p2p");

    let mut presence_confirmations = 0u32;
    let mut paid_confirmations = 0u32;
    for idx in 0..holder_count {
        let target = harness.test_node(idx).expect("target");
        let peer = *target.p2p_node.as_ref().expect("p2p").peer_id();

        let request = VerificationRequest {
            keys: vec![address],
            paid_list_check_indices: vec![0],
        };
        let msg = ReplicationMessage {
            request_id: 1200 + idx as u64,
            body: ReplicationMessageBody::VerificationRequest(request),
        };

        let resp_msg = send_replication_request(p2p_q, &peer, msg, Duration::from_secs(10)).await;
        if let ReplicationMessageBody::VerificationResponse(resp) = resp_msg.body {
            if let Some(result) = resp.results.first() {
                if result.present {
                    presence_confirmations += 1;
                }
                if result.paid == Some(true) {
                    paid_confirmations += 1;
                }
            }
        }
    }

    // Quorum threshold is floor(CLOSE_GROUP_SIZE/2)+1 = 4, but dynamic
    // QuorumNeeded uses min(4, floor(|targets|/2)+1). With 4 targets:
    // min(4, 3) = 3. Require at least 3 confirmations.
    let min_quorum = 3;
    assert!(
        presence_confirmations >= min_quorum,
        "Bootstrap node should receive enough presence confirmations for quorum: \
         got {presence_confirmations}, need {min_quorum}"
    );
    assert!(
        paid_confirmations >= min_quorum,
        "Bootstrap node should receive enough paid-list confirmations: \
         got {paid_confirmations}, need {min_quorum}"
    );

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #14: Coverage under backlog
// =========================================================================

/// Under load, neighbor-sync hint construction covers the full local
/// inventory: when node A stores multiple chunks and node B sends a
/// `NeighborSyncRequest`, A's response hints include all locally stored
/// keys that B should hold (Section 18 #14).
#[tokio::test]
#[serial]
async fn scenario_14_sync_hints_cover_all_local_keys() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *node_a.p2p_node.as_ref().expect("p2p_a").peer_id();

    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol_a");
    let storage_a = protocol_a.storage();

    // Store multiple chunks on node A (simulating backlog)
    let chunk_count = 10u8;
    let mut addresses = Vec::new();
    for i in 0..chunk_count {
        let content = format!("backlog test chunk {i}");
        let address = compute_address(content.as_bytes());
        storage_a
            .put(&address, content.as_bytes())
            .await
            .expect("put");
        addresses.push(address);
    }

    // Verify the local inventory is complete
    let all_keys = storage_a.all_keys().await.expect("all_keys");
    assert_eq!(
        all_keys.len(),
        addresses.len(),
        "all_keys should cover every stored chunk"
    );

    // Send a NeighborSyncRequest from B to A and inspect the response hints.
    let request = NeighborSyncRequest {
        replica_hints: vec![],
        paid_hints: vec![],
        bootstrapping: false,
        commitment: None,
    };
    let msg = ReplicationMessage {
        request_id: 1400,
        body: ReplicationMessageBody::NeighborSyncRequest(request),
    };

    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    let hints = match resp_msg.body {
        ReplicationMessageBody::NeighborSyncResponse(resp) => resp.replica_hints,
        other => panic!("Expected NeighborSyncResponse, got: {other:?}"),
    };

    // Node A builds replica hints for B based on B's close-group membership.
    // In a 5-node network every node is close to every key, so the hints
    // should include ALL locally stored keys.
    for addr in &addresses {
        assert!(
            hints.contains(addr),
            "Sync response hints should include stored key {addr:?}; \
             got {} hints total",
            hints.len()
        );
    }

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #15: Partition and heal
// =========================================================================

/// Partition and heal: data and paid-list authorization survive a network
/// partition. After the partition, remaining nodes can still confirm
/// paid-list status via verification requests, enabling recovery
/// (Section 18 #15).
#[tokio::test]
#[serial]
async fn scenario_15_partition_and_heal() {
    let mut harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let content = b"partition test data";
    let address = compute_address(content);

    // Store chunk + paid-list entry on nodes 3 AND 4
    for idx in [3, 4] {
        let node = harness.test_node(idx).expect("node");
        let protocol = node.ant_protocol.as_ref().expect("protocol");
        protocol
            .storage()
            .put(&address, content)
            .await
            .expect("put");
        if let Some(ref engine) = node.replication_engine {
            engine
                .paid_list()
                .insert(&address)
                .await
                .expect("paid insert");
        }
    }

    // "Partition": shut down node 4 (simulates peer loss)
    harness.shutdown_node(4).await.expect("shutdown");

    // Data should still exist on node 3
    let node3 = harness.test_node(3).expect("node3 after partition");
    let protocol3 = node3.ant_protocol.as_ref().expect("protocol");
    assert!(
        protocol3.storage().exists(&address).expect("exists"),
        "Data should survive partition on remaining node"
    );

    // Paid-list authorization still confirmable: query remaining nodes
    // (0,1,2,3) from node 0. Node 3 should confirm paid status.
    let querier = harness.test_node(0).expect("querier");
    let p2p_q = querier.p2p_node.as_ref().expect("p2p");

    let node3_peer = *node3.p2p_node.as_ref().expect("p2p").peer_id();
    let request = VerificationRequest {
        keys: vec![address],
        paid_list_check_indices: vec![0],
    };
    let msg = ReplicationMessage {
        request_id: 1500,
        body: ReplicationMessageBody::VerificationRequest(request),
    };

    let resp_msg = send_replication_request(p2p_q, &node3_peer, msg, Duration::from_secs(10)).await;
    if let ReplicationMessageBody::VerificationResponse(resp) = resp_msg.body {
        let result = resp.results.first().expect("should have a result");
        assert!(
            result.present,
            "Node 3 should still report chunk as present after partition"
        );
        assert_eq!(
            result.paid,
            Some(true),
            "Node 3 should still confirm paid-list status — this enables recovery \
             when paid-list authorization survives the partition"
        );
    } else {
        panic!("Expected VerificationResponse");
    }

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #17: Admission asymmetry
// =========================================================================

/// When sender IS in receiver's `LocalRT`, sync is bidirectional: the
/// receiver sends outbound hints AND accepts inbound hints. This test
/// verifies the outbound direction: after warmup (all nodes in each
/// other's RT), node A stores data, node B sends sync, and A's response
/// includes replica hints for its stored keys (Section 18 #17).
///
/// The inbound admission guard (dropping hints from non-RT senders) is
/// tested in the unit-level `admission.rs` tests.
#[tokio::test]
#[serial]
async fn scenario_17_bidirectional_sync_when_sender_in_rt() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let node_a = harness.test_node(3).expect("node_a");
    let node_b = harness.test_node(4).expect("node_b");
    let p2p_b = node_b.p2p_node.as_ref().expect("p2p_b");
    let peer_a = *node_a.p2p_node.as_ref().expect("p2p_a").peer_id();

    // Store data on node A so it has something to hint about
    let content = b"admission asymmetry test";
    let address = compute_address(content);
    let protocol_a = node_a.ant_protocol.as_ref().expect("protocol");
    protocol_a
        .storage()
        .put(&address, content)
        .await
        .expect("put");

    // B sends sync request with a hint for a fabricated key
    let inbound_hint = [0x17; 32];
    let request = NeighborSyncRequest {
        replica_hints: vec![inbound_hint],
        paid_hints: vec![],
        bootstrapping: false,
        commitment: None,
    };
    let msg = ReplicationMessage {
        request_id: 1700,
        body: ReplicationMessageBody::NeighborSyncRequest(request),
    };

    let resp_msg = send_replication_request(p2p_b, &peer_a, msg, Duration::from_secs(10)).await;
    match resp_msg.body {
        ReplicationMessageBody::NeighborSyncResponse(resp) => {
            assert!(!resp.bootstrapping, "Node A should not claim bootstrapping");

            // A should send outbound hints back to B — in a 5-node network
            // after warmup, B is in A's close group for all keys, so A's
            // stored key should appear in the replica hints.
            assert!(
                resp.replica_hints.contains(&address),
                "When sender is in receiver's RT, receiver should send outbound \
                 replica hints. Expected address {address:?} in hints, got {} hints.",
                resp.replica_hints.len()
            );
        }
        other => panic!("Expected NeighborSyncResponse, got: {other:?}"),
    }

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #21: Paid-list majority confirmation
// =========================================================================

/// Paid-list status is confirmed by querying multiple peers via verification
/// requests (Section 18 #21).
///
/// Insert a key into the paid lists of 4 out of 5 nodes, then query each
/// from the remaining node and verify a majority confirms paid status.
#[tokio::test]
#[serial]
async fn scenario_21_paid_list_majority_from_multiple_peers() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let key = [0x21; 32];

    // Add key to paid lists on nodes 0,1,2,3 (4 of 5 nodes)
    let populated_count = 4;
    for idx in 0..populated_count {
        if let Some(node) = harness.test_node(idx) {
            if let Some(ref engine) = node.replication_engine {
                engine.paid_list().insert(&key).await.expect("paid insert");
            }
        }
    }

    // Node 4 queries nodes 0..3 for paid-list status via verification
    let querier = harness.test_node(4).expect("querier");
    let p2p_q = querier.p2p_node.as_ref().expect("p2p");

    let mut paid_confirmations = 0u32;
    for idx in 0..populated_count {
        let target = harness.test_node(idx).expect("target");
        let target_p2p = target.p2p_node.as_ref().expect("target_p2p");
        let peer = *target_p2p.peer_id();

        let request = VerificationRequest {
            keys: vec![key],
            paid_list_check_indices: vec![0],
        };
        let msg = ReplicationMessage {
            request_id: 2100 + idx as u64,
            body: ReplicationMessageBody::VerificationRequest(request),
        };

        let resp_msg = send_replication_request(p2p_q, &peer, msg, Duration::from_secs(10)).await;
        if let ReplicationMessageBody::VerificationResponse(resp) = resp_msg.body {
            if resp.results.first().and_then(|r| r.paid) == Some(true) {
                paid_confirmations += 1;
            }
        }
    }

    // Should have at least 3 confirmations (we added to 4 nodes)
    let min_confirmations = 3;
    assert!(
        paid_confirmations >= min_confirmations,
        "Should get paid confirmations from multiple peers, got {paid_confirmations}"
    );

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #24: Fresh replication paid-list propagation
// =========================================================================

/// After fresh replication, `PaidNotify` propagates to remote nodes' paid
/// lists (Section 18 #24).
#[tokio::test]
#[serial]
async fn scenario_24_fresh_replication_propagates_paid_notify() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let source_idx = 3;
    let source = harness.test_node(source_idx).expect("source");
    let protocol = source.ant_protocol.as_ref().expect("protocol");

    let content = b"paid notify propagation test";
    let address = compute_address(content);
    protocol
        .storage()
        .put(&address, content)
        .await
        .expect("put");

    // Pre-populate payment cache on ALL nodes so receivers accept the offer
    // and PaidNotify (bypasses EVM verification, unavailable without Anvil).
    for i in 0..harness.node_count() {
        if let Some(node) = harness.test_node(i) {
            if let Some(p) = &node.ant_protocol {
                p.payment_verifier().cache_insert(address);
            }
        }
    }

    // Trigger fresh replication (includes PaidNotify to PaidCloseGroup)
    let dummy_pop = [0x01u8; 64];
    if let Some(ref engine) = source.replication_engine {
        engine.replicate_fresh(&address, content, &dummy_pop).await;
    }

    // Poll until PaidNotify propagates (or timeout).
    let deadline = tokio::time::Instant::now() + PROPAGATION_TIMEOUT;
    let mut paid_count;
    loop {
        paid_count = 0u32;
        for i in 0..harness.node_count() {
            if i == source_idx {
                continue;
            }
            if let Some(node) = harness.test_node(i) {
                if let Some(ref engine) = node.replication_engine {
                    if engine.paid_list().contains(&address).unwrap_or(false) {
                        paid_count += 1;
                    }
                }
            }
        }
        if paid_count >= 1 || tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(PROPAGATION_POLL_INTERVAL).await;
    }

    // At least one other node should have received the PaidNotify
    // (PaidCloseGroup is up to 20, but in a 5-node network all peers are close)
    assert!(
        paid_count >= 1,
        "PaidNotify should propagate to at least 1 other node, got {paid_count}"
    );

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #25: Convergence repair
// =========================================================================

/// Paid-list convergence: a majority of queried peers confirm paid status
/// for a key added to a subset of nodes (Section 18 #25).
#[tokio::test]
#[serial]
async fn scenario_25_paid_list_convergence_via_verification() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let key = [0x25; 32];

    // Add to paid list on nodes 0,1,2 (majority of 5)
    let populated_count = 3;
    for idx in 0..populated_count {
        if let Some(node) = harness.test_node(idx) {
            if let Some(ref engine) = node.replication_engine {
                engine.paid_list().insert(&key).await.expect("insert");
            }
        }
    }

    // Node 4 queries nodes 0,1,2 for paid-list status
    let querier = harness.test_node(4).expect("querier");
    let p2p_q = querier.p2p_node.as_ref().expect("p2p");

    let mut confirmations = 0u32;
    for idx in 0..populated_count {
        let target = harness.test_node(idx).expect("target");
        let peer = *target.p2p_node.as_ref().expect("p2p").peer_id();

        let request = VerificationRequest {
            keys: vec![key],
            paid_list_check_indices: vec![0],
        };
        let msg = ReplicationMessage {
            request_id: 2500 + idx as u64,
            body: ReplicationMessageBody::VerificationRequest(request),
        };

        let resp_msg = send_replication_request(p2p_q, &peer, msg, Duration::from_secs(10)).await;
        if let ReplicationMessageBody::VerificationResponse(v) = resp_msg.body {
            if v.results.first().and_then(|r| r.paid) == Some(true) {
                confirmations += 1;
            }
        }
    }

    let min_confirmations = 2;
    assert!(
        confirmations >= min_confirmations,
        "Majority of queried peers should confirm paid status, got {confirmations}"
    );

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #26: Paid-list majority authorises repair
// =========================================================================

/// A missing responsible replica is repaired when storage presence is below
/// quorum but the paid-list close group still has a majority (Section 18 #26).
///
/// This drives the live path end-to-end:
/// 1. one peer stores the bytes, which is below storage quorum;
/// 2. three of five paid-list peers confirm the key;
/// 3. the holder sends a replica hint to a missing responsible peer;
/// 4. verification learns paid-list authorization and fetches the record.
#[tokio::test]
#[serial]
async fn scenario_26_paid_list_majority_repairs_missing_replica_below_storage_quorum() {
    let mut net_config = TestNetworkConfig::minimal();
    net_config.replication_config = Some(ReplicationConfig {
        close_group_size: PAID_REPAIR_GROUP_SIZE,
        quorum_threshold: PAID_REPAIR_STORAGE_THRESHOLD,
        paid_list_close_group_size: PAID_REPAIR_GROUP_SIZE,
        verification_request_timeout: PAID_REPAIR_VERIFICATION_TIMEOUT,
        fetch_request_timeout: PAID_REPAIR_FETCH_TIMEOUT,
        ..ReplicationConfig::default()
    });

    let harness = TestHarness::setup_with_config(net_config)
        .await
        .expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let source = harness.test_node(PAID_REPAIR_SOURCE_INDEX).expect("source");
    let target = harness.test_node(PAID_REPAIR_TARGET_INDEX).expect("target");
    let source_p2p = source.p2p_node.as_ref().expect("source p2p");
    let target_p2p = target.p2p_node.as_ref().expect("target p2p");
    let source_peer = *source_p2p.peer_id();
    let target_peer = *target_p2p.peer_id();

    let content = b"paid-list-majority-authorizes-missing-replica-repair";
    let address = compute_address(content);

    assert!(
        target_p2p
            .dht_manager()
            .is_in_routing_table(&source_peer)
            .await,
        "precondition: target must accept inbound hints from source in LocalRT"
    );
    let storage_admission_peers: HashSet<PeerId> = target_p2p
        .dht_manager()
        .find_closest_nodes_local_with_self(
            &address,
            storage_admission_width(PAID_REPAIR_GROUP_SIZE),
        )
        .await
        .iter()
        .map(|node| node.peer_id)
        .collect();
    assert!(
        storage_admission_peers.contains(&target_peer),
        "precondition: target must be storage-admitted for the hinted key"
    );
    let paid_group = target_p2p
        .dht_manager()
        .find_closest_nodes_local_with_self(&address, PAID_REPAIR_GROUP_SIZE)
        .await;
    assert_eq!(
        paid_group.len(),
        PAID_REPAIR_GROUP_SIZE,
        "precondition: deterministic paid-list majority needs a full five-peer group"
    );
    assert!(
        paid_group.iter().any(|node| node.peer_id == target_peer),
        "precondition: target must be in the paid-list close group"
    );

    let source_protocol = source.ant_protocol.as_ref().expect("source protocol");
    source_protocol
        .storage()
        .put(&address, content)
        .await
        .expect("put source record");

    for idx in 0..harness.node_count() {
        if let Some(protocol) = harness
            .test_node(idx)
            .and_then(|node| node.ant_protocol.as_ref())
        {
            protocol.payment_verifier().cache_insert(address);
        }
    }

    for idx in 0..PAID_REPAIR_CONFIRMING_NODES {
        let engine = harness
            .test_node(idx)
            .and_then(|node| node.replication_engine.as_ref())
            .expect("paid-list confirming engine");
        engine
            .paid_list()
            .insert(&address)
            .await
            .expect("paid-list insert");
    }

    let mut seeded_storage_holders = 0usize;
    for idx in 0..harness.node_count() {
        if let Some(protocol) = harness
            .test_node(idx)
            .and_then(|node| node.ant_protocol.as_ref())
        {
            if protocol.storage().exists(&address).expect("exists check") {
                seeded_storage_holders += 1;
            }
        }
    }
    assert_eq!(
        seeded_storage_holders, 1,
        "precondition: only the source should hold the record before repair"
    );
    assert!(
        seeded_storage_holders < PAID_REPAIR_STORAGE_QUORUM,
        "precondition: storage quorum must be impossible without paid-list authorization"
    );

    let target_protocol = target.ant_protocol.as_ref().expect("target protocol");
    let target_engine = target.replication_engine.as_ref().expect("target engine");
    assert!(
        !target_protocol.storage().exists(&address).expect("exists"),
        "precondition: target starts without the record"
    );
    assert!(
        !target_engine
            .paid_list()
            .contains(&address)
            .expect("contains"),
        "precondition: target starts without local paid-list authorization"
    );

    let request = NeighborSyncRequest {
        replica_hints: vec![address],
        paid_hints: vec![],
        bootstrapping: false,
        commitment: None,
    };
    let response = send_replication_request(
        source_p2p,
        &target_peer,
        ReplicationMessage {
            request_id: PAID_REPAIR_HINT_REQUEST_ID,
            body: ReplicationMessageBody::NeighborSyncRequest(request),
        },
        PAID_REPAIR_HINT_REQUEST_TIMEOUT,
    )
    .await;
    match response.body {
        ReplicationMessageBody::NeighborSyncResponse(_) => {}
        other => panic!("expected NeighborSyncResponse, got: {other:?}"),
    }

    let deadline = tokio::time::Instant::now() + PAID_REPAIR_SETTLE_TIMEOUT;
    let mut learned_paid = false;
    let mut repaired_record = false;
    while tokio::time::Instant::now() < deadline {
        learned_paid = target_engine
            .paid_list()
            .contains(&address)
            .expect("contains");
        repaired_record = target_protocol.storage().exists(&address).expect("exists");
        if learned_paid && repaired_record {
            break;
        }
        tokio::time::sleep(PROPAGATION_POLL_INTERVAL).await;
    }

    assert!(
        learned_paid,
        "target should learn paid-list authorization from remote majority"
    );
    assert!(
        repaired_record,
        "paid-list majority should authorize fetching the missing replica"
    );
    let fetched = target_protocol
        .storage()
        .get(&address)
        .await
        .expect("read repaired record")
        .expect("repaired record should be present");
    assert_eq!(fetched, content, "target should store the fetched bytes");

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #43: Paid-list persistence across restart
// =========================================================================

/// `PaidForList` survives restart: keys inserted before shutdown are found
/// when the list is reopened from the same data directory (Section 18 #43).
#[tokio::test]
#[serial]
async fn scenario_43_paid_list_persists_across_restart() {
    let mut harness = TestHarness::setup_minimal().await.expect("setup");

    let data_dir = {
        let node = harness.test_node(3).expect("node");
        let dir = node.data_dir.clone();
        let key = [0x44; 32];

        // Insert into paid list
        if let Some(ref engine) = node.replication_engine {
            engine.paid_list().insert(&key).await.expect("insert");
        }
        dir
    };

    // Shut down the replication engine so the chunk store is released
    {
        let node = harness.network_mut().node_mut(3).expect("node");
        if let Some(ref mut engine) = node.replication_engine {
            engine.shutdown().await;
        }
        node.replication_engine = None;
        node.replication_shutdown = None;
    }

    // Simulate restart: reopen PaidList from same directory
    let key = [0x44; 32];
    let paid_list2 = ant_node::replication::paid_list::PaidList::new(&data_dir)
        .await
        .expect("reopen");

    assert!(
        paid_list2.contains(&key).expect("contains"),
        "PaidForList should survive restart (cold-start recovery)"
    );

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Section 18, Scenario #45: Unrecoverable when paid-list lost
// =========================================================================

/// If `PaidForList` is lost AND no quorum exists, the key is unrecoverable.
/// A fresh `PaidList` in a different directory does NOT contain previously-paid
/// keys (Section 18 #45).
#[tokio::test]
#[serial]
async fn scenario_45_unrecoverable_when_paid_list_lost() {
    let harness = TestHarness::setup_minimal().await.expect("setup");

    let key = [0x45; 32];

    // Insert into node 3's paid list
    let node = harness.test_node(3).expect("node");
    if let Some(ref engine) = node.replication_engine {
        engine.paid_list().insert(&key).await.expect("insert");
    }

    // Create a fresh PaidList in a different directory (simulating data loss)
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let fresh_paid_list = ant_node::replication::paid_list::PaidList::new(temp_dir.path())
        .await
        .expect("fresh paid list");

    assert!(
        !fresh_paid_list.contains(&key).expect("contains"),
        "Key should NOT be found in a fresh (lost) PaidForList"
    );

    harness.teardown().await.expect("teardown");
}

// =========================================================================
// Late-joiner bootstrap replication
// =========================================================================

/// A new node joining an existing network replicates all chunks it is
/// responsible for during bootstrap.
///
/// This is the critical "late joiner" scenario: the network already holds
/// data, a fresh node appears, and the replication subsystem must ensure
/// the new node converges to hold every chunk whose close group includes
/// it.
///
/// Flow:
/// 1. Start a 5-node network and warm up DHT.
/// 2. Store several chunks on existing nodes, pre-populate payment caches.
/// 3. Trigger fresh replication so chunks spread across close groups.
/// 4. Add a 6th node via `add_node()` (starts, bootstraps, replication
///    engine finishes bootstrap).
/// 5. Allow time for neighbor-sync and fetch workers to propagate chunks.
/// 6. For each chunk whose close group (according to the new node's DHT)
///    includes the new node, verify the chunk exists in the new node's
///    storage.
#[tokio::test]
#[serial]
async fn test_late_joiner_replicates_responsible_chunks() {
    const REPLICATION_SETTLE_TIMEOUT: Duration = Duration::from_secs(90);
    const SETTLE_POLL_INTERVAL: Duration = Duration::from_millis(500);

    let mut harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    // ------------------------------------------------------------------
    // Step 1: Store chunks on the existing 5-node network
    // ------------------------------------------------------------------
    let chunk_count = 10;
    let mut chunks: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(chunk_count);

    for i in 0..chunk_count {
        let content = format!("late-joiner-test-chunk-{i}").into_bytes();
        let address = compute_address(&content);
        chunks.push((address, content));
    }

    // Store each chunk on node 2 and pre-populate payment caches on ALL
    // existing nodes so fresh replication offers are accepted.
    let source_idx = 2;
    {
        let source = harness.test_node(source_idx).expect("source node");
        let storage = source.ant_protocol.as_ref().expect("protocol").storage();
        for (address, content) in &chunks {
            storage.put(address, content).await.expect("put");
        }
    }

    for (address, _) in &chunks {
        for i in 0..harness.node_count() {
            if let Some(node) = harness.test_node(i) {
                if let Some(protocol) = &node.ant_protocol {
                    protocol.payment_verifier().cache_insert(*address);
                }
            }
        }
    }

    // Trigger fresh replication for each chunk so they spread to close groups.
    let dummy_pop = [0x01u8; 64];
    {
        let source = harness.test_node(source_idx).expect("source node");
        if let Some(ref engine) = source.replication_engine {
            for (address, content) in &chunks {
                engine.replicate_fresh(address, content, &dummy_pop).await;
            }
        }
    }

    // Wait for replication to settle across the existing network.
    tokio::time::sleep(Duration::from_secs(5)).await;

    // ------------------------------------------------------------------
    // Step 2: Add a new (6th) node
    // ------------------------------------------------------------------
    let new_idx = harness.add_node().await.expect("add_node");

    // Pre-populate payment caches on the new node so it accepts fetched chunks.
    {
        let new_node = harness.test_node(new_idx).expect("new node");
        let protocol = new_node.ant_protocol.as_ref().expect("protocol");
        for (address, _) in &chunks {
            protocol.payment_verifier().cache_insert(*address);
        }
    }

    // ------------------------------------------------------------------
    // Step 3: Wait for replication to propagate to the new node
    // ------------------------------------------------------------------
    // The replication subsystem discovers missing chunks via neighbor-sync
    // and fetches them. Give it time to complete.
    let new_node = harness.test_node(new_idx).expect("new node");
    let new_p2p = new_node.p2p_node.as_ref().expect("p2p");
    let new_peer_id = *new_p2p.peer_id();
    let new_storage = new_node.ant_protocol.as_ref().expect("protocol").storage();
    let close_group_size = ant_node::CLOSE_GROUP_SIZE;

    // Determine which chunks the new node should be responsible for.
    let mut responsible_chunks: Vec<[u8; 32]> = Vec::new();
    for (address, _) in &chunks {
        let closest = new_p2p
            .dht_manager()
            .find_closest_nodes_local_with_self(address, close_group_size)
            .await;
        if closest.iter().any(|n| n.peer_id == new_peer_id) {
            responsible_chunks.push(*address);
        }
    }

    // The new node should be responsible for at least some chunks in a
    // 6-node network with CLOSE_GROUP_SIZE=7 (it should be responsible
    // for all of them since 6 < 7, but be defensive).
    assert!(
        !responsible_chunks.is_empty(),
        "New node should be in the close group for at least some chunks"
    );

    // Poll until all responsible chunks are present in the new node's storage.
    let deadline = tokio::time::Instant::now() + REPLICATION_SETTLE_TIMEOUT;
    let mut all_present = false;
    while tokio::time::Instant::now() < deadline {
        let mut count = 0;
        for address in &responsible_chunks {
            if new_storage.exists(address).unwrap_or(false) {
                count += 1;
            }
        }
        if count == responsible_chunks.len() {
            all_present = true;
            break;
        }
        tokio::time::sleep(SETTLE_POLL_INTERVAL).await;
    }

    // ------------------------------------------------------------------
    // Step 4: Verify
    // ------------------------------------------------------------------
    if !all_present {
        let mut missing = Vec::new();
        for address in &responsible_chunks {
            if !new_storage.exists(address).unwrap_or(false) {
                missing.push(hex::encode(address));
            }
        }
        panic!(
            "New node is missing {}/{} responsible chunks after {REPLICATION_SETTLE_TIMEOUT:?}: [{}]",
            missing.len(),
            responsible_chunks.len(),
            missing.join(", "),
        );
    }

    // Verify the data content is correct, not just presence.
    for (address, content) in &chunks {
        if responsible_chunks.contains(address) {
            let stored = new_storage
                .get(address)
                .await
                .expect("get should succeed")
                .expect("chunk should exist");
            assert_eq!(
                &stored,
                content,
                "Stored chunk content should match original for key {}",
                hex::encode(address),
            );
        }
    }

    harness.teardown().await.expect("teardown");
}
