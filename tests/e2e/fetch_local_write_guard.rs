//! A node that cannot write does not spend anyone else's bandwidth.
//!
//! `execute_single_fetch` rechecks storage *responsibility* at download time,
//! and now rechecks local possession and local capacity there too. The unit
//! tests on `apply_fetch_result` pin what the queue does with the resulting
//! `AlreadyHeld` / `LocalWriteFailed` outcomes; what they cannot show is the
//! part that matters for egress — that a node which cannot use the bytes does
//! not ask for them in the first place.
//!
//! (`LocalWriteFailed` also covers a `put` that fails *after* a round trip, so
//! the variant does not mean "no bytes moved". What the pre-check adds is that
//! the refusal happens before any holder is contacted, and what the
//! classification adds is that no *further* holder is contacted.)
//!
//! The dial scenarios are observed through the holder's `chunks_retrieved`
//! counter; the probe scenario is observed through a sender-side count of
//! verification requests, since a request that was never sent leaves no trace on
//! any receiver.
//! Only `ChunkStore::get` increments it — the replication fetch responder and
//! the client GET handler; audits read through `get_raw` and leave it alone.
//! It is not keyed by chunk or requester, so it is an "it served something"
//! signal rather than an exact per-key one; on a freshly built testnet with no
//! other traffic to the holder, a delta means it served this fetch.
//!
//! Two gaps this file deliberately does not close, because neither is
//! constructible without adding test-only hooks to `ChunkStore`:
//!
//! - **Ordering.** Possession is checked before capacity so a full node still
//!   accepts a key it already holds, matching `put`. Proving it needs a node
//!   that both holds the key and refuses writes, and `disk_reserve` is fixed at
//!   construction — seeding such a node fails. The ordering rests on inspection
//!   and on the `FetchResult::AlreadyHeld` doc comment.
//! - **Post-round-trip classification.** Nothing here forces `put` to fail
//!   *after* the bytes arrive, so reverting that one arm to `SourceFailed`
//!   would still pass. The pre-check fires first in every reachable local
//!   failure mode this harness can build.
//!
//! Why this matters in bytes: before the capacity gate, a write-blocked node
//! pulled the whole chunk first, and the failure was then classified as the
//! source's, so the worker walked to the next verified holder and every one of
//! them re-uploaded the same chunk into the same full store.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::testnet::TestNetworkConfig;
use super::verify_storage_gate::find_key_for_target;
use super::TestHarness;
use ant_node::client::XorName;
use ant_node::replication::config::storage_admission_width;
use ant_node::replication::{
    verification_requests_for_key_from_for_test, watch_verification_requests_for_test,
};
use ant_node::{ReplicationConfig, ReplicationEngine};
use saorsa_core::identity::PeerId;
use serial_test::serial;
use std::collections::HashMap;
use std::time::Duration;

/// Above `storage_admission_width` (9), so a key the target is *not*
/// responsible for can exist — otherwise every node is responsible for
/// everything and `find_key_for_target` has nothing to choose between.
const NODE_COUNT: usize = 12;
/// Production close-group size, so the admission width is the real 9.
const CLOSE_GROUP_SIZE: usize = 7;
const TARGET_INDEX: usize = 5;
const HOLDER_INDEX: usize = 6;
/// Far above any real free space, so the target's capacity check always
/// refuses — the same `Insufficient disk space` error a full partition raises,
/// through the same `check_disk_space_cached` call `put` makes.
const IMPOSSIBLE_DISK_RESERVE: u64 = u64::MAX / 2;
const OBSERVATION_WINDOW: Duration = Duration::from_secs(15);
const OBSERVATION_POLL: Duration = Duration::from_millis(200);
/// Storage is untouched on this node, so it is the positive control.
const CONTROL_INDEX: usize = 7;
/// A delay no ordinary requeue reaches, so the check identifies the capacity
/// backoff rather than just "something deferred it". Every other requeue in this
/// path waits `verification_request_timeout`, which is 15 s.
const CAPACITY_BACKOFF_FLOOR: Duration = Duration::from_secs(60);

/// Put `key` into `engine`'s pending-verification queue, tolerating a hint that
/// arrived first.
///
/// Seeding a key on other nodes is what makes it advertisable, so a replica hint
/// can land in the target's queue before this call runs. `add_pending_verify`
/// then merges the hint into the entry already there and reports
/// `AlreadyPresent` rather than `Admitted`, which is not a failure: every phase
/// below needs the key to *be* pending verification, not this call to be what
/// put it there. Asserting on the admission result alone made the phases lose a
/// race that widens on a slow runner, and did so at the setup step rather than
/// at anything the gate decides.
///
/// A key that is neither newly admitted nor already pending is still a hard
/// stop. Left unchecked, the later assertions would read a missing queue entry
/// as a gate decision.
async fn ensure_pending_verify(engine: &ReplicationEngine, key: XorName, hinter: PeerId) {
    if engine.enqueue_pending_verify_for_test(key, hinter).await {
        return;
    }
    assert!(
        engine.pending_verify_delay_for_test(&key).await.is_some(),
        "key {} was refused admission to pending verification and is not already \
         there, so the phase that follows has nothing to observe",
        hex::encode(key)
    );
}

/// A node whose available space is below its reserve must neither dial for a
/// chunk it has already authorized nor ask its close group where to find one.
///
/// Three phases on one network, because they are facets of the same duty and a
/// second 12-node testnet is real port pressure on a CI runner.
///
/// **Phase 1, the dial.** `execute_single_fetch` refuses before the dial, so no
/// holder is conscripted. Observed through the holder's `chunks_retrieved`
/// counter: only `ChunkStore::get` moves it — the replication fetch responder
/// and the client GET handler — while audits read through `get_raw` and leave it
/// alone. It is not keyed by chunk or requester, so it is an "it served
/// something" signal rather than an exact per-key one; on a freshly built
/// testnet with no other traffic to the holder, a delta means it served this
/// fetch.
///
/// **Phase 2, the probe.** Ending the dial does not end the source-discovery
/// round in front of it. Before the capacity gate a write-blocked node still
/// asked its close group about every key it owed, on every cycle the key came
/// back on, for as long as it owed them — a cost that scales with the owed set
/// rather than with anything the node can do about it.
/// Both nodes are seeded through the local paid-list path, which is where a full
/// node spends its life: authorization is already settled, so all that remains is
/// finding a holder to download from.
///
/// In phase 2 the discriminator is the probe count, not the delay: it counts
/// whether the close group was asked at all, per key, so unrelated background
/// convergence — which a full node rightly still does — cannot disturb it.
///
/// In phase 3 the delay *is* the discriminator, and only because a refused fetch
/// now requeues on the ordinary `verification_request_timeout`: held before
/// promotion the key waits five minutes, promoted and then refused it waits
/// fifteen seconds.
#[tokio::test]
#[serial]
async fn write_blocked_node_neither_probes_nor_dials() {
    let mut storage_disk_reserve_overrides = HashMap::new();
    storage_disk_reserve_overrides.insert(TARGET_INDEX, IMPOSSIBLE_DISK_RESERVE);
    let config = TestNetworkConfig {
        node_count: NODE_COUNT,
        storage_disk_reserve_overrides,
        replication_config: Some(ReplicationConfig {
            close_group_size: CLOSE_GROUP_SIZE,
            ..ReplicationConfig::default()
        }),
        ..TestNetworkConfig::default()
    };
    let harness = TestHarness::setup_with_config(config)
        .await
        .expect("setup write-blocked network");
    harness.warmup_dht().await.expect("warmup");

    let width = storage_admission_width(CLOSE_GROUP_SIZE);
    let (content, key) = find_key_for_target(&harness, TARGET_INDEX, width, true, "blocked").await;

    let target = harness.test_node(TARGET_INDEX).expect("target");
    let target_storage = target
        .ant_protocol
        .as_ref()
        .expect("target protocol")
        .storage();
    let target_engine = target.replication_engine.as_ref().expect("target engine");
    let target_peer = *target.p2p_node.as_ref().expect("target p2p").peer_id();
    let holder = harness.test_node(HOLDER_INDEX).expect("holder");
    let holder_peer = *holder.p2p_node.as_ref().expect("holder p2p").peer_id();
    let holder_storage = holder
        .ant_protocol
        .as_ref()
        .expect("holder protocol")
        .storage();

    // The holder can serve it, so a zero below means the target declined to
    // ask — not that nobody could answer.
    holder_storage
        .put(&key, &content)
        .await
        .expect("host the chunk");
    // Establish the precondition through the public write path, which runs the
    // same capacity check the fetch pre-check calls.
    let probe = b"local-write-guard-precondition-probe".to_vec();
    let probe_address = ant_node::client::compute_address(&probe);
    assert!(
        target_storage.put(&probe_address, &probe).await.is_err(),
        "the target's storage must be refusing writes, or this test proves nothing"
    );

    let served_before = holder_storage.stats().chunks_retrieved;
    assert!(
        target_engine
            .enqueue_fetch_for_test(key, vec![holder_peer])
            .await,
        "candidate must enqueue"
    );

    let deadline = tokio::time::Instant::now() + OBSERVATION_WINDOW;
    while target_engine.fetch_pipeline_contains_for_test(&key).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the candidate never resolved; a key stuck in the fetch pipeline \
             would stall bootstrap drain (key {})",
            hex::encode(key)
        );
        tokio::time::sleep(OBSERVATION_POLL).await;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;

    let served = holder_storage.stats().chunks_retrieved - served_before;
    println!("LOCAL-WRITE-GUARD-RESULT served_by_holder={served}");

    assert_eq!(
        served, 0,
        "a node whose storage cannot accept a write pulled {served} chunk(s) \
         from the holder. The bytes could never have been stored, and the old \
         classification treated the failure as the source's for retry-selection \
         purposes, so the worker walked to every remaining holder and each \
         re-sent the same chunk into the same full store."
    );
    assert!(
        !target_storage.exists(&key).unwrap_or(true),
        "the target cannot have stored a chunk its storage refuses to write"
    );

    // ---- Phase 2: the source-discovery round in front of the dial ----------

    let control = harness.test_node(CONTROL_INDEX).expect("control");
    let control_storage = control
        .ant_protocol
        .as_ref()
        .expect("control protocol")
        .storage();
    let control_engine = control.replication_engine.as_ref().expect("control engine");
    let control_peer = *control.p2p_node.as_ref().expect("control p2p").peer_id();

    let (blocked_content, blocked_key) =
        find_key_for_target(&harness, TARGET_INDEX, width, true, "capblocked").await;
    let (control_content, control_key) =
        find_key_for_target(&harness, CONTROL_INDEX, width, true, "capcontrol").await;

    // Both keys are answerable, so a node that stays quiet chose to.
    holder_storage
        .put(&blocked_key, &blocked_content)
        .await
        .expect("host the blocked key");
    holder_storage
        .put(&control_key, &control_content)
        .await
        .expect("host the control key");

    // Count probes only for these two keys, so the convergence traffic a full
    // node rightly still sends for unauthorized keys cannot disturb the result.
    // Counted where they are sent, so a responder shedding a request cannot
    // turn a probe that happened into a zero here.
    watch_verification_requests_for_test(&[blocked_key, control_key]);

    // Authorization settled locally on both nodes. That is the state a full
    // node reaches for an owed key once its paid list has caught up, which is
    // the case the gate exists for; keys still awaiting that, or stuck on an
    // inconclusive quorum, keep running the ungated round. Once settled, the
    // cycle skips the quorum round and goes straight to the presence probe.
    target_engine
        .paid_list()
        .insert(&blocked_key)
        .await
        .expect("seed target paid list");
    control_engine
        .paid_list()
        .insert(&control_key)
        .await
        .expect("seed control paid list");

    ensure_pending_verify(target_engine, blocked_key, holder_peer).await;
    ensure_pending_verify(control_engine, control_key, holder_peer).await;

    let deadline = tokio::time::Instant::now() + OBSERVATION_WINDOW;
    let mut blocked_delay = None;
    let mut control_stored = false;
    while tokio::time::Instant::now() < deadline {
        let delay = target_engine
            .pending_verify_delay_for_test(&blocked_key)
            .await;
        if delay.is_some_and(|d| d >= CAPACITY_BACKOFF_FLOOR) {
            blocked_delay = delay;
        }
        control_stored = control_storage.exists(&control_key).unwrap_or(false);
        if blocked_delay.is_some() && control_stored {
            break;
        }
        tokio::time::sleep(OBSERVATION_POLL).await;
    }

    let blocked_probes = verification_requests_for_key_from_for_test(&target_peer, &blocked_key);
    let control_probes = verification_requests_for_key_from_for_test(&control_peer, &control_key);
    println!(
        "CAPACITY-GATE-RESULT blocked_probes={blocked_probes} control_probes={control_probes} \
         blocked_delay={blocked_delay:?} control_stored={control_stored}"
    );

    // The load-bearing assertion. Counted per key, so the convergence traffic a
    // full node rightly still sends for keys it has not authorized cannot mask
    // or manufacture this result.
    assert_eq!(
        blocked_probes, 0,
        "the write-blocked node sent {blocked_probes} verification request(s) for a key \
         its own capacity check will refuse. That probe is what scales with the owed \
         set, and it is paid whether or not the dial behind it is stopped"
    );
    assert!(
        control_probes > 0,
        "the control asked nobody either, so the zero above is not evidence of \
         anything — the cycle never reached the probe on either node"
    );
    assert!(
        control_stored,
        "the control never acquired its key, so the run says nothing about the gate"
    );
    assert!(
        blocked_delay.is_some_and(|d| d >= CAPACITY_BACKOFF_FLOOR),
        "the blocked key must be held on the capacity backoff, not merely skipped \
         for one cycle: a skip without a deferral is re-selected on the next poll"
    );
    assert!(
        !target_storage.exists(&blocked_key).unwrap_or(true),
        "the target cannot have stored a chunk its storage refuses to write"
    );

    // ---- Phase 3: the second gate, on promotion after the quorum round -----
    //
    // The first gate covers keys the node has already authorized. A key it has
    // not is authorized by a network quorum round instead, and that round is
    // deliberately left alone — it is how `PaidForList` converges. What must
    // still be stopped is the promotion that follows it.
    //
    // The delay is what separates the two outcomes here, and only because a
    // refused fetch now requeues on the ordinary schedule: gated before
    // promotion the key waits `CAPACITY_BLOCKED_RETRY`, whereas promoted and
    // refused at the dial it waits `verification_request_timeout`. Those are
    // 5 minutes against 15 seconds.
    let (quorum_content, quorum_key) =
        find_key_for_target(&harness, TARGET_INDEX, width, true, "capquorum").await;

    // Host it widely enough that the round can actually reach quorum
    // (`QUORUM_THRESHOLD` is 4 of a 7-wide close group), and deliberately do
    // not touch the target's paid list, so the key takes the network branch.
    for idx in 0..harness.node_count() {
        if idx == TARGET_INDEX {
            continue;
        }
        if let Some(node) = harness.test_node(idx) {
            if let Some(protocol) = node.ant_protocol.as_ref() {
                let _ = protocol.storage().put(&quorum_key, &quorum_content).await;
            }
        }
    }
    ensure_pending_verify(target_engine, quorum_key, holder_peer).await;

    let deadline = tokio::time::Instant::now() + OBSERVATION_WINDOW;
    let mut quorum_delay = None;
    while tokio::time::Instant::now() < deadline {
        let delay = target_engine
            .pending_verify_delay_for_test(&quorum_key)
            .await;
        if delay.is_some_and(|d| d >= CAPACITY_BACKOFF_FLOOR) {
            quorum_delay = delay;
            break;
        }
        tokio::time::sleep(OBSERVATION_POLL).await;
    }
    // The gate has to sit *after* authorization, not in front of it. A delay on
    // its own cannot tell those apart: a gate moved ahead of the quorum round
    // would hold the key for the same five minutes while never learning it was
    // paid for, which is the failure mode that strands keys, keeps bootstrap
    // drain pending and leaves audits disabled. The paid list is the record of
    // the round having completed, so assert on it directly.
    let quorum_authorized = target_engine
        .paid_list()
        .contains(&quorum_key)
        .unwrap_or(false);
    println!(
        "CAPACITY-GATE-PROMOTION-RESULT quorum_delay={quorum_delay:?} \
         quorum_authorized={quorum_authorized}"
    );
    assert!(
        quorum_authorized,
        "the key was held without being authorized first: the quorum round did not \
         reach the target's paid list, so the gate is in front of authorization \
         rather than behind it (key {})",
        hex::encode(quorum_key)
    );

    // One caveat on what a pass here proves. Without the promotion gate,
    // `promote_pending_to_fetch` can also fail because the fetch queue is at
    // capacity, which leaves the key ready and — since Step 4 has by then
    // inserted it into `PaidForList` — the *first* gate would defer it five
    // minutes on the next cycle. On a fresh 12-node harness the queue is
    // nowhere near its 131,072 bound, and the gate-2-only mutation run
    // confirms the assertion does fail when the gate is removed, so that path
    // is not what is being observed. It is recorded because the assertion is
    // not intrinsically exclusive to the second gate.
    assert!(
        quorum_delay.is_some(),
        "the network-verified key was not held at the promotion gate. Either it was \
         promoted and refused at the dial — which requeues on the 15 s schedule, not \
         the capacity backoff — or the round never resolved (key {})",
        hex::encode(quorum_key)
    );
    assert!(
        !target_storage.exists(&quorum_key).unwrap_or(true),
        "the target cannot have stored a chunk its storage refuses to write"
    );

    harness.teardown().await.expect("teardown");
}

/// A node that already holds the key must not dial for it either.
#[tokio::test]
#[serial]
async fn already_held_key_is_not_fetched_again() {
    let config = TestNetworkConfig {
        node_count: NODE_COUNT,
        replication_config: Some(ReplicationConfig {
            close_group_size: CLOSE_GROUP_SIZE,
            ..ReplicationConfig::default()
        }),
        ..TestNetworkConfig::default()
    };
    let harness = TestHarness::setup_with_config(config)
        .await
        .expect("setup possession-recheck network");
    harness.warmup_dht().await.expect("warmup");

    let width = storage_admission_width(CLOSE_GROUP_SIZE);
    let (held_content, held_key) =
        find_key_for_target(&harness, TARGET_INDEX, width, true, "held").await;
    let (missing_content, missing_key) =
        find_key_for_target(&harness, TARGET_INDEX, width, true, "missing").await;

    let target = harness.test_node(TARGET_INDEX).expect("target");
    let target_storage = target
        .ant_protocol
        .as_ref()
        .expect("target protocol")
        .storage();
    let target_engine = target.replication_engine.as_ref().expect("target engine");
    let holder = harness.test_node(HOLDER_INDEX).expect("holder");
    let holder_peer = *holder.p2p_node.as_ref().expect("holder p2p").peer_id();
    let holder_storage = holder
        .ant_protocol
        .as_ref()
        .expect("holder protocol")
        .storage();

    holder_storage
        .put(&held_key, &held_content)
        .await
        .expect("host held key");
    holder_storage
        .put(&missing_key, &missing_content)
        .await
        .expect("host control key");
    target_storage
        .put(&held_key, &held_content)
        .await
        .expect("target already holds the key");

    let served_before = holder_storage.stats().chunks_retrieved;
    assert!(
        target_engine
            .enqueue_fetch_for_test(held_key, vec![holder_peer])
            .await,
        "held-key candidate must enqueue"
    );
    let deadline = tokio::time::Instant::now() + OBSERVATION_WINDOW;
    while target_engine
        .fetch_pipeline_contains_for_test(&held_key)
        .await
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "a candidate for an already-held key must leave the fetch pipeline"
        );
        tokio::time::sleep(OBSERVATION_POLL).await;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    let held_serves = holder_storage.stats().chunks_retrieved - served_before;

    // Positive control: same seam, same holder, a key the target genuinely
    // lacks. Without this the assertion above could pass on a broken pipeline.
    let served_before = holder_storage.stats().chunks_retrieved;
    assert!(
        target_engine
            .enqueue_fetch_for_test(missing_key, vec![holder_peer])
            .await,
        "control candidate must enqueue"
    );
    let deadline = tokio::time::Instant::now() + OBSERVATION_WINDOW;
    while !target_storage.exists(&missing_key).unwrap_or(false) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "REGRESSION: a key the target does not hold was not fetched — the \
             possession recheck must not decline genuine work"
        );
        tokio::time::sleep(OBSERVATION_POLL).await;
    }
    let control_serves = holder_storage.stats().chunks_retrieved - served_before;

    println!("POSSESSION-RESULT held_serves={held_serves} control_serves={control_serves}");

    assert_eq!(
        held_serves, 0,
        "the target pulled {held_serves} chunk(s) for a key it already had"
    );
    assert!(
        control_serves >= 1,
        "the holder served nothing for a key the target lacks, so the \
         zero-serve assertion above proves nothing"
    );

    harness.teardown().await.expect("teardown");
}
