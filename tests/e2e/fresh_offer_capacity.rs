//! Capacity headroom driver for the fresh-offer admission path.
//!
//! A node should never refuse a fresh replication offer under legitimate load.
//! Refusal is not ordinary backpressure: the sender transmits offers one-way
//! (`send_message`) and never reads the rejection, so the chunk's absence
//! resurfaces at the sender's delayed possession check and is charged to the
//! *refusing* node at audit severity (ADR-0003). A node at capacity is
//! therefore a node accruing unearned trust damage, and reaching the ceiling at
//! all is a health signal rather than a normal operating state.
//!
//! This driver establishes that a healthy node has headroom for a realistic
//! single-file upload fan-out. It is deliberately a *lower bound*: payment
//! verification is served from the cache (no Anvil in this suite), so the
//! receiver's per-offer hold time excludes the EVM round trip that dominates
//! it in production. Passing here means the admission shares are not absurdly
//! tight; it does not establish headroom under uncached verification. That
//! regime needs the busy-conditions driver and a testnet run.
//!
//! On failure the printed counters distinguish the two possible causes: a
//! `global_pool` refusal means the node was saturated overall, a
//! `per_peer_share` refusal means one sender outran its allotment — which for
//! fresh offers, whose legitimate traffic is bulk from the single node handling
//! a client's PUT, usually indicts the share's size rather than the sender.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::TestHarness;
use ant_node::client::compute_address;
use ant_node::replication::{
    fresh_offer_admission_refusals, fresh_offer_refusals_global_pool,
    fresh_offer_refusals_per_peer_share, paid_notify_admission_refusals,
};
use serial_test::serial;
use std::time::{Duration, Instant};

/// Chunks in the simulated upload.
///
/// Sized to exceed every admission ceiling on the path several times over —
/// the 16-slot global fresh-offer pool and, more importantly, the much smaller
/// per-source share — so the burst genuinely exercises admission rather than
/// trickling under it.
const UPLOAD_CHUNKS: usize = 48;

/// Bytes per chunk.
///
/// Well under `MAX_CHUNK_SIZE` (4 MiB) deliberately: the whole fleet runs in
/// one test process, so full-size chunks across every node would dominate the
/// harness's memory. An admission slot is held per *offer* regardless of
/// payload size, so the count above is what stresses the ceiling. The
/// trade-off is that the receiver's write is faster than production's,
/// which is part of why this is a lower bound.
const CHUNK_BYTES: usize = 64 * 1024;

/// Node originating the upload, standing in for the node that took a client
/// PUT and is fanning the file out to its close group.
const UPLOAD_SOURCE_INDEX: usize = 3;

/// How long to let replication settle before reading the counters.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(45);

/// Poll interval while waiting for propagation.
const SETTLE_POLL: Duration = Duration::from_millis(200);

/// Dummy proof, sized past the verifier's minimum. Payment is served from the
/// cache, so its contents are never inspected.
const DUMMY_POP: [u8; 64] = [0x01; 64];

fn chunk_content(index: usize) -> Vec<u8> {
    let mut content = vec![0u8; CHUNK_BYTES];
    // Vary the leading bytes so every chunk hashes to a distinct address and
    // the offers fan out across different close groups, as a real file does.
    let tag = format!("fresh-offer-capacity-{index}");
    content[..tag.len()].copy_from_slice(tag.as_bytes());
    content
}

/// A healthy node must not refuse fresh offers during a normal upload.
#[tokio::test]
#[serial]
async fn normal_upload_never_reaches_fresh_offer_capacity() {
    let harness = TestHarness::setup_minimal().await.expect("setup");
    harness.warmup_dht().await.expect("warmup");

    let chunks: Vec<(Vec<u8>, [u8; 32])> = (0..UPLOAD_CHUNKS)
        .map(|index| {
            let content = chunk_content(index);
            let address = compute_address(&content);
            (content, address)
        })
        .collect();

    // Every node must accept the offers without an on-chain proof; Anvil is not
    // running in this suite.
    for (_, address) in &chunks {
        for index in 0..harness.node_count() {
            if let Some(node) = harness.test_node(index) {
                if let Some(protocol) = node.ant_protocol.as_ref() {
                    protocol.payment_verifier().cache_insert(*address);
                }
            }
        }
    }

    let source = harness.test_node(UPLOAD_SOURCE_INDEX).expect("source node");
    let source_storage = source
        .ant_protocol
        .as_ref()
        .expect("source protocol")
        .storage();
    let engine = source
        .replication_engine
        .as_ref()
        .expect("source replication engine");

    // Counters are process-global and cumulative, and other tests share this
    // binary, so measure a delta rather than an absolute.
    let fresh_before = fresh_offer_admission_refusals();
    let notify_before = paid_notify_admission_refusals();
    let global_before = fresh_offer_refusals_global_pool();
    let share_before = fresh_offer_refusals_per_peer_share();

    // Drive the upload the way the fresh-write drainer does: store, then hand
    // off to replication, moving to the next chunk immediately. No pacing —
    // pacing here would be the test quietly avoiding the very pressure it
    // exists to apply.
    let started = Instant::now();
    for (content, address) in &chunks {
        source_storage.put(address, content).await.expect("put");
        engine.replicate_fresh(address, content, &DUMMY_POP).await;
    }
    let dispatch_elapsed = started.elapsed();

    // Let the fan-out drain before reading the counters, so offers still queued
    // behind a worker are not miscounted as "no pressure".
    let deadline = tokio::time::Instant::now() + SETTLE_TIMEOUT;
    let mut replicated = 0usize;
    while tokio::time::Instant::now() < deadline {
        replicated = chunks
            .iter()
            .filter(|(_, address)| {
                (0..harness.node_count()).any(|index| {
                    index != UPLOAD_SOURCE_INDEX
                        && harness.test_node(index).is_some_and(|node| {
                            node.ant_protocol
                                .as_ref()
                                .is_some_and(|p| p.storage().exists(address).unwrap_or(false))
                        })
                })
            })
            .count();
        if replicated == chunks.len() {
            break;
        }
        tokio::time::sleep(SETTLE_POLL).await;
    }

    let fresh_refusals = fresh_offer_admission_refusals().saturating_sub(fresh_before);
    let notify_refusals = paid_notify_admission_refusals().saturating_sub(notify_before);
    let by_global = fresh_offer_refusals_global_pool().saturating_sub(global_before);
    let by_share = fresh_offer_refusals_per_peer_share().saturating_sub(share_before);
    let chunks_per_sec = f64::from(u32::try_from(UPLOAD_CHUNKS).unwrap_or(u32::MAX))
        / dispatch_elapsed.as_secs_f64();

    println!(
        "CAPACITY-RESULT chunks={UPLOAD_CHUNKS} chunk_bytes={CHUNK_BYTES} \
         dispatch_ms={} dispatch_chunks_per_sec={chunks_per_sec:.1} \
         replicated={replicated}/{} fresh_offer_refusals={fresh_refusals} \
         (global_pool={by_global} per_peer_share={by_share}) \
         paid_notify_refusals={notify_refusals}",
        dispatch_elapsed.as_millis(),
        chunks.len(),
    );

    // Ordered so a failure reads correctly: without propagation the refusal
    // count is vacuous, so prove work actually happened first.
    assert!(
        replicated > 0,
        "no chunk replicated anywhere, so the zero-refusal assertion below \
         would be vacuous — the upload never exercised admission"
    );
    assert_eq!(
        fresh_refusals, 0,
        "a node refused {fresh_refusals} fresh offer(s) during a normal \
         {UPLOAD_CHUNKS}-chunk upload. Refusals are not free backpressure: the \
         sender never reads them, so each one returns as a missing key at the \
         delayed possession check and is charged to the refusing node at audit \
         severity. Check which ceiling bound — a per-peer-share refusal means \
         FRESH_OFFER_MAX_OUTSTANDING_PER_PEER is sized below one legitimate \
         single-source fan-out."
    );
    assert_eq!(
        notify_refusals, 0,
        "a node dropped {notify_refusals} paid-list notification(s) during a \
         normal upload. PaidNotify is one-way with no retry, so each drop \
         discards durable paid-list evidence until a verification cycle \
         re-derives it."
    );

    harness.teardown().await.expect("teardown");
}
