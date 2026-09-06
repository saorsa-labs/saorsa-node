//! Replication subsystem for the Autonomi network.
//!
//! Implements Kademlia-style replication with:
//! - Fresh replication with `PoP` verification
//! - Neighbor sync with round-robin cycle management
//! - Batched quorum verification
//! - Storage audit protocol (anti-outsourcing)
//! - `PaidForList` persistence and convergence
//! - Responsibility pruning with hysteresis

// The replication engine intentionally holds `RwLock` read guards across await
// boundaries (e.g. reading sync_history while calling audit_tick). Clippy's
// nursery lint `significant_drop_tightening` flags these, but the guards must
// remain live for the duration of the call.
#![allow(clippy::significant_drop_tightening)]

pub mod admission;
pub mod audit;
pub mod audit_coordinator;
pub(crate) mod audit_metrics;
pub mod bootstrap;
pub mod commitment;
pub mod commitment_state;
pub mod config;
pub mod fresh;
pub mod neighbor_sync;
pub mod paid_list;
pub mod possession;
pub mod protocol;
pub mod pruning;
pub mod quorum;
pub mod recent_provers;
pub mod scheduling;
pub mod slice;
pub mod storage_commitment_audit;
pub mod subtree;
pub mod types;

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use lru::LruCache;
use std::pin::Pin;

use crate::logging::{debug, error, info, warn};
use futures::stream::FuturesUnordered;
use futures::{future::join_all, Future, StreamExt};
use parking_lot::Mutex;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{mpsc, Notify, RwLock, Semaphore};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::ant_protocol::XorName;
use crate::error::{Error, Result};
use crate::payment::{
    PaymentVerifier, VerificationContext, MAX_PAYMENT_PROOF_SIZE_BYTES,
    MIN_PAYMENT_PROOF_SIZE_BYTES,
};
use crate::replication::audit::AuditTickResult;
use crate::replication::audit_coordinator::AuditChallengeCoordinator;
use crate::replication::audit_metrics::{
    AuditResponderClass, AuditResponderDropReason, AuditResponderMetrics,
    ReplicationResponderClass, ResponderAdmissionCeiling,
};
use crate::replication::commitment::{commitment_hash, StorageCommitment};
use crate::replication::commitment_state::{
    PeerCommitmentRecord, PersistedRetention, ResponderCommitmentState, GOSSIP_ANSWERABILITY_TTL,
};
use crate::replication::config::{
    max_parallel_fetch, storage_admission_width, ReplicationConfig, MAX_AUDIT_RESPONSES_PER_PEER,
    MAX_CONCURRENT_AUDIT_RESPONSES, MAX_CONCURRENT_REPLICATION_SENDS,
    MAX_DIGEST_AUDIT_RESPONSES_PER_PEER, MAX_INCOMING_VERIFICATION_KEYS,
    MAX_SUBTREE_ROUND1_PER_PEER, MAX_SUBTREE_SESSIONS, MAX_VERIFICATION_KEYS_PER_CYCLE,
    REPLICATION_PROTOCOL_ID, SUBTREE_AUDIT_PROTOCOL_ID, SUBTREE_ROUND1_WORK_BURST_BYTES,
    SUBTREE_ROUND1_WORK_REFILL_BYTES_PER_SEC, SUBTREE_SESSION_TTL,
};
use crate::replication::paid_list::PaidList;
use crate::replication::protocol::{
    FreshReplicationResponse, NeighborSyncResponse, ReplicationMessage, ReplicationMessageBody,
    VerificationResponse,
};
use crate::replication::quorum::KeyVerificationOutcome;
use crate::replication::recent_provers::RecentProvers;
use crate::replication::scheduling::{CapacityDisplacement, DeferralOutcome, ReplicationQueues};
use crate::replication::types::{
    AuditFailureReason, BootstrapClaimObservation, BootstrapState, FailureEvidence,
    NeighborSyncState, PeerSyncRecord, PresenceEvidence, RepairProofs, VerificationEntry,
    VerificationState,
};
use crate::storage::{CapacityVerdict, ChunkStore};
use saorsa_core::identity::{NodeIdentity, PeerId};
use saorsa_core::{DhtNetworkEvent, P2PEvent, P2PNode, TrustEvent};
use saorsa_pqc::api::sig::{MlDsaSecretKey, MlDsaVariant};

/// Count of monetized-pin nominations DROPPED at the bounded ingress channel
/// because it was full (Amendment 2). Process-global because the producer is
/// the payment verifier (a different module) and the drop happens before the
/// per-drainer `received` counter. A non-zero value is the rollout signal that
/// nomination ingress is saturating — benign (penalty-free, lottery/next-
/// payment covered) but worth watching. `Closed` (engine shut down) is not
/// counted: it is not a saturation signal.
static FIRST_AUDIT_INGRESS_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Record one ingress-full drop. Called by the payment verifier's `try_send`
/// sites; read by the drainer's periodic summary.
pub(crate) fn note_monetized_ingress_drop() {
    FIRST_AUDIT_INGRESS_DROPPED.fetch_add(1, Ordering::Relaxed);
}

#[derive(Default)]
struct FirstAuditObservability {
    received: AtomicU64,
    queued: AtomicU64,
    coalesced: AtomicU64,
    duplicates: AtomicU64,
    capacity_evicted: AtomicU64,
    /// An event targeting the local peer itself, dropped at ingress: the node
    /// cannot network-audit itself (no dialable address for the local peer).
    self_target_skipped: AtomicU64,
    /// A strictly-lower-count same-peer nomination that was dropped so a
    /// higher-count pending pin survived. A sustained rise is the signal of an
    /// attempted "erase the inflated pin with a cheaper one" self-suppression.
    suppressed_lower: AtomicU64,
    cooldown_deferred_attempts: AtomicU64,
    rate_deferred_attempts: AtomicU64,
    window_deduped: AtomicU64,
    launched: AtomicU64,
    passed: AtomicU64,
    timed_out: AtomicU64,
    failed: AtomicU64,
    bootstrap_claims: AtomicU64,
    idle: AtomicU64,
    insufficient_keys: AtomicU64,
    outside_answerability_window: AtomicU64,
    inflight: AtomicU64,
}

/// Test-only snapshot of the first-audit scheduler counters.
///
/// Lets e2e tests assert on the scheduler's decisions (e.g. that a
/// self-targeting monetized pin was dropped and never launched) instead of
/// scraping log lines.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Clone, Copy)]
pub struct FirstAuditStats {
    /// Events ingested from the monetized-pin channel.
    pub received: u64,
    /// Events accepted into the pending first-audit queue.
    pub queued: u64,
    /// Events dropped because they targeted the local peer.
    pub self_target_skipped: u64,
    /// Audits launched.
    pub launched: u64,
    /// Launched audits that passed.
    pub passed: u64,
    /// Launched audits that timed out (non-response lane).
    pub timed_out: u64,
    /// Launched audits that ended in a confirmed failure.
    pub failed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstAuditTerminalOutcome {
    Passed,
    Timeout,
    Failed,
    BootstrapClaim,
    Idle,
    InsufficientKeys,
}

impl FirstAuditTerminalOutcome {
    #[cfg(any(feature = "logging", test))]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Timeout => "timeout",
            Self::Failed => "failed",
            Self::BootstrapClaim => "bootstrap_claim",
            Self::Idle => "idle",
            Self::InsufficientKeys => "insufficient_keys",
        }
    }
}

fn first_audit_terminal_outcome(result: &AuditTickResult) -> FirstAuditTerminalOutcome {
    match result {
        AuditTickResult::Passed { .. } => FirstAuditTerminalOutcome::Passed,
        AuditTickResult::Failed {
            evidence:
                FailureEvidence::AuditFailure {
                    reason: AuditFailureReason::Timeout,
                    ..
                },
            ..
        } => FirstAuditTerminalOutcome::Timeout,
        AuditTickResult::Failed { .. } => FirstAuditTerminalOutcome::Failed,
        AuditTickResult::BootstrapClaim { .. } => FirstAuditTerminalOutcome::BootstrapClaim,
        AuditTickResult::Idle => FirstAuditTerminalOutcome::Idle,
        AuditTickResult::InsufficientKeys => FirstAuditTerminalOutcome::InsufficientKeys,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstAuditQueueOutcome {
    /// New peer inserted with free capacity.
    Queued,
    /// Collapsed with an existing same-peer entry; the incoming won (higher
    /// count, or equal count and newer) and replaced it.
    Coalesced,
    /// Collapsed with an existing same-peer entry; the incoming LOST because it
    /// had a STRICTLY LOWER count and was dropped, leaving the higher-count pin
    /// in place. This is the attempted cheaper-pin self-erasure signal.
    SuppressedLower,
    /// Collapsed with an existing same-peer entry of EQUAL count; the incoming
    /// lost the freshness tie (it was not the newer of the two) and the
    /// existing entry was retained. Benign, not an attack signal.
    RetainedOnTie,
    /// A DIFFERENT peer's entry was displaced from the capped pending queue
    /// (random victim) to make room.
    CapacityEvicted { peer: PeerId, pin: [u8; 32] },
}

/// Coalesce a monetized nomination into the per-peer pending queue with a
/// SECURITY-AWARE rule (ADR-0004 Amendment 2): keep the pin that most needs
/// auditing — the HIGHEST committed key count for that peer, newest on a tie.
///
/// A strictly-lower-count incoming must NOT displace a higher-count pending pin,
/// otherwise a peer can erase an inflated (audit-worthy) commitment by simply
/// monetizing a cheaper one right after — and a sidecar-only inflated pin has no
/// gossip-lottery backstop. When the incoming loses, the retained entry's LRU
/// recency is left UNTOUCHED (via `peek`), so a flood of low-count nominations
/// cannot promote the retained pin's lane position.
///
/// `incoming_is_newer` distinguishes ordinary enqueue (the incoming arrived
/// last, so it wins an equal-count tie for freshness) from a cooldown-race
/// requeue of an older reserved event (the pending successor is newer, so it
/// wins the tie).
fn coalesce_first_audit_event(
    pending: &mut LruCache<PeerId, MonetizedPinEvent>,
    incoming: MonetizedPinEvent,
    incoming_is_newer: bool,
    rng: &mut StdRng,
) -> FirstAuditQueueOutcome {
    if let Some(existing) = pending.peek(&incoming.peer) {
        // Strictly lower -> the incoming loses and is dropped WITHOUT touching
        // the retained pin's recency (the security-relevant self-erasure case).
        if incoming.key_count < existing.key_count {
            return FirstAuditQueueOutcome::SuppressedLower;
        }
        // Equal count -> keep the fresher; an older incoming loses a benign tie.
        if incoming.key_count == existing.key_count && !incoming_is_newer {
            return FirstAuditQueueOutcome::RetainedOnTie;
        }
        // Strictly higher, or equal-and-newer: the incoming wins. `push` updates
        // the value and bumps MRU; replacing an existing key never evicts a
        // different peer.
        let _ = pending.push(incoming.peer, incoming);
        return FirstAuditQueueOutcome::Coalesced;
    }
    // No same-peer entry. At capacity, displace a UNIFORMLY RANDOM incumbent,
    // never the LRU: deterministic keep-newest would let an ordered batch of
    // `cap` distinct-peer nominations flush a chosen target before any launch
    // lane sees it, cutting the eviction cost from probabilistic to exact. A
    // random victim caps an attacker's per-nomination eviction probability at
    // `1/cap` regardless of arrival order or timing, so suppressing a specific
    // target with confidence `1-e` costs ~`cap*ln(1/e)` distinct-peer paid
    // nominations and is never certain (ADR-0004 Amendment 4).
    if pending.len() >= pending.cap().get() {
        let victim = {
            let idx = rng.gen_range(0..pending.len());
            pending.iter().nth(idx).map(|(p, _)| *p)
        };
        if let Some(victim_peer) = victim {
            if let Some(evicted) = pending.pop(&victim_peer) {
                let _ = pending.push(incoming.peer, incoming);
                return FirstAuditQueueOutcome::CapacityEvicted {
                    peer: victim_peer,
                    pin: evicted.pin,
                };
            }
        }
    }
    match pending.push(incoming.peer, incoming) {
        None => FirstAuditQueueOutcome::Queued,
        // Unreachable: the random-displacement branch above guarantees
        // `len < cap` here (the caller holds `&mut`, so no concurrent insert
        // exists). Kept so any future logic error surfaces as an ACCOUNTED
        // eviction rather than silent loss — but note this arm would be
        // LRU-order, not random, so it must stay unreachable.
        Some((evicted_peer, evicted)) => FirstAuditQueueOutcome::CapacityEvicted {
            peer: evicted_peer,
            pin: evicted.pin,
        },
    }
}

/// ADR-0004 Amendment 2 (E′): slack added to the max launch jitter when
/// prefiltering a nomination's answerability at schedule time, covering the
/// spawn/dispatch latency between the timer firing and the wire challenge so a
/// jitter==MAX pin is not admitted only to fail the authoritative check by a
/// few milliseconds. Tiny against the multi-hour answerability window.
const FIRST_AUDIT_SEND_LATENCY_SLACK: Duration = Duration::from_secs(1);

/// A first audit the limiter recently launched at a peer: when, and the
/// committed key count that was audited (for the count-jump override).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecentFirstAudit {
    launched_at: Instant,
    key_count: u32,
}

/// Holds one first-audit in-flight slot; decrements the gauge on drop so a
/// panicking or cancelled audit task can never leak a slot and wedge the
/// [`config::FIRST_AUDIT_MAX_INFLIGHT`] cap shut.
struct FirstAuditInflightSlot(Arc<FirstAuditObservability>);

impl FirstAuditInflightSlot {
    fn acquire(observability: &Arc<FirstAuditObservability>) -> Self {
        observability.inflight.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(observability))
    }
}

impl Drop for FirstAuditInflightSlot {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// ADR-0004 Amendment 2: whether `new_count` exceeds `audited_count` by more
/// than the [`config::FIRST_AUDIT_COUNT_JUMP_NUM`]/
/// [`config::FIRST_AUDIT_COUNT_JUMP_DEN`] ratio (`new > old * NUM / DEN`,
/// overflow-free integer math). A jump re-nominates a peer despite a recent
/// first audit: an inflated SIDECAR-ONLY pin is visible to payment verifiers
/// only, so no gossip-lottery audit can ever cover it.
const fn first_audit_count_jump(audited_count: u32, new_count: u32) -> bool {
    (new_count as u64) * config::FIRST_AUDIT_COUNT_JUMP_DEN
        > (audited_count as u64) * config::FIRST_AUDIT_COUNT_JUMP_NUM
}

/// The launch limiter's verdict for one pending monetized pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LimiterVerdict {
    /// Within budget and window: the caller may reserve a launch (and consumes
    /// a token via [`FirstAuditLimiter::reserve_token`] only if it does).
    Admit,
    /// Launch-rate budget or in-flight cap exhausted. Penalty-free: keep the
    /// pin pending and retry on a later tick.
    RateDeferred,
    /// The peer had a first audit within
    /// [`config::FIRST_AUDIT_PEER_REAUDIT_INTERVAL`] and the new pin's count
    /// shows no [`first_audit_count_jump`]. Drop the nomination (the
    /// gossip-lottery re-audit path is unaffected).
    WindowDeduped,
}

/// ADR-0004 Amendment 2: the first-audit launch limiter — a token bucket
/// (launch rate), an in-flight cap, and a per-peer re-audit window that
/// survives pin rotation.
///
/// This is the load-bearing aggregate bound the original scheduler lacked:
/// fleet-wide first-audit pressure becomes `nodes x refill-rate` instead of
/// `uploads x pinned-quotes-per-proof x verifying-storers`. Pure over passed
/// `now`/`inflight` values so every decision is unit-testable without a
/// runtime.
struct FirstAuditLimiter {
    /// Launch tokens available, at most [`config::FIRST_AUDIT_BUDGET_BURST`].
    tokens: u32,
    /// Refill anchor. While the bucket is full this tracks `now` (a full
    /// bucket accrues nothing); while below capacity it advances only by
    /// whole refill intervals so fractional elapsed time is never lost.
    last_refill: Instant,
    /// Peers given a first audit recently, with the audited key count.
    /// Bounded like the drainer's other per-peer maps.
    recent: LruCache<PeerId, RecentFirstAudit>,
}

impl FirstAuditLimiter {
    fn new(now: Instant) -> Self {
        Self {
            tokens: config::FIRST_AUDIT_BUDGET_BURST,
            last_refill: now,
            recent: LruCache::new(
                NonZeroUsize::new(MAX_LAST_COMMITMENT_BY_PEER).unwrap_or(NonZeroUsize::MIN),
            ),
        }
    }

    /// Whether the per-peer re-audit window admits a nomination for `peer`
    /// carrying `key_count` at `now`. Read-only (`peek`), so it is safe to
    /// call at ENQUEUE time — suppressed nominations never occupy pending
    /// slots — without disturbing LRU recency.
    fn window_allows(&self, peer: &PeerId, key_count: u32, now: Instant) -> bool {
        self.recent.peek(peer).map_or(true, |prev| {
            now.saturating_duration_since(prev.launched_at)
                >= config::FIRST_AUDIT_PEER_REAUDIT_INTERVAL
                || first_audit_count_jump(prev.key_count, key_count)
        })
    }

    /// Refill the token bucket for the time elapsed up to `now`.
    fn refill(&mut self, now: Instant) {
        if self.tokens >= config::FIRST_AUDIT_BUDGET_BURST {
            // Full bucket accrues nothing; keep the anchor current so the
            // next consumption starts its interval from here.
            self.last_refill = now;
            return;
        }
        let interval = config::FIRST_AUDIT_LAUNCH_INTERVAL;
        let elapsed = now.saturating_duration_since(self.last_refill);
        let earned = elapsed.as_nanos() / interval.as_nanos().max(1);
        if earned == 0 {
            return;
        }
        let capacity_gap = u128::from(config::FIRST_AUDIT_BUDGET_BURST - self.tokens);
        if earned >= capacity_gap {
            self.tokens = config::FIRST_AUDIT_BUDGET_BURST;
            self.last_refill = now;
        } else {
            // earned < capacity_gap <= u32::MAX, so both casts are lossless.
            self.tokens = self
                .tokens
                .saturating_add(u32::try_from(earned).unwrap_or(u32::MAX));
            let advance = interval.saturating_mul(u32::try_from(earned).unwrap_or(u32::MAX));
            self.last_refill = self.last_refill.checked_add(advance).unwrap_or(now);
        }
    }

    /// Decide whether a pending pin may launch now. Consumes NOTHING: the
    /// caller runs the remaining (per-peer cooldown) gate and calls
    /// [`Self::commit_launch`] only for a launch that actually happens, so a
    /// deferral elsewhere never burns budget or stamps the window.
    fn assess(
        &mut self,
        peer: &PeerId,
        key_count: u32,
        now: Instant,
        inflight: u64,
    ) -> LimiterVerdict {
        if !self.window_allows(peer, key_count, now) {
            return LimiterVerdict::WindowDeduped;
        }
        self.refill(now);
        if inflight >= config::FIRST_AUDIT_MAX_INFLIGHT || self.tokens == 0 {
            return LimiterVerdict::RateDeferred;
        }
        LimiterVerdict::Admit
    }

    /// Consume one launch token for a RESERVATION (ADR-0004 Amendment 2 E′).
    /// Does NOT stamp the per-peer window: the durable `recent` stamp happens
    /// only at [`Self::promote`], after the authoritative post-jitter
    /// answerability check, so a reservation that is later cancelled leaves no
    /// suppression behind.
    fn reserve_token(&mut self) {
        self.tokens = self.tokens.saturating_sub(1);
    }

    /// Return a token consumed by a reservation that was cancelled before it
    /// launched (answerability lapsed or a concurrent gossip audit won the
    /// cooldown). Capped at the burst so a spurious double-refund cannot exceed
    /// the bucket.
    fn refund_token(&mut self) {
        self.tokens = (self.tokens + 1).min(config::FIRST_AUDIT_BUDGET_BURST);
    }

    /// Stamp the per-peer re-audit window for a launch that is ACTUALLY firing
    /// (promotion). Separated from token consumption so suppression is only
    /// ever recorded for a real send.
    fn promote(&mut self, peer: PeerId, key_count: u32, now: Instant) {
        self.recent.put(
            peer,
            RecentFirstAudit {
                launched_at: now,
                key_count,
            },
        );
    }

    /// Test convenience: the pre-E′ atomic "a launch happened" — consume a token
    /// and stamp the window in one call. Production splits these across
    /// reservation and promotion; the limiter's own budget/window unit tests do
    /// not model the jitter reservation and use this shorthand.
    #[cfg(test)]
    fn commit_launch(&mut self, peer: PeerId, key_count: u32, now: Instant) {
        self.reserve_token();
        self.promote(peer, key_count, now);
    }
}

/// ADR-0004 Amendment 2 (E′ B-prefilter): whether a monetized pin is answerable
/// across the ENTIRE launch-jitter window ending at
/// `now + FIRST_AUDIT_LAUNCH_JITTER_MAX + slack`, so committing scheduling state
/// for it cannot later require aborting an out-of-window challenge. The
/// too-future bound is enforced at `now` (a jitter delay only ages a pin
/// forward, never toward the future); the too-old bound is enforced at the
/// latest possible send time. This is a conservative admission prefilter; the
/// authoritative answerability check still runs at promotion against the real
/// send-time wall clock, so A1 (no false conviction) holds regardless of how
/// jitter and the answerability margin are sized. `checked_add` overflow fails
/// closed (skip the pin).
fn quote_answerable_through_nominal_jitter(quote_ts: SystemTime, now: SystemTime) -> bool {
    let Some(latest_send) = now
        .checked_add(config::FIRST_AUDIT_LAUNCH_JITTER_MAX)
        .and_then(|t| t.checked_add(FIRST_AUDIT_SEND_LATENCY_SLACK))
    else {
        return false;
    };
    quote_within_audit_window(quote_ts, now) && quote_within_audit_window(quote_ts, latest_send)
}

/// Open the single first-audit reservation from `pending` if none is
/// outstanding: samples the launch jitter, snapshots the shared cooldown
/// read-only, and delegates to [`FirstAuditScheduler::try_reserve`]. One
/// shared implementation for both drainer call sites — the per-wake launch
/// phase and the pre-overflow opportunity inside the ingress batch — so the
/// two cannot drift.
async fn open_first_audit_reservation(
    scheduler: &mut FirstAuditScheduler,
    cooldown: &RwLock<HashMap<PeerId, Instant>>,
    observability: &Arc<FirstAuditObservability>,
) {
    if scheduler.has_reservation() {
        return;
    }
    let jitter = Duration::from_millis(rand::thread_rng().gen_range(
        0..=u64::try_from(config::FIRST_AUDIT_LAUNCH_JITTER_MAX.as_millis()).unwrap_or(u64::MAX),
    ));
    let inflight = observability.inflight.load(Ordering::Relaxed);
    let reserved = {
        let cooldown = cooldown.read().await;
        scheduler.try_reserve(Instant::now(), inflight, jitter, &cooldown, observability)
    };
    if reserved {
        if let Some(peer) = scheduler.reserved_peer() {
            debug!(
                "First-audit scheduler: audit_trigger=first_monetized outcome=reserved peer={peer} pending={}",
                scheduler.pending_len()
            );
        }
    }
}

/// A far-future `Instant` used to effectively DISABLE the promotion-timer
/// select arm when no reservation is outstanding. The drainer still wakes at
/// least every [`config::FIRST_AUDIT_RETRY_INTERVAL`] via its tick, so this only
/// needs to be comfortably past the next tick.
fn first_audit_far_future() -> Instant {
    Instant::now()
        .checked_add(Duration::from_secs(3600))
        .unwrap_or_else(Instant::now)
}

/// ADR-0004 Amendment 2 (E′): one outstanding first-audit reservation. Holds
/// its in-flight slot and launch token from schedule time until the jitter
/// timer fires; the durable suppression (`recent` + `first_audited`) is stamped
/// only if the authoritative post-jitter answerability + cooldown checks pass at
/// promotion, so a cancelled reservation leaves NO suppression behind.
struct FirstAuditReservation {
    event: MonetizedPinEvent,
    ready_at: Instant,
    inflight: FirstAuditInflightSlot,
}

/// ADR-0004 Amendment 2 (E′): the drainer-owned first-audit scheduler. Owns the
/// pending queue, the dedup set, the launch limiter, the alternating lane, and
/// the single outstanding reservation. All mutation is single-threaded in the
/// drainer task; the only asynchrony is the spawned audit I/O (which just holds
/// the moved-in in-flight slot). Kept as a struct so the reserve/promote/cancel
/// state machine is unit-testable with injected clocks.
struct FirstAuditScheduler {
    /// Pins already given a first audit (dedup). A pin enters only at PROMOTION
    /// (a real send), never at reservation, so a cancelled reservation can be
    /// re-nominated.
    first_audited: LruCache<[u8; 32], ()>,
    /// Highest-count-per-peer pending nominations not yet launched. Capped at
    /// [`FIRST_AUDIT_PENDING_CAP`] (what the token budget can launch within
    /// one effective answerability window); at capacity a uniformly RANDOM
    /// incumbent is displaced and counted as `capacity_evicted`, so eviction
    /// of a specific entry can never be forced deterministically. One further
    /// entry may be held in `reserved` outside this queue — a deliberate
    /// one-entry guard slot, so total schedulable occupancy is at most
    /// `cap + 1`; the summary line reports both (`pending`/`reserved`).
    pending: LruCache<PeerId, MonetizedPinEvent>,
    /// Token bucket + per-peer re-audit window.
    limiter: FirstAuditLimiter,
    /// The single outstanding reservation (E′ serializes reservations so the
    /// per-launch lane alternation is preserved and at most one jitter timer is
    /// live).
    reserved: Option<FirstAuditReservation>,
    /// Alternating launch lane, flipped on every PROMOTION (real launch).
    oldest_first_lane: bool,
    /// The local node's own peer ID. A verified payment's quote list includes
    /// the node's own quote, so the verifier emits a monetized-pin event for
    /// the local peer on every payment it verifies. The node cannot
    /// network-audit itself (there is no dialable address for the local peer,
    /// so the challenge fails instantly and is miscounted as a timeout), while
    /// any other payee that verifies the same payment schedules its own first
    /// audit of this node's pin — a self-dial adds no coverage either way.
    /// Such an event is dropped at ingress: never queued, and hence never
    /// launched nor marked first-audited.
    self_peer: PeerId,
    /// RNG for random-victim displacement (ADR-0004 Amendment 4). Owned by the
    /// scheduler so tests can seed it and reproduce eviction sequences exactly;
    /// production seeds from OS entropy at construction.
    rng: StdRng,
}

impl FirstAuditScheduler {
    fn new(now: Instant, self_peer: PeerId) -> Self {
        let dedup_cap = NonZeroUsize::new(MAX_LAST_COMMITMENT_BY_PEER).unwrap_or(NonZeroUsize::MIN);
        let pending_cap = NonZeroUsize::new(FIRST_AUDIT_PENDING_CAP).unwrap_or(NonZeroUsize::MIN);
        Self {
            first_audited: LruCache::new(dedup_cap),
            pending: LruCache::new(pending_cap),
            limiter: FirstAuditLimiter::new(now),
            reserved: None,
            oldest_first_lane: false,
            self_peer,
            rng: StdRng::from_entropy(),
        }
    }

    /// Observability getter: used by the scheduler summary log and unit tests,
    /// both absent from a release `--no-default-features` build, so it is dead
    /// only in that configuration.
    #[cfg_attr(not(feature = "logging"), allow(dead_code))]
    fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Observability getter (see [`Self::pending_len`]).
    #[cfg_attr(not(feature = "logging"), allow(dead_code))]
    fn tokens(&self) -> u32 {
        self.limiter.tokens
    }

    /// Observability getter (see [`Self::pending_len`]). Milliseconds since the
    /// signed quote timestamp of the oldest pin still awaiting a first audit:
    /// how close the longest-waiting pending pin is to aging out of the
    /// answerability window. A value climbing toward the window means pending
    /// work is expiring unaudited instead of launching; a small, steady value
    /// means the queue is draining promptly. Returns `0` when `pending` is empty
    /// and saturates to `0` for a future-dated quote (clock skew), never panics.
    #[cfg_attr(not(feature = "logging"), allow(dead_code))]
    fn oldest_pending_quote_age_ms(&self, now: SystemTime) -> u64 {
        self.pending
            .iter()
            .map(|(_, e)| e.quote_ts)
            .min()
            .and_then(|oldest| now.duration_since(oldest).ok())
            .map_or(0, |age| u64::try_from(age.as_millis()).unwrap_or(u64::MAX))
    }

    /// Drop every pending nomination that has aged past the answerability
    /// horizon. `try_reserve` collects expired entries only while it can scan —
    /// under token starvation it returns at the budget gate first — so without
    /// a periodic sweep dead entries squat the capped pending queue (displacing
    /// at capacity) and inflate the `pending`/`oldest_pending_quote_age_ms`
    /// telemetry. Each removal is accounted as `outside_answerability_window`,
    /// exactly like a scan-time expiry. Returns how many entries were dropped;
    /// survivor recency is untouched.
    fn sweep_expired(&mut self, wall_now: SystemTime, obs: &Arc<FirstAuditObservability>) -> usize {
        let expired: Vec<PeerId> = self
            .pending
            .iter()
            .filter(|(_, event)| !quote_answerable_through_nominal_jitter(event.quote_ts, wall_now))
            .map(|(peer, _)| *peer)
            .collect();
        for peer in &expired {
            self.pending.pop(peer);
        }
        if !expired.is_empty() {
            obs.outside_answerability_window.fetch_add(
                u64::try_from(expired.len()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
        expired.len()
    }

    fn has_reservation(&self) -> bool {
        self.reserved.is_some()
    }

    /// Whether admitting `event` would displace a DIFFERENT peer's pending
    /// entry: the queue is at capacity and `event.peer` has no incumbent to
    /// coalesce into. The drainer checks this before enqueueing so pending
    /// work gets a reservation opportunity BEFORE destructive overflow
    /// (ADR-0004 Amendment 4) — a successful reservation moves one entry out
    /// of `pending`, freeing the slot without any eviction.
    fn would_displace(&self, event: &MonetizedPinEvent) -> bool {
        self.pending.len() >= self.pending.cap().get() && self.pending.peek(&event.peer).is_none()
    }

    /// When the outstanding reservation becomes eligible for promotion.
    fn reserved_ready_at(&self) -> Option<Instant> {
        self.reserved.as_ref().map(|r| r.ready_at)
    }

    /// The peer of the outstanding reservation, if any.
    fn reserved_peer(&self) -> Option<PeerId> {
        self.reserved.as_ref().map(|r| r.event.peer)
    }

    /// Admit a monetized nomination into `pending`. Dropped at ingress if it
    /// targets the local peer (see [`Self::self_peer`]); dropped as a duplicate
    /// if already first-audited; the window screen is bypassed for the currently
    /// reserved peer (so a successor is retained across the reservation, never
    /// window-dropped); otherwise window-screened. Coalescing is
    /// highest-count-per-peer (newest on a tie) — a lower-count successor never
    /// displaces a higher-count pending pin. An incumbent that has aged past
    /// the answerability horizon is dropped (and accounted as an expiry) before
    /// coalescing, so a dead pin never vetoes a live nomination. Admission for
    /// a NEW peer at capacity displaces a uniformly RANDOM incumbent (see
    /// [`FIRST_AUDIT_PENDING_CAP`] and [`coalesce_first_audit_event`]):
    /// displacement is accounted as `capacity_evicted` and stamps no
    /// suppression, so a displaced peer's next nomination is judged like any
    /// newcomer. The drainer additionally offers a reservation opportunity
    /// via [`Self::would_displace`] before calling this on an overflowing
    /// arrival.
    fn enqueue(&mut self, event: MonetizedPinEvent, obs: &Arc<FirstAuditObservability>) {
        if event.peer == self.self_peer {
            obs.self_target_skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.first_audited.contains(&event.pin) {
            obs.duplicates.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let reserved_peer = self.reserved_peer();
        let is_reserved_peer = reserved_peer == Some(event.peer);
        if !is_reserved_peer
            && !self
                .limiter
                .window_allows(&event.peer, event.key_count, Instant::now())
        {
            obs.window_deduped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // A pending incumbent past the answerability horizon can never launch,
        // yet its (possibly higher) key count would still win the coalesce
        // against a live incoming — e.g. a fresh post-prune lower-count pin —
        // and under token starvation no reserve scan runs to collect it. Drop
        // it first so the incoming is judged on its own merits.
        let stale_incumbent = self.pending.peek(&event.peer).is_some_and(|existing| {
            !quote_answerable_through_nominal_jitter(existing.quote_ts, SystemTime::now())
        });
        if stale_incumbent {
            self.pending.pop(&event.peer);
            obs.outside_answerability_window
                .fetch_add(1, Ordering::Relaxed);
        }
        // Ordinary enqueue: the incoming arrived last, so it wins an equal-count
        // tie.
        match coalesce_first_audit_event(&mut self.pending, event, true, &mut self.rng) {
            FirstAuditQueueOutcome::Queued => {
                obs.queued.fetch_add(1, Ordering::Relaxed);
            }
            FirstAuditQueueOutcome::Coalesced | FirstAuditQueueOutcome::RetainedOnTie => {
                obs.coalesced.fetch_add(1, Ordering::Relaxed);
            }
            FirstAuditQueueOutcome::SuppressedLower => {
                obs.suppressed_lower.fetch_add(1, Ordering::Relaxed);
            }
            FirstAuditQueueOutcome::CapacityEvicted { .. } => {
                obs.queued.fetch_add(1, Ordering::Relaxed);
                obs.capacity_evicted.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Attempt to create the single reservation from `pending` (E′ reserve).
    /// Scans in the current lane order and reserves the FIRST eligible pin:
    /// consumes one token, acquires one in-flight slot, and sets `ready_at =
    /// mono_now + jitter`. Does NOT stamp `recent`/`first_audited` and does NOT
    /// flip the lane — those happen only at promotion. Returns whether a
    /// reservation was made. `cooldown` is a read-only snapshot (the
    /// authoritative check-and-stamp is at promotion).
    fn try_reserve(
        &mut self,
        mono_now: Instant,
        inflight: u64,
        jitter: Duration,
        cooldown: &HashMap<PeerId, Instant>,
        obs: &Arc<FirstAuditObservability>,
    ) -> bool {
        if self.reserved.is_some() || self.pending.is_empty() {
            return false;
        }
        self.limiter.refill(mono_now);
        if inflight >= config::FIRST_AUDIT_MAX_INFLIGHT || self.limiter.tokens == 0 {
            obs.rate_deferred_attempts.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        // MRU->LRU order; reverse for the oldest-first lane so the preferred
        // end is at the front.
        let mut ordered: Vec<(usize, PeerId, MonetizedPinEvent)> = self
            .pending
            .iter()
            .enumerate()
            .map(|(i, (p, e))| (i, *p, *e))
            .collect();
        self.pending.clear();
        if self.oldest_first_lane {
            ordered.reverse();
        }
        let mut chosen: Option<MonetizedPinEvent> = None;
        let mut kept: Vec<(usize, PeerId, MonetizedPinEvent)> = Vec::new();
        for (idx, peer, event) in ordered {
            if chosen.is_some() {
                kept.push((idx, peer, event));
                continue;
            }
            if self.first_audited.contains(&event.pin) {
                obs.duplicates.fetch_add(1, Ordering::Relaxed);
                continue; // drop: already audited
            }
            if !quote_answerable_through_nominal_jitter(event.quote_ts, SystemTime::now()) {
                obs.outside_answerability_window
                    .fetch_add(1, Ordering::Relaxed);
                continue; // drop: cannot stay answerable through the jitter
            }
            // Window + budget + inflight. Tokens do not decrease during the
            // scan (reserve happens after the loop) and `inflight` is fixed, so
            // after the upfront budget gate `assess` never returns RateDeferred
            // here; a defensive RateDeferred keeps the pin.
            match self
                .limiter
                .assess(&peer, event.key_count, mono_now, inflight)
            {
                LimiterVerdict::WindowDeduped => {
                    obs.window_deduped.fetch_add(1, Ordering::Relaxed);
                    continue; // drop: recently first-audited, no count jump
                }
                LimiterVerdict::RateDeferred => {
                    kept.push((idx, peer, event));
                    continue; // keep (defensive; unreachable after upfront gate)
                }
                LimiterVerdict::Admit => {}
            }
            if !cooldown_would_allow(cooldown, &peer, mono_now) {
                obs.cooldown_deferred_attempts
                    .fetch_add(1, Ordering::Relaxed);
                kept.push((idx, peer, event));
                continue; // keep: on shared cooldown, retry later
            }
            chosen = Some(event);
        }
        // Restore relative recency (oldest re-put first -> newest stays MRU).
        kept.sort_unstable_by_key(|(idx, _, _)| std::cmp::Reverse(*idx));
        for (_, peer, event) in kept {
            self.pending.put(peer, event);
        }
        let Some(event) = chosen else {
            return false;
        };
        self.limiter.reserve_token();
        let inflight_slot = FirstAuditInflightSlot::acquire(obs);
        let ready_at = mono_now.checked_add(jitter).unwrap_or(mono_now);
        self.reserved = Some(FirstAuditReservation {
            event,
            ready_at,
            inflight: inflight_slot,
        });
        true
    }

    /// Take the outstanding reservation if its jitter has elapsed at `mono_now`.
    fn take_due_reservation(&mut self, mono_now: Instant) -> Option<FirstAuditReservation> {
        if self
            .reserved
            .as_ref()
            .is_some_and(|r| mono_now >= r.ready_at)
        {
            self.reserved.take()
        } else {
            None
        }
    }

    /// Authoritative promotion of a due reservation (E′). The caller holds the
    /// shared cooldown write lock and passes the real send-time `wall_now` and
    /// `mono_now`. Returns `Some((event, slot))` to spawn the audit on a real
    /// launch, or `None` when the launch was cancelled (answerability lapsed
    /// during jitter) or requeued (a concurrent gossip audit won the cooldown).
    /// On both `None` paths the token is refunded, the in-flight slot released,
    /// and NO suppression is recorded.
    ///
    /// Known operational residual: suppression is stamped here, at promotion,
    /// while the wire challenge is sent by the detached task the caller spawns
    /// with the returned event. A task-start or encoding failure between the
    /// two therefore leaves a stamped-but-unsent window. No remote input can
    /// force that failure (it requires local task-spawn/alloc failure), so it
    /// is accepted rather than closed; closing it would require stamping from
    /// inside the spawned task and re-introduce the cancel-leaves-suppression
    /// race this design exists to prevent.
    fn resolve(
        &mut self,
        reservation: FirstAuditReservation,
        wall_now: SystemTime,
        mono_now: Instant,
        cooldown: &mut HashMap<PeerId, Instant>,
        obs: &Arc<FirstAuditObservability>,
    ) -> Option<(MonetizedPinEvent, FirstAuditInflightSlot)> {
        let FirstAuditReservation {
            event, inflight, ..
        } = reservation;
        // Authoritative answerability at the REAL send time.
        if !quote_within_audit_window(event.quote_ts, wall_now) {
            self.limiter.refund_token();
            obs.outside_answerability_window
                .fetch_add(1, Ordering::Relaxed);
            drop(inflight);
            return None; // cancelled; nothing stamped, nothing to roll back
        }
        // Authoritative shared-cooldown check-and-stamp. Losing this race to a
        // concurrent gossip audit requeues the reserved event through the SAME
        // security-aware coalescing: the reserved event is OLDER than any
        // same-peer successor (`incoming_is_newer = false`), so a higher-count
        // reserved event still wins over a lower-count successor (the inflated
        // pin must be audited), while an equal/higher successor is preserved.
        if !cooldown_allows_audit(cooldown, &event.peer, mono_now) {
            self.limiter.refund_token();
            obs.cooldown_deferred_attempts
                .fetch_add(1, Ordering::Relaxed);
            drop(inflight);
            // Account for the requeue outcome (the nomination itself was already
            // counted at ingress, so `queued` is not re-incremented): a capacity
            // eviction of a DIFFERENT peer and a suppressed reserved event are
            // both observable per the ADR funnel.
            match coalesce_first_audit_event(&mut self.pending, event, false, &mut self.rng) {
                FirstAuditQueueOutcome::CapacityEvicted { .. } => {
                    obs.capacity_evicted.fetch_add(1, Ordering::Relaxed);
                }
                FirstAuditQueueOutcome::SuppressedLower => {
                    obs.suppressed_lower.fetch_add(1, Ordering::Relaxed);
                }
                FirstAuditQueueOutcome::Queued
                | FirstAuditQueueOutcome::Coalesced
                | FirstAuditQueueOutcome::RetainedOnTie => {}
            }
            return None;
        }
        // Promote: stamp durable suppression, flip the lane, count the launch.
        self.limiter.promote(event.peer, event.key_count, mono_now);
        self.first_audited.put(event.pin, ());
        self.oldest_first_lane = !self.oldest_first_lane;
        obs.launched.fetch_add(1, Ordering::Relaxed);
        Some((event, inflight))
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Prefix used by saorsa-core's request-response mechanism.
const RR_PREFIX: &str = "/rr/";

/// Bounded handoff from the P2P broadcast receiver to serial non-audit
/// replication processing.
///
/// The receiver fast-paths digest `AuditChallenge`s immediately and queues
/// bulk/non-audit messages here. If this fills, the message is **dropped** —
/// `start_message_handler` must never block on a full queue, because a stalled
/// receiver laps the P2P broadcast ring and silently loses messages it never
/// observed. Every serial-lane class has protocol recovery, so a drop costs a
/// retry rather than the message.
///
/// This bounds a message COUNT, but a queued item is an owned decoded message
/// of up to [`config::MAX_REPLICATION_MESSAGE_SIZE`], so the resident worst
/// case is 64 × 10 MiB = 640 MiB. That ceiling is acknowledged, not designed
/// for: the lane carries small requests and challenges alongside
/// `FreshReplicationOffer`, its one multi-MiB class, so no single count is
/// right for both. Responses never reach here — `replication_payload_from_event`
/// filters them out and their requesters correlate them. ADR-0005 decision 12
/// records the trade and why byte accounting is the correct eventual fix.
const INBOUND_REPLICATION_SERIAL_QUEUE_CAPACITY: usize = 64;

/// Maximum fresh-replication offers processed concurrently, away from the
/// serial non-audit loop.
///
/// Fresh offers can perform an on-chain payment verification and a 4 MiB
/// write. Four workers keep that latency off the responder dispatch path while
/// keeping concurrent EVM/storage pressure small and predictable.
const FRESH_OFFER_WORKER_LIMIT: usize = 4;

/// Maximum fresh offers admitted at once, counting both those running on a
/// worker and those queued for one.
///
/// An admitted offer holds its payload until it completes, so this bounds
/// memory rather than latency: at 4 MiB each, sixteen is a 64 MiB ceiling.
/// Offers past the bound are refused rather than queued or handled inline —
/// handling one on the message loop stalls every other non-audit message behind
/// a payment verification and a multi-MiB write. A refusal is not free: the
/// sender does not read it, so it resurfaces as a missing key at the delayed
/// possession check (5-15 min, ADR-0003) and is charged to this node at audit
/// severity. Only neighbor sync (10-20 min) actually refills the gap, so the
/// bound is sized to make refusal rare rather than cheap.
const FRESH_OFFER_MAX_OUTSTANDING: usize = 16;

/// Distinct payment proofs queued for one fresh-offer key.
///
/// Duplicate offers for a key are routine rather than adversarial: a client PUT
/// is confirmed by `CLOSE_GROUP_MAJORITY` nodes, and *each* of them fans the
/// chunk out to the close group, so a receiver sees the same key from about that
/// many senders. They differ only in their proof — the bytes are provably
/// identical, since `fresh_offer_structural_rejection` has confirmed
/// `key == BLAKE3(data)` before any of them is queued.
///
/// Sizing the queue to the number of legitimate senders is what lets a failing
/// proof fall through to the next one instead of costing the node the record.
///
/// This is a **lifetime budget per entry**, not a queue depth: it counts proofs
/// admitted, and a proof the handler has popped has spent its slot rather than
/// returned it. That distinction is what bounds the work an attacker can buy —
/// at most this many on-chain verifications per key, after which the entry
/// refuses everyone until it closes. Gating on the queue's instantaneous length
/// instead would let a stream of distinct sources refill each popped slot and
/// run unbounded sequential verifications while holding one of the four worker
/// slots. One attempt per source additionally means a single peer can only ever
/// consume one of these.
const MAX_FRESH_OFFER_ATTEMPTS_PER_KEY: usize = crate::ant_protocol::CLOSE_GROUP_MAJORITY;

/// Fresh-offer slots kept reachable by sources that hold none.
///
/// The property worth guaranteeing is that one peer cannot *starve* others, not
/// that any peer is held to a small quota. Expressing the bound as a reserve
/// rather than a quota is what keeps those two apart.
const FRESH_OFFER_RESERVED_FOR_OTHER_SOURCES: usize = 4;

/// Maximum fresh offers admitted from one source peer.
///
/// Without a per-source bound, one peer can hold every slot in the global pool
/// and every honest offer arriving in that window is refused — and because a
/// refusal is later read as absence by the sender's delayed possession check,
/// those refusals land as audit-severity trust penalties on the *refuser*.
/// That makes an unbounded global pool a targeted eviction primitive.
///
/// The bound is deliberately far looser than the other responder classes'
/// (fetch 2, verification 1, neighbor sync 1), because the traffic pattern is
/// the opposite shape. Those are request/response: a requester needs only a
/// couple in flight, so a small quota costs it nothing. Fresh offers are a
/// one-way bulk fan-out, and in the ordinary case a node's offers come almost
/// entirely from ONE peer — whichever node took the client's PUT. A quota sized
/// for request/response traffic therefore binds on completely legitimate
/// uploads: at 2, an ordinary 48-chunk upload had offers refused (see
/// `tests/e2e/fresh_offer_capacity.rs`), every one of them attributed to this
/// ceiling and none to the global pool.
///
/// Sizing it as "the pool minus a reserve" keeps the anti-starvation guarantee
/// exact — [`FRESH_OFFER_RESERVED_FOR_OTHER_SOURCES`] slots always remain for a
/// peer holding none — while leaving a single legitimate fan-out unthrottled.
// The cast is from a compile-time constant difference of two small literals
// (16 - 4), so truncation is impossible; deriving the share keeps the reserve
// relationship visible in the code rather than only in a test.
#[allow(clippy::cast_possible_truncation)]
const FRESH_OFFER_MAX_OUTSTANDING_PER_PEER: u32 =
    (FRESH_OFFER_MAX_OUTSTANDING - FRESH_OFFER_RESERVED_FOR_OTHER_SOURCES) as u32;

/// Maximum paid-list notifications served concurrently.
///
/// A `PaidNotify` runs the same on-chain proof verification as a fresh offer
/// but stores only paid-list metadata, so it needs no chunk-write headroom.
/// Two workers keep cross-peer progress without multiplying concurrent EVM
/// and DHT lookup pressure.
const PAID_NOTIFY_WORKER_LIMIT: usize = 2;

/// Maximum paid-list notifications admitted across workers and their waiters.
///
/// Sized as a **memory** ceiling, not a fairness device, because `PaidNotify`
/// is one-way: the protocol defines no response and the sender never retries,
/// so a refused notify is information permanently lost to this node until a
/// later verification cycle happens to re-derive the key's paid status from a
/// paid-list quorum. A tight admission bound therefore does not shed load, it
/// discards durable state — which is why the class's real protection is
/// [`PAID_NOTIFY_WORKER_LIMIT`], bounding the concurrent EVM and DHT work that
/// is actually expensive, rather than this queue depth.
///
/// A client PUT fans one notify per key out to the whole paid close group, so
/// a single upload legitimately arrives as a burst of tens. At the 512 KiB
/// `MAX_PAYMENT_PROOF_SIZE_BYTES` worst case, sixty-four outstanding is a
/// 32 MiB ceiling — half the fresh-offer admission ceiling, for messages that
/// carry no chunk payload.
const PAID_NOTIFY_MAX_OUTSTANDING: usize = 64;

/// Maximum admitted paid-list notifications from one source peer.
///
/// A quarter of the pool. One peer legitimately supplies a whole upload's
/// worth of notifies, so this must comfortably exceed a typical file's chunk
/// count in flight; it exists to stop a single source evicting every other
/// peer's durable paid-list evidence, not to ration ordinary traffic.
const PAID_NOTIFY_MAX_OUTSTANDING_PER_PEER: u32 = 16;

/// Maximum fetch responses served concurrently.
///
/// Each successful response can upload a 4 MiB chunk. Matching
/// [`MAX_CONCURRENT_REPLICATION_SENDS`] keeps fetch serving to about 12 MiB of
/// simultaneous chunk data, which avoids saturating typical home upload links.
const FETCH_RESPONDER_WORKER_LIMIT: usize = 3;

/// Maximum fetch requests admitted across workers and their bounded waiters.
///
/// Four worker waves absorb short bursts without retaining chunk bytes—the
/// request contains only a key—while the dequeue deadline sheds work before a
/// sustained flood can keep the node serving requests whose callers timed out.
const FETCH_RESPONDER_MAX_OUTSTANDING: usize = FETCH_RESPONDER_WORKER_LIMIT * 4;

/// Maximum admitted fetch requests from one source peer.
///
/// Two requests let one peer pipeline useful reads while leaving at least one
/// of the three workers available to other peers under a single-source flood.
const FETCH_RESPONDER_MAX_OUTSTANDING_PER_PEER: u32 = 2;

/// Maximum verification batches served concurrently.
///
/// Point lookups are fast, but a batch can contain 8,192 of them. Two
/// workers isolate that synchronous work from message dispatch without turning
/// large batches into an I/O fan-out throughput contest.
const VERIFICATION_RESPONDER_WORKER_LIMIT: usize = 2;

/// Maximum verification batches admitted across workers and bounded waiters.
///
/// Four worker waves absorb ordinary cross-peer bursts while the dequeue
/// deadline prevents queued batches from consuming lookup capacity after their
/// requesters have stopped waiting.
const VERIFICATION_RESPONDER_MAX_OUTSTANDING: usize = VERIFICATION_RESPONDER_WORKER_LIMIT * 4;

/// Maximum admitted verification batches from one source peer.
///
/// Senders already aggregate a peer's keys into one batch. One outstanding
/// batch therefore preserves useful work while reserving the other worker and
/// the bounded queue for different peers.
const VERIFICATION_RESPONDER_MAX_OUTSTANDING_PER_PEER: u32 = 1;

/// Maximum neighbor-sync requests served concurrently across source peers.
///
/// Building a response scans local keys and performs DHT lookups, so two
/// workers allow cross-peer progress without multiplying that expensive scan
/// into broad network and storage contention.
const NEIGHBOR_SYNC_RESPONDER_WORKER_LIMIT: usize = 2;

/// Maximum neighbor-sync requests admitted across workers and bounded waiters.
///
/// Four worker waves cover ordinary cadence overlap while keeping retained sync
/// payloads bounded; expired waiters are shed before any key scan begins.
const NEIGHBOR_SYNC_RESPONDER_MAX_OUTSTANDING: usize = NEIGHBOR_SYNC_RESPONDER_WORKER_LIMIT * 4;

/// Maximum admitted neighbor-sync requests from one source peer.
///
/// Sync history must be updated before repair proofs for the same peer. A
/// single slot preserves that ordering while independent peers remain parallel.
const NEIGHBOR_SYNC_RESPONDER_MAX_OUTSTANDING_PER_PEER: u32 = 1;

/// Match an inbound topic against the replication protocol ids, in both the bare
/// gossip form and the `/rr/<id>` request-response form.
///
/// Returns the matched core or [`SUBTREE_AUDIT_PROTOCOL_ID`] id and whether it
/// was the RR form. The matched id is carried into the handler so it can enforce
/// that subtree messages only arrive on the subtree id.
fn match_replication_protocol(topic: &str) -> Option<(&'static str, bool)> {
    for id in [REPLICATION_PROTOCOL_ID, SUBTREE_AUDIT_PROTOCOL_ID] {
        if topic == id {
            return Some((id, false));
        }
        if let Some(rest) = topic.strip_prefix(RR_PREFIX) {
            if rest == id {
                return Some((id, true));
            }
        }
    }
    None
}

/// Whether a decoded body belongs on the protocol id it arrived on:
/// subtree-audit bodies on [`SUBTREE_AUDIT_PROTOCOL_ID`] and every other body,
/// including digest audits, on [`REPLICATION_PROTOCOL_ID`].
///
/// The receive guard drops any mismatch (a cross-version or misrouted message);
/// sharing this one predicate between the guard and its regression test means a
/// change to the rule cannot pass the test unnoticed.
fn body_matches_protocol(body: &ReplicationMessageBody, protocol: &str) -> bool {
    protocol == response_protocol_for(body)
}

/// The protocol id a body belongs on — the single source of truth for BOTH
/// directions: the receive guard ([`body_matches_protocol`]) and the outbound
/// response selector in `send_replication_response_checked`.
///
/// Sharing one function makes the subtree/core isolation symmetric.
fn response_protocol_for(body: &ReplicationMessageBody) -> &'static str {
    if body.is_subtree_audit() {
        SUBTREE_AUDIT_PROTOCOL_ID
    } else {
        REPLICATION_PROTOCOL_ID
    }
}

fn fresh_offer_payment_context() -> VerificationContext {
    VerificationContext::FreshReplication
}

fn paid_notify_payment_context() -> VerificationContext {
    VerificationContext::PaidListAdmission
}

/// Boxed future type for in-flight fetch tasks.
type FetchFuture = Pin<Box<dyn Future<Output = (XorName, Option<FetchOutcome>)> + Send>>;

/// Fresh-offer keys currently being handled, each with the proofs still to try.
///
/// Concurrent duplicates are routine: a client PUT is confirmed by
/// `CLOSE_GROUP_MAJORITY` nodes and each of them fans the chunk out, so one key
/// commonly arrives from several senders at once. Collapsing them onto one
/// handler is what keeps a burst of PUTs from costing a permit, a worker slot,
/// and an on-chain verification per copy.
///
/// What they collapse *onto* is the load-bearing part. Keeping only the key and
/// refusing every later offer outright made the first arrival the only arrival:
/// if its proof failed, the record was lost even though a valid proof for the
/// same bytes was queued behind it, and the resulting absence was charged to
/// this node by the delayed possession check. So the entry holds the bytes once
/// and queues each sender's proof, and the handler works down that queue. A
/// later offer therefore costs a proof, not a payload — sound only because
/// `fresh_offer_structural_rejection` has confirmed `key == BLAKE3(data)` for
/// every one of them before it is queued, which is what makes their bytes
/// provably identical.
///
/// Entries are exact keys rather than hash shards. A node only receives offers
/// for keys it is close to, so the accepted key set clusters tightly around its
/// own ID — any index derived from the key would land nearly every offer on one
/// shard and serialize unrelated keys behind each other. Exact keys keep them
/// independent, and the map stays bounded by [`FRESH_OFFER_MAX_OUTSTANDING`],
/// each entry by [`MAX_FRESH_OFFER_ATTEMPTS_PER_KEY`].
///
/// The critical section is a map insert, pop, or remove and is never held across
/// an await, so this is a blocking mutex rather than an async one.
type FreshOfferInFlight = Arc<Mutex<HashMap<XorName, FreshOfferEntry>>>;

/// One sender's unverified claim to have paid for a key already in flight.
///
/// Carries no payload: the bytes live once in [`FreshOfferEntryGuard`], and the
/// content-address check ran before this attempt was queued.
struct FreshOfferAttempt {
    source: PeerId,
    proof_of_payment: Vec<u8>,
    request_id: u64,
    rr_message_id: Option<String>,
}

/// Proofs still to try for one in-flight key, and who supplied them.
///
/// Deliberately holds neither the bytes nor an arrival time: both belong to the
/// handler that owns the key, and live once in [`FreshOfferEntryGuard`].
struct FreshOfferEntry {
    /// Untried proofs in arrival order. The handler holds the current one.
    pending: VecDeque<FreshOfferAttempt>,
    /// Sources already represented, so one peer cannot fill the queue alone.
    sources: HashSet<PeerId>,
    /// Proofs admitted over this entry's whole life, **never decremented**.
    ///
    /// The budget has to be spent by admissions rather than held by the queue.
    /// The handler pops a proof before verifying it, so gating on
    /// `pending.len()` would let a fresh source refill the slot that pop just
    /// freed, and a stream of distinct sources could then run unbounded
    /// sequential payment verifications while holding one of only four worker
    /// slots. Counting admissions makes the cap a lifetime budget instead.
    admitted: usize,
}

/// How an arriving fresh offer joined the work already in flight for its key.
enum FreshOfferAdmission {
    /// Opened the entry. This offer's handler owns the key and drives every
    /// queued proof, including proofs that arrive later.
    Opened(Box<FreshOfferEntryGuard>),
    /// Merged into an entry another offer opened; its handler reaches this proof
    /// if the ones ahead of it fail.
    Joined,
    /// The entry already holds [`MAX_FRESH_OFFER_ATTEMPTS_PER_KEY`] proofs.
    Full,
    /// This source already has a proof queued for this key.
    DuplicateSource,
}

// Gated on `logging` like `SerialQueueDropReason::as_str`: the only caller is a
// `debug!`, which compiles to nothing without the feature.
#[cfg(feature = "logging")]
impl FreshOfferAdmission {
    /// Why the offer added nothing to the work already queued for its key.
    ///
    /// Local logging only — the wire reason stays uniform so a probing peer
    /// cannot tell a full queue from a repeat of its own proof.
    const fn surplus_reason(&self) -> &'static str {
        match self {
            Self::DuplicateSource => "this source already has a proof queued",
            Self::Full => "the key already holds its full complement of proofs",
            Self::Opened(_) | Self::Joined => "not surplus",
        }
    }
}

/// RAII ownership of one in-flight fresh-offer key.
///
/// Clears the entry on drop, so an early return, an error, or a panic cannot
/// strand a key as permanently in flight. Also owns the single copy of the
/// offered bytes that every queued proof is tried against.
struct FreshOfferEntryGuard {
    in_flight: FreshOfferInFlight,
    key: XorName,
    /// The bytes every attempt for this key shares, held exactly once.
    data: Vec<u8>,
    /// Arrival of the offer that opened the entry.
    received_at: Instant,
    /// Cleared once the entry has been removed, so `drop` cannot delete an entry
    /// a *later* offer has since opened for the same key.
    holds_entry: bool,
}

impl FreshOfferEntryGuard {
    /// Open an entry for this offer's key, or queue its proof behind the entry
    /// already open.
    ///
    /// Takes the offer by value: on `Opened` its bytes move into the guard, and
    /// on every other outcome they are dropped here rather than held for the
    /// lifetime of the entry.
    fn admit(
        in_flight: &FreshOfferInFlight,
        offer: protocol::FreshReplicationOffer,
        source: PeerId,
        request_id: u64,
        rr_message_id: Option<String>,
        received_at: Instant,
    ) -> FreshOfferAdmission {
        let key = offer.key;
        let attempt = FreshOfferAttempt {
            source,
            proof_of_payment: offer.proof_of_payment,
            request_id,
            rr_message_id,
        };

        let mut in_flight_map = in_flight.lock();
        if let Some(entry) = in_flight_map.get_mut(&key) {
            if entry.sources.contains(&source) {
                return FreshOfferAdmission::DuplicateSource;
            }
            // Lifetime budget, not queue depth: a proof the handler has already
            // popped has spent its slot, not returned it.
            if entry.admitted >= MAX_FRESH_OFFER_ATTEMPTS_PER_KEY {
                return FreshOfferAdmission::Full;
            }
            entry.admitted = entry.admitted.saturating_add(1);
            entry.sources.insert(source);
            entry.pending.push_back(attempt);
            return FreshOfferAdmission::Joined;
        }

        let mut sources = HashSet::new();
        sources.insert(source);
        let mut pending = VecDeque::new();
        pending.push_back(attempt);
        in_flight_map.insert(
            key,
            FreshOfferEntry {
                pending,
                sources,
                admitted: 1,
            },
        );
        drop(in_flight_map);
        FreshOfferAdmission::Opened(Box::new(Self {
            in_flight: Arc::clone(in_flight),
            key,
            data: offer.data,
            received_at,
            holds_entry: true,
        }))
    }

    /// The bytes every proof for this key is tried against.
    fn data(&self) -> &[u8] {
        &self.data
    }

    /// When the first offer for this key arrived.
    fn received_at(&self) -> Instant {
        self.received_at
    }

    /// Take the next untried proof, releasing the key when none remain.
    ///
    /// Popping and releasing happen under one lock so a proof arriving exactly
    /// as the queue empties is never silently discarded: it either lands in this
    /// entry and is returned here, or finds no entry and opens its own.
    fn next_attempt(&mut self) -> Option<FreshOfferAttempt> {
        let mut in_flight = self.in_flight.lock();
        let Some(entry) = in_flight.get_mut(&self.key) else {
            self.holds_entry = false;
            return None;
        };
        if let Some(attempt) = entry.pending.pop_front() {
            return Some(attempt);
        }
        in_flight.remove(&self.key);
        self.holds_entry = false;
        None
    }

    /// Release the key and return the proofs that were never tried, so their
    /// senders can be told the outcome the key reached without them.
    fn release(&mut self) -> Vec<FreshOfferAttempt> {
        let mut in_flight = self.in_flight.lock();
        self.holds_entry = false;
        in_flight
            .remove(&self.key)
            .map(|entry| entry.pending.into_iter().collect())
            .unwrap_or_default()
    }
}

impl Drop for FreshOfferEntryGuard {
    fn drop(&mut self) {
        if self.holds_entry {
            self.in_flight.lock().remove(&self.key);
        }
    }
}

/// Shared dependencies for one verification worker cycle.
struct VerificationCycleContext<'a> {
    p2p_node: &'a Arc<P2PNode>,
    paid_list: &'a Arc<PaidList>,
    storage: &'a Arc<ChunkStore>,
    queues: &'a Arc<RwLock<ReplicationQueues>>,
    config: &'a ReplicationConfig,
    bootstrap_state: &'a Arc<RwLock<BootstrapState>>,
    is_bootstrapping: &'a Arc<RwLock<bool>>,
    bootstrap_complete_notify: &'a Arc<Notify>,
    /// v12 §6 holder-eligibility inputs. The verifier downgrades a
    /// peer's Present claim to Unresolved unless they're a credited
    /// holder of the key (i.e. they recently passed a commitment-bound
    /// audit on it under their currently-credited commitment hash).
    last_commitment_by_peer: &'a Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    ever_capable_peers: &'a Arc<RwLock<HashSet<PeerId>>>,
    recent_provers: &'a Arc<RwLock<RecentProvers>>,
}

/// Fetch worker polling interval in milliseconds.
const FETCH_WORKER_POLL_MS: u64 = 100;

/// Verification worker polling interval in milliseconds.
const VERIFICATION_WORKER_POLL_MS: u64 = 250;

/// Verification cycle duration that is worth surfacing at info level.
const VERIFICATION_CYCLE_SLOW_LOG_MS: u128 = 500;

/// Standard trust event weight for per-operation success/failure signals.
///
/// Used for individual replication fetch outcomes, integrity check failures,
/// and bootstrap claim abuse. Distinct from `AUDIT_FAILURE_TRUST_WEIGHT` which
/// is reserved for confirmed audit failures.
const REPLICATION_TRUST_WEIGHT: f64 = 1.0;
/// Bound trust updates from one verification cycle. A malicious peer can
/// advertise thousands of bad singleton keys at once; a few independent
/// contradictions are enough for the trust engine without flooding it.
const MAX_BAD_HINT_TRUST_REPORTS_PER_PEER_PER_CYCLE: usize = 3;

/// Bootstrap drain check interval in seconds.
const BOOTSTRAP_DRAIN_CHECK_SECS: u64 = 5;

/// Grace period `shutdown()` waits for each long-lived background task to
/// observe the cancellation token and terminate before aborting it.
///
/// Detached tasks are drained without a timeout because storage-capable work
/// may be awaiting a `spawn_blocking` storage operation, which continues running
/// if its async waiter is dropped.
const SHUTDOWN_TASK_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the responder rebuilds + rotates its storage commitment.
///
/// Each rebuild scans the store to compute leaf hashes; for ~10k keys this is
/// sub-100ms (BLAKE3 + tree build). Retention is gossip-anchored, NOT
/// rotation-anchored: the responder stays answerable for the current
/// commitment plus every root it recently gossiped that is still in-window
/// (~2 in steady state), each kept for `GOSSIP_ANSWERABILITY_TTL` (3 h) after
/// its last emission (see `commitment_state`). So the rotation cadence does
/// not by itself bound answerability — a gossiped commitment stays
/// answerable across rotations until its gossip TTL lapses.
///
/// Default: 1 hour, aligned with the worst-case neighbor-sync cooldown
/// (`NEIGHBOR_SYNC_COOLDOWN_SECS = 3600`). Because the gossip TTL (3 h)
/// comfortably exceeds the gap between our rotation and the next gossip
/// arrival at a remote peer, this prevents the "unknown commitment hash" ->
/// Idle audit-skip pattern from being the common case.
///
/// Why not faster: the v12 pin is bound to a specific point-in-time
/// commitment, so rotation isn't security-critical for pin freshness —
/// only for keeping the committed key set current as the responder
/// writes new keys. 1 hour is plenty for that, and slow enough that
/// honest auditors mostly hit `current` or `previous` rather than the
/// "rotated past" case.
const COMMITMENT_ROTATION_INTERVAL_SECS: u64 = 3600;

/// How often the responder retention snapshot is flushed to disk (ADR-0004 A1).
/// Short relative to the answerability TTL (3 h) so a gossip-stamp refresh is
/// durable well before it could matter to a restart, while the write-on-change
/// guard keeps idle nodes from needless disk writes.
const RETENTION_PERSIST_INTERVAL_SECS: u64 = 30;

/// Cadence of the `replication traffic summary (cumulative)` INFO lines
/// (V2-623). A `const` so testnets can drop it to 60s; 300s is the production
/// default that keeps log volume negligible.
const TRAFFIC_SUMMARY_INTERVAL_SECS: u64 = 300;

/// Cadence of the read-only bootstrap state snapshot used to separate drain
/// debt from cache and broader connectivity failures in fleet logs.
#[cfg(feature = "logging")]
const BOOTSTRAP_STATE_SNAPSHOT_INTERVAL_SECS: u64 = 60;

/// Maximum tolerated auditor↔responder wall-clock skew for the first-audit
/// in-window screen (ADR-0004 A1 guardrail A). The screen accepts a monetized pin
/// for first audit only if its SIGNED `quote_ts` lands in
/// `[now - (GOSSIP_ANSWERABILITY_TTL - MONETIZED_AUDIT_SKEW_MARGIN), now + MONETIZED_AUDIT_SKEW_MARGIN]`
/// — fail-closed on BOTH ends: a quote dated too far in the future (a
/// badly-skewed or replayed quote) and one too old (the responder may have aged
/// the pin out) are both skipped, so — with grace removed — a stale/skewed quote
/// cannot frame an honest node. This assumes bounded clock skew (nodes NTP-synced
/// within this margin); a legit first audit fires moments after payment
/// (`quote_ts ≈ now`), far from either bound. The gossip-lottery path (which pins
/// the responder's OWN freshly-gossiped root) is the clock-skew-immune backstop.
/// 30 min dwarfs any realistic honest skew while leaving a wide audit window.
const MONETIZED_AUDIT_SKEW_MARGIN: Duration = Duration::from_secs(30 * 60);

/// ADR-0004 A1 (guardrail A): whether a monetized pin's SIGNED `quote_ts` lands
/// inside the answerability window relative to `now`, so first-auditing it cannot
/// false-convict once grace is removed. Fail-closed on BOTH ends (see
/// [`MONETIZED_AUDIT_SKEW_MARGIN`]): a quote more than the skew margin in the
/// future, or older than `GOSSIP_ANSWERABILITY_TTL - margin`, is out of window.
/// All comparisons use `duration_since` (no `Duration` overflow).
fn quote_within_audit_window(quote_ts: SystemTime, now: SystemTime) -> bool {
    let too_future = quote_ts
        .duration_since(now)
        .is_ok_and(|ahead| ahead > MONETIZED_AUDIT_SKEW_MARGIN);
    let audit_cutoff = GOSSIP_ANSWERABILITY_TTL.saturating_sub(MONETIZED_AUDIT_SKEW_MARGIN);
    let too_old = now
        .duration_since(quote_ts)
        .is_ok_and(|age| age >= audit_cutoff);
    !(too_future || too_old)
}

/// Minimum interval between commitment signature verifications for a
/// single peer (v10/v12 §2 step 3 + §11 `DoS`).
///
/// A sybil that bypasses the routing-table gate (e.g. by transient
/// bucket pollution) could otherwise force one ML-DSA-65 verify (~1 ms)
/// per gossip message. This rate limit caps the verify-per-peer rate
/// at 1/min, which is comfortably above the legitimate gossip cadence
/// (the 10-20 min neighbor-sync round on each peer).
const COMMITMENT_SIG_VERIFY_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Hard cap on the size of `last_commitment_by_peer`.
///
/// Bounds the per-process memory cost of the auditor's per-peer
/// commitment cache. Each entry holds a `StorageCommitment`
/// (~5 KiB: 1952-byte pubkey + 3293-byte signature + small fields).
/// At 4096 entries the cache is ~20 MiB, which comfortably covers a
/// realistic close-group neighborhood. When the cap is hit, one
/// arbitrary existing entry is evicted on insert (`HashMap` iteration
/// order is unspecified; we do not track insertion order). The
/// `PeerRemoved` handler proactively drops entries as the DHT
/// detects departures, and `ingest_peer_commitment` only admits
/// commitments from peers currently in the routing table — together
/// the cap is the third line of defence against sybil/churn flooding.
const MAX_LAST_COMMITMENT_BY_PEER: usize = 4096;

/// ADR-0004 Amendment 4: admission cap for the first-audit pending queue,
/// sized to the launch budget instead of the commitment cache.
///
/// The token bucket can launch at most one audit per
/// [`config::FIRST_AUDIT_LAUNCH_INTERVAL`] (plus the
/// [`config::FIRST_AUDIT_BUDGET_BURST`] allowance), and a pending pin stays
/// launchable for at most the effective answerability window
/// ([`GOSSIP_ANSWERABILITY_TTL`] − [`MONETIZED_AUDIT_SKEW_MARGIN`]). Any
/// occupancy beyond `window / interval + burst` is work that cannot launch
/// before it expires, so admitting it only builds an aging backlog whose
/// telemetry measures the backlog instead of schedulable work.
///
/// At capacity, admission displaces a uniformly RANDOM incumbent (counted as
/// `capacity_evicted`), so under overload `pending` degrades to a budget-sized
/// rolling sample in which no arrival order lets an attacker deterministically
/// flush a chosen target; a fresh pin always enters the sample with an
/// unpredictable chance of near-immediate audit, whereas refusing at the door
/// would let a sustained payment flood guarantee that every later pin is never
/// admitted. See [`coalesce_first_audit_event`] for the displacement rule and
/// ADR-0004 Amendment 4 for the eviction-cost math.
///
/// Derivation uses the STRICT reserve-time horizon: a launch at quote age `a`
/// is usable only if the quote stays answerable through `a` plus the maximum
/// launch jitter and send slack, so the last usable refill is the largest
/// `k` with `k * interval < cutoff - jitter_max - slack`. The unit test
/// simulates the shipped predicate instant-by-instant and must agree.
#[allow(clippy::cast_possible_truncation)] // bounded by TTL-secs/interval-secs + burst (~31)
const FIRST_AUDIT_PENDING_CAP: usize = {
    let strict_horizon_secs = GOSSIP_ANSWERABILITY_TTL
        .as_secs()
        .saturating_sub(MONETIZED_AUDIT_SKEW_MARGIN.as_secs())
        .saturating_sub(config::FIRST_AUDIT_LAUNCH_JITTER_MAX.as_secs())
        .saturating_sub(FIRST_AUDIT_SEND_LATENCY_SLACK.as_secs());
    // Strictly-inside count: a refill landing exactly ON the horizon is dead
    // (`age >= cutoff` rejects), hence the `- 1`. Compile-time division-by-zero
    // if the launch interval is ever zeroed: a zero interval makes the budget
    // (and this cap) meaningless.
    let refills =
        strict_horizon_secs.saturating_sub(1) / config::FIRST_AUDIT_LAUNCH_INTERVAL.as_secs();
    (refills + config::FIRST_AUDIT_BUDGET_BURST as u64) as usize
};

// Compile-time guardrails: the cap must be a usable `LruCache` capacity and
// strictly tighter than the commitment-cache bound it replaced.
const _: () = {
    assert!(FIRST_AUDIT_PENDING_CAP >= 1);
    assert!(FIRST_AUDIT_PENDING_CAP < MAX_LAST_COMMITMENT_BY_PEER);
};

/// Cap on the sticky `ever_capable_peers` set. Bounds memory so a
/// long-running bootstrap node cannot have the set grow without limit
/// from peer-id churn. Sized at 4x `MAX_LAST_COMMITMENT_BY_PEER` so
/// the set comfortably outlives normal LRU churn but still caps the
/// blast radius of identity-rotation attacks. Once full we refuse new
/// inserts (no eviction) — keeps the historic set stable; new v12
/// peers above the cap are treated as legacy on rejoin, which matches
/// the behaviour before this set existed, not a security regression.
const MAX_EVER_CAPABLE_PEERS: usize = 4 * MAX_LAST_COMMITMENT_BY_PEER;

// ---------------------------------------------------------------------------
// ReplicationEngine
// ---------------------------------------------------------------------------

/// The replication engine manages all replication background tasks and state.
pub struct ReplicationEngine {
    /// Replication configuration (shared across spawned tasks).
    config: Arc<ReplicationConfig>,
    /// P2P networking node.
    p2p_node: Arc<P2PNode>,
    /// Local chunk storage.
    storage: Arc<ChunkStore>,
    /// Persistent paid-for-list.
    paid_list: Arc<PaidList>,
    /// Payment verifier for `PoP` validation.
    payment_verifier: Arc<PaymentVerifier>,
    /// Replication pipeline queues.
    queues: Arc<RwLock<ReplicationQueues>>,
    /// Neighbor sync cycle state.
    sync_state: Arc<RwLock<NeighborSyncState>>,
    /// Per-peer sync history (for `RepairOpportunity`).
    ///
    /// This map grows with peer churn and is intentionally unbounded: entries
    /// are lightweight (`PeerSyncRecord` is two fields) and peer IDs are
    /// naturally bounded by the routing table's k-bucket capacity.
    sync_history: Arc<RwLock<HashMap<PeerId, PeerSyncRecord>>>,
    /// Per-peer cooldown for gossip-triggered subtree audits (ADR-0002).
    ///
    /// Records when each peer was last audited so a burst of gossiped
    /// commitment changes cannot spawn back-to-back audits of the same peer.
    /// Bounded by routing-table membership and cleaned on `PeerRemoved`.
    audit_on_gossip_cooldown: Arc<RwLock<HashMap<PeerId, Instant>>>,
    /// Gossip-private lottery attempt window (one roll per peer per window,
    /// win or lose). Kept separate from `audit_on_gossip_cooldown` so a losing
    /// ticket never stamps the shared map and thus never defers a monetized
    /// first audit. Bounded like its sibling and cleaned on `PeerRemoved`.
    gossip_lottery_attempts: Arc<RwLock<HashMap<PeerId, Instant>>>,
    /// Completed local neighbor-sync cycle epoch for proof maturity.
    sync_cycle_epoch: Arc<RwLock<u64>>,
    /// Per-key repair proof tracking for audit eligibility.
    repair_proofs: Arc<RwLock<RepairProofs>>,
    /// Bootstrap state tracking.
    bootstrap_state: Arc<RwLock<BootstrapState>>,
    /// Whether this node is currently bootstrapping.
    is_bootstrapping: Arc<RwLock<bool>>,
    /// Trigger for early neighbor sync (signalled on topology changes).
    sync_trigger: Arc<Notify>,
    /// Notified when `is_bootstrapping` transitions from `true` to `false`.
    bootstrap_complete_notify: Arc<Notify>,
    /// Node identity (for signing storage commitments).
    ///
    /// Phase 3 of the v12 storage-bound audit design. The responder
    /// uses this to sign its periodically-built `StorageCommitment`.
    identity: Arc<NodeIdentity>,
    /// Responder-side commitment state (two-slot atomic rotation).
    ///
    /// Periodically rebuilt from the live key set; gossiped on
    /// outbound `NeighborSyncRequest`/`Response`; consulted by the
    /// commitment-bound audit handler.
    commitment_state: Arc<ResponderCommitmentState>,
    /// Path to the persisted responder retention snapshot
    /// (`{root_dir}/commitment_retention.bin`): reloaded on startup so an honest
    /// node's answerability survives restart (ADR-0004 A1), which is what makes
    /// removing audit grace safe (an unanswerable in-window pin is then provable
    /// misbehaviour, not an honest crash-restart).
    retention_path: PathBuf,
    /// Auditor-side per-peer commitment record (last known commitment +
    /// sticky `commitment_capable` flag).
    ///
    /// Populated whenever an inbound gossip carries a verified
    /// commitment from the sender. Used by `audit_tick` to snapshot
    /// `expected_commitment_hash` into outbound challenges, and by
    /// holder-eligibility (§6) to decide whether a peer's `recent_provers`
    /// proof should be honoured. The sticky `commitment_capable` flag
    /// flips true on first successful ingest and never reverts (§2
    /// step 5).
    last_commitment_by_peer: Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    /// Sticky set of peer IDs we have EVER seen carrying a v12
    /// commitment, independent of whether their commitment bytes are
    /// still in `last_commitment_by_peer`. The §6 holder-eligibility
    /// closure consults this set to keep treating churned-out
    /// previously-v12 peers as v12-capable (rather than degrading them
    /// to "legacy" credit-unconditionally) when they re-appear on the
    /// network before their next gossip arrives. Bounded growth: even
    /// at one million peers seen over the node's lifetime, the set is
    /// 32 MB.
    ever_capable_peers: Arc<RwLock<HashSet<PeerId>>>,
    /// Auditor-side holder-eligibility cache (v12 §6).
    ///
    /// Recorded on successful commitment-bound audit; read by future
    /// quorum / paid-list eligibility checks (phase-3 stretch).
    recent_provers: Arc<RwLock<RecentProvers>>,
    /// Per-peer last sig-verify attempt timestamp for the §2 step 3 /
    /// §11 `DoS` rate limit. Bumped on EVERY verify attempt (success or
    /// failure) so a peer we've never successfully verified can't burn
    /// CPU on a flood of structurally-plausible-but-invalid gossips.
    /// Lives separately from `last_commitment_by_peer` because that
    /// map's records only exist after a successful verify.
    sig_verify_attempts: Arc<RwLock<HashMap<PeerId, Instant>>>,
    /// Limits concurrent outbound replication sends to prevent bandwidth
    /// saturation on home broadband connections.
    send_semaphore: Arc<Semaphore>,
    /// Bounds concurrent IN-FLIGHT LIGHT audit-responder tasks (responsible-chunk
    /// audits + subtree slice round 2). The heavy subtree round 1 has its own
    /// tighter pool ([`SubtreeRound1Limiter`]). Those are spawned off the serial
    /// message loop so disk
    /// reads don't block replication; the semaphore restores a global
    /// backpressure ceiling so the node can't fan out unbounded `get_raw` reads
    /// / multi-MiB byte serves.
    audit_responder_semaphore: Arc<Semaphore>,
    /// Per-source in-flight audit-responder counts, capped at
    /// [`MAX_AUDIT_RESPONSES_PER_PEER`]. The GLOBAL semaphore alone is not
    /// flood-fair: one peer spamming challenges could occupy every slot and
    /// starve honest auditors, whose dropped challenges then convert to
    /// audit timeouts against HONEST peers (codex-r2 A). This
    /// per-peer cap guarantees no single source can hold more than its share,
    /// so a flood self-throttles without denying service to everyone else.
    audit_responder_inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    /// Windowed per-origin capacity and processing-time telemetry for every
    /// request sharing the audit responder pool.
    audit_responder_metrics: Arc<AuditResponderMetrics>,
    /// Shared auditor-side limiter for outbound digest `AuditChallenge`s.
    ///
    /// Responsible-chunk audits, prune confirmations, and possession checks
    /// all use this before sending so local bursts wait instead of breaching
    /// the responder's deployed per-source admission cap.
    audit_challenge_coordinator: Arc<AuditChallengeCoordinator>,
    /// Worker permits for bandwidth-bound fetch responses.
    fetch_responder_worker_semaphore: Arc<Semaphore>,
    /// Admission permits bounding fetch workers and queued waiters together.
    fetch_responder_admission_semaphore: Arc<Semaphore>,
    /// Per-source fetch responder counts for flood-fair admission.
    fetch_responder_inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    /// Worker permits for lookup-heavy verification batches.
    verification_responder_worker_semaphore: Arc<Semaphore>,
    /// Admission permits bounding verification workers and queued waiters.
    verification_responder_admission_semaphore: Arc<Semaphore>,
    /// Per-source verification responder counts for flood-fair admission.
    verification_responder_inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    /// Worker permits for expensive inbound neighbor-sync requests.
    neighbor_sync_responder_worker_semaphore: Arc<Semaphore>,
    /// Admission permits bounding sync workers and queued waiters together.
    neighbor_sync_responder_admission_semaphore: Arc<Semaphore>,
    /// Per-source sync responder counts; capped at one to preserve ordering.
    neighbor_sync_responder_inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    /// Bounded worker permits for expensive fresh-offer handling.
    fresh_offer_worker_semaphore: Arc<Semaphore>,
    /// Admission permits bounding offers running on a worker or queued for one.
    fresh_offer_admission_semaphore: Arc<Semaphore>,
    /// Per-source fresh-offer counts, so one sender cannot hold the whole pool
    /// and turn honest senders' refusals into trust penalties on this node.
    fresh_offer_responder_inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    /// Keys claimed by an in-flight fresh-offer handler, so concurrent
    /// duplicates collapse onto one verification and one write.
    fresh_offer_in_flight: FreshOfferInFlight,
    /// Bounded worker permits for paid-list notification proof verification.
    paid_notify_worker_semaphore: Arc<Semaphore>,
    /// Admission permits bounding notifies on a worker or queued for one.
    paid_notify_admission_semaphore: Arc<Semaphore>,
    /// Per-source paid-notify counts for flood-fair admission.
    paid_notify_responder_inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    /// Resource controls for the HEAVY subtree-audit round 1: its own
    /// tight admission pool (so a burst of full-subtree hashing can't starve the
    /// light audits), a per-peer rate cooldown, and single-use round-1 → round-2
    /// sessions binding a slice challenge to a matching round 1.
    subtree_round1: SubtreeRound1Limiter,
    /// Receiver for fresh-write events from the chunk PUT handler.
    ///
    /// When present, `start()` spawns a drainer task that calls
    /// `replicate_fresh` for each event.
    fresh_write_rx: Option<mpsc::UnboundedReceiver<fresh::FreshWriteEvent>>,
    /// Sender for delayed possession-check events (ADR-0003). The fresh-write
    /// drainer pushes the responsible close-group peers here after each fresh
    /// replication; the possession-check scheduler drains the paired receiver.
    possession_check_tx: mpsc::UnboundedSender<possession::PossessionCheckEvent>,
    /// Receiver paired with `possession_check_tx`; taken by the scheduler task.
    possession_check_rx: Option<mpsc::UnboundedReceiver<possession::PossessionCheckEvent>>,
    /// ADR-0004: sender the payment verifier clones to surface monetized pins
    /// for a deterministic first audit. The matching receiver is drained by
    /// `start_first_audit_drainer`. BOUNDED (Amendment 2): the producer
    /// `try_send`s and drops on a full queue, so ingress memory is capped just
    /// like launches; a dropped nomination is penalty-free — the peer's
    /// gossiped commitments stay lottery-covered and its next settled payment
    /// re-nominates the paid pin.
    monetized_pin_tx: mpsc::Sender<MonetizedPinEvent>,
    /// ADR-0004: receiver half of the monetized-pin channel, taken by
    /// `start_first_audit_drainer`.
    monetized_pin_rx: Option<mpsc::Receiver<MonetizedPinEvent>>,
    /// Counters shared with the first-audit drainer task, so the scheduler's
    /// decisions (queued / launched / self-target skipped / outcome) stay
    /// observable from the engine after the drainer takes the receiver.
    first_audit_observability: Arc<FirstAuditObservability>,
    /// Shutdown token.
    shutdown: CancellationToken,
    /// Background task handles.
    task_handles: Vec<JoinHandle<()>>,
    /// Tracks detached, short-lived work spawned by background producers.
    ///
    /// Fresh-offer and bounded responder workers, audit launches, per-fetch
    /// tasks, and delayed possession checks may retain storage or P2P state
    /// after their producer exits, so shutdown drains them before those
    /// resources may be reopened.
    detached_task_tracker: TaskTracker,
}

impl ReplicationEngine {
    /// Create a new replication engine.
    ///
    /// # Errors
    ///
    /// Returns an error if the `PaidList` LMDB environment cannot be opened
    /// or if the configuration fails validation.
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        config: ReplicationConfig,
        p2p_node: Arc<P2PNode>,
        storage: Arc<ChunkStore>,
        payment_verifier: Arc<PaymentVerifier>,
        identity: Arc<NodeIdentity>,
        root_dir: &Path,
        fresh_write_rx: mpsc::UnboundedReceiver<fresh::FreshWriteEvent>,
        shutdown: CancellationToken,
    ) -> Result<Self> {
        config.validate().map_err(Error::Config)?;

        let paid_list = Arc::new(
            PaidList::new(root_dir)
                .await
                .map_err(|e| Error::Storage(format!("Failed to open PaidList: {e}")))?,
        );

        let initial_neighbors = NeighborSyncState::new_cycle(Vec::new());
        let config = Arc::new(config);
        let (possession_check_tx, possession_check_rx) = mpsc::unbounded_channel();

        // ADR-0004: monetized-pin channel (verifier -> first-audit drainer).
        // Bounded (Amendment 2): every stage of the first-audit pipeline is
        // now capacity-limited — ingress queue here, pending set (LRU), and
        // launch rate (token bucket).
        let (monetized_pin_tx, monetized_pin_rx) =
            mpsc::channel(config::FIRST_AUDIT_INGRESS_CAPACITY);

        let engine = Self {
            config: Arc::clone(&config),
            p2p_node,
            storage,
            paid_list,
            payment_verifier,
            queues: Arc::new(RwLock::new(ReplicationQueues::new())),
            sync_state: Arc::new(RwLock::new(initial_neighbors)),
            sync_history: Arc::new(RwLock::new(HashMap::new())),
            audit_on_gossip_cooldown: Arc::new(RwLock::new(HashMap::new())),
            gossip_lottery_attempts: Arc::new(RwLock::new(HashMap::new())),
            sync_cycle_epoch: Arc::new(RwLock::new(0)),
            repair_proofs: Arc::new(RwLock::new(RepairProofs::new())),
            bootstrap_state: Arc::new(RwLock::new(BootstrapState::new())),
            is_bootstrapping: Arc::new(RwLock::new(true)),
            sync_trigger: Arc::new(Notify::new()),
            bootstrap_complete_notify: Arc::new(Notify::new()),
            identity,
            commitment_state: Arc::new(ResponderCommitmentState::new()),
            retention_path: root_dir.join("commitment_retention.bin"),
            last_commitment_by_peer: Arc::new(RwLock::new(HashMap::new())),
            ever_capable_peers: Arc::new(RwLock::new(HashSet::new())),
            recent_provers: Arc::new(RwLock::new(RecentProvers::new())),
            sig_verify_attempts: Arc::new(RwLock::new(HashMap::new())),
            send_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_REPLICATION_SENDS)),
            audit_responder_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_AUDIT_RESPONSES)),
            audit_responder_inflight: Arc::new(RwLock::new(HashMap::new())),
            audit_responder_metrics: Arc::new(AuditResponderMetrics::default()),
            audit_challenge_coordinator: Arc::new(AuditChallengeCoordinator::new()),
            fetch_responder_worker_semaphore: Arc::new(Semaphore::new(
                FETCH_RESPONDER_WORKER_LIMIT,
            )),
            fetch_responder_admission_semaphore: Arc::new(Semaphore::new(
                FETCH_RESPONDER_MAX_OUTSTANDING,
            )),
            fetch_responder_inflight: Arc::new(RwLock::new(HashMap::new())),
            verification_responder_worker_semaphore: Arc::new(Semaphore::new(
                VERIFICATION_RESPONDER_WORKER_LIMIT,
            )),
            verification_responder_admission_semaphore: Arc::new(Semaphore::new(
                VERIFICATION_RESPONDER_MAX_OUTSTANDING,
            )),
            verification_responder_inflight: Arc::new(RwLock::new(HashMap::new())),
            neighbor_sync_responder_worker_semaphore: Arc::new(Semaphore::new(
                NEIGHBOR_SYNC_RESPONDER_WORKER_LIMIT,
            )),
            neighbor_sync_responder_admission_semaphore: Arc::new(Semaphore::new(
                NEIGHBOR_SYNC_RESPONDER_MAX_OUTSTANDING,
            )),
            neighbor_sync_responder_inflight: Arc::new(RwLock::new(HashMap::new())),
            fresh_offer_worker_semaphore: Arc::new(Semaphore::new(FRESH_OFFER_WORKER_LIMIT)),
            fresh_offer_admission_semaphore: Arc::new(Semaphore::new(FRESH_OFFER_MAX_OUTSTANDING)),
            fresh_offer_responder_inflight: Arc::new(RwLock::new(HashMap::new())),
            fresh_offer_in_flight: Arc::new(Mutex::new(HashMap::new())),
            paid_notify_worker_semaphore: Arc::new(Semaphore::new(PAID_NOTIFY_WORKER_LIMIT)),
            paid_notify_admission_semaphore: Arc::new(Semaphore::new(PAID_NOTIFY_MAX_OUTSTANDING)),
            paid_notify_responder_inflight: Arc::new(RwLock::new(HashMap::new())),
            subtree_round1: SubtreeRound1Limiter::new(
                config.subtree_round1_responder_cooldown,
                config.subtree_round1_max_concurrent,
            ),
            fresh_write_rx: Some(fresh_write_rx),
            possession_check_tx,
            possession_check_rx: Some(possession_check_rx),
            monetized_pin_tx,
            monetized_pin_rx: Some(monetized_pin_rx),
            first_audit_observability: Arc::new(FirstAuditObservability::default()),
            shutdown,
            task_handles: Vec::new(),
            detached_task_tracker: TaskTracker::new(),
        };
        // ADR-0004 A1: reload persisted responder retention BEFORE any task
        // spawns, so an honest restarted node is answerable for its pre-restart
        // pins from the first audit it serves, and the persist loop never races
        // an empty snapshot over the good on-disk file.
        load_commitment_retention(&engine.commitment_state, &engine.retention_path).await;
        Ok(engine)
    }

    /// ADR-0004: a sender the payment verifier uses to surface monetized pins
    /// (commitments that backed a payment) for a first audit. Cloneable; the
    /// engine drains the matching receiver. Bounded: senders must `try_send`
    /// and treat a full queue as a benign drop (Amendment 2 best-effort).
    #[must_use]
    pub fn monetized_pin_sender(&self) -> mpsc::Sender<MonetizedPinEvent> {
        self.monetized_pin_tx.clone()
    }

    /// Get a reference to the `PaidList`.
    #[must_use]
    pub fn paid_list(&self) -> &Arc<PaidList> {
        &self.paid_list
    }

    /// Get a reference to the responder's commitment state. Used by audit
    /// handlers to look up commitments by hash; used by the rotation tick
    /// to install fresh ones.
    #[must_use]
    pub fn commitment_state(&self) -> &Arc<ResponderCommitmentState> {
        &self.commitment_state
    }

    /// Neighbour-sync state, for the storage migration's possession challenges.
    #[must_use]
    pub fn sync_state(&self) -> &Arc<RwLock<NeighborSyncState>> {
        &self.sync_state
    }

    /// The audit-challenge coordinator, for the storage migration's possession challenges.
    #[must_use]
    pub fn audit_challenge_coordinator(&self) -> &Arc<AuditChallengeCoordinator> {
        &self.audit_challenge_coordinator
    }

    /// Replication settings, for the storage migration's possession challenges.
    #[must_use]
    pub fn config(&self) -> &Arc<ReplicationConfig> {
        &self.config
    }

    /// Get a reference to the auditor's last-commitment-by-peer table.
    #[must_use]
    pub fn last_commitment_by_peer(&self) -> &Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>> {
        &self.last_commitment_by_peer
    }

    /// Get a reference to the holder-eligibility cache. Phase-3 stretch:
    /// will be read by quorum / paid-list eligibility checks.
    #[must_use]
    pub fn recent_provers(&self) -> &Arc<RwLock<RecentProvers>> {
        &self.recent_provers
    }

    /// Test-only: rebuild + rotate this node's storage commitment now over its
    /// current key set (normally on a 1h timer). Lets a test commit to chunks it
    /// just stored without waiting for the rotation cadence.
    ///
    /// # Errors
    ///
    /// Propagates any error from reading the local key set or building/signing
    /// the commitment.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn rebuild_commitment_now(&self) -> Result<()> {
        rebuild_and_rotate_commitment(
            &self.storage,
            &self.identity,
            &self.commitment_state,
            &self.p2p_node,
            &self.config,
        )
        .await
    }

    /// Test-only: directly seed this node's cached commitment for `peer`,
    /// simulating "we received `peer`'s gossiped commitment" without depending
    /// on neighbor-sync propagation timing. Lets a two-node audit test pin the
    /// peer's commitment deterministically.
    #[cfg(any(feature = "test-utils", test))]
    pub async fn inject_peer_commitment_for_test(
        &self,
        peer: &PeerId,
        commitment: StorageCommitment,
    ) {
        let now = Instant::now();
        self.last_commitment_by_peer
            .write()
            .await
            .insert(*peer, PeerCommitmentRecord::from_verified(commitment, now));
        self.ever_capable_peers.write().await.insert(*peer);
    }

    /// Test-only: isolate a monetized first audit of `peer` from live gossip
    /// audits. Suppresses new gossip lottery attempts for the current cooldown
    /// window and clears any shared cooldown stamped by an earlier gossip
    /// launch. The locks follow the production gossip-audit lock order.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn isolate_first_audit_for_test(&self, peer: &PeerId) {
        let now = Instant::now();
        let mut lottery_attempts = self.gossip_lottery_attempts.write().await;
        let mut launched = self.audit_on_gossip_cooldown.write().await;
        lottery_attempts.insert(*peer, now);
        launched.remove(peer);
    }

    /// Test-only: run ONE subtree audit against `peer` right now, pinned to the
    /// commitment this node has cached for it (from gossip), over the live wire.
    /// Returns the audit outcome so tests can assert honest-pass / adversary-fail
    /// in a real two-node setting without waiting for the gossip cadence.
    ///
    /// Returns `AuditTickResult::Idle` if we have no cached commitment for the
    /// peer yet (gossip hasn't reached us). Gated to test builds.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn audit_peer_now(&self, peer: &PeerId) -> audit::AuditTickResult {
        let target = {
            let map = self.last_commitment_by_peer.read().await;
            map.get(peer)
                .and_then(PeerCommitmentRecord::last_commitment)
                .and_then(|c| commitment_hash(c).map(|h| (h, c.key_count)))
        };
        let Some((pin, key_count)) = target else {
            return audit::AuditTickResult::Idle;
        };
        let credit = storage_commitment_audit::AuditCredit {
            recent_provers: &self.recent_provers,
        };
        storage_commitment_audit::run_subtree_audit(
            &self.p2p_node,
            &self.config,
            peer,
            pin,
            key_count,
            Some(&credit),
        )
        .await
    }

    /// Test-only: snapshot the first-audit scheduler's counters. Lets e2e
    /// tests assert what the live drainer decided for an injected
    /// [`MonetizedPinEvent`] (dropped as self-target vs queued and launched).
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn first_audit_stats(&self) -> FirstAuditStats {
        let o = &self.first_audit_observability;
        FirstAuditStats {
            received: o.received.load(Ordering::Relaxed),
            queued: o.queued.load(Ordering::Relaxed),
            self_target_skipped: o.self_target_skipped.load(Ordering::Relaxed),
            launched: o.launched.load(Ordering::Relaxed),
            passed: o.passed.load(Ordering::Relaxed),
            timed_out: o.timed_out.load(Ordering::Relaxed),
            failed: o.failed.load(Ordering::Relaxed),
        }
    }

    /// Test-only: run the possession check immediately for `key` against
    /// `peers`, bypassing the scheduler's randomised 5-15 minute settle delay.
    ///
    /// Penalises any peer that does not hold `key` at `AuditChallenge`
    /// severity (ADR-0003). Lets e2e tests assert the detection+penalty path
    /// deterministically without waiting for the scheduled check.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn run_possession_check_now(&self, key: XorName, peers: Vec<PeerId>) {
        possession::run_possession_check(
            key,
            peers,
            &self.p2p_node,
            &self.storage,
            &self.config,
            &self.sync_state,
            &self.audit_challenge_coordinator,
            &self.shutdown,
        )
        .await;
    }

    /// Test-only: place `key` directly into the fetch queue as though a
    /// verification cycle had just promoted it, with `sources` as its
    /// verified holders. Returns whether the key was enqueued.
    ///
    /// Bypasses admission, verification, and the promotion-time
    /// responsibility pre-filter, modelling a promotion decision that has
    /// since gone stale (topology churn between promotion and download).
    /// The only guard left standing is the per-attempt recheck inside
    /// `execute_single_fetch` — exactly the gate e2e tests use this seam to
    /// exercise.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn enqueue_fetch_for_test(&self, key: XorName, sources: Vec<PeerId>) -> bool {
        let distance = crate::client::xor_distance(&key, self.p2p_node.peer_id().as_bytes());
        self.queues
            .write()
            .await
            .enqueue_fetch(key, distance, sources)
    }

    /// Test-only: whether `key` is still tracked in any fetch-pipeline stage
    /// (pending verification, fetch queue, or in-flight fetch).
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn fetch_pipeline_contains_for_test(&self, key: &XorName) -> bool {
        self.queues.read().await.contains_key(key)
    }

    /// Test-only: place `key` into pending verification as though `hinter` had
    /// just advertised it with a replica hint. Returns whether it was admitted.
    ///
    /// Enters the pipeline one stage earlier than
    /// [`Self::enqueue_fetch_for_test`], so what the verification cycle itself
    /// decides about the key is observable.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn enqueue_pending_verify_for_test(&self, key: XorName, hinter: PeerId) -> bool {
        let now = Instant::now();
        let entry = VerificationEntry {
            state: VerificationState::PendingVerify,
            verified_sources: Vec::new(),
            tried_sources: HashSet::new(),
            created_at: now,
            next_verify_at: now,
            hint_sources: HashSet::from([hinter]),
            replica_hint_sources: HashSet::from([hinter]),
            unresolved_retries: 0,
            no_holder_reported: false,
        };
        self.queues
            .write()
            .await
            .add_pending_verify(key, entry)
            .admitted()
    }

    /// Test-only: how far ahead `key`'s next verification round is scheduled,
    /// or `None` when the key is not pending verification.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn pending_verify_delay_for_test(&self, key: &XorName) -> Option<Duration> {
        self.queues.read().await.get_pending(key).map(|entry| {
            entry
                .next_verify_at
                .saturating_duration_since(Instant::now())
        })
    }

    /// Start all background tasks.
    ///
    /// `dht_events` must be subscribed **before** `P2PNode::start()` so that
    /// the `BootstrapComplete` event emitted during DHT bootstrap is not
    /// missed by the bootstrap-sync gate.
    pub fn start(&mut self, dht_events: tokio::sync::broadcast::Receiver<DhtNetworkEvent>) {
        if !self.task_handles.is_empty() {
            error!("ReplicationEngine::start() called while already running — ignoring");
            return;
        }
        info!("Starting replication engine");

        self.start_message_handler();
        self.start_neighbor_sync_loop();
        self.start_self_lookup_loop();
        // Audit #2 (responsible-chunk): periodic tick auditing peers for the
        // chunks they SHOULD store (responsibility + prior hint).
        self.start_audit_loop();
        // Audit #1 (storage-commitment) is gossip-triggered in the message
        // handler when a peer's commitment is ingested, not on a periodic tick.
        self.start_commitment_rotation_loop();
        self.start_retention_persist_loop();
        self.start_fetch_worker();
        self.start_verification_worker();
        self.start_bootstrap_sync(dht_events);
        self.start_fresh_write_drainer();
        self.start_possession_check_scheduler();
        // ADR-0004: deterministic first audit of commitments that backed a
        // payment (surfaced by the verifier cross-check).
        self.start_first_audit_drainer();
        // V2-623: periodic cumulative per-variant traffic accounting.
        self.start_traffic_summary_loop();
        // V2-884: read-only bootstrap state for cache/drain/connectivity triage.
        #[cfg(feature = "logging")]
        self.start_bootstrap_state_snapshot_loop();
        #[cfg(feature = "logging")]
        self.start_audit_responder_summary_loop();

        info!(
            "Replication engine started with {} background tasks",
            self.task_handles.len()
        );
    }

    /// Returns `true` if the node is still in the replication bootstrap phase.
    ///
    /// During bootstrap, audit challenges return `Bootstrapping` instead of
    /// digests, and neighbor sync responses carry `bootstrapping: true`.
    pub async fn is_bootstrapping(&self) -> bool {
        *self.is_bootstrapping.read().await
    }

    /// Wait until the replication bootstrap phase completes.
    ///
    /// Returns immediately if bootstrap has already completed. Useful for
    /// readiness probes, health checks, and test harnesses that need the
    /// node to be fully operational before proceeding.
    ///
    /// Returns `true` if bootstrap completed within the timeout, `false`
    /// if the timeout elapsed first.
    pub async fn wait_for_bootstrap_complete(&self, timeout: Duration) -> bool {
        // Register the notification future *before* checking the flag so that
        // a transition between the read and the await is not missed.
        let notified = self.bootstrap_complete_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        if !*self.is_bootstrapping.read().await {
            return true;
        }

        tokio::time::timeout(timeout, notified).await.is_ok()
    }

    /// Cancel all background tasks and wait for them to terminate.
    ///
    /// This must be awaited before dropping the engine when the caller needs
    /// the `Arc<ChunkStore>` references held by background tasks to be
    /// released (e.g. before reopening the same store).
    ///
    /// When this returns, no engine-spawned task still holds
    /// `Arc<ChunkStore>` or `Arc<PaidList>`, and no blocking storage operation
    /// (read or write, against either the chunk store or the paid-list LMDB
    /// environment) is still running.  Engine tasks race their work against
    /// the shutdown token; a dropped future may leave a `spawn_blocking`
    /// operation running detached, so this method additionally waits
    /// for both storage layers to go quiescent before returning.
    pub async fn shutdown(&mut self) {
        self.shutdown.cancel();
        for (i, mut handle) in self.task_handles.drain(..).enumerate() {
            match tokio::time::timeout(SHUTDOWN_TASK_DRAIN_TIMEOUT, &mut handle).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) if e.is_cancelled() => {}
                Ok(Err(e)) => warn!("Replication task {i} panicked during shutdown: {e}"),
                Err(_) => {
                    warn!(
                        "Replication task {i} did not stop within {}s, aborting",
                        SHUTDOWN_TASK_DRAIN_TIMEOUT.as_secs()
                    );
                    handle.abort();
                    // `abort` only requests cancellation. Await the handle so
                    // synchronous sections finish and the task drops every
                    // storage/P2P clone before we claim producer quiescence.
                    match handle.await {
                        Ok(()) => {}
                        Err(e) if e.is_cancelled() => {}
                        Err(e) => warn!("Replication task {i} panicked after abort: {e}"),
                    }
                }
            }
        }

        // Close the responder worker pools. Detached tasks still queued for a
        // worker take the `Err` arm of `acquire_owned()` and exit immediately
        // rather than waiting for a slot that will never free up — without
        // this, work admitted just before shutdown would queue behind the last
        // in-flight batch and hold the drain below open for its full duration.
        self.fresh_offer_worker_semaphore.close();
        self.paid_notify_worker_semaphore.close();
        self.fetch_responder_worker_semaphore.close();
        self.verification_responder_worker_semaphore.close();
        self.neighbor_sync_responder_worker_semaphore.close();

        // All producers have stopped, so close and drain their detached work.
        // A started storage operation must run to completion: dropping an async
        // waiter does not cancel `spawn_blocking`, and would let shutdown return
        // while a blocking storage operation is still running.
        //
        // Deliberately unbounded: every worker has to release its
        // `Arc<ChunkStore>` before the caller may reopen the store, whose lock
        // admits one process at a time, and a timeout here could return with one
        // still held.
        // What makes that safe is that every detached task is now guaranteed to
        // finish — the pools above are closed, stale work is shed at dequeue,
        // and the one genuinely unbounded await (payment verification) races
        // `self.shutdown` via `verify_payment_until_shutdown`.
        self.detached_task_tracker.close();
        self.detached_task_tracker.wait().await;

        // Every producer is gone, but a select! racing the shutdown token may
        // have dropped a future while it awaited a storage `spawn_blocking` op
        // (fetch `storage.put`, prune `storage.delete` /
        // `paid_list.remove_batch`, verification `paid_list.insert`).  The
        // detached blocking closure owns a cloned `Env`; wait for both
        // environments to go quiescent — bounded by one in-flight transaction
        // per op — so the caller may reopen them.
        self.storage.wait_idle().await;
        self.paid_list.wait_idle().await;
    }

    /// Trigger an early neighbor sync round.
    ///
    /// Useful after topology changes (new nodes joining, network heal after
    /// partition) when the caller wants replication to converge faster than
    /// the regular 10-20 minute cadence.
    pub fn trigger_neighbor_sync(&self) {
        self.sync_trigger.notify_one();
    }

    /// Execute fresh replication for a newly stored record, then schedule the
    /// delayed possession check for the responsible close-group peers
    /// (ADR-0003). The production PUT path schedules via the fresh-write
    /// drainer; this direct entry point schedules here so callers (and tests)
    /// that drive replication directly still get the possession check.
    pub async fn replicate_fresh(&self, key: &XorName, data: &[u8], proof_of_payment: &[u8]) {
        let peers = fresh::replicate_fresh(
            key,
            data,
            proof_of_payment,
            &self.p2p_node,
            &self.paid_list,
            &self.config,
            &self.send_semaphore,
        )
        .await;
        if !peers.is_empty() {
            let _ = self
                .possession_check_tx
                .send(possession::PossessionCheckEvent { key: *key, peers });
        }
    }

    // =======================================================================
    // Background task launchers
    // =======================================================================

    /// Spawn a task that drains the fresh-write channel and triggers
    /// replication for each newly-stored chunk.
    fn start_fresh_write_drainer(&mut self) {
        let Some(mut rx) = self.fresh_write_rx.take() else {
            return;
        };
        let p2p = Arc::clone(&self.p2p_node);
        let paid_list = Arc::clone(&self.paid_list);
        let config = Arc::clone(&self.config);
        let send_semaphore = Arc::clone(&self.send_semaphore);
        let possession_tx = self.possession_check_tx.clone();
        let shutdown = self.shutdown.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    event = rx.recv() => {
                        let Some(event) = event else { break };
                        let peers = fresh::replicate_fresh(
                            &event.key,
                            &event.data,
                            &event.payment_proof,
                            &p2p,
                            &paid_list,
                            &config,
                            &send_semaphore,
                        )
                        .await;
                        // Schedule the delayed possession check (ADR-0003) for
                        // the responsible close-group peers. A closed receiver
                        // (engine shutting down) is ignored.
                        if !peers.is_empty() {
                            let _ = possession_tx.send(possession::PossessionCheckEvent {
                                key: event.key,
                                peers,
                            });
                        }
                    }
                }
            }
            debug!("Fresh-write drainer shut down");
        });
        self.task_handles.push(handle);
    }

    /// Spawn the possession-check scheduler (ADR-0003).
    ///
    /// Drains scheduled possession-check events and, for each, waits a
    /// randomised 5-15 minute settle delay before probing every responsible
    /// peer for actual possession. A peer that fails to prove possession or does
    /// not answer is penalised at `AuditChallenge` severity.
    fn start_possession_check_scheduler(&mut self) {
        let Some(mut rx) = self.possession_check_rx.take() else {
            return;
        };
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let config = Arc::clone(&self.config);
        let sync_state = Arc::clone(&self.sync_state);
        let audit_challenge_coordinator = Arc::clone(&self.audit_challenge_coordinator);
        let shutdown = self.shutdown.clone();
        let detached_task_tracker = self.detached_task_tracker.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    event = rx.recv() => {
                        let Some(event) = event else { break };
                        // Spawn a per-chunk delayed check so the drain loop
                        // keeps pace with the write rate. Each check sleeps the
                        // randomised settle delay, then probes every peer.
                        let p2p = Arc::clone(&p2p);
                        let storage = Arc::clone(&storage);
                        let config = Arc::clone(&config);
                        let sync_state = Arc::clone(&sync_state);
                        let audit_challenge_coordinator = Arc::clone(&audit_challenge_coordinator);
                        let shutdown = shutdown.clone();
                        let delay_min = config.possession_check_delay_min;
                        let delay_max = config.possession_check_delay_max;
                        detached_task_tracker.spawn(async move {
                            let delay = possession::random_delay(delay_min, delay_max);
                            // Race shutdown against the whole settle-then-probe
                            // sequence, not just the sleep. Once a check starts it
                            // may park on the per-target audit coordinator, which
                            // has no deadline of its own: with the settle delay
                            // inside the branch BODY the select is already resolved,
                            // so those waiters would drain only at the probe timeout
                            // (roughly `queued / per-target-limit` probes deep) while
                            // `detached_task_tracker.wait()` — deliberately unbounded
                            // for the storage contract — held shutdown open.
                            //
                            // Dropping this future mid-probe is safe and is the same
                            // shape the neighbor-sync round uses: a parked coordinator
                            // acquire releases its counted reference via
                            // `ReferenceGuard`, and a dropped storage `spawn_blocking` is
                            // covered by the storage-quiescence wait in `shutdown`.
                            tokio::select! {
                                () = shutdown.cancelled() => {}
                                () = async {
                                    tokio::time::sleep(delay).await;
                                    possession::run_possession_check(
                                        event.key,
                                        event.peers,
                                        &p2p,
                                        &storage,
                                        &config,
                                        &sync_state,
                                        &audit_challenge_coordinator,
                                        &shutdown,
                                    )
                                    .await;
                                } => {}
                            }
                        });
                    }
                }
            }
            debug!("Possession-check scheduler shut down");
        });
        self.task_handles.push(handle);
    }

    /// ADR-0004: drain monetized pins surfaced by the verifier cross-check and
    /// run a **deterministic first audit** of each — the same `run_subtree_audit`
    /// as the gossip path, under the same per-peer cooldown and concurrency
    /// caps, but with the probability lottery BYPASSED (the lottery governs
    /// re-audits only). Deduped by pin via a bounded set so a pin gets one
    /// deterministic first audit; a peer minting fresh pins faster than the
    /// cooldown forfeits the older ones' coverage, never the newest's (the
    /// channel surfaces newest pins as they are monetized).
    #[allow(clippy::too_many_lines)]
    fn start_first_audit_drainer(&mut self) {
        let Some(mut rx) = self.monetized_pin_rx.take() else {
            return;
        };
        let gossip_audit = GossipAuditTrigger {
            p2p_node: Arc::clone(&self.p2p_node),
            config: Arc::clone(&self.config),
            recent_provers: Arc::clone(&self.recent_provers),
            sync_state: Arc::clone(&self.sync_state),
            cooldown: Arc::clone(&self.audit_on_gossip_cooldown),
            detached_task_tracker: self.detached_task_tracker.clone(),
            lottery_attempts: Arc::clone(&self.gossip_lottery_attempts),
        };
        let shutdown = self.shutdown.clone();
        let observability = Arc::clone(&self.first_audit_observability);
        let self_peer = *self.p2p_node.peer_id();

        let handle = tokio::spawn(async move {
            // ADR-0004 Amendment 2 (E'): the drainer-owned first-audit
            // scheduler. Payments only NOMINATE pins; the token bucket launches
            // them at a fixed per-node rate, and durable suppression is stamped
            // only at PROMOTION (after an authoritative post-jitter answerability
            // + cooldown check), so a cancelled reservation leaves nothing behind.
            let mut scheduler = FirstAuditScheduler::new(Instant::now(), self_peer);
            // Periodic retry tick so budget/cooldown-deferred pins get retried
            // even when no new nomination arrives. `Skip` collapses a backlog.
            let mut tick = tokio::time::interval(config::FIRST_AUDIT_RETRY_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut last_summary = Instant::now();
            loop {
                // The reservation's jitter deadline is a wake source: if a
                // reservation is outstanding, sleep until it is due; otherwise
                // a far-future deadline effectively disables that arm and only
                // shutdown/rx/tick wake the loop. Recreated each iteration so a
                // newly reserved (earlier) deadline is honoured next turn.
                let promotion_due = scheduler
                    .reserved_ready_at()
                    .unwrap_or_else(first_audit_far_future);
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    event = rx.recv() => match event {
                        Some(e) => {
                            observability.received.fetch_add(1, Ordering::Relaxed);
                            // Pre-overflow reservation opportunity: before an
                            // arrival may displace a DIFFERENT peer, let the
                            // queue launch — a successful reservation frees the
                            // slot without eviction. One reservation can be
                            // outstanding at a time, so this consumes at most
                            // one slot per jitter window; arrivals beyond it
                            // fall through to random displacement (ADR-0004
                            // Amendment 4).
                            if scheduler.would_displace(&e) {
                                open_first_audit_reservation(
                                    &mut scheduler,
                                    &gossip_audit.cooldown,
                                    &observability,
                                )
                                .await;
                            }
                            scheduler.enqueue(e, &observability);
                            // Drain a bounded burst so a flood cannot starve the
                            // launch phase.
                            let mut drained = 1usize;
                            while drained < config::FIRST_AUDIT_DRAIN_BATCH {
                                match rx.try_recv() {
                                    Ok(e) => {
                                        observability.received.fetch_add(1, Ordering::Relaxed);
                                        if scheduler.would_displace(&e) {
                                            open_first_audit_reservation(
                                                &mut scheduler,
                                                &gossip_audit.cooldown,
                                                &observability,
                                            )
                                            .await;
                                        }
                                        scheduler.enqueue(e, &observability);
                                        drained += 1;
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                        None => break,
                    },
                    _ = tick.tick() => {}
                    () = tokio::time::sleep_until(promotion_due.into()) => {}
                }

                // 1) Promote a due reservation. Resolved after EVERY wake (not
                //    only when the timer arm wins) so a continuously-ready `rx`
                //    cannot indefinitely delay a due promotion. The authoritative
                //    answerability + cooldown check-and-stamp happens here under
                //    the shared cooldown write lock, immediately before the send.
                if let Some(reservation) = scheduler.take_due_reservation(Instant::now()) {
                    let promoted = {
                        let mut cooldown = gossip_audit.cooldown.write().await;
                        scheduler.resolve(
                            reservation,
                            SystemTime::now(),
                            Instant::now(),
                            &mut cooldown,
                            &observability,
                        )
                    };
                    if let Some((event, inflight_slot)) = promoted {
                        debug!(
                            "First-audit scheduler: audit_trigger=first_monetized outcome=launched peer={} pin={} key_count={} inflight={}",
                            event.peer, hex::encode(event.pin), event.key_count,
                            observability.inflight.load(Ordering::Relaxed)
                        );
                        let trigger = gossip_audit.clone();
                        let audit_observability = Arc::clone(&observability);
                        // Track the launch so `shutdown()`'s detached drain
                        // covers it. This task outlives the drainer loop that
                        // spawned it — the loop breaks on the shutdown token
                        // while the audit is still awaiting its response — so a
                        // bare spawn would let an in-flight subtree audit keep
                        // running, and keep its `Arc<P2PNode>`, past the point
                        // `shutdown()` claims every engine task has stopped.
                        let tracker = trigger.detached_task_tracker.clone();
                        tracker.spawn(async move {
                            // The jitter already elapsed as the reservation's
                            // timer; the slot is held for the audit's duration
                            // and released on drop (panic-safe).
                            let inflight_slot = inflight_slot;
                            let started = Instant::now();
                            let credit = storage_commitment_audit::AuditCredit {
                                recent_provers: &trigger.recent_provers,
                            };
                            let result = storage_commitment_audit::run_subtree_audit(
                                &trigger.p2p_node,
                                &trigger.config,
                                &event.peer,
                                event.pin,
                                event.key_count,
                                Some(&credit),
                            )
                            .await;
                            let outcome = first_audit_terminal_outcome(&result);
                            match outcome {
                                FirstAuditTerminalOutcome::Passed => {
                                    audit_observability.passed.fetch_add(1, Ordering::Relaxed);
                                }
                                FirstAuditTerminalOutcome::Timeout => {
                                    audit_observability
                                        .timed_out
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                FirstAuditTerminalOutcome::Failed => {
                                    audit_observability.failed.fetch_add(1, Ordering::Relaxed);
                                }
                                FirstAuditTerminalOutcome::BootstrapClaim => {
                                    audit_observability
                                        .bootstrap_claims
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                FirstAuditTerminalOutcome::Idle => {
                                    audit_observability.idle.fetch_add(1, Ordering::Relaxed);
                                }
                                FirstAuditTerminalOutcome::InsufficientKeys => {
                                    audit_observability
                                        .insufficient_keys
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            drop(inflight_slot);
                            debug!(
                                "First-audit scheduler: audit_trigger=first_monetized outcome={} peer={} pin={} key_count={} elapsed_ms={} inflight={}",
                                outcome.as_str(),
                                event.peer, hex::encode(event.pin), event.key_count,
                                started.elapsed().as_millis(),
                                audit_observability.inflight.load(Ordering::Relaxed)
                            );
                            handle_subtree_audit_result(
                                &result,
                                &trigger.p2p_node,
                                &trigger.sync_state,
                                &trigger.recent_provers,
                                &trigger.config,
                            )
                            .await;
                        });
                    }
                }

                // 2) Open the single reservation from the pending queue if none
                //    is outstanding (read-only cooldown snapshot; the
                //    authoritative stamp is at promotion). Serializing
                //    reservations preserves per-launch lane alternation and keeps
                //    at most one jitter timer live.
                open_first_audit_reservation(
                    &mut scheduler,
                    &gossip_audit.cooldown,
                    &observability,
                )
                .await;

                if last_summary.elapsed() >= config::FIRST_AUDIT_SUMMARY_INTERVAL {
                    // Token-independent hygiene: collect entries that aged past
                    // the answerability horizon while the budget gate kept the
                    // reserve scan from running, so the summary below reports
                    // only live work.
                    let swept = scheduler.sweep_expired(SystemTime::now(), &observability);
                    if swept > 0 {
                        debug!(
                            "First-audit scheduler: audit_trigger=first_monetized outcome=expired_swept count={swept} pending={}",
                            scheduler.pending_len()
                        );
                    }
                    info!(
                        "First-audit scheduler summary: audit_trigger=first_monetized ingress_dropped={} received={} queued={} coalesced={} suppressed_lower={} duplicates={} capacity_evicted={} self_target_skipped={} cooldown_deferred_attempts={} rate_deferred_attempts={} window_deduped={} launched={} passed={} timeout={} failed={} bootstrap_claims={} idle={} insufficient_keys={} outside_answerability_window={} pending={} pending_cap={} reserved={} oldest_pending_quote_age_ms={} inflight={} tokens={}",
                        FIRST_AUDIT_INGRESS_DROPPED.load(Ordering::Relaxed),
                        observability.received.load(Ordering::Relaxed),
                        observability.queued.load(Ordering::Relaxed),
                        observability.coalesced.load(Ordering::Relaxed),
                        observability.suppressed_lower.load(Ordering::Relaxed),
                        observability.duplicates.load(Ordering::Relaxed),
                        observability.capacity_evicted.load(Ordering::Relaxed),
                        observability.self_target_skipped.load(Ordering::Relaxed),
                        observability.cooldown_deferred_attempts.load(Ordering::Relaxed),
                        observability.rate_deferred_attempts.load(Ordering::Relaxed),
                        observability.window_deduped.load(Ordering::Relaxed),
                        observability.launched.load(Ordering::Relaxed),
                        observability.passed.load(Ordering::Relaxed),
                        observability.timed_out.load(Ordering::Relaxed),
                        observability.failed.load(Ordering::Relaxed),
                        observability.bootstrap_claims.load(Ordering::Relaxed),
                        observability.idle.load(Ordering::Relaxed),
                        observability.insufficient_keys.load(Ordering::Relaxed),
                        observability.outside_answerability_window.load(Ordering::Relaxed),
                        scheduler.pending_len(),
                        FIRST_AUDIT_PENDING_CAP,
                        u8::from(scheduler.has_reservation()),
                        scheduler.oldest_pending_quote_age_ms(SystemTime::now()),
                        observability.inflight.load(Ordering::Relaxed),
                        scheduler.tokens(),
                    );
                    last_summary = Instant::now();
                }
            }
            debug!("First-audit drainer shut down");
        });
        self.task_handles.push(handle);
    }

    #[allow(clippy::too_many_lines)]
    fn start_message_handler(&mut self) {
        let mut p2p_events = self.p2p_node.subscribe_events();
        let mut dht_events = self.p2p_node.dht_manager().subscribe_events();
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let paid_list = Arc::clone(&self.paid_list);
        let payment_verifier = Arc::clone(&self.payment_verifier);
        let queues = Arc::clone(&self.queues);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let bootstrap_complete_notify = Arc::clone(&self.bootstrap_complete_notify);
        let sync_history = Arc::clone(&self.sync_history);
        let sync_cycle_epoch = Arc::clone(&self.sync_cycle_epoch);
        let repair_proofs = Arc::clone(&self.repair_proofs);
        let sync_trigger = Arc::clone(&self.sync_trigger);
        let my_commitment_state = Arc::clone(&self.commitment_state);
        let last_commitment_by_peer = Arc::clone(&self.last_commitment_by_peer);
        let ever_capable_peers = Arc::clone(&self.ever_capable_peers);
        let recent_provers = Arc::clone(&self.recent_provers);
        let sig_verify_attempts = Arc::clone(&self.sig_verify_attempts);
        let audit_on_gossip_cooldown = Arc::clone(&self.audit_on_gossip_cooldown);
        let gossip_lottery_attempts = Arc::clone(&self.gossip_lottery_attempts);
        let sync_state = Arc::clone(&self.sync_state);
        let audit_responder_semaphore = Arc::clone(&self.audit_responder_semaphore);
        let audit_responder_inflight = Arc::clone(&self.audit_responder_inflight);
        let audit_responder_metrics = Arc::clone(&self.audit_responder_metrics);
        let fetch_responder_worker_semaphore = Arc::clone(&self.fetch_responder_worker_semaphore);
        let fetch_responder_admission_semaphore =
            Arc::clone(&self.fetch_responder_admission_semaphore);
        let fetch_responder_inflight = Arc::clone(&self.fetch_responder_inflight);
        let verification_responder_worker_semaphore =
            Arc::clone(&self.verification_responder_worker_semaphore);
        let verification_responder_admission_semaphore =
            Arc::clone(&self.verification_responder_admission_semaphore);
        let verification_responder_inflight = Arc::clone(&self.verification_responder_inflight);
        let neighbor_sync_responder_worker_semaphore =
            Arc::clone(&self.neighbor_sync_responder_worker_semaphore);
        let neighbor_sync_responder_admission_semaphore =
            Arc::clone(&self.neighbor_sync_responder_admission_semaphore);
        let neighbor_sync_responder_inflight = Arc::clone(&self.neighbor_sync_responder_inflight);
        let fresh_offer_worker_semaphore = Arc::clone(&self.fresh_offer_worker_semaphore);
        let fresh_offer_admission_semaphore = Arc::clone(&self.fresh_offer_admission_semaphore);
        let fresh_offer_responder_inflight = Arc::clone(&self.fresh_offer_responder_inflight);
        let fresh_offer_in_flight = Arc::clone(&self.fresh_offer_in_flight);
        let paid_notify_worker_semaphore = Arc::clone(&self.paid_notify_worker_semaphore);
        let paid_notify_admission_semaphore = Arc::clone(&self.paid_notify_admission_semaphore);
        let paid_notify_responder_inflight = Arc::clone(&self.paid_notify_responder_inflight);
        let detached_task_tracker = self.detached_task_tracker.clone();
        let subtree_round1 = self.subtree_round1.clone();

        // ADR-0002 gossip-audit trigger: bundled state so an ingested *changed*
        // commitment can spawn a probabilistic, cooldown-gated subtree audit.
        let gossip_audit = GossipAuditTrigger {
            p2p_node: Arc::clone(&p2p),
            config: Arc::clone(&config),
            recent_provers: Arc::clone(&recent_provers),
            sync_state: Arc::clone(&sync_state),
            cooldown: Arc::clone(&audit_on_gossip_cooldown),
            detached_task_tracker: detached_task_tracker.clone(),
            lottery_attempts: Arc::clone(&gossip_lottery_attempts),
        };

        let handler_context = ReplicationMessageHandlerContext {
            p2p_node: Arc::clone(&p2p),
            storage,
            paid_list,
            payment_verifier,
            queues,
            config: Arc::clone(&config),
            is_bootstrapping,
            bootstrap_state,
            sync_history,
            sync_cycle_epoch,
            repair_proofs: Arc::clone(&repair_proofs),
            last_commitment_by_peer: Arc::clone(&last_commitment_by_peer),
            ever_capable_peers,
            sig_verify_attempts: Arc::clone(&sig_verify_attempts),
            my_commitment_state,
            gossip_audit,
            audit_responder_semaphore,
            audit_responder_inflight,
            audit_responder_metrics,
            subtree_round1,
            fetch_responder_worker_semaphore,
            fetch_responder_admission_semaphore,
            fetch_responder_inflight,
            verification_responder_worker_semaphore,
            verification_responder_admission_semaphore,
            verification_responder_inflight,
            neighbor_sync_responder_worker_semaphore,
            neighbor_sync_responder_admission_semaphore,
            neighbor_sync_responder_inflight,
            fresh_offer_worker_semaphore,
            fresh_offer_admission_semaphore,
            fresh_offer_responder_inflight,
            fresh_offer_in_flight,
            paid_notify_worker_semaphore,
            paid_notify_admission_semaphore,
            paid_notify_responder_inflight,
            shutdown: shutdown.clone(),
            detached_task_tracker,
        };

        let (replication_tx, mut replication_rx) =
            mpsc::channel::<InboundReplicationMessage>(INBOUND_REPLICATION_SERIAL_QUEUE_CAPACITY);
        let serial_context = handler_context.clone();
        let serial_shutdown = shutdown.clone();
        let serial_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = serial_shutdown.cancelled() => break,
                    inbound = replication_rx.recv() => {
                        let Some(inbound) = inbound else { break };
                        let source = inbound.source;
                        match handle_replication_message(
                            &source,
                            inbound.msg,
                            &serial_context,
                            inbound.received_at,
                            inbound.rr_message_id.as_deref(),
                        )
                        .await
                        {
                            Ok(()) => {}
                            Err(e) => {
                                debug!("Replication message from {source} error: {e}");
                            }
                        }
                    }
                }
            }
            debug!("Replication non-audit serial handler shut down");
        });
        self.task_handles.push(serial_handle);

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    event = p2p_events.recv() => {
                        let event = match event {
                            Ok(event) => event,
                            Err(error) => match handle_replication_event_recv_error(&error) {
                                ControlFlow::Continue(()) => continue,
                                ControlFlow::Break(()) => break,
                            },
                        };
                        let Some((source, payload, inbound_protocol, rr_message_id)) =
                            replication_payload_from_event(event)
                        else {
                            continue;
                        };
                        let received_at = Instant::now();
                        let msg = match ReplicationMessage::decode(&payload) {
                            Ok(msg) => msg,
                            Err(e) => {
                                debug!("Replication message from {source} decode error: {e}");
                                continue;
                            }
                        };
                        if !body_matches_protocol(&msg.body, inbound_protocol) {
                            debug!(
                                "Dropping replication body (variant {}) on protocol \
                                 {inbound_protocol}: wrong id for its family \
                                 (cross-version or misrouted)",
                                msg.body.variant_index()
                            );
                            continue;
                        }
                        if let Some(class) = audit_responder_class(&msg.body) {
                            handler_context
                                .audit_responder_metrics
                                .record_received(source, class);
                        }
                        let inbound = InboundReplicationMessage {
                            source,
                            msg,
                            rr_message_id,
                            received_at,
                        };
                        if matches!(
                            inbound.msg.body,
                            ReplicationMessageBody::AuditChallenge(_)
                                | ReplicationMessageBody::SubtreeAuditChallenge(_)
                                | ReplicationMessageBody::SubtreeSliceChallenge(_)
                        ) {
                            let source = inbound.source;
                            match handle_replication_message(
                                &source,
                                inbound.msg,
                                &handler_context,
                                inbound.received_at,
                                inbound.rr_message_id.as_deref(),
                            )
                            .await
                            {
                                Ok(()) => {}
                                Err(e) => {
                                    debug!("Replication message from {source} error: {e}");
                                }
                            }
                            continue;
                        }
                        if let Err(dropped) = try_enqueue_serial_message(&replication_tx, inbound) {
                            if dropped.audit_responder_class.is_some() {
                                handler_context
                                    .audit_responder_metrics
                                    .record_serial_queue_drop(dropped.source);
                            }
                            // Every serial-lane class has protocol recovery: syncs rerun,
                            // fetches retry, verification re-asks, and a dropped fresh
                            // offer is refilled by neighbor sync (the possession check
                            // penalises the absence but never re-offers). Responses are
                            // covered by their requester's deadline/retry path. Never run
                            // a bulk handler here: event receipt must remain non-blocking.
                            warn!(
                                message_class = dropped.message_class,
                                source = %dropped.source,
                                queue_depth = dropped.queue_depth,
                                reason = dropped.reason.as_str(),
                                "Replication serial-queue message dropped"
                            );
                        }
                    }
                    // Gap 4: Topology churn handling (Section 13).
                    //
                    // The DHT routing table emits KClosestPeersChanged when the
                    // K-closest peer set actually changes, which is the precise
                    // signal for triggering neighbor sync. This replaces the
                    // previous approach of checking every PeerConnected /
                    // PeerDisconnected event against the close group.
                    dht_event = dht_events.recv() => {
                        let dht_event = match dht_event {
                            Ok(event) => event,
                            Err(RecvError::Lagged(missed)) => {
                                // Under heavy churn the broadcast buffer can overflow
                                // and drop routing-table events — the moment
                                // convergence matters most. A dropped
                                // KClosestPeersChanged means its entrants were never
                                // queued and its departures were never pruned, so
                                // draining priority_order cannot recover either.
                                // Resync from ground truth instead: snapshot the
                                // current close-peer set, prune pending peers that
                                // left it during the lost window (retain_sync_peers,
                                // as the normal topology-change path does), and queue
                                // every member. Dedup (queue_priority_peers) and
                                // per-peer cooldown (select_next_sync_peer) drop peers
                                // already queued or recently synced, so only genuine
                                // entrants surface.
                                warn!(
                                    "Missed {missed} DHT routing events (broadcast lag); resynchronizing close-peer set for neighbor sync"
                                );
                                let self_id = *p2p.peer_id();
                                let neighbors = neighbor_sync::snapshot_close_neighbors(
                                    &p2p,
                                    &self_id,
                                    config.neighbor_sync_scope,
                                )
                                .await;
                                let neighbor_set =
                                    neighbors.iter().copied().collect::<HashSet<_>>();
                                let (requeued, sync_removals) = {
                                    let mut state = sync_state.write().await;
                                    let sync_removals =
                                        state.retain_sync_peers(&neighbor_set);
                                    let requeued = state.queue_priority_peers(neighbors);
                                    (requeued, sync_removals)
                                };
                                if sync_removals > 0 {
                                    debug!(
                                        "Resync after broadcast lag pruned {sync_removals} departed pending sync entries"
                                    );
                                }
                                if requeued > 0 {
                                    debug!(
                                        "Resync after broadcast lag queued {requeued} close peers for priority neighbor sync"
                                    );
                                    sync_trigger.notify_one();
                                }
                                continue;
                            }
                            Err(RecvError::Closed) => {
                                // A closed broadcast channel never yields again;
                                // continuing would spin the select! loop forever.
                                warn!(
                                    "DHT event stream closed on replication branch; stopping message handler"
                                );
                                break;
                            }
                        };
                        match dht_event {
                            DhtNetworkEvent::KClosestPeersChanged { old, new, .. } => {
                                let old_peers = old
                                    .iter()
                                    .take(config.neighbor_sync_scope)
                                    .copied()
                                    .collect::<HashSet<_>>();
                                let new_scoped = new
                                    .iter()
                                    .take(config.neighbor_sync_scope)
                                    .copied()
                                    .collect::<Vec<_>>();
                                let new_peers =
                                    new_scoped.iter().copied().collect::<HashSet<_>>();
                                let entrants = new_scoped
                                    .iter()
                                    .copied()
                                    .filter(|peer| !old_peers.contains(peer))
                                    .collect::<Vec<_>>();
                                let entrant_count = entrants.len();
                                let (priority_insertions, sync_removals) = {
                                    let mut state = sync_state.write().await;
                                    let sync_removals = state.retain_sync_peers(&new_peers);
                                    let priority_insertions = state.queue_priority_peers(entrants);
                                    (priority_insertions, sync_removals)
                                };
                                if priority_insertions > 0 {
                                    debug!(
                                        "K-closest peers changed, queued {priority_insertions}/{entrant_count} new close peers for priority neighbor sync and pruned {sync_removals} departed pending sync entries"
                                    );
                                } else {
                                    debug!(
                                        "K-closest peers changed, no additional close peers queued, pruned {sync_removals} departed pending sync entries, triggering early neighbor sync"
                                    );
                                }
                                sync_trigger.notify_one();
                            }
                            DhtNetworkEvent::PeerRemoved { peer_id } => {
                                sync_state.write().await.remove_peer(&peer_id);
                                repair_proofs.write().await.remove_peer(&peer_id);
                                update_bootstrap_after_peer_removed(
                                    &peer_id,
                                    &handler_context.bootstrap_state,
                                    &handler_context.queues,
                                    &handler_context.is_bootstrapping,
                                    &bootstrap_complete_notify,
                                )
                                .await;
                                // v12: drop the commitment bytes and the
                                // recent-prover credit so a churn / sybil
                                // attacker cannot leave behind one
                                // StorageCommitment per identity in
                                // `last_commitment_by_peer`. Also drop the
                                // sig-verify rate-limit timestamp.
                                last_commitment_by_peer.write().await.remove(&peer_id);
                                recent_provers.write().await.forget_peer(&peer_id);
                                sig_verify_attempts.write().await.remove(&peer_id);
                                // Same for the gossip-audit cooldown (ADR-0002)
                                // and the lottery-attempt window.
                                audit_on_gossip_cooldown.write().await.remove(&peer_id);
                                gossip_lottery_attempts.write().await.remove(&peer_id);
                                // The sticky `commitment_capable` flag is
                                // preserved orthogonally via
                                // `ever_capable_peers` — even after this
                                // removal, a re-joining peer continues to
                                // be treated as v12-capable rather than
                                // legacy (§3 shield).
                            }
                            _ => {}
                        }
                    }
                }
            }
            debug!("Replication message handler shut down");
        });
        self.task_handles.push(handle);
    }

    fn start_neighbor_sync_loop(&mut self) {
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let paid_list = Arc::clone(&self.paid_list);
        let queues = Arc::clone(&self.queues);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();
        let sync_state = Arc::clone(&self.sync_state);
        let sync_history = Arc::clone(&self.sync_history);
        let sync_cycle_epoch = Arc::clone(&self.sync_cycle_epoch);
        let repair_proofs = Arc::clone(&self.repair_proofs);
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let sync_trigger = Arc::clone(&self.sync_trigger);
        let commitment_state = Arc::clone(&self.commitment_state);
        let last_commitment_by_peer = Arc::clone(&self.last_commitment_by_peer);
        let ever_capable_peers = Arc::clone(&self.ever_capable_peers);
        let sig_verify_attempts = Arc::clone(&self.sig_verify_attempts);
        let audit_challenge_coordinator = Arc::clone(&self.audit_challenge_coordinator);
        let detached_task_tracker = self.detached_task_tracker.clone();
        // ADR-0002: a peer's commitment also arrives on the sync RESPONSE path
        // (we initiated, they piggybacked theirs). Carry a gossip-audit trigger
        // here too so a peer that only ever answers — never initiates sync —
        // is still audited; otherwise it could fully evade auditing.
        let gossip_audit = GossipAuditTrigger {
            p2p_node: Arc::clone(&p2p),
            config: Arc::clone(&config),
            recent_provers: Arc::clone(&self.recent_provers),
            sync_state: Arc::clone(&sync_state),
            cooldown: Arc::clone(&self.audit_on_gossip_cooldown),
            detached_task_tracker,
            lottery_attempts: Arc::clone(&self.gossip_lottery_attempts),
        };

        let handle = tokio::spawn(async move {
            loop {
                // Park for the periodic tick or an explicit trigger ONLY when no
                // priority (topology-change) peers are queued. `sync_trigger` is a
                // coalescing `Notify`, so a churn burst that queues many entrants
                // produces a single wakeup; parking after draining one batch would
                // leave the rest waiting up to a full periodic tick. `priority_order`
                // is the durable record of pending work, so drain it back-to-back —
                // each round removes the peers it selects (`select_next_sync_peer`),
                // so the drain terminates once the queue empties.
                if !sync_state.read().await.has_priority_peers() {
                    let interval = config.random_neighbor_sync_interval();
                    tokio::select! {
                        () = shutdown.cancelled() => break,
                        () = tokio::time::sleep(interval) => {}
                        () = sync_trigger.notified() => {
                            debug!("Neighbor sync triggered by topology change");
                        }
                    }
                }
                // Wrap the sync round in a select so shutdown cancels
                // in-progress network operations rather than waiting for
                // the full round to complete.
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = run_neighbor_sync_round(
                        &p2p,
                        &storage,
                        &paid_list,
                        &queues,
                        &config,
                        &sync_state,
                        &sync_history,
                        &sync_cycle_epoch,
                        &repair_proofs,
                        &is_bootstrapping,
                        &bootstrap_state,
                        &commitment_state,
                        &last_commitment_by_peer,
                        &ever_capable_peers,
                        &sig_verify_attempts,
                        &audit_challenge_coordinator,
                        &gossip_audit,
                    ) => {}
                }
            }
            debug!("Neighbor sync loop shut down");
        });
        self.task_handles.push(handle);
    }

    fn start_self_lookup_loop(&mut self) {
        let p2p = Arc::clone(&self.p2p_node);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();

        let handle = tokio::spawn(async move {
            loop {
                let interval = config.random_self_lookup_interval();
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(interval) => {
                        if let Err(e) = p2p.dht_manager().trigger_self_lookup().await {
                            debug!("Self-lookup failed: {e}");
                        }
                    }
                }
            }
            debug!("Self-lookup loop shut down");
        });
        self.task_handles.push(handle);
    }

    /// Periodic responsible-chunk audit loop (audit #2): every
    /// [`ReplicationConfig::random_audit_tick_interval`] (~10-20 min), audit one
    /// eligible close peer for the chunks it *should* be storing (by
    /// responsibility and prior repair hint), independent of the gossip-triggered
    /// storage-commitment audit. Waits for bootstrap to drain, then runs one tick
    /// immediately and periodically thereafter.
    fn start_audit_loop(&mut self) {
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();
        let sync_history = Arc::clone(&self.sync_history);
        let sync_cycle_epoch = Arc::clone(&self.sync_cycle_epoch);
        let repair_proofs = Arc::clone(&self.repair_proofs);
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let sync_state = Arc::clone(&self.sync_state);
        let audit_challenge_coordinator = Arc::clone(&self.audit_challenge_coordinator);

        let handle = tokio::spawn(async move {
            // Invariant 19: wait for bootstrap to drain before starting audits.
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => return,
                    () = tokio::time::sleep(
                        std::time::Duration::from_secs(BOOTSTRAP_DRAIN_CHECK_SECS)
                    ) => {
                        if bootstrap_state.read().await.is_drained() {
                            break;
                        }
                    }
                }
            }

            // Run one audit tick immediately after bootstrap drain.
            {
                let bootstrapping = *is_bootstrapping.read().await;
                let result = {
                    let history = sync_history.read().await;
                    let current_sync_epoch = *sync_cycle_epoch.read().await;
                    audit::audit_tick_with_repair_proofs(
                        &p2p,
                        &storage,
                        &config,
                        &history,
                        &repair_proofs,
                        &audit_challenge_coordinator,
                        current_sync_epoch,
                        bootstrapping,
                    )
                    .await
                };
                handle_audit_result(&result, &p2p, &sync_state, &config).await;
            }

            // Then run periodically.
            loop {
                let interval = config.random_audit_tick_interval();
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(interval) => {
                        let bootstrapping = *is_bootstrapping.read().await;
                        let result = {
                            let history = sync_history.read().await;
                            let current_sync_epoch = *sync_cycle_epoch.read().await;
                            audit::audit_tick_with_repair_proofs(
                                &p2p,
                                &storage,
                                &config,
                                &history,
                                &repair_proofs,
                                &audit_challenge_coordinator,
                                current_sync_epoch,
                                bootstrapping,
                            )
                            .await
                        };
                        handle_audit_result(&result, &p2p, &sync_state, &config).await;
                    }
                }
            }
            debug!("Audit loop shut down");
        });
        self.task_handles.push(handle);
    }

    /// Periodically rebuild + sign + rotate the responder's storage
    /// commitment.
    ///
    /// Phase 3 of the v12 storage-bound audit. Once per
    /// [`COMMITMENT_ROTATION_INTERVAL_SECS`], the responder reads the
    /// current key set, builds a Merkle tree (for content-addressed
    /// chunks `bytes_hash == key`, so no chunk re-read is needed), signs
    /// the root with the node's `MlDsaSecretKey`, and rotates the result
    /// into `commitment_state`. Old `previous` slot is dropped by the
    /// rotate (per `ResponderCommitmentState::rotate`).
    ///
    /// Skips if the key set is empty (no commitment to make) — the
    /// auditor side falls back to the legacy plain-digest path for
    /// peers that have never gossiped a commitment.
    fn start_commitment_rotation_loop(&mut self) {
        let storage = Arc::clone(&self.storage);
        let identity = Arc::clone(&self.identity);
        let commitment_state = Arc::clone(&self.commitment_state);
        let shutdown = self.shutdown.clone();
        let p2p = Arc::clone(&self.p2p_node);
        let config = Arc::clone(&self.config);
        let sync_trigger = Arc::clone(&self.sync_trigger);
        let recent_provers = Arc::clone(&self.recent_provers);

        let handle = tokio::spawn(async move {
            // Build the first commitment immediately on startup so a
            // restarted node can answer commitment-bound audits right
            // away — otherwise current() stays None for a full rotation
            // interval and audits silently fall back to legacy.
            //
            // After the first build, trigger an immediate neighbor-sync
            // round so the new commitment gossips out within seconds.
            // Without this, after a restart remote auditors keep pinning
            // the pre-restart (rotated-away) hash until their normal
            // sync cadence elapses — up to 1 h in the worst case,
            // during which time commitment-bound audits hit "unknown
            // commitment hash" -> Idle no-ops.
            // ML-DSA signatures are randomized so we cannot reproduce
            // the pre-restart hash; the only honest path to recovery
            // is fast re-gossip.
            // ADR-0004 A1: retention was reloaded in `new()` (before any task
            // spawned), so this initial rebuild no-ops when the key set is
            // unchanged — preserving the reloaded current pin; otherwise the
            // reloaded roots stay answerable as retained slots until their gossip
            // TTL lapses. Persistence is handled by the retention-persist loop.
            if let Err(e) =
                rebuild_and_rotate_commitment(&storage, &identity, &commitment_state, &p2p, &config)
                    .await
            {
                warn!("Initial commitment build failed: {e}");
            } else {
                sync_trigger.notify_one();
            }
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(
                        std::time::Duration::from_secs(COMMITMENT_ROTATION_INTERVAL_SECS)
                    ) => {
                        if let Err(e) = rebuild_and_rotate_commitment(
                            &storage,
                            &identity,
                            &commitment_state,
                            &p2p,
                            &config,
                        ).await {
                            warn!("Commitment rotation failed: {e}");
                        }
                        // Piggyback a sweep of expired recent_provers
                        // entries on the rotation tick (same cadence,
                        // 1 h). is_credited_holder already honours the
                        // TTL on read, but the sweep reclaims memory
                        // for entries we'll never re-read.
                        let dropped = recent_provers.write().await.sweep_expired(
                            std::time::Instant::now()
                        );
                        if dropped > 0 {
                            debug!("recent_provers: swept {dropped} expired entries");
                        }
                    }
                }
            }
            debug!("Commitment rotation loop shut down");
        });
        self.task_handles.push(handle);
    }

    /// ADR-0004 A1: periodically flush the responder retention snapshot to disk
    /// (write-on-change) so answerability — including gossip-stamp refreshes and
    /// rotations — survives a restart. Flushes once immediately, then every
    /// `RETENTION_PERSIST_INTERVAL_SECS`, and once more on shutdown.
    fn start_retention_persist_loop(&mut self) {
        let commitment_state = Arc::clone(&self.commitment_state);
        let retention_path = self.retention_path.clone();
        let shutdown = self.shutdown.clone();
        let handle = tokio::spawn(async move {
            let mut last: Option<Vec<u8>> = None;
            persist_retention_if_changed(&commitment_state, &retention_path, &mut last).await;
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => {
                        persist_retention_if_changed(&commitment_state, &retention_path, &mut last)
                            .await;
                        break;
                    }
                    () = tokio::time::sleep(std::time::Duration::from_secs(
                        RETENTION_PERSIST_INTERVAL_SECS,
                    )) => {
                        persist_retention_if_changed(&commitment_state, &retention_path, &mut last)
                            .await;
                    }
                }
            }
            debug!("Commitment retention persist loop shut down");
        });
        self.task_handles.push(handle);
    }

    /// Periodically emit the cumulative replication traffic summaries: the
    /// per-variant line (V2-623) and the per-peer top-10 served-bytes line
    /// (V2-684). Both read process-global counter tables maintained by the
    /// encode/decode and serve choke points in [`protocol`]; needs no engine
    /// state.
    fn start_traffic_summary_loop(&mut self) {
        let shutdown = self.shutdown.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(std::time::Duration::from_secs(
                        TRAFFIC_SUMMARY_INTERVAL_SECS,
                    )) => {
                        protocol::log_traffic_summary();
                        protocol::log_served_peers_summary();
                        protocol::log_audit_outcome_summary();
                        audit_metrics::log_responder_admission_summary();
                    }
                }
            }
            debug!("Replication traffic summary loop shut down");
        });
        self.task_handles.push(handle);
    }

    /// Periodically expose the state that gates bootstrap completion and prune
    /// admission. The state counts are copied before reading `is_bootstrapping`
    /// so this diagnostic path never nests async locks.
    #[cfg(feature = "logging")]
    fn start_bootstrap_state_snapshot_loop(&mut self) {
        let shutdown = self.shutdown.clone();
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let started_at = Instant::now();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(Duration::from_secs(
                        BOOTSTRAP_STATE_SNAPSHOT_INTERVAL_SECS,
                    )) => {
                        let (
                            drained,
                            pending_peer_requests,
                            pending_keys,
                            capacity_rejected_sources,
                        ) = {
                            let state = bootstrap_state.read().await;
                            (
                                state.drained,
                                state.pending_peer_requests,
                                state.pending_keys.len(),
                                state.capacity_rejected_sources.len(),
                            )
                        };
                        let bootstrapping = *is_bootstrapping.read().await;
                        let snapshot_state = if drained && !bootstrapping {
                            "healthy"
                        } else if drained {
                            "drained_waiting_for_bootstrap_flag"
                        } else {
                            "pending"
                        };
                        info!(
                            drained,
                            pending_peer_requests,
                            pending_keys,
                            capacity_rejected_sources,
                            is_bootstrapping = bootstrapping,
                            snapshot_state,
                            uptime_secs = started_at.elapsed().as_secs(),
                            "Replication bootstrap state snapshot"
                        );
                        if drained && !bootstrapping {
                            info!(
                                "Replication bootstrap diagnostics reached healthy state; stopping periodic snapshots"
                            );
                            break;
                        }
                    }
                }
            }
            debug!("Bootstrap state snapshot loop shut down");
        });
        self.task_handles.push(handle);
    }

    /// Periodically rank remote peers using the shared audit responder pool and
    /// report handler-only versus end-to-end latency. Windowed values make a
    /// burst visible even after a long-running node has accumulated traffic.
    #[cfg(feature = "logging")]
    fn start_audit_responder_summary_loop(&mut self) {
        let shutdown = self.shutdown.clone();
        let metrics = Arc::clone(&self.audit_responder_metrics);
        let semaphore = Arc::clone(&self.audit_responder_semaphore);
        let handle = tokio::spawn(async move {
            let mut window_started = Instant::now();
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => {
                        log_audit_responder_summary(
                            &metrics,
                            &semaphore,
                            window_started.elapsed(),
                        );
                        break;
                    }
                    () = tokio::time::sleep(config::AUDIT_RESPONDER_SUMMARY_INTERVAL) => {
                        log_audit_responder_summary(
                            &metrics,
                            &semaphore,
                            window_started.elapsed(),
                        );
                        window_started = Instant::now();
                    }
                }
            }
            debug!("Audit responder summary loop shut down");
        });
        self.task_handles.push(handle);
    }

    #[allow(clippy::too_many_lines, clippy::option_if_let_else)]
    fn start_fetch_worker(&mut self) {
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let queues = Arc::clone(&self.queues);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let bootstrap_complete_notify = Arc::clone(&self.bootstrap_complete_notify);
        let detached_task_tracker = self.detached_task_tracker.clone();
        let concurrency = max_parallel_fetch();

        info!("Fetch worker concurrency set to {concurrency} (hardware threads)");

        let handle = tokio::spawn(async move {
            // Each in-flight future yields (key, Option<FetchOutcome>) so we
            // always recover the key — even if the inner task panics.
            let mut in_flight = FuturesUnordered::<FetchFuture>::new();

            loop {
                // Fill up to `concurrency` slots from the queue.
                {
                    let mut q = queues.write().await;
                    while in_flight.len() < concurrency {
                        let Some(candidate) = q.dequeue_fetch() else {
                            break;
                        };
                        let fetch_key = candidate.key;
                        let Some(&source) = candidate.sources.first() else {
                            warn!(
                                "Fetch candidate {} has no sources; requeueing for verification",
                                hex::encode(fetch_key)
                            );
                            let _ = q.requeue_candidate_for_verification(
                                candidate,
                                config.verification_request_timeout,
                            );
                            continue;
                        };
                        q.start_dequeued_fetch(candidate, source);

                        let p2p = Arc::clone(&p2p);
                        let storage = Arc::clone(&storage);
                        let config = Arc::clone(&config);
                        let token = shutdown.clone();
                        let tracker = detached_task_tracker.clone();
                        in_flight.push(Box::pin(async move {
                            // Tracked so shutdown() still awaits the task if
                            // this awaiter is dropped (e.g. the worker is
                            // aborted): it holds Arc<ChunkStore> and must
                            // not outlive the engine.
                            let handle = tracker.spawn(async move {
                                // Cancel-aware: abort when the engine shuts down.
                                tokio::select! {
                                    () = token.cancelled() => FetchOutcome {
                                        key: fetch_key,
                                        result: FetchResult::SourceFailed,
                                    },
                                    outcome = execute_single_fetch(
                                        p2p, storage, config, fetch_key, source,
                                    ) => outcome,
                                }
                            });
                            match handle.await {
                                Ok(outcome) => (outcome.key, Some(outcome)),
                                Err(e) => {
                                    error!(
                                        "Fetch task for {} panicked: {e}",
                                        hex::encode(fetch_key)
                                    );
                                    (fetch_key, None)
                                }
                            }
                        }));
                    }
                } // release queues write lock

                if in_flight.is_empty() {
                    // No work — wait for new items or shutdown.
                    tokio::select! {
                        () = shutdown.cancelled() => break,
                        () = tokio::time::sleep(
                            std::time::Duration::from_millis(FETCH_WORKER_POLL_MS)
                        ) => continue,
                    }
                }

                // Wait for the next fetch to complete and process the result.
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    Some((key, maybe_outcome)) = in_flight.next() => {
                        let mut q = queues.write().await;
                        let terminal = if let Some(outcome) = maybe_outcome {
                            match apply_fetch_result(
                                &mut q,
                                &key,
                                &outcome.result,
                                config.verification_request_timeout,
                            ) {
                                FetchFollowUp::Terminal => true,
                                FetchFollowUp::RequeuedForVerification => false,
                                FetchFollowUp::RetryFrom(next_peer) => {
                                    // Spawn a new fetch task for the next source.
                                    let p2p = Arc::clone(&p2p);
                                    let storage = Arc::clone(&storage);
                                    let config = Arc::clone(&config);
                                    let token = shutdown.clone();
                                    let tracker = detached_task_tracker.clone();
                                    let fetch_key = key;
                                    in_flight.push(Box::pin(async move {
                                        // Tracked for the same reason as the
                                        // initial fetch spawn above.
                                        let handle = tracker.spawn(async move {
                                            tokio::select! {
                                                () = token.cancelled() => FetchOutcome {
                                                    key: fetch_key,
                                                    result: FetchResult::SourceFailed,
                                                },
                                                outcome = execute_single_fetch(
                                                    p2p, storage, config, fetch_key, next_peer,
                                                ) => outcome,
                                            }
                                        });
                                        match handle.await {
                                            Ok(outcome) => (outcome.key, Some(outcome)),
                                            Err(e) => {
                                                error!(
                                                    "Fetch task for {} panicked: {e}",
                                                    hex::encode(fetch_key)
                                                );
                                                (fetch_key, None)
                                            }
                                        }
                                    }));
                                    false
                                }
                            }
                        } else {
                            // Task panicked — retry verification when this was
                            // a verified repair, otherwise reclaim the slot.
                            !q.requeue_fetch_for_verification(
                                &key,
                                config.verification_request_timeout,
                            )
                        };

                        // Shrink bootstrap pending set on terminal exit.
                        if terminal {
                            drop(q); // release queues lock before acquiring bootstrap_state
                            if !bootstrap_state.read().await.is_drained() {
                                bootstrap_state.write().await.remove_key(&key);
                                let q = queues.read().await;
                                if bootstrap::check_bootstrap_drained(
                                    &bootstrap_state,
                                    &q,
                                )
                                .await
                                {
                                    complete_bootstrap(
                                        &is_bootstrapping,
                                        &bootstrap_complete_notify,
                                    ).await;
                                }
                            }
                        }
                    }
                }
            }

            // Cancel and drain remaining in-flight fetches on shutdown.
            // The CancellationToken is already cancelled by this point, so
            // spawned tasks will see cancellation via their select! branches.
            while in_flight.next().await.is_some() {}
            debug!("Fetch worker shut down");
        });
        self.task_handles.push(handle);
    }

    fn start_verification_worker(&mut self) {
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let queues = Arc::clone(&self.queues);
        let paid_list = Arc::clone(&self.paid_list);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let bootstrap_complete_notify = Arc::clone(&self.bootstrap_complete_notify);
        let last_commitment_by_peer = Arc::clone(&self.last_commitment_by_peer);
        let ever_capable_peers = Arc::clone(&self.ever_capable_peers);
        let recent_provers = Arc::clone(&self.recent_provers);

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    () = tokio::time::sleep(
                        std::time::Duration::from_millis(VERIFICATION_WORKER_POLL_MS)
                    ) => {
                        let ctx = VerificationCycleContext {
                            p2p_node: &p2p,
                            paid_list: &paid_list,
                            storage: &storage,
                            queues: &queues,
                            config: &config,
                            bootstrap_state: &bootstrap_state,
                            is_bootstrapping: &is_bootstrapping,
                            bootstrap_complete_notify: &bootstrap_complete_notify,
                            last_commitment_by_peer: &last_commitment_by_peer,
                            ever_capable_peers: &ever_capable_peers,
                            recent_provers: &recent_provers,
                        };
                        run_verification_cycle(ctx).await;
                    }
                }
            }
            debug!("Verification worker shut down");
        });
        self.task_handles.push(handle);
    }

    /// Gap 3: Run a one-shot bootstrap sync on startup.
    ///
    /// Waits for saorsa-core to emit `DhtNetworkEvent::BootstrapComplete`
    /// (indicating the routing table is populated) before snapshotting
    /// close neighbors. Falls back after a timeout so bootstrap nodes
    /// (which have no peers and therefore never receive the event) still
    /// proceed.
    ///
    /// After the gate, finds close neighbors, syncs with each in
    /// round-robin batches, admits returned hints into the verification
    /// pipeline, and tracks discovered keys for bootstrap drain detection.
    #[allow(clippy::too_many_lines)]
    fn start_bootstrap_sync(
        &mut self,
        dht_events: tokio::sync::broadcast::Receiver<DhtNetworkEvent>,
    ) {
        let p2p = Arc::clone(&self.p2p_node);
        let storage = Arc::clone(&self.storage);
        let paid_list = Arc::clone(&self.paid_list);
        let queues = Arc::clone(&self.queues);
        let config = Arc::clone(&self.config);
        let shutdown = self.shutdown.clone();
        let is_bootstrapping = Arc::clone(&self.is_bootstrapping);
        let bootstrap_state = Arc::clone(&self.bootstrap_state);
        let bootstrap_complete_notify = Arc::clone(&self.bootstrap_complete_notify);
        let sync_cycle_epoch = Arc::clone(&self.sync_cycle_epoch);
        let repair_proofs = Arc::clone(&self.repair_proofs);
        let my_commitment_state = Arc::clone(&self.commitment_state);
        let last_commitment_by_peer = Arc::clone(&self.last_commitment_by_peer);
        let ever_capable_peers = Arc::clone(&self.ever_capable_peers);
        let sig_verify_attempts = Arc::clone(&self.sig_verify_attempts);

        let handle = tokio::spawn(async move {
            // Wait for DHT bootstrap to complete before snapshotting
            // neighbors. The routing table is empty until saorsa-core
            // finishes its FIND_NODE rounds and bucket refreshes.
            let gate = bootstrap::wait_for_bootstrap_complete(
                dht_events,
                config.bootstrap_complete_timeout_secs,
                &shutdown,
            )
            .await;

            if gate == bootstrap::BootstrapGateResult::Shutdown {
                return;
            }

            let self_id = *p2p.peer_id();
            let neighbors =
                neighbor_sync::snapshot_close_neighbors(&p2p, &self_id, config.neighbor_sync_scope)
                    .await;

            if neighbors.is_empty() {
                info!("Bootstrap sync: no close neighbors found, marking drained");
                bootstrap::mark_bootstrap_drained(&bootstrap_state).await;
                complete_bootstrap(&is_bootstrapping, &bootstrap_complete_notify).await;
                return;
            }

            let neighbor_count = neighbors.len();
            info!("Bootstrap sync: syncing with {neighbor_count} close neighbors");

            // Process neighbors in batches of NEIGHBOR_SYNC_PEER_COUNT.
            for batch in neighbors.chunks(config.neighbor_sync_peer_count) {
                if shutdown.is_cancelled() {
                    break;
                }

                let mut hints_by_peer = neighbor_sync::build_sync_hints_for_peers(
                    batch,
                    &storage,
                    &paid_list,
                    &p2p,
                    config.close_group_size,
                    config.paid_list_close_group_size,
                )
                .await;

                // Keep the batch outstanding until every response has been
                // admitted and bootstrap accounting is updated. The verification
                // worker uses this counter as a batch barrier, so it cannot race
                // the source aggregation below.
                bootstrap::increment_pending_requests(&bootstrap_state, batch.len()).await;
                let bootstrapping = *is_bootstrapping.read().await;

                let sync_futures = batch.iter().map(|peer| {
                    let peer = *peer;
                    let hints = hints_by_peer.remove(&peer).unwrap_or_default();
                    // Atomically snapshot + mark-gossiped for each emitted
                    // bootstrap request so we remain answerable for it.
                    let commitment = my_commitment_state
                        .current_for_gossip()
                        .map(|binding| binding.commitment().clone());
                    let p2p = &p2p;
                    let config = &config;
                    async move {
                        let outcome = neighbor_sync::sync_with_peer_with_hints(
                            &peer,
                            p2p,
                            config,
                            bootstrapping,
                            hints,
                            commitment,
                        )
                        .await;
                        (peer, outcome)
                    }
                });
                let completed = join_all(sync_futures).await;

                // Process response metadata before exposing any of this batch's
                // hints to verification.
                for (peer, outcome) in &completed {
                    if let Some(outcome) = outcome {
                        // Ingest the peer's piggybacked commitment from the
                        // response (same verification as the request path).
                        // Bootstrap is the FIRST gossip we receive from most
                        // peers, so this populates last_commitment_by_peer.
                        //
                        // We intentionally do NOT trigger a gossip-audit here:
                        // during bootstrap this node may itself still be
                        // bootstrapping (audits are gated on that), and the
                        // close-group/RT view is not yet stable. The peer is
                        // audited on the first STEADY-STATE neighbor-sync round
                        // after bootstrap drains (request + response paths both
                        // trigger), which is within one sync cycle — so caching
                        // the commitment here is sufficient and there is no
                        // coverage gap (ADR-0002).
                        ingest_peer_commitment(
                            peer,
                            outcome.response.commitment.as_ref(),
                            &p2p,
                            &last_commitment_by_peer,
                            &ever_capable_peers,
                            &sig_verify_attempts,
                        )
                        .await; // sig_verify_attempts in scope from line ~1080

                        if !outcome.response.bootstrapping {
                            record_sent_replica_hints(
                                peer,
                                &outcome.sent_replica_hints,
                                &repair_proofs,
                                &sync_cycle_epoch,
                            )
                            .await;
                        }
                    }
                }

                let pending_keys: HashSet<XorName> = {
                    let q = queues.read().await;
                    q.pending_keys().into_iter().collect()
                };
                let admission_futures = completed.iter().map(|(_, outcome)| async {
                    match outcome {
                        Some(outcome) if !outcome.response.bootstrapping => Some(
                            admission::admit_hints(
                                &self_id,
                                &outcome.response.replica_hints,
                                &outcome.response.paid_hints,
                                &p2p,
                                &config,
                                &storage,
                                &paid_list,
                                &pending_keys,
                            )
                            .await,
                        ),
                        _ => None,
                    }
                });
                let admitted = join_all(admission_futures).await;

                // Queue every peer's admitted hints under one write lock. Once
                // released, source-count ordering sees the complete batch.
                let (batch_outcomes, batch_discovered) = {
                    let mut q = queues.write().await;
                    let outcomes = completed
                        .iter()
                        .zip(admitted)
                        .filter_map(|((peer, _), admitted)| {
                            admitted.map(|admitted| {
                                (
                                    *peer,
                                    queue_admitted_hints(peer, admitted, &storage, &mut q),
                                )
                            })
                        })
                        .collect::<Vec<_>>();
                    let live_discovered = outcomes
                        .iter()
                        .flat_map(|(_, outcome)| outcome.discovered.iter().copied())
                        .filter(|key| q.contains_key(key))
                        .collect::<HashSet<_>>();
                    (outcomes, live_discovered)
                };

                publish_bootstrap_admission_outcomes(
                    &bootstrap_state,
                    &batch_outcomes,
                    &batch_discovered,
                )
                .await;

                bootstrap::decrement_pending_requests(&bootstrap_state, batch.len()).await;
            }

            // Check drain condition.
            {
                let q = queues.read().await;
                if bootstrap::check_bootstrap_drained(&bootstrap_state, &q).await {
                    complete_bootstrap(&is_bootstrapping, &bootstrap_complete_notify).await;
                }
            }

            info!("Bootstrap sync completed");
        });
        self.task_handles.push(handle);
    }
}

// ===========================================================================
// Free functions for background tasks
// ===========================================================================

#[cfg(feature = "logging")]
fn log_audit_responder_summary(
    metrics: &AuditResponderMetrics,
    semaphore: &Semaphore,
    window: Duration,
) {
    let snapshot = metrics.take_snapshot();
    if snapshot.origins.is_empty() {
        return;
    }

    let total = snapshot.total;
    let [digest_received, subtree_received, byte_received, commitment_pin_received] =
        total.received_by_class;
    let global_inflight =
        MAX_CONCURRENT_AUDIT_RESPONSES.saturating_sub(semaphore.available_permits());
    info!(
        target: "ant_node::replication::audit_responder",
        window_ms = window.as_millis(),
        source_count = snapshot.origins.len(),
        received = total.received(),
        digest_received,
        subtree_received,
        byte_received,
        commitment_pin_received,
        admitted = total.admitted,
        global_pool_drops = total.global_pool_drops,
        per_peer_cap_drops = total.per_peer_cap_drops,
        serial_queue_drops = total.serial_queue_drops,
        completed = total.completed,
        send_failures = total.send_failures,
        processing_avg_ms = total.processing_avg_ms(),
        processing_max_ms = total.processing_max_ms,
        total_avg_ms = total.total_avg_ms(),
        total_max_ms = total.total_max_ms,
        global_inflight,
        global_limit = MAX_CONCURRENT_AUDIT_RESPONSES,
        peak_global_inflight = total.peak_global_inflight,
        "Audit responder summary"
    );

    for (index, origin) in snapshot
        .origins
        .iter()
        .take(config::AUDIT_RESPONDER_TOP_ORIGINS)
        .enumerate()
    {
        let Some(source) = origin.source else {
            continue;
        };
        let [digest_received, subtree_received, byte_received, commitment_pin_received] =
            origin.received_by_class;
        info!(
            target: "ant_node::replication::audit_responder",
            rank = index + 1,
            source = %source,
            received = origin.received(),
            digest_received,
            subtree_received,
            byte_received,
            commitment_pin_received,
            admitted = origin.admitted,
            global_pool_drops = origin.global_pool_drops,
            per_peer_cap_drops = origin.per_peer_cap_drops,
            serial_queue_drops = origin.serial_queue_drops,
            completed = origin.completed,
            send_failures = origin.send_failures,
            processing_avg_ms = origin.processing_avg_ms(),
            processing_max_ms = origin.processing_max_ms,
            total_avg_ms = origin.total_avg_ms(),
            total_max_ms = origin.total_max_ms,
            peak_global_inflight = origin.peak_global_inflight,
            peak_peer_inflight = origin.peak_peer_inflight,
            "Audit responder top origin"
        );
    }
}

/// Which ceiling rejected an audit-responder admission attempt.
///
/// Stable, machine-readable so a production log-scrape can bucket drops by
/// cause. A 24 h node log collapsed 117 dropped responsible replies into a
/// single opaque "capacity reached" line; this splits the two distinct causes
/// so the next such investigation can tell a global-pool exhaustion (the whole
/// node is saturated) from a per-peer cap hit (one source is self-throttling)
/// without re-instrumenting.
///
/// This branch runs a SINGLE shared audit-responder pool for all challenge
/// kinds (responsible / subtree / byte), so there is no separate slow/fast
/// pool to distinguish here — the `kind=` log field already separates the
/// responsible (fast-path) challenge from the heavier subtree/byte ones. If a
/// dedicated slow pool is later split out, add its variants here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponderRejectReason {
    /// The global [`MAX_CONCURRENT_AUDIT_RESPONSES`] semaphore had no permit
    /// free; the per-peer cap was not the binding constraint.
    GlobalPoolFull,
    /// `source` already held its [`MAX_AUDIT_RESPONSES_PER_PEER`] in-flight
    /// share, so the global permit was never attempted.
    PerPeerCapFull,
}

impl ResponderRejectReason {
    /// Stable token emitted as `reason=<token>` in drop logs. Keep these values
    /// frozen — production log tooling greps for them.
    fn as_str(self) -> &'static str {
        match self {
            Self::GlobalPoolFull => "global_pool_full",
            Self::PerPeerCapFull => "per_peer_cap_full",
        }
    }
}

impl From<ResponderRejectReason> for AuditResponderDropReason {
    fn from(reason: ResponderRejectReason) -> Self {
        match reason {
            ResponderRejectReason::GlobalPoolFull => Self::GlobalPoolFull,
            ResponderRejectReason::PerPeerCapFull => Self::PerPeerCapFull,
        }
    }
}

impl From<ResponderRejectReason> for ResponderAdmissionCeiling {
    fn from(reason: ResponderRejectReason) -> Self {
        match reason {
            ResponderRejectReason::GlobalPoolFull => Self::GlobalPool,
            ResponderRejectReason::PerPeerCapFull => Self::PerPeerShare,
        }
    }
}

/// Cumulative fresh-offer admission refusals in this process.
///
/// **Expected value in healthy operation is zero.** A node that refuses a
/// legitimate fresh offer does not merely shed load: the sender transmits
/// offers one-way and never reads the refusal, so the chunk's absence
/// resurfaces at the sender's delayed possession check and is charged to the
/// refusing node at audit severity (ADR-0003). Reaching this ceiling therefore
/// means the node is either under-provisioned for its offered load or its
/// admission share is mis-sized — and is accruing unearned trust damage either
/// way. Operators should alarm on any sustained non-zero rate.
///
/// Process-global rather than per-engine, which is exactly right in production
/// (one node per process) and adequate in multi-node test harnesses, where the
/// useful assertion is that *no* node in the fleet refused.
#[must_use]
pub fn fresh_offer_admission_refusals() -> u64 {
    audit_metrics::responder_admission_drops(ReplicationResponderClass::FreshOffer)
}

/// Cumulative paid-list notification admission refusals in this process.
///
/// As with [`fresh_offer_admission_refusals`], zero is the expected value.
/// `PaidNotify` is one-way with no retry, so a refusal discards durable
/// paid-list evidence outright rather than pushing work back onto a requester.
#[must_use]
pub fn paid_notify_admission_refusals() -> u64 {
    audit_metrics::responder_admission_drops(ReplicationResponderClass::PaidNotify)
}

/// Fresh-offer refusals caused by the class-wide pool being exhausted.
///
/// Split from [`fresh_offer_refusals_per_peer_share`] because the two indict
/// different things: this one says the node was saturated across all sources
/// and is genuinely under-provisioned for its offered load.
#[must_use]
pub fn fresh_offer_refusals_global_pool() -> u64 {
    audit_metrics::responder_admission_drops_by_ceiling(
        ReplicationResponderClass::FreshOffer,
        ResponderAdmissionCeiling::GlobalPool,
    )
}

/// Fresh-offer refusals caused by one source exhausting its per-peer share.
///
/// For fresh offers this usually indicts the *share's size* rather than the
/// sender: the legitimate traffic pattern is bulk from a single peer — the one
/// node handling a client's PUT and fanning it out — so a share sized for
/// request/response traffic will refuse ordinary uploads.
#[must_use]
pub fn fresh_offer_refusals_per_peer_share() -> u64 {
    audit_metrics::responder_admission_drops_by_ceiling(
        ReplicationResponderClass::FreshOffer,
        ResponderAdmissionCeiling::PerPeerShare,
    )
}

/// Why an audit-responder admission attempt failed, with the decision-time
/// capacity counters that let a drop be logged with full context.
///
/// `global_inflight`/`peer_inflight` are best-effort snapshots taken as the
/// decision was made (the two ceilings are read under different locks, so they
/// are not a single atomic view), but they are exact enough to tell a saturated
/// node from a single self-throttling flooder.
#[derive(Debug, Clone, Copy)]
struct ResponderAdmissionFailure {
    reason: ResponderRejectReason,
    /// Global permits in use across the whole engine at decision time.
    global_inflight: usize,
    /// Configured global ceiling ([`MAX_CONCURRENT_AUDIT_RESPONSES`]).
    global_limit: usize,
    /// In-flight audit responders already held for `source` at decision time.
    peer_inflight: u32,
    /// Configured per-peer ceiling ([`MAX_AUDIT_RESPONSES_PER_PEER`]).
    peer_limit: u32,
}

impl fmt::Display for ResponderAdmissionFailure {
    /// Renders the stable `reason=... global_inflight=... global_limit=...
    /// peer_inflight=... peer_limit=...` suffix appended to every drop log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "reason={} global_inflight={} global_limit={} peer_inflight={} peer_limit={}",
            self.reason.as_str(),
            self.global_inflight,
            self.global_limit,
            self.peer_inflight,
            self.peer_limit,
        )
    }
}

/// RAII admission for one audit-responder task: holds the GLOBAL permit and,
/// on drop, decrements the PER-PEER in-flight count. Moving this into the
/// spawned task ties both bounds to the task's exact lifetime — no manual
/// decrement to forget on an early return or panic.
struct ResponderGuard {
    _permit: tokio::sync::OwnedSemaphorePermit,
    _peer_slot: PeerResponderSlot,
    global_inflight: usize,
    peer_inflight: u32,
}

type AuditResponderGuard = ResponderGuard;
type AuditResponderAdmissionFailure = ResponderAdmissionFailure;

/// Provisional or admitted per-peer responder slot.
///
/// The slot is claimed before the global permit is attempted. Keeping that
/// claim under RAII means cancellation while rolling a failed admission back
/// cannot strand a peer at its cap. Once admission succeeds this guard moves
/// into [`ResponderGuard`] and remains held for the worker's exact lifetime.
struct PeerResponderSlot {
    inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    peer: PeerId,
}

#[derive(Clone)]
struct ReplicationMessageHandlerContext {
    p2p_node: Arc<P2PNode>,
    storage: Arc<ChunkStore>,
    paid_list: Arc<PaidList>,
    payment_verifier: Arc<PaymentVerifier>,
    queues: Arc<RwLock<ReplicationQueues>>,
    config: Arc<ReplicationConfig>,
    is_bootstrapping: Arc<RwLock<bool>>,
    bootstrap_state: Arc<RwLock<BootstrapState>>,
    sync_history: Arc<RwLock<HashMap<PeerId, PeerSyncRecord>>>,
    sync_cycle_epoch: Arc<RwLock<u64>>,
    repair_proofs: Arc<RwLock<RepairProofs>>,
    last_commitment_by_peer: Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    ever_capable_peers: Arc<RwLock<HashSet<PeerId>>>,
    sig_verify_attempts: Arc<RwLock<HashMap<PeerId, Instant>>>,
    my_commitment_state: Arc<ResponderCommitmentState>,
    gossip_audit: GossipAuditTrigger,
    audit_responder_semaphore: Arc<Semaphore>,
    audit_responder_inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    audit_responder_metrics: Arc<AuditResponderMetrics>,
    subtree_round1: SubtreeRound1Limiter,
    fetch_responder_worker_semaphore: Arc<Semaphore>,
    fetch_responder_admission_semaphore: Arc<Semaphore>,
    fetch_responder_inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    verification_responder_worker_semaphore: Arc<Semaphore>,
    verification_responder_admission_semaphore: Arc<Semaphore>,
    verification_responder_inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    neighbor_sync_responder_worker_semaphore: Arc<Semaphore>,
    neighbor_sync_responder_admission_semaphore: Arc<Semaphore>,
    neighbor_sync_responder_inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    fresh_offer_worker_semaphore: Arc<Semaphore>,
    fresh_offer_admission_semaphore: Arc<Semaphore>,
    fresh_offer_responder_inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    fresh_offer_in_flight: FreshOfferInFlight,
    paid_notify_worker_semaphore: Arc<Semaphore>,
    paid_notify_admission_semaphore: Arc<Semaphore>,
    paid_notify_responder_inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    /// The engine's shutdown token, for detached responder work.
    ///
    /// Workers on [`Self::detached_task_tracker`] race this around their
    /// *network* phase only — never around a storage `spawn_blocking` await,
    /// where dropping the awaiter would detach a live transaction. This is
    /// what lets `shutdown()` keep its unbounded `tracker.wait()` and still
    /// terminate: the wait stays safe because it is now guaranteed finite.
    shutdown: CancellationToken,
    /// Shared tracker for detached work so `shutdown()` can await release of
    /// storage and P2P resources after all producer tasks have stopped.
    detached_task_tracker: TaskTracker,
}

struct InboundReplicationMessage {
    source: PeerId,
    msg: ReplicationMessage,
    rr_message_id: Option<String>,
    received_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SerialQueueDropReason {
    Full,
    Closed,
}

#[cfg(feature = "logging")]
impl SerialQueueDropReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Closed => "closed",
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(any(feature = "logging", test)), allow(dead_code))]
struct SerialQueueDrop {
    source: PeerId,
    message_class: &'static str,
    audit_responder_class: Option<AuditResponderClass>,
    queue_depth: usize,
    reason: SerialQueueDropReason,
}

fn try_enqueue_serial_message(
    sender: &mpsc::Sender<InboundReplicationMessage>,
    inbound: InboundReplicationMessage,
) -> std::result::Result<(), SerialQueueDrop> {
    let source = inbound.source;
    let message_class = replication_message_class(&inbound.msg.body);
    let audit_responder_class = audit_responder_class(&inbound.msg.body);
    let queue_depth = sender.max_capacity().saturating_sub(sender.capacity());
    sender.try_send(inbound).map_err(|error| {
        let (reason, dropped) = match error {
            mpsc::error::TrySendError::Full(dropped) => (SerialQueueDropReason::Full, dropped),
            mpsc::error::TrySendError::Closed(dropped) => (SerialQueueDropReason::Closed, dropped),
        };
        audit_metrics::record_serial_queue_overflow_drop(&dropped.msg.body);
        SerialQueueDrop {
            source,
            message_class,
            audit_responder_class,
            queue_depth,
            reason,
        }
    })
}

const fn replication_message_class(body: &ReplicationMessageBody) -> &'static str {
    match body {
        ReplicationMessageBody::FreshReplicationOffer(_) => "fresh_offer",
        ReplicationMessageBody::FreshReplicationResponse(_) => "fresh_response",
        ReplicationMessageBody::PaidNotify(_) => "paid_notify",
        ReplicationMessageBody::NeighborSyncRequest(_) => "neighbor_sync_request",
        ReplicationMessageBody::NeighborSyncResponse(_) => "neighbor_sync_response",
        ReplicationMessageBody::VerificationRequest(_) => "verification_request",
        ReplicationMessageBody::VerificationResponse(_) => "verification_response",
        ReplicationMessageBody::FetchRequest(_) => "fetch_request",
        ReplicationMessageBody::FetchResponse(_) => "fetch_response",
        ReplicationMessageBody::AuditChallenge(_) => "audit_challenge",
        ReplicationMessageBody::AuditResponse(_) => "audit_response",
        ReplicationMessageBody::SubtreeAuditChallenge(_) => "subtree_audit_challenge",
        ReplicationMessageBody::SubtreeAuditResponse(_) => "subtree_audit_response",
        ReplicationMessageBody::SubtreeSliceChallenge(_) => "subtree_slice_challenge",
        ReplicationMessageBody::SubtreeSliceResponse(_) => "subtree_slice_response",
        ReplicationMessageBody::GetCommitmentByPin(_) => "commitment_pin_request",
        ReplicationMessageBody::GetCommitmentByPinResponse(_) => "commitment_pin_response",
    }
}

const fn audit_responder_class(body: &ReplicationMessageBody) -> Option<AuditResponderClass> {
    match body {
        ReplicationMessageBody::AuditChallenge(_) => Some(AuditResponderClass::Digest),
        ReplicationMessageBody::SubtreeAuditChallenge(_) => Some(AuditResponderClass::Subtree),
        ReplicationMessageBody::SubtreeSliceChallenge(_) => Some(AuditResponderClass::Byte),
        ReplicationMessageBody::GetCommitmentByPin(_) => Some(AuditResponderClass::CommitmentPin),
        _ => None,
    }
}

impl AuditResponderClass {
    const fn per_peer_limit(self) -> u32 {
        match self {
            Self::Digest => MAX_DIGEST_AUDIT_RESPONSES_PER_PEER,
            Self::Subtree | Self::Byte | Self::CommitmentPin => MAX_AUDIT_RESPONSES_PER_PEER,
        }
    }
}

fn handle_replication_event_recv_error(error: &RecvError) -> ControlFlow<()> {
    match error {
        RecvError::Lagged(missed) => {
            audit_metrics::record_replication_event_lagged(*missed);
            warn!(
                "Missed {missed} P2P events on replication branch (broadcast lag); \
                 replication messages may have been dropped before dispatch"
            );
            ControlFlow::Continue(())
        }
        RecvError::Closed => {
            // A closed broadcast channel never yields again, so the branch
            // would otherwise be immediately ready on every select! iteration.
            warn!("P2P event stream closed on replication branch; stopping message handler");
            ControlFlow::Break(())
        }
    }
}

fn replication_payload_from_event(
    event: P2PEvent,
) -> Option<(PeerId, Vec<u8>, &'static str, Option<String>)> {
    let P2PEvent::Message {
        topic,
        source: Some(source),
        data,
        ..
    } = event
    else {
        return None;
    };

    let (matched_id, is_rr) = match_replication_protocol(&topic)?;
    if !is_rr {
        return Some((source, data, matched_id, None));
    }
    if is_rr {
        return P2PNode::parse_request_envelope(&data)
            .filter(|(_, is_resp, _)| !is_resp)
            .map(|(msg_id, _, payload)| (source, payload, matched_id, Some(msg_id)));
    }
    None
}

impl Drop for PeerResponderSlot {
    fn drop(&mut self) {
        // Decrement (and prune to keep the map bounded) without blocking the
        // async runtime: a short lock on a tiny map.
        //
        // Fast path: if the (uncontended, tiny) lock is free, decrement inline
        // with no spawn. Otherwise defer to a task — but only if a runtime is
        // actually current, so `Drop` during shutdown (no runtime) can never
        // panic. A missed decrement at shutdown is harmless: the whole map is
        // being dropped with the engine.
        let peer = self.peer;
        if let Ok(mut map) = self.inflight.try_write() {
            if let Some(n) = map.get_mut(&peer) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    map.remove(&peer);
                }
            }
            return;
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let inflight = Arc::clone(&self.inflight);
            handle.spawn(async move {
                let mut map = inflight.write().await;
                if let Some(n) = map.get_mut(&peer) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        map.remove(&peer);
                    }
                }
            });
        }
    }
}

/// Try to admit one bounded responder task for `source`: claim a per-peer slot
/// and then a global permit. The limits are parameters so independent responder
/// classes can reuse the same flood-fair admission and cancellation semantics.
async fn admit_bounded_responder(
    semaphore: &Arc<Semaphore>,
    inflight: &Arc<RwLock<HashMap<PeerId, u32>>>,
    source: &PeerId,
    global_limit: usize,
    peer_limit: u32,
) -> std::result::Result<ResponderGuard, ResponderAdmissionFailure> {
    let global_inflight = |sem: &Semaphore| global_limit.saturating_sub(sem.available_permits());

    let admitted_peer_inflight = {
        let mut map = inflight.write().await;
        let entry = map.entry(*source).or_insert(0);
        if *entry >= peer_limit {
            let peer_inflight = *entry;
            drop(map);
            return Err(ResponderAdmissionFailure {
                reason: ResponderRejectReason::PerPeerCapFull,
                global_inflight: global_inflight(semaphore),
                global_limit,
                peer_inflight,
                peer_limit,
            });
        }
        *entry += 1;
        *entry
    };

    let peer_slot = PeerResponderSlot {
        inflight: Arc::clone(inflight),
        peer: *source,
    };
    let Ok(permit) = Arc::clone(semaphore).try_acquire_owned() else {
        return Err(ResponderAdmissionFailure {
            reason: ResponderRejectReason::GlobalPoolFull,
            global_inflight: global_inflight(semaphore),
            global_limit,
            peer_inflight: admitted_peer_inflight.saturating_sub(1),
            peer_limit,
        });
    };

    Ok(ResponderGuard {
        _permit: permit,
        _peer_slot: peer_slot,
        global_inflight: global_inflight(semaphore),
        peer_inflight: admitted_peer_inflight,
    })
}

/// A live round-1 → round-2 subtree-audit session: proof of a matching round 1.
struct SubtreeSession {
    commitment_hash: [u8; 32],
    nonce: [u8; 32],
    inserted: Instant,
}

/// Responder-wide token bucket over the chunk bytes round-1 proof building may
/// read and hash, refilled continuously at
/// [`SUBTREE_ROUND1_WORK_REFILL_BYTES_PER_SEC`] up to
/// [`SUBTREE_ROUND1_WORK_BURST_BYTES`].
///
/// Deliberately keyed by nothing. The per-peer cooldown limits how often one
/// identity may ask, so it is refilled by acquiring more identities; this is
/// charged for work done regardless of who asked, so it is not.
///
/// Charged after the fact, with the bytes the proof actually covered: the cost
/// of a request is not known until the pinned commitment has been resolved and
/// its subtree selected, both of which happen inside the handler. Admission
/// therefore asks only whether the balance is positive, and a proof that costs
/// more than is left drives the balance NEGATIVE rather than stopping at zero.
/// Carrying the debt is what makes the bound real: without it a maximal proof
/// would cost the same as a trivial one, since either way the next request only
/// has to wait for the balance to climb back above zero. With it, sustained
/// throughput settles at refill ÷ cost-per-proof, so expensive proofs are
/// admitted proportionally less often.
struct Round1WorkBudget {
    /// Signed, so an over-large proof leaves debt to work off.
    balance: i64,
    last_refill: Instant,
}

impl Round1WorkBudget {
    /// Deepest debt carried, so one huge proof cannot lock out honest audits
    /// for longer than the burst takes to refill.
    const MAX_DEBT: i64 = -SUBTREE_ROUND1_WORK_BURST_BYTES;
    /// Nanoseconds per second, for the sub-second part of a refill.
    const NANOS_PER_SEC: i64 = 1_000_000_000;

    fn new() -> Self {
        Self {
            balance: SUBTREE_ROUND1_WORK_BURST_BYTES,
            last_refill: Instant::now(),
        }
    }

    /// Add the tokens accrued since the last touch, capped at the burst size.
    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill);
        self.last_refill = now;
        let whole_secs = i64::try_from(elapsed.as_secs())
            .unwrap_or(i64::MAX)
            .saturating_mul(SUBTREE_ROUND1_WORK_REFILL_BYTES_PER_SEC);
        let sub_sec = i64::from(elapsed.subsec_nanos())
            .saturating_mul(SUBTREE_ROUND1_WORK_REFILL_BYTES_PER_SEC)
            / Self::NANOS_PER_SEC;
        self.balance = self
            .balance
            .saturating_add(whole_secs.saturating_add(sub_sec))
            .min(SUBTREE_ROUND1_WORK_BURST_BYTES);
    }

    /// Whether budget remains for a new round-1 proof.
    fn has_budget(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.balance > 0
    }

    /// Charge `bytes` of completed proof work, carrying debt down to
    /// [`Self::MAX_DEBT`].
    fn charge(&mut self, bytes: i64, now: Instant) {
        self.refill(now);
        self.balance = self.balance.saturating_sub(bytes).max(Self::MAX_DEBT);
    }
}

/// Resource controls for the HEAVY subtree-audit round 1: a tight
/// admission pool separate from the light responsible/slice audits, a per-peer
/// rate cooldown, and single-use round-1 → round-2 sessions so a round-2 slice
/// challenge is only served after a matching round 1.
///
/// It also holds the responder-wide [`Round1WorkBudget`], the only one of those
/// bounds not keyed by peer identity, and so the only one that bounds sustained
/// work rather than concurrency or per-identity frequency.
#[derive(Clone)]
struct SubtreeRound1Limiter {
    semaphore: Arc<Semaphore>,
    /// Global ceiling on concurrent round-1 proofs (config-driven;
    /// [`MAX_CONCURRENT_SUBTREE_ROUND1`] in production). Held alongside the
    /// semaphore because the per-peer admission helper needs the same number.
    max_concurrent: usize,
    inflight: Arc<RwLock<HashMap<PeerId, u32>>>,
    cooldown: Arc<RwLock<HashMap<PeerId, Instant>>>,
    /// Per-peer minimum spacing between served round-1 proofs (config-driven;
    /// [`SUBTREE_ROUND1_RESPONDER_COOLDOWN`] in production, near-zero in tests).
    cooldown_interval: Duration,
    sessions: Arc<RwLock<HashMap<(PeerId, u64), SubtreeSession>>>,
    /// Identity-independent ceiling on sustained round-1 work.
    work: Arc<RwLock<Round1WorkBudget>>,
}

impl SubtreeRound1Limiter {
    /// `max_concurrent` of 0 would wedge the responder into refusing every
    /// round-1 proof, which reads on the auditor side as a silent whole-fleet
    /// audit outage. Clamp to at least one so a mis-set config degrades to slow
    /// rather than to off.
    fn new(cooldown_interval: Duration, max_concurrent: usize) -> Self {
        let max_concurrent = max_concurrent.max(1);
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            max_concurrent,
            inflight: Arc::new(RwLock::new(HashMap::new())),
            cooldown: Arc::new(RwLock::new(HashMap::new())),
            cooldown_interval,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            work: Arc::new(RwLock::new(Round1WorkBudget::new())),
        }
    }

    /// Charge completed round-1 proof work against the responder-wide budget.
    async fn charge_work(&self, content_bytes: i64) {
        self.work
            .write()
            .await
            .charge(content_bytes, Instant::now());
    }

    /// Admit one heavy round-1 proof for `source`: take a concurrency permit
    /// FIRST (so a full pool never wastes the peer's cooldown allowance), then
    /// the responder-wide work budget, then the per-peer rate cooldown. `None`
    /// drops the challenge (the remote auditor applies its own graced-timeout
    /// policy).
    async fn admit(&self, source: &PeerId) -> Option<AuditResponderGuard> {
        let guard = admit_bounded_responder(
            &self.semaphore,
            &self.inflight,
            source,
            self.max_concurrent,
            MAX_SUBTREE_ROUND1_PER_PEER,
        )
        .await
        .ok()?;
        // Checked before the per-peer cooldown is stamped, so a peer refused for
        // want of budget is not also charged its next allowance.
        if !self.work.write().await.has_budget(Instant::now()) {
            return None; // guard drops here, releasing the permit + slot
        }
        let now = Instant::now();
        let mut cooldown = self.cooldown.write().await;
        if let Some(&last) = cooldown.get(source) {
            if now.duration_since(last) < self.cooldown_interval {
                return None; // guard drops here, releasing the permit + slot
            }
        }
        // Evict lapsed entries (their cooldown has expired, so they no longer
        // limit) and cap capacity, so peer-id churn can't grow this map unbounded.
        cooldown.retain(|_, &mut last| now.duration_since(last) < self.cooldown_interval);
        if cooldown.len() >= MAX_SUBTREE_SESSIONS {
            if let Some(oldest) = cooldown.iter().min_by_key(|(_, &t)| t).map(|(k, _)| *k) {
                cooldown.remove(&oldest);
            }
        }
        cooldown.insert(*source, now);
        Some(guard)
    }

    /// Record a single-use session once a round-1 proof is built and about to be
    /// sent, so the matching round 2 is admitted exactly once.
    async fn open_session(
        &self,
        source: PeerId,
        challenge_id: u64,
        commitment_hash: [u8; 32],
        nonce: [u8; 32],
    ) {
        let now = Instant::now();
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, e| now.duration_since(e.inserted) < SUBTREE_SESSION_TTL);
        if sessions.len() >= MAX_SUBTREE_SESSIONS {
            if let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, e)| e.inserted)
                .map(|(k, _)| *k)
            {
                sessions.remove(&oldest);
            }
        }
        sessions.insert(
            (source, challenge_id),
            SubtreeSession {
                commitment_hash,
                nonce,
                inserted: now,
            },
        );
    }

    /// Atomically consume the round-2 session for this exchange. `true` iff a
    /// live session matching `(source, challenge_id, commitment_hash, nonce)`
    /// existed (and is now removed); a miss silently drops round 2 to the graced
    /// timeout lane (sessions are ephemeral and can be lost across a restart).
    async fn consume_session(
        &self,
        source: &PeerId,
        challenge_id: u64,
        commitment_hash: &[u8; 32],
        nonce: &[u8; 32],
    ) -> bool {
        let mut sessions = self.sessions.write().await;
        let matches = sessions.get(&(*source, challenge_id)).is_some_and(|e| {
            Instant::now().duration_since(e.inserted) < SUBTREE_SESSION_TTL
                && &e.commitment_hash == commitment_hash
                && &e.nonce == nonce
        });
        if matches {
            sessions.remove(&(*source, challenge_id));
        }
        matches
    }
}

/// Outcome of admitting a round-2 slice challenge.
enum SliceAdmission {
    /// Admitted: the guard holds the global permit and the per-peer slot, and
    /// the single-use round-1 session has been consumed.
    Admitted(AuditResponderGuard),
    /// Refused at a responder ceiling. The round-1 session is left INTACT.
    Capacity(AuditResponderAdmissionFailure),
    /// No live round-1 session matched this challenge.
    NoSession,
}

/// Admit a round-2 slice challenge: take the responder permit BEFORE consuming
/// the single-use round-1 session.
///
/// The order is the point: a single-use token must not be spent on work that is
/// then refused. Consuming first and testing admission second leaves the session
/// destroyed by a purely local capacity drop, so the refusal is not recoverable
/// even in principle.
///
/// Scope of the benefit today, stated honestly: `request_slice_proof` issues one
/// `send_request` and maps any failure straight to `SliceRound::Timeout`, so the
/// auditor does not currently re-send round 2 within an audit. The preserved
/// session is therefore not yet *recovering* an audit — it keeps a refusal
/// truthful (temporary means temporary) and keeps the invariant available for a
/// retry, rather than baking "capacity drop is permanent" into the state
/// machine. If an application-level retry is ruled out for good, this ordering
/// still costs nothing over the alternative.
///
/// Cost of the ordering: the permit and per-peer slot are held across the
/// session probe, which is one in-memory map lookup and no chunk work. The
/// per-peer cap still bounds a peer sending unsessioned challenges to the same
/// share it could already occupy with well-formed ones, so the admission
/// surface is unchanged.
async fn admit_slice_challenge(
    semaphore: &Arc<Semaphore>,
    inflight: &Arc<RwLock<HashMap<PeerId, u32>>>,
    round1: &SubtreeRound1Limiter,
    source: &PeerId,
    challenge: &protocol::SubtreeSliceChallenge,
) -> SliceAdmission {
    let guard =
        match admit_audit_responder(semaphore, inflight, source, AuditResponderClass::Byte).await {
            Ok(guard) => guard,
            Err(failure) => return SliceAdmission::Capacity(failure),
        };
    if !round1
        .consume_session(
            source,
            challenge.challenge_id,
            &challenge.expected_commitment_hash,
            &challenge.nonce,
        )
        .await
    {
        // Release the permit and per-peer slot before the caller replies: no
        // chunk work follows, so holding them would shrink the pool for nothing.
        drop(guard);
        return SliceAdmission::NoSession;
    }
    SliceAdmission::Admitted(guard)
}

/// Try to admit one audit-responder task for `source`: take a global permit AND
/// a per-peer slot (both bounded). Returns `Err` with the binding ceiling and
/// its decision-time counters (caller drops the challenge, leaving the remote
/// auditor to apply that audit path's timeout policy) if either ceiling is hit,
/// so one flooder can neither exhaust the global pool's effect on others nor
/// exceed its own per-peer share (codex-r2 A). The `Err` reason lets the caller
/// log exactly WHY the drop happened rather than a single opaque "capacity
/// reached".
async fn admit_audit_responder(
    semaphore: &Arc<Semaphore>,
    inflight: &Arc<RwLock<HashMap<PeerId, u32>>>,
    source: &PeerId,
    class: AuditResponderClass,
) -> std::result::Result<AuditResponderGuard, AuditResponderAdmissionFailure> {
    let global_limit = MAX_CONCURRENT_AUDIT_RESPONSES;
    let peer_limit = class.per_peer_limit();
    admit_bounded_responder(semaphore, inflight, source, global_limit, peer_limit).await
}

/// Handle an incoming replication protocol message.
///
/// When `rr_message_id` is `Some`, the request arrived via the `/rr/`
/// request-response path and the response must be sent via `send_response`
/// so saorsa-core can route it back to the waiting `send_request` caller.
#[allow(clippy::too_many_lines)]
async fn handle_replication_message(
    source: &PeerId,
    msg: ReplicationMessage,
    ctx: &ReplicationMessageHandlerContext,
    received_at: Instant,
    rr_message_id: Option<&str>,
) -> Result<()> {
    match msg.body {
        ReplicationMessageBody::FreshReplicationOffer(offer) => {
            dispatch_fresh_offer(
                *source,
                offer,
                ctx,
                msg.request_id,
                received_at,
                rr_message_id,
            )
            .await
        }
        ReplicationMessageBody::PaidNotify(notify) => {
            dispatch_paid_notify(*source, notify, ctx, received_at).await
        }
        ReplicationMessageBody::NeighborSyncRequest(request) => {
            let bootstrapping = *ctx.is_bootstrapping.read().await;
            // Phase-3 storage-bound audit: store the sender's
            // commitment for use as `expected_commitment_hash` in
            // future audits. Verify signature before storing so a peer
            // cannot inject a forged commitment for someone else.
            if let Some(target) = ingest_peer_commitment(
                source,
                request.commitment.as_ref(),
                &ctx.p2p_node,
                &ctx.last_commitment_by_peer,
                &ctx.ever_capable_peers,
                &ctx.sig_verify_attempts,
            )
            .await
            {
                maybe_trigger_gossip_audit(&ctx.gossip_audit, source, target).await;
            }
            dispatch_neighbor_sync_request(
                *source,
                request,
                ctx,
                bootstrapping,
                // Atomically snapshot + mark-gossiped: emitted in the sync
                // response, so we must stay answerable for it (ADR-0002).
                ctx.my_commitment_state
                    .current_for_gossip()
                    .map(|b| b.commitment().clone()),
                msg.request_id,
                received_at,
                rr_message_id,
            )
            .await
        }
        ReplicationMessageBody::VerificationRequest(request) => {
            dispatch_verification_request(
                *source,
                request,
                ctx,
                msg.request_id,
                received_at,
                rr_message_id,
            )
            .await
        }
        ReplicationMessageBody::FetchRequest(request) => {
            dispatch_fetch_request(
                *source,
                request,
                ctx,
                msg.request_id,
                received_at,
                rr_message_id,
            )
            .await
        }
        ReplicationMessageBody::AuditChallenge(challenge) => {
            // Responsible-chunk audit (audit #2) responder: answer with per-key
            // possession digests. This same handler also answers the
            // prune-confirmation audit, which sends the same `AuditChallenge`
            // wire message.
            //
            // Answering digests the stored bytes of every challenged key, so —
            // like the subtree/byte audits below — run it on a detached task off
            // this serial message loop. Handling it inline lets one challenge
            // block all other replication traffic until its digests complete
            // (head-of-line blocking). The same flood-fair admission applies: a
            // global ceiling AND a per-peer cap, dropping the challenge if either
            // is hit. A dropped challenge reads as a penalised timeout to the
            // auditor, so the caps must remain high enough for honest audit load;
            // the per-peer share still prevents one flooder from starving others.
            let class = AuditResponderClass::Digest;
            let guard = match admit_audit_responder(
                &ctx.audit_responder_semaphore,
                &ctx.audit_responder_inflight,
                source,
                class,
            )
            .await
            {
                Ok(guard) => guard,
                Err(failure) => {
                    protocol::record_audit_drop(protocol::AuditDropKind::Responsible);
                    audit_metrics::record_admission_drop(class);
                    ctx.audit_responder_metrics
                        .record_drop(*source, failure.reason.into());
                    warn!(
                        target: "ant_node::replication::audit_responder",
                        event = "admission_dropped",
                        kind = "responsible",
                        responder_class = class.as_str(),
                        source = %source,
                        challenge_id = challenge.challenge_id,
                        key_count = challenge.keys.len(),
                        request_response = rr_message_id.is_some(),
                        dispatch_ms = received_at.elapsed().as_millis(),
                        reason = failure.reason.as_str(),
                        global_inflight = failure.global_inflight,
                        global_limit = failure.global_limit,
                        peer_inflight = failure.peer_inflight,
                        peer_limit = failure.peer_limit,
                        "Audit responder admission dropped"
                    );
                    return Ok(());
                }
            };
            let admission_global_inflight = guard.global_inflight;
            let admission_peer_inflight = guard.peer_inflight;
            ctx.audit_responder_metrics.record_admitted(
                *source,
                admission_global_inflight,
                admission_peer_inflight,
            );
            info!(
                target: "ant_node::replication::audit_responder",
                event = "admitted",
                kind = "responsible",
                responder_class = class.as_str(),
                source = %source,
                challenge_id = challenge.challenge_id,
                key_count = challenge.keys.len(),
                request_response = rr_message_id.is_some(),
                dispatch_ms = received_at.elapsed().as_millis(),
                global_inflight = admission_global_inflight,
                global_limit = MAX_CONCURRENT_AUDIT_RESPONSES,
                peer_inflight = admission_peer_inflight,
                peer_limit = class.per_peer_limit(),
                "Audit responder request admitted"
            );
            let bootstrapping = *ctx.is_bootstrapping.read().await;
            let dispatch_latency = received_at.elapsed();
            audit_metrics::record_digest_dispatch_latency(dispatch_latency);
            debug!(
                audit_type = "digest_responder",
                dispatch_latency_ms = dispatch_latency.as_millis(),
                source = %source,
                "Audit challenge dispatch latency measured"
            );
            let storage = Arc::clone(&ctx.storage);
            let p2p_node = Arc::clone(&ctx.p2p_node);
            let source = *source;
            let request_id = msg.request_id;
            let rr_message_id = rr_message_id.map(ToOwned::to_owned);
            let responder_metrics = Arc::clone(&ctx.audit_responder_metrics);
            ctx.detached_task_tracker.spawn(async move {
                let _guard = guard; // global permit + per-peer slot, held until done
                let worker_started = Instant::now();
                match handle_audit_challenge_msg(
                    &source,
                    &challenge,
                    &storage,
                    &p2p_node,
                    bootstrapping,
                    ReplyRoute {
                        request_id,
                        rr_message_id: rr_message_id.as_deref(),
                        protocol: REPLICATION_PROTOCOL_ID,
                    },
                )
                .await
                {
                    Ok(completion) => log_audit_responder_completion(
                        &responder_metrics,
                        source,
                        class,
                        "responsible",
                        challenge.challenge_id,
                        challenge.keys.len(),
                        completion.response_kind,
                        completion.sent,
                        received_at,
                        worker_started,
                        completion.processing,
                        completion.response_send,
                    ),
                    Err(e) => debug!("Audit challenge from {source} error: {e}"),
                }
            });
            Ok(())
        }
        ReplicationMessageBody::SubtreeAuditChallenge(challenge) => {
            // Gossip-triggered storage-bound subtree audit (ADR-0002). The
            // responder rebuilds the WHOLE nonce-selected subtree, reading every
            // leaf's bytes from disk (`get_raw` × ~sqrt(N) leaves). Run it on a
            // detached task so this serial message loop is never blocked on disk
            // I/O — otherwise one audit stalls all replication traffic (§5).
            //
            // A bounded, flood-fair admission restores backpressure (codex#1 +
            // codex-r2 A): a global ceiling AND a per-peer cap. If either is hit
            // we drop this challenge. Subtree auditors grace timeout
            // non-responses, so capacity drops throttle flooders without turning
            // into trust penalties (and one source cannot starve other peers,
            // since its share is capped per-peer).
            let class = AuditResponderClass::Subtree;
            info!(
                "Audit challenge received: kind=subtree source={source} request_response={}",
                rr_message_id.is_some(),
            );
            // Round 1 is the HEAVY path (rebuilds + hashes the whole sqrt-subtree),
            // so it uses its own tight admission pool + per-peer rate cooldown,
            // separate from the light responsible/slice audits, and a miss silently
            // drops (subtree auditors grace timeouts).
            let Some(guard) = ctx.subtree_round1.admit(source).await else {
                protocol::record_audit_drop(protocol::AuditDropKind::Subtree);
                warn!(
                    target: "ant_node::replication::audit_responder",
                    event = "admission_dropped",
                    kind = "subtree",
                    responder_class = class.as_str(),
                    source = %source,
                    challenge_id = challenge.challenge_id,
                    request_response = rr_message_id.is_some(),
                    dispatch_ms = received_at.elapsed().as_millis(),
                    reason = "heavy_pool_cooldown_or_work_budget",
                    "Audit responder admission dropped"
                );
                return Ok(());
            };
            let admission_global_inflight = guard.global_inflight;
            let admission_peer_inflight = guard.peer_inflight;
            ctx.audit_responder_metrics.record_admitted(
                *source,
                admission_global_inflight,
                admission_peer_inflight,
            );
            info!(
                target: "ant_node::replication::audit_responder",
                event = "admitted",
                kind = "subtree",
                responder_class = class.as_str(),
                source = %source,
                challenge_id = challenge.challenge_id,
                request_response = rr_message_id.is_some(),
                dispatch_ms = received_at.elapsed().as_millis(),
                global_inflight = admission_global_inflight,
                global_limit = ctx.subtree_round1.max_concurrent,
                peer_inflight = admission_peer_inflight,
                peer_limit = MAX_SUBTREE_ROUND1_PER_PEER,
                "Audit responder request admitted"
            );
            let bootstrapping = *ctx.is_bootstrapping.read().await;
            let storage = Arc::clone(&ctx.storage);
            let p2p_node = Arc::clone(&ctx.p2p_node);
            let my_commitment_state = Arc::clone(&ctx.my_commitment_state);
            let source = *source;
            let request_id = msg.request_id;
            let rr_message_id = rr_message_id.map(ToOwned::to_owned);
            let responder_metrics = Arc::clone(&ctx.audit_responder_metrics);
            let subtree_round1 = ctx.subtree_round1.clone();
            ctx.detached_task_tracker.spawn(async move {
                let _guard = guard; // global permit + per-peer slot, held until done
                let worker_started = Instant::now();
                let processing_started = Instant::now();
                let storage_commitment_audit::Round1Work {
                    response,
                    content_bytes,
                } = storage_commitment_audit::handle_subtree_challenge_measured(
                    &challenge,
                    &storage,
                    p2p_node.peer_id(),
                    bootstrapping,
                    Some(&my_commitment_state),
                )
                .await;
                let processing = processing_started.elapsed();
                // Charge the work actually done, on EVERY outcome.
                //
                // This used to charge only the `Proof` arm, reasoning that the
                // rejecting paths either read nothing or reflected this node's
                // own broken storage. The second half of that was wrong: a
                // retained commitment containing one unreadable key still costs
                // a full run of reads and keyed-BLAKE3 passes over every leaf
                // before it, and then rejects. An attacker who finds such a
                // commitment could replay subtrees over it indefinitely for
                // free. The per-peer cooldown does not catch that either, since
                // it is escapable by rotating identity — the responder-wide
                // budget is the only bound that applies, so it has to see the
                // work. A zero charge is a no-op, so the untouched paths are
                // unaffected.
                subtree_round1.charge_work(content_bytes).await;
                // A round-1 proof authorizes exactly one matching round 2: open a
                // single-use session so a slice challenge cannot be served without
                // a live round-1 exchange.
                if let crate::replication::protocol::SubtreeAuditResponse::Proof { .. } = &response
                {
                    subtree_round1
                        .open_session(
                            source,
                            challenge.challenge_id,
                            challenge.expected_commitment_hash,
                            challenge.nonce,
                        )
                        .await;
                }
                let response_kind = subtree_audit_response_kind(&response);
                let work_items = subtree_audit_response_work_items(&response);
                let response_send_started = Instant::now();
                let sent = send_replication_response_checked(
                    &source,
                    &p2p_node,
                    request_id,
                    ReplicationMessageBody::SubtreeAuditResponse(response),
                    rr_message_id.as_deref(),
                    None,
                )
                .await;
                let response_send = response_send_started.elapsed();
                log_audit_responder_completion(
                    &responder_metrics,
                    source,
                    class,
                    "subtree",
                    challenge.challenge_id,
                    work_items,
                    response_kind,
                    sent,
                    received_at,
                    worker_started,
                    processing,
                    response_send,
                );
            });
            Ok(())
        }
        ReplicationMessageBody::SubtreeSliceChallenge(challenge) => {
            // Round 2 of the storage audit (ADR-0002 / V2-685): open one 1 KiB
            // block of each auditor-selected spot-check key with a Bao verified
            // slice + nonced block-tree opening. Reads chunk bytes from disk to
            // build the proofs, so it runs off the serial loop under the light
            // audit pool's global and per-peer ceilings.
            let class = AuditResponderClass::Byte;
            info!(
                "Audit challenge received: kind=slice source={source} request_response={}",
                rr_message_id.is_some(),
            );
            let guard = match admit_slice_challenge(
                &ctx.audit_responder_semaphore,
                &ctx.audit_responder_inflight,
                &ctx.subtree_round1,
                source,
                &challenge,
            )
            .await
            {
                SliceAdmission::Admitted(guard) => guard,
                SliceAdmission::Capacity(failure) => {
                    protocol::record_audit_drop(protocol::AuditDropKind::Slice);
                    audit_metrics::record_admission_drop(class);
                    ctx.audit_responder_metrics
                        .record_drop(*source, failure.reason.into());
                    warn!(
                        target: "ant_node::replication::audit_responder",
                        event = "admission_dropped",
                        kind = "byte",
                        responder_class = class.as_str(),
                        source = %source,
                        challenge_id = challenge.challenge_id,
                        key_count = challenge.openings.len(),
                        request_response = rr_message_id.is_some(),
                        dispatch_ms = received_at.elapsed().as_millis(),
                        reason = failure.reason.as_str(),
                        global_inflight = failure.global_inflight,
                        global_limit = failure.global_limit,
                        peer_inflight = failure.peer_inflight,
                        peer_limit = failure.peer_limit,
                        "Audit responder admission dropped"
                    );
                    return Ok(());
                }
                // No live round-1 session: reply with a cheap `Transient` rejection
                // rather than dropping silently. Sessions are ephemeral (an honest
                // responder that restarts between rounds loses its session), and an
                // unanswered `send_request` would make saorsa-core record a
                // transport trust failure against that honest responder — an
                // ongoing effect, not just a rollout-window one. A `Transient`
                // reply routes the auditor to the graced timeout lane (no trust
                // penalty; the responder re-earns pinned credit on the next audit)
                // and does no chunk work, so it is not a DoS lever.
                SliceAdmission::NoSession => {
                    protocol::record_audit_drop(protocol::AuditDropKind::Slice);
                    debug!(
                        "Slice challenge without a live round-1 session source={source} \
                         challenge_id={} → Transient reject",
                        challenge.challenge_id
                    );
                    send_replication_response_checked(
                        source,
                        &ctx.p2p_node,
                        msg.request_id,
                        ReplicationMessageBody::SubtreeSliceResponse(
                            protocol::SubtreeSliceResponse::Rejected {
                                challenge_id: challenge.challenge_id,
                                kind: protocol::RejectKind::Transient,
                                reason: "no live round-1 session".to_string(),
                            },
                        ),
                        rr_message_id,
                        None,
                    )
                    .await;
                    return Ok(());
                }
            };
            let admission_global_inflight = guard.global_inflight;
            let admission_peer_inflight = guard.peer_inflight;
            ctx.audit_responder_metrics.record_admitted(
                *source,
                admission_global_inflight,
                admission_peer_inflight,
            );
            info!(
                target: "ant_node::replication::audit_responder",
                event = "admitted",
                kind = "byte",
                responder_class = class.as_str(),
                source = %source,
                challenge_id = challenge.challenge_id,
                key_count = challenge.openings.len(),
                request_response = rr_message_id.is_some(),
                dispatch_ms = received_at.elapsed().as_millis(),
                global_inflight = admission_global_inflight,
                global_limit = MAX_CONCURRENT_AUDIT_RESPONSES,
                peer_inflight = admission_peer_inflight,
                peer_limit = class.per_peer_limit(),
                "Audit responder request admitted"
            );
            let bootstrapping = *ctx.is_bootstrapping.read().await;
            let storage = Arc::clone(&ctx.storage);
            let p2p_node = Arc::clone(&ctx.p2p_node);
            let my_commitment_state = Arc::clone(&ctx.my_commitment_state);
            let source = *source;
            let request_id = msg.request_id;
            let rr_message_id = rr_message_id.map(ToOwned::to_owned);
            let responder_metrics = Arc::clone(&ctx.audit_responder_metrics);
            ctx.detached_task_tracker.spawn(async move {
                let _guard = guard; // global permit + per-peer slot, held until done
                let worker_started = Instant::now();
                let processing_started = Instant::now();
                let response = storage_commitment_audit::handle_subtree_slice_challenge(
                    &challenge,
                    &storage,
                    p2p_node.peer_id(),
                    bootstrapping,
                    Some(&my_commitment_state),
                )
                .await;
                let processing = processing_started.elapsed();
                let response_kind = subtree_slice_response_kind(&response);
                let response_send_started = Instant::now();
                let sent = send_replication_response_checked(
                    &source,
                    &p2p_node,
                    request_id,
                    ReplicationMessageBody::SubtreeSliceResponse(response),
                    rr_message_id.as_deref(),
                    None,
                )
                .await;
                let response_send = response_send_started.elapsed();
                log_audit_responder_completion(
                    &responder_metrics,
                    source,
                    class,
                    "byte",
                    challenge.challenge_id,
                    challenge.openings.len(),
                    response_kind,
                    sent,
                    received_at,
                    worker_started,
                    processing,
                    response_send,
                );
            });
            Ok(())
        }
        ReplicationMessageBody::GetCommitmentByPin(ref request) => {
            // ADR-0004: answer a commitment-by-pin fetch from the retained set
            // only. `lookup_by_hash` is an allocation-light read over the
            // bounded slot set; it returns the live current commitment or any
            // still-answerable recently-gossiped/quoted one. A miss is reported
            // as `NotRetained` (graced, never confirmed) rather than an error,
            // so an aged-out pin can never brand an honest node.
            //
            // Reuse the audit-responder admission guard (global ceiling + per-peer
            // cap) so a flood of fetches cannot drive unbounded commitment
            // clone/encode/send work; over-limit is dropped, which the fetching
            // peer graces exactly like a missed audit response.
            let class = AuditResponderClass::CommitmentPin;
            let guard = match admit_audit_responder(
                &ctx.audit_responder_semaphore,
                &ctx.audit_responder_inflight,
                source,
                class,
            )
            .await
            {
                Ok(guard) => guard,
                Err(failure) => {
                    audit_metrics::record_admission_drop(class);
                    ctx.audit_responder_metrics
                        .record_drop(*source, failure.reason.into());
                    warn!(
                        target: "ant_node::replication::audit_responder",
                        event = "admission_dropped",
                        kind = "commitment_pin",
                        responder_class = class.as_str(),
                        source = %source,
                        challenge_id = msg.request_id,
                        request_response = rr_message_id.is_some(),
                        dispatch_ms = received_at.elapsed().as_millis(),
                        reason = failure.reason.as_str(),
                        global_inflight = failure.global_inflight,
                        global_limit = failure.global_limit,
                        peer_inflight = failure.peer_inflight,
                        peer_limit = failure.peer_limit,
                        "Audit responder admission dropped"
                    );
                    return Ok(());
                }
            };
            ctx.audit_responder_metrics.record_admitted(
                *source,
                guard.global_inflight,
                guard.peer_inflight,
            );
            info!(
                target: "ant_node::replication::audit_responder",
                event = "admitted",
                kind = "commitment_pin",
                responder_class = class.as_str(),
                source = %source,
                challenge_id = msg.request_id,
                request_response = rr_message_id.is_some(),
                dispatch_ms = received_at.elapsed().as_millis(),
                global_inflight = guard.global_inflight,
                global_limit = MAX_CONCURRENT_AUDIT_RESPONSES,
                peer_inflight = guard.peer_inflight,
                peer_limit = class.per_peer_limit(),
                "Audit responder request admitted"
            );
            let worker_started = Instant::now();
            let processing_started = Instant::now();
            let response = ctx.my_commitment_state.lookup_by_hash(&request.pin).map_or(
                protocol::GetCommitmentByPinResponse::NotRetained { pin: request.pin },
                |built| protocol::GetCommitmentByPinResponse::Found {
                    commitment: built.commitment().clone(),
                },
            );
            let processing = processing_started.elapsed();
            let response_kind = commitment_pin_response_kind(&response);
            let response_send_started = Instant::now();
            let sent = send_replication_response_checked(
                source,
                &ctx.p2p_node,
                msg.request_id,
                ReplicationMessageBody::GetCommitmentByPinResponse(response),
                rr_message_id,
                None,
            )
            .await;
            let response_send = response_send_started.elapsed();
            log_audit_responder_completion(
                &ctx.audit_responder_metrics,
                *source,
                class,
                "commitment_pin",
                msg.request_id,
                1,
                response_kind,
                sent,
                received_at,
                worker_started,
                processing,
                response_send,
            );
            drop(guard);
            Ok(())
        }
        // Response messages are handled by their respective request initiators.
        ReplicationMessageBody::FreshReplicationResponse(_)
        | ReplicationMessageBody::NeighborSyncResponse(_)
        | ReplicationMessageBody::VerificationResponse(_)
        | ReplicationMessageBody::FetchResponse(_)
        | ReplicationMessageBody::AuditResponse(_)
        | ReplicationMessageBody::SubtreeAuditResponse(_)
        | ReplicationMessageBody::SubtreeSliceResponse(_)
        | ReplicationMessageBody::GetCommitmentByPinResponse(_) => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Per-message-type handlers
// ---------------------------------------------------------------------------

/// Verify a payment proof, yielding early if the engine is shutting down.
///
/// Returns `None` when shutdown won the race, meaning no verdict was reached
/// and the caller must abandon the message without storing or penalising.
///
/// Payment verification is pure network I/O — an EVM round trip and, on the
/// merkle path, an iterative Kademlia lookup bounded only by the verifier's
/// own `CLOSENESS_LOOKUP_TIMEOUT`. Racing it against the shutdown token is
/// what keeps `ReplicationEngine::shutdown()`'s deliberately unbounded
/// `detached_task_tracker.wait()` finite: the wait may block only on work that
/// is guaranteed to end.
///
/// Deliberately NOT applied to `storage.put`: that awaits `spawn_blocking`, so
/// dropping its awaiter would detach a live storage operation and break the
/// very contract the unbounded wait exists to uphold.
async fn verify_payment_until_shutdown(
    payment_verifier: &Arc<PaymentVerifier>,
    key: &XorName,
    proof_of_payment: &[u8],
    context: VerificationContext,
    shutdown: &CancellationToken,
) -> Option<Result<crate::payment::PaymentStatus>> {
    tokio::select! {
        () = shutdown.cancelled() => None,
        result = payment_verifier.verify_payment(key, Some(proof_of_payment), context) => {
            Some(result)
        }
    }
}

/// A fresh offer rejected on payload shape alone.
struct FreshOfferRejection {
    /// Wire-visible reason returned to the sender.
    reason: String,
    /// Whether the sender is charged for it. Reserved for offers no honest
    /// node would construct, so an ordinary capacity refusal stays free.
    penalise: bool,
}

/// Reject a fresh offer on payload shape, or return `None` to admit it.
///
/// Pure and non-blocking by construction: these are the checks answerable from
/// the payload alone, run on the serial message loop *before* the in-flight
/// claim and the admission permit, so a malformed offer can neither lock an
/// honest offer out of its key nor occupy one of the scarce
/// [`FRESH_OFFER_MAX_OUTSTANDING`] slots for the duration of a payment
/// verification. Anything needing I/O — routing lookups, capacity checks, proof
/// verification — stays on the worker.
///
/// The content-address hash is deliberately included despite costing real CPU
/// on the loop: it is what makes the entry below *earned* rather than merely
/// asserted. Its cost is self-limiting — BLAKE3 runs at GB/s while offers
/// arrive at link speed, so a flooder can never make this loop hash faster than
/// it can deliver the bytes, and delivering them already cost it more than the
/// hash costs us. The receive path has in any case already deserialised the
/// same buffer.
///
/// Every rejection here is penalised. These are the conditions no honest sender
/// can produce — an absent, undersized, oversized, or non-matching payload — as
/// distinct from a capacity refusal, which is this node's own state and stays
/// free. Payment *outcomes* are deliberately not judged here or anywhere: a
/// proof that fails to verify may simply have been read against a lagging chain
/// view, and penalising that would charge honest senders in correlated bursts.
fn fresh_offer_structural_rejection(
    key: &XorName,
    data: &[u8],
    proof_of_payment: &[u8],
) -> Option<FreshOfferRejection> {
    // Rule 5: reject if PoP is missing. An honest sender always attaches one,
    // and an absent proof is the cheapest possible slot-filler, so this is the
    // first thing checked.
    if proof_of_payment.is_empty() {
        return Some(FreshOfferRejection {
            reason: "Missing proof of payment".to_string(),
            penalise: true,
        });
    }

    // Bound the proof before it can be queued. The verifier applies the same
    // limits, but only once the offer reaches a worker — too late here, because
    // an entry retains a proof per queued sender, and a proof is capped on the
    // wire only by MAX_REPLICATION_MESSAGE_SIZE. Without this an offer carrying
    // a byte of data and a 10 MiB "proof" would be admitted, and
    // MAX_FRESH_OFFER_ATTEMPTS_PER_KEY of them per key across
    // FRESH_OFFER_MAX_OUTSTANDING keys would dwarf the payload ceiling the
    // admission bound exists to enforce.
    if proof_of_payment.len() < MIN_PAYMENT_PROOF_SIZE_BYTES {
        return Some(FreshOfferRejection {
            reason: format!(
                "Proof of payment {} is below the minimum {MIN_PAYMENT_PROOF_SIZE_BYTES} bytes",
                proof_of_payment.len(),
            ),
            penalise: true,
        });
    }
    if proof_of_payment.len() > MAX_PAYMENT_PROOF_SIZE_BYTES {
        return Some(FreshOfferRejection {
            reason: format!(
                "Proof of payment {} exceeds the maximum {MAX_PAYMENT_PROOF_SIZE_BYTES} bytes",
                proof_of_payment.len(),
            ),
            penalise: true,
        });
    }

    // Enforce chunk size invariant: the normal PUT path rejects data larger
    // than MAX_CHUNK_SIZE; the replication receive path must do the same to
    // prevent peers from pushing oversized records through replication.
    if data.len() > crate::ant_protocol::MAX_CHUNK_SIZE {
        return Some(FreshOfferRejection {
            reason: format!(
                "Data size {} exceeds maximum chunk size {}",
                data.len(),
                crate::ant_protocol::MAX_CHUNK_SIZE,
            ),
            penalise: true,
        });
    }

    // Mirror the normal PUT path: the advertised key must be the content
    // address of the supplied bytes. Ordered last so an oversized payload is
    // refused without being hashed.
    //
    // This is the check that makes the entry safe to open, and safe for later
    // offers to be folded into. Until it passes, the sender has only *asserted*
    // an association between the key and the bytes. Opening an entry on an
    // assertion would let any peer that knows a key — every recipient of its
    // `PaidNotify`, not just the close group — seize it with junk; folding a
    // later offer into an entry on an assertion would be worse still, since the
    // handler tries each queued proof against the *opener's* bytes and would be
    // storing bytes nobody offered for that proof.
    let computed_key = crate::client::compute_address(data);
    if computed_key != *key {
        return Some(FreshOfferRejection {
            reason: format!(
                "Content address mismatch: expected {}, computed {}",
                hex::encode(key),
                hex::encode(computed_key),
            ),
            penalise: true,
        });
    }

    None
}

/// Tell `source` its offer for `key` was not taken.
///
/// Note the sender does not currently read this: `fresh::replicate_fresh` uses
/// one-way `send_message`, so the refusal is observed only as a later absence by
/// the delayed possession check. Recorded in ADR-0005 as a known gap.
async fn refuse_fresh_offer(
    source: &PeerId,
    key: XorName,
    reason: String,
    ctx: &ReplicationMessageHandlerContext,
    request_id: u64,
    rr_message_id: Option<&str>,
) {
    send_replication_response(
        source,
        &ctx.p2p_node,
        request_id,
        ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
            key,
            reason,
        }),
        rr_message_id,
    )
    .await;
}

/// Refuse an offer that failed [`fresh_offer_structural_rejection`], charging
/// the sender when the defect is one no honest node could produce.
///
/// Kept apart from the capacity refusal in `dispatch_fresh_offer` because the
/// two say opposite things: this is the sender's fault, that one is ours.
async fn refuse_malformed_fresh_offer(
    source: &PeerId,
    key: XorName,
    rejection: FreshOfferRejection,
    ctx: &ReplicationMessageHandlerContext,
    request_id: u64,
    rr_message_id: Option<&str>,
) {
    if rejection.penalise {
        warn!(
            "Rejecting fresh offer for key {} from {source}: {}",
            hex::encode(key),
            rejection.reason
        );
        ctx.p2p_node
            .report_trust_event(
                source,
                TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
            )
            .await;
    } else {
        debug!(
            "Fresh offer for {} from {source} refused before admission: {}",
            hex::encode(key),
            rejection.reason
        );
    }
    refuse_fresh_offer(
        source,
        key,
        rejection.reason,
        ctx,
        request_id,
        rr_message_id,
    )
    .await;
}

/// Tell senders whose proofs joined an entry that was torn down before a handler
/// ever ran for it.
///
/// Only reachable in the window between opening an entry and failing to take an
/// admission permit. Their proofs are answered rather than dropped with the
/// entry, so the refusal count reflects what actually happened.
async fn refuse_stranded_fresh_offers(
    key: XorName,
    stranded: Vec<FreshOfferAttempt>,
    ctx: &ReplicationMessageHandlerContext,
) {
    for attempt in stranded {
        refuse_fresh_offer(
            &attempt.source,
            key,
            "Receiver at fresh-offer capacity".to_string(),
            ctx,
            attempt.request_id,
            attempt.rr_message_id.as_deref(),
        )
        .await;
    }
}

/// Admit a fresh offer for handling on a worker, or refuse it.
///
/// This runs on the serial non-audit message loop, so it must stay cheap: every
/// path here is a set insert, a permit try, or a small response send. The offer
/// itself — an on-chain payment verification and a multi-MiB write — always
/// runs on a tracked worker task, never inline, because stalling this loop backs
/// up the inbound queue and ultimately drops replication messages wholesale.
///
/// Admission is bounded **per source** as well as globally
/// ([`FRESH_OFFER_MAX_OUTSTANDING_PER_PEER`]). Without that share one peer can
/// hold every slot, and since a refusal is later read as absence by the
/// sender's delayed possession check, the resulting refusals land as
/// audit-severity penalties on this node rather than on the flooder.
///
/// The structurally-invalid checks run **before** the entry is opened and before
/// the permit is taken, so junk can neither seize a key nor occupy a slot for
/// the duration of a payment verification.
///
/// Only the offer that *opens* an entry costs a permit and a worker. Later
/// offers for the same key contribute their proof and are answered by whatever
/// the opener's handler concludes, which is what keeps the routine
/// `CLOSE_GROUP_MAJORITY`-way duplication of a client PUT down to one permit and
/// one verification per key.
async fn dispatch_fresh_offer(
    source: PeerId,
    offer: protocol::FreshReplicationOffer,
    ctx: &ReplicationMessageHandlerContext,
    request_id: u64,
    received_at: Instant,
    rr_message_id: Option<&str>,
) -> Result<()> {
    if let Some(rejection) =
        fresh_offer_structural_rejection(&offer.key, &offer.data, &offer.proof_of_payment)
    {
        refuse_malformed_fresh_offer(
            &source,
            offer.key,
            rejection,
            ctx,
            request_id,
            rr_message_id,
        )
        .await;
        return Ok(());
    }

    // Join the work already in flight for this key before taking an admission
    // permit, so the duplicates a single client PUT produces cost one permit
    // between them rather than one each.
    //
    // Reaching this point means `fresh_offer_structural_rejection` has confirmed
    // `key == BLAKE3(data)`, so this offer's bytes are provably identical to any
    // already held for the key. That is what lets its payload be dropped here
    // and only its proof retained: the handler will try that proof against the
    // bytes it already has.
    let key = offer.key;
    let admission_outcome = FreshOfferEntryGuard::admit(
        &ctx.fresh_offer_in_flight,
        offer,
        source,
        request_id,
        rr_message_id.map(ToOwned::to_owned),
        received_at,
    );
    let mut entry = match admission_outcome {
        FreshOfferAdmission::Opened(entry) => entry,
        FreshOfferAdmission::Joined => {
            // No response yet: this proof has not been judged. The handler that
            // owns the key answers every queued sender once it settles.
            debug!(
                "Fresh offer for {} from {source} queued behind the handler already \
                 holding the key",
                hex::encode(key)
            );
            return Ok(());
        }
        // Surplus, not suspect: the proofs already queued are enough to place
        // the record, so neither case is charged as misbehaviour.
        surplus => {
            debug!(
                "Fresh offer for {} from {source} refused: {}",
                hex::encode(key),
                surplus.surplus_reason()
            );
            refuse_fresh_offer(
                &source,
                key,
                "Duplicate offer already in flight".to_string(),
                ctx,
                request_id,
                rr_message_id,
            )
            .await;
            return Ok(());
        }
    };

    let admission = match admit_bounded_responder(
        &ctx.fresh_offer_admission_semaphore,
        &ctx.fresh_offer_responder_inflight,
        &source,
        FRESH_OFFER_MAX_OUTSTANDING,
        FRESH_OFFER_MAX_OUTSTANDING_PER_PEER,
    )
    .await
    {
        Ok(guard) => guard,
        Err(failure) => {
            audit_metrics::record_responder_admission_drop(
                ReplicationResponderClass::FreshOffer,
                failure.reason.into(),
            );
            // WARN, not DEBUG: a healthy node should never refuse a legitimate
            // fresh offer. The sender does not read this refusal, so it
            // resurfaces as a missing key at the delayed possession check and
            // is charged to US at audit severity. Log the binding ceiling
            // locally; the wire reason stays generic so a probing peer cannot
            // map out this node's live occupancy.
            warn!(
                responder_class = "fresh_offer",
                source = %source,
                key = %hex::encode(key),
                penalty_suspended = config::close_group_storage_penalty_suspended(),
                "Fresh offer refused at admission; the resulting absence is recorded \
                 against this node, and penalised unless the release withholds it: \
                 {failure}"
            );
            // Release the key explicitly rather than on drop, so the next offer
            // opens a fresh entry rather than queueing behind a handler that was
            // never spawned — and so any proof that joined in the window between
            // opening the entry and failing here is answered rather than
            // discarded with it.
            let stranded = entry.release();
            refuse_fresh_offer(
                &source,
                key,
                "Receiver at fresh-offer capacity".to_string(),
                ctx,
                request_id,
                rr_message_id,
            )
            .await;
            refuse_stranded_fresh_offers(key, stranded, ctx).await;
            return Ok(());
        }
    };

    let ctx = ctx.clone();
    // Track the worker so `ReplicationEngine::shutdown()` can await it: it holds
    // an `Arc<ChunkStore>` while writing, and the shutdown contract requires
    // those references be released before the caller reopens the environment.
    ctx.detached_task_tracker
        .clone()
        .spawn(run_fresh_offer_worker(key, entry, ctx, admission));
    Ok(())
}

/// Body of one tracked fresh-offer worker: drive one key to a verdict.
///
/// Split out so `dispatch_fresh_offer` stays a readable admission decision.
/// A started handler is never cancelled: `storage.put()` awaits
/// `spawn_blocking`, and dropping that awaiter would detach the live storage
/// transaction. Shutdown responsiveness comes from the closed worker semaphore
/// and from `handle_fresh_offer` racing the token around payment verification.
///
/// Works down the key's queued proofs rather than judging the key on the first
/// one. A proof that fails to establish payment disqualifies its *sender*, not
/// the record: the bytes are content-addressed and identical across every offer,
/// so the next sender's proof is tried against the copy already in hand — no
/// second payload, no second permit, no refetch. Only when a failure is about
/// the key itself (not responsible, no capacity, shutting down) does rotating
/// become pointless, because every remaining proof would meet the same wall.
async fn run_fresh_offer_worker(
    key: XorName,
    mut entry: Box<FreshOfferEntryGuard>,
    ctx: ReplicationMessageHandlerContext,
    admission: ResponderGuard,
) {
    // The admission permit is released on completion, freeing the payload's
    // memory budget and the opening source's per-peer share. The entry releases
    // the key itself, either as the queue empties or on drop.
    let _admission = admission;
    let received_at = entry.received_at();
    // Wait for a worker slot here rather than in the caller. The worker bound
    // caps concurrent EVM and storage pressure; making the message loop wait on
    // it is what put that pressure back on the loop.
    //
    // The semaphore is closed by `shutdown()`, so this arm is the prompt exit
    // path for offers still queued behind a worker when the engine stops — not
    // dead code.
    let Ok(_worker) = Arc::clone(&ctx.fresh_offer_worker_semaphore)
        .acquire_owned()
        .await
    else {
        debug!(
            "Fresh offer for {} dropped: worker pool shut down",
            hex::encode(key)
        );
        return;
    };
    // Fresh offers are fire-and-forget (`send_message`), so there is no
    // requester deadline to honour and a late store is still genuinely useful.
    // The threshold is the point past which the offer has already cost us what
    // it was going to cost: the possession check (ADR-0003) has run by then and
    // charged the absence to this node, and it does not re-offer the key —
    // repair comes later from neighbor sync. Shedding here trades a copy that
    // would have arrived after the penalty for the multi-MiB payload it is
    // holding, and keeps a backlog from outliving its own admission bound.
    //
    // Note this is a memory-pressure decision, not a redundancy one: the copy
    // is late, not useless, so on a node with headroom finishing it would still
    // beat waiting for neighbor sync.
    if request_is_stale(received_at, ctx.config.possession_check_delay_min) {
        debug!(
            responder_class = "fresh_offer",
            key = %hex::encode(key),
            request_age_ms = received_at.elapsed().as_millis(),
            "Superseded fresh offer shed at dequeue"
        );
        return;
    }

    let mut verdict = FreshOfferOutcome::Abandoned;
    while let Some(attempt) = entry.next_attempt() {
        match handle_fresh_offer(&key, entry.data(), &attempt, &ctx).await {
            Ok(outcome) => {
                verdict = outcome;
                match outcome {
                    // Settled: the record is down and every remaining sender
                    // wanted exactly that. Abandoned: the key cannot be placed
                    // by anyone right now, so the proofs behind this one would
                    // fail identically. Either way there is nothing left to try.
                    FreshOfferOutcome::Settled | FreshOfferOutcome::Abandoned => break,
                    // This sender's claim to have paid did not hold up. Say so
                    // to that sender alone and try the next proof.
                    FreshOfferOutcome::ProofRejected => {}
                }
            }
            Err(e) => {
                debug!(
                    "Fresh replication offer for {} from {} error: {e}",
                    hex::encode(key),
                    attempt.source
                );
                verdict = FreshOfferOutcome::Abandoned;
                break;
            }
        }
    }

    // Answer the senders whose proofs were never reached. A stored record is
    // what they were asking for, so it is an acceptance even though their own
    // proof went untested.
    let unreached = entry.release();
    if unreached.is_empty() {
        return;
    }
    let response = match verdict {
        FreshOfferOutcome::Settled => FreshReplicationResponse::Accepted { key },
        FreshOfferOutcome::ProofRejected | FreshOfferOutcome::Abandoned => {
            FreshReplicationResponse::Rejected {
                key,
                reason: "Record could not be stored from any offered proof".to_string(),
            }
        }
    };
    for attempt in unreached {
        send_replication_response(
            &attempt.source,
            &ctx.p2p_node,
            attempt.request_id,
            ReplicationMessageBody::FreshReplicationResponse(response.clone()),
            attempt.rr_message_id.as_deref(),
        )
        .await;
    }
}

/// What one proof concluded, and whether another proof for the same key is worth
/// trying.
///
/// The distinction the worker acts on is *what the failure was about*. A
/// rejected proof is a statement about its sender; anything else is a statement
/// about the key or this node, which no other sender's proof can change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FreshOfferOutcome {
    /// The record is stored. The key is done.
    Settled,
    /// This proof did not establish payment. A different sender's proof for the
    /// same bytes may still succeed.
    ProofRejected,
    /// Nothing about this key can succeed right now — not responsible, no disk,
    /// shutting down, or a write that failed. Rotating repeats the failure.
    Abandoned,
}

// A linear sequence of protocol steps — structural recheck, responsibility,
// capacity, payment, write — each with its own refusal response. Splitting it
// would scatter one decision across several functions.
#[allow(clippy::too_many_lines)]
async fn handle_fresh_offer(
    key: &XorName,
    data: &[u8],
    attempt: &FreshOfferAttempt,
    ctx: &ReplicationMessageHandlerContext,
) -> Result<FreshOfferOutcome> {
    let source = &attempt.source;
    let request_id = attempt.request_id;
    let rr_message_id = attempt.rr_message_id.as_deref();
    let p2p_node = &ctx.p2p_node;
    let config = &ctx.config;
    let self_id = *p2p_node.peer_id();

    // Defence in depth: `dispatch_fresh_offer` already applied these — missing
    // proof, bad proof size, oversized payload, content-address mismatch —
    // before opening the entry or taking an admission permit, so nothing
    // reaching a worker should trip them. Kept so the handler is correct in
    // isolation. Note this re-checks the *pairing* actually being used: these
    // bytes against this attempt's proof.
    if let Some(rejection) = fresh_offer_structural_rejection(key, data, &attempt.proof_of_payment)
    {
        if rejection.penalise {
            warn!(
                "Rejecting fresh offer for key {}: {}",
                hex::encode(key),
                rejection.reason
            );
            p2p_node
                .report_trust_event(
                    source,
                    TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                )
                .await;
        }
        send_replication_response(
            source,
            p2p_node,
            request_id,
            ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
                key: *key,
                reason: rejection.reason,
            }),
            rr_message_id,
        )
        .await;
        // Structurally invalid is a fact about this attempt, not the key.
        return Ok(FreshOfferOutcome::ProofRejected);
    }

    // Rule 7: check storage admission. Fresh chunk receivers accept across the
    // paid-close-group neighbourhood (`paid_list_close_group_size`, = K_BUCKET_SIZE,
    // the same width client PUTs use), not just the close group plus a small
    // margin (ADR-0003). During full-node shunning a healthy replica's routing
    // table may still list closer full nodes it hasn't evicted yet, ranking it
    // outside the narrow window in its own view; the wider accept window absorbs
    // that transient skew so the chunk still lands. Retention (pruning) stays at
    // `storage_admission_width`, so steady-state replication is unchanged.
    if !admission::is_responsible(&self_id, key, p2p_node, config.paid_list_close_group_size).await
    {
        send_replication_response(
            source,
            p2p_node,
            request_id,
            ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
                key: *key,
                reason: "Not in storage-admission range for this key".to_string(),
            }),
            rr_message_id,
        )
        .await;
        // About the key and this node's place in the routing table, not about
        // the sender: every queued proof would be refused identically.
        return Ok(FreshOfferOutcome::Abandoned);
    }

    // Disk-space pre-check — mirror the PUT handler (V2-411). A full node can
    // never store this record, so reject it before the expensive payment
    // verification (EVM on-chain query / merkle pool work) rather than verifying
    // and only then failing at `storage.put` below. Reuses the cached capacity
    // check (passing results only, so freed space is detected promptly), and the
    // store path keeps its own check as defence-in-depth.
    if let Err(e) = ctx.storage.check_capacity() {
        info!(
            target: "ant_node::storage::disk_precheck",
            key = %hex::encode(key),
            "Rejecting fresh replication offer before payment verification: {e}"
        );
        send_replication_response(
            source,
            p2p_node,
            request_id,
            ReplicationMessageBody::FreshReplicationResponse(FreshReplicationResponse::Rejected {
                key: *key,
                reason: e.to_string(),
            }),
            rr_message_id,
        )
        .await;
        // A full disk is this node's condition, not the sender's.
        return Ok(FreshOfferOutcome::Abandoned);
    }

    // Gap 1: Validate PoP via PaymentVerifier. Fresh replication is still
    // part of the immediate write fan-out: this receiver is about to store the
    // record as if the client had PUT it here directly. Storage admission
    // was checked above before proof work. FreshReplication verification is
    // identical to ClientPut — store-strength cache semantics, paid-quote
    // issuer K-closeness checks for single-node proofs, merkle candidate
    // closeness for merkle proofs, and the same price-floor policy — the
    // distinct context only labels price-floor telemetry.
    let Some(verification) = verify_payment_until_shutdown(
        &ctx.payment_verifier,
        key,
        &attempt.proof_of_payment,
        fresh_offer_payment_context(),
        &ctx.shutdown,
    )
    .await
    else {
        debug!(
            "Fresh offer for {} from {source} abandoned: engine shutting down \
             during payment verification",
            hex::encode(key)
        );
        return Ok(FreshOfferOutcome::Abandoned);
    };
    match verification {
        Ok(status) if status.can_store() => {
            debug!("PoP validated for fresh offer key {}", hex::encode(key));
        }
        // The chain has no record of this payment. That is a statement about
        // *this sender's* proof, so the key rotates to the next one rather than
        // being written off — the whole point of queueing them.
        //
        // Deliberately unpenalised. `PaymentRequired` means "no payment found",
        // not "definitively unpaid", so a lagging or reorganising chain view
        // renders honest senders indistinguishable from forgers, and penalising
        // would land on the entire close group at once. The structural checks in
        // `fresh_offer_structural_rejection` are where misbehaviour is charged,
        // because those cannot be produced by an honest sender at all.
        Ok(_) => {
            debug!(
                "Fresh offer for {} from {source}: no payment found for this proof",
                hex::encode(key)
            );
            send_replication_response(
                source,
                p2p_node,
                request_id,
                ReplicationMessageBody::FreshReplicationResponse(
                    FreshReplicationResponse::Rejected {
                        key: *key,
                        reason: "Payment verification failed: payment required".to_string(),
                    },
                ),
                rr_message_id,
            )
            .await;
            return Ok(FreshOfferOutcome::ProofRejected);
        }
        // A verification *error* is usually ours — an unreachable or failing EVM
        // endpoint — so it is neither penalised nor treated as this sender's
        // fault. Another proof still gets its turn, since the next call may well
        // succeed against a recovered endpoint.
        Err(e) => {
            warn!("PoP verification error for key {}: {e}", hex::encode(key));
            send_replication_response(
                source,
                p2p_node,
                request_id,
                ReplicationMessageBody::FreshReplicationResponse(
                    FreshReplicationResponse::Rejected {
                        key: *key,
                        reason: format!("Payment verification error: {e}"),
                    },
                ),
                rr_message_id,
            )
            .await;
            return Ok(FreshOfferOutcome::ProofRejected);
        }
    }

    // Rule 6: add to PaidForList.
    if let Err(e) = ctx.paid_list.insert(key).await {
        warn!("Failed to add key to PaidForList: {e}");
    }

    // Store the record.
    match ctx.storage.put(key, data).await {
        Ok(_) => {
            send_replication_response(
                source,
                p2p_node,
                request_id,
                ReplicationMessageBody::FreshReplicationResponse(
                    FreshReplicationResponse::Accepted { key: *key },
                ),
                rr_message_id,
            )
            .await;
            Ok(FreshOfferOutcome::Settled)
        }
        Err(e) => {
            send_replication_response(
                source,
                p2p_node,
                request_id,
                ReplicationMessageBody::FreshReplicationResponse(
                    FreshReplicationResponse::Rejected {
                        key: *key,
                        reason: e.to_string(),
                    },
                ),
                rr_message_id,
            )
            .await;
            // The payment was good and the write still failed, so this is local
            // storage trouble that another proof cannot get around.
            Ok(FreshOfferOutcome::Abandoned)
        }
    }
}

/// Admit a paid-list notification for handling on a worker, or drop it.
///
/// `PaidNotify` used to be handled inline on the serial non-audit loop, which
/// meant one message could park every other non-audit message behind a full
/// payment verification. That verification is not a bounded local computation:
/// on the merkle path it performs an iterative Kademlia lookup capped only by
/// the verifier's `CLOSENESS_LOOKUP_TIMEOUT`, so a single notify could stall
/// the loop for minutes while the bounded inbound queue behind it overflowed
/// and dropped unrelated replication traffic wholesale.
///
/// It now follows the same detached-responder pattern as neighbor sync and
/// verification (ADR-0005 decision 2): bounded globally and per source, shed
/// when stale, and run on a tracked worker.
///
/// `PaidNotify` is one-way — the protocol defines no response variant — so a
/// refused notify is simply dropped. The sender's own paid-list convergence
/// (periodic neighbor sync and the verification cycle's paid-list quorum) is
/// the recovery path, exactly as for a notify lost in transit.
async fn dispatch_paid_notify(
    source: PeerId,
    notify: protocol::PaidNotify,
    ctx: &ReplicationMessageHandlerContext,
    received_at: Instant,
) -> Result<()> {
    let admission = match admit_bounded_responder(
        &ctx.paid_notify_admission_semaphore,
        &ctx.paid_notify_responder_inflight,
        &source,
        PAID_NOTIFY_MAX_OUTSTANDING,
        PAID_NOTIFY_MAX_OUTSTANDING_PER_PEER,
    )
    .await
    {
        Ok(guard) => guard,
        Err(failure) => {
            audit_metrics::record_responder_admission_drop(
                ReplicationResponderClass::PaidNotify,
                failure.reason.into(),
            );
            // WARN for the same reason as fresh offers: PaidNotify is one-way,
            // so a refusal discards durable paid-list evidence outright rather
            // than pushing work back onto a requester.
            warn!(
                responder_class = "paid_notify",
                source = %source,
                key = %hex::encode(notify.key),
                "Paid notify dropped at admission — paid-list evidence lost                  until a verification cycle re-derives it: {failure}"
            );
            return Ok(());
        }
    };

    let ctx = ctx.clone();
    let worker_semaphore = Arc::clone(&ctx.paid_notify_worker_semaphore);
    // Deliberately NOT the verification request deadline used by the
    // request/response responders. Nobody is waiting on a notify, and shedding
    // one discards durable paid-list evidence rather than a reply a requester
    // has already given up on. The threshold is instead the point at which the
    // pull path would have learned the same fact anyway: one slow-cadence
    // neighbor-sync interval, after which the verification cycle's paid-list
    // quorum makes this notify genuinely redundant.
    let queue_max_age = ctx.config.neighbor_sync_interval_max;
    ctx.detached_task_tracker.clone().spawn(async move {
        let _admission = admission;
        // Closed by `shutdown()`, so this is the prompt exit path for notifies
        // still queued behind a worker when the engine stops.
        let Ok(_worker) = worker_semaphore.acquire_owned().await else {
            debug!("Paid notify from {source} dropped: worker pool shut down");
            return;
        };
        if request_is_stale(received_at, queue_max_age) {
            debug!(
                responder_class = "paid_notify",
                source = %source,
                request_age_ms = received_at.elapsed().as_millis(),
                "Redundant paid notify shed at dequeue"
            );
            return;
        }
        if let Err(e) = handle_paid_notify(
            &source,
            &notify,
            &ctx.paid_list,
            &ctx.payment_verifier,
            &ctx.p2p_node,
            &ctx.config,
            &ctx.shutdown,
        )
        .await
        {
            debug!("Paid notify from {source} error: {e}");
        }
    });

    Ok(())
}

async fn handle_paid_notify(
    _source: &PeerId,
    notify: &protocol::PaidNotify,
    paid_list: &Arc<PaidList>,
    payment_verifier: &Arc<PaymentVerifier>,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    shutdown: &CancellationToken,
) -> Result<()> {
    let self_id = *p2p_node.peer_id();

    // Rule 3: validate PoP presence before adding.
    if notify.proof_of_payment.is_empty() {
        return Ok(());
    }

    // Check if we're in PaidCloseGroup for this key.
    if !admission::is_in_paid_close_group(
        &self_id,
        &notify.key,
        p2p_node,
        config.paid_list_close_group_size,
    )
    .await
    {
        return Ok(());
    }

    // Gap 1: Validate PoP via PaymentVerifier. PaidNotify admits fresh
    // paid-list metadata, so local paid-list close-group membership was checked
    // above before proof work. The verifier then runs the same payment proof
    // checks as ClientPut while writing a paid-list-strength cache entry.
    let Some(verification) = verify_payment_until_shutdown(
        payment_verifier,
        &notify.key,
        &notify.proof_of_payment,
        paid_notify_payment_context(),
        shutdown,
    )
    .await
    else {
        debug!(
            "Paid notify for {} abandoned: engine shutting down during payment \
             verification",
            hex::encode(notify.key)
        );
        return Ok(());
    };
    match verification {
        Ok(status) if status.can_store() => {
            debug!(
                "PoP validated for paid notify key {}",
                hex::encode(notify.key)
            );
        }
        Ok(_) => {
            warn!(
                "Paid notify rejected: payment required for key {}",
                hex::encode(notify.key)
            );
            return Ok(());
        }
        Err(e) => {
            warn!(
                "PoP verification error for paid notify key {}: {e}",
                hex::encode(notify.key)
            );
            return Ok(());
        }
    }

    if let Err(e) = paid_list.insert(&notify.key).await {
        warn!("Failed to add paid notify key to PaidForList: {e}");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_neighbor_sync_request(
    source: PeerId,
    request: protocol::NeighborSyncRequest,
    ctx: &ReplicationMessageHandlerContext,
    is_bootstrapping: bool,
    my_commitment: Option<StorageCommitment>,
    request_id: u64,
    received_at: Instant,
    rr_message_id: Option<&str>,
) -> Result<()> {
    let guard = match admit_bounded_responder(
        &ctx.neighbor_sync_responder_admission_semaphore,
        &ctx.neighbor_sync_responder_inflight,
        &source,
        NEIGHBOR_SYNC_RESPONDER_MAX_OUTSTANDING,
        NEIGHBOR_SYNC_RESPONDER_MAX_OUTSTANDING_PER_PEER,
    )
    .await
    {
        Ok(guard) => guard,
        Err(failure) => {
            audit_metrics::record_responder_admission_drop(
                ReplicationResponderClass::NeighborSync,
                failure.reason.into(),
            );
            warn!(
                responder_class = "neighbor_sync",
                source = %source,
                "Neighbor-sync response dropped at admission: {failure}"
            );
            return Ok(());
        }
    };

    let worker_semaphore = Arc::clone(&ctx.neighbor_sync_responder_worker_semaphore);
    let p2p_node = Arc::clone(&ctx.p2p_node);
    let storage = Arc::clone(&ctx.storage);
    let paid_list = Arc::clone(&ctx.paid_list);
    let queues = Arc::clone(&ctx.queues);
    let config = Arc::clone(&ctx.config);
    let bootstrap_state = Arc::clone(&ctx.bootstrap_state);
    let sync_history = Arc::clone(&ctx.sync_history);
    let sync_cycle_epoch = Arc::clone(&ctx.sync_cycle_epoch);
    let repair_proofs = Arc::clone(&ctx.repair_proofs);
    let request_timeout = ctx.config.verification_request_timeout;
    let rr_message_id = rr_message_id.map(ToOwned::to_owned);
    ctx.detached_task_tracker.spawn(async move {
        let _guard = guard;
        let Ok(_worker_permit) = worker_semaphore.acquire_owned().await else {
            debug!(
                responder_class = "neighbor_sync",
                source = %source,
                "Neighbor-sync responder worker pool closed before dequeue"
            );
            return;
        };
        if request_is_stale(received_at, request_timeout) {
            audit_metrics::record_responder_staleness_shed(ReplicationResponderClass::NeighborSync);
            debug!(
                responder_class = "neighbor_sync",
                source = %source,
                request_age_ms = received_at.elapsed().as_millis(),
                "Stale neighbor-sync request shed at dequeue"
            );
            return;
        }
        if let Err(e) = handle_neighbor_sync_request(
            &source,
            &request,
            &p2p_node,
            &storage,
            &paid_list,
            &queues,
            &config,
            is_bootstrapping,
            &bootstrap_state,
            &sync_history,
            &sync_cycle_epoch,
            &repair_proofs,
            my_commitment,
            request_id,
            rr_message_id.as_deref(),
        )
        .await
        {
            debug!(source = %source, "Neighbor-sync request handling failed: {e}");
        }
    });

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_neighbor_sync_request(
    source: &PeerId,
    request: &protocol::NeighborSyncRequest,
    p2p_node: &Arc<P2PNode>,
    storage: &Arc<ChunkStore>,
    paid_list: &Arc<PaidList>,
    queues: &Arc<RwLock<ReplicationQueues>>,
    config: &ReplicationConfig,
    is_bootstrapping: bool,
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    sync_history: &Arc<RwLock<HashMap<PeerId, PeerSyncRecord>>>,
    sync_cycle_epoch: &Arc<RwLock<u64>>,
    repair_proofs: &Arc<RwLock<RepairProofs>>,
    my_commitment: Option<StorageCommitment>,
    request_id: u64,
    rr_message_id: Option<&str>,
) -> Result<()> {
    let self_id = *p2p_node.peer_id();

    // No per-request hint count limit: the wire message size limit
    // (MAX_REPLICATION_MESSAGE_SIZE) already caps the payload. Unlike audit
    // challenges, sync hints don't drive expensive computation — they just
    // enter the verification queue. A per-request limit here would break
    // bootstrap replication for newly-joined nodes with 0 stored chunks.

    // Build response (outbound hints).
    let (response, sent_replica_hints, sender_in_rt) =
        neighbor_sync::handle_sync_request_with_proofs(
            source,
            request,
            p2p_node,
            storage,
            paid_list,
            config,
            is_bootstrapping,
            my_commitment.clone(),
        )
        .await;

    // Send response.
    let response_sent = send_replication_response_checked(
        source,
        p2p_node,
        request_id,
        ReplicationMessageBody::NeighborSyncResponse(response),
        rr_message_id,
        None,
    )
    .await;

    // Process inbound hints only if sender is in LocalRT (Rule 4-6).
    if !sender_in_rt {
        return Ok(());
    }

    // Update sync history for this peer before recording repair proofs so a
    // same-tick audit cannot combine a fresh key proof with stale peer maturity.
    {
        let mut history = sync_history.write().await;
        let record = history.entry(*source).or_insert(PeerSyncRecord {
            last_sync: None,
            cycles_since_sync: 0,
        });
        record.last_sync = Some(Instant::now());
        record.cycles_since_sync = 0;
    }

    if response_sent && !request.bootstrapping {
        record_sent_replica_hints(source, &sent_replica_hints, repair_proofs, sync_cycle_epoch)
            .await;
    }

    // Admit inbound hints and queue for verification.
    let outcome = admit_and_queue_hints(
        &self_id,
        source,
        &request.replica_hints,
        &request.paid_hints,
        p2p_node,
        config,
        storage,
        paid_list,
        queues,
    )
    .await;

    // Track discovered keys for bootstrap drain detection so that hints
    // admitted via inbound sync requests are not missed. Capacity-rejected
    // hints keep this source on the "not yet drained" list until its next
    // sync re-admits them; a clean cycle clears the source.
    if is_bootstrapping {
        let live_discovered = outcome.discovered.clone();
        let outcomes = [(*source, outcome)];
        publish_bootstrap_admission_outcomes(bootstrap_state, &outcomes, &live_discovered).await;
    }

    Ok(())
}

/// Test-only record of who *sent* a verification request covering a watched key.
///
/// The capacity gate's entire effect is a request that is never sent, and a
/// request that was not sent leaves no production counter anywhere — not on the
/// sender, whose traffic counters are process-global and so cannot separate one
/// node of a single-process testnet from another, and not on the responder,
/// which simply never hears from it. Recording who asked is what lets a test
/// tell "held the key back" apart from "probed the close group, was refused at
/// the dial, and then held the key back", which are otherwise identical from the
/// queue's point of view.
///
/// Arming replaces the previous watch, so the outer map holds exactly the keys
/// the current test named, and each inner map holds at most one entry per node
/// in the process. Nothing is recorded until a test arms it, and the armed path
/// costs one read lock on the sending side.
///
/// Counting is per key because a node that cannot write legitimately keeps
/// sending verification requests for keys it has not yet authorized — that is
/// `PaidForList` convergence, which the gate leaves alone — so a per-peer total
/// would assert something untrue.
///
/// It counts *send attempts*, deliberately, recorded immediately before the wire
/// call. A responder sheds requests at admission and as stale, so a
/// receiver-side count would report zero for probes that were really sent, and
/// an assertion that this node asked nobody would pass on the strength of the
/// receiver dropping the question. It is not proof of delivery: a send that
/// fails immediately, with no route or during shutdown, is still counted.
///
/// `OnceLock` rather than `LazyLock`, which needs a newer Rust than this crate's
/// MSRV.
#[cfg(any(test, feature = "test-utils"))]
type VerificationWatch = HashMap<XorName, HashMap<PeerId, usize>>;

#[cfg(any(test, feature = "test-utils"))]
static VERIFICATION_WATCH: std::sync::OnceLock<std::sync::RwLock<VerificationWatch>> =
    std::sync::OnceLock::new();

#[cfg(any(test, feature = "test-utils"))]
fn verification_watch() -> &'static std::sync::RwLock<VerificationWatch> {
    VERIFICATION_WATCH.get_or_init(|| std::sync::RwLock::new(HashMap::new()))
}

/// Test-only: start counting verification requests for `keys`, from zero.
///
/// Replaces any previous watch rather than adding to it, so the map is bounded
/// by the keys of the test that armed it last and nothing accumulates across a
/// process running many tests.
#[cfg(any(test, feature = "test-utils"))]
pub fn watch_verification_requests_for_test(keys: &[XorName]) {
    if let Ok(mut watch) = verification_watch().write() {
        watch.clear();
        for key in keys {
            watch.insert(*key, HashMap::new());
        }
    }
}

/// Record that `requester` sent a verification request covering `keys`, for
/// whichever of them are watched. A poisoned lock is ignored rather than
/// propagated: this is observation for tests and must never change behaviour.
#[cfg(any(test, feature = "test-utils"))]
pub(crate) fn record_verification_request_sent(requester: &PeerId, keys: &[XorName]) {
    // Fast path under a read lock: with nothing watched — every production
    // build, and every test that did not ask — this is all the sender pays.
    match verification_watch().read() {
        Ok(watch) if watch.is_empty() => return,
        Ok(watch) if !keys.iter().any(|key| watch.contains_key(key)) => return,
        Ok(_) => {}
        Err(_) => return,
    }
    if let Ok(mut watch) = verification_watch().write() {
        for key in keys {
            if let Some(by_peer) = watch.get_mut(key) {
                *by_peer.entry(*requester).or_insert(0) += 1;
            }
        }
    }
}

/// Test-only: how many times `requester` has asked this process about `key`.
/// Zero unless the key was registered with `watch_verification_requests_for_test`.
#[cfg(any(test, feature = "test-utils"))]
#[must_use]
pub fn verification_requests_for_key_from_for_test(requester: &PeerId, key: &XorName) -> usize {
    verification_watch().read().map_or(0, |watch| {
        watch
            .get(key)
            .and_then(|by_peer| by_peer.get(requester))
            .copied()
            .unwrap_or(0)
    })
}

async fn handle_verification_request(
    source: &PeerId,
    request: &protocol::VerificationRequest,
    storage: &Arc<ChunkStore>,
    paid_list: &Arc<PaidList>,
    p2p_node: &Arc<P2PNode>,
    request_id: u64,
    rr_message_id: Option<&str>,
) -> Result<()> {
    #[derive(Clone, Copy)]
    enum CachedPaidLookup {
        NotChecked,
        Checked(Option<bool>),
    }

    #[derive(Clone, Copy)]
    struct CachedVerificationLookup {
        present: Option<bool>,
        paid: CachedPaidLookup,
    }

    if verification_request_exceeds_limit(request.keys.len()) {
        warn!(
            "Verification request from {source} has {} keys, exceeding max {MAX_INCOMING_VERIFICATION_KEYS}; rejecting batch",
            request.keys.len(),
        );
        send_verification_results(source, p2p_node, request_id, Vec::new(), rr_message_id).await;
        return Ok(());
    }

    let requested_keys = request.keys.as_slice();

    if request.paid_list_check_indices.len() > request.keys.len() {
        warn!(
            "Verification request from {source} has {} paid-list indices for {} keys; rejecting batch",
            request.paid_list_check_indices.len(),
            request.keys.len(),
        );
        send_verification_results(source, p2p_node, request_id, Vec::new(), rr_message_id).await;
        return Ok(());
    }

    let keys_len = u32::try_from(requested_keys.len()).unwrap_or(u32::MAX);
    let paid_check_set: HashSet<u32> = request
        .paid_list_check_indices
        .iter()
        .copied()
        .filter(|&idx| {
            if idx >= keys_len {
                warn!(
                    "Verification request from {source}: paid_list_check_index {idx} out of bounds (keys.len() = {})",
                    requested_keys.len(),
                );
                false
            } else {
                true
            }
        })
        .collect();

    let mut results = Vec::with_capacity(requested_keys.len());
    let mut lookup_cache: HashMap<XorName, CachedVerificationLookup> = HashMap::new();
    for (i, key) in requested_keys.iter().enumerate() {
        let needs_paid = paid_check_set.contains(&u32::try_from(i).unwrap_or(u32::MAX));
        let cached = lookup_cache.entry(*key).or_insert_with(|| {
            let present = match storage.exists(key) {
                Ok(present) => Some(present),
                Err(e) => {
                    warn!(
                        "Verification request from {source}: failed to check storage for {}: {e}",
                        hex::encode(key)
                    );
                    None
                }
            };
            CachedVerificationLookup {
                present,
                paid: CachedPaidLookup::NotChecked,
            }
        });

        if needs_paid && matches!(cached.paid, CachedPaidLookup::NotChecked) {
            cached.paid = CachedPaidLookup::Checked(match paid_list.contains(key) {
                Ok(paid) => Some(paid),
                Err(e) => {
                    warn!(
                        "Verification request from {source}: failed to check paid-list for {}: {e}",
                        hex::encode(key)
                    );
                    None
                }
            });
        }

        let paid = if needs_paid {
            match cached.paid {
                CachedPaidLookup::Checked(paid) => paid,
                CachedPaidLookup::NotChecked => None,
            }
        } else {
            None
        };

        if cached.present.is_none() && paid.is_none() {
            continue;
        }

        results.push(protocol::KeyVerificationResult {
            key: *key,
            present: cached.present.unwrap_or(false),
            paid,
        });
    }

    send_verification_results(source, p2p_node, request_id, results, rr_message_id).await;

    Ok(())
}

async fn dispatch_verification_request(
    source: PeerId,
    request: protocol::VerificationRequest,
    ctx: &ReplicationMessageHandlerContext,
    request_id: u64,
    received_at: Instant,
    rr_message_id: Option<&str>,
) -> Result<()> {
    let guard = match admit_bounded_responder(
        &ctx.verification_responder_admission_semaphore,
        &ctx.verification_responder_inflight,
        &source,
        VERIFICATION_RESPONDER_MAX_OUTSTANDING,
        VERIFICATION_RESPONDER_MAX_OUTSTANDING_PER_PEER,
    )
    .await
    {
        Ok(guard) => guard,
        Err(failure) => {
            audit_metrics::record_responder_admission_drop(
                ReplicationResponderClass::Verification,
                failure.reason.into(),
            );
            warn!(
                responder_class = "verification",
                source = %source,
                "Verification response dropped at admission: {failure}"
            );
            return Ok(());
        }
    };

    let worker_semaphore = Arc::clone(&ctx.verification_responder_worker_semaphore);
    let storage = Arc::clone(&ctx.storage);
    let paid_list = Arc::clone(&ctx.paid_list);
    let p2p_node = Arc::clone(&ctx.p2p_node);
    let request_timeout = ctx.config.verification_request_timeout;
    let rr_message_id = rr_message_id.map(ToOwned::to_owned);
    ctx.detached_task_tracker.spawn(async move {
        let _guard = guard;
        let Ok(_worker_permit) = worker_semaphore.acquire_owned().await else {
            debug!(
                responder_class = "verification",
                source = %source,
                "Verification responder worker pool closed before dequeue"
            );
            return;
        };
        if request_is_stale(received_at, request_timeout) {
            audit_metrics::record_responder_staleness_shed(ReplicationResponderClass::Verification);
            debug!(
                responder_class = "verification",
                source = %source,
                request_age_ms = received_at.elapsed().as_millis(),
                "Stale verification request shed at dequeue"
            );
            return;
        }
        if let Err(e) = handle_verification_request(
            &source,
            &request,
            &storage,
            &paid_list,
            &p2p_node,
            request_id,
            rr_message_id.as_deref(),
        )
        .await
        {
            debug!(source = %source, "Verification request handling failed: {e}");
        }
    });

    Ok(())
}

const fn verification_request_exceeds_limit(key_count: usize) -> bool {
    key_count > MAX_INCOMING_VERIFICATION_KEYS
}

async fn send_verification_results(
    source: &PeerId,
    p2p_node: &Arc<P2PNode>,
    request_id: u64,
    results: Vec<protocol::KeyVerificationResult>,
    rr_message_id: Option<&str>,
) {
    send_replication_response(
        source,
        p2p_node,
        request_id,
        ReplicationMessageBody::VerificationResponse(VerificationResponse { results }),
        rr_message_id,
    )
    .await;
}

async fn dispatch_fetch_request(
    source: PeerId,
    request: protocol::FetchRequest,
    ctx: &ReplicationMessageHandlerContext,
    request_id: u64,
    received_at: Instant,
    rr_message_id: Option<&str>,
) -> Result<()> {
    let guard = match admit_bounded_responder(
        &ctx.fetch_responder_admission_semaphore,
        &ctx.fetch_responder_inflight,
        &source,
        FETCH_RESPONDER_MAX_OUTSTANDING,
        FETCH_RESPONDER_MAX_OUTSTANDING_PER_PEER,
    )
    .await
    {
        Ok(guard) => guard,
        Err(failure) => {
            audit_metrics::record_responder_admission_drop(
                ReplicationResponderClass::Fetch,
                failure.reason.into(),
            );
            warn!(
                responder_class = "fetch",
                source = %source,
                "Fetch response dropped at admission: {failure}"
            );
            return Ok(());
        }
    };

    let worker_semaphore = Arc::clone(&ctx.fetch_responder_worker_semaphore);
    let storage = Arc::clone(&ctx.storage);
    let p2p_node = Arc::clone(&ctx.p2p_node);
    let request_timeout = ctx.config.fetch_request_timeout;
    let rr_message_id = rr_message_id.map(ToOwned::to_owned);
    ctx.detached_task_tracker.spawn(async move {
        let _guard = guard;
        let Ok(_worker_permit) = worker_semaphore.acquire_owned().await else {
            debug!(
                responder_class = "fetch",
                source = %source,
                "Fetch responder worker pool closed before dequeue"
            );
            return;
        };
        if request_is_stale(received_at, request_timeout) {
            audit_metrics::record_responder_staleness_shed(ReplicationResponderClass::Fetch);
            debug!(
                responder_class = "fetch",
                source = %source,
                request_age_ms = received_at.elapsed().as_millis(),
                "Stale fetch request shed at dequeue"
            );
            return;
        }
        if let Err(e) = handle_fetch_request(
            &source,
            &request,
            &storage,
            &p2p_node,
            request_id,
            rr_message_id.as_deref(),
        )
        .await
        {
            debug!(source = %source, "Fetch request handling failed: {e}");
        }
    });

    Ok(())
}

fn request_is_stale(received_at: Instant, timeout: Duration) -> bool {
    received_at.elapsed() >= timeout
}

/// How a fetch responder's answer is charged against its reputation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchFault {
    /// The peer does not hold a chunk it was expected to hold.
    ///
    /// This was the lane the migration releases withheld, because a node part-way through
    /// moving off the old store answered exactly this way about chunks it had legitimately
    /// given up. That is over, and it is penalised again.
    UnheldChunk,
    /// The peer's own storage failed, or served bytes that no longer hash to their
    /// address.
    ///
    /// Never withheld. `FetchResponse::Error` has one producer, and it is the responder's
    /// storage read returning an error: an I/O fault, an exhausted descriptor table, or a
    /// failed integrity check. A peer that merely does not hold the chunk answers
    /// `NotFound` instead, so nothing about the migration produces this.
    ResponderFault,
}

/// Classify a fetch response that did not carry the chunk.
///
/// `Success` yields `None`. Every other answer is a fault of one kind or the other, and
/// which kind decides whether this release charges for it.
fn fetch_fault_for(response: &protocol::FetchResponse) -> Option<FetchFault> {
    match response {
        protocol::FetchResponse::Success { .. } => None,
        protocol::FetchResponse::NotFound { .. } => Some(FetchFault::UnheldChunk),
        protocol::FetchResponse::Error { .. } => Some(FetchFault::ResponderFault),
    }
}

/// Charge a fetch fault to the responder.
///
/// The only place the two kinds are treated differently. An unheld chunk goes through the
/// release switch, which is currently withholding it; a responder fault is charged
/// directly and is not affected by the switch at all.
async fn charge_fetch_fault(
    p2p_node: &Arc<P2PNode>,
    source: &PeerId,
    fault: FetchFault,
    lane: &'static str,
) {
    match fault {
        FetchFault::UnheldChunk => {
            config::penalise_unheld_close_group_chunk(
                p2p_node,
                source,
                lane,
                REPLICATION_TRUST_WEIGHT,
            )
            .await;
        }
        FetchFault::ResponderFault => {
            p2p_node
                .report_trust_event(
                    source,
                    TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                )
                .await;
        }
    }
}

/// Turn the responder's storage read into the answer it sends back.
///
/// The whole distinction the fetch lanes rest on is made here. A key this node does not
/// hold reads as `Ok(None)` and is answered `NotFound`. A read that fails, from an I/O
/// fault, an exhausted descriptor table, or a failed integrity check, is answered `Error`.
/// Nothing about a node giving chunks up produces the second.
fn fetch_response_for(key: XorName, read: Result<Option<Vec<u8>>>) -> protocol::FetchResponse {
    match read {
        Ok(Some(data)) => protocol::FetchResponse::Success { key, data },
        Ok(None) => protocol::FetchResponse::NotFound { key },
        Err(e) => protocol::FetchResponse::Error {
            key,
            reason: format!("{e}"),
        },
    }
}

async fn handle_fetch_request(
    source: &PeerId,
    request: &protocol::FetchRequest,
    storage: &Arc<ChunkStore>,
    p2p_node: &Arc<P2PNode>,
    request_id: u64,
    rr_message_id: Option<&str>,
) -> Result<()> {
    let response = fetch_response_for(request.key, storage.get(&request.key).await);

    send_replication_response(
        source,
        p2p_node,
        request_id,
        ReplicationMessageBody::FetchResponse(response),
        rr_message_id,
    )
    .await;

    Ok(())
}

/// Responder for an incoming `AuditChallenge` (responsible-chunk audit #2, and
/// the prune-confirmation audit, which reuses the same wire message): reply with
/// per-key possession digests.
struct AuditResponderCompletion {
    response_kind: &'static str,
    sent: bool,
    processing: Duration,
    response_send: Duration,
}

async fn handle_audit_challenge_msg(
    source: &PeerId,
    challenge: &protocol::AuditChallenge,
    storage: &Arc<ChunkStore>,
    p2p_node: &Arc<P2PNode>,
    is_bootstrapping: bool,
    reply: ReplyRoute<'_>,
) -> Result<AuditResponderCompletion> {
    #[allow(clippy::cast_possible_truncation)]
    let stored_chunks = storage.current_chunks().map_or(0, |c| c as usize);
    info!(
        "Audit challenge received: kind=responsible keys={} bootstrapping={} request_response={}",
        challenge.keys.len(),
        is_bootstrapping,
        reply.rr_message_id.is_some(),
    );

    let processing_started = Instant::now();
    let response = audit::handle_audit_challenge(
        challenge,
        storage,
        p2p_node.peer_id(),
        is_bootstrapping,
        stored_chunks,
    )
    .await;
    let processing = processing_started.elapsed();
    let response_kind = audit_response_kind(&response);

    let response_send_started = Instant::now();
    let sent = send_replication_response_checked(
        source,
        p2p_node,
        reply.request_id,
        ReplicationMessageBody::AuditResponse(response),
        reply.rr_message_id,
        Some(reply.protocol),
    )
    .await;
    let response_send = response_send_started.elapsed();

    Ok(AuditResponderCompletion {
        response_kind,
        sent,
        processing,
        response_send,
    })
}

#[allow(clippy::too_many_arguments)]
fn log_audit_responder_completion(
    metrics: &AuditResponderMetrics,
    source: PeerId,
    class: AuditResponderClass,
    kind: &'static str,
    challenge_id: u64,
    work_items: usize,
    response_kind: &'static str,
    sent: bool,
    received_at: Instant,
    worker_started: Instant,
    processing: Duration,
    response_send: Duration,
) {
    let dispatch = worker_started.saturating_duration_since(received_at);
    let total = received_at.elapsed();
    metrics.record_completed(source, processing, total, sent);
    if sent {
        info!(
            target: "ant_node::replication::audit_responder",
            event = "completed",
            kind,
            responder_class = class.as_str(),
            source = %source,
            challenge_id,
            work_items,
            response = response_kind,
            sent,
            dispatch_ms = dispatch.as_millis(),
            processing_ms = processing.as_millis(),
            response_send_ms = response_send.as_millis(),
            total_ms = total.as_millis(),
            "Audit responder request completed"
        );
    } else {
        warn!(
            target: "ant_node::replication::audit_responder",
            event = "completed",
            kind,
            responder_class = class.as_str(),
            source = %source,
            challenge_id,
            work_items,
            response = response_kind,
            sent,
            dispatch_ms = dispatch.as_millis(),
            processing_ms = processing.as_millis(),
            response_send_ms = response_send.as_millis(),
            total_ms = total.as_millis(),
            "Audit responder request completed without sending a reply"
        );
    }
}

/// Where a reply goes and how it is addressed.
///
/// Grouped because the audit responder needs all three together and one of them
/// is not derivable from the body: during the rollout window a possession reply
/// may have to go out on the core id rather than its family's own (see
/// [`is_legacy_possession_challenge`]).
struct ReplyRoute<'a> {
    /// Correlates the reply with the challenge, at the replication layer.
    request_id: u64,
    /// Present when the challenge arrived over request-response, in which case
    /// the reply rides the same exchange back.
    rr_message_id: Option<&'a str>,
    /// The protocol id to answer on.
    protocol: &'static str,
}

fn audit_response_kind(response: &protocol::AuditResponse) -> &'static str {
    match response {
        protocol::AuditResponse::Digests { .. } => "digests",
        protocol::AuditResponse::Bootstrapping { .. } => "bootstrapping",
        protocol::AuditResponse::Rejected { .. } => "rejected",
    }
}

fn subtree_audit_response_kind(response: &protocol::SubtreeAuditResponse) -> &'static str {
    match response {
        protocol::SubtreeAuditResponse::Proof { .. } => "proof",
        protocol::SubtreeAuditResponse::Bootstrapping { .. } => "bootstrapping",
        protocol::SubtreeAuditResponse::Rejected { .. } => "rejected",
    }
}

fn subtree_audit_response_work_items(response: &protocol::SubtreeAuditResponse) -> usize {
    match response {
        protocol::SubtreeAuditResponse::Proof { proof, .. } => proof.leaves.len(),
        protocol::SubtreeAuditResponse::Bootstrapping { .. }
        | protocol::SubtreeAuditResponse::Rejected { .. } => 0,
    }
}

fn subtree_slice_response_kind(response: &protocol::SubtreeSliceResponse) -> &'static str {
    match response {
        protocol::SubtreeSliceResponse::Items { .. } => "items",
        protocol::SubtreeSliceResponse::Bootstrapping { .. } => "bootstrapping",
        protocol::SubtreeSliceResponse::Rejected { .. } => "rejected",
    }
}

fn commitment_pin_response_kind(response: &protocol::GetCommitmentByPinResponse) -> &'static str {
    match response {
        protocol::GetCommitmentByPinResponse::Found { .. } => "found",
        protocol::GetCommitmentByPinResponse::NotRetained { .. } => "not_retained",
    }
}

// ---------------------------------------------------------------------------
// Message sending helper
// ---------------------------------------------------------------------------

/// Send a replication response message as a best-effort reply.
///
/// Encode and send failures are logged by the checked helper. Most response
/// paths do not need to branch on send success, so this wrapper keeps those
/// call sites explicit about their best-effort behavior.
async fn send_replication_response(
    peer: &PeerId,
    p2p_node: &Arc<P2PNode>,
    request_id: u64,
    body: ReplicationMessageBody,
    rr_message_id: Option<&str>,
) {
    let _ =
        send_replication_response_checked(peer, p2p_node, request_id, body, rr_message_id, None)
            .await;
}

/// Send a replication response message and report whether it was accepted.
///
/// Returns `true` after the message is encoded and accepted by the P2P send
/// path. Returns `false` after logging an encode or send failure. Repair-proof
/// recording uses this to avoid trusting hints that were not actually sent.
///
/// When `rr_message_id` is `Some`, the response is sent via the `/rr/`
/// request-response path so saorsa-core can route it back to the caller's
/// `send_request` future. Otherwise it is sent as a plain message.
///
/// `protocol` overrides the id the body would route on by family. Exactly one
/// caller needs it: a possession challenge from a peer that predates the family
/// split has to be answered where it was asked (see
/// [`is_legacy_possession_challenge`]). Everything else passes `None` and gets
/// [`response_protocol_for`], which is what keeps send and receive symmetric.
async fn send_replication_response_checked(
    peer: &PeerId,
    p2p_node: &Arc<P2PNode>,
    request_id: u64,
    body: ReplicationMessageBody,
    rr_message_id: Option<&str>,
    protocol: Option<&'static str>,
) -> bool {
    let msg = ReplicationMessage { request_id, body };
    let encoded = match msg.encode() {
        Ok(data) => data,
        Err(e) => {
            warn!("Failed to encode replication response: {e}");
            return false;
        }
    };
    // V2-684: per-peer served-bytes attribution for the heavy serve paths.
    // `FetchResponse` carries ~99% of served bytes; `NeighborSyncResponse` is
    // included for completeness. Other response variants (verification/audit/
    // commitment) are intentionally excluded — the round-2 audit reply is now a
    // few-KB verified slice (V2-685), not a full-chunk transfer, so it is light.
    if matches!(
        msg.body,
        ReplicationMessageBody::FetchResponse(_) | ReplicationMessageBody::NeighborSyncResponse(_)
    ) {
        protocol::record_served(peer, encoded.len());
    }
    let protocol = protocol.unwrap_or_else(|| response_protocol_for(&msg.body));
    let result = if let Some(msg_id) = rr_message_id {
        p2p_node
            .send_response(peer, protocol, msg_id, encoded)
            .await
    } else {
        p2p_node.send_message(peer, protocol, encoded, &[]).await
    };
    if let Err(e) = result {
        debug!("Failed to send replication response to {peer}: {e}");
        return false;
    }
    true
}

async fn record_sent_replica_hints(
    peer: &PeerId,
    hints: &[neighbor_sync::SentReplicaHint],
    repair_proofs: &Arc<RwLock<RepairProofs>>,
    sync_cycle_epoch: &Arc<RwLock<u64>>,
) {
    if hints.is_empty() {
        return;
    }

    let hinted_at_epoch = *sync_cycle_epoch.read().await;
    let mut proofs = repair_proofs.write().await;
    for hint in hints {
        if proofs.record_replica_hint_sent(*peer, hint.key, &hint.close_peers, hinted_at_epoch) {
            debug!(
                "Recorded repair hint proof for peer {peer} and key {}",
                hex::encode(hint.key)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Neighbor sync round
// ---------------------------------------------------------------------------

/// Run one neighbor sync round.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_neighbor_sync_round(
    p2p_node: &Arc<P2PNode>,
    storage: &Arc<ChunkStore>,
    paid_list: &Arc<PaidList>,
    queues: &Arc<RwLock<ReplicationQueues>>,
    config: &ReplicationConfig,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    sync_history: &Arc<RwLock<HashMap<PeerId, PeerSyncRecord>>>,
    sync_cycle_epoch: &Arc<RwLock<u64>>,
    repair_proofs: &Arc<RwLock<RepairProofs>>,
    is_bootstrapping: &Arc<RwLock<bool>>,
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    commitment_state: &Arc<ResponderCommitmentState>,
    last_commitment_by_peer: &Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    ever_capable_peers: &Arc<RwLock<HashSet<PeerId>>>,
    sig_verify_attempts: &Arc<RwLock<HashMap<PeerId, Instant>>>,
    audit_challenge_coordinator: &Arc<AuditChallengeCoordinator>,
    gossip_audit: &GossipAuditTrigger,
) {
    let self_id = *p2p_node.peer_id();
    let bootstrapping = *is_bootstrapping.read().await;

    // Check if cycle is complete; start new one if needed.
    // We check under a read lock, then release it before the expensive
    // prune pass and DHT snapshot so other tasks are not starved.
    let cycle_complete = sync_state.read().await.is_cycle_complete();
    if cycle_complete {
        // A completed local neighbor-sync cycle advances the epoch component
        // of repair-proof maturity. The per-key wall-clock minimum age is
        // checked when audits are selected.
        {
            let mut history = sync_history.write().await;
            for record in history.values_mut() {
                record.cycles_since_sync = record.cycles_since_sync.saturating_add(1);
            }
        }
        {
            let mut epoch = sync_cycle_epoch.write().await;
            *epoch = epoch.saturating_add(1);
        }

        // Post-cycle pruning (Section 11) — runs without holding sync_state.
        // Prune candidacy is unconditional once the hysteresis elapses;
        // bootstrap state only defers the remote prune-confirmation audits
        // until bootstrap has drained.
        let allow_remote_prune_audits = !bootstrapping && bootstrap_state.read().await.is_drained();
        pruning::run_prune_pass_with_context(pruning::PrunePassContext {
            self_id: &self_id,
            storage,
            paid_list,
            p2p_node,
            config,
            sync_state,
            repair_proofs,
            allow_remote_prune_audits,
            commitment_state: Some(commitment_state),
            audit_challenge_coordinator,
        })
        .await;

        // Take fresh close-neighbor snapshot (DHT query, no lock held).
        let neighbors =
            neighbor_sync::snapshot_close_neighbors(p2p_node, &self_id, config.neighbor_sync_scope)
                .await;

        // Now re-acquire write lock and re-check before swapping cycle.
        let mut state = sync_state.write().await;
        if state.is_cycle_complete() {
            // Preserve cooldown and bootstrap-claim tracking across cycles.
            // Claims have a 24h lifecycle vs 10-20 min cycles — dropping them
            // would reset the abuse detection timer every cycle.
            let old_sync_times = std::mem::take(&mut state.last_sync_times);
            let old_bootstrap_claims = std::mem::take(&mut state.bootstrap_claims);
            let old_bootstrap_claim_history = std::mem::take(&mut state.bootstrap_claim_history);
            let old_prune_cursor = state.prune_cursor;
            *state = NeighborSyncState::new_cycle(neighbors);
            state.last_sync_times = old_sync_times;
            state.bootstrap_claims = old_bootstrap_claims;
            state.bootstrap_claim_history = old_bootstrap_claim_history;
            state.prune_cursor = old_prune_cursor;
        }
    }

    // Select batch of peers.
    let batch = {
        let mut state = sync_state.write().await;
        neighbor_sync::select_sync_batch(
            &mut state,
            config.neighbor_sync_peer_count,
            config.neighbor_sync_cooldown,
        )
    };

    if batch.is_empty() {
        return;
    }

    debug!("Neighbor sync: syncing with {} peers", batch.len());

    // Snapshot our current commitment once per round so all peers in
    // this batch see the same thing (gossip is the responder's attestation;
    // same value across the batch is fine and reduces RwLock churn). Atomically
    // snapshot + mark-gossiped so we stay answerable for exactly what we emit
    // (ADR-0002 retention), with no TOCTOU vs a concurrent retire/rotate.
    let gossiped = commitment_state.current_for_gossip();
    // The hash actually put on the wire, captured with the payload. A rotation later in
    // the round must not let a reply be credited to a root the peer never saw.
    let gossiped_hash = gossiped.as_ref().map(|b| b.hash());
    let my_commitment = gossiped.map(|b| b.commitment().clone());

    let mut hints_by_peer = neighbor_sync::build_sync_hints_for_peers(
        &batch,
        storage,
        paid_list,
        p2p_node,
        config.close_group_size,
        config.paid_list_close_group_size,
    )
    .await;

    // Sync with each peer in the batch.
    for peer in &batch {
        let hints = hints_by_peer.remove(peer).unwrap_or_default();
        let outcome = neighbor_sync::sync_with_peer_with_hints(
            peer,
            p2p_node,
            config,
            bootstrapping,
            hints,
            my_commitment.clone(),
        )
        .await;

        if let Some(outcome) = outcome {
            // The peer answered, so the request that carried our commitment root arrived.
            // That is proof of delivery rather than proof of emission, and the storage
            // migration will not let a node give anything up until its close group has
            // actually seen the reduced root.
            if let Some(hash) = gossiped_hash {
                commitment_state.note_commitment_delivered(*peer, hash);
            }
            handle_sync_response(
                &self_id,
                peer,
                &outcome.response,
                &outcome.sent_replica_hints,
                p2p_node,
                config,
                bootstrapping,
                bootstrap_state,
                storage,
                paid_list,
                queues,
                sync_state,
                sync_history,
                sync_cycle_epoch,
                repair_proofs,
                last_commitment_by_peer,
                ever_capable_peers,
                sig_verify_attempts,
                gossip_audit,
            )
            .await;
        } else {
            // Sync failed -- remove peer and try to fill slot.
            let replacement = {
                let mut state = sync_state.write().await;
                neighbor_sync::handle_sync_failure(&mut state, peer, config.neighbor_sync_cooldown)
            };

            // Attempt sync with the replacement peer (if one was found).
            if let Some(replacement_peer) = replacement {
                let mut replacement_hints = neighbor_sync::build_sync_hints_for_peers(
                    std::slice::from_ref(&replacement_peer),
                    storage,
                    paid_list,
                    p2p_node,
                    config.close_group_size,
                    config.paid_list_close_group_size,
                )
                .await;
                let hints = replacement_hints
                    .remove(&replacement_peer)
                    .unwrap_or_default();
                let replacement_outcome = neighbor_sync::sync_with_peer_with_hints(
                    &replacement_peer,
                    p2p_node,
                    config,
                    bootstrapping,
                    hints,
                    my_commitment.clone(),
                )
                .await;

                if let Some(outcome) = replacement_outcome {
                    // Same payload, same round trip, same proof: a reply can only come
                    // back if the request carrying the root reached this peer. Omitting it
                    // here made the counter under-report on any node whose primary syncs
                    // often fall through to a replacement, which is exactly the node most
                    // likely to be short of disk, and stalled its migration indefinitely.
                    if let Some(hash) = gossiped_hash {
                        commitment_state.note_commitment_delivered(replacement_peer, hash);
                    }
                    handle_sync_response(
                        &self_id,
                        &replacement_peer,
                        &outcome.response,
                        &outcome.sent_replica_hints,
                        p2p_node,
                        config,
                        bootstrapping,
                        bootstrap_state,
                        storage,
                        paid_list,
                        queues,
                        sync_state,
                        sync_history,
                        sync_cycle_epoch,
                        repair_proofs,
                        last_commitment_by_peer,
                        ever_capable_peers,
                        sig_verify_attempts,
                        gossip_audit,
                    )
                    .await;
                }
            }
        }
    }
}

/// Process a successful neighbor sync response: record the sync, check for
/// bootstrap claim abuse, and admit inbound hints.
#[allow(clippy::too_many_arguments)]
async fn handle_sync_response(
    self_id: &PeerId,
    peer: &PeerId,
    resp: &NeighborSyncResponse,
    sent_replica_hints: &[neighbor_sync::SentReplicaHint],
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    bootstrapping: bool,
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    storage: &Arc<ChunkStore>,
    paid_list: &Arc<PaidList>,
    queues: &Arc<RwLock<ReplicationQueues>>,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    sync_history: &Arc<RwLock<HashMap<PeerId, PeerSyncRecord>>>,
    sync_cycle_epoch: &Arc<RwLock<u64>>,
    repair_proofs: &Arc<RwLock<RepairProofs>>,
    last_commitment_by_peer: &Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    ever_capable_peers: &Arc<RwLock<HashSet<PeerId>>>,
    sig_verify_attempts: &Arc<RwLock<HashMap<PeerId, Instant>>>,
    gossip_audit: &GossipAuditTrigger,
) {
    // Ingest the peer's commitment if they piggybacked one on the response.
    // Same verification as the request path (peer-id binding + signature);
    // forged commitments are dropped at the edge. A *changed* commitment here
    // is a gossip-audit trigger just like on the request path — so a peer that
    // only ever answers sync (never initiates) is still audited (ADR-0002).
    if let Some(target) = ingest_peer_commitment(
        peer,
        resp.commitment.as_ref(),
        p2p_node,
        last_commitment_by_peer,
        ever_capable_peers,
        sig_verify_attempts,
    )
    .await
    {
        maybe_trigger_gossip_audit(gossip_audit, peer, target).await;
    }

    // Record successful sync.
    {
        let mut state = sync_state.write().await;
        neighbor_sync::record_successful_sync(&mut state, peer);
    }
    {
        let mut history = sync_history.write().await;
        let record = history.entry(*peer).or_insert(PeerSyncRecord {
            last_sync: None,
            cycles_since_sync: 0,
        });
        record.last_sync = Some(Instant::now());
        record.cycles_since_sync = 0;
    }

    // Process inbound hints from response (skip if peer is bootstrapping).
    if resp.bootstrapping {
        // Gap 6: BootstrapClaimAbuse grace period enforcement.
        // Separate state mutation from network I/O to avoid holding the
        // write lock across report_trust_event.
        let should_report = {
            let now = Instant::now();
            let mut state = sync_state.write().await;
            match state.observe_bootstrap_claim(*peer, now, config.bootstrap_claim_grace_period) {
                BootstrapClaimObservation::WithinGrace { .. } => false,
                BootstrapClaimObservation::PastGrace { first_seen } => {
                    warn!(
                        "Peer {peer} has been claiming bootstrap for {:?}, \
                         exceeding grace period of {:?} — reporting abuse",
                        now.duration_since(first_seen),
                        config.bootstrap_claim_grace_period,
                    );
                    true
                }
                BootstrapClaimObservation::Repeated { first_seen } => {
                    warn!(
                        "Peer {peer} repeated bootstrap claim after previously stopping; \
                         first claim was {:?} ago — reporting abuse",
                        now.duration_since(first_seen),
                    );
                    true
                }
            }
        };
        if should_report {
            p2p_node
                .report_trust_event(
                    peer,
                    TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                )
                .await;
        }
    } else {
        // Peer is not claiming bootstrap; clear active claim while retaining
        // history so the peer cannot start a second grace window later.
        {
            let mut state = sync_state.write().await;
            state.clear_active_bootstrap_claim(peer);
        }
        record_sent_replica_hints(peer, sent_replica_hints, repair_proofs, sync_cycle_epoch).await;
        let outcome = admit_and_queue_hints(
            self_id,
            peer,
            &resp.replica_hints,
            &resp.paid_hints,
            p2p_node,
            config,
            storage,
            paid_list,
            queues,
        )
        .await;

        // Track discovered keys for bootstrap drain detection so that hints
        // admitted via regular neighbor sync are not missed. Capacity-
        // rejected hints keep this source on the "not yet drained" list
        // until its next sync replays them; a clean cycle clears it.
        if bootstrapping {
            let live_discovered = outcome.discovered.clone();
            let outcomes = [(*peer, outcome)];
            publish_bootstrap_admission_outcomes(bootstrap_state, &outcomes, &live_discovered)
                .await;
        }
    }
}

/// Admit hints and queue them for verification, returning newly-discovered keys.
///
/// Shared by neighbor-sync request handling, response handling, and bootstrap
/// sync so that admission + queueing logic lives in one place.
#[allow(clippy::too_many_arguments)]
/// Outcome of [`admit_and_queue_hints`].
///
/// `capacity_rejected_count` tracks incoming hints for which no fair slot was
/// available; that source is kept outstanding until it re-hints. `displaced`
/// tracks older borrowed hints reclaimed for another sender; only the key is
/// dropped from bootstrap tracking — the former owner's standing is untouched
/// (see [`publish_bootstrap_admission_outcomes`]).
struct AdmissionOutcome {
    discovered: HashSet<XorName>,
    capacity_rejected_count: usize,
    displaced: Vec<CapacityDisplacement>,
}

/// Publish one atomic admission unit into bootstrap drain accounting.
///
/// Only sources that were themselves capacity-rejected are kept outstanding.
/// A fairness displacement forfeits the displaced *key* but never stamps its
/// former owner: reclaiming a borrowed slot is this node's own fairness
/// decision, so charging it to the victim would let a sustained flooder wedge
/// our bootstrap drain open through an unrelated honest peer. Clean sources
/// are cleared only after every outcome in the unit is known, so peer
/// iteration order cannot falsely clear a rejection recorded later in the same
/// bootstrap batch.
async fn publish_bootstrap_admission_outcomes(
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    outcomes: &[(PeerId, AdmissionOutcome)],
    live_discovered: &HashSet<XorName>,
) {
    let mut rejected_sources = HashSet::new();
    let mut clean_sources = HashSet::new();
    let mut displaced_keys = HashSet::new();

    for (source, outcome) in outcomes {
        if outcome.capacity_rejected_count > 0 {
            rejected_sources.insert(*source);
        } else {
            clean_sources.insert(*source);
        }
        // Only the *key* of a fairness displacement is forfeited here, never
        // its owner's standing. Reclaiming a borrowed slot is our own fairness
        // decision, not a failure by the peer that held it: stamping the victim
        // would let a sustained flooder block our bootstrap drain through an
        // unrelated honest peer that never overflowed us. The displaced key
        // falls to the same post-bootstrap neighbor-sync and audit/repair
        // recovery path that TTL expiry already relies on.
        for displacement in &outcome.displaced {
            displaced_keys.insert(displacement.key);
        }
    }
    clean_sources.retain(|source| !rejected_sources.contains(source));

    let now = Instant::now();
    let mut state = bootstrap_state.write().await;
    for key in displaced_keys {
        state.remove_key(&key);
    }
    state.pending_keys.extend(live_discovered);
    for source in clean_sources {
        state.capacity_rejected_sources.remove(&source);
    }
    for source in rejected_sources {
        // First-seen: a source that keeps overflowing us must not keep its own
        // record fresh, or bootstrap never drains and auditing stays off.
        state.note_capacity_rejected(source, now);
    }
}

#[allow(clippy::too_many_arguments)]
async fn admit_and_queue_hints(
    self_id: &PeerId,
    source_peer: &PeerId,
    replica_hints: &[XorName],
    paid_hints: &[XorName],
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    storage: &Arc<ChunkStore>,
    paid_list: &Arc<PaidList>,
    queues: &Arc<RwLock<ReplicationQueues>>,
) -> AdmissionOutcome {
    let pending_keys: HashSet<XorName> = {
        let q = queues.read().await;
        q.pending_keys().into_iter().collect()
    };

    let admitted = admission::admit_hints(
        self_id,
        replica_hints,
        paid_hints,
        p2p_node,
        config,
        storage,
        paid_list,
        &pending_keys,
    )
    .await;

    let mut q = queues.write().await;
    queue_admitted_hints(source_peer, admitted, storage, &mut q)
}

fn queue_admitted_hints(
    source_peer: &PeerId,
    admitted: admission::AdmissionResult,
    storage: &ChunkStore,
    q: &mut ReplicationQueues,
) -> AdmissionOutcome {
    let mut discovered = HashSet::new();
    let mut capacity_rejected_count: usize = 0;
    let mut displaced = Vec::new();
    let now = Instant::now();

    for key in admitted.replica_keys {
        if !storage.exists(&key).unwrap_or(false) {
            let result = q.add_pending_verify(
                key,
                VerificationEntry {
                    state: VerificationState::PendingVerify,
                    verified_sources: Vec::new(),
                    tried_sources: HashSet::new(),
                    created_at: now,
                    next_verify_at: now,
                    hint_sources: HashSet::from([*source_peer]),
                    // Non-empty: this peer claimed possession, so it is a
                    // fetch-source candidate. Derives HintPipeline::Replica.
                    replica_hint_sources: HashSet::from([*source_peer]),
                    unresolved_retries: 0,
                    no_holder_reported: false,
                },
            );
            match result {
                crate::replication::scheduling::AdmissionResult::Admitted => {
                    discovered.insert(key);
                }
                crate::replication::scheduling::AdmissionResult::AlreadyPresent => {}
                crate::replication::scheduling::AdmissionResult::CapacityRejected => {
                    capacity_rejected_count += 1;
                }
            }
        }
    }

    for key in admitted.paid_only_keys {
        let result = q.add_pending_verify(
            key,
            VerificationEntry {
                state: VerificationState::PendingVerify,
                verified_sources: Vec::new(),
                tried_sources: HashSet::new(),
                created_at: now,
                next_verify_at: now,
                hint_sources: HashSet::from([*source_peer]),
                // Empty: a paid hint makes no possession claim, so this peer is
                // not a fetch source. Derives HintPipeline::PaidOnly.
                replica_hint_sources: HashSet::new(),
                unresolved_retries: 0,
                no_holder_reported: false,
            },
        );
        match result {
            crate::replication::scheduling::AdmissionResult::Admitted => {
                discovered.insert(key);
            }
            crate::replication::scheduling::AdmissionResult::AlreadyPresent => {}
            crate::replication::scheduling::AdmissionResult::CapacityRejected => {
                capacity_rejected_count += 1;
            }
        }
    }

    if capacity_rejected_count > 0 {
        debug!(
            "admit_and_queue_hints from {source_peer}: {capacity_rejected_count} hints \
             rejected at queue capacity; source will need to re-hint after pending_verify drains"
        );
    }

    displaced.extend(q.take_capacity_displacements());

    AdmissionOutcome {
        discovered,
        capacity_rejected_count,
        displaced,
    }
}

// ---------------------------------------------------------------------------
// Verification cycle
// ---------------------------------------------------------------------------

/// Run one verification cycle: process pending keys through quorum checks.
#[allow(clippy::too_many_lines)]
async fn run_verification_cycle(ctx: VerificationCycleContext<'_>) {
    let cycle_started = Instant::now();
    let VerificationCycleContext {
        p2p_node,
        paid_list,
        storage,
        queues,
        config,
        bootstrap_state,
        is_bootstrapping,
        bootstrap_complete_notify,
        last_commitment_by_peer,
        ever_capable_peers,
        recent_provers,
    } = ctx;

    // Self-heal the bootstrap drain before any early-return below: abandoned
    // capacity-rejection records must expire, and a drain condition that
    // became true without a triggering event must still be observed. Pending
    // peer requests legitimately block the drain check itself, but not this.
    expire_and_recheck_bootstrap_drain(
        bootstrap_state,
        queues,
        is_bootstrapping,
        bootstrap_complete_notify,
        config.capacity_rejected_max_age(),
    )
    .await;

    // Bootstrap admits one concurrent neighbor batch as an atomic source
    // aggregation unit. Do not select newly queued keys until that batch's
    // hints and drain accounting have both been published.
    if bootstrap_state.read().await.pending_peer_requests > 0 {
        return;
    }

    // Evict stale entries that have been pending too long (e.g. unreachable
    // verification targets during a network partition).
    let stale_pending_keys = {
        let mut q = queues.write().await;
        q.evict_stale(config::PENDING_VERIFY_MAX_AGE)
    };
    if !stale_pending_keys.is_empty() {
        update_bootstrap_after_verification(
            &stale_pending_keys,
            bootstrap_state,
            queues,
            is_bootstrapping,
            bootstrap_complete_notify,
        )
        .await;
    }

    let pending_keys = {
        let mut q = queues.write().await;
        // Re-check while holding the queue write lock used by fair selection.
        // This closes the race
        // where a bootstrap batch starts after the early check: the batch
        // cannot publish its hints under the queue write lock until this
        // selection either returns or declines to run.
        if bootstrap_state.read().await.pending_peer_requests > 0 {
            return;
        }
        q.select_ready_pending_keys(Instant::now(), MAX_VERIFICATION_KEYS_PER_CYCLE)
    };

    if pending_keys.is_empty() {
        return;
    }
    let initial_pending_count = pending_keys.len();

    // Capacity verdict for this cycle — the same pre-check the PUT handler and
    // the fresh-offer path already run (V2-411), read once and reused below.
    //
    // It gates only the two steps that exist to enable a fetch: the presence
    // probe that discovers holders, and the promotion that queues the download.
    // Everything a cycle does that does not need a local write still runs on a
    // full node — the local paid-list fast path, `PaidForList` convergence
    // through the quorum round, and the terminal checks that retire a key this
    // node already holds or is no longer admitted for. Gating earlier than this
    // would stop a full node learning which of its keys were paid for, and
    // would strand keys that should have retired, which keeps bootstrap drain
    // pending and audits disabled until stale eviction.
    // Only a *full* disk is a standing condition worth minutes of backoff. A
    // failed `statvfs` says nothing about available space and may have cleared
    // by the next cycle, so it is treated as writable here and left to the
    // pre-check at the dial, which queries again and may well permit the write.
    let write_blocked = storage.capacity_verdict() == CapacityVerdict::Full;
    // Counted per gate rather than combined. `local_paid_probe` below counts
    // probes actually sent, so it reads zero once the first gate fires; keeping
    // the two deferral counts apart is what lets an operator see which branch a
    // full node's keys are taking without adding a code path to find out.
    let mut capacity_deferred_probe = 0usize;
    let mut capacity_deferred_promote = 0usize;

    let self_id = *p2p_node.peer_id();

    // Step 1: Check local PaidForList for fast-path authorization (Section 9,
    // step 4). Paid-list membership settles *validity* — the key is known-paid,
    // so no quorum round is needed. It says nothing about whether we must hold
    // the bytes; that is decided below.
    let mut local_paid_keys = Vec::new();
    let mut keys_needing_network = Vec::new();
    let mut terminal_keys: Vec<XorName> = Vec::new();
    {
        let mut q = queues.write().await;
        for key in &pending_keys {
            if paid_list.contains(key).unwrap_or(false) {
                if q.set_pending_state(key, VerificationState::PaidListVerified) {
                    local_paid_keys.push(*key);
                }
            } else {
                keys_needing_network.push(*key);
            }
        }
    }

    // Storage responsibility is a live routing question, decided identically
    // for every known-paid key regardless of how the advertising peer labelled
    // its hint — a replica hint is a possession *claim* by the sender, never
    // permission for us to store. Held outside the queue lock: `is_responsible`
    // awaits into the DHT manager.
    let mut local_paid_presence_probe_keys = Vec::new();
    if !local_paid_keys.is_empty() {
        let mut terminal_paid = Vec::new();
        for key in local_paid_keys {
            if storage.exists(&key).unwrap_or(false) {
                terminal_paid.push(key);
            } else if is_storage_admitted(&self_id, &key, p2p_node, config).await {
                // We carry storage responsibility and lack the bytes. The
                // presence probe below discovers holders to fetch from; it is
                // source discovery, not re-verification.
                local_paid_presence_probe_keys.push(key);
            } else {
                terminal_paid.push(key);
            }
        }

        if !terminal_paid.is_empty() {
            let mut q = queues.write().await;
            for key in terminal_paid {
                q.remove_pending(&key);
                terminal_keys.push(key);
            }
        }

        // Capacity gate, first of two. Everything above this point has already
        // run: authorization succeeded via the local `PaidForList` hit, and the
        // keys that should retire (already held, or no longer storage-admitted)
        // have retired. What is left is a probe whose only purpose is finding a
        // holder to download from, and this node cannot write what it would
        // download.
        if write_blocked && !local_paid_presence_probe_keys.is_empty() {
            let mut q = queues.write().await;
            for key in std::mem::take(&mut local_paid_presence_probe_keys) {
                if q.defer_pending(&key, config::CAPACITY_BLOCKED_RETRY) {
                    capacity_deferred_probe += 1;
                }
            }
        }
    }

    let local_paid_probe_count = local_paid_presence_probe_keys.len();
    let keys_needing_network_count = keys_needing_network.len();
    // Keys this cycle put back because no peer claimed possession. Reported in
    // aggregate below; the per-key line is warned once per entry, not per retry.
    let mut no_holder_deferrals = 0usize;

    // Step 1b: Local paid-list hit for fetch-eligible keys. Per Section 9
    // step 4, authorization succeeds immediately; run a presence-only probe
    // to find any holder we can fetch from.
    if !local_paid_presence_probe_keys.is_empty() {
        let targets = quorum::compute_presence_targets(
            &local_paid_presence_probe_keys,
            p2p_node,
            config,
            &self_id,
        )
        .await;
        let evidence = quorum::run_verification_round(
            &local_paid_presence_probe_keys,
            &targets,
            p2p_node,
            config,
        )
        .await;

        let mut q = queues.write().await;
        for key in local_paid_presence_probe_keys {
            if storage.exists(&key).unwrap_or(false) {
                q.remove_pending(&key);
                terminal_keys.push(key);
                continue;
            }
            let mut sources = evidence.get(&key).map_or_else(Vec::new, |ev| {
                quorum::present_sources_for_key(&key, ev, &targets)
            });
            if let Some(entry) = q.get_pending(&key) {
                add_replica_hint_sources(&mut sources, &entry.replica_hint_sources);
            }
            if sources.is_empty() {
                no_holder_deferrals += 1;
                let outcome = q.defer_unresolved(&key, config.verification_request_timeout);
                let first_report = q.claim_no_holder_report(&key);
                report_unresolved_deferral("Locally paid key", &key, outcome, first_report);
            } else {
                // A holder answered, so whatever came before is not a run of
                // consecutive failures any more. Clear before promoting: if the
                // fetch queue is full the entry stays pending, and it must not
                // carry the old backoff.
                q.clear_unresolved(&key);
                let distance = crate::client::xor_distance(&key, p2p_node.peer_id().as_bytes());
                // Atomic remove+enqueue: if fetch_queue is at capacity, the
                // pending entry is preserved and retried next cycle (no
                // silent drop of verified replica-repair work).
                let _ = q.promote_pending_to_fetch(key, distance, sources);
            }
        }
    }

    // Steps 2-5: Network verification (skipped if all keys resolved locally).
    if !keys_needing_network.is_empty() {
        // Step 2: Compute targets and run network verification round.
        let targets =
            quorum::compute_verification_targets(&keys_needing_network, p2p_node, config, &self_id)
                .await;

        let evidence =
            quorum::run_verification_round(&keys_needing_network, &targets, p2p_node, config).await;

        // Step 3: Evaluate results — collect outcomes without holding the write
        // lock across paid-list I/O.
        //
        // v12 §6 holder-eligibility: snapshot the per-peer last-commitment
        // table and recent_provers cache up front so the synchronous
        // evaluate_key_evidence_with_holder_check predicate can consult
        // them without awaiting. The predicate downgrades a Present
        // claim to Unresolved unless the peer is credited for that key.
        // Snapshot per-peer commitment data. We need two views:
        //   - `commitment_by_peer_snapshot`: peers that currently have
        //     a verified commitment record on file (used to look up
        //     their current hash).
        //   - `capable_peer_snapshot`: the sticky "ever v12-capable"
        //     set. Sourced from a separate set rather than the
        //     commitment map so eviction (PeerRemoved cleanup, sybil
        //     cap at `MAX_LAST_COMMITMENT_BY_PEER`) does NOT downgrade
        //     a previously-v12 peer to "legacy" credit-unconditionally.
        //     Legacy / pre-v12 peers that have never sent a commitment
        //     remain absent from the set and are credited via the
        //     legacy path so mixed-version networks stay live.
        let commitment_by_peer_snapshot: HashMap<PeerId, [u8; 32]> = {
            let map = last_commitment_by_peer.read().await;
            map.iter()
                // Read the CACHED hash (§13) — no per-cycle re-serialize/re-hash
                // of every peer's ~5 KiB commitment.
                .filter_map(|(p, rec)| rec.commitment_hash().map(|h| (*p, h)))
                .collect()
        };
        let capable_peer_snapshot: HashSet<PeerId> = ever_capable_peers.read().await.clone();
        // Take a full snapshot of recent_provers under the read lock,
        // then release. The cache is bounded (16/key × keys), so the
        // clone is cheap.
        let provers_snapshot = recent_provers.read().await.clone();
        // For the replica-fetch path, we need to know whether THIS
        // node already holds the key being verified. The v12 §6
        // holder-credit gate is meant to prevent uncredited Present
        // claims from contributing to paid-list / reward quorum for
        // keys we DO hold (and could audit ourselves). For keys we
        // are trying to FETCH (i.e. not in local storage), there is
        // no possible local audit credit, and gating the presence
        // quorum on credit would deadlock replica-repair in a
        // fully v12-capable close group.
        let mut locally_held: HashSet<XorName> = HashSet::new();
        for key in &keys_needing_network {
            if storage.exists(key).unwrap_or(false) {
                locally_held.insert(*key);
            }
        }
        let holder_credit = |peer: &PeerId, key: &XorName| -> bool {
            if !locally_held.contains(key) {
                // Replica-fetch path: we don't hold this key, so we
                // cannot have collected audit credit for it. Trust
                // Present claims to drive fetch-source promotion;
                // chunk-PUT payment_verifier is the security backstop
                // when the bytes actually arrive.
                return true;
            }
            if !capable_peer_snapshot.contains(peer) {
                // Pre-v12 / legacy peer that has never gossiped a
                // commitment. The v12 §6 holder-eligibility check
                // doesn't apply: their Present evidence comes through
                // the legacy path and we credit it unconditionally
                // so a mixed-version network stays live during
                // transition.
                return true;
            }
            let Some(hash) = commitment_by_peer_snapshot.get(peer) else {
                // Peer is commitment_capable (sticky) but currently
                // has no live commitment record on file (e.g. their
                // last gossip was evicted from the LRU cache, or it
                // failed verification). Withhold credit until they
                // re-prove storage under a fresh commitment.
                return false;
            };
            provers_snapshot.is_credited_holder(key, peer, hash)
        };

        let mut evaluated: Vec<(XorName, KeyVerificationOutcome)> = Vec::new();
        {
            let q = queues.read().await;
            for key in &keys_needing_network {
                let Some(ev) = evidence.get(key) else {
                    continue;
                };
                if q.get_pending(key).is_none() {
                    continue;
                }
                let outcome = quorum::evaluate_key_evidence_with_holder_check(
                    key,
                    ev,
                    &targets,
                    config,
                    holder_credit,
                );
                evaluated.push((*key, outcome));
            }
        } // read lock released

        // Step 4: Insert verified keys into PaidForList (no lock held).
        let mut paid_insert_keys: Vec<XorName> = Vec::new();
        for (key, outcome) in &evaluated {
            if matches!(
                outcome,
                KeyVerificationOutcome::QuorumVerified { .. }
                    | KeyVerificationOutcome::PaidListVerified { .. }
            ) {
                paid_insert_keys.push(*key);
            }
        }
        for key in &paid_insert_keys {
            if let Err(e) = paid_list.insert(key).await {
                warn!("Failed to add verified key to PaidForList: {e}");
            }
        }

        // Verification established validity; the paid-list insert above records
        // it. Downloading the bytes is a separate duty, owed only by the
        // storage-admission group, asked on the same terms for every verified
        // key — the advertising peer's replica/paid labelling is a claim about
        // itself and carries no authority over what we store. This check is a
        // cheap pre-filter that keeps never-responsible keys out of the fetch
        // queue entirely; the authoritative gate is the per-attempt recheck in
        // `execute_single_fetch`, because a key can wait in the nearest-first
        // fetch queue long enough for this promotion-time answer to go stale.
        let mut fetch_allowed_keys: HashSet<XorName> = HashSet::new();
        for (key, outcome) in &evaluated {
            if matches!(
                outcome,
                KeyVerificationOutcome::QuorumVerified { .. }
                    | KeyVerificationOutcome::PaidListVerified { .. }
            ) && !storage.exists(key).unwrap_or(false)
                && is_storage_admitted(&self_id, key, p2p_node, config).await
            {
                fetch_allowed_keys.insert(*key);
            }
        }

        // Step 5: Update queues with the evaluated outcomes.
        let mut bad_singleton_hints: HashMap<(PeerId, SingletonHintFault), usize> = HashMap::new();
        let mut q = queues.write().await;
        for (key, outcome) in evaluated {
            let replica_hint_sources = q
                .get_pending(&key)
                .map(|entry| entry.replica_hint_sources.clone())
                .unwrap_or_default();
            if let Some(ev) = evidence.get(&key) {
                if let Some(source) =
                    punishable_singleton_replica_hint_source(&replica_hint_sources, &outcome, ev)
                {
                    *bad_singleton_hints.entry(source).or_insert(0) += 1;
                }
            }
            match outcome {
                KeyVerificationOutcome::QuorumVerified { sources }
                | KeyVerificationOutcome::PaidListVerified { sources } => {
                    let mut fetch_sources = sources;
                    add_replica_hint_sources(&mut fetch_sources, &replica_hint_sources);
                    let fetch_eligible = fetch_allowed_keys.contains(&key);
                    if fetch_eligible && write_blocked {
                        // Capacity gate, second of two, and deliberately after
                        // Step 4: the key is now recorded in `PaidForList` and
                        // its verification stands. Only the download is held,
                        // because `execute_single_fetch` would refuse it and
                        // hand the key straight back here.
                        if q.defer_pending(&key, config::CAPACITY_BLOCKED_RETRY) {
                            capacity_deferred_promote += 1;
                        }
                    } else if fetch_eligible && !fetch_sources.is_empty() {
                        // A holder answered; see the matching clear on the
                        // local-paid path.
                        q.clear_unresolved(&key);
                        let distance =
                            crate::client::xor_distance(&key, p2p_node.peer_id().as_bytes());
                        // Atomic remove+enqueue: on fetch_queue capacity miss
                        // the pending entry is preserved so this verified key
                        // is retried on the next cycle (no silent drop).
                        let _ = q.promote_pending_to_fetch(key, distance, fetch_sources);
                        // Not terminal — either moved to fetch queue, or
                        // retained as pending until queue drains.
                    } else if fetch_eligible && fetch_sources.is_empty() {
                        no_holder_deferrals += 1;
                        let outcome = q.defer_unresolved(&key, config.verification_request_timeout);
                        let first_report = q.claim_no_holder_report(&key);
                        report_unresolved_deferral(
                            "Verified storage-admitted key",
                            &key,
                            outcome,
                            first_report,
                        );
                    } else {
                        q.remove_pending(&key);
                        terminal_keys.push(key);
                    }
                }
                KeyVerificationOutcome::QuorumFailed => {
                    q.remove_pending(&key);
                    terminal_keys.push(key);
                }
                KeyVerificationOutcome::QuorumInconclusive => {
                    q.set_pending_state(&key, VerificationState::QuorumInconclusive);
                    // Backed off like any other unresolved round, but it does
                    // NOT claim the no-holder report: nothing yet says this key
                    // has no holder, so the first round that does say so must
                    // still be the one that warns.
                    let _ = q.defer_unresolved(&key, config.verification_request_timeout);
                }
            }
        }
        drop(q);

        for ((peer, fault), bad_hint_count) in bad_singleton_hints {
            let reports = bad_hint_count.min(MAX_BAD_HINT_TRUST_REPORTS_PER_PEER_PER_CYCLE);
            warn!(
                "Peer {peer} submitted {bad_hint_count} rejected or self-contradicting \
                 sole-source replica hints ({fault:?}); \
                 reporting {reports} bounded trust failure(s)"
            );
            for _ in 0..reports {
                match fault {
                    // A claim about a key that does not exist. Punishable whatever the
                    // sender's disk is doing.
                    SingletonHintFault::RejectedByCloseGroup => {
                        p2p_node
                            .report_trust_event(
                                &peer,
                                TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                            )
                            .await;
                    }
                    // "I advertised it and no longer have it." That is the one statement a
                    // node short of disk cannot avoid making while it moves its chunks, so
                    // it goes through the release switch.
                    SingletonHintFault::DeniedPossession => {
                        config::penalise_unheld_close_group_chunk(
                            p2p_node,
                            &peer,
                            "replica_hint_denied_possession",
                            REPLICATION_TRUST_WEIGHT,
                        )
                        .await;
                    }
                }
            }
        }
    }

    // Step 6: Remove terminal keys from bootstrap pending set and re-check
    // the drain condition.
    update_bootstrap_after_verification(
        &terminal_keys,
        bootstrap_state,
        queues,
        is_bootstrapping,
        bootstrap_complete_notify,
    )
    .await;

    let (pending_after, fetch_after, in_flight_after) = {
        let q = queues.read().await;
        (
            q.pending_count(),
            q.fetch_queue_count(),
            q.in_flight_count(),
        )
    };
    let terminal_key_count = terminal_keys.len();
    let elapsed_ms = cycle_started.elapsed().as_millis();

    if elapsed_ms >= VERIFICATION_CYCLE_SLOW_LOG_MS {
        info!(
            target: "ant_node::replication::verification",
            "Slow replication verification cycle: pending_start={initial_pending_count}, capacity_deferred_probe={capacity_deferred_probe}, capacity_deferred_promote={capacity_deferred_promote}, local_paid_probe={local_paid_probe_count}, network_verify={keys_needing_network_count}, terminal={terminal_key_count}, no_holders={no_holder_deferrals}, pending_after={pending_after}, fetch_after={fetch_after}, in_flight_after={in_flight_after}, elapsed_ms={elapsed_ms}",
        );
    } else {
        debug!(
            target: "ant_node::replication::verification",
            "Replication verification cycle: pending_start={initial_pending_count}, capacity_deferred_probe={capacity_deferred_probe}, capacity_deferred_promote={capacity_deferred_promote}, local_paid_probe={local_paid_probe_count}, network_verify={keys_needing_network_count}, terminal={terminal_key_count}, no_holders={no_holder_deferrals}, pending_after={pending_after}, fetch_after={fetch_after}, in_flight_after={in_flight_after}, elapsed_ms={elapsed_ms}",
        );
    }
}

/// Report a verification round that left a key without a usable holder.
///
/// Warns once per entry — the first failure is news, and by the hundredth the
/// node is re-asking peers it has already exhausted. Later failures stay at
/// `debug`, and the per-cycle count is carried in the cycle summary so the
/// scale of a backlog is still visible without a line per key per retry.
///
/// `first_report` comes from `claim_no_holder_report`, not from the attempt
/// number: a round may advance the count without producing a no-holder result,
/// and such a round must not consume the warning.
///
/// Eviction at `PENDING_VERIFY_MAX_AGE` drops the entry, and a round that finds
/// a holder clears it, so a later relapse warns again: "once per episode", not
/// "once ever".
fn report_unresolved_deferral(
    what: &str,
    key: &XorName,
    outcome: Option<DeferralOutcome>,
    first_report: bool,
) {
    let Some(outcome) = outcome else {
        // The entry left `pending_verify` under the same lock; nothing deferred.
        return;
    };
    if first_report {
        warn!(
            "{what} {} has no responding holders yet; deferring retry",
            hex::encode(key)
        );
    } else {
        debug!(
            "{what} {} still has no responding holders after {} attempts; \
             retrying in {}s",
            hex::encode(key),
            outcome.attempt,
            outcome.retry_after.as_secs()
        );
    }
}

/// Add peers that claimed possession as fallback fetch sources.
///
/// Paid-only advertisers make no possession claim and are absent from
/// `replica_hint_sources` by construction, so they are never added.
fn add_replica_hint_sources(sources: &mut Vec<PeerId>, replica_hint_sources: &HashSet<PeerId>) {
    for source in replica_hint_sources {
        if !sources.contains(source) {
            sources.push(*source);
        }
    }
}

/// Why a sole-source replica hint is punishable.
///
/// The two cases look alike and are not. A hint the close group rejects outright is a
/// claim about a key that does not exist, which is a bad hint however the sender's disk is
/// doing. A sender that advertised a key and then answers `Absent` for it is making a
/// statement about its own storage, and that is the one thing a node short of disk cannot
/// avoid saying while it moves its chunks out of a store that will not give the space back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SingletonHintFault {
    /// The close group says the key does not exist.
    RejectedByCloseGroup,
    /// The sender advertised the key and then denied holding it.
    DeniedPossession,
}

/// Return the sole replica advertiser when either the close group definitively
/// rejects the key or the advertiser explicitly denies possessing it, and say which.
/// Paid-only advertisements, corroborated replica hints, and inconclusive
/// rounds without that direct contradiction are deliberately non-penalizing.
fn punishable_singleton_replica_hint_source(
    replica_hint_sources: &HashSet<PeerId>,
    outcome: &KeyVerificationOutcome,
    evidence: &crate::replication::types::KeyVerificationEvidence,
) -> Option<(PeerId, SingletonHintFault)> {
    // A paid-only advertiser leaves this set empty, so the sole-source lane is
    // reserved for peers that actually claimed possession.
    if replica_hint_sources.len() != 1 {
        return None;
    }
    let source = *replica_hint_sources.iter().next()?;
    if matches!(outcome, KeyVerificationOutcome::QuorumFailed) {
        return Some((source, SingletonHintFault::RejectedByCloseGroup));
    }
    if evidence.presence.get(&source) == Some(&PresenceEvidence::Absent) {
        return Some((source, SingletonHintFault::DeniedPossession));
    }
    None
}

/// Post-verification bootstrap bookkeeping: remove terminal keys from the
/// bootstrap pending set and transition out of bootstrapping when drained.
async fn update_bootstrap_after_verification(
    terminal_keys: &[XorName],
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    queues: &Arc<RwLock<ReplicationQueues>>,
    is_bootstrapping: &Arc<RwLock<bool>>,
    bootstrap_complete_notify: &Arc<Notify>,
) {
    if terminal_keys.is_empty() || bootstrap_state.read().await.is_drained() {
        return;
    }
    {
        let mut bs = bootstrap_state.write().await;
        for key in terminal_keys {
            bs.remove_key(key);
        }
    }
    let q = queues.read().await;
    if bootstrap::check_bootstrap_drained(bootstrap_state, &q).await {
        complete_bootstrap(is_bootstrapping, bootstrap_complete_notify).await;
    }
}

/// Retire bootstrap work owed by a peer that permanently left the routing
/// table, then immediately re-check drain so this removal can complete
/// bootstrap without waiting for an unrelated pipeline event.
async fn update_bootstrap_after_peer_removed(
    peer: &PeerId,
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    queues: &Arc<RwLock<ReplicationQueues>>,
    is_bootstrapping: &Arc<RwLock<bool>>,
    bootstrap_complete_notify: &Arc<Notify>,
) {
    let orphaned_keys = queues.write().await.remove_hint_source(peer);
    let cleared_rejection = bootstrap::clear_capacity_rejected(bootstrap_state, peer).await;

    if !orphaned_keys.is_empty() {
        let mut state = bootstrap_state.write().await;
        for key in &orphaned_keys {
            state.remove_key(key);
        }
    }

    if orphaned_keys.is_empty() && !cleared_rejection {
        return;
    }
    let q = queues.read().await;
    if bootstrap::check_bootstrap_drained(bootstrap_state, &q).await {
        complete_bootstrap(is_bootstrapping, bootstrap_complete_notify).await;
    }
}

/// Periodic bootstrap-drain self-healing, run on every verification worker
/// tick until bootstrap drains.
///
/// Two liveness gaps make this necessary. A `PeerRemoved` that races the
/// recording of a capacity rejection leaves an entry no future event can
/// clear — `max_age` expiry is its only exit. And a clean-cycle
/// `clear_capacity_rejected` never triggers its own drain re-check, so on a
/// quiet node the drain condition can become true with nothing left to
/// observe it. Expiry must run even while `pending_peer_requests` blocks the
/// drain itself, so this is invoked before `run_verification_cycle`'s
/// early-returns.
async fn expire_and_recheck_bootstrap_drain(
    bootstrap_state: &Arc<RwLock<BootstrapState>>,
    queues: &Arc<RwLock<ReplicationQueues>>,
    is_bootstrapping: &Arc<RwLock<bool>>,
    bootstrap_complete_notify: &Arc<Notify>,
    max_age: Duration,
) {
    if bootstrap_state.read().await.is_drained() {
        return;
    }
    bootstrap::expire_capacity_rejected(bootstrap_state, max_age).await;
    let q = queues.read().await;
    if bootstrap::check_bootstrap_drained(bootstrap_state, &q).await {
        complete_bootstrap(is_bootstrapping, bootstrap_complete_notify).await;
    }
}

/// Set `is_bootstrapping` to `false` and wake all waiters.
async fn complete_bootstrap(
    is_bootstrapping: &Arc<RwLock<bool>>,
    bootstrap_complete_notify: &Arc<Notify>,
) {
    *is_bootstrapping.write().await = false;
    bootstrap_complete_notify.notify_waiters();
    info!("Replication bootstrap complete");
}

// ---------------------------------------------------------------------------
// Fetch types and single-fetch executor
// ---------------------------------------------------------------------------

/// Result classification for a single fetch attempt.
enum FetchResult {
    /// Data fetched, integrity-checked, and stored successfully.
    Stored,
    /// Content-address integrity check failed — do not retry.
    IntegrityFailed,
    /// Source failed (network error or non-success response) — retryable.
    SourceFailed,
    /// This node could not write the chunk locally: the capacity pre-check
    /// refused before the dial, or `put` failed after the bytes arrived.
    ///
    /// Distinct from [`Self::SourceFailed`] because nothing about the source
    /// is implicated, and because the remedy is the opposite one. A source
    /// failure should move on to the next holder; a local write failure must
    /// not — every remaining source would send the same chunk into the same
    /// full disk. The key returns to verification instead, so a later cycle
    /// retries it once local capacity allows. That is a retry path, not a
    /// liveness guarantee: `evict_stale` still expires the entry at
    /// `PENDING_VERIFY_MAX_AGE` measured from when it was first queued, after
    /// which re-acquisition depends on a fresh hint.
    LocalWriteFailed,
    /// This node already holds the key, so there is nothing to fetch —
    /// terminal, exactly like [`Self::Stored`], because the duty is already
    /// discharged.
    ///
    /// Responsibility is rechecked at download time; possession has to be too.
    /// The earlier gates already drop held keys out of the fetch pipeline —
    /// `queue_admitted_hints` skips them, and the promotion-time
    /// `fetch_allowed_keys` filter and the local-paid probe both terminate
    /// them. (`is_relevant` is not one of them: possession there makes a key
    /// *relevant*, which is what keeps us tracking it.) So a held key reaches
    /// the dial only when it arrived *after* promotion — a fresh-offer push, a
    /// client PUT, or another source landing first. The nearest-first fetch
    /// queue is deep enough for that window to be real.
    ///
    /// This check must also precede the capacity pre-check below, because
    /// `ChunkStore::put` tests `exists` *before* it tests disk space: without
    /// it, a full node would decline a key it already holds, which `put` would
    /// have accepted as a duplicate.
    AlreadyHeld,
    /// Live routing state no longer places this node in the storage-admission
    /// group for the key — terminal, exactly like [`Self::Stored`]. The duty
    /// the fetch was serving has lapsed, so no alternate source is tried and
    /// no trust event is reported: the source did nothing wrong.
    NoLongerResponsible,
}

/// Outcome produced by [`execute_single_fetch`] and consumed by the fetch
/// worker loop to update queue state.
struct FetchOutcome {
    key: XorName,
    result: FetchResult,
}

/// What the fetch worker must do next for a key whose fetch attempt resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchFollowUp {
    /// The key terminally left the fetch pipeline (its in-flight entry is
    /// removed and any verification retry-slot reservation released); the
    /// caller must run bootstrap accounting for it.
    Terminal,
    /// The key returned to `pending_verify` for a later verification round.
    RequeuedForVerification,
    /// Retry immediately from this next untried verified source.
    RetryFrom(PeerId),
}

/// Apply a resolved [`FetchResult`] to the queues and report the follow-up.
///
/// Split out of the fetch-worker loop so the per-variant queue transitions
/// are unit-testable without a live network. The caller holds the queues
/// write lock. [`FetchResult::NoLongerResponsible`] deliberately shares
/// [`FetchResult::Stored`]'s terminal path: `complete_fetch` releases the
/// retry-slot reservation, and the caller's terminal handling shrinks the
/// bootstrap pending set — dropping the key without that accounting would
/// stall bootstrap drain forever.
///
/// The nursery `option_if_let_else` rewrite is impossible here: both
/// `map_or_else` closures would need `&mut *q` simultaneously.
#[allow(clippy::option_if_let_else)]
fn apply_fetch_result(
    q: &mut ReplicationQueues,
    key: &XorName,
    result: &FetchResult,
    verification_retry_after: Duration,
) -> FetchFollowUp {
    match result {
        FetchResult::Stored | FetchResult::NoLongerResponsible | FetchResult::AlreadyHeld => {
            q.complete_fetch(key);
            FetchFollowUp::Terminal
        }
        FetchResult::IntegrityFailed | FetchResult::SourceFailed => {
            if let Some(next_peer) = q.retry_fetch(key) {
                FetchFollowUp::RetryFrom(next_peer)
            } else if q.requeue_fetch_for_verification(key, verification_retry_after) {
                FetchFollowUp::RequeuedForVerification
            } else {
                FetchFollowUp::Terminal
            }
        }
        // No `retry_fetch`: the local write is what failed, so every other
        // source would be asked to send the same chunk into the same full
        // disk. Requeueing for verification is what keeps the key from being
        // stranded — it comes back once capacity allows — and the fallthrough
        // to `Terminal` when there is no retry metadata is what keeps
        // bootstrap drain accounting correct, exactly as for a source failure.
        //
        // The ordinary requeue delay, deliberately. A standing capacity block
        // does not need a longer one here: the key returns to pending, and the
        // gate at the head of the next cycle defers it for minutes. A separate
        // backoff on this path would duplicate that to save one 15 s round, on
        // a race the gate already makes rare.
        FetchResult::LocalWriteFailed => {
            if q.requeue_fetch_for_verification(key, verification_retry_after) {
                FetchFollowUp::RequeuedForVerification
            } else {
                FetchFollowUp::Terminal
            }
        }
    }
}

/// Whether this node currently sits inside the storage-admission group for
/// `key`, per live local routing state.
///
/// This is the one question every storage decision in this module asks; see
/// [`admission::is_responsible`]. A purely local routing-table lookup — no
/// network I/O — but it awaits into the DHT manager, so callers must not
/// hold the queues lock across it.
async fn is_storage_admitted(
    self_id: &PeerId,
    key: &XorName,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
) -> bool {
    admission::is_responsible(
        self_id,
        key,
        p2p_node,
        storage_admission_width(config.close_group_size),
    )
    .await
}

#[allow(clippy::too_many_lines)]
/// Execute a single fetch request against `source` for `key`.
///
/// Handles encoding, network I/O, integrity checking, storage, and trust
/// event reporting.  Returns a [`FetchOutcome`] so the caller can update
/// queue state without holding any locks during the network round-trip.
///
/// This is the authoritative storage-responsibility gate: each attempt —
/// including every per-source retry, which re-enters here — rechecks live
/// routing state before spending bandwidth, and once more before writing
/// bytes that arrived after a round-trip. The verification-time check that
/// promoted the key into the fetch queue is only a pre-filter; the queue is
/// nearest-first and deep, so a promotion decision can go stale under
/// topology churn before the key is ever dequeued.
async fn execute_single_fetch(
    p2p_node: Arc<P2PNode>,
    storage: Arc<ChunkStore>,
    config: Arc<ReplicationConfig>,
    key: XorName,
    source: PeerId,
) -> FetchOutcome {
    let self_id = *p2p_node.peer_id();
    if !is_storage_admitted(&self_id, &key, &p2p_node, &config).await {
        debug!(
            "Skipping fetch for {}: no longer in the storage-admission group",
            hex::encode(key)
        );
        return FetchOutcome {
            key,
            result: FetchResult::NoLongerResponsible,
        };
    }

    // Possession, then capacity — both before the dial, and in that order.
    //
    // `ChunkStore::put` tests `exists` before it tests disk space, so a full
    // node still accepts a key it already holds. Checking possession first is
    // what keeps this pair of gates from declining work `put` would have
    // taken.
    if storage.exists(&key).unwrap_or(false) {
        debug!(
            "Skipping fetch for {}: already held locally",
            hex::encode(key)
        );
        return FetchOutcome {
            key,
            result: FetchResult::AlreadyHeld,
        };
    }

    // Capacity is checked before the dial rather than after the bytes arrive.
    // `put` runs this same check on every write of a key it does not already
    // hold, so this reaches the same verdict `put` would reach *at this
    // instant*. It is not a guarantee about the later write: both answers can
    // change across the round trip. Space freed in between would have let a
    // post-download `put` succeed, so a refusal here can cost a fleeting
    // acquisition and one retry cycle of delay; space lost in between is why
    // the check inside `put` still has to stay.
    //
    // What it buys is that the refusal costs no bandwidth. Without it a
    // disk-full node pulls the whole chunk over the network first, and the
    // failure is then classified as the source's — no trust event, but the
    // worker walks to every remaining holder, and each re-uploads the same
    // chunk into the same full disk.
    if let Err(e) = storage.check_capacity() {
        debug!(
            "Skipping fetch for {}: local storage cannot accept a write: {e}",
            hex::encode(key)
        );
        return FetchOutcome {
            key,
            result: FetchResult::LocalWriteFailed,
        };
    }

    let request = protocol::FetchRequest { key };
    let msg = ReplicationMessage {
        request_id: rand::thread_rng().gen::<u64>(),
        body: ReplicationMessageBody::FetchRequest(request),
    };

    let encoded = match msg.encode() {
        Ok(data) => data,
        Err(e) => {
            warn!("Failed to encode fetch request: {e}");
            return FetchOutcome {
                key,
                result: FetchResult::SourceFailed,
            };
        }
    };

    let result = p2p_node
        .send_request(
            &source,
            REPLICATION_PROTOCOL_ID,
            encoded,
            config.fetch_request_timeout,
        )
        .await;

    match result {
        Ok(response) => {
            let Ok(resp_msg) = ReplicationMessage::decode(&response.data) else {
                p2p_node
                    .report_trust_event(
                        &source,
                        TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                    )
                    .await;
                return FetchOutcome {
                    key,
                    result: FetchResult::SourceFailed,
                };
            };

            match resp_msg.body {
                ReplicationMessageBody::FetchResponse(protocol::FetchResponse::Success {
                    key: resp_key,
                    data,
                }) => {
                    // Validate the response key matches the requested key.
                    // A malicious peer could serve valid data for a different
                    // key, passing integrity checks while the requested key
                    // is falsely marked as fetched.
                    if resp_key != key {
                        warn!(
                            "Fetch response key mismatch: requested {}, got {}",
                            hex::encode(key),
                            hex::encode(resp_key)
                        );
                        p2p_node
                            .report_trust_event(
                                &source,
                                TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                            )
                            .await;
                        return FetchOutcome {
                            key,
                            result: FetchResult::IntegrityFailed,
                        };
                    }

                    // Enforce chunk size invariant on fetched data.
                    // Checked before the content-address hash to avoid
                    // hashing up to 10 MiB of oversized junk data.
                    if data.len() > crate::ant_protocol::MAX_CHUNK_SIZE {
                        warn!(
                            "Fetched record {} exceeds MAX_CHUNK_SIZE ({} > {})",
                            hex::encode(resp_key),
                            data.len(),
                            crate::ant_protocol::MAX_CHUNK_SIZE,
                        );
                        p2p_node
                            .report_trust_event(
                                &source,
                                TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                            )
                            .await;
                        return FetchOutcome {
                            key,
                            result: FetchResult::IntegrityFailed,
                        };
                    }

                    // Content-address integrity check.
                    let computed = crate::client::compute_address(&data);
                    if computed != resp_key {
                        warn!(
                            "Fetched record integrity check failed: expected {}, got {}",
                            hex::encode(resp_key),
                            hex::encode(computed)
                        );
                        p2p_node
                            .report_trust_event(
                                &source,
                                TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                            )
                            .await;
                        return FetchOutcome {
                            key,
                            result: FetchResult::IntegrityFailed,
                        };
                    }

                    // Responsibility can lapse during the network round-trip.
                    // The bandwidth is already spent; declining the write is
                    // what still avoids the disk write and the later
                    // fetch→store→prune churn. Edge flapping is dampened by
                    // the margin `storage_admission_width` adds over
                    // `close_group_size`.
                    if !is_storage_admitted(&self_id, &key, &p2p_node, &config).await {
                        debug!(
                            "Fetched {} but responsibility lapsed in transit; not storing",
                            hex::encode(key)
                        );
                        return FetchOutcome {
                            key,
                            result: FetchResult::NoLongerResponsible,
                        };
                    }

                    if let Err(e) = storage.put(&resp_key, &data).await {
                        // The bytes arrived and passed the content-address
                        // check, so the source did its job; the failure is
                        // entirely local (disk-full, or a storage error). Any
                        // valid source must serve identical content, so trying
                        // the next one cannot cure a local error — it only
                        // re-downloads the same chunk into the same store.
                        warn!(
                            "Failed to store fetched record {}: {e}",
                            hex::encode(resp_key)
                        );
                        return FetchOutcome {
                            key,
                            result: FetchResult::LocalWriteFailed,
                        };
                    }

                    FetchOutcome {
                        key,
                        result: FetchResult::Stored,
                    }
                }
                ReplicationMessageBody::FetchResponse(
                    ref response @ (protocol::FetchResponse::NotFound { .. }
                    | protocol::FetchResponse::Error { .. }),
                ) => {
                    // This peer was selected as a fetch source because it recently
                    // answered `Present` during verification, so either answer is
                    // evidence of something. Which one decides what it is charged: a peer
                    // that does not hold the chunk is the lane this release withholds, a
                    // peer whose own read failed is not.
                    if let protocol::FetchResponse::Error { reason, .. } = response {
                        warn!(
                            "Fetch: peer {source} returned error for {}: {reason}",
                            hex::encode(key)
                        );
                    } else {
                        warn!(
                            "Fetch: verified source {source} returned NotFound for {}",
                            hex::encode(key)
                        );
                    }
                    if let Some(fault) = fetch_fault_for(response) {
                        let lane = match fault {
                            FetchFault::UnheldChunk => "fetch_not_found",
                            FetchFault::ResponderFault => "fetch_error",
                        };
                        charge_fetch_fault(&p2p_node, &source, fault, lane).await;
                    }
                    FetchOutcome {
                        key,
                        result: FetchResult::SourceFailed,
                    }
                }
                _ => {
                    // Unexpected message type — treat as malformed.
                    p2p_node
                        .report_trust_event(
                            &source,
                            TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                        )
                        .await;
                    FetchOutcome {
                        key,
                        result: FetchResult::SourceFailed,
                    }
                }
            }
        }
        Err(e) => {
            debug!("Fetch request to {source} failed: {e}");
            // No ApplicationFailure here — P2PNode::send_request() already
            // reports ConnectionTimeout / ConnectionFailed to the TrustEngine.
            FetchOutcome {
                key,
                result: FetchResult::SourceFailed,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Audit result handler
// ---------------------------------------------------------------------------

/// Format the first confirmed-failed key as a 16-hex-char label.
///
/// Pairs with `challenged_peer` to form a stable cross-host correlation
/// handle in the audit-failure log line, e.g.
///
/// ```text
/// Audit failure for <peer>: …, `first_failed_key=0x18878f1d2d9e0612`
/// ```
///
/// Falls back to `"0x"` when the list is empty so the log line never
/// contains a misleading default.
fn first_failed_key_label(confirmed_failed_keys: &[XorName]) -> String {
    confirmed_failed_keys.first().map_or_else(
        || "0x".to_string(),
        |k| format!("0x{}", hex::encode(&k[..8])),
    )
}

/// Execute the side effects for a subtree storage-commitment audit failure.
///
/// Subtree timeouts are fully graced: the multi-round, multi-chunk challenge can
/// legitimately time out on slow or loaded honest peers, so it never touches the
/// responsible-chunk audit path or its timeout accounting. Confirmed subtree
/// failures still penalise immediately and revoke holder credit.
async fn handle_subtree_failed_audit(
    challenged_peer: &PeerId,
    confirmed_failed_key_count: usize,
    reason: &AuditFailureReason,
    p2p_node: &Arc<P2PNode>,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    recent_provers: &Arc<RwLock<RecentProvers>>,
) {
    if matches!(reason, AuditFailureReason::Timeout) {
        debug!(
            "Audit timeout for {challenged_peer} fully graced \
             (subtree audit does not evict on timeout)"
        );
        return;
    }

    // The caller already logged the rich failure line with reason + per-category
    // summary; avoid a redundant second error log here.
    let _ = confirmed_failed_key_count;
    {
        let mut state = sync_state.write().await;
        state.clear_active_bootstrap_claim(challenged_peer);
    }
    {
        let mut provers_guard = recent_provers.write().await;
        apply_audit_failure_credit_revocation(&mut provers_guard, challenged_peer, reason);
    }
    // Deliberately NOT routed through the release switch. This is the commitment-bound
    // subtree audit: the peer published a signed claim to hold these keys and could not
    // answer for them. That contract is enforced in every release, including the one that
    // withholds the penalty for merely not holding a close-group chunk, because the whole
    // migration depends on a node's reduced commitment still meaning something.
    p2p_node
        .report_trust_event(
            challenged_peer,
            TrustEvent::ApplicationFailure(config::AUDIT_FAILURE_TRUST_WEIGHT),
        )
        .await;
}

/// Handle audit result: log findings and emit trust events.
async fn handle_subtree_audit_result(
    result: &AuditTickResult,
    p2p_node: &Arc<P2PNode>,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    recent_provers: &Arc<RwLock<RecentProvers>>,
    config: &ReplicationConfig,
) {
    match result {
        AuditTickResult::Passed {
            challenged_peer,
            keys_checked,
        } => {
            protocol::record_audit_pass(protocol::AuditOutcomeKind::Subtree);
            debug!("Audit passed for {challenged_peer} ({keys_checked} keys)");
            // Peer responded normally — clear the active bootstrap claim while
            // retaining history so a later claim is treated as repeated abuse.
            {
                let mut state = sync_state.write().await;
                state.clear_active_bootstrap_claim(challenged_peer);
            }
            p2p_node
                .report_trust_event(
                    challenged_peer,
                    TrustEvent::ApplicationSuccess(REPLICATION_TRUST_WEIGHT),
                )
                .await;
        }
        AuditTickResult::Failed {
            evidence,
            no_response_class,
        } => {
            if let FailureEvidence::AuditFailure {
                challenged_peer,
                confirmed_failed_keys,
                summary,
                reason,
                ..
            } = evidence
            {
                protocol::record_audit_fail(protocol::AuditOutcomeKind::Subtree, reason);
                // Rich diagnostics (from main's audit-failure logging) + the
                // first-failed-key correlation handle.
                let first_failed_key = first_failed_key_label(confirmed_failed_keys);
                let audit_failure_class = no_response_class.unwrap_or("confirmed");
                error!(
                    "Audit failure for {challenged_peer}: reason={reason:?}, audit_failure_class={}, confirmed_failed_keys={}, challenged_keys={}, absent_keys={}, digest_mismatch_keys={}, first_failed_key={first_failed_key}",
                    audit_failure_class,
                    confirmed_failed_keys.len(),
                    summary.challenged_keys,
                    summary.absent_keys,
                    summary.digest_mismatch_keys,
                );
                // Route the side effects through the subtree-only failure path.
                // Responsible-chunk `AuditChallenge` handling intentionally uses
                // its own old immediate-penalty handler below.
                handle_subtree_failed_audit(
                    challenged_peer,
                    confirmed_failed_keys.len(),
                    reason,
                    p2p_node,
                    sync_state,
                    recent_provers,
                )
                .await;
            }
        }
        AuditTickResult::BootstrapClaim { peer } => {
            // Gap 6: BootstrapClaimAbuse grace period in audit path.
            // Separate state mutation from network I/O to avoid holding the
            // write lock across report_trust_event.
            let should_report = {
                let now = Instant::now();
                let mut state = sync_state.write().await;
                match state.observe_bootstrap_claim(*peer, now, config.bootstrap_claim_grace_period)
                {
                    BootstrapClaimObservation::WithinGrace { .. } => {
                        debug!("Audit: peer {peer} claims bootstrapping (within grace period)");
                        false
                    }
                    BootstrapClaimObservation::PastGrace { first_seen } => {
                        warn!(
                            "Audit: peer {peer} claiming bootstrap past grace period \
                             ({:?} > {:?}), reporting abuse",
                            now.duration_since(first_seen),
                            config.bootstrap_claim_grace_period,
                        );
                        true
                    }
                    BootstrapClaimObservation::Repeated { first_seen } => {
                        warn!(
                            "Audit: peer {peer} repeated bootstrap claim after previously \
                             stopping; first claim was {:?} ago, reporting abuse",
                            now.duration_since(first_seen),
                        );
                        true
                    }
                }
            };
            if should_report {
                p2p_node
                    .report_trust_event(
                        peer,
                        TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                    )
                    .await;
            }
        }
        AuditTickResult::Idle | AuditTickResult::InsufficientKeys => {}
    }
}

/// Whether a confirmed audit failure with this reason clears the peer's active
/// bootstrap claim. A `Timeout` does not (the peer may still be legitimately
/// bootstrapping); every confirmed storage-integrity reason does.
///
/// Responsible-chunk `AuditChallenge` failures use this directly: timeouts keep
/// the bootstrap claim, matching the pre-ADR-0002 behaviour, while every failure
/// still reports the normal audit trust penalty.
fn audit_failure_clears_bootstrap_claim(reason: &AuditFailureReason) -> bool {
    !matches!(reason, AuditFailureReason::Timeout)
}

/// Handle the result of a responsible-chunk audit tick (audit #2): emit trust
/// events and manage bootstrap-claim state.
///
/// This is intentionally separate from the subtree audit result handler. A
/// responsible-chunk `AuditChallenge` `Failed` result reports
/// `ApplicationFailure` immediately for every reason, including `Timeout`,
/// restoring the pre-ADR-0002 behaviour.
#[allow(clippy::too_many_lines)]
async fn handle_audit_result(
    result: &AuditTickResult,
    p2p_node: &Arc<P2PNode>,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    config: &ReplicationConfig,
) {
    match result {
        AuditTickResult::Passed {
            challenged_peer,
            keys_checked,
        } => {
            protocol::record_audit_pass(protocol::AuditOutcomeKind::Responsible);
            debug!("Audit passed for {challenged_peer} ({keys_checked} keys)");
            {
                let mut state = sync_state.write().await;
                state.clear_active_bootstrap_claim(challenged_peer);
            }
            p2p_node
                .report_trust_event(
                    challenged_peer,
                    TrustEvent::ApplicationSuccess(REPLICATION_TRUST_WEIGHT),
                )
                .await;
        }
        AuditTickResult::Failed {
            evidence,
            no_response_class,
        } => {
            if let FailureEvidence::AuditFailure {
                challenged_peer,
                confirmed_failed_keys,
                summary,
                reason,
                ..
            } = evidence
            {
                protocol::record_audit_fail(protocol::AuditOutcomeKind::Responsible, reason);
                let first_failed_key = first_failed_key_label(confirmed_failed_keys);
                let audit_failure_class = no_response_class.unwrap_or("confirmed");
                error!(
                    "Audit failure for {challenged_peer}: reason={reason:?}, audit_failure_class={}, confirmed_failed_keys={}, challenged_keys={}, absent_keys={}, digest_mismatch_keys={}, first_failed_key={first_failed_key}",
                    audit_failure_class,
                    confirmed_failed_keys.len(),
                    summary.challenged_keys,
                    summary.absent_keys,
                    summary.digest_mismatch_keys,
                );
                if audit_failure_clears_bootstrap_claim(reason) {
                    let mut state = sync_state.write().await;
                    state.clear_active_bootstrap_claim(challenged_peer);
                } else {
                    debug!("Audit timeout for {challenged_peer}; retaining active bootstrap claim");
                }
                config::penalise_unheld_close_group_chunk(
                    p2p_node,
                    challenged_peer,
                    crate::replication::audit_metrics::AuditType::ResponsibleChunk.as_str(),
                    config::AUDIT_FAILURE_TRUST_WEIGHT,
                )
                .await;
            }
        }
        AuditTickResult::BootstrapClaim { peer } => {
            let should_report = {
                let now = Instant::now();
                let mut state = sync_state.write().await;
                match state.observe_bootstrap_claim(*peer, now, config.bootstrap_claim_grace_period)
                {
                    BootstrapClaimObservation::WithinGrace { .. } => {
                        debug!("Audit: peer {peer} claims bootstrapping (within grace period)");
                        false
                    }
                    BootstrapClaimObservation::PastGrace { first_seen } => {
                        warn!(
                            "Audit: peer {peer} claiming bootstrap past grace period \
                             ({:?} > {:?}), reporting abuse",
                            now.duration_since(first_seen),
                            config.bootstrap_claim_grace_period,
                        );
                        true
                    }
                    BootstrapClaimObservation::Repeated { first_seen } => {
                        warn!(
                            "Audit: peer {peer} repeated bootstrap claim after previously \
                             stopping; first claim was {:?} ago, reporting abuse",
                            now.duration_since(first_seen),
                        );
                        true
                    }
                }
            };
            if should_report {
                p2p_node
                    .report_trust_event(
                        peer,
                        TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                    )
                    .await;
            }
        }
        AuditTickResult::Idle | AuditTickResult::InsufficientKeys => {}
    }
}

/// Whether a confirmed audit failure with this reason should revoke the
/// peer's `recent_provers` holder credit immediately (v12 §6).
///
/// `true` for any reason where the peer actually answered (or admitted
/// it cannot): `DigestMismatch`, `KeyAbsent`, `Rejected` ("missing
/// bytes for committed key"), `MalformedResponse` — these prove the
/// peer no longer holds what it committed to, so it must not keep
/// holder credit for the proof TTL. `false` for `Timeout`: a single
/// dropped packet must not strip an honest peer; the 40-min TTL is the
/// deliberate liveness cushion there.
fn audit_failure_revokes_holder_credit(reason: &AuditFailureReason) -> bool {
    !matches!(reason, AuditFailureReason::Timeout)
}

/// Apply the holder-credit revocation decision for a confirmed audit
/// failure. Pure over `RecentProvers` so the handler wiring is unit-
/// testable without a live `P2PNode`: the production `Failed` arm of
/// `handle_subtree_audit_result` calls exactly this.
fn apply_audit_failure_credit_revocation(
    provers: &mut RecentProvers,
    challenged_peer: &PeerId,
    reason: &AuditFailureReason,
) {
    if audit_failure_revokes_holder_credit(reason) {
        provers.forget_peer(challenged_peer);
    }
}

// `admit_bootstrap_hints` was consolidated into `admit_and_queue_hints`.

// ---------------------------------------------------------------------------
// Storage-bound audit (ADR-0002) — gossip trigger + auditor-side ingestion
// ---------------------------------------------------------------------------

/// State the gossip-audit trigger needs to spawn an audit. Bundled so the
/// message handler passes one value instead of a long argument list; all
/// fields are cheap `Arc` clones.
#[derive(Clone)]
struct GossipAuditTrigger {
    p2p_node: Arc<P2PNode>,
    config: Arc<ReplicationConfig>,
    recent_provers: Arc<RwLock<RecentProvers>>,
    sync_state: Arc<RwLock<NeighborSyncState>>,
    /// Shared "an audit actually launched" cooldown, consulted by BOTH the
    /// gossip-lottery path and the monetized first-audit scheduler. Stamped
    /// only when a real audit is about to be sent — never by a losing lottery
    /// ticket — so gossip traffic alone can never suppress a paid first audit.
    cooldown: Arc<RwLock<HashMap<PeerId, Instant>>>,
    detached_task_tracker: TaskTracker,
    /// Gossip-private lottery attempt window: stamped on every roll (win or
    /// lose) so a gossip flood cannot re-roll the lottery within the window.
    /// The first-audit scheduler never reads this map.
    lottery_attempts: Arc<RwLock<HashMap<PeerId, Instant>>>,
}

/// What a gossip ingest yields for the audit trigger: the commitment hash to
/// pin and the `key_count` needed to size the response deadline from the actual
/// `ceil(sqrt(N))` subtree (ADR-0002). Returned on every VALID gossip (changed
/// or not) so a stable-keyset node stays auditable — not just on its first
/// commitment.
#[derive(Debug, Clone, Copy)]
struct AuditTarget {
    pin_hash: [u8; 32],
    key_count: u32,
}

/// ADR-0004: a commitment that backed a payment, surfaced by the payment
/// verifier's cross-check so it can receive a **deterministic first audit**.
///
/// Sent from the verifier to the replication engine's first-audit drainer. The
/// drainer dedups by `pin` (a pin gets one deterministic first audit; later
/// audits of the same peer revert to the gossip lottery), orders most-recently-
/// monetized first, and runs the same `run_subtree_audit` under the same
/// per-peer cooldown and concurrency caps — only the lottery is bypassed.
#[derive(Debug, Clone, Copy)]
pub struct MonetizedPinEvent {
    /// The peer whose commitment backed the payment.
    pub peer: PeerId,
    /// The pinned commitment hash.
    pub pin: [u8; 32],
    /// The committed key count (sizes the audit deadline).
    pub key_count: u32,
    /// The accused's own SIGNED quote timestamp. The first-audit drainer skips a
    /// pin whose quote is older than the answerability window (ADR-0004 A1
    /// guardrail A): with grace removed, challenging an aged-out pin would
    /// false-convict, so a stale client-forwarded quote must not trigger an audit.
    pub quote_ts: SystemTime,
}

/// Per-peer audit cooldown check-and-stamp (ADR-0002 "occasional surprise
/// exams, keeps load low"). Returns `true` if `peer` may be audited now (and
/// stamps `now`), `false` if it was audited within
/// `AUDIT_ON_GOSSIP_COOLDOWN_SECS`. Bounds the map under a flood of distinct
/// peers. Pure over the passed map so the flood/cooldown behaviour is testable
/// without a live node: a burst of gossips from one peer yields at most one
/// `true` per cooldown window.
fn cooldown_allows_audit(map: &mut HashMap<PeerId, Instant>, peer: &PeerId, now: Instant) -> bool {
    let cooldown = Duration::from_secs(config::AUDIT_ON_GOSSIP_COOLDOWN_SECS);
    let known = match map.get(peer) {
        Some(&last) => {
            if now.saturating_duration_since(last) < cooldown {
                return false;
            }
            true
        }
        None => false,
    };
    // Bound the map under churn like its siblings (drop the oldest stamp) before
    // admitting a brand-new peer.
    if !known && map.len() >= MAX_LAST_COMMITMENT_BY_PEER {
        if let Some(victim) = map.iter().min_by_key(|(_, &ts)| ts).map(|(p, _)| *p) {
            map.remove(&victim);
        }
    }
    map.insert(*peer, now);
    true
}

/// Read-only companion to [`cooldown_allows_audit`]: whether `peer` is OUTSIDE
/// its cooldown at `now`, WITHOUT stamping. Used by the first-audit reserve gate
/// (ADR-0004 Amendment 2 E′) to avoid reserving a peer that a recent audit
/// already covered; the authoritative check-and-stamp still runs at promotion,
/// so this is only an optimization and never the security boundary.
fn cooldown_would_allow(map: &HashMap<PeerId, Instant>, peer: &PeerId, now: Instant) -> bool {
    let cooldown = Duration::from_secs(config::AUDIT_ON_GOSSIP_COOLDOWN_SECS);
    map.get(peer).map_or(true, |&last| {
        now.saturating_duration_since(last) >= cooldown
    })
}

/// The gossip-audit launch decision in ONE place so the ordering is shared
/// between production and its test (ADR-0002 "occasional surprise exams").
///
/// Order matters and is the security-relevant property. Gate 1 checks-and-stamps
/// the gossip-PRIVATE `attempts` window, win or lose: if the lottery were
/// sampled first, a gossip flood would re-roll it on every message until one
/// won, multiplying audits, so each peer gets at most one lottery roll per
/// window regardless of how often it gossips. Gate 3 checks-and-stamps the
/// SHARED `launched` cooldown — the map the monetized first-audit scheduler
/// also consults — only after a WIN, i.e. only when a real audit is about to be
/// sent. A losing ticket must never stamp `launched`: no challenge went on the
/// wire, so it must not defer a paid first audit (repeatable losses could
/// otherwise hold a monetized pin past its answerability window). Production
/// calls this with `lottery_wins = gen_bool(AUDIT_ON_GOSSIP_PROBABILITY)`; the
/// test calls it with a deterministic `lottery_wins`, so a reorder regression
/// here fails the test.
fn audit_launch_decision(
    attempts: &mut HashMap<PeerId, Instant>,
    launched: &mut HashMap<PeerId, Instant>,
    peer: &PeerId,
    now: Instant,
    lottery_wins: bool,
) -> bool {
    // Gate 1: lottery-attempt window check-and-stamp (consumes the attempt
    // window even on a loss; private to the gossip path).
    if !cooldown_allows_audit(attempts, peer, now) {
        return false;
    }
    // Gate 2: the probability lottery. A loss stops here and stamps nothing
    // shared.
    if !lottery_wins {
        return false;
    }
    // Gate 3: the shared actual-audit cooldown (a recent real audit from
    // either path still suppresses this launch), stamped only on launch.
    cooldown_allows_audit(launched, peer, now)
}

/// On a peer's *changed* gossiped commitment, maybe launch a subtree audit
/// (ADR-0002): fire with probability `AUDIT_ON_GOSSIP_PROBABILITY`, subject to a
/// per-peer cooldown, pinned to the just-ingested root. Detached so gossip
/// handling is never blocked on a network round-trip.
async fn maybe_trigger_gossip_audit(
    trigger: &GossipAuditTrigger,
    peer: &PeerId,
    target: AuditTarget,
) {
    // The launch decision (attempt-window, lottery, shared-cooldown ordering)
    // lives in the pure `audit_launch_decision` so the ordering is shared with
    // its test. Sample the lottery here, then let the helper apply the gates.
    let now = Instant::now();
    let lottery_wins = rand::thread_rng().gen_bool(config::AUDIT_ON_GOSSIP_PROBABILITY);
    {
        // Lock order: attempts before the shared cooldown; this is the only
        // place both are held together.
        let mut attempts = trigger.lottery_attempts.write().await;
        let mut launched = trigger.cooldown.write().await;
        if !audit_launch_decision(&mut attempts, &mut launched, peer, now, lottery_wins) {
            return;
        }
    }

    let detached_task_tracker = trigger.detached_task_tracker.clone();
    let trigger = trigger.clone();
    let peer = *peer;
    detached_task_tracker.spawn(async move {
        let credit = storage_commitment_audit::AuditCredit {
            recent_provers: &trigger.recent_provers,
        };
        let result = storage_commitment_audit::run_subtree_audit_with_origin(
            &trigger.p2p_node,
            &trigger.config,
            &peer,
            target.pin_hash,
            target.key_count,
            Some(&credit),
            storage_commitment_audit::SubtreeAuditOrigin::Gossip,
        )
        .await;
        handle_subtree_audit_result(
            &result,
            &trigger.p2p_node,
            &trigger.sync_state,
            &trigger.recent_provers,
            &trigger.config,
        )
        .await;
    });
}

/// Atomic check-and-stamp of the per-peer commitment sig-verify rate limit.
///
/// Returns `true` if a signature verify is allowed now (and stamps the attempt
/// time), `false` if the peer is within [`COMMITMENT_SIG_VERIFY_MIN_INTERVAL`]
/// of its last attempt. Holds one write lock across the decision so two
/// concurrent ingests from the same peer cannot both pass. Stamps BEFORE the
/// caller's expensive verify so a slow/failed verify still rate-limits the next
/// message. Bounds the map under a flood of distinct peer ids.
async fn sig_verify_rate_limit_ok(
    sig_verify_attempts: &Arc<RwLock<HashMap<PeerId, Instant>>>,
    source: &PeerId,
    now: Instant,
) -> bool {
    let mut attempts = sig_verify_attempts.write().await;
    if let Some(&last) = attempts.get(source) {
        if now.saturating_duration_since(last) < COMMITMENT_SIG_VERIFY_MIN_INTERVAL {
            return false;
        }
    }
    if attempts.len() >= MAX_LAST_COMMITMENT_BY_PEER && !attempts.contains_key(source) {
        if let Some(victim) = attempts.iter().min_by_key(|(_, &ts)| ts).map(|(p, _)| *p) {
            attempts.remove(&victim);
        }
    }
    attempts.insert(*source, now);
    true
}

/// Verify + store an inbound commitment from a gossip peer.
///
/// Called from the inbound `NeighborSyncRequest`/`Response` handlers and
/// the bootstrap-sync loop. Drops the commitment unless all five gates
/// pass:
///   1. `source` is in our DHT routing table (sybil/churn cap).
///   2. `commitment.sender_peer_id == source.as_bytes()` (peer-id
///      binding to the authenticated transport peer).
///   3. `BLAKE3(commitment.sender_public_key) == commitment.sender_peer_id`
///      (the embedded pubkey actually belongs to the claimed identity —
///      saorsa-core derives `PeerId = BLAKE3(pubkey)`).
///   4. `verify_commitment_signature(commitment)` succeeds against the
///      embedded public key. The signed payload binds the pubkey, so an
///      adversary cannot swap the key while keeping the body.
///   5. The cache has room or this is an update for an existing entry
///      (sybil cap, `MAX_LAST_COMMITMENT_BY_PEER`).
///
/// On all-pass, the commitment is stored as the auditor's per-peer
/// "last known commitment" for use as `expected_commitment_hash` in
/// future audits.
///
/// Failures (no commitment / mismatched peer id / bad signature) are
/// silent drops — gossip is best-effort and a malformed commitment from
/// one peer should not affect anything else.
///
/// Returns `Some(AuditTarget)` whenever a VALID commitment was stored (whether
/// or not its root changed), so the caller can run a probabilistic,
/// cooldown-gated subtree audit. Returning on *every* valid gossip — not only
/// changed ones — is deliberate (ADR-0002): a node with a stable key set keeps
/// being auditable, so it cannot pass one audit and then delete data while
/// re-gossiping the same root forever. The cooldown + probability bound the
/// audit frequency. Returns `None` only if the commitment was dropped (failed a
/// gate) or there is nothing to pin.
///
/// Handle a capable peer gossiping `None` (a commitment downgrade).
///
/// A capable peer that previously gossiped a commitment but now gossips `None`
/// is trying to drop off the audit path. Within the answerability window we keep
/// the cached commitment pinned AND return it as an audit target so this gossip
/// still schedules a subtree audit against the peer's last known commitment — if
/// it genuinely dropped the data, the audit fails (there is no periodic tick, so
/// the trigger MUST fire here or the downgrade is never re-challenged).
///
/// But this only holds within the SAME `GOSSIP_ANSWERABILITY_TTL` the responder
/// honours for its own retired commitment: once that elapses since we last
/// received the peer's commitment, an honest peer has legitimately retired that
/// root (its responder side `retire_current`s and lets it age out) and can no
/// longer answer a pin on it. Auditing it past the TTL would manufacture a false
/// failure, so we then forget the cached commitment (keeping the sticky
/// `commitment_capable` bit) and stop pinning it.
async fn handle_commitment_downgrade(
    source: &PeerId,
    last_commitment_by_peer: &Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
) -> Option<AuditTarget> {
    let now = Instant::now();
    let cached = {
        let map = last_commitment_by_peer.read().await;
        map.get(source).and_then(|rec| {
            if !rec.commitment_capable {
                return None;
            }
            let last = rec.last_commitment()?;
            let pin = rec.commitment_hash()?;
            let fresh = now.saturating_duration_since(rec.received_at) < GOSSIP_ANSWERABILITY_TTL;
            Some((pin, last.key_count, fresh))
        })
    };
    match cached {
        Some((pin, key_count, true)) => {
            warn!(
                "ingest_peer_commitment: commitment-capable peer {source} sent None \
                 (downgrade attempt); auditing against its last cached commitment"
            );
            Some(AuditTarget {
                pin_hash: pin,
                key_count,
            })
        }
        Some((_, _, false)) => {
            // Cached commitment has aged past the answerability window — forget
            // it so we stop pinning a root the peer is no longer obliged to
            // answer. Keep `commitment_capable` (sticky). Re-check freshness
            // UNDER the write lock (compare-and-clear): a concurrent valid gossip
            // from this peer may have refreshed `received_at` in the gap between
            // our read and write locks; if so, leave its fresh commitment intact.
            if let Some(rec) = last_commitment_by_peer.write().await.get_mut(source) {
                let still_stale =
                    now.saturating_duration_since(rec.received_at) >= GOSSIP_ANSWERABILITY_TTL;
                if still_stale {
                    rec.clear_commitment();
                    debug!(
                        "ingest_peer_commitment: capable peer {source} sent None and its cached \
                         commitment aged past the answerability TTL; forgetting it"
                    );
                }
            }
            None
        }
        None => None,
    }
}

async fn ingest_peer_commitment(
    source: &PeerId,
    commitment: Option<&StorageCommitment>,
    p2p_node: &Arc<P2PNode>,
    last_commitment_by_peer: &Arc<RwLock<HashMap<PeerId, PeerCommitmentRecord>>>,
    ever_capable_peers: &Arc<RwLock<HashSet<PeerId>>>,
    sig_verify_attempts: &Arc<RwLock<HashMap<PeerId, Instant>>>,
) -> Option<AuditTarget> {
    let Some(c) = commitment else {
        return handle_commitment_downgrade(source, last_commitment_by_peer).await;
    };
    // RT-membership gate: only accept commitments from peers in our
    // routing table. Off-RT senders (sybils, drive-by relays) cannot
    // populate the cache, which closes the hole where a flood of
    // off-RT identities could fill the cap and evict honest
    // peers. The neighbor-sync request handler applies the same gate
    // before admitting inbound replication hints (see neighbor_sync.rs
    // `sender_in_rt`); we mirror that policy here for the commitment
    // piggyback.
    if !p2p_node.dht_manager().is_in_routing_table(source).await {
        debug!("ingest_peer_commitment: source {source} not in routing table (dropped)");
        return None;
    }
    // Peer-id binding: the commitment's claimed sender must match the
    // authenticated transport peer (`source`). Defeats relay/replay
    // and also pins which embedded public key we are about to verify
    // against — the verify itself trusts the embedded key, so the
    // peer-id binding is the link to a real identity.
    if &c.sender_peer_id != source.as_bytes() {
        warn!(
            "ingest_peer_commitment: sender_peer_id mismatch from {source} \
             (dropped, possible relay attempt)"
        );
        return None;
    }
    // Peer-id to embedded-pubkey binding: saorsa-core derives PeerId as
    // BLAKE3(pubkey_bytes). Without this check, a responder could sign
    // with a throwaway key they own and lie about which identity it
    // belongs to (the embedded-key signature would verify trivially).
    let derived_peer_id = *blake3::hash(&c.sender_public_key).as_bytes();
    if derived_peer_id != c.sender_peer_id {
        warn!(
            "ingest_peer_commitment: embedded pubkey does not hash to claimed peer_id for \
             {source} (dropped, throwaway-key attack)"
        );
        return None;
    }
    // §2 step 3 + §11 DoS: rate-limit per-peer to at most one ML-DSA
    // signature verify per `COMMITMENT_SIG_VERIFY_MIN_INTERVAL`. A
    // sybil/RT-membership-bypassing peer that flooded valid-looking
    // gossip would otherwise burn CPU on every message. The rate
    // limit is checked AFTER cheap structural gates (RT, peer-id
    // binding, pubkey-binding) and BEFORE the expensive sig verify.
    //
    // Tracked in `sig_verify_attempts` (separate from
    // last_commitment_by_peer) so EVERY attempt — successful or not —
    // bumps the rate-limit clock. Reading only from PeerCommitmentRecord
    // would skip the cap for peers we've never successfully verified,
    // letting a flood of invalid-but-structurally-plausible gossips
    // burn CPU.
    let now = Instant::now();
    if !sig_verify_rate_limit_ok(sig_verify_attempts, source, now).await {
        debug!(
            "ingest_peer_commitment: rate-limited sig verify from {source} \
             (< {COMMITMENT_SIG_VERIFY_MIN_INTERVAL:?} since last attempt); dropped"
        );
        return None;
    }
    // Signature verify, using the public key embedded in the commitment
    // itself. The pubkey is bound by the signature payload (see
    // commitment_signed_payload) so an adversary cannot keep the body
    // and swap the key to one they hold the secret for.
    if !crate::replication::commitment::verify_commitment_signature(c) {
        warn!(
            "ingest_peer_commitment: signature did not verify under embedded key for {source} \
             (dropped, forged commitment)"
        );
        return None;
    }
    // The new commitment's hash, used to store and to pin for the audit target.
    let new_hash = commitment_hash(c);
    let mut map = last_commitment_by_peer.write().await;
    // Sybil/churn cap: if we're at the hard cap AND this is a new peer,
    // evict an arbitrary existing entry to make room. Updates for peers
    // already in the map are always accepted (they replace, not grow).
    if map.len() >= MAX_LAST_COMMITMENT_BY_PEER && !map.contains_key(source) {
        // Drop one arbitrary entry. HashMap iter order is random which
        // is fine — over time PeerRemoved cleanup keeps the working set
        // anchored on the real RT membership; this cap only fires under
        // active flooding attempts.
        if let Some(victim) = map.keys().next().copied() {
            map.remove(&victim);
            warn!(
                "ingest_peer_commitment: cache full ({MAX_LAST_COMMITMENT_BY_PEER}); \
                 evicted {victim} to admit {source}"
            );
        }
    }
    // Preserve sticky commitment_capable across updates — once true,
    // always true. New entries start with capable = true (we just
    // verified a valid commitment from this peer).
    map.entry(*source)
        .and_modify(|r| {
            // set_commitment refreshes the cached hash (§13) alongside the
            // commitment + received_at so they never drift.
            r.set_commitment(c.clone(), now);
            r.last_sig_verify_at = now;
            r.commitment_capable = true; // sticky-redundant but explicit
        })
        .or_insert_with(|| PeerCommitmentRecord::from_verified(c.clone(), now));
    drop(map);
    // Record the sticky "ever v12-capable" bit in a set independent of
    // `last_commitment_by_peer` (whose entries can be evicted by
    // `PeerRemoved` and the sybil cap). This is what the §3 audit
    // shield and the §6 holder-eligibility closure consult to decide
    // whether the peer is expected to speak v12.
    //
    // Capped at `MAX_EVER_CAPABLE_PEERS` to bound memory under
    // identity-rotation attacks: once full, new entries are refused.
    // Refusal degrades over-cap peers to the behaviour before this set
    // existed (treated as legacy on rejoin), which is not a security
    // regression and preserves the historic set stable.
    {
        let mut set = ever_capable_peers.write().await;
        if set.contains(source) || set.len() < MAX_EVER_CAPABLE_PEERS {
            set.insert(*source);
        } else {
            warn!(
                "ingest_peer_commitment: ever_capable_peers at cap \
                 ({MAX_EVER_CAPABLE_PEERS}); refusing to record {source} as sticky-capable"
            );
        }
    }
    // Return an audit target for EVERY valid stored commitment (changed or
    // not), so the caller's cooldown+probability-gated trigger keeps a
    // stable-keyset peer auditable over time (ADR-0002). Only a serialization
    // failure (new_hash == None, unreachable for a real commitment) yields None.
    new_hash.map(|pin_hash| AuditTarget {
        pin_hash,
        key_count: c.key_count,
    })
}

// ---------------------------------------------------------------------------
// Storage-bound audit (v12) — responder commitment rotation
// ---------------------------------------------------------------------------

/// Reload persisted responder retention at startup (ADR-0004 A1). A missing file
/// is a normal fresh start; a corrupt snapshot is logged and skipped (fail-open
/// LOCALLY — the node re-gossips a fresh root — which never grants a remote grace).
async fn load_commitment_retention(state: &ResponderCommitmentState, path: &Path) {
    let bytes = match tokio::fs::read(path).await {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            debug!(
                "Commitment retention: no snapshot at {} (fresh start)",
                path.display()
            );
            return;
        }
        Err(e) => {
            warn!(
                "Commitment retention: failed to read {}: {e}",
                path.display()
            );
            return;
        }
    };
    if let Some(persisted) = PersistedRetention::from_bytes(&bytes) {
        state.restore(&persisted);
        info!(
            "Commitment retention: reloaded {} slot(s) from {}",
            state.retained_slot_count(),
            path.display()
        );
    } else {
        warn!(
            "Commitment retention: corrupt snapshot at {}; starting with empty retention",
            path.display()
        );
    }
}

/// Persist the responder retention snapshot IF it changed since `last` (ADR-0004
/// A1). Write-on-change keeps frequent gossip-stamp refreshes durable without
/// needless disk writes on idle nodes. On success updates `last` to the bytes
/// written; on a serialization/write error the existing on-disk snapshot is left
/// intact (never truncated).
async fn persist_retention_if_changed(
    state: &ResponderCommitmentState,
    path: &Path,
    last: &mut Option<Vec<u8>>,
) {
    let Some(bytes) = state.snapshot().to_bytes() else {
        warn!("Commitment retention: serialization failed; keeping previous snapshot");
        return;
    };
    if last.as_deref() == Some(bytes.as_slice()) {
        return;
    }
    if write_retention_atomic(path, bytes.clone()).await {
        *last = Some(bytes);
    }
}

/// Durably write `bytes` to `path`: temp file → fsync temp → atomic rename →
/// fsync parent dir (so the rename itself survives a crash). Returns `true` on
/// success. Only the retention-persist loop writes this path, so a fixed temp
/// name is safe.
async fn write_retention_atomic(path: &Path, bytes: Vec<u8>) -> bool {
    let path = path.to_path_buf();
    let res = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::File::open(&tmp)?.sync_all()?;
        std::fs::rename(&tmp, &path)?;
        // Fsync the directory so the rename (the durable-commit point) is not
        // lost on a crash right after it. An empty parent (relative filename)
        // means the current directory.
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    })
    .await;
    match res {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            warn!("Commitment retention: persist failed: {e}");
            false
        }
        Err(e) => {
            warn!("Commitment retention: persist task join failed: {e}");
            false
        }
    }
}

/// Read the current key set, build + sign a fresh
/// `StorageCommitment`, and rotate it into `state` as the new `current`.
/// The prior `current` is demoted to `previous`; the prior `previous` is
/// dropped (per `ResponderCommitmentState::rotate`).
///
/// For content-addressed chunks (Autonomi's chunk store), `address ==
/// BLAKE3(content)`, so `bytes_hash := key` and we don't have to
/// re-read each chunk's bytes to compute the leaf hash.
///
/// Skips (returns `Ok(())`) if the key set is empty — no commitment to
/// rotate. The auditor side handles "no commitment for this peer" by
/// falling back to the legacy plain-digest audit path.
async fn rebuild_and_rotate_commitment(
    storage: &Arc<ChunkStore>,
    identity: &Arc<NodeIdentity>,
    state: &Arc<ResponderCommitmentState>,
    p2p: &Arc<P2PNode>,
    config: &Arc<ReplicationConfig>,
) -> Result<()> {
    // Not `all_keys()`. While the node is bridging off the legacy store these are the
    let stored_keys = storage
        .all_keys()
        .await
        .map_err(|e| Error::Storage(format!("commitment build: read keys: {e}")))?;

    // Commit only to keys we are still RESPONSIBLE for ("want-to-hold"), not
    // everything currently on disk ("hold"). This is the half of the retention
    // contract that lets out-of-range chunks age out: a key that has left our
    // close group is excluded from the NEXT commitment, so once its last gossip
    // ages past GOSSIP_ANSWERABILITY_TTL it falls out of the in-window retained
    // set, `ResponderCommitmentState::is_held` goes false,
    // and the pruner (which until then vetoes its deletion) reclaims it. Without
    // this filter the pruner's reprieve would keep re-committing stale keys
    // forever (the rebuild reads all_keys, so a retained-on-disk key would be
    // re-committed and re-gossiped every rotation — a permanent pin).
    let storage_empty = stored_keys.is_empty();
    let self_id = *p2p.peer_id();
    let mut keys = Vec::with_capacity(stored_keys.len());
    for k in stored_keys {
        if admission::is_responsible(&self_id, &k, p2p, config.close_group_size).await {
            keys.push(k);
        }
    }

    if keys.is_empty() {
        if storage_empty {
            // Storage is genuinely empty — there is nothing to answer for, so
            // drop the previously advertised commitment immediately. Keeping it
            // would leave remote auditors pinning a hash we can never satisfy
            // again (the bytes are gone).
            if state.retained_slot_count() > 0 {
                debug!("Commitment rotation: storage empty, clearing retained slots");
                state.clear_all();
            }
            return Ok(());
        }
        // Bytes are still on disk but no key is currently in range. We must NOT
        // clear retention here: a peer may still be pinning a root we gossiped
        // moments ago and could demand its bytes in a round-2 challenge, which
        // we can still answer (the bytes are present). But we must STOP
        // advertising the stale commitment: retire it so `current()` returns
        // `None` and the gossip-emit sites stop re-emitting and re-stamping it.
        // The retired slot then ages out by its gossip-answerability TTL while
        // remaining answerable for in-flight pins until then. Once it ages out,
        // `is_held` flips false and the pruner reclaims the now-uncommitted,
        // out-of-range chunks. (Calling `age_out` alone would leave `current()`
        // pointing at the stale root, which the gossip loop would keep
        // re-stamping — pinning its keys forever.)
        debug!(
            "Commitment rotation: no responsible keys to commit to; retiring current commitment \
             (stays answerable until its gossip TTL lapses, bytes still on disk)"
        );
        state.retire_current();
        return Ok(());
    }

    // Cap to MAX_COMMITMENT_KEY_COUNT for v12 (responder must not commit
    // to more than the protocol limit; auditor would reject the
    // commitment otherwise).
    let cap = commitment::MAX_COMMITMENT_KEY_COUNT as usize;
    if keys.len() > cap {
        warn!(
            "Commitment rotation: key set ({}) exceeds MAX_COMMITMENT_KEY_COUNT ({}); \
             truncating — investigate as this likely means a misconfiguration",
            keys.len(),
            cap
        );
    }

    // INVARIANT: this module is only used with CONTENT-ADDRESSED chunks,
    // where `key == BLAKE3(content)`, so `bytes_hash := key` and we skip a
    // full chunk re-read per rotation.
    //
    // Consequence to be precise about: because the leaf is `(key, key)`,
    // the Merkle root commits to the SET OF KEYS, not to the bytes. The
    // commitment therefore binds "which keys I claim to hold"; it does NOT
    // by itself prove byte possession. Byte possession is enforced by the
    // round-2 slice audit: a Bao verified slice decoded against the chunk
    // ADDRESS plus a keyed nonced block-tree opening under a fresh per-audit
    // nonce, so a responder that holds the key list but dropped the bytes
    // cannot answer. This is sound ONLY while keys are content addresses;
    // the round-1 verifier enforces `bytes_hash == key` on every audited leaf
    // (`evaluate_subtree_structure`), so a non-content-addressed
    // `(key, bytes_hash)` leaf is rejected rather than letting a byte-less node
    // earn credit for `key`. If this module is ever reused for
    // non-content-addressed records, that `(k, k)` shortcut AND the verifier
    // gate must be replaced with `(key, BLAKE3(bytes))` computed from real bytes.
    let entries: Vec<_> = keys.into_iter().take(cap).map(|k| (k, k)).collect();

    // No-op-rotation guard: compute just the Merkle root from `entries`
    // and compare against the currently-advertised commitment's root.
    // If they match, the key set is unchanged and a new rotation would
    // only swap a randomized ML-DSA signature for a fresh one — same
    // content, different commitment_hash. That invalidates every
    // outstanding `recent_provers` credit on this node across the
    // close group with no security benefit, breaking steady-state
    // quorum liveness on large nodes that can't re-audit every key
    // every rotation interval. Skip the rotation entirely when the
    // tree is unchanged.
    // Build the tree ONCE here (moving `entries`): it serves both the no-op
    // root check below and, if we proceed, the signed commitment via
    // `build_from_tree` (§11 — previously the tree was built here and AGAIN
    // inside `BuiltCommitment::build`).
    let candidate_tree = commitment::MerkleTree::build(entries)
        .map_err(|e| Error::Crypto(format!("commitment tree build: {e}")))?;
    let candidate_root = candidate_tree.root();
    if let Some(current) = state.current() {
        if current.commitment().root == candidate_root {
            debug!(
                "Commitment rotation: key set unchanged (root={}); skipping no-op re-sign",
                hex::encode(candidate_root)
            );
            // Even though we skip re-signing (to avoid invalidating holder
            // credit), retention must still advance on the wall clock: a
            // previously-gossiped commitment that holds a now-out-of-range key
            // must be able to age out of the answerability window even when the
            // committed key set is frozen here for many rotations. Without this,
            // the no-op guard would pin a stale slot — and its key — forever.
            state.age_out();
            return Ok(());
        }
    }

    let sk_bytes = identity.secret_key_bytes().to_vec();
    let sk = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &sk_bytes)
        .map_err(|e| Error::Crypto(format!("commitment build: load sk: {e}")))?;
    let pk_bytes = identity.public_key().as_bytes().to_vec();
    let peer_id_bytes = *p2p.peer_id().as_bytes();

    let built = commitment_state::BuiltCommitment::build_from_tree(
        candidate_tree,
        &peer_id_bytes,
        &sk,
        &pk_bytes,
    )
    .map_err(|e| Error::Crypto(format!("commitment build: {e}")))?;

    let hash = hex::encode(built.hash());
    let key_count = built.commitment().key_count;
    state.rotate(built);
    info!("Storage commitment rotated: hash={hash} key_count={key_count}");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {

    /// The two fetch failures mean different things and must be charged differently.
    ///
    /// `NotFound` is a peer saying it does not hold the chunk, which is what a node
    /// part-way through the migration says about chunks it has legitimately given up, so
    /// it is the lane this release withholds. `Error` has a single producer, the
    /// responder's own storage read failing, and that is never about the migration.
    #[test]
    fn a_missing_chunk_and_a_failed_read_are_different_faults() {
        let key = [7u8; 32];
        assert_eq!(
            fetch_fault_for(&protocol::FetchResponse::NotFound { key }),
            Some(FetchFault::UnheldChunk)
        );
        assert_eq!(
            fetch_fault_for(&protocol::FetchResponse::Error {
                key,
                reason: "read failed".to_string(),
            }),
            Some(FetchFault::ResponderFault)
        );
        assert_eq!(
            fetch_fault_for(&protocol::FetchResponse::Success {
                key,
                data: vec![1, 2, 3],
            }),
            None
        );
    }

    /// The responder's answer says which fault it is, so the mapping from a storage read
    /// to a response is what the classification above rests on.
    ///
    /// A key the peer does not hold reads as `Ok(None)`. A read that fails, whether from
    /// an I/O fault or a failed integrity check, reads as `Err`. Nothing turns the first
    /// into the second.
    #[tokio::test]
    async fn a_missing_key_reads_as_a_plain_miss_and_a_failed_read_as_a_fault() {
        let dir = tempfile::tempdir().expect("temp dir");
        let storage = crate::storage::ChunkStore::new(crate::storage::ChunkStoreConfig {
            root_dir: dir.path().to_path_buf(),
            verify_on_read: true,
            disk_reserve: 0,
        })
        .await
        .expect("open store");

        let absent = [9u8; 32];
        assert!(
            matches!(storage.get(&absent).await, Ok(None)),
            "a chunk this node does not hold must read as a plain miss, not a fault"
        );

        // And the answer each read produces. A miss is `NotFound`, which is the withheld
        // lane; a failed read is `Error`, which is not.
        assert!(matches!(
            fetch_response_for(absent, Ok(None)),
            protocol::FetchResponse::NotFound { .. }
        ));
        assert!(matches!(
            fetch_response_for(absent, Ok(Some(vec![1, 2, 3]))),
            protocol::FetchResponse::Success { .. }
        ));
        assert!(matches!(
            fetch_response_for(
                absent,
                Err(crate::error::Error::Storage("read failed".into()))
            ),
            protocol::FetchResponse::Error { .. }
        ));
    }
    use super::*;
    use super::{
        apply_audit_failure_credit_revocation, audit_failure_clears_bootstrap_claim,
        audit_failure_revokes_holder_credit, audit_launch_decision, coalesce_first_audit_event,
        config, cooldown_allows_audit, first_audit_count_jump, first_audit_terminal_outcome,
        first_failed_key_label, fresh_offer_payment_context, paid_notify_payment_context,
        quote_answerable_through_nominal_jitter, quote_within_audit_window, FirstAuditLimiter,
        FirstAuditObservability, FirstAuditQueueOutcome, FirstAuditScheduler,
        FirstAuditTerminalOutcome, LimiterVerdict, MonetizedPinEvent,
        FIRST_AUDIT_SEND_LATENCY_SLACK, MONETIZED_AUDIT_SKEW_MARGIN,
    };
    use crate::payment::VerificationContext;
    use crate::replication::audit::AuditTickResult;
    use crate::replication::commitment_state::GOSSIP_ANSWERABILITY_TTL;
    use crate::replication::recent_provers::RecentProvers;
    use crate::replication::types::{AuditFailureReason, FailureEvidence};
    use lru::LruCache;
    use saorsa_core::identity::PeerId;
    use std::collections::HashMap;
    use std::num::NonZeroUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::Instant;
    use std::time::SystemTime;

    #[test]
    fn match_replication_protocol_accepts_core_and_subtree_bare_and_rr() {
        for id in [REPLICATION_PROTOCOL_ID, SUBTREE_AUDIT_PROTOCOL_ID] {
            assert_eq!(match_replication_protocol(id), Some((id, false)));
            assert_eq!(
                match_replication_protocol(&format!("{RR_PREFIX}{id}")),
                Some((id, true))
            );
        }
        assert_eq!(
            match_replication_protocol("autonomi.ant.replication.possession-audit.v2"),
            None
        );
        assert_eq!(match_replication_protocol("autonomi.ant.dht.v1"), None);
        assert_eq!(match_replication_protocol(RR_PREFIX), None);
    }

    #[test]
    fn body_matches_protocol_is_symmetric_over_core_and_subtree_bodies() {
        use crate::replication::protocol::{
            AuditChallenge, AuditResponse, FreshReplicationOffer, ReplicationMessageBody,
            SubtreeSliceChallenge,
        };

        let subtree = ReplicationMessageBody::SubtreeSliceChallenge(SubtreeSliceChallenge {
            challenge_id: 1,
            nonce: [0u8; 32],
            challenged_peer_id: [0u8; 32],
            expected_commitment_hash: [0u8; 32],
            openings: vec![],
        });
        let digest_challenge = ReplicationMessageBody::AuditChallenge(AuditChallenge {
            challenge_id: 1,
            nonce: [0u8; 32],
            challenged_peer_id: [0u8; 32],
            keys: vec![[0u8; 32]],
        });
        let digest_response =
            ReplicationMessageBody::AuditResponse(AuditResponse::Bootstrapping { challenge_id: 1 });
        let core = ReplicationMessageBody::FreshReplicationOffer(FreshReplicationOffer {
            key: [0u8; 32],
            data: vec![],
            proof_of_payment: vec![],
        });

        assert!(body_matches_protocol(&subtree, SUBTREE_AUDIT_PROTOCOL_ID));
        assert!(!body_matches_protocol(&subtree, REPLICATION_PROTOCOL_ID));

        for body in [&digest_challenge, &digest_response, &core] {
            assert!(body_matches_protocol(body, REPLICATION_PROTOCOL_ID));
            assert!(!body_matches_protocol(body, SUBTREE_AUDIT_PROTOCOL_ID));
        }

        for body in [&subtree, &digest_challenge, &digest_response, &core] {
            assert!(body_matches_protocol(body, response_protocol_for(body)));
        }
    }

    fn test_peer(b: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        PeerId::from_bytes(bytes)
    }

    /// A structurally valid offer for `data`: real content address, a proof of
    /// the minimum accepted size, distinguished by `proof_marker` so a test can
    /// tell whose proof came back out of the queue.
    fn test_fresh_offer(data: Vec<u8>, proof_marker: u8) -> protocol::FreshReplicationOffer {
        protocol::FreshReplicationOffer {
            key: crate::client::compute_address(&data),
            data,
            proof_of_payment: vec![proof_marker; MIN_PAYMENT_PROOF_SIZE_BYTES],
        }
    }

    fn admit_test_offer(
        in_flight: &FreshOfferInFlight,
        offer: protocol::FreshReplicationOffer,
        source: PeerId,
    ) -> FreshOfferAdmission {
        FreshOfferEntryGuard::admit(in_flight, offer, source, 0, None, Instant::now())
    }

    #[test]
    fn fresh_offer_entry_queues_one_proof_per_source_then_frees_the_key_on_drop() {
        let in_flight: FreshOfferInFlight = Arc::new(Mutex::new(HashMap::new()));
        let data = vec![0x11u8; 64];

        let opened = admit_test_offer(&in_flight, test_fresh_offer(data.clone(), 1), test_peer(1));
        let FreshOfferAdmission::Opened(entry) = opened else {
            panic!("first offer for a key should open the entry")
        };

        // A second sender contributes its proof instead of being turned away:
        // its bytes are provably the same, so only the proof is worth keeping.
        assert!(
            matches!(
                admit_test_offer(&in_flight, test_fresh_offer(data.clone(), 2), test_peer(2)),
                FreshOfferAdmission::Joined
            ),
            "a duplicate from a new source should queue its proof"
        );
        // The same peer twice is not extra evidence, just extra work.
        assert!(
            matches!(
                admit_test_offer(&in_flight, test_fresh_offer(data.clone(), 3), test_peer(1)),
                FreshOfferAdmission::DuplicateSource
            ),
            "one source should hold at most one queued proof per key"
        );

        // An entry that outlived its handler would bar the key forever.
        drop(entry);
        assert!(
            matches!(
                admit_test_offer(&in_flight, test_fresh_offer(data, 4), test_peer(3)),
                FreshOfferAdmission::Opened(_)
            ),
            "a released key should be openable again"
        );
    }

    #[test]
    fn fresh_offer_entries_are_independent_across_keys_sharing_a_prefix() {
        let in_flight: FreshOfferInFlight = Arc::new(Mutex::new(HashMap::new()));

        // A node only receives offers for keys close to its own ID, so accepted
        // keys share a long prefix. Any prefix-derived shard index would have
        // funnelled these two onto one lock and serialized them.
        let _first = admit_test_offer(&in_flight, test_fresh_offer(vec![1u8; 8], 1), test_peer(1));
        assert!(
            matches!(
                admit_test_offer(&in_flight, test_fresh_offer(vec![2u8; 8], 1), test_peer(1)),
                FreshOfferAdmission::Opened(_)
            ),
            "distinct keys should never block each other"
        );
    }

    /// The regression that motivated queueing proofs at all.
    ///
    /// A sender whose proof does not verify must cost the network its own
    /// attempt and nothing more. Refusing every later offer outright made the
    /// first arrival the only arrival, so one bad proof lost the record — and
    /// the delayed possession check then charged that absence to this node.
    #[test]
    fn a_failing_proof_hands_the_key_to_the_next_sender() {
        let in_flight: FreshOfferInFlight = Arc::new(Mutex::new(HashMap::new()));
        let data = vec![0x5Au8; 128];
        let forger = test_peer(0xF0);
        let genuine = test_peer(0x0F);

        let FreshOfferAdmission::Opened(mut entry) =
            admit_test_offer(&in_flight, test_fresh_offer(data.clone(), 0xBA), forger)
        else {
            panic!("the first offer should open the entry");
        };
        assert!(
            matches!(
                admit_test_offer(&in_flight, test_fresh_offer(data.clone(), 0x60), genuine),
                FreshOfferAdmission::Joined
            ),
            "the genuine sender must not be turned away by the forger"
        );

        let first = entry
            .next_attempt()
            .expect("the opener's proof comes first");
        assert_eq!(first.source, forger);

        // Treat the forger's proof as failed: the next one is still reachable,
        // and it is tried against the bytes already held rather than a refetch.
        let second = entry
            .next_attempt()
            .expect("a failed proof must not consume the key");
        assert_eq!(second.source, genuine);
        assert_eq!(
            second.proof_of_payment,
            vec![0x60u8; MIN_PAYMENT_PROOF_SIZE_BYTES]
        );
        assert_eq!(
            entry.data(),
            data.as_slice(),
            "every proof is tried against the one copy of the bytes"
        );

        // Draining the queue releases the key rather than stranding it.
        assert!(entry.next_attempt().is_none());
        assert!(
            matches!(
                admit_test_offer(&in_flight, test_fresh_offer(data, 0x70), test_peer(9)),
                FreshOfferAdmission::Opened(_)
            ),
            "an exhausted entry should release its key"
        );
    }

    /// The cap has to be a lifetime budget, not a queue depth.
    ///
    /// The handler pops a proof before verifying it, so gating admission on the
    /// *instantaneous* queue length lets a fresh source refill the slot that pop
    /// just freed. Each refill is another on-chain payment verification, run
    /// sequentially while the entry holds its admission permit and a worker
    /// slot, so a stream of distinct sources could keep one key's handler — and
    /// one of only four workers — busy indefinitely.
    #[test]
    fn refilling_a_popped_slot_cannot_extend_a_keys_attempt_budget() {
        let in_flight: FreshOfferInFlight = Arc::new(Mutex::new(HashMap::new()));
        let data = vec![0x3Du8; 32];

        let FreshOfferAdmission::Opened(mut entry) =
            admit_test_offer(&in_flight, test_fresh_offer(data.clone(), 0), test_peer(0))
        else {
            panic!("the first offer should open the entry")
        };

        // Drive pop-then-admit with a fresh source every time, exactly as a
        // sybil stream would. The budget must be spent by admissions, not
        // returned by pops.
        let mut admitted = 1;
        for i in 1..u8::try_from(MAX_FRESH_OFFER_ATTEMPTS_PER_KEY * 4).unwrap_or(u8::MAX) {
            let _ = entry.next_attempt();
            if matches!(
                admit_test_offer(&in_flight, test_fresh_offer(data.clone(), 0), test_peer(i)),
                FreshOfferAdmission::Joined
            ) {
                admitted += 1;
            }
        }

        assert!(
            admitted <= MAX_FRESH_OFFER_ATTEMPTS_PER_KEY,
            "a key accepted {admitted} proofs over its lifetime, but the budget is \
             {MAX_FRESH_OFFER_ATTEMPTS_PER_KEY}: popping a proof must not return its slot"
        );
    }

    #[test]
    fn a_fresh_offer_entry_queues_no_more_proofs_than_the_close_group_can_send() {
        let in_flight: FreshOfferInFlight = Arc::new(Mutex::new(HashMap::new()));
        let data = vec![0x2Cu8; 32];

        // The opener occupies the first slot, so the cap is reached after
        // MAX_FRESH_OFFER_ATTEMPTS_PER_KEY distinct sources in total.
        let _entry = admit_test_offer(&in_flight, test_fresh_offer(data.clone(), 0), test_peer(0));
        for i in 1..MAX_FRESH_OFFER_ATTEMPTS_PER_KEY {
            let source = test_peer(u8::try_from(i).unwrap_or(u8::MAX));
            assert!(
                matches!(
                    admit_test_offer(&in_flight, test_fresh_offer(data.clone(), 0), source),
                    FreshOfferAdmission::Joined
                ),
                "sender {i} is within the legitimate close-group fan-out"
            );
        }

        let surplus = test_peer(0xEE);
        assert!(
            matches!(
                admit_test_offer(&in_flight, test_fresh_offer(data, 0), surplus),
                FreshOfferAdmission::Full
            ),
            "past the cap a proof is surplus: enough are already queued to place the record"
        );
    }

    #[test]
    fn verification_receiver_accepts_a_full_cycle_and_rejects_more() {
        assert!(!verification_request_exceeds_limit(
            config::MAX_VERIFICATION_KEYS_PER_CYCLE
        ));
        assert!(verification_request_exceeds_limit(
            config::MAX_VERIFICATION_KEYS_PER_CYCLE + 1
        ));
    }

    // The heavy round-1 limiter enforces the per-peer rate cooldown
    // and single-use round-1 → round-2 sessions.
    #[tokio::test]
    async fn subtree_round1_limiter_cooldown_and_single_use_session() {
        let limiter = SubtreeRound1Limiter::new(
            Duration::from_secs(3600),
            config::MAX_CONCURRENT_SUBTREE_ROUND1,
        );
        let peer = test_peer(1);

        // First round-1 is admitted; drop the guard so concurrency is free again.
        let guard = limiter.admit(&peer).await;
        assert!(guard.is_some(), "first round-1 admitted");
        drop(guard);
        // A second round-1 within the cooldown is dropped even though the heavy
        // pool now has a free slot — the rate cooldown, not concurrency, blocks it.
        assert!(
            limiter.admit(&peer).await.is_none(),
            "second round-1 within cooldown is rate-dropped"
        );
        // A different peer has its own cooldown.
        assert!(limiter.admit(&test_peer(2)).await.is_some());

        // Session: opened by round 1, consumed exactly once by the matching round 2.
        let hash = [7u8; 32];
        let nonce = [9u8; 32];
        limiter.open_session(peer, 42, hash, nonce).await;
        // Wrong nonce / commitment does not match.
        assert!(!limiter.consume_session(&peer, 42, &hash, &[0u8; 32]).await);
        assert!(!limiter.consume_session(&peer, 42, &[0u8; 32], &nonce).await);
        // A round 2 with no prior round 1 (wrong challenge_id) misses.
        assert!(!limiter.consume_session(&peer, 99, &hash, &nonce).await);
        // The matching round 2 consumes it — and only once (single-use).
        assert!(limiter.consume_session(&peer, 42, &hash, &nonce).await);
        assert!(!limiter.consume_session(&peer, 42, &hash, &nonce).await);
    }

    // The concurrency pool and the per-peer cooldown are both keyed by peer id,
    // so a party holding several identities refills its allowance by rotating
    // between them and can keep the heavy pool busy indefinitely. The work
    // budget is keyed by nothing: it is charged for bytes proved, whoever asked,
    // so a fresh identity is refused exactly like a repeat caller once it is
    // spent. That is the difference between bounding concurrency and bounding
    // sustained work.
    #[tokio::test]
    async fn round1_work_budget_is_not_refilled_by_a_fresh_identity() {
        // Cooldown disabled so only the work budget can refuse anything.
        let limiter =
            SubtreeRound1Limiter::new(Duration::ZERO, config::MAX_CONCURRENT_SUBTREE_ROUND1);
        assert!(
            limiter.admit(&test_peer(1)).await.is_some(),
            "a node starts with budget in hand so it can serve audits at once"
        );

        // Serve enough proof work to run the balance into debt. Charging exactly
        // the burst would leave it at zero, which the next nanosecond of refill
        // lifts back above the line — the debt is the point.
        limiter
            .charge_work(2 * SUBTREE_ROUND1_WORK_BURST_BYTES)
            .await;

        for id in 2..8u8 {
            assert!(
                limiter.admit(&test_peer(id)).await.is_none(),
                "a never-seen peer must still be refused while the budget is spent"
            );
        }
    }

    // The budget is a rate, not a quota: it comes back on its own, so an honest
    // auditor blocked by a flood is only delayed. Carrying the debt is what
    // prices an expensive proof above a cheap one — without it, a proof reading
    // a maximal subtree would cost no more of the next caller's wait than a
    // one-leaf proof.
    #[test]
    fn round1_work_budget_carries_debt_and_refills_over_time() {
        let now = Instant::now();
        let at = |secs: u64| {
            now.checked_add(Duration::from_secs(secs))
                .unwrap_or_else(Instant::now)
        };
        let mut budget = Round1WorkBudget {
            balance: 0,
            last_refill: now,
        };
        assert!(!budget.has_budget(now), "empty means empty");

        // A proof costing four seconds' worth of refill leaves four seconds of
        // debt, so the wait scales with what was actually served.
        budget.charge(4 * SUBTREE_ROUND1_WORK_REFILL_BYTES_PER_SEC, now);
        assert!(
            !budget.has_budget(at(3)),
            "still in debt three seconds after an over-large proof"
        );
        assert!(
            budget.has_budget(at(5)),
            "the debt is worked off at the refill rate"
        );

        // Idle time does not bank unbounded credit for a later flood.
        budget.refill(at(24 * 60 * 60));
        assert_eq!(
            budget.balance, SUBTREE_ROUND1_WORK_BURST_BYTES,
            "refill is capped at the burst size"
        );
    }

    // The heavy round-1 pool size is the tightest bound the responder applies and
    // the one least backed by fleet measurement, so it is read from config rather
    // than baked into the binary: a fleet that lands on the wrong number retunes
    // instead of waiting for a release. These pin that the configured value is
    // what actually gates admission, and that a 0 degrades to slow, not to off —
    // a wedged-shut responder would read on every auditor as a graced timeout,
    // i.e. a silent audit outage with nobody penalised and nothing in the logs.
    #[tokio::test]
    async fn round1_pool_size_comes_from_config() {
        // Cooldown disabled so only concurrency can refuse anything.
        let limiter = SubtreeRound1Limiter::new(Duration::ZERO, 1);
        let held = limiter.admit(&test_peer(1)).await;
        assert!(held.is_some(), "the single configured slot is admitted");
        assert!(
            limiter.admit(&test_peer(2)).await.is_none(),
            "a second concurrent round 1 is refused at a configured pool of 1, \
             proving admission follows config rather than the compiled-in default"
        );
        drop(held);
        assert!(
            limiter.admit(&test_peer(2)).await.is_some(),
            "the slot is reusable once the first proof completes"
        );
    }

    #[tokio::test]
    async fn round1_pool_size_of_zero_is_clamped_to_one() {
        let limiter = SubtreeRound1Limiter::new(Duration::ZERO, 0);
        assert!(
            limiter.admit(&test_peer(1)).await.is_some(),
            "a mis-set pool of 0 must still serve audits, not silently refuse every one"
        );
    }

    fn test_key(b: u8) -> crate::ant_protocol::XorName {
        let mut k = [0u8; 32];
        k[0] = b;
        k
    }

    #[test]
    fn bad_hint_penalty_rejects_or_directly_contradicts_sole_replica_source() {
        let source = test_peer(0x91);
        let corroborator = test_peer(0x92);
        let mut evidence = types::KeyVerificationEvidence {
            presence: HashMap::from([(source, PresenceEvidence::Absent)]),
            paid_list: HashMap::new(),
        };
        let failed = KeyVerificationOutcome::QuorumFailed;

        assert_eq!(
            punishable_singleton_replica_hint_source(&HashSet::from([source]), &failed, &evidence),
            Some((source, SingletonHintFault::RejectedByCloseGroup)),
            "a close-group rejection outranks the denial: the key does not exist, which is \
             a bad hint however the sender's own disk is doing"
        );
        assert_eq!(
            punishable_singleton_replica_hint_source(
                &HashSet::from([source, corroborator]),
                &failed,
                &evidence,
            ),
            None,
            "corroborated hints must not use the sole-source penalty lane"
        );
        assert_eq!(
            punishable_singleton_replica_hint_source(&HashSet::new(), &failed, &evidence),
            None,
            "paid-list advertisements do not claim possession, so they leave the \
             replica-hint source set empty and cannot be penalized"
        );

        evidence
            .presence
            .insert(source, PresenceEvidence::Unresolved);
        assert_eq!(
            punishable_singleton_replica_hint_source(&HashSet::from([source]), &failed, &evidence),
            Some((source, SingletonHintFault::RejectedByCloseGroup)),
            "definitive close-group rejection is punishable without direct contradiction"
        );
        assert_eq!(
            punishable_singleton_replica_hint_source(
                &HashSet::from([source]),
                &KeyVerificationOutcome::QuorumInconclusive,
                &evidence,
            ),
            None,
            "timeouts and inconclusive evidence are neutral"
        );

        evidence.presence.insert(source, PresenceEvidence::Absent);
        assert_eq!(
            punishable_singleton_replica_hint_source(
                &HashSet::from([source]),
                &KeyVerificationOutcome::QuorumVerified {
                    sources: vec![corroborator],
                },
                &evidence,
            ),
            Some((source, SingletonHintFault::DeniedPossession)),
            "an explicit denial is punishable regardless of the overall outcome, and is \
             classified separately because it is a statement about the sender's own \
             storage rather than about the key"
        );
    }

    /// Build a round-2 slice challenge matching an open session. `openings` is
    /// empty: these tests exercise admission and session handling only, which
    /// run before any block is opened.
    fn slice_challenge(
        challenge_id: u64,
        commitment_hash: [u8; 32],
        nonce: [u8; 32],
    ) -> protocol::SubtreeSliceChallenge {
        protocol::SubtreeSliceChallenge {
            challenge_id,
            nonce,
            challenged_peer_id: [0u8; 32],
            expected_commitment_hash: commitment_hash,
            openings: Vec::new(),
        }
    }

    // Regression (Copilot, PR #181): a round-2 slice challenge refused at the
    // responder caps MUST NOT burn the single-use round-1 session.
    //
    // The handler used to consume the session first and admit second, so a
    // transient local capacity drop permanently destroyed that audit exchange —
    // every retry hit the `no live round-1 session` path and got `Transient`,
    // even after load cleared. Turning momentary local load into a deterministic
    // round-2 miss costs the responder its whole-slice credit for that round.
    #[tokio::test]
    async fn capacity_refused_slice_challenge_preserves_round1_session() {
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_AUDIT_RESPONSES));
        let inflight = Arc::new(RwLock::new(HashMap::new()));
        let round1 =
            SubtreeRound1Limiter::new(Duration::ZERO, config::MAX_CONCURRENT_SUBTREE_ROUND1);
        let peer = test_peer(0xB1);
        let (id, hash, nonce) = (77u64, [3u8; 32], [4u8; 32]);
        let challenge = slice_challenge(id, hash, nonce);

        round1.open_session(peer, id, hash, nonce).await;

        // Saturate this peer's share so the next admission must be refused.
        let mut hold = Vec::new();
        for _ in 0..MAX_AUDIT_RESPONSES_PER_PEER {
            match admit_audit_responder(&semaphore, &inflight, &peer, AuditResponderClass::Byte)
                .await
            {
                Ok(guard) => hold.push(guard),
                Err(err) => panic!("unexpected admission failure below the cap: {err:?}"),
            }
        }

        let refused =
            admit_slice_challenge(&semaphore, &inflight, &round1, &peer, &challenge).await;
        assert!(
            matches!(refused, SliceAdmission::Capacity(_)),
            "a saturated peer share must refuse on capacity, not on session"
        );

        // Load clears. The session must have survived the refusal.
        drop(hold);
        let retried =
            admit_slice_challenge(&semaphore, &inflight, &round1, &peer, &challenge).await;
        assert!(
            matches!(retried, SliceAdmission::Admitted(_)),
            "the round-1 session must survive a capacity refusal so the retry succeeds"
        );

        // Still single-use: the successful admission consumed it exactly once.
        drop(retried);
        let replayed =
            admit_slice_challenge(&semaphore, &inflight, &round1, &peer, &challenge).await;
        assert!(
            matches!(replayed, SliceAdmission::NoSession),
            "a consumed session must not be replayable"
        );
    }

    // The permit taken for the session probe is released when the probe misses,
    // so an unsessioned flood cannot pin the responder pool shut.
    #[tokio::test]
    async fn unsessioned_slice_challenge_releases_its_admission_slot() {
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_AUDIT_RESPONSES));
        let inflight = Arc::new(RwLock::new(HashMap::new()));
        let round1 =
            SubtreeRound1Limiter::new(Duration::ZERO, config::MAX_CONCURRENT_SUBTREE_ROUND1);
        let peer = test_peer(0xB2);
        let challenge = slice_challenge(1, [0u8; 32], [0u8; 32]);

        // Far more unsessioned challenges than the per-peer cap would allow if
        // the slot leaked on the miss path.
        for _ in 0..(MAX_AUDIT_RESPONSES_PER_PEER * 4) {
            let outcome =
                admit_slice_challenge(&semaphore, &inflight, &round1, &peer, &challenge).await;
            assert!(
                matches!(outcome, SliceAdmission::NoSession),
                "no session was ever opened, so every attempt must miss"
            );
        }

        assert_eq!(
            semaphore.available_permits(),
            MAX_CONCURRENT_AUDIT_RESPONSES,
            "every global permit must be returned"
        );
        assert!(
            inflight.read().await.get(&peer).copied().unwrap_or(0) == 0,
            "no per-peer slot may be left occupied"
        );
    }

    #[test]
    fn holder_credit_revocation_distinguishes_timeout_from_confirmed_failure() {
        assert!(!audit_failure_revokes_holder_credit(
            &AuditFailureReason::Timeout
        ));
        assert!(audit_failure_revokes_holder_credit(
            &AuditFailureReason::DigestMismatch
        ));
    }

    #[tokio::test]
    async fn audit_responder_admission_reports_per_peer_cap_full() {
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_AUDIT_RESPONSES));
        let inflight = Arc::new(RwLock::new(HashMap::new()));
        let peer = test_peer(0xA1);

        let mut guards = Vec::new();
        for _ in 0..MAX_AUDIT_RESPONSES_PER_PEER {
            match admit_audit_responder(&semaphore, &inflight, &peer, AuditResponderClass::Subtree)
                .await
            {
                Ok(guard) => guards.push(guard),
                Err(err) => panic!("unexpected admission failure before peer cap: {err:?}"),
            }
        }

        let Err(err) =
            admit_audit_responder(&semaphore, &inflight, &peer, AuditResponderClass::Subtree).await
        else {
            panic!("admission should fail once per-peer cap is full");
        };
        assert_eq!(err.reason, ResponderRejectReason::PerPeerCapFull);
        assert_eq!(err.peer_inflight, MAX_AUDIT_RESPONSES_PER_PEER);
        assert_eq!(err.peer_limit, MAX_AUDIT_RESPONSES_PER_PEER);
        assert_eq!(err.global_limit, MAX_CONCURRENT_AUDIT_RESPONSES);

        drop(guards);
    }

    #[tokio::test]
    async fn audit_responder_admission_reports_global_pool_full() {
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_AUDIT_RESPONSES));
        let inflight = Arc::new(RwLock::new(HashMap::new()));
        let peer = test_peer(0xA2);

        let mut held_global_permits = Vec::new();
        for _ in 0..MAX_CONCURRENT_AUDIT_RESPONSES {
            held_global_permits.push(
                Arc::clone(&semaphore)
                    .try_acquire_owned()
                    .expect("test should be able to exhaust the global pool"),
            );
        }

        let Err(err) =
            admit_audit_responder(&semaphore, &inflight, &peer, AuditResponderClass::Subtree).await
        else {
            panic!("admission should fail once global pool is full");
        };
        assert_eq!(err.reason, ResponderRejectReason::GlobalPoolFull);
        assert_eq!(err.global_inflight, MAX_CONCURRENT_AUDIT_RESPONSES);
        assert_eq!(err.global_limit, MAX_CONCURRENT_AUDIT_RESPONSES);
        assert_eq!(err.peer_inflight, 0);
        assert_eq!(err.peer_limit, MAX_AUDIT_RESPONSES_PER_PEER);

        drop(held_global_permits);
    }

    #[tokio::test]
    async fn bounded_responder_guard_releases_global_and_peer_slots_on_drop() {
        let semaphore = Arc::new(Semaphore::new(1));
        let inflight = Arc::new(RwLock::new(HashMap::new()));
        let peer = test_peer(0xA3);

        let guard = admit_bounded_responder(&semaphore, &inflight, &peer, 1, 1)
            .await
            .expect("first responder should be admitted");
        assert_eq!(semaphore.available_permits(), 0);
        assert_eq!(inflight.read().await.get(&peer), Some(&1));

        drop(guard);
        assert_eq!(semaphore.available_permits(), 1);
        assert!(!inflight.read().await.contains_key(&peer));
    }

    #[tokio::test]
    async fn cancelled_bounded_responder_wait_does_not_leak_a_peer_slot() {
        let semaphore = Arc::new(Semaphore::new(1));
        let inflight = Arc::new(RwLock::new(HashMap::new()));
        let peer = test_peer(0xA4);
        let held_map = inflight.write().await;

        let waiting = admit_bounded_responder(&semaphore, &inflight, &peer, 1, 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), waiting)
                .await
                .is_err(),
            "admission should still be waiting for the peer map"
        );

        drop(held_map);
        assert_eq!(semaphore.available_permits(), 1);
        assert!(!inflight.read().await.contains_key(&peer));
    }

    #[test]
    fn responder_staleness_sheds_expired_requests_but_serves_fresh_ones() {
        let timeout = Duration::from_secs(1);
        let old_received_at = Instant::now()
            .checked_sub(timeout)
            .unwrap_or_else(Instant::now);

        assert!(request_is_stale(old_received_at, timeout));
        assert!(!request_is_stale(Instant::now(), timeout));
    }

    #[tokio::test]
    async fn neighbor_sync_admission_serializes_each_peer_but_allows_other_peers() {
        let semaphore = Arc::new(Semaphore::new(NEIGHBOR_SYNC_RESPONDER_MAX_OUTSTANDING));
        let inflight = Arc::new(RwLock::new(HashMap::new()));
        let first_peer = test_peer(0xB3);
        let second_peer = test_peer(0xB4);

        let first_guard = admit_bounded_responder(
            &semaphore,
            &inflight,
            &first_peer,
            NEIGHBOR_SYNC_RESPONDER_MAX_OUTSTANDING,
            NEIGHBOR_SYNC_RESPONDER_MAX_OUTSTANDING_PER_PEER,
        )
        .await
        .expect("first sync from a peer should be admitted");
        let duplicate = admit_bounded_responder(
            &semaphore,
            &inflight,
            &first_peer,
            NEIGHBOR_SYNC_RESPONDER_MAX_OUTSTANDING,
            NEIGHBOR_SYNC_RESPONDER_MAX_OUTSTANDING_PER_PEER,
        )
        .await;
        let other_peer = admit_bounded_responder(
            &semaphore,
            &inflight,
            &second_peer,
            NEIGHBOR_SYNC_RESPONDER_MAX_OUTSTANDING,
            NEIGHBOR_SYNC_RESPONDER_MAX_OUTSTANDING_PER_PEER,
        )
        .await;

        assert!(matches!(
            duplicate,
            Err(ResponderAdmissionFailure {
                reason: ResponderRejectReason::PerPeerCapFull,
                ..
            })
        ));
        assert!(other_peer.is_ok());
        drop(first_guard);
        drop(other_peer);
    }

    /// One flooding peer must not be able to hold every fresh-offer slot.
    ///
    /// This is the eviction primitive the per-peer share closes: with only a
    /// global bound, a single source occupies the pool, every honest offer in
    /// that window is refused, and because a refusal reads as absence to the
    /// sender's delayed possession check those refusals land as
    /// audit-severity penalties on *this* node.
    #[tokio::test]
    async fn fresh_offer_admission_reserves_capacity_for_other_peers() {
        let semaphore = Arc::new(Semaphore::new(FRESH_OFFER_MAX_OUTSTANDING));
        let inflight = Arc::new(RwLock::new(HashMap::new()));
        let flooder = test_peer(0xC1);
        let honest = test_peer(0xC2);

        let mut held = Vec::new();
        for _ in 0..FRESH_OFFER_MAX_OUTSTANDING_PER_PEER {
            held.push(
                admit_bounded_responder(
                    &semaphore,
                    &inflight,
                    &flooder,
                    FRESH_OFFER_MAX_OUTSTANDING,
                    FRESH_OFFER_MAX_OUTSTANDING_PER_PEER,
                )
                .await
                .expect("offers within the per-peer share are admitted"),
            );
        }

        let flooder_excess = admit_bounded_responder(
            &semaphore,
            &inflight,
            &flooder,
            FRESH_OFFER_MAX_OUTSTANDING,
            FRESH_OFFER_MAX_OUTSTANDING_PER_PEER,
        )
        .await;
        assert!(
            matches!(
                flooder_excess,
                Err(ResponderAdmissionFailure {
                    reason: ResponderRejectReason::PerPeerCapFull,
                    ..
                })
            ),
            "one source must not exceed its fresh-offer share"
        );

        let honest_offer = admit_bounded_responder(
            &semaphore,
            &inflight,
            &honest,
            FRESH_OFFER_MAX_OUTSTANDING,
            FRESH_OFFER_MAX_OUTSTANDING_PER_PEER,
        )
        .await;
        assert!(
            honest_offer.is_ok(),
            "an honest sender must still be admitted while another peer floods"
        );

        assert!(
            usize::try_from(FRESH_OFFER_MAX_OUTSTANDING_PER_PEER).unwrap_or(usize::MAX)
                < FRESH_OFFER_MAX_OUTSTANDING,
            "the per-peer share must leave room for other sources"
        );

        drop(held);
        drop(honest_offer);
    }

    /// Paid notifies get the same per-source treatment as every other class.
    #[tokio::test]
    async fn paid_notify_admission_reserves_capacity_for_other_peers() {
        let semaphore = Arc::new(Semaphore::new(PAID_NOTIFY_MAX_OUTSTANDING));
        let inflight = Arc::new(RwLock::new(HashMap::new()));
        let flooder = test_peer(0xC3);
        let honest = test_peer(0xC4);

        let mut held = Vec::new();
        for _ in 0..PAID_NOTIFY_MAX_OUTSTANDING_PER_PEER {
            held.push(
                admit_bounded_responder(
                    &semaphore,
                    &inflight,
                    &flooder,
                    PAID_NOTIFY_MAX_OUTSTANDING,
                    PAID_NOTIFY_MAX_OUTSTANDING_PER_PEER,
                )
                .await
                .expect("notifies within the per-peer share are admitted"),
            );
        }

        assert!(
            matches!(
                admit_bounded_responder(
                    &semaphore,
                    &inflight,
                    &flooder,
                    PAID_NOTIFY_MAX_OUTSTANDING,
                    PAID_NOTIFY_MAX_OUTSTANDING_PER_PEER,
                )
                .await,
                Err(ResponderAdmissionFailure {
                    reason: ResponderRejectReason::PerPeerCapFull,
                    ..
                })
            ),
            "one source must not exceed its paid-notify share"
        );
        assert!(
            admit_bounded_responder(
                &semaphore,
                &inflight,
                &honest,
                PAID_NOTIFY_MAX_OUTSTANDING,
                PAID_NOTIFY_MAX_OUTSTANDING_PER_PEER,
            )
            .await
            .is_ok(),
            "an honest sender must still be admitted while another peer floods"
        );

        drop(held);
    }

    /// The fresh-offer per-source bound must guarantee headroom for a peer
    /// holding nothing, without throttling a single legitimate fan-out.
    ///
    /// Sized as a quota rather than a reserve, this bound refused offers during
    /// an ordinary upload (see `tests/e2e/fresh_offer_capacity.rs`), and every
    /// refusal is charged to THIS node at audit severity because the sender
    /// never reads it.
    #[test]
    fn fresh_offer_share_reserves_headroom_without_throttling_one_sender() {
        let share = usize::try_from(FRESH_OFFER_MAX_OUTSTANDING_PER_PEER).unwrap_or(usize::MAX);

        assert_eq!(
            FRESH_OFFER_MAX_OUTSTANDING - share,
            FRESH_OFFER_RESERVED_FOR_OTHER_SOURCES,
            "a source holding none must always find a free slot"
        );
        assert!(
            share < FRESH_OFFER_MAX_OUTSTANDING,
            "one peer must not be able to take the whole pool"
        );
        // The failure this pins: a share sized like the request/response
        // classes (fetch 2, verification 1, neighbor sync 1) binds on ordinary
        // one-way bulk traffic.
        assert!(
            share > usize::try_from(FETCH_RESPONDER_MAX_OUTSTANDING_PER_PEER).unwrap_or(usize::MAX),
            "fresh offers are one-way bulk, not request/response — their share \
             must not be sized like the request classes'"
        );
    }

    /// A malformed offer must be refused before it can occupy an admission
    /// slot, so junk cannot hold capacity for the length of a verification.
    #[test]
    fn structurally_invalid_fresh_offers_are_rejected_before_admission() {
        let key = test_key(0xC5);

        let valid_proof = vec![1u8; MIN_PAYMENT_PROOF_SIZE_BYTES];

        let rejection = fresh_offer_structural_rejection(&key, &[0u8; 1], &[])
            .expect("an offer with no proof must be refused");
        assert!(
            rejection.penalise,
            "an honest sender always attaches a proof"
        );

        // A proof is retained per queued sender, so its size has to be bounded
        // here rather than at the verifier, which only sees it on a worker.
        let undersized = vec![1u8; MIN_PAYMENT_PROOF_SIZE_BYTES - 1];
        let rejection = fresh_offer_structural_rejection(&key, &[0u8; 1], &undersized)
            .expect("an undersized proof must be refused");
        assert!(
            rejection.penalise,
            "no honest sender constructs an undersized proof"
        );
        let oversized_proof = vec![1u8; MAX_PAYMENT_PROOF_SIZE_BYTES + 1];
        let rejection = fresh_offer_structural_rejection(&key, &[0u8; 1], &oversized_proof)
            .expect("an oversized proof must be refused");
        assert!(
            rejection.penalise,
            "no honest sender constructs an oversized proof"
        );

        let rejection = fresh_offer_structural_rejection(
            &key,
            &vec![0u8; crate::ant_protocol::MAX_CHUNK_SIZE + 1],
            &valid_proof,
        )
        .expect("an oversized offer must be refused");
        assert!(
            rejection.penalise,
            "no honest sender constructs an oversized offer"
        );

        let data = vec![0u8; 1];
        assert!(
            fresh_offer_structural_rejection(
                &crate::client::compute_address(&data),
                &data,
                &valid_proof
            )
            .is_none(),
            "a well-formed offer must reach admission"
        );
    }

    /// Knowing a key must not be enough to enter its entry.
    ///
    /// Opening an entry on an unverified key/bytes association would let a peer
    /// that has only *learned* the key — every recipient of its `PaidNotify`,
    /// not just the close group that gets the chunk — seize it with junk.
    /// Joining one would be worse: the handler tries each queued proof against
    /// the *opener's* bytes, so an unchecked joiner could have its proof spent
    /// on bytes it never offered.
    #[test]
    fn a_fresh_offer_cannot_enter_an_entry_for_bytes_it_lacks() {
        let genuine_data = vec![0x5Au8; 128];
        let key = crate::client::compute_address(&genuine_data);
        let valid_proof = vec![1u8; MIN_PAYMENT_PROOF_SIZE_BYTES];

        let rejection = fresh_offer_structural_rejection(&key, &[0xFFu8; 1], &valid_proof)
            .expect("bytes that do not hash to the advertised key must be refused");
        assert!(
            rejection.penalise,
            "no honest sender offers bytes that do not hash to the advertised key"
        );

        // Dispatch reaches the entry only past that rejection, so the forged
        // offer never touched the key and the genuine one still opens it.
        assert!(
            fresh_offer_structural_rejection(&key, &genuine_data, &valid_proof).is_none(),
            "the offer that actually carries the key's bytes must reach the entry"
        );

        let in_flight: FreshOfferInFlight = Arc::new(Mutex::new(HashMap::new()));
        assert!(
            matches!(
                admit_test_offer(&in_flight, test_fresh_offer(genuine_data, 1), test_peer(1)),
                FreshOfferAdmission::Opened(_)
            ),
            "an offer refused on payload shape must leave the key openable"
        );
    }

    #[tokio::test]
    async fn peer_removed_clears_capacity_rejection_and_completes_bootstrap() {
        let peer = test_peer(0xA5);
        let key = test_key(0xA5);
        let bootstrap_state = Arc::new(RwLock::new(BootstrapState::new()));
        let queues = Arc::new(RwLock::new(ReplicationQueues::new()));
        let is_bootstrapping = Arc::new(RwLock::new(true));
        let bootstrap_complete_notify = Arc::new(Notify::new());

        let now = Instant::now();
        queues.write().await.add_pending_verify(
            key,
            VerificationEntry {
                state: VerificationState::PendingVerify,
                verified_sources: Vec::new(),
                tried_sources: HashSet::new(),
                created_at: now,
                next_verify_at: now,
                hint_sources: HashSet::from([peer]),
                replica_hint_sources: HashSet::from([peer]),
                unresolved_retries: 0,
                no_holder_reported: false,
            },
        );
        super::bootstrap::track_discovered_keys(&bootstrap_state, &HashSet::from([key])).await;
        super::bootstrap::note_capacity_rejected(&bootstrap_state, peer).await;
        {
            let q = queues.read().await;
            assert!(
                !super::bootstrap::check_bootstrap_drained(&bootstrap_state, &q).await,
                "capacity rejection should initially block bootstrap drain"
            );
        }

        update_bootstrap_after_peer_removed(
            &peer,
            &bootstrap_state,
            &queues,
            &is_bootstrapping,
            &bootstrap_complete_notify,
        )
        .await;

        let state = bootstrap_state.read().await;
        assert!(state.capacity_rejected_sources.is_empty());
        assert!(state.pending_keys.is_empty());
        assert!(state.is_drained());
        drop(state);
        assert!(!*is_bootstrapping.read().await);
    }

    /// A fairness displacement forfeits the key but must not stamp its former
    /// owner: the owner did nothing wrong, and stamping it lets a flooding
    /// source block bootstrap drain through an unrelated honest peer.
    #[tokio::test]
    async fn fairness_displacement_does_not_stamp_its_victim() {
        let displaced_owner = test_peer(0xB1);
        let incoming_source = test_peer(0xB2);
        let displaced_key = test_key(0xB1);
        let admitted_key = test_key(0xB2);
        let bootstrap_state = Arc::new(RwLock::new(BootstrapState::new()));
        {
            let mut state = bootstrap_state.write().await;
            state.pending_keys.insert(displaced_key);
            state
                .capacity_rejected_sources
                .insert(incoming_source, Instant::now());
        }
        let outcomes = [(
            incoming_source,
            AdmissionOutcome {
                discovered: HashSet::from([admitted_key]),
                capacity_rejected_count: 0,
                displaced: vec![CapacityDisplacement {
                    key: displaced_key,
                    owner: displaced_owner,
                }],
            },
        )];

        publish_bootstrap_admission_outcomes(
            &bootstrap_state,
            &outcomes,
            &HashSet::from([admitted_key]),
        )
        .await;

        let state = bootstrap_state.read().await;
        assert!(!state.pending_keys.contains(&displaced_key));
        assert!(state.pending_keys.contains(&admitted_key));
        assert!(
            !state
                .capacity_rejected_sources
                .contains_key(&displaced_owner),
            "the displaced owner must not be charged for our own fairness reclaim"
        );
        assert!(!state
            .capacity_rejected_sources
            .contains_key(&incoming_source));
    }

    /// A source that keeps overflowing us must not keep its own record fresh.
    ///
    /// This is the wedge the first-seen stamp closes: with refresh-on-every-
    /// rejection the debt could never age out, so `check_bootstrap_drained`
    /// stayed false forever and auditing never started (Invariant 19).
    #[tokio::test]
    async fn repeat_capacity_rejection_keeps_the_first_seen_stamp() {
        const REJECTION_ROUNDS: usize = 5;

        let source = test_peer(0xB3);
        let key = test_key(0xB3);
        let bootstrap_state = Arc::new(RwLock::new(BootstrapState::new()));

        let first_seen = {
            let outcomes = [(
                source,
                AdmissionOutcome {
                    discovered: HashSet::new(),
                    capacity_rejected_count: 1,
                    displaced: Vec::new(),
                },
            )];
            publish_bootstrap_admission_outcomes(&bootstrap_state, &outcomes, &HashSet::new())
                .await;
            bootstrap_state
                .read()
                .await
                .capacity_rejected_sources
                .get(&source)
                .copied()
                .expect("first rejection recorded")
        };

        for _ in 0..REJECTION_ROUNDS {
            let outcomes = [(
                source,
                AdmissionOutcome {
                    discovered: HashSet::from([key]),
                    capacity_rejected_count: 1,
                    displaced: Vec::new(),
                },
            )];
            publish_bootstrap_admission_outcomes(
                &bootstrap_state,
                &outcomes,
                &HashSet::from([key]),
            )
            .await;
        }

        let recorded = bootstrap_state
            .read()
            .await
            .capacity_rejected_sources
            .get(&source)
            .copied()
            .expect("debt still outstanding");
        assert_eq!(
            recorded, first_seen,
            "repeat rejections must not restart the expiry clock"
        );
    }

    /// The verification-worker tick's self-heal path: a capacity rejection
    /// recorded after the peer's `PeerRemoved` cleanup (the TOCTOU orphan)
    /// blocks drain until the TTL expires it, at which point the same tick
    /// completes bootstrap without any external event.
    #[tokio::test]
    async fn drain_self_heal_expires_orphaned_rejection_and_completes_bootstrap() {
        let peer = test_peer(0xA6);
        let bootstrap_state = Arc::new(RwLock::new(BootstrapState::new()));
        let queues = Arc::new(RwLock::new(ReplicationQueues::new()));
        let is_bootstrapping = Arc::new(RwLock::new(true));
        let bootstrap_complete_notify = Arc::new(Notify::new());

        // PeerRemoved was fully processed before the rejection landed, so no
        // future event will ever clear this entry.
        super::bootstrap::note_capacity_rejected(&bootstrap_state, peer).await;

        // Within the TTL the tick keeps waiting for re-delivery.
        expire_and_recheck_bootstrap_drain(
            &bootstrap_state,
            &queues,
            &is_bootstrapping,
            &bootstrap_complete_notify,
            ReplicationConfig::default().capacity_rejected_max_age(),
        )
        .await;
        assert!(!bootstrap_state.read().await.is_drained());
        assert!(*is_bootstrapping.read().await);

        // Past the TTL the tick expires the orphan and completes bootstrap.
        expire_and_recheck_bootstrap_drain(
            &bootstrap_state,
            &queues,
            &is_bootstrapping,
            &bootstrap_complete_notify,
            Duration::ZERO,
        )
        .await;
        assert!(bootstrap_state.read().await.is_drained());
        assert!(!*is_bootstrapping.read().await);
    }

    #[test]
    fn first_audit_terminal_outcomes_are_stable() {
        let peer = test_peer(1);
        let passed = AuditTickResult::Passed {
            challenged_peer: peer,
            keys_checked: 1,
        };
        let timed_out = AuditTickResult::Failed {
            evidence: FailureEvidence::AuditFailure {
                challenge_id: 1,
                challenged_peer: peer,
                confirmed_failed_keys: vec![test_key(1)],
                summary: crate::replication::types::AuditFailureSummary::default(),
                reason: AuditFailureReason::Timeout,
            },
            no_response_class: Some("timeout"),
        };

        assert_eq!(
            first_audit_terminal_outcome(&passed),
            FirstAuditTerminalOutcome::Passed
        );
        assert_eq!(
            first_audit_terminal_outcome(&timed_out),
            FirstAuditTerminalOutcome::Timeout
        );
        assert_eq!(
            first_audit_terminal_outcome(&AuditTickResult::Idle),
            FirstAuditTerminalOutcome::Idle
        );
        assert_eq!(FirstAuditTerminalOutcome::Passed.as_str(), "passed");
        assert_eq!(FirstAuditTerminalOutcome::Timeout.as_str(), "timeout");
        assert_eq!(FirstAuditTerminalOutcome::Failed.as_str(), "failed");
        assert_eq!(FirstAuditTerminalOutcome::Idle.as_str(), "idle");
        assert_eq!(
            FirstAuditTerminalOutcome::InsufficientKeys.as_str(),
            "insufficient_keys"
        );
        assert_eq!(
            FirstAuditTerminalOutcome::BootstrapClaim.as_str(),
            "bootstrap_claim"
        );
    }

    #[test]
    fn first_audit_coalescing_keeps_highest_count_and_exposes_eviction() {
        let mut pending = LruCache::new(NonZeroUsize::new(1).unwrap());
        let mut rng = StdRng::seed_from_u64(7);
        let peer = test_peer(1);
        let base = MonetizedPinEvent {
            peer,
            pin: [1; 32],
            key_count: 100,
            quote_ts: SystemTime::now(),
        };

        // First insert into an empty slot: Queued.
        assert_eq!(
            coalesce_first_audit_event(&mut pending, base, true, &mut rng),
            FirstAuditQueueOutcome::Queued
        );

        // A strictly LOWER-count same-peer nomination must NOT displace it.
        let lower = MonetizedPinEvent {
            pin: [2; 32],
            key_count: 50,
            ..base
        };
        assert_eq!(
            coalesce_first_audit_event(&mut pending, lower, true, &mut rng),
            FirstAuditQueueOutcome::SuppressedLower
        );
        assert_eq!(
            pending.peek(&peer).map(|e| (e.pin, e.key_count)),
            Some(([1; 32], 100)),
            "the higher-count pin is retained"
        );

        // A HIGHER-count same-peer nomination wins (the inflated pin to audit).
        let higher = MonetizedPinEvent {
            pin: [3; 32],
            key_count: 400,
            ..base
        };
        assert_eq!(
            coalesce_first_audit_event(&mut pending, higher, true, &mut rng),
            FirstAuditQueueOutcome::Coalesced
        );
        assert_eq!(
            pending.peek(&peer).map(|e| (e.pin, e.key_count)),
            Some(([3; 32], 400))
        );

        // EQUAL count: an ordinary (newer) enqueue replaces for freshness...
        let equal_newer = MonetizedPinEvent {
            pin: [4; 32],
            key_count: 400,
            ..base
        };
        assert_eq!(
            coalesce_first_audit_event(&mut pending, equal_newer, true, &mut rng),
            FirstAuditQueueOutcome::Coalesced
        );
        assert_eq!(pending.peek(&peer).map(|e| e.pin), Some([4; 32]));
        // ...but an equal-count OLDER requeue (incoming_is_newer=false) does not.
        let equal_older = MonetizedPinEvent {
            pin: [5; 32],
            key_count: 400,
            ..base
        };
        assert_eq!(
            coalesce_first_audit_event(&mut pending, equal_older, false, &mut rng),
            FirstAuditQueueOutcome::RetainedOnTie
        );
        assert_eq!(pending.peek(&peer).map(|e| e.pin), Some([4; 32]));

        // A different peer at capacity 1 evicts the LRU (a DIFFERENT peer).
        let other_peer = MonetizedPinEvent {
            peer: test_peer(2),
            pin: [6; 32],
            key_count: 100,
            ..base
        };
        assert_eq!(
            coalesce_first_audit_event(&mut pending, other_peer, true, &mut rng),
            FirstAuditQueueOutcome::CapacityEvicted { peer, pin: [4; 32] }
        );
        assert_eq!(pending.len(), 1);
        assert_eq!(pending.peek(&other_peer.peer).map(|e| e.pin), Some([6; 32]));
    }

    // -- ADR-0004 Amendment 2: first-audit launch limiter --------------------

    #[test]
    fn first_audit_limiter_enforces_burst_then_refills() {
        let base = Instant::now();
        let mut limiter = FirstAuditLimiter::new(base);
        let interval = config::FIRST_AUDIT_LAUNCH_INTERVAL;

        // The full burst is admitted back-to-back (distinct peers).
        for i in 0..config::FIRST_AUDIT_BUDGET_BURST {
            let peer = test_peer(u8::try_from(i).expect("small burst"));
            assert_eq!(limiter.assess(&peer, 10, base, 0), LimiterVerdict::Admit);
            limiter.commit_launch(peer, 10, base);
        }
        // Bucket empty: the next distinct peer is deferred, never dropped.
        let extra = test_peer(0xEE);
        assert_eq!(
            limiter.assess(&extra, 10, base, 0),
            LimiterVerdict::RateDeferred
        );

        // One full interval later exactly one token is available again.
        let later = base + interval;
        assert_eq!(limiter.assess(&extra, 10, later, 0), LimiterVerdict::Admit);
        limiter.commit_launch(extra, 10, later);
        let extra2 = test_peer(0xEF);
        assert_eq!(
            limiter.assess(&extra2, 10, later, 0),
            LimiterVerdict::RateDeferred
        );
    }

    #[test]
    fn first_audit_limiter_refill_keeps_fractional_remainder() {
        let base = Instant::now();
        let mut limiter = FirstAuditLimiter::new(base);
        let interval = config::FIRST_AUDIT_LAUNCH_INTERVAL;
        for i in 0..config::FIRST_AUDIT_BUDGET_BURST {
            let peer = test_peer(u8::try_from(i).expect("small burst"));
            assert_eq!(limiter.assess(&peer, 1, base, 0), LimiterVerdict::Admit);
            limiter.commit_launch(peer, 1, base);
        }
        // 1.5 intervals later one token is earned and the half interval is
        // NOT lost to drift...
        let at_1_5 = base + interval + interval / 2;
        let p = test_peer(0xAA);
        assert_eq!(limiter.assess(&p, 1, at_1_5, 0), LimiterVerdict::Admit);
        limiter.commit_launch(p, 1, at_1_5);
        // ...so the next token arrives at 2.0 intervals, not 2.5.
        let at_2_0 = base + interval * 2;
        let q = test_peer(0xAB);
        assert_eq!(limiter.assess(&q, 1, at_2_0, 0), LimiterVerdict::Admit);
    }

    #[test]
    fn first_audit_limiter_inflight_cap_defers_until_slot_frees() {
        let base = Instant::now();
        let mut limiter = FirstAuditLimiter::new(base);
        let peer = test_peer(1);
        assert_eq!(
            limiter.assess(&peer, 1, base, config::FIRST_AUDIT_MAX_INFLIGHT),
            LimiterVerdict::RateDeferred
        );
        // A freed slot admits without any clock movement.
        assert_eq!(
            limiter.assess(&peer, 1, base, config::FIRST_AUDIT_MAX_INFLIGHT - 1),
            LimiterVerdict::Admit
        );
    }

    #[test]
    fn first_audit_limiter_assess_consumes_nothing() {
        let base = Instant::now();
        let mut limiter = FirstAuditLimiter::new(base);
        let peer = test_peer(3);
        // Repeated assessment must not burn budget or stamp the window: only
        // `commit_launch` consumes (the cooldown gate between assess and
        // commit can defer, and that deferral must be free).
        for _ in 0..10 {
            assert_eq!(limiter.assess(&peer, 5, base, 0), LimiterVerdict::Admit);
        }
        for i in 0..config::FIRST_AUDIT_BUDGET_BURST {
            let p = test_peer(0x20 + u8::try_from(i).expect("small burst"));
            assert_eq!(limiter.assess(&p, 5, base, 0), LimiterVerdict::Admit);
            limiter.commit_launch(p, 5, base);
        }
    }

    #[test]
    fn first_audit_limiter_window_dedups_rotated_pins_and_count_jump_overrides() {
        let base = Instant::now();
        let mut limiter = FirstAuditLimiter::new(base);
        let peer = test_peer(7);
        assert_eq!(limiter.assess(&peer, 100, base, 0), LimiterVerdict::Admit);
        limiter.commit_launch(peer, 100, base);

        // A rotated pin with a similar count inside the window is dropped...
        let soon = base + Duration::from_secs(60);
        assert_eq!(
            limiter.assess(&peer, 100, soon, 0),
            LimiterVerdict::WindowDeduped
        );
        // ...even at the exact jump boundary (new*DEN == old*NUM is no jump)...
        assert_eq!(
            limiter.assess(&peer, 150, soon, 0),
            LimiterVerdict::WindowDeduped
        );
        // ...but a >1.5x committed-count jump re-nominates immediately (an
        // inflated sidecar-only pin is invisible to the gossip lottery, so
        // the window must not shield it).
        assert_eq!(limiter.assess(&peer, 151, soon, 0), LimiterVerdict::Admit);

        // Window expiry re-admits an unchanged count.
        let expired = base + config::FIRST_AUDIT_PEER_REAUDIT_INTERVAL;
        assert_eq!(
            limiter.assess(&peer, 100, expired, 0),
            LimiterVerdict::Admit
        );
    }

    #[test]
    fn first_audit_limiter_window_verdict_outranks_empty_budget() {
        // A window-deduped nomination must be DROPPED, not kept pending as
        // rate-deferred, even when the bucket is also empty: re-queuing a
        // suppressed rotation would hold a pending slot for two hours.
        let base = Instant::now();
        let mut limiter = FirstAuditLimiter::new(base);
        let peer = test_peer(9);
        assert_eq!(limiter.assess(&peer, 10, base, 0), LimiterVerdict::Admit);
        limiter.commit_launch(peer, 10, base);
        let other = test_peer(10);
        assert_eq!(limiter.assess(&other, 10, base, 0), LimiterVerdict::Admit);
        limiter.commit_launch(other, 10, base);
        assert_eq!(
            limiter.assess(&peer, 10, base, 0),
            LimiterVerdict::WindowDeduped
        );
    }

    /// ADR-0004 Amendment 2 (E'): the B horizon prefilter rejects a quote that
    /// is answerable now but would age out of the answerability window during
    /// the launch jitter, so scheduling state is only ever committed for a pin
    /// that can still be challenged when it actually sends.
    #[test]
    fn first_audit_horizon_prefilter_boundary() {
        let now = SystemTime::now();
        // C = the too-old cutoff; H = the worst-case send horizon.
        let c = GOSSIP_ANSWERABILITY_TTL.saturating_sub(MONETIZED_AUDIT_SKEW_MARGIN);
        let h = config::FIRST_AUDIT_LAUNCH_JITTER_MAX + FIRST_AUDIT_SEND_LATENCY_SLACK;
        // A quote whose age is exactly C at `now + H` (in the past, since C > H).
        let boundary = now
            .checked_add(h)
            .and_then(|t| t.checked_sub(c))
            .expect("boundary time");

        // In window at `now` (age = C - H < C)...
        assert!(quote_within_audit_window(boundary, now));
        // ...but the horizon prefilter rejects it (age == C at now + H).
        assert!(!quote_answerable_through_nominal_jitter(boundary, now));

        // A hair newer stays answerable through the horizon; a hair older does
        // not. Use 1µs (not 1ns): Windows `SystemTime` has 100ns granularity, so
        // a nanosecond step would round to the same instant there.
        let newer = boundary
            .checked_add(Duration::from_micros(1))
            .expect("newer");
        let older = boundary
            .checked_sub(Duration::from_micros(1))
            .expect("older");
        assert!(quote_answerable_through_nominal_jitter(newer, now));
        assert!(!quote_answerable_through_nominal_jitter(older, now));

        // A quote too far in the FUTURE is rejected at `now`, independent of the
        // horizon.
        let future = now
            .checked_add(MONETIZED_AUDIT_SKEW_MARGIN)
            .and_then(|t| t.checked_add(Duration::from_secs(60)))
            .expect("future");
        assert!(!quote_answerable_through_nominal_jitter(future, now));
    }

    /// ADR-0004 Amendment 2 (E'): a reservation whose AUTHORITATIVE post-jitter
    /// answerability check fails at promotion is fully state-neutral — it stamps
    /// no `first_audited`, no per-peer window, refunds its token, releases its
    /// in-flight slot, does not flip the lane, and does not count a launch — and
    /// a same-peer, same-count successor enqueued DURING the reservation is
    /// retained and becomes the next reservation after the cancel. This is the
    /// exact hole the reviewer flagged: suppression must never outlive a launch
    /// that did not send.
    /// A pending pin that has aged past the answerability horizon must not
    /// suppress a live lower-count nomination for the same peer: under token
    /// starvation no reserve scan ever collects the dead entry, so without the
    /// enqueue-time check the peer would stay unauditable through this path
    /// indefinitely (e.g. after a prune legitimately lowered its key count).
    #[test]
    fn first_audit_stale_incumbent_does_not_suppress_live_lower_count() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mut scheduler = FirstAuditScheduler::new(Instant::now(), test_peer(99));
        let peer = test_peer(1);

        let dead_quote = SystemTime::now()
            .checked_sub(GOSSIP_ANSWERABILITY_TTL)
            .and_then(|t| t.checked_sub(Duration::from_secs(60)))
            .expect("past wall time");
        let stale_high = MonetizedPinEvent {
            peer,
            pin: [1; 32],
            key_count: 400,
            quote_ts: dead_quote,
        };
        scheduler.enqueue(stale_high, &obs);
        assert_eq!(scheduler.pending_len(), 1);

        // A fresh, lower-count nomination (a post-prune commitment).
        let fresh_lower = MonetizedPinEvent {
            peer,
            pin: [2; 32],
            key_count: 100,
            quote_ts: SystemTime::now(),
        };
        scheduler.enqueue(fresh_lower, &obs);

        assert_eq!(scheduler.pending_len(), 1);
        assert_eq!(
            scheduler.pending.peek(&peer).map(|e| e.pin),
            Some([2; 32]),
            "the live nomination replaced the dead incumbent"
        );
        assert_eq!(
            obs.suppressed_lower.load(Ordering::Relaxed),
            0,
            "no self-erasure signal for displacing a dead pin"
        );
        assert_eq!(obs.queued.load(Ordering::Relaxed), 2);
        assert_eq!(
            obs.outside_answerability_window.load(Ordering::Relaxed),
            1,
            "the dead incumbent is accounted as an expiry"
        );
    }

    /// The self-erasure defence is untouched for LIVE incumbents: a lower-count
    /// nomination still loses to an answerable higher-count pending pin.
    #[test]
    fn first_audit_live_incumbent_still_suppresses_lower_count() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mut scheduler = FirstAuditScheduler::new(Instant::now(), test_peer(99));
        let peer = test_peer(1);

        let live_high = MonetizedPinEvent {
            peer,
            pin: [1; 32],
            key_count: 400,
            quote_ts: SystemTime::now(),
        };
        scheduler.enqueue(live_high, &obs);
        let cheaper = MonetizedPinEvent {
            peer,
            pin: [2; 32],
            key_count: 100,
            quote_ts: SystemTime::now(),
        };
        scheduler.enqueue(cheaper, &obs);

        assert_eq!(scheduler.pending_len(), 1);
        assert_eq!(
            scheduler.pending.peek(&peer).map(|e| e.pin),
            Some([1; 32]),
            "the higher-count live pin is retained"
        );
        assert_eq!(obs.suppressed_lower.load(Ordering::Relaxed), 1);
        assert_eq!(obs.outside_answerability_window.load(Ordering::Relaxed), 0);
    }

    /// A fresh nomination for peer `b` (distinct pin per peer).
    fn live_nomination(b: u8) -> MonetizedPinEvent {
        MonetizedPinEvent {
            peer: test_peer(b),
            pin: [b; 32],
            key_count: 100,
            quote_ts: SystemTime::now(),
        }
    }

    /// The pending admission cap must equal the number of usable launches the
    /// token budget can perform inside one answerability window, counted by
    /// SIMULATING the shipped reserve-time predicate instant-by-instant (burst
    /// tokens at age zero, one refill per launch interval), not by repeating
    /// the derivation formula. Any larger and admitted work is guaranteed to
    /// expire unlaunched; any smaller and the budget idles while nominations
    /// are displaced.
    #[test]
    fn first_audit_pending_cap_matches_strict_launch_horizon() {
        let quote_ts = SystemTime::now();
        // Burst launches fire at age zero and must pass the reserve predicate.
        assert!(quote_answerable_through_nominal_jitter(quote_ts, quote_ts));
        let mut usable = usize::try_from(config::FIRST_AUDIT_BUDGET_BURST).expect("burst fits");
        let mut refill = 1u32;
        loop {
            let age = config::FIRST_AUDIT_LAUNCH_INTERVAL * refill;
            let at = quote_ts + age;
            if !quote_answerable_through_nominal_jitter(quote_ts, at) {
                break;
            }
            usable += 1;
            refill += 1;
            assert!(refill < 10_000, "runaway horizon simulation");
        }
        assert_eq!(
            FIRST_AUDIT_PENDING_CAP, usable,
            "cap must match the simulated strict launch horizon"
        );
    }

    /// The pending queue is sized to the launch budget while the dedup set
    /// keeps the commitment-cache bound: shrinking `first_audited` would
    /// forget audited pins and re-admit duplicates.
    #[test]
    fn first_audit_pending_cap_independent_of_dedup_cap() {
        let scheduler = FirstAuditScheduler::new(Instant::now(), test_peer(99));
        assert_eq!(scheduler.pending.cap().get(), FIRST_AUDIT_PENDING_CAP);
        assert_eq!(
            scheduler.first_audited.cap().get(),
            MAX_LAST_COMMITMENT_BY_PEER
        );
    }

    /// Admission beyond the cap displaces exactly one incumbent per overflow
    /// and every displacement is accounted as `capacity_evicted` — the steady
    /// overload signal — never silent loss, and never an admission refusal.
    #[test]
    fn first_audit_admission_beyond_cap_displaces_and_counts() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mut scheduler = FirstAuditScheduler::new(Instant::now(), test_peer(99));
        let overflow: usize = 5;
        let total = FIRST_AUDIT_PENDING_CAP + overflow;

        for i in 0..total {
            let b = u8::try_from(i + 1).expect("test peer count fits u8");
            scheduler.enqueue(live_nomination(b), &obs);
        }

        assert_eq!(scheduler.pending_len(), FIRST_AUDIT_PENDING_CAP);
        assert_eq!(
            obs.capacity_evicted.load(Ordering::Relaxed),
            u64::try_from(overflow).expect("overflow fits u64"),
            "each admission past the cap displaces exactly one entry"
        );
        assert_eq!(
            obs.queued.load(Ordering::Relaxed),
            u64::try_from(total).expect("total fits u64"),
            "displacement is not an admission refusal"
        );
        // Every arrival was admitted (the newest always enters the sample).
        let last = u8::try_from(total).expect("test peer count fits u8");
        assert!(
            scheduler.pending.peek(&test_peer(last)).is_some(),
            "the newest arrival always enters the sample"
        );
    }

    /// The reviewer-demonstrated suppression route: a target followed by an
    /// ordered batch of distinct-peer nominations, all inside one ingress
    /// drain batch (`pending_cap < batch <= FIRST_AUDIT_DRAIN_BATCH`), with
    /// the token bucket EMPTY so no reservation can intervene. Under the old
    /// keep-newest LRU the target was evicted with certainty; under random
    /// displacement its per-overflow eviction probability is `1/cap`, so
    /// across repeated trials the target must survive some runs and be
    /// displaced in others — never deterministically flushed, and every
    /// displacement accounted.
    #[test]
    fn first_audit_ordered_flood_cannot_deterministically_evict_target() {
        let flood: usize = 60; // pending_cap < 60 <= FIRST_AUDIT_DRAIN_BATCH
        assert!(FIRST_AUDIT_PENDING_CAP < flood);
        assert!(flood <= config::FIRST_AUDIT_DRAIN_BATCH);

        let trials = 100u64;
        let mut survived = 0u32;
        let mut evicted = 0u32;
        for trial in 0..trials {
            let obs = Arc::new(FirstAuditObservability::default());
            let mut scheduler = FirstAuditScheduler::new(Instant::now(), test_peer(99));
            // Deterministic per-trial seed: the run is fully reproducible (no
            // flake budget at all) while still exercising 100 distinct
            // eviction sequences.
            scheduler.rng = StdRng::seed_from_u64(trial);
            // Drain the burst tokens so the pre-overflow reservation
            // opportunity cannot fire: this isolates pure retention.
            scheduler.limiter.reserve_token();
            scheduler.limiter.reserve_token();

            let target = test_peer(200);
            scheduler.enqueue(live_nomination(200), &obs);
            for i in 0..flood {
                let b = u8::try_from(i + 1).expect("flood peer fits u8");
                scheduler.enqueue(live_nomination(b), &obs);
            }

            assert_eq!(scheduler.pending_len(), FIRST_AUDIT_PENDING_CAP);
            let overflows = u64::try_from(1 + flood - FIRST_AUDIT_PENDING_CAP)
                .expect("overflow count fits u64");
            assert_eq!(
                obs.capacity_evicted.load(Ordering::Relaxed),
                overflows,
                "every overflow past the cap is accounted, none silent"
            );
            if scheduler.pending.peek(&target).is_some() {
                survived += 1;
            } else {
                evicted += 1;
            }
        }
        // With eviction probability 1/cap per overflow, P(target survives one
        // trial) ~= (1 - 1/31)^30 ~= 0.37, so both outcomes appear across the
        // 100 seeded trials — and the seeds make the split exactly
        // reproducible rather than a (vanishingly small) flake budget.
        assert!(
            survived > 0,
            "target must survive some ordered floods — deterministic eviction \
             would mean keep-newest retention regressed"
        );
        assert!(
            evicted > 0,
            "target must also be displaceable — otherwise overflow is refusing \
             admissions instead of sampling"
        );
    }

    /// With a token AVAILABLE, an overflowing arrival must first give pending
    /// work a launch opportunity: the drainer's pre-overflow reservation pulls
    /// one entry out of the queue, so admission proceeds without any eviction.
    #[test]
    fn first_audit_overflow_reserves_before_destructive_eviction() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mut scheduler = FirstAuditScheduler::new(Instant::now(), test_peer(99));
        let cooldown: HashMap<PeerId, Instant> = HashMap::new();

        for i in 0..FIRST_AUDIT_PENDING_CAP {
            let b = u8::try_from(i + 1).expect("test peer count fits u8");
            scheduler.enqueue(live_nomination(b), &obs);
        }
        let overflowing = live_nomination(250);
        assert!(scheduler.would_displace(&overflowing));

        // The drainer's pre-overflow sequence: reserve, then enqueue.
        assert!(scheduler.try_reserve(Instant::now(), 0, Duration::ZERO, &cooldown, &obs));
        assert!(
            !scheduler.would_displace(&overflowing),
            "a successful reservation frees the slot"
        );
        scheduler.enqueue(overflowing, &obs);

        assert_eq!(scheduler.pending_len(), FIRST_AUDIT_PENDING_CAP);
        assert_eq!(
            obs.capacity_evicted.load(Ordering::Relaxed),
            0,
            "no destructive eviction when a launch opportunity existed"
        );
    }

    /// Displacement stamps no suppression state: a displaced peer's next
    /// nomination re-enters like any newcomer (it is NOT window-deduped or
    /// treated as a duplicate), so under overload every peer keeps an
    /// unpredictable chance of prompt first audit.
    #[test]
    fn first_audit_displaced_peer_may_be_renominated() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mut scheduler = FirstAuditScheduler::new(Instant::now(), test_peer(99));
        let total = FIRST_AUDIT_PENDING_CAP + 1;

        for i in 0..total {
            let b = u8::try_from(i + 1).expect("test peer count fits u8");
            scheduler.enqueue(live_nomination(b), &obs);
        }
        assert_eq!(obs.capacity_evicted.load(Ordering::Relaxed), 1);
        // Find whichever peer the random displacement removed.
        let displaced = (1..=total)
            .map(|i| u8::try_from(i).expect("test peer count fits u8"))
            .find(|b| scheduler.pending.peek(&test_peer(*b)).is_none())
            .expect("exactly one admitted peer was displaced");

        scheduler.enqueue(live_nomination(displaced), &obs);

        assert!(
            scheduler.pending.peek(&test_peer(displaced)).is_some(),
            "the displaced peer re-enters the sample"
        );
        assert_eq!(scheduler.pending_len(), FIRST_AUDIT_PENDING_CAP);
        assert_eq!(obs.capacity_evicted.load(Ordering::Relaxed), 2);
        assert_eq!(obs.duplicates.load(Ordering::Relaxed), 0);
        assert_eq!(obs.window_deduped.load(Ordering::Relaxed), 0);
    }

    /// The periodic sweep collects expired pending entries even when the token
    /// bucket is empty — the reserve path returns at the budget gate and never
    /// scans — keeping the capped pending queue and the pending/oldest-age telemetry
    /// honest under fleet-wide starvation.
    #[test]
    fn first_audit_sweep_expired_collects_dead_entries_without_tokens() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mono = Instant::now();
        let mut scheduler = FirstAuditScheduler::new(mono, test_peer(99));

        let dead_quote = SystemTime::now()
            .checked_sub(GOSSIP_ANSWERABILITY_TTL)
            .and_then(|t| t.checked_sub(Duration::from_secs(60)))
            .expect("past wall time");
        scheduler.enqueue(
            MonetizedPinEvent {
                peer: test_peer(1),
                pin: [1; 32],
                key_count: 100,
                quote_ts: dead_quote,
            },
            &obs,
        );
        scheduler.enqueue(
            MonetizedPinEvent {
                peer: test_peer(2),
                pin: [2; 32],
                key_count: 100,
                quote_ts: SystemTime::now(),
            },
            &obs,
        );
        assert_eq!(scheduler.pending_len(), 2);

        // Empty the bucket so the reserve path is budget-gated (fleet-wide
        // starvation) and cannot collect the dead entry itself.
        scheduler.limiter.tokens = 0;
        let cooldown: HashMap<PeerId, Instant> = HashMap::new();
        assert!(!scheduler.try_reserve(mono, 0, Duration::ZERO, &cooldown, &obs));
        assert_eq!(
            scheduler.pending_len(),
            2,
            "budget-gated reserve scans nothing"
        );

        let wall_now = SystemTime::now();
        assert_eq!(scheduler.sweep_expired(wall_now, &obs), 1);
        assert_eq!(scheduler.pending_len(), 1);
        assert!(
            scheduler.pending.peek(&test_peer(2)).is_some(),
            "the live entry survives the sweep"
        );
        assert_eq!(obs.outside_answerability_window.load(Ordering::Relaxed), 1);
        let age_ms = scheduler.oldest_pending_quote_age_ms(wall_now);
        assert!(
            Duration::from_millis(age_ms) < GOSSIP_ANSWERABILITY_TTL,
            "the age gauge reflects only live work after the sweep"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn first_audit_answerability_cancel_is_state_neutral_and_retains_successor() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mono = Instant::now();
        let mut scheduler = FirstAuditScheduler::new(mono, test_peer(99));

        // A pre-existing window sentinel for an UNRELATED peer must survive the
        // cancel byte-for-byte (cancel never touches `recent`).
        let sentinel_peer = test_peer(0xAA);
        scheduler.limiter.promote(sentinel_peer, 500, mono);
        let sentinel_before = scheduler
            .limiter
            .recent
            .peek(&sentinel_peer)
            .copied()
            .expect("sentinel present");

        let peer = test_peer(1);
        let a = MonetizedPinEvent {
            peer,
            pin: [1; 32],
            key_count: 100,
            quote_ts: SystemTime::now(), // fresh: passes the horizon prefilter now
        };
        scheduler.enqueue(a, &obs);

        let tokens_before = scheduler.tokens();
        let lane_before = scheduler.oldest_first_lane;
        let launched_before = obs.launched.load(Ordering::Relaxed);
        let mut cooldown: HashMap<PeerId, Instant> = HashMap::new();

        // Reserve A (jitter 0 so it is immediately due).
        let inflight0 = obs.inflight.load(Ordering::Relaxed);
        assert!(scheduler.try_reserve(mono, inflight0, Duration::ZERO, &cooldown, &obs));
        assert_eq!(scheduler.reserved_peer(), Some(peer));
        assert_eq!(
            scheduler.tokens(),
            tokens_before - 1,
            "reserve consumes a token"
        );
        assert_eq!(
            obs.inflight.load(Ordering::Relaxed),
            1,
            "reserve holds a slot"
        );

        // A same-peer, same-count successor arrives DURING the reservation. It
        // must be retained (bypasses the window for the reserved peer) and must
        // NOT create a second reservation.
        let b = MonetizedPinEvent {
            peer,
            pin: [2; 32],
            key_count: 100,
            quote_ts: SystemTime::now(),
        };
        scheduler.enqueue(b, &obs);
        assert_eq!(scheduler.pending_len(), 1, "successor retained in pending");
        assert!(
            !scheduler.try_reserve(
                mono,
                obs.inflight.load(Ordering::Relaxed),
                Duration::ZERO,
                &cooldown,
                &obs
            ),
            "no second reservation while one is outstanding"
        );

        // Resolve A with an injected wall time PAST A's answerability cutoff.
        let reservation = scheduler
            .take_due_reservation(mono)
            .expect("A is due at jitter 0");
        let wall_fail = a
            .quote_ts
            .checked_add(GOSSIP_ANSWERABILITY_TTL)
            .and_then(|t| t.checked_add(Duration::from_secs(1)))
            .expect("past-cutoff wall time");
        let promoted = scheduler.resolve(reservation, wall_fail, mono, &mut cooldown, &obs);
        assert!(
            promoted.is_none(),
            "answerability lapsed -> cancelled, not promoted"
        );

        // State-neutral cancel.
        assert!(scheduler.first_audited.is_empty(), "no pin marked audited");
        assert!(
            scheduler.limiter.recent.peek(&peer).is_none(),
            "cancel stamps no per-peer window"
        );
        assert_eq!(
            scheduler.limiter.recent.peek(&sentinel_peer).copied(),
            Some(sentinel_before),
            "unrelated window sentinel untouched"
        );
        assert!(!cooldown.contains_key(&peer), "cancel stamps no cooldown");
        assert_eq!(
            scheduler.tokens(),
            tokens_before,
            "token refunded on cancel"
        );
        assert_eq!(
            obs.inflight.load(Ordering::Relaxed),
            0,
            "in-flight slot released"
        );
        assert_eq!(scheduler.oldest_first_lane, lane_before, "lane not flipped");
        assert_eq!(
            obs.launched.load(Ordering::Relaxed),
            launched_before,
            "no launch counted"
        );
        assert_eq!(
            obs.outside_answerability_window.load(Ordering::Relaxed),
            1,
            "the cancel reason is recorded"
        );

        // The successor is still pending and is now fully schedulable: a fresh
        // reserve makes B the next reservation (proving eligibility, not merely
        // that the limiter would admit it).
        assert_eq!(
            scheduler.pending_len(),
            1,
            "successor still pending after cancel"
        );
        assert!(scheduler.reserved.is_none());
        assert!(scheduler.try_reserve(
            mono,
            obs.inflight.load(Ordering::Relaxed),
            Duration::ZERO,
            &cooldown,
            &obs
        ));
        assert_eq!(
            scheduler.reserved_peer(),
            Some(peer),
            "the retained successor becomes the next reservation"
        );
    }

    /// ADR-0004 Amendment 2 (E'): when a promotion loses the shared-cooldown
    /// race, the reserved event is requeued ONLY if no same-peer successor is
    /// already pending. A successor arrived after the reservation, so it is the
    /// newer nomination (e.g. a count jump) and must not be overwritten by the
    /// older reserved event.
    #[test]
    fn first_audit_cooldown_race_requeue_preserves_newer_successor() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mono = Instant::now();
        let mut scheduler = FirstAuditScheduler::new(mono, test_peer(99));
        let peer = test_peer(1);

        // Reserve A.
        let a = MonetizedPinEvent {
            peer,
            pin: [1; 32],
            key_count: 100,
            quote_ts: SystemTime::now(),
        };
        scheduler.enqueue(a, &obs);
        let cooldown_reserve: HashMap<PeerId, Instant> = HashMap::new();
        assert!(scheduler.try_reserve(mono, 0, Duration::ZERO, &cooldown_reserve, &obs));

        // A newer same-peer successor B (a count jump) arrives during the
        // reservation and is retained.
        let b = MonetizedPinEvent {
            peer,
            pin: [2; 32],
            key_count: 400,
            quote_ts: SystemTime::now(),
        };
        scheduler.enqueue(b, &obs);
        assert_eq!(scheduler.pending_len(), 1);

        // Resolve A: answerability PASSES (fresh quote) but the shared cooldown
        // is already stamped for the peer, so promotion loses the race.
        let reservation = scheduler.take_due_reservation(mono).expect("due");
        let mut cooldown: HashMap<PeerId, Instant> = HashMap::new();
        cooldown.insert(peer, mono); // freshly on cooldown
        let promoted = scheduler.resolve(reservation, SystemTime::now(), mono, &mut cooldown, &obs);
        assert!(promoted.is_none(), "cooldown race -> not promoted");

        // B (newer) is preserved; A did NOT overwrite it.
        assert_eq!(scheduler.pending_len(), 1, "still exactly one pending");
        assert_eq!(
            scheduler.pending.peek(&peer).map(|e| e.pin),
            Some([2; 32]),
            "the newer successor B is retained, not the older reserved A"
        );
        assert!(scheduler.first_audited.is_empty());
        assert!(scheduler.limiter.recent.peek(&peer).is_none());
    }

    /// The oldest-pending-quote-age gauge reports the age of the OLDEST quote
    /// still awaiting a first audit (not the newest), is `0` on an empty queue,
    /// and saturates to `0` for a future-dated quote (clock skew) without
    /// panicking. A climbing value is the pending-work-aging-out signal.
    #[test]
    fn first_audit_oldest_pending_quote_age_tracks_the_oldest() {
        let now = SystemTime::now();
        let mut scheduler = FirstAuditScheduler::new(Instant::now(), test_peer(99));
        assert_eq!(
            scheduler.oldest_pending_quote_age_ms(now),
            0,
            "empty pending -> zero"
        );

        // Two peers: quotes 10s and 2s old. The gauge must track the older.
        for (peer_id, pin, secs) in [(1u8, [1; 32], 10u64), (2, [2; 32], 2)] {
            let _ = coalesce_first_audit_event(
                &mut scheduler.pending,
                MonetizedPinEvent {
                    peer: test_peer(peer_id),
                    pin,
                    key_count: 100,
                    quote_ts: now - Duration::from_secs(secs),
                },
                true,
                &mut scheduler.rng,
            );
        }
        assert_eq!(
            scheduler.oldest_pending_quote_age_ms(now),
            10_000,
            "tracks the oldest (10s), not the newest (2s)"
        );

        // A future-dated quote (clock skew) saturates to zero, never panics.
        let mut skewed = FirstAuditScheduler::new(Instant::now(), test_peer(99));
        let _ = coalesce_first_audit_event(
            &mut skewed.pending,
            MonetizedPinEvent {
                peer: test_peer(3),
                pin: [3; 32],
                key_count: 100,
                quote_ts: now + Duration::from_secs(5),
            },
            true,
            &mut skewed.rng,
        );
        assert_eq!(
            skewed.oldest_pending_quote_age_ms(now),
            0,
            "future quote_ts saturates to zero"
        );
    }

    /// A flood of strictly-lower-count same-peer nominations must neither
    /// displace the retained higher pin NOR disturb its recency position (each
    /// is suppressed via `peek`, no `push`), and each must be counted as
    /// `suppressed_lower` — the attempted cheaper-pin self-erasure signal.
    /// Recency is asserted DIRECTLY via the queue's MRU-to-LRU iteration order
    /// (the documented `lru` contract that also drives the reserve scan's lane
    /// ordering), deliberately independent of the overflow policy: eviction is
    /// random-victim, so no assertion may require a particular peer to be
    /// displaced.
    #[test]
    fn first_audit_suppressed_lower_flood_leaves_recency_and_counts() {
        let mut pending: LruCache<PeerId, MonetizedPinEvent> =
            LruCache::new(NonZeroUsize::new(2).unwrap());
        let mut rng = StdRng::seed_from_u64(11);
        let victim = test_peer(1);
        let other = test_peer(2);
        // Victim (high count) inserted first (older), then `other` (newer/MRU).
        let _ = coalesce_first_audit_event(
            &mut pending,
            MonetizedPinEvent {
                peer: victim,
                pin: [1; 32],
                key_count: 400,
                quote_ts: SystemTime::now(),
            },
            true,
            &mut rng,
        );
        let _ = coalesce_first_audit_event(
            &mut pending,
            MonetizedPinEvent {
                peer: other,
                pin: [9; 32],
                key_count: 100,
                quote_ts: SystemTime::now(),
            },
            true,
            &mut rng,
        );
        let order_before: Vec<PeerId> = pending.iter().map(|(p, _)| *p).collect();
        assert_eq!(
            order_before,
            vec![other, victim],
            "sanity: `other` is MRU, the victim is LRU"
        );

        // Flood the victim with cheaper nominations.
        let mut suppressed = 0u64;
        for i in 0..8u8 {
            let out = coalesce_first_audit_event(
                &mut pending,
                MonetizedPinEvent {
                    peer: victim,
                    pin: [i; 32],
                    key_count: 50,
                    quote_ts: SystemTime::now(),
                },
                true,
                &mut rng,
            );
            assert_eq!(out, FirstAuditQueueOutcome::SuppressedLower);
            suppressed += 1;
        }
        assert_eq!(suppressed, 8);
        // Victim pin/count unchanged.
        assert_eq!(
            pending.peek(&victim).map(|e| (e.pin, e.key_count)),
            Some(([1; 32], 400))
        );
        // Recency untouched: the iteration order (which the reserve lanes
        // consume) is byte-for-byte what it was before the flood.
        let order_after: Vec<PeerId> = pending.iter().map(|(p, _)| *p).collect();
        assert_eq!(
            order_after, order_before,
            "the suppressed-lower flood must not have changed any recency position"
        );
    }

    /// The cooldown-race requeue counts a genuine different-peer capacity
    /// eviction (the ADR promises capacity loss is observable).
    #[test]
    fn first_audit_cooldown_race_requeue_counts_capacity_eviction() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mono = Instant::now();
        let mut scheduler = FirstAuditScheduler::new(mono, test_peer(99));
        // Pending capacity 1 so a requeue of a different peer must evict.
        scheduler.pending = LruCache::new(NonZeroUsize::new(1).unwrap());
        let reserved_peer = test_peer(1);
        let other_peer = test_peer(2);

        // Reserve peer 1.
        scheduler.enqueue(
            MonetizedPinEvent {
                peer: reserved_peer,
                pin: [1; 32],
                key_count: 100,
                quote_ts: SystemTime::now(),
            },
            &obs,
        );
        let cooldown_read: HashMap<PeerId, Instant> = HashMap::new();
        assert!(scheduler.try_reserve(mono, 0, Duration::ZERO, &cooldown_read, &obs));

        // A DIFFERENT peer fills the single pending slot during the reservation.
        scheduler.enqueue(
            MonetizedPinEvent {
                peer: other_peer,
                pin: [2; 32],
                key_count: 100,
                quote_ts: SystemTime::now(),
            },
            &obs,
        );
        assert_eq!(scheduler.pending_len(), 1);

        // Resolve peer 1: cooldown race -> requeue peer 1, evicting peer 2.
        let reservation = scheduler.take_due_reservation(mono).expect("due");
        let mut cooldown: HashMap<PeerId, Instant> = HashMap::new();
        cooldown.insert(reserved_peer, mono);
        let cap_before = obs.capacity_evicted.load(Ordering::Relaxed);
        assert!(scheduler
            .resolve(reservation, SystemTime::now(), mono, &mut cooldown, &obs)
            .is_none());
        assert_eq!(
            obs.capacity_evicted.load(Ordering::Relaxed),
            cap_before + 1,
            "the requeue eviction of a different peer is counted"
        );
        assert_eq!(
            scheduler.pending.peek(&reserved_peer).map(|e| e.pin),
            Some([1; 32])
        );
    }

    /// ADR-0004 Amendment 2 (reviewer blocker): a strictly-lower-count same-peer
    /// nomination arriving while an inflated pin is PENDING must not displace it.
    /// The inflated pin stays and is the one launched.
    #[test]
    fn first_audit_pending_lower_count_does_not_replace_higher() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mono = Instant::now();
        let mut scheduler = FirstAuditScheduler::new(mono, test_peer(99));
        let peer = test_peer(1);

        // Inflated (high-count) sidecar pin lands in pending.
        scheduler.enqueue(
            MonetizedPinEvent {
                peer,
                pin: [1; 32],
                key_count: 400,
                quote_ts: SystemTime::now(),
            },
            &obs,
        );
        // A cheaper same-peer settlement arrives right after.
        scheduler.enqueue(
            MonetizedPinEvent {
                peer,
                pin: [2; 32],
                key_count: 100,
                quote_ts: SystemTime::now(),
            },
            &obs,
        );

        assert_eq!(scheduler.pending_len(), 1);
        assert_eq!(
            scheduler.pending.peek(&peer).map(|e| (e.pin, e.key_count)),
            Some(([1; 32], 400)),
            "the inflated pin must not be erased by the cheaper successor"
        );
        // The dropped cheaper nomination is counted through the enqueue path.
        assert_eq!(
            obs.suppressed_lower.load(Ordering::Relaxed),
            1,
            "the attempted cheaper-pin self-erasure is observable"
        );

        // It reserves and promotes as the inflated pin/count.
        let cooldown_read: HashMap<PeerId, Instant> = HashMap::new();
        assert!(scheduler.try_reserve(mono, 0, Duration::ZERO, &cooldown_read, &obs));
        let reservation = scheduler.take_due_reservation(mono).expect("due");
        let mut cooldown: HashMap<PeerId, Instant> = HashMap::new();
        let (event, _slot) = scheduler
            .resolve(reservation, SystemTime::now(), mono, &mut cooldown, &obs)
            .expect("promotes");
        assert_eq!((event.pin, event.key_count), ([1; 32], 400));
    }

    /// ADR-0004 Amendment 2 (reviewer blocker): a RESERVED inflated pin that
    /// loses the cooldown race must be requeued OVER a lower-count same-peer
    /// successor that arrived during its jitter, and must remain launchable once
    /// the shared cooldown expires — the cheaper successor cannot suppress it.
    #[test]
    fn first_audit_cooldown_race_requeues_reserved_higher_over_lower_successor() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mono = Instant::now();
        let mut scheduler = FirstAuditScheduler::new(mono, test_peer(99));
        let peer = test_peer(1);

        // Reserve the inflated pin.
        scheduler.enqueue(
            MonetizedPinEvent {
                peer,
                pin: [1; 32],
                key_count: 400,
                quote_ts: SystemTime::now(),
            },
            &obs,
        );
        let cooldown_read: HashMap<PeerId, Instant> = HashMap::new();
        assert!(scheduler.try_reserve(mono, 0, Duration::ZERO, &cooldown_read, &obs));

        // A cheaper successor arrives during the reservation (bypasses the
        // window as the reserved peer) and sits in pending.
        scheduler.enqueue(
            MonetizedPinEvent {
                peer,
                pin: [2; 32],
                key_count: 100,
                quote_ts: SystemTime::now(),
            },
            &obs,
        );
        assert_eq!(scheduler.pending_len(), 1);

        // Resolve: answerability passes but the shared cooldown is already
        // stamped, so the reservation loses the race and requeues.
        let reservation = scheduler.take_due_reservation(mono).expect("due");
        let mut cooldown: HashMap<PeerId, Instant> = HashMap::new();
        cooldown.insert(peer, mono);
        assert!(scheduler
            .resolve(reservation, SystemTime::now(), mono, &mut cooldown, &obs)
            .is_none());

        // The inflated pin (400) replaced the cheaper successor (100).
        assert_eq!(scheduler.pending_len(), 1);
        assert_eq!(
            scheduler.pending.peek(&peer).map(|e| (e.pin, e.key_count)),
            Some(([1; 32], 400)),
            "the inflated reserved pin must survive the requeue over the cheaper successor"
        );
        assert!(scheduler.first_audited.is_empty());
        assert!(scheduler.limiter.recent.peek(&peer).is_none());

        // Once the shared cooldown expires, the inflated pin reserves and
        // promotes with its intended pin/count.
        let later = mono
            .checked_add(Duration::from_secs(
                config::AUDIT_ON_GOSSIP_COOLDOWN_SECS + 1,
            ))
            .expect("later");
        let cooldown_read_later: HashMap<PeerId, Instant> = HashMap::new();
        assert!(scheduler.try_reserve(later, 0, Duration::ZERO, &cooldown_read_later, &obs));
        let reservation = scheduler.take_due_reservation(later).expect("due");
        let mut cooldown_later: HashMap<PeerId, Instant> = HashMap::new();
        let (event, _slot) = scheduler
            .resolve(
                reservation,
                SystemTime::now(),
                later,
                &mut cooldown_later,
                &obs,
            )
            .expect("promotes after cooldown");
        assert_eq!((event.pin, event.key_count), ([1; 32], 400));
    }

    /// ADR-0004 Amendment 2 (E'): consecutive PROMOTIONS strictly alternate the
    /// launch lane, driven through the real scheduler (reserve -> resolve ->
    /// promote), so a stream of fresh nominations cannot keep every launch on
    /// the newest lane and starve the oldest.
    #[test]
    fn first_audit_lane_alternates_across_promotions() {
        let obs = Arc::new(FirstAuditObservability::default());
        let mono = Instant::now();
        let mut scheduler = FirstAuditScheduler::new(mono, test_peer(99));
        let mut cooldown: HashMap<PeerId, Instant> = HashMap::new();

        // Two distinct peers; the newest-inserted is the MRU (newest lane end).
        let oldest_peer = test_peer(1);
        let newest_peer = test_peer(2);
        scheduler.enqueue(
            MonetizedPinEvent {
                peer: oldest_peer,
                pin: [1; 32],
                key_count: 100,
                quote_ts: SystemTime::now(),
            },
            &obs,
        );
        scheduler.enqueue(
            MonetizedPinEvent {
                peer: newest_peer,
                pin: [2; 32],
                key_count: 100,
                quote_ts: SystemTime::now(),
            },
            &obs,
        );

        let mut launched_peers = Vec::new();
        for _ in 0..2 {
            assert!(scheduler.try_reserve(
                mono,
                obs.inflight.load(Ordering::Relaxed),
                Duration::ZERO,
                &cooldown,
                &obs
            ));
            let reservation = scheduler.take_due_reservation(mono).expect("due");
            // Answerable wall time == the quote's own time (age 0).
            let (event, _slot) = scheduler
                .resolve(reservation, SystemTime::now(), mono, &mut cooldown, &obs)
                .expect("fresh in-window quote promotes");
            launched_peers.push(event.peer);
        }

        // First launch takes the newest lane (lane starts false = newest), the
        // second takes the oldest lane: strict alternation.
        assert_eq!(
            launched_peers,
            vec![newest_peer, oldest_peer],
            "consecutive promotions alternate newest-then-oldest lane"
        );
    }

    #[test]
    fn first_audit_count_jump_boundaries() {
        // Exactly 1.5x is NOT a jump; strictly above is.
        assert!(!first_audit_count_jump(100, 150));
        assert!(first_audit_count_jump(100, 151));
        // Anything beats an audited zero; zero never jumps.
        assert!(first_audit_count_jump(0, 1));
        assert!(!first_audit_count_jump(0, 0));
        // Equal max counts must not jump (and must not overflow).
        assert!(!first_audit_count_jump(u32::MAX, u32::MAX));
    }

    /// A verified payment's quote list includes the local node's own quote, so
    /// the verifier emits a monetized-pin event for the local peer on every
    /// payment it verifies. The node cannot network-audit itself, so the
    /// scheduler must drop such an event at ingress: never queued, and hence
    /// never launched nor marked first-audited.
    #[test]
    fn first_audit_queue_drops_self_targeting_events() {
        let obs = Arc::new(FirstAuditObservability::default());
        let self_peer = test_peer(1);
        let mut scheduler = FirstAuditScheduler::new(Instant::now(), self_peer);
        let self_event = MonetizedPinEvent {
            peer: self_peer,
            pin: [7; 32],
            key_count: 1,
            quote_ts: SystemTime::now(),
        };

        scheduler.enqueue(self_event, &obs);
        assert_eq!(obs.self_target_skipped.load(Ordering::Relaxed), 1);
        assert_eq!(obs.queued.load(Ordering::Relaxed), 0);
        assert_eq!(scheduler.pending_len(), 0, "self-target must never queue");

        // A remote peer's event still queues normally under the same filter.
        let remote_event = MonetizedPinEvent {
            peer: test_peer(2),
            pin: [8; 32],
            ..self_event
        };
        scheduler.enqueue(remote_event, &obs);
        assert_eq!(obs.queued.load(Ordering::Relaxed), 1);
        assert_eq!(scheduler.pending_len(), 1);
        assert_eq!(
            obs.self_target_skipped.load(Ordering::Relaxed),
            1,
            "remote event must not count as a self-target skip"
        );
    }

    #[test]
    fn fresh_offer_runs_store_admission_payment_checks() {
        let context = fresh_offer_payment_context();
        assert_eq!(context, VerificationContext::FreshReplication);
        // Fresh replication must keep verifying exactly like a direct client
        // PUT (store-strength cache, same live checks); the variant only
        // exists so price-floor telemetry can tell the two paths apart.
        assert!(context.is_store_admission());
    }

    #[test]
    fn paid_notify_uses_paid_list_admission_payment_checks() {
        assert_eq!(
            paid_notify_payment_context(),
            VerificationContext::PaidListAdmission
        );
    }

    /// ADR-0004 A1 (guardrail A): the monetized first-audit only fires for a
    /// signed quote inside the answerability window, fail-closed on BOTH ends so a
    /// stale or future/skewed client-forwarded quote cannot frame an honest node.
    #[test]
    fn monetized_quote_audit_window_fails_closed_both_ends() {
        let now = SystemTime::now();
        // Fresh (just quoted) and small future/past skew -> audited.
        assert!(quote_within_audit_window(now, now));
        assert!(quote_within_audit_window(
            now + Duration::from_secs(60),
            now
        ));
        assert!(quote_within_audit_window(
            now - Duration::from_secs(3600),
            now
        ));
        // Far future (badly-skewed / replayed) -> skipped.
        assert!(!quote_within_audit_window(
            now + MONETIZED_AUDIT_SKEW_MARGIN + Duration::from_secs(60),
            now
        ));
        // Older than the window -> skipped (pin may have aged out).
        assert!(!quote_within_audit_window(
            now - commitment_state::GOSSIP_ANSWERABILITY_TTL,
            now
        ));
    }

    #[tokio::test]
    async fn replication_branch_lagged_events_are_counted() {
        let before = audit_metrics::replication_event_lagged_total();
        let flow = handle_replication_event_recv_error(
            &tokio::sync::broadcast::error::RecvError::Lagged(3),
        );
        assert_eq!(flow, std::ops::ControlFlow::Continue(()));
        let after = audit_metrics::replication_event_lagged_total();
        assert_eq!(after.saturating_sub(before), 3);
    }

    #[tokio::test]
    async fn replication_branch_closed_events_stop_the_loop() {
        let flow =
            handle_replication_event_recv_error(&tokio::sync::broadcast::error::RecvError::Closed);
        assert_eq!(flow, std::ops::ControlFlow::Break(()));
    }

    #[tokio::test]
    async fn full_serial_queue_drops_instead_of_running_the_message_inline() {
        let (sender, mut receiver) = mpsc::channel(1);
        let dropped_body =
            ReplicationMessageBody::VerificationRequest(protocol::VerificationRequest {
                keys: Vec::new(),
                paid_list_check_indices: Vec::new(),
            });
        let overflow_before = audit_metrics::serial_queue_overflow_drops_total(&dropped_body);
        let first = InboundReplicationMessage {
            source: test_peer(0xC1),
            msg: ReplicationMessage {
                request_id: 1,
                body: ReplicationMessageBody::FetchRequest(protocol::FetchRequest {
                    key: test_key(1),
                }),
            },
            rr_message_id: None,
            received_at: Instant::now(),
        };
        let second = InboundReplicationMessage {
            source: test_peer(0xC2),
            msg: ReplicationMessage {
                request_id: 2,
                body: dropped_body.clone(),
            },
            rr_message_id: None,
            received_at: Instant::now(),
        };

        assert!(try_enqueue_serial_message(&sender, first).is_ok());
        let dropped = try_enqueue_serial_message(&sender, second)
            .expect_err("a full serial queue must refuse the second message");
        assert_eq!(dropped.reason, SerialQueueDropReason::Full);
        assert_eq!(dropped.message_class, "verification_request");
        assert_eq!(dropped.queue_depth, 1);
        let overflow_after = audit_metrics::serial_queue_overflow_drops_total(&dropped_body);
        assert_eq!(overflow_after.saturating_sub(overflow_before), 1);

        let queued = receiver
            .recv()
            .await
            .expect("first message should remain queued");
        assert_eq!(queued.msg.request_id, 1);
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn digest_admission_gets_higher_per_peer_cap_subtree_stays_at_two() {
        let peer = test_peer(0x44);
        let semaphore = Arc::new(Semaphore::new(config::MAX_CONCURRENT_AUDIT_RESPONSES));

        let digest_inflight = Arc::new(RwLock::new(HashMap::new()));
        let mut digest_guards = Vec::new();
        for _ in 0..config::MAX_DIGEST_AUDIT_RESPONSES_PER_PEER {
            let guard = admit_audit_responder(
                &semaphore,
                &digest_inflight,
                &peer,
                AuditResponderClass::Digest,
            )
            .await;
            assert!(guard.is_ok());
            digest_guards.push(guard);
        }
        assert!(
            admit_audit_responder(
                &semaphore,
                &digest_inflight,
                &peer,
                AuditResponderClass::Digest,
            )
            .await
            .is_err(),
            "digest class must stop at its documented per-source cap"
        );
        drop(digest_guards);

        let subtree_inflight = Arc::new(RwLock::new(HashMap::new()));
        let mut subtree_guards = Vec::new();
        for _ in 0..config::MAX_AUDIT_RESPONSES_PER_PEER {
            let guard = admit_audit_responder(
                &semaphore,
                &subtree_inflight,
                &peer,
                AuditResponderClass::Subtree,
            )
            .await;
            assert!(guard.is_ok());
            subtree_guards.push(guard);
        }
        assert!(
            admit_audit_responder(
                &semaphore,
                &subtree_inflight,
                &peer,
                AuditResponderClass::Subtree,
            )
            .await
            .is_err(),
            "subtree class must retain the deployed cap of two"
        );
        drop(subtree_guards);
    }

    #[test]
    fn in_scope_audit_deadlines_share_one_formula() {
        let config = config::ReplicationConfig::default();
        for key_count in [1, 4, 16] {
            assert_eq!(
                audit::responsible_audit_response_timeout(&config, key_count),
                config.audit_response_timeout(key_count)
            );
            assert_eq!(
                pruning::prune_audit_response_timeout(&config, key_count),
                config.audit_response_timeout(key_count)
            );
        }
        assert_eq!(
            possession::possession_probe_response_timeout(&config),
            config.audit_response_timeout(1)
        );
    }

    #[test]
    fn replica_hint_sources_are_added_as_fallback_fetch_sources() {
        const EXISTING_SOURCE_ID: u8 = 1;
        const HINT_SENDER_ID: u8 = 2;

        let existing_source = test_peer(EXISTING_SOURCE_ID);
        let hint_sender = test_peer(HINT_SENDER_ID);
        let mut sources = vec![existing_source];

        let hint_sources = HashSet::from([hint_sender]);
        add_replica_hint_sources(&mut sources, &hint_sources);
        add_replica_hint_sources(&mut sources, &hint_sources);

        // A paid-only advertiser leaves the claim set empty (see
        // `queue_admitted_hints`), so it contributes no fetch source.
        add_replica_hint_sources(&mut sources, &HashSet::new());

        assert_eq!(sources, vec![existing_source, hint_sender]);
    }

    #[test]
    fn audit_timeout_preserves_active_bootstrap_claim() {
        assert!(!audit_failure_clears_bootstrap_claim(
            &AuditFailureReason::Timeout
        ));
    }

    fn strike_peer(b: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        PeerId::from_bytes(bytes)
    }

    // ADR-0002: "occasional surprise exams, keeps load low" — the per-peer
    // cooldown must collapse a gossip flood into at most one audit per window.

    #[test]
    fn gossip_flood_yields_at_most_one_audit_per_cooldown_window() {
        let peer = strike_peer(1);
        let mut map: HashMap<PeerId, Instant> = HashMap::new();
        let t0 = Instant::now();
        // First gossip in the window passes; a burst of further gossips at the
        // same instant are all suppressed.
        assert!(cooldown_allows_audit(&mut map, &peer, t0));
        let mut passed = 1;
        for _ in 0..100 {
            if cooldown_allows_audit(&mut map, &peer, t0) {
                passed += 1;
            }
        }
        assert_eq!(
            passed, 1,
            "a flood at one instant must trigger exactly one audit"
        );
    }

    // ADR-0002 ordering invariant: `maybe_trigger_gossip_audit` stamps the
    // per-peer cooldown BEFORE the probability lottery, so a LOSING ticket still
    // consumes the window. This is the property the isolated cooldown tests above
    // cannot see: they never sample the lottery, so a regression that reordered
    // the gates (sample probability first, only stamp the cooldown on a win)
    // would still pass them while breaking flood-resistance: a flood would then
    // re-roll the lottery on EVERY message until one won, multiplying audits.
    //
    // We model the exact production gate order (attempt-window, lottery,
    // shared cooldown) with a lottery driven by a fixed outcome instead of
    // `gen_bool(..)`. The first message LOSES the lottery; the remaining flood
    // messages all WIN. With the production order, the losing first ticket
    // burns the ATTEMPT window and every later winner in the same window is
    // blocked, so there are 0 audits this window. If the gates were flipped,
    // the second message's winning ticket would slip through. The window only
    // reopens after it elapses.
    //
    // FLIPS IF: the lottery is sampled before the attempt-window
    // check-and-stamp (a losing ticket no longer consumes the window),
    // re-enabling a flood-amplified audit storm.
    #[test]
    fn losing_lottery_still_consumes_attempt_window() {
        // Calls the SHIPPED `audit_launch_decision` (the same function
        // `maybe_trigger_gossip_audit` uses), so a reorder of the gates in
        // production fails this test — not a local reimplementation.
        let peer = strike_peer(3);
        let mut attempts: HashMap<PeerId, Instant> = HashMap::new();
        let mut launched: HashMap<PeerId, Instant> = HashMap::new();
        let t0 = Instant::now();

        // First flooded message at t0 LOSES the lottery, but the attempt window
        // is stamped BEFORE the lottery is consulted, so the window is consumed.
        assert!(
            !audit_launch_decision(&mut attempts, &mut launched, &peer, t0, false),
            "a losing ticket launches no audit"
        );

        // 99 more flooded messages at the same instant would all WIN the lottery,
        // yet every one must be blocked by the attempt window the loser stamped.
        // (If production sampled the lottery FIRST, these would each get a fresh
        // roll and audits would multiply — this assertion catches that reorder.)
        let mut audits = 0;
        for _ in 0..99 {
            if audit_launch_decision(&mut attempts, &mut launched, &peer, t0, true) {
                audits += 1;
            }
        }
        assert_eq!(
            audits, 0,
            "a losing first ticket must consume the attempt window so no later \
             flooded message in the same window can audit"
        );

        // The window only reopens after it elapses; the next winning ticket
        // then launches exactly one audit and stamps the SHARED cooldown.
        let after = t0 + Duration::from_secs(config::AUDIT_ON_GOSSIP_COOLDOWN_SECS + 1);
        assert!(
            audit_launch_decision(&mut attempts, &mut launched, &peer, after, true),
            "after the window a winning ticket audits again"
        );
        assert!(
            launched.contains_key(&peer),
            "a real launch stamps the shared cooldown"
        );
    }

    /// The reviewer-flagged suppression route: a LOSING gossip lottery must not
    /// stamp the SHARED audit cooldown, otherwise repeated losses (one per
    /// 30-minute window, no challenge ever sent) keep a paid monetized pin's
    /// first audit deferred until its answerability window expires.
    ///
    /// FLIPS IF: `audit_launch_decision` stamps the shared `launched` map on a
    /// loss (the pre-split behavior, where both paths shared one map).
    #[test]
    fn losing_lottery_does_not_suppress_monetized_first_audit() {
        let peer = strike_peer(4);
        let mut attempts: HashMap<PeerId, Instant> = HashMap::new();
        let mut launched: HashMap<PeerId, Instant> = HashMap::new();
        let t0 = Instant::now();

        // A losing ticket consumes the gossip attempt window...
        assert!(!audit_launch_decision(
            &mut attempts,
            &mut launched,
            &peer,
            t0,
            false
        ));
        // ...but leaves the shared map untouched, so the first-audit reserve
        // gate (read-only) and the authoritative promotion check-and-stamp both
        // still allow the paid audit to launch immediately.
        assert!(
            cooldown_would_allow(&launched, &peer, t0),
            "reserve gate must not see a losing ticket as audit coverage"
        );
        assert!(
            cooldown_allows_audit(&mut launched, &peer, t0),
            "promotion must not be deferred by a losing ticket"
        );

        // Conversely a WINNING ticket (real audit sent) does suppress the
        // first audit for the window, which is the intended shared semantics.
        let peer_won = strike_peer(5);
        assert!(audit_launch_decision(
            &mut attempts,
            &mut launched,
            &peer_won,
            t0,
            true
        ));
        assert!(
            !cooldown_would_allow(&launched, &peer_won, t0),
            "a real gossip audit still covers the peer for the window"
        );
    }

    #[test]
    fn cooldown_lets_audit_through_after_the_window() {
        let peer = strike_peer(2);
        let mut map: HashMap<PeerId, Instant> = HashMap::new();
        let t0 = Instant::now();
        assert!(cooldown_allows_audit(&mut map, &peer, t0));
        // Within the window: suppressed.
        let within = t0 + Duration::from_secs(config::AUDIT_ON_GOSSIP_COOLDOWN_SECS - 1);
        assert!(!cooldown_allows_audit(&mut map, &peer, within));
        // Past the window: allowed again.
        let after = t0 + Duration::from_secs(config::AUDIT_ON_GOSSIP_COOLDOWN_SECS + 1);
        assert!(cooldown_allows_audit(&mut map, &peer, after));
    }

    #[test]
    fn cooldown_is_per_peer_independent() {
        let mut map: HashMap<PeerId, Instant> = HashMap::new();
        let t0 = Instant::now();
        // Different peers each get their own first-audit pass at the same instant.
        for i in 0..20u8 {
            assert!(
                cooldown_allows_audit(&mut map, &strike_peer(i), t0),
                "peer {i} should be auditable independently"
            );
        }
    }

    #[test]
    fn audit_on_gossip_constants_match_adr() {
        // Tripwire on the ADR-locked tunables. The spot-check count sits at the
        // top of the auditor's 3..=5 band (the auditor clamps to that band, so
        // values above 5 would silently never be requested).
        assert_eq!(config::AUDIT_SPOTCHECK_COUNT, 5);
        assert!((config::AUDIT_ON_GOSSIP_PROBABILITY - 0.2).abs() < f64::EPSILON);
        assert_eq!(config::AUDIT_ON_GOSSIP_COOLDOWN_SECS, 30 * 60);
    }

    // (d) A confirmed storage-integrity failure penalizes immediately and
    // revokes credit; it is not a timeout.
    #[test]
    fn digest_mismatch_is_not_a_timeout_and_penalizes_immediately() {
        assert!(audit_failure_clears_bootstrap_claim(
            &AuditFailureReason::DigestMismatch
        ));
        assert!(audit_failure_revokes_holder_credit(
            &AuditFailureReason::DigestMismatch
        ));
    }

    /// The exact decision the `Failed` arm of `handle_subtree_audit_result`
    /// uses: confirmed failures revoke credit, `Timeout` does not.
    #[test]
    fn confirmed_failures_revoke_credit_timeout_does_not() {
        for reason in [
            AuditFailureReason::MalformedResponse,
            AuditFailureReason::DigestMismatch,
            AuditFailureReason::KeyAbsent,
            AuditFailureReason::Rejected,
        ] {
            assert!(
                audit_failure_revokes_holder_credit(&reason),
                "confirmed failure {reason:?} must revoke holder credit"
            );
        }
        assert!(
            !audit_failure_revokes_holder_credit(&AuditFailureReason::Timeout),
            "Timeout must NOT revoke credit (single dropped packet != storage loss)"
        );
    }

    /// Wiring test for the security fix: the helper the handler calls
    /// actually strips a credited peer on a confirmed failure
    /// (`DigestMismatch`), and actually RETAINS credit on `Timeout`.
    /// Records genuine credit first so neither assertion is vacuous;
    /// this fails if `forget_peer` stops being called, or if the
    /// `Timeout` exclusion is dropped (both verified by mutation).
    #[test]
    fn apply_revocation_strips_on_digest_mismatch_retains_on_timeout() {
        let peer = test_peer(0xAB);
        let key = test_key(1);
        let hash = [0xCD; 32];

        // Confirmed failure -> credit revoked.
        let mut provers = RecentProvers::new();
        provers.record_proof(key, peer, hash, Instant::now());
        assert!(
            provers.is_credited_holder(&key, &peer, &hash),
            "precondition: peer credited before failure"
        );
        apply_audit_failure_credit_revocation(
            &mut provers,
            &peer,
            &AuditFailureReason::DigestMismatch,
        );
        assert!(
            !provers.is_credited_holder(&key, &peer, &hash),
            "DigestMismatch must strip the peer's holder credit"
        );

        // Timeout -> credit retained.
        let mut provers_timeout = RecentProvers::new();
        provers_timeout.record_proof(key, peer, hash, Instant::now());
        apply_audit_failure_credit_revocation(
            &mut provers_timeout,
            &peer,
            &AuditFailureReason::Timeout,
        );
        assert!(
            provers_timeout.is_credited_holder(&key, &peer, &hash),
            "Timeout must retain holder credit (deliberate liveness cushion)"
        );
    }

    #[test]
    fn decoded_audit_failures_clear_active_bootstrap_claim() {
        for reason in [
            AuditFailureReason::MalformedResponse,
            AuditFailureReason::DigestMismatch,
            AuditFailureReason::KeyAbsent,
            AuditFailureReason::Rejected,
        ] {
            assert!(
                audit_failure_clears_bootstrap_claim(&reason),
                "decoded non-bootstrap failure {reason:?} should clear active claim"
            );
        }
    }

    #[test]
    fn first_failed_key_label_truncates_to_16_hex_chars() {
        // The high-order 8 bytes of the XorName determine the label so an
        // operator can group audit-failures on the same chunk prefix.
        let mut key = [0u8; 32];
        key[0] = 0x18;
        key[7] = 0xff;
        // Low-order bytes (positions 8..32) are deliberately set to 0xAA
        // to verify they are NOT included in the label.
        for byte in &mut key[8..] {
            *byte = 0xAA;
        }
        let label = first_failed_key_label(&[key]);
        // Only the first 8 bytes are encoded, low-order bytes are dropped.
        assert_eq!(label, "0x18000000000000ff");
        assert_eq!(label.len(), "0x".len() + 16);
    }

    #[test]
    fn first_failed_key_label_falls_back_when_empty() {
        // Should never happen in production (audit failure handling rejects
        // empty sets), but the formatter must still produce a valid label
        // so the log line doesn't contain a misleading default.
        assert_eq!(first_failed_key_label(&[]), "0x");
    }

    #[test]
    fn first_failed_key_label_uses_first_key_only() {
        let first = [0x11u8; 32];
        let second = [0x22u8; 32];
        assert_eq!(
            first_failed_key_label(&[first, second]),
            format!("0x{}", hex::encode(&first[..8]))
        );
    }

    // -- apply_fetch_result --------------------------------------------------
    //
    // The worker's disposition of a fetch outcome. Note there is no trust
    // handle in `apply_fetch_result`'s signature: the worker cannot report a
    // trust event for ANY outcome, and `execute_single_fetch` returns
    // `NoLongerResponsible` before its trust-reporting paths — the source did
    // nothing wrong when this node's own responsibility lapsed.

    /// Route `key` through the real pipeline stages (pending → promoted →
    /// dequeued → in-flight) so it carries a verification retry-slot
    /// reservation, exactly as a worker-dequeued key does. Returns the
    /// in-flight source.
    fn drive_key_in_flight(
        q: &mut ReplicationQueues,
        key: XorName,
        sources: Vec<PeerId>,
    ) -> PeerId {
        let hinter = sources.first().copied().unwrap_or_else(|| test_peer(0x01));
        let now = Instant::now();
        let entry = VerificationEntry {
            state: VerificationState::PendingVerify,
            verified_sources: Vec::new(),
            tried_sources: HashSet::new(),
            created_at: now,
            next_verify_at: now,
            hint_sources: HashSet::from([hinter]),
            replica_hint_sources: HashSet::from([hinter]),
            unresolved_retries: 0,
            no_holder_reported: false,
        };
        assert!(q.add_pending_verify(key, entry).admitted());
        assert!(q.promote_pending_to_fetch(key, key, sources));
        let candidate = q.dequeue_fetch().expect("promoted key must dequeue");
        let source = *candidate.sources.first().expect("candidate has a source");
        q.start_dequeued_fetch(candidate, source);
        source
    }

    #[test]
    fn no_longer_responsible_is_terminal_and_releases_the_retry_slot() {
        const RETRY_AFTER: Duration = Duration::from_secs(60);

        let mut q = ReplicationQueues::new();
        let key = test_key(0xAB);
        drive_key_in_flight(&mut q, key, vec![test_peer(0x01), test_peer(0x02)]);
        assert_eq!(q.retry_reserved_slot_count(), 1);

        let follow_up =
            apply_fetch_result(&mut q, &key, &FetchResult::NoLongerResponsible, RETRY_AFTER);

        assert_eq!(
            follow_up,
            FetchFollowUp::Terminal,
            "lapsed responsibility must run the caller's terminal bootstrap accounting"
        );
        assert!(
            !q.contains_key(&key),
            "the key must leave every pipeline stage — alternate sources included"
        );
        assert_eq!(
            q.pending_count(),
            0,
            "a lapsed-responsibility key must not be requeued for verification"
        );
        assert_eq!(
            q.retry_reserved_slot_count(),
            0,
            "terminal exit must release the verification retry-slot reservation"
        );
    }

    #[test]
    fn no_longer_responsible_shares_the_stored_terminal_path() {
        const RETRY_AFTER: Duration = Duration::from_secs(60);

        // Both variants must walk the identical terminal gate so the
        // battle-tested Stored accounting (retry-slot release + bootstrap
        // pending-set shrink in the caller) covers lapsed responsibility too.
        for result in [FetchResult::Stored, FetchResult::NoLongerResponsible] {
            let mut q = ReplicationQueues::new();
            let key = test_key(0xCD);
            drive_key_in_flight(&mut q, key, vec![test_peer(0x03)]);

            let follow_up = apply_fetch_result(&mut q, &key, &result, RETRY_AFTER);

            assert_eq!(follow_up, FetchFollowUp::Terminal);
            assert!(!q.contains_key(&key));
            assert_eq!(q.retry_reserved_slot_count(), 0);
        }
    }

    #[test]
    fn source_failure_walks_alternate_sources_then_requeues_for_verification() {
        const RETRY_AFTER: Duration = Duration::from_secs(60);

        let mut q = ReplicationQueues::new();
        let key = test_key(0xEF);
        let first = test_peer(0x04);
        let second = test_peer(0x05);
        drive_key_in_flight(&mut q, key, vec![first, second]);

        let follow_up = apply_fetch_result(&mut q, &key, &FetchResult::SourceFailed, RETRY_AFTER);
        assert_eq!(
            follow_up,
            FetchFollowUp::RetryFrom(second),
            "a failed source must not abandon the remaining verified sources"
        );
        assert_eq!(q.in_flight_count(), 1, "retry keeps the key in flight");

        let follow_up = apply_fetch_result(&mut q, &key, &FetchResult::SourceFailed, RETRY_AFTER);
        assert_eq!(
            follow_up,
            FetchFollowUp::RequeuedForVerification,
            "exhausted sources must restore the reserved verification entry"
        );
        assert_eq!(q.pending_count(), 1);
        assert_eq!(
            q.retry_reserved_slot_count(),
            0,
            "the reservation converts back into the pending entry itself"
        );
    }

    #[test]
    fn source_failure_without_retry_metadata_is_terminal() {
        const RETRY_AFTER: Duration = Duration::from_secs(60);

        // Direct enqueue (no pending entry) models a fetch with no
        // verification retry reservation to restore.
        let mut q = ReplicationQueues::new();
        let key = test_key(0x1F);
        let source = test_peer(0x06);
        assert!(q.enqueue_fetch(key, key, vec![source]));
        let candidate = q.dequeue_fetch().expect("enqueued key must dequeue");
        q.start_dequeued_fetch(candidate, source);

        let follow_up = apply_fetch_result(&mut q, &key, &FetchResult::SourceFailed, RETRY_AFTER);

        assert_eq!(follow_up, FetchFollowUp::Terminal);
        assert!(!q.contains_key(&key));
    }

    #[test]
    fn already_held_key_leaves_the_pipeline_terminally() {
        const RETRY_AFTER: Duration = Duration::from_secs(60);

        let mut q = ReplicationQueues::new();
        let key = test_key(0x4C);
        let source = test_peer(0x0B);
        drive_key_in_flight(&mut q, key, vec![source, test_peer(0x0C)]);

        let follow_up = apply_fetch_result(&mut q, &key, &FetchResult::AlreadyHeld, RETRY_AFTER);

        assert_eq!(
            follow_up,
            FetchFollowUp::Terminal,
            "holding the key already discharges the duty, so the key must leave \
             the pipeline exactly as a completed fetch does — requeueing it \
             would re-verify a key that needs nothing"
        );
        assert!(!q.contains_key(&key));
        assert_eq!(
            q.retry_reserved_slot_count(),
            0,
            "the terminal path must release the retry-slot reservation, or the \
             owner's verification budget leaks"
        );
    }

    #[test]
    fn local_write_failure_does_not_conscript_the_remaining_sources() {
        const RETRY_AFTER: Duration = Duration::from_secs(60);

        let mut q = ReplicationQueues::new();
        let key = test_key(0x2A);
        let first = test_peer(0x07);
        let second = test_peer(0x08);
        let third = test_peer(0x09);
        drive_key_in_flight(&mut q, key, vec![first, second, third]);

        let follow_up =
            apply_fetch_result(&mut q, &key, &FetchResult::LocalWriteFailed, RETRY_AFTER);

        assert_eq!(
            follow_up,
            FetchFollowUp::RequeuedForVerification,
            "a local write failure must go straight back to verification: the two \
             untried sources would each re-upload the same chunk into the same \
             full disk, and neither of them did anything wrong"
        );
        assert_eq!(q.in_flight_count(), 0);
        assert_eq!(
            q.pending_count(),
            1,
            "the key must come back — capacity frees up, and a stranded key is \
             a replica this node silently stops owing"
        );
        assert_eq!(q.retry_reserved_slot_count(), 0);
    }

    #[test]
    fn local_write_failure_without_retry_metadata_is_terminal() {
        const RETRY_AFTER: Duration = Duration::from_secs(60);

        // No pending entry to restore, so the only way not to strand the key
        // in `in_flight_fetch` forever — which would also stall bootstrap
        // drain — is the terminal path.
        let mut q = ReplicationQueues::new();
        let key = test_key(0x3B);
        let source = test_peer(0x0A);
        assert!(q.enqueue_fetch(key, key, vec![source]));
        let candidate = q.dequeue_fetch().expect("enqueued key must dequeue");
        q.start_dequeued_fetch(candidate, source);

        let follow_up =
            apply_fetch_result(&mut q, &key, &FetchResult::LocalWriteFailed, RETRY_AFTER);

        assert_eq!(follow_up, FetchFollowUp::Terminal);
        assert!(!q.contains_key(&key));
        assert_eq!(q.retry_reserved_slot_count(), 0);
    }
}
