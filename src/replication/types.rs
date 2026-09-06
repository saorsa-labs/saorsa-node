//! Core types for the replication subsystem.
//!
//! These types represent the state machine states, queue entries, and domain
//! concepts from the Kademlia-style replication design (see
//! `docs/REPLICATION_DESIGN.md`).

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::ant_protocol::XorName;
use crate::replication::config::REPAIR_HINT_MIN_AGE;
use saorsa_core::identity::PeerId;

// ---------------------------------------------------------------------------
// Verification state machine (Section 8 of REPLICATION_DESIGN.md)
// ---------------------------------------------------------------------------

/// Verification state machine.
///
/// Each unknown key transitions through these states exactly once per offer
/// lifecycle.  See Section 8 of `REPLICATION_DESIGN.md` for the full
/// state-transition diagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationState {
    /// Offer received, not yet processed.
    OfferReceived,
    /// Passed admission filter, awaiting quorum / paid-list verification.
    PendingVerify,
    /// Presence quorum passed (>= `QuorumNeeded` positives from
    /// `QuorumTargets`).
    QuorumVerified,
    /// Paid-list authorisation succeeded (>= `ConfirmNeeded` confirmations or
    /// derived from replica majority).
    PaidListVerified,
    /// Queued for record fetch.
    QueuedForFetch,
    /// Actively fetching from a verified source.
    Fetching,
    /// Successfully stored locally.
    Stored,
    /// Fetch failed but retryable (alternate sources remain).
    FetchRetryable,
    /// Fetch permanently abandoned (terminal failure or no alternate sources).
    FetchAbandoned,
    /// Quorum failed definitively (both paid-list and presence impossible this
    /// round).
    QuorumFailed,
    /// Quorum inconclusive (timeout with neither success nor fail-fast).
    QuorumInconclusive,
    /// Terminal: quorum abandoned, key forgotten.
    QuorumAbandoned,
    /// Terminal: key returned to idle (forgotten, requires new offer to
    /// re-enter).
    Idle,
}

// ---------------------------------------------------------------------------
// Hint pipeline classification
// ---------------------------------------------------------------------------

/// Whether a key was admitted via replica hints or paid hints only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HintPipeline {
    /// Key is in the admitted replica-hint pipeline (fetch-eligible).
    Replica,
    /// Key is in the paid-hint-only pipeline (`PaidForList` update only, no
    /// fetch).
    PaidOnly,
}

// ---------------------------------------------------------------------------
// Pending-verification table entry
// ---------------------------------------------------------------------------

/// Entry in the pending-verification table.
///
/// Tracks a single key through the verification FSM, recording which peers
/// responded and which have been tried for fetch.
#[derive(Debug, Clone)]
pub struct VerificationEntry {
    /// Current state in the verification FSM.
    pub state: VerificationState,
    /// Peers that responded `Present` during verification (verified fetch
    /// sources).
    pub verified_sources: Vec<PeerId>,
    /// Peers already tried for fetch (to avoid retrying the same source).
    pub tried_sources: HashSet<PeerId>,
    /// When this entry was created.
    pub created_at: Instant,
    /// Earliest time this key should be included in another verification
    /// round.
    pub next_verify_at: Instant,
    /// Routing-table peers that advertised this key and have not subsequently
    /// departed. Duplicate hints add to this set instead of being discarded.
    pub hint_sources: HashSet<PeerId>,
    /// Subset of [`Self::hint_sources`] that advertised a replica hint and
    /// therefore claimed chunk possession. Paid-only advertisers are excluded.
    pub replica_hint_sources: HashSet<PeerId>,
    /// Consecutive verification rounds that left this key unresolved.
    ///
    /// Counts deferrals, not rounds: it advances only when a round ends with no
    /// usable holder (or an inconclusive quorum) and the key is put back for a
    /// later retry. Zero means the key has not yet failed a round, so the next
    /// deferral is its first.
    ///
    /// Drives the retry backoff. Lifetime is the entry's own — eviction and
    /// re-admission start a fresh count.
    ///
    /// Cleared by a round that *did* find a holder, so it counts consecutive
    /// failures rather than lifetime ones: a key held up only by a full fetch
    /// queue is making progress and must not inherit an earlier backoff.
    pub unresolved_retries: u32,
    /// Whether this entry's one no-holder warning has already been emitted.
    ///
    /// Deliberately **not** derived from [`Self::unresolved_retries`]. The two
    /// answer different questions: the counter asks "how many consecutive
    /// rounds failed", which an inconclusive quorum legitimately advances, and
    /// this asks "have we told anyone", which only a no-holder result may
    /// consume. Deriving one from the other loses the first — and only —
    /// warning for any key whose opening round is inconclusive.
    ///
    /// Cleared alongside the counter, so "once per episode" is literal: a key
    /// that resolves and later becomes unresolvable again is reported again.
    pub no_holder_reported: bool,
}

impl VerificationEntry {
    /// Which pipeline this key arrived on.
    ///
    /// Derived from [`Self::replica_hint_sources`] rather than stored: the
    /// pipeline *is* "did any peer claim to hold this key", so a stored copy
    /// can only drift from its own definition as advertisers are merged in and
    /// departed peers are pruned out.
    ///
    /// This describes hint *provenance*, not authorization. It selects fetch
    /// sources (only a peer claiming possession is worth fetching from) and
    /// scopes sole-source trust penalties. It must never gate storage:
    /// possession claims come from the sender, so treating one as permission to
    /// store lets a peer conscript a node that carries no responsibility for
    /// the key. Storage responsibility is decided separately, against live
    /// routing state, by `is_responsible(storage_admission_width)` at the point
    /// of download.
    #[must_use]
    pub fn pipeline(&self) -> HintPipeline {
        if self.replica_hint_sources.is_empty() {
            HintPipeline::PaidOnly
        } else {
            HintPipeline::Replica
        }
    }
}

// ---------------------------------------------------------------------------
// Fetch queue
// ---------------------------------------------------------------------------

/// Heap-ordering key for the fetch queue, ordered by relevance
/// (nearest-first).
///
/// Carries **only** the two fields the ordering reads, and both are fixed for
/// as long as a key stays queued. The mutable half of a queued fetch lives in
/// [`FetchPayload`], outside the heap, so that merging a newly-discovered
/// source into an already-queued key cannot disturb heap order — and therefore
/// needs no heap rebuild.
///
/// Implements [`Ord`] with *reversed* distance comparison so that a
/// [`BinaryHeap`](std::collections::BinaryHeap) (max-heap) dequeues the
/// nearest key first.
#[derive(Debug, Clone, Copy)]
pub struct FetchOrder {
    /// The key to fetch.
    pub key: XorName,
    /// XOR distance from self to key (for priority ordering).
    pub distance: XorName,
}

impl Eq for FetchOrder {}

impl PartialEq for FetchOrder {
    fn eq(&self, other: &Self) -> bool {
        self.distance == other.distance && self.key == other.key
    }
}

impl Ord for FetchOrder {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering: smaller distance = higher priority (BinaryHeap is
        // max-heap).  Tie-break on key for consistency with PartialEq.
        other
            .distance
            .cmp(&self.distance)
            .then_with(|| self.key.cmp(&other.key))
    }
}

impl PartialOrd for FetchOrder {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The mutable half of a queued fetch, held outside the priority heap.
///
/// Neither field participates in [`FetchOrder`]'s ordering, and both are read
/// only once the key is dequeued. Holding them in a key-indexed map is what
/// lets a further source be merged into an already-queued key in O(1) instead
/// of costing a full rebuild of the fetch heap.
#[derive(Debug, Clone)]
pub struct FetchPayload {
    /// Verified source peers that responded `Present`.
    pub sources: Vec<PeerId>,
    /// Pending-verification entry to restore if every fetch source is
    /// exhausted before the chunk is recovered.
    pub retry_verification: Option<VerificationEntry>,
}

/// A candidate dequeued for fetch: a [`FetchOrder`] rejoined with its
/// [`FetchPayload`].
#[derive(Debug, Clone)]
pub struct FetchCandidate {
    /// The key to fetch.
    pub key: XorName,
    /// XOR distance from self to key.
    pub distance: XorName,
    /// Verified source peers that responded `Present`.
    pub sources: Vec<PeerId>,
    /// Pending-verification entry to restore if every fetch source is
    /// exhausted before the chunk is recovered.
    pub retry_verification: Option<VerificationEntry>,
}

// ---------------------------------------------------------------------------
// Verification evidence types
// ---------------------------------------------------------------------------

/// Per-key presence evidence from a verification round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresenceEvidence {
    /// Peer holds the record.
    Present,
    /// Peer does not hold the record.
    Absent,
    /// Peer did not respond in time (neutral, not negative).
    Unresolved,
}

/// Per-key paid-list evidence from a verification round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaidListEvidence {
    /// Peer confirms key is in its `PaidForList`.
    Confirmed,
    /// Peer says key is NOT in its `PaidForList`.
    NotFound,
    /// Peer did not respond in time (neutral).
    Unresolved,
}

/// Aggregated verification evidence for a single key from one verification
/// round.
#[derive(Debug, Clone)]
pub struct KeyVerificationEvidence {
    /// Presence evidence per peer (from `QuorumTargets`).
    pub presence: HashMap<PeerId, PresenceEvidence>,
    /// Paid-list evidence per peer (from `PaidTargets`).
    pub paid_list: HashMap<PeerId, PaidListEvidence>,
}

// ---------------------------------------------------------------------------
// Failure evidence (Section 14 — TrustEngine integration)
// ---------------------------------------------------------------------------

/// Counts that describe a confirmed audit failure without logging per-key
/// detail at `ERROR` level.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuditFailureSummary {
    /// Number of keys in the original audit challenge.
    pub challenged_keys: usize,
    /// Number of keys that still failed after responsibility confirmation.
    pub failed_keys: usize,
    /// Confirmed failures where the responder returned the absent-key sentinel.
    pub absent_keys: usize,
    /// Confirmed failures where the responder returned a digest that did not
    /// match the challenger's local bytes.
    pub digest_mismatch_keys: usize,
}

/// Failure evidence types emitted to `TrustEngine` (Section 14).
#[derive(Debug, Clone)]
pub enum FailureEvidence {
    /// Failed fetch attempt from a source peer.
    ReplicationFailure {
        /// The peer that failed to serve the record.
        peer: PeerId,
        /// The key that could not be fetched.
        key: XorName,
    },
    /// Audit failure with confirmed responsible keys.
    AuditFailure {
        /// Unique identifier for the audit challenge.
        challenge_id: u64,
        /// The peer that was challenged.
        challenged_peer: PeerId,
        /// Keys confirmed as failed.
        confirmed_failed_keys: Vec<XorName>,
        /// Aggregated reason counts for the confirmed failures.
        summary: AuditFailureSummary,
        /// Why the audit failed.
        reason: AuditFailureReason,
    },
    /// Peer claiming bootstrap past grace period.
    BootstrapClaimAbuse {
        /// The offending peer.
        peer: PeerId,
        /// When this peer was first seen.
        first_seen: Instant,
    },
    /// ADR-0004: a quote's claimed committed key count contradicts the signed
    /// commitment it pinned. The quote and the commitment are both signed by
    /// the same key, so this is a deterministic, first-occurrence
    /// contradiction — not bad luck — and lands in the same trust lane as a
    /// confirmed deterministic audit failure. Reported only in the
    /// client-put context (a replication receipt's pin has legitimately aged
    /// out). The fields are the portable contradiction: any third party
    /// holding the two signed artifacts can recompute it.
    QuoteCommitmentMismatch {
        /// The peer whose quote and commitment disagree.
        peer: PeerId,
        /// The commitment hash the quote pinned (identifies the signed
        /// commitment artifact); equals `commitment.hash()`.
        pinned_commitment: [u8; 32],
        /// The key count the quote claimed (and priced against).
        quoted_key_count: u32,
        /// The key count the pinned commitment actually attests.
        committed_key_count: u32,
        /// The signed quote artifact that carries the contradicting
        /// `committed_key_count` + pin, ML-DSA-signed by `peer`, as canonical
        /// serialized bytes. Carried opaquely (rmp of a `PaymentQuote` on the
        /// single-node path, or a `MerklePaymentCandidateNode` on the merkle
        /// path) so the one variant serves both paths; a third party
        /// deserializes and re-verifies it against `peer`.
        quote_artifact: Vec<u8>,
        /// The signed commitment artifact the quote pinned (ML-DSA-signed by
        /// the same `peer`). Together with `quote_artifact`, this is the
        /// PORTABLE evidence: any third party re-verifies both signatures and
        /// recomputes `quoted_key_count != commitment.key_count` without
        /// trusting the reporter.
        commitment: Box<crate::replication::commitment::StorageCommitment>,
    },
}

/// Reason for audit failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditFailureReason {
    /// Peer timed out (no response within deadline).
    Timeout,
    /// Response was malformed.
    MalformedResponse,
    /// One or more per-key digest mismatches.
    DigestMismatch,
    /// Key was absent (signalled by sentinel digest).
    KeyAbsent,
    /// Peer explicitly rejected the audit challenge.
    Rejected,
}

// ---------------------------------------------------------------------------
// Peer sync tracking
// ---------------------------------------------------------------------------

/// Record of sync history with a peer, for `RepairOpportunity` tracking.
#[derive(Debug, Clone)]
pub struct PeerSyncRecord {
    /// Last time we successfully synced with this peer.
    pub last_sync: Option<Instant>,
    /// Number of full neighbor-sync cycles completed since last sync with this
    /// peer.
    pub cycles_since_sync: u32,
}

impl PeerSyncRecord {
    /// Whether this peer has had a repair opportunity (synced at least once
    /// and at least one subsequent cycle has completed).
    #[must_use]
    pub fn has_repair_opportunity(&self) -> bool {
        self.last_sync.is_some() && self.cycles_since_sync >= 1
    }
}

// ---------------------------------------------------------------------------
// Repair proof tracking
// ---------------------------------------------------------------------------

/// Evidence that this node has sent a replica repair hint for a key to a peer.
#[derive(Debug, Clone)]
struct RepairProof {
    /// Local neighbor-sync cycle epoch when the hint was sent.
    hinted_at_epoch: u64,
    /// Monotonic local time when the hint was sent.
    hinted_at: Instant,
}

/// Repair proofs for one key, tied to the close-group snapshot they were
/// recorded against.
#[derive(Debug, Clone)]
struct RepairProofEntry {
    /// Self-inclusive close group observed when these proofs were recorded.
    close_peers: HashSet<PeerId>,
    /// Per-peer proof metadata for peers in `close_peers`.
    peer_proofs: HashMap<PeerId, RepairProof>,
}

impl RepairProofEntry {
    fn new(close_peers: HashSet<PeerId>) -> Self {
        Self {
            close_peers,
            peer_proofs: HashMap::new(),
        }
    }
}

/// Evidence that this node has sent replica repair hints for local keys.
///
/// The map is keyed by record key so each key retains only one close-group
/// snapshot and at most that snapshot's peers. This bounds memory by local key
/// count times the replication close-group size rather than by churn history.
#[derive(Debug, Clone, Default)]
pub struct RepairProofs {
    /// Key-scoped repair proofs.
    proofs_by_key: HashMap<XorName, RepairProofEntry>,
}

impl RepairProofs {
    /// Create an empty repair-proof table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `peer` was sent a replica repair hint for `key`.
    ///
    /// `current_close_peers` must be the current self-inclusive close group for
    /// `key`. If that close group differs from the previous proof snapshot,
    /// proofs for peers that left the close group are invalidated before
    /// recording. Stable peers keep their proofs, while a peer that leaves and
    /// later re-enters still needs a fresh hint.
    pub fn record_replica_hint_sent(
        &mut self,
        peer: PeerId,
        key: XorName,
        current_close_peers: &HashSet<PeerId>,
        hinted_at_epoch: u64,
    ) -> bool {
        self.insert_replica_hint_sent(
            peer,
            key,
            current_close_peers,
            hinted_at_epoch,
            Instant::now(),
        )
    }

    /// Record that `peer` was sent a replica repair hint at a caller-provided
    /// time.
    ///
    /// This is exposed only for deterministic tests and test harnesses. Normal
    /// production callers use [`Self::record_replica_hint_sent`] so the proof
    /// timestamp is captured internally at send-recording time.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn record_replica_hint_sent_at(
        &mut self,
        peer: PeerId,
        key: XorName,
        current_close_peers: &HashSet<PeerId>,
        hinted_at_epoch: u64,
        hinted_at: Instant,
    ) -> bool {
        self.insert_replica_hint_sent(peer, key, current_close_peers, hinted_at_epoch, hinted_at)
    }

    fn insert_replica_hint_sent(
        &mut self,
        peer: PeerId,
        key: XorName,
        current_close_peers: &HashSet<PeerId>,
        hinted_at_epoch: u64,
        hinted_at: Instant,
    ) -> bool {
        self.reconcile_key_close_group(&key, current_close_peers);

        if !current_close_peers.contains(&peer) {
            return false;
        }

        let entry = self
            .proofs_by_key
            .entry(key)
            .or_insert_with(|| RepairProofEntry::new(current_close_peers.clone()));

        if entry.peer_proofs.contains_key(&peer) {
            return false;
        }

        entry.peer_proofs.insert(
            peer,
            RepairProof {
                hinted_at_epoch,
                hinted_at,
            },
        );
        true
    }

    /// Whether this node has mature repair-hint evidence for `(peer, key)`.
    ///
    /// The check invalidates proofs for peers that have left the current
    /// self-inclusive close group. A proof is mature only after at least one
    /// later local sync-cycle epoch and the repair hint is at least
    /// [`REPAIR_HINT_MIN_AGE`] old.
    pub fn has_mature_replica_hint(
        &mut self,
        peer: &PeerId,
        key: &XorName,
        current_close_peers: &HashSet<PeerId>,
        current_epoch: u64,
        now: Instant,
    ) -> bool {
        self.reconcile_key_close_group(key, current_close_peers);

        self.proofs_by_key
            .get(key)
            .and_then(|entry| entry.peer_proofs.get(peer))
            .is_some_and(|proof| {
                proof.hinted_at_epoch < current_epoch
                    && now.saturating_duration_since(proof.hinted_at) >= REPAIR_HINT_MIN_AGE
            })
    }

    /// Remove all repair proofs for a key, e.g. after local deletion.
    pub fn remove_key(&mut self, key: &XorName) {
        self.proofs_by_key.remove(key);
    }

    /// Remove all repair proofs for a peer, e.g. after routing-table removal.
    pub fn remove_peer(&mut self, peer: &PeerId) {
        self.proofs_by_key.retain(|_, entry| {
            entry.peer_proofs.remove(peer);
            !entry.peer_proofs.is_empty()
        });
    }

    fn reconcile_key_close_group(&mut self, key: &XorName, current_close_peers: &HashSet<PeerId>) {
        let should_remove = if let Some(entry) = self.proofs_by_key.get_mut(key) {
            if entry.close_peers == *current_close_peers {
                return;
            }

            entry.close_peers.clone_from(current_close_peers);
            entry
                .peer_proofs
                .retain(|peer, _| current_close_peers.contains(peer));
            entry.peer_proofs.is_empty()
        } else {
            false
        };

        if should_remove {
            self.proofs_by_key.remove(key);
        }
    }
}

// ---------------------------------------------------------------------------
// Neighbor sync cycle state
// ---------------------------------------------------------------------------

/// Result of observing a peer's bootstrap claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapClaimObservation {
    /// The peer is inside its first and only bootstrap-claim grace window.
    WithinGrace {
        /// First time this peer claimed bootstrap status.
        first_seen: Instant,
    },
    /// The peer has continuously claimed bootstrap status past the grace period.
    PastGrace {
        /// First time this peer claimed bootstrap status.
        first_seen: Instant,
    },
    /// The peer previously stopped claiming bootstrap and then claimed it again.
    Repeated {
        /// First time this peer ever claimed bootstrap status.
        first_seen: Instant,
    },
}

/// Neighbor sync cycle state.
///
/// Tracks a deterministic walk through the current close-group snapshot,
/// per-peer cooldown times, active bootstrap claims, and peers that have already
/// used their one bootstrap-claim window.
#[derive(Debug)]
pub struct NeighborSyncState {
    /// Newly-entered close peers to sync before the normal cycle cursor.
    ///
    /// This queue is populated from `KClosestPeersChanged` routing-table
    /// events and is intentionally separate from `order`: priority syncs do
    /// not restart the current round-robin cycle or discard already-scanned
    /// peers.
    pub priority_order: VecDeque<PeerId>,
    /// Deterministic ordering of peers for the current cycle (snapshot).
    pub order: Vec<PeerId>,
    /// Current cursor position into `order`.
    pub cursor: usize,
    /// Per-peer last successful sync time (for cooldown).
    pub last_sync_times: HashMap<PeerId, Instant>,
    /// Active bootstrap claim first-seen timestamps per peer.
    ///
    /// Entries are removed when a peer stops claiming bootstrap. The peer
    /// remains in `bootstrap_claim_history`, so a later claim is repeated-claim
    /// abuse instead of a fresh grace period.
    pub bootstrap_claims: HashMap<PeerId, Instant>,
    /// First-ever bootstrap claim timestamp per peer.
    ///
    /// This is retained after active claims are cleared so each peer gets at
    /// most one bootstrap-claim grace window. Under Sybil attack with many
    /// distinct peer IDs claiming bootstrap, this map grows unboundedly. In
    /// practice the trust engine limits Sybil impact before this becomes a
    /// memory issue.
    pub bootstrap_claim_history: HashMap<PeerId, Instant>,
    /// Cursor used by post-cycle pruning to rotate through stored records when
    /// the per-pass prune-confirmation budget is exhausted.
    pub prune_cursor: usize,
}

impl NeighborSyncState {
    /// Create a new cycle from the given close neighbors.
    #[must_use]
    pub fn new_cycle(close_neighbors: Vec<PeerId>) -> Self {
        Self {
            priority_order: VecDeque::new(),
            order: close_neighbors,
            cursor: 0,
            last_sync_times: HashMap::new(),
            bootstrap_claims: HashMap::new(),
            bootstrap_claim_history: HashMap::new(),
            prune_cursor: 0,
        }
    }

    /// Observe a peer claiming bootstrap status.
    ///
    /// A peer receives one grace window from its first observed bootstrap claim.
    /// If it later stops claiming bootstrap, callers should clear only the
    /// active claim with [`Self::clear_active_bootstrap_claim`]. A subsequent
    /// claim is then reported as [`BootstrapClaimObservation::Repeated`].
    #[must_use]
    pub fn observe_bootstrap_claim(
        &mut self,
        peer: PeerId,
        now: Instant,
        grace_period: Duration,
    ) -> BootstrapClaimObservation {
        if let Some(first_seen) = self.bootstrap_claims.get(&peer).copied() {
            if now.duration_since(first_seen) > grace_period {
                BootstrapClaimObservation::PastGrace { first_seen }
            } else {
                BootstrapClaimObservation::WithinGrace { first_seen }
            }
        } else if let Some(first_seen) = self.bootstrap_claim_history.get(&peer).copied() {
            BootstrapClaimObservation::Repeated { first_seen }
        } else {
            self.bootstrap_claims.insert(peer, now);
            self.bootstrap_claim_history.insert(peer, now);
            BootstrapClaimObservation::WithinGrace { first_seen: now }
        }
    }

    /// Clear the active bootstrap claim for a peer, retaining claim history.
    pub fn clear_active_bootstrap_claim(&mut self, peer: &PeerId) -> bool {
        self.bootstrap_claims.remove(peer).is_some()
    }

    /// Queue newly-entered close peers for priority sync.
    ///
    /// Existing queued peers are retained in their original position and
    /// duplicates from the same routing-table churn burst are ignored.
    pub fn queue_priority_peers<I>(&mut self, peers: I) -> usize
    where
        I: IntoIterator<Item = PeerId>,
    {
        let mut queued = 0;
        for peer in peers {
            if self.priority_order.contains(&peer) {
                continue;
            }
            self.priority_order.push_back(peer);
            queued += 1;
        }
        queued
    }

    /// Drop pending sync peers that are no longer in the close-peer set.
    ///
    /// Peers still in `close_peers` keep their relative position. The cursor is
    /// adjusted so already-scanned retained peers are not selected again.
    pub fn retain_sync_peers(&mut self, close_peers: &HashSet<PeerId>) -> usize {
        let old_priority_len = self.priority_order.len();
        self.priority_order
            .retain(|peer| close_peers.contains(peer));

        let old_order_len = self.order.len();
        let old_cursor = self.cursor;
        let mut retained_before_cursor = 0;
        let mut retained_order = Vec::with_capacity(old_order_len);
        for (idx, peer) in self.order.drain(..).enumerate() {
            if close_peers.contains(&peer) {
                if idx < old_cursor {
                    retained_before_cursor += 1;
                }
                retained_order.push(peer);
            }
        }

        self.order = retained_order;
        self.cursor = retained_before_cursor;

        (old_priority_len - self.priority_order.len()) + (old_order_len - self.order.len())
    }

    /// Remove a peer from any pending neighbor-sync state.
    pub fn remove_peer(&mut self, peer: &PeerId) -> bool {
        let old_priority_len = self.priority_order.len();
        self.priority_order.retain(|queued| queued != peer);

        let old_order_len = self.order.len();
        if let Some(pos) = self.order.iter().position(|queued| queued == peer) {
            self.order.remove(pos);
            if pos < self.cursor {
                self.cursor = self.cursor.saturating_sub(1);
            }
        }

        old_priority_len != self.priority_order.len() || old_order_len != self.order.len()
    }

    /// Whether the current cycle is complete.
    #[must_use]
    pub fn is_cycle_complete(&self) -> bool {
        self.priority_order.is_empty() && self.cursor >= self.order.len()
    }

    /// Whether topology-change (priority) peers are still queued.
    ///
    /// The neighbor-sync loop drains these back-to-back rather than parking on
    /// the periodic tick, so a churn burst converges at round-trip speed. The
    /// `sync_trigger` `Notify` coalesces multiple wakeups into one, so it cannot
    /// be the sole signal for pending work — this queue is the source of truth.
    #[must_use]
    pub fn has_priority_peers(&self) -> bool {
        !self.priority_order.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Bootstrap drain state (Section 16)
// ---------------------------------------------------------------------------

/// Bootstrap drain state tracking (Section 16).
#[derive(Debug)]
pub struct BootstrapState {
    /// Whether bootstrap is complete (all peer requests done, queues empty).
    pub drained: bool,
    /// Number of bootstrap peer requests still pending.
    pub pending_peer_requests: usize,
    /// Keys discovered during bootstrap that are still in the verification /
    /// fetch pipeline.
    pub pending_keys: HashSet<XorName>,
    /// Peers whose bootstrap admission unit had one or more hints rejected at
    /// capacity, mapped to the time of their **first** such rejection. Each
    /// entry means "this source still owes us at least one re-hinted key after
    /// the queues drain".
    /// `check_bootstrap_drained` refuses to claim the node fully drained
    /// while this map is non-empty: a source's presence is cleared by its
    /// next admission cycle that completes with zero capacity rejections
    /// (i.e. the source successfully re-delivered everything that
    /// previously overflowed). Tracking per-source instead of a global
    /// counter prevents one peer's rejection from being "cleared" by an
    /// unrelated peer's clean cycle.
    ///
    /// The recorded time is **first-seen and never refreshed** (see
    /// [`Self::note_capacity_rejected`]). A repeat rejection re-asserts that
    /// the source still owes work, but it must not restart the expiry clock:
    /// a source that keeps overflowing the queue would otherwise keep its own
    /// record permanently fresh and wedge bootstrap open forever, which
    /// disables auditing (Invariant 19) for the lifetime of the pressure.
    /// First-seen semantics bound the wedge at
    /// `ReplicationConfig::capacity_rejected_max_age` regardless of how a
    /// source behaves.
    ///
    /// Entries expire once that first-rejection time is older than
    /// `capacity_rejected_max_age` (see
    /// `super::bootstrap::expire_capacity_rejected`): the source either
    /// abandoned re-delivery, is overflowing us faster than it can re-deliver,
    /// or its `PeerRemoved` cleanup raced the recording of the rejection and
    /// left an entry no future event can clear. Expiring an entry means
    /// bootstrap may drain without ever admitting keys that source
    /// advertised. This is acceptable and consistent with
    /// `update_bootstrap_after_peer_removed`, which already forfeits a
    /// departed source's owed work wholesale — post-bootstrap periodic
    /// neighbor sync and the audit/repair pipeline are the recovery path for
    /// missed keys.
    ///
    /// Sources whose key was *displaced* by another sender reclaiming a
    /// borrowed slot are deliberately NOT recorded here: fairness reclamation
    /// is our decision, not a failure of theirs, and stamping the victim lets
    /// a third party block our drain through an unrelated honest peer. The
    /// displaced key is forfeited to the same post-bootstrap recovery path.
    pub capacity_rejected_sources: HashMap<PeerId, Instant>,
}

impl BootstrapState {
    /// Create initial bootstrap state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            drained: false,
            pending_peer_requests: 0,
            pending_keys: HashSet::new(),
            capacity_rejected_sources: HashMap::new(),
        }
    }

    /// Record that `source` had one or more hints rejected at capacity.
    ///
    /// First-seen semantics: a repeat rejection re-asserts the debt but leaves
    /// the original timestamp alone, so the expiry clock in
    /// `super::bootstrap::expire_capacity_rejected` measures how long the
    /// source has owed us work rather than how recently it last overflowed us.
    /// See [`Self::capacity_rejected_sources`] for why refreshing wedges
    /// bootstrap open.
    ///
    /// Returns whether this was the source's first outstanding rejection.
    pub fn note_capacity_rejected(&mut self, source: PeerId, now: Instant) -> bool {
        let first = !self.capacity_rejected_sources.contains_key(&source);
        self.capacity_rejected_sources.entry(source).or_insert(now);
        first
    }

    /// Check if bootstrap is drained.
    ///
    /// Only returns `true` after [`super::bootstrap::check_bootstrap_drained`] or
    /// [`super::bootstrap::mark_bootstrap_drained`] has explicitly set the flag. A fresh
    /// `BootstrapState` is NOT drained — the audit loop must wait until
    /// bootstrap work has actually completed (Invariant 19).
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.drained
    }

    /// Remove a key from the bootstrap pending set.
    ///
    /// Called when a key terminally leaves the verification/fetch pipeline
    /// (stored, abandoned, quorum failed, etc.) so the drain check set
    /// shrinks incrementally rather than being re-scanned in full.
    pub fn remove_key(&mut self, key: &XorName) {
        self.pending_keys.remove(key);
    }
}

impl Default for BootstrapState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a `PeerId` from a single byte (zero-padded to 32 bytes).
    fn peer_id_from_byte(b: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        PeerId::from_bytes(bytes)
    }

    fn mature_hint_times() -> (Instant, Instant) {
        let hinted_at = Instant::now();
        let now = hinted_at
            .checked_add(REPAIR_HINT_MIN_AGE)
            .unwrap_or(hinted_at);
        (hinted_at, now)
    }

    // -- FetchOrder ordering -----------------------------------------------

    #[test]
    fn fetch_order_nearest_key_has_highest_priority() {
        let near = FetchOrder {
            key: [1u8; 32],
            distance: [
                0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
        };

        let far = FetchOrder {
            key: [2u8; 32],
            distance: [
                0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
        };

        // In a max-heap the "greatest" element pops first.
        // Our reversed Ord makes smaller-distance candidates greater.
        assert!(near > far, "nearer candidate should compare greater");

        let mut heap = std::collections::BinaryHeap::new();
        heap.push(far);
        heap.push(near);

        assert_eq!(heap.len(), 2, "heap should contain both candidates");

        let first = heap.pop();
        assert!(first.is_some(), "first pop should succeed");
        assert_eq!(
            first.map(|c| c.key),
            Some(near.key),
            "nearest key should pop first"
        );

        let second = heap.pop();
        assert!(second.is_some(), "second pop should succeed");
        assert_eq!(
            second.map(|c| c.key),
            Some(far.key),
            "farthest key should pop second"
        );
    }

    #[test]
    fn fetch_order_same_distance_and_key_is_equal() {
        let a = FetchOrder {
            key: [1u8; 32],
            distance: [5u8; 32],
        };

        let b = FetchOrder {
            key: [1u8; 32],
            distance: [5u8; 32],
        };

        assert_eq!(
            a.cmp(&b),
            Ordering::Equal,
            "same distance + same key should yield Equal"
        );
        assert_eq!(a, b, "PartialEq must agree with Ord");
    }

    #[test]
    fn fetch_order_same_distance_different_key_is_deterministic() {
        let a = FetchOrder {
            key: [1u8; 32],
            distance: [5u8; 32],
        };

        let b = FetchOrder {
            key: [2u8; 32],
            distance: [5u8; 32],
        };

        assert_ne!(
            a.cmp(&b),
            Ordering::Equal,
            "same distance + different key must not be Equal"
        );
        assert_ne!(a, b, "PartialEq must agree with Ord");
    }

    // -- PeerSyncRecord ----------------------------------------------------

    #[test]
    fn peer_sync_record_no_sync_yet() {
        let record = PeerSyncRecord {
            last_sync: None,
            cycles_since_sync: 0,
        };
        assert!(
            !record.has_repair_opportunity(),
            "never-synced peer has no repair opportunity"
        );
    }

    #[test]
    fn peer_sync_record_synced_but_no_cycle() {
        let record = PeerSyncRecord {
            last_sync: Some(Instant::now()),
            cycles_since_sync: 0,
        };
        assert!(
            !record.has_repair_opportunity(),
            "synced peer with zero subsequent cycles has no repair opportunity"
        );
    }

    #[test]
    fn peer_sync_record_synced_with_cycle() {
        let record = PeerSyncRecord {
            last_sync: Some(Instant::now()),
            cycles_since_sync: 1,
        };
        assert!(
            record.has_repair_opportunity(),
            "synced peer with >= 1 cycle should have repair opportunity"
        );
    }

    #[test]
    fn peer_sync_record_no_sync_many_cycles() {
        let record = PeerSyncRecord {
            last_sync: None,
            cycles_since_sync: 10,
        };
        assert!(
            !record.has_repair_opportunity(),
            "never-synced peer has no repair opportunity regardless of cycle count"
        );
    }

    // -- RepairProofs --------------------------------------------------------

    #[test]
    fn repair_proofs_record_sent_hint_for_close_peer() {
        const HINT_EPOCH: u64 = 7;
        const CURRENT_EPOCH: u64 = HINT_EPOCH + 1;

        let key = [0xA1; 32];
        let peer = peer_id_from_byte(1);
        let close_peers = HashSet::from([peer, peer_id_from_byte(2), peer_id_from_byte(3)]);
        let mut proofs = RepairProofs::new();
        let (hinted_at, now) = mature_hint_times();

        assert!(proofs.record_replica_hint_sent_at(peer, key, &close_peers, HINT_EPOCH, hinted_at,));

        assert!(
            proofs.has_mature_replica_hint(&peer, &key, &close_peers, CURRENT_EPOCH, now),
            "old sent hint should make key auditable for that peer"
        );
    }

    #[test]
    fn repair_proofs_reject_peer_outside_current_close_group() {
        const HINT_EPOCH: u64 = 7;
        const CURRENT_EPOCH: u64 = HINT_EPOCH + 1;

        let key = [0xA2; 32];
        let peer = peer_id_from_byte(1);
        let close_peers = HashSet::from([peer_id_from_byte(2), peer_id_from_byte(3)]);
        let mut proofs = RepairProofs::new();
        let (hinted_at, now) = mature_hint_times();

        assert!(!proofs.record_replica_hint_sent_at(
            peer,
            key,
            &close_peers,
            HINT_EPOCH,
            hinted_at,
        ));

        assert!(
            !proofs.has_mature_replica_hint(&peer, &key, &close_peers, CURRENT_EPOCH, now),
            "peers outside current close group must not get repair proof"
        );
    }

    #[test]
    fn repair_proofs_require_later_epoch() {
        const HINT_EPOCH: u64 = 7;
        const CURRENT_EPOCH: u64 = HINT_EPOCH + 1;

        let key = [0xA3; 32];
        let peer = peer_id_from_byte(1);
        let close_peers = HashSet::from([peer, peer_id_from_byte(2), peer_id_from_byte(3)]);
        let mut proofs = RepairProofs::new();
        let (hinted_at, now) = mature_hint_times();

        assert!(proofs.record_replica_hint_sent_at(peer, key, &close_peers, HINT_EPOCH, hinted_at,));

        assert!(
            !proofs.has_mature_replica_hint(&peer, &key, &close_peers, HINT_EPOCH, now),
            "same-cycle proof should not be audit-eligible"
        );
        assert!(
            proofs.has_mature_replica_hint(&peer, &key, &close_peers, CURRENT_EPOCH, now),
            "old proof should mature after a later local sync-cycle epoch"
        );
    }

    #[test]
    fn repair_proofs_require_min_hint_age() {
        const HINT_EPOCH: u64 = 7;
        const CURRENT_EPOCH: u64 = HINT_EPOCH + 1;

        let key = [0xA8; 32];
        let peer = peer_id_from_byte(1);
        let close_peers = HashSet::from([peer, peer_id_from_byte(2), peer_id_from_byte(3)]);
        let mut proofs = RepairProofs::new();
        let hinted_at = Instant::now();

        assert!(proofs.record_replica_hint_sent_at(peer, key, &close_peers, HINT_EPOCH, hinted_at));

        assert!(
            !proofs.has_mature_replica_hint(&peer, &key, &close_peers, CURRENT_EPOCH, hinted_at),
            "fresh repair hints should not be audit-eligible"
        );
        assert!(
            proofs.has_mature_replica_hint(
                &peer,
                &key,
                &close_peers,
                CURRENT_EPOCH,
                hinted_at
                    .checked_add(REPAIR_HINT_MIN_AGE)
                    .unwrap_or(hinted_at),
            ),
            "repair hints should mature once they are at least the minimum age"
        );
    }

    #[test]
    fn repair_proofs_repeated_hint_does_not_reset_maturity() {
        const HINT_EPOCH: u64 = 7;
        const REPEATED_HINT_EPOCH: u64 = HINT_EPOCH + 1;

        let key = [0xA5; 32];
        let peer = peer_id_from_byte(1);
        let close_peers = HashSet::from([peer, peer_id_from_byte(2), peer_id_from_byte(3)]);
        let mut proofs = RepairProofs::new();
        let (hinted_at, now) = mature_hint_times();

        assert!(proofs.record_replica_hint_sent_at(peer, key, &close_peers, HINT_EPOCH, hinted_at,));
        assert!(
            !proofs.record_replica_hint_sent_at(peer, key, &close_peers, REPEATED_HINT_EPOCH, now),
            "duplicate hint in the same close group should keep existing proof"
        );
        assert!(
            proofs.has_mature_replica_hint(&peer, &key, &close_peers, REPEATED_HINT_EPOCH, now),
            "duplicate hint must not reset an already mature proof"
        );
    }

    #[test]
    fn repair_proofs_retain_stable_peers_on_close_group_change() {
        const HINT_EPOCH: u64 = 7;
        const CURRENT_EPOCH: u64 = HINT_EPOCH + 1;

        let key = [0xA7; 32];
        let stable_peer = peer_id_from_byte(1);
        let departing_peer = peer_id_from_byte(2);
        let retained_peer = peer_id_from_byte(3);
        let new_peer = peer_id_from_byte(4);
        let old_group = HashSet::from([stable_peer, departing_peer, retained_peer]);
        let changed_group = HashSet::from([stable_peer, retained_peer, new_peer]);
        let mut proofs = RepairProofs::new();
        let (hinted_at, now) = mature_hint_times();

        assert!(proofs.record_replica_hint_sent_at(
            stable_peer,
            key,
            &old_group,
            HINT_EPOCH,
            hinted_at,
        ));
        assert!(proofs.record_replica_hint_sent_at(
            departing_peer,
            key,
            &old_group,
            HINT_EPOCH,
            hinted_at,
        ));

        assert!(
            proofs.has_mature_replica_hint(&stable_peer, &key, &changed_group, CURRENT_EPOCH, now),
            "stable peers should keep mature repair proofs across unrelated close-group churn"
        );
        assert!(
            !proofs.has_mature_replica_hint(
                &departing_peer,
                &key,
                &changed_group,
                CURRENT_EPOCH,
                now,
            ),
            "peers that left the close group should lose repair proofs"
        );
        assert!(
            !proofs.has_mature_replica_hint(&new_peer, &key, &changed_group, CURRENT_EPOCH, now),
            "new close-group peers need their own repair hint before auditing"
        );
    }

    #[test]
    fn repair_proofs_evicted_peer_reentry_requires_fresh_hint() {
        const FIRST_HINT_EPOCH: u64 = 7;
        const SECOND_HINT_EPOCH: u64 = FIRST_HINT_EPOCH + 1;
        const CURRENT_EPOCH: u64 = SECOND_HINT_EPOCH + 1;

        let key = [0xA3; 32];
        let returning_peer = peer_id_from_byte(1);
        let new_peer = peer_id_from_byte(4);
        let old_group = HashSet::from([returning_peer, peer_id_from_byte(2), peer_id_from_byte(3)]);
        let changed_group = HashSet::from([new_peer, peer_id_from_byte(2), peer_id_from_byte(3)]);
        let mut proofs = RepairProofs::new();
        let (hinted_at, now) = mature_hint_times();

        assert!(proofs.record_replica_hint_sent_at(
            returning_peer,
            key,
            &old_group,
            FIRST_HINT_EPOCH,
            hinted_at,
        ));

        assert!(
            !proofs.has_mature_replica_hint(
                &new_peer,
                &key,
                &changed_group,
                SECOND_HINT_EPOCH,
                now
            ),
            "new close-group peer should not inherit another peer's repair proof"
        );
        assert!(
            !proofs.has_mature_replica_hint(&returning_peer, &key, &old_group, CURRENT_EPOCH, now),
            "a peer that re-enters must receive a fresh repair hint"
        );

        assert!(proofs.record_replica_hint_sent_at(
            returning_peer,
            key,
            &old_group,
            SECOND_HINT_EPOCH,
            hinted_at,
        ));
        assert!(
            proofs.has_mature_replica_hint(&returning_peer, &key, &old_group, CURRENT_EPOCH, now),
            "fresh repair hint after re-entry should be eligible once mature"
        );
    }

    #[test]
    fn repair_proofs_remove_peer_requires_fresh_hint_after_reentry() {
        const FIRST_HINT_EPOCH: u64 = 7;
        const SECOND_HINT_EPOCH: u64 = FIRST_HINT_EPOCH + 1;
        const CURRENT_EPOCH: u64 = SECOND_HINT_EPOCH + 1;

        let key = [0xA6; 32];
        let peer = peer_id_from_byte(1);
        let close_peers = HashSet::from([peer, peer_id_from_byte(2), peer_id_from_byte(3)]);
        let mut proofs = RepairProofs::new();
        let (hinted_at, now) = mature_hint_times();

        assert!(proofs.record_replica_hint_sent_at(
            peer,
            key,
            &close_peers,
            FIRST_HINT_EPOCH,
            hinted_at,
        ));
        proofs.remove_peer(&peer);

        assert!(
            !proofs.has_mature_replica_hint(&peer, &key, &close_peers, CURRENT_EPOCH, now),
            "routing-table removal should clear proof even if peer re-enters same close group"
        );

        assert!(proofs.record_replica_hint_sent_at(
            peer,
            key,
            &close_peers,
            SECOND_HINT_EPOCH,
            hinted_at,
        ));
        assert!(
            proofs.has_mature_replica_hint(&peer, &key, &close_peers, CURRENT_EPOCH, now),
            "fresh hint after re-entry should become eligible after a later epoch"
        );
    }

    #[test]
    fn repair_proofs_remove_key_clears_all_peer_entries() {
        const HINT_EPOCH: u64 = 7;
        const CURRENT_EPOCH: u64 = HINT_EPOCH + 1;

        let key = [0xA4; 32];
        let peer = peer_id_from_byte(1);
        let close_peers = HashSet::from([peer]);
        let mut proofs = RepairProofs::new();
        let (hinted_at, now) = mature_hint_times();

        assert!(proofs.record_replica_hint_sent_at(peer, key, &close_peers, HINT_EPOCH, hinted_at,));
        proofs.remove_key(&key);

        assert!(
            !proofs.has_mature_replica_hint(&peer, &key, &close_peers, CURRENT_EPOCH, now),
            "deleted local key should not retain repair proof entries"
        );
    }

    // -- NeighborSyncState -------------------------------------------------

    #[test]
    fn neighbor_sync_empty_cycle_is_immediately_complete() {
        let state = NeighborSyncState::new_cycle(vec![]);
        assert!(
            state.is_cycle_complete(),
            "empty neighbor list means cycle is complete"
        );
    }

    #[test]
    fn neighbor_sync_new_cycle_not_complete() {
        let peers = vec![peer_id_from_byte(1), peer_id_from_byte(2)];
        let state = NeighborSyncState::new_cycle(peers);
        assert!(
            !state.is_cycle_complete(),
            "fresh cycle with peers should not be complete"
        );
    }

    #[test]
    fn neighbor_sync_cycle_completes_when_cursor_reaches_end() {
        let peers = vec![
            peer_id_from_byte(1),
            peer_id_from_byte(2),
            peer_id_from_byte(3),
        ];
        let mut state = NeighborSyncState::new_cycle(peers);

        // Simulate stepping through the cycle.
        state.cursor = 2;
        assert!(
            !state.is_cycle_complete(),
            "cursor at len-1 should not be complete"
        );

        state.cursor = 3;
        assert!(
            state.is_cycle_complete(),
            "cursor at len should be complete"
        );
    }

    #[test]
    fn neighbor_sync_cursor_past_end_is_still_complete() {
        let peers = vec![peer_id_from_byte(1)];
        let mut state = NeighborSyncState::new_cycle(peers);
        state.cursor = 5;
        assert!(
            state.is_cycle_complete(),
            "cursor past end should still report complete"
        );
    }

    #[test]
    fn neighbor_sync_priority_queue_blocks_cycle_completion() {
        let peer = peer_id_from_byte(2);
        let mut state = NeighborSyncState::new_cycle(Vec::new());

        assert!(state.is_cycle_complete());
        assert_eq!(state.queue_priority_peers([peer]), 1);
        assert!(
            !state.is_cycle_complete(),
            "pending priority peers must sync before the cycle completes"
        );
    }

    #[test]
    fn neighbor_sync_priority_queue_deduplicates_peers() {
        let peer = peer_id_from_byte(3);
        let mut state = NeighborSyncState::new_cycle(Vec::new());

        assert_eq!(state.queue_priority_peers([peer, peer]), 1);
        assert_eq!(state.priority_order.len(), 1);
    }

    #[test]
    fn neighbor_sync_has_priority_peers_tracks_queue_and_drain() {
        // The neighbor-sync loop drains the priority queue back-to-back and only
        // parks once `has_priority_peers` reports false. Draining removes each
        // queued peer (as `select_next_sync_peer` does via `remove_peer`), so the
        // signal must flip to false once every entrant is consumed — this is the
        // loop's termination guarantee.
        let first = peer_id_from_byte(6);
        let second = peer_id_from_byte(7);
        let mut state = NeighborSyncState::new_cycle(Vec::new());
        assert!(!state.has_priority_peers());

        assert_eq!(state.queue_priority_peers([first, second]), 2);
        assert!(state.has_priority_peers());

        assert!(state.remove_peer(&first));
        assert!(state.has_priority_peers(), "one entrant still pending");

        assert!(state.remove_peer(&second));
        assert!(
            !state.has_priority_peers(),
            "drained queue must let the loop park"
        );
    }

    #[test]
    fn neighbor_sync_remove_peer_clears_order_and_priority_queue() {
        let peer = peer_id_from_byte(4);
        let retained = peer_id_from_byte(5);
        let mut state = NeighborSyncState::new_cycle(vec![peer, retained]);
        assert_eq!(state.queue_priority_peers([peer]), 1);
        state.cursor = 1;

        assert!(state.remove_peer(&peer));

        assert!(!state.order.contains(&peer));
        assert!(!state.priority_order.contains(&peer));
        assert_eq!(state.order, vec![retained]);
        assert_eq!(state.cursor, 0);
    }

    #[test]
    fn neighbor_sync_retain_sync_peers_prunes_only_departed_peers() {
        let already_scanned = peer_id_from_byte(1);
        let stable_scanned = peer_id_from_byte(2);
        let departed_priority = peer_id_from_byte(3);
        let stable_unscanned = peer_id_from_byte(4);
        let stable_priority = peer_id_from_byte(5);
        let mut state = NeighborSyncState::new_cycle(vec![
            already_scanned,
            stable_scanned,
            departed_priority,
            stable_unscanned,
        ]);
        assert_eq!(
            state.queue_priority_peers([departed_priority, stable_priority]),
            2
        );
        state.cursor = 2;
        let close_peers = HashSet::from([stable_scanned, stable_unscanned, stable_priority]);

        let removed = state.retain_sync_peers(&close_peers);

        assert_eq!(removed, 3);
        assert_eq!(state.order, vec![stable_scanned, stable_unscanned]);
        assert_eq!(
            state.priority_order.iter().copied().collect::<Vec<_>>(),
            vec![stable_priority]
        );
        assert_eq!(
            state.cursor, 1,
            "stable peer scanned before churn must not be selected again"
        );
    }

    #[test]
    fn bootstrap_claim_history_prevents_second_grace_window() {
        let peer = peer_id_from_byte(9);
        let mut state = NeighborSyncState::new_cycle(vec![peer]);
        let first_seen = Instant::now();
        let grace = Duration::from_mins(1);

        assert_eq!(
            state.observe_bootstrap_claim(peer, first_seen, grace),
            BootstrapClaimObservation::WithinGrace { first_seen }
        );
        assert!(state.clear_active_bootstrap_claim(&peer));
        assert!(!state.bootstrap_claims.contains_key(&peer));
        assert!(state.bootstrap_claim_history.contains_key(&peer));

        assert_eq!(
            state.observe_bootstrap_claim(peer, first_seen + Duration::from_secs(1), grace),
            BootstrapClaimObservation::Repeated { first_seen }
        );
        assert!(
            !state.bootstrap_claims.contains_key(&peer),
            "repeated claims must not recreate an active grace window"
        );
        assert_eq!(
            state.observe_bootstrap_claim(peer, first_seen + Duration::from_secs(2), grace),
            BootstrapClaimObservation::Repeated { first_seen }
        );
    }

    #[test]
    fn bootstrap_claim_active_window_reports_past_grace() {
        let peer = peer_id_from_byte(10);
        let mut state = NeighborSyncState::new_cycle(vec![peer]);
        let first_seen = Instant::now();
        let grace = Duration::from_mins(1);

        let _ = state.observe_bootstrap_claim(peer, first_seen, grace);

        assert_eq!(
            state.observe_bootstrap_claim(peer, first_seen + grace + Duration::from_secs(1), grace),
            BootstrapClaimObservation::PastGrace { first_seen }
        );
    }

    // -- BootstrapState ----------------------------------------------------

    #[test]
    fn bootstrap_state_initial_not_drained() {
        // A freshly created state must NOT report drained — the bootstrap
        // sync task has not started yet (Invariant 19 race prevention).
        let state = BootstrapState::new();
        assert!(
            !state.is_drained(),
            "initial state must not be drained before bootstrap begins"
        );
    }

    #[test]
    fn bootstrap_state_pending_requests_block_drain() {
        let mut state = BootstrapState::new();
        state.pending_peer_requests = 3;
        assert!(
            !state.is_drained(),
            "pending peer requests should block drain"
        );
    }

    #[test]
    fn bootstrap_state_pending_keys_block_drain() {
        let mut state = BootstrapState::new();
        state.pending_keys.insert([42u8; 32]);
        assert!(!state.is_drained(), "pending keys should block drain");
    }

    #[test]
    fn bootstrap_state_explicit_drained_overrides() {
        let mut state = BootstrapState::new();
        state.pending_peer_requests = 5;
        state.pending_keys.insert([99u8; 32]);
        state.drained = true;
        assert!(
            state.is_drained(),
            "explicit drained flag should override pending counts"
        );
    }

    #[test]
    fn bootstrap_state_requires_explicit_drain() {
        let mut state = BootstrapState::new();
        state.pending_peer_requests = 2;
        state.pending_keys.insert([1u8; 32]);

        // Simulate completing work — but without explicit drain flag.
        state.pending_peer_requests = 0;
        state.pending_keys.clear();

        assert!(
            !state.is_drained(),
            "clearing counters alone must not drain — requires check_bootstrap_drained"
        );

        // Explicit drain (set by check_bootstrap_drained or mark_bootstrap_drained).
        state.drained = true;
        assert!(state.is_drained(), "explicit flag should drain");
    }

    #[test]
    fn bootstrap_state_default_matches_new() {
        let from_new = BootstrapState::new();
        let from_default = BootstrapState::default();

        assert_eq!(from_new.drained, from_default.drained);
        assert_eq!(
            from_new.pending_peer_requests,
            from_default.pending_peer_requests
        );
        assert_eq!(from_new.pending_keys, from_default.pending_keys);
    }

    // -- Scenario tests -------------------------------------------------------

    /// #13: Bootstrap not drained while `pending_keys` overlap with the
    /// pipeline. Keys must be removed from `pending_keys` for drain to occur.
    #[test]
    fn bootstrap_drain_requires_empty_pending_keys() {
        let key_a: XorName = [0xA0; 32];
        let key_b: XorName = [0xB0; 32];
        let key_c: XorName = [0xC0; 32];

        let mut state = BootstrapState::new();
        state.pending_peer_requests = 0; // requests already done
        state.pending_keys = std::iter::once(key_a)
            .chain(std::iter::once(key_b))
            .chain(std::iter::once(key_c))
            .collect();

        assert!(
            !state.is_drained(),
            "should NOT be drained while pending_keys still has entries"
        );

        // Simulate pipeline processing — remove one key at a time.
        state.pending_keys.remove(&key_a);
        assert!(!state.is_drained(), "still not drained with 2 pending keys");

        state.pending_keys.remove(&key_b);
        assert!(!state.is_drained(), "still not drained with 1 pending key");

        state.pending_keys.remove(&key_c);
        assert!(
            !state.is_drained(),
            "removing all keys is necessary but not sufficient — needs explicit drain"
        );

        // Simulate check_bootstrap_drained setting the flag.
        state.drained = true;
        assert!(state.is_drained(), "explicit drain flag should finalize");
    }

    /// Verify that the FSM terminal states are distinguishable and document
    /// which variants are logically terminal (no outgoing transitions).
    #[test]
    fn verification_state_terminal_variants() {
        let terminal_states = [
            VerificationState::QuorumAbandoned,
            VerificationState::FetchAbandoned,
            VerificationState::Stored,
            VerificationState::Idle,
        ];

        // All terminal states must be distinct from each other.
        for (i, a) in terminal_states.iter().enumerate() {
            for (j, b) in terminal_states.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        a, b,
                        "terminal states at indices {i} and {j} must be distinct"
                    );
                }
            }
        }

        // Terminal states must be distinct from all non-terminal states.
        let non_terminal_states = [
            VerificationState::OfferReceived,
            VerificationState::PendingVerify,
            VerificationState::QuorumVerified,
            VerificationState::PaidListVerified,
            VerificationState::QueuedForFetch,
            VerificationState::Fetching,
            VerificationState::FetchRetryable,
            VerificationState::QuorumFailed,
            VerificationState::QuorumInconclusive,
        ];

        for terminal in &terminal_states {
            for non_terminal in &non_terminal_states {
                assert_ne!(
                    terminal, non_terminal,
                    "terminal state {terminal:?} must not equal non-terminal state {non_terminal:?}"
                );
            }
        }
    }

    /// `has_repair_opportunity` requires BOTH a previous sync AND at least
    /// one subsequent cycle.
    #[test]
    fn repair_opportunity_requires_both_sync_and_cycle() {
        // last_sync = Some, cycles_since_sync = 0 → false (synced but no cycle yet)
        let synced_no_cycle = PeerSyncRecord {
            last_sync: Some(
                Instant::now()
                    .checked_sub(std::time::Duration::from_secs(2))
                    .unwrap_or_else(Instant::now),
            ),
            cycles_since_sync: 0,
        };
        assert!(
            !synced_no_cycle.has_repair_opportunity(),
            "synced with zero subsequent cycles should NOT have repair opportunity"
        );

        // last_sync = None, cycles_since_sync = 5 → false (never synced)
        let never_synced = PeerSyncRecord {
            last_sync: None,
            cycles_since_sync: 5,
        };
        assert!(
            !never_synced.has_repair_opportunity(),
            "never-synced peer should NOT have repair opportunity regardless of cycles"
        );

        // last_sync = Some, cycles_since_sync = 1 → true
        let ready = PeerSyncRecord {
            last_sync: Some(
                Instant::now()
                    .checked_sub(std::time::Duration::from_secs(5))
                    .unwrap_or_else(Instant::now),
            ),
            cycles_since_sync: 1,
        };
        assert!(
            ready.has_repair_opportunity(),
            "synced peer with >= 1 cycle SHOULD have repair opportunity"
        );
    }
}
