//! Scheduling and queue management (Section 12).
//!
//! Manages `PendingVerify`, `FetchQueue`, and `InFlightFetch` queues for the
//! replication pipeline. Each key progresses through at most one queue at a
//! time, with strict dedup across all three stages.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use crate::logging::debug;

use crate::ant_protocol::XorName;
use crate::replication::config::VERIFICATION_RETRY_BACKOFF_MAX;
use crate::replication::types::{
    FetchCandidate, FetchOrder, FetchPayload, VerificationEntry, VerificationState,
};
use saorsa_core::identity::PeerId;

/// Result of deferring a pending key to a later verification round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeferralOutcome {
    /// Consecutive unresolved rounds for this entry, counting this one. `1` is
    /// the entry's first failure, which is the one worth reporting.
    pub attempt: u32,
    /// Delay applied before this key is eligible for another round.
    pub retry_after: Duration,
}

/// Exponential backoff for an unresolved pending key.
///
/// `attempt` is 1-based, so the first deferral waits `base` and each subsequent
/// one doubles, saturating at [`VERIFICATION_RETRY_BACKOFF_MAX`]. The shift is
/// bounded before it is applied so a long-lived entry cannot overflow into a
/// short delay.
fn backoff_delay(base: Duration, attempt: u32) -> Duration {
    // Clamp the exponent before shifting: `1u32 << 32` is undefined behaviour
    // territory in release builds, and any base doubled 31 times has long since
    // saturated the cap anyway.
    let exponent = attempt.saturating_sub(1).min(31);
    base.saturating_mul(1u32 << exponent)
        .min(VERIFICATION_RETRY_BACKOFF_MAX)
        // Never retry faster than the caller asked for, even if a config sets a
        // base above the cap.
        .max(base)
}

/// Global hard upper bound on the number of keys held in `pending_verify`.
///
/// Without a bound, a peer in the local routing table can flood
/// `NeighborSyncRequest` messages (each capped only by
/// `MAX_REPLICATION_MESSAGE_SIZE` ≈ 10 MiB, i.e. ~320k 32-byte hints per
/// message) and grow this map without limit, exhausting node memory and
/// driving a self-amplifying storm of outbound verification requests.
///
/// `131_072` entries is far above any legitimate aggregate need while
/// bounding worst-case memory to a few tens of MiB (each `VerificationEntry`
/// is on the order of a few hundred bytes; its sub-collections are populated
/// only from close-group-sized verification evidence, never from attacker
/// hint volume).
///
/// The global cap is paired with elastic max-min sender accounting: one peer
/// may borrow otherwise-unused capacity for a large bootstrap snapshot, but a
/// later under-represented sender reclaims slots from an over-represented one.
/// Verification service is round-robin across capacity owners, so arrival
/// order cannot turn this memory circuit breaker into sender starvation.
pub const MAX_PENDING_VERIFY: usize = 131_072;

/// Hard upper bound on the number of keys held in `fetch_queue`.
///
/// `fetch_queue` is fed only by `enqueue_fetch`, which is reached **after** a
/// key passes quorum verification in `run_verification_cycle` — attacker junk
/// keys (no real holder) fail quorum and never reach this stage, so the
/// bounded-and-fair `pending_verify` upstream is the primary protection. This
/// global cap remains as a defence-in-depth memory backstop and is dropped
/// (consistent with the existing cross-queue-dedup no-op contract of
/// `enqueue_fetch`) when full.
pub const MAX_FETCH_QUEUE: usize = 131_072;

/// Maximum distinct hint sources retained per pending key.
///
/// [`MAX_PENDING_VERIFY`] bounds unique *keys*, not the peers remembered
/// against each one. Duplicate advertisements take the `AlreadyPresent` path,
/// which merges the advertiser into two per-key sets plus the reverse index at
/// no capacity cost — and re-advertising an already-pending key is the cheapest
/// path through admission, since `is_relevant` short-circuits on it without
/// even a routing-table lookup. Left unbounded, N routing-table peers
/// re-advertising a full queue costs `N * MAX_PENDING_VERIFY` associations
/// against a cap that only ever counted keys.
///
/// Sized at the close-group width: source diversity is only useful as fetch
/// candidates and corroboration weight, and both saturate well before this.
/// See [`ReplicationQueues::add_pending_verify`] for the retention policy that
/// decides *which* sources survive the cap.
pub const MAX_HINT_SOURCES_PER_KEY: usize = 8;

/// Outcome of [`ReplicationQueues::add_pending_verify`].
///
/// Distinguishes "the key is already being handled" from "the key was
/// silently dropped due to a queue capacity bound". Bootstrap drain
/// accounting and source-side retry logic MUST treat `CapacityRejected` as
/// outstanding work; treating it like a dedup hit was the silent-drop
/// regression introduced when the queues first became bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionResult {
    /// New entry inserted into `pending_verify`.
    Admitted,
    /// Key was already in some pipeline stage; the existing entry is left
    /// in place. No retry required.
    AlreadyPresent,
    /// Global capacity bound rejected the entry. The caller
    /// MUST treat this as work still to do (not as silently completed).
    CapacityRejected,
}

impl AdmissionResult {
    /// `true` only for [`AdmissionResult::Admitted`]. Preserves call sites
    /// that only want to know "did the insert happen".
    #[must_use]
    pub fn admitted(self) -> bool {
        matches!(self, Self::Admitted)
    }
}

/// An existing pending hint displaced to restore sender fairness.
///
/// Bootstrap accounting uses this to keep the displaced source's work
/// outstanding until that source re-advertises it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CapacityDisplacement {
    /// Key removed from `pending_verify`.
    pub(crate) key: XorName,
    /// Authenticated source whose borrowed capacity slot was reclaimed.
    pub(crate) owner: PeerId,
}

/// Lazy heap entry for choosing the least valuable reclaimable hint owned by
/// an over-represented sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EvictionOrder {
    key: XorName,
    source_count: usize,
    paid_only: bool,
    created_at: Instant,
}

impl Ord for EvictionOrder {
    fn cmp(&self, other: &Self) -> Ordering {
        // BinaryHeap pops the greatest item. Prefer singleton, paid-only,
        // newest entries for eviction, with a deterministic key tie-break.
        other
            .source_count
            .cmp(&self.source_count)
            .then_with(|| self.paid_only.cmp(&other.paid_only))
            .then_with(|| self.created_at.cmp(&other.created_at))
            .then_with(|| self.key.cmp(&other.key))
    }
}

impl PartialOrd for EvictionOrder {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ---------------------------------------------------------------------------
// In-flight entry
// ---------------------------------------------------------------------------

/// An in-flight fetch entry tracking an active download.
#[derive(Debug, Clone)]
pub struct InFlightEntry {
    /// The key being fetched.
    pub key: XorName,
    /// The peer we are currently fetching from.
    pub source: PeerId,
    /// When the fetch started.
    pub started_at: Instant,
    /// All verified sources for this key.
    pub all_sources: Vec<PeerId>,
    /// Sources already attempted (failed or in progress).
    pub tried: HashSet<PeerId>,
    /// Pending-verification entry to restore if all fetch sources fail.
    pub retry_verification: Option<VerificationEntry>,
}

// ---------------------------------------------------------------------------
// Central queue manager
// ---------------------------------------------------------------------------

/// Central queue manager for the replication pipeline.
///
/// Maintains three stages of the pipeline with global dedup:
/// 1. **`PendingVerify`** -- keys awaiting quorum verification.
/// 2. **`FetchQueue`** -- quorum-passed keys waiting for a fetch slot.
/// 3. **`InFlightFetch`** -- keys actively being downloaded.
///
/// A key promoted from `PendingVerify` to fetch keeps a reserved verification
/// slot until it either stores successfully or returns to `PendingVerify`.
/// That reservation prevents unrelated new hints from stealing the capacity
/// needed to retry verification after every fetch source fails.
pub struct ReplicationQueues {
    /// Keys awaiting quorum result (dedup by key).
    ///
    /// Capacity-bounded by [`MAX_PENDING_VERIFY`]. At capacity, max-min sender
    /// accounting reclaims borrowed entries before rejecting new work.
    pending_verify: HashMap<XorName, VerificationEntry>,
    /// Nearest-first priority order over the keys in `fetch_payloads`.
    ///
    /// Holds ordering data only: every entry has exactly one matching
    /// `fetch_payloads` entry, and vice versa. Splitting the mutable half of a
    /// queued fetch out into `fetch_payloads` keeps this heap's ordering
    /// immutable for as long as a key is queued, so a source merge never has
    /// to rebuild it.
    fetch_queue: BinaryHeap<FetchOrder>,
    /// The mutable half of each queued fetch, keyed for O(1) lookup.
    ///
    /// Doubles as the `fetch_queue` membership index (Rule 8 cross-queue
    /// dedup) and as the authoritative queue length.
    ///
    /// Capacity-bounded by [`MAX_FETCH_QUEUE`]: enqueues are dropped once
    /// full, preventing unbounded growth under a network hint flood.
    fetch_payloads: HashMap<XorName, FetchPayload>,
    /// Active downloads keyed by `XorName`.
    in_flight_fetch: HashMap<XorName, InFlightEntry>,
    /// Reverse index for removing a departed peer from every pending hint
    /// without scanning the entire pending table.
    pending_keys_by_source: HashMap<PeerId, HashSet<XorName>>,
    /// Capacity owner for every retry-capable key, retained while the key
    /// moves through pending, fetch-queued, and in-flight states.
    capacity_owner_by_key: HashMap<XorName, PeerId>,
    /// Pending keys charged to each authenticated source.
    pending_keys_by_owner: HashMap<PeerId, HashSet<XorName>>,
    /// Lazy per-owner victim heaps used when borrowed capacity is reclaimed.
    eviction_candidates_by_owner: HashMap<PeerId, BinaryHeap<EvictionOrder>>,
    /// Verified fetch retries restored to pending verification. These entries
    /// are not eligible for fairness eviction.
    protected_pending_keys: HashSet<XorName>,
    /// Last owner selected by the fair verification scheduler.
    last_served_owner: Option<PeerId>,
    /// Fairness evictions accumulated since the caller last drained them.
    capacity_displacements: Vec<CapacityDisplacement>,
    /// Owners proven unable to reclaim a slot at the current queue state.
    /// Cleared by every capacity-changing mutation, this avoids repeating the
    /// max-min calculation for every key in an oversized rejected suffix.
    fair_rejection_cache: HashSet<PeerId>,
    /// Pending-verification capacity slots reserved by retry-capable keys that
    /// have left `pending_verify` for `fetch_queue` / `in_flight_fetch`.
    retry_reserved_slots: usize,
    /// The same reservations, attributed to the capacity owner that holds them.
    ///
    /// A promoted key leaves `pending_keys_by_owner` but keeps its reservation
    /// against the global pool. Without this attribution the reservation is
    /// subtracted from everyone's share while being charged to no one, so an
    /// owner with many in-flight retries reads as under-loaded to
    /// [`Self::reclaim_borrowed_slot`] and wins a larger allocation than it has
    /// earned — a skew that grows with exactly how much work it already holds.
    retry_reserved_by_owner: HashMap<PeerId, usize>,
}

impl Default for ReplicationQueues {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplicationQueues {
    /// Create new empty queues.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending_verify: HashMap::new(),
            fetch_queue: BinaryHeap::new(),
            fetch_payloads: HashMap::new(),
            in_flight_fetch: HashMap::new(),
            pending_keys_by_source: HashMap::new(),
            capacity_owner_by_key: HashMap::new(),
            pending_keys_by_owner: HashMap::new(),
            eviction_candidates_by_owner: HashMap::new(),
            protected_pending_keys: HashSet::new(),
            last_served_owner: None,
            capacity_displacements: Vec::new(),
            fair_rejection_cache: HashSet::new(),
            retry_reserved_slots: 0,
            retry_reserved_by_owner: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // PendingVerify
    // -----------------------------------------------------------------------

    /// Add a key to pending verification if not already present in any queue.
    ///
    /// Returns an [`AdmissionResult`] distinguishing the three outcomes:
    /// * `Admitted` — newly inserted.
    /// * `AlreadyPresent` — Rule 8 cross-queue dedup. For a key still in
    ///   `pending_verify`, the new advertiser is merged into its source set.
    /// * `CapacityRejected` — the global bound was hit and no over-represented
    ///   sender had reclaimable borrowed work; the incoming work is
    ///   genuinely lost and the caller (e.g. bootstrap drain accounting,
    ///   source-side retry) MUST treat this as still-outstanding work, not as
    ///   "done". Without this distinction a bootstrap snapshot whose hints
    ///   are capacity-rejected would silently mark itself drained.
    pub fn add_pending_verify(
        &mut self,
        key: XorName,
        entry: VerificationEntry,
    ) -> AdmissionResult {
        if self.pending_verify.contains_key(&key) {
            // Read before the mutable borrow: the capacity owner must survive
            // any displacement, since `insert_pending_owned_unchecked` requires
            // it to remain a live hint source.
            let owner = self.capacity_owner_by_key.get(&key).copied();
            let Some(existing) = self.pending_verify.get_mut(&key) else {
                debug_assert!(false, "pending entry vanished between lookups");
                return AdmissionResult::AlreadyPresent;
            };
            let mut changed = false;

            // Replica claimants first. They are the only sources that assert
            // possession, so they are the ones worth a slot: a paid-only
            // advertiser adds corroboration weight but can never be fetched
            // from, and yields its place when the cap binds.
            for source in entry.replica_hint_sources.iter().copied() {
                if existing.replica_hint_sources.contains(&source) {
                    continue;
                }
                if existing.hint_sources.len() >= MAX_HINT_SOURCES_PER_KEY
                    && !Self::displace_paid_only_source(
                        existing,
                        &mut self.pending_keys_by_source,
                        &key,
                        owner,
                    )
                {
                    // Cap reached with nothing droppable: every slot is held by
                    // a replica claimant or the capacity owner.
                    break;
                }
                existing.replica_hint_sources.insert(source);
                existing.hint_sources.insert(source);
                self.pending_keys_by_source
                    .entry(source)
                    .or_default()
                    .insert(key);
                changed = true;
            }

            // Then paid-only advertisers, strictly while under the cap. Losing
            // one costs a unit of corroboration weight — never a fetch
            // candidate, and never the key itself.
            for source in entry.hint_sources {
                if existing.hint_sources.len() >= MAX_HINT_SOURCES_PER_KEY {
                    break;
                }
                if existing.hint_sources.insert(source) {
                    self.pending_keys_by_source
                        .entry(source)
                        .or_default()
                        .insert(key);
                    changed = true;
                }
            }

            // Any change to `hint_sources` invalidates the key's queued
            // eviction candidate, whose `source_count` snapshot is compared for
            // equality in `pop_reclaimable_victim`. Re-push it or the key
            // becomes permanently un-reclaimable.
            if changed {
                self.refresh_eviction_candidate(&key);
            }
            return AdmissionResult::AlreadyPresent;
        }
        // Merging a source touches only `FetchPayload`, which no ordering
        // reads, so the fetch heap is left completely untouched here.
        if let Some(payload) = self.fetch_payloads.get_mut(&key) {
            for source in &entry.replica_hint_sources {
                if !payload.sources.contains(source) {
                    payload.sources.push(*source);
                }
            }
            if let Some(retry) = &mut payload.retry_verification {
                retry
                    .replica_hint_sources
                    .extend(entry.replica_hint_sources);
                retry.hint_sources.extend(entry.hint_sources);
            }
            return AdmissionResult::AlreadyPresent;
        }
        if let Some(in_flight) = self.in_flight_fetch.get_mut(&key) {
            for source in &entry.replica_hint_sources {
                if !in_flight.all_sources.contains(source) {
                    in_flight.all_sources.push(*source);
                }
            }
            if let Some(retry) = &mut in_flight.retry_verification {
                retry
                    .replica_hint_sources
                    .extend(entry.replica_hint_sources);
                retry.hint_sources.extend(entry.hint_sources);
            }
            return AdmissionResult::AlreadyPresent;
        }
        let Some(owner) = self.least_loaded_source(&entry.hint_sources) else {
            debug_assert!(false, "pending hint admitted without a source");
            return AdmissionResult::CapacityRejected;
        };

        if self.pending_capacity_used() >= MAX_PENDING_VERIFY {
            if self.fair_rejection_cache.contains(&owner) {
                return AdmissionResult::CapacityRejected;
            }
            if let Some(displaced) = self.reclaim_borrowed_slot(owner) {
                self.insert_pending_owned_unchecked(key, entry, owner, false);
                self.capacity_displacements.push(displaced);
                return AdmissionResult::Admitted;
            }
            debug!(
                "pending_verify at capacity ({MAX_PENDING_VERIFY}); source {owner} has no fair \
                 reclaimable slot for key {}",
                hex::encode(key),
            );
            self.fair_rejection_cache.insert(owner);
            return AdmissionResult::CapacityRejected;
        }
        self.insert_pending_owned_unchecked(key, entry, owner, false);
        AdmissionResult::Admitted
    }

    /// Drain fairness displacements produced by recent admissions.
    ///
    /// Neighbor-sync admission calls this while it still holds the queue lock
    /// so bootstrap can attribute every displaced key to its former owner.
    pub(crate) fn take_capacity_displacements(&mut self) -> Vec<CapacityDisplacement> {
        std::mem::take(&mut self.capacity_displacements)
    }

    fn pending_capacity_used(&self) -> usize {
        self.pending_verify
            .len()
            .saturating_add(self.retry_reserved_slots)
    }

    fn pending_count_for_owner_internal(&self, owner: &PeerId) -> usize {
        self.pending_keys_by_owner
            .get(owner)
            .map_or(0, HashSet::len)
    }

    fn retry_reserved_for_owner(&self, owner: &PeerId) -> usize {
        self.retry_reserved_by_owner
            .get(owner)
            .copied()
            .unwrap_or(0)
    }

    /// Total pending capacity charged to `owner`: keys resident in
    /// `pending_verify` plus the slots its promoted keys still reserve.
    ///
    /// This is the per-owner counterpart of [`Self::pending_capacity_used`],
    /// and the two must stay in step: a reservation occupies a slot in the
    /// global cap, so it has to be charged to somebody's share or fair-share
    /// targets are computed against a pool that nobody is billed for.
    fn charged_count_for_owner(&self, owner: &PeerId) -> usize {
        self.pending_count_for_owner_internal(owner)
            .saturating_add(self.retry_reserved_for_owner(owner))
    }

    fn least_loaded_source(&self, sources: &HashSet<PeerId>) -> Option<PeerId> {
        sources.iter().copied().min_by(|a, b| {
            self.charged_count_for_owner(a)
                .cmp(&self.charged_count_for_owner(b))
                .then_with(|| a.cmp(b))
        })
    }

    fn reclaim_borrowed_slot(&mut self, incoming_owner: PeerId) -> Option<CapacityDisplacement> {
        // Allocate the FULL pool and charge reservations to their holders,
        // rather than deducting reservations off the top and billing no one.
        let mut demands = BTreeMap::new();
        for owner in self
            .pending_keys_by_owner
            .keys()
            .chain(self.retry_reserved_by_owner.keys())
        {
            demands.insert(*owner, self.charged_count_for_owner(owner));
        }
        *demands.entry(incoming_owner).or_default() += 1;

        let targets = max_min_allocations(&demands, MAX_PENDING_VERIFY);
        let incoming_count = self.charged_count_for_owner(&incoming_owner);
        if targets.get(&incoming_owner).copied().unwrap_or(0) <= incoming_count {
            return None;
        }

        // Only a resident key can actually be reclaimed — a reservation has no
        // entry to evict — so an owner over its target purely on reservations
        // is skipped rather than chased.
        let mut over_represented = self
            .pending_keys_by_owner
            .iter()
            .filter_map(|(owner, keys)| {
                if keys.is_empty() {
                    return None;
                }
                let target = targets.get(owner).copied().unwrap_or(0);
                let excess = self.charged_count_for_owner(owner).saturating_sub(target);
                (excess > 0).then_some((*owner, excess))
            })
            .collect::<Vec<_>>();
        over_represented.sort_unstable_by(|(owner_a, excess_a), (owner_b, excess_b)| {
            excess_b.cmp(excess_a).then_with(|| owner_a.cmp(owner_b))
        });

        for (owner, _) in over_represented {
            if let Some(key) = self.pop_reclaimable_victim(owner) {
                let removed = self.remove_pending(&key);
                debug_assert!(removed.is_some(), "fairness victim vanished before removal");
                return Some(CapacityDisplacement { key, owner });
            }
        }
        None
    }

    fn pop_reclaimable_victim(&mut self, owner: PeerId) -> Option<XorName> {
        loop {
            let candidate = self
                .eviction_candidates_by_owner
                .get_mut(&owner)
                .and_then(BinaryHeap::pop)?;
            let Some(entry) = self.pending_verify.get(&candidate.key) else {
                continue;
            };
            let valid = self.capacity_owner_by_key.get(&candidate.key) == Some(&owner)
                && !self.protected_pending_keys.contains(&candidate.key)
                && candidate.source_count == entry.hint_sources.len()
                && candidate.paid_only == entry.replica_hint_sources.is_empty()
                && candidate.created_at == entry.created_at;
            if valid {
                return Some(candidate.key);
            }
        }
    }

    fn refresh_eviction_candidate(&mut self, key: &XorName) {
        if self.protected_pending_keys.contains(key) {
            return;
        }
        let (Some(entry), Some(owner)) = (
            self.pending_verify.get(key),
            self.capacity_owner_by_key.get(key).copied(),
        ) else {
            return;
        };
        self.eviction_candidates_by_owner
            .entry(owner)
            .or_default()
            .push(EvictionOrder {
                key: *key,
                source_count: entry.hint_sources.len(),
                paid_only: entry.replica_hint_sources.is_empty(),
                created_at: entry.created_at,
            });

        let owner_len = self.pending_count_for_owner_internal(&owner);
        let heap_len = self
            .eviction_candidates_by_owner
            .get(&owner)
            .map_or(0, BinaryHeap::len);
        if heap_len > owner_len.saturating_mul(2).saturating_add(64) {
            self.rebuild_eviction_heap(owner);
        }
    }

    fn rebuild_eviction_heap(&mut self, owner: PeerId) {
        let candidates = self
            .pending_keys_by_owner
            .get(&owner)
            .into_iter()
            .flatten()
            .filter(|key| !self.protected_pending_keys.contains(*key))
            .filter_map(|key| {
                self.pending_verify.get(key).map(|entry| EvictionOrder {
                    key: *key,
                    source_count: entry.hint_sources.len(),
                    paid_only: entry.replica_hint_sources.is_empty(),
                    created_at: entry.created_at,
                })
            })
            .collect::<BinaryHeap<_>>();
        self.eviction_candidates_by_owner.insert(owner, candidates);
    }

    fn insert_pending_owned_unchecked(
        &mut self,
        key: XorName,
        entry: VerificationEntry,
        owner: PeerId,
        protected_retry: bool,
    ) {
        debug_assert!(
            !entry.hint_sources.is_empty(),
            "pending hint inserted without a live source"
        );
        debug_assert!(
            entry.replica_hint_sources.is_subset(&entry.hint_sources),
            "replica advertisers must be included in all hint sources"
        );
        debug_assert!(
            entry.hint_sources.contains(&owner),
            "capacity owner must be a live hint source"
        );
        for source in &entry.hint_sources {
            self.pending_keys_by_source
                .entry(*source)
                .or_default()
                .insert(key);
        }
        let replaced = self.pending_verify.insert(key, entry);
        debug_assert!(
            replaced.is_none(),
            "pending entry inserted twice for {}",
            hex::encode(key)
        );
        self.capacity_owner_by_key.insert(key, owner);
        self.fair_rejection_cache.clear();
        self.pending_keys_by_owner
            .entry(owner)
            .or_default()
            .insert(key);
        if protected_retry {
            self.protected_pending_keys.insert(key);
        } else {
            self.refresh_eviction_candidate(&key);
        }
    }

    /// Free one hint-source slot on `entry` by dropping a paid-only advertiser.
    ///
    /// Returns whether a slot was freed. Replica claimants are never chosen —
    /// they are the fetch candidates the set exists to hold — and neither is
    /// `protected_owner`, which must remain a live hint source for the capacity
    /// accounting in `insert_pending_owned_unchecked` to stay valid.
    ///
    /// The victim among eligible paid-only sources is arbitrary: they are
    /// interchangeable, each contributing one unit of corroboration weight and
    /// nothing else.
    fn displace_paid_only_source(
        entry: &mut VerificationEntry,
        keys_by_source: &mut HashMap<PeerId, HashSet<XorName>>,
        key: &XorName,
        protected_owner: Option<PeerId>,
    ) -> bool {
        let victim = entry.hint_sources.iter().copied().find(|source| {
            !entry.replica_hint_sources.contains(source) && protected_owner != Some(*source)
        });
        let Some(victim) = victim else {
            return false;
        };
        entry.hint_sources.remove(&victim);
        if let Some(keys) = keys_by_source.get_mut(&victim) {
            keys.remove(key);
            if keys.is_empty() {
                keys_by_source.remove(&victim);
            }
        }
        true
    }

    /// Reserve a pending slot for `key`, charged to its capacity owner.
    ///
    /// Must be called while `capacity_owner_by_key` still holds `key`, which is
    /// why `promote_pending_to_fetch` takes the pending entry with
    /// `forget_capacity_owner: false`.
    fn reserve_retry_slot(&mut self, key: &XorName) {
        self.retry_reserved_slots = self.retry_reserved_slots.saturating_add(1);
        if let Some(owner) = self.capacity_owner_by_key.get(key).copied() {
            *self.retry_reserved_by_owner.entry(owner).or_default() += 1;
        }
        self.fair_rejection_cache.clear();
    }

    /// Release `key`'s reserved pending slot.
    ///
    /// Call before dropping `key` from `capacity_owner_by_key`, or the
    /// per-owner charge is stranded.
    fn release_retry_slot(&mut self, key: &XorName) {
        self.retry_reserved_slots = self.retry_reserved_slots.saturating_sub(1);
        if let Some(owner) = self.capacity_owner_by_key.get(key).copied() {
            if let Some(count) = self.retry_reserved_by_owner.get_mut(&owner) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.retry_reserved_by_owner.remove(&owner);
                }
            }
        }
        self.fair_rejection_cache.clear();
    }

    fn release_retry_slot_for_entry(&mut self, entry: &InFlightEntry) {
        if entry.retry_verification.is_some() {
            self.release_retry_slot(&entry.key);
        }
    }

    fn release_retry_slot_for_candidate(&mut self, candidate: &FetchCandidate) {
        if candidate.retry_verification.is_some() {
            self.release_retry_slot(&candidate.key);
        }
    }

    /// Test-only: number of live verification retry-slot reservations, so
    /// tests can assert a terminal fetch outcome released its reservation.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn retry_reserved_slot_count(&self) -> usize {
        self.retry_reserved_slots
    }

    /// Get a reference to a pending verification entry.
    #[must_use]
    pub fn get_pending(&self, key: &XorName) -> Option<&VerificationEntry> {
        self.pending_verify.get(key)
    }

    /// Advance a pending entry's verification `state`, reporting whether the
    /// key was found.
    ///
    /// Narrow mutation API used by the verification state machine.
    pub fn set_pending_state(&mut self, key: &XorName, state: VerificationState) -> bool {
        let Some(entry) = self.pending_verify.get_mut(key) else {
            return false;
        };
        entry.state = state;
        true
    }

    /// Remove a key from pending verification.
    pub fn remove_pending(&mut self, key: &XorName) -> Option<VerificationEntry> {
        self.take_pending(key, true)
    }

    fn take_pending(
        &mut self,
        key: &XorName,
        forget_capacity_owner: bool,
    ) -> Option<VerificationEntry> {
        let removed = self.pending_verify.remove(key);
        if let Some(entry) = &removed {
            self.fair_rejection_cache.clear();
            self.remove_key_from_source_index(key, &entry.hint_sources);
            if let Some(owner) = self.capacity_owner_by_key.get(key).copied() {
                self.remove_key_from_owner_index(key, &owner);
            }
            self.protected_pending_keys.remove(key);
            if forget_capacity_owner {
                self.capacity_owner_by_key.remove(key);
            }
        }
        removed
    }

    fn remove_key_from_source_index(&mut self, key: &XorName, sources: &HashSet<PeerId>) {
        for source in sources {
            if let Some(keys) = self.pending_keys_by_source.get_mut(source) {
                keys.remove(key);
                if keys.is_empty() {
                    self.pending_keys_by_source.remove(source);
                }
            }
        }
    }

    fn remove_key_from_owner_index(&mut self, key: &XorName, owner: &PeerId) {
        if let Some(keys) = self.pending_keys_by_owner.get_mut(owner) {
            keys.remove(key);
            if keys.is_empty() {
                self.pending_keys_by_owner.remove(owner);
                self.eviction_candidates_by_owner.remove(owner);
            }
        }
    }

    /// Collect all pending verification keys (for batch processing).
    #[must_use]
    pub fn pending_keys(&self) -> Vec<XorName> {
        self.pending_verify.keys().copied().collect()
    }

    /// Collect pending verification keys whose retry delay has elapsed.
    #[must_use]
    pub fn ready_pending_keys(&self, now: Instant) -> Vec<XorName> {
        let mut ready = self
            .pending_verify
            .iter()
            .filter_map(|(key, entry)| (entry.next_verify_at <= now).then_some(*key))
            .collect::<Vec<_>>();
        ready.sort_unstable_by(|a, b| {
            let entry_a = &self.pending_verify[a];
            let entry_b = &self.pending_verify[b];
            entry_b
                .hint_sources
                .len()
                .cmp(&entry_a.hint_sources.len())
                .then_with(|| entry_a.created_at.cmp(&entry_b.created_at))
                .then_with(|| a.cmp(b))
        });
        ready
    }

    /// Select a bounded, sender-fair set of ready verification keys.
    ///
    /// Owners are served round-robin with persistent rotation between cycles;
    /// unused service is immediately redistributed. Within an owner's share,
    /// protected retries and corroborated/older hints retain priority.
    pub fn select_ready_pending_keys(&mut self, now: Instant, limit: usize) -> Vec<XorName> {
        if limit == 0 {
            return Vec::new();
        }

        let mut grouped = BTreeMap::<PeerId, Vec<XorName>>::new();
        for (key, entry) in &self.pending_verify {
            if entry.next_verify_at > now {
                continue;
            }
            let Some(owner) = self.capacity_owner_by_key.get(key).copied() else {
                debug_assert!(false, "pending key has no capacity owner");
                continue;
            };
            grouped.entry(owner).or_default().push(*key);
        }

        for keys in grouped.values_mut() {
            keys.sort_unstable_by(|a, b| {
                let entry_a = &self.pending_verify[a];
                let entry_b = &self.pending_verify[b];
                self.protected_pending_keys
                    .contains(b)
                    .cmp(&self.protected_pending_keys.contains(a))
                    .then_with(|| entry_b.hint_sources.len().cmp(&entry_a.hint_sources.len()))
                    .then_with(|| entry_a.created_at.cmp(&entry_b.created_at))
                    .then_with(|| a.cmp(b))
            });
        }

        let mut owners = grouped.keys().copied().collect::<Vec<_>>();
        if owners.is_empty() {
            return Vec::new();
        }
        if let Some(last) = self.last_served_owner {
            let start = owners.iter().position(|owner| *owner > last).unwrap_or(0);
            owners.rotate_left(start);
        }

        let mut queues = grouped
            .into_iter()
            .map(|(owner, keys)| (owner, VecDeque::from(keys)))
            .collect::<HashMap<_, _>>();
        let mut active = VecDeque::from(owners);
        let mut selected = Vec::with_capacity(limit.min(self.pending_verify.len()));
        let mut last_selected = None;

        while selected.len() < limit {
            let Some(owner) = active.pop_front() else {
                break;
            };
            let Some(owner_queue) = queues.get_mut(&owner) else {
                continue;
            };
            let Some(key) = owner_queue.pop_front() else {
                continue;
            };
            selected.push(key);
            last_selected = Some(owner);
            if !owner_queue.is_empty() {
                active.push_back(owner);
            }
        }

        if let Some(owner) = last_selected {
            self.last_served_owner = Some(owner);
        }
        selected
    }

    /// Remove a departed routing-table peer from every pending hint it
    /// advertised. Entries with no remaining live advertisers are dropped.
    ///
    /// Returns keys that became orphaned so bootstrap accounting can retire
    /// them and re-check its drain transition.
    pub fn remove_hint_source(&mut self, source: &PeerId) -> Vec<XorName> {
        let keys = self
            .pending_keys_by_source
            .remove(source)
            .unwrap_or_default();
        let mut orphaned = Vec::new();

        for key in keys {
            let remaining_sources = if let Some(entry) = self.pending_verify.get_mut(&key) {
                entry.hint_sources.remove(source);
                entry.replica_hint_sources.remove(source);
                Some(entry.hint_sources.clone())
            } else {
                None
            };

            let Some(remaining_sources) = remaining_sources else {
                continue;
            };
            if remaining_sources.is_empty() {
                self.remove_pending(&key);
                orphaned.push(key);
                continue;
            }

            if self.capacity_owner_by_key.get(&key) == Some(source) {
                if let Some(new_owner) = self.least_loaded_source(&remaining_sources) {
                    self.transfer_pending_owner(key, *source, new_owner);
                }
            } else {
                self.refresh_eviction_candidate(&key);
            }
        }

        let mut retry_owner_updates = Vec::new();
        let mut orphaned_fetch_keys = HashSet::new();
        for (key, payload) in &mut self.fetch_payloads {
            payload.sources.retain(|peer| peer != source);
            if let Some(verification) = &mut payload.retry_verification {
                if verification.hint_sources.remove(source) {
                    verification.replica_hint_sources.remove(source);
                    if verification.hint_sources.is_empty() {
                        payload.retry_verification = None;
                        retry_owner_updates.push((*key, None));
                    } else if self.capacity_owner_by_key.get(key) == Some(source) {
                        retry_owner_updates
                            .push((*key, verification.hint_sources.iter().copied().min()));
                    }
                }
            }
            if payload.sources.is_empty() && payload.retry_verification.is_none() {
                orphaned_fetch_keys.insert(*key);
            }
        }
        // Only an orphaned key changes heap *membership*; the source edits
        // above cannot, so the heap is rebuilt at most once per departed peer
        // and not at all when the peer left nothing orphaned.
        if !orphaned_fetch_keys.is_empty() {
            self.fetch_payloads
                .retain(|key, _| !orphaned_fetch_keys.contains(key));
            self.fetch_queue
                .retain(|order| !orphaned_fetch_keys.contains(&order.key));
            orphaned.extend(orphaned_fetch_keys);
        }

        for entry in self.in_flight_fetch.values_mut() {
            entry.all_sources.retain(|peer| peer != source);
            if let Some(verification) = &mut entry.retry_verification {
                if verification.hint_sources.remove(source) {
                    verification.replica_hint_sources.remove(source);
                    if verification.hint_sources.is_empty() {
                        entry.retry_verification = None;
                        retry_owner_updates.push((entry.key, None));
                    } else if self.capacity_owner_by_key.get(&entry.key) == Some(source) {
                        retry_owner_updates
                            .push((entry.key, verification.hint_sources.iter().copied().min()));
                    }
                }
            }
        }

        // Every key here holds a retry reservation charged to its current
        // capacity owner, so each release must happen while
        // `capacity_owner_by_key` still names that owner.
        for (key, owner) in retry_owner_updates {
            self.release_retry_slot(&key);
            if let Some(new_owner) = owner {
                // The retry survives but changes hands: re-charge it to the new
                // owner, or it stays billed to a peer that has just departed
                // and is never recovered.
                self.capacity_owner_by_key.insert(key, new_owner);
                self.reserve_retry_slot(&key);
            } else {
                // The retry itself is gone with its last hint source.
                self.capacity_owner_by_key.remove(&key);
            }
        }

        orphaned
    }

    fn transfer_pending_owner(&mut self, key: XorName, old_owner: PeerId, new_owner: PeerId) {
        if old_owner == new_owner {
            self.refresh_eviction_candidate(&key);
            return;
        }
        self.fair_rejection_cache.clear();
        self.remove_key_from_owner_index(&key, &old_owner);
        self.capacity_owner_by_key.insert(key, new_owner);
        self.pending_keys_by_owner
            .entry(new_owner)
            .or_default()
            .insert(key);
        self.refresh_eviction_candidate(&key);
    }

    /// Defer a pending key before its next verification attempt, by a flat
    /// delay.
    ///
    /// For deferrals that are *not* a failed round: the caller chose not to ask
    /// (a full disk, say), so nothing was learned about the key and the
    /// unresolved-round count must not move.
    pub fn defer_pending(&mut self, key: &XorName, retry_after: Duration) -> bool {
        let Some(entry) = self.pending_verify.get_mut(key) else {
            return false;
        };
        entry.next_verify_at = Instant::now() + retry_after;
        true
    }

    /// Defer a pending key whose verification round left it unresolved.
    ///
    /// `base_retry_after` is the delay for the entry's *first* such deferral.
    /// Each consecutive one doubles it, capped at
    /// [`VERIFICATION_RETRY_BACKOFF_MAX`]. A key that keeps failing is failing
    /// for a reason a faster retry cannot change, so the cost of asking decays
    /// rather than being paid in full every 15 seconds.
    ///
    /// Returns `None` if the key is not pending, otherwise the resulting
    /// [`DeferralOutcome`], whose `attempt` is 1 on this entry's first
    /// unresolved round — the one worth reporting.
    pub fn defer_unresolved(
        &mut self,
        key: &XorName,
        base_retry_after: Duration,
    ) -> Option<DeferralOutcome> {
        let entry = self.pending_verify.get_mut(key)?;
        entry.unresolved_retries = entry.unresolved_retries.saturating_add(1);
        let attempt = entry.unresolved_retries;
        let retry_after = backoff_delay(base_retry_after, attempt);
        entry.next_verify_at = Instant::now() + retry_after;
        Some(DeferralOutcome {
            attempt,
            retry_after,
        })
    }

    /// Claim this entry's single no-holder warning.
    ///
    /// Returns `true` the first time it is called for a given entry and `false`
    /// after, so the caller can warn once and drop to `debug` thereafter.
    ///
    /// Kept separate from [`Self::defer_unresolved`] on purpose. A round can
    /// legitimately advance the failure count without producing a no-holder
    /// result — an inconclusive quorum does exactly that — and if the two
    /// shared state, such a round would consume the warning before the
    /// condition it describes had ever been observed.
    pub fn claim_no_holder_report(&mut self, key: &XorName) -> bool {
        let Some(entry) = self.pending_verify.get_mut(key) else {
            return false;
        };
        !std::mem::replace(&mut entry.no_holder_reported, true)
    }

    /// Clear an entry's unresolved history after a round that found a holder.
    ///
    /// The round succeeded even if the key could not move on — a full fetch
    /// queue leaves it pending — so it must not inherit the earlier backoff, and
    /// a later relapse deserves a fresh warning. Returns whether an entry was
    /// present to clear.
    pub fn clear_unresolved(&mut self, key: &XorName) -> bool {
        let Some(entry) = self.pending_verify.get_mut(key) else {
            return false;
        };
        entry.unresolved_retries = 0;
        entry.no_holder_reported = false;
        true
    }

    /// Number of keys in pending verification.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending_verify.len()
    }

    /// Number of pending entries currently charged to one capacity owner.
    /// Useful for fairness observability and invariant tests.
    #[must_use]
    pub fn pending_count_for_owner(&self, owner: &PeerId) -> usize {
        self.pending_count_for_owner_internal(owner)
    }

    // -----------------------------------------------------------------------
    // FetchQueue
    // -----------------------------------------------------------------------

    /// Enqueue a key for fetch with its distance and verified sources.
    ///
    /// Returns `true` if the candidate was enqueued, `false` if it was
    /// already present in any pipeline stage (Rule 8: cross-queue dedup) or
    /// the `fetch_queue` is at [`MAX_FETCH_QUEUE`].
    ///
    /// Callers that have removed the key from `pending_verify` immediately
    /// before this call should prefer [`promote_pending_to_fetch`](Self::promote_pending_to_fetch),
    /// which performs the move atomically and leaves the pending entry in
    /// place when the fetch queue is full (so verified work is retried on
    /// the next cycle instead of being silently lost).
    pub fn enqueue_fetch(&mut self, key: XorName, distance: XorName, sources: Vec<PeerId>) -> bool {
        self.enqueue_fetch_with_retry(key, distance, sources, None)
    }

    fn enqueue_fetch_with_retry(
        &mut self,
        key: XorName,
        distance: XorName,
        sources: Vec<PeerId>,
        retry_verification: Option<VerificationEntry>,
    ) -> bool {
        if self.pending_verify.contains_key(&key)
            || self.fetch_payloads.contains_key(&key)
            || self.in_flight_fetch.contains_key(&key)
        {
            return false;
        }
        if self.fetch_payloads.len() >= MAX_FETCH_QUEUE {
            debug!(
                "fetch_queue at capacity ({MAX_FETCH_QUEUE}); dropping new key {}",
                hex::encode(key)
            );
            return false;
        }
        self.fetch_payloads.insert(
            key,
            FetchPayload {
                sources,
                retry_verification,
            },
        );
        self.fetch_queue.push(FetchOrder { key, distance });
        true
    }

    /// Atomically promote a key from `pending_verify` to `fetch_queue`.
    ///
    /// Checks `fetch_queue` capacity FIRST, then removes the pending entry
    /// and enqueues the fetch candidate. If `fetch_queue` is full, the
    /// pending entry is **left in place** so the next verification cycle
    /// can retry — preventing the silent-drop regression where a verified
    /// key removed from `pending_verify` could be dropped by a full fetch
    /// queue and lost from every stage.
    ///
    /// Returns `true` on successful promotion, `false` when the fetch queue
    /// is at capacity (pending entry preserved).
    pub fn promote_pending_to_fetch(
        &mut self,
        key: XorName,
        distance: XorName,
        sources: Vec<PeerId>,
    ) -> bool {
        if self.fetch_payloads.len() >= MAX_FETCH_QUEUE {
            debug!(
                "fetch_queue at capacity ({MAX_FETCH_QUEUE}); leaving {} pending \
                 for retry next cycle",
                hex::encode(key)
            );
            return false;
        }
        // Capacity confirmed; safe to release the pending slot and enqueue.
        let retry_verification = self.take_pending(&key, false);
        let reserved_retry = retry_verification.is_some();
        if reserved_retry {
            self.reserve_retry_slot(&key);
        }
        // enqueue_fetch returns false only on capacity or already-queued; the
        // capacity check above and the just-removed pending state make this
        // succeed. If a concurrent path put the key into fetch_queue/in_flight
        // between, dropping the duplicate is fine.
        let enqueued = self.enqueue_fetch_with_retry(key, distance, sources, retry_verification);
        if !enqueued && reserved_retry {
            self.release_retry_slot(&key);
            self.capacity_owner_by_key.remove(&key);
        }
        enqueued
    }

    /// Dequeue the nearest fetch candidate.
    ///
    /// Returns `None` when the queue is empty.  Silently skips candidates
    /// that are somehow already in-flight.  Concurrency is enforced by the
    /// fetch worker, not by this method.
    ///
    /// A returned candidate may carry a live verification retry-slot
    /// reservation. Callers must consume it with
    /// [`Self::start_dequeued_fetch`], [`Self::discard_fetch_candidate`], or
    /// [`Self::requeue_candidate_for_verification`] so that reservation is
    /// either transferred, released, or restored to `pending_verify`.
    pub fn dequeue_fetch(&mut self) -> Option<FetchCandidate> {
        while let Some(order) = self.fetch_queue.pop() {
            let Some(payload) = self.fetch_payloads.remove(&order.key) else {
                debug_assert!(
                    false,
                    "fetch order without payload for {}",
                    hex::encode(order.key)
                );
                continue;
            };
            let candidate = FetchCandidate {
                key: order.key,
                distance: order.distance,
                sources: payload.sources,
                retry_verification: payload.retry_verification,
            };
            if !self.in_flight_fetch.contains_key(&candidate.key) {
                return Some(candidate);
            }
            self.release_retry_slot_for_candidate(&candidate);
        }
        None
    }

    /// Number of keys waiting in the fetch queue.
    #[must_use]
    pub fn fetch_queue_count(&self) -> usize {
        self.fetch_payloads.len()
    }

    // -----------------------------------------------------------------------
    // InFlightFetch
    // -----------------------------------------------------------------------

    /// Mark a key as in-flight (actively being fetched from `source`).
    ///
    /// Candidates returned by [`Self::dequeue_fetch`] MUST be consumed by a
    /// by-value dequeued-candidate method instead. They may carry a live
    /// verification retry-slot reservation; [`Self::start_dequeued_fetch`]
    /// transfers that reservation into the in-flight entry.
    pub fn start_fetch(&mut self, key: XorName, source: PeerId, all_sources: Vec<PeerId>) {
        self.start_fetch_with_retry(key, source, all_sources, None);
    }

    /// Mark a key as in-flight and retain verification retry metadata.
    ///
    /// This is for direct starts where the caller already owns any retry
    /// reservation paired with `retry_verification`. Candidates obtained from
    /// [`Self::dequeue_fetch`] MUST be consumed intact via a by-value
    /// dequeued-candidate method, otherwise their reserved verification
    /// capacity can be orphaned.
    pub fn start_fetch_with_retry(
        &mut self,
        key: XorName,
        source: PeerId,
        all_sources: Vec<PeerId>,
        retry_verification: Option<VerificationEntry>,
    ) {
        let mut tried = HashSet::new();
        tried.insert(source);
        let replaced = self.in_flight_fetch.insert(
            key,
            InFlightEntry {
                key,
                source,
                started_at: Instant::now(),
                all_sources,
                tried,
                retry_verification,
            },
        );
        if let Some(entry) = replaced {
            self.release_retry_slot_for_entry(&entry);
        }
    }

    /// Consume a dequeued fetch candidate and transfer its retry reservation
    /// into the in-flight entry.
    pub fn start_dequeued_fetch(&mut self, candidate: FetchCandidate, source: PeerId) {
        let FetchCandidate {
            key,
            sources,
            retry_verification,
            ..
        } = candidate;
        self.start_fetch_with_retry(key, source, sources, retry_verification);
    }

    /// Mark a fetch as completed (success or permanent failure).
    pub fn complete_fetch(&mut self, key: &XorName) -> Option<InFlightEntry> {
        let removed = self.in_flight_fetch.remove(key);
        if let Some(entry) = &removed {
            self.release_retry_slot_for_entry(entry);
            self.capacity_owner_by_key.remove(key);
        }
        removed
    }

    /// Drop a dequeued fetch candidate without starting it.
    pub fn discard_fetch_candidate(&mut self, candidate: FetchCandidate) {
        let FetchCandidate {
            key,
            retry_verification,
            ..
        } = candidate;
        if retry_verification.is_some() {
            self.release_retry_slot(&key);
            self.capacity_owner_by_key.remove(&key);
        }
    }

    /// Mark the current fetch attempt as failed and try the next untried source.
    ///
    /// Returns the next source peer if one is available, or `None` if all
    /// sources have been exhausted.
    pub fn retry_fetch(&mut self, key: &XorName) -> Option<PeerId> {
        let entry = self.in_flight_fetch.get_mut(key)?;
        entry.tried.insert(entry.source);

        let next = entry
            .all_sources
            .iter()
            .find(|p| !entry.tried.contains(p))
            .copied();

        if let Some(next_peer) = next {
            entry.source = next_peer;
            entry.tried.insert(next_peer);
            Some(next_peer)
        } else {
            None
        }
    }

    /// Consume a dequeued candidate and restore its verification entry for a
    /// later retry when retry metadata exists.
    pub fn requeue_candidate_for_verification(
        &mut self,
        candidate: FetchCandidate,
        retry_after: Duration,
    ) -> bool {
        let FetchCandidate {
            key,
            retry_verification,
            ..
        } = candidate;
        let Some(mut verification) = retry_verification else {
            return false;
        };
        verification.state = VerificationState::PendingVerify;
        verification.verified_sources.clear();
        verification.tried_sources.clear();
        verification.next_verify_at = Instant::now() + retry_after;

        let owner = self
            .capacity_owner_by_key
            .get(&key)
            .copied()
            .or_else(|| self.least_loaded_source(&verification.hint_sources));
        let Some(owner) = owner else {
            self.release_retry_slot(&key);
            return false;
        };
        // Release before re-inserting: the reservation is charged to the owner
        // recorded now, which `insert_pending_owned_unchecked` may replace.
        self.release_retry_slot(&key);
        self.insert_pending_owned_unchecked(key, verification, owner, true);
        true
    }

    /// Complete an exhausted fetch and restore its verification entry for a
    /// later retry when retry metadata exists.
    pub fn requeue_fetch_for_verification(&mut self, key: &XorName, retry_after: Duration) -> bool {
        let Some(mut entry) = self.in_flight_fetch.remove(key) else {
            return false;
        };
        let Some(mut verification) = entry.retry_verification.take() else {
            self.capacity_owner_by_key.remove(key);
            return false;
        };
        verification.state = VerificationState::PendingVerify;
        verification.verified_sources.clear();
        verification.tried_sources.clear();
        verification.next_verify_at = Instant::now() + retry_after;

        let owner = self
            .capacity_owner_by_key
            .get(key)
            .copied()
            .or_else(|| self.least_loaded_source(&verification.hint_sources));
        let Some(owner) = owner else {
            self.release_retry_slot(key);
            return false;
        };
        // Release before re-inserting: the reservation is charged to the owner
        // recorded now, which `insert_pending_owned_unchecked` may replace.
        self.release_retry_slot(key);
        self.insert_pending_owned_unchecked(*key, verification, owner, true);
        true
    }

    /// Number of in-flight fetches.
    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.in_flight_fetch.len()
    }

    // -----------------------------------------------------------------------
    // Cross-queue queries
    // -----------------------------------------------------------------------

    /// Check if a key is present in any pipeline stage.
    #[must_use]
    pub fn contains_key(&self, key: &XorName) -> bool {
        self.pending_verify.contains_key(key)
            || self.fetch_payloads.contains_key(key)
            || self.in_flight_fetch.contains_key(key)
    }

    /// Check if all bootstrap-related work is done.
    ///
    /// Returns `true` when none of the given bootstrap keys remain in any queue.
    #[must_use]
    pub fn is_bootstrap_work_empty(&self, bootstrap_keys: &HashSet<XorName>) -> bool {
        !bootstrap_keys.iter().any(|k| self.contains_key(k))
    }

    /// Evict stale pending-verification entries older than `max_age`.
    pub fn evict_stale(&mut self, max_age: Duration) -> Vec<XorName> {
        let now = Instant::now();
        let evicted_keys = self
            .pending_verify
            .iter()
            .filter_map(|(key, entry)| {
                (now.duration_since(entry.created_at) >= max_age).then_some(*key)
            })
            .collect::<Vec<_>>();

        for key in &evicted_keys {
            self.remove_pending(key);
        }

        if !evicted_keys.is_empty() {
            debug!(
                "Evicted {} stale pending-verification entries",
                evicted_keys.len()
            );
        }

        evicted_keys
    }
}

/// Integer max-min allocation with deterministic remainder distribution.
///
/// Small demands are satisfied in full. Remaining capacity is divided evenly
/// between saturated senders, so unused capacity is automatically borrowable.
fn max_min_allocations(
    demands: &BTreeMap<PeerId, usize>,
    capacity: usize,
) -> BTreeMap<PeerId, usize> {
    if demands.values().copied().sum::<usize>() <= capacity {
        return demands.clone();
    }

    let mut by_demand = demands
        .iter()
        .map(|(owner, demand)| (*owner, *demand))
        .collect::<Vec<_>>();
    by_demand.sort_unstable_by(|(owner_a, demand_a), (owner_b, demand_b)| {
        demand_a.cmp(demand_b).then_with(|| owner_a.cmp(owner_b))
    });

    let mut allocations = BTreeMap::new();
    let mut remaining_capacity = capacity;
    let mut index = 0usize;

    while index < by_demand.len() {
        let remaining_senders = by_demand.len() - index;
        let even_share = remaining_capacity / remaining_senders;
        let (owner, demand) = by_demand[index];
        if demand <= even_share {
            allocations.insert(owner, demand);
            remaining_capacity = remaining_capacity.saturating_sub(demand);
            index += 1;
            continue;
        }

        let base = even_share;
        let remainder = remaining_capacity % remaining_senders;
        let mut saturated = by_demand[index..]
            .iter()
            .map(|(owner, _)| *owner)
            .collect::<Vec<_>>();
        saturated.sort_unstable();
        for (position, owner) in saturated.into_iter().enumerate() {
            allocations.insert(owner, base + usize::from(position < remainder));
        }
        break;
    }

    allocations
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::replication::config::CAPACITY_BLOCKED_RETRY;

    /// Build a `PeerId` from a single byte (zero-padded to 32 bytes).
    fn peer_id_from_byte(b: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        PeerId::from_bytes(bytes)
    }

    /// Build an `XorName` from a single byte (repeated to 32 bytes).
    fn xor_name_from_byte(b: u8) -> XorName {
        [b; 32]
    }

    fn xor_name_from_u32(value: u32) -> XorName {
        let mut name = [0u8; 32];
        name[..4].copy_from_slice(&value.to_le_bytes());
        name
    }

    /// Create a minimal `VerificationEntry` for testing.
    fn test_entry(sender_byte: u8) -> VerificationEntry {
        let now = Instant::now();
        VerificationEntry {
            state: VerificationState::PendingVerify,
            verified_sources: Vec::new(),
            tried_sources: HashSet::new(),
            created_at: now,
            next_verify_at: now,
            hint_sources: HashSet::from([peer_id_from_byte(sender_byte)]),
            replica_hint_sources: HashSet::from([peer_id_from_byte(sender_byte)]),
            unresolved_retries: 0,
            no_holder_reported: false,
        }
    }

    #[test]
    fn max_min_allocation_lends_unused_capacity() {
        let attacker = peer_id_from_byte(1);
        let honest = peer_id_from_byte(2);
        let demands = BTreeMap::from([(attacker, MAX_PENDING_VERIFY), (honest, 50_000)]);

        let allocated = max_min_allocations(&demands, MAX_PENDING_VERIFY);

        assert_eq!(allocated[&honest], 50_000);
        assert_eq!(allocated[&attacker], MAX_PENDING_VERIFY - 50_000);
        assert_eq!(allocated.values().sum::<usize>(), MAX_PENDING_VERIFY);
    }

    #[test]
    fn max_min_allocation_is_even_under_saturation() {
        let demands = (0..20u8)
            .map(|index| (peer_id_from_byte(index), MAX_PENDING_VERIFY))
            .collect::<BTreeMap<_, _>>();

        let allocated = max_min_allocations(&demands, MAX_PENDING_VERIFY);
        let min = allocated.values().copied().min().unwrap();
        let max = allocated.values().copied().max().unwrap();

        assert!(max - min <= 1);
        assert_eq!(allocated.values().sum::<usize>(), MAX_PENDING_VERIFY);
    }

    #[test]
    fn fair_verification_selection_shares_service_and_redistributes_slack() {
        let mut queues = ReplicationQueues::new();
        let first = peer_id_from_byte(1);
        let second = peer_id_from_byte(2);
        for index in 0..12u32 {
            assert!(queues
                .add_pending_verify(xor_name_from_u32(index), test_entry(1))
                .admitted());
        }
        for index in 100..104u32 {
            assert!(queues
                .add_pending_verify(xor_name_from_u32(index), test_entry(2))
                .admitted());
        }

        let selected = queues.select_ready_pending_keys(Instant::now(), 12);
        let first_count = selected
            .iter()
            .filter(|key| queues.capacity_owner_by_key.get(*key) == Some(&first))
            .count();
        let second_count = selected
            .iter()
            .filter(|key| queues.capacity_owner_by_key.get(*key) == Some(&second))
            .count();

        assert_eq!(
            second_count, 4,
            "small sender should receive all its ready work"
        );
        assert_eq!(
            first_count, 8,
            "unused service should return to the busy sender"
        );
    }

    #[test]
    fn fair_verification_selection_prevents_cycle_monopoly() {
        const PER_OWNER: u32 = 10_000;
        const CYCLE: usize = 8_192;
        let mut queues = ReplicationQueues::new();
        let first = peer_id_from_byte(1);
        let second = peer_id_from_byte(2);
        for index in 0..PER_OWNER {
            assert!(queues
                .add_pending_verify(xor_name_from_u32(index), test_entry(1))
                .admitted());
            assert!(queues
                .add_pending_verify(xor_name_from_u32(1_000_000 + index), test_entry(2),)
                .admitted());
        }

        let selected = queues.select_ready_pending_keys(Instant::now(), CYCLE);
        let first_count = selected
            .iter()
            .filter(|key| queues.capacity_owner_by_key.get(*key) == Some(&first))
            .count();
        let second_count = selected
            .iter()
            .filter(|key| queues.capacity_owner_by_key.get(*key) == Some(&second))
            .count();

        assert_eq!(first_count, CYCLE / 2);
        assert_eq!(second_count, CYCLE / 2);
    }

    // -- add_pending_verify dedup ------------------------------------------

    #[test]
    fn add_pending_verify_new_key_succeeds() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        assert!(queues.add_pending_verify(key, test_entry(1)).admitted());
        assert_eq!(queues.pending_count(), 1);
    }

    #[test]
    fn large_single_source_backlog_is_not_subject_to_a_per_peer_cap() {
        const KEY_COUNT: u32 = 10_000;
        let mut queues = ReplicationQueues::new();

        for index in 0..KEY_COUNT {
            assert!(
                queues
                    .add_pending_verify(xor_name_from_u32(index), test_entry(1))
                    .admitted(),
                "key {index} should be admitted below the global emergency bound"
            );
        }
        assert_eq!(queues.pending_count(), KEY_COUNT as usize);
    }

    /// Duplicate advertisements must not grow a key's source set without bound.
    ///
    /// `MAX_PENDING_VERIFY` counts keys, not the peers remembered against each
    /// one, so before the cap N peers re-advertising a full queue cost
    /// `N * MAX_PENDING_VERIFY` associations charged to nothing.
    #[test]
    fn duplicate_hints_cannot_grow_a_keys_source_set_without_bound() {
        const ADVERTISERS: u8 = 40;

        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x5A);
        assert!(queues.add_pending_verify(key, test_entry(1)).admitted());

        for advertiser in 2..=ADVERTISERS {
            queues.add_pending_verify(key, test_entry(advertiser));
        }

        let entry = queues.get_pending(&key).expect("pending entry");
        assert!(
            entry.hint_sources.len() <= MAX_HINT_SOURCES_PER_KEY,
            "hint sources must stay capped, got {}",
            entry.hint_sources.len()
        );
        assert!(
            entry.replica_hint_sources.len() <= MAX_HINT_SOURCES_PER_KEY,
            "replica hint sources must stay capped"
        );
        let indexed: usize = queues
            .pending_keys_by_source
            .values()
            .map(|keys| keys.iter().filter(|k| **k == key).count())
            .sum();
        assert_eq!(
            indexed,
            entry.hint_sources.len(),
            "the reverse index must not outlive the sources it mirrors"
        );
    }

    /// Replica claimants outrank paid-only advertisers for a capped slot: they
    /// are the only sources that assert possession, so only they are usable as
    /// fetch candidates.
    #[test]
    fn replica_claimants_displace_paid_only_sources_at_the_cap() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x5B);

        // Fill the cap with paid-only advertisers (no possession claim).
        let mut first = test_entry(1);
        first.replica_hint_sources.clear();
        assert!(queues.add_pending_verify(key, first).admitted());
        for advertiser in 2..=u8::try_from(MAX_HINT_SOURCES_PER_KEY).unwrap_or(u8::MAX) {
            let mut paid_only = test_entry(advertiser);
            paid_only.replica_hint_sources.clear();
            queues.add_pending_verify(key, paid_only);
        }
        assert_eq!(
            queues
                .get_pending(&key)
                .expect("pending entry")
                .hint_sources
                .len(),
            MAX_HINT_SOURCES_PER_KEY,
            "the cap should now be saturated with paid-only advertisers"
        );

        let claimant = peer_id_from_byte(0xF0);
        let mut replica = test_entry(0xF0);
        replica.hint_sources = HashSet::from([claimant]);
        replica.replica_hint_sources = HashSet::from([claimant]);
        queues.add_pending_verify(key, replica);

        let entry = queues.get_pending(&key).expect("pending entry");
        assert!(
            entry.replica_hint_sources.contains(&claimant),
            "a replica claimant must take a slot from a paid-only advertiser"
        );
        assert_eq!(
            entry.hint_sources.len(),
            MAX_HINT_SOURCES_PER_KEY,
            "displacement must not grow the set"
        );
        assert!(
            entry.hint_sources.contains(&claimant),
            "the claimant must also be recorded as a live hint source"
        );
    }

    /// A promoted key's retry reservation must stay charged to its owner.
    ///
    /// Reservations are deducted from the global pool, so if they are billed to
    /// nobody an owner with many in-flight retries reads as under-loaded and
    /// wins a larger fair share than it earned.
    #[test]
    fn promoted_retry_reservation_stays_charged_to_its_owner() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x5C);
        let owner = peer_id_from_byte(1);

        assert!(queues.add_pending_verify(key, test_entry(1)).admitted());
        assert_eq!(queues.charged_count_for_owner(&owner), 1);

        assert!(queues.promote_pending_to_fetch(key, key, vec![owner]));
        assert_eq!(
            queues.retry_reserved_slot_count(),
            1,
            "promotion must reserve a slot for the later retry"
        );
        assert_eq!(
            queues.charged_count_for_owner(&owner),
            1,
            "the reservation must remain charged to the promoting owner while \
             the key sits in the fetch queue"
        );

        let candidate = queues.dequeue_fetch().expect("promoted key is fetchable");
        queues.start_dequeued_fetch(candidate, owner);
        assert_eq!(
            queues.charged_count_for_owner(&owner),
            1,
            "the charge must survive the transfer into in-flight fetch"
        );

        queues.complete_fetch(&key);
        assert_eq!(queues.retry_reserved_slot_count(), 0);
        assert_eq!(
            queues.charged_count_for_owner(&owner),
            0,
            "a terminal fetch must clear the owner's charge"
        );
    }

    /// ADR-0005 decision 7: a sole sender may borrow the whole pool, but a
    /// later sender reclaims its fair share within a bounded number of
    /// admissions. This pins that convergence — the property that replaced the
    /// removed `MAX_PENDING_VERIFY_PER_PEER` hard cap.
    #[test]
    fn borrowed_capacity_converges_to_fair_share_for_a_late_sender() {
        /// Admissions the late sender is allowed before fairness must hold.
        /// Each one reclaims at most a single borrowed slot, so reaching an
        /// even split needs at least half the pool; the doubling is headroom
        /// for skipped candidates, not an expectation.
        const RECLAIM_BUDGET: usize = MAX_PENDING_VERIFY;

        let mut queues = ReplicationQueues::new();
        let borrower = peer_id_from_byte(1);
        let late = peer_id_from_byte(2);

        // A sole sender borrows the entire pool — permitted by design, and the
        // behaviour that replaced the removed per-peer hard cap.
        for index in 0..MAX_PENDING_VERIFY {
            let index = u32::try_from(index).unwrap_or(u32::MAX);
            assert!(queues
                .add_pending_verify(xor_name_from_u32(index), test_entry(1))
                .admitted());
        }
        assert_eq!(
            queues.charged_count_for_owner(&borrower),
            MAX_PENDING_VERIFY
        );
        assert!(
            !queues
                .add_pending_verify(xor_name_from_u32(u32::MAX), test_entry(1))
                .admitted(),
            "the borrower cannot exceed the global pool"
        );

        // A second sender arrives and keeps offering work. Every admission it
        // wins must come out of the over-represented borrower's share.
        let mut late_admitted = 0usize;
        for offset in 0..RECLAIM_BUDGET {
            let index = u32::try_from(MAX_PENDING_VERIFY + offset).unwrap_or(u32::MAX);
            if queues
                .add_pending_verify(xor_name_from_u32(index), test_entry(2))
                .admitted()
            {
                late_admitted += 1;
            }
            if late_admitted >= MAX_PENDING_VERIFY / 2 {
                break;
            }
        }

        assert_eq!(
            queues.charged_count_for_owner(&late),
            MAX_PENDING_VERIFY / 2,
            "a late sender must reclaim an even share within its budget"
        );
        assert_eq!(
            queues.charged_count_for_owner(&borrower) + late_admitted,
            MAX_PENDING_VERIFY,
            "reclaim must move slots between owners, never create them"
        );
        assert_eq!(
            queues.pending_count(),
            MAX_PENDING_VERIFY,
            "the global bound must hold throughout"
        );
    }

    #[test]
    fn duplicate_pending_hint_adds_live_source_without_bypassing_deferral() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        let source_a = peer_id_from_byte(1);
        let source_b = peer_id_from_byte(2);
        let mut first = test_entry(1);
        first.next_verify_at = Instant::now() + Duration::from_secs(60);
        assert!(queues.add_pending_verify(key, first).admitted());
        assert!(queues.ready_pending_keys(Instant::now()).is_empty());
        assert!(!queues.add_pending_verify(key, test_entry(2)).admitted());
        assert_eq!(queues.pending_count(), 1);
        assert_eq!(
            queues
                .get_pending(&key)
                .expect("pending entry")
                .hint_sources,
            HashSet::from([source_a, source_b])
        );
        assert!(
            queues.ready_pending_keys(Instant::now()).is_empty(),
            "a duplicate source must not bypass verification retry deferral"
        );
    }

    #[test]
    fn repeated_duplicate_from_same_source_does_not_grow_eviction_heap() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x77);
        let owner = peer_id_from_byte(1);
        assert!(queues.add_pending_verify(key, test_entry(1)).admitted());

        for _ in 0..1_000 {
            assert_eq!(
                queues.add_pending_verify(key, test_entry(1)),
                AdmissionResult::AlreadyPresent
            );
        }

        assert_eq!(
            queues
                .eviction_candidates_by_owner
                .get(&owner)
                .map_or(0, BinaryHeap::len),
            1
        );
    }

    #[test]
    fn ready_pending_keys_prioritizes_more_live_sources_then_age() {
        let mut queues = ReplicationQueues::new();
        let oldest_singleton = xor_name_from_byte(0x10);
        let newer_singleton = xor_name_from_byte(0x20);
        let corroborated = xor_name_from_byte(0x30);
        let now = Instant::now();

        let mut oldest = test_entry(1);
        oldest.created_at = now.checked_sub(Duration::from_secs(2)).unwrap();
        let mut newer = test_entry(1);
        newer.created_at = now.checked_sub(Duration::from_secs(1)).unwrap();
        let mut multi = test_entry(1);
        multi.created_at = now;

        assert!(queues
            .add_pending_verify(oldest_singleton, oldest)
            .admitted());
        assert!(queues.add_pending_verify(newer_singleton, newer).admitted());
        assert!(queues.add_pending_verify(corroborated, multi).admitted());
        assert_eq!(
            queues.add_pending_verify(corroborated, test_entry(2)),
            AdmissionResult::AlreadyPresent
        );

        assert_eq!(
            queues.ready_pending_keys(Instant::now()),
            vec![corroborated, oldest_singleton, newer_singleton]
        );
    }

    #[test]
    fn peer_removal_drops_orphans_and_preserves_corroborated_hints() {
        let mut queues = ReplicationQueues::new();
        let source_a = peer_id_from_byte(1);
        let source_b = peer_id_from_byte(2);
        let orphaned_key = xor_name_from_byte(0x40);
        let shared_key = xor_name_from_byte(0x41);

        assert!(queues
            .add_pending_verify(orphaned_key, test_entry(1))
            .admitted());
        assert!(queues
            .add_pending_verify(shared_key, test_entry(1))
            .admitted());
        assert_eq!(
            queues.add_pending_verify(shared_key, test_entry(2)),
            AdmissionResult::AlreadyPresent
        );

        assert_eq!(queues.remove_hint_source(&source_a), vec![orphaned_key]);
        let shared = queues
            .get_pending(&shared_key)
            .expect("shared hint retained");
        assert_eq!(shared.hint_sources, HashSet::from([source_b]));
        assert_eq!(queues.pending_count_for_owner(&source_a), 0);
        assert_eq!(queues.pending_count_for_owner(&source_b), 1);

        assert_eq!(queues.remove_hint_source(&source_b), vec![shared_key]);
        assert_eq!(queues.pending_count(), 0);
    }

    #[test]
    fn peer_removal_prunes_fetch_and_retry_sources() {
        let mut queues = ReplicationQueues::new();
        let source_a = peer_id_from_byte(1);
        let source_b = peer_id_from_byte(2);
        let key = xor_name_from_byte(0x42);

        assert!(queues.add_pending_verify(key, test_entry(1)).admitted());
        assert_eq!(
            queues.add_pending_verify(key, test_entry(2)),
            AdmissionResult::AlreadyPresent
        );
        assert!(queues.promote_pending_to_fetch(
            key,
            xor_name_from_byte(0x01),
            vec![source_a, source_b],
        ));

        assert!(queues.remove_hint_source(&source_a).is_empty());
        let candidate = queues.dequeue_fetch().expect("candidate remains fetchable");
        assert_eq!(candidate.sources, vec![source_b]);
        assert_eq!(
            candidate
                .retry_verification
                .as_ref()
                .expect("retry provenance retained")
                .hint_sources,
            HashSet::from([source_b])
        );
        queues.discard_fetch_candidate(candidate);
    }

    #[test]
    fn add_pending_verify_rejected_if_in_fetch_queue() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x02);
        let distance = xor_name_from_byte(0x10);
        queues.enqueue_fetch(key, distance, vec![peer_id_from_byte(1)]);

        assert!(
            !queues.add_pending_verify(key, test_entry(1)).admitted(),
            "should reject key already in fetch queue"
        );
    }

    #[test]
    fn add_pending_verify_merges_source_into_queued_candidate() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x02);
        let queued_source = peer_id_from_byte(1);
        let extra_source = peer_id_from_byte(2);

        queues.enqueue_fetch(key, xor_name_from_byte(0x10), vec![queued_source]);

        assert_eq!(
            queues.add_pending_verify(key, test_entry(2)),
            AdmissionResult::AlreadyPresent
        );
        // A repeat hint from an already-known advertiser must not duplicate it.
        assert_eq!(
            queues.add_pending_verify(key, test_entry(1)),
            AdmissionResult::AlreadyPresent
        );

        let candidate = queues.dequeue_fetch().expect("queued candidate");
        assert_eq!(
            candidate.sources,
            vec![queued_source, extra_source],
            "a new advertiser is merged as a fetch source exactly once"
        );
        queues.discard_fetch_candidate(candidate);
    }

    #[test]
    fn add_pending_verify_merge_preserves_fetch_priority_order() {
        let mut queues = ReplicationQueues::new();
        let near_key = xor_name_from_byte(0x01);
        let far_key = xor_name_from_byte(0x02);
        let near_dist = [0x00; 32]; // nearest
        let far_dist = [0xFF; 32]; // farthest

        queues.enqueue_fetch(far_key, far_dist, vec![peer_id_from_byte(1)]);
        queues.enqueue_fetch(near_key, near_dist, vec![peer_id_from_byte(2)]);

        // Merging a source into the farthest key must not reorder the queue:
        // the merge touches no field the heap orders on.
        assert_eq!(
            queues.add_pending_verify(far_key, test_entry(3)),
            AdmissionResult::AlreadyPresent
        );

        let first = queues.dequeue_fetch().expect("should dequeue");
        assert_eq!(
            first.key, near_key,
            "nearest key still dequeues first after a merge"
        );
        queues.discard_fetch_candidate(first);

        let second = queues.dequeue_fetch().expect("should dequeue");
        assert_eq!(second.key, far_key, "farthest key dequeues second");
        queues.discard_fetch_candidate(second);
    }

    #[test]
    fn peer_removal_drops_orphaned_fetch_candidate() {
        let mut queues = ReplicationQueues::new();
        let source = peer_id_from_byte(1);
        let key = xor_name_from_byte(0x43);

        queues.enqueue_fetch(key, xor_name_from_byte(0x10), vec![source]);

        assert_eq!(
            queues.remove_hint_source(&source),
            vec![key],
            "a candidate whose last source departed is reported orphaned"
        );
        assert_eq!(queues.fetch_queue_count(), 0);
        assert!(
            !queues.contains_key(&key),
            "orphaned key leaves the pipeline entirely"
        );
        assert!(
            queues.dequeue_fetch().is_none(),
            "orphaned candidate must not linger in the priority heap"
        );
    }

    #[test]
    fn add_pending_verify_rejected_if_in_flight() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x03);
        let source = peer_id_from_byte(1);
        queues.start_fetch(key, source, vec![source]);

        assert!(
            !queues.add_pending_verify(key, test_entry(1)).admitted(),
            "should reject key already in-flight"
        );
    }

    // -- enqueue/dequeue ordering -----------------------------------------

    #[test]
    fn dequeue_returns_nearest_first() {
        let mut queues = ReplicationQueues::new();

        let near_key = xor_name_from_byte(0x01);
        let far_key = xor_name_from_byte(0x02);
        let near_dist = [0x00; 32]; // nearest
        let far_dist = [0xFF; 32]; // farthest

        queues.enqueue_fetch(far_key, far_dist, vec![peer_id_from_byte(1)]);
        queues.enqueue_fetch(near_key, near_dist, vec![peer_id_from_byte(2)]);

        let first = queues.dequeue_fetch().expect("should dequeue");
        assert_eq!(first.key, near_key, "nearest key should dequeue first");
        queues.discard_fetch_candidate(first);

        let second = queues.dequeue_fetch().expect("should dequeue");
        assert_eq!(second.key, far_key, "farthest key should dequeue second");
        queues.discard_fetch_candidate(second);
    }

    #[test]
    fn enqueue_dedup_prevents_duplicates() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);

        queues.enqueue_fetch(key, [0x10; 32], vec![peer_id_from_byte(1)]);
        queues.enqueue_fetch(key, [0x10; 32], vec![peer_id_from_byte(2)]);

        assert_eq!(
            queues.fetch_queue_count(),
            1,
            "duplicate enqueue should be ignored"
        );
    }

    // -- in-flight tracking -----------------------------------------------

    #[test]
    fn start_and_complete_fetch() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        let source = peer_id_from_byte(1);

        queues.start_fetch(key, source, vec![source]);
        assert_eq!(queues.in_flight_count(), 1);

        let completed = queues.complete_fetch(&key);
        assert!(completed.is_some());
        assert_eq!(queues.in_flight_count(), 0);
    }

    #[test]
    fn complete_nonexistent_returns_none() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x99);
        assert!(queues.complete_fetch(&key).is_none());
    }

    // -- retry_fetch ------------------------------------------------------

    #[test]
    fn retry_fetch_returns_next_untried_source() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        let source_a = peer_id_from_byte(1);
        let source_b = peer_id_from_byte(2);
        let source_c = peer_id_from_byte(3);

        queues.start_fetch(key, source_a, vec![source_a, source_b, source_c]);

        // First retry: should skip source_a (already tried), return source_b.
        let next = queues.retry_fetch(&key);
        assert_eq!(next, Some(source_b));

        // Second retry: should return source_c.
        let next = queues.retry_fetch(&key);
        assert_eq!(next, Some(source_c));

        // Third retry: all exhausted.
        let next = queues.retry_fetch(&key);
        assert!(next.is_none(), "all sources exhausted");
    }

    #[test]
    fn retry_fetch_nonexistent_returns_none() {
        let mut queues = ReplicationQueues::new();
        assert!(queues.retry_fetch(&xor_name_from_byte(0xFF)).is_none());
    }

    #[test]
    fn exhausted_promoted_fetch_requeues_verification() {
        const KEY_BYTE: u8 = 0x44;
        const DISTANCE_BYTE: u8 = 0x01;
        const SOURCE_BYTE: u8 = 2;
        const HINT_SENDER_BYTE: u8 = 9;
        const RETRY_DELAY: Duration = Duration::from_secs(15);
        const RETRY_DELAY_SLACK: Duration = Duration::from_secs(1);

        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(KEY_BYTE);
        let distance = xor_name_from_byte(DISTANCE_BYTE);
        let source = peer_id_from_byte(SOURCE_BYTE);
        let entry = test_entry(HINT_SENDER_BYTE);

        assert!(queues.add_pending_verify(key, entry).admitted());
        assert!(queues.promote_pending_to_fetch(key, distance, vec![source]));

        let candidate = queues.dequeue_fetch().expect("fetch candidate");
        queues.start_dequeued_fetch(candidate, source);

        assert!(
            queues.retry_fetch(&key).is_none(),
            "single source should be exhausted"
        );
        assert!(queues.requeue_fetch_for_verification(&key, RETRY_DELAY));

        assert_eq!(queues.in_flight_count(), 0);
        assert!(
            queues.ready_pending_keys(Instant::now()).is_empty(),
            "requeued key should observe retry delay"
        );

        let after_retry = Instant::now() + RETRY_DELAY + RETRY_DELAY_SLACK;
        assert_eq!(queues.ready_pending_keys(after_retry), vec![key]);
        assert_eq!(
            queues.pending_count_for_owner(&peer_id_from_byte(HINT_SENDER_BYTE)),
            1
        );
        assert!(queues.protected_pending_keys.contains(&key));
        assert_eq!(
            queues.capacity_owner_by_key.get(&key),
            Some(&peer_id_from_byte(HINT_SENDER_BYTE))
        );
    }

    #[test]
    fn no_sources_dequeued_candidate_requeues_for_verification() {
        const KEY_INDEX: u32 = 70_000;
        const DISTANCE_BYTE: u8 = 0x01;
        const HINT_SENDER_BYTE: u8 = 9;
        const VERIFIED_SOURCE_BYTE: u8 = 2;
        const TRIED_SOURCE_BYTE: u8 = 3;
        const RETRY_DELAY: Duration = Duration::from_secs(15);
        const RETRY_DELAY_SLACK: Duration = Duration::from_secs(1);

        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_u32(KEY_INDEX);
        let distance = xor_name_from_byte(DISTANCE_BYTE);
        let verified_source = peer_id_from_byte(VERIFIED_SOURCE_BYTE);
        let tried_source = peer_id_from_byte(TRIED_SOURCE_BYTE);
        let mut entry = test_entry(HINT_SENDER_BYTE);
        entry.state = VerificationState::QueuedForFetch;
        entry.verified_sources.push(verified_source);
        entry.tried_sources.insert(tried_source);

        assert!(queues.add_pending_verify(key, entry).admitted());
        assert!(queues.promote_pending_to_fetch(key, distance, Vec::new()));

        let candidate = queues.dequeue_fetch().expect("fetch candidate");
        assert!(
            candidate.sources.is_empty(),
            "test candidate should exercise the no-sources branch"
        );
        assert!(
            queues.requeue_candidate_for_verification(candidate, RETRY_DELAY),
            "no-sources retry candidate should be restored to pending verification"
        );

        let pending = queues.get_pending(&key).expect("key should be pending");
        assert_eq!(pending.state, VerificationState::PendingVerify);
        assert!(
            pending.verified_sources.is_empty(),
            "verified sources should be cleared before retry"
        );
        assert!(
            pending.tried_sources.is_empty(),
            "tried sources should be cleared before retry"
        );
        assert!(
            queues.ready_pending_keys(Instant::now()).is_empty(),
            "requeued key should observe retry delay"
        );

        let after_retry = Instant::now() + RETRY_DELAY + RETRY_DELAY_SLACK;
        assert_eq!(queues.ready_pending_keys(after_retry), vec![key]);

        assert!(queues.remove_pending(&key).is_some());
    }

    #[test]
    fn exhausted_direct_fetch_remains_terminal() {
        const KEY_BYTE: u8 = 0x45;
        const DISTANCE_BYTE: u8 = 0x01;
        const SOURCE_BYTE: u8 = 2;
        const RETRY_DELAY: Duration = Duration::from_secs(15);

        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(KEY_BYTE);
        let source = peer_id_from_byte(SOURCE_BYTE);

        queues.enqueue_fetch(key, xor_name_from_byte(DISTANCE_BYTE), vec![source]);
        let candidate = queues.dequeue_fetch().expect("fetch candidate");
        queues.start_dequeued_fetch(candidate, source);

        assert!(
            queues.retry_fetch(&key).is_none(),
            "single source should be exhausted"
        );
        assert!(!queues.requeue_fetch_for_verification(&key, RETRY_DELAY));
        assert_eq!(queues.in_flight_count(), 0);
        assert_eq!(queues.pending_count(), 0);
    }

    // -- contains_key across pipelines ------------------------------------

    #[test]
    fn contains_key_in_pending() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        queues.add_pending_verify(key, test_entry(1));
        assert!(queues.contains_key(&key));
    }

    #[test]
    fn contains_key_in_fetch_queue() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x02);
        queues.enqueue_fetch(key, [0x10; 32], vec![peer_id_from_byte(1)]);
        assert!(queues.contains_key(&key));
    }

    #[test]
    fn contains_key_in_flight() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x03);
        queues.start_fetch(key, peer_id_from_byte(1), vec![]);
        assert!(queues.contains_key(&key));
    }

    #[test]
    fn contains_key_absent() {
        let queues = ReplicationQueues::new();
        assert!(!queues.contains_key(&xor_name_from_byte(0xFF)));
    }

    // -- bootstrap work empty ---------------------------------------------

    #[test]
    fn bootstrap_work_empty_when_no_keys_present() {
        let queues = ReplicationQueues::new();
        let bootstrap_keys: HashSet<XorName> = [xor_name_from_byte(0x01), xor_name_from_byte(0x02)]
            .into_iter()
            .collect();
        assert!(queues.is_bootstrap_work_empty(&bootstrap_keys));
    }

    #[test]
    fn bootstrap_work_not_empty_when_key_in_pending() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        queues.add_pending_verify(key, test_entry(1));

        let bootstrap_keys: HashSet<XorName> = std::iter::once(key).collect();
        assert!(!queues.is_bootstrap_work_empty(&bootstrap_keys));
    }

    // -- evict_stale ------------------------------------------------------

    #[test]
    fn evict_stale_removes_old_entries() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);

        let mut entry = test_entry(1);
        // Backdate via the same defensive checked_sub used elsewhere so
        // freshly-booted CI clocks don't trip us up.
        entry.created_at = Instant::now()
            .checked_sub(Duration::from_secs(2))
            .unwrap_or_else(Instant::now);
        assert!(queues.add_pending_verify(key, entry).admitted());

        assert_eq!(queues.pending_count(), 1);

        let evicted = queues.evict_stale(Duration::from_secs(1));
        assert_eq!(evicted, vec![key]);
        assert_eq!(
            queues.pending_count(),
            0,
            "entry older than max_age should be evicted"
        );
    }

    #[test]
    fn evict_stale_keeps_fresh_entries() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        queues.add_pending_verify(key, test_entry(1));

        let evicted = queues.evict_stale(Duration::from_hours(1));
        assert!(
            evicted.is_empty(),
            "fresh entry should not be reported as evicted"
        );
        assert_eq!(
            queues.pending_count(),
            1,
            "fresh entry should not be evicted"
        );
    }

    #[test]
    fn deferred_pending_key_is_not_ready_until_retry_time() {
        const RETRY_DELAY: Duration = Duration::from_secs(15);
        const RETRY_DELAY_SLACK: Duration = Duration::from_secs(1);

        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0xAA);
        queues.add_pending_verify(key, test_entry(1));

        assert_eq!(queues.ready_pending_keys(Instant::now()), vec![key]);
        assert!(queues.defer_pending(&key, RETRY_DELAY));
        assert!(
            queues.ready_pending_keys(Instant::now()).is_empty(),
            "deferred key should not be retried immediately"
        );

        let after_retry = Instant::now() + RETRY_DELAY + RETRY_DELAY_SLACK;
        assert_eq!(queues.ready_pending_keys(after_retry), vec![key]);
    }

    #[test]
    fn repeated_deferrals_back_off_and_saturate_at_the_cap() {
        const BASE: Duration = Duration::from_secs(15);

        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0xAB);
        queues.add_pending_verify(key, test_entry(1));

        // 15s doubling per consecutive unresolved round.
        for (attempt, expected_secs) in [(1, 15), (2, 30), (3, 60), (4, 120), (5, 240)] {
            let outcome = queues
                .defer_unresolved(&key, BASE)
                .expect("pending key should defer");
            assert_eq!(outcome.attempt, attempt);
            assert_eq!(
                outcome.retry_after,
                Duration::from_secs(expected_secs),
                "attempt {attempt} should back off to {expected_secs}s"
            );
        }

        // Everything past the cap stays at the cap rather than overflowing the
        // shift into a short (or zero) delay.
        for _ in 0..64 {
            let outcome = queues
                .defer_unresolved(&key, BASE)
                .expect("pending key should defer");
            assert_eq!(
                outcome.retry_after, VERIFICATION_RETRY_BACKOFF_MAX,
                "backoff must saturate at the cap, never wrap"
            );
        }
    }

    /// The counter and the warning answer different questions, so a round that
    /// advances the count without producing a no-holder result — an
    /// inconclusive quorum — must leave the warning unclaimed. Deriving the
    /// report from `attempt == 1` loses the first and only warning for every
    /// key whose opening round is inconclusive.
    #[test]
    fn a_non_reporting_round_does_not_consume_the_no_holder_warning() {
        const BASE: Duration = Duration::from_secs(15);

        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0xAE);
        queues.add_pending_verify(key, test_entry(1));

        // Round 1: inconclusive quorum. Backs off, reports nothing.
        let first = queues
            .defer_unresolved(&key, BASE)
            .expect("pending key should defer");
        assert_eq!(first.attempt, 1);

        // Round 2 is the first that actually finds no holder. It is at
        // attempt 2, but it is the first report and must still warn.
        let second = queues
            .defer_unresolved(&key, BASE)
            .expect("pending key should defer");
        assert_eq!(second.attempt, 2, "the inconclusive round still counts");
        assert!(
            queues.claim_no_holder_report(&key),
            "the first no-holder result must warn even at attempt 2"
        );
        assert!(
            !queues.claim_no_holder_report(&key),
            "the warning is claimed exactly once per entry"
        );
    }

    /// A round that found a holder ends the run of failures, even when a full
    /// fetch queue leaves the key pending. It must not inherit the old backoff,
    /// and a later relapse deserves a fresh warning.
    #[test]
    fn finding_a_holder_clears_the_backoff_and_rearms_the_warning() {
        const BASE: Duration = Duration::from_secs(15);

        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0xAF);
        queues.add_pending_verify(key, test_entry(1));

        for _ in 0..4 {
            queues
                .defer_unresolved(&key, BASE)
                .expect("pending key should defer");
        }
        assert!(queues.claim_no_holder_report(&key));

        assert!(queues.clear_unresolved(&key));

        let outcome = queues
            .defer_unresolved(&key, BASE)
            .expect("pending key should defer");
        assert_eq!(outcome.attempt, 1, "a resolved round restarts the run");
        assert_eq!(outcome.retry_after, BASE);
        assert!(
            queues.claim_no_holder_report(&key),
            "a relapse after a good round is reported again"
        );
    }

    /// The whole fix rests on a duplicate hint merging into the live entry
    /// rather than replacing it. A refactor that replaced would silently revert
    /// the backoff with every other test here still green.
    #[test]
    fn a_duplicate_hint_does_not_reset_the_backoff_or_the_retry_time() {
        const BASE: Duration = Duration::from_secs(15);

        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0xB0);
        queues.add_pending_verify(key, test_entry(1));

        for _ in 0..3 {
            queues
                .defer_unresolved(&key, BASE)
                .expect("pending key should defer");
        }
        assert!(queues.claim_no_holder_report(&key));
        let deferred_until = queues.pending_verify[&key].next_verify_at;

        // A second advertiser re-hints the same key.
        assert!(!queues.add_pending_verify(key, test_entry(2)).admitted());

        let entry = &queues.pending_verify[&key];
        assert_eq!(
            entry.unresolved_retries, 3,
            "a re-hint must not restart the backoff"
        );
        assert!(
            entry.no_holder_reported,
            "a re-hint must not re-arm the warning; only eviction ends an episode"
        );
        assert_eq!(
            entry.next_verify_at, deferred_until,
            "a re-hint must not pull the key forward into an earlier round"
        );
    }

    /// The write-blocked capacity gate defers without asking anyone, so it must
    /// not consume the entry's first-failure warning or advance its backoff:
    /// nothing was learned about the key.
    #[test]
    fn flat_defer_does_not_advance_the_unresolved_backoff() {
        const BASE: Duration = Duration::from_secs(15);

        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0xAD);
        queues.add_pending_verify(key, test_entry(1));

        for _ in 0..10 {
            assert!(queues.defer_pending(&key, Duration::from_secs(300)));
        }

        let outcome = queues
            .defer_unresolved(&key, BASE)
            .expect("pending key should defer");
        assert_eq!(
            outcome.attempt, 1,
            "a flat deferral is not a failed round and must not consume attempt 1"
        );
        assert_eq!(outcome.retry_after, BASE);
        assert!(
            queues.claim_no_holder_report(&key),
            "nor may it consume the warning"
        );
    }

    #[test]
    fn defer_unresolved_reports_none_for_unknown_key() {
        let mut queues = ReplicationQueues::new();
        assert!(queues
            .defer_unresolved(&xor_name_from_byte(0xFF), Duration::from_secs(15))
            .is_none());
    }

    #[test]
    fn re_admission_after_eviction_restarts_the_backoff() {
        const BASE: Duration = Duration::from_secs(15);

        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0xAC);
        queues.add_pending_verify(key, test_entry(1));

        for _ in 0..5 {
            queues
                .defer_unresolved(&key, BASE)
                .expect("pending key should defer");
        }

        // Stale eviction drops the entry; the next hint admits a fresh one. The
        // count lives on the entry, so the episode — and its single warning —
        // starts over.
        queues.evict_stale(Duration::ZERO);
        assert_eq!(queues.pending_count(), 0);
        queues.add_pending_verify(key, test_entry(1));

        let outcome = queues
            .defer_unresolved(&key, BASE)
            .expect("re-admitted key should defer");
        assert_eq!(outcome.attempt, 1, "re-admission starts a new episode");
        assert_eq!(outcome.retry_after, BASE);
    }

    #[test]
    fn backoff_never_retries_faster_than_the_caller_base() {
        // A base above the cap (an unusual config, but representable) must not
        // be shortened into a tighter retry loop than the caller asked for.
        let long_base = VERIFICATION_RETRY_BACKOFF_MAX + Duration::from_secs(60);
        assert_eq!(backoff_delay(long_base, 1), long_base);
        assert_eq!(backoff_delay(long_base, 9), long_base);
    }

    // -- remove_pending ---------------------------------------------------

    #[test]
    fn remove_pending_returns_entry() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x01);
        queues.add_pending_verify(key, test_entry(1));

        let removed = queues.remove_pending(&key);
        assert!(removed.is_some());
        assert_eq!(queues.pending_count(), 0);
    }

    #[test]
    fn remove_pending_nonexistent_returns_none() {
        let mut queues = ReplicationQueues::new();
        assert!(queues.remove_pending(&xor_name_from_byte(0xFF)).is_none());
    }

    // -----------------------------------------------------------------------
    // Section 18 scenarios
    // -----------------------------------------------------------------------

    /// Scenario 8: A key already in `PendingVerify` cannot be enqueued into
    /// `FetchQueue` (cross-queue dedup). Also, a key in `FetchQueue` cannot be
    /// re-added to `PendingVerify`.
    #[test]
    fn scenario_8_duplicate_key_not_double_queued() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0xE0);
        let distance = xor_name_from_byte(0x10);

        // Step 1: Add to PendingVerify.
        assert!(
            queues.add_pending_verify(key, test_entry(1)).admitted(),
            "first add to PendingVerify should succeed"
        );
        assert!(
            queues.contains_key(&key),
            "key should be present in pipeline"
        );

        // Step 2: Attempt to enqueue fetch while still in PendingVerify.
        // enqueue_fetch checks all three stages (pending_verify,
        // fetch_queue_keys, in_flight), so this is a no-op while the key
        // is still in PendingVerify.
        queues.enqueue_fetch(key, distance, vec![peer_id_from_byte(2)]);
        // Verify the key is still tracked via the cross-stage check.
        assert!(queues.contains_key(&key), "key should still be in pipeline");

        // Step 3: Remove from PendingVerify, add to FetchQueue.
        queues.remove_pending(&key);
        queues.enqueue_fetch(key, distance, vec![peer_id_from_byte(3)]);
        assert_eq!(queues.fetch_queue_count(), 1);

        // Step 4: Attempt to re-add to PendingVerify -> should fail.
        assert!(
            !queues.add_pending_verify(key, test_entry(4)).admitted(),
            "key in FetchQueue should be rejected from PendingVerify"
        );

        // Step 5: Dequeue, start fetch -> key is in-flight.
        let candidate = queues.dequeue_fetch().expect("should dequeue");
        let source = candidate.sources[0];
        queues.start_dequeued_fetch(candidate, source);

        // Step 6: Attempt to add to PendingVerify while in-flight -> reject.
        assert!(
            !queues.add_pending_verify(key, test_entry(5)).admitted(),
            "key in-flight should be rejected from PendingVerify"
        );

        // Step 7: Attempt to enqueue fetch while in-flight -> no-op.
        queues.enqueue_fetch(key, distance, vec![peer_id_from_byte(6)]);
        // fetch_queue should still be empty (the enqueue was a no-op).
        assert_eq!(
            queues.fetch_queue_count(),
            0,
            "enqueue_fetch should be no-op for in-flight key"
        );
    }

    /// Scenario 8 (continued): Verify that pipeline field for a key
    /// admitted as both replica and paid hint collapses to Replica only,
    /// because cross-set precedence in admission gives replica priority.
    #[test]
    fn scenario_8_replica_and_paid_hint_collapses_to_replica() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0xE1);

        // Simulate admission result: key was in both replica_hints and
        // paid_hints, so admission records a possession claim for it.
        let entry = VerificationEntry {
            state: VerificationState::PendingVerify,
            verified_sources: Vec::new(),
            tried_sources: HashSet::new(),
            created_at: Instant::now(),
            next_verify_at: Instant::now(),
            hint_sources: HashSet::from([peer_id_from_byte(1)]),
            replica_hint_sources: HashSet::from([peer_id_from_byte(1)]),
            unresolved_retries: 0,
            no_holder_reported: false,
        };

        assert!(queues.add_pending_verify(key, entry).admitted());

        let pending = queues.get_pending(&key).expect("should be pending");
        assert_eq!(
            pending.pipeline(),
            crate::replication::types::HintPipeline::Replica,
            "key in both hint sets should be Replica pipeline"
        );

        // A second add (e.g. from paid hints arriving separately) is rejected.
        let paid_entry = VerificationEntry {
            state: VerificationState::PendingVerify,
            verified_sources: Vec::new(),
            tried_sources: HashSet::new(),
            created_at: Instant::now(),
            next_verify_at: Instant::now(),
            hint_sources: HashSet::from([peer_id_from_byte(2)]),
            replica_hint_sources: HashSet::new(),
            unresolved_retries: 0,
            no_holder_reported: false,
        };

        assert!(
            !queues.add_pending_verify(key, paid_entry).admitted(),
            "duplicate key should be rejected regardless of pipeline"
        );

        // Pipeline stays Replica: merging a paid-only advertiser adds no
        // possession claim, so it cannot demote the existing one.
        let pending = queues.get_pending(&key).expect("should still be pending");
        assert_eq!(
            pending.pipeline(),
            crate::replication::types::HintPipeline::Replica,
            "pipeline should remain Replica after duplicate rejection"
        );
    }

    /// A paid-only key cannot be escalated into the fetch-eligible pipeline by
    /// a peer re-advertising it as a replica hint.
    ///
    /// The queue still records the possession claim — that is what the sender
    /// asserted, and it makes the sender a fetch-source candidate. What it must
    /// not do is turn that claim into permission to store: the storage-
    /// admission check at download time is what decides, and it consults live
    /// routing state rather than this tag.
    #[test]
    fn replica_hint_on_paid_only_key_does_not_grant_storage_admission() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0xE2);
        let paid_advertiser = peer_id_from_byte(1);
        let replica_advertiser = peer_id_from_byte(2);

        let paid_entry = VerificationEntry {
            state: VerificationState::PendingVerify,
            verified_sources: Vec::new(),
            tried_sources: HashSet::new(),
            created_at: Instant::now(),
            next_verify_at: Instant::now(),
            hint_sources: HashSet::from([paid_advertiser]),
            replica_hint_sources: HashSet::new(),
            unresolved_retries: 0,
            no_holder_reported: false,
        };
        assert!(queues.add_pending_verify(key, paid_entry).admitted());
        assert_eq!(
            queues
                .get_pending(&key)
                .expect("should be pending")
                .pipeline(),
            crate::replication::types::HintPipeline::PaidOnly,
        );

        // Second message re-advertises the same key as a replica hint.
        let replica_entry = VerificationEntry {
            state: VerificationState::PendingVerify,
            verified_sources: Vec::new(),
            tried_sources: HashSet::new(),
            created_at: Instant::now(),
            next_verify_at: Instant::now(),
            hint_sources: HashSet::from([replica_advertiser]),
            replica_hint_sources: HashSet::from([replica_advertiser]),
            unresolved_retries: 0,
            no_holder_reported: false,
        };
        assert!(!queues.add_pending_verify(key, replica_entry).admitted());

        let pending = queues.get_pending(&key).expect("should still be pending");
        assert!(
            pending.replica_hint_sources.contains(&replica_advertiser),
            "the possession claim is recorded for fetch-source discovery"
        );
        assert!(
            !pending.replica_hint_sources.contains(&paid_advertiser),
            "a paid-only advertiser never becomes a fetch source"
        );
    }

    /// Losing the only replica advertiser demotes the derived pipeline without
    /// any explicit bookkeeping, because the tag *is* the possession-claim set.
    #[test]
    fn departing_sole_replica_advertiser_demotes_derived_pipeline() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0xE3);
        let replica_advertiser = peer_id_from_byte(1);
        let paid_advertiser = peer_id_from_byte(2);

        let entry = VerificationEntry {
            state: VerificationState::PendingVerify,
            verified_sources: Vec::new(),
            tried_sources: HashSet::new(),
            created_at: Instant::now(),
            next_verify_at: Instant::now(),
            hint_sources: HashSet::from([replica_advertiser, paid_advertiser]),
            replica_hint_sources: HashSet::from([replica_advertiser]),
            unresolved_retries: 0,
            no_holder_reported: false,
        };
        assert!(queues.add_pending_verify(key, entry).admitted());

        queues.remove_hint_source(&replica_advertiser);

        let pending = queues
            .get_pending(&key)
            .expect("paid advertiser still holds the entry open");
        assert_eq!(
            pending.pipeline(),
            crate::replication::types::HintPipeline::PaidOnly,
            "no possession claims remain, so the key is paid-only again"
        );
    }

    /// Scenario 3: Neighbor-sync unknown key transitions through the full
    /// state machine to stored.
    ///
    /// Exercises the complete queue pipeline that a key follows when it
    /// arrives as a neighbor-sync hint, passes quorum verification, is
    /// fetched, and completes:
    ///   `PendingVerify` → (quorum pass) → `QueuedForFetch` → `Fetching` → `Stored`
    #[test]
    fn scenario_3_neighbor_sync_quorum_pass_full_pipeline() {
        let mut queues = ReplicationQueues::new();
        let key = xor_name_from_byte(0x03);
        let distance = xor_name_from_byte(0x01);
        let source_a = peer_id_from_byte(1);
        let source_b = peer_id_from_byte(2);

        // Stage 1: Hint admitted → PendingVerify
        let entry = VerificationEntry {
            state: VerificationState::PendingVerify,
            verified_sources: Vec::new(),
            tried_sources: HashSet::new(),
            created_at: Instant::now(),
            next_verify_at: Instant::now(),
            hint_sources: HashSet::from([peer_id_from_byte(3)]),
            replica_hint_sources: HashSet::from([peer_id_from_byte(3)]),
            unresolved_retries: 0,
            no_holder_reported: false,
        };
        assert!(
            queues.add_pending_verify(key, entry).admitted(),
            "new key should be admitted to PendingVerify"
        );
        assert!(queues.contains_key(&key));
        assert_eq!(queues.pending_count(), 1);

        // Stage 2: Quorum passes — remove from pending and enqueue for fetch
        // with the verified sources discovered during the quorum round.
        let removed = queues.remove_pending(&key);
        assert!(removed.is_some(), "key should exist in pending");
        assert_eq!(queues.pending_count(), 0);

        queues.enqueue_fetch(key, distance, vec![source_a, source_b]);
        assert_eq!(queues.fetch_queue_count(), 1);
        assert!(
            queues.contains_key(&key),
            "key should be in pipeline (fetch queue)"
        );

        // Stage 3: Dequeue → Fetching
        let candidate = queues.dequeue_fetch().expect("should dequeue");
        assert_eq!(candidate.key, key);
        assert_eq!(candidate.sources.len(), 2);
        queues.start_dequeued_fetch(candidate, source_a);
        assert_eq!(queues.in_flight_count(), 1);
        assert_eq!(queues.fetch_queue_count(), 0);
        assert!(
            queues.contains_key(&key),
            "key should be in pipeline (in-flight)"
        );

        // Stage 4: Fetch completes → Stored
        let completed = queues.complete_fetch(&key);
        assert!(
            completed.is_some(),
            "should have in-flight entry to complete"
        );
        assert_eq!(queues.in_flight_count(), 0);
        assert!(
            !queues.contains_key(&key),
            "key should be fully processed out of pipeline"
        );
    }

    // -- capacity gate -----------------------------------------------------

    /// Deferral moves the next look, not the entry's birth, so a blocked key
    /// still ages out on the ordinary schedule.
    ///
    /// This is why the change carries no eviction protection for deferred keys:
    /// protecting them would preserve, against a bounded queue, exactly the duty
    /// a full node cannot discharge. The deferred key here is older than the age
    /// limit and the control is not, so the assertion fails both if deferral
    /// exempted a key from eviction and if it refreshed `created_at` — either
    /// would let a full node hold entries indefinitely.
    ///
    /// What this does not show: that either gate calls `defer_pending`. The
    /// gates need a network, so the e2e covers them.
    #[test]
    fn capacity_deferral_does_not_extend_entry_lifetime() {
        // Small enough that the back-dated instant is representable on a
        // machine that only just booted, wide enough that the control cannot
        // age out while three in-memory queue operations run.
        const MAX_AGE: Duration = Duration::from_secs(1);

        let mut queues = ReplicationQueues::new();
        let aged = xor_name_from_byte(1);
        let fresh = xor_name_from_byte(2);

        let mut aged_entry = test_entry(1);
        aged_entry.created_at = Instant::now()
            .checked_sub(MAX_AGE * 2)
            .expect("backdate the aged entry");
        assert!(queues.add_pending_verify(aged, aged_entry).admitted());
        assert!(queues.add_pending_verify(fresh, test_entry(2)).admitted());

        // The deferral puts the next look beyond the age limit, so an eviction
        // that read the next look instead of the creation time would spare it.
        assert!(queues.defer_pending(&aged, CAPACITY_BLOCKED_RETRY));

        let evicted = queues.evict_stale(MAX_AGE);
        assert!(
            evicted.contains(&aged),
            "a capacity-deferred key must still age out on its creation time"
        );
        assert!(
            !evicted.contains(&fresh),
            "the age limit, not the deferral, is what retires an entry"
        );
        assert_eq!(queues.pending_count(), 1);
    }
}
