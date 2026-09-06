//! Holder-eligibility cache: which peers recently proved storage of
//! which key, against which commitment.
//!
//! Phase 2d of the v12 storage-bound audit design (`notes/security-
//! findings-2026-05-22/proposal-gossip-audit-v12.md`).
//!
//! When the auditor successfully verifies a commitment-bound audit for
//! peer P on key K (against P's currently-credited commitment hash H),
//! it inserts `(P, H, now)` into `recent_provers[K]`. Reward / quorum
//! eligibility for P-as-holder-of-K then checks that this cache entry
//! still matches P's *currently credited* commitment hash; if P rotates
//! the hash via fresh gossip, the cache entry becomes stale and credit
//! is denied until the next successful audit against the new hash.
//!
//! Invariants enforced here:
//!
//! - **Per-key cap**: at most [`MAX_PROVERS_PER_KEY`] entries per key,
//!   LRU-evicted by `proved_at`. Bounds the per-key working set so a
//!   well-replicated key cannot fill memory.
//! - **RT-only**: only peers in the caller's routing table populate
//!   entries — the caller is responsible for filtering before
//!   [`RecentProvers::record_proof`]; this module just stores what it's
//!   told.
//! - **Hash-bound credit**: [`RecentProvers::is_credited_holder`]
//!   requires the cache entry's `commitment_hash` to match the peer's
//!   *current* `commitment_hash`. A peer who proves K under C1 then
//!   rotates to C2 loses credit until re-proving K under C2.
//!
//! - **TTL**: entries older than [`PROVER_ENTRY_TTL`] are ignored by
//!   [`RecentProvers::is_credited_holder`] on read, and
//!   [`RecentProvers::sweep_expired`] reclaims their memory when a
//!   caller invokes it (e.g. periodically from the engine).
//! - **`PeerRemoved` cleanup**: the caller should call
//!   [`RecentProvers::forget_peer`] when a peer leaves the routing
//!   table to drop their entries immediately (faster than waiting for
//!   TTL).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use saorsa_core::identity::PeerId;

use crate::ant_protocol::XorName;

/// Maximum number of cached provers per key.
///
/// Comfortably above `CLOSE_GROUP_SIZE = 7` (a key has at most 7 responsible
/// holders), leaving slack slots for churn without unbounded growth.
/// LRU-evicted within the cap.
pub const MAX_PROVERS_PER_KEY: usize = 16;

/// Maximum age of a cached prover entry before it is considered stale.
///
/// A proof older than this is treated as "no credit" by
/// [`RecentProvers::is_credited_holder`] even if the commitment hash
/// still matches.
///
/// v10/v12 §6 spec: `RECENT_PROOF_TTL = 2 × max audit interval` (≈40 min
/// at the default 20 min max). Setting too low → peers fall out of
/// credit between audits. Setting too high → lazy node has more leeway
/// before re-audit is required. 40 min comfortably covers one audit
/// cycle on the average peer while still requiring re-proof inside the
/// rotation window.
pub const PROVER_ENTRY_TTL: Duration = Duration::from_mins(40);

/// One cached prover entry: who proved the key, when, and against which
/// commitment.
#[derive(Debug, Clone, Copy)]
pub struct ProverEntry {
    /// The peer that produced the audit proof.
    pub peer_id: PeerId,
    /// When the proof was recorded. Used for LRU eviction.
    pub proved_at: Instant,
    /// The peer's commitment hash at proof time. Holder-eligibility
    /// requires this to match the peer's *currently credited* hash.
    pub commitment_hash: [u8; 32],
}

/// Per-key cache of recent provers, capped at [`MAX_PROVERS_PER_KEY`].
#[derive(Debug, Default, Clone)]
pub struct RecentProvers {
    /// `entries[K]` is the per-key bounded list. Entries are kept sorted
    /// by `proved_at` ascending so eviction is `O(1)` (drop head).
    entries: HashMap<XorName, Vec<ProverEntry>>,
}

impl RecentProvers {
    /// Empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `peer_id` proved storage of `key` under commitment
    /// `commitment_hash` at `proved_at`.
    ///
    /// If the same `(peer_id, commitment_hash)` is already cached for
    /// this key, the entry is updated in place (refreshes `proved_at`).
    /// Otherwise a new entry is appended, evicting the oldest entry if
    /// the per-key cap would be exceeded.
    pub fn record_proof(
        &mut self,
        key: XorName,
        peer_id: PeerId,
        commitment_hash: [u8; 32],
        proved_at: Instant,
    ) {
        let bucket = self.entries.entry(key).or_default();

        // Refresh-in-place if the (peer, hash) already exists.
        for e in bucket.iter_mut() {
            if e.peer_id == peer_id && e.commitment_hash == commitment_hash {
                e.proved_at = proved_at;
                bucket.sort_by_key(|e| e.proved_at);
                return;
            }
        }

        // Evict the oldest entry if we're at the cap.
        if bucket.len() >= MAX_PROVERS_PER_KEY {
            // bucket is sorted ascending; oldest is index 0.
            bucket.remove(0);
        }

        bucket.push(ProverEntry {
            peer_id,
            proved_at,
            commitment_hash,
        });
        bucket.sort_by_key(|e| e.proved_at);
    }

    /// Is `peer_id` currently credited as a holder of `key`?
    ///
    /// Returns `true` iff there is a non-stale cached entry with `peer_id`
    /// and `commitment_hash == current_commitment_hash`.
    ///
    /// "Non-stale" means `now - proved_at < PROVER_ENTRY_TTL`. The hash
    /// binding is the v12 §6 lever: a peer that rotates their commitment
    /// must re-prove every key they want credit for. The TTL is a
    /// secondary safety net that revokes credit even if the hash
    /// happens to match (e.g. a peer who proved long ago but has been
    /// silent or offline since).
    #[must_use]
    pub fn is_credited_holder(
        &self,
        key: &XorName,
        peer_id: &PeerId,
        current_commitment_hash: &[u8; 32],
    ) -> bool {
        let now = Instant::now();
        self.entries.get(key).is_some_and(|bucket| {
            bucket.iter().any(|e| {
                &e.peer_id == peer_id
                    && &e.commitment_hash == current_commitment_hash
                    && now.saturating_duration_since(e.proved_at) < PROVER_ENTRY_TTL
            })
        })
    }

    /// Sweep entries older than [`PROVER_ENTRY_TTL`] across all keys.
    ///
    /// Returns the number of entries dropped. Intended for periodic
    /// invocation by a background task; `is_credited_holder` already
    /// honours the TTL on read, so the sweep only reclaims memory.
    pub fn sweep_expired(&mut self, now: Instant) -> usize {
        let mut dropped = 0;
        for bucket in self.entries.values_mut() {
            let before = bucket.len();
            bucket.retain(|e| now.saturating_duration_since(e.proved_at) < PROVER_ENTRY_TTL);
            dropped += before - bucket.len();
        }
        self.entries.retain(|_, b| !b.is_empty());
        dropped
    }

    /// Drop every cached entry for `peer_id` across all keys.
    ///
    /// Called when a peer leaves the routing table (RT-only invariant)
    /// or on explicit eviction.
    pub fn forget_peer(&mut self, peer_id: &PeerId) {
        for bucket in self.entries.values_mut() {
            bucket.retain(|e| &e.peer_id != peer_id);
        }
        self.entries.retain(|_, b| !b.is_empty());
    }

    /// Drop every entry whose `commitment_hash` matches `stale_hash`
    /// (used when the auditor invalidates a peer's `last_commitment` —
    /// e.g. on `UnknownCommitmentHash` rejection — to remove the cached
    /// proofs against that no-longer-valid commitment).
    pub fn forget_commitment(&mut self, stale_hash: &[u8; 32]) {
        for bucket in self.entries.values_mut() {
            bucket.retain(|e| &e.commitment_hash != stale_hash);
        }
        self.entries.retain(|_, b| !b.is_empty());
    }

    /// Number of cached entries for `key`. Test/observability helper.
    #[must_use]
    pub fn provers_for(&self, key: &XorName) -> usize {
        self.entries.get(key).map_or(0, Vec::len)
    }

    /// Total number of cached entries across all keys.
    #[must_use]
    pub fn total_entries(&self) -> usize {
        self.entries.values().map(Vec::len).sum()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn peer(byte: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        PeerId::from_bytes(bytes)
    }

    fn key(byte: u8) -> XorName {
        let mut k = [0u8; 32];
        k[0] = byte;
        k
    }

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn empty_cache_credits_no_one() {
        let cache = RecentProvers::new();
        assert!(!cache.is_credited_holder(&key(1), &peer(1), &hash(1)));
        assert_eq!(cache.total_entries(), 0);
    }

    #[test]
    fn recorded_proof_credits_under_same_hash() {
        let mut cache = RecentProvers::new();
        cache.record_proof(key(1), peer(7), hash(0xAB), Instant::now());
        assert!(cache.is_credited_holder(&key(1), &peer(7), &hash(0xAB)));
    }

    #[test]
    fn rotated_hash_loses_credit() {
        // Core v12 §6 attack-bound property: a peer who proves K under
        // C1 must re-prove under C2 to keep credit. The cache entry's
        // hash binding enforces this.
        let mut cache = RecentProvers::new();
        cache.record_proof(key(1), peer(7), hash(0xAB), Instant::now());
        // Same peer, same key, but the auditor's "current" hash for
        // this peer is now different (peer gossiped a new commitment).
        assert!(!cache.is_credited_holder(&key(1), &peer(7), &hash(0xCD)));
    }

    #[test]
    fn other_peer_under_same_hash_not_credited() {
        let mut cache = RecentProvers::new();
        cache.record_proof(key(1), peer(7), hash(0xAB), Instant::now());
        assert!(!cache.is_credited_holder(&key(1), &peer(8), &hash(0xAB)));
    }

    #[test]
    fn per_key_cap_evicts_oldest() {
        let mut cache = RecentProvers::new();
        let now = Instant::now();
        // MAX_PROVERS_PER_KEY is a small usize (16). Narrow to u8 once
        // so the test loop can hand the peer-id byte directly to
        // `peer(...)` without per-iteration casts.
        let max_u8 = u8::try_from(MAX_PROVERS_PER_KEY).unwrap_or(u8::MAX);
        // Fill the bucket with MAX_PROVERS_PER_KEY + 1 distinct peers.
        for i in 0..=max_u8 {
            let t = now + Duration::from_millis(u64::from(i));
            cache.record_proof(key(1), peer(i), hash(0xAB), t);
        }
        assert_eq!(cache.provers_for(&key(1)), MAX_PROVERS_PER_KEY);
        // The oldest (peer 0) should be evicted; peer MAX should be present.
        assert!(!cache.is_credited_holder(&key(1), &peer(0), &hash(0xAB)));
        assert!(cache.is_credited_holder(&key(1), &peer(max_u8), &hash(0xAB)));
    }

    #[test]
    fn refresh_in_place_does_not_grow_bucket() {
        let mut cache = RecentProvers::new();
        let now = Instant::now();
        // Same (peer, hash) repeated three times. Bucket should stay at 1.
        cache.record_proof(key(1), peer(1), hash(0xAB), now);
        cache.record_proof(key(1), peer(1), hash(0xAB), now + Duration::from_secs(1));
        cache.record_proof(key(1), peer(1), hash(0xAB), now + Duration::from_secs(2));
        assert_eq!(cache.provers_for(&key(1)), 1);
    }

    #[test]
    fn forget_peer_drops_all_entries() {
        let mut cache = RecentProvers::new();
        let now = Instant::now();
        cache.record_proof(key(1), peer(1), hash(0xAB), now);
        cache.record_proof(key(2), peer(1), hash(0xAB), now);
        cache.record_proof(key(1), peer(2), hash(0xAB), now);
        assert_eq!(cache.total_entries(), 3);

        cache.forget_peer(&peer(1));
        assert_eq!(cache.total_entries(), 1);
        assert!(!cache.is_credited_holder(&key(1), &peer(1), &hash(0xAB)));
        assert!(cache.is_credited_holder(&key(1), &peer(2), &hash(0xAB)));
    }

    #[test]
    fn forget_peer_drops_credit_across_all_commitments() {
        // A confirmed audit failure (e.g. a `ResponsiveBootstrap` on a stale pin
        // H1) revokes ALL of the peer's holder credit, INCLUDING credit earned
        // under a newer commitment H2: the contradiction is identity-level, not
        // scoped to one key set. Another peer's credit is untouched.
        let mut cache = RecentProvers::new();
        let now = Instant::now();
        let h1 = hash(0x11);
        let h2 = hash(0x22);
        cache.record_proof(key(1), peer(1), h1, now);
        cache.record_proof(key(2), peer(1), h2, now);
        cache.record_proof(key(1), peer(2), h1, now);

        cache.forget_peer(&peer(1));

        assert!(
            !cache.is_credited_holder(&key(1), &peer(1), &h1),
            "H1 credit dropped"
        );
        assert!(
            !cache.is_credited_holder(&key(2), &peer(1), &h2),
            "H2 credit dropped too (peer-wide, not pin-scoped)"
        );
        assert!(
            cache.is_credited_holder(&key(1), &peer(2), &h1),
            "another peer's credit is preserved"
        );
    }

    #[test]
    fn forget_commitment_drops_only_matching_entries() {
        let mut cache = RecentProvers::new();
        let now = Instant::now();
        cache.record_proof(key(1), peer(1), hash(0xAB), now);
        cache.record_proof(key(1), peer(1), hash(0xCD), now);
        cache.record_proof(key(2), peer(2), hash(0xAB), now);
        assert_eq!(cache.total_entries(), 3);

        cache.forget_commitment(&hash(0xAB));
        assert_eq!(cache.total_entries(), 1);
        // Only the (peer(1), hash 0xCD) entry remains.
        assert!(cache.is_credited_holder(&key(1), &peer(1), &hash(0xCD)));
        assert!(!cache.is_credited_holder(&key(1), &peer(1), &hash(0xAB)));
        assert!(!cache.is_credited_holder(&key(2), &peer(2), &hash(0xAB)));
    }

    #[test]
    fn lazy_rotation_via_unknown_commitment_hash_drops_credit() {
        // Scenario from v12 §5 (revised UnknownCommitmentHash handler):
        //   1. Peer P proves K under C1 → cached.
        //   2. Auditor pinned to C1 sends a new challenge.
        //   3. P replies UnknownCommitmentHash (they rotated and
        //      dropped the bytes).
        //   4. Auditor invalidates last_commitment[P] AND calls
        //      forget_commitment(C1) so credit doesn't linger.
        //
        // Property checked: after forget_commitment(C1), P is no longer
        // credited as holder of K under C1.
        let mut cache = RecentProvers::new();
        cache.record_proof(key(1), peer(7), hash(0xAB), Instant::now());
        assert!(cache.is_credited_holder(&key(1), &peer(7), &hash(0xAB)));

        // Auditor detects rotation/dodge, invalidates the C1 hash.
        cache.forget_commitment(&hash(0xAB));

        assert!(!cache.is_credited_holder(&key(1), &peer(7), &hash(0xAB)));
        // And under any new hash too — the peer has to re-prove.
        assert!(!cache.is_credited_holder(&key(1), &peer(7), &hash(0xCD)));
    }
}
