//! Storage-bound audit via piggybacked commitments.
//!
//! Implements the v12 storage-bound audit design: it closes the
//! storage-binding holes where a node could pass audits while holding chunk
//! addresses (not bytes), or answer against a commitment it never gossiped.
//!
//! ## What this module provides
//!
//! - [`StorageCommitment`] — the wire type sent on neighbour-sync gossip
//!   and embedded in commitment-bound audit responses. `ML-DSA-65` signed
//!   over `(root, key_count, sender_peer_id)` with explicit domain separation.
//! - [`MerkleTree`] — an in-memory Merkle tree over `(key, BLAKE3(bytes))`
//!   leaves. Rebuilt by the responder when its key set changes; produces
//!   inclusion paths used in audit responses.
//! - [`commitment_hash`] — the auditor's pin: a `BLAKE3` digest over the
//!   full signed commitment blob. Audit challenges carry this; audit
//!   responses must include a commitment that hashes to the same value.
//! - [`verify_path`] — auditor's per-key check: rebuilds the leaf from
//!   `(key, bytes_hash)` and verifies the inclusion path against the
//!   committed root.
//!
//! Nothing else (responder gossip loop, auditor verify path,
//! reward-eligibility cache) lives here yet — that's the next phase.

use blake3::Hasher;
use saorsa_pqc::api::sig::{ml_dsa_65, MlDsaSecretKey};

use crate::ant_protocol::XorName;

// ADR-0004: the commitment wire type, its pin (`commitment_hash`), its
// signature verification, and the key-count cap are the SINGLE SOURCE OF TRUTH
// in `ant-protocol` so the paying client and the node verify identically.
// Re-exported here so all existing `crate::replication::commitment::…` callers
// keep resolving. The Merkle tree, inclusion paths, and signing stay node-side
// below (the client never builds or signs a commitment, only verifies one).
pub use ::ant_protocol::payment::commitment::{
    commitment_hash, verify_commitment_signature, StorageCommitment, DOMAIN_COMMITMENT,
    DOMAIN_COMMITMENT_HASH, MAX_COMMITMENT_KEY_COUNT, MAX_COMMITMENT_SIDECAR_BYTES,
};

/// Domain-separation tag for Merkle leaves: `BLAKE3(this || key || H(bytes))`.
pub const DOMAIN_LEAF: &[u8] = b"autonomi.ant.replication.storage_leaf.v1";

/// Domain-separation tag for Merkle internal nodes: `BLAKE3(this || left || right)`.
pub const DOMAIN_NODE: &[u8] = b"autonomi.ant.replication.storage_node.v1";

// `MAX_COMMITMENT_KEY_COUNT` and `StorageCommitment` are re-exported from
// `ant-protocol` above (single source of truth); their fields and wire size are
// documented there.

// ---------------------------------------------------------------------------
// Hashing helpers
// ---------------------------------------------------------------------------

/// Compute the Merkle leaf hash for `(key, bytes_hash)`.
///
/// `bytes_hash` is BLAKE3 over the record bytes; the leaf binds the key to
/// the content so an adversary cannot reuse a leaf for a different chunk.
#[must_use]
pub fn leaf_hash(key: &XorName, bytes_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_LEAF);
    h.update(key);
    h.update(bytes_hash);
    *h.finalize().as_bytes()
}

/// Combine two child hashes into a Merkle internal-node hash.
#[must_use]
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_NODE);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

// `commitment_hash` is re-exported from `ant-protocol` above (single source of
// truth for the pin), so the paying client and the node compute the same pin.

/// Canonical bytes the ML-DSA signature covers: the commitment fields
/// minus the signature itself.
///
/// `sender_public_key` is included so an adversary cannot keep the body
/// and re-sign under a different key (the audit-time verifier would
/// otherwise accept the swap because verification uses the embedded key).
fn commitment_signed_payload(
    root: &[u8; 32],
    key_count: u32,
    sender_peer_id: &[u8; 32],
    sender_public_key: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + 4 + 32 + 4 + sender_public_key.len());
    v.extend_from_slice(root);
    v.extend_from_slice(&key_count.to_le_bytes());
    v.extend_from_slice(sender_peer_id);
    // Length-prefix the pubkey so two different (key, suffix) splits cannot
    // produce the same byte stream (canonical encoding).
    let pk_len = u32::try_from(sender_public_key.len()).unwrap_or(u32::MAX);
    v.extend_from_slice(&pk_len.to_le_bytes());
    v.extend_from_slice(sender_public_key);
    v
}

// ---------------------------------------------------------------------------
// Merkle tree
// ---------------------------------------------------------------------------

/// In-memory Merkle tree over the responder's claimed keys.
///
/// Leaves are `BLAKE3(DOMAIN_LEAF || key || BLAKE3(bytes))`, sorted by
/// `key`. Internal nodes are `BLAKE3(DOMAIN_NODE || left || right)`. When
/// a level has an odd number of nodes, the last node is paired with
/// **itself** — i.e. `node_hash(x, x)` — so the level above has
/// `ceil(n/2)` nodes. This is a standard self-pair construction (NOT
/// node promotion) and deterministically maps any non-empty key set to
/// a single root.
///
/// Rebuilt by the responder whenever its key set changes meaningfully
/// (debounced in the integration layer; not this module's concern).
pub struct MerkleTree {
    /// Sorted leaves, indexed by their position in the sorted key set.
    ///
    /// `leaves[i] = (key_i, leaf_hash(key_i, bytes_hash_i))`.
    leaves: Vec<(XorName, [u8; 32])>,
    /// Tree levels, level 0 is the leaves and the last level is the root.
    ///
    /// `levels[0].len() == leaves.len()`; `levels[L].len() == 1` where L
    /// is the root level.
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Build a Merkle tree over `(key, bytes_hash)` pairs.
    ///
    /// `entries` does not need to be sorted; this method sorts internally
    /// so the produced root is deterministic per key set. Duplicate keys
    /// are an error: the responder must deduplicate before calling.
    ///
    /// # Errors
    ///
    /// Returns an error if `entries` is empty (no commitment to make), if
    /// `entries.len() > MAX_COMMITMENT_KEY_COUNT`, or if it contains
    /// duplicate keys.
    pub fn build(mut entries: Vec<(XorName, [u8; 32])>) -> Result<Self, CommitmentError> {
        if entries.is_empty() {
            return Err(CommitmentError::EmptyKeySet);
        }
        if entries.len() > MAX_COMMITMENT_KEY_COUNT as usize {
            return Err(CommitmentError::TooManyKeys(entries.len()));
        }

        entries.sort_by_key(|a| a.0);
        for w in entries.windows(2) {
            if let [a, b] = w {
                if a.0 == b.0 {
                    return Err(CommitmentError::DuplicateKey(a.0));
                }
            }
        }

        let leaves: Vec<(XorName, [u8; 32])> = entries
            .into_iter()
            .map(|(k, bh)| {
                let lh = leaf_hash(&k, &bh);
                (k, lh)
            })
            .collect();

        let mut level: Vec<[u8; 32]> = leaves.iter().map(|(_, h)| *h).collect();
        let mut levels = vec![level.clone()];
        while level.len() > 1 {
            level = build_next_level(&level);
            levels.push(level.clone());
        }

        Ok(Self { leaves, levels })
    }

    /// The Merkle root of this tree.
    ///
    /// `unwrap`-free: `build` guarantees at least one level with at least
    /// one entry, so `last().first()` is always `Some`.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        // SAFETY: build() enforces non-empty entries → non-empty leaves →
        // non-empty levels → last level has exactly one hash.
        self.levels
            .last()
            .and_then(|l| l.first())
            .copied()
            .unwrap_or([0u8; 32])
    }

    /// The number of leaves (== claimed keys).
    #[must_use]
    pub fn key_count(&self) -> u32 {
        // Cast is safe because build() rejects > MAX_COMMITMENT_KEY_COUNT.
        u32::try_from(self.leaves.len()).unwrap_or(u32::MAX)
    }

    /// The committed leaf keys, in the tree's sorted order. Lets a persisted
    /// commitment be rebuilt from its key set alone — `MerkleTree::build(keys
    /// .map(|k| (k, k)))` for content-addressed leaves — without re-reading
    /// chunks, so a restart can restore the exact signed root (ADR-0004 A1).
    #[must_use]
    pub fn leaf_keys(&self) -> Vec<XorName> {
        self.leaves.iter().map(|(k, _)| *k).collect()
    }

    /// Inclusion path for `key` from its leaf up to (but not including)
    /// the root.
    ///
    /// Returns `None` if `key` is not in this tree.
    #[must_use]
    pub fn path_for(&self, key: &XorName) -> Option<Vec<[u8; 32]>> {
        let idx = self.leaves.binary_search_by(|(k, _)| k.cmp(key)).ok()?;

        let mut path = Vec::with_capacity(self.levels.len());
        let mut i = idx;
        for level in &self.levels[..self.levels.len().saturating_sub(1)] {
            // Sibling is the *other* half of the pair containing `i`. If
            // `i` is the unpaired last node at this level, its sibling is
            // itself (matches the self-pair construction in
            // `build_next_level`).
            let sibling_idx = if i % 2 == 0 {
                if i + 1 < level.len() {
                    i + 1
                } else {
                    i
                }
            } else {
                i - 1
            };
            path.push(level[sibling_idx]);
            i /= 2;
        }
        Some(path)
    }

    /// Iterate over `(key, leaf_hash)` pairs in sorted order. Test-only.
    #[cfg(test)]
    pub(crate) fn iter_leaves(&self) -> impl Iterator<Item = &(XorName, [u8; 32])> {
        self.leaves.iter()
    }

    /// The keys this tree commits to, in sorted order.
    ///
    /// `sorted_keys()[i]` is the key at leaf index `i`. Used by the
    /// responder's audit-answer path to recover the `leaf_index` field
    /// for a challenged key in `O(log n)` via binary search.
    #[must_use]
    pub fn sorted_keys(&self) -> Vec<XorName> {
        self.leaves.iter().map(|(k, _)| *k).collect()
    }

    /// The key at sorted leaf index `idx`, if in range.
    ///
    /// Used by the subtree-proof builder to enumerate the keys of a
    /// contiguous leaf range without cloning the whole key list.
    #[must_use]
    pub fn key_at(&self, idx: usize) -> Option<XorName> {
        self.leaves.get(idx).map(|(k, _)| *k)
    }

    /// The sorted leaf index of `key`, if committed. `O(log n)` binary search
    /// over the (key-sorted) leaves — no separate key list needed, so callers
    /// don't have to keep a duplicate `sorted_keys` Vec alongside the tree.
    #[must_use]
    pub fn key_index(&self, key: &XorName) -> Option<usize> {
        self.leaves.binary_search_by(|(k, _)| k.cmp(key)).ok()
    }

    /// Whether `key` is committed. Allocation-free membership check via the same
    /// binary search as [`Self::key_index`].
    #[must_use]
    pub fn contains_key(&self, key: &XorName) -> bool {
        self.key_index(key).is_some()
    }

    /// The node hash at `(level, index)`, where `level` counts up from the
    /// leaves (`level == 0` is the leaf level, the last level is the root).
    ///
    /// Returns `None` if out of range. Used by the subtree-proof builder to
    /// read sibling cut-hashes along the path from the root to the selected
    /// subtree; honours the same left-packed self-pair construction as the
    /// rest of the tree (a caller asking for an out-of-range sibling on an
    /// odd-length level should substitute the node itself).
    #[must_use]
    pub fn node_at(&self, level: usize, index: u64) -> Option<[u8; 32]> {
        let index = usize::try_from(index).ok()?;
        self.levels.get(level).and_then(|l| l.get(index)).copied()
    }

    /// The number of levels in the tree (`1` for a single-leaf tree; the
    /// last index is the root level). `depth == levels_count() - 1`.
    #[must_use]
    pub fn levels_count(&self) -> usize {
        self.levels.len()
    }
}

/// Build the next level up from `cur`. Odd-length levels pair the last
/// node with itself (`node_hash(x, x)`) so the level above has
/// `ceil(n/2)` nodes. Keeps the tree balanced without needing a dummy
/// leaf domain.
///
/// `pub(crate)` so the subtree-proof verifier folds a contiguous leaf block to
/// its subtree root with the EXACT same self-pair rule (§10 — previously
/// duplicated as `fold_levels`'s inner loop), guaranteeing the rebuilt node
/// matches the committed tree bit-for-bit.
pub(crate) fn build_next_level(cur: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut next = Vec::with_capacity(cur.len().div_ceil(2));
    let mut i = 0;
    while i < cur.len() {
        let left = &cur[i];
        let right = if i + 1 < cur.len() { &cur[i + 1] } else { left };
        next.push(node_hash(left, right));
        i += 2;
    }
    next
}

/// Verify an inclusion path against a commitment of size `key_count`.
///
/// `leaf_index` is the responder's position of this leaf in the sorted
/// leaf set; the commitment's `key_count` comes from
/// `StorageCommitment.key_count`.
/// At each level of the path, if the current index is even, the current
/// hash is the left child and we compute `node_hash(self, sibling)`;
/// otherwise it is the right child and we compute `node_hash(sibling, self)`.
///
/// Returns `true` iff:
///   - `leaf_index < key_count` (rejects out-of-range claims), AND
///   - `path.len() == ceil(log2(key_count))` for `key_count > 1`, or
///     `path.is_empty()` for `key_count == 1` (rejects wrong-shape paths
///     before doing any hashing), AND
///   - the recomputed root equals `expected_root`.
#[must_use]
pub fn verify_path(
    leaf: &[u8; 32],
    path: &[[u8; 32]],
    leaf_index: usize,
    key_count: u32,
    expected_root: &[u8; 32],
) -> bool {
    if key_count == 0
        || key_count > MAX_COMMITMENT_KEY_COUNT
        || (leaf_index as u64) >= u64::from(key_count)
    {
        return false;
    }
    // Tree depth = ceil(log2(key_count)). For a power-of-two `n`,
    // `n.next_power_of_two() == n` so trailing_zeros == log2(n). For non
    // powers-of-two, next_power_of_two rounds up so trailing_zeros gives
    // ceil(log2). Special case: key_count == 1 → next_power_of_two == 1
    // → trailing_zeros == 0 → empty path, which matches the single-leaf
    // tree's root == leaf invariant.
    //
    // `checked_next_power_of_two` returns None on overflow; combined with
    // the MAX_COMMITMENT_KEY_COUNT cap above it cannot fail in practice,
    // but the explicit check is profile-independent (release vs debug
    // would otherwise differ on overflow per Rust's primitive docs).
    let Some(rounded) = key_count.checked_next_power_of_two() else {
        return false;
    };
    let expected_path_len = rounded.trailing_zeros() as usize;
    if path.len() != expected_path_len {
        return false;
    }

    let mut cur = *leaf;
    let mut i = leaf_index;
    for sibling in path {
        cur = if i.is_multiple_of(2) {
            node_hash(&cur, sibling)
        } else {
            node_hash(sibling, &cur)
        };
        i /= 2;
    }
    cur == *expected_root
}

// ---------------------------------------------------------------------------
// Sign + verify
// ---------------------------------------------------------------------------

/// Sign a commitment's `(root, key_count, sender_peer_id, sender_public_key)`
/// with `secret_key`.
///
/// The signature is over the canonical signed payload (see
/// `commitment_signed_payload`) under [`DOMAIN_COMMITMENT`].
///
/// # Errors
///
/// Returns an error if the underlying ML-DSA-65 signer fails.
pub fn sign_commitment(
    secret_key: &MlDsaSecretKey,
    root: &[u8; 32],
    key_count: u32,
    sender_peer_id: &[u8; 32],
    sender_public_key: &[u8],
) -> Result<Vec<u8>, CommitmentError> {
    let payload = commitment_signed_payload(root, key_count, sender_peer_id, sender_public_key);
    let dsa = ml_dsa_65();
    let sig = dsa
        .sign_with_context(secret_key, &payload, DOMAIN_COMMITMENT)
        .map_err(|e| CommitmentError::SignatureFailed(e.to_string()))?;
    Ok(sig.to_bytes())
}

// `verify_commitment_signature` (embedded-key) is re-exported from
// `ant-protocol` above (single source of truth), so the paying client and the
// node accept exactly the same commitments. The externally-keyed variant was
// removed in the ADR-0004 move — it had no remaining callers once the embedded-
// key verify moved to `ant-protocol`.

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from commitment construction or verification.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CommitmentError {
    /// `MerkleTree::build` was called with an empty key set.
    #[error("cannot build commitment over empty key set")]
    EmptyKeySet,
    /// Key set exceeds [`MAX_COMMITMENT_KEY_COUNT`].
    #[error("commitment key count {0} exceeds MAX_COMMITMENT_KEY_COUNT")]
    TooManyKeys(usize),
    /// `MerkleTree::build` received the same key twice.
    #[error("duplicate key in commitment: {}", hex::encode(.0))]
    DuplicateKey(XorName),
    /// Underlying ML-DSA-65 signer failed.
    #[error("commitment signing failed: {0}")]
    SignatureFailed(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use saorsa_pqc::api::sig::MlDsaPublicKey;

    fn xn(byte: u8) -> XorName {
        [byte; 32]
    }

    fn bh(byte: u8) -> [u8; 32] {
        [byte ^ 0x5A; 32]
    }

    #[test]
    fn empty_key_set_rejected() {
        let result = MerkleTree::build(vec![]);
        assert!(matches!(result, Err(CommitmentError::EmptyKeySet)));
    }

    #[test]
    fn duplicate_keys_rejected() {
        let result = MerkleTree::build(vec![(xn(1), bh(1)), (xn(1), bh(2))]);
        assert!(matches!(result, Err(CommitmentError::DuplicateKey(_))));
    }

    #[test]
    fn single_leaf_tree_root_is_leaf_hash() {
        let key = xn(1);
        let bytes_hash = bh(1);
        let tree = MerkleTree::build(vec![(key, bytes_hash)]).unwrap();
        assert_eq!(tree.root(), leaf_hash(&key, &bytes_hash));
        assert_eq!(tree.key_count(), 1);
        assert_eq!(tree.path_for(&key), Some(vec![]));
        // Empty path verifies trivially (root == leaf).
        assert!(verify_path(
            &leaf_hash(&key, &bytes_hash),
            &[],
            0,
            1,
            &tree.root()
        ));
    }

    #[test]
    fn two_leaf_tree_root_combines_both_leaves() {
        let entries = vec![(xn(1), bh(1)), (xn(2), bh(2))];
        let tree = MerkleTree::build(entries).unwrap();
        // Sorted order: xn(1), xn(2).
        let l1 = leaf_hash(&xn(1), &bh(1));
        let l2 = leaf_hash(&xn(2), &bh(2));
        assert_eq!(tree.root(), node_hash(&l1, &l2));
    }

    #[test]
    fn root_is_deterministic_regardless_of_input_order() {
        let mut a = vec![(xn(3), bh(3)), (xn(1), bh(1)), (xn(2), bh(2))];
        let mut b = vec![(xn(2), bh(2)), (xn(3), bh(3)), (xn(1), bh(1))];
        let tree_a = MerkleTree::build(a.clone()).unwrap();
        let tree_b = MerkleTree::build(b.clone()).unwrap();
        a.sort_by_key(|x| x.0);
        b.sort_by_key(|x| x.0);
        assert_eq!(tree_a.root(), tree_b.root());
    }

    fn xn_u32(i: u32) -> XorName {
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(&i.to_le_bytes());
        k
    }

    fn bh_u32(i: u32) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..4].copy_from_slice(&i.to_le_bytes());
        h[4] = 0x5A;
        h
    }

    #[test]
    fn paths_verify_for_every_key_at_various_sizes() {
        for n in [1u32, 2, 3, 4, 5, 7, 8, 16, 17, 100, 333] {
            let entries: Vec<_> = (0..n).map(|i| (xn_u32(i), bh_u32(i))).collect();
            let tree = MerkleTree::build(entries.clone()).unwrap();
            let root = tree.root();
            let key_count = tree.key_count();
            for (idx, (k, _)) in tree.iter_leaves().enumerate() {
                let path = tree.path_for(k).expect("path for present key");
                let bytes_hash = entries.iter().find(|(kk, _)| kk == k).unwrap().1;
                let lh = leaf_hash(k, &bytes_hash);
                assert!(
                    verify_path(&lh, &path, idx, key_count, &root),
                    "path verify failed at n={n} idx={idx}",
                );
            }
        }
    }

    #[test]
    fn path_for_absent_key_is_none() {
        let tree = MerkleTree::build(vec![(xn(1), bh(1)), (xn(2), bh(2))]).unwrap();
        assert!(tree.path_for(&xn(99)).is_none());
    }

    #[test]
    fn tampered_bytes_hash_breaks_path_verify() {
        // Use 8 distinct sorted keys so the index in `entries` matches the
        // sorted leaf index in the tree.
        let entries: Vec<_> = (1..=8u8).map(|i| (xn(i), bh(i))).collect();
        let tree = MerkleTree::build(entries.clone()).unwrap();
        let root = tree.root();
        let (k, _) = &entries[3];
        let path = tree.path_for(k).unwrap();

        let wrong_bytes_hash = [0xFFu8; 32];
        let lh = leaf_hash(k, &wrong_bytes_hash);
        assert!(!verify_path(&lh, &path, 3, 8, &root));
    }

    #[test]
    fn tampered_path_node_breaks_verify() {
        let entries: Vec<_> = (1..=8u8).map(|i| (xn(i), bh(i))).collect();
        let tree = MerkleTree::build(entries.clone()).unwrap();
        let root = tree.root();
        let (k, _) = &entries[3];
        let mut path = tree.path_for(k).unwrap();
        path[0][0] ^= 0x01;
        let lh = leaf_hash(k, &bh(4));
        assert!(!verify_path(&lh, &path, 3, 8, &root));
    }

    #[test]
    fn wrong_leaf_index_breaks_verify() {
        let entries: Vec<_> = (1..=8u8).map(|i| (xn(i), bh(i))).collect();
        let tree = MerkleTree::build(entries.clone()).unwrap();
        let root = tree.root();
        let (k, _) = &entries[3];
        let path = tree.path_for(k).unwrap();
        let lh = leaf_hash(k, &bh(4));
        // Correct index is 3; using 2 should fail because the left/right
        // child ordering swaps.
        assert!(!verify_path(&lh, &path, 2, 8, &root));
        assert!(verify_path(&lh, &path, 3, 8, &root));
    }

    #[test]
    fn out_of_range_leaf_index_rejected() {
        let entries: Vec<_> = (1..=8u8).map(|i| (xn(i), bh(i))).collect();
        let tree = MerkleTree::build(entries.clone()).unwrap();
        let root = tree.root();
        let (k, _) = &entries[3];
        let path = tree.path_for(k).unwrap();
        let lh = leaf_hash(k, &bh(4));
        // leaf_index >= key_count must be rejected without even hashing.
        assert!(!verify_path(&lh, &path, 8, 8, &root));
        assert!(!verify_path(&lh, &path, 99, 8, &root));
        // Valid baseline.
        assert!(verify_path(&lh, &path, 3, 8, &root));
    }

    #[test]
    fn wrong_path_length_rejected_pre_hashing() {
        let entries: Vec<_> = (1..=8u8).map(|i| (xn(i), bh(i))).collect();
        let tree = MerkleTree::build(entries.clone()).unwrap();
        let root = tree.root();
        let (k, _) = &entries[3];
        let path = tree.path_for(k).unwrap();
        let lh = leaf_hash(k, &bh(4));
        // For key_count=8 the expected path length is 3 (ceil(log2(8))=3).
        assert_eq!(path.len(), 3);
        // Truncating breaks structural check.
        let short: Vec<_> = path.iter().take(2).copied().collect();
        assert!(!verify_path(&lh, &short, 3, 8, &root));
        // Padding too long also breaks structural check.
        let mut long = path;
        long.push([0; 32]);
        assert!(!verify_path(&lh, &long, 3, 8, &root));
    }

    #[test]
    fn zero_key_count_rejected() {
        // Defensive: even with an empty path and correct-shape root, a
        // commitment claiming zero keys is nonsensical.
        let lh = [0u8; 32];
        assert!(!verify_path(&lh, &[], 0, 0, &[0u8; 32]));
    }

    #[test]
    fn out_of_protocol_key_count_rejected() {
        // Wire-supplied key_count exceeding MAX_COMMITMENT_KEY_COUNT is
        // refused before any hashing. Guards an overflow found in review:
        // `next_power_of_two()` would otherwise panic in debug and wrap in
        // release on key_count > 1 << 31.
        let lh = [0u8; 32];
        assert!(!verify_path(
            &lh,
            &[],
            0,
            MAX_COMMITMENT_KEY_COUNT + 1,
            &[0u8; 32]
        ));
        assert!(!verify_path(&lh, &[], 0, u32::MAX, &[0u8; 32]));
    }

    fn pk_bytes(pk: &MlDsaPublicKey) -> Vec<u8> {
        pk.to_bytes()
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let dsa = ml_dsa_65();
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let entries: Vec<_> = (0..5u8).map(|i| (xn(i), bh(i))).collect();
        let tree = MerkleTree::build(entries).unwrap();
        let root = tree.root();
        let key_count = tree.key_count();
        let peer_id = [0xAB; 32];
        let pk_b = pk_bytes(&pk);
        let signature = sign_commitment(&sk, &root, key_count, &peer_id, &pk_b).unwrap();
        let c = StorageCommitment {
            root,
            key_count,
            sender_peer_id: peer_id,
            sender_public_key: pk_b,
            signature,
        };
        // Verifies via embedded key, no external lookup needed.
        assert!(verify_commitment_signature(&c));
    }

    #[test]
    fn signature_fails_when_root_tampered() {
        let dsa = ml_dsa_65();
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let root = [0u8; 32];
        let pk_b = pk_bytes(&pk);
        let signature = sign_commitment(&sk, &root, 1, &[0; 32], &pk_b).unwrap();
        let c = StorageCommitment {
            root: [1u8; 32], // tampered
            key_count: 1,
            sender_peer_id: [0; 32],
            sender_public_key: pk_b,
            signature,
        };
        assert!(!verify_commitment_signature(&c));
    }

    #[test]
    fn signature_fails_under_swapped_public_key() {
        let dsa = ml_dsa_65();
        let (pk1, sk1) = dsa.generate_keypair().unwrap();
        let (pk2, _sk2) = dsa.generate_keypair().unwrap();
        let pk1_b = pk_bytes(&pk1);
        let pk2_b = pk_bytes(&pk2);
        // Sign under pk1 but embed pk2 — verification (using embedded key)
        // should fail because pk2 didn't sign this payload AND because the
        // signed payload binds pk1, not pk2.
        let signature = sign_commitment(&sk1, &[0u8; 32], 1, &[0; 32], &pk1_b).unwrap();
        let c = StorageCommitment {
            root: [0u8; 32],
            key_count: 1,
            sender_peer_id: [0; 32],
            sender_public_key: pk2_b,
            signature,
        };
        assert!(!verify_commitment_signature(&c));
    }

    #[test]
    fn signature_fails_with_garbage_bytes() {
        let dsa = ml_dsa_65();
        let (pk, _sk) = dsa.generate_keypair().unwrap();
        let c = StorageCommitment {
            root: [0u8; 32],
            key_count: 1,
            sender_peer_id: [0; 32],
            sender_public_key: pk_bytes(&pk),
            signature: vec![0u8; 100], // too short and zero-filled
        };
        assert!(!verify_commitment_signature(&c));
    }

    #[test]
    fn signature_fails_with_garbage_public_key() {
        // Embedded pubkey is wrong length / invalid → from_bytes fails →
        // verify returns false. Defends against malformed gossip.
        let c = StorageCommitment {
            root: [0u8; 32],
            key_count: 1,
            sender_peer_id: [0; 32],
            sender_public_key: vec![0u8; 100], // wrong length
            signature: vec![0u8; 3293],
        };
        assert!(!verify_commitment_signature(&c));
    }

    #[test]
    fn commitment_hash_differs_on_any_field_change() {
        let dsa = ml_dsa_65();
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let pk_b = pk_bytes(&pk);
        let sig = sign_commitment(&sk, &[0; 32], 1, &[0; 32], &pk_b).unwrap();
        let c1 = StorageCommitment {
            root: [0; 32],
            key_count: 1,
            sender_peer_id: [0; 32],
            sender_public_key: pk_b,
            signature: sig,
        };
        let h1 = commitment_hash(&c1).unwrap();

        let mut c2 = c1.clone();
        c2.root = [1; 32];
        assert_ne!(h1, commitment_hash(&c2).unwrap());

        let mut c3 = c1.clone();
        c3.key_count = 2;
        assert_ne!(h1, commitment_hash(&c3).unwrap());

        let mut c4 = c1.clone();
        c4.sender_peer_id = [1; 32];
        assert_ne!(h1, commitment_hash(&c4).unwrap());

        let mut c5 = c1.clone();
        c5.signature[0] ^= 1;
        assert_ne!(h1, commitment_hash(&c5).unwrap());

        let (pk_other, _) = dsa.generate_keypair().unwrap();
        let mut c6 = c1;
        c6.sender_public_key = pk_bytes(&pk_other);
        assert_ne!(h1, commitment_hash(&c6).unwrap());
    }

    #[test]
    fn commitment_hash_stable_for_identical_input() {
        let dsa = ml_dsa_65();
        let (pk, sk) = dsa.generate_keypair().unwrap();
        let pk_b = pk_bytes(&pk);
        let sig = sign_commitment(&sk, &[7; 32], 42, &[3; 32], &pk_b).unwrap();
        let c = StorageCommitment {
            root: [7; 32],
            key_count: 42,
            sender_peer_id: [3; 32],
            sender_public_key: pk_b,
            signature: sig,
        };
        assert_eq!(commitment_hash(&c), commitment_hash(&c));
    }

    #[test]
    fn commitment_hash_signature_length_change_changes_hash() {
        // Postcard's varint length prefix means hashing a 1-byte signature
        // and a 2-byte signature whose first byte is the same produces
        // different commitment hashes — a hash that omitted the serialized
        // length prefix would let boundary-shifted fields collide.
        let c1 = StorageCommitment {
            root: [0; 32],
            key_count: 1,
            sender_peer_id: [0; 32],
            sender_public_key: vec![0u8; 1952],
            signature: vec![0xAB],
        };
        let c2 = StorageCommitment {
            root: [0; 32],
            key_count: 1,
            sender_peer_id: [0; 32],
            sender_public_key: vec![0u8; 1952],
            signature: vec![0xAB, 0x00],
        };
        assert_ne!(commitment_hash(&c1).unwrap(), commitment_hash(&c2).unwrap());
    }

    #[test]
    fn too_many_keys_rejected() {
        let mut entries = Vec::with_capacity(MAX_COMMITMENT_KEY_COUNT as usize + 1);
        for i in 0..=MAX_COMMITMENT_KEY_COUNT {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&i.to_le_bytes());
            entries.push((k, [0; 32]));
        }
        let result = MerkleTree::build(entries);
        assert!(matches!(result, Err(CommitmentError::TooManyKeys(_))));
    }
}
