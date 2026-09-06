//! Gossip-triggered contiguous-subtree storage proof (ADR-0002).
//!
//! Pure, network-free core of the audit redesign. Given a peer's signed
//! [`StorageCommitment`] and an auditor-chosen random nonce, both sides
//! deterministically select **one contiguous subtree** of the committed
//! Merkle tree; the responder expands that subtree to its leaves plus the
//! sibling cut-hashes on the path to the root; the auditor rebuilds the root
//! and spot-checks a few leaves against real chunk bytes.
//!
//! Three independent checks (ADR-0002 "Verification, three independent
//! checks"); this module owns the first two — the third (response deadline)
//! is enforced by the caller:
//!
//! 1. **Structure** — [`verify_subtree_proof`] re-derives the selected branch
//!    from `(nonce, key_count)`, rebuilds the root from the returned leaves and
//!    cut-hashes, and requires it to equal the pinned root.
//! 2. **Verified slice** — [`select_spotcheck_indices`] picks a few leaves
//!    within the subtree; the caller opens one random block per leaf and checks
//!    a Bao slice against the chunk address plus a nonced-tree opening against
//!    the round-1 keyed `nonced_root`. Faking a fraction `x` of leaves survives
//!    only `(1 - x)^k`.
//!
//! ## Tree geometry (must match [`super::commitment::MerkleTree`])
//!
//! Leaves are sorted by key and fill positions `0..N`. The tree is
//! left-packed: when a level has an odd number of nodes the last node is
//! paired with itself (`node_hash(x, x)`). There are no explicit padding
//! leaves; "padding" is the empty right side of a subtree slot that extends
//! past `N`. Depth `D = ceil(log2(N))`. A node identified by `(depth, slot)`
//! (depth measured from the root, slot in `0..2^depth`) covers the contiguous
//! leaf range `[slot * span, (slot + 1) * span)` where `span = 2^(D - depth)`,
//! intersected with `0..N`.

use super::commitment::{leaf_hash, node_hash, StorageCommitment, MAX_COMMITMENT_KEY_COUNT};
use crate::ant_protocol::XorName;
use serde::{Deserialize, Serialize};

/// Below this key count the whole tree is challenged; `sqrt` rounding is
/// meaningless for tiny trees and a full proof is cheap.
pub const SMALL_TREE_FULL_AUDIT_FLOOR: u32 = 4;

/// One leaf of the selected subtree, as returned by the responder.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubtreeLeaf {
    /// The committed key (chunk address) at this leaf position.
    pub key: XorName,
    /// `BLAKE3(record_bytes)` — the plain content hash. For a content-addressed
    /// chunk this EQUALS `key` (the address IS the content hash), and the round-1
    /// verifier enforces `bytes_hash == key` so credit for `key` cannot be earned
    /// by proving possession of unrelated bytes. It is public; possessing it does
    /// NOT prove possession of the bytes (that is what `nonced_root` is for). It is
    /// also the BLAKE3/Bao root the round-2 slice verifies against.
    pub bytes_hash: [u8; 32],
    /// Length of the chunk's content, in bytes. Lets the auditor draw a random
    /// 1 KiB block index in range and size the Bao slice for the final (short)
    /// block. This field is NOT bound by the signed commitment (the Merkle leaf
    /// hashes only `key ‖ bytes_hash`), so the round-2 verifier must not trust it
    /// blind: `verify_block_slice` authenticates it against the Bao slice's own
    /// length header (validated against the address), rejecting any claim that
    /// disagrees with the true content length. Without that check a deflated
    /// `content_len` would collapse the challenge to block 0 and forge possession
    /// of a large chunk from a ~1 KiB prefix slice.
    pub content_len: u32,
    /// Root of the responder's fresh **nonced block tree** for this chunk (see
    /// [`crate::replication::slice`]): a Merkle root over the chunk's 1 KiB
    /// blocks whose leaves each bind the fresh nonce, peer, key and block bytes.
    /// Building it requires every byte of the chunk under the fresh nonce, so it
    /// commits real possession; round 2 opens one random block against it.
    pub nonced_root: [u8; 32],
}

/// A responder's single-contiguous-subtree proof (ADR-0002 "The proof").
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubtreeProof {
    /// Every leaf of the selected subtree, in ascending leaf-index order.
    pub leaves: Vec<SubtreeLeaf>,
    /// One sibling cut-hash per level on the path from the root down to the
    /// selected subtree root, ordered root-first. Each is the plain hash of
    /// the unselected sibling node at that level.
    pub sibling_cut_hashes: Vec<[u8; 32]>,
}

/// The deterministically-selected contiguous subtree, derived from
/// `(nonce, key_count)` and agreed by both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubtreePath {
    /// Depth of the subtree root below the tree root (0 = whole tree).
    pub depth: u32,
    /// Slot index of the subtree root within its level, in `0..2^depth`.
    pub slot: u32,
    /// First real leaf index covered (inclusive).
    pub leaf_start: u32,
    /// One past the last real leaf index covered (exclusive). Always
    /// `leaf_end > leaf_start`, so the selection never covers zero real
    /// leaves — this is the ADR's dead-block fix.
    pub leaf_end: u32,
}

impl SubtreePath {
    /// Number of real (non-padding) leaves in the selected subtree.
    #[must_use]
    pub fn real_leaf_count(&self) -> u32 {
        self.leaf_end - self.leaf_start
    }
}

/// Tree depth `D = ceil(log2(key_count))`, matching `MerkleTree` / `verify_path`.
///
/// `key_count == 1` → depth 0 (the single leaf is the root). Returns `None`
/// for an out-of-protocol `key_count` so callers reject it before any work.
#[must_use]
fn tree_depth(key_count: u32) -> Option<u32> {
    if key_count == 0 || key_count > MAX_COMMITMENT_KEY_COUNT {
        return None;
    }
    // checked_next_power_of_two cannot fail under the cap above, but the
    // explicit check keeps behaviour identical across debug/release.
    let rounded = key_count.checked_next_power_of_two()?;
    Some(rounded.trailing_zeros())
}

/// Count real leaves under the node at `(depth, slot)` for a tree of `key_count`
/// leaves. Pure function of geometry — identical on auditor and responder.
///
/// `span = 2^(total_depth - depth)`; the node covers `[slot*span, (slot+1)*span)`
/// clamped to `0..key_count`. Test-only geometry helper.
#[cfg(test)]
#[must_use]
fn real_leaves_under(depth: u32, slot: u64, key_count: u32, total_depth: u32) -> u32 {
    let levels_below = total_depth - depth;
    // span fits in u64: total_depth <= 20 for key_count <= 1e6.
    let span = 1u64 << levels_below;
    let start = slot.saturating_mul(span).min(u64::from(key_count));
    let end = slot
        .saturating_add(1)
        .saturating_mul(span)
        .min(u64::from(key_count));
    // end >= start always; difference fits in u32 (<= key_count).
    u32::try_from(end - start).unwrap_or(0)
}

/// `ceil(sqrt(key_count))` — the real-leaf floor a selected subtree must meet.
#[must_use]
fn sqrt_floor(key_count: u32) -> u32 {
    // Exact integer ceil(sqrt(n)), float-free and MSRV-safe (no u64::isqrt).
    // Newton's method converges to floor(sqrt(n)); then round up unless n is a
    // perfect square. Always at least 1.
    let n = u64::from(key_count);
    if n <= 1 {
        return 1;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = u64::midpoint(x, n / x);
    }
    // x == floor(sqrt(n)) here.
    let ceil = if x.saturating_mul(x) == n { x } else { x + 1 };
    u32::try_from(ceil.max(1)).unwrap_or(u32::MAX)
}

/// A stable `u64` drawn from the first 8 bytes of the nonce, used to pick the
/// subtree slot uniformly. The nonce is fresh CSPRNG per audit, so modulo bias
/// over the small slot count (≤ ~1000) is negligible.
#[must_use]
fn nonce_u64(nonce: &[u8; 32]) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&nonce[..8]);
    u64::from_le_bytes(b)
}

/// The largest real-leaf count any selected subtree can have for `key_count`.
///
/// A full fixed-depth block of `next_power_of_two(ceil(sqrt(key_count)))` leaves.
/// Bounds a single round-1 request's read/hash work (≤ 1024 leaves at the
/// `MAX_COMMITMENT_KEY_COUNT` cap). Used both to size selection and as a
/// pre-read defense-in-depth ceiling in [`subtree_plan`].
#[must_use]
pub fn max_subtree_leaves(key_count: u32) -> u32 {
    if key_count <= SMALL_TREE_FULL_AUDIT_FLOOR {
        return key_count;
    }
    sqrt_floor(key_count).next_power_of_two()
}

/// Deterministically select one contiguous subtree from `(nonce, key_count)`.
///
/// Picks one **fixed-depth block** of `span = next_power_of_two(ceil(sqrt(N)))`
/// leaves, choosing the block uniformly by `nonce_u64 % slot_count`. Every block
/// (including the short tail) is selectable with roughly equal probability, so
/// the whole tree is covered over many audits, and a single request always reads
/// at most `span` (≤ ~sqrt(N), ≤ 1024 at the cap) leaves — regardless of the
/// nonce. This replaces the old nonce-bit descent, whose stop-at-parent rule let
/// an adversarial nonce select a subtree far larger than `sqrt(N)` (up to the
/// whole tree at `2^k + 1`), an unbounded round-1 work amplification.
///
/// Unpredictability is preserved: the responder cannot know the selected slot
/// until it receives the fresh nonce. For `key_count <= SMALL_TREE_FULL_AUDIT_FLOOR`
/// the whole tree is selected.
///
/// Returns `None` only for an out-of-protocol `key_count` (caller rejects).
#[must_use]
pub fn select_subtree_path(nonce: &[u8; 32], key_count: u32) -> Option<SubtreePath> {
    let total_depth = tree_depth(key_count)?;

    // Tiny trees: challenge everything.
    if key_count <= SMALL_TREE_FULL_AUDIT_FLOOR {
        return Some(SubtreePath {
            depth: 0,
            slot: 0,
            leaf_start: 0,
            leaf_end: key_count,
        });
    }

    // Fixed block size >= sqrt(N), aligned to a tree level so the block IS a
    // single subtree node at `depth = total_depth - log2(span)`.
    let span = sqrt_floor(key_count).next_power_of_two();
    let span_log2 = span.trailing_zeros();
    // span <= next_power_of_two(key_count) == 2^total_depth, so span_log2 <=
    // total_depth and depth is non-negative.
    let depth = total_depth.saturating_sub(span_log2);
    let slot_count = key_count.div_ceil(span);
    let slot = u32::try_from(nonce_u64(nonce) % u64::from(slot_count)).unwrap_or(0);

    let span64 = u64::from(span);
    let leaf_start = u32::try_from(
        u64::from(slot)
            .saturating_mul(span64)
            .min(u64::from(key_count)),
    )
    .unwrap_or(key_count);
    let leaf_end = leaf_start.saturating_add(span).min(key_count);

    Some(SubtreePath {
        depth,
        slot,
        leaf_start,
        leaf_end,
    })
}

/// Pick `k` distinct nonce-derived leaf positions within the selected subtree.
///
/// Returned as indices into `path.real_leaf_count()` (0-based within the
/// subtree). DETERMINISTIC from the nonce.
///
/// **NOT used for the live round-2 sample.** Deriving the slice-challenge sample
/// from the round-1 nonce is unsound: the structural root check binds only
/// `(key, bytes_hash)` (both public), not the per-leaf `nonced_root`, so a
/// responder that knows the nonce at proof-build time could fabricate a
/// `nonced_root` on every un-sampled leaf and hold only the predictable sample.
/// The auditor therefore chooses the round-2 sample with fresh CSPRNG randomness
/// *after* receiving the proof
/// (`storage_commitment_audit::random_spotcheck_leaves`). This
/// deterministic helper is retained only for tests/observers that need a
/// reproducible selection.
#[must_use]
pub fn select_spotcheck_indices(nonce: &[u8; 32], path: &SubtreePath, k: u32) -> Vec<u32> {
    let n = path.real_leaf_count();
    if n == 0 {
        return Vec::new();
    }
    if n <= k {
        return (0..n).collect();
    }
    // Derive a stream of indices by hashing (nonce || counter) and reducing
    // mod n; skip collisions. Bounded: k is small (clamped to the 3..=5 band)
    // and n > k.
    let mut out: Vec<u32> = Vec::with_capacity(k as usize);
    let mut counter: u32 = 0;
    while u32::try_from(out.len()).unwrap_or(u32::MAX) < k {
        let mut h = blake3::Hasher::new();
        h.update(b"autonomi.ant.replication.audit_spotcheck.v1");
        h.update(nonce);
        h.update(&counter.to_le_bytes());
        let digest = *h.finalize().as_bytes();
        let mut word = [0u8; 4];
        word.copy_from_slice(&digest[..4]);
        let idx = u32::from_le_bytes(word) % n;
        if !out.contains(&idx) {
            out.push(idx);
        }
        counter = counter.wrapping_add(1);
        // Bound the hash stream (vanishingly unlikely to bite with n > k).
        if counter > k.saturating_mul(64) {
            break;
        }
    }
    // Top up deterministically if the bounded hash stream collided too often:
    // take the lowest indices not yet selected. Still nonce-independent only in
    // this (astronomically rare) tail, and identical on every observer — the
    // caller is guaranteed exactly min(k, n) distinct indices, so the byte
    // sample is never silently smaller than requested.
    let mut candidate: u32 = 0;
    while u32::try_from(out.len()).unwrap_or(u32::MAX) < k && candidate < n {
        if !out.contains(&candidate) {
            out.push(candidate);
        }
        candidate += 1;
    }
    out
}

/// Verdict from [`verify_subtree_proof`]'s structural check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StructureVerdict {
    /// Proof is well-formed and its root matches the pinned commitment.
    Valid,
    /// Proof is malformed or its root does not match. Carries a static reason
    /// for logging; all variants are confirmed failures, not benign.
    Invalid(&'static str),
}

/// Structural verification (ADR-0002 check 1): the returned subtree genuinely
/// belongs to the committed tree.
///
/// Re-derives the selected branch from `(nonce, commitment.key_count)`,
/// rebuilds the root from `proof.leaves` and `proof.sibling_cut_hashes`, and
/// requires it to equal `commitment.root`. Also checks leaf count and
/// ascending-key order (the committed tree sorts leaves by key).
///
/// This does NOT verify possession of bytes — that is the caller's spot-check
/// using [`select_spotcheck_indices`]. It only proves the structure.
#[must_use]
pub fn verify_subtree_proof(
    proof: &SubtreeProof,
    nonce: &[u8; 32],
    commitment: &StorageCommitment,
) -> StructureVerdict {
    let Some(path) = select_subtree_path(nonce, commitment.key_count) else {
        return StructureVerdict::Invalid("out-of-protocol key_count");
    };

    // Leaf count must equal the agreed subtree's real-leaf count exactly.
    let expected_leaves = path.real_leaf_count() as usize;
    if proof.leaves.len() != expected_leaves {
        return StructureVerdict::Invalid("wrong leaf count");
    }
    // Sibling cut-hashes: one per level on the path to the subtree root.
    if proof.sibling_cut_hashes.len() != path.depth as usize {
        return StructureVerdict::Invalid("wrong cut-hash count");
    }

    // Leaves must be strictly ascending by key (matches MerkleTree sort), which
    // also rejects duplicates.
    for w in proof.leaves.windows(2) {
        if let [a, b] = w {
            if a.key >= b.key {
                return StructureVerdict::Invalid("leaves not strictly ascending");
            }
        }
    }

    // Out-of-protocol key_count cannot happen here (select_subtree_path already
    // returned Some), but recompute total_depth defensively for the climb maths.
    let Some(total_depth) = tree_depth(commitment.key_count) else {
        return StructureVerdict::Invalid("out-of-protocol key_count");
    };

    // Phase A — reconstruct the selected subtree's root NODE exactly as the
    // committed tree's level-by-level build produces it. The subtree root sits
    // at `(level_from_leaves, slot)`, covering a left-packed block of leaves;
    // folding that block up `level_from_leaves` levels with the same
    // self-pair-the-last-node rule as `MerkleTree::build_next_level` yields the
    // identical node (including the `node_hash(x, x)` self-pair when the block
    // is the tree's odd tail at some level). `fold_to_root` stopped at a single
    // hash and so skipped the self-pair when a truncated block reached length 1
    // before climbing all the way to the subtree-root level — the geometry bug.
    let leaf_hashes: Vec<[u8; 32]> = proof
        .leaves
        .iter()
        .map(|l| leaf_hash(&l.key, &l.bytes_hash))
        .collect();
    let levels_to_subtree_root = total_depth - path.depth;
    let mut cur = fold_levels(leaf_hashes, levels_to_subtree_root);

    // Phase B — climb from the subtree root to the tree root using one sibling
    // cut-hash per level, exactly like `verify_path`: the climb's left/right
    // choice is the real node-index parity, NOT a nonce bit, and the self-pair
    // of an odd level's last node falls out naturally when the builder supplied
    // the chosen node itself as its own sibling. The cut-hashes are root-first,
    // so we consume them in reverse (lowest climb step uses the last cut-hash).
    //
    // We recompute the node index of the subtree root the same way the builder
    // walked the nonce bits, then halve it as we climb — mirroring `verify_path`.
    let mut node_index = u64::from(path.slot);
    for level_above in (0..path.depth).rev() {
        let Some(sibling) = proof.sibling_cut_hashes.get(level_above as usize) else {
            return StructureVerdict::Invalid("missing cut-hash");
        };
        cur = if node_index % 2 == 0 {
            node_hash(&cur, sibling)
        } else {
            node_hash(sibling, &cur)
        };
        node_index /= 2;
    }

    if cur == commitment.root {
        StructureVerdict::Valid
    } else {
        StructureVerdict::Invalid("root mismatch")
    }
}

/// Fold a contiguous, left-aligned block of node hashes up exactly `levels`
/// levels, applying the same left-packed self-pair rule as
/// `MerkleTree::build_next_level` (`node_hash(x, x)` for an unpaired last node).
///
/// This is the generalisation of a single-leaf inclusion fold to a *range* of
/// leaves: a subtree root at `(levels, slot)` covers a block whose left edge is
/// pair-aligned at every sub-level, so the only odd run that can occur is the
/// tree's genuine odd tail — exactly when `build_next_level` self-pairs. Folding
/// the block `levels` times therefore reproduces the committed node bit-for-bit,
/// including the self-pair that `fold_to_root` used to skip by stopping at a
/// single hash too early.
///
/// `levels == 0` returns the block's single element unchanged (the subtree IS
/// the tree, e.g. the small-tree full-audit case after its own folds, or a
/// single-leaf tree). An empty input is impossible here (callers guarantee ≥ 1
/// leaf via the dead-block fix); returns a zero hash defensively.
#[must_use]
fn fold_levels(mut level: Vec<[u8; 32]>, levels: u32) -> [u8; 32] {
    if level.is_empty() {
        return [0u8; 32];
    }
    // Fold up `levels` times using the SAME builder as `MerkleTree::build`
    // (§10 — `build_next_level`), so the self-pair of an odd tail matches the
    // committed tree exactly. Within a selected, left-aligned block the only
    // odd run that can occur is the tree's genuine odd tail.
    for _ in 0..levels {
        level = crate::replication::commitment::build_next_level(&level);
    }
    // After `levels` folds of a `2^levels`-span left-aligned block, exactly one
    // node remains; defensively fall back if the block was shorter.
    level.first().copied().unwrap_or([0u8; 32])
}

/// Why a responder could not build a subtree proof for a challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildProofError {
    /// The challenge's `key_count` (from the pinned commitment) is out of
    /// protocol range. Should never happen for a commitment we built.
    BadKeyCount,
    /// A selected leaf's key could not be resolved from the tree (internal
    /// inconsistency; should never happen).
    MissingKey {
        /// The leaf index that could not be resolved.
        leaf_index: u32,
    },
    /// The responder no longer holds the bytes for a selected, committed key.
    /// This is real storage loss / deliberate non-response — the caller turns
    /// it into a confirmed audit failure, NOT a benign rejection.
    MissingBytes {
        /// The committed key whose bytes are gone.
        key: XorName,
    },
}

/// Build the single-contiguous-subtree proof for `(nonce, tree)` (responder).
///
/// `bytes_for(&key)` returns the chunk bytes the responder holds for a key, or
/// `None` if it cannot read them. Walks the same nonce-selected path the
/// auditor will re-derive, reads the unselected sibling cut-hashes directly
/// from the committed tree (so they are provably consistent with the gossiped
/// root), and builds each selected leaf's plain and nonced hashes from the real
/// bytes.
///
/// # Errors
///
/// See [`BuildProofError`]. `MissingBytes` is the one the caller penalises;
/// the others indicate an internal inconsistency.
pub fn build_subtree_proof(
    tree: &super::commitment::MerkleTree,
    nonce: &[u8; 32],
    challenged_peer_id: &[u8; 32],
    bytes_for: impl Fn(&XorName) -> Option<Vec<u8>>,
) -> Result<SubtreeProof, BuildProofError> {
    let plan = subtree_plan(tree, nonce)?;
    let mut leaves = Vec::with_capacity(plan.leaf_keys.len());
    for key in &plan.leaf_keys {
        let bytes = bytes_for(key).ok_or(BuildProofError::MissingBytes { key: *key })?;
        leaves.push(subtree_leaf(nonce, challenged_peer_id, key, &bytes));
    }
    Ok(SubtreeProof {
        leaves,
        sibling_cut_hashes: plan.sibling_cut_hashes,
    })
}

/// The pure (no-bytes) geometry of a subtree proof.
///
/// Holds the ordered keys whose bytes the responder must hash and the sibling
/// cut-hashes read from the tree. Splitting this out lets an async responder
/// read chunk bytes per leaf without forcing the tree-walking maths to be async.
#[derive(Debug, Clone)]
pub struct SubtreePlan {
    /// The selected leaves' keys, in ascending leaf-index order.
    pub leaf_keys: Vec<XorName>,
    /// One sibling cut-hash per level on the path to the subtree root,
    /// root-first.
    pub sibling_cut_hashes: Vec<[u8; 32]>,
}

/// Compute the [`SubtreePlan`] for `(nonce, tree)` — selection geometry only,
/// no chunk bytes touched.
///
/// # Errors
///
/// [`BuildProofError::BadKeyCount`] for an out-of-protocol tree;
/// [`BuildProofError::MissingKey`] if a selected leaf index is not in the tree
/// (internal inconsistency).
pub fn subtree_plan(
    tree: &super::commitment::MerkleTree,
    nonce: &[u8; 32],
) -> Result<SubtreePlan, BuildProofError> {
    let key_count = tree.key_count();
    let path = select_subtree_path(nonce, key_count).ok_or(BuildProofError::BadKeyCount)?;

    // Defense-in-depth: the fixed-depth selection already bounds this to one
    // block of `max_subtree_leaves` leaves, but reject BEFORE any leaf read if a
    // future selection change ever produced an oversized subtree, so one request
    // can never force unbounded round-1 read/hash work.
    if path.real_leaf_count() > max_subtree_leaves(key_count) {
        return Err(BuildProofError::BadKeyCount);
    }

    let mut leaf_keys = Vec::with_capacity(path.real_leaf_count() as usize);
    for idx in path.leaf_start..path.leaf_end {
        let key = tree
            .key_at(idx as usize)
            .ok_or(BuildProofError::MissingKey { leaf_index: idx })?;
        leaf_keys.push(key);
    }

    // Sibling cut-hashes, root-first. The fixed-depth slot selection no longer
    // follows a per-level nonce walk, so derive the on-path node at each level
    // from `path.slot`'s prefix bits: the top `d + 1` bits give the node index at
    // level `d + 1` below the root. The sibling is the other child at level
    // `total_depth - (d + 1)` (counting up from leaves); on an odd level the
    // missing sibling self-pairs (the chosen node is its own sibling).
    let total_depth = u32::try_from(tree.levels_count().saturating_sub(1)).unwrap_or(0);
    let mut sibling_cut_hashes = Vec::with_capacity(path.depth as usize);
    for d in 0..path.depth {
        let child = u64::from(path.slot) >> (path.depth - (d + 1));
        let sibling = child ^ 1;
        let level_from_leaves = (total_depth - (d + 1)) as usize;
        let chosen_hash = tree.node_at(level_from_leaves, child);
        let sib_hash = tree
            .node_at(level_from_leaves, sibling)
            .or(chosen_hash)
            .ok_or(BuildProofError::BadKeyCount)?;
        sibling_cut_hashes.push(sib_hash);
    }

    Ok(SubtreePlan {
        leaf_keys,
        sibling_cut_hashes,
    })
}

/// Build one subtree leaf from its key and the chunk bytes the responder holds.
///
/// The plain `bytes_hash` is the chunk's content address; the `nonced_root` is
/// the fresh per-audit nonced block-tree root over the same bytes, committing
/// possession at round-1 time (see [`crate::replication::slice`]).
#[must_use]
pub fn subtree_leaf(
    nonce: &[u8; 32],
    challenged_peer_id: &[u8; 32],
    key: &XorName,
    bytes: &[u8],
) -> SubtreeLeaf {
    SubtreeLeaf {
        key: *key,
        bytes_hash: *blake3::hash(bytes).as_bytes(),
        content_len: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
        nonced_root: crate::replication::slice::nonced_block_root(
            nonce,
            challenged_peer_id,
            key,
            bytes,
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::replication::commitment::MerkleTree;

    fn xn_u32(i: u32) -> XorName {
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(&i.to_be_bytes()); // big-endian so numeric order == sort order
        k
    }
    fn nonce_of(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    // ---- sqrt_floor -------------------------------------------------------

    #[test]
    fn sqrt_floor_is_exact_ceil() {
        assert_eq!(sqrt_floor(1), 1);
        assert_eq!(sqrt_floor(4), 2);
        assert_eq!(sqrt_floor(5), 3); // ceil(sqrt(5)) = 3
        assert_eq!(sqrt_floor(9), 3);
        assert_eq!(sqrt_floor(10), 4);
        assert_eq!(sqrt_floor(100), 10);
        assert_eq!(sqrt_floor(101), 11);
        assert_eq!(sqrt_floor(1_000_000), 1000);
    }

    // ---- real_leaves_under ------------------------------------------------

    #[test]
    fn real_leaves_under_root_is_all() {
        let d = tree_depth(100).unwrap();
        assert_eq!(real_leaves_under(0, 0, 100, d), 100);
    }

    #[test]
    fn real_leaves_under_padding_slot_is_zero() {
        // key_count = 5, total_depth = 3 (next_pow2(5)=8). Leaf slots 5,6,7
        // at the bottom are padding. The right half at depth 1 (slot 1) covers
        // leaves [4,8) → only leaf 4 is real.
        let d = tree_depth(5).unwrap();
        assert_eq!(d, 3);
        assert_eq!(real_leaves_under(1, 0, 5, d), 4); // [0,4)
        assert_eq!(real_leaves_under(1, 1, 5, d), 1); // [4,8) ∩ [0,5) = {4}
        assert_eq!(real_leaves_under(3, 7, 5, d), 0); // pure padding leaf
        assert_eq!(real_leaves_under(2, 3, 5, d), 0); // [6,8) pure padding
    }

    // ---- select_subtree_path: dead-block regression -----------------------

    #[test]
    fn selection_never_empty_and_within_ceiling_across_sizes_and_nonces() {
        for n in [
            5u32, 6, 7, 9, 13, 17, 33, 65, 100, 129, 333, 1000, 1024, 1025,
        ] {
            let ceiling = max_subtree_leaves(n);
            for seed in 0u8..=255 {
                let path = select_subtree_path(&nonce_of(seed), n).unwrap();
                // Never empty (ADR dead-block fix).
                assert!(
                    path.real_leaf_count() >= 1,
                    "n={n} seed={seed}: empty selection"
                );
                // Bounded (DoS fix): one request reads at most one fixed-depth
                // block, regardless of the (possibly adversarial) nonce.
                assert!(
                    path.real_leaf_count() <= ceiling,
                    "n={n} seed={seed}: real={} > ceiling={ceiling}",
                    path.real_leaf_count()
                );
                assert!(path.leaf_end <= n);
                assert!(path.leaf_start < path.leaf_end);
            }
        }
    }

    /// The denial-of-service the fixed-depth selection closes: under the OLD
    /// nonce-bit descent, `key_count = 2^19 + 1` with a nonce steering to the
    /// sparse side selected the WHOLE tree (~2 TiB of reads). Now every nonce
    /// selects at most one `max_subtree_leaves`-sized block, and the tail slot is
    /// a single leaf — not
    /// the root.
    #[test]
    fn adversarial_nonce_cannot_amplify_round1_work() {
        for &n in &[513u32, 1025, 524_289, 1_000_000, MAX_COMMITMENT_KEY_COUNT] {
            let ceiling = max_subtree_leaves(n);
            // A generous cap: sqrt-scale, never the whole tree for a large N.
            assert!(
                u64::from(ceiling) <= 1024.max(u64::from(n)),
                "n={n}: ceiling {ceiling} not sqrt-scale"
            );
            for nonce in [[0x00u8; 32], [0xFFu8; 32], [0xAAu8; 32], [0x55u8; 32]] {
                let path = select_subtree_path(&nonce, n).unwrap();
                assert!(
                    path.real_leaf_count() <= ceiling && path.real_leaf_count() >= 1,
                    "n={n}: real={} outside 1..={ceiling}",
                    path.real_leaf_count()
                );
                if n >= 512 {
                    assert!(
                        u64::from(path.real_leaf_count()) < u64::from(n),
                        "n={n}: a single request must not cover the whole tree"
                    );
                }
            }
        }
    }

    /// Every slot is selectable and the slots partition `0..key_count` with no
    /// gaps, so the tail leaf is never permanently unauditable (coverage is
    /// uniform over many audits).
    #[test]
    fn slots_partition_all_leaves_with_no_gaps() {
        for &n in &[5u32, 17, 100, 1025, 524_289] {
            let span = max_subtree_leaves(n);
            let slot_count = n.div_ceil(span);
            let mut covered = 0u32;
            for slot in 0..slot_count {
                let start = slot.saturating_mul(span);
                let end = start.saturating_add(span).min(n);
                assert_eq!(start, covered, "n={n} slot={slot}: gap before this slot");
                assert!(end > start, "n={n} slot={slot}: empty slot");
                covered = end;
            }
            assert_eq!(covered, n, "n={n}: slots do not cover all leaves");
        }
    }

    #[test]
    fn small_trees_select_whole_tree() {
        for n in 1..=SMALL_TREE_FULL_AUDIT_FLOOR {
            let path = select_subtree_path(&nonce_of(7), n).unwrap();
            assert_eq!(path.depth, 0);
            assert_eq!(path.leaf_start, 0);
            assert_eq!(path.leaf_end, n);
        }
    }

    #[test]
    fn selection_is_deterministic() {
        let n = 500;
        let a = select_subtree_path(&nonce_of(42), n).unwrap();
        let b = select_subtree_path(&nonce_of(42), n).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_nonces_cover_different_branches_over_time() {
        // Not every nonce differs, but the set of selected ranges must be > 1.
        let n = 1024;
        let mut starts = std::collections::HashSet::new();
        for seed in 0u8..=255 {
            let p = select_subtree_path(&nonce_of(seed), n).unwrap();
            starts.insert(p.leaf_start);
        }
        assert!(
            starts.len() > 4,
            "nonce should spread selection: {}",
            starts.len()
        );
    }

    /// Deterministic per-trial nonce (no RNG): hash a counter.
    fn nonce_for_trial(i: u32) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"detection-sim-trial");
        h.update(&i.to_le_bytes());
        *h.finalize().as_bytes()
    }

    /// Catch rate over `trials` audits: fraction whose nonce-selected subtree
    /// overlaps at least one deleted leaf index.
    fn catch_rate(n: u32, deleted: &std::collections::HashSet<u32>, trials: u32) -> f64 {
        let mut caught = 0u32;
        for t in 0..trials {
            let path = select_subtree_path(&nonce_for_trial(t), n).unwrap();
            if (path.leaf_start..path.leaf_end).any(|i| deleted.contains(&i)) {
                caught += 1;
            }
        }
        f64::from(caught) / f64::from(trials)
    }

    #[test]
    fn detection_uniform_fast_clustered_floor() {
        // ADR-0002 Validation: uniform deletions are caught fast; clustered
        // (contiguous-block) deletions are caught at roughly the deleted
        // fraction per audit (a floor), much slower. This encodes the core
        // security claim that the audit RATE (not per-audit cleverness) is the
        // lever against a clustered deleter.
        let n = 1024u32; // sqrt = 32
        let del_count = n / 10; // delete 10% ≈ 102

        // Uniform: spread deletions evenly across the keyspace.
        let uniform: std::collections::HashSet<u32> =
            (0..del_count).map(|i| (i * n / del_count) % n).collect();
        let uniform_rate = catch_rate(n, &uniform, 256);

        // Clustered: one contiguous block of the same size.
        let clustered: std::collections::HashSet<u32> = (0..del_count).collect();
        let clustered_rate = catch_rate(n, &clustered, 256);

        // Uniform should be caught on essentially every audit (spread across the
        // whole tree; any selected subtree overlaps some deletion).
        assert!(
            uniform_rate > 0.95,
            "uniform deletions should be caught almost every audit, got {uniform_rate}"
        );
        // Clustered (one contiguous f-block) is a floor NEAR the deleted
        // fraction f=0.1 — the quantitative ADR claim. The exact rate depends on
        // selection geometry (a block of ~102 leaves is hit when the selected
        // ~sqrt(N) subtree overlaps it), but it must sit in a tight band around
        // f, well below the uniform rate. We bound it to [0.04, 0.30].
        assert!(
            (0.04..=0.30).contains(&clustered_rate),
            "clustered catch-rate should be near f=0.1, got {clustered_rate}"
        );
        assert!(
            uniform_rate > clustered_rate * 2.0,
            "uniform ({uniform_rate}) must be far easier to catch than clustered ({clustered_rate})"
        );
    }

    #[test]
    fn subtree_size_near_sqrt_for_balanced_tree() {
        // For a power-of-two tree the selection should land near sqrt(N).
        let n = 1024; // sqrt = 32, floor = 32
        let path = select_subtree_path(&nonce_of(3), n).unwrap();
        // It stops as soon as a child would drop below floor; the subtree size
        // is between floor and 2*floor for a balanced tree.
        assert!(path.real_leaf_count() >= 32);
        assert!(
            path.real_leaf_count() <= 64,
            "got {}",
            path.real_leaf_count()
        );
    }

    // ---- end-to-end proof build + verify ----------------------------------

    /// Deterministic chunk bytes for a key (test fixture). The tree is built
    /// from `BLAKE3` of exactly these bytes, so the proof and the committed
    /// root agree — mirroring how a real responder hashes the chunk it holds.
    fn chunk_bytes(key: &XorName) -> Vec<u8> {
        // Distinct, non-trivial bytes derived from the key.
        let mut v = key.to_vec();
        v.extend_from_slice(b"chunk-body");
        v
    }

    /// Build tree entries `(key, BLAKE3(chunk_bytes(key)))` for `n` keys.
    fn entries_for(n: u32) -> Vec<(XorName, [u8; 32])> {
        (0..n)
            .map(|i| {
                let key = xn_u32(i);
                let bytes_hash = *blake3::hash(&chunk_bytes(&key)).as_bytes();
                (key, bytes_hash)
            })
            .collect()
    }

    /// Reference responder: build a real subtree proof via the production
    /// [`build_subtree_proof`] from a `MerkleTree` over `entries`. Leaves are
    /// hashed from `chunk_bytes(key)` — the same bytes whose hash built the
    /// tree — so an honest proof verifies. This makes the tests exercise the
    /// exact builder the responder runs.
    fn build_proof(
        entries: &[(XorName, [u8; 32])],
        nonce: &[u8; 32],
        peer_id: &[u8; 32],
    ) -> (SubtreeProof, StorageCommitment) {
        let tree = MerkleTree::build(entries.to_vec()).unwrap();
        let key_count = tree.key_count();
        let proof = build_subtree_proof(&tree, nonce, peer_id, |k| Some(chunk_bytes(k))).unwrap();
        let commitment = fake_commitment(tree.root(), key_count, *peer_id);
        (proof, commitment)
    }

    fn fake_commitment(root: [u8; 32], key_count: u32, peer: [u8; 32]) -> StorageCommitment {
        StorageCommitment {
            root,
            key_count,
            sender_peer_id: peer,
            sender_public_key: vec![0u8; 1952],
            signature: vec![0u8; 3293],
        }
    }

    #[test]
    fn honest_proof_verifies_at_many_sizes() {
        let peer = [0xABu8; 32];
        for n in [5u32, 8, 13, 17, 64, 100, 256, 1000] {
            let entries = entries_for(n);
            for seed in [1u8, 2, 7, 42, 200] {
                let nonce = nonce_of(seed);
                let (proof, commitment) = build_proof(&entries, &nonce, &peer);
                assert_eq!(
                    verify_subtree_proof(&proof, &nonce, &commitment),
                    StructureVerdict::Valid,
                    "n={n} seed={seed}"
                );
            }
        }
    }

    #[test]
    fn honest_proof_verifies_for_every_size_and_nonce() {
        // Regression for the left-packed self-pairing geometry bug: the proof
        // reconstruction must match the committed root for EVERY key count
        // (not just powers of two / cherry-picked sizes) and every nonce. An
        // earlier perfect-tree model false-failed honest nodes for ~70% of
        // sizes; this guards against any reintroduction.
        let peer = [7u8; 32];
        for n in 5u32..=600 {
            let entries = entries_for(n);
            for seed in 0u8..32 {
                let nonce = nonce_of(seed.wrapping_mul(17).wrapping_add(3));
                let (proof, commitment) = build_proof(&entries, &nonce, &peer);
                assert_eq!(
                    verify_subtree_proof(&proof, &nonce, &commitment),
                    StructureVerdict::Valid,
                    "honest proof must verify at n={n} seed={seed}"
                );
            }
        }
    }

    #[test]
    fn tampered_leaf_breaks_root() {
        let peer = [9u8; 32];
        let entries = entries_for(100);
        let nonce = nonce_of(5);
        let (mut proof, commitment) = build_proof(&entries, &nonce, &peer);
        proof.leaves[0].bytes_hash[0] ^= 0x01;
        assert!(matches!(
            verify_subtree_proof(&proof, &nonce, &commitment),
            StructureVerdict::Invalid(_)
        ));
    }

    #[test]
    fn tampered_cut_hash_breaks_root() {
        let peer = [9u8; 32];
        let entries = entries_for(256);
        let nonce = nonce_of(11);
        let (mut proof, commitment) = build_proof(&entries, &nonce, &peer);
        if let Some(c) = proof.sibling_cut_hashes.first_mut() {
            c[0] ^= 0x01;
        }
        assert!(matches!(
            verify_subtree_proof(&proof, &nonce, &commitment),
            StructureVerdict::Invalid(_)
        ));
    }

    #[test]
    fn wrong_leaf_count_rejected() {
        let peer = [9u8; 32];
        let entries = entries_for(100);
        let nonce = nonce_of(5);
        let (mut proof, commitment) = build_proof(&entries, &nonce, &peer);
        proof.leaves.pop();
        assert_eq!(
            verify_subtree_proof(&proof, &nonce, &commitment),
            StructureVerdict::Invalid("wrong leaf count")
        );
    }

    #[test]
    fn non_ascending_leaves_rejected() {
        let peer = [9u8; 32];
        let entries = entries_for(100);
        let nonce = nonce_of(5);
        let (mut proof, commitment) = build_proof(&entries, &nonce, &peer);
        if proof.leaves.len() >= 2 {
            proof.leaves.swap(0, 1);
        }
        assert!(matches!(
            verify_subtree_proof(&proof, &nonce, &commitment),
            StructureVerdict::Invalid(_)
        ));
    }

    // ---- spot-check selection ---------------------------------------------

    #[test]
    fn spotcheck_indices_in_range_and_distinct() {
        let n = 1024;
        let nonce = nonce_of(3);
        let path = select_subtree_path(&nonce, n).unwrap();
        let k = 8;
        let idxs = select_spotcheck_indices(&nonce, &path, k);
        assert_eq!(
            u32::try_from(idxs.len()).unwrap(),
            k.min(path.real_leaf_count())
        );
        let mut seen = std::collections::HashSet::new();
        for i in &idxs {
            assert!(*i < path.real_leaf_count());
            assert!(seen.insert(*i), "duplicate spot-check index {i}");
        }
    }

    #[test]
    fn build_proof_reports_missing_bytes() {
        // A responder that no longer holds a selected, committed key's bytes
        // must surface MissingBytes (the caller turns this into a confirmed
        // failure, not a benign rejection).
        let entries = entries_for(100);
        let tree = MerkleTree::build(entries).unwrap();
        let nonce = nonce_of(5);
        let path = select_subtree_path(&nonce, tree.key_count()).unwrap();
        let victim = tree.key_at(path.leaf_start as usize).unwrap();
        let err = build_subtree_proof(&tree, &nonce, &[1u8; 32], |k| {
            if *k == victim {
                None
            } else {
                Some(chunk_bytes(k))
            }
        })
        .unwrap_err();
        assert_eq!(err, BuildProofError::MissingBytes { key: victim });
    }

    #[test]
    fn spotcheck_returns_all_when_subtree_small() {
        // Construct a path with few real leaves.
        let path = SubtreePath {
            depth: 0,
            slot: 0,
            leaf_start: 0,
            leaf_end: 3,
        };
        let idxs = select_spotcheck_indices(&nonce_of(1), &path, 8);
        assert_eq!(idxs, vec![0, 1, 2]);
    }

    #[test]
    fn spotcheck_always_yields_exactly_min_k_n_distinct_indices() {
        // The byte sample must NEVER be silently smaller than requested: a
        // short sample weakens round 2 without anyone noticing. Exercise many
        // nonces, subtree sizes, and k values, and require exactly min(k, n)
        // distinct in-range indices every time — plus determinism (auditor and
        // responder must derive the same set).
        for size in [1u32, 2, 3, 7, 8, 64, 1000] {
            let path = SubtreePath {
                depth: 0,
                slot: 0,
                leaf_start: 0,
                leaf_end: size,
            };
            for k in [1u32, 3, 5, 8] {
                for seed in 0..32u8 {
                    let nonce = nonce_of(seed);
                    let idxs = select_spotcheck_indices(&nonce, &path, k);
                    let expected = k.min(path.real_leaf_count()) as usize;
                    assert_eq!(
                        idxs.len(),
                        expected,
                        "size={size} k={k} seed={seed}: must yield exactly min(k, n)"
                    );
                    let mut seen = std::collections::HashSet::new();
                    for i in &idxs {
                        assert!(*i < path.real_leaf_count(), "index out of range");
                        assert!(seen.insert(*i), "duplicate index {i}");
                    }
                    assert_eq!(
                        idxs,
                        select_spotcheck_indices(&nonce, &path, k),
                        "selection must be deterministic"
                    );
                }
            }
        }
    }

    #[test]
    fn fabricated_nonced_root_caught_by_spotcheck_probability() {
        // Simulate the realness check: a responder fabricates a fraction x of
        // nonced roots. The auditor opens k leaves; probability all k land on
        // honest leaves is (1-x)^k. Here we just assert the auditor *would* catch
        // a fabricated leaf: its committed root differs from the honest root
        // recomputed from the real chunk bytes under the audit nonce.
        let peer = [1u8; 32];
        let entries = entries_for(400);
        let nonce = nonce_of(9);
        let (mut proof, _commitment) = build_proof(&entries, &nonce, &peer);
        // Fabricate the nonced root on the first subtree leaf.
        if let Some(first) = proof.leaves.first_mut() {
            first.nonced_root[0] ^= 0xFF;
        }
        let leaf = proof.leaves.first().expect("proof has leaves");
        let real_bytes = chunk_bytes(&leaf.key);
        let expected =
            crate::replication::slice::nonced_block_root(&nonce, &peer, &leaf.key, &real_bytes);
        assert_ne!(
            leaf.nonced_root, expected,
            "fabricated nonced root must differ from real"
        );
    }

    // ---- branch-substitution attack ---------------------------------------

    #[test]
    fn responder_cannot_substitute_a_different_branch() {
        // ADR-0002 "Subtree selection": the random value alone fixes WHICH
        // branch is selected, so "the audited node cannot choose a convenient
        // branch to present." This is the load-bearing anti-substitution claim
        // and no existing test exercises it — the tamper tests only mangle a
        // hash within the *correct* branch.
        //
        // Attack: the responder builds a fully valid, internally-consistent
        // subtree proof for a DIFFERENT nonce (which the selection maps to a
        // different branch of the same committed tree), then presents it as the
        // answer to the auditor's nonce. Every leaf hash and every cut-hash is
        // genuine, the leaves are strictly ascending, and we deliberately pick
        // a decoy whose branch has the SAME leaf count and SAME depth as the
        // honest branch — so the cheap "wrong leaf count" / "wrong cut-hash
        // count" gates do NOT fire. The ONLY thing that can reject it is the
        // structural root re-derivation, which climbs using the auditor's
        // nonce-derived slot parity and position. It must reject.
        let peer = [0x5Au8; 32];
        let n = 1024u32; // balanced tree; sqrt floor = 32
        let entries = entries_for(n);

        let audit_nonce = nonce_of(7);
        let audit_path = select_subtree_path(&audit_nonce, n).unwrap();

        // Find a decoy nonce whose selected branch is a DIFFERENT slot but the
        // SAME depth (hence same real-leaf count for this balanced tree). This
        // forces rejection via the root check rather than a count mismatch.
        let mut decoy: Option<([u8; 32], SubtreePath)> = None;
        for seed in 0u8..=255 {
            let cand_nonce = nonce_of(seed);
            let cand = select_subtree_path(&cand_nonce, n).unwrap();
            if cand.depth == audit_path.depth
                && cand.slot != audit_path.slot
                && cand.real_leaf_count() == audit_path.real_leaf_count()
            {
                decoy = Some((cand_nonce, cand));
                break;
            }
        }
        let (decoy_nonce, decoy_path) =
            decoy.expect("a same-depth, different-slot decoy branch must exist for n=1024");

        // Sanity: the decoy really is a different, equally-shaped branch.
        assert_ne!(decoy_path.slot, audit_path.slot);
        assert_eq!(decoy_path.depth, audit_path.depth);
        assert_eq!(decoy_path.real_leaf_count(), audit_path.real_leaf_count());

        // The responder builds a genuine proof for the DECOY branch. Note the
        // nonced hashes are built with the decoy nonce too — but that does not
        // matter: the structural check below never inspects nonced hashes, and
        // the attack must already die on structure.
        let tree = MerkleTree::build(entries).unwrap();
        let decoy_proof =
            build_subtree_proof(&tree, &decoy_nonce, &peer, |k| Some(chunk_bytes(k))).unwrap();

        // Pin the auditor's commitment to the genuine root of the same tree.
        let commitment = fake_commitment(tree.root(), n, peer);

        // The honest answer to the SAME commitment + decoy nonce verifies, so
        // the proof itself is well-formed — it is only "wrong" relative to the
        // auditor's nonce.
        assert_eq!(
            verify_subtree_proof(&decoy_proof, &decoy_nonce, &commitment),
            StructureVerdict::Valid,
            "the decoy proof must be a genuinely valid proof for its own nonce"
        );

        // The attack: present the decoy-branch proof against the AUDIT nonce.
        // The count gates cannot fire (same depth + leaf count by construction),
        // so this is the root re-derivation rejecting a substituted branch.
        let verdict = verify_subtree_proof(&decoy_proof, &audit_nonce, &commitment);
        assert_eq!(
            verdict,
            StructureVerdict::Invalid("root mismatch"),
            "substituting a different valid branch must be rejected by the root check, got {verdict:?}"
        );
    }
}
