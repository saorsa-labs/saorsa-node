//! Tunable parameters for the replication subsystem.
//!
//! All values below are a reference profile used for logic validation.
//! Parameter safety constraints (Section 4):
//! 1. `1 <= QUORUM_THRESHOLD <= CLOSE_GROUP_SIZE`
//! 2. Effective paid-list threshold is per-key dynamic:
//!    `ConfirmNeeded(K) = floor(PaidGroupSize(K)/2)+1`
//! 3. If constraints are violated at runtime reconfiguration, node MUST reject
//!    the config.

#![allow(clippy::module_name_repetitions)]

use std::time::Duration;

use rand::Rng;

use crate::ant_protocol::CLOSE_GROUP_SIZE;
use crate::logging::{debug, info, warn};
use saorsa_core::identity::PeerId;
use saorsa_core::{P2PNode, TrustEvent};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Static constants (compile-time reference profile)
// ---------------------------------------------------------------------------

/// Maximum number of peers per k-bucket in the Kademlia routing table.
pub const K_BUCKET_SIZE: usize = 20;

/// Extra local-routing-table positions accepted for local chunk storage
/// admission and stored-record pruning.
///
/// This margin absorbs small local RT disagreement between peers. It does not
/// widen audit, quorum, or paid-list target sets; those remain strict
/// `close_group_size` / paid-list group checks.
pub const STORAGE_ADMISSION_MARGIN: usize = 2;

/// Full-network target for required positive presence votes.
///
/// Effective per-key threshold is
/// `QuorumNeeded(K) = min(QUORUM_THRESHOLD, floor(|QuorumTargets|/2)+1)`.
pub const QUORUM_THRESHOLD: usize = 4; // floor(CLOSE_GROUP_SIZE / 2) + 1

/// Maximum number of closest nodes tracking paid status for a key.
pub const PAID_LIST_CLOSE_GROUP_SIZE: usize = 20;

/// Maximum number of furthest paid-list close-group peers treated as churny
/// edge voters.
///
/// Once the paid-list close group reaches [`PAID_LIST_CLOSE_GROUP_SIZE`], edge
/// peers are queried, but a negative edge paid-list response does not count
/// into the paid-list majority denominator. A positive edge response does
/// count. This absorbs local routing-table disagreement at the boundary of the
/// paid close group. Undersized groups keep their ordinary strict majority.
///
/// This is a **ceiling**, not a fixed width: the effective edge is scaled to
/// the group by [`ReplicationConfig::paid_list_flex_edge_count`] so the discount stays
/// proportionate. A fixed four peers is a fifth of the production width but
/// would be four fifths of a configured width of five, collapsing the voting
/// core to a single peer.
pub const PAID_LIST_FLEX_EDGE_COUNT: usize = 4;

/// Divisor fixing the edge as a proportion of the paid close group.
///
/// Five gives the production ratio: 20 / 5 = 4 edge voters, matching
/// [`PAID_LIST_FLEX_EDGE_COUNT`] exactly, so default behaviour is unchanged.
const PAID_LIST_FLEX_EDGE_DIVISOR: usize = 5;

/// Minimum `Confirmed` paid-list votes required to authorize a key, whatever
/// the flexible edge does to the denominator.
///
/// The edge discount shrinks the denominator, and with it the majority
/// threshold. Without an absolute floor a sufficiently small or sufficiently
/// silent group authorizes on a single confirmation — and `PaidListVerified`
/// writes the paid list and enables repair fetches, so that is the gate
/// deciding what a node fetches and retains. Three independent confirmations
/// keeps a lone voter (honest or not) from being decisive; groups genuinely
/// smaller than this fall back to their strict majority via the `min` in
/// [`ReplicationConfig::paid_confirm_needed`], since a floor above the group
/// size would make authorization impossible rather than merely strict.
pub const PAID_LIST_ABSOLUTE_CONFIRM_FLOOR: usize = 3;

/// Number of closest peers to self eligible for neighbor sync.
pub const NEIGHBOR_SYNC_SCOPE: usize = 20;

/// Number of close-neighbor peers synced concurrently per round-robin repair
/// round.
pub const NEIGHBOR_SYNC_PEER_COUNT: usize = 4;

/// Best-effort delivery retries for a fresh-replication push, per peer.
///
/// ADR-0003: on a transport/send failure the offer is retried up to this many
/// times so a transient hiccup does not silently drop it. This is delivery
/// assurance only — possession is judged separately by the delayed possession
/// check, which still penalises a close peer that lacks the chunk even if the
/// push never reached it.
pub const FRESH_REPLICATION_DELIVERY_MAX_RETRIES: u32 = 2;

const POSSESSION_CHECK_DELAY_MIN_SECS: u64 = 5 * 60;
const POSSESSION_CHECK_DELAY_MAX_SECS: u64 = 15 * 60;

/// Lower bound of the delay before a fresh-replication possession check runs
/// (ADR-0003).
///
/// The delay lets replication settle so an honest peer still mid-store is not
/// judged prematurely, and makes the check unpredictable to the peer.
pub const POSSESSION_CHECK_DELAY_MIN: Duration =
    Duration::from_secs(POSSESSION_CHECK_DELAY_MIN_SECS);

/// Upper bound of the possession-check delay (ADR-0003).
pub const POSSESSION_CHECK_DELAY_MAX: Duration =
    Duration::from_secs(POSSESSION_CHECK_DELAY_MAX_SECS);

// The possession probe reuses the `AuditChallenge` wire and the bandwidth-
// calibrated `audit_response_timeout(1)` deadline, so it needs no bespoke
// per-probe timeout or retry constants.

/// Width used when deciding whether this node may locally store or retain a
/// chunk.
#[must_use]
pub const fn storage_admission_width(close_group_size: usize) -> usize {
    close_group_size.saturating_add(STORAGE_ADMISSION_MARGIN)
}

/// Minimum neighbor-sync cadence. Actual interval is randomized within
/// `[min, max]`.
const NEIGHBOR_SYNC_INTERVAL_MIN_SECS: u64 = 10 * 60;
/// Maximum neighbor-sync cadence.
const NEIGHBOR_SYNC_INTERVAL_MAX_SECS: u64 = 20 * 60;

/// Neighbor sync cadence range (min).
pub const NEIGHBOR_SYNC_INTERVAL_MIN: Duration =
    Duration::from_secs(NEIGHBOR_SYNC_INTERVAL_MIN_SECS);

/// Neighbor sync cadence range (max).
pub const NEIGHBOR_SYNC_INTERVAL_MAX: Duration =
    Duration::from_secs(NEIGHBOR_SYNC_INTERVAL_MAX_SECS);

/// Per-peer minimum spacing between successive syncs with the same peer.
const NEIGHBOR_SYNC_COOLDOWN_SECS: u64 = 60 * 60; // 1 hour
/// Per-peer minimum spacing between successive syncs with the same peer.
pub const NEIGHBOR_SYNC_COOLDOWN: Duration = Duration::from_secs(NEIGHBOR_SYNC_COOLDOWN_SECS);

/// Minimum age for a replica repair hint before the hinted peer can be audited
/// for that key.
const REPAIR_HINT_MIN_AGE_SECS: u64 = 60 * 60; // 1 hour
/// Minimum age for a replica repair hint before the hinted peer can be audited
/// for that key.
pub const REPAIR_HINT_MIN_AGE: Duration = Duration::from_secs(REPAIR_HINT_MIN_AGE_SECS);

/// Minimum self-lookup cadence.
const SELF_LOOKUP_INTERVAL_MIN_SECS: u64 = 5 * 60;
/// Maximum self-lookup cadence.
const SELF_LOOKUP_INTERVAL_MAX_SECS: u64 = 10 * 60;

/// Periodic self-lookup cadence range (min) to keep close neighborhood
/// current.
pub const SELF_LOOKUP_INTERVAL_MIN: Duration = Duration::from_secs(SELF_LOOKUP_INTERVAL_MIN_SECS);

/// Periodic self-lookup cadence range (max).
pub const SELF_LOOKUP_INTERVAL_MAX: Duration = Duration::from_secs(SELF_LOOKUP_INTERVAL_MAX_SECS);

/// Maximum number of concurrent outbound replication sends.
///
/// Caps how many fresh-replication chunk transfers can be in-flight at once
/// across the entire replication engine. Prevents bandwidth saturation on
/// home broadband connections when multiple chunks arrive simultaneously.
/// Each send transfers up to 4 MB (`MAX_CHUNK_SIZE`), so a limit of 3 means
/// at most ~12 MB queued for the upload link at any instant.
pub const MAX_CONCURRENT_REPLICATION_SENDS: usize = 3;

/// Maximum number of concurrent in-flight audit-responder tasks.
///
/// The LIGHT audit-responder handlers — responsible-chunk audits and subtree
/// slice (round 2) — are spawned off the serial replication message loop so their
/// disk reads don't stall replication. (The HEAVY subtree round 1 has its own
/// tighter pool, [`MAX_CONCURRENT_SUBTREE_ROUND1`].) This caps how many run at once
/// across the engine, restoring backpressure: a peer flooding audit challenges
/// cannot fan out unbounded `get_raw` reads. When the cap is hit, the challenge
/// is dropped and the caller's audit-specific timeout policy applies. The cap
/// must therefore stay high enough for honest audit traffic while still
/// throttling flooders.
/// Sized to cover a handful of concurrent honest auditors (the per-peer
/// gossip-audit cooldown is 30 min, so genuine concurrent audits are few) while
/// bounding the round-2 worst-case disk reads (each request reads at most
/// `BYTE_SPOTCHECK_MAX` distinct chunks — the openings are coalesced and the
/// distinct-key count is capped — to build its slice proofs).
pub const MAX_CONCURRENT_AUDIT_RESPONSES: usize = 32;

/// Maximum concurrent in-flight audit-responder tasks from any SINGLE peer.
///
/// The global [`MAX_CONCURRENT_AUDIT_RESPONSES`] ceiling alone is not
/// flood-fair: one peer spamming challenges could occupy every slot and starve
/// honest auditors (whose dropped challenges convert to audit failures or
/// timeout verdicts on the challenged peers). This per-peer cap guarantees no
/// source holds more than its share, so a flood self-throttles. Audits are
/// cooldown-gated (one
/// gossip-triggered audit per peer per 30 min), so 4 in-flight per peer leaves
/// headroom beyond the legitimate round-1 + round-2 overlap.
pub const MAX_AUDIT_RESPONSES_PER_PEER: u32 = 4;

/// Maximum concurrent digest-only `AuditChallenge` responses from any single
/// source peer.
///
/// Digest challenges are KB-scale replies: at most
/// `max_incoming_audit_keys(stored_chunks)` bounded disk reads plus BLAKE3
/// digests. A higher per-source allowance absorbs the three legitimate issuer
/// subsystems (responsible-chunk audit, prune confirmation, and possession
/// checks) from one auditor without weakening the existing subtree/byte audit
/// budget. The multi-MiB subtree and byte challenge paths intentionally keep
/// [`MAX_AUDIT_RESPONSES_PER_PEER`] exactly unchanged.
pub const MAX_DIGEST_AUDIT_RESPONSES_PER_PEER: u32 = 8;

/// Cadence of audit-responder capacity and slow-processing summaries.
///
/// Each window is reset after logging, so the ranked origins describe current
/// testnet load rather than being permanently dominated by an old burst.
pub const AUDIT_RESPONDER_SUMMARY_INTERVAL: Duration = Duration::from_secs(60);

/// Number of busiest source peers included in each responder summary window.
pub const AUDIT_RESPONDER_TOP_ORIGINS: usize = 10;

/// Dedicated global concurrency cap for the HEAVY subtree-audit round 1.
///
/// Round 1 hashes every leaf of the selected `sqrt(key_count)` subtree (up to
/// ~1000 chunks × `MAX_CHUNK_SIZE` for a maximal commitment), far heavier than a
/// responsible-chunk or slice (round-2) response. Giving it its own tiny pool —
/// rather than sharing [`MAX_CONCURRENT_AUDIT_RESPONSES`] — keeps a burst of
/// round-1 proofs from starving the light audits, and bounds concurrent
/// multi-gigabyte hashing to this many at once. Two allows overlap without
/// admitting many simultaneous full-subtree hashes; there is little benefit in
/// more concurrent large LMDB scans against one disk.
pub const MAX_CONCURRENT_SUBTREE_ROUND1: usize = 2;

/// Per-peer concurrency cap for the heavy subtree-audit round 1. One in-flight
/// round-1 proof per source at a time (an honest auditor never needs more).
pub const MAX_SUBTREE_ROUND1_PER_PEER: u32 = 1;

/// Per-peer responder-side cooldown between heavy subtree round-1 proofs.
///
/// An honest auditor already self-limits to one gossip-triggered subtree audit
/// per peer per 30 min, so matching that as a responder-side floor costs honest
/// traffic nothing while bounding the sustained round-1 work a single identity
/// can extract (a concurrency cap alone lets a peer refill its slot forever).
pub const SUBTREE_ROUND1_RESPONDER_COOLDOWN: Duration = Duration::from_secs(30 * 60);

/// Lifetime of a single-use round-1 → round-2 session.
///
/// A round-2 slice challenge is only served if the same peer completed a matching
/// round 1 within this window. Long enough for the auditor to verify round 1 and
/// send round 2, far shorter than commitment retention; ephemeral, so a loss
/// across a restart just
/// drops that round to the (graced) timeout lane.
pub const SUBTREE_SESSION_TTL: Duration = Duration::from_secs(2 * 60);

/// Capacity backstop on the live round-1 session map (bounds memory if many
/// peers open sessions; oldest are evicted past this).
pub const MAX_SUBTREE_SESSIONS: usize = 4 * MAX_CONCURRENT_SUBTREE_ROUND1 * 256;

/// Sustained rate at which the responder-wide round-1 work budget refills, in
/// bytes of chunk content per second.
///
/// [`MAX_CONCURRENT_SUBTREE_ROUND1`] bounds how many round-1 proofs run at once
/// and [`SUBTREE_ROUND1_RESPONDER_COOLDOWN`] bounds how often one peer id may
/// ask, but neither bounds sustained work: the cooldown is keyed by identity, so
/// a party holding several identities refills its allowance by rotating between
/// them and keeps the small pool permanently busy. This budget is keyed by
/// nothing at all — it is charged for the bytes read and hashed no matter who
/// asked — so identity count cannot buy more of it.
///
/// Sized to clear honest demand even at the worst commitment size, since
/// starving honest audits would cost more than it saves. The 990-node run
/// served about 24 audits per node per hour. At the `MAX_COMMITMENT_KEY_COUNT`
/// cap one proof reads close to 4 GiB, so honest demand there is ~96 GiB/h,
/// against the 225 GiB/h this allows — and a flooder is held to about twice
/// honest load rather than to whatever the disk will bear. For the far more
/// common mid-sized commitment, where a proof reads a few hundred MiB, the
/// headroom is more than an order of magnitude.
///
/// Signed because the budget it refills carries debt when a proof costs more
/// than is left.
pub const SUBTREE_ROUND1_WORK_REFILL_BYTES_PER_SEC: i64 = 64 * 1024 * 1024;

/// Burst capacity of the round-1 work budget, in bytes of chunk content.
///
/// Also its starting fill, so a freshly started node can serve audits at once.
/// Two maximal proofs' worth, matching [`MAX_CONCURRENT_SUBTREE_ROUND1`], so a
/// legitimate burst is never refused for arriving together — the budget limits
/// the sustained rate, which is what a concurrency cap cannot do.
pub const SUBTREE_ROUND1_WORK_BURST_BYTES: i64 = 8 * 1024 * 1024 * 1024;

/// Floor charged against the round-1 work budget per leaf attempted, in bytes.
///
/// The budget counts content bytes, which is the right unit for the hashing but
/// misses what a leaf costs before its size is known: an LMDB point lookup with
/// its retries, and a `spawn_blocking` dispatch and join. Nothing bounds a
/// chunk from below, so a commitment made of a million tiny records would run a
/// full subtree of reads and task round-trips per audit while charging almost
/// nothing, and a leaf that fails to read charged nothing at all. Since the
/// per-peer cooldown is escapable by rotating identity, the budget is the only
/// bound that applies, so it has to see that cost.
///
/// Charged at the attempt, then topped up by whatever the content exceeds it
/// by, so a leaf costs `max(bytes, this)`. At 4 KiB an honest chunk is almost
/// always above it and pays exactly its bytes, which leaves the sizing of the
/// refill rate above unchanged.
pub const SUBTREE_ROUND1_LEAF_WORK_FLOOR_BYTES: i64 = 4 * 1024;

/// Concurrent fetches cap, derived from hardware thread count.
///
/// Uses `std::thread::available_parallelism()` so the node scales to the
/// machine it runs on.  Falls back to 4 if the OS query fails.
const AVAILABLE_PARALLELISM_FALLBACK: usize = 4;

/// Returns the number of hardware threads available, used as the fetch
/// concurrency limit.
#[allow(clippy::incompatible_msrv)] // NonZero::get is stable since 1.79; MSRV lint conflicts with redundant_closure
pub fn max_parallel_fetch() -> usize {
    std::thread::available_parallelism()
        .map_or(AVAILABLE_PARALLELISM_FALLBACK, std::num::NonZero::get)
}

/// Minimum audit-scheduler cadence.
const AUDIT_TICK_INTERVAL_MIN_SECS: u64 = 10 * 60;
/// Maximum audit-scheduler cadence.
const AUDIT_TICK_INTERVAL_MAX_SECS: u64 = 20 * 60;

/// Audit scheduler cadence range (min).
pub const AUDIT_TICK_INTERVAL_MIN: Duration = Duration::from_secs(AUDIT_TICK_INTERVAL_MIN_SECS);

/// Audit scheduler cadence range (max).
pub const AUDIT_TICK_INTERVAL_MAX: Duration = Duration::from_secs(AUDIT_TICK_INTERVAL_MAX_SECS);

/// Floor on the audit response deadline (independent of challenge size).
///
/// Sized to absorb worst-case global RTT for the audit envelope
/// (the request + response messages are KB-scale, not chunk-scale)
/// plus scheduling jitter. Tokyo↔NY round-trip is ~150ms each way,
/// so 4 seconds comfortably covers cross-continent communication
/// for the round-1 proof, whose payload is hashes (KB-scale).
const AUDIT_RESPONSE_FLOOR_SECS: u64 = 4;

/// Floor on the round-2 SLICE-challenge deadline.
///
/// The round-2 reply is only a few KB per opening (a 1 KiB block plus two short
/// hash chains), but an honest responder still reads each opened chunk's full
/// bytes from disk to build its Bao slice and nonced opening, so the floor must
/// cover a cold QUIC handshake plus a busy honest peer's full-chunk disk read.
/// The round-1 4 s floor is sized for a hashes-only reply; round 2 keeps a
/// slightly larger 5 s base for the disk-read envelope, with the per-byte scaled
/// term (one full chunk per opening) added on top.
const BYTE_AUDIT_RESPONSE_FLOOR_SECS: u64 = 5;

/// Conservative honest-responder read throughput, in bytes per second.
///
/// Used to size the audit response deadline. An honest peer answers
/// a k-key challenge by reading k chunks from local disk, computing
/// BLAKE3 + path proofs, and signing the response. The bottleneck is
/// disk read; BLAKE3 at ~3 GB/s + ML-DSA signing at ~3 ms are
/// negligible.
///
/// Set conservatively below any modern SSD (typical: 500 MB/s+).
/// At 50 MB/s, a k=10 sample at 4 MiB chunks reads in ~0.8s, well
/// inside even an aggressive timeout. A relay attacker who must
/// fetch the same 40 MB over the network at typical bandwidth
/// (100 Mbps = 12.5 MB/s) takes 3+ seconds for the data alone, plus
/// per-chunk network round-trips. At larger sample sizes the gap
/// is exponential in the relay's disadvantage.
const AUDIT_HONEST_READ_BPS: u64 = 50 * 1024 * 1024;

/// Slack multiplier on the honest-read estimate.
///
/// Set so an honest peer that's slower than `HONEST_READ_BPS` (e.g. an
/// HDD-backed node, or one under load) still answers within the
/// timeout. 5× is generous; a relay peer fetching the same data over a
/// residential link (~5-12 MB/s) sees ~10-100× higher latency than disk
/// and misses the budget. This is an economic deterrent calibrated for
/// residential bandwidth, NOT a hard cryptographic bound — a relay on a
/// datacenter cross-connect could still fetch fast enough to answer in
/// time (see the §7 note on `audit_response_timeout`).
const AUDIT_RESPONSE_HONEST_MULTIPLIER: u64 = 5;

/// Maximum duration a peer may claim bootstrap status before penalties apply.
const BOOTSTRAP_CLAIM_GRACE_PERIOD_SECS: u64 = 24 * 60 * 60; // 24 h
/// Maximum duration a peer may claim bootstrap status before penalties apply.
pub const BOOTSTRAP_CLAIM_GRACE_PERIOD: Duration =
    Duration::from_secs(BOOTSTRAP_CLAIM_GRACE_PERIOD_SECS);

/// Minimum continuous out-of-range duration before pruning a key.
const PRUNE_HYSTERESIS_DURATION_SECS: u64 = 3 * 24 * 60 * 60; // 3 days
/// Minimum continuous out-of-range duration before pruning a key.
pub const PRUNE_HYSTERESIS_DURATION: Duration = Duration::from_secs(PRUNE_HYSTERESIS_DURATION_SECS);

/// Protocol identifier for core replication operations, including the
/// digest-based responsible-chunk, possession, and prune-confirmation audits.
///
/// Kept at `v2`: the V2-685 work changes only the subtree-audit wire family.
/// Fresh replication, neighbour sync, fetch, repair, verification, and the
/// digest-based audit lanes therefore continue interoperating on this id. A node
/// filters inbound messages by exact topic match (see the dispatch in `mod.rs`).
pub const REPLICATION_PROTOCOL_ID: &str = "autonomi.ant.replication.v2";

/// Protocol identifier for the subtree storage-commitment audit (ADR-0002 /
/// V2-685), both rounds: `SubtreeAuditChallenge`/`Response` (round 1) and
/// `SubtreeSliceChallenge`/`Response` (round 2).
///
/// These are the only replication messages whose wire format changed for the
/// slice audit (round 1's `SubtreeLeaf` now carries `content_len` + `nonced_root`
/// instead of a flat `nonced_hash`; round 2 replaced full-byte responses with Bao
/// verified slices). Routing them on their own id — instead of bumping the whole
/// [`REPLICATION_PROTOCOL_ID`] — means a mixed-version fleet keeps doing fresh
/// replication, neighbour sync, fetch and repair across versions; only
/// cross-version subtree *audits* pause during the ~24 h auto-upgrade window.
///
/// Rollout effect is bounded, not zero: `saorsa-core`'s `send_request` records a
/// unit trust failure on any unanswered request (before ant-node's graced-timeout
/// policy), so a v3 auditor's subtree challenge to a still-v2 peer (and the
/// reverse, where a v2 subtree audit is dropped by the id/body guard) each ding
/// that peer's EMA trust once per 30-minute audit cooldown. Trust decays back to
/// neutral (a worst-case dip recovers above the 0.35 routing-swap threshold in
/// ~1 online day, and a successful audit after upgrade adds a unit success), and
/// crossing 0.35 only makes a peer replaceable in a full bucket — it does not
/// delete data or ban the peer. This is strictly milder than bumping the shared
/// id, which would fail every cross-version request path (sync/quorum/prune/
/// possession/repair/commitment-fetch) with no per-peer limiter. A truly
/// zero-penalty rollout needs an upstream `send_request` that does not
/// auto-report trust; tracked as a saorsa-core follow-up.
pub const SUBTREE_AUDIT_PROTOCOL_ID: &str = "autonomi.ant.replication.subtree-audit.v1";

/// 10 MiB — maximum replication wire message size (accommodates hint batches).
const REPLICATION_MESSAGE_SIZE_MIB: usize = 10;
/// Maximum replication wire message size.
pub const MAX_REPLICATION_MESSAGE_SIZE: usize = REPLICATION_MESSAGE_SIZE_MIB * 1024 * 1024;

/// Maximum wire size for a message in the subtree-audit protocol family.
///
/// The 10 MiB core ceiling is sized for hint batches, which no subtree-audit
/// body carries. Applying it to the subtree family would let a peer make this node
/// allocate and decode megabytes of attacker-shaped collection before any
/// family, session or admission check has run — those checks all read fields of
/// the decoded body, so they cannot come first. Checking the encoded length
/// against a family-appropriate ceiling can, because it needs nothing but the
/// byte count.
///
/// Sized against the largest legitimate audit body, the round-1
/// `SubtreeAuditResponse::Proof`: at the `MAX_COMMITMENT_KEY_COUNT` cap a
/// subtree is at most 1,024 leaves of ~100 bytes each, plus the sibling cut
/// hashes and the signed commitment, so ~110 KiB. Every other subtree body is
/// far smaller. This leaves roughly
/// 4x headroom over the worst legitimate case while cutting the pre-admission
/// allocation ceiling by a factor of 20.
pub const MAX_SUBTREE_AUDIT_MESSAGE_SIZE: usize = 512 * 1024;
const _: () = assert!(
    MAX_SUBTREE_AUDIT_MESSAGE_SIZE < MAX_REPLICATION_MESSAGE_SIZE,
    "the subtree-audit ceiling must be tighter than the core one, or it is pointless"
);

/// Maximum block openings per round-2 [`SubtreeSliceChallenge`].
///
/// Each opening is a Bao verified slice (a 1 KiB block plus O(log n) BLAKE3
/// parent hashes) plus a nonced block-tree sibling chain — a few KB, so even
/// this many openings encode far under [`MAX_REPLICATION_MESSAGE_SIZE`] with no
/// batching. The auditor draws up to *two* openings per sampled leaf — one
/// fresh-random block (possession) and one at the claimed final block (a length
/// pin: opening the final block forces Bao's EOF validation, which authenticates
/// the true content length and defeats a forged-short `content_len` that would
/// otherwise shrink the challenge space). With at most `BYTE_SPOTCHECK_MAX`
/// leaves that is `2 × BYTE_SPOTCHECK_MAX` openings; this cap sits just above
/// that, and the responder rejects any challenge requesting more (a forged-
/// auditor guard: each opening forces one full chunk read to build its proof).
///
/// [`SubtreeSliceChallenge`]: crate::replication::protocol::SubtreeSliceChallenge
pub const MAX_SLICE_OPENINGS: usize = 10;
const _: () = assert!(
    MAX_SLICE_OPENINGS >= 1,
    "at least one block opening must be allowed per slice challenge"
);

/// Rollout gate for ADR-0004 quote-arithmetic enforcement.
///
/// When `true`, the payment verifier rejects any quote whose signed price does
/// not lie exactly on the public pricing curve, i.e. there is no integer
/// `key_count` for which `calculate_price(key_count) == quote.price`. The check
/// is exact recomputation against the curve, never price-inversion (which
/// rounds), per ADR-0004's "never by inverting the price" rule.
///
/// When `false`, the check still runs and logs every would-be rejection, but
/// does not reject — matching the ADR-0004 rollout: ship observe-only first,
/// enforce only once the fleet has upgraded. Off-curve quotes are honest
/// errors, not signs of an old node (every honest implementation derives its
/// price from the same public formula), so flipping this to `true` does not
/// risk evicting un-upgraded peers; it only catches modified nodes that minted
/// prices off the curve.
///
/// This is a reject-only gate: an off-curve quote produces no trust evidence
/// and no audit, per ADR-0004 ("an off-curve quote is reject-only"). It does
/// NOT gate the quote/commitment mismatch trust report — see
/// [`QUOTE_COMMITMENT_MISMATCH_TRUST_ENABLED`] for that, kept separate because
/// the two have different ADR-0004 contracts (this one rejects with no trust
/// action; that one reports a deterministic contradiction to the trust engine).
///
/// Enabled after the observe-only canary came back clean on ant-prod-01. Over
/// the 2026-07-29 to 2026-08-04 window the check ran against every quote in
/// more than 70,000 verified bundles across 912 of 913 node instances and
/// flagged nothing: no off-curve price, no invalid binding shape, no
/// price/count mismatch. Honest traffic therefore sits exactly on the curve, so
/// enforcing rejects nothing that is accepted today.
pub const QUOTE_ARITHMETIC_RECHECK_ENABLED: bool = true;

/// Rollout gate for ADR-0004 quote/commitment **mismatch** trust reporting.
///
/// When a client-put quote's signed `committed_key_count` contradicts the
/// `key_count` of the commitment it pinned (resolved from the gossip cache, a
/// sidecar, or a fetch), that is two artifacts signed by the same key that
/// contradict each other — a deterministic, first-occurrence misbehaviour. When
/// `true`, the cross-check reports it to the trust engine as an
/// `ApplicationFailure` (the same lane as a confirmed deterministic audit
/// failure, NOT the timeout silence lane). When `false`, the cross-check only
/// logs the would-be report (observe-only).
///
/// Kept independent of [`QUOTE_ARITHMETIC_RECHECK_ENABLED`] (which is
/// reject-only with no trust action): a confirmed mismatch is not a mere
/// off-curve price, so it deserves its own dial.
pub const QUOTE_COMMITMENT_MISMATCH_TRUST_ENABLED: bool = false;

/// Instant from which a merkle batch payment must carry the same 3x settlement
/// multiplier the single-node path has always applied (ADR-0008). Unix seconds.
///
/// The single-node path settles a chunk at 3x the median quoted price. The
/// merkle path submitted the bare quoted price as the on-chain payable amount,
/// so the contract's `median16(amount) x 2^depth` came to 1x the median per
/// padded leaf: the same chunk, stored and replicated identically, earned a
/// third as much when it arrived in a batch.
///
/// **The rollout is client-first, and this constant is only its second half.**
/// ant-client (ant-client#161) pays 3x immediately and unconditionally once
/// released — no date, no flag — and un-upgraded nodes accept that, because 3x
/// clears the 1x minimum they require. So the network is paid correctly from
/// the moment the client ships. This instant is when upgraded nodes stop
/// accepting anything less.
///
/// **Enforcement is on by default.** There is no shadow mode and no flag to
/// flip later: a receipt stamped at or after this instant must settle at 3x or
/// the store is refused. What the boundary buys is not a soft launch, it is
/// compatibility with money that was already spent:
///
/// - A receipt stamped **before** the boundary is held to the historic 1x. It
///   was paid in good faith under the old rule and the payer cannot get it
///   back, so refusing it would destroy value rather than protect it.
/// - Merkle receipts expire after `MERKLE_PAYMENT_EXPIRATION` (one week), and
///   a receipt stamped in the future is refused outright. So once
///   `boundary + one week` has passed, **every** still-valid receipt is
///   necessarily stamped at or after the boundary and the 1x branch becomes
///   unreachable. It retires itself; nobody has to remember to turn it off.
/// - Backdating is **not** prevented during that week. The timestamp is
///   client-chosen — it is a `payForMerkleTree` argument, the contract only
///   rejects future and week-old stamps, and quoting nodes sign whatever stamp
///   the request carries — so a modified client can stamp just before the
///   boundary and keep paying 1x until such a stamp expires. Expiry is what
///   closes the route, not detection, and it closes it at
///   `boundary + one week`. The same branch protects honest in-flight receipts,
///   so the window cannot be narrowed without also destroying those.
///
/// Set to 2026-08-04 15:00 UTC, after the client release with room for
/// adoption. Two invariants when moving it: **it must never be earlier than the
/// client release that pays 3x** (an earlier value refuses receipts bought
/// under the previous rule, the one outcome this constant exists to avoid), and
/// it must move forward if that **client** release slips — a node enforcing
/// before clients pay fails every batch upload. A slip in *node* rollout needs
/// no change: it only means fewer nodes enforce for a while.
pub const MERKLE_PARITY_ENFORCED_FROM_UNIX: u64 = 1_785_855_600;

/// ADR-0004: max unresolved quote pins to fetch per payment bundle.
///
/// A bundle has at most `CLOSE_GROUP_SIZE` quotes; capping fetches per bundle
/// bounds the amplification a single malicious upload (many distinct unknown
/// pins) can drive. Excess unresolved pins in one bundle are dropped (left
/// unresolved, i.e. graced — the audit funnel still catches a serving cheater).
pub const MAX_PIN_FETCHES_PER_BUNDLE: usize = 3;

/// ADR-0004: capacity of the per-peer negative cache for unresolved pin fetches.
///
/// A pin that a peer answered `NotRetained` (or that timed out) is remembered so
/// repeated bundles citing the same unknown pin don't re-fetch.
pub const PIN_FETCH_NEGATIVE_CACHE_CAPACITY: usize = 4096;

/// ADR-0004: timeout for a `GetCommitmentByPin` fetch.
///
/// Sized for a single small round-trip plus the responder's bounded in-memory
/// lookup; a fetch is off the payment hot path, so this only bounds the
/// background cross-check.
pub const PIN_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Verification request timeout (per-batch).
const VERIFICATION_REQUEST_TIMEOUT_SECS: u64 = 15;
/// Verification request timeout (per-batch).
pub const VERIFICATION_REQUEST_TIMEOUT: Duration =
    Duration::from_secs(VERIFICATION_REQUEST_TIMEOUT_SECS);

/// Ceiling on the exponential backoff applied to a pending key that keeps
/// failing to resolve.
///
/// [`VERIFICATION_REQUEST_TIMEOUT`] is the *first* retry delay, not a flat
/// cadence. A key whose presence probe finds no holder is almost always in that
/// state because the answer has not changed — a new node that claims a slice of
/// the keyspace its routing table cannot yet resolve keeps asking the same peers
/// the same question. Re-asking every 15 seconds costs a verification round trip
/// per key per retry and produces one log line each time, for no new
/// information.
///
/// Doubling from 15s and capping here gives roughly ten attempts inside one
/// [`PENDING_VERIFY_MAX_AGE`] residency instead of roughly a hundred and ten,
/// while bounding the worst-case delay in noticing that a holder *has* appeared
/// to this value.
const VERIFICATION_RETRY_BACKOFF_MAX_SECS: u64 = 5 * 60;
/// Ceiling on the exponential backoff applied to an unresolved pending key.
pub const VERIFICATION_RETRY_BACKOFF_MAX: Duration =
    Duration::from_secs(VERIFICATION_RETRY_BACKOFF_MAX_SECS);

/// Maximum ready hints processed by one verification cycle.
///
/// The pending queue may be much larger. Each cycle takes a sender-fair bounded
/// sample, retaining corroboration/age priority within each sender's share.
/// This value keeps today's roughly 6k-chunk average bootstrap within one cycle
/// while preventing a full emergency-cap queue from creating one enormous
/// verification round.
pub const MAX_VERIFICATION_KEYS_PER_CYCLE: usize = 8_192;

/// Maximum keys accepted in one incoming verification request.
///
/// Senders aggregate all keys for a peer into one request. Matching this limit
/// to the cycle bound lets an honest round use one request per peer while still
/// bounding the LMDB work performed on the responder's serial replication
/// message path. Oversized requests are rejected as an empty, wire-compatible
/// verification response.
pub const MAX_INCOMING_VERIFICATION_KEYS: usize = MAX_VERIFICATION_KEYS_PER_CYCLE;

/// Maximum simultaneous verification request/response exchanges.
/// Larger rounds remain fully batched but wait for a permit instead of
/// launching hundreds or thousands of network requests at once.
pub const MAX_CONCURRENT_VERIFICATION_REQUESTS: usize = 32;

/// Fetch request timeout.
const FETCH_REQUEST_TIMEOUT_SECS: u64 = 30;
/// Fetch request timeout.
pub const FETCH_REQUEST_TIMEOUT: Duration = Duration::from_secs(FETCH_REQUEST_TIMEOUT_SECS);

/// Maximum age for pending-verification entries before stale eviction.
const PENDING_VERIFY_MAX_AGE_SECS: u64 = 30 * 60;
/// Maximum age for pending-verification entries before stale eviction.
pub const PENDING_VERIFY_MAX_AGE: Duration = Duration::from_secs(PENDING_VERIFY_MAX_AGE_SECS);

/// How long a key waits for another look once this node's disk is **full**.
///
/// Only a full disk, not any refused write: a space query that fails says
/// nothing about available space and keeps the ordinary retry schedule.
///
/// A node that cannot write cannot finish an acquisition, so before this gate
/// the key came straight back. At [`VERIFICATION_REQUEST_TIMEOUT`] that was a
/// close-group probe as often as every 15 s for every key the node owes — the
/// requested delay, so cycle polling, round duration and bounded per-cycle
/// selection make it an upper rate rather than an observed cadence. The owed set
/// grows with the network rather than with anything this node does — 25.6% of a
/// 195-service testnet, held full, produced 99.6% of every verification-request
/// byte on the network (V2-987).
///
/// What this schedules is a *look*: the cycle re-reads local capacity and only
/// probes if space has returned. A key that stays full and authorized sends no
/// probes at all, because the gate stops the round before it is sent.
///
/// Five minutes is chosen against [`PENDING_VERIFY_MAX_AGE`], which it is well
/// inside. That is not a guarantee that freed space is noticed while the entry
/// lives: one deferred inside its final five minutes expires first, and a
/// backlog can delay selection further.
///
/// This is deliberately a constant rather than a [`ReplicationConfig`] field.
/// The struct is publicly re-exported and is not `#[non_exhaustive]`, so a new
/// field would break downstream exhaustive construction for a knob nothing
/// needs to tune at runtime.
///
/// Applied flat, through the ordinary `defer_pending`. A key deferred inside the
/// last five minutes of its entry's life therefore expires at
/// [`PENDING_VERIFY_MAX_AGE`] without a further look and comes back on the next
/// neighbour-sync hint. An earlier revision clamped the delay to half the
/// entry's remaining life to avoid that; it was cut because the extra looks it
/// bought near expiry can themselves become ungated quorum rounds.
const CAPACITY_BLOCKED_RETRY_SECS: u64 = 5 * 60;
/// How long a key waits for another look once this node's disk is full.
pub(crate) const CAPACITY_BLOCKED_RETRY: Duration =
    Duration::from_secs(CAPACITY_BLOCKED_RETRY_SECS);

/// Trust event weight for confirmed audit failures.
pub const AUDIT_FAILURE_TRUST_WEIGHT: f64 = 5.0;

/// Whether this build penalises a peer for not holding a chunk it was supposed to hold.
///
/// **`true` while the fleet moves off the legacy LMDB chunk store; back to `false` once it
/// has.** Flipping it is a one-line change in one release.
///
/// Deliberately narrow. It covers exactly one accusation: "you did not have a chunk you
/// were supposed to be holding". It does **not** cover the commitment-bound subtree audit,
/// where a peer published a signed claim to hold specific keys and could not answer for
/// them. That contract stays enforced in every release.
///
/// The reason it has to exist at all is that the penalty is the *auditor's* decision. A
/// node that has to give up chunks, because it cannot fit them while it moves them out of
/// a store that never returns disk, cannot stop its peers penalising it for that. So the
/// peers stop first, one release ahead, and the node moves in the next one.
///
/// A build constant rather than a config field on purpose: a node writes its effective
/// configuration back to disk, so shipping this as an ordinary setting would bake this
/// release's value into every operator's file and the next release would change nothing.
pub const RELEASE_SUSPEND_CLOSE_GROUP_STORAGE_PENALTY: bool = true;

/// Environment override for [`RELEASE_SUSPEND_CLOSE_GROUP_STORAGE_PENALTY`], for a canary.
pub const SUSPEND_CLOSE_GROUP_STORAGE_PENALTY_ENV: &str = "ANT_SUSPEND_UNHELD_CHUNK_PENALTY";

/// The live switch.
///
/// Initialised **from the release constant**, not to `false`. That matters: a code path
/// that never applies the policy then behaves like this release rather than the previous
/// one. Defaulting the other way meant any constructor that skipped the startup call would
/// keep penalising nodes for the very thing this release exists to stop penalising, and
/// `ReplicationEngine::new` is public and is constructed directly by test harnesses.
///
/// Process-wide rather than threaded through a parameter because it is exactly that: one
/// release-level decision that every affected site has to obey identically, and those
/// sites are spread across call graphs that share no configuration object.
static CLOSE_GROUP_STORAGE_PENALTY_SUSPENDED: AtomicBool =
    AtomicBool::new(RELEASE_SUSPEND_CLOSE_GROUP_STORAGE_PENALTY);

/// Apply this release's decision. Called once, before anything can audit.
pub fn apply_close_group_storage_penalty_policy() {
    let Ok(raw) = std::env::var(SUSPEND_CLOSE_GROUP_STORAGE_PENALTY_ENV) else {
        apply_and_announce(RELEASE_SUSPEND_CLOSE_GROUP_STORAGE_PENALTY);
        return;
    };
    let suspended = match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        other => {
            warn!(
                "{SUSPEND_CLOSE_GROUP_STORAGE_PENALTY_ENV}={other} is not a boolean; \
                 using the build default {RELEASE_SUSPEND_CLOSE_GROUP_STORAGE_PENALTY}"
            );
            RELEASE_SUSPEND_CLOSE_GROUP_STORAGE_PENALTY
        }
    };
    apply_and_announce(suspended);
}

/// Set the switch and say so, once, where an operator will see it.
///
/// Both states are logged. An operator reading "penalties are suspended" and an operator
/// reading nothing at all cannot tell the second from a missing log line, and the state
/// that most needs to be visible is the one that disagrees with what the release intended.
fn apply_and_announce(suspended: bool) {
    set_close_group_storage_penalty_suspended(suspended);
    if suspended != RELEASE_SUSPEND_CLOSE_GROUP_STORAGE_PENALTY {
        warn!(
            close_group_storage_penalty_suspended = suspended,
            "{SUSPEND_CLOSE_GROUP_STORAGE_PENALTY_ENV} overrides this build: the penalty \
             for not holding a close-group chunk is {}, where the release intends {}. \
             Clear that variable unless this node is a deliberate canary.",
            if suspended { "SUSPENDED" } else { "APPLIED" },
            if RELEASE_SUSPEND_CLOSE_GROUP_STORAGE_PENALTY {
                "SUSPENDED"
            } else {
                "APPLIED"
            }
        );
    }
    if suspended {
        info!(
            close_group_storage_penalty_suspended = true,
            "This release does NOT penalise a peer for failing to hold a close-group \
             chunk. Commitment-bound audits still penalise. Audits run and record \
             throughout."
        );
    } else {
        info!(
            close_group_storage_penalty_suspended = false,
            "This release penalises a peer for failing to hold a close-group chunk."
        );
    }
}

/// Set whether failing to hold a close-group chunk penalises.
///
/// Startup applies the release policy through this. Tests that mean to exercise the
/// penalty itself set it explicitly, so what they assert is not an accident of whichever
/// release they happen to be compiled against.
pub fn set_close_group_storage_penalty_suspended(suspended: bool) {
    CLOSE_GROUP_STORAGE_PENALTY_SUSPENDED.store(suspended, Ordering::Relaxed);
}

/// Whether failing to hold a close-group chunk currently penalises.
#[must_use]
pub fn close_group_storage_penalty_suspended() -> bool {
    CLOSE_GROUP_STORAGE_PENALTY_SUSPENDED.load(Ordering::Relaxed)
}

/// Penalise `peer` at `weight` for not holding a chunk it was supposed to be holding,
/// unless this release withholds that particular penalty.
///
/// Covers the responsible-chunk audit, the fresh-replication possession check, the prune
/// audit, and the fetch paths where a peer that answered `Present` could not then serve
/// the bytes. A node short of the disk to hold its chunks produces every one of those, so
/// leaving any of them out would stop some of its accusers and not others.
///
/// Only the penalty is withheld. The caller has already logged the failure with its type,
/// class and key, and that record is what tells us when it is safe to switch the penalty
/// back on.
pub async fn penalise_unheld_close_group_chunk(
    p2p_node: &Arc<P2PNode>,
    peer: &PeerId,
    audit_type: &str,
    weight: f64,
) {
    if close_group_storage_penalty_suspended() {
        debug!(
            audit_type,
            peer = %peer,
            "Recorded but not penalised: this release withholds the penalty for not \
             holding a close-group chunk. Commitment-bound audits still penalise."
        );
        return;
    }
    p2p_node
        .report_trust_event(peer, TrustEvent::ApplicationFailure(weight))
        .await;
}

/// Probability of launching a subtree audit when a peer's *changed* commitment
/// is ingested via gossip (ADR-0002). Keeps audits occasional surprise exams.
pub const AUDIT_ON_GOSSIP_PROBABILITY: f64 = 0.2;

/// Per-peer cooldown between gossip-triggered subtree audits (ADR-0002), in
/// seconds. Bounds how often any one peer is audited regardless of gossip rate.
pub const AUDIT_ON_GOSSIP_COOLDOWN_SECS: u64 = 30 * 60;

/// ADR-0004: first-audit drainer retry cadence for cooldown-pending pins.
///
/// How often the drainer retries pins it kept pending because their peer was on
/// cooldown. Finer than the cooldown itself so a monetized commitment is
/// first-audited promptly after its peer's window reopens; the retry just
/// re-checks a small per-peer map, so the tick is cheap.
pub const FIRST_AUDIT_RETRY_INTERVAL: Duration = Duration::from_mins(1);

/// Interval for the cumulative first-audit scheduler observability summary.
///
/// Deliberately low frequency: this is intended for fleet-level Elasticsearch
/// aggregation without recreating the high-volume logging load it measures.
pub const FIRST_AUDIT_SUMMARY_INTERVAL: Duration = Duration::from_mins(5);

/// ADR-0004: max monetized-pin events the first-audit drainer drains from its
/// channel per wake before it must run the audit-launch phase.
///
/// Bounds the synchronous `try_recv` batch so a sustained producer flood cannot
/// starve audit launching by spinning in the drain loop forever. After this many
/// events the drainer processes audits, then loops back to drain more.
pub const FIRST_AUDIT_DRAIN_BATCH: usize = 64;

/// ADR-0004 Amendment 2: token-bucket refill interval for monetized first-audit
/// launches — one launch token per interval, per node.
///
/// This is the load-bearing bound: fleet-wide first-audit pressure becomes
/// `nodes x (1 / interval)` regardless of upload volume, where the pre-amendment
/// scheduler scaled with `uploads x pinned-quotes-per-proof x verifying-storers`
/// (measured at ~110 storage-commitment audit events/hour/service in the
/// DEV-01 staging run, with 77.7% of launches timing out in the DEV-03
/// per-service-concurrency attempt). At 5 minutes the sustained rate is
/// 12 launches/hour/node (a drained burst bucket adds at most
/// [`FIRST_AUDIT_BUDGET_BURST`] more in the first hour); steady-state demand
/// sits far below it because nomination is paid-pin-only and re-nominations
/// are suppressed by [`FIRST_AUDIT_PEER_REAUDIT_INTERVAL`].
pub const FIRST_AUDIT_LAUNCH_INTERVAL: Duration = Duration::from_mins(5);

/// ADR-0004 Amendment 2: token-bucket capacity for monetized first-audit
/// launches.
///
/// Lets a node absorb a small burst of NEW earning peers (several distinct
/// paid pins verified back-to-back) without waiting a full refill interval per
/// launch, while keeping the sustained rate pinned to
/// [`FIRST_AUDIT_LAUNCH_INTERVAL`].
pub const FIRST_AUDIT_BUDGET_BURST: u32 = 2;

/// ADR-0004 Amendment 2: max concurrently in-flight monetized first audits per
/// node.
///
/// A first audit can hold a slot for the full size-scaled two-round deadline,
/// so without this cap a burst of slow/timing-out targets would pile up
/// concurrent subtree audits even under the launch-rate budget. Deferral is
/// penalty-free: the pin stays pending and is retried when a slot frees.
pub const FIRST_AUDIT_MAX_INFLIGHT: u64 = 2;

/// ADR-0004 Amendment 2: max uniform random delay applied before sending a
/// monetized first-audit challenge.
///
/// Every storer of a chunk verifies the same payment at the same instant, so
/// unjittered first audits from the whole close group would hit the paid peer
/// simultaneously and trip its per-peer responder admission cap (drops that
/// auditors then record as Timeout). The jitter decorrelates the observers.
pub const FIRST_AUDIT_LAUNCH_JITTER_MAX: Duration = Duration::from_secs(30);

/// ADR-0004 Amendment 2: per-peer suppression window between monetized first
/// audits, across commitment rotations.
///
/// Pin-level dedup alone is defeated by the hourly commitment rotation (every
/// rotation mints a fresh pin, re-arming every observer). After a first audit
/// LAUNCHES at a peer, further monetized nominations for that peer are dropped
/// for this window — unless the new pin's committed key count exceeds the
/// audited one by more than [`FIRST_AUDIT_COUNT_JUMP_NUM`]/
/// [`FIRST_AUDIT_COUNT_JUMP_DEN`] (a peer that passes an audit on an honest
/// count and then mints a much larger commitment must be re-nominated
/// immediately: inflated SIDECAR-ONLY pins are visible to payment verifiers
/// only, so no gossip-lottery audit can ever cover them). Kept comfortably
/// inside the 3h answerability TTL so a re-nomination after the window still
/// lands in-window. Gossip-lottery re-audits are unaffected.
pub const FIRST_AUDIT_PEER_REAUDIT_INTERVAL: Duration = Duration::from_hours(2);

/// ADR-0004 Amendment 2: committed-count jump that overrides the per-peer
/// re-audit window, as a ratio (`new > old * NUM / DEN`, integer math).
///
/// 3/2: a >1.5x growth in claimed committed keys within the suppression window
/// re-nominates the peer despite a recent first audit.
pub const FIRST_AUDIT_COUNT_JUMP_NUM: u64 = 3;
/// Denominator of the count-jump override ratio. See
/// [`FIRST_AUDIT_COUNT_JUMP_NUM`].
pub const FIRST_AUDIT_COUNT_JUMP_DEN: u64 = 2;

/// ADR-0004 Amendment 2: capacity of the bounded verifier-to-drainer
/// monetized-pin channel.
///
/// Nominations are gated behind SETTLED on-chain payments, so legitimate
/// ingress is tiny; the drainer drains every wake (batched at
/// [`FIRST_AUDIT_DRAIN_BATCH`]) and coalesces newest-per-peer, so a backlog
/// this deep implies the drainer is starved, not that work is arriving fast.
/// Producers `try_send` and drop on full: a dropped nomination is
/// penalty-free; the peer's gossiped commitments stay lottery-covered and
/// its next settled payment re-nominates the paid pin.
pub const FIRST_AUDIT_INGRESS_CAPACITY: usize = 1024;

/// Number of subtree leaves spot-checked against real chunk bytes per audit
/// (ADR-0002 real-bytes layer).
///
/// The auditor clamps this to its 3..=5 band (`BYTE_SPOTCHECK_MIN..=MAX` in
/// `storage_commitment_audit`), so this is the effective MAXIMUM — set it
/// within the band rather than advertising a sample size the auditor never
/// requests.
pub const AUDIT_SPOTCHECK_COUNT: u32 = 5;

/// Conservative leaf-count hint for sizing the subtree-audit response deadline.
///
/// The deadline is set before the proof arrives, so we size for the largest
/// legal store: `sqrt(MAX_COMMITMENT_KEY_COUNT) = 1000`. Honest small stores
/// finish well within it.
pub const SUBTREE_AUDIT_TIMEOUT_LEAF_HINT: usize = 1000;

/// Maximum mature records selected for prune-confirmation auditing per pass.
///
/// This bounds local digest/proof bookkeeping independently from the number
/// of network requests. Keys for the same peer are batched below.
pub const MAX_PRUNE_AUDIT_CANDIDATES_PER_PASS: usize = 1024;

/// Maximum initial prune-confirmation audit requests sent per pass.
///
/// A request may contain multiple keys. Keeping this separate from the
/// candidate cap prevents the old candidate-to-peer-edge accounting from
/// limiting a production pass to roughly nine records.
pub const MAX_PRUNE_AUDIT_REQUESTS_PER_PASS: usize = 256;

/// Maximum mature records deleted through the complete width-20 fast path per
/// pass.
pub const MAX_FAST_PRUNE_DELETIONS_PER_PASS: usize = 2048;

/// Seconds to wait for `DhtNetworkEvent::BootstrapComplete` before proceeding
/// with bootstrap sync. Covers bootstrap nodes with no peers to connect to.
const BOOTSTRAP_COMPLETE_TIMEOUT_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Runtime-configurable wrapper
// ---------------------------------------------------------------------------

/// Runtime-configurable replication parameters.
///
/// Validated on construction — node rejects invalid configs.
#[derive(Debug, Clone)]
pub struct ReplicationConfig {
    /// Close-group width and target holder count per key.
    pub close_group_size: usize,
    /// Required positive presence votes for quorum.
    pub quorum_threshold: usize,
    /// Maximum closest nodes tracking paid status for a key.
    pub paid_list_close_group_size: usize,
    /// Number of closest peers to self eligible for neighbor sync.
    pub neighbor_sync_scope: usize,
    /// Peers synced concurrently per round-robin repair round.
    pub neighbor_sync_peer_count: usize,
    /// Neighbor sync cadence range (min).
    pub neighbor_sync_interval_min: Duration,
    /// Neighbor sync cadence range (max).
    pub neighbor_sync_interval_max: Duration,
    /// Minimum spacing between successive syncs with the same peer.
    pub neighbor_sync_cooldown: Duration,
    /// Self-lookup cadence range (min).
    pub self_lookup_interval_min: Duration,
    /// Self-lookup cadence range (max).
    pub self_lookup_interval_max: Duration,
    /// Audit scheduler cadence range (min).
    pub audit_tick_interval_min: Duration,
    /// Audit scheduler cadence range (max).
    pub audit_tick_interval_max: Duration,
    /// Floor on the audit response deadline. Covers global RTT for
    /// the small request/response envelope plus scheduling jitter.
    /// See `AUDIT_RESPONSE_FLOOR_SECS` for sizing.
    pub audit_response_floor: Duration,
    /// Conservative honest-responder read throughput (bytes/sec).
    /// Used to scale the audit response deadline against the size of
    /// the challenge. Slow enough that even an HDD-backed honest peer
    /// fits inside the budget; fast enough that a relay attacker who
    /// must fetch bytes over the network falls outside.
    pub audit_honest_read_bps: u64,
    /// Slack multiplier on the honest-read estimate before
    /// declaring an audit timed out.
    pub audit_response_honest_multiplier: u64,
    /// Maximum duration a peer may claim bootstrap status.
    pub bootstrap_claim_grace_period: Duration,
    /// Minimum continuous out-of-range duration before pruning a key.
    pub prune_hysteresis_duration: Duration,
    /// Verification request timeout (per-batch).
    pub verification_request_timeout: Duration,
    /// Fetch request timeout.
    pub fetch_request_timeout: Duration,
    /// Seconds to wait for `DhtNetworkEvent::BootstrapComplete` before
    /// proceeding with bootstrap sync (covers bootstrap nodes with no peers).
    pub bootstrap_complete_timeout_secs: u64,
    /// Lower bound of the delay before a fresh-replication possession check
    /// runs (ADR-0003). Defaults to [`POSSESSION_CHECK_DELAY_MIN`]; tests
    /// shorten it so the scheduled check fires quickly.
    pub possession_check_delay_min: Duration,
    /// Upper bound of the possession-check delay window (ADR-0003). Defaults
    /// to [`POSSESSION_CHECK_DELAY_MAX`].
    pub possession_check_delay_max: Duration,
    /// Per-peer responder-side cooldown between heavy subtree round-1 proofs.
    /// Defaults to [`SUBTREE_ROUND1_RESPONDER_COOLDOWN`]; tests set
    /// it low so rapid back-to-back audits of one holder are not rate-dropped.
    pub subtree_round1_responder_cooldown: Duration,
    /// Global ceiling on concurrent heavy subtree round-1 proofs this node will
    /// serve. Defaults to [`MAX_CONCURRENT_SUBTREE_ROUND1`].
    ///
    /// Exposed here rather than read straight from the constant because it is the
    /// tightest bound the responder applies and the one with the least fleet
    /// evidence behind its value: too low and honest auditors are capacity-dropped
    /// (their audits land in the graced timeout lane, so coverage silently falls
    /// without any peer being penalised), too high and concurrent full-subtree
    /// hashing competes with serving real traffic. Making it configurable means a
    /// fleet that lands on the wrong number can be retuned without cutting a
    /// release. A value of 0 is clamped to 1 by
    /// [`SubtreeRound1Limiter::new`](crate::replication) rather than disabling
    /// round 1 outright.
    pub subtree_round1_max_concurrent: usize,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            close_group_size: CLOSE_GROUP_SIZE,
            quorum_threshold: QUORUM_THRESHOLD,
            paid_list_close_group_size: PAID_LIST_CLOSE_GROUP_SIZE,
            neighbor_sync_scope: NEIGHBOR_SYNC_SCOPE,
            neighbor_sync_peer_count: NEIGHBOR_SYNC_PEER_COUNT,
            neighbor_sync_interval_min: NEIGHBOR_SYNC_INTERVAL_MIN,
            neighbor_sync_interval_max: NEIGHBOR_SYNC_INTERVAL_MAX,
            neighbor_sync_cooldown: NEIGHBOR_SYNC_COOLDOWN,
            self_lookup_interval_min: SELF_LOOKUP_INTERVAL_MIN,
            self_lookup_interval_max: SELF_LOOKUP_INTERVAL_MAX,
            audit_tick_interval_min: AUDIT_TICK_INTERVAL_MIN,
            audit_tick_interval_max: AUDIT_TICK_INTERVAL_MAX,
            audit_response_floor: Duration::from_secs(AUDIT_RESPONSE_FLOOR_SECS),
            audit_honest_read_bps: AUDIT_HONEST_READ_BPS,
            audit_response_honest_multiplier: AUDIT_RESPONSE_HONEST_MULTIPLIER,
            bootstrap_claim_grace_period: BOOTSTRAP_CLAIM_GRACE_PERIOD,
            prune_hysteresis_duration: PRUNE_HYSTERESIS_DURATION,
            verification_request_timeout: VERIFICATION_REQUEST_TIMEOUT,
            fetch_request_timeout: FETCH_REQUEST_TIMEOUT,
            bootstrap_complete_timeout_secs: BOOTSTRAP_COMPLETE_TIMEOUT_SECS,
            possession_check_delay_min: POSSESSION_CHECK_DELAY_MIN,
            possession_check_delay_max: POSSESSION_CHECK_DELAY_MAX,
            subtree_round1_responder_cooldown: SUBTREE_ROUND1_RESPONDER_COOLDOWN,
            subtree_round1_max_concurrent: MAX_CONCURRENT_SUBTREE_ROUND1,
        }
    }
}

impl ReplicationConfig {
    /// Validate safety constraints. Returns `Err` with a description if any
    /// constraint is violated.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message describing the first violated
    /// constraint.
    pub fn validate(&self) -> Result<(), String> {
        if self.close_group_size == 0 {
            return Err("close_group_size must be >= 1".to_string());
        }
        if self.quorum_threshold == 0 || self.quorum_threshold > self.close_group_size {
            return Err(format!(
                "quorum_threshold ({}) must satisfy 1 <= quorum_threshold <= close_group_size ({})",
                self.quorum_threshold, self.close_group_size,
            ));
        }
        if self.close_group_size > MAX_PRUNE_AUDIT_REQUESTS_PER_PASS {
            return Err(format!(
                "close_group_size ({}) must be <= MAX_PRUNE_AUDIT_REQUESTS_PER_PASS ({})",
                self.close_group_size, MAX_PRUNE_AUDIT_REQUESTS_PER_PASS,
            ));
        }
        if self.paid_list_close_group_size == 0 {
            return Err("paid_list_close_group_size must be >= 1".to_string());
        }
        if self.neighbor_sync_interval_min > self.neighbor_sync_interval_max {
            return Err(format!(
                "neighbor_sync_interval_min ({:?}) must be <= neighbor_sync_interval_max ({:?})",
                self.neighbor_sync_interval_min, self.neighbor_sync_interval_max,
            ));
        }
        if self.audit_tick_interval_min > self.audit_tick_interval_max {
            return Err(format!(
                "audit_tick_interval_min ({:?}) must be <= audit_tick_interval_max ({:?})",
                self.audit_tick_interval_min, self.audit_tick_interval_max,
            ));
        }
        if self.self_lookup_interval_min > self.self_lookup_interval_max {
            return Err(format!(
                "self_lookup_interval_min ({:?}) must be <= self_lookup_interval_max ({:?})",
                self.self_lookup_interval_min, self.self_lookup_interval_max,
            ));
        }
        if self.neighbor_sync_peer_count == 0 {
            return Err("neighbor_sync_peer_count must be >= 1".to_string());
        }
        if self.neighbor_sync_scope == 0 {
            return Err("neighbor_sync_scope must be >= 1".to_string());
        }
        if self.neighbor_sync_scope > K_BUCKET_SIZE {
            return Err(format!(
                "neighbor_sync_scope ({}) must be <= K_BUCKET_SIZE ({})",
                self.neighbor_sync_scope, K_BUCKET_SIZE,
            ));
        }
        Ok(())
    }

    /// Effective quorum votes required for a key given the number of
    /// reachable quorum targets.
    ///
    /// `min(self.quorum_threshold, floor(quorum_targets_count / 2) + 1)`
    #[must_use]
    pub fn quorum_needed(&self, quorum_targets_count: usize) -> usize {
        if quorum_targets_count == 0 {
            return 0;
        }
        let majority = quorum_targets_count / 2 + 1;
        self.quorum_threshold.min(majority)
    }

    /// Confirmations required for paid-list consensus given the number of
    /// peers in the paid-list close group for a key.
    ///
    /// `floor(paid_group_size / 2) + 1`
    #[must_use]
    pub fn confirm_needed(paid_group_size: usize) -> usize {
        paid_group_size / 2 + 1
    }

    /// Confirmations required to authorize a key, given the edge-discounted
    /// denominator and the true (undiscounted) group size.
    ///
    /// The strict majority of the discounted group, raised to
    /// [`PAID_LIST_ABSOLUTE_CONFIRM_FLOOR`] so a shrunken denominator cannot
    /// make a single voter decisive — but never above `full_group_size`, which
    /// would demand more confirmations than there are peers to give them.
    #[must_use]
    pub fn paid_confirm_needed(effective_group_size: usize, full_group_size: usize) -> usize {
        Self::confirm_needed(effective_group_size)
            .max(PAID_LIST_ABSOLUTE_CONFIRM_FLOOR.min(full_group_size))
    }

    /// Number of furthest peers treated as churny edge voters for a paid close
    /// group of `paid_group_size`, when the group is at full configured width.
    ///
    /// Scaled to the group so the discount stays proportionate at every
    /// configured width, and capped at [`PAID_LIST_FLEX_EDGE_COUNT`]. Returns
    /// `0` for an undersized group, which keeps its ordinary strict majority.
    #[must_use]
    pub fn paid_list_flex_edge_count(
        paid_group_size: usize,
        configured_group_size: usize,
    ) -> usize {
        if paid_group_size < configured_group_size {
            return 0;
        }
        PAID_LIST_FLEX_EDGE_COUNT.min(configured_group_size / PAID_LIST_FLEX_EDGE_DIVISOR)
    }

    /// Returns a random duration in `[neighbor_sync_interval_min,
    /// neighbor_sync_interval_max]`.
    #[must_use]
    pub fn random_neighbor_sync_interval(&self) -> Duration {
        random_duration_in_range(
            self.neighbor_sync_interval_min,
            self.neighbor_sync_interval_max,
        )
    }

    /// Maximum age of an outstanding bootstrap capacity-rejection record.
    ///
    /// A source is revisited only after the round-robin loop has advanced
    /// through every neighbor batch. Size the window from that full configured
    /// cycle (including one request deadline per peer), the peer cooldown, and
    /// one slow-cadence interval of slack. This prevents a live source near the
    /// end of a 20-peer cycle from being expired before it can legitimately
    /// re-deliver its rejected hints.
    #[must_use]
    pub fn capacity_rejected_max_age(&self) -> Duration {
        let batch_size = self.neighbor_sync_peer_count.max(1);
        let batch_count = self.neighbor_sync_scope.saturating_add(batch_size - 1) / batch_size;
        let batch_count = u32::try_from(batch_count).unwrap_or(u32::MAX);
        let peer_count = u32::try_from(self.neighbor_sync_scope).unwrap_or(u32::MAX);
        let full_cycle = self
            .neighbor_sync_interval_max
            .saturating_mul(batch_count)
            .saturating_add(self.verification_request_timeout.saturating_mul(peer_count));

        full_cycle
            .max(self.neighbor_sync_cooldown)
            .saturating_add(self.neighbor_sync_interval_max)
    }

    /// Compute the number of keys to sample for an audit round, scaled
    /// dynamically by the total number of locally stored keys.
    ///
    /// Formula: `max(floor(sqrt(total_keys)), 1)`, capped at `total_keys`.
    #[must_use]
    pub fn audit_sample_count(total_keys: usize) -> usize {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let sqrt = (total_keys as f64).sqrt() as usize;
        sqrt.max(1).min(total_keys)
    }

    /// Maximum number of keys this node should send in one responsible-chunk
    /// [`AuditChallenge`].
    ///
    /// This is the sender-side limit used by the normal responsible audit path:
    /// one challenge samples at most `sqrt(local_stored_keys)` keys. Other paths
    /// that reuse the same `AuditChallenge` wire message, such as
    /// prune-confirmation audits, should chunk to this same limit instead of
    /// inventing a larger batch size.
    ///
    /// [`AuditChallenge`]: crate::replication::protocol::AuditChallenge
    #[must_use]
    pub fn responsible_audit_key_limit(local_stored_keys: usize) -> usize {
        Self::audit_sample_count(local_stored_keys)
    }

    /// Maximum number of keys to accept in an incoming audit challenge.
    ///
    /// Scales dynamically from the same responsible-audit sender limit, with a
    /// 2x margin to account for the challenger having a larger local store than
    /// us and therefore sampling more keys.
    #[must_use]
    pub fn max_incoming_audit_keys(stored_chunks: usize) -> usize {
        // Allow at least 1 key so a newly-joined node can still be audited.
        (2 * Self::responsible_audit_key_limit(stored_chunks)).max(1)
    }

    /// Compute the audit response timeout for a challenge with
    /// `challenged_key_count` keys, **sized to be tight enough that a
    /// relay attacker that must fetch the chunk bytes from elsewhere
    /// falls outside the budget**.
    ///
    /// Formula:
    ///   `floor + (challenged_bytes / honest_read_bps) × multiplier`
    ///
    /// Where `challenged_bytes = k × MAX_CHUNK_SIZE`. An honest peer
    /// reads `k × 4 MiB` from local disk at `honest_read_bps` (set
    /// conservatively at 50 MB/s — well below modern SSDs); the
    /// multiplier of 5 absorbs jitter, BLAKE3, ML-DSA, and slow disks.
    ///
    /// A relay attacker on a residential link (~5-12 MB/s) who must
    /// fetch the same `k × 4 MiB` over the network sees ~10-100× higher
    /// latency than disk for the data alone, plus per-chunk round-trips,
    /// and misses the budget. In the periodic responsible-chunk
    /// `AuditChallenge`, prune-confirmation, and ADR-0003 possession-check paths
    /// that timeout is an immediate audit failure. The heavier subtree audit
    /// still graces timeouts separately.
    ///
    /// This is an economic deterrent for the §7 relay limit calibrated
    /// for residential bandwidth, NOT a hard bound: a relay on a
    /// datacenter cross-connect (≥1 Gbps) can fetch `k × 4 MiB` fast
    /// enough to answer in time. It raises the relay's cost (bandwidth
    /// per audit) without claiming to make relaying impossible. The
    /// cryptographic guarantee remains commitment-binding (the relay
    /// must still hold or fetch the exact committed bytes); the timeout
    /// only attacks the economics.
    #[must_use]
    pub fn audit_response_timeout(&self, challenged_key_count: usize) -> Duration {
        let bytes_per_key = u64::try_from(crate::ant_protocol::MAX_CHUNK_SIZE).unwrap_or(u64::MAX);
        let keys = u64::try_from(challenged_key_count).unwrap_or(u64::MAX);
        let total_bytes = bytes_per_key.saturating_mul(keys);
        let bps = self.audit_honest_read_bps.max(1);
        // Apply the multiplier BEFORE integer-dividing by bps so each
        // chunk contributes a fractional second rather than rounding
        // down to zero. Otherwise k in 1..=12 would all collapse to the
        // floor (~40 MiB / 50 MB/s = 0 secs in integer arithmetic), and
        // an honest HDD-backed peer at sqrt(N)=10 stored chunks could
        // miss the budget under load.
        let multiplied = total_bytes.saturating_mul(self.audit_response_honest_multiplier);
        // Resolve the scaled term in MILLISECONDS, not seconds: at small
        // sample sizes (e.g. a 2-key challenge → 8 MiB) the per-second quotient
        // `multiplied / bps` integer-truncates to 0, leaving only the floor.
        // Small challenges still need the sub-second honest-read estimate
        // (e.g. 8 MiB × 5 / 50 MB/s ≈ 840 ms) instead of dropping it.
        let scaled_ms = multiplied.saturating_mul(1000) / bps;
        // saturating_add avoids a panic if the floor plus the scaled term would
        // overflow `Duration::MAX`.
        self.audit_response_floor
            .saturating_add(Duration::from_millis(scaled_ms))
    }

    /// Deadline for the round-2 SLICE challenge opening `openings` blocks.
    ///
    /// The reply itself is only a few KB per opening (a 1 KiB block plus two
    /// short hash chains), but an honest responder still reads each opened
    /// chunk's full bytes from disk to build its Bao slice and nonced opening. So
    /// the deadline is sized to that honest full-chunk disk read (the same
    /// per-byte scaling as [`Self::audit_response_timeout`], one full chunk per
    /// opening), on the `BYTE_AUDIT_RESPONSE_FLOOR_SECS` floor to absorb the
    /// handshake and a busy disk.
    ///
    /// The deadline is not a security parameter, and this is worth stating
    /// precisely because an earlier version of this comment claimed more than
    /// it should. The round-1 `nonced_root` is uncomputable without all the
    /// bytes under a fresh nonce, but that binds only that SOMEONE holding them
    /// computed it, not that the audited peer did: nonce, peer id and key are
    /// all public, so a backend holding one copy can compute roots and openings
    /// for any number of front-end identities, and only the compact proof
    /// crosses the link. The old full-byte round 2 did not prevent that either
    /// — it priced it, by forcing megabytes through the relay per audit, and a
    /// tight deadline was part of that price. Both are gone here. So the
    /// deadline exists only to bound how long the auditor waits for an honest
    /// reply, and non-delegability is not a property either design provides;
    /// see ADR-0009 for where that is left.
    #[must_use]
    pub fn slice_audit_response_timeout(&self, openings: usize) -> Duration {
        let scaled = self
            .audit_response_timeout(openings)
            .saturating_sub(self.audit_response_floor);
        Duration::from_secs(BYTE_AUDIT_RESPONSE_FLOOR_SECS).saturating_add(scaled)
    }

    /// Number of subtree leaves to spot-check against real chunk bytes per
    /// audit (ADR-0002 real-bytes layer). Faking a fraction `x` of nonced
    /// leaves survives only `(1 - x)^k`.
    #[must_use]
    pub fn audit_spotcheck_count(&self) -> u32 {
        AUDIT_SPOTCHECK_COUNT
    }

    /// Conservative leaf-count hint for sizing the subtree-audit response
    /// deadline before the proof arrives.
    ///
    /// The selected subtree holds about `sqrt(key_count)` real leaves; sizing
    /// for a large store keeps an honest peer with a big store from timing out.
    #[must_use]
    pub fn subtree_audit_timeout_leaf_hint(&self) -> usize {
        SUBTREE_AUDIT_TIMEOUT_LEAF_HINT
    }

    /// Returns a random duration in `[audit_tick_interval_min,
    /// audit_tick_interval_max]`.
    #[must_use]
    pub fn random_audit_tick_interval(&self) -> Duration {
        random_duration_in_range(self.audit_tick_interval_min, self.audit_tick_interval_max)
    }

    /// Returns a random duration in `[self_lookup_interval_min,
    /// self_lookup_interval_max]`.
    #[must_use]
    pub fn random_self_lookup_interval(&self) -> Duration {
        random_duration_in_range(self.self_lookup_interval_min, self.self_lookup_interval_max)
    }
}

/// Pick a random `Duration` uniformly in `[min, max]` at millisecond
/// granularity.
///
/// When `min == max` the result is deterministic.
fn random_duration_in_range(min: Duration, max: Duration) -> Duration {
    if min == max {
        return min;
    }
    // Our intervals are minutes/hours, well within u64 range. Saturate to
    // u64::MAX on the impossible overflow path to avoid a lossy cast.
    let to_u64_millis = |d: Duration| -> u64 { u64::try_from(d.as_millis()).unwrap_or(u64::MAX) };
    let chosen = rand::thread_rng().gen_range(to_u64_millis(min)..=to_u64_millis(max));
    Duration::from_millis(chosen)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn defaults_pass_validation() {
        let config = ReplicationConfig::default();
        assert!(config.validate().is_ok(), "default config must be valid");
    }

    #[test]
    fn default_prune_hysteresis_is_three_days() {
        let config = ReplicationConfig::default();
        assert_eq!(config.prune_hysteresis_duration, Duration::from_hours(72));
    }

    #[test]
    fn storage_admission_width_adds_margin() {
        const TEST_CLOSE_GROUP_SIZE: usize = 7;

        assert_eq!(
            storage_admission_width(TEST_CLOSE_GROUP_SIZE),
            TEST_CLOSE_GROUP_SIZE + STORAGE_ADMISSION_MARGIN
        );
        assert_eq!(storage_admission_width(usize::MAX), usize::MAX);
    }

    #[test]
    fn audit_failure_weight_is_five() {
        assert!((AUDIT_FAILURE_TRUST_WEIGHT - 5.0).abs() <= f64::EPSILON);
    }

    /// One test rather than several, because the switch is process-wide: separate tests
    /// would race each other under the default parallel runner.
    #[test]
    #[serial]
    fn the_unheld_chunk_penalty_switch_follows_the_release_it_is_compiled_into() {
        // A build that never applies the policy still behaves like THIS release, not the
        // previous one. `ReplicationEngine::new` is public and is constructed directly by
        // test harnesses, so defaulting the other way would leave those engines penalising
        // exactly what the release exists to stop penalising.
        assert_eq!(
            close_group_storage_penalty_suspended(),
            RELEASE_SUSPEND_CLOSE_GROUP_STORAGE_PENALTY
        );

        set_close_group_storage_penalty_suspended(true);
        assert!(close_group_storage_penalty_suspended());
        set_close_group_storage_penalty_suspended(false);
        assert!(!close_group_storage_penalty_suspended());

        // And applying the release policy lands on whatever this build ships, without
        // asserting the constant itself, which the follow-up release flips on purpose.
        apply_and_announce(RELEASE_SUSPEND_CLOSE_GROUP_STORAGE_PENALTY);
        assert_eq!(
            close_group_storage_penalty_suspended(),
            RELEASE_SUSPEND_CLOSE_GROUP_STORAGE_PENALTY
        );
    }

    #[test]
    fn core_replication_id_stays_v2_and_subtree_rides_its_own_id() {
        // Core replication, including all digest audit lanes, stays on v2.
        // Only the subtree family changed and therefore receives a separate id.
        assert_eq!(REPLICATION_PROTOCOL_ID, "autonomi.ant.replication.v2");
        assert_eq!(
            SUBTREE_AUDIT_PROTOCOL_ID,
            "autonomi.ant.replication.subtree-audit.v1"
        );
        assert_ne!(REPLICATION_PROTOCOL_ID, SUBTREE_AUDIT_PROTOCOL_ID);
    }

    #[test]
    fn audit_response_timeout_floor_at_zero_keys() {
        let config = ReplicationConfig::default();
        assert_eq!(
            config.audit_response_timeout(0),
            Duration::from_secs(AUDIT_RESPONSE_FLOOR_SECS),
            "zero-key challenge should yield the floor exactly"
        );
    }

    #[test]
    fn audit_response_timeout_scales_with_key_count() {
        let config = ReplicationConfig::default();
        let t1 = config.audit_response_timeout(1);
        let t10 = config.audit_response_timeout(10);
        let t100 = config.audit_response_timeout(100);
        assert!(t1 <= t10 && t10 < t100, "timeout must not decrease with k");

        // Scaling now resolves in MILLISECONDS so a sub-second honest read no
        // longer truncates to zero (§4). For k=1:
        // (4_194_304 × 5 × 1000) / 52_428_800 = 400 ms, + 4 s round-1 floor =
        // 4.4 s.
        assert_eq!(t1, Duration::from_millis(4400));

        // For k=10: (10 × 4_194_304 × 5 × 1000) / 52_428_800 = 4000 ms scaled,
        // + 4 s floor = 8 s. An HDD-backed honest peer at 20 MB/s reads 40 MiB
        // in ~2 s, comfortably inside; a relay fetching 40 MiB at 5 MB/s
        // residential bandwidth needs ~8 s for the data alone, outside.
        assert_eq!(t10, Duration::from_secs(8));

        // For k=100: (100 × 4_194_304 × 5 × 1000) / 52_428_800 = 40_000 ms
        // scaled, + 4 s floor = 44 s.
        assert_eq!(t100, Duration::from_secs(44));
    }

    #[test]
    fn audit_response_timeout_fits_honest_hdd_at_typical_sample_size() {
        // The canonical audit sample is sqrt(N) at N stored chunks.
        // At N=100 stored chunks, sample is 10. An HDD-backed honest
        // peer at the slowest realistic random-read throughput (20 MB/s,
        // well below modern HDDs which sustain 80-150 MB/s sequential)
        // reads 10 × 4 MiB = 40 MiB in ~2 s. Add 300 ms cross-continent
        // RTT, ~10 ms scheduling, ~3 ms ML-DSA sign, and the honest
        // envelope is ~2.3 s. The 8 s budget at k=10 leaves >5 s of
        // slack.
        let config = ReplicationConfig::default();
        let budget = config.audit_response_timeout(10);
        let realistic_hdd_bps: u64 = 20 * 1024 * 1024;
        let bytes: u64 = 10 * 4 * 1024 * 1024;
        let honest_envelope_secs = bytes / realistic_hdd_bps + 1; // +1 s for network/scheduling/sign
        assert!(
            Duration::from_secs(honest_envelope_secs) < budget,
            "honest HDD envelope ({honest_envelope_secs}s) must fit inside k=10 budget ({}s)",
            budget.as_secs(),
        );
    }

    #[test]
    fn audit_response_timeout_relay_is_outside_envelope() {
        // The intended invariant: an honest peer with the SSD-class
        // read budget fits inside `audit_response_timeout(k)`, while a
        // relay attacker fetching k*4MiB over residential bandwidth
        // (≈ 5 MB/s realistic for sustained download) does NOT. Spot-
        // check this at k=100: honest budget is 44s, relay needs at
        // least 100 * 4 MiB / 5 MB/s = 80s for the data alone, which
        // exceeds the budget.
        let config = ReplicationConfig::default();
        let budget = config.audit_response_timeout(100);
        let relay_data_only = Duration::from_secs(100 * 4 * 1024 * 1024 / (5 * 1024 * 1024));
        assert!(
            relay_data_only > budget,
            "relay fetch ({}s) must exceed honest audit budget ({}s)",
            relay_data_only.as_secs(),
            budget.as_secs(),
        );
    }

    #[test]
    fn audit_response_timeout_saturates_on_huge_k() {
        let config = ReplicationConfig::default();
        // Should not panic or overflow at extreme k values.
        let _ = config.audit_response_timeout(usize::MAX);
    }

    #[test]
    fn quorum_threshold_zero_rejected() {
        let config = ReplicationConfig {
            quorum_threshold: 0,
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn quorum_threshold_exceeds_close_group_rejected() {
        let defaults = ReplicationConfig::default();
        let config = ReplicationConfig {
            quorum_threshold: defaults.close_group_size + 1,
            ..defaults
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn close_group_size_zero_rejected() {
        let config = ReplicationConfig {
            close_group_size: 0,
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn close_group_size_exceeding_prune_audit_request_budget_rejected() {
        let config = ReplicationConfig {
            close_group_size: MAX_PRUNE_AUDIT_REQUESTS_PER_PASS + 1,
            quorum_threshold: QUORUM_THRESHOLD,
            ..ReplicationConfig::default()
        };

        let err = config.validate().unwrap_err();

        assert!(
            err.contains("MAX_PRUNE_AUDIT_REQUESTS_PER_PASS"),
            "error should mention prune audit budget: {err}"
        );
    }

    #[test]
    fn paid_list_close_group_size_zero_rejected() {
        let config = ReplicationConfig {
            paid_list_close_group_size: 0,
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn neighbor_sync_interval_inverted_rejected() {
        let config = ReplicationConfig {
            neighbor_sync_interval_min: Duration::from_secs(100),
            neighbor_sync_interval_max: Duration::from_secs(50),
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn capacity_rejection_expiry_covers_full_configured_sync_cycle() {
        let config = ReplicationConfig {
            // Keep the scope deliberately indivisible by the batch size so the
            // expectation verifies that the final partial batch is included.
            neighbor_sync_scope: 21,
            neighbor_sync_peer_count: 4,
            ..ReplicationConfig::default()
        };
        let batches = config
            .neighbor_sync_scope
            .div_ceil(config.neighbor_sync_peer_count);
        let cycle_cadence = config.neighbor_sync_interval_max * u32::try_from(batches).unwrap();
        let request_budget = config.verification_request_timeout
            * u32::try_from(config.neighbor_sync_scope).unwrap();
        let full_cycle = cycle_cadence + request_budget;

        assert_eq!(
            config.capacity_rejected_max_age(),
            full_cycle + config.neighbor_sync_interval_max,
        );
        assert!(config.capacity_rejected_max_age() > Duration::from_secs(70 * 60));
    }

    #[test]
    fn capacity_rejection_expiry_tracks_runtime_sync_configuration() {
        let config = ReplicationConfig {
            neighbor_sync_scope: 9,
            neighbor_sync_peer_count: 2,
            neighbor_sync_interval_max: Duration::from_secs(10),
            neighbor_sync_cooldown: Duration::from_secs(100),
            verification_request_timeout: Duration::from_secs(1),
            ..ReplicationConfig::default()
        };

        // Five batches take 50s and their nine request budgets take 9s, so
        // the 100s cooldown dominates; one 10s cadence interval is slack.
        assert_eq!(config.capacity_rejected_max_age(), Duration::from_secs(110));
    }

    #[test]
    fn audit_tick_interval_inverted_rejected() {
        let config = ReplicationConfig {
            audit_tick_interval_min: Duration::from_secs(100),
            audit_tick_interval_max: Duration::from_secs(50),
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn self_lookup_interval_inverted_rejected() {
        let config = ReplicationConfig {
            self_lookup_interval_min: Duration::from_secs(100),
            self_lookup_interval_max: Duration::from_secs(50),
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn neighbor_sync_peer_count_zero_rejected() {
        let config = ReplicationConfig {
            neighbor_sync_peer_count: 0,
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn neighbor_sync_scope_exceeding_k_bucket_size_rejected() {
        let config = ReplicationConfig {
            neighbor_sync_scope: K_BUCKET_SIZE + 1,
            ..ReplicationConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn audit_sample_count_scales_with_sqrt() {
        // Empty store
        assert_eq!(ReplicationConfig::audit_sample_count(0), 0);

        // Single key
        assert_eq!(ReplicationConfig::audit_sample_count(1), 1);

        // Small stores: sqrt(3)=1
        assert_eq!(ReplicationConfig::audit_sample_count(3), 1);

        // sqrt scaling
        assert_eq!(ReplicationConfig::audit_sample_count(4), 2);
        assert_eq!(ReplicationConfig::audit_sample_count(25), 5);
        assert_eq!(ReplicationConfig::audit_sample_count(100), 10);
        assert_eq!(ReplicationConfig::audit_sample_count(1_000), 31);
        assert_eq!(ReplicationConfig::audit_sample_count(7_000), 83);
        assert_eq!(ReplicationConfig::audit_sample_count(10_000), 100);
        assert_eq!(ReplicationConfig::audit_sample_count(1_000_000), 1_000);
    }

    #[test]
    fn responsible_audit_key_limit_matches_audit_sample_count() {
        for stored_keys in [0, 1, 3, 4, 25, 100, 1_000, 7_000, 10_000, 1_000_000] {
            assert_eq!(
                ReplicationConfig::responsible_audit_key_limit(stored_keys),
                ReplicationConfig::audit_sample_count(stored_keys),
                "responsible audit sender limit must stay identical to audit sample count"
            );
        }
    }

    #[test]
    fn max_incoming_audit_keys_scales_dynamically() {
        // Empty store: at least 1 key accepted.
        assert_eq!(ReplicationConfig::max_incoming_audit_keys(0), 1);

        // 1 chunk: 2 * responsible_audit_key_limit(1) = 2.
        assert_eq!(ReplicationConfig::max_incoming_audit_keys(1), 2);

        // 100 chunks: 2 * responsible_audit_key_limit(100) = 20.
        assert_eq!(ReplicationConfig::max_incoming_audit_keys(100), 20);

        // 1M chunks: 2 * responsible_audit_key_limit(1_000_000) = 2_000.
        assert_eq!(ReplicationConfig::max_incoming_audit_keys(1_000_000), 2_000);

        // 5M chunks: 2 * responsible_audit_key_limit(5_000_000) = 4_472.
        assert_eq!(ReplicationConfig::max_incoming_audit_keys(5_000_000), 4_472);
    }

    #[test]
    fn quorum_needed_uses_smaller_of_threshold_and_majority() {
        let config = ReplicationConfig::default();

        // With 7 targets: majority = 7/2+1 = 4, threshold = 4 → min = 4
        assert_eq!(config.quorum_needed(7), 4);

        // With 3 targets: majority = 3/2+1 = 2, threshold = 4 → min = 2
        assert_eq!(config.quorum_needed(3), 2);

        // With 0 targets: quorum is impossible — returns 0
        assert_eq!(config.quorum_needed(0), 0);

        // With 100 targets: majority = 51, threshold = 4 → min = 4
        assert_eq!(config.quorum_needed(100), 4);
    }

    #[test]
    fn confirm_needed_is_strict_majority() {
        assert_eq!(ReplicationConfig::confirm_needed(1), 1);
        assert_eq!(ReplicationConfig::confirm_needed(2), 2);
        assert_eq!(ReplicationConfig::confirm_needed(3), 2);
        assert_eq!(ReplicationConfig::confirm_needed(4), 3);
        assert_eq!(ReplicationConfig::confirm_needed(20), 11);
    }

    /// The edge is a proportion of the group, not a fixed four peers.
    ///
    /// A fixed four is a fifth of the production width but four fifths of a
    /// configured width of five, which collapsed the voting core to one peer.
    #[test]
    fn flex_edge_scales_with_the_configured_group() {
        // Production width is unchanged: 20 / 5 == PAID_LIST_FLEX_EDGE_COUNT.
        assert_eq!(
            ReplicationConfig::paid_list_flex_edge_count(
                PAID_LIST_CLOSE_GROUP_SIZE,
                PAID_LIST_CLOSE_GROUP_SIZE
            ),
            PAID_LIST_FLEX_EDGE_COUNT,
        );

        // Small widths keep a majority-sized core rather than a single peer.
        assert_eq!(ReplicationConfig::paid_list_flex_edge_count(5, 5), 1);
        assert_eq!(ReplicationConfig::paid_list_flex_edge_count(10, 10), 2);
        assert_eq!(ReplicationConfig::paid_list_flex_edge_count(15, 15), 3);

        // Never more than the ceiling, however wide the group is configured.
        assert_eq!(
            ReplicationConfig::paid_list_flex_edge_count(100, 100),
            PAID_LIST_FLEX_EDGE_COUNT,
        );

        // An undersized group keeps its ordinary strict majority.
        assert_eq!(ReplicationConfig::paid_list_flex_edge_count(19, 20), 0);
    }

    /// A shrunken denominator must never make one voter decisive.
    #[test]
    fn paid_confirm_needed_applies_an_absolute_floor() {
        // The floor binds where the discounted majority would be trivial.
        assert_eq!(
            ReplicationConfig::paid_confirm_needed(1, 5),
            PAID_LIST_ABSOLUTE_CONFIRM_FLOOR
        );
        assert_eq!(
            ReplicationConfig::paid_confirm_needed(2, 5),
            PAID_LIST_ABSOLUTE_CONFIRM_FLOOR
        );

        // Above the floor the strict majority governs, unchanged.
        assert_eq!(ReplicationConfig::paid_confirm_needed(16, 20), 9);
        assert_eq!(ReplicationConfig::paid_confirm_needed(20, 20), 11);

        // The floor never demands more confirmations than there are peers.
        assert_eq!(ReplicationConfig::paid_confirm_needed(1, 1), 1);
        assert_eq!(ReplicationConfig::paid_confirm_needed(2, 2), 2);
    }

    /// The reviewed collapse: at a configured width of five, four fixed edge
    /// voters left a core of one, so a single `Confirmed` authorized the key.
    #[test]
    fn small_configured_group_cannot_authorize_on_one_vote() {
        const SMALL_GROUP: usize = 5;

        let edge = ReplicationConfig::paid_list_flex_edge_count(SMALL_GROUP, SMALL_GROUP);
        let core = SMALL_GROUP - edge;
        assert!(
            core > 1,
            "the voting core must not collapse to a single peer"
        );
        assert!(
            ReplicationConfig::paid_confirm_needed(core, SMALL_GROUP) > 1,
            "a lone confirmation must not authorize a key"
        );
    }

    #[test]
    fn random_intervals_within_bounds() {
        let config = ReplicationConfig::default();

        // Run several iterations to exercise randomness.
        let iterations = 50;
        for _ in 0..iterations {
            let ns = config.random_neighbor_sync_interval();
            assert!(ns >= config.neighbor_sync_interval_min);
            assert!(ns <= config.neighbor_sync_interval_max);

            let at = config.random_audit_tick_interval();
            assert!(at >= config.audit_tick_interval_min);
            assert!(at <= config.audit_tick_interval_max);

            let sl = config.random_self_lookup_interval();
            assert!(sl >= config.self_lookup_interval_min);
            assert!(sl <= config.self_lookup_interval_max);
        }
    }

    #[test]
    fn random_interval_equal_bounds_is_deterministic() {
        let fixed = Duration::from_secs(42);
        let config = ReplicationConfig {
            neighbor_sync_interval_min: fixed,
            neighbor_sync_interval_max: fixed,
            ..ReplicationConfig::default()
        };
        assert_eq!(config.random_neighbor_sync_interval(), fixed);
    }

    // -----------------------------------------------------------------------
    // Section 18 scenarios
    // -----------------------------------------------------------------------

    /// Scenario 18: Invalid runtime config is rejected by `validate()`.
    #[test]
    fn scenario_18_invalid_config_rejected() {
        // quorum_threshold > close_group_size -> validation fails.
        let config = ReplicationConfig {
            quorum_threshold: 10,
            close_group_size: 7,
            ..ReplicationConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("quorum_threshold"),
            "error should mention quorum_threshold: {err}"
        );

        // close_group_size = 0 -> validation fails.
        let config = ReplicationConfig {
            close_group_size: 0,
            ..ReplicationConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("close_group_size"),
            "error should mention close_group_size: {err}"
        );

        // neighbor_sync interval min > max -> validation fails.
        let config = ReplicationConfig {
            neighbor_sync_interval_min: Duration::from_secs(200),
            neighbor_sync_interval_max: Duration::from_secs(100),
            ..ReplicationConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("neighbor_sync_interval"),
            "error should mention neighbor_sync_interval: {err}"
        );

        // self_lookup interval min > max -> validation fails.
        let config = ReplicationConfig {
            self_lookup_interval_min: Duration::from_secs(999),
            self_lookup_interval_max: Duration::from_secs(1),
            ..ReplicationConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("self_lookup_interval"),
            "error should mention self_lookup_interval: {err}"
        );

        // audit_tick interval min > max -> validation fails.
        let config = ReplicationConfig {
            audit_tick_interval_min: Duration::from_secs(500),
            audit_tick_interval_max: Duration::from_secs(10),
            ..ReplicationConfig::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("audit_tick_interval"),
            "error should mention audit_tick_interval: {err}"
        );
    }

    /// Scenario 26: Dynamic paid-list threshold for undersized set.
    /// With PaidGroupSize=8, `ConfirmNeeded` = floor(8/2)+1 = 5.
    #[test]
    fn scenario_26_dynamic_paid_threshold_undersized() {
        assert_eq!(ReplicationConfig::confirm_needed(8), 5, "floor(8/2)+1 = 5");

        // Additional boundary checks for small paid groups.
        assert_eq!(
            ReplicationConfig::confirm_needed(1),
            1,
            "single peer requires 1 confirmation"
        );
        assert_eq!(
            ReplicationConfig::confirm_needed(2),
            2,
            "2 peers require 2 confirmations"
        );
        assert_eq!(
            ReplicationConfig::confirm_needed(3),
            2,
            "3 peers require 2 confirmations"
        );
        assert_eq!(
            ReplicationConfig::confirm_needed(0),
            1,
            "0 peers yields floor(0/2)+1 = 1 (degenerate case)"
        );
    }

    /// Scenario 31: Consecutive audit ticks occur on randomized intervals
    /// bounded by the configured `[audit_tick_interval_min, audit_tick_interval_max]`
    /// window.
    #[test]
    fn scenario_31_audit_cadence_within_jitter_bounds() {
        let config = ReplicationConfig {
            audit_tick_interval_min: Duration::from_mins(10),
            audit_tick_interval_max: Duration::from_mins(20),
            ..ReplicationConfig::default()
        };

        // Sample many intervals and verify each is within bounds.
        let iterations = 100;
        let mut saw_different = false;
        let mut prev = Duration::ZERO;

        for _ in 0..iterations {
            let interval = config.random_audit_tick_interval();
            assert!(
                interval >= config.audit_tick_interval_min,
                "interval {interval:?} below min {:?}",
                config.audit_tick_interval_min,
            );
            assert!(
                interval <= config.audit_tick_interval_max,
                "interval {interval:?} above max {:?}",
                config.audit_tick_interval_max,
            );
            if interval != prev && prev != Duration::ZERO {
                saw_different = true;
            }
            prev = interval;
        }

        // With 100 samples from a 10-minute range, at least two should differ
        // (probabilistically near-certain).
        assert!(
            saw_different,
            "audit intervals should exhibit randomized jitter across samples"
        );
    }

    /// The capacity stand-down has to be an order of magnitude above the retry
    /// it replaces and still below the life of the entry it defers.
    ///
    /// A stand-down only a little above the request timeout would leave the
    /// repeat cost the same order as before, which is the cost this change
    /// exists to remove. At or past `PENDING_VERIFY_MAX_AGE` every deferral
    /// would instead become an eviction, which is a different design with
    /// different failure modes: the key would only return on a fresh
    /// neighbour-sync hint rather than on its own schedule.
    ///
    /// What this does not show: that either gate uses the constant. It pins the
    /// policy the constant encodes; the e2e proves the gates.
    #[test]
    fn capacity_blocked_retry_is_an_order_above_the_request_timeout_and_below_the_entry_lifetime() {
        assert!(
            CAPACITY_BLOCKED_RETRY >= VERIFICATION_REQUEST_TIMEOUT * 10,
            "a stand-down near the request timeout leaves the repeat cost unchanged in order"
        );
        assert!(
            CAPACITY_BLOCKED_RETRY < PENDING_VERIFY_MAX_AGE,
            "a deferral at or past the entry lifetime is an eviction, not a deferral"
        );
    }

    /// The backoff ceiling sits in the same band, and for the same reasons: far
    /// enough above the request timeout to actually cut the repeat cost, far
    /// enough below the entry lifetime that a capped retry still gets several
    /// looks before stale eviction ends the episode.
    #[test]
    fn verification_retry_backoff_max_is_between_the_request_timeout_and_the_entry_lifetime() {
        assert!(
            VERIFICATION_RETRY_BACKOFF_MAX > VERIFICATION_REQUEST_TIMEOUT,
            "a ceiling at or below the base delay is not a backoff"
        );
        assert!(
            VERIFICATION_RETRY_BACKOFF_MAX * 4 <= PENDING_VERIFY_MAX_AGE,
            "a capped retry must still get several looks inside one entry lifetime"
        );
    }
}
