//! Gossip-triggered contiguous-subtree storage audit (ADR-0002).
//!
//! A node commits to what it stores (a signed Merkle [`StorageCommitment`]
//! gossiped to neighbours). On receiving a peer's changed commitment, a
//! neighbour may audit it: pin the just-gossiped root, send a fresh nonce that
//! deterministically selects one contiguous subtree, and require the peer to
//! prove that subtree (structure + real bytes) within a deadline. This module
//! owns the auditor entry point [`run_subtree_audit`] and the responder handler
//! [`handle_subtree_challenge`]; the pure proof maths live in
//! [`crate::replication::subtree`].

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::logging::{debug, info, warn};
use rand::Rng;

use crate::ant_protocol::XorName;
use crate::replication::commitment::{commitment_hash, StorageCommitment};
use crate::replication::commitment_state::ResponderCommitmentState;
use crate::replication::config::{
    ReplicationConfig, MAX_SLICE_OPENINGS, SUBTREE_AUDIT_PROTOCOL_ID,
    SUBTREE_ROUND1_LEAF_WORK_FLOOR_BYTES,
};
use crate::replication::protocol::{
    RejectKind, ReplicationMessage, ReplicationMessageBody, SubtreeAuditChallenge,
    SubtreeAuditResponse, SubtreeSliceChallenge, SubtreeSliceItem, SubtreeSliceOpening,
    SubtreeSliceResponse,
};
use crate::replication::recent_provers::RecentProvers;
use crate::replication::subtree::{
    select_subtree_path, subtree_plan, verify_subtree_proof, StructureVerdict, SubtreeProof,
};
use crate::replication::types::{AuditFailureReason, AuditFailureSummary, FailureEvidence};
use crate::storage::ChunkStore;
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use tokio::sync::RwLock;

// The gossip-triggered auditor shares the engine's [`AuditTickResult`] outcome
// type with the responsible-chunk audit (defined in [`super::audit`]), so the
// engine can dispatch both audits' results through one match.
use crate::replication::audit::AuditTickResult;

// ---------------------------------------------------------------------------
// Auditor side
// ---------------------------------------------------------------------------

/// ADR-0002 round-2 slice challenge samples a SMALL surprise set of the proven
/// leaves (3..=5). Small enough that the responder's honest local-disk read of
/// the original chunks stays well inside the response deadline, which is a
/// liveness bound and nothing more here: the reply is a few KB, so no deadline
/// prices a relay out of fetching it (ADR-0009). Large enough that faking a
/// fraction `x` of leaves survives only `(1 - x)^k`.
const BYTE_SPOTCHECK_MIN: u32 = 3;
const BYTE_SPOTCHECK_MAX: u32 = 5;

// Each sampled leaf produces up to two openings (a fresh-random block plus the
// claimed final block, deduplicated when they coincide), so the opening cap must
// cover twice the leaf sample.
const _: () = assert!(
    2 * BYTE_SPOTCHECK_MAX as usize <= MAX_SLICE_OPENINGS,
    "MAX_SLICE_OPENINGS must cover two openings per sampled leaf"
);

/// ADR-0004 A1: with grace removed, the responder retries a TRANSIENT chunk-read
/// error a few times before rejecting `Transient` (which routes to the timeout
/// lane). A momentary disk blip usually clears within these attempts; only a
/// persistent read failure — the node genuinely cannot serve committed bytes —
/// falls through. Total added latency ((attempts − 1) × backoff) stays well inside the
/// audit response deadline.
const AUDIT_READ_RETRY_ATTEMPTS: u32 = 3;
const AUDIT_READ_RETRY_BACKOFF: Duration = Duration::from_millis(200);

/// Read a committed chunk's bytes, retrying a transient read error up to
/// [`AUDIT_READ_RETRY_ATTEMPTS`] times with [`AUDIT_READ_RETRY_BACKOFF`] between
/// tries. `Ok(None)` (bytes definitively absent — real loss) is NOT retried; only
/// an `Err` (transient IO) is. A persistent `Err` is returned so the caller emits
/// `RejectKind::Transient` (timeout lane).
async fn get_raw_retrying(
    storage: &ChunkStore,
    key: &XorName,
) -> crate::error::Result<Option<Vec<u8>>> {
    let mut attempt = 1u32;
    loop {
        match storage.get_raw(key).await {
            Ok(v) => return Ok(v),
            Err(e) if attempt < AUDIT_READ_RETRY_ATTEMPTS => {
                debug!(
                    "Audit: transient read error for {} (attempt {attempt}/{AUDIT_READ_RETRY_ATTEMPTS}): {e}; retrying",
                    hex::encode(key)
                );
                attempt += 1;
                tokio::time::sleep(AUDIT_READ_RETRY_BACKOFF).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// How the auditor grades a *responsive* audit rejection (ADR-0004 A1: grace
/// removed). The decision is a pure function of the [`RejectKind`] so it can be
/// unit-tested independently of the P2P/side-effect machinery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RejectGrade {
    /// Provable misbehaviour → confirmed failure (trust penalty + credit
    /// revocation downstream).
    Confirmed,
    /// Non-response/timeout lane: no trust penalty, but the pinned commitment's
    /// holder credit is revoked (the peer answered but could not prove possession).
    TimeoutLane,
}

/// Grade a responsive rejection. Repudiating a pinned root (`UnknownCommitment`)
/// or an explicit protocol fault is a confirmed failure; a `Transient` read error
/// (already retried by the responder) routes to the timeout lane.
const fn grade_reject(kind: RejectKind) -> RejectGrade {
    match kind {
        RejectKind::UnknownCommitment | RejectKind::Protocol => RejectGrade::Confirmed,
        RejectKind::Transient => RejectGrade::TimeoutLane,
    }
}

/// Holder-eligibility cache the auditor credits on a passing audit.
///
/// Owned by [`crate::replication::ReplicationEngine`]; borrowed here so a
/// passing audit can record `(peer, commitment_hash)` as a proven holder for
/// downstream quorum / paid-list credit.
pub struct AuditCredit<'a> {
    /// Holder-eligibility cache.
    pub recent_provers: &'a Arc<RwLock<RecentProvers>>,
}

/// Local subsystem that launched a storage-commitment audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubtreeAuditOrigin {
    /// Lottery-gated audit after commitment gossip.
    Gossip,
    /// Deterministic audit after a commitment-backed payment.
    FirstMonetized,
    /// Explicit test or diagnostic request.
    Manual,
}

#[cfg(feature = "logging")]
impl SubtreeAuditOrigin {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Gossip => "gossip",
            Self::FirstMonetized => "first_monetized",
            Self::Manual => "manual",
        }
    }
}

/// The cross-cutting context for verifying one audit response, bundled so the
/// response-dispatch and verification functions stay readable.
struct AuditCtx<'a> {
    p2p_node: &'a Arc<P2PNode>,
    challenged_peer: &'a PeerId,
    challenge_id: u64,
    nonce: [u8; 32],
    expected_commitment_hash: [u8; 32],
    config: &'a ReplicationConfig,
    credit: Option<&'a AuditCredit<'a>>,
    #[cfg_attr(not(feature = "logging"), allow(dead_code))]
    origin: SubtreeAuditOrigin,
}

/// Run one gossip-triggered subtree audit against `challenged_peer`, pinned to
/// the commitment hash the peer just gossiped (`expected_commitment_hash`).
///
/// ADR-0002 two-round audit. The auditor sends a fresh random nonce and runs:
///
/// 1. **Structure** (round 1) — the returned subtree rebuilds to the pinned
///    root, within a size-scaled deadline.
/// 2. **Verified slice** (round 2) — for a 3..=5 FRESHLY-RANDOM sample of the
///    proven leaves (chosen after the proof arrives, not nonce-derived — see
///    `random_spotcheck_leaves`), the auditor opens one random 1 KiB block per
///    leaf (plus its final block) and verifies a Bao slice against the chunk
///    address and a nonced-tree opening against the round-1 `nonced_root`, over
///    the bytes the responder serves. The auditor holds none of the peer's
///    chunks, and possession is the round-1 commitment, not a full-chunk transfer.
/// 3. **Timing** — a response deadline still bounds liveness, but (unlike the old
///    full-byte round 2) it is no longer the possession proof; that is the
///    round-1 `nonced_root` commitment.
///
/// A timeout (either round) is reported as [`AuditFailureReason::Timeout`] (the
/// caller applies the strike/grace policy). Any structural failure, served
/// content that fails a hash, an explicit `Absent` for a committed sampled key,
/// or a rejection of a recently gossiped commitment, is a confirmed failure
/// acted on immediately. On a full pass, records the peer as a proven holder.
pub async fn run_subtree_audit(
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    challenged_peer: &PeerId,
    expected_commitment_hash: [u8; 32],
    key_count: u32,
    credit: Option<&AuditCredit<'_>>,
) -> AuditTickResult {
    run_subtree_audit_with_origin(
        p2p_node,
        config,
        challenged_peer,
        expected_commitment_hash,
        key_count,
        credit,
        SubtreeAuditOrigin::Manual,
    )
    .await
}

/// Run a subtree audit while retaining the local scheduler origin in logs.
pub(crate) async fn run_subtree_audit_with_origin(
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    challenged_peer: &PeerId,
    expected_commitment_hash: [u8; 32],
    key_count: u32,
    credit: Option<&AuditCredit<'_>>,
    origin: SubtreeAuditOrigin,
) -> AuditTickResult {
    let (nonce, challenge_id) = {
        let mut rng = rand::thread_rng();
        (rng.gen::<[u8; 32]>(), rng.gen::<u64>())
    };

    let challenge = SubtreeAuditChallenge {
        challenge_id,
        nonce,
        challenged_peer_id: *challenged_peer.as_bytes(),
        expected_commitment_hash,
    };
    let msg = ReplicationMessage {
        request_id: challenge_id,
        body: ReplicationMessageBody::SubtreeAuditChallenge(challenge),
    };
    let encoded = match msg.encode() {
        Ok(data) => data,
        Err(e) => {
            warn!("Audit: failed to encode subtree challenge for {challenged_peer}: {e}");
            return AuditTickResult::Idle;
        }
    };

    // Size the proof deadline from the ACTUAL selected subtree (its real-leaf
    // count for this nonce + key_count), not a fixed worst-case hint. This keeps
    // the deadline proportional to the work an honest responder actually owes —
    // hashing ~sqrt(N) chunks at local-disk speed — so a slow honest node is not
    // failed for being large. It is not an anti-relay bound: see ADR-0009, the
    // proof is delegable at any deadline. The auditor and responder derive the
    // same selection, so we know the leaf count before the response arrives.
    let subtree_leaves = select_subtree_path(&nonce, key_count).map_or_else(
        || config.subtree_audit_timeout_leaf_hint(),
        |p| p.real_leaf_count() as usize,
    );
    let timeout = config.audit_response_timeout(subtree_leaves);

    info!(
        target: "ant_node::replication::audit_requester",
        event = "started",
        audit_origin = origin.as_str(),
        audit_round = "subtree",
        challenged_peer = %challenged_peer,
        challenge_id,
        work_items = subtree_leaves,
        timeout_ms = timeout.as_millis(),
        "Outbound audit request started"
    );
    let request_started = Instant::now();
    let response = match p2p_node
        .send_request(challenged_peer, SUBTREE_AUDIT_PROTOCOL_ID, encoded, timeout)
        .await
    {
        Ok(resp) => {
            info!(
                target: "ant_node::replication::audit_requester",
                event = "completed",
                audit_origin = origin.as_str(),
                audit_round = "subtree",
                challenged_peer = %challenged_peer,
                challenge_id,
                work_items = subtree_leaves,
                elapsed_ms = request_started.elapsed().as_millis(),
                outcome = "response",
                "Outbound audit request completed"
            );
            resp
        }
        Err(e) => {
            warn!(
                target: "ant_node::replication::audit_requester",
                event = "completed",
                audit_origin = origin.as_str(),
                audit_round = "subtree",
                challenged_peer = %challenged_peer,
                challenge_id,
                work_items = subtree_leaves,
                elapsed_ms = request_started.elapsed().as_millis(),
                outcome = "no_response",
                error = %e,
                "Outbound audit request completed without a response"
            );
            return failed(challenged_peer, challenge_id, AuditFailureReason::Timeout);
        }
    };

    let resp_msg = match ReplicationMessage::decode_subtree_audit_response(&response.data) {
        Ok(m) => m,
        Err(e) => {
            warn!("Audit: failed to decode subtree response from {challenged_peer}: {e}");
            return failed(
                challenged_peer,
                challenge_id,
                AuditFailureReason::MalformedResponse,
            );
        }
    };

    let ctx = AuditCtx {
        p2p_node,
        challenged_peer,
        challenge_id,
        nonce,
        expected_commitment_hash,
        config,
        credit,
        origin,
    };
    dispatch_subtree_response(resp_msg.body, &ctx).await
}

/// Outcome of the round-2 slice challenge round-trip (auditor side).
enum SliceRound {
    /// The responder returned per-opening items (verified by the caller).
    Served(Vec<SubtreeSliceItem>),
    /// The responder rejected the slice challenge (confirmed failure for a
    /// recently pinned commitment).
    Rejected,
    /// The responder rejected with `Transient` (a local read error): routed to
    /// the non-response/timeout lane — no trust penalty, but the pinned
    /// commitment's holder credit is revoked, because the peer answered and
    /// could not prove possession, so it must not keep stale credit.
    ///
    /// This lands in the same place as [`SliceRound::Timeout`] below, which also
    /// revokes commitment-scoped credit without a trust penalty. The two are
    /// kept separate because they say different things about the peer — one
    /// could not read its disk, the other did not reply at all — and only the
    /// reason is logged differently.
    TransientReject,
    /// No response within the slice deadline, or a transport error. Routed to
    /// the non-response/timeout lane: no trust penalty, but the pinned
    /// commitment's holder credit is revoked.
    ///
    /// Silence here is not the same as a silent peer in general. The responder
    /// answered round 1 in this same exchange, so it was live and reachable, and
    /// it saw which blocks were drawn before deciding whether to reply. Leaving
    /// credit in place would make "answer only when the draw is favourable" a
    /// free strategy: an unfavourable sample would cost nothing and the credit
    /// earned from an earlier favourable one would survive. Revoking scopes the
    /// cost to the pinned commitment, so the peer must actually answer a round 2
    /// to hold credit, while an honest node that drops one reply keeps its trust
    /// intact and re-earns credit on its next audit.
    Timeout,
    /// The responder claimed `Bootstrapping` in round 2 after answering a valid
    /// round-1 proof. A node that just produced a signed subtree proof is
    /// provably not bootstrapping, so this responsive contradiction is a
    /// confirmed failure (not a graced timeout): it revokes the peer's holder
    /// credit and takes the trust penalty.
    ///
    /// This classification relies on `is_bootstrapping` being ONE-WAY (true →
    /// false; see `mod.rs`): a round-1 proof implies the snapshot was already
    /// `false`, and a restart drops the single-use round-1 session so round 2 is
    /// answered `Transient` before this branch is ever reached. An honest running
    /// node therefore cannot produce this response; only a malicious, incompatible,
    /// or future broken-state peer can. If a "re-bootstrap" (false → true)
    /// transition is ever added, it MUST clear live sessions or this policy must
    /// be revisited.
    ResponsiveBootstrap,
    /// Malformed / unexpected round-2 response body.
    Malformed,
}

/// Round 2: ask the responder to open `openings` blocks (one 1 KiB block per
/// sampled leaf, at most [`MAX_SLICE_OPENINGS`]) with a Bao verified slice plus a
/// nonced block-tree opening each. The reply is a few KB total, so there is no
/// batching. The responder cannot have predicted which leaves — or which block
/// within each — are opened (fresh post-proof randomness).
#[allow(clippy::too_many_lines)]
async fn request_slice_proof(ctx: &AuditCtx<'_>, openings: &[SubtreeSliceOpening]) -> SliceRound {
    let challenge = SubtreeSliceChallenge {
        challenge_id: ctx.challenge_id,
        nonce: ctx.nonce,
        challenged_peer_id: *ctx.challenged_peer.as_bytes(),
        expected_commitment_hash: ctx.expected_commitment_hash,
        openings: openings.to_vec(),
    };
    let msg = ReplicationMessage {
        request_id: ctx.challenge_id,
        body: ReplicationMessageBody::SubtreeSliceChallenge(challenge),
    };
    let encoded = match msg.encode() {
        Ok(data) => data,
        Err(e) => {
            warn!("Audit: failed to encode slice challenge: {e}");
            return SliceRound::Malformed;
        }
    };

    // Deadline sized to "honest responder reads `openings.len()` full local
    // chunks to build their proofs": generous, because what binds the bytes is
    // the round-1 nonced commitment, not the clock. It is a liveness bound only
    // — the reply is a few KB, so no deadline prices a relay out of it, and the
    // proof is delegable at any deadline (ADR-0009).
    let timeout = ctx.config.slice_audit_response_timeout(openings.len());
    info!(
        target: "ant_node::replication::audit_requester",
        event = "started",
        audit_origin = ctx.origin.as_str(),
        audit_round = "byte",
        challenged_peer = %ctx.challenged_peer,
        challenge_id = ctx.challenge_id,
        work_items = openings.len(),
        timeout_ms = timeout.as_millis(),
        "Outbound audit request started"
    );
    let request_started = Instant::now();
    let response = match ctx
        .p2p_node
        .send_request(
            ctx.challenged_peer,
            SUBTREE_AUDIT_PROTOCOL_ID,
            encoded,
            timeout,
        )
        .await
    {
        Ok(resp) => {
            info!(
                target: "ant_node::replication::audit_requester",
                event = "completed",
                audit_origin = ctx.origin.as_str(),
                audit_round = "byte",
                challenged_peer = %ctx.challenged_peer,
                challenge_id = ctx.challenge_id,
                work_items = openings.len(),
                elapsed_ms = request_started.elapsed().as_millis(),
                outcome = "response",
                "Outbound audit request completed"
            );
            resp
        }
        Err(e) => {
            warn!(
                target: "ant_node::replication::audit_requester",
                event = "completed",
                audit_origin = ctx.origin.as_str(),
                audit_round = "byte",
                challenged_peer = %ctx.challenged_peer,
                challenge_id = ctx.challenge_id,
                work_items = openings.len(),
                elapsed_ms = request_started.elapsed().as_millis(),
                outcome = "no_response",
                error = %e,
                "Outbound audit request completed without a response"
            );
            return SliceRound::Timeout;
        }
    };

    let resp_msg = match ReplicationMessage::decode_subtree_audit_response(&response.data) {
        Ok(m) => m,
        Err(e) => {
            warn!("Audit: failed to decode slice response: {e}");
            return SliceRound::Malformed;
        }
    };

    classify_slice_response(resp_msg.body, ctx.challenge_id, ctx.challenged_peer)
}

/// Classify a decoded round-2 body into a [`SliceRound`].
///
/// Pure over the wire body so the round-2 accounting boundary is testable
/// without a live `P2PNode`; [`request_slice_proof`] calls exactly this on the
/// bytes it decoded.
///
/// Every arm is guarded on `challenge_id`: a body carrying any other id is
/// `Malformed`, so a responder cannot answer a hard challenge with a softer
/// verdict minted for a different one.
fn classify_slice_response(
    body: ReplicationMessageBody,
    challenge_id: u64,
    challenged_peer: &PeerId,
) -> SliceRound {
    match body {
        ReplicationMessageBody::SubtreeSliceResponse(SubtreeSliceResponse::Items {
            challenge_id: id,
            items,
        }) if id == challenge_id => SliceRound::Served(items),
        ReplicationMessageBody::SubtreeSliceResponse(SubtreeSliceResponse::Rejected {
            challenge_id: id,
            kind,
            reason,
        }) if id == challenge_id => {
            // ADR-0004 A1: grace removed. UnknownCommitment/Protocol repudiation
            // of a pinned root is a confirmed failure; a Transient read error
            // routes to the timeout lane (credit revoked, no trust penalty) — the
            // responder retries reads first, so a Transient reaching round 2 means
            // it still could not serve committed bytes.
            match grade_reject(kind) {
                RejectGrade::Confirmed => {
                    warn!(
                        "Audit: {challenged_peer} rejected slice challenge \
                         ({kind:?}; confirmed): {reason}"
                    );
                    SliceRound::Rejected
                }
                RejectGrade::TimeoutLane => {
                    debug!(
                        "Audit: {challenged_peer} returned Transient for slice challenge \
                         (timeout lane): {reason}"
                    );
                    SliceRound::TransientReject
                }
            }
        }
        // A node claiming bootstrap MID-AUDIT (it just answered round 1 with a
        // valid signed proof) is contradicting itself: a bootstrapping node has
        // no committed data to prove. A graced timeout here would let it keep the
        // holder credit it earned earlier while dodging every round-2 possession
        // check, so this is a confirmed failure with credit revocation.
        ReplicationMessageBody::SubtreeSliceResponse(SubtreeSliceResponse::Bootstrapping {
            challenge_id: id,
        }) if id == challenge_id => SliceRound::ResponsiveBootstrap,
        _ => SliceRound::Malformed,
    }
}

/// Whether a round-2 outcome must revoke the holder credit carried by the
/// commitment the auditor pinned.
///
/// True for every outcome that ends round 2 without a completed possession
/// proof but stays in the graced timeout lane — an explicit `Transient` reject
/// and silence alike. Both mean the peer did not prove it still holds the bytes
/// it committed to, so it must not keep standing earned by an earlier audit.
///
/// Silence matters most here. By round 2 the responder has already answered
/// round 1, so it is demonstrably live, and it learns which blocks were drawn
/// before it decides whether to reply. If silence kept credit, replying only to
/// favourable draws would cost nothing: unfavourable samples would be free and
/// credit from an earlier favourable one would persist, so the sampling
/// probability would describe answered passes rather than detection. Revoking
/// makes every unanswered round 2 cost the peer its standing for that
/// commitment, while an honest peer that drops one reply takes no trust penalty
/// and re-earns credit on its next audit.
///
/// The confirmed lanes (`Rejected`, `ResponsiveBootstrap`, `Malformed`) are
/// excluded because they revoke more broadly downstream, via
/// `apply_audit_failure_credit_revocation` → `forget_peer`.
const fn round2_revokes_pinned_credit(round: &SliceRound) -> bool {
    matches!(round, SliceRound::TransientReject | SliceRound::Timeout)
}

/// Map a decoded response body to an audit outcome (auditor side). A response
/// whose `challenge_id` doesn't match, or any non-subtree body, is malformed.
async fn dispatch_subtree_response(
    body: ReplicationMessageBody,
    ctx: &AuditCtx<'_>,
) -> AuditTickResult {
    let challenged_peer = ctx.challenged_peer;
    let challenge_id = ctx.challenge_id;
    let malformed = || {
        failed(
            challenged_peer,
            challenge_id,
            AuditFailureReason::MalformedResponse,
        )
    };
    match body {
        ReplicationMessageBody::SubtreeAuditResponse(SubtreeAuditResponse::Bootstrapping {
            challenge_id: resp_id,
        }) => {
            if resp_id != challenge_id {
                return malformed();
            }
            AuditTickResult::BootstrapClaim {
                peer: *challenged_peer,
            }
        }
        ReplicationMessageBody::SubtreeAuditResponse(SubtreeAuditResponse::Rejected {
            challenge_id: resp_id,
            kind,
            reason,
        }) => {
            if resp_id != challenge_id {
                return malformed();
            }
            // ADR-0004 A1: audit grace is REMOVED. Answerability is now
            // restart-durable (persisted retention) and the auditor only pins
            // in-window roots, so an honest node can always answer a pin it could
            // be challenged on. A responsive rejection is therefore graded on the
            // kind, with no grace:
            match grade_reject(kind) {
                // Repudiating a pinned root the node published (`UnknownCommitment`)
                // or an explicit protocol fault is provable misbehaviour →
                // confirmed failure (trust penalty + credit revocation happen
                // downstream in handle_subtree_failed_audit).
                RejectGrade::Confirmed => {
                    warn!(
                        "Audit: peer {challenged_peer} rejected subtree challenge \
                         ({kind:?}; confirmed — grace removed): {reason}"
                    );
                    failed(challenged_peer, challenge_id, AuditFailureReason::Rejected)
                }
                // A transient local read error (already retried by the responder)
                // is not a provable cheat, but not graced-with-standing either:
                // route it to the non-response/timeout lane — no trust penalty, but
                // revoke the holder credit for THIS pinned commitment so it gains
                // no positive standing (a Transient-spammer profits nothing).
                // Scoped to the commitment hash, not the whole peer, so a stale
                // audit of an old commitment cannot erase credit re-earned for a
                // newer one.
                RejectGrade::TimeoutLane => {
                    if let Some(credit) = ctx.credit {
                        credit
                            .recent_provers
                            .write()
                            .await
                            .forget_commitment(&ctx.expected_commitment_hash);
                    }
                    debug!(
                        "Audit: peer {challenged_peer} returned Transient for subtree challenge \
                         (timeout lane; credit for the pinned commitment revoked): {reason}"
                    );
                    failed(challenged_peer, challenge_id, AuditFailureReason::Timeout)
                }
            }
        }
        ReplicationMessageBody::SubtreeAuditResponse(SubtreeAuditResponse::Proof {
            challenge_id: resp_id,
            commitment,
            proof,
        }) => {
            if resp_id != challenge_id {
                return malformed();
            }
            verify_subtree_response(ctx, &commitment, &proof).await
        }
        _ => {
            warn!("Audit: unexpected response type from {challenged_peer}");
            malformed()
        }
    }
}

/// The pure verdict of evaluating a subtree-audit response, independent of
/// storage/network. Tests call this directly so the SHIPPED gate logic is what
/// gets exercised (no reimplementation that could drift).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuditVerdict {
    /// All gates passed and at least one leaf was byte-verified.
    Pass {
        /// Number of leaves whose real bytes were verified in round 2.
        checked: usize,
    },
    /// A confirmed failure with this reason (penalizable / acted upon).
    Fail(AuditFailureReason),
}

/// Round-1 structural evaluation of a subtree-audit proof (ADR-0002).
///
/// Runs the cheap gates in fail-fast order: pin / identity / signature →
/// structure (the returned subtree rebuilds to the pinned root). It does **not**
/// prove byte possession — the leaves carry only the public `bytes_hash` (the
/// chunk address), a `content_len`, and a `nonced_root` the responder computed
/// itself. Possession is proven in round 2 ([`verify_slice_response`]), where the
/// auditor opens a freshly-random (post-proof) block per sampled leaf and
/// verifies a Bao slice against the address plus a nonced-tree opening against
/// the round-1 `nonced_root` — over the SERVED bytes, so the auditor never holds
/// the peer's chunks.
///
/// Returns [`StructureVerdict::Valid`] (proceed to round 2) or a confirmed
/// [`AuditFailureReason`] mapped from the failing gate.
pub(crate) fn evaluate_subtree_structure(
    commitment: &StorageCommitment,
    proof: &SubtreeProof,
    nonce: &[u8; 32],
    expected_commitment_hash: &[u8; 32],
    challenged_peer_bytes: &[u8; 32],
) -> Result<(), AuditFailureReason> {
    // -- Pin + identity + signature --
    if &commitment.sender_peer_id != challenged_peer_bytes {
        return Err(AuditFailureReason::Rejected);
    }
    let derived_peer_id = *blake3::hash(&commitment.sender_public_key).as_bytes();
    if derived_peer_id != commitment.sender_peer_id {
        return Err(AuditFailureReason::Rejected);
    }
    match commitment_hash(commitment) {
        Some(h) if &h == expected_commitment_hash => {}
        _ => return Err(AuditFailureReason::Rejected),
    }
    if !crate::replication::commitment::verify_commitment_signature(commitment) {
        return Err(AuditFailureReason::Rejected);
    }

    // -- Structure --
    if let StructureVerdict::Invalid(_) = verify_subtree_proof(proof, nonce, commitment) {
        return Err(AuditFailureReason::DigestMismatch);
    }

    // -- Content-address binding (possession-forgery guard) --
    // The commitment is only sound for CONTENT-ADDRESSED chunks, where the key IS
    // the content hash (`key == BLAKE3(content)`), so an honest leaf is always
    // `(key, key)` (see the commitment builder's `(k, k)` shortcut). The signed
    // Merkle leaf hashes `key ‖ bytes_hash` WITHOUT forcing them equal, yet round 2
    // authenticates the served slice against `bytes_hash` while holder credit is
    // recorded for `key`. A leaf with `bytes_hash != key` would therefore let a peer
    // earn credit for an expensive address `key` by proving possession of an
    // unrelated (e.g. one-byte) chunk hashing to `bytes_hash`. Reject any such leaf:
    // for honest content-addressed data the two are identical, so this never fails
    // an honest holder, and it re-binds Chain 1's `bytes_hash` check to the credited
    // `key`.
    if proof.leaves.iter().any(|l| l.bytes_hash != l.key) {
        return Err(AuditFailureReason::DigestMismatch);
    }
    Ok(())
}

/// The auditor's **freshly-randomised** spot-check sample of the round-1 proof:
/// `count` distinct leaves (deduplicated, in increasing-index order) whose
/// original bytes the auditor will demand in round 2.
///
/// CRITICAL (ADR-0002 soundness): the sample MUST NOT be derivable from
/// anything the responder knew when it built the round-1 proof. The structural
/// root check binds only `(key, bytes_hash)` (both public — `bytes_hash` is the
/// chunk's network address), NOT `nonced_root`. So a relay holding only public
/// addresses can fabricate a structurally-valid proof with a bogus `nonced_root`
/// on every leaf and, if it could predict which leaves round 2 opens, fetch
/// only those and pass — earning holder credit for leaves it never held.
///
/// Picking the sample with fresh CSPRNG randomness AFTER the proof is received
/// turns round 1 into a commitment and round 2 into an unpredictable challenge
/// (cut-and-choose): to pass with probability above `(1 - faked_fraction)^count`
/// the responder must have produced a correct `nonced_root` — which requires the
/// real bytes under the fresh nonce — for essentially every leaf at round-1
/// commit time. The auditor still holds none of the peer's chunks. The block
/// index opened within each sampled leaf is likewise drawn fresh
/// ([`random_block_index`]), so no single block can be prepared in advance.
fn random_spotcheck_leaves(
    proof: &SubtreeProof,
    count: u32,
) -> Vec<&crate::replication::subtree::SubtreeLeaf> {
    let n = proof.leaves.len();
    if n == 0 {
        return Vec::new();
    }
    let want = (count as usize).min(n);
    let mut rng = rand::thread_rng();
    let mut picked = std::collections::BTreeSet::new();
    // n >= want, so this terminates quickly; bound the loop defensively against
    // a pathological RNG rather than risk spinning.
    let mut guard = 0u32;
    while picked.len() < want && guard < count.saturating_mul(64).max(64) {
        picked.insert(rng.gen_range(0..n));
        guard = guard.saturating_add(1);
    }
    // Deterministic top-up if the RNG kept colliding (astronomically unlikely):
    // fill the lowest missing indices so the sample is never silently short.
    for idx in 0..n {
        if picked.len() >= want {
            break;
        }
        picked.insert(idx);
    }
    picked
        .into_iter()
        .filter_map(|idx| proof.leaves.get(idx))
        .collect()
}

/// Draw a fresh-random 1 KiB block index in `0..block_count(content_len)`.
///
/// Called AFTER the round-1 proof is in hand, per sampled leaf, so the responder
/// could not have prepared only the opened block (the cut-and-choose property,
/// now at block granularity).
fn random_block_index(content_len: u32) -> u32 {
    let count = crate::replication::slice::block_count(u64::from(content_len));
    if count <= 1 {
        return 0;
    }
    rand::thread_rng().gen_range(0..count)
}

/// The two block indices opened for one sampled leaf: a fresh-random block (the
/// cut-and-choose possession check) and the claimed final block.
///
/// The final block is opened so the auditor's Bao decode reaches EOF, which is
/// where Bao authenticates the encoded length against the address. Without it a
/// responder can forge a *shorter* `content_len` (which is not signed by the
/// round-1 commitment), collapse the challenge space, and pass while storing only
/// the prefix — the length header alone is not bound for a prefix slice that
/// never touches EOF. Opening the final block pins the true length: a forged
/// short length fails the final-block decode against the real address.
///
/// Returns one index when the random draw already lands on the final block (or
/// the chunk is a single block), two otherwise, never more than two.
fn block_indices_for_leaf(content_len: u32) -> Vec<u32> {
    let count = crate::replication::slice::block_count(u64::from(content_len));
    let final_index = count.saturating_sub(1);
    let random = random_block_index(content_len);
    if random == final_index {
        vec![final_index]
    } else {
        vec![random, final_index]
    }
}

/// Round-2 verdict (ADR-0002 / V2-685): the responder opened one 1 KiB block per
/// sampled leaf with a Bao verified slice plus a nonced block-tree opening;
/// verify possession from those.
///
/// `openings` pairs each sampled leaf with the block index the auditor drew for
/// it. `items` is what the responder returned. For each opening the auditor:
///   1. finds the responder's `Present` item for exactly this `(key, block_index)`
///      (a missing, `Absent` or wrong-block item is a provable lie);
///   2. **Chain 1** — decodes the Bao slice against `leaf.bytes_hash` (the chunk
///      address), recovering the verified block bytes. This proves the block is
///      the real content at that offset, without the auditor holding the chunk.
///   3. **Chain 2** — folds the nonced block leaf (recomputed from those verified
///      bytes under the audit nonce/peer/key/index) with the returned siblings to
///      `leaf.nonced_root`. This proves the responder committed a nonced tree
///      over the real content at round-1 time, so it held the bytes then.
///
/// Both chains are over the SAME block bytes and the auditor holds none of the
/// peer's chunks. Every failure here is a confirmed one, split by what the
/// responder actually did so the audit log can tell them apart:
///
/// - an explicit `Absent` for a key committed in round 1 is an admitted loss →
///   [`AuditFailureReason::KeyAbsent`] (`absent_keys`);
/// - a missing item, a wrong block, a slice that fails to decode against the
///   address, or a nonced opening that does not fold to the committed root, is a
///   proof failure → [`AuditFailureReason::DigestMismatch`]
///   (`digest_mismatch_keys`).
///
/// Both reasons take the same trust penalty, clear the bootstrap claim and
/// revoke holder credit, so the split is diagnostic and not an enforcement
/// change. All openings verifying → `Pass { checked }`.
pub(crate) fn verify_slice_response(
    openings: &[(crate::replication::subtree::SubtreeLeaf, u32)],
    nonce: &[u8; 32],
    challenged_peer_bytes: &[u8; 32],
    items: &[SubtreeSliceItem],
) -> AuditVerdict {
    // Validate the response shape before matching. A well-formed response has at
    // most one item per SOLICITED identity; the per-opening `find_map` below
    // returns the FIRST match, so a duplicate `(key, block_index)` `Present`, a
    // key that is both `Present` and `Absent`, a repeated `Absent`, or an
    // UNSOLICITED item would let the responder's item order (or padding) decide
    // the verdict. Bounding `items.len()` to the request count also keeps this
    // check (and the matching below) at O(openings) — a peer cannot pad the
    // response with thousands of unique items to force quadratic validation work.
    if items.len() > openings.len() {
        return AuditVerdict::Fail(AuditFailureReason::MalformedResponse);
    }
    let requested_blocks: HashSet<(XorName, u32)> =
        openings.iter().map(|(leaf, i)| (leaf.key, *i)).collect();
    let requested_keys: HashSet<XorName> = openings.iter().map(|(leaf, _)| leaf.key).collect();
    let mut present: HashSet<(XorName, u32)> = HashSet::new();
    let mut absent: HashSet<XorName> = HashSet::new();
    for it in items {
        let ok = match it {
            SubtreeSliceItem::Present {
                key, block_index, ..
            } => {
                requested_blocks.contains(&(*key, *block_index))
                    && present.insert((*key, *block_index))
                    && !absent.contains(key)
            }
            SubtreeSliceItem::Absent { key } => {
                requested_keys.contains(key)
                    && absent.insert(*key)
                    && !present.iter().any(|(k, _)| k == key)
            }
        };
        if !ok {
            return AuditVerdict::Fail(AuditFailureReason::MalformedResponse);
        }
    }

    let mut checked = 0usize;
    for (leaf, block_index) in openings {
        let block_index = *block_index;
        // Match the responder's item for exactly this (key, block_index). A
        // missing item, an explicit Absent, or a different block is a provable lie.
        let served = items.iter().find_map(|it| match it {
            SubtreeSliceItem::Present {
                key,
                block_index: served_index,
                bao_slice,
                nonced_siblings,
            } if key == &leaf.key && *served_index == block_index => {
                Some(Some((bao_slice.as_slice(), nonced_siblings.as_slice())))
            }
            SubtreeSliceItem::Absent { key } if key == &leaf.key => Some(None),
            _ => None,
        });
        let (bao_slice, nonced_siblings) = match served {
            Some(Some(opening)) => opening,
            // The responder explicitly answered "I do not hold this key", for a
            // key it committed to in round 1. That is an admitted loss, not a
            // broken proof, and it is reported as `KeyAbsent` so the failure log
            // line separates the two: `absent_keys` counts a peer that owned up
            // to missing data, `digest_mismatch_keys` counts one whose proof did
            // not verify. Both are confirmed failures and carry identical trust,
            // bootstrap-claim and holder-credit effects, so this changes what an
            // operator can see, not what the audit enforces.
            Some(None) => return AuditVerdict::Fail(AuditFailureReason::KeyAbsent),
            // No item at all for a solicited opening: the responder neither
            // served the block nor admitted the key is gone, so nothing about
            // possession was established. That stays a proof failure.
            None => return AuditVerdict::Fail(AuditFailureReason::DigestMismatch),
        };

        // Chain 1: authenticate the block against the chunk address.
        let Some(block) = crate::replication::slice::verify_block_slice(
            bao_slice,
            &leaf.bytes_hash,
            u64::from(leaf.content_len),
            block_index,
        ) else {
            return AuditVerdict::Fail(AuditFailureReason::DigestMismatch);
        };

        // Chain 2: prove the block was committed under round 1's fresh nonce,
        // with the sibling chain pinned to the canonical depth for the chunk's
        // block count (bound the claimed tree geometry).
        if !crate::replication::slice::verify_nonced_block(
            nonce,
            challenged_peer_bytes,
            &leaf.key,
            block_index,
            &block,
            nonced_siblings,
            &leaf.nonced_root,
            crate::replication::slice::block_count(u64::from(leaf.content_len)),
        ) {
            return AuditVerdict::Fail(AuditFailureReason::DigestMismatch);
        }
        checked += 1;
    }
    AuditVerdict::Pass { checked }
}

/// Verify a subtree-proof response (auditor side), ADR-0002 two-round audit.
///
/// **Round 1** (this proof): pin + identity + signature + structure. If the
/// proof structurally rebuilds to the pinned root, the tree SHAPE is committed —
/// but not yet that the bytes are held. **Round 2**: the auditor picks a small
/// freshly-random (post-proof) sample of the just-proven leaves, draws a fresh
/// block index for each, and sends a [`SubtreeSliceChallenge`] opening those
/// blocks. It verifies each opened block against the committed `bytes_hash`
/// (Bao slice → content address) and `nonced_root` (nonced block-tree opening →
/// round-1 possession commit). A responder that committed to a chunk it no
/// longer held cannot have committed a correct `nonced_root`, so it fails —
/// regardless of what the auditor holds. On a full pass, credits the peer as a
/// proven holder.
async fn verify_subtree_response(
    ctx: &AuditCtx<'_>,
    commitment: &StorageCommitment,
    proof: &SubtreeProof,
) -> AuditTickResult {
    let challenged_peer = ctx.challenged_peer;
    let challenge_id = ctx.challenge_id;

    // -- Round 1: pin/identity/signature + structure (no bytes). --
    if let Err(reason) = evaluate_subtree_structure(
        commitment,
        proof,
        &ctx.nonce,
        &ctx.expected_commitment_hash,
        challenged_peer.as_bytes(),
    ) {
        warn!("Audit: {challenged_peer} failed subtree structure ({reason:?})");
        return failed(challenged_peer, challenge_id, reason);
    }

    // -- Round 2: surprise slice challenge for a 3..=5 FRESHLY-RANDOM sample. --
    // The sample is chosen now, with CSPRNG randomness, AFTER the round-1 proof
    // is in hand — NOT derived from the round-1 nonce. The responder committed
    // every leaf's `nonced_root` in round 1 without knowing which leaves — or
    // which block within each — we will open, so it could not have prepared only
    // the opened blocks (cut-and-choose). The reply is a few KB per opening (a
    // 1 KiB block plus two short hash chains), so one round-2 message serves the
    // whole sample; no batching.
    let sample_n = ctx
        .config
        .audit_spotcheck_count()
        .clamp(BYTE_SPOTCHECK_MIN, BYTE_SPOTCHECK_MAX);
    let sampled = random_spotcheck_leaves(proof, sample_n);
    if sampled.is_empty() {
        // Cannot happen after a valid structure (subtree is never empty), but
        // guard rather than credit an unproven peer.
        warn!("Audit: {challenged_peer} produced an empty spot-check sample; rejecting");
        return failed(
            challenged_peer,
            challenge_id,
            AuditFailureReason::DigestMismatch,
        );
    }
    // Pair each sampled leaf with up to two block indices: a fresh-random block
    // (possession) and the claimed final block (a length pin — see
    // `block_indices_for_leaf`). Own the leaves so the borrow on `proof` ends
    // before the await. The sample is <= BYTE_SPOTCHECK_MAX and each leaf yields
    // <= 2 openings, so the total is <= 2 * BYTE_SPOTCHECK_MAX <= MAX_SLICE_OPENINGS
    // (statically asserted); `take` is a defensive backstop.
    let openings_with_leaves: Vec<(crate::replication::subtree::SubtreeLeaf, u32)> = sampled
        .iter()
        .flat_map(|leaf| {
            let leaf = (*leaf).clone();
            block_indices_for_leaf(leaf.content_len)
                .into_iter()
                .map(move |block_index| (leaf.clone(), block_index))
        })
        .take(MAX_SLICE_OPENINGS)
        .collect();
    let openings: Vec<SubtreeSliceOpening> = openings_with_leaves
        .iter()
        .map(|(leaf, block_index)| SubtreeSliceOpening {
            key: leaf.key,
            block_index: *block_index,
        })
        .collect();

    let round = request_slice_proof(ctx, &openings).await;

    // Round 2 ended without a completed possession proof: drop the holder credit
    // this pinned commitment carries, before mapping the outcome to a verdict.
    // Scoped to the commitment hash, so credit the peer re-earned for a newer
    // commitment survives.
    if round2_revokes_pinned_credit(&round) {
        if let Some(credit) = ctx.credit {
            credit
                .recent_provers
                .write()
                .await
                .forget_commitment(&ctx.expected_commitment_hash);
        }
    }

    let verdict = match round {
        // The responder served openings: verify both chains for every one. Any
        // failing chain is a confirmed cheat.
        SliceRound::Served(items) => verify_slice_response(
            &openings_with_leaves,
            &ctx.nonce,
            challenged_peer.as_bytes(),
            &items,
        ),
        // Confirmed round-2 failures. `Rejected`: the responder repudiated the
        // slice challenge for a recently pinned commitment. `ResponsiveBootstrap`:
        // it claimed bootstrap AFTER producing a valid round-1 proof, which is a
        // self-contradiction (a bootstrapping node has no committed data to
        // prove). Both are classified as any other confirmed `Rejected`, which
        // revokes the peer's holder credit and takes the trust penalty downstream
        // (`apply_audit_failure_credit_revocation` → `forget_peer`).
        SliceRound::Rejected | SliceRound::ResponsiveBootstrap => {
            AuditVerdict::Fail(AuditFailureReason::Rejected)
        }
        // Round 2 produced no proof, either as an explicit `Transient` (a local
        // read error) or as silence. Both route to the timeout lane: no trust
        // penalty, the strike policy still graces them, and the credit for the
        // pinned commitment was already revoked above.
        SliceRound::TransientReject | SliceRound::Timeout => {
            AuditVerdict::Fail(AuditFailureReason::Timeout)
        }
        // Malformed/unexpected round-2 body.
        SliceRound::Malformed => AuditVerdict::Fail(AuditFailureReason::MalformedResponse),
    };

    match verdict {
        AuditVerdict::Fail(reason) => {
            warn!("Audit: {challenged_peer} failed subtree audit ({reason:?})");
            failed(challenged_peer, challenge_id, reason)
        }
        AuditVerdict::Pass { checked } => {
            // Closeness (ADR-0002, soft/observe-only) — see observe_closeness.
            observe_closeness(ctx.p2p_node, ctx.config, challenged_peer, proof).await;
            // Credit the peer as a proven holder of its committed keys.
            if let (Some(credit), Some(pin)) = (ctx.credit, commitment_hash(commitment)) {
                let now = std::time::Instant::now();
                let mut provers = credit.recent_provers.write().await;
                for leaf in &proof.leaves {
                    provers.record_proof(leaf.key, *challenged_peer, pin, now);
                }
            }
            info!(
                "Audit: peer {challenged_peer} passed subtree audit ({} leaves, {checked} \
                 block openings verified)",
                proof.leaves.len()
            );
            AuditTickResult::Passed {
                challenged_peer: *challenged_peer,
                keys_checked: checked,
            }
        }
    }
}

/// Soft, density-aware closeness observation (ADR-0002). Logs — never fails —
/// when a suspicious fraction of the proof's leaves are keys the auditor itself
/// is NOT responsible for (a proxy for "implausibly far from the peer").
///
/// Using the auditor's own `SelfInclusiveRT` responsibility as the yardstick
/// makes this density-aware for free: on a small/dense network the auditor is
/// close to nearly every key, so almost nothing reads as far and no honest peer
/// is ever flagged. Enforcement is intentionally deferred until a testnet
/// calibrates the density threshold.
async fn observe_closeness(
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    challenged_peer: &PeerId,
    proof: &SubtreeProof,
) {
    /// Max leaves probed for the closeness estimate (bounds the DHT lookups).
    const CLOSENESS_SAMPLE_CAP: usize = 8;

    // This is an observe-only DEBUG signal (never enforced). The check costs one
    // DHT responsibility lookup per inspected leaf, so (§12): (a) skip it
    // entirely unless debug logging is on — there is no other consumer — and
    // (b) inspect at most a bounded SAMPLE of leaves rather than all ~sqrt(N),
    // which still reveals the "mostly far" padding shape without N lookups.
    if !crate::logging::enabled!(crate::logging::Level::DEBUG) {
        return;
    }

    let self_id = *p2p_node.peer_id();
    let inspected = proof.leaves.len().min(CLOSENESS_SAMPLE_CAP);
    let mut far = 0usize;
    for leaf in proof.leaves.iter().take(inspected) {
        if !crate::replication::admission::is_responsible(
            &self_id,
            &leaf.key,
            p2p_node,
            config.close_group_size,
        )
        .await
        {
            far += 1;
        }
    }
    // Only worth a line when MOST of the inspected sample is far — that's the
    // padding shape. A normal proof on a sparse network has some far keys.
    if inspected > 0 && far * 2 > inspected {
        debug!(
            "Audit: closeness signal — {far}/{inspected} sampled of {challenged_peer}'s proven \
             leaves are keys this auditor is not close to (observe-only; possible padding, not \
             penalized)"
        );
    }
}

/// Build a confirmed-failure result. The auditor pinned a commitment the peer
/// committed to itself, so there is no per-key responsibility to re-confirm:
/// the failure is about the peer's own committed tree.
///
/// The subtree audit fails a peer as a whole (one challenge, one verdict) rather
/// than per-key, so the [`AuditFailureSummary`] is a single-failure rollup
/// mapped from `reason` — enough for the shared audit-failure diagnostics log
/// line (`absent_keys`/`digest_mismatch_keys`) without inventing per-key counts
/// this audit shape does not have.
fn failed(
    challenged_peer: &PeerId,
    challenge_id: u64,
    reason: AuditFailureReason,
) -> AuditTickResult {
    let summary = subtree_failure_summary(&reason);
    AuditTickResult::Failed {
        evidence: FailureEvidence::AuditFailure {
            challenge_id,
            challenged_peer: *challenged_peer,
            confirmed_failed_keys: Vec::new(),
            summary,
            reason,
        },
        no_response_class: None,
    }
}

/// Map a subtree-audit `reason` to a single-failure [`AuditFailureSummary`].
///
/// A `Timeout` is not a confirmed failure (it is the non-response/timeout lane),
/// so it rolls up as zero confirmed failures; every other reason is one confirmed failure,
/// categorised where the category is meaningful (byte/nonce/root mismatch →
/// `digest_mismatch_keys`; explicit absent → `absent_keys`).
fn subtree_failure_summary(reason: &AuditFailureReason) -> AuditFailureSummary {
    let mut summary = AuditFailureSummary {
        challenged_keys: 1,
        ..AuditFailureSummary::default()
    };
    match reason {
        AuditFailureReason::Timeout => {}
        AuditFailureReason::DigestMismatch => {
            summary.failed_keys = 1;
            summary.digest_mismatch_keys = 1;
        }
        AuditFailureReason::KeyAbsent => {
            summary.failed_keys = 1;
            summary.absent_keys = 1;
        }
        AuditFailureReason::MalformedResponse | AuditFailureReason::Rejected => {
            summary.failed_keys = 1;
        }
    }
    summary
}

// ---------------------------------------------------------------------------
// Responder side
// ---------------------------------------------------------------------------

/// Handle an incoming subtree audit challenge (responder side).
///
/// Validates the challenge targets this node, looks up the pinned commitment in
/// the retained (in-window) set, and builds the subtree proof for the
/// nonce-selected branch. If this node is bootstrapping it says so; if it
/// genuinely does not retain the pinned commitment it rejects (which, with audit
/// grace removed, the auditor treats as a confirmed failure for an in-window pin).
pub async fn handle_subtree_challenge(
    challenge: &SubtreeAuditChallenge,
    storage: &ChunkStore,
    self_peer_id: &PeerId,
    is_bootstrapping: bool,
    commitment_state: Option<&Arc<ResponderCommitmentState>>,
) -> SubtreeAuditResponse {
    handle_subtree_challenge_measured(
        challenge,
        storage,
        self_peer_id,
        is_bootstrapping,
        commitment_state,
    )
    .await
    .response
}

/// A round-1 response together with the chunk bytes spent producing it.
pub struct Round1Work {
    /// What to send back.
    pub response: SubtreeAuditResponse,
    /// Chunk content read from the store and hashed BEFORE this response was
    /// produced.
    ///
    /// Counted on the rejecting paths too, which is the point. A subtree is read
    /// leaf by leaf, so a commitment holding one unreadable key still costs a
    /// full run of reads and keyed-BLAKE3 passes over every leaf before it. If
    /// only the `Proof` arm were charged, an attacker who found such a
    /// commitment could replay subtrees over it indefinitely for free — and
    /// since the per-peer cooldown is escapable by rotating identity, the
    /// responder-wide work budget is the only bound that would have caught it.
    pub content_bytes: i64,
}

/// [`handle_subtree_challenge`], additionally reporting the read-and-hash work
/// it performed so the caller can charge it on every exit path.
pub async fn handle_subtree_challenge_measured(
    challenge: &SubtreeAuditChallenge,
    storage: &ChunkStore,
    self_peer_id: &PeerId,
    is_bootstrapping: bool,
    commitment_state: Option<&Arc<ResponderCommitmentState>>,
) -> Round1Work {
    // The accumulator is threaded in rather than returned per-arm so that every
    // exit reports its work by construction: a new early return cannot forget to
    // account for the reads that already happened.
    let mut content_bytes = 0i64;
    let response = subtree_challenge_response(
        challenge,
        storage,
        self_peer_id,
        is_bootstrapping,
        commitment_state,
        &mut content_bytes,
    )
    .await;
    Round1Work {
        response,
        content_bytes,
    }
}

/// The round-1 responder proper. `content_bytes` accrues the chunk content read
/// and hashed so far, and is meaningful on every return path, not just the
/// successful one.
#[allow(clippy::too_many_lines)]
async fn subtree_challenge_response(
    challenge: &SubtreeAuditChallenge,
    storage: &ChunkStore,
    self_peer_id: &PeerId,
    is_bootstrapping: bool,
    commitment_state: Option<&Arc<ResponderCommitmentState>>,
    content_bytes: &mut i64,
) -> SubtreeAuditResponse {
    if is_bootstrapping {
        return SubtreeAuditResponse::Bootstrapping {
            challenge_id: challenge.challenge_id,
        };
    }

    if challenge.challenged_peer_id != *self_peer_id.as_bytes() {
        warn!(
            "Subtree audit challenge targeted wrong peer: expected {}, got {}",
            hex::encode(self_peer_id.as_bytes()),
            hex::encode(challenge.challenged_peer_id),
        );
        return SubtreeAuditResponse::Rejected {
            challenge_id: challenge.challenge_id,
            kind: RejectKind::Protocol,
            reason: "challenged_peer_id does not match this node".to_string(),
        };
    }

    let Some(state) = commitment_state else {
        return SubtreeAuditResponse::Rejected {
            challenge_id: challenge.challenge_id,
            kind: RejectKind::Protocol,
            reason: "no commitment state".to_string(),
        };
    };

    // Look up the pinned commitment among the in-window retained set (TTL-bounded
    // answerability with a MAX_RETAINED_GOSSIPED_SLOTS backstop).
    // A miss is `UnknownCommitment`. With audit grace removed (ADR-0004 A1) the
    // auditor treats a responsive miss on an in-window pin as a CONFIRMED failure:
    // answerability is restart-durable and pins are challenged only while in
    // window, so failing to answer is a real repudiation, not benign rotation.
    let Some(built) = state.lookup_by_hash(&challenge.expected_commitment_hash) else {
        return SubtreeAuditResponse::Rejected {
            challenge_id: challenge.challenge_id,
            kind: RejectKind::UnknownCommitment,
            reason: "unknown commitment hash".to_string(),
        };
    };

    // Geometry first (no bytes touched): which leaves to prove + the sibling
    // cut-hashes from the committed tree.
    let plan = match subtree_plan(built.tree(), &challenge.nonce) {
        Ok(p) => p,
        Err(e) => {
            warn!("Subtree audit: failed to plan proof: {e:?}");
            return SubtreeAuditResponse::Rejected {
                challenge_id: challenge.challenge_id,
                kind: RejectKind::Protocol,
                reason: "could not build subtree proof".to_string(),
            };
        }
    };

    // Read chunk bytes one leaf at a time so peak memory is bounded regardless
    // of subtree size, hashing each into its plain + nonced leaf.
    let mut leaves = Vec::with_capacity(plan.leaf_keys.len());
    for key in &plan.leaf_keys {
        // Charge the fixed cost of ATTEMPTING a leaf before the read, because
        // it is owed whether or not the read succeeds: the lookup and its
        // retries, and the blocking-task round trip below. Charging only
        // content bytes left both a failing leaf and a tiny one nearly free,
        // and nothing bounds a chunk from below, so a commitment of a million
        // small records could run a full subtree of lookups per audit against
        // almost no budget. The top-up after a successful read makes the total
        // `max(bytes, floor)` rather than a surcharge on honest chunks.
        *content_bytes = content_bytes.saturating_add(SUBTREE_ROUND1_LEAF_WORK_FLOOR_BYTES);
        let bytes = match get_raw_retrying(storage, key).await {
            Ok(Some(bytes)) => bytes,
            // Key is in our committed tree but definitively NOT stored — real
            // storage loss / the classic deleter. For a recently gossiped pin
            // the auditor counts this as a CONFIRMED failure.
            Ok(None) => {
                warn!(
                    "Subtree audit: missing bytes for committed key {}",
                    hex::encode(key)
                );
                return SubtreeAuditResponse::Rejected {
                    challenge_id: challenge.challenge_id,
                    kind: RejectKind::Protocol,
                    reason: format!("missing bytes for committed key: {}", hex::encode(key)),
                };
            }
            // Persistent transient read error after retries — NOT proof of missing
            // data. Reject `Transient`; the auditor routes it to the timeout lane
            // (no confirmed penalty) so a genuinely flaky disk is not branded a
            // deleter, while gaining no positive standing.
            Err(e) => {
                warn!(
                    "Subtree audit: storage read error for committed key {}: {e} \
                     (rejecting as transient, not a confirmed failure)",
                    hex::encode(key)
                );
                return SubtreeAuditResponse::Rejected {
                    challenge_id: challenge.challenge_id,
                    kind: RejectKind::Transient,
                    reason: format!("transient storage read error: {e}"),
                };
            }
        };
        // Top up to the content actually read, above the floor already charged.
        // Charged at the READ, not at the end: the disk read and the
        // keyed-BLAKE3 pass below are both already owed at this point, and
        // every remaining exit from this loop — a later missing key, a
        // persistent read error, a failed hashing task — discards the leaves
        // but not the work. Accruing here is what makes a commitment with one
        // bad key cost the attacker something per replay instead of nothing.
        let content = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
        *content_bytes = content_bytes.saturating_add(
            content
                .saturating_sub(SUBTREE_ROUND1_LEAF_WORK_FLOOR_BYTES)
                .max(0),
        );
        // Hash the leaf (a full keyed-BLAKE3 pass over the chunk) on a blocking
        // thread, not the async worker: a maximal subtree is ~sqrt(N) leaves of up
        // to MAX_CHUNK_SIZE each, so doing this inline would tie up a Tokio worker
        // for the whole proof and let a few round-1 requests starve the runtime.
        // One chunk is resident at a time, so peak memory is bounded.
        let nonce = challenge.nonce;
        let peer = challenge.challenged_peer_id;
        let leaf_key = *key;
        let leaf = match tokio::task::spawn_blocking(move || {
            crate::replication::subtree::subtree_leaf(&nonce, &peer, &leaf_key, &bytes)
        })
        .await
        {
            Ok(leaf) => leaf,
            Err(e) => {
                warn!(
                    "Subtree audit: leaf hashing task failed for key {}: {e}",
                    hex::encode(key)
                );
                return SubtreeAuditResponse::Rejected {
                    challenge_id: challenge.challenge_id,
                    kind: RejectKind::Transient,
                    reason: format!("leaf hashing task error: {e}"),
                };
            }
        };
        leaves.push(leaf);
    }

    SubtreeAuditResponse::Proof {
        challenge_id: challenge.challenge_id,
        commitment: built.commitment().clone(),
        proof: SubtreeProof {
            leaves,
            sibling_cut_hashes: plan.sibling_cut_hashes,
        },
    }
}

/// Build every requested opening for one committed key from a single hashing
/// pass over its bytes: a Bao verified slice (authenticity against the chunk
/// address) plus a nonced block-tree opening (possession against round 1's
/// `nonced_root`) per block index.
///
/// The Bao outboard and nonced tree each hash the full chunk, so this builds
/// them once (via [`ChunkOpener`]) and serves all `indices` from them rather
/// than re-hashing per opening (V2-685 round-2 amplification fix). `indices` is
/// deduplicated by the caller. CPU-heavy, so callers run it on a blocking thread.
///
/// Returns `Err((kind, reason))` for the terminal cases that abort the whole
/// response: a block index out of range (only a forged/buggy auditor sends one →
/// `Protocol`), or a surprise in-memory Bao extraction error (`Transient`, so an
/// honest holder is not branded a deleter).
fn build_slice_items_for_key(
    nonce: [u8; 32],
    peer: [u8; 32],
    key: XorName,
    bytes: &[u8],
    indices: &[u32],
) -> Result<Vec<SubtreeSliceItem>, (RejectKind, String)> {
    let opener = crate::replication::slice::ChunkOpener::new(&nonce, &peer, &key, bytes);
    let count = opener.block_count();
    let mut items = Vec::with_capacity(indices.len());
    for &block_index in indices {
        if block_index >= count {
            return Err((
                RejectKind::Protocol,
                format!(
                    "block index {block_index} out of range for key {}",
                    hex::encode(key)
                ),
            ));
        }
        let bao_slice = match opener.bao_slice(block_index) {
            Ok(slice) => slice,
            Err(e) => {
                warn!(
                    "Subtree slice audit: bao extraction failed for key {}: {e}",
                    hex::encode(key)
                );
                return Err((RejectKind::Transient, format!("bao extraction error: {e}")));
            }
        };
        // `block_index < count` was just checked, so siblings must exist. A
        // `None` here is an internal proof-building inconsistency, not an honest
        // condition: abort the whole response as `Transient` (routes to the
        // timeout lane) rather than emit an empty-siblings `Present` that would
        // make an honest holder fail its own audit.
        let Some(nonced_siblings) = opener.nonced_siblings(block_index) else {
            warn!(
                "Subtree slice audit: no nonced siblings for in-range block {block_index} of key {}",
                hex::encode(key)
            );
            return Err((
                RejectKind::Transient,
                format!("nonced sibling build inconsistency for block {block_index}"),
            ));
        };
        items.push(SubtreeSliceItem::Present {
            key,
            block_index,
            bao_slice,
            nonced_siblings,
        });
    }
    Ok(items)
}

/// Handle a round-2 slice challenge (responder side), ADR-0002 / V2-685.
///
/// The auditor has already structurally verified this node's round-1 subtree
/// proof and now opens up to two 1 KiB blocks (a fresh-random block plus the
/// final block) of a small freshly-random sample of those leaves. For each
/// opening the responder reads the committed chunk and builds a two-chain
/// opening (a Bao verified slice for authenticity against the chunk address, and
/// a nonced block-tree opening for possession against round 1's `nonced_root`),
/// returning [`SubtreeSliceItem::Present`]. If it committed to the key but can no
/// longer
/// produce the bytes it returns [`SubtreeSliceItem::Absent`], which the auditor
/// counts as a provable failure.
///
/// Openings are authorised against the subtree round 1 actually proved, not
/// merely against the pinned commitment. A challenge naming any key outside that
/// subtree is refused whole, before any chunk is read, so the work this round can
/// cost is bounded by the work the caller already paid for in round 1. An honest
/// auditor cannot trip this: it samples only the leaves round 1 returned, and
/// without that leaf's `nonced_root` and `content_len` it has nothing to verify
/// an answer against.
pub async fn handle_subtree_slice_challenge(
    challenge: &SubtreeSliceChallenge,
    storage: &ChunkStore,
    self_peer_id: &PeerId,
    is_bootstrapping: bool,
    commitment_state: Option<&Arc<ResponderCommitmentState>>,
) -> SubtreeSliceResponse {
    if is_bootstrapping {
        return SubtreeSliceResponse::Bootstrapping {
            challenge_id: challenge.challenge_id,
        };
    }

    if challenge.challenged_peer_id != *self_peer_id.as_bytes() {
        return SubtreeSliceResponse::Rejected {
            challenge_id: challenge.challenge_id,
            kind: RejectKind::Protocol,
            reason: "challenged_peer_id does not match this node".to_string(),
        };
    }

    // An honest auditor opens at most MAX_SLICE_OPENINGS blocks per challenge.
    // Reject larger requests up front: each opening forces a full chunk read to
    // build its proof, so an oversized request is a disk-read amplification lever
    // for a forged auditor.
    if challenge.openings.len() > MAX_SLICE_OPENINGS {
        let requested = challenge.openings.len();
        return SubtreeSliceResponse::Rejected {
            challenge_id: challenge.challenge_id,
            kind: RejectKind::Protocol,
            reason: format!(
                "slice challenge requests {requested} openings; max {MAX_SLICE_OPENINGS} per challenge"
            ),
        };
    }

    let Some(state) = commitment_state else {
        return SubtreeSliceResponse::Rejected {
            challenge_id: challenge.challenge_id,
            kind: RejectKind::Protocol,
            reason: "no commitment state".to_string(),
        };
    };
    // Resolve the SAME commitment the auditor pinned in round 1. If we no longer
    // retain it (rotated past it), reject as `UnknownCommitment`. With audit
    // grace removed (ADR-0004 A1) the auditor treats a responsive miss on an
    // in-window pin as a confirmed failure — answerability is restart-durable and
    // pins are challenged only in-window. We open blocks only for keys committed
    // under this pin.
    let Some(built) = state.lookup_by_hash(&challenge.expected_commitment_hash) else {
        return SubtreeSliceResponse::Rejected {
            challenge_id: challenge.challenge_id,
            kind: RejectKind::UnknownCommitment,
            reason: "unknown commitment hash".to_string(),
        };
    };

    // Coalesce openings by key, preserving first-seen order and deduplicating
    // block indices per key, so each committed chunk is read from the store and hashed
    // at most once even when the auditor opens several of its blocks (the normal
    // random + final pair, or a forged duplicate). Without this a ten-opening
    // request could re-read and re-hash the same chunk ten times.
    let mut key_order: Vec<XorName> = Vec::new();
    let mut indices_by_key: HashMap<XorName, Vec<u32>> = HashMap::new();
    for opening in &challenge.openings {
        let entry = indices_by_key.entry(opening.key).or_default();
        if entry.is_empty() {
            key_order.push(opening.key);
        }
        if !entry.contains(&opening.block_index) {
            entry.push(opening.block_index);
        }
    }

    // Coalescing only saves work when keys REPEAT. A forged auditor could still
    // spread its MAX_SLICE_OPENINGS across that many DISTINCT keys to force a
    // full-chunk read each (up to ~40 MiB). An honest auditor samples at most
    // BYTE_SPOTCHECK_MAX leaves, so cap distinct keys to that.
    if key_order.len() > BYTE_SPOTCHECK_MAX as usize {
        let distinct = key_order.len();
        return SubtreeSliceResponse::Rejected {
            challenge_id: challenge.challenge_id,
            kind: RejectKind::Protocol,
            reason: format!(
                "slice challenge spans {distinct} distinct keys; max {BYTE_SPOTCHECK_MAX}"
            ),
        };
    }

    // Round 2 may open ONLY the leaves round 1 actually proved, not the whole
    // pinned commitment. Membership of the pinned tree is the weaker property:
    // it would let a cheap round 1 over small records authorise openings against
    // large records elsewhere in the commitment, so the work this round costs
    // would not be bounded by the work the caller paid for in round 1.
    //
    // The authorised set is recomputed from `(tree, nonce)` rather than carried
    // in the round-1 session. The subtree is a pure function of those two, both
    // of which are already pinned — the nonce was matched against the session
    // before this handler ran — so recomputing costs one tree walk with no chunk
    // reads, while storing the key list would cost up to a full subtree of keys
    // per live session.
    let plan = match subtree_plan(built.tree(), &challenge.nonce) {
        Ok(plan) => plan,
        // The tree is ours and round 1 already walked it, so a failure here is
        // local inconsistency rather than anything the caller did. Transient
        // routes the auditor to the graced timeout lane instead of branding this
        // node with a confirmed failure it did not earn.
        Err(e) => {
            warn!("Subtree slice audit: cannot rebuild the round-1 subtree plan: {e:?}");
            return SubtreeSliceResponse::Rejected {
                challenge_id: challenge.challenge_id,
                kind: RejectKind::Transient,
                reason: "cannot rebuild the audited subtree".to_string(),
            };
        }
    };
    let authorised: HashSet<XorName> = plan.leaf_keys.iter().copied().collect();

    // Refuse the whole challenge before touching storage, matching how an
    // over-broad challenge is handled above. An honest auditor cannot reach this:
    // it samples only the leaves round 1 returned, and it has no `nonced_root` or
    // `content_len` to verify an answer for anything else against, so an opening
    // outside the subtree could not tell it anything even if served.
    if let Some(outside) = key_order.iter().find(|key| !authorised.contains(*key)) {
        return SubtreeSliceResponse::Rejected {
            challenge_id: challenge.challenge_id,
            kind: RejectKind::Protocol,
            reason: format!(
                "slice challenge opens {} which is outside the audited subtree",
                hex::encode(outside)
            ),
        };
    }

    let mut items = Vec::with_capacity(challenge.openings.len());
    for key in key_order {
        let indices = indices_by_key.remove(&key).unwrap_or_default();
        match serve_committed_key_openings(challenge, storage, key, indices).await {
            KeyServe::Items(mut built_items) => items.append(&mut built_items),
            KeyServe::Absent => items.push(SubtreeSliceItem::Absent { key }),
            KeyServe::Reject(reject) => return reject,
        }
    }

    SubtreeSliceResponse::Items {
        challenge_id: challenge.challenge_id,
        items,
    }
}

/// Outcome of serving all requested openings for one committed key.
enum KeyServe {
    /// Openings built for this key; append to the response.
    Items(Vec<SubtreeSliceItem>),
    /// Committed but the bytes are gone → provable `Absent`.
    Absent,
    /// A terminal condition (out-of-range index, read/build error) that aborts
    /// the whole response.
    Reject(SubtreeSliceResponse),
}

/// Read a committed key's chunk once and build every requested opening from it.
///
/// The Bao outboard + nonced tree hash the whole chunk, so the CPU-heavy build
/// runs on a blocking thread to keep an audit-responder flood off the Tokio pool.
/// `indices` is already deduplicated by the caller.
async fn serve_committed_key_openings(
    challenge: &SubtreeSliceChallenge,
    storage: &ChunkStore,
    key: XorName,
    indices: Vec<u32>,
) -> KeyServe {
    let reject = |kind, reason| {
        KeyServe::Reject(SubtreeSliceResponse::Rejected {
            challenge_id: challenge.challenge_id,
            kind,
            reason,
        })
    };
    match get_raw_retrying(storage, &key).await {
        Ok(Some(bytes)) => {
            let nonce = challenge.nonce;
            let peer = challenge.challenged_peer_id;
            match tokio::task::spawn_blocking(move || {
                build_slice_items_for_key(nonce, peer, key, &bytes, &indices)
            })
            .await
            {
                Ok(Ok(built_items)) => KeyServe::Items(built_items),
                Ok(Err((kind, reason))) => reject(kind, reason),
                Err(e) => {
                    warn!(
                        "Subtree slice audit: proof build task failed for key {}: {e}",
                        hex::encode(key)
                    );
                    reject(
                        RejectKind::Transient,
                        format!("proof build task error: {e}"),
                    )
                }
            }
        }
        // Committed key, definitively absent → provable failure (§7: a real "I
        // don't hold it" answer, distinct from a read error).
        Ok(None) => {
            warn!(
                "Subtree slice audit: committed key {} requested but bytes absent",
                hex::encode(key)
            );
            KeyServe::Absent
        }
        // Persistent transient read error after retries → do NOT brand the peer a
        // deleter. Reject `Transient`; the auditor routes it to the timeout lane
        // so a flaky read never manufactures a confirmed possession failure
        // on an honest holder (which also gains no credit).
        Err(e) => {
            warn!(
                "Subtree slice audit: storage read error for committed key {}: {e} \
                 (rejecting as transient, not a confirmed failure)",
                hex::encode(key)
            );
            reject(
                RejectKind::Transient,
                format!("transient storage read error: {e}"),
            )
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::replication::commitment_state::BuiltCommitment;
    use crate::replication::subtree::{build_subtree_proof, SubtreeLeaf};
    use saorsa_pqc::api::sig::ml_dsa_65;
    use std::time::Instant;

    /// ADR-0004 A1 grade flip (grace removed): a responsive `UnknownCommitment`
    /// or `Protocol` rejection is a CONFIRMED failure; only `Transient` routes to
    /// the timeout lane. This pure decision backs both audit rounds
    /// (`Confirmed → AuditFailureReason::Rejected` / `SliceRound::Rejected`;
    /// `TimeoutLane → AuditFailureReason::Timeout` + pinned-credit revocation).
    #[test]
    fn grade_reject_removes_grace_for_unknown_commitment() {
        assert_eq!(
            grade_reject(RejectKind::UnknownCommitment),
            RejectGrade::Confirmed,
            "an unanswerable pinned root is now a confirmed failure, not graced"
        );
        assert_eq!(grade_reject(RejectKind::Protocol), RejectGrade::Confirmed);
        assert_eq!(
            grade_reject(RejectKind::Transient),
            RejectGrade::TimeoutLane,
            "a transient read error routes to the timeout lane (no confirmed penalty)"
        );
    }

    /// A peer id for classification tests (never dialled).
    fn classify_peer() -> PeerId {
        PeerId::from_bytes([0x5Au8; 32])
    }

    // A node that answers round 1 with a valid signed proof and then claims
    // `Bootstrapping` in round 2 is contradicting itself: a bootstrapping node
    // has no committed data to prove. Grading that as a graced timeout would be
    // the cheapest possible way to dodge every possession check while KEEPING
    // the holder credit earned in round 1 — so it must be a confirmed failure.
    #[test]
    fn responsive_bootstrap_is_a_confirmed_failure_not_a_graced_timeout() {
        let id = 4242u64;
        let round = classify_slice_response(
            ReplicationMessageBody::SubtreeSliceResponse(SubtreeSliceResponse::Bootstrapping {
                challenge_id: id,
            }),
            id,
            &classify_peer(),
        );
        assert!(
            matches!(round, SliceRound::ResponsiveBootstrap),
            "mid-audit Bootstrapping must classify as ResponsiveBootstrap"
        );

        // The production arm maps `ResponsiveBootstrap` alongside `Rejected` to
        // `AuditFailureReason::Rejected`, and THAT reason is what revokes the
        // peer's holder credit wholesale. Pin the policy both ways, since the
        // whole point of the classification is landing on the revoking side.
        assert!(
            super::super::audit_failure_revokes_holder_credit(&AuditFailureReason::Rejected),
            "a confirmed round-2 failure must revoke holder credit"
        );
        assert!(
            !super::super::audit_failure_revokes_holder_credit(&AuditFailureReason::Timeout),
            "the timeout lane must not revoke credit WHOLESALE — the contrast that \
             makes classifying ResponsiveBootstrap as confirmed load-bearing. The \
             timeout lane still drops the pinned commitment's own credit; see \
             round2_revokes_pinned_credit"
        );
    }

    /// A responder that answered round 1 and then goes quiet must not keep the
    /// holder credit for the commitment under audit.
    ///
    /// Round 2 names the blocks after the roots are committed, so a responder
    /// chooses whether to reply already knowing the draw. If silence kept
    /// credit, answering only favourable draws would be free and standing earned
    /// once would survive every dodged check afterwards. Both no-proof outcomes
    /// therefore drop the pinned credit, while the confirmed lanes are excluded
    /// here because they revoke the peer's credit wholesale downstream.
    #[test]
    fn round2_without_a_proof_drops_the_pinned_commitment_credit() {
        assert!(
            round2_revokes_pinned_credit(&SliceRound::Timeout),
            "silence after a valid round-1 proof must cost the pinned credit"
        );
        assert!(
            round2_revokes_pinned_credit(&SliceRound::TransientReject),
            "a transient reject also ends round 2 with no possession proof"
        );
        assert!(
            !round2_revokes_pinned_credit(&SliceRound::Served(vec![])),
            "a served response is judged on its contents, not here"
        );
        for confirmed in [
            SliceRound::Rejected,
            SliceRound::ResponsiveBootstrap,
            SliceRound::Malformed,
        ] {
            assert!(
                !round2_revokes_pinned_credit(&confirmed),
                "confirmed failures revoke wholesale downstream, not scoped here"
            );
        }
    }

    /// The scoped revocation must not erase credit the peer re-earned under a
    /// different commitment: an unanswered round 2 costs the pin it was about,
    /// not the peer's whole standing.
    #[test]
    fn pinned_credit_revocation_is_scoped_to_the_audited_commitment() {
        let peer = classify_peer();
        let (audited, newer) = ([0x11u8; 32], [0x22u8; 32]);
        let key: XorName = [0xC3u8; 32];
        let now = Instant::now();
        let mut provers = RecentProvers::new();
        provers.record_proof(key, peer, audited, now);
        provers.record_proof(key, peer, newer, now);

        // What `verify_subtree_response` does when round 2 yields no proof.
        provers.forget_commitment(&audited);

        assert!(
            !provers.is_credited_holder(&key, &peer, &audited),
            "credit for the audited pin must be gone after an unanswered round 2"
        );
        assert!(
            provers.is_credited_holder(&key, &peer, &newer),
            "credit re-earned under a newer commitment must survive"
        );
    }

    // Every classification arm is guarded on `challenge_id`. A responder must not
    // be able to answer the challenge it was actually sent with a body minted for
    // a different one — in particular it must not downgrade a live challenge by
    // replaying a `Bootstrapping` or `Transient` body from another exchange.
    #[test]
    fn slice_response_for_another_challenge_is_malformed() {
        let (sent, other) = (7u64, 8u64);
        let peer = classify_peer();
        let bodies = [
            ReplicationMessageBody::SubtreeSliceResponse(SubtreeSliceResponse::Bootstrapping {
                challenge_id: other,
            }),
            ReplicationMessageBody::SubtreeSliceResponse(SubtreeSliceResponse::Items {
                challenge_id: other,
                items: vec![],
            }),
            ReplicationMessageBody::SubtreeSliceResponse(SubtreeSliceResponse::Rejected {
                challenge_id: other,
                kind: RejectKind::Transient,
                reason: String::new(),
            }),
        ];
        for body in bodies {
            assert!(
                matches!(
                    classify_slice_response(body, sent, &peer),
                    SliceRound::Malformed
                ),
                "a body carrying another challenge_id must be malformed"
            );
        }

        // A non-round-2 body on the round-2 path is malformed too.
        assert!(matches!(
            classify_slice_response(
                ReplicationMessageBody::SubtreeAuditResponse(
                    crate::replication::protocol::SubtreeAuditResponse::Bootstrapping {
                        challenge_id: sent,
                    }
                ),
                sent,
                &peer,
            ),
            SliceRound::Malformed
        ));
    }

    // The two-round audit splits into SHIPPED pure functions exercised directly
    // here (no reimplementation that could drift):
    //   - round 1: `evaluate_subtree_structure` (pin/identity/signature +
    //     structural root rebuild),
    //   - sampling: `random_spotcheck_leaves` (3..=5 FRESHLY-RANDOM leaves chosen
    //     after the proof is in hand — see its doc for the soundness argument), and
    //   - round 2: `verify_slice_response` (decode the Bao slice against the chunk
    //     address + fold the nonced opening to the round-1 `nonced_root`, both from
    //     what the RESPONDER served — the auditor holds nothing).

    fn key(i: u32) -> XorName {
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(&i.to_be_bytes());
        k
    }

    // The auditor's per-opening matcher returns the FIRST item with a matching
    // identity, so an oversized, unsolicited, or colliding response must be
    // rejected as malformed BEFORE matching — otherwise item order (or padding)
    // could decide the verdict or force quadratic validation work.
    #[test]
    fn verify_slice_response_rejects_malformed_item_sets() {
        let leaf = |k: XorName| SubtreeLeaf {
            key: k,
            bytes_hash: [0u8; 32],
            content_len: 0,
            nonced_root: [0u8; 32],
        };
        let present = |k: XorName, i: u32| SubtreeSliceItem::Present {
            key: k,
            block_index: i,
            bao_slice: vec![],
            nonced_siblings: vec![],
        };
        let malformed = |verdict| {
            matches!(
                verdict,
                AuditVerdict::Fail(AuditFailureReason::MalformedResponse)
            )
        };
        let nonce = [0u8; 32];
        let peer = [0u8; 32];
        // The auditor requested (key1, block 0), (key1, block 1), (key2, block 0).
        let openings = vec![(leaf(key(1)), 0u32), (leaf(key(1)), 1), (leaf(key(2)), 0)];

        // More items than requested openings.
        let oversized = vec![
            present(key(1), 0),
            present(key(1), 1),
            present(key(2), 0),
            present(key(2), 0),
        ];
        assert!(malformed(verify_slice_response(
            &openings, &nonce, &peer, &oversized
        )));

        // An item that was not requested.
        let unsolicited = vec![present(key(9), 0)];
        assert!(malformed(verify_slice_response(
            &openings,
            &nonce,
            &peer,
            &unsolicited
        )));

        // Duplicate (key, block_index).
        let dup = vec![present(key(1), 0), present(key(1), 0)];
        assert!(malformed(verify_slice_response(
            &openings, &nonce, &peer, &dup
        )));

        // A key that is both Present and Absent.
        let conflict = vec![present(key(1), 0), SubtreeSliceItem::Absent { key: key(1) }];
        assert!(malformed(verify_slice_response(
            &openings, &nonce, &peer, &conflict
        )));

        // A well-formed, unique, solicited response passes the identity guard (the
        // empty proofs then fail verification as DigestMismatch, NOT malformed).
        let ok = vec![present(key(1), 0), present(key(1), 1), present(key(2), 0)];
        assert!(!malformed(verify_slice_response(
            &openings, &nonce, &peer, &ok
        )));
    }
    /// Deterministic chunk content for fixture index `i`. Fixture keys are
    /// CONTENT-ADDRESSED (`ckey(i) == BLAKE3(chunk_bytes(i))`), so a committed
    /// leaf is `(key, key)` exactly as production, and round 2 serves this content.
    fn chunk_bytes(i: u32) -> Vec<u8> {
        let mut v = b"chunk-body".to_vec();
        v.extend_from_slice(&i.to_le_bytes());
        v
    }

    /// Content-addressed key for fixture index `i` (so `bytes_hash == key`).
    fn ckey(i: u32) -> XorName {
        *blake3::hash(&chunk_bytes(i)).as_bytes()
    }

    /// The content behind a committed fixture key (reverse of `ckey`), so round-2
    /// fixtures can serve the real bytes for any sampled leaf.
    fn content_for_key(k: &XorName) -> Vec<u8> {
        (0..16_384u32)
            .find(|&i| &ckey(i) == k)
            .map(chunk_bytes)
            .expect("fixture content for committed key")
    }

    /// Build an honest committed tree of `n` keys + a valid round-1 proof for
    /// `nonce`. Returns `(built, proof, peer_id)`. The auditor pins `built.hash()`.
    fn honest(n: u32, nonce: &[u8; 32]) -> (BuiltCommitment, SubtreeProof, [u8; 32]) {
        let (pk, sk) = ml_dsa_65().generate_keypair().unwrap();
        let peer_id = *blake3::hash(&pk.to_bytes()).as_bytes();
        let pk_b = pk.to_bytes();
        // Content-addressed: bytes_hash == key, exactly as production commits.
        let entries: Vec<_> = (0..n).map(|i| (ckey(i), ckey(i))).collect();
        let built = BuiltCommitment::build(entries, &peer_id, &sk, &pk_b).unwrap();
        let proof =
            build_subtree_proof(built.tree(), nonce, &peer_id, |k| Some(content_for_key(k)))
                .unwrap();
        (built, proof, peer_id)
    }

    /// Round-1 verdict against the pinned commitment.
    fn structure(
        built: &BuiltCommitment,
        proof: &SubtreeProof,
        nonce: &[u8; 32],
        peer: &[u8; 32],
    ) -> Result<(), AuditFailureReason> {
        evaluate_subtree_structure(built.commitment(), proof, nonce, &built.hash(), peer)
    }

    /// The 3..=5 spot-check leaves the auditor would open in round 2. Now
    /// freshly-random (post-proof) rather than nonce-derived; the `_nonce`/
    /// `_key_count` params are kept so existing call sites read unchanged.
    fn sample<'a>(
        proof: &'a SubtreeProof,
        _nonce: &[u8; 32],
        _key_count: u32,
    ) -> Vec<&'a SubtreeLeaf> {
        random_spotcheck_leaves(proof, 8u32.clamp(BYTE_SPOTCHECK_MIN, BYTE_SPOTCHECK_MAX))
    }

    /// Pair each sampled leaf with a block index for round 2. The fixtures use
    /// short (single-block) chunks, so block 0 is the only block; the production
    /// auditor draws a fresh random index via `random_block_index`.
    fn openings_for(sample: &[&SubtreeLeaf]) -> Vec<(SubtreeLeaf, u32)> {
        sample.iter().map(|l| ((*l).clone(), 0u32)).collect()
    }

    /// Honest responder: for each opening build a real Bao slice + nonced opening
    /// from the true chunk content, exactly as `handle_subtree_slice_challenge`
    /// would.
    fn served_honest_items(
        openings: &[(SubtreeLeaf, u32)],
        nonce: &[u8; 32],
        peer: &[u8; 32],
    ) -> Vec<SubtreeSliceItem> {
        openings
            .iter()
            .map(|(leaf, block_index)| {
                let content = content_for_key(&leaf.key);
                let bao_slice =
                    crate::replication::slice::extract_block_slice(&content, *block_index).unwrap();
                let nonced_siblings = crate::replication::slice::nonced_block_siblings(
                    nonce,
                    peer,
                    &leaf.key,
                    &content,
                    *block_index,
                )
                .unwrap();
                SubtreeSliceItem::Present {
                    key: leaf.key,
                    block_index: *block_index,
                    bao_slice,
                    nonced_siblings,
                }
            })
            .collect()
    }

    // ---- round 1: structure --------------------------------------------------

    #[test]
    fn honest_structure_then_bytes_passes() {
        let nonce = [9u8; 32];
        let (built, proof, peer) = honest(400, &nonce);
        // Round 1.
        assert!(structure(&built, &proof, &nonce, &peer).is_ok());
        // Round 2: honest responder opens real slices for the sample.
        let s = sample(&proof, &nonce, built.commitment().key_count);
        assert!(!s.is_empty());
        let openings = openings_for(&s);
        let items = served_honest_items(&openings, &nonce, &peer);
        match verify_slice_response(&openings, &nonce, &peer, &items) {
            AuditVerdict::Pass { checked } => assert!(checked >= 1, "must verify >=1 leaf"),
            other @ AuditVerdict::Fail(_) => panic!("expected Pass, got {other:?}"),
        }
    }

    /// Possession-forgery guard: a peer that signs a commitment whose leaves
    /// decouple the credited `key` from the authenticated content hash
    /// (`bytes_hash != key`) is rejected at round 1 — even though the structural
    /// root still rebuilds from `(key, bytes_hash)`. Without the guard such a peer
    /// could earn holder credit for an expensive address `key` while only proving
    /// possession of an unrelated (e.g. one-byte) chunk hashing to `bytes_hash`.
    #[test]
    fn leaf_with_bytes_hash_decoupled_from_key_is_rejected() {
        let nonce = [5u8; 32];
        let (pk, sk) = ml_dsa_65().generate_keypair().unwrap();
        let peer_id = *blake3::hash(&pk.to_bytes()).as_bytes();
        let pk_b = pk.to_bytes();
        // Every leaf commits (key, bytes_hash) with bytes_hash != key.
        let entries: Vec<_> = (0..64u32).map(|i| (ckey(i), ckey(i + 10_000))).collect();
        let built = BuiltCommitment::build(entries, &peer_id, &sk, &pk_b).unwrap();
        let proof =
            build_subtree_proof(built.tree(), &nonce, &peer_id, |k| Some(content_for_key(k)))
                .unwrap();
        // The structural root rebuilds (it is a genuinely signed tree), so the
        // decoupled-address gate is what must reject it.
        assert_eq!(
            structure(&built, &proof, &nonce, &peer_id),
            Err(AuditFailureReason::DigestMismatch),
            "a leaf whose bytes_hash != key must be rejected at round 1"
        );
    }

    #[test]
    fn commitment_bound_to_another_peer_rejected() {
        let nonce = [3u8; 32];
        let (built, proof, _peer) = honest(200, &nonce);
        let other = [0xAAu8; 32];
        assert_eq!(
            structure(&built, &proof, &nonce, &other),
            Err(AuditFailureReason::Rejected)
        );
    }

    #[test]
    fn wrong_pinned_commitment_rejected() {
        let nonce = [3u8; 32];
        let (built, proof, peer) = honest(200, &nonce);
        let mut wrong_pin = built.hash();
        wrong_pin[0] ^= 0x01;
        assert_eq!(
            evaluate_subtree_structure(built.commitment(), &proof, &nonce, &wrong_pin, &peer),
            Err(AuditFailureReason::Rejected)
        );
    }

    #[test]
    fn tampered_leaf_structure_rejected() {
        let nonce = [3u8; 32];
        let (built, mut proof, peer) = honest(200, &nonce);
        if let Some(first) = proof.leaves.first_mut() {
            first.bytes_hash[0] ^= 0x01; // breaks root reconstruction
        }
        assert_eq!(
            structure(&built, &proof, &nonce, &peer),
            Err(AuditFailureReason::DigestMismatch)
        );
    }

    #[test]
    fn wrong_leaf_count_structure_rejected() {
        let nonce = [3u8; 32];
        let (built, mut proof, peer) = honest(200, &nonce);
        proof.leaves.pop();
        assert_eq!(
            structure(&built, &proof, &nonce, &peer),
            Err(AuditFailureReason::DigestMismatch)
        );
    }

    // ---- round 2: responder-served bytes ------------------------------------

    #[test]
    fn deleter_absent_bytes_is_confirmed_failure() {
        // THE headline fix: a node whose round-1 proof is structurally perfect
        // but which has DELETED a committed chunk cannot serve its bytes. It
        // signals `Absent` for the sampled key → provable lie → confirmed
        // failure, reported as `KeyAbsent` because the peer admitted the loss.
        // Crucially, the auditor holds NONE of the peer's chunks; the
        // verdict depends only on what the responder serves.
        let nonce = [9u8; 32];
        let (built, proof, peer) = honest(400, &nonce);
        assert!(structure(&built, &proof, &nonce, &peer).is_ok());
        let s = sample(&proof, &nonce, built.commitment().key_count);
        let openings = openings_for(&s);
        // Responder returns Absent for the FIRST opening, honest for the rest.
        let victim = openings.first().map(|(l, _)| l.key).unwrap();
        let mut items = served_honest_items(&openings, &nonce, &peer);
        if let Some(slot) = items.first_mut() {
            *slot = SubtreeSliceItem::Absent { key: victim };
        }
        let v = verify_slice_response(&openings, &nonce, &peer, &items);
        assert_eq!(v, AuditVerdict::Fail(AuditFailureReason::KeyAbsent));
    }

    #[test]
    fn omitted_committed_key_is_confirmed_failure() {
        // A responder that simply omits a sampled committed opening from its items
        // (neither Present nor Absent) is a confirmed failure just like Absent,
        // but it never admitted the loss, so it is a proof failure rather than
        // `KeyAbsent`. This is the counterpart to
        // `deleter_absent_bytes_is_confirmed_failure`: together they pin that the
        // two reasons stay distinguishable in the audit-failure log line.
        let nonce = [9u8; 32];
        let (built, proof, peer) = honest(400, &nonce);
        let s = sample(&proof, &nonce, built.commitment().key_count);
        let openings = openings_for(&s);
        let mut items = served_honest_items(&openings, &nonce, &peer);
        items.remove(0); // omit the first opening entirely
        let v = verify_slice_response(&openings, &nonce, &peer, &items);
        assert_eq!(v, AuditVerdict::Fail(AuditFailureReason::DigestMismatch));
    }

    #[test]
    fn fake_storage_garbage_bytes_is_confirmed_failure() {
        // A "fake-storage" responder claims possession but opens a slice built
        // from garbage content. The garbage slice does not decode against the
        // committed content address (`bytes_hash`), so chain 1 fails → confirmed
        // failure. No auditor holdings involved.
        let nonce = [9u8; 32];
        let (built, proof, peer) = honest(400, &nonce);
        let s = sample(&proof, &nonce, built.commitment().key_count);
        let openings = openings_for(&s);
        let items: Vec<SubtreeSliceItem> = openings
            .iter()
            .map(|(leaf, bi)| {
                let mut garbage = blake3::hash(&leaf.key).as_bytes().to_vec();
                garbage.extend_from_slice(b"adversary-fake-storage");
                let bao_slice =
                    crate::replication::slice::extract_block_slice(&garbage, *bi).unwrap();
                let nonced_siblings = crate::replication::slice::nonced_block_siblings(
                    &nonce, &peer, &leaf.key, &garbage, *bi,
                )
                .unwrap();
                SubtreeSliceItem::Present {
                    key: leaf.key,
                    block_index: *bi,
                    bao_slice,
                    nonced_siblings,
                }
            })
            .collect();
        let v = verify_slice_response(&openings, &nonce, &peer, &items);
        assert_eq!(v, AuditVerdict::Fail(AuditFailureReason::DigestMismatch));
    }

    #[test]
    fn correct_content_address_but_stale_nonced_root_fails() {
        // A responder can serve the real block (chain 1, the Bao slice against the
        // address, passes), but if its committed `nonced_root` does not correspond
        // to the audit's nonce over that content, the nonced opening (chain 2)
        // cannot fold to it. We model a leaf whose committed `nonced_root` was
        // built under a DIFFERENT nonce; the honest opening under the audit nonce
        // then fails to match it.
        let nonce = [9u8; 32];
        let (built, mut proof, peer) = honest(400, &nonce);
        let other_nonce = [0xEEu8; 32];
        for leaf in &mut proof.leaves {
            leaf.nonced_root = crate::replication::slice::nonced_block_root(
                &other_nonce,
                &peer,
                &leaf.key,
                &content_for_key(&leaf.key),
            );
        }
        let s = sample(&proof, &nonce, built.commitment().key_count);
        let openings = openings_for(&s);
        let items = served_honest_items(&openings, &nonce, &peer);
        let v = verify_slice_response(&openings, &nonce, &peer, &items);
        assert_eq!(v, AuditVerdict::Fail(AuditFailureReason::DigestMismatch));
    }

    #[test]
    fn auditor_holds_nothing_still_catches_deleter() {
        // Explicit contract: the auditor's own storage is irrelevant. A deleter
        // is caught purely from its served (absent) response. (Compare the OLD
        // design, where an auditor holding none of the chunks went Inconclusive
        // and the deleter walked free.)
        let nonce = [0x21u8; 32];
        let (built, proof, peer) = honest(256, &nonce);
        assert!(structure(&built, &proof, &nonce, &peer).is_ok());
        let s = sample(&proof, &nonce, built.commitment().key_count);
        let openings = openings_for(&s);
        // Responder is a total deleter: Absent for every opening.
        let items: Vec<SubtreeSliceItem> = openings
            .iter()
            .map(|(l, _)| SubtreeSliceItem::Absent { key: l.key })
            .collect();
        let v = verify_slice_response(&openings, &nonce, &peer, &items);
        assert_eq!(v, AuditVerdict::Fail(AuditFailureReason::KeyAbsent));
    }

    #[test]
    fn admitted_absence_and_failed_proof_are_reported_separately() {
        // ROLLOUT DIAGNOSTICS: the two ways a peer fails round 2 must stay
        // distinguishable in the failure summary, because they mean different
        // things operationally — a peer owning up to lost data versus one whose
        // proof did not verify. Before this was split, both rolled up as
        // `digest_mismatch_keys` and `absent_keys` was always 0, so a fleet-wide
        // audit regression and a fleet-wide data loss looked identical.
        let nonce = [0x33u8; 32];
        let (built, proof, peer) = honest(256, &nonce);
        let s = sample(&proof, &nonce, built.commitment().key_count);
        let openings = openings_for(&s);

        // Admitted loss → KeyAbsent → counted under `absent_keys`.
        let absent_items: Vec<SubtreeSliceItem> = openings
            .iter()
            .map(|(l, _)| SubtreeSliceItem::Absent { key: l.key })
            .collect();
        assert_eq!(
            verify_slice_response(&openings, &nonce, &peer, &absent_items),
            AuditVerdict::Fail(AuditFailureReason::KeyAbsent),
        );
        let absent_summary = subtree_failure_summary(&AuditFailureReason::KeyAbsent);
        assert_eq!(absent_summary.absent_keys, 1);
        assert_eq!(absent_summary.digest_mismatch_keys, 0);

        // Withheld without admission → DigestMismatch → `digest_mismatch_keys`.
        let withheld: Vec<SubtreeSliceItem> = served_honest_items(&openings, &nonce, &peer)
            .into_iter()
            .skip(1)
            .collect();
        assert_eq!(
            verify_slice_response(&openings, &nonce, &peer, &withheld),
            AuditVerdict::Fail(AuditFailureReason::DigestMismatch),
        );
        let mismatch_summary = subtree_failure_summary(&AuditFailureReason::DigestMismatch);
        assert_eq!(mismatch_summary.digest_mismatch_keys, 1);
        assert_eq!(mismatch_summary.absent_keys, 0);

        // Both are confirmed failures with identical enforcement, so the split is
        // diagnostic only: it must not quietly soften what an absent key costs.
        assert_eq!(absent_summary.failed_keys, mismatch_summary.failed_keys);
    }

    #[test]
    fn sample_size_is_in_3_to_5_band() {
        // ADR-0002: round-2 samples a SMALL surprise set (3..=5) of the proven
        // leaves. For a large subtree the sample is capped at 5.
        let nonce = [7u8; 32];
        let (built, proof, _peer) = honest(1024, &nonce);
        let s = sample(&proof, &nonce, built.commitment().key_count);
        assert!(
            (BYTE_SPOTCHECK_MIN as usize..=BYTE_SPOTCHECK_MAX as usize).contains(&s.len()),
            "sample {} must be within 3..=5",
            s.len()
        );
    }

    #[test]
    fn full_pass_requires_every_sampled_leaf() {
        // checked must equal the number of sampled leaves on a pass (no leaf is
        // silently skipped — every sampled, committed key must verify).
        let nonce = [11u8; 32];
        let (built, proof, peer) = honest(400, &nonce);
        let s = sample(&proof, &nonce, built.commitment().key_count);
        let openings = openings_for(&s);
        let items = served_honest_items(&openings, &nonce, &peer);
        match verify_slice_response(&openings, &nonce, &peer, &items) {
            AuditVerdict::Pass { checked } => assert_eq!(checked, openings.len()),
            other @ AuditVerdict::Fail(_) => panic!("expected Pass, got {other:?}"),
        }
    }

    // ---- end-to-end gate composition ----------------------------------------

    #[test]
    fn structure_fail_short_circuits_before_round_2() {
        // A structurally invalid proof is rejected in round 1; the slice challenge
        // is never issued. We assert the round-1 gate returns Err so the auditor
        // (verify_subtree_response) never reaches request_slice_proof.
        let nonce = [5u8; 32];
        let (built, mut proof, peer) = honest(300, &nonce);
        if let Some(first) = proof.leaves.first_mut() {
            first.bytes_hash[0] ^= 0x01;
        }
        assert!(structure(&built, &proof, &nonce, &peer).is_err());
    }

    /// Build an honest committed tree whose keys are content-addressed but biased
    /// to the FAR half of the XOR space (top bit set), so `observe_closeness`
    /// counts them toward `far`. Keys stay content-addressed (`bytes_hash == key`)
    /// so round 2 serves real bytes.
    fn honest_far(n: u32, nonce: &[u8; 32]) -> (BuiltCommitment, SubtreeProof, [u8; 32]) {
        let (pk, sk) = ml_dsa_65().generate_keypair().unwrap();
        let peer_id = *blake3::hash(&pk.to_bytes()).as_bytes();
        let pk_b = pk.to_bytes();
        let mut entries: Vec<(XorName, [u8; 32])> = Vec::new();
        let mut i = 0u32;
        while entries.len() < n as usize {
            let k = ckey(i);
            if k[0] >= 0x80 {
                entries.push((k, k));
            }
            i = i.saturating_add(1);
        }
        let built = BuiltCommitment::build(entries, &peer_id, &sk, &pk_b).unwrap();
        let proof =
            build_subtree_proof(built.tree(), nonce, &peer_id, |k| Some(content_for_key(k)))
                .unwrap();
        (built, proof, peer_id)
    }

    /// ADR-0002 "Closeness" is OBSERVE-ONLY: far-keyed honest proofs verify
    /// exactly like near-keyed ones. The verdict (structure + served bytes) is
    /// closeness-blind, so a "far/padding" shape can never produce a Fail.
    #[test]
    fn closeness_is_observe_only_far_keys_still_pass() {
        let nonce = [9u8; 32];

        let (built_far, proof_far, peer_far) = honest_far(400, &nonce);
        assert!(structure(&built_far, &proof_far, &nonce, &peer_far).is_ok());
        let sf = sample(&proof_far, &nonce, built_far.commitment().key_count);
        let of = openings_for(&sf);
        let v_far = verify_slice_response(
            &of,
            &nonce,
            &peer_far,
            &served_honest_items(&of, &nonce, &peer_far),
        );

        let (built_near, proof_near, peer_near) = honest(400, &nonce);
        assert!(structure(&built_near, &proof_near, &nonce, &peer_near).is_ok());
        let sn = sample(&proof_near, &nonce, built_near.commitment().key_count);
        let on = openings_for(&sn);
        let v_near = verify_slice_response(
            &on,
            &nonce,
            &peer_near,
            &served_honest_items(&on, &nonce, &peer_near),
        );

        match (&v_far, &v_near) {
            (AuditVerdict::Pass { checked: cf }, AuditVerdict::Pass { checked: cn }) => {
                assert!(*cf >= 1 && *cn >= 1);
            }
            other => panic!("both honest proofs must Pass regardless of closeness, got {other:?}"),
        }
        assert!(
            !matches!(v_far, AuditVerdict::Fail(_)),
            "far/padding-shaped honest proof must NEVER fail, got {v_far:?}"
        );
    }

    // Unused-leaf constructor guard: keep SubtreeLeaf import meaningful.
    #[test]
    fn subtree_leaf_is_constructible() {
        let _l = SubtreeLeaf {
            key: key(1),
            bytes_hash: [0u8; 32],
            content_len: 0,
            nonced_root: [0u8; 32],
        };
    }
}
