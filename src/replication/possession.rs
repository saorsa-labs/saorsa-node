//! Delayed possession verification for fresh replication (ADR-0003).
//!
//! After a node fresh-replicates a chunk, every close-group peer responsible
//! for it is checked 5-15 minutes later for actual possession. The check is a
//! single-key cryptographic
//! [`AuditChallenge`]: the probed
//! peer must return `BLAKE3(nonce ‖ peer_id ‖ key ‖ bytes)` computed over the
//! chunk it claims to hold. It cannot produce that digest without the bytes, so
//! — unlike a self-reported presence flag — a peer cannot escape the check by
//! falsely asserting possession. A peer that holds the chunk earns nothing —
//! storing what it was paid to store is the baseline expectation, not
//! meritorious; a peer that returns the absent sentinel, or a digest that does
//! not match the checker's canonical copy (cryptographic proof it lacks the
//! bytes), is penalised at `AuditChallenge` severity. Delivery of the original
//! push is irrelevant: a peer the push never reached is still checked and
//! penalised if it lacks the chunk.
//!
//! A peer unreachable at check time is penalised immediately at audit severity,
//! matching the responsible-chunk `AuditChallenge` path. A matching bootstrap
//! claim uses the shared bootstrap-claim grace/abuse tracker; peer-side
//! malformed, rejected, or mismatched responses are audit failures.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng;
use saorsa_core::identity::PeerId;
use saorsa_core::{P2PNode, TrustEvent};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::ant_protocol::XorName;
use crate::logging::{debug, info, warn};
use crate::replication::audit_coordinator::AuditChallengeCoordinator;
use crate::replication::audit_metrics::{self, AuditFailureClass, AuditType};
use crate::replication::config::{
    ReplicationConfig, AUDIT_FAILURE_TRUST_WEIGHT, REPLICATION_PROTOCOL_ID,
};
use crate::replication::protocol::{
    compute_audit_digest, AuditChallenge, AuditResponse, ReplicationMessage,
    ReplicationMessageBody, ABSENT_KEY_DIGEST,
};
use crate::replication::types::{BootstrapClaimObservation, NeighborSyncState};
use crate::storage::ChunkStore;

use super::REPLICATION_TRUST_WEIGHT;

/// A possession probe challenges exactly one key, so the per-probe response
/// budget is the audit-response timeout sized for a single chunk.
const POSSESSION_PROBE_KEY_COUNT: usize = 1;

pub(crate) fn possession_probe_response_timeout(config: &ReplicationConfig) -> Duration {
    config.audit_response_timeout(POSSESSION_PROBE_KEY_COUNT)
}

/// A scheduled possession check for one freshly-replicated chunk.
pub struct PossessionCheckEvent {
    /// Content-address of the chunk.
    pub key: XorName,
    /// Close-group peers responsible for holding it (excludes self).
    pub peers: Vec<PeerId>,
}

/// Verdict of cryptographically probing a single peer for possession of a chunk.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
enum ProbeOutcome {
    /// Peer returned a digest proving it holds the chunk's bytes.
    Present,
    /// Peer failed the audit challenge: absent sentinel, digest mismatch,
    /// rejection, mismatched challenge ID, wrong digest count, or malformed reply.
    Failed(PossessionFailureReason),
    /// No response. Penalised immediately at audit-failure severity; the class
    /// is node-local observability only.
    NoResponse(AuditFailureClass),
    /// Peer returned a matching bootstrap claim. Graced only through the shared
    /// bootstrap-claim tracker.
    BootstrapClaim,
    /// The probe could not be sent locally. Graced: no penalty.
    Inconclusive,
}

/// Exact reason a responsive peer failed a possession proof check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PossessionFailureReason {
    ResponseDecode,
    UnexpectedResponseType,
    DigestChallengeIdMismatch,
    DigestCountMismatch,
    AbsentKey,
    DigestMismatch,
    BootstrapChallengeIdMismatch,
    Rejected,
}

#[cfg(any(feature = "logging", test))]
impl PossessionFailureReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ResponseDecode => "response_decode",
            Self::UnexpectedResponseType => "unexpected_response_type",
            Self::DigestChallengeIdMismatch => "digest_challenge_id_mismatch",
            Self::DigestCountMismatch => "digest_count_mismatch",
            Self::AbsentKey => "absent_key",
            Self::DigestMismatch => "digest_mismatch",
            Self::BootstrapChallengeIdMismatch => "bootstrap_challenge_id_mismatch",
            Self::Rejected => "rejected",
        }
    }
}

/// Pick a randomised delay in `[min, max]` to wait before a possession check
/// runs. The bounds come from `ReplicationConfig` (defaulting to
/// `POSSESSION_CHECK_DELAY_MIN`/`MAX`) so tests can shorten them.
#[must_use]
pub fn random_delay(min: Duration, max: Duration) -> Duration {
    let to_millis = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
    let min_ms = to_millis(min);
    let max_ms = to_millis(max);
    if min_ms >= max_ms {
        return min;
    }
    Duration::from_millis(rand::thread_rng().gen_range(min_ms..=max_ms))
}

/// Run the possession check for one chunk against every responsible peer.
///
/// Recomputes the expected audit digest from the checker's own canonical copy
/// of `key`, so the check is meaningful only while the checker still holds the
/// chunk — which it does immediately after accepting and fresh-replicating a
/// PUT. If the checker no longer holds it (e.g. pruned), the check is moot and
/// is skipped without penalising anyone.
///
/// A peer that fails to prove possession, including by timeout, is penalised at
/// `AuditChallenge` severity immediately. A responsive peer is left unrewarded.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_possession_check(
    key: XorName,
    peers: Vec<PeerId>,
    p2p_node: &Arc<P2PNode>,
    storage: &Arc<ChunkStore>,
    config: &ReplicationConfig,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
    audit_challenge_coordinator: &Arc<AuditChallengeCoordinator>,
    shutdown: &CancellationToken,
) {
    let key_hex = hex::encode(key);

    // Read our canonical copy once: the audit digest is recomputed from these
    // bytes for every peer (hoisted out of the per-peer loop). If we no longer
    // hold the chunk we cannot verify any peer's proof, and we are no longer a
    // responsible checker for it — skip without penalising anyone.
    let local_bytes = match storage.get_raw(&key).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            debug!("Possession check: checker no longer holds {key_hex}; skipping");
            return;
        }
        Err(e) => {
            warn!("Possession check: failed to read local {key_hex}: {e}; skipping");
            return;
        }
    };

    // Single-key probe budget, matched to the audit response timeout's
    // bandwidth-calibrated deadline (tight enough that a relay that must refetch
    // the bytes blows it, generous for an honest local-disk read).
    let probe_timeout = possession_probe_response_timeout(config);

    for peer in peers {
        if shutdown.is_cancelled() {
            return;
        }
        match probe_once(
            &key,
            &local_bytes,
            &peer,
            p2p_node,
            audit_challenge_coordinator,
            probe_timeout,
        )
        .await
        {
            ProbeOutcome::Present => {
                debug!("Possession check: {peer} proved possession of {key_hex}");
                clear_possession_bootstrap_claim(&peer, sync_state).await;
            }
            ProbeOutcome::Failed(reason) => {
                clear_possession_bootstrap_claim(&peer, sync_state).await;
                report_possession_confirmed_failure(&peer, &key_hex, reason, p2p_node).await;
            }
            ProbeOutcome::NoResponse(class) => {
                audit_metrics::record_audit_no_response(AuditType::Possession, class);
                report_possession_audit_failure(&peer, &key_hex, class, p2p_node).await;
            }
            ProbeOutcome::BootstrapClaim => {
                handle_possession_bootstrap_claim(&peer, &key_hex, p2p_node, config, sync_state)
                    .await;
            }
            ProbeOutcome::Inconclusive => {
                debug!(
                    "Possession check: inconclusive probe of {peer} for {key_hex}; not penalised"
                );
            }
        }
    }
}

async fn clear_possession_bootstrap_claim(
    peer: &PeerId,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
) {
    sync_state.write().await.clear_active_bootstrap_claim(peer);
}

async fn report_possession_confirmed_failure(
    peer: &PeerId,
    key_hex: &str,
    failure_reason: PossessionFailureReason,
    p2p_node: &Arc<P2PNode>,
) {
    warn!(
        audit_type = AuditType::Possession.as_str(),
        audit_failure_class = "confirmed",
        possession_failure_reason = failure_reason.as_str(),
        peer = %peer,
        key = %key_hex,
        trust_weight = AUDIT_FAILURE_TRUST_WEIGHT,
        "Possession check: {peer} failed to prove possession for {key_hex} ({}); recorded at audit severity",
        failure_reason.as_str()
    );
    crate::replication::config::penalise_unheld_close_group_chunk(
        p2p_node,
        peer,
        AuditType::Possession.as_str(),
        AUDIT_FAILURE_TRUST_WEIGHT,
    )
    .await;
}

async fn report_possession_audit_failure(
    peer: &PeerId,
    key_hex: &str,
    failure_class: AuditFailureClass,
    p2p_node: &Arc<P2PNode>,
) {
    warn!(
        audit_type = AuditType::Possession.as_str(),
        audit_failure_class = failure_class.as_str(),
        peer = %peer,
        key = %key_hex,
        trust_weight = AUDIT_FAILURE_TRUST_WEIGHT,
        "Possession check: {peer} {} for {key_hex}; recorded at audit severity",
        failure_class.as_str()
    );
    crate::replication::config::penalise_unheld_close_group_chunk(
        p2p_node,
        peer,
        AuditType::Possession.as_str(),
        AUDIT_FAILURE_TRUST_WEIGHT,
    )
    .await;
}

async fn handle_possession_bootstrap_claim(
    peer: &PeerId,
    key_hex: &str,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    sync_state: &Arc<RwLock<NeighborSyncState>>,
) {
    let (now, observation) = {
        let now = Instant::now();
        let mut state = sync_state.write().await;
        (
            now,
            state.observe_bootstrap_claim(*peer, now, config.bootstrap_claim_grace_period),
        )
    };

    match observation {
        BootstrapClaimObservation::WithinGrace { .. } => {
            debug!(
                "Possession check: peer {peer} claims bootstrapping for {key_hex} \
                 (within grace period)"
            );
        }
        BootstrapClaimObservation::PastGrace { first_seen } => {
            warn!(
                "Possession check: peer {peer} claiming bootstrap for {key_hex} past grace period \
                 ({:?} > {:?}), reporting abuse",
                now.duration_since(first_seen),
                config.bootstrap_claim_grace_period,
            );
            p2p_node
                .report_trust_event(
                    peer,
                    TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                )
                .await;
        }
        BootstrapClaimObservation::Repeated { first_seen } => {
            warn!(
                "Possession check: peer {peer} repeated bootstrap claim for {key_hex} after \
                 previously stopping; first claim was {:?} ago, reporting abuse",
                now.duration_since(first_seen),
            );
            p2p_node
                .report_trust_event(
                    peer,
                    TrustEvent::ApplicationFailure(REPLICATION_TRUST_WEIGHT),
                )
                .await;
        }
    }
}

/// Send one single-key cryptographic [`AuditChallenge`] and interpret the
/// response. The peer proves possession by returning
/// `compute_audit_digest(nonce, peer, key, bytes)`; absence is proven by the
/// [`ABSENT_KEY_DIGEST`] sentinel or any digest that does not match the
/// checker's canonical copy. A transport failure / deadline is a `Timeout`; a
/// matching bootstrap response is a `BootstrapClaim`; a local encode failure is
/// `Inconclusive`; peer-side malformed, rejected, or mismatched replies are
/// `Failed`.
#[allow(clippy::too_many_lines)]
async fn probe_once(
    key: &XorName,
    local_bytes: &[u8],
    peer: &PeerId,
    p2p_node: &Arc<P2PNode>,
    audit_challenge_coordinator: &Arc<AuditChallengeCoordinator>,
    probe_timeout: Duration,
) -> ProbeOutcome {
    // Fresh nonce per probe so a stored digest cannot be replayed, and bind the
    // challenge to this peer's identity so it cannot relay another node's proof.
    let (nonce, challenge_id) = {
        let mut rng = rand::thread_rng();
        let nonce: [u8; 32] = rng.gen();
        let challenge_id: u64 = rng.gen();
        (nonce, challenge_id)
    };
    let challenge = AuditChallenge {
        challenge_id,
        nonce,
        challenged_peer_id: *peer.as_bytes(),
        keys: vec![*key],
    };
    let msg = ReplicationMessage {
        request_id: challenge_id,
        body: ReplicationMessageBody::AuditChallenge(challenge),
    };
    let Ok(encoded) = msg.encode() else {
        warn!(
            "Failed to encode possession challenge for {}",
            hex::encode(key)
        );
        return ProbeOutcome::Inconclusive;
    };

    let Some(_slot) = audit_challenge_coordinator.acquire(*peer).await else {
        warn!("Failed to acquire possession audit coordinator slot for {peer}");
        return ProbeOutcome::Inconclusive;
    };
    info!(
        target: "ant_node::replication::audit_requester",
        event = "started",
        audit_origin = AuditType::Possession.as_str(),
        audit_round = "digest",
        challenged_peer = %peer,
        challenge_id,
        work_items = 1,
        timeout_ms = probe_timeout.as_millis(),
        "Outbound audit request started"
    );
    let request_started = Instant::now();
    let response = match p2p_node
        .send_request(peer, REPLICATION_PROTOCOL_ID, encoded, probe_timeout)
        .await
    {
        Ok(response) => {
            info!(
                target: "ant_node::replication::audit_requester",
                event = "completed",
                audit_origin = AuditType::Possession.as_str(),
                audit_round = "digest",
                challenged_peer = %peer,
                challenge_id,
                work_items = 1,
                elapsed_ms = request_started.elapsed().as_millis(),
                outcome = "response",
                "Outbound audit request completed"
            );
            response
        }
        Err(e) => {
            let error = e.to_string();
            let (send_error_class, audit_failure_class) =
                audit_metrics::classify_audit_send_error(&error);
            warn!(
                target: "ant_node::replication::audit_requester",
                event = "completed",
                audit_origin = AuditType::Possession.as_str(),
                audit_round = "digest",
                challenged_peer = %peer,
                challenge_id,
                work_items = 1,
                elapsed_ms = request_started.elapsed().as_millis(),
                outcome = "no_response",
                audit_type = AuditType::Possession.as_str(),
                audit_failure_class = audit_failure_class.as_str(),
                send_error_class,
                "Possession probe to {peer} got no response: {e}"
            );
            return ProbeOutcome::NoResponse(audit_failure_class);
        }
    };

    let decoded = match ReplicationMessage::decode(&response.data) {
        Ok(decoded) => decoded,
        Err(e) => {
            debug!("Failed to decode possession response from {peer}: {e}");
            return ProbeOutcome::Failed(PossessionFailureReason::ResponseDecode);
        }
    };

    let ReplicationMessageBody::AuditResponse(resp) = decoded.body else {
        debug!("Unexpected possession response type from {peer}");
        return ProbeOutcome::Failed(PossessionFailureReason::UnexpectedResponseType);
    };

    interpret_audit_response(
        key,
        local_bytes,
        peer.as_bytes(),
        &nonce,
        challenge_id,
        resp,
    )
}

/// Classify an [`AuditResponse`] into a possession verdict. Pure (no I/O): the
/// digest is verified against `local_bytes`, the checker's canonical copy.
fn interpret_audit_response(
    key: &XorName,
    local_bytes: &[u8],
    challenged_peer_id: &[u8; 32],
    nonce: &[u8; 32],
    challenge_id: u64,
    response: AuditResponse,
) -> ProbeOutcome {
    match response {
        AuditResponse::Digests {
            challenge_id: resp_id,
            digests,
        } => {
            if resp_id != challenge_id {
                return ProbeOutcome::Failed(PossessionFailureReason::DigestChallengeIdMismatch);
            }
            if digests.len() != 1 {
                return ProbeOutcome::Failed(PossessionFailureReason::DigestCountMismatch);
            }
            let received = digests[0];
            if received == ABSENT_KEY_DIGEST {
                return ProbeOutcome::Failed(PossessionFailureReason::AbsentKey);
            }
            let expected = compute_audit_digest(nonce, challenged_peer_id, key, local_bytes);
            if received == expected {
                ProbeOutcome::Present
            } else {
                // A non-sentinel digest that does not match our canonical bytes
                // proves the peer cannot reproduce the content — treat as absent
                // (matches the audit's DigestMismatch handling).
                ProbeOutcome::Failed(PossessionFailureReason::DigestMismatch)
            }
        }
        AuditResponse::Bootstrapping {
            challenge_id: resp_id,
        } => {
            if resp_id == challenge_id {
                ProbeOutcome::BootstrapClaim
            } else {
                ProbeOutcome::Failed(PossessionFailureReason::BootstrapChallengeIdMismatch)
            }
        }
        AuditResponse::Rejected { .. } => ProbeOutcome::Failed(PossessionFailureReason::Rejected),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replication::config::{POSSESSION_CHECK_DELAY_MAX, POSSESSION_CHECK_DELAY_MIN};

    const PEER_ID: [u8; 32] = [0x42; 32];
    const NONCE: [u8; 32] = [0x7a; 32];
    const CHALLENGE_ID: u64 = 0xDEAD_BEEF;
    const KEY: XorName = [0x11; 32];
    const BYTES: &[u8] = b"possession-check payload";

    fn digests_response(challenge_id: u64, digests: Vec<[u8; 32]>) -> AuditResponse {
        AuditResponse::Digests {
            challenge_id,
            digests,
        }
    }

    #[test]
    fn possession_failure_reasons_have_stable_log_labels() {
        let cases = [
            (PossessionFailureReason::ResponseDecode, "response_decode"),
            (
                PossessionFailureReason::UnexpectedResponseType,
                "unexpected_response_type",
            ),
            (
                PossessionFailureReason::DigestChallengeIdMismatch,
                "digest_challenge_id_mismatch",
            ),
            (
                PossessionFailureReason::DigestCountMismatch,
                "digest_count_mismatch",
            ),
            (PossessionFailureReason::AbsentKey, "absent_key"),
            (PossessionFailureReason::DigestMismatch, "digest_mismatch"),
            (
                PossessionFailureReason::BootstrapChallengeIdMismatch,
                "bootstrap_challenge_id_mismatch",
            ),
            (PossessionFailureReason::Rejected, "rejected"),
        ];

        for (reason, expected) in cases {
            assert_eq!(reason.as_str(), expected);
        }
    }

    #[test]
    fn random_delay_is_within_bounds() {
        for _ in 0..100 {
            let d = random_delay(POSSESSION_CHECK_DELAY_MIN, POSSESSION_CHECK_DELAY_MAX);
            assert!(d >= POSSESSION_CHECK_DELAY_MIN);
            assert!(d <= POSSESSION_CHECK_DELAY_MAX);
        }
    }

    #[test]
    fn matching_digest_is_present() {
        let valid = compute_audit_digest(&NONCE, &PEER_ID, &KEY, BYTES);
        let verdict = interpret_audit_response(
            &KEY,
            BYTES,
            &PEER_ID,
            &NONCE,
            CHALLENGE_ID,
            digests_response(CHALLENGE_ID, vec![valid]),
        );
        assert_eq!(verdict, ProbeOutcome::Present);
    }

    #[test]
    fn absent_sentinel_is_failed() {
        let verdict = interpret_audit_response(
            &KEY,
            BYTES,
            &PEER_ID,
            &NONCE,
            CHALLENGE_ID,
            digests_response(CHALLENGE_ID, vec![ABSENT_KEY_DIGEST]),
        );
        assert_eq!(
            verdict,
            ProbeOutcome::Failed(PossessionFailureReason::AbsentKey)
        );
    }

    #[test]
    fn forged_digest_is_failed() {
        // A peer that lacks the bytes cannot compute the right digest; whatever
        // non-sentinel value it sends must not match our canonical copy.
        let forged = [0x99; 32];
        let valid = compute_audit_digest(&NONCE, &PEER_ID, &KEY, BYTES);
        assert_ne!(forged, valid, "test fixture must use a wrong digest");
        let verdict = interpret_audit_response(
            &KEY,
            BYTES,
            &PEER_ID,
            &NONCE,
            CHALLENGE_ID,
            digests_response(CHALLENGE_ID, vec![forged]),
        );
        assert_eq!(
            verdict,
            ProbeOutcome::Failed(PossessionFailureReason::DigestMismatch)
        );
    }

    #[test]
    fn mismatched_challenge_id_is_failed() {
        let valid = compute_audit_digest(&NONCE, &PEER_ID, &KEY, BYTES);
        let verdict = interpret_audit_response(
            &KEY,
            BYTES,
            &PEER_ID,
            &NONCE,
            CHALLENGE_ID,
            digests_response(CHALLENGE_ID.wrapping_add(1), vec![valid]),
        );
        assert_eq!(
            verdict,
            ProbeOutcome::Failed(PossessionFailureReason::DigestChallengeIdMismatch)
        );
    }

    #[test]
    fn wrong_arity_is_failed() {
        let valid = compute_audit_digest(&NONCE, &PEER_ID, &KEY, BYTES);
        let verdict = interpret_audit_response(
            &KEY,
            BYTES,
            &PEER_ID,
            &NONCE,
            CHALLENGE_ID,
            digests_response(CHALLENGE_ID, vec![valid, ABSENT_KEY_DIGEST]),
        );
        assert_eq!(
            verdict,
            ProbeOutcome::Failed(PossessionFailureReason::DigestCountMismatch)
        );
    }

    #[test]
    fn bootstrapping_is_bootstrap_claim() {
        let verdict = interpret_audit_response(
            &KEY,
            BYTES,
            &PEER_ID,
            &NONCE,
            CHALLENGE_ID,
            AuditResponse::Bootstrapping {
                challenge_id: CHALLENGE_ID,
            },
        );
        assert_eq!(verdict, ProbeOutcome::BootstrapClaim);
    }

    #[test]
    fn bootstrapping_with_wrong_challenge_id_is_failed() {
        let verdict = interpret_audit_response(
            &KEY,
            BYTES,
            &PEER_ID,
            &NONCE,
            CHALLENGE_ID,
            AuditResponse::Bootstrapping {
                challenge_id: CHALLENGE_ID.wrapping_add(1),
            },
        );
        assert_eq!(
            verdict,
            ProbeOutcome::Failed(PossessionFailureReason::BootstrapChallengeIdMismatch)
        );
    }

    #[tokio::test]
    async fn possession_success_clears_active_bootstrap_claim_but_keeps_history() {
        let peer = PeerId::from_bytes(PEER_ID);
        let sync_state = Arc::new(RwLock::new(NeighborSyncState::new_cycle(Vec::new())));
        {
            let mut state = sync_state.write().await;
            let now = Instant::now();
            state.bootstrap_claims.insert(peer, now);
            state.bootstrap_claim_history.insert(peer, now);
        }

        clear_possession_bootstrap_claim(&peer, &sync_state).await;

        let state = sync_state.read().await;
        assert!(!state.bootstrap_claims.contains_key(&peer));
        assert!(state.bootstrap_claim_history.contains_key(&peer));
    }

    #[test]
    fn rejected_is_failed() {
        let verdict = interpret_audit_response(
            &KEY,
            BYTES,
            &PEER_ID,
            &NONCE,
            CHALLENGE_ID,
            AuditResponse::Rejected {
                challenge_id: CHALLENGE_ID,
                reason: "nope".to_string(),
            },
        );
        assert_eq!(
            verdict,
            ProbeOutcome::Failed(PossessionFailureReason::Rejected)
        );
    }
}
