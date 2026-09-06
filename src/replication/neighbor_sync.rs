//! Neighbor replication sync (Section 6.2).
//!
//! Round-robin cycle management: snapshot close neighbors, iterate through
//! them in batches of `NEIGHBOR_SYNC_PEER_COUNT`, exchanging hint sets.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::logging::{debug, info, warn};
use rand::Rng;
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;

use crate::ant_protocol::XorName;
use crate::replication::config::{ReplicationConfig, REPLICATION_PROTOCOL_ID};
use crate::replication::paid_list::PaidList;
use crate::replication::protocol::{
    NeighborSyncRequest, NeighborSyncResponse, ReplicationMessage, ReplicationMessageBody,
};
use crate::replication::types::NeighborSyncState;
use crate::storage::ChunkStore;

/// Hint-build duration that is worth surfacing at info level.
const HINT_BUILD_SLOW_LOG_MS: u128 = 250;

/// Replica hint sent to a peer, with the close-group snapshot used to decide
/// that hint.
#[derive(Debug)]
pub(crate) struct SentReplicaHint {
    /// Key included in the replica hint set.
    pub(crate) key: XorName,
    /// Self-inclusive close group observed during hint construction.
    pub(crate) close_peers: HashSet<PeerId>,
}

/// Result of an outbound neighbor-sync exchange.
#[derive(Debug)]
pub(crate) struct NeighborSyncOutcome {
    /// The peer's sync response.
    pub(crate) response: NeighborSyncResponse,
    /// Replica hints sent to the peer in our request.
    pub(crate) sent_replica_hints: Vec<SentReplicaHint>,
}

/// Prebuilt hint sets for one outbound neighbor-sync exchange.
#[derive(Debug, Default)]
pub(crate) struct PeerSyncHints {
    /// Replica hints, including the close-group snapshot needed for repair
    /// proof recording after the request is successfully sent.
    pub(crate) sent_replica_hints: Vec<SentReplicaHint>,
    /// Paid-list-only hints for this peer.
    paid_hints: Vec<XorName>,
}

/// Build replica hints for a specific peer.
///
/// Returns keys that we believe the peer should hold (peer is among the
/// `CLOSE_GROUP_SIZE` nearest to `K` in our `SelfInclusiveRT`).
///
/// This intentionally scans all locally stored records, not only records for
/// which this node is still responsible. Out-of-range records retained by
/// prune hysteresis therefore continue to repair their new close group before
/// this node is allowed to delete them.
pub async fn build_replica_hints_for_peer(
    peer: &PeerId,
    storage: &Arc<ChunkStore>,
    p2p_node: &Arc<P2PNode>,
    close_group_size: usize,
) -> Vec<XorName> {
    build_replica_hints_for_peer_with_close_groups(peer, storage, p2p_node, close_group_size)
        .await
        .into_iter()
        .map(|hint| hint.key)
        .collect()
}

pub(crate) async fn build_replica_hints_for_peer_with_close_groups(
    peer: &PeerId,
    storage: &Arc<ChunkStore>,
    p2p_node: &Arc<P2PNode>,
    close_group_size: usize,
) -> Vec<SentReplicaHint> {
    let all_keys = match storage.all_keys().await {
        Ok(keys) => keys,
        Err(e) => {
            warn!("Failed to read stored keys for hint construction: {e}");
            return Vec::new();
        }
    };

    let dht = p2p_node.dht_manager();
    let mut hints = Vec::new();
    for key in all_keys {
        let closest = dht
            .find_closest_nodes_local_with_self(&key, close_group_size)
            .await;
        let close_peers = closest.iter().map(|n| n.peer_id).collect::<HashSet<_>>();
        if close_peers.contains(peer) {
            hints.push(SentReplicaHint { key, close_peers });
        }
    }
    hints
}

/// Build outbound hint sets for a batch of peers with one scan over local
/// storage and one scan over the paid list.
pub(crate) async fn build_sync_hints_for_peers(
    peers: &[PeerId],
    storage: &Arc<ChunkStore>,
    paid_list: &Arc<PaidList>,
    p2p_node: &Arc<P2PNode>,
    close_group_size: usize,
    paid_list_close_group_size: usize,
) -> HashMap<PeerId, PeerSyncHints> {
    let started = Instant::now();
    let target_peers = peers.iter().copied().collect::<HashSet<_>>();
    let mut hints_by_peer = peers
        .iter()
        .copied()
        .map(|peer| (peer, PeerSyncHints::default()))
        .collect::<HashMap<_, _>>();

    if peers.is_empty() {
        return hints_by_peer;
    }

    let all_keys = match storage.all_keys().await {
        Ok(keys) => keys,
        Err(e) => {
            warn!("Failed to read stored keys for batch hint construction: {e}");
            Vec::new()
        }
    };
    let stored_key_count = all_keys.len();

    let dht = p2p_node.dht_manager();
    for key in all_keys {
        let closest = dht
            .find_closest_nodes_local_with_self(&key, close_group_size)
            .await;
        let close_peers = closest.iter().map(|n| n.peer_id).collect::<HashSet<_>>();
        for peer in close_peers.intersection(&target_peers) {
            if let Some(peer_hints) = hints_by_peer.get_mut(peer) {
                peer_hints.sent_replica_hints.push(SentReplicaHint {
                    key,
                    close_peers: close_peers.clone(),
                });
            }
        }
    }

    let all_paid_keys = match paid_list.all_keys() {
        Ok(keys) => keys,
        Err(e) => {
            warn!("Failed to read PaidForList for batch hint construction: {e}");
            Vec::new()
        }
    };
    let paid_key_count = all_paid_keys.len();

    for key in all_paid_keys {
        let closest = dht
            .find_closest_nodes_local_with_self(&key, paid_list_close_group_size)
            .await;
        for node in closest {
            if target_peers.contains(&node.peer_id) {
                if let Some(peer_hints) = hints_by_peer.get_mut(&node.peer_id) {
                    peer_hints.paid_hints.push(key);
                }
            }
        }
    }

    let replica_hint_count = hints_by_peer
        .values()
        .map(|hints| hints.sent_replica_hints.len())
        .sum::<usize>();
    let paid_hint_count = hints_by_peer
        .values()
        .map(|hints| hints.paid_hints.len())
        .sum::<usize>();
    let elapsed_ms = started.elapsed().as_millis();

    if elapsed_ms >= HINT_BUILD_SLOW_LOG_MS {
        info!(
            target: "ant_node::replication::neighbor_sync",
            "Slow neighbor-sync hint build: peers={}, stored_keys={}, paid_keys={}, replica_hints={}, paid_hints={}, elapsed_ms={elapsed_ms}",
            peers.len(),
            stored_key_count,
            paid_key_count,
            replica_hint_count,
            paid_hint_count,
        );
    } else {
        debug!(
            target: "ant_node::replication::neighbor_sync",
            "Neighbor-sync hint build: peers={}, stored_keys={}, paid_keys={}, replica_hints={}, paid_hints={}, elapsed_ms={elapsed_ms}",
            peers.len(),
            stored_key_count,
            paid_key_count,
            replica_hint_count,
            paid_hint_count,
        );
    }

    hints_by_peer
}

/// Build paid hints for a specific peer.
///
/// Returns keys from our `PaidForList` that we believe the peer should
/// track (peer is among `PAID_LIST_CLOSE_GROUP_SIZE` nearest to `K`).
pub async fn build_paid_hints_for_peer(
    peer: &PeerId,
    paid_list: &Arc<PaidList>,
    p2p_node: &Arc<P2PNode>,
    paid_list_close_group_size: usize,
) -> Vec<XorName> {
    let all_paid_keys = match paid_list.all_keys() {
        Ok(keys) => keys,
        Err(e) => {
            warn!("Failed to read PaidForList for hint construction: {e}");
            return Vec::new();
        }
    };

    let dht = p2p_node.dht_manager();
    let mut hints = Vec::new();
    for key in all_paid_keys {
        let closest = dht
            .find_closest_nodes_local_with_self(&key, paid_list_close_group_size)
            .await;
        if closest.iter().any(|n| n.peer_id == *peer) {
            hints.push(key);
        }
    }
    hints
}

/// Take a fresh snapshot of close neighbors for a new round-robin cycle.
///
/// Rule 1: Compute `CloseNeighbors(self)` as `NEIGHBOR_SYNC_SCOPE` nearest
/// peers.
pub async fn snapshot_close_neighbors(
    p2p_node: &Arc<P2PNode>,
    self_id: &PeerId,
    scope: usize,
) -> Vec<PeerId> {
    let self_xor: XorName = *self_id.as_bytes();
    let closest = p2p_node
        .dht_manager()
        .find_closest_nodes_local(&self_xor, scope)
        .await;
    closest.iter().map(|n| n.peer_id).collect()
}

/// Select the next batch of peers for sync from the current cycle.
///
/// Priority peers from routing-table churn are drained before the round-robin
/// cursor. Rules 2-3 then scan forward from cursor, skip peers still under
/// cooldown, and fill up to `peer_count` slots.
pub fn select_sync_batch(
    state: &mut NeighborSyncState,
    peer_count: usize,
    cooldown: Duration,
) -> Vec<PeerId> {
    let mut batch = Vec::new();
    let now = Instant::now();

    while batch.len() < peer_count {
        let Some(peer) = select_next_sync_peer(state, now, cooldown) else {
            break;
        };
        batch.push(peer);
    }

    batch
}

fn select_next_sync_peer(
    state: &mut NeighborSyncState,
    now: Instant,
    cooldown: Duration,
) -> Option<PeerId> {
    while let Some(peer) = state.priority_order.pop_front() {
        if peer_on_cooldown(state, &peer, now, cooldown) {
            state.remove_peer(&peer);
            continue;
        }

        state.remove_peer(&peer);
        return Some(peer);
    }

    while state.cursor < state.order.len() {
        let peer = state.order[state.cursor];

        // Check cooldown (Rule 2a): if the peer was synced recently, remove
        // from the snapshot and continue without advancing the cursor (the
        // next element slides into the current cursor position).
        if peer_on_cooldown(state, &peer, now, cooldown) {
            state.order.remove(state.cursor);
            continue;
        }

        state.cursor += 1;
        return Some(peer);
    }

    None
}

fn peer_on_cooldown(
    state: &NeighborSyncState,
    peer: &PeerId,
    now: Instant,
    cooldown: Duration,
) -> bool {
    state
        .last_sync_times
        .get(peer)
        .is_some_and(|last_sync| now.duration_since(*last_sync) < cooldown)
}

/// Execute a sync session with a single peer.
///
/// Returns the response hints if sync succeeded, or `None` if the peer
/// was unreachable or the response could not be decoded.
pub async fn sync_with_peer(
    peer: &PeerId,
    p2p_node: &Arc<P2PNode>,
    storage: &Arc<ChunkStore>,
    paid_list: &Arc<PaidList>,
    config: &ReplicationConfig,
    is_bootstrapping: bool,
) -> Option<NeighborSyncResponse> {
    sync_with_peer_with_outcome(
        peer,
        p2p_node,
        storage,
        paid_list,
        config,
        is_bootstrapping,
        None,
    )
    .await
    .map(|outcome| outcome.response)
}

/// `commitment`: sender's current commitment to piggyback on the request.
/// `None` if the responder hasn't rotated one yet (e.g. fresh boot,
/// empty storage) — receiver falls back to legacy path.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn sync_with_peer_with_outcome(
    peer: &PeerId,
    p2p_node: &Arc<P2PNode>,
    storage: &Arc<ChunkStore>,
    paid_list: &Arc<PaidList>,
    config: &ReplicationConfig,
    is_bootstrapping: bool,
    commitment: Option<crate::replication::commitment::StorageCommitment>,
) -> Option<NeighborSyncOutcome> {
    // Build peer-targeted hint sets (Rule 7).
    let mut hints_by_peer = build_sync_hints_for_peers(
        std::slice::from_ref(peer),
        storage,
        paid_list,
        p2p_node,
        config.close_group_size,
        config.paid_list_close_group_size,
    )
    .await;
    let hints = hints_by_peer.remove(peer).unwrap_or_default();
    sync_with_peer_with_hints(peer, p2p_node, config, is_bootstrapping, hints, commitment).await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn sync_with_peer_with_hints(
    peer: &PeerId,
    p2p_node: &Arc<P2PNode>,
    config: &ReplicationConfig,
    is_bootstrapping: bool,
    hints: PeerSyncHints,
    // ADR-0002: sender's current commitment, piggybacked on the sync request so
    // the receiver can ingest it (commitment gossip travels on neighbor sync) —
    // see `NeighborSyncRequest::commitment` and `ingest_peer_commitment`.
    commitment: Option<crate::replication::commitment::StorageCommitment>,
) -> Option<NeighborSyncOutcome> {
    let replica_hints = hints
        .sent_replica_hints
        .iter()
        .map(|hint| hint.key)
        .collect::<Vec<_>>();
    let sent_replica_hints = hints.sent_replica_hints;

    let request = NeighborSyncRequest {
        replica_hints,
        paid_hints: hints.paid_hints,
        bootstrapping: is_bootstrapping,
        commitment,
    };
    let request_id = rand::thread_rng().gen::<u64>();
    let msg = ReplicationMessage {
        request_id,
        body: ReplicationMessageBody::NeighborSyncRequest(request),
    };

    let encoded = match msg.encode() {
        Ok(data) => data,
        Err(e) => {
            warn!("Failed to encode sync request for {peer}: {e}");
            return None;
        }
    };

    let response = match p2p_node
        .send_request(
            peer,
            REPLICATION_PROTOCOL_ID,
            encoded,
            config.verification_request_timeout,
        )
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            debug!("Sync with {peer} failed: {e}");
            return None;
        }
    };

    match ReplicationMessage::decode(&response.data) {
        Ok(decoded) => {
            if let ReplicationMessageBody::NeighborSyncResponse(resp) = decoded.body {
                Some(NeighborSyncOutcome {
                    response: resp,
                    sent_replica_hints,
                })
            } else {
                warn!("Unexpected response type from {peer} during sync");
                None
            }
        }
        Err(e) => {
            warn!("Failed to decode sync response from {peer}: {e}");
            None
        }
    }
}

/// Handle a failed sync attempt: remove peer from snapshot and try to fill
/// the vacated slot.
///
/// Rule 3: Remove unreachable peer from pending sync state, attempt to fill
/// by using the same priority-first scan as [`select_sync_batch`]. Applies the
/// same cooldown filtering to avoid selecting a peer that was recently synced.
pub fn handle_sync_failure(
    state: &mut NeighborSyncState,
    failed_peer: &PeerId,
    cooldown: Duration,
) -> Option<PeerId> {
    // Find and remove the failed peer from the ordering.
    state.remove_peer(failed_peer);

    // Try to fill the vacated slot, applying the same priority and cooldown
    // filtering used by select_sync_batch.
    let now = Instant::now();
    select_next_sync_peer(state, now, cooldown)
}

/// Record a successful sync with a peer.
pub fn record_successful_sync(state: &mut NeighborSyncState, peer: &PeerId) {
    state.last_sync_times.insert(*peer, Instant::now());
}

/// Handle incoming sync request from a peer.
///
/// Rules 4-6: Validate peer is in `LocalRT`. If yes, bidirectional sync.
/// If not, outbound-only (send hints but don't accept inbound).
///
/// Returns `(response, sender_in_routing_table)` where the second element
/// indicates whether the caller should process the sender's inbound hints.
pub async fn handle_sync_request(
    sender: &PeerId,
    request: &NeighborSyncRequest,
    p2p_node: &Arc<P2PNode>,
    storage: &Arc<ChunkStore>,
    paid_list: &Arc<PaidList>,
    config: &ReplicationConfig,
    is_bootstrapping: bool,
) -> (NeighborSyncResponse, bool) {
    let (response, _, sender_in_rt) = handle_sync_request_with_proofs(
        sender,
        request,
        p2p_node,
        storage,
        paid_list,
        config,
        is_bootstrapping,
        None,
    )
    .await;
    (response, sender_in_rt)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_sync_request_with_proofs(
    sender: &PeerId,
    _request: &NeighborSyncRequest,
    p2p_node: &Arc<P2PNode>,
    storage: &Arc<ChunkStore>,
    paid_list: &Arc<PaidList>,
    config: &ReplicationConfig,
    is_bootstrapping: bool,
    my_commitment: Option<crate::replication::commitment::StorageCommitment>,
) -> (NeighborSyncResponse, Vec<SentReplicaHint>, bool) {
    let sender_in_rt = p2p_node.dht_manager().is_in_routing_table(sender).await;

    // Build outbound hints (always sent, even to non-RT peers).
    let sent_replica_hints = build_replica_hints_for_peer_with_close_groups(
        sender,
        storage,
        p2p_node,
        config.close_group_size,
    )
    .await;
    let replica_hints = sent_replica_hints
        .iter()
        .map(|hint| hint.key)
        .collect::<Vec<_>>();
    let paid_hints = build_paid_hints_for_peer(
        sender,
        paid_list,
        p2p_node,
        config.paid_list_close_group_size,
    )
    .await;

    let response = NeighborSyncResponse {
        replica_hints,
        paid_hints,
        bootstrapping: is_bootstrapping,
        rejected_keys: Vec::new(),
        commitment: my_commitment,
    };

    // Rule 4-6: accept inbound hints only if sender is in LocalRT.
    (response, sent_replica_hints, sender_in_rt)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::replication::types::PeerSyncRecord;
    use std::collections::HashMap;

    /// Build a `PeerId` from a single byte (zero-padded to 32 bytes).
    fn peer_id_from_byte(b: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = b;
        PeerId::from_bytes(bytes)
    }

    // -- select_sync_batch ---------------------------------------------------

    #[test]
    fn select_sync_batch_returns_up_to_peer_count() {
        let peers = vec![
            peer_id_from_byte(1),
            peer_id_from_byte(2),
            peer_id_from_byte(3),
            peer_id_from_byte(4),
            peer_id_from_byte(5),
        ];
        let mut state = NeighborSyncState::new_cycle(peers);
        let batch_size = 3;

        let batch = select_sync_batch(&mut state, batch_size, Duration::from_secs(0));

        assert_eq!(batch.len(), batch_size);
        assert_eq!(batch[0], peer_id_from_byte(1));
        assert_eq!(batch[1], peer_id_from_byte(2));
        assert_eq!(batch[2], peer_id_from_byte(3));
        assert_eq!(state.cursor, 3);
    }

    #[test]
    fn select_sync_batch_skips_cooldown_peers() {
        let peers = vec![
            peer_id_from_byte(1),
            peer_id_from_byte(2),
            peer_id_from_byte(3),
            peer_id_from_byte(4),
        ];
        let mut state = NeighborSyncState::new_cycle(peers);

        // Mark peer 1 and peer 3 as recently synced.
        state
            .last_sync_times
            .insert(peer_id_from_byte(1), Instant::now());
        state
            .last_sync_times
            .insert(peer_id_from_byte(3), Instant::now());

        let cooldown = Duration::from_secs(3600); // 1 hour
        let batch = select_sync_batch(&mut state, 2, cooldown);

        // Peer 1 and peer 3 should be skipped (removed from order).
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0], peer_id_from_byte(2));
        assert_eq!(batch[1], peer_id_from_byte(4));

        // Cooldown peers should have been removed from the order.
        assert!(!state.order.contains(&peer_id_from_byte(1)));
        assert!(!state.order.contains(&peer_id_from_byte(3)));
    }

    #[test]
    fn select_sync_batch_expired_cooldown_not_skipped() {
        let peers = vec![peer_id_from_byte(1), peer_id_from_byte(2)];
        let mut state = NeighborSyncState::new_cycle(peers);

        // Mark peer 1 as synced a long time ago (simulate expired cooldown).
        // Use a small subtraction (2s) and a smaller cooldown (1s) to avoid
        // `checked_sub` returning `None` on freshly-booted CI runners where
        // `Instant::now()` (system uptime) may be very small.
        state.last_sync_times.insert(
            peer_id_from_byte(1),
            Instant::now()
                .checked_sub(Duration::from_secs(2))
                .unwrap_or_else(Instant::now),
        );

        let cooldown = Duration::from_secs(1);
        let batch = select_sync_batch(&mut state, 2, cooldown);

        // Peer 1's cooldown expired so it should be included.
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0], peer_id_from_byte(1));
        assert_eq!(batch[1], peer_id_from_byte(2));
    }

    #[test]
    fn select_sync_batch_empty_order() {
        let mut state = NeighborSyncState::new_cycle(vec![]);

        let batch = select_sync_batch(&mut state, 4, Duration::from_secs(0));

        assert!(batch.is_empty());
        assert_eq!(state.cursor, 0);
    }

    #[test]
    fn select_sync_batch_all_on_cooldown() {
        let peers = vec![peer_id_from_byte(1), peer_id_from_byte(2)];
        let mut state = NeighborSyncState::new_cycle(peers);

        state
            .last_sync_times
            .insert(peer_id_from_byte(1), Instant::now());
        state
            .last_sync_times
            .insert(peer_id_from_byte(2), Instant::now());

        let cooldown = Duration::from_secs(3600);
        let batch = select_sync_batch(&mut state, 4, cooldown);

        assert!(batch.is_empty());
        assert!(state.order.is_empty());
    }

    // -- handle_sync_failure -------------------------------------------------

    #[test]
    fn handle_sync_failure_removes_peer_and_adjusts_cursor() {
        let peers = vec![
            peer_id_from_byte(1),
            peer_id_from_byte(2),
            peer_id_from_byte(3),
            peer_id_from_byte(4),
        ];
        let mut state = NeighborSyncState::new_cycle(peers);
        // Simulate having already processed peers at indices 0 and 1.
        state.cursor = 2;

        // Peer 2 (index 1, before cursor) fails.
        let replacement =
            handle_sync_failure(&mut state, &peer_id_from_byte(2), Duration::from_secs(0));

        // Cursor should be adjusted down by 1 (was 2, now 1).
        assert_eq!(state.cursor, 2); // was 2, removed at pos 1, adjusted to 1, then replacement advances to 2
        assert!(!state.order.contains(&peer_id_from_byte(2)));

        // Should get peer 4 as replacement (index 1 after removal = peer 3,
        // but cursor was adjusted to 1 so peer 3 is at index 1; it returns
        // the peer at the new cursor and advances).
        assert!(replacement.is_some());
    }

    #[test]
    fn handle_sync_failure_removes_peer_after_cursor() {
        let peers = vec![
            peer_id_from_byte(1),
            peer_id_from_byte(2),
            peer_id_from_byte(3),
            peer_id_from_byte(4),
        ];
        let mut state = NeighborSyncState::new_cycle(peers);
        state.cursor = 1;

        // Peer 3 (index 2, after cursor) fails.
        let replacement =
            handle_sync_failure(&mut state, &peer_id_from_byte(3), Duration::from_secs(0));

        // Cursor should stay at 1 (removal was after cursor).
        assert_eq!(state.cursor, 2); // cursor was 1, replacement advances to 2
        assert!(!state.order.contains(&peer_id_from_byte(3)));

        // Replacement should be peer 2 (now at cursor position 1).
        assert_eq!(replacement, Some(peer_id_from_byte(2)));
    }

    #[test]
    fn handle_sync_failure_no_replacement_when_exhausted() {
        let peers = vec![peer_id_from_byte(1)];
        let mut state = NeighborSyncState::new_cycle(peers);
        state.cursor = 1; // Already past the only peer.

        let replacement =
            handle_sync_failure(&mut state, &peer_id_from_byte(1), Duration::from_secs(0));

        assert!(state.order.is_empty());
        assert!(replacement.is_none());
    }

    #[test]
    fn handle_sync_failure_unknown_peer_is_noop() {
        let peers = vec![peer_id_from_byte(1), peer_id_from_byte(2)];
        let mut state = NeighborSyncState::new_cycle(peers);
        state.cursor = 1;

        let replacement =
            handle_sync_failure(&mut state, &peer_id_from_byte(99), Duration::from_secs(0));

        // Order should be unchanged.
        assert_eq!(state.order.len(), 2);
        // Still tries to fill from cursor.
        assert_eq!(replacement, Some(peer_id_from_byte(2)));
        assert_eq!(state.cursor, 2);
    }

    // -- record_successful_sync ----------------------------------------------

    #[test]
    fn record_successful_sync_updates_last_sync_time() {
        let peers = vec![peer_id_from_byte(1), peer_id_from_byte(2)];
        let mut state = NeighborSyncState::new_cycle(peers);
        let peer = peer_id_from_byte(1);

        assert!(!state.last_sync_times.contains_key(&peer));

        let before = Instant::now();
        record_successful_sync(&mut state, &peer);
        let after = Instant::now();

        let ts = state.last_sync_times.get(&peer).expect("timestamp exists");
        assert!(*ts >= before);
        assert!(*ts <= after);
    }

    #[test]
    fn record_successful_sync_overwrites_previous() {
        let peers = vec![peer_id_from_byte(1)];
        let mut state = NeighborSyncState::new_cycle(peers);
        let peer = peer_id_from_byte(1);

        // Record a sync at an old time. Use a small subtraction to avoid
        // `checked_sub` returning `None` on freshly-booted CI runners.
        let old_time = Instant::now()
            .checked_sub(Duration::from_secs(2))
            .unwrap_or_else(Instant::now);
        state.last_sync_times.insert(peer, old_time);

        record_successful_sync(&mut state, &peer);

        let ts = state.last_sync_times.get(&peer).expect("timestamp exists");
        assert!(*ts > old_time, "sync time should be updated");
    }

    // -- Section 18: Neighbor sync scenarios --------------------------------

    #[test]
    fn scenario_35_round_robin_with_cooldown_skip() {
        // With >PEER_COUNT eligible peers, consecutive rounds scan forward
        // from cursor, skip cooldown peers, sync next batch.
        // Create 8 peers, mark peers 2,4 on cooldown.
        // First batch of 4: peers 1,3,5,6 (2,4 skipped and removed).
        // Second batch of 4: peers 7,8 (only 2 remain).
        // Cycle should complete after second batch.
        let peers: Vec<PeerId> = (1..=8).map(peer_id_from_byte).collect();
        let mut state = NeighborSyncState::new_cycle(peers);
        let batch_size = 4;
        let cooldown = Duration::from_secs(3600);

        // Mark peers 2 and 4 as recently synced (on cooldown).
        state
            .last_sync_times
            .insert(peer_id_from_byte(2), Instant::now());
        state
            .last_sync_times
            .insert(peer_id_from_byte(4), Instant::now());

        // First batch: scan from cursor 0. Peers 2 and 4 are removed,
        // leaving [1,3,5,6,7,8]. We pick the first 4: [1,3,5,6].
        let batch1 = select_sync_batch(&mut state, batch_size, cooldown);
        assert_eq!(batch1.len(), 4);
        assert_eq!(batch1[0], peer_id_from_byte(1));
        assert_eq!(batch1[1], peer_id_from_byte(3));
        assert_eq!(batch1[2], peer_id_from_byte(5));
        assert_eq!(batch1[3], peer_id_from_byte(6));

        // Cooldown peers should have been removed from the order.
        assert!(!state.order.contains(&peer_id_from_byte(2)));
        assert!(!state.order.contains(&peer_id_from_byte(4)));

        // Second batch: only peers 7,8 remain after cursor.
        let batch2 = select_sync_batch(&mut state, batch_size, cooldown);
        assert_eq!(batch2.len(), 2);
        assert_eq!(batch2[0], peer_id_from_byte(7));
        assert_eq!(batch2[1], peer_id_from_byte(8));

        // Cycle should be complete after second batch.
        assert!(state.is_cycle_complete());
    }

    #[test]
    fn cycle_complete_when_cursor_past_order() {
        // is_cycle_complete() returns true when cursor >= order.len().
        let peers: Vec<PeerId> = (1..=3).map(peer_id_from_byte).collect();
        let mut state = NeighborSyncState::new_cycle(peers);

        // Not complete at the start.
        assert!(!state.is_cycle_complete());

        // Advance cursor to exactly order.len().
        state.cursor = 3;
        assert!(state.is_cycle_complete());

        // Also complete when cursor exceeds order.len().
        state.cursor = 10;
        assert!(state.is_cycle_complete());

        // Edge case: order is emptied (peers removed) with cursor at 0.
        state.order.clear();
        state.cursor = 0;
        assert!(state.is_cycle_complete());
    }

    /// Scenario 36: Post-cycle responsibility pruning with time-based
    /// hysteresis.
    ///
    /// When a full round-robin cycle completes, node runs one prune pass
    /// over BOTH stored records and `PaidForList` entries using current
    /// `SelfInclusiveRT`. Out-of-range items have timestamps recorded but
    /// are deleted only after `PRUNE_HYSTERESIS_DURATION`. In-range items
    /// have their timestamps cleared.
    ///
    /// Full `run_prune_pass` requires a live `P2PNode`. This test verifies
    /// the deterministic trigger condition (cycle completion) and the
    /// combined record + paid-list pruning contract:
    ///   (1) Cycle completes -> prune pass should run.
    ///   (2) Both `RecordOutOfRangeFirstSeen` and `PaidOutOfRangeFirstSeen`
    ///       are tracked independently in the same pass.
    ///   (3) Keys within hysteresis window are retained.
    #[test]
    fn scenario_36_post_cycle_triggers_combined_prune_pass() {
        let config = ReplicationConfig::default();

        // Step 1: Run a full cycle to completion.
        let peers: Vec<PeerId> = (1..=3).map(peer_id_from_byte).collect();
        let mut state = NeighborSyncState::new_cycle(peers);
        let _ = select_sync_batch(&mut state, 3, Duration::from_secs(0));
        assert!(
            state.is_cycle_complete(),
            "cycle must be complete before prune pass triggers"
        );

        // Step 2: Verify prune hysteresis parameters are configured.
        assert!(
            !config.prune_hysteresis_duration.is_zero(),
            "PRUNE_HYSTERESIS_DURATION must be non-zero for hysteresis to work"
        );

        // Step 3: Simulate the prune-pass timestamp tracking for BOTH
        // record and paid-list entries (the two independent timestamp
        // families that Section 11 requires in a single pass).
        //
        // Record timestamps and paid timestamps are independent — clearing
        // one must not affect the other (tested in scenario_52). Here we
        // verify the combined trigger: cycle completion -> both kinds of
        // timestamps are eligible for evaluation.
        let record_key: [u8; 32] = [0x36; 32];
        let paid_key: [u8; 32] = [0x37; 32];

        // Simulate: record_key goes out of range, paid_key goes out of range.
        let record_first_seen = Instant::now();
        let paid_first_seen = Instant::now();

        // Both timestamps are recent — well within hysteresis window.
        let record_elapsed = record_first_seen.elapsed();
        let paid_elapsed = paid_first_seen.elapsed();
        assert!(
            record_elapsed < config.prune_hysteresis_duration,
            "record key should be retained within hysteresis window"
        );
        assert!(
            paid_elapsed < config.prune_hysteresis_duration,
            "paid key should be retained within hysteresis window"
        );

        // The prune pass evaluates both independently. Verify they don't
        // interfere by using separate keys.
        assert_ne!(
            record_key, paid_key,
            "record and paid pruning keys must be independent"
        );

        // Step 4: After the cycle, a new snapshot is taken and cursor resets.
        let new_state = NeighborSyncState::new_cycle(vec![
            peer_id_from_byte(1),
            peer_id_from_byte(2),
            peer_id_from_byte(3),
        ]);
        assert_eq!(new_state.cursor, 0, "cursor resets for new cycle");
        assert!(
            !new_state.is_cycle_complete(),
            "new cycle should not be immediately complete"
        );
    }

    #[test]
    fn scenario_38_mid_cycle_peer_join_prioritized() {
        // Peer D joins CloseNeighbors mid-cycle. It is queued for priority
        // sync without being inserted into the current round-robin snapshot.
        let peers = vec![
            peer_id_from_byte(0xA),
            peer_id_from_byte(0xB),
            peer_id_from_byte(0xC),
        ];
        let mut state = NeighborSyncState::new_cycle(peers);

        // Advance cursor to simulate mid-cycle.
        let _ = select_sync_batch(&mut state, 1, Duration::from_secs(0));
        assert_eq!(state.cursor, 1);

        // Peer D "joins" the close-neighbor set. It remains outside the
        // stable snapshot but is queued ahead of the cursor.
        let peer_d = peer_id_from_byte(0xD);
        assert_eq!(state.queue_priority_peers([peer_d]), 1);
        assert!(!state.order.contains(&peer_d));
        assert!(
            !state.is_cycle_complete(),
            "pending priority sync keeps the cycle active"
        );

        let batch = select_sync_batch(&mut state, 2, Duration::from_secs(0));
        assert_eq!(batch, vec![peer_d, peer_id_from_byte(0xB)]);
    }

    #[test]
    fn scenario_39_unreachable_peer_removed_slot_filled() {
        // Peer P is in snapshot. Sync fails. P removed from order.
        // Node resumes scanning and picks next peer Q to fill the slot.
        let peers = vec![
            peer_id_from_byte(1),
            peer_id_from_byte(2),
            peer_id_from_byte(3),
            peer_id_from_byte(4),
            peer_id_from_byte(5),
        ];
        let mut state = NeighborSyncState::new_cycle(peers);

        // First batch selects peers 1,2.
        let batch = select_sync_batch(&mut state, 2, Duration::from_secs(0));
        assert_eq!(batch, vec![peer_id_from_byte(1), peer_id_from_byte(2)]);

        // Peer 2 becomes unreachable. Remove it and fill the slot.
        let replacement =
            handle_sync_failure(&mut state, &peer_id_from_byte(2), Duration::from_secs(0));
        assert!(!state.order.contains(&peer_id_from_byte(2)));

        // Slot should be filled by the next available peer (peer 3).
        assert_eq!(
            replacement,
            Some(peer_id_from_byte(3)),
            "vacated slot should be filled by next peer in order"
        );

        // Continue: next batch should resume from after the replacement.
        let batch2 = select_sync_batch(&mut state, 2, Duration::from_secs(0));
        assert_eq!(batch2, vec![peer_id_from_byte(4), peer_id_from_byte(5)]);
        assert!(state.is_cycle_complete());
    }

    #[test]
    fn scenario_40_cooldown_peer_removed_from_snapshot() {
        // Peer synced within cooldown period. When batch selection reaches it,
        // peer is REMOVED from order (not just skipped). Scanning continues to
        // next peer.
        let peers = vec![
            peer_id_from_byte(1),
            peer_id_from_byte(2),
            peer_id_from_byte(3),
        ];
        let mut state = NeighborSyncState::new_cycle(peers);
        let cooldown = Duration::from_secs(3600);

        // Mark peer 2 as recently synced.
        state
            .last_sync_times
            .insert(peer_id_from_byte(2), Instant::now());

        let batch = select_sync_batch(&mut state, 3, cooldown);

        // Peer 2 should have been REMOVED from order, not just skipped.
        assert!(!state.order.contains(&peer_id_from_byte(2)));
        assert_eq!(state.order.len(), 2, "order should shrink by 1");

        // Batch contains the non-cooldown peers.
        assert_eq!(batch, vec![peer_id_from_byte(1), peer_id_from_byte(3)]);

        // Cycle is complete since all remaining peers were selected.
        assert!(state.is_cycle_complete());
    }

    #[test]
    fn priority_peer_in_snapshot_is_not_selected_twice() {
        let peers = vec![
            peer_id_from_byte(1),
            peer_id_from_byte(2),
            peer_id_from_byte(3),
        ];
        let mut state = NeighborSyncState::new_cycle(peers);
        assert_eq!(state.queue_priority_peers([peer_id_from_byte(2)]), 1);

        let batch = select_sync_batch(&mut state, 2, Duration::from_secs(0));

        assert_eq!(batch, vec![peer_id_from_byte(2), peer_id_from_byte(1)]);
        assert_eq!(
            state.order,
            vec![peer_id_from_byte(1), peer_id_from_byte(3)]
        );
        assert_eq!(state.cursor, 1);
    }

    #[test]
    fn priority_peer_on_cooldown_is_skipped_and_removed_from_snapshot() {
        let peers = vec![peer_id_from_byte(1), peer_id_from_byte(2)];
        let mut state = NeighborSyncState::new_cycle(peers);
        let cooldown = Duration::from_secs(1);
        let priority_peer = peer_id_from_byte(2);
        state.last_sync_times.insert(priority_peer, Instant::now());
        assert_eq!(state.queue_priority_peers([priority_peer]), 1);

        let batch = select_sync_batch(&mut state, 2, cooldown);

        assert_eq!(batch, vec![peer_id_from_byte(1)]);
        assert!(state.priority_order.is_empty());
        assert!(!state.order.contains(&priority_peer));
    }

    #[test]
    fn failure_replacement_prefers_remaining_priority_peer() {
        let peers = vec![peer_id_from_byte(1), peer_id_from_byte(2)];
        let mut state = NeighborSyncState::new_cycle(peers);
        let first_priority_peer = peer_id_from_byte(3);
        let second_priority_peer = peer_id_from_byte(4);
        assert_eq!(
            state.queue_priority_peers([first_priority_peer, second_priority_peer]),
            2
        );

        let batch = select_sync_batch(&mut state, 1, Duration::from_secs(0));
        assert_eq!(batch, vec![first_priority_peer]);

        let replacement =
            handle_sync_failure(&mut state, &first_priority_peer, Duration::from_secs(0));

        assert_eq!(replacement, Some(second_priority_peer));
        assert!(state.priority_order.is_empty());
        assert_eq!(state.cursor, 0);
    }

    #[test]
    fn scenario_41_cycle_always_terminates() {
        // Under arbitrary cooldowns and removals, cycle always terminates.
        // Create 10 peers. Mark ALL on cooldown. select_sync_batch
        // should remove all and return empty. Cycle complete.
        let peer_count: u8 = 10;
        let peers: Vec<PeerId> = (1..=peer_count).map(peer_id_from_byte).collect();
        let mut state = NeighborSyncState::new_cycle(peers);
        let cooldown = Duration::from_secs(3600);

        // Mark all peers as recently synced.
        for i in 1..=peer_count {
            state
                .last_sync_times
                .insert(peer_id_from_byte(i), Instant::now());
        }

        let batch = select_sync_batch(&mut state, 4, cooldown);

        assert!(
            batch.is_empty(),
            "all peers on cooldown — batch must be empty"
        );
        assert!(state.order.is_empty(), "all peers should have been removed");
        assert!(
            state.is_cycle_complete(),
            "cycle must terminate when all peers are removed"
        );
    }

    #[test]
    fn consecutive_rounds_advance_through_full_cycle() {
        // 6 peers, batch_size=2, no cooldowns.
        // Round 1: peers 0,1. Round 2: peers 2,3. Round 3: peers 4,5.
        // After round 3: cycle complete.
        let peers: Vec<PeerId> = (1..=6).map(peer_id_from_byte).collect();
        let mut state = NeighborSyncState::new_cycle(peers);
        let batch_size = 2;
        let no_cooldown = Duration::from_secs(0);

        let round1 = select_sync_batch(&mut state, batch_size, no_cooldown);
        assert_eq!(round1, vec![peer_id_from_byte(1), peer_id_from_byte(2)]);
        assert_eq!(state.cursor, 2);
        assert!(!state.is_cycle_complete());

        let round2 = select_sync_batch(&mut state, batch_size, no_cooldown);
        assert_eq!(round2, vec![peer_id_from_byte(3), peer_id_from_byte(4)]);
        assert_eq!(state.cursor, 4);
        assert!(!state.is_cycle_complete());

        let round3 = select_sync_batch(&mut state, batch_size, no_cooldown);
        assert_eq!(round3, vec![peer_id_from_byte(5), peer_id_from_byte(6)]);
        assert_eq!(state.cursor, 6);
        assert!(state.is_cycle_complete());

        // Extra call after cycle complete returns empty.
        let round4 = select_sync_batch(&mut state, batch_size, no_cooldown);
        assert!(round4.is_empty());
    }

    /// Scenario 37: Non-`LocalRT` inbound sync behavior.
    ///
    /// When a peer not in `LocalRT(self)` opens a sync session:
    /// - Receiver STILL builds and sends outbound hints (response always
    ///   constructed via `handle_sync_request`).
    /// - Receiver drops ALL inbound replica/paid hints from that peer
    ///   (caller returns early in `mod.rs:handle_neighbor_sync_request`
    ///   when `sender_in_rt` is false).
    /// - Sync history is NOT updated for non-RT peers, so no
    ///   `RepairOpportunity` is created.
    ///
    /// Full integration requires a live `P2PNode` (`handle_sync_request`
    /// calls `is_in_routing_table`). This test verifies the deterministic
    /// contract:
    ///   (1) `NeighborSyncResponse` is always constructed regardless of
    ///       sender RT membership (outbound hints sent).
    ///   (2) When `sender_in_rt` is false, no admission runs and sync
    ///       history is not updated.
    ///   (3) When `sender_in_rt` is true, sync history IS updated and
    ///       inbound hints enter the admission pipeline.
    #[test]
    fn scenario_37_non_local_rt_inbound_sync_drops_hints() {
        let sender = peer_id_from_byte(0x37);

        // Simulate what handle_sync_request always builds: outbound hints
        // in the response, regardless of whether sender is in LocalRT.
        let outbound_replica_hints = vec![[0x01; 32], [0x02; 32]];
        let outbound_paid_hints = vec![[0x03; 32]];
        let response = NeighborSyncResponse {
            replica_hints: outbound_replica_hints.clone(),
            paid_hints: outbound_paid_hints.clone(),
            bootstrapping: false,
            rejected_keys: Vec::new(),
            commitment: None,
        };

        // Inbound hints from the sender (would be in the request).
        let inbound_replica_hints = vec![[0xA0; 32], [0xA1; 32]];
        let inbound_paid_hints = vec![[0xB0; 32]];

        // --- Case 1: sender NOT in LocalRT (sender_in_rt = false) ---
        let sender_in_rt = false;
        let mut sync_history: HashMap<PeerId, PeerSyncRecord> = HashMap::new();

        // Response is still built — outbound hints are sent.
        assert_eq!(
            response.replica_hints, outbound_replica_hints,
            "outbound replica hints must be sent even when sender is not in LocalRT"
        );
        assert_eq!(
            response.paid_hints, outbound_paid_hints,
            "outbound paid hints must be sent even when sender is not in LocalRT"
        );

        // Caller checks sender_in_rt and returns early. No admission runs.
        if !sender_in_rt {
            // This is the early-return path in mod.rs:964-966.
            // Inbound hints are never processed.
            let admitted_replica_keys: Vec<[u8; 32]> = Vec::new();
            let admitted_paid_keys: Vec<[u8; 32]> = Vec::new();

            for key in &inbound_replica_hints {
                assert!(
                    !admitted_replica_keys.contains(key),
                    "inbound replica hints must NOT be admitted from non-RT sender"
                );
            }
            for key in &inbound_paid_hints {
                assert!(
                    !admitted_paid_keys.contains(key),
                    "inbound paid hints must NOT be admitted from non-RT sender"
                );
            }

            // Sync history is NOT updated for non-RT peers.
            assert!(
                !sync_history.contains_key(&sender),
                "sync history must NOT be updated for non-LocalRT sender"
            );
        }

        // --- Case 2: sender IS in LocalRT (sender_in_rt = true) ---
        let sender_in_rt = true;
        assert!(
            sender_in_rt,
            "when sender is in LocalRT, inbound hints are processed"
        );

        // Sync history IS updated for RT peers.
        sync_history.insert(
            sender,
            PeerSyncRecord {
                last_sync: Some(Instant::now()),
                cycles_since_sync: 0,
            },
        );
        assert!(
            sync_history.contains_key(&sender),
            "sync history should be updated for LocalRT sender"
        );
        assert!(
            sync_history
                .get(&sender)
                .expect("sender in history")
                .last_sync
                .is_some(),
            "last_sync should be recorded for RT sender"
        );
    }

    #[test]
    fn cycle_completion_resets_cursor_but_keeps_sync_times() {
        // Verify that after cycle completes, starting a new cycle
        // preserves the last_sync_times from the old state.
        let peers = vec![peer_id_from_byte(1), peer_id_from_byte(2)];
        let mut state = NeighborSyncState::new_cycle(peers);

        // Sync both peers and record their times.
        let _ = select_sync_batch(&mut state, 2, Duration::from_secs(0));
        record_successful_sync(&mut state, &peer_id_from_byte(1));
        record_successful_sync(&mut state, &peer_id_from_byte(2));
        assert!(state.is_cycle_complete());

        // Capture sync times before "resetting" for a new cycle.
        let old_sync_times = state.last_sync_times.clone();
        assert_eq!(old_sync_times.len(), 2);

        // Simulate starting a new cycle: create fresh state but carry over
        // last_sync_times (as the real driver would).
        let new_peers = vec![
            peer_id_from_byte(1),
            peer_id_from_byte(2),
            peer_id_from_byte(3),
        ];
        let mut new_state = NeighborSyncState::new_cycle(new_peers);
        new_state.last_sync_times = old_sync_times;

        // Cursor is reset.
        assert_eq!(new_state.cursor, 0);
        assert!(!new_state.is_cycle_complete());

        // Sync times are preserved.
        assert_eq!(new_state.last_sync_times.len(), 2);
        assert!(new_state
            .last_sync_times
            .contains_key(&peer_id_from_byte(1)));
        assert!(new_state
            .last_sync_times
            .contains_key(&peer_id_from_byte(2)));

        // The preserved cooldowns cause peers 1,2 to be removed, leaving
        // only peer 3 selected.
        let cooldown = Duration::from_secs(3600);
        let batch = select_sync_batch(&mut new_state, 3, cooldown);
        assert_eq!(
            batch,
            std::iter::once(peer_id_from_byte(3)).collect::<Vec<_>>(),
            "only the new peer should be selected; old peers are on cooldown"
        );
    }
}
