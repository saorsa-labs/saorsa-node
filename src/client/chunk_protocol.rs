//! Shared helper for the chunk protocol request/response pattern.
//!
//! Extracts the duplicated "subscribe → send → poll event loop" into a single
//! generic function used by both [`super::QuantumClient`] and E2E test helpers.

use crate::ant_protocol::{ChunkMessage, ChunkMessageBody, CHUNK_PROTOCOL_ID};
use saorsa_core::{P2PEvent, P2PNode};
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use tokio::time::Instant;
use tracing::{debug, warn};

/// Send a chunk-protocol message to `target_peer` and await a matching response.
///
/// The event loop filters by topic (`CHUNK_PROTOCOL_ID`), source peer, decode
/// errors (warn + skip), and `request_id` mismatch (skip).
///
/// * `response_handler` — inspects the decoded [`ChunkMessageBody`] and returns:
///   - `Some(Ok(T))` to resolve successfully,
///   - `Some(Err(E))` to resolve with an error,
///   - `None` to keep waiting (wrong variant / not our response).
/// * `send_error` — produces the caller's error type when `send_message` fails.
/// * `timeout_error` — produces the caller's error type on deadline expiry.
///
/// # Errors
///
/// Returns `Err(E)` if sending fails (via `send_error`), the `response_handler`
/// returns a protocol-level error, or the deadline expires (via `timeout_error`).
#[allow(clippy::too_many_arguments)]
pub async fn send_and_await_chunk_response<T, E>(
    node: &P2PNode,
    target_peer: &str,
    message_bytes: Vec<u8>,
    request_id: u64,
    timeout: Duration,
    response_handler: impl Fn(ChunkMessageBody) -> Option<Result<T, E>>,
    send_error: impl FnOnce(String) -> E,
    timeout_error: impl FnOnce() -> E,
) -> Result<T, E> {
    // Subscribe before sending so we don't miss the response
    let mut events = node.subscribe_events();

    let target_peer_id = target_peer.to_string();

    node.send_message(&target_peer_id, CHUNK_PROTOCOL_ID, message_bytes)
        .await
        .map_err(|e| send_error(e.to_string()))?;

    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Ok(P2PEvent::Message {
                topic,
                source,
                data,
            })) if topic == CHUNK_PROTOCOL_ID && source == target_peer_id => {
                let response = match ChunkMessage::decode(&data) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("Failed to decode chunk message, skipping: {e}");
                        continue;
                    }
                };
                if response.request_id != request_id {
                    continue;
                }
                if let Some(result) = response_handler(response.body) {
                    return result;
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(RecvError::Lagged(skipped))) => {
                debug!("Chunk protocol events lagged by {skipped} messages, continuing");
            }
            Ok(Err(RecvError::Closed)) | Err(_) => break,
        }
    }

    Err(timeout_error())
}
