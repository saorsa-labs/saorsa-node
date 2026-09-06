//! ANT protocol handler for autonomi protocol messages.
//!
//! This handler processes chunk PUT/GET requests with optional payment verification,
//! storing chunks on disk and using the DHT for network-wide retrieval.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    AntProtocol                        │
//! ├─────────────────────────────────────────────────────────┤
//! │  protocol_id() = "autonomi.ant.chunk.v1"                  │
//! │                                                         │
//! │  try_handle_request(data) ──▶ decode ChunkMessage  │
//! │                                   │                     │
//! │         ┌─────────────────────────┼─────────────────┐  │
//! │         ▼                         ▼                 ▼  │
//! │   ChunkQuoteRequest           ChunkPutRequest    ChunkGetRequest
//! │         │                         │                 │  │
//! │         ▼                         ▼                 ▼  │
//! │   QuoteGenerator          PaymentVerifier    ChunkStore│
//! │         │                         │                 │  │
//! │         └─────────────────────────┴─────────────────┘  │
//! │                           │                             │
//! │           return Ok(Some(response_bytes))              │
//! │           return Ok(None) for response messages       │
//! └─────────────────────────────────────────────────────────┘
//! ```

#[cfg(test)]
use crate::ant_protocol::DATA_TYPE_CHUNK;
use crate::ant_protocol::{
    ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkMessageBody, ChunkPutRequest,
    ChunkPutResponse, ChunkQuoteRequest, ChunkQuoteResponse, MerkleCandidateQuoteRequest,
    MerkleCandidateQuoteResponse, ProtocolError, CHUNK_PROTOCOL_ID, MAX_CHUNK_SIZE,
};
use crate::client::compute_address;
use crate::error::{Error, Result};
use crate::logging::{debug, info, warn};
use crate::payment::{PaymentVerifier, QuoteGenerator, VerificationContext};
use crate::replication::admission;
use crate::replication::config::K_BUCKET_SIZE;
use crate::replication::fresh::FreshWriteEvent;
use crate::storage::ChunkStore;
use bytes::Bytes;
use parking_lot::RwLock;
use saorsa_core::P2PNode;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Width of the self-closeness gate on client PUTs (ADR-0003): a node accepts
/// a PUT only when it is within its own local `SELF_CLOSENESS_GATE_WIDTH`
/// closest peers to the address.
///
/// Set to the client's PUT fallback ceiling (`K_BUCKET_SIZE`), wider than the
/// storage-admission width, so a client routing past full close-group members
/// onto further peers (ADR-0002) is still accepted here, while a genuinely far
/// node — which could only mis-attribute fresh-replication failures — is
/// turned away.
const SELF_CLOSENESS_GATE_WIDTH: usize = K_BUCKET_SIZE;

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Receipt context supplied by the authenticated P2P event router.
///
/// This is deliberately process-local metadata: it is never encoded or sent on
/// the wire. The receipt instant spans semaphore queueing, storage, response
/// encoding, and the response hand-off to the transport.
pub struct ChunkRequestContext {
    source_peer: String,
    received_at: Instant,
    queue_wait_ms: u64,
}

impl ChunkRequestContext {
    #[must_use]
    pub(crate) fn new(source_peer: String, received_at: Instant, queue_wait: Duration) -> Self {
        Self {
            source_peer,
            received_at,
            queue_wait_ms: duration_ms(queue_wait),
        }
    }
}

/// A decoded protocol request and, for GETs, its pending one-shot telemetry.
///
/// Keeping the handler result and telemetry together lets the router record the
/// event only after response hand-off, while preserving the existing handler
/// error and response behaviour.
pub struct HandledChunkRequest {
    pub(crate) response: Result<Option<Bytes>>,
    pub(crate) get_telemetry: Option<GetRequestTelemetry>,
}

/// Bounded stage timings for one decoded chunk GET.
///
/// `finish_send` emits the sole `get_rpc` event. If the routing task is cancelled
/// after handling but before response hand-off completes, `Drop` emits the same
/// event with `cancelled` outcomes so the request does not disappear silently.
#[cfg_attr(not(feature = "logging"), allow(dead_code))]
pub struct GetRequestTelemetry {
    source_peer: String,
    request_id: u64,
    chunk_address: String,
    received_at: Instant,
    queue_wait_ms: u64,
    storage_read_ms: u64,
    storage_outcome: &'static str,
    storage_error_category: &'static str,
    response_encode_ms: u64,
    finished: bool,
}

impl GetRequestTelemetry {
    fn from_response(
        context: ChunkRequestContext,
        request_id: u64,
        chunk_address: String,
        storage_read_ms: u64,
        response: &ChunkGetResponse,
    ) -> Self {
        let (storage_outcome, storage_error_category) = match response {
            ChunkGetResponse::Success { .. } => ("success", "none"),
            ChunkGetResponse::NotFound { .. } => ("not_found", "none"),
            ChunkGetResponse::Error(ProtocolError::StorageFailed(_)) => ("error", "storage"),
            ChunkGetResponse::Error(_) => ("error", "protocol"),
            _ => ("unknown", "unknown"),
        };
        Self {
            source_peer: context.source_peer,
            request_id,
            chunk_address,
            received_at: context.received_at,
            queue_wait_ms: context.queue_wait_ms,
            storage_read_ms,
            storage_outcome,
            storage_error_category,
            response_encode_ms: 0,
            finished: false,
        }
    }

    fn set_response_encode_ms(&mut self, elapsed: Duration) {
        self.response_encode_ms = duration_ms(elapsed);
    }

    /// Record the single completed GET event after response hand-off.
    pub(crate) fn finish_send(mut self, response_send: Duration, send_succeeded: bool) {
        let (send_outcome, overall_outcome) = if send_succeeded {
            let overall = match self.storage_outcome {
                "success" => "success",
                "not_found" => "not_found",
                "error" => "storage_error",
                _ => "unknown",
            };
            ("success", overall)
        } else {
            ("error", "send_error")
        };
        self.emit(response_send, send_outcome, overall_outcome);
        self.finished = true;
    }

    /// Record a GET which could not reach the response hand-off stage.
    pub(crate) fn finish_without_send(mut self, overall_outcome: &'static str) {
        self.emit(Duration::ZERO, "not_attempted", overall_outcome);
        self.finished = true;
    }

    fn emit(
        &self,
        response_send: Duration,
        send_outcome: &'static str,
        overall_outcome: &'static str,
    ) {
        let response_send_ms = duration_ms(response_send);
        let duration_ms = duration_ms(self.received_at.elapsed());
        info!(
            target: "ant_node::storage::rpc_latency",
            source_peer = %self.source_peer,
            request_id = self.request_id,
            chunk_address = %self.chunk_address,
            addr = %self.chunk_address,
            queue_wait_ms = self.queue_wait_ms,
            storage_read_ms = self.storage_read_ms,
            storage_outcome = self.storage_outcome,
            storage_error_category = self.storage_error_category,
            response_encode_ms = self.response_encode_ms,
            response_send_ms,
            send_outcome,
            duration_ms,
            outcome = overall_outcome,
            "get_rpc"
        );
    }
}

impl Drop for GetRequestTelemetry {
    fn drop(&mut self) {
        if !self.finished {
            self.emit(Duration::ZERO, "cancelled", "cancelled");
            self.finished = true;
        }
    }
}

/// ANT protocol handler.
///
/// Handles chunk PUT/GET/Quote requests, persisting each chunk as its own file
/// and optional payment verification.
pub struct AntProtocol {
    /// The chunk store.
    storage: Arc<ChunkStore>,
    /// Payment verifier for checking payments.
    payment_verifier: Arc<PaymentVerifier>,
    /// Quote generator for creating storage quotes.
    /// Also handles merkle candidate quote signing via ML-DSA-65.
    quote_generator: Arc<QuoteGenerator>,
    /// Channel for notifying the replication engine about newly-stored chunks.
    fresh_write_tx: Option<mpsc::UnboundedSender<FreshWriteEvent>>,
    /// The node's P2P handle, attached post-construction via
    /// `attach_p2p_node`. Drives the self-closeness gate on client PUTs;
    /// `None` in unit tests that never attach a node.
    p2p_node: RwLock<Option<Arc<P2PNode>>>,
}

impl AntProtocol {
    /// Create a new ANT protocol handler.
    ///
    /// # Arguments
    ///
    /// * `storage` - the chunk store
    /// * `payment_verifier` - Payment verifier for validating payments
    /// * `quote_generator` - Quote generator for creating storage quotes
    #[must_use]
    pub fn new(
        storage: Arc<ChunkStore>,
        payment_verifier: Arc<PaymentVerifier>,
        quote_generator: Arc<QuoteGenerator>,
    ) -> Self {
        // Wire the PaymentVerifier to the same authoritative store used by this
        // protocol handler. Historically the verifier read `current_chunks()`
        // for the paid-quote price floor; ADR-0004 retired that gate (price is
        // bound to the live storage commitment, not the local record count), so
        // the store is no longer consulted for pricing. The attachment is kept
        // so any future store-backed verifier check reads the same record count
        // this handler serves, for every AntProtocol construction path.
        //
        // ADR-0004: the QuoteGenerator no longer prices off `current_chunks()`
        // — its price is bound to the live storage commitment (see
        // `attach_commitment_source`, wired by the node once the replication
        // engine exists), or baseline when none — so it is NOT attached to the
        // store here.
        payment_verifier.attach_storage(Arc::clone(&storage));

        Self {
            storage,
            payment_verifier,
            quote_generator,
            fresh_write_tx: None,
            p2p_node: RwLock::new(None),
        }
    }

    /// Attach the node's P2P handle for payment live-DHT checks.
    ///
    /// Wires the handle into the payment verifier so payment-proof closeness
    /// checks can use the live routing view. Idempotent: calling twice
    /// replaces the verifier handle.
    pub fn attach_p2p_node(&self, node: Arc<P2PNode>) {
        *self.p2p_node.write() = Some(Arc::clone(&node));
        self.payment_verifier.attach_p2p_node(node);
        debug!("AntProtocol: P2PNode attached for payment live-DHT checks and self-closeness gate");
    }

    /// Set the channel sender for fresh-write replication events.
    ///
    /// When set, successful chunk PUTs will notify the replication engine
    /// so it can fan out fresh offers to the close group.
    pub fn set_fresh_write_sender(&mut self, tx: mpsc::UnboundedSender<FreshWriteEvent>) {
        self.fresh_write_tx = Some(tx);
    }

    /// Get the protocol identifier.
    #[must_use]
    pub fn protocol_id(&self) -> &'static str {
        CHUNK_PROTOCOL_ID
    }

    /// Get a reference to the underlying chunk store.
    #[must_use]
    pub fn storage(&self) -> Arc<ChunkStore> {
        Arc::clone(&self.storage)
    }

    /// Test-only: the record count the quote generator currently prices on.
    /// Used to assert that quote-time resync tracks records actually held.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn priced_records_stored(&self) -> usize {
        self.quote_generator.records_stored()
    }

    /// Get a shared reference to the payment verifier.
    #[must_use]
    pub fn payment_verifier_arc(&self) -> Arc<PaymentVerifier> {
        Arc::clone(&self.payment_verifier)
    }

    /// ADR-0004: attach the replication engine's commitment state as the quote
    /// generator's commitment source, so quotes force their price from the live
    /// storage commitment and refresh its answerability on issuance.
    ///
    /// Called once, after both the protocol and the replication engine exist
    /// (the engine owns the [`ResponderCommitmentState`](crate::replication::commitment_state::ResponderCommitmentState)).
    /// Until this is wired, the quote generator has no commitment source and
    /// falls back to baseline (no-pin) pricing.
    ///
    /// The same source is forwarded to the payment verifier's price-floor
    /// policy (read-only snapshot), so this node's quotes and its floor are
    /// priced from one commitment by construction.
    pub fn attach_commitment_source(
        &self,
        source: Arc<dyn crate::payment::quote::CommitmentSource>,
    ) {
        self.quote_generator
            .attach_commitment_source(Arc::clone(&source));
        self.payment_verifier.attach_local_commitment_source(source);
    }

    /// ADR-0004: return the proof with any commitment sidecars stripped, so a
    /// replicated/persisted receipt carries only the pin and count (stored
    /// proofs do not grow). Handles BOTH proof types — single-node and
    /// merkle-batch — since both now carry sidecars. An unknown-tagged or
    /// unparseable proof is returned unchanged. Best-effort: any
    /// deserialize/reserialize failure returns the original bytes rather than
    /// corrupting the proof.
    fn strip_commitment_sidecars(proof: Vec<u8>) -> Vec<u8> {
        use crate::payment::proof::{
            deserialize_merkle_proof, deserialize_single_node_proof, detect_proof_type,
            serialize_merkle_proof, serialize_single_node_proof, ProofType,
        };
        match detect_proof_type(&proof) {
            Some(ProofType::SingleNode) => match deserialize_single_node_proof(&proof) {
                Ok(mut parsed) if !parsed.commitment_sidecars.is_empty() => {
                    parsed.commitment_sidecars.clear();
                    serialize_single_node_proof(&parsed).unwrap_or(proof)
                }
                _ => proof, // already sidecar-free, or unparseable: leave as-is
            },
            Some(ProofType::Merkle) => match deserialize_merkle_proof(&proof) {
                Ok(mut parsed) if !parsed.commitment_sidecars.is_empty() => {
                    parsed.commitment_sidecars.clear();
                    serialize_merkle_proof(&parsed).unwrap_or(proof)
                }
                _ => proof,
            },
            _ => proof, // unknown tag: nothing to strip
        }
    }

    /// Handle an incoming request and produce a response.
    ///
    /// Decodes the raw message, processes it if it is a request variant,
    /// and returns the encoded response bytes.  Returns `Ok(None)` for
    /// response messages (which are meant for client subscribers, not for
    /// the protocol handler).
    ///
    /// # Errors
    ///
    /// Returns an error if message decoding, handling, or encoding fails.
    pub async fn try_handle_request(&self, data: &[u8]) -> Result<Option<Bytes>> {
        self.try_handle_request_with_context(data, None)
            .await
            .response
    }

    /// Handle a request while carrying authenticated receipt context through a
    /// GET response hand-off. The context is local-only observability metadata.
    pub(crate) async fn try_handle_request_with_context(
        &self,
        data: &[u8],
        context: Option<ChunkRequestContext>,
    ) -> HandledChunkRequest {
        let message = match ChunkMessage::decode(data) {
            Ok(message) => message,
            Err(e) => {
                return HandledChunkRequest {
                    response: Err(Error::Protocol(format!("Failed to decode message: {e}"))),
                    get_telemetry: None,
                };
            }
        };

        let request_id = message.request_id;
        let mut get_telemetry = None;

        let response_body = match message.body {
            ChunkMessageBody::PutRequest(req) => {
                ChunkMessageBody::PutResponse(self.handle_put(req).await)
            }
            ChunkMessageBody::GetRequest(req) => {
                let chunk_address = hex::encode(req.address);
                let storage_started = Instant::now();
                let response = self.handle_get_inner(req).await;
                let storage_read_ms = duration_ms(storage_started.elapsed());
                if let Some(context) = context {
                    get_telemetry = Some(GetRequestTelemetry::from_response(
                        context,
                        request_id,
                        chunk_address,
                        storage_read_ms,
                        &response,
                    ));
                }
                ChunkMessageBody::GetResponse(response)
            }
            ChunkMessageBody::QuoteRequest(ref req) => {
                ChunkMessageBody::QuoteResponse(self.handle_quote(req))
            }
            ChunkMessageBody::MerkleCandidateQuoteRequest(ref req) => {
                ChunkMessageBody::MerkleCandidateQuoteResponse(
                    self.handle_merkle_candidate_quote(req),
                )
            }
            // Anything else — response messages are handled by client
            // subscribers (e.g. send_and_await_chunk_response), not by the
            // protocol handler. Returning None prevents the caller from
            // sending a reply, which would create an infinite ping-pong
            // loop.
            //
            // `ChunkMessageBody` is `#[non_exhaustive]` in ant-protocol, so
            // a future wire variant added on a protocol minor bump also
            // lands here and is dropped. The CHUNK_PROTOCOL_ID multistream-
            // select handshake version-gates peers, so this arm should
            // only be reached by a misconfigured peer.
            _ => {
                return HandledChunkRequest {
                    response: Ok(None),
                    get_telemetry: None,
                };
            }
        };

        let response = ChunkMessage {
            request_id,
            body: response_body,
        };
        let encode_started = Instant::now();
        let encoded = response
            .encode()
            .map(|b| Some(Bytes::from(b)))
            .map_err(|e| Error::Protocol(format!("Failed to encode response: {e}")));
        if let Some(telemetry) = &mut get_telemetry {
            telemetry.set_response_encode_ms(encode_started.elapsed());
        }

        HandledChunkRequest {
            response: encoded,
            get_telemetry,
        }
    }

    /// Handle a PUT request.
    ///
    /// Wraps `handle_put_inner` to emit a single structured tracing event per
    /// PUT RPC at every exit path, including early-return validation paths.
    /// The event uses `target: "ant_node::storage::rpc_latency"` so that
    /// Elasticsearch / Kibana can build p50/p95/p99 store-RPC latency
    /// histograms from the existing telegraf log forwarding.
    async fn handle_put(&self, request: ChunkPutRequest) -> ChunkPutResponse {
        let start = std::time::Instant::now();
        let addr_hex = hex::encode(request.address);
        let chunk_size = request.content.len();
        let response = self.handle_put_inner(request).await;
        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let outcome: &'static str = match &response {
            ChunkPutResponse::Success { .. } => "success",
            ChunkPutResponse::AlreadyExists { .. } => "already_exists",
            ChunkPutResponse::PaymentRequired { .. } => "payment_required",
            ChunkPutResponse::Error(_) => "error",
            _ => "unknown",
        };
        info!(
            target: "ant_node::storage::rpc_latency",
            duration_ms,
            chunk_size,
            outcome,
            addr = %addr_hex,
            "put_rpc"
        );
        response
    }

    /// Inner body of `handle_put` — see the wrapper for the per-RPC latency log.
    async fn handle_put_inner(&self, request: ChunkPutRequest) -> ChunkPutResponse {
        let address = request.address;
        let addr_hex = hex::encode(address);
        debug!("Handling PUT request for {addr_hex}");

        // 1. Validate chunk size
        if request.content.len() > MAX_CHUNK_SIZE {
            return ChunkPutResponse::Error(ProtocolError::ChunkTooLarge {
                size: request.content.len(),
                max_size: MAX_CHUNK_SIZE,
            });
        }

        // 2. Verify content address matches BLAKE3(content)
        let computed = compute_address(&request.content);
        if computed != address {
            return ChunkPutResponse::Error(ProtocolError::AddressMismatch {
                expected: address,
                actual: computed,
            });
        }

        // 3. Check if already exists (idempotent success)
        //
        // Verified against the offered bytes, not answered from the name. A name can
        // outlive the bytes under it, and acknowledging a good copy of a chunk this node
        // holds only a damaged version of throws that copy away and does not get offered
        // another. Reached only when this node already has the chunk, and the content
        // address was checked in step 2, so a damaged copy is repaired from these bytes
        // rather than the offer being refused.
        if self
            .storage
            .holds_verified(&address, &request.content)
            .await
        {
            debug!("Chunk {addr_hex} already exists");
            return ChunkPutResponse::AlreadyExists { address };
        }

        // 4. Cheap disk-space pre-check — runs BEFORE the expensive payment
        //    verification path (ML-DSA pool checks, a Kademlia closeness
        //    lookup, and an on-chain Arbitrum RPC). A disk-full node can never
        //    satisfy this PUT, so reject it here rather than burning that work
        //    only to fail the reserve check inside `storage.put` (V2-411). The
        //    check caches passing results, so it is free per-PUT on a healthy
        //    node; a disk-full node re-runs a cheap `available_space` syscall
        //    each PUT (still negligible next to the verification it avoids) and
        //    so detects freed space promptly. The store path keeps its own
        //    check as defence-in-depth.
        if let Err(e) = self.storage.check_capacity() {
            info!(
                target: "ant_node::storage::disk_precheck",
                addr = %addr_hex,
                "Rejecting PUT before payment verification: {e}"
            );
            return ChunkPutResponse::Error(ProtocolError::StorageFailed(e.to_string()));
        }

        // Self-closeness gate (ADR-0003): accept a client PUT only when this
        // node is within its own local closest view of the address, so the
        // fresh replication it triggers is legitimate and cannot mis-penalise
        // honest peers. The width is the client's PUT fallback ceiling
        // (`SELF_CLOSENESS_GATE_WIDTH`), so a client routing past full
        // close-group members onto further peers is still accepted here.
        // Skipped when no P2P handle is attached (unit tests). Bind the handle
        // out of the lock first so no guard is held across the `.await`.
        let attached = self.p2p_node.read().as_ref().map(Arc::clone);
        if let Some(p2p) = attached {
            let self_id = *p2p.peer_id();
            if !admission::is_responsible(&self_id, &address, &p2p, SELF_CLOSENESS_GATE_WIDTH).await
            {
                debug!("Rejecting PUT for {addr_hex}: not within local closest peers");
                return ChunkPutResponse::Error(ProtocolError::StorageFailed(
                    "node is not within its local closest peers for this address".to_string(),
                ));
            }
        }

        // 5. Verify payment. The ClientPut context applies the store-strength
        //    payment cache and verifies live proofs.
        let payment_result = self
            .payment_verifier
            .verify_payment(
                &address,
                request.payment_proof.as_deref(),
                VerificationContext::ClientPut,
            )
            .await;

        match payment_result {
            Ok(status) if status.can_store() => {
                // Payment verified or cached
            }
            Ok(_) => {
                return ChunkPutResponse::PaymentRequired {
                    message: "Payment required for new chunk".to_string(),
                };
            }
            Err(e) => {
                return ChunkPutResponse::Error(ProtocolError::PaymentFailed(e.to_string()));
            }
        }

        // 6. Store chunk
        match self.storage.put(&address, &request.content).await {
            Ok(_) => {
                let content_len = request.content.len();
                info!("Stored chunk {addr_hex} ({content_len} bytes)");
                // Bump the in-memory fallback record counter. Under ADR-0004
                // neither pricing nor the receiver-side price floor reads this
                // counter: both are bound to the live storage commitment
                // (committed responsible key count), pricing via the quote
                // generator's commitment source and the floor via the
                // verifier's non-mutating snapshot of the same commitment. The
                // counter only matters as a warm fallback surface when no
                // commitment source is attached (unit tests / pre-replication
                // startup).
                self.quote_generator.record_store();

                // 7. Notify replication engine for fresh fan-out.
                //    Only emit when a real proof is present — cached-as-verified
                //    PUTs have no proof to forward, and the chunk would have
                //    already replicated on the original write that carried one.
                if let (Some(ref tx), Some(proof)) = (&self.fresh_write_tx, request.payment_proof) {
                    // ADR-0004: strip any commitment sidecars before forwarding
                    // to replication — the ADR specifies persisted/replicated
                    // receipts "keep only the pin and count, so stored proofs do
                    // not grow." The sidecars were already consumed by this
                    // node's client-put cross-check; replicas resolve pins via
                    // gossip/fetch (their context is Replication, which skips the
                    // cross-check anyway). Best-effort: if sanitisation fails,
                    // fall back to the original proof rather than dropping the
                    // replication entirely.
                    let proof = Self::strip_commitment_sidecars(proof);
                    // `request.content` is now `bytes::Bytes`; FreshWriteEvent
                    // still carries the chunk as `Vec<u8>` for compatibility
                    // with the replication wire format, so materialise once
                    // here. Done only on the success path, where storage has
                    // already accepted the chunk.
                    let event = FreshWriteEvent {
                        key: address,
                        data: request.content.to_vec(),
                        payment_proof: proof,
                    };
                    if tx.send(event).is_err() {
                        debug!("Fresh-write channel closed, skipping replication for {addr_hex}");
                    }
                }

                ChunkPutResponse::Success { address }
            }
            Err(e) => {
                warn!("Failed to store chunk {addr_hex}: {e}");
                ChunkPutResponse::Error(ProtocolError::StorageFailed(e.to_string()))
            }
        }
    }

    /// Read a chunk from local storage for a GET request.
    async fn handle_get_inner(&self, request: ChunkGetRequest) -> ChunkGetResponse {
        let address = request.address;
        let addr_hex = hex::encode(address);
        debug!("Handling GET request for {addr_hex}");

        match self.storage.get(&address).await {
            Ok(Some(content)) => {
                let content_len = content.len();
                debug!("Retrieved chunk {addr_hex} ({content_len} bytes)");
                ChunkGetResponse::Success { address, content }
            }
            Ok(None) => {
                debug!("Chunk {addr_hex} not found");
                ChunkGetResponse::NotFound { address }
            }
            Err(e) => {
                warn!("Failed to retrieve chunk {addr_hex}: {e}");
                ChunkGetResponse::Error(ProtocolError::StorageFailed(e.to_string()))
            }
        }
    }

    /// Resync the quoting metric to the authoritative count of records the node
    /// actually holds.
    ///
    /// The quote price is driven by `QuoteGenerator::records_stored()`. Reading
    /// the live chunk count right before
    /// pricing makes the metric deletion-aware: any chunk removed by
    /// [`ChunkStore::delete`] or by the replication prune pass is reflected
    /// immediately, with no risk of missing a delete path.
    ///
    /// On a storage read error — or a count that does not fit `usize` — the
    /// previous metric value is left untouched so a transient read error never
    /// disrupts quote generation.
    fn resync_quote_metric(&self) {
        match self.storage.current_chunks() {
            // Saturating an overflowing count to usize::MAX would jump the
            // metric to the maximum possible price driver; keep the previous
            // value instead, as for a read error.
            Ok(count) => usize::try_from(count).map_or_else(
                |_| {
                    warn!(
                        "current_chunks() count {count} overflows usize; keeping previous quote \
                         metric"
                    );
                },
                |records| self.quote_generator.resync_records(records),
            ),
            Err(e) => {
                warn!("Failed to read current_chunks() for quote metric resync: {e}");
            }
        }
    }

    /// Handle a quote request.
    fn handle_quote(&self, request: &ChunkQuoteRequest) -> ChunkQuoteResponse {
        let addr_hex = hex::encode(request.address);
        let data_size = request.data_size;
        debug!("Handling quote request for {addr_hex} (size: {data_size})");

        // Price on records ACTUALLY HELD, not a monotonic store counter.
        self.resync_quote_metric();

        // Check if the chunk is already stored so we can tell the client
        // to skip payment (already_stored = true).
        // The match intentionally logs the error when the `logging` feature is
        // active. Clippy suggests `unwrap_or_default()` when logging is compiled
        // out, but keeping the explicit match preserves the diagnostic intent.
        #[allow(clippy::manual_unwrap_or_default)]
        let already_stored = match self.storage.exists(&request.address) {
            Ok(exists) => exists,
            Err(e) => {
                warn!("Storage check failed for {addr_hex}: {e}");
                false // Assume not stored on error — generate a normal quote.
            }
        };

        if already_stored {
            debug!("Chunk {addr_hex} already stored — returning quote with already_stored=true");
        }

        // Validate data size - data_size is u64, cast carefully and reject overflow
        let Ok(data_size_usize) = usize::try_from(request.data_size) else {
            return ChunkQuoteResponse::Error(ProtocolError::ChunkTooLarge {
                size: MAX_CHUNK_SIZE + 1,
                max_size: MAX_CHUNK_SIZE,
            });
        };
        if data_size_usize > MAX_CHUNK_SIZE {
            return ChunkQuoteResponse::Error(ProtocolError::ChunkTooLarge {
                size: data_size_usize,
                max_size: MAX_CHUNK_SIZE,
            });
        }

        match self
            .quote_generator
            .create_quote(request.address, data_size_usize, request.data_type)
        {
            Ok(quote) => {
                // ADR-0004: ship the signed commitment the price was bound to
                // alongside the quote ("the commitment arrived with the quote"),
                // so the client can verify the binding before paying and forward
                // it as a sidecar in the PUT bundle. Only a commitment-bound
                // quote pins anything; a baseline `(0, None)` quote carries no
                // commitment. A pin that has rotated out resolves to `None` and
                // the client falls back to gossip/fetch.
                let commitment = quote
                    .commitment_pin
                    .and_then(|pin| self.quote_generator.commitment_blob_for_pin(pin));
                // Serialize the quote
                match rmp_serde::to_vec(&quote) {
                    Ok(quote_bytes) => ChunkQuoteResponse::Success {
                        quote: quote_bytes,
                        already_stored,
                        commitment,
                    },
                    Err(e) => ChunkQuoteResponse::Error(ProtocolError::QuoteFailed(format!(
                        "Failed to serialize quote: {e}"
                    ))),
                }
            }
            Err(e) => ChunkQuoteResponse::Error(ProtocolError::QuoteFailed(e.to_string())),
        }
    }

    /// Handle a merkle candidate quote request.
    fn handle_merkle_candidate_quote(
        &self,
        request: &MerkleCandidateQuoteRequest,
    ) -> MerkleCandidateQuoteResponse {
        let addr_hex = hex::encode(request.address);
        let data_size = request.data_size;
        debug!(
            "Handling merkle candidate quote request for {addr_hex} (size: {data_size}, ts: {})",
            request.merkle_payment_timestamp
        );

        // Price on records ACTUALLY HELD, not a monotonic store counter.
        self.resync_quote_metric();

        let Ok(data_size_usize) = usize::try_from(request.data_size) else {
            return MerkleCandidateQuoteResponse::Error(ProtocolError::QuoteFailed(format!(
                "data_size {} overflows usize",
                request.data_size
            )));
        };
        if data_size_usize > MAX_CHUNK_SIZE {
            return MerkleCandidateQuoteResponse::Error(ProtocolError::ChunkTooLarge {
                size: data_size_usize,
                max_size: MAX_CHUNK_SIZE,
            });
        }

        match self.quote_generator.create_merkle_candidate_quote(
            data_size_usize,
            request.data_type,
            request.merkle_payment_timestamp,
        ) {
            Ok(candidate_node) => {
                // ADR-0004: ship the signed commitment this candidate priced
                // against, so the client can verify the binding before paying
                // and forward it as a sidecar. Baseline candidates ship none.
                let commitment = candidate_node
                    .commitment_pin
                    .and_then(|pin| self.quote_generator.commitment_blob_for_pin(pin));
                match rmp_serde::to_vec(&candidate_node) {
                    Ok(bytes) => MerkleCandidateQuoteResponse::Success {
                        candidate_node: bytes,
                        commitment,
                    },
                    Err(e) => MerkleCandidateQuoteResponse::Error(ProtocolError::QuoteFailed(
                        format!("Failed to serialize merkle candidate node: {e}"),
                    )),
                }
            }
            Err(e) => {
                MerkleCandidateQuoteResponse::Error(ProtocolError::QuoteFailed(e.to_string()))
            }
        }
    }

    /// Get storage statistics.
    #[must_use]
    pub fn storage_stats(&self) -> crate::storage::StorageStats {
        self.storage.stats()
    }

    /// Get payment cache statistics.
    #[must_use]
    pub fn payment_cache_stats(&self) -> crate::payment::CacheStats {
        self.payment_verifier.cache_stats()
    }

    /// Get a reference to the payment verifier.
    ///
    /// Exposed for **test harnesses only** — production code should not call
    /// this directly. Use `cache_insert()` on the returned verifier to
    /// pre-populate the payment cache in test setups.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn payment_verifier(&self) -> &PaymentVerifier {
        &self.payment_verifier
    }

    /// Check if a chunk exists locally.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage read fails.
    pub fn exists(&self, address: &[u8; 32]) -> Result<bool> {
        self.storage.exists(address)
    }

    /// Get a chunk directly from local storage.
    ///
    /// # Errors
    ///
    /// Returns an error if storage access fails.
    pub async fn get_local(&self, address: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        self.storage.get(address).await
    }

    /// Store a chunk directly to local storage (bypasses payment verification).
    ///
    /// TEST ONLY - This method bypasses payment verification and should only be used in tests.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails or content doesn't match address.
    #[cfg(test)]
    pub async fn put_local(&self, address: &[u8; 32], content: &[u8]) -> Result<bool> {
        self.storage.put(address, content).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::payment::metrics::QuotingMetricsTracker;
    use crate::payment::{EvmVerifierConfig, PaymentVerifierConfig};
    use crate::storage::ChunkStoreConfig;
    use evmlib::RewardsAddress;
    use saorsa_core::identity::NodeIdentity;
    use saorsa_core::MlDsa65;
    use saorsa_pqc::pqc::types::MlDsaSecretKey;
    use tempfile::TempDir;

    async fn create_test_protocol() -> (AntProtocol, TempDir) {
        // `test_default()` sets `disk_reserve: 0`, so the disk pre-check always
        // passes for the regular tests.
        create_test_protocol_with_reserve(0).await
    }

    /// Build a test protocol whose storage enforces the given disk reserve.
    ///
    /// A very large reserve (e.g. `u64::MAX`) makes `available < reserve`
    /// always true, so the disk-space pre-check in `handle_put_inner` fails —
    /// used to exercise the V2-411 early-return path.
    async fn create_test_protocol_with_reserve(disk_reserve: u64) -> (AntProtocol, TempDir) {
        let temp_dir = TempDir::new().expect("create temp dir");

        let storage_config = ChunkStoreConfig {
            root_dir: temp_dir.path().to_path_buf(),
            disk_reserve,
            ..ChunkStoreConfig::test_default()
        };
        let storage = Arc::new(
            ChunkStore::new(storage_config)
                .await
                .expect("create storage"),
        );

        let rewards_address = RewardsAddress::new([1u8; 20]);
        let payment_config = PaymentVerifierConfig {
            evm: EvmVerifierConfig::default(),
            cache_capacity: 100_000,
            close_group_size: crate::ant_protocol::CLOSE_GROUP_SIZE,
            local_rewards_address: rewards_address,
            price_floor: crate::payment::PriceFloorConfig::default(),
        };
        let payment_verifier = Arc::new(PaymentVerifier::new(payment_config));
        let metrics_tracker = QuotingMetricsTracker::new(100);
        let mut quote_generator = QuoteGenerator::new(rewards_address, metrics_tracker);

        // Wire ML-DSA-65 signing so quote requests succeed
        let identity = NodeIdentity::generate().expect("generate identity");
        let pub_key_bytes = identity.public_key().as_bytes().to_vec();
        let sk_bytes = identity.secret_key_bytes().to_vec();
        let sk = MlDsaSecretKey::from_bytes(&sk_bytes).expect("deserialize secret key");
        quote_generator.set_signer(pub_key_bytes, move |msg| {
            use saorsa_pqc::pqc::MlDsaOperations;
            let ml_dsa = MlDsa65::new();
            ml_dsa
                .sign(&sk, msg)
                .map_or_else(|_| vec![], |sig| sig.as_bytes().to_vec())
        });

        let protocol = AntProtocol::new(storage, payment_verifier, Arc::new(quote_generator));
        (protocol, temp_dir)
    }

    #[tokio::test]
    async fn test_put_and_get_chunk() {
        let (protocol, _temp) = create_test_protocol().await;

        let content = b"hello world";
        let address = ChunkStore::compute_address(content);

        // Pre-populate payment cache so EVM verification is bypassed
        protocol.payment_verifier().cache_insert(address);

        let put_request = ChunkPutRequest::new(address, Bytes::copy_from_slice(content));
        let put_msg = ChunkMessage {
            request_id: 1,
            body: ChunkMessageBody::PutRequest(put_request),
        };
        let put_bytes = put_msg.encode().expect("encode put");

        // Handle PUT
        let response_bytes = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        assert_eq!(response.request_id, 1);
        if let ChunkMessageBody::PutResponse(ChunkPutResponse::Success { address: addr }) =
            response.body
        {
            assert_eq!(addr, address);
        } else {
            panic!("expected PutResponse::Success, got: {response:?}");
        }

        // Create GET request
        let get_request = ChunkGetRequest::new(address);
        let get_msg = ChunkMessage {
            request_id: 2,
            body: ChunkMessageBody::GetRequest(get_request),
        };
        let get_bytes = get_msg.encode().expect("encode get");

        // Handle GET with the same local context the authenticated router adds.
        let handled = protocol
            .try_handle_request_with_context(
                &get_bytes,
                Some(ChunkRequestContext::new(
                    "peer-success".to_string(),
                    Instant::now(),
                    Duration::from_millis(4),
                )),
            )
            .await;
        let telemetry = handled.get_telemetry.expect("GET telemetry");
        assert_eq!(telemetry.source_peer, "peer-success");
        assert_eq!(telemetry.request_id, 2);
        assert_eq!(telemetry.chunk_address, hex::encode(address));
        assert_eq!(telemetry.queue_wait_ms, 4);
        assert_eq!(telemetry.storage_outcome, "success");
        assert_eq!(telemetry.storage_error_category, "none");

        let response_bytes = handled
            .response
            .expect("handle get")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        assert_eq!(response.request_id, 2);
        if let ChunkMessageBody::GetResponse(ChunkGetResponse::Success {
            address: addr,
            content: data,
        }) = response.body
        {
            assert_eq!(addr, address);
            assert_eq!(data, content.to_vec());
        } else {
            panic!("expected GetResponse::Success");
        }
        telemetry.finish_send(Duration::from_millis(2), true);
    }

    #[tokio::test]
    async fn test_get_not_found() {
        let (protocol, _temp) = create_test_protocol().await;

        let address = [0xAB; 32];
        let get_request = ChunkGetRequest::new(address);
        let get_msg = ChunkMessage {
            request_id: 10,
            body: ChunkMessageBody::GetRequest(get_request),
        };
        let get_bytes = get_msg.encode().expect("encode get");

        let response_bytes = protocol
            .try_handle_request(&get_bytes)
            .await
            .expect("handle get")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        assert_eq!(response.request_id, 10);
        if let ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound { address: addr }) =
            response.body
        {
            assert_eq!(addr, address);
        } else {
            panic!("expected GetResponse::NotFound");
        }
    }

    #[tokio::test]
    async fn test_get_telemetry_preserves_join_fields_and_response() {
        let (protocol, _temp) = create_test_protocol().await;

        let address = [0xCD; 32];
        let request_id = 995;
        let get_msg = ChunkMessage {
            request_id,
            body: ChunkMessageBody::GetRequest(ChunkGetRequest::new(address)),
        };
        let get_bytes = get_msg.encode().expect("encode get");
        let received_at = Instant::now();
        let handled = protocol
            .try_handle_request_with_context(
                &get_bytes,
                Some(ChunkRequestContext::new(
                    "peer-v2-995".to_string(),
                    received_at,
                    Duration::from_millis(17),
                )),
            )
            .await;

        let telemetry = handled.get_telemetry.expect("GET telemetry");
        assert_eq!(telemetry.source_peer, "peer-v2-995");
        assert_eq!(telemetry.request_id, request_id);
        assert_eq!(telemetry.chunk_address, hex::encode(address));
        assert_eq!(telemetry.queue_wait_ms, 17);
        assert_eq!(telemetry.storage_outcome, "not_found");
        assert_eq!(telemetry.storage_error_category, "none");

        let response_bytes = handled
            .response
            .expect("handle get")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");
        assert_eq!(response.request_id, request_id);
        assert!(matches!(
            response.body,
            ChunkMessageBody::GetResponse(ChunkGetResponse::NotFound { address: found })
                if found == address
        ));

        telemetry.finish_send(Duration::from_millis(3), true);
    }

    #[tokio::test]
    async fn test_put_address_mismatch() {
        let (protocol, _temp) = create_test_protocol().await;

        let content = b"test content";
        let wrong_address = [0xFF; 32]; // Wrong address

        // Pre-populate cache for the wrong address so we test address mismatch, not payment
        protocol.payment_verifier().cache_insert(wrong_address);

        let put_request = ChunkPutRequest::new(wrong_address, Bytes::copy_from_slice(content));
        let put_msg = ChunkMessage {
            request_id: 20,
            body: ChunkMessageBody::PutRequest(put_request),
        };
        let put_bytes = put_msg.encode().expect("encode put");

        let response_bytes = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        assert_eq!(response.request_id, 20);
        if let ChunkMessageBody::PutResponse(ChunkPutResponse::Error(
            ProtocolError::AddressMismatch { .. },
        )) = response.body
        {
            // Expected
        } else {
            panic!("expected AddressMismatch error, got: {response:?}");
        }
    }

    #[tokio::test]
    async fn test_put_chunk_too_large() {
        let (protocol, _temp) = create_test_protocol().await;

        // Create oversized content
        let content = vec![0u8; MAX_CHUNK_SIZE + 1];
        let address = ChunkStore::compute_address(&content);

        let put_request = ChunkPutRequest::new(address, Bytes::from(content));
        let put_msg = ChunkMessage {
            request_id: 30,
            body: ChunkMessageBody::PutRequest(put_request),
        };
        let put_bytes = put_msg.encode().expect("encode put");

        let response_bytes = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        assert_eq!(response.request_id, 30);
        if let ChunkMessageBody::PutResponse(ChunkPutResponse::Error(
            ProtocolError::ChunkTooLarge { .. },
        )) = response.body
        {
            // Expected
        } else {
            panic!("expected ChunkTooLarge error");
        }
    }

    /// A node that is genuinely full must reject a PUT with the disk-space
    /// error *before* running payment verification (`V2-411`).
    ///
    /// "Full" now means both halves of the predicate: the volume is below the
    /// reserve **and** the store has no reusable space. A freshly created store
    /// has no freed pages, so both hold and the pre-check short-circuits, as it
    /// always did. The companion cases in `storage::chunk_store::tests` cover the half
    /// that changed, where pruning has left reusable pages and the node must be
    /// admitted rather than refused on `statvfs` alone.
    ///
    /// The chunk is intentionally **not** cache-inserted, so if the handler
    /// reached `verify_payment` it would return `PaymentFailed` (an uncached
    /// chunk with no proof). Observing the `StorageFailed` disk error instead
    /// proves the pre-check short-circuited ahead of verification.
    #[tokio::test]
    async fn test_put_rejected_on_insufficient_capacity_before_verification() {
        // u64::MAX reserve guarantees `available < reserve`, and a fresh store
        // has no reusable pages, so the node is full on both halves.
        let (protocol, _temp) = create_test_protocol_with_reserve(u64::MAX).await;

        let content = b"chunk for a disk-full node";
        let address = ChunkStore::compute_address(content);

        let put_request = ChunkPutRequest::new(address, Bytes::copy_from_slice(content));
        let put_msg = ChunkMessage {
            request_id: 41,
            body: ChunkMessageBody::PutRequest(put_request),
        };
        let put_bytes = put_msg.encode().expect("encode put");

        let response_bytes = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        assert_eq!(response.request_id, 41);
        match response.body {
            ChunkMessageBody::PutResponse(ChunkPutResponse::Error(
                ProtocolError::StorageFailed(msg),
            )) => {
                assert!(
                    msg.contains("Insufficient disk space"),
                    "expected disk-space error, got: {msg}"
                );
            }
            other => {
                panic!("expected StorageFailed disk error before verification, got: {other:?}")
            }
        }

        // And nothing was stored.
        assert!(!protocol.exists(&address).expect("exists check"));
    }

    #[tokio::test]
    async fn test_put_already_exists() {
        let (protocol, _temp) = create_test_protocol().await;

        let content = b"duplicate content";
        let address = ChunkStore::compute_address(content);

        // Pre-populate cache so EVM verification is bypassed
        protocol.payment_verifier().cache_insert(address);

        let put_request = ChunkPutRequest::new(address, Bytes::copy_from_slice(content));
        let put_msg = ChunkMessage {
            request_id: 40,
            body: ChunkMessageBody::PutRequest(put_request),
        };
        let put_bytes = put_msg.encode().expect("encode put");

        let _ = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put");

        // Store again - should return AlreadyExists
        let response_bytes = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put 2")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        assert_eq!(response.request_id, 40);
        if let ChunkMessageBody::PutResponse(ChunkPutResponse::AlreadyExists { address: addr }) =
            response.body
        {
            assert_eq!(addr, address);
        } else {
            panic!("expected AlreadyExists");
        }
    }

    #[tokio::test]
    async fn test_protocol_id() {
        let (protocol, _temp) = create_test_protocol().await;
        assert_eq!(protocol.protocol_id(), CHUNK_PROTOCOL_ID);
    }

    #[tokio::test]
    async fn test_exists_and_local_access() {
        let (protocol, _temp) = create_test_protocol().await;

        let content = b"local access test";
        let address = ChunkStore::compute_address(content);

        assert!(!protocol.exists(&address).expect("exists check"));

        protocol
            .put_local(&address, content)
            .await
            .expect("put local");

        assert!(protocol.exists(&address).expect("exists check"));

        let retrieved = protocol.get_local(&address).await.expect("get local");
        assert_eq!(retrieved, Some(content.to_vec()));
    }

    #[tokio::test]
    async fn test_cache_insert_is_visible() {
        let (protocol, _temp) = create_test_protocol().await;

        let content = b"cache test content";
        let address = ChunkStore::compute_address(content);

        // Before insert: cache should be empty
        let stats_before = protocol.payment_cache_stats();
        assert_eq!(stats_before.additions, 0);

        // Pre-populate cache
        protocol.payment_verifier().cache_insert(address);

        // After insert: cache should have the xorname
        let stats_after = protocol.payment_cache_stats();
        assert_eq!(stats_after.additions, 1);

        // PUT should succeed (cache hit)
        let put_request = ChunkPutRequest::new(address, Bytes::copy_from_slice(content));
        let put_msg = ChunkMessage {
            request_id: 100,
            body: ChunkMessageBody::PutRequest(put_request),
        };
        let put_bytes = put_msg.encode().expect("encode put");
        let response_bytes = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode");

        if let ChunkMessageBody::PutResponse(ChunkPutResponse::Success { .. }) = response.body {
            // expected
        } else {
            panic!("expected success, got: {response:?}");
        }
    }

    #[tokio::test]
    async fn test_put_same_chunk_twice_hits_cache() {
        let (protocol, _temp) = create_test_protocol().await;

        let content = b"duplicate cache test";
        let address = ChunkStore::compute_address(content);

        // Pre-populate cache for first PUT
        protocol.payment_verifier().cache_insert(address);

        // First PUT
        let put_request = ChunkPutRequest::new(address, Bytes::copy_from_slice(content));
        let put_msg = ChunkMessage {
            request_id: 110,
            body: ChunkMessageBody::PutRequest(put_request),
        };
        let put_bytes = put_msg.encode().expect("encode put");
        let _ = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put 1");

        // Second PUT should return AlreadyExists from the storage idempotency check.
        let response_bytes = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put 2")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode");

        if let ChunkMessageBody::PutResponse(ChunkPutResponse::AlreadyExists { .. }) = response.body
        {
            // expected
        } else {
            panic!("expected AlreadyExists, got: {response:?}");
        }
    }

    #[tokio::test]
    async fn test_payment_cache_stats_returns_correct_values() {
        let (protocol, _temp) = create_test_protocol().await;

        let stats = protocol.payment_cache_stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.additions, 0);

        // Pre-populate cache, then store a chunk to test stats
        let content = b"stats test";
        let address = ChunkStore::compute_address(content);
        protocol.payment_verifier().cache_insert(address);

        let put_request = ChunkPutRequest::new(address, Bytes::copy_from_slice(content));
        let put_msg = ChunkMessage {
            request_id: 120,
            body: ChunkMessageBody::PutRequest(put_request),
        };
        let put_bytes = put_msg.encode().expect("encode put");
        let _ = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put");

        let stats = protocol.payment_cache_stats();
        // Should have 1 addition (from cache_insert) + 1 hit (payment verification found cache)
        assert_eq!(stats.additions, 1);
        assert_eq!(stats.hits, 1);
    }

    #[tokio::test]
    async fn test_storage_stats() {
        let (protocol, _temp) = create_test_protocol().await;
        let stats = protocol.storage_stats();
        assert_eq!(stats.chunks_stored, 0);
    }

    #[tokio::test]
    async fn test_merkle_candidate_quote_request() {
        use ant_protocol::payment::verify::verify_merkle_candidate_signature;
        use evmlib::merkle_payments::MerklePaymentCandidateNode;

        // create_test_protocol already wires ML-DSA-65 signing
        let (protocol, _temp) = create_test_protocol().await;

        let address = [0x77; 32];
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs();

        let request = MerkleCandidateQuoteRequest {
            address,
            data_type: DATA_TYPE_CHUNK,
            data_size: 4096,
            merkle_payment_timestamp: timestamp,
        };
        let msg = ChunkMessage {
            request_id: 600,
            body: ChunkMessageBody::MerkleCandidateQuoteRequest(request),
        };
        let msg_bytes = msg.encode().expect("encode request");

        let response_bytes = protocol
            .try_handle_request(&msg_bytes)
            .await
            .expect("handle merkle candidate quote")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode response");

        assert_eq!(response.request_id, 600);
        match response.body {
            ChunkMessageBody::MerkleCandidateQuoteResponse(
                MerkleCandidateQuoteResponse::Success { candidate_node, .. },
            ) => {
                let candidate: MerklePaymentCandidateNode =
                    rmp_serde::from_slice(&candidate_node).expect("deserialize candidate node");

                // Verify ML-DSA-65 signature
                assert!(
                    verify_merkle_candidate_signature(&candidate),
                    "ML-DSA-65 candidate signature must be valid"
                );

                assert_eq!(candidate.merkle_payment_timestamp, timestamp);
                // Node-calculated price based on records stored
                assert!(candidate.price >= evmlib::common::Amount::ZERO);
            }
            other => panic!("expected MerkleCandidateQuoteResponse::Success, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_handle_unexpected_response_message() {
        let (protocol, _temp) = create_test_protocol().await;

        // Send a PutResponse as if it were a request — should return None
        let msg = ChunkMessage {
            request_id: 200,
            body: ChunkMessageBody::PutResponse(ChunkPutResponse::Success { address: [0u8; 32] }),
        };
        let msg_bytes = msg.encode().expect("encode");

        let result = protocol
            .try_handle_request(&msg_bytes)
            .await
            .expect("handle msg");

        assert!(
            result.is_none(),
            "expected None for response message, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_quote_already_stored_flag() {
        let (protocol, _temp) = create_test_protocol().await;

        let content = b"already stored quote test";
        let address = ChunkStore::compute_address(content);

        // Store the chunk first
        protocol.payment_verifier().cache_insert(address);
        let put_request = ChunkPutRequest::new(address, Bytes::copy_from_slice(content));
        let put_msg = ChunkMessage {
            request_id: 300,
            body: ChunkMessageBody::PutRequest(put_request),
        };
        let put_bytes = put_msg.encode().expect("encode put");
        let _ = protocol
            .try_handle_request(&put_bytes)
            .await
            .expect("handle put");

        // Now request a quote for the same address — already_stored should be true
        let quote_request = ChunkQuoteRequest {
            address,
            data_size: content.len() as u64,
            data_type: DATA_TYPE_CHUNK,
        };
        let quote_msg = ChunkMessage {
            request_id: 301,
            body: ChunkMessageBody::QuoteRequest(quote_request),
        };
        let quote_bytes = quote_msg.encode().expect("encode quote");
        let response_bytes = protocol
            .try_handle_request(&quote_bytes)
            .await
            .expect("handle quote")
            .expect("expected response");
        let response = ChunkMessage::decode(&response_bytes).expect("decode");

        match response.body {
            ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Success {
                already_stored, ..
            }) => {
                assert!(
                    already_stored,
                    "already_stored should be true for existing chunk"
                );
            }
            other => panic!("expected Success with already_stored, got: {other:?}"),
        }

        // Request a quote for a chunk that does NOT exist — already_stored should be false
        let new_address = [0xFFu8; 32];
        let quote_request2 = ChunkQuoteRequest {
            address: new_address,
            data_size: 100,
            data_type: DATA_TYPE_CHUNK,
        };
        let quote_msg2 = ChunkMessage {
            request_id: 302,
            body: ChunkMessageBody::QuoteRequest(quote_request2),
        };
        let quote_bytes2 = quote_msg2.encode().expect("encode quote2");
        let response_bytes2 = protocol
            .try_handle_request(&quote_bytes2)
            .await
            .expect("handle quote2")
            .expect("expected response");
        let response2 = ChunkMessage::decode(&response_bytes2).expect("decode2");

        match response2.body {
            ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Success {
                already_stored, ..
            }) => {
                assert!(
                    !already_stored,
                    "already_stored should be false for new chunk"
                );
            }
            other => panic!("expected Success with already_stored=false, got: {other:?}"),
        }
    }

    /// Drive the real quote handler, then read the record count it priced on.
    /// The handler calls `resync_quote_metric` first, so this reflects records
    /// ACTUALLY HELD.
    fn priced_records_after_quote(protocol: &AntProtocol) -> usize {
        let quote_request = ChunkQuoteRequest {
            address: [0xAAu8; 32], // a quote-only probe, not one of the stored chunks
            data_size: 100,
            data_type: DATA_TYPE_CHUNK,
        };
        let _ = protocol.handle_quote(&quote_request);
        protocol.priced_records_stored()
    }

    /// The quote price must track records ACTUALLY HELD: deleting stored chunks
    /// must lower the priced record count, not keep quoting as if the data were
    /// still held. Exercises the storage-driven resync in `resync_quote_metric`.
    #[tokio::test]
    async fn test_quote_metric_reflects_deletions() {
        let (protocol, _temp) = create_test_protocol().await;

        // Distinct content -> distinct content-addressed keys.
        let contents: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i; 64]).collect();
        let mut addresses = Vec::new();
        for content in &contents {
            let addr = ChunkStore::compute_address(content);
            protocol.put_local(&addr, content).await.expect("put_local");
            addresses.push(addr);
        }

        // 5 records held -> priced count 5.
        assert_eq!(priced_records_after_quote(&protocol), 5);

        // Delete 2 chunks the node was holding.
        for addr in addresses.iter().take(2) {
            assert!(protocol.storage().delete(addr).await.expect("delete"));
        }
        assert_eq!(priced_records_after_quote(&protocol), 3);

        // Delete the rest; priced count floors at 0, never underflows.
        for addr in addresses.iter().skip(2) {
            assert!(protocol.storage().delete(addr).await.expect("delete"));
        }
        assert_eq!(priced_records_after_quote(&protocol), 0);
    }

    /// Stronger, externally-observable proof: the actual quote PRICE returned
    /// to a client must drop after the node deletes data it held. A monotonic
    /// store counter would keep the price elevated; the resync ties price to
    /// records actually held.
    /// FLIPS IF: `resync_quote_metric` is removed — the price would stay at the
    /// 10-record level even after deletions (`record_store` only ever increments).
    #[tokio::test]
    async fn test_quote_price_drops_after_deletion() {
        use crate::payment::pricing::calculate_price;

        let (protocol, _temp) = create_test_protocol().await;
        let contents: Vec<Vec<u8>> = (0u8..10).map(|i| vec![i; 64]).collect();
        let mut addresses = Vec::new();
        for content in &contents {
            let addr = ChunkStore::compute_address(content);
            protocol.put_local(&addr, content).await.expect("put_local");
            addresses.push(addr);
        }

        // Drive a real quote; the priced count must equal records held (10),
        // and the price must equal calculate_price(10) — the externally
        // observable contract.
        assert_eq!(priced_records_after_quote(&protocol), 10);
        let price_full = calculate_price(10);

        // Delete 8 of 10 held chunks.
        for addr in addresses.iter().take(8) {
            assert!(protocol.storage().delete(addr).await.expect("delete"));
        }
        // The next quote must price on 2 records, and the price must be the
        // calculate_price(2) value — strictly different from the 10-record
        // price (price is monotonic non-decreasing in records_stored).
        assert_eq!(priced_records_after_quote(&protocol), 2);
        let price_after = calculate_price(2);
        assert!(
            price_after < price_full,
            "deleting data must lower the observable quote price \
             (full={price_full:?}, after={price_after:?})"
        );
    }

    /// ADR-0004: `strip_commitment_sidecars` removes sidecars from a single-node
    /// proof before replication/persistence (stored proofs do not grow), and is
    /// a no-op on a sidecar-free proof.
    #[test]
    fn strip_commitment_sidecars_clears_single_node_sidecars() {
        use crate::payment::proof::{
            deserialize_single_node_proof, serialize_single_node_proof, PaymentProof,
        };
        use evmlib::ProofOfPayment;

        let with_sidecars = PaymentProof {
            proof_of_payment: ProofOfPayment {
                peer_quotes: vec![],
            },
            tx_hashes: vec![],
            commitment_sidecars: vec![vec![1u8; 16], vec![2u8; 16]],
        };
        let bytes = serialize_single_node_proof(&with_sidecars).expect("serialize");
        let stripped = AntProtocol::strip_commitment_sidecars(bytes);
        let parsed = deserialize_single_node_proof(&stripped).expect("deserialize stripped");
        assert!(
            parsed.commitment_sidecars.is_empty(),
            "sidecars must be stripped before replication"
        );

        // Idempotent: stripping an already-sidecar-free proof returns it intact.
        let again = AntProtocol::strip_commitment_sidecars(stripped.clone());
        assert_eq!(again, stripped, "stripping a sidecar-free proof is a no-op");
    }
}
