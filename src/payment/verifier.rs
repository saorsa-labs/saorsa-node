//! Payment verifier with LRU cache and EVM verification.
//!
//! This is the core payment verification logic for ant-node.
//! All new data requires EVM payment on Arbitrum (no free tier).

use crate::ant_protocol::CLOSE_GROUP_SIZE;
use crate::error::{Error, Result};
use crate::logging::{debug, info, warn};
use crate::payment::cache::{CacheStats, VerifiedCache, XorName};
use crate::payment::pricing::{calculate_price, derive_records_stored_from_price};
use crate::payment::proof::{
    deserialize_merkle_proof, deserialize_single_node_proof, detect_proof_type, ProofType,
};
use crate::replication::commitment::MAX_COMMITMENT_KEY_COUNT;
use crate::replication::config::K_BUCKET_SIZE;
use crate::storage::lmdb::LmdbStorage;
use ant_protocol::payment::verify::{verify_quote_content, verify_quote_signature};
use evmlib::common::{Amount, QuoteHash};
use evmlib::contract::payment_vault;
use evmlib::merkle_batch_payment::{OnChainPaymentInfo, PoolHash};
use evmlib::Network as EvmNetwork;
use evmlib::PaymentQuote;
use evmlib::ProofOfPayment;
use evmlib::RewardsAddress;
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use saorsa_core::identity::node_identity::peer_id_from_public_key_bytes;
use saorsa_core::identity::PeerId;
use saorsa_core::P2PNode;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;

/// Minimum allowed size for a payment proof in bytes.
///
/// This minimum ensures the proof contains at least a basic cryptographic hash or identifier.
/// Proofs smaller than this are rejected as they cannot contain sufficient payment information.
pub const MIN_PAYMENT_PROOF_SIZE_BYTES: usize = 32;

/// Maximum allowed size for a payment proof in bytes (512 KB).
///
/// Single-node proofs with 7 ML-DSA-65 quotes reach ~40 KB; with ADR-0004
/// commitment sidecars (one ~5.3 KB commitment per bound quote, ~13 KB each
/// after rmp encoding) they reach ~150 KB.
/// Merkle proofs include 16 candidate nodes (each with ~1,952-byte ML-DSA pub
/// key and ~3,309-byte signature) plus merkle branch hashes, totaling ~130 KB.
/// A merkle proof that ALSO ships all 16 commitment sidecars (clients built
/// before the sidecars were dropped from the per-chunk bundle) reaches
/// ~342 KB — the previous 256 KB cap rejected every such PUT the moment nodes
/// carried live commitments, which is exactly how it was discovered.
/// 512 KB accepts every shape above with headroom while still capping memory
/// during verification.
pub const MAX_PAYMENT_PROOF_SIZE_BYTES: usize = 524_288;

const PAID_QUOTE_PAYMENT_MULTIPLIER: u64 = 3;
const PAYMENT_VERIFY_SLOW_LOG_MS: u128 = 500;

/// Number of nearest DHT peers accepted for paid-quote issuer locality.
///
/// This is the Kademlia K width, intentionally wider than `CLOSE_GROUP_SIZE`.
const PAID_QUOTE_ISSUER_CLOSENESS_WIDTH: usize = K_BUCKET_SIZE;

/// Default tolerance for the receiver-side price floor, as a percentage of the
/// close group's MEDIAN commitment-bound price (see
/// [`PaymentVerifier::group_reference_price`]).
///
/// Derived from production, not chosen: on ant-prod-01 over 2026-07-29..08-04,
/// pricing each receiver against its OWN price rejected 0.377% of honest stores
/// while still admitting the cheapest-of-K underpayment at 62.9% of receivers,
/// because node prices span ~4x across the fleet and an honest client pays the
/// group median. Against the group median instead, honest payments land near the
/// reference and the underpayment lands well below it, so a tolerance separates
/// them.
///
/// At the minimum permitted view, 65% rejects 0.140% of honest payments while
/// catching ~90% of underpayment, against the own-price floor's measured 0.377%
/// and 37.1%. Both axes improve, by roughly 2.7x on rejections rather than the
/// order of magnitude an earlier revision claimed. 60% is the conservative
/// alternative: 5x safer on honest traffic, at 66% detection.
///
/// The full sweep, the sample-size table and the simulation's assumptions live
/// in ADR-0006 — deliberately in one place, because the same tables
/// duplicated here and in the ADR had already drifted apart once. Tighten or
/// loosen only from observed shadow telemetry, never speculatively.
const PRICE_FLOOR_DEFAULT_TOLERANCE_PERCENT: u64 = 65;

/// Minimum number of fresh NEIGHBOUR commitments (this node's own is counted
/// separately) required before the price floor will evaluate at all.
///
/// Below this the local view is too thin for a median to mean anything (fresh
/// start, post-churn, a gossip cache that has not filled), so the floor SKIPS
/// rather than guessing. Skipping is the safe direction: the cost is a missed
/// underpayment, whereas guessing from a handful of peers rejects honest stores
/// whose payment already settled on-chain and cannot be refunded.
///
/// The value is not a round number chosen by feel. A median over a small sample
/// of a distribution this wide is unstable, and the floor is *more* dangerous
/// than the own-price reference it replaces until the sample is large: at 3
/// neighbours it rejects 2.0% of honest stores, at 7 it rejects 0.6%, and only
/// past about 11 does it beat the 0.377% the own-price floor measured in
/// production. The gate therefore sits at 15 of the
/// [`PAID_QUOTE_ISSUER_CLOSENESS_WIDTH`] closest, with the full table in
/// ADR-0006.
///
/// Availability cost is expected to be small — the gossip TTL is hours against a
/// much shorter sweep, so a settled node should normally know most of its
/// neighbours — but that is an assumption, not a measurement, and the sample is
/// drawn from peers close to the CHUNK while the cache is filled from peers
/// close to THIS NODE, so edge-of-range chunks will skip more often. The
/// `skipped=true` / `skip_reason` telemetry exists to measure that in shadow
/// mode before anyone enforces.
///
/// A node that could suppress its neighbours' gossip can therefore disable this
/// receiver's floor, but cannot make it reject honest traffic. That asymmetry is
/// deliberate.
const PRICE_FLOOR_MIN_NEIGHBOUR_COMMITMENTS: usize = 15;

/// Why a price-floor evaluation did not produce a reference price.
///
/// Shadow mode exists to calibrate
/// [`PRICE_FLOOR_MIN_NEIGHBOUR_COMMITMENTS`] from real deployments, and these
/// three causes call for completely different responses: a mid-rotation node is
/// expected and self-correcting, an unwired cache is a startup-order bug, and a
/// persistently thin sample means the gate is set above what the network can
/// supply. Collapsing them into one counter would make the telemetry unable to
/// answer the only question it is there to answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SkipReason {
    /// The gossip commitment cache is not attached.
    NoCommitmentCache,
    /// No local routing view of the close group (no P2P handle attached).
    NoRoutingView,
    /// This node has no live commitment of its own.
    NoOwnCommitment,
    /// Fewer fresh neighbour commitments than the gate requires.
    ThinSample,
}

impl SkipReason {
    /// Only ever called from the price-floor telemetry, which compiles to
    /// nothing without the `logging` feature.
    #[cfg_attr(not(feature = "logging"), allow(dead_code))]
    const fn as_str(self) -> &'static str {
        match self {
            Self::NoCommitmentCache => "no_commitment_cache",
            Self::NoRoutingView => "no_routing_view",
            Self::NoOwnCommitment => "no_own_commitment",
            Self::ThinSample => "thin_sample",
        }
    }
}

/// What the price floor could see of the close group on one admission.
///
/// `neighbours` is the quantity the gate actually tests; `total` includes this
/// node's own commitment and is what the median is taken over. Both are logged
/// because reporting only the total makes `group_sample=15, skipped=true` look
/// like a contradiction when it is simply 14 neighbours plus self.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GroupSample {
    neighbours: usize,
    total: usize,
    skip_reason: Option<SkipReason>,
}

impl GroupSample {
    const fn none(reason: SkipReason) -> Self {
        Self {
            neighbours: 0,
            total: 0,
            skip_reason: Some(reason),
        }
    }

    const fn skipped(self, reason: SkipReason) -> Self {
        Self {
            skip_reason: Some(reason),
            ..self
        }
    }

    /// Only ever called from the price-floor telemetry, which compiles to
    /// nothing without the `logging` feature.
    #[cfg_attr(not(feature = "logging"), allow(dead_code))]
    fn skip_reason_str(self) -> &'static str {
        self.skip_reason.map_or("none", SkipReason::as_str)
    }
}

/// Environment variable enabling price-floor ENFORCEMENT (`1`/`true`).
///
/// Absent or any other value means shadow mode: the floor is computed and
/// logged, never enforced. Per-node so enforcement can roll out canary-first;
/// unsetting it (and restarting) is the kill switch.
pub const PRICE_FLOOR_ENFORCE_ENV: &str = "ANT_PRICE_FLOOR_ENFORCE";

/// Environment variable overriding the price-floor tolerance percentage
/// (`0..=100`). Invalid or absent values use the default.
pub const PRICE_FLOOR_TOLERANCE_ENV: &str = "ANT_PRICE_FLOOR_TOLERANCE_PERCENT";

/// Receiver-side price floor for single-node store admissions.
///
/// ADR-0004 gives every quote a price CEILING (`price ==
/// calculate_price(committed_key_count)`), but a ceiling is not a revenue
/// floor: a modified client can fetch quotes from the whole neighbourhood and
/// settle only the cheapest valid one in a 1-quote proof. This policy is the
/// floor half: the settled amount must also clear the close group's MEDIAN
/// commitment-bound price, scaled by a tolerance.
///
/// The reference is the group's median rather than this receiver's own price.
/// A client pays `3x` the median of the quotes it collected, so comparing that
/// to a single node's price compares a median to one draw from a distribution
/// spanning ~4x — which in production rejected honest stores on the fullest
/// nodes while admitting underpayment at the emptiest. The reference is built
/// only from this node's own commitment and its neighbours' TTL-fresh gossiped
/// ones, never from the payment bundle.
///
/// Rollout is shadow-first: with `enforce == false` (the default) the floor
/// is evaluated and logged on every single-node store admission but never
/// rejects. Enforcement is enabled per node via [`PRICE_FLOOR_ENFORCE_ENV`]
/// for canary rollout. A floor rejection is an economic admission decision
/// only — it must never feed trust/misbehaviour scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceFloorConfig {
    /// When true, a below-floor settled payment is rejected. When false
    /// (default), the verifier only logs would-reject telemetry.
    pub enforce: bool,
    /// Floor as a percentage of the close group's median commitment-bound
    /// price (`0..=100`).
    pub tolerance_percent: u64,
}

impl Default for PriceFloorConfig {
    fn default() -> Self {
        Self {
            enforce: false,
            tolerance_percent: PRICE_FLOOR_DEFAULT_TOLERANCE_PERCENT,
        }
    }
}

impl PriceFloorConfig {
    /// Build from the environment (see [`PRICE_FLOOR_ENFORCE_ENV`] and
    /// [`PRICE_FLOOR_TOLERANCE_ENV`]). Never panics.
    ///
    /// An unset tolerance uses the default. A tolerance that is *present but
    /// invalid* (unparseable or `> 100`) is an operator error: rather than
    /// silently enforce at the default, this **fails closed to shadow mode**
    /// (`enforce = false`) and logs a prominent error, so a fat-fingered
    /// tolerance can never enforce an unintended floor against real payments.
    #[must_use]
    pub fn from_env() -> Self {
        let enforce_requested = std::env::var(PRICE_FLOOR_ENFORCE_ENV)
            .is_ok_and(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "True"));

        let tolerance_raw = std::env::var(PRICE_FLOOR_TOLERANCE_ENV).ok();
        let valid_tolerance = tolerance_raw
            .as_deref()
            .map(str::trim)
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|percent| *percent <= 100);
        // A tolerance that is set but does not parse to `0..=100` is an operator
        // error. Fail CLOSED: never enforce a tolerance the operator did not
        // actually specify.
        let tolerance_present_but_invalid = tolerance_raw.is_some() && valid_tolerance.is_none();

        if tolerance_present_but_invalid {
            if enforce_requested {
                crate::logging::error!(
                    "{PRICE_FLOOR_TOLERANCE_ENV}={tolerance_raw:?} is not an integer in 0..=100; \
                     refusing to enforce the price floor with an unspecified tolerance. \
                     Price-floor enforcement DISABLED (shadow mode). Fix the value and restart \
                     to enable enforcement."
                );
            } else {
                crate::logging::warn!(
                    "{PRICE_FLOOR_TOLERANCE_ENV}={tolerance_raw:?} is not an integer in 0..=100; \
                     using the default {PRICE_FLOOR_DEFAULT_TOLERANCE_PERCENT}% for shadow-mode \
                     telemetry."
                );
            }
        }

        Self {
            enforce: enforce_requested && !tolerance_present_but_invalid,
            tolerance_percent: valid_tolerance.unwrap_or(PRICE_FLOOR_DEFAULT_TOLERANCE_PERCENT),
        }
    }
}

#[derive(Clone, Copy)]
struct LegacyMedianCandidate<'a> {
    encoded_peer_id: &'a evmlib::EncodedPeerId,
    quote: &'a PaymentQuote,
    expected_amount: Amount,
}

fn median_quote_index(quote_count: usize) -> usize {
    quote_count / 2
}

/// The settlement multiplier a merkle receipt must satisfy, from the instant it
/// was stamped (ADR-0008).
///
/// `PAID_QUOTE_PAYMENT_MULTIPLIER` (3x, matching the single-node path) for a
/// receipt stamped at or after `enforced_from`; the historic `1` for one
/// stamped before it, which was bought under the previous rule and cannot be
/// refunded.
///
/// The boundary needs no sunset logic because receipt expiry supplies it: a
/// receipt older than one week is refused regardless, so once
/// `enforced_from + one week` has passed no valid receipt can still reach the
/// `1` branch.
///
/// Expiry bounds backdating rather than preventing it. The stamp is
/// client-chosen and quoting nodes sign what they are asked for, so during the
/// week after `enforced_from` a modified client can stamp just before the
/// boundary and still settle at 1x — the same route honest in-flight receipts
/// take. It closes when such stamps expire, at `enforced_from + one week`, and
/// it cannot be narrowed without also refusing receipts bought in good faith
/// under the previous rule.
fn merkle_required_multiplier(receipt_timestamp: u64, enforced_from: u64) -> u64 {
    if receipt_timestamp >= enforced_from {
        PAID_QUOTE_PAYMENT_MULTIPLIER
    } else {
        1
    }
}

/// Per-node payment implied by the merkle contract formula, for a given
/// payment multiplier.
///
/// The contract settles `total = median16(amount) x 2^depth` and splits it
/// evenly across the `depth` nodes it paid, so
/// `per_node = multiplier x median16(price) x 2^depth / depth`.
///
/// `candidate_prices` are the candidates' **signed quoted** prices as they
/// appear in the proof — always 1x, because the multiplier is applied by the
/// client to the on-chain payable `amount` and never to the signed quote
/// (ADR-0008). Passing `multiplier = 1` therefore reproduces the historic
/// merkle expectation, and `PAID_QUOTE_PAYMENT_MULTIPLIER` the single-node
/// parity expectation.
///
/// `median16` is the upper median (index `len / 2`), matching Solidity's
/// `median16` with `k = 8`. Depth `0` yields zero: there is nothing to pay.
///
/// **Not linear in `multiplier`.** The trailing `/ depth` is integer division,
/// so `expected(m)` is `floor(m x median x 2^depth / depth)`, which is NOT
/// generally `m x expected(1)` — the two differ by up to `m - 1` wei whenever
/// `depth` does not divide `median x 2^depth`. For example median 901 at depth
/// 7 gives `expected(3) = 49426` but `3 x expected(1) = 49425`. Callers must
/// therefore ask for the multiplier they mean and compare against that value;
/// scaling a 1x result is wrong. The order here — multiply the total, then
/// divide once — is deliberate, and matches the contract, which computes
/// `totalAmount` before splitting it.
fn merkle_expected_per_node(
    candidate_prices: &[Amount],
    depth: u8,
    multiplier: u64,
) -> Result<Amount> {
    if depth == 0 {
        return Ok(Amount::ZERO);
    }

    let mut sorted = candidate_prices.to_vec();
    sorted.sort_unstable(); // ascending
    let median_price = *sorted
        .get(sorted.len() / 2)
        .ok_or_else(|| Error::Payment("empty candidate pool in merkle proof".into()))?;

    let leaves = 1u64
        .checked_shl(u32::from(depth))
        .ok_or_else(|| Error::Payment("merkle proof depth too large".into()))?;

    let total_amount = median_price
        .checked_mul(Amount::from(leaves))
        .and_then(|total| total.checked_mul(Amount::from(multiplier)))
        .ok_or_else(|| Error::Payment("merkle total payment overflow".into()))?;

    Ok(total_amount / Amount::from(u64::from(depth)))
}

fn payment_proof_type_label(payment_proof: Option<&[u8]>) -> &'static str {
    match payment_proof.and_then(detect_proof_type) {
        Some(ProofType::Merkle) => "merkle",
        Some(ProofType::SingleNode) => "single_node",
        Some(_) => "unsupported",
        None if payment_proof.is_some() => "unknown",
        None => "none",
    }
}

/// Configuration for EVM payment verification.
///
/// EVM verification is always on. All new data requires on-chain
/// payment verification. The network field selects which EVM chain to use.
#[derive(Debug, Clone)]
pub struct EvmVerifierConfig {
    /// EVM network to use (Arbitrum One, Arbitrum Sepolia, etc.)
    pub network: EvmNetwork,
}

impl Default for EvmVerifierConfig {
    fn default() -> Self {
        Self {
            network: EvmNetwork::ArbitrumOne,
        }
    }
}

/// Configuration for the payment verifier.
///
/// All new data requires EVM payment on Arbitrum. The cache stores
/// previously verified payments to avoid redundant on-chain lookups.
#[derive(Debug, Clone)]
pub struct PaymentVerifierConfig {
    /// EVM verifier configuration.
    pub evm: EvmVerifierConfig,
    /// Cache capacity (number of `XorName` values to cache).
    pub cache_capacity: usize,
    /// Close-group width exposed to storage and replication admission callers.
    pub close_group_size: usize,
    /// Local node's rewards address.
    ///
    /// Kept in the verifier config for payment policies that bind receipts to
    /// this node's payout address.
    pub local_rewards_address: RewardsAddress,
    /// Receiver-side price floor policy (shadow mode by default).
    pub price_floor: PriceFloorConfig,
}

/// The fresh admission path a payment proof is being verified for.
///
/// - **`ClientPut`** — the node is admitting a chunk store from a direct
///   client PUT. The verifier applies store-strength cache semantics and live
///   payment checks.
/// - **`FreshReplication`** — the node is admitting a chunk store via the
///   immediate fresh-write fan-out. The receiver is about to store the newly
///   written chunk as if the client PUT it there directly, so this context is
///   verified EXACTLY like `ClientPut` (store-strength cache semantics, same
///   live checks, same price-floor policy). It exists as a separate variant so
///   price-floor telemetry can distinguish direct ingress from fan-out — the
///   two paths can legitimately diverge during commitment rotation, and the
///   floor policy for fan-out must be tunable from observed data without
///   touching direct-PUT behaviour.
/// - **`PaidListAdmission`** — the node is admitting fresh paid-list metadata.
///   It runs the same live payment checks, but writes a weaker cache entry
///   that does not authorize future chunk stores. The price floor never
///   applies here: paid-list records reprice no fresh economic decision.
///
/// The caller must check local receiver/admission membership before invoking
/// the verifier for replication admission: fresh chunk replication requires
/// local close-group responsibility, and fresh paid-list replication requires
/// local paid-list close-group membership. Direct client PUT deliberately does
/// not perform a receiver-responsibility gate. The verifier itself only checks
/// payment proof validity and that the paid quote's issuer is in the K closest
/// peers for the quoted chunk address.
///
/// Later neighbour-sync repair does not include proof-of-payment bytes and
/// does not call this verifier. It authorizes repair from network evidence:
/// majority storage among the configured close group, or majority paid-list
/// membership among the closest K.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationContext {
    /// The node is admitting a chunk store from a direct client PUT, with
    /// store-strength cache semantics.
    ClientPut,
    /// The node is admitting a chunk store via immediate fresh replication —
    /// verified identically to `ClientPut`, split out for price-floor
    /// telemetry and policy.
    FreshReplication,
    /// The node is admitting fresh paid-list metadata with paid-list-strength
    /// cache semantics.
    PaidListAdmission,
}

impl VerificationContext {
    /// True for contexts that admit chunk BYTES with store-strength cache
    /// semantics: direct client PUT and immediate fresh replication. These two
    /// are verified identically everywhere — the only policy that reads the
    /// variant itself (rather than this predicate) is price-floor telemetry.
    #[must_use]
    pub fn is_store_admission(self) -> bool {
        matches!(self, Self::ClientPut | Self::FreshReplication)
    }
}

/// Status returned by payment verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentStatus {
    /// Data was found in local cache - previously paid.
    CachedAsVerified,
    /// New data - payment required.
    PaymentRequired,
    /// Payment was provided and verified.
    PaymentVerified,
}

/// Outcome of the ADR-0004 quote-vs-commitment cross-check (see
/// [`PaymentVerifier::cross_check_binding`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossCheck {
    /// Pin resolves to the commitment and the counts agree: nothing to report.
    Match,
    /// Pin resolves to the commitment but the claimed and committed counts
    /// disagree: deterministic, first-occurrence contradiction (evidence).
    Mismatch {
        /// The key count the quote claimed.
        quoted_key_count: u32,
        /// The key count the pinned commitment actually attests.
        committed_key_count: u32,
    },
    /// The supplied commitment does not hash to the quote's pin: the pin is
    /// unresolved (treat as fetch/skip), never evidence.
    PinDoesNotResolve,
}

impl PaymentStatus {
    /// Returns true if the data can be stored (cached or payment verified).
    #[must_use]
    pub fn can_store(&self) -> bool {
        matches!(self, Self::CachedAsVerified | Self::PaymentVerified)
    }

    /// Returns true if this status indicates the data was already paid for.
    #[must_use]
    pub fn is_cached(&self) -> bool {
        matches!(self, Self::CachedAsVerified)
    }
}

/// Default capacity for the merkle pool cache (number of pool hashes to cache).
const DEFAULT_POOL_CACHE_CAPACITY: usize = 1_000;

/// Capacity of the ADR-0008 parity-telemetry first-emission cache: how many
/// recently measured pool hashes this node remembers in order to emit one
/// sample per settlement instead of one per admitted chunk.
///
/// Bounded, and deliberately its own cache rather than a flag on the pool
/// cache: the pool cache is populated as soon as the on-chain record is read,
/// which happens *before* the paid indices, addresses and amounts are checked,
/// so keying first-emission off it would let a proof that is rejected moments
/// later suppress (or produce) a sample. This one is written only after full
/// admission validation.
///
/// LRU eviction means a pool that goes quiet for more than
/// `MERKLE_PARITY_TELEMETRY_CACHE_CAPACITY` distinct pools can be sampled a
/// second time. That is the intended trade: the cache bounds memory, and the
/// stream stays deduplicable by `pool` downstream.
const MERKLE_PARITY_TELEMETRY_CACHE_CAPACITY: usize = 1_000;

/// ADR-0004: max commitment sidecars processed per bundle. A legitimate bundle
/// carries at most one commitment per quote/candidate — `CANDIDATES_PER_POOL`
/// (16) is the larger of the single-node (`CLOSE_GROUP_SIZE` = 7) and merkle
/// cases, so it covers both. Excess sidecars from a malicious client are
/// ignored before any deserialize/verify work (bounds the hot-path cost).
const MAX_SIDECARS_PER_BUNDLE: usize = evmlib::merkle_batch_payment::CANDIDATES_PER_POOL;

/// Shared handle to the replication engine's gossip commitment cache
/// (`last_commitment_by_peer`), used by the ADR-0004 cross-check to resolve a
/// quote's pin against a neighbour's recently gossiped commitment. A `tokio`
/// `RwLock` to match the engine's; read with `.await` on the async path.
type CommitmentCache = Arc<
    tokio::sync::RwLock<
        HashMap<PeerId, crate::replication::commitment_state::PeerCommitmentRecord>,
    >,
>;

/// Per-`(peer, pin)` negative cache for unresolved ADR-0004 pin fetches: a pin a
/// peer answered `NotRetained` (or that timed out) is remembered so repeated
/// bundles don't re-fetch it. Behind an `Arc` so the detached fetch task owns a
/// handle without borrowing the verifier.
type PinFetchNegativeCache = Arc<Mutex<LruCache<(PeerId, [u8; 32]), ()>>>;

/// Test-override shape for one on-chain settlement: the settled amount and
/// the recorded `bytes16` rewards-address prefix (`None` = matches the quote).
#[cfg(any(test, feature = "test-utils"))]
type TestSettlementOverride = (Amount, Option<[u8; 16]>);

/// Main payment verifier for ant-node.
///
/// Uses:
/// 1. LRU cache for fast lookups of previously verified `XorName` values
/// 2. EVM payment verification for new data (always required)
/// 3. Pool-level cache for merkle batch payments (avoids repeated on-chain queries)
pub struct PaymentVerifier {
    /// LRU cache of verified `XorName` values.
    cache: VerifiedCache,
    /// LRU cache of verified merkle pool hashes → on-chain payment info.
    pool_cache: Mutex<LruCache<PoolHash, OnChainPaymentInfo>>,
    /// LRU cache of pool hashes whose candidate closeness has already been
    /// verified by this node. Collapses the per-chunk Kademlia lookup cost
    /// within a batch (256 chunks × 1 pool = 1 lookup instead of 256).
    closeness_pass_cache: Mutex<LruCache<PoolHash, ()>>,
    /// In-flight closeness lookups, keyed by pool hash. Lets concurrent PUTs
    /// for the same pool coalesce onto a single Kademlia lookup AND share
    /// its result — on both success and failure — which bounds `DoS`
    /// amplification to one lookup per unique `pool_hash` regardless of
    /// concurrency.
    inflight_closeness: Mutex<LruCache<PoolHash, Arc<ClosenessSlot>>>,
    /// P2P node handle, attached post-construction so paid-quote verification
    /// can check paid-quote issuer K-closeness, and merkle verification can
    /// check that candidate `pub_keys` map to peers actually close to the pool
    /// midpoint in the live DHT. `None` in unit tests that don't exercise
    /// live-DHT checks; production startup MUST call [`attach_p2p_node`].
    p2p_node: RwLock<Option<Arc<P2PNode>>>,
    /// LMDB storage handle, attached post-construction. Retained for
    /// store-backed verifier checks that need the authoritative on-disk record
    /// count without depending on a side counter that may drift from
    /// replication/repair/prune paths. NOTE: the ADR-0006 price floor does NOT
    /// read this — it is bound to the live storage commitment via
    /// [`Self::local_commitment_source`], not the on-disk count (the old floor
    /// compared unlike counts and false-rejected honest quotes). `None` in unit
    /// tests that don't exercise store-backed checks; production wires it via
    /// [`Self::attach_storage`].
    storage: RwLock<Option<Arc<LmdbStorage>>>,
    /// Test-only override for the paid-quote issuer K-closest check.
    ///
    /// Production code derives closest peers from the attached [`P2PNode`].
    #[cfg(any(test, feature = "test-utils"))]
    test_paid_quote_k_closest_override: RwLock<Option<Vec<[u8; 32]>>>,
    /// Test-only override for `completedPayments(quote_hash)`.
    ///
    /// Production always queries the payment vault; unit tests use this to
    /// exercise the full verifier path without starting an EVM chain. Maps a
    /// quote hash to the settled amount plus the recorded rewards-address
    /// prefix (`None` means "matches the quote", the honest-settlement
    /// default). The prefix is 16 bytes because the vault packs the address
    /// as `bytes16` in the `completedPayments` slot.
    #[cfg(any(test, feature = "test-utils"))]
    test_completed_payments_override: RwLock<HashMap<QuoteHash, TestSettlementOverride>>,
    // NOTE: the test-only own-peer-id override was removed with the ADR-retired
    // quote-freshness/staleness gate (ADR-0004 binds price to the committed
    // count instead), so it no longer has any reader.
    /// ADR-0004 gossip commitment cache, shared with the replication engine
    /// (`last_commitment_by_peer`). The cross-check resolves a quote's
    /// `commitment_pin` against the neighbour's most recently gossiped
    /// commitment held here, *only if seen within the answerability TTL*;
    /// otherwise the pin is treated as unknown (fetch/skip), never a penalty.
    /// A `tokio` `RwLock` to match the engine's; read with `.await` on the
    /// async verification path. `None` until [`Self::attach_commitment_cache`]
    /// (unit tests, or pre-replication startup).
    commitment_cache: RwLock<Option<CommitmentCache>>,
    /// ADR-0004 negative cache for unresolved pin fetches: a `(peer, pin)` that
    /// resolved to `NotRetained` or timed out is remembered here so repeated
    /// bundles citing the same unknown pin don't re-fetch (bounding the
    /// amplification an attacker can drive). Keyed by `(PeerId, pin)`. Behind an
    /// `Arc` so the detached background fetch task (which runs off the payment
    /// hot path) can read and update it without borrowing the verifier.
    pin_fetch_negative_cache: PinFetchNegativeCache,
    /// ADR-0004: sender to surface monetized pins (commitments that backed a
    /// payment) to the replication engine's deterministic first-audit drainer.
    /// `None` until [`Self::attach_monetized_pin_sender`] (unit tests, or
    /// pre-replication startup), in which case no first audit is scheduled.
    monetized_pin_tx:
        RwLock<Option<tokio::sync::mpsc::Sender<crate::replication::MonetizedPinEvent>>>,
    /// Price-floor input: the SAME live commitment source the local
    /// `QuoteGenerator` prices from, read via the non-mutating snapshot so the
    /// floor never extends commitment answerability. `None` until
    /// [`Self::attach_local_commitment_source`] (unit tests, or storage
    /// disabled / pre-replication startup) — the floor then SKIPS the admission
    /// entirely rather than pricing against anything, so a node in that state
    /// never rejects.
    local_commitment_source: RwLock<Option<Arc<dyn crate::payment::quote::CommitmentSource>>>,
    /// Live price-floor policy, initialized from
    /// [`PaymentVerifierConfig::price_floor`]. Behind a lock so tests (and any
    /// future ops surface) can flip enforcement without rebuilding the
    /// verifier.
    price_floor: RwLock<PriceFloorConfig>,
    /// ADR-0008: the instant from which a merkle receipt must settle at the
    /// single-node 3x multiplier, defaulting to
    /// [`crate::replication::config::MERKLE_PARITY_ENFORCED_FROM_UNIX`].
    ///
    /// Behind a lock purely so tests can pin it. Every merkle receipt is
    /// necessarily stamped within one week of now (older ones are expired,
    /// future ones refused), so a test that used the production boundary would
    /// silently change which side of it the test data fell on as the wall clock
    /// crossed that date. Pinning the boundary keeps those tests deterministic
    /// forever.
    merkle_parity_from: RwLock<u64>,
    /// ADR-0008: pool hashes this node has already emitted a parity telemetry
    /// line for. Bounded by
    /// [`MERKLE_PARITY_TELEMETRY_CACHE_CAPACITY`]; see that constant for why
    /// this is separate from [`Self::pool_cache`].
    ///
    /// Check-and-insert happens under this one lock, so concurrent admissions
    /// of different chunks from the same batch emit exactly one line between
    /// them rather than one each.
    merkle_parity_logged: Mutex<LruCache<PoolHash, ()>>,
    /// Count of ADR-0008 parity lines this verifier has actually emitted.
    /// Incremented only on first emission for a pool, so it measures
    /// settlements sampled rather than chunks admitted.
    merkle_parity_emissions: std::sync::atomic::AtomicUsize,
    /// Configuration.
    config: PaymentVerifierConfig,
}

/// Shared state for an inflight closeness verification. The leader publishes
/// its result via the `OnceLock`; waiters read that result directly instead
/// of racing on a cache re-check. Wrapped in an `Arc` and held both by the
/// leader's drop guard and by each waiting task.
struct ClosenessSlot {
    notify: Arc<tokio::sync::Notify>,
    /// `Some(Ok(()))` on success, `Some(Err(msg))` on failure, `None` if the
    /// leader disappeared without publishing (panic, cancellation).
    result: std::sync::OnceLock<std::result::Result<(), String>>,
}

impl ClosenessSlot {
    fn new() -> Self {
        Self {
            notify: Arc::new(tokio::sync::Notify::new()),
            result: std::sync::OnceLock::new(),
        }
    }

    /// Build an owned `Notified` future that snapshots the `notify_waiters`
    /// counter at call time. Awaiting this future after dropping external
    /// locks is race-free: if `notify_waiters` fires between construction
    /// and the first poll, the snapshot mismatch resolves the future
    /// immediately.
    fn notified_owned(&self) -> tokio::sync::futures::OwnedNotified {
        Arc::clone(&self.notify).notified_owned()
    }
}

/// Drop guard that publishes the leader's result, clears the inflight slot,
/// and wakes all waiters. Fires on every exit path: success, failure, panic,
/// future-cancellation.
///
/// The guard owns its own `Arc<ClosenessSlot>` so `notify_waiters` still
/// fires even if LRU pressure evicted the slot before the leader finished.
/// Waiters see the published result via `result.get()`; the `Notify` is only
/// the wake-up signal.
struct InflightGuard<'a> {
    slot_cache: &'a Mutex<LruCache<PoolHash, Arc<ClosenessSlot>>>,
    pool_hash: PoolHash,
    slot: Arc<ClosenessSlot>,
}

impl InflightGuard<'_> {
    /// Publish the leader's result. Called exactly once by the leader on
    /// every successful or explicit-error exit. If dropped without calling
    /// (panic, cancellation) the guard still wakes waiters but leaves
    /// `result` empty, which waiters treat as a transient failure and retry.
    fn publish(&self, result: &Result<()>) {
        let stored: std::result::Result<(), String> = match result {
            Ok(()) => Ok(()),
            Err(e) => Err(e.to_string()),
        };
        let _ = self.slot.result.set(stored);
    }
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        // Remove the slot entry if it's still ours. A separate leader may
        // have inserted a new slot for the same pool_hash after LRU
        // eviction — don't pop someone else's entry.
        {
            let mut cache = self.slot_cache.lock();
            if let Some(existing) = cache.peek(&self.pool_hash) {
                if Arc::ptr_eq(existing, &self.slot) {
                    cache.pop(&self.pool_hash);
                }
            }
        }
        // Wake every waiter registered against OUR slot, regardless of
        // whether the cache entry is still ours.
        self.slot.notify.notify_waiters();
    }
}

impl PaymentVerifier {
    /// Create a new payment verifier.
    #[must_use]
    pub fn new(config: PaymentVerifierConfig) -> Self {
        const _: () = assert!(
            DEFAULT_POOL_CACHE_CAPACITY > 0,
            "pool cache capacity must be > 0"
        );
        let cache = VerifiedCache::with_capacity(config.cache_capacity);
        let pool_cache_size =
            NonZeroUsize::new(DEFAULT_POOL_CACHE_CAPACITY).unwrap_or(NonZeroUsize::MIN);
        let pool_cache = Mutex::new(LruCache::new(pool_cache_size));
        let closeness_pass_cache = Mutex::new(LruCache::new(pool_cache_size));
        let inflight_closeness = Mutex::new(LruCache::new(pool_cache_size));

        let cache_capacity = config.cache_capacity;
        info!("Payment verifier initialized (cache_capacity={cache_capacity}, evm=always-on, pool_cache={DEFAULT_POOL_CACHE_CAPACITY})");

        // Loud warning if a production binary was accidentally built with
        // `test-utils`: that feature flips the live-DHT payment-check
        // fail-open switches when P2PNode isn't attached. Safe in tests, never
        // intended for prod.
        #[cfg(feature = "test-utils")]
        crate::logging::error!(
            "PaymentVerifier: built with `test-utils` feature — payment live-DHT \
             checks fall back to fail-open when no P2PNode is attached. This \
             feature is for test binaries only; production nodes must be built \
             without it."
        );

        Self {
            cache,
            pool_cache,
            closeness_pass_cache,
            inflight_closeness,
            p2p_node: RwLock::new(None),
            storage: RwLock::new(None),
            #[cfg(any(test, feature = "test-utils"))]
            test_paid_quote_k_closest_override: RwLock::new(None),
            #[cfg(any(test, feature = "test-utils"))]
            test_completed_payments_override: RwLock::new(HashMap::new()),
            commitment_cache: RwLock::new(None),
            pin_fetch_negative_cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(crate::replication::config::PIN_FETCH_NEGATIVE_CACHE_CAPACITY)
                    .unwrap_or(NonZeroUsize::MIN),
            ))),
            monetized_pin_tx: RwLock::new(None),
            local_commitment_source: RwLock::new(None),
            price_floor: RwLock::new(config.price_floor),
            merkle_parity_from: RwLock::new(
                crate::replication::config::MERKLE_PARITY_ENFORCED_FROM_UNIX,
            ),
            merkle_parity_logged: Mutex::new(LruCache::new(
                NonZeroUsize::new(MERKLE_PARITY_TELEMETRY_CACHE_CAPACITY)
                    .unwrap_or(NonZeroUsize::MIN),
            )),
            merkle_parity_emissions: std::sync::atomic::AtomicUsize::new(0),
            config,
        }
    }

    /// Attach the ADR-0004 monetized-pin sender (the replication engine's
    /// first-audit drainer channel) so the cross-check can route commitments
    /// that backed a payment into a deterministic first audit. Idempotent;
    /// absent (unit tests / pre-replication) no first audit is scheduled.
    pub fn attach_monetized_pin_sender(
        &self,
        tx: tokio::sync::mpsc::Sender<crate::replication::MonetizedPinEvent>,
    ) {
        *self.monetized_pin_tx.write() = Some(tx);
        debug!("PaymentVerifier: ADR-0004 monetized-pin sender attached");
    }

    /// Attach the ADR-0004 gossip commitment cache (the replication engine's
    /// `last_commitment_by_peer`) so the cross-check can resolve a quote's
    /// `commitment_pin` against the neighbour's recently gossiped commitment.
    ///
    /// Wired by the node once the replication engine exists, alongside the
    /// quote generator's commitment source. Idempotent. Absent (unit tests,
    /// pre-replication startup), the cross-check resolves no pins from gossip
    /// and falls back to fetch/skip — never a penalty.
    pub fn attach_commitment_cache(&self, cache: CommitmentCache) {
        *self.commitment_cache.write() = Some(cache);
        debug!("PaymentVerifier: ADR-0004 commitment cache attached");
    }

    /// Attach the node's [`P2PNode`] handle so paid-quote verification can
    /// check issuer closeness, and merkle-payment verification can check
    /// candidate `pub_keys` against the DHT's actual closest peers to the pool
    /// midpoint.
    ///
    /// Production startup MUST call this once the `P2PNode` exists. Without
    /// it, live-DHT payment checks fail CLOSED in release builds with a visible
    /// error and fail open in test builds. Idempotent: calling twice replaces
    /// the handle.
    pub fn attach_p2p_node(&self, node: Arc<P2PNode>) {
        *self.p2p_node.write() = Some(node);
        debug!("PaymentVerifier: P2PNode attached for payment live-DHT checks");
    }

    /// Configured close-group width used by storage admission callers.
    #[must_use]
    pub fn close_group_size(&self) -> usize {
        self.config.close_group_size
    }

    /// Attach the node's [`LmdbStorage`] handle for store-backed verifier
    /// checks that read the authoritative on-disk record count.
    ///
    /// NOTE: the ADR-0006 price floor does NOT depend on this handle — it is
    /// priced from the close group's gossiped commitments plus this node's own
    /// ([`Self::attach_local_commitment_source`]), and a missing commitment
    /// makes the floor skip rather than reject. So a node without storage
    /// attached still admits PUTs; this
    /// attachment only feeds any current/future store-count-backed checks.
    /// Idempotent: calling twice replaces the handle.
    pub fn attach_storage(&self, storage: Arc<LmdbStorage>) {
        *self.storage.write() = Some(storage);
        debug!("PaymentVerifier: LmdbStorage attached for paid-quote price-floor checks");
    }

    /// Attach the live commitment source for the price floor: the SAME
    /// `ResponderCommitmentState` the local `QuoteGenerator` prices from, so
    /// the floor and this node's own quotes read one pricing basis by
    /// construction. Read via the non-mutating snapshot only. Idempotent.
    /// Absent (unit tests, storage disabled, pre-replication startup), the
    /// floor SKIPS the admission entirely with `skip_reason=no_own_commitment`
    /// rather than pricing against anything, so a node in that state never
    /// rejects.
    pub fn attach_local_commitment_source(
        &self,
        source: Arc<dyn crate::payment::quote::CommitmentSource>,
    ) {
        *self.local_commitment_source.write() = Some(source);
        debug!("PaymentVerifier: local commitment source attached for price-floor checks");
    }

    /// The live price-floor policy this verifier applies.
    #[must_use]
    pub fn price_floor_config(&self) -> PriceFloorConfig {
        *self.price_floor.read()
    }

    /// Test-only setter for the price-floor policy, so enforcement and
    /// tolerance can be exercised without environment variables.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_price_floor_for_tests(&self, config: PriceFloorConfig) {
        *self.price_floor.write() = config;
    }

    /// Test-only setter for the ADR-0008 merkle parity boundary, so both the
    /// pre-boundary (historic 1x) and enforcing (3x) regimes can be exercised
    /// against fixed receipt timestamps instead of the wall clock. `0` enforces
    /// on every receipt; `u64::MAX` puts every receipt in the legacy window.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_merkle_parity_from_for_tests(&self, enforced_from: u64) {
        *self.merkle_parity_from.write() = enforced_from;
    }

    /// Number of ADR-0008 parity telemetry lines this verifier has emitted.
    ///
    /// One per settlement pool this node admitted a store for — not one per
    /// chunk, and none at all for proofs that failed validation or for
    /// non-store contexts. Test-only surface for the cardinality regression
    /// tests; the production signal is the log line itself.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn merkle_parity_emission_count(&self) -> usize {
        self.merkle_parity_emissions
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Test-only setter for local closest peers used by the paid-quote
    /// issuer K-closest check.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_paid_quote_k_closest_for_tests(&self, peer_ids: Vec<[u8; 32]>) {
        *self.test_paid_quote_k_closest_override.write() = Some(peer_ids);
    }

    /// Compatibility alias for older tests that called this the close group.
    /// The check now accepts the K closest peers for the quoted chunk address.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_paid_quote_close_group_for_tests(&self, peer_ids: Vec<[u8; 32]>) {
        self.set_paid_quote_k_closest_for_tests(peer_ids);
    }

    /// Compatibility alias for older tests that called this the known-peer
    /// set. The check now accepts the K closest peers for the quoted chunk
    /// address.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_paid_quote_known_peers_for_tests(&self, peer_ids: Vec<[u8; 32]>) {
        self.set_paid_quote_k_closest_for_tests(peer_ids);
    }

    /// Test-only setter for an on-chain completed payment amount. The recorded
    /// rewards address is treated as matching the quote (honest settlement).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_completed_payment_for_tests(&self, quote_hash: QuoteHash, amount: Amount) {
        self.test_completed_payments_override
            .write()
            .insert(quote_hash, (amount, None));
    }

    /// Test-only setter for an on-chain completed payment with an explicit
    /// recorded rewards address, to exercise the settlement-redirect rejection.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn set_completed_payment_with_address_for_tests(
        &self,
        quote_hash: QuoteHash,
        amount: Amount,
        rewards_address: evmlib::RewardsAddress,
    ) {
        self.test_completed_payments_override.write().insert(
            quote_hash,
            (amount, Some(Self::rewards_address_prefix(&rewards_address))),
        );
    }

    /// The vault's `completedPayments` slot packs the payee as
    /// `bytes16(bytes20(rewardsAddress))` — the leading 16 bytes of the
    /// address (Solidity `bytesN` conversions truncate on the right). This is
    /// the form the on-chain record is compared in.
    fn rewards_address_prefix(rewards_address: &evmlib::RewardsAddress) -> [u8; 16] {
        let mut prefix = [0u8; 16];
        if let Some(head) = rewards_address.as_slice().get(..16) {
            prefix.copy_from_slice(head);
        }
        prefix
    }

    /// Check if payment is required for the given `XorName`.
    ///
    /// This is the main entry point for payment verification:
    /// 1. Check LRU cache (fast path)
    /// 2. If not cached, payment is required
    ///
    /// The fast path is context-aware. A store-admission lookup (`ClientPut` /
    /// `FreshReplication`) is satisfied only by a close-group store
    /// verification. A `PaidListAdmission` lookup is satisfied by either a
    /// paid-list or client-PUT verification.
    ///
    /// # Arguments
    ///
    /// * `xorname` - The content-addressed name of the data
    /// * `context` - The verification context of the caller
    ///
    /// # Returns
    ///
    /// * `PaymentStatus::CachedAsVerified` - Found in local cache (previously paid)
    /// * `PaymentStatus::PaymentRequired` - Not cached (payment required)
    pub fn check_payment_required(
        &self,
        xorname: &XorName,
        context: VerificationContext,
    ) -> PaymentStatus {
        // Check LRU cache (fast path)
        let cached = if context.is_store_admission() {
            self.cache.contains_client_put_verified(xorname)
        } else {
            self.cache.contains_paid_list_verified(xorname)
        };
        if cached {
            if crate::logging::enabled!(crate::logging::Level::DEBUG) {
                debug!("Data {} found in verified cache", hex::encode(xorname));
            }
            return PaymentStatus::CachedAsVerified;
        }

        // Not in cache - payment required
        if crate::logging::enabled!(crate::logging::Level::DEBUG) {
            debug!(
                "Data {} not in cache - payment required",
                hex::encode(xorname)
            );
        }
        PaymentStatus::PaymentRequired
    }

    /// Verify that a PUT request has valid payment.
    ///
    /// This is the complete payment verification flow:
    /// 1. Check if data is in cache (previously paid)
    /// 2. If not, verify the provided payment proof
    ///
    /// # Arguments
    ///
    /// * `xorname` - The content-addressed name of the data
    /// * `payment_proof` - Optional payment proof (required if not in cache)
    /// * `context` - Which fresh admission path is verifying the proof — see
    ///   [`VerificationContext`] for cache-strength semantics
    ///
    /// # Returns
    ///
    /// * `Ok(PaymentStatus)` - Verification succeeded
    /// * `Err(Error::Payment)` - No payment and not cached, or payment invalid
    ///
    /// # Errors
    ///
    /// Returns an error if payment is required but not provided, or if payment is invalid.
    pub async fn verify_payment(
        &self,
        xorname: &XorName,
        payment_proof: Option<&[u8]>,
        context: VerificationContext,
    ) -> Result<PaymentStatus> {
        let started = Instant::now();
        let proof_type = payment_proof_type_label(payment_proof);
        let proof_bytes = payment_proof.map_or(0, <[u8]>::len);
        let result = self
            .verify_payment_inner(xorname, payment_proof, context)
            .await;
        let elapsed_ms = started.elapsed().as_millis();

        match &result {
            Ok(status) if elapsed_ms >= PAYMENT_VERIFY_SLOW_LOG_MS => {
                info!(
                    target: "ant_node::payment::verify",
                    "Slow payment verification: context={context:?}, proof_type={proof_type}, proof_bytes={proof_bytes}, status={status:?}, elapsed_ms={elapsed_ms}",
                );
            }
            Ok(status) => {
                debug!(
                    target: "ant_node::payment::verify",
                    "Payment verification: context={context:?}, proof_type={proof_type}, proof_bytes={proof_bytes}, status={status:?}, elapsed_ms={elapsed_ms}",
                );
            }
            Err(e) if elapsed_ms >= PAYMENT_VERIFY_SLOW_LOG_MS => {
                warn!(
                    target: "ant_node::payment::verify",
                    "Slow payment verification failed: context={context:?}, proof_type={proof_type}, proof_bytes={proof_bytes}, elapsed_ms={elapsed_ms}: {e}",
                );
            }
            Err(e) => {
                debug!(
                    target: "ant_node::payment::verify",
                    "Payment verification failed: context={context:?}, proof_type={proof_type}, proof_bytes={proof_bytes}, elapsed_ms={elapsed_ms}: {e}",
                );
            }
        }

        result
    }

    async fn verify_payment_inner(
        &self,
        xorname: &XorName,
        payment_proof: Option<&[u8]>,
        context: VerificationContext,
    ) -> Result<PaymentStatus> {
        // First check if payment is required
        let status = self.check_payment_required(xorname, context);

        match status {
            PaymentStatus::CachedAsVerified => {
                // No payment needed - already in cache
                Ok(status)
            }
            PaymentStatus::PaymentRequired => {
                // EVM verification is always on — verify the proof
                if let Some(proof) = payment_proof {
                    let proof_len = proof.len();
                    if proof_len < MIN_PAYMENT_PROOF_SIZE_BYTES {
                        return Err(Error::Payment(format!(
                            "Payment proof too small: {proof_len} bytes (min {MIN_PAYMENT_PROOF_SIZE_BYTES})"
                        )));
                    }
                    if proof_len > MAX_PAYMENT_PROOF_SIZE_BYTES {
                        return Err(Error::Payment(format!(
                            "Payment proof too large: {proof_len} bytes (max {MAX_PAYMENT_PROOF_SIZE_BYTES} bytes)"
                        )));
                    }

                    // Detect proof type from version tag byte
                    match detect_proof_type(proof) {
                        Some(ProofType::Merkle) => {
                            self.verify_merkle_payment(xorname, proof, context).await?;
                        }
                        Some(ProofType::SingleNode) => {
                            let parsed = deserialize_single_node_proof(proof).map_err(|e| {
                                Error::Payment(format!("Failed to deserialize payment proof: {e}"))
                            })?;

                            if !parsed.tx_hashes.is_empty() {
                                debug!(
                                    "Proof includes {} transaction hash(es)",
                                    parsed.tx_hashes.len()
                                );
                            }

                            self.verify_evm_payment(
                                xorname,
                                &parsed.proof_of_payment,
                                &parsed.commitment_sidecars,
                                context,
                            )
                            .await?;
                        }
                        None => {
                            let tag = proof.first().copied().unwrap_or(0);
                            return Err(Error::Payment(format!(
                                "Unknown payment proof type tag: 0x{tag:02x}"
                            )));
                        }
                        // ant-protocol marks `ProofType` as `#[non_exhaustive]`.
                        // A future proof variant that this node does not yet
                        // understand must be rejected, not silently accepted.
                        Some(_) => {
                            let tag = proof.first().copied().unwrap_or(0);
                            return Err(Error::Payment(format!(
                                "Unsupported payment proof type tag: 0x{tag:02x} (this node's protocol version does not handle it — upgrade ant-node)"
                            )));
                        }
                    }

                    // Cache the verified xorname at the context's verification
                    // strength. Stronger entries satisfy weaker future lookups,
                    // but not the reverse.
                    if context.is_store_admission() {
                        self.cache.insert(*xorname);
                    } else {
                        self.cache.insert_paid_list_verified(*xorname);
                    }

                    Ok(PaymentStatus::PaymentVerified)
                } else {
                    // No payment provided in production mode
                    let xorname_hex = hex::encode(xorname);
                    Err(Error::Payment(format!(
                        "Payment required for new data {xorname_hex}"
                    )))
                }
            }
            PaymentStatus::PaymentVerified => Err(Error::Payment(
                "Unexpected PaymentVerified status from check_payment_required".to_string(),
            )),
        }
    }

    /// Get cache statistics.
    #[must_use]
    pub fn cache_stats(&self) -> CacheStats {
        self.cache.stats()
    }

    /// Get the number of cached entries.
    #[must_use]
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// Pre-populate the payment cache for a given address.
    ///
    /// This marks the address as already paid, so subsequent `verify_payment`
    /// calls will return `CachedAsVerified` without on-chain verification.
    /// Useful for test setups where real EVM payment is not needed.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn cache_insert(&self, xorname: XorName) {
        self.cache.insert(xorname);
    }

    /// Mark startup content as prepaid for the in-process browser devnet.
    ///
    /// This remains crate-private and feature-gated: it is used only by
    /// [`crate::devnet::Devnet::publish_public_file`] before that local devnet
    /// is handed to a browser. The subsequent PUT still traverses the normal
    /// address, responsibility, payment-cache, storage, and read-verification
    /// checks.
    #[cfg(feature = "webrtc-direct")]
    pub(crate) fn cache_insert_browser_devnet_seed(&self, xorname: XorName) {
        self.cache.insert(xorname);
    }

    /// Pre-populate the merkle pool cache. Testing helper that lets e2e tests
    /// bypass the on-chain `completedMerklePayments` lookup when the point of
    /// the test is to exercise merkle-verification logic BEFORE the on-chain
    /// call (e.g. the pay-yourself closeness check).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn pool_cache_insert(&self, pool_hash: PoolHash, info: OnChainPaymentInfo) {
        let mut cache = self.pool_cache.lock();
        cache.put(pool_hash, info);
    }

    /// Verify a single-node EVM payment proof.
    ///
    /// Verification steps:
    /// 1. Between 1 and `CLOSE_GROUP_SIZE` quotes are present
    /// 2. Median-priced candidate quotes are derived from the supplied bundle
    /// 3. Each candidate is checked for content binding, peer binding, and a
    ///    valid ML-DSA-65 signature
    /// 4. Each candidate must also come from a local K-close peer
    /// 5. A candidate is accepted only if `completedPayments(quoteHash)` is at
    ///    least 3x the median price
    ///
    /// Non-median quotes are parsed only to locate the median. Their content,
    /// peer bindings, and signatures are deliberately ignored: the paid
    /// quote's content hash, quote hash, signature, issuer
    /// K-closeness check, and on-chain settlement are the authority. A
    /// one-quote proof is valid when that single quote passes these checks and
    /// was paid 3x.
    async fn verify_evm_payment(
        &self,
        xorname: &XorName,
        payment: &ProofOfPayment,
        commitment_sidecars: &[Vec<u8>],
        context: VerificationContext,
    ) -> Result<()> {
        if crate::logging::enabled!(crate::logging::Level::DEBUG) {
            let xorname_hex = hex::encode(xorname);
            let quote_count = payment.peer_quotes.len();
            debug!(
                "Verifying EVM payment for {xorname_hex} with {quote_count} quotes ({context:?})"
            );
        }

        Self::validate_quote_structure(payment)?;
        // ADR-0004: re-run the `price == calculate_price(committed_key_count)`
        // arithmetic/binding check on EVERY quote in the bundle (all single-node
        // quotes), per the ADR's "every storer re-runs the
        // price-equals-formula-of-count check on every quote in the bundle"
        // rule — bundle-level, before median selection (the candidate loop below
        // only sees median-priced quotes). This hard cutover also RETIRES the
        // percentage-based own-quote price-staleness gate: a quote's price is
        // now exactly bound to its committed count here (both the `(n>0, Some)`
        // and baseline `(0, None)` shapes), and the committed responsible count
        // legitimately differs from the on-disk count, so the old gate would
        // FALSE-REJECT healthy ADR quotes. The binding gate supersedes it.
        Self::validate_quote_arithmetic(payment)?;
        let candidates = Self::legacy_median_candidates(payment)?;
        let mut failures = Vec::with_capacity(candidates.len());
        // The paid (median) price and settled on-chain amount of the winning
        // candidate, kept for the receiver-side price-floor policy below.
        let mut verified_paid_quote: Option<(Amount, Amount)> = None;
        // ADR-0004 Amendment 2: remember WHICH candidate's on-chain settlement
        // verified — only that peer's commitment actually earned money, so only
        // its pin is nominated for a deterministic first audit below. The
        // non-median quotes merely locate the median and stay covered by the
        // gossip-lottery audit path.
        let mut paid_peer: Option<[u8; 32]> = None;

        for candidate in candidates {
            let paid_price = candidate.quote.price;
            let candidate_peer = *candidate.encoded_peer_id.as_bytes();
            match self
                .verify_legacy_median_candidate(xorname, candidate)
                .await
            {
                Ok(settled_amount) => {
                    verified_paid_quote = Some((paid_price, settled_amount));
                    // First settlement-verified median candidate wins the paid
                    // slot and the sole first-audit nomination. If a client
                    // settled several TIED-median candidates, only this one is
                    // first-audited; gossiped extras keep the ADR-0002 lottery,
                    // sidecar-only extras are an accepted best-effort residual
                    // (ADR-0004 Amendment 2). The honest client pays one.
                    paid_peer = Some(candidate_peer);
                    break;
                }
                Err(err) => failures.push(err.to_string()),
            }
        }

        let Some((paid_price, settled_amount)) = verified_paid_quote else {
            let xorname_hex = hex::encode(xorname);
            let details = if failures.is_empty() {
                "no median-priced candidates were available".to_string()
            } else {
                failures.join("; ")
            };
            return Err(Error::Payment(format!(
                "Median quote payment verification failed for {xorname_hex}: {details}"
            )));
        };

        // Receiver-side price floor (single-node store admissions only). Runs
        // AFTER the paid quote's signature and settlement verified above, so
        // unauthenticated bundles can never poison floor telemetry. Shadow
        // mode logs; enforcement rejects — an economic admission decision
        // only, never trust/misbehaviour evidence.
        self.enforce_price_floor(xorname, paid_price, settled_amount, context)
            .await?;

        // ADR-0004 observe-only telemetry: log off-curve quotes only AFTER the
        // paid (median) quote's ML-DSA-65 signature has verified above, so
        // unauthenticated senders cannot poison rollout logs. In enforce mode
        // `validate_quote_arithmetic` already rejected; this is a no-op there.
        Self::log_off_curve_single_node(payment);

        // ADR-0004 cross-check + first-audit enqueue (store admissions only —
        // direct client PUT and immediate fresh replication, exactly the paths
        // that previously verified under `ClientPut`) runs ONLY after on-chain
        // payment verification has SUCCEEDED above, so an unpaid (but signed)
        // bundle can never enqueue audits or drive pin fetches — closing the
        // free-amplification path.
        if context.is_store_admission() {
            self.cross_check_quotes(payment, commitment_sidecars, paid_peer)
                .await;
        }

        if crate::logging::enabled!(crate::logging::Level::INFO) {
            let xorname_hex = hex::encode(xorname);
            info!("EVM payment verified for {xorname_hex}");
        }
        Ok(())
    }

    fn legacy_median_candidates(
        payment: &ProofOfPayment,
    ) -> Result<Vec<LegacyMedianCandidate<'_>>> {
        let mut sorted_quotes: Vec<(&evmlib::EncodedPeerId, &PaymentQuote)> = payment
            .peer_quotes
            .iter()
            .map(|(encoded_peer_id, quote)| (encoded_peer_id, quote))
            .collect();
        sorted_quotes.sort_by_key(|(_, quote)| quote.price);
        let quote_count = sorted_quotes.len();
        let median_index = median_quote_index(quote_count);
        let median_price = sorted_quotes
            .get(median_index)
            .ok_or_else(|| {
                Error::Payment(format!("Missing paid quote at median index {median_index}"))
            })?
            .1
            .price;
        let expected_amount = median_price
            .checked_mul(Amount::from(PAID_QUOTE_PAYMENT_MULTIPLIER))
            .ok_or_else(|| {
                Error::Payment(format!(
                    "Median quote payment amount overflow for price {median_price}"
                ))
            })?;

        if expected_amount == Amount::ZERO || median_price == Amount::ZERO {
            return Err(Error::Payment(format!(
                "Median quote has zero price/amount (price={median_price}, amount={expected_amount}); refusing to verify as paid"
            )));
        }

        Ok(sorted_quotes
            .into_iter()
            .filter(|(_, quote)| quote.price == median_price)
            .map(|(encoded_peer_id, quote)| LegacyMedianCandidate {
                encoded_peer_id,
                quote,
                expected_amount,
            })
            .collect())
    }

    /// Fully validate one median-priced candidate. On success returns the
    /// settled on-chain amount for the candidate's quote hash, which the
    /// price-floor policy compares against the close group's median
    /// commitment price (the settled amount, not the quoted price, so an
    /// honest client may overpay a cheap quote to clear stricter receivers).
    async fn verify_legacy_median_candidate(
        &self,
        xorname: &XorName,
        candidate: LegacyMedianCandidate<'_>,
    ) -> Result<Amount> {
        Self::validate_paid_quote_content(xorname, candidate)?;
        let issuer_peer_id =
            Self::validate_paid_quote_peer_binding(candidate.encoded_peer_id, candidate.quote)?;

        self.validate_paid_quote_issuer_k_closest(xorname, &issuer_peer_id)
            .await?;

        Self::validate_paid_quote_signature(candidate).await?;

        let (on_chain_amount, recorded_rewards_prefix) = self
            .completed_payment_settlement(candidate.quote.hash())
            .await?;
        // ADR-0004 Amendment 2: the settlement must be RECORDED FOR THE QUOTE'S
        // rewards address, not merely under its quote hash. The vault stores
        // whatever `(rewardsAddress, amount)` the payer supplied for the hash,
        // so an amount-only check would accept a payment the client redirected
        // to its own wallet — the issuer would be treated (and first-audited)
        // as "paid" without ever being compensated. Honest clients build the
        // payment from the quote itself, so this never rejects a legit upload.
        // The vault packs the payee as `bytes16`, so the comparison is on the
        // leading 16 bytes (128 bits — far beyond grinding range).
        if let Some(recorded) = recorded_rewards_prefix {
            let expected = Self::rewards_address_prefix(&candidate.quote.rewards_address);
            if recorded != expected {
                return Err(Error::Payment(format!(
                    "Median-priced quote settlement for peer {:?} was redirected: recorded rewards address prefix {} does not match the quote's {}",
                    candidate.encoded_peer_id,
                    hex::encode(recorded),
                    hex::encode(expected)
                )));
            }
        }
        if on_chain_amount >= candidate.expected_amount {
            return Ok(on_chain_amount);
        }

        Err(Error::Payment(format!(
            "Median-priced quote for peer {:?} was not paid enough: expected at least {}, got {on_chain_amount}",
            candidate.encoded_peer_id, candidate.expected_amount
        )))
    }

    /// The peer ids this node considers closest to `xorname`, by pure XOR
    /// distance, mirroring the selection the paid-quote closeness check uses.
    ///
    /// Returns an empty vec when the node is not wired to the P2P layer, which
    /// callers must treat as "no local view" rather than "no close peers".
    async fn local_k_closest_peer_ids(&self, xorname: &XorName) -> Vec<PeerId> {
        #[cfg(any(test, feature = "test-utils"))]
        if let Some(k_closest_peer_ids) = self.test_paid_quote_k_closest_override.read().as_ref() {
            return k_closest_peer_ids
                .iter()
                .map(|bytes| PeerId::from_bytes(*bytes))
                .collect();
        }

        let Some(p2p_node) = self.p2p_node.read().as_ref().map(Arc::clone) else {
            return Vec::new();
        };
        p2p_node
            .dht_manager()
            .find_closest_nodes_local_by_distance_with_self(
                xorname,
                PAID_QUOTE_ISSUER_CLOSENESS_WIDTH,
            )
            .await
            .into_iter()
            .map(|node| node.peer_id)
            .collect()
    }

    /// The close group's MEDIAN commitment-bound price for `xorname`, and the
    /// number of peers that median was taken over.
    ///
    /// This is the price floor's reference, and choosing the median of the group
    /// rather than this node's own price is the whole point of the policy.
    ///
    /// A client pays `3x` the MEDIAN of the quotes it collected. Pricing the
    /// floor against a receiver's OWN price compares that median to a single
    /// draw from a distribution that spans ~4x across the fleet, so the fullest
    /// receivers reject honest payments while the emptiest admit deep
    /// underpayment — measured on ant-prod-01, 0.377% of honest stores rejected
    /// with the cheapest-of-K underpayment still admitted by 62.9% of receivers.
    /// Both sides of that are the same defect: the reference is a sample, and
    /// the payment is a median. Comparing median to median removes it.
    ///
    /// The reference is built ONLY from state this node already holds:
    ///
    /// * the K peers closest to `xorname` in its own routing table, and
    /// * those peers' own signed commitments from the gossip cache, TTL-gated
    ///   by [`GOSSIP_ANSWERABILITY_TTL`], plus this node's own live commitment.
    ///
    /// Nothing in the payment bundle feeds it. A client cannot pad, prune or
    /// reorder quotes to move this number, which is what makes the floor
    /// resistant to the quote-selection games it exists to stop.
    ///
    /// The remaining lever is gossiping a false commitment, and it cuts BOTH
    /// ways, which is why the sample gate is set where it is:
    ///
    /// * **Understating** drags the median down and weakens the floor. The cost
    ///   is a missed underpayment.
    /// * **Overstating** drags it up and makes this node reject settled, honest
    ///   payments. That is the dangerous direction, because the money is already
    ///   spent and cannot be refunded, so a griefer would be spending nothing to
    ///   destroy someone else's payment.
    ///
    /// The bound is NOT "a majority of the group", and it is worth stating
    /// precisely because it is what an enforcement decision rests on. The floor
    /// does not need the median to reach the liars' value — only to move past
    /// the tolerance headroom. Each liar shifts the order statistic by one rank,
    /// and on the measured fleet spread one rank is worth roughly 15% of price
    /// while a 65% tolerance buys 1.54x. So **about a quarter of the sample**
    /// suffices in either direction: measured on this crate's own fixture, 4 of
    /// 15 overstating neighbours reject an honest payment sitting at the true
    /// median, and 4 of 15 understating ones (placed above the median, where an
    /// attacker would put them) admit a cheapest-of-K underpayment.
    ///
    /// Counts above `MAX_COMMITMENT_KEY_COUNT` are dropped outright, since
    /// gossip ingest authenticates the sender without bounding the count. That
    /// caps how far a single liar can reach but does not change the cardinality
    /// bound above. A signature proves who said a number, never that the number
    /// is true, and address grinding into a close group is a known adjacent
    /// problem. This is why the policy ships shadow-only: the ~25% bound is a
    /// reason not to enforce yet, not a property to rely on.
    ///
    /// Returns the reference price only when at least
    /// [`PRICE_FLOOR_MIN_NEIGHBOUR_COMMITMENTS`] neighbour commitments are
    /// fresh AND this node has its own live commitment; the `usize` is the
    /// sample size either way, so the caller can log how close it came. A `None`
    /// price means "do not evaluate".
    ///
    /// [`GOSSIP_ANSWERABILITY_TTL`]: crate::replication::commitment_state::GOSSIP_ANSWERABILITY_TTL
    async fn group_reference_price(&self, xorname: &XorName) -> (Option<Amount>, GroupSample) {
        // This node's own live commitment. It is in the group whenever it is
        // being asked to store the chunk, so it belongs in the sample. Bound to
        // a local first so the source lock is released before the awaits below.
        //
        // It is counted separately from the neighbour tally: the gate below asks
        // "how much of the group do I actually know", and answering that with a
        // number that includes yourself overstates it by one, which matters most
        // exactly when the view is thinnest.
        // Wiring faults are reported before state faults, so a startup-order bug
        // is never mistaken for "this node is mid-rotation" or for "the gate is
        // above what the network supplies". Those three have three different
        // fixes and shadow mode exists to tell them apart.
        let Some(cache) = self.commitment_cache.read().as_ref().map(Arc::clone) else {
            return (None, GroupSample::none(SkipReason::NoCommitmentCache));
        };
        // Cache is checked first so a node without one does not pay for a
        // routing-table scan it will discard.
        let closest = self.local_k_closest_peer_ids(xorname).await;
        if closest.is_empty() {
            return (None, GroupSample::none(SkipReason::NoRoutingView));
        }

        let own_source = self.local_commitment_source.read().as_ref().map(Arc::clone);
        // No own commitment means fresh, retired, or mid-rotation. Such a node
        // prices its OWN quotes at baseline, so letting it hold an incoming
        // payment to its neighbours' (higher) median would reject settlements it
        // would itself have quoted. Skip, which is also what ADR-0006 says a
        // receiver in this state does.
        let Some(own) = own_source.and_then(|source| source.current_binding_snapshot()) else {
            return (None, GroupSample::none(SkipReason::NoOwnCommitment));
        };
        let now = std::time::Instant::now();
        let ttl = crate::replication::commitment_state::GOSSIP_ANSWERABILITY_TTL;
        let mut key_counts: Vec<u32> = {
            let guard = cache.read().await;
            closest
                .iter()
                .filter_map(|peer_id| {
                    let record = guard.get(peer_id)?;
                    // Stale gossip is treated as unknown rather than as a low
                    // price, so a peer going quiet can never drag the median
                    // down, nor count toward the minimum sample.
                    if now.saturating_duration_since(record.received_at) >= ttl {
                        return None;
                    }
                    record
                        .last_commitment()
                        .map(|c| c.key_count)
                        .filter(|count| *count <= MAX_COMMITMENT_KEY_COUNT)
                })
                .collect()
        };

        let neighbours_known = key_counts.len();
        // Own count is held to the same cap as a neighbour's. Unreachable today
        // (the local builder refuses to build over-cap), but an asymmetry here
        // is the kind that quietly becomes a hole later.
        if own.key_count <= MAX_COMMITMENT_KEY_COUNT {
            key_counts.push(own.key_count);
        }
        let sample = GroupSample {
            neighbours: neighbours_known,
            total: key_counts.len(),
            skip_reason: None,
        };

        if neighbours_known < PRICE_FLOOR_MIN_NEIGHBOUR_COMMITMENTS {
            return (None, sample.skipped(SkipReason::ThinSample));
        }

        // Median of the PRICES, via the median key count. `calculate_price` is
        // monotonic in the key count, so the two orderings agree and taking the
        // median count avoids averaging two U256 prices.
        //
        // The LOWER median on even samples, deliberately: the upper median
        // rounds the reference UP, and a reference that is too high rejects
        // honest payments that have already settled on-chain and cannot be
        // refunded. (The merkle settlement path deliberately uses the UPPER
        // median instead: there it must match the on-chain contract's formula,
        // not choose a safe direction.) ADR-0006 carries the
        // measured difference.
        key_counts.sort_unstable();
        let median_key_count = key_counts
            .get((sample.total.saturating_sub(1)) / 2)
            .copied()
            .unwrap_or_default();
        let reference = calculate_price(usize::try_from(median_key_count).unwrap_or_default());
        (Some(reference), sample)
    }

    /// Receiver-side price floor for single-node store admissions.
    ///
    /// Requires the settled on-chain amount to also clear
    /// `PAID_QUOTE_PAYMENT_MULTIPLIER × tolerance% ×` the close group's median
    /// commitment-bound price (see [`Self::group_reference_price`]). Together
    /// with the per-quote check above, the effective rule is
    /// `settled >= 3 × max(paid_price, tolerated_floor)`.
    ///
    /// When the group reference cannot be built — too few fresh commitments, no
    /// P2P handle, no gossip cache — the floor SKIPS the admission rather than
    /// falling back to this node's own price. Falling back is what the previous
    /// revision did, and it is precisely the comparison that rejected honest
    /// stores on the fullest nodes. A skipped evaluation is logged with its
    /// real `neighbours` / `group_sample` counts and a `skip_reason`, so shadow
    /// telemetry can separate an unwired node from one whose gate simply sits
    /// above what the network supplies.
    ///
    /// Always emits one telemetry line per evaluated admission (target
    /// `ant_node::payment::price_floor`) so shadow mode measures the exact
    /// rejections enforcement would cause. Rejects only when
    /// [`PriceFloorConfig::enforce`] is set.
    async fn enforce_price_floor(
        &self,
        xorname: &XorName,
        paid_price: Amount,
        settled_amount: Amount,
        context: VerificationContext,
    ) -> Result<()> {
        if !context.is_store_admission() {
            return Ok(());
        }

        let floor = *self.price_floor.read();
        let tolerance_percent = floor.tolerance_percent.min(100);

        let (reference, group_sample) = self.group_reference_price(xorname).await;
        let Some(reference_price) = reference else {
            // Not enough of the close group is known to price anything. Skip
            // rather than guess: see `group_reference_price`. The reason and
            // both counts are logged because shadow telemetry has to separate a
            // mid-rotation node from an unwired cache from a gate set above what
            // the network can supply — three causes with three different fixes.
            info!(
                target: "ant_node::payment::price_floor",
                "Price floor: context={context:?}, xorname={}, paid_price={paid_price}, \
                 settled={settled_amount}, neighbours={}, group_sample={}, reference_price=0, \
                 tolerance_percent={tolerance_percent}, required=0, below_floor=false, \
                 skipped=true, skip_reason={}, enforce={}",
                hex::encode(xorname),
                group_sample.neighbours,
                group_sample.total,
                group_sample.skip_reason_str(),
                floor.enforce,
            );
            return Ok(());
        };

        // Amount is a U256: reference_price is bounded by the saturating pricing
        // curve and the multipliers are <= 300, so this arithmetic cannot
        // overflow; saturating keeps that a proof instead of an assumption.
        let tolerated_price =
            reference_price.saturating_mul(Amount::from(tolerance_percent)) / Amount::from(100u64);
        let required_amount =
            tolerated_price.saturating_mul(Amount::from(PAID_QUOTE_PAYMENT_MULTIPLIER));
        let below_floor = settled_amount < required_amount;

        info!(
            target: "ant_node::payment::price_floor",
            "Price floor: context={context:?}, xorname={}, paid_price={paid_price}, \
             settled={settled_amount}, neighbours={}, group_sample={}, \
             reference_price={reference_price}, tolerance_percent={tolerance_percent}, \
             required={required_amount}, below_floor={below_floor}, skipped=false, \
             skip_reason=none, enforce={}",
            hex::encode(xorname),
            group_sample.neighbours,
            group_sample.total,
            floor.enforce,
        );

        if below_floor && floor.enforce {
            return Err(Error::Payment(format!(
                "Settled payment {settled_amount} is below the close-group price floor \
                 {required_amount} ({PAID_QUOTE_PAYMENT_MULTIPLIER}x {tolerance_percent}% of \
                 the group median price {reference_price}, taken over {} peers)",
                group_sample.total
            )));
        }

        Ok(())
    }

    fn validate_paid_quote_content(
        xorname: &XorName,
        candidate: LegacyMedianCandidate<'_>,
    ) -> Result<()> {
        if verify_quote_content(candidate.quote, xorname) {
            return Ok(());
        }

        let expected_hex = hex::encode(xorname);
        let actual_hex = hex::encode(candidate.quote.content.0);
        Err(Error::Payment(format!(
            "Paid quote content address mismatch for peer {:?}: expected {expected_hex}, got {actual_hex}",
            candidate.encoded_peer_id
        )))
    }

    async fn validate_paid_quote_signature(candidate: LegacyMedianCandidate<'_>) -> Result<()> {
        let quote_for_signature = candidate.quote.clone();
        let peer_id_for_error = candidate.encoded_peer_id.clone();
        tokio::task::spawn_blocking(move || {
            if !verify_quote_signature(&quote_for_signature) {
                return Err(Error::Payment(format!(
                    "Paid quote ML-DSA-65 signature verification failed for peer {peer_id_for_error:?}"
                )));
            }
            Ok(())
        })
        .await
        .map_err(|e| Error::Payment(format!("Signature verification task failed: {e}")))?
    }

    /// Look up the on-chain settlement recorded for `quote_hash`: the settled
    /// amount and the `bytes16` rewards-address prefix it was recorded for.
    /// The prefix is `None` only on the test-override path (meaning "matches
    /// the quote"); the production contract read always returns the recorded
    /// prefix so the caller's redirect check always applies.
    async fn completed_payment_settlement(
        &self,
        quote_hash: QuoteHash,
    ) -> Result<(Amount, Option<[u8; 16]>)> {
        #[cfg(any(test, feature = "test-utils"))]
        {
            let completed_payment_override = {
                self.test_completed_payments_override
                    .read()
                    .get(&quote_hash)
                    .copied()
            };
            if let Some((amount, recorded)) = completed_payment_override {
                return Ok((amount, recorded));
            }
        }

        let provider = evmlib::utils::http_provider(self.config.evm.network.rpc_url().clone());
        let vault_address = *self.config.evm.network.payment_vault_address();
        let contract = payment_vault::interface::IPaymentVault::new(vault_address, provider);

        let result = contract
            .completedPayments(quote_hash)
            .call()
            .await
            .map_err(|e| Error::Payment(format!("completedPayments lookup failed: {e}")))?;

        Ok((Amount::from(result.amount), Some(result.rewardsAddress.0)))
    }

    fn validate_paid_quote_peer_binding(
        encoded_peer_id: &evmlib::EncodedPeerId,
        quote: &PaymentQuote,
    ) -> Result<PeerId> {
        let expected_peer_id = peer_id_from_public_key_bytes(&quote.pub_key)
            .map_err(|e| Error::Payment(format!("Invalid ML-DSA public key in quote: {e}")))?;

        if expected_peer_id.as_bytes() != encoded_peer_id.as_bytes() {
            let expected_hex = expected_peer_id.to_hex();
            let actual_hex = hex::encode(encoded_peer_id.as_bytes());
            return Err(Error::Payment(format!(
                "Paid quote pub_key does not belong to claimed peer {encoded_peer_id:?}: \
                 BLAKE3(pub_key) = {expected_hex}, peer_id = {actual_hex}"
            )));
        }

        Ok(expected_peer_id)
    }

    async fn validate_paid_quote_issuer_k_closest(
        &self,
        xorname: &XorName,
        issuer_peer_id: &PeerId,
    ) -> Result<()> {
        #[cfg(any(test, feature = "test-utils"))]
        if let Some(k_closest_peer_ids) = self.test_paid_quote_k_closest_override.read().as_ref() {
            if k_closest_peer_ids
                .iter()
                .any(|peer_id| peer_id == issuer_peer_id.as_bytes())
            {
                return Ok(());
            }
            let issuer_closeness_width = PAID_QUOTE_ISSUER_CLOSENESS_WIDTH;
            return Err(Error::Payment(format!(
                "Paid quote issuer {} is not among this node's local K={issuer_closeness_width} closest peers for {}",
                issuer_peer_id.to_hex(),
                hex::encode(xorname)
            )));
        }

        let attached = self.p2p_node.read().as_ref().map(Arc::clone);
        let Some(p2p_node) = attached else {
            #[cfg(any(test, feature = "test-utils"))]
            {
                crate::logging::warn!(
                    "PaymentVerifier: no P2PNode attached; paid-quote issuer \
                     K-closest check SKIPPED (test build). Production startup MUST call \
                     PaymentVerifier::attach_p2p_node."
                );
                return Ok(());
            }
            #[cfg(not(any(test, feature = "test-utils")))]
            {
                crate::logging::error!(
                    "PaymentVerifier: no P2PNode attached; rejecting paid-quote \
                     payment. This is a node-startup bug — \
                     PaymentVerifier::attach_p2p_node must be called before \
                     any PUT handler runs."
                );
                return Err(Error::Payment(
                    "Paid quote rejected: verifier is not wired to the P2P \
                     layer; cannot verify issuer closeness."
                        .into(),
                ));
            }
        };

        // Closeness *verification* must mirror the uploader's pure XOR-distance
        // peer selection. `find_closest_nodes_local_with_self` reranks the local
        // routing table by reachability (preferring directly-reachable peers,
        // XOR only as a tiebreaker), which demotes an XOR-close relay-only /
        // NAT'd peer out of the compared window and falsely rejects an honest
        // payment that legitimately quoted that peer. Use the XOR-only sibling
        // so this check matches how the client chose the quoted K-closest set.
        let issuer_closeness_width = PAID_QUOTE_ISSUER_CLOSENESS_WIDTH;
        let closest = p2p_node
            .dht_manager()
            .find_closest_nodes_local_by_distance_with_self(xorname, issuer_closeness_width)
            .await;
        if closest.iter().any(|node| node.peer_id == *issuer_peer_id) {
            return Ok(());
        }

        Err(Error::Payment(format!(
            "Paid quote issuer {} is not among this node's local K={issuer_closeness_width} closest peers for {}",
            issuer_peer_id.to_hex(),
            hex::encode(xorname)
        )))
    }

    /// Validate quote count, uniqueness, and basic structure.
    fn validate_quote_structure(payment: &ProofOfPayment) -> Result<()> {
        if payment.peer_quotes.is_empty() {
            return Err(Error::Payment("Payment has no quotes".to_string()));
        }

        let quote_count = payment.peer_quotes.len();
        if quote_count > CLOSE_GROUP_SIZE {
            return Err(Error::Payment(format!(
                "Payment must have at most {CLOSE_GROUP_SIZE} quotes, got {quote_count}"
            )));
        }

        let mut seen: Vec<&evmlib::EncodedPeerId> = Vec::with_capacity(quote_count);
        for (encoded_peer_id, _) in &payment.peer_quotes {
            if seen.contains(&encoded_peer_id) {
                return Err(Error::Payment(format!(
                    "Duplicate peer ID in payment quotes: {encoded_peer_id:?}"
                )));
            }
            seen.push(encoded_peer_id);
        }

        Ok(())
    }

    /// ADR-0004: enforce that every quoted price lies exactly on the public
    /// pricing curve.
    ///
    /// **Scope**: the price is forced by the quote's own signed
    /// `committed_key_count`, not merely required to be *somewhere* on the
    /// curve. `PaymentQuote` now carries `committed_key_count` and
    /// `commitment_pin`, both covered by the quote signature and the quote
    /// hash, so [`Self::binding_violation`] can hold the price to the count the
    /// quoter committed to. What this gate does not do is resolve the pin
    /// against the commitment the peer actually gossiped — a quoter can still
    /// commit to a count it does not store and price consistently with it.
    /// That cross-check is [`Self::cross_check_quotes`], gated separately by
    /// [`crate::replication::config::QUOTE_COMMITMENT_MISMATCH_TRUST_ENABLED`]
    /// because it carries a trust penalty rather than being reject-only.
    ///
    /// **Check**: exact recomputation, never price-inversion. The price is
    /// compared against `calculate_price(committed_key_count)` recomputed from
    /// the signed count. Inverting the price to a count would silently accept
    /// any value between two curve points, and would also let a quote price
    /// itself off one count while committing to another.
    ///
    /// **Where it runs**: in every [`VerificationContext`] over **every**
    /// quote in **both** quote types — all 7 single-node quotes
    /// ([`Self::validate_quote_arithmetic`]) and all 16 merkle candidates
    /// ([`Self::validate_merkle_candidate_arithmetic`]) — because the rule
    /// "every storer re-runs the price-equals-formula-of-count check on every
    /// quote in the bundle" (ADR-0004) needs no peer-specific state and depends
    /// only on the bundle itself, so every honest storer reaches the same
    /// verdict with no split-brain risk.
    ///
    /// **Reject-only**, per ADR-0004: no trust evidence is emitted, no audit
    /// is scheduled. The rejection is the consequence. The gate is
    /// rollout-gated by
    /// [`crate::replication::config::QUOTE_ARITHMETIC_RECHECK_ENABLED`]; when
    /// `false`, off-curve quotes are accepted and only telemetered
    /// ([`Self::log_off_curve_single_node`] /
    /// [`Self::log_off_curve_merkle`]), matching ADR-0004's observe-only
    /// rollout. Telemetry is invoked **after** ML-DSA-65 signature
    /// verification so unauthenticated senders cannot poison the rollout
    /// logs.
    fn validate_quote_arithmetic(payment: &ProofOfPayment) -> Result<()> {
        if !crate::replication::config::QUOTE_ARITHMETIC_RECHECK_ENABLED {
            return Ok(());
        }
        for (encoded_peer_id, quote) in &payment.peer_quotes {
            if let Some(detail) = Self::quote_arithmetic_violation(quote) {
                return Err(Error::Payment(format!(
                    "ADR-0004 off-curve quote rejected for peer {encoded_peer_id:?}: {detail}"
                )));
            }
        }
        Ok(())
    }

    /// The ADR-0004 forced-price rule for a single quote, returning a human
    /// diagnostic iff the quote violates it. Shared by single-node quotes and
    /// merkle candidates via [`Self::binding_violation`].
    ///
    /// The rule is the ADR's exact one — `price == calculate_price(
    /// committed_key_count)`, recomputed, never inverted from the price (which
    /// rounds) — PLUS a binding-shape check. There is no "legacy degradation"
    /// that infers an old quote from its field values: a `(0, None)` quote is
    /// rejected unless its price is exactly `calculate_price(0)`, closing the
    /// bypass where a modified node strips the pin yet prices above baseline.
    /// Old-format quotes (which never carried these fields) are tolerated only
    /// at the *wire-decode* layer, where they decode as `(0, None)` and are then
    /// held to the same baseline rule; an explicit version negotiation, not
    /// field inference, is the sanctioned path if non-baseline legacy quotes
    /// must ever be accepted.
    fn quote_arithmetic_violation(quote: &evmlib::PaymentQuote) -> Option<String> {
        Self::binding_violation(
            quote.committed_key_count,
            quote.commitment_pin,
            &quote.price,
        )
    }

    /// The shared ADR-0004 binding rule over a `(committed_key_count,
    /// commitment_pin, price)` triple, used for both quote types.
    ///
    /// Enforces, in order:
    /// 1. **Shape.** `(0, None)` baseline or `(n>0, Some(pin))` bound; the mixed
    ///    shapes `(n>0, None)` and `(0, Some(_))` are always rejected — a count
    ///    without a pin is unauditable, and a pin without a count is incoherent.
    /// 2. **Cap.** `committed_key_count <= MAX_COMMITMENT_KEY_COUNT`; a count a
    ///    commitment could never legitimately attest is rejected before pricing.
    /// 3. **Forced price.** `price == calculate_price(committed_key_count)`, by
    ///    exact recomputation.
    fn binding_violation(
        committed_key_count: u32,
        commitment_pin: Option<[u8; 32]>,
        price: &Amount,
    ) -> Option<String> {
        match (committed_key_count, commitment_pin.is_some()) {
            (0, false) | (1.., true) => {}
            (1.., false) => {
                return Some(format!(
                    "binding shape invalid: committed_key_count={committed_key_count} > 0 \
                     but commitment_pin is None (unauditable count)"
                ));
            }
            (0, true) => {
                return Some(
                    "binding shape invalid: committed_key_count=0 with a commitment_pin \
                     (incoherent baseline)"
                        .to_string(),
                );
            }
        }
        if committed_key_count > crate::replication::commitment::MAX_COMMITMENT_KEY_COUNT {
            return Some(format!(
                "committed_key_count={committed_key_count} exceeds MAX_COMMITMENT_KEY_COUNT={}",
                crate::replication::commitment::MAX_COMMITMENT_KEY_COUNT
            ));
        }
        let expected = calculate_price(Self::candidate_count_to_usize(u64::from(
            committed_key_count,
        )));
        if &expected == price {
            None
        } else {
            Some(format!(
                "price {price} does not equal calculate_price(committed_key_count={committed_key_count}) = {expected}"
            ))
        }
    }

    /// Pure ADR-0004 cross-check: compare a quote's claimed `(key_count, pin)`
    /// against a resolved signed commitment.
    ///
    /// This is the decision core of "peers cross-check the original": given a
    /// quote's binding and the actual `StorageCommitment` the pin was resolved
    /// to (from the sidecar, the gossip cache, or a fetch), decide whether the
    /// quote contradicts the commitment. It is deliberately a pure function over
    /// the two artifacts so it is exhaustively unit-testable without any cache,
    /// network, or trust wiring; the caller owns resolution and emission.
    ///
    /// Outcomes:
    /// - [`CrossCheck::Match`] — the pin matches the commitment's hash and the
    ///   counts agree: nothing to report.
    /// - [`CrossCheck::Mismatch`] — the pin matches the commitment's hash but
    ///   the quote's `committed_key_count` differs from the commitment's
    ///   `key_count`. Two artifacts signed by the same key contradict each
    ///   other: this is the deterministic, first-occurrence evidence.
    /// - [`CrossCheck::PinDoesNotResolve`] — the supplied commitment's hash does
    ///   not equal the quote's pin (wrong/garbled resolution). NOT evidence: the
    ///   caller must treat it as an unresolved pin (fetch/skip), never a
    ///   penalty, exactly like an unanswerable pin.
    ///
    /// A baseline quote `(0, None)` is never cross-checked (it pins nothing);
    /// callers skip it before reaching here.
    fn cross_check_binding(
        quoted_key_count: u32,
        quoted_pin: [u8; 32],
        commitment: &crate::replication::commitment::StorageCommitment,
    ) -> CrossCheck {
        // The pin IS the commitment hash; if the resolved commitment hashes to
        // something else, this is not the artifact the quote pinned.
        match crate::replication::commitment::commitment_hash(commitment) {
            Some(h) if h == quoted_pin => {
                if commitment.key_count == quoted_key_count {
                    CrossCheck::Match
                } else {
                    CrossCheck::Mismatch {
                        quoted_key_count,
                        committed_key_count: commitment.key_count,
                    }
                }
            }
            _ => CrossCheck::PinDoesNotResolve,
        }
    }

    /// Resolve a cached peer commitment record to its commitment *only if* it
    /// was seen within the answerability TTL; a staler entry is treated as
    /// unknown (ADR-0004: "a cached commitment older than the answerability TTL
    /// is treated as unknown"). Pure over `(record, now, ttl)` so the TTL
    /// boundary is unit-testable without the async cache/network path.
    fn fresh_cached_commitment(
        rec: &crate::replication::commitment_state::PeerCommitmentRecord,
        pin: [u8; 32],
        now: std::time::Instant,
        ttl: std::time::Duration,
    ) -> Option<crate::replication::commitment::StorageCommitment> {
        if now.saturating_duration_since(rec.received_at) >= ttl {
            return None; // stale cache entry -> treat as unknown
        }
        // Only resolve when the cached commitment is actually the one the quote
        // pinned. The auditor cache holds a peer's LATEST gossiped commitment,
        // which may be a DIFFERENT pin than this quote's; returning it would make
        // `cross_check_binding` yield `PinDoesNotResolve` and wrongly suppress
        // the fetch fallback for the quoted pin. A pin mismatch here means "not
        // cached" -> fall through to fetch.
        if rec.commitment_hash() != Some(pin) {
            return None;
        }
        rec.last_commitment().cloned()
    }

    /// Resolve a `(peer, pin)` from the gossip commitment cache, if the cache is
    /// wired and holds a fresh entry whose hash matches the pin. Shared by the
    /// single-node and merkle cross-check paths.
    async fn cache_resolve(
        cache: Option<&CommitmentCache>,
        peer_id: PeerId,
        pin: [u8; 32],
        now: std::time::Instant,
        ttl: std::time::Duration,
    ) -> Option<crate::replication::commitment::StorageCommitment> {
        let cache = cache?;
        let guard = cache.read().await;
        guard
            .get(&peer_id)
            .and_then(|rec| Self::fresh_cached_commitment(rec, pin, now, ttl))
    }

    /// Parse and validate ADR-0004 commitment sidecars into a `(peer, pin) ->
    /// commitment` map. Each blob is deserialized and held to the SAME gates as
    /// a gossip-ingested or fetched commitment (peer id derived from its own
    /// `sender_peer_id`, `BLAKE3(pubkey) == sender_peer_id`, valid signature),
    /// keyed by `(its own peer, its own hash)`. Resolution then matches a quote
    /// only when both the quote's peer AND pin equal the sidecar's, so a sidecar
    /// can never satisfy a different peer's or a different pin's quote. An
    /// unparseable or invalid sidecar is silently skipped (resolution falls back
    /// to gossip/fetch), never a hard error on the payment path.
    fn index_valid_sidecars(
        sidecars: &[Vec<u8>],
    ) -> HashMap<(PeerId, [u8; 32]), crate::replication::commitment::StorageCommitment> {
        use crate::replication::commitment::MAX_COMMITMENT_SIDECAR_BYTES;
        let mut map = HashMap::new();
        // Bound the number of sidecars we even look at: a legitimate bundle has
        // at most one commitment per quote/candidate. `MAX_SIDECARS_PER_BUNDLE`
        // (= CANDIDATES_PER_POOL, the larger of the two) caps the deserialize/
        // verify work a malicious client can force on the hot path.
        for blob in sidecars.iter().take(MAX_SIDECARS_PER_BUNDLE) {
            // Cap blob size before parsing: never attempt to deserialize an
            // oversized commitment.
            if blob.len() > MAX_COMMITMENT_SIDECAR_BYTES {
                continue;
            }
            let Ok(commitment) =
                rmp_serde::from_slice::<crate::replication::commitment::StorageCommitment>(blob)
            else {
                continue; // unparseable -> skip
            };
            let peer_id = PeerId::from_bytes(commitment.sender_peer_id);
            let Some(pin) = crate::replication::commitment::commitment_hash(&commitment) else {
                continue;
            };
            // Validate against its own (peer, pin): peer binding + pubkey
            // derivation + signature + hash==pin.
            if Self::fetched_commitment_is_valid(&commitment, &peer_id, pin) {
                map.insert((peer_id, pin), commitment);
            }
        }
        map
    }

    /// ADR-0004 "peers cross-check the original": for each non-baseline quote in
    /// a client-put bundle, resolve its `commitment_pin` and report a count/pin
    /// contradiction.
    ///
    /// Resolution order: the sidecar first (the commitment arrived with the
    /// quote, validated synchronously — no state, no network), then the gossip
    /// cache (only if the neighbour's commitment was seen within
    /// `GOSSIP_ANSWERABILITY_TTL`; a staler entry is treated as unknown, per the
    /// ADR's "cached commitment older than the answerability TTL is treated as
    /// unknown"), then an off-hot-path `GetCommitmentByPin` fetch for pins still
    /// unresolved. A pin that resolves nowhere is simply skipped — an unresolved
    /// pin is never a penalty.
    ///
    /// A genuine [`CrossCheck::Mismatch`] is a deterministic, first-occurrence
    /// contradiction between two same-key-signed artifacts: when enforcing, it
    /// emits [`FailureEvidence::QuoteCommitmentMismatch`] to the trust engine
    /// (same lane as a confirmed deterministic audit failure — NOT the timeout
    /// silence lane); when observe-only, it only logs. Always best-effort: a
    /// missing cache or absent `P2PNode` degrades to "resolve nothing", never an
    /// error on the payment path — the synchronous arithmetic gate and the
    /// later audit remain the load-bearing checks.
    async fn cross_check_quotes(
        &self,
        payment: &ProofOfPayment,
        commitment_sidecars: &[Vec<u8>],
        paid_peer: Option<[u8; 32]>,
    ) {
        let now = std::time::Instant::now();
        let ttl = crate::replication::commitment_state::GOSSIP_ANSWERABILITY_TTL;
        let p2p = self.p2p_node.read().as_ref().map(Arc::clone);
        let monetized_pin_tx = self.monetized_pin_tx.read().as_ref().cloned();
        let cache = self.commitment_cache.read().as_ref().map(Arc::clone);

        // ADR-0004 "the commitment arrived with the quote": parse and FULLY
        // validate the sidecars (peer/pubkey/signature/hash gates, keyed by
        // `(peer, pin)`), so the cross-check resolves synchronously without a
        // gossip-cache hit or a post-payment fetch. An invalid sidecar is simply
        // dropped (resolution falls back to gossip/fetch), never a hard error.
        let sidecar_map = Self::index_valid_sidecars(commitment_sidecars);

        // Inline pass: resolve from the sidecar first, then the gossip cache
        // (cheap, no network). Pins that don't resolve here are collected for
        // the off-hot-path fetch.
        let mut unresolved: Vec<(PeerId, [u8; 32], u32, Vec<u8>)> = Vec::new();
        for (encoded_peer_id, quote) in &payment.peer_quotes {
            let Some(pin) = quote.commitment_pin else {
                continue; // baseline quote pins nothing
            };
            let peer_id = PeerId::from_bytes(*encoded_peer_id.as_bytes());

            // ADR-0004 Amendment 2: only the PAID candidate's commitment earned
            // money, so only its pin is routed for a deterministic first audit
            // (the drainer dedups, rate-budgets, and respects the cooldown).
            // Pre-amendment this fired for every pinned quote in the bundle —
            // up to CLOSE_GROUP_SIZE audits per proof for peers that were never
            // paid — a 7x term in the fleet-wide amplification that degraded
            // v0.14.3. Best-effort: a closed channel just means no first audit
            // is scheduled, never an error on the payment path.
            let is_paid = paid_peer.is_some_and(|paid| paid == *encoded_peer_id.as_bytes());
            if is_paid {
                if let Some(ref tx) = monetized_pin_tx {
                    // Bounded queue: drop on full (best-effort, penalty-free;
                    // the peer's next settled payment re-nominates it). Count a
                    // Full drop so ingress saturation is observable; a Closed
                    // channel just means the engine is shutting down.
                    if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) =
                        tx.try_send(crate::replication::MonetizedPinEvent {
                            peer: peer_id,
                            pin,
                            key_count: quote.committed_key_count,
                            quote_ts: quote.timestamp,
                        })
                    {
                        crate::replication::note_monetized_ingress_drop();
                    }
                }
            }
            // Resolution order: sidecar (synchronous, no state) -> gossip cache
            // (fresh within TTL) -> fetch fallback (collected as unresolved).
            let resolved = match sidecar_map.get(&(peer_id, pin)) {
                Some(c) => Some(c.clone()),
                None => Self::cache_resolve(cache.as_ref(), peer_id, pin, now, ttl).await,
            };
            match resolved {
                Some(commitment) => {
                    let artifact = rmp_serde::to_vec(quote).unwrap_or_default();
                    Self::handle_cross_check(
                        &peer_id,
                        pin,
                        quote.committed_key_count,
                        artifact,
                        &commitment,
                        p2p.as_ref(),
                    )
                    .await;
                }
                None => unresolved.push((
                    peer_id,
                    pin,
                    quote.committed_key_count,
                    rmp_serde::to_vec(quote).unwrap_or_default(),
                )),
            }
        }

        // Off-hot-path fallback: fetch the unresolved pins via
        // `GetCommitmentByPin` and cross-check the results in a detached task,
        // so `verify_payment` does not block on the network.
        if unresolved.is_empty() {
            return;
        }
        let Some(p2p) = p2p else {
            return; // no P2P handle: cannot fetch, leave graced
        };
        let neg_cache = Arc::clone(&self.pin_fetch_negative_cache);
        tokio::spawn(async move {
            Self::drain_unresolved_pin_fetches(&p2p, &neg_cache, unresolved).await;
        });
    }

    /// Fetch each unresolved pin via `GetCommitmentByPin` and cross-check the
    /// result. Bounded at [`MAX_PIN_FETCHES_PER_BUNDLE`] per call, negatively
    /// cached per `(peer, pin)`, and graced on any miss/timeout. Shared by the
    /// single-node and merkle cross-check paths; meant to run in a detached task
    /// off the payment hot path.
    async fn drain_unresolved_pin_fetches(
        p2p: &Arc<P2PNode>,
        neg_cache: &PinFetchNegativeCache,
        unresolved: Vec<(PeerId, [u8; 32], u32, Vec<u8>)>,
    ) {
        let mut fetched = 0usize;
        for (peer_id, pin, quoted_key_count, artifact) in unresolved {
            if fetched >= crate::replication::config::MAX_PIN_FETCHES_PER_BUNDLE {
                debug!("ADR-0004 pin-fetch cap reached for this bundle; leaving rest graced");
                break;
            }
            // Skip pins already known-unresolvable for this peer.
            if neg_cache.lock().get(&(peer_id, pin)).is_some() {
                continue;
            }
            fetched += 1;
            match Self::fetch_commitment_by_pin(p2p, &peer_id, pin).await {
                Some(commitment) => {
                    Self::handle_cross_check(
                        &peer_id,
                        pin,
                        quoted_key_count,
                        artifact,
                        &commitment,
                        Some(p2p),
                    )
                    .await;
                }
                None => {
                    // NotRetained / timeout / malformed: graced (never a
                    // penalty), but remembered so we don't re-fetch.
                    neg_cache.lock().put((peer_id, pin), ());
                }
            }
        }
    }

    /// Apply the ADR-0004 cross-check verdict for one resolved `(peer, pin,
    /// quoted_count)` against `commitment`, emitting a trust failure on a
    /// genuine mismatch (when enforcing) or logging it (observe-only). Shared by
    /// the inline cache pass and the background fetch path so both reach the
    /// same verdict and emission.
    async fn handle_cross_check(
        peer_id: &PeerId,
        pin: [u8; 32],
        quoted_key_count: u32,
        quote_artifact: Vec<u8>,
        commitment: &crate::replication::commitment::StorageCommitment,
        p2p: Option<&Arc<P2PNode>>,
    ) {
        let CrossCheck::Mismatch {
            quoted_key_count,
            committed_key_count,
        } = Self::cross_check_binding(quoted_key_count, pin, commitment)
        else {
            return; // Match or PinDoesNotResolve: nothing to report
        };
        // The evidence is only meaningful if it carries the signed quote
        // artifact (one of the two contradicting same-key signatures). An empty
        // artifact — a re-serialization failure upstream — would produce
        // non-portable, unverifiable evidence, so grace it (log) instead of
        // emitting it: the deterministic first audit still convicts a genuine
        // inflater on the disk bytes.
        if quote_artifact.is_empty() {
            warn!(
                "ADR-0004 quote/commitment mismatch for {peer_id}: dropping evidence, \
                 quote artifact failed to serialize (graced; the audit still runs)"
            );
            return;
        }
        // Build the portable evidence variant — the two same-key-signed
        // artifacts that contradict each other, carried in full so any third
        // party can re-verify both signatures and recompute the contradiction.
        // This value IS the record; `emit_mismatch_evidence` turns it into the
        // trust action (or an observe-only log).
        let evidence = crate::replication::types::FailureEvidence::QuoteCommitmentMismatch {
            peer: *peer_id,
            pinned_commitment: pin,
            quoted_key_count,
            committed_key_count,
            quote_artifact,
            commitment: Box::new(commitment.clone()),
        };
        Self::emit_mismatch_evidence(&evidence, p2p).await;
    }

    /// Route a `QuoteCommitmentMismatch` evidence record: when enforcing, report
    /// it to the trust engine as a confirmed deterministic failure (an
    /// `ApplicationFailure` — same lane as a confirmed audit failure, NOT the
    /// timeout silence lane); when observe-only, only log it. Separated so the
    /// evidence→action mapping is unit-testable independent of resolution.
    async fn emit_mismatch_evidence(
        evidence: &crate::replication::types::FailureEvidence,
        p2p: Option<&Arc<P2PNode>>,
    ) {
        let crate::replication::types::FailureEvidence::QuoteCommitmentMismatch {
            peer,
            quoted_key_count,
            committed_key_count,
            ..
        } = evidence
        else {
            return; // only this variant is handled here
        };
        let enforce = crate::replication::config::QUOTE_COMMITMENT_MISMATCH_TRUST_ENABLED;
        if enforce {
            warn!(
                "ADR-0004 quote/commitment mismatch (enforcing) for {peer}: quote claims \
                 {quoted_key_count} keys but pinned commitment attests {committed_key_count}"
            );
            if let Some(p2p) = p2p {
                p2p.report_trust_event(
                    peer,
                    saorsa_core::TrustEvent::ApplicationFailure(
                        crate::replication::config::AUDIT_FAILURE_TRUST_WEIGHT,
                    ),
                )
                .await;
            }
        } else {
            warn!(
                "ADR-0004 quote/commitment mismatch observed (not enforcing) for {peer}: quote \
                 claims {quoted_key_count} keys but pinned commitment attests {committed_key_count}"
            );
        }
    }

    /// Fetch a peer's commitment by pin via `GetCommitmentByPin`, returning it
    /// only if the peer answered `Found` with a commitment that (a) is validly
    /// signed and peer-bound and (b) actually hashes to the requested pin.
    /// `None` on `NotRetained`, timeout, malformed, or any verification failure
    /// — all graced (the caller never penalises an unresolved pin).
    async fn fetch_commitment_by_pin(
        p2p: &Arc<P2PNode>,
        peer_id: &PeerId,
        pin: [u8; 32],
    ) -> Option<crate::replication::commitment::StorageCommitment> {
        use crate::replication::config::{PIN_FETCH_TIMEOUT, REPLICATION_PROTOCOL_ID};
        use crate::replication::protocol::{
            GetCommitmentByPin, GetCommitmentByPinResponse, ReplicationMessage,
            ReplicationMessageBody,
        };
        let msg = ReplicationMessage {
            request_id: 0,
            body: ReplicationMessageBody::GetCommitmentByPin(GetCommitmentByPin { pin }),
        };
        let encoded = msg.encode().ok()?;
        let resp = p2p
            .send_request(peer_id, REPLICATION_PROTOCOL_ID, encoded, PIN_FETCH_TIMEOUT)
            .await
            .ok()?;
        let decoded = ReplicationMessage::decode(&resp.data).ok()?;
        let ReplicationMessageBody::GetCommitmentByPinResponse(GetCommitmentByPinResponse::Found {
            commitment,
        }) = decoded.body
        else {
            return None; // NotRetained / unexpected -> graced
        };
        Self::fetched_commitment_is_valid(&commitment, peer_id, pin).then_some(commitment)
    }

    /// The untrusted-fetched-commitment validation gates, pure over
    /// `(commitment, peer_id, pin)` so they are unit-testable. A fetched
    /// commitment is accepted only if it passes the SAME gates as a gossip
    /// ingest, so a peer cannot answer with another peer's (validly signed)
    /// commitment and have it pass as its own:
    ///   (a) it is bound to THIS peer (`sender_peer_id == peer_id`),
    ///   (b) the embedded pubkey derives that peer id (`BLAKE3(pk) == id`),
    ///   (c) its signature is valid (binds the pubkey),
    ///   (d) it actually hashes to the pin we asked for.
    fn fetched_commitment_is_valid(
        commitment: &crate::replication::commitment::StorageCommitment,
        peer_id: &PeerId,
        pin: [u8; 32],
    ) -> bool {
        commitment.sender_peer_id == *peer_id.as_bytes()
            && *blake3::hash(&commitment.sender_public_key).as_bytes() == commitment.sender_peer_id
            && crate::replication::commitment::verify_commitment_signature(commitment)
            && crate::replication::commitment::commitment_hash(commitment) == Some(pin)
    }

    /// Single-node telemetry for off-curve quotes. Always returns; never
    /// errors. MUST be called only after ML-DSA-65 signature verification has
    /// passed, so unauthenticated peers cannot drive log volume.
    fn log_off_curve_single_node(payment: &ProofOfPayment) {
        if crate::replication::config::QUOTE_ARITHMETIC_RECHECK_ENABLED {
            return; // enforce mode already rejected; no separate telemetry.
        }
        for (encoded_peer_id, quote) in &payment.peer_quotes {
            if let Some(detail) = Self::quote_arithmetic_violation(quote) {
                warn!(
                    "ADR-0004 off-curve single-node quote observed (not enforcing): \
                     peer {encoded_peer_id:?} {detail}"
                );
            }
        }
    }

    /// ADR-0004 sister gate for the merkle batch path: every candidate's
    /// `price` field must lie on the pricing curve, by exact recomputation.
    /// See [`Self::validate_quote_arithmetic`] for the rationale; semantics
    /// (reject-only, rollout-gated, no trust evidence) are identical.
    fn validate_merkle_candidate_arithmetic(
        pool: &evmlib::merkle_payments::MerklePaymentCandidatePool,
    ) -> Result<()> {
        if !crate::replication::config::QUOTE_ARITHMETIC_RECHECK_ENABLED {
            return Ok(());
        }
        for candidate in &pool.candidate_nodes {
            if let Some(detail) = Self::binding_violation(
                candidate.committed_key_count,
                candidate.commitment_pin,
                &candidate.price,
            ) {
                return Err(Error::Payment(format!(
                    "ADR-0004 merkle candidate rejected (reward {}): {detail}",
                    candidate.reward_address
                )));
            }
        }
        Ok(())
    }

    /// Merkle batch telemetry for off-curve candidates. Always returns; never
    /// errors. MUST be called only after ML-DSA-65 signature verification has
    /// passed.
    fn log_off_curve_merkle(pool: &evmlib::merkle_payments::MerklePaymentCandidatePool) {
        if crate::replication::config::QUOTE_ARITHMETIC_RECHECK_ENABLED {
            return; // enforce mode already rejected; no separate telemetry.
        }
        for candidate in &pool.candidate_nodes {
            if let Some(detail) = Self::binding_violation(
                candidate.committed_key_count,
                candidate.commitment_pin,
                &candidate.price,
            ) {
                warn!(
                    "ADR-0004 merkle candidate violation observed (not enforcing): \
                     reward {} {detail}",
                    candidate.reward_address
                );
            }
        }
    }

    /// ADR-0008 merkle payment-parity telemetry.
    ///
    /// Records what a batch actually settled per paid node against what
    /// single-node parity requires, and which regime the receipt's timestamp put
    /// it in. Parity is enforced, so a post-boundary shortfall has already been
    /// rejected before this runs and cannot appear here; what this measures is
    /// how much traffic is still arriving on pre-boundary (1x) receipts, which
    /// is what tells us the compatibility window can be considered closed.
    /// Observational only: it never rejects and never feeds trust scoring — a
    /// client on a legacy receipt is running old code, not misbehaving.
    ///
    /// Two call-site requirements, both load-bearing for the signal:
    /// - **After full admission validation.** Every paid index, reward address
    ///   and amount must already have been checked. Logging earlier lets a
    ///   proof that is rejected moments later enter the rollout signal, which
    ///   would understate parity with samples that never resulted in a store.
    /// - **Store admissions only.** A paid-list admission reprices nothing and
    ///   would double-count a batch already measured when it was stored.
    ///
    /// Keyed by `pool_hash`, not by chunk address: one on-chain settlement
    /// covers up to 256 chunks, so a line per chunk would emit 256 duplicate
    /// samples of one economic event and let a big batch outvote a small one.
    ///
    /// Carrying the pool hash in the line is not enough on its own — it makes
    /// the stream *deduplicable* but leaves the emitted cardinality at one line
    /// per chunk. So the first emission for a pool is recorded in
    /// [`Self::merkle_parity_logged`] and later admissions from the same batch
    /// return without logging. The check-and-insert is a single locked
    /// operation, so concurrent admissions from one batch also produce exactly
    /// one line. "Once per pool" is per node/verifier: every storer that admits
    /// a chunk from the batch still contributes its own sample, which is what
    /// makes the signal a measure of traffic reaching the fleet.
    fn log_merkle_parity(
        &self,
        pool_hash: PoolHash,
        payment_info: &OnChainPaymentInfo,
        expected_bare: Amount,
        expected_parity: Amount,
        required_multiplier: u64,
    ) {
        // Check-and-insert under one lock: the loser of a race sees its own
        // insert report a prior entry and stays quiet.
        if self
            .merkle_parity_logged
            .lock()
            .put(pool_hash, ())
            .is_some()
        {
            return;
        }
        self.merkle_parity_emissions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let min_paid = payment_info
            .paid_node_addresses
            .iter()
            .map(|(_, _, amount)| *amount)
            .min()
            .unwrap_or(Amount::ZERO);
        let at_parity = min_paid >= expected_parity;
        let legacy_receipt = required_multiplier < PAID_QUOTE_PAYMENT_MULTIPLIER;

        info!(
            target: "ant_node::payment::merkle_parity",
            "Merkle parity: pool={}, depth={}, paid_nodes={}, receipt_ts={}, \
             min_paid={min_paid}, expected_bare={expected_bare}, \
             expected_parity={expected_parity}, required_multiplier={required_multiplier}, \
             legacy_receipt={legacy_receipt}, at_parity={at_parity}",
            hex::encode(pool_hash),
            payment_info.depth,
            payment_info.paid_node_addresses.len(),
            payment_info.merkle_payment_timestamp,
        );
    }

    /// Pure curve-canonicality predicate: does `price` lie exactly on the
    /// pricing curve? Equivalent to "there exists some non-negative integer
    /// `n` such that `calculate_price(n) == price`".
    ///
    /// Separated from the rollout-gated outer gates so the canonicality rule
    /// itself is unit-testable independent of the gate. Callers MUST use this
    /// and not `derive_records_stored_from_price` directly: the latter floors
    /// and is not a canonicality test.
    ///
    /// Saturation: `derive_records_stored_from_price` saturates to `u64::MAX`
    /// for prices beyond `calculate_price(u64::MAX)`, and
    /// [`Self::candidate_count_to_usize`] saturates to `usize::MAX` on 32-bit
    /// targets. Both saturation regimes converge on `calculate_price`'s own
    /// saturation ceiling; an honest in-range price (which can never approach
    /// these regions — `MAX_COMMITMENT_KEY_COUNT` is `1_000_000`) round-trips
    /// exactly.
    #[allow(dead_code)] // boolean convenience for tests + follow-up slices
    fn quote_price_is_on_curve(price: &Amount) -> bool {
        Self::price_off_curve_diagnostics(price).is_none()
    }

    /// Returns `Some((candidate_count, recomputed))` iff `price` is off-curve;
    /// `None` iff `price` is on-curve. The tuple is the diagnostic detail used
    /// by both the rejection error message and the telemetry warning.
    fn price_off_curve_diagnostics(price: &Amount) -> Option<(u64, Amount)> {
        let candidate_count = derive_records_stored_from_price(*price);
        let recomputed = calculate_price(Self::candidate_count_to_usize(candidate_count));
        if recomputed == *price {
            None
        } else {
            Some((candidate_count, recomputed))
        }
    }

    /// Narrow the canonicality predicate's `u64` candidate into `usize` for
    /// [`calculate_price`]. On every 64-bit target (the only supported
    /// production target) this is the identity; on 32-bit targets we saturate
    /// to `usize::MAX`, which matches `calculate_price`'s own
    /// `Amount::saturating_mul` behaviour so the round-trip still terminates
    /// in the same saturation regime rather than panicking.
    fn candidate_count_to_usize(candidate_count: u64) -> usize {
        usize::try_from(candidate_count).unwrap_or(usize::MAX)
    }

    /// Minimum number of candidate `pub_keys` (out of 16) whose derived
    /// `PeerId` must be among the DHT's actual closest peers to the pool
    /// midpoint address for the pool to be accepted.
    ///
    /// Set to a simple majority (9/16). Two nodes' views of the closest set
    /// to a midpoint diverge on a young, high-churn, NAT-heavy network — by
    /// more than a near-unanimous threshold tolerates — so a stricter bar
    /// rejected honest pools whose candidates are genuinely drawn from the
    /// midpoint's close group but don't all reappear in this storer's own
    /// lookup. A majority absorbs that divergence while still requiring most
    /// candidates to be real peers the live DHT lists as closest.
    ///
    /// Security cost: a lower threshold widens the room for the "pay-yourself"
    /// attack — an attacker running real neighbourhood peers needs fewer of
    /// them to clear a majority than to clear a near-unanimous bar. No theft
    /// of funds is possible regardless (payment binds on-chain to the rewards
    /// address); the cost is that grinding storage payments back to your own
    /// nodes gets cheaper. Each counted candidate must still be a peer the
    /// live DHT actually returns as closest — a fabricated off-network key
    /// cannot satisfy this — so the floor is "run N real top-K Sybil nodes
    /// AND grind the midpoint", just with a smaller N. Pairs with the planned
    /// pool-midpoint consensus-anchor work, which removes the midpoint
    /// grinding freedom that makes a low threshold dangerous.
    const CANDIDATE_CLOSENESS_REQUIRED: usize = 9;

    /// Timeout for the authoritative network lookup used by the closeness
    /// check.
    ///
    /// Iterative Kademlia lookups can cascade through `MAX_ITERATIONS = 20`
    /// rounds in saorsa-core's `find_closest_nodes_network`, and a single
    /// unresponsive peer's dial can take 20–30s before timing out. On a
    /// young network (e.g. fresh testnet, NAT-simulated peers in 30% of
    /// the swarm) iterations average ~10s each — captured trace from
    /// STG-01 EWR-3 ant-node-1 just before a pre-fix timeout:
    ///
    /// ```text
    /// Iter 0: +0.0s | Iter 1: +0.2s | Iter 2: +6.6s | Iter 3: +13.1s
    /// Iter 4: +20.9s | Iter 5: +39.8s | Iter 6: +50.8s | [60s wall]
    /// ```
    ///
    /// 60s caps the lookup at ~7 iterations and rejects honest pools whose
    /// candidates only emerge after iteration 7. 240s gives ~1.2× headroom
    /// over the ~200s natural worst-case runtime on a 1k-node testnet.
    ///
    /// `DoS` amplification stays bounded at roughly one in-flight lookup
    /// per unique `pool_hash` under typical load, via
    /// [`closeness_pass_cache`] + [`inflight_closeness`]. The bound is
    /// "typical" because `inflight_closeness` is an LRU and a sustained
    /// flood of unique `pool_hash` entries can evict an in-flight slot,
    /// at which point a second leader can race for the same pool (see
    /// [`InflightGuard::drop`]). At steady state the pool cache and pool
    /// signature verification gate keep this rare in practice.
    const CLOSENESS_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(4);

    /// Width of the storer's authoritative network lookup, in peers.
    ///
    /// The client over-queries `2 * CANDIDATES_PER_POOL = 32` peers via
    /// `find_closest_peers(addr, 32)` (see
    /// `ant-client/ant-core/src/data/client/merkle.rs::get_merkle_candidate_pool`)
    /// and selects 16 valid responders by XOR distance — so truly-close
    /// peers that are slow, NAT'd, or briefly unreachable get filtered
    /// out and replaced by peers from positions 17–32 of the network's
    /// actual ranking. The storer must therefore verify against the same
    /// wider window: a pool containing peers from positions 17–32 is
    /// honest (those peers really exist in the network's closest-32 set),
    /// it's just that the client's quote-collection step couldn't reach
    /// the peers at positions <17 in time.
    ///
    /// Empirical effect on STG-01 (1k-node testnet, 30% NAT-simulated):
    /// widening from K=16 to K=32 dropped client-side closeness
    /// mismatches from ~115 to ~31 per 5 min, a 73% reduction.
    ///
    /// Performance note: `count` does not just truncate the lookup —
    /// `find_closest_nodes_network` keeps iterating until either
    /// `MAX_ITERATIONS` is reached or `best_nodes.len() >= count`. K=32
    /// can therefore extend lookups by a few iterations on sparse
    /// networks vs K=16, which reinforces (rather than undermines) the
    /// timeout bump above.
    ///
    /// Security: the pay-yourself attack still requires the attacker's
    /// fabricated `PeerId`s to land in the storer's authoritative top-K, so
    /// the dominant cost is Sybil-grinding midpoint addresses or running real
    /// nodes near the target. The leniency for honest divergence comes from
    /// the `CANDIDATE_CLOSENESS_REQUIRED` majority threshold, not from this
    /// window; widening the window further was measured as too heavy on the
    /// lookup path.
    const CLOSENESS_LOOKUP_WIDTH: usize = 2 * evmlib::merkle_payments::CANDIDATES_PER_POOL;

    /// Maximum waiter → leader retries when the leader's future was cancelled
    /// or panicked before publishing a result. Beyond this the waiter returns
    /// a visible error rather than spinning indefinitely through a
    /// cancellation cascade.
    ///
    /// Worst-case waiter wall-clock is `(MAX_LEADER_RETRIES + 1) *
    /// CLOSENESS_LOOKUP_TIMEOUT` (one wait per attempt). Kept low (1)
    /// because the only realistic trigger is leader future-cancellation,
    /// which should be extraordinarily rare; under sustained adversarial
    /// cancellation a higher cap doesn't add resilience, it just hides
    /// the symptom. With `CLOSENESS_LOOKUP_TIMEOUT = 240s` this caps a
    /// single user-visible verification at ~8 min worst case (vs ~20 min
    /// at the previous value of 4).
    const MAX_LEADER_RETRIES: usize = 1;

    /// Compute the storer's authoritative-lookup width for a candidate pool.
    ///
    /// Returns `max(CLOSENESS_LOOKUP_WIDTH, pool_len)`: matches the client's
    /// over-query width today, and scales with the pool if a future protocol
    /// bump grows pool size beyond `CLOSENESS_LOOKUP_WIDTH`. Truncating to
    /// `CLOSENESS_LOOKUP_WIDTH` in that future case would re-open the
    /// K-too-small failure mode (the storer would reject honest pools whose
    /// candidates legitimately span a wider XOR range than the storer
    /// fetched). Pinned by `closeness_lookup_count_uses_max_of_width_and_pool_len`.
    const fn closeness_lookup_count(pool_len: usize) -> usize {
        if Self::CLOSENESS_LOOKUP_WIDTH > pool_len {
            Self::CLOSENESS_LOOKUP_WIDTH
        } else {
            pool_len
        }
    }

    /// Verify that the candidate pool's `pub_keys` correspond to peers that
    /// are actually XOR-closest to the pool midpoint address, by querying
    /// the DHT for its closest peers to that address and requiring that a
    /// majority of the candidates match.
    ///
    /// **What this blocks**: the "pay yourself" attack. Candidate signatures
    /// only cover `(price, reward_address, timestamp)` and the `pub_key` bytes —
    /// nothing ties a candidate to a network-registered identity or to the
    /// pool neighbourhood. Without this check an attacker can generate 16
    /// ML-DSA keypairs locally, point all 16 `reward_address` fields at a
    /// single attacker-controlled wallet, submit the merkle payment, and drain
    /// their own payment back out.
    ///
    /// **How it blocks**: each candidate's `PeerId = BLAKE3(pub_key)`; the DHT
    /// is the authoritative source of "which peers exist at this XOR
    /// coordinate". If the attacker's 16 fabricated `PeerId`s are not among
    /// the peers the network actually lists as closest to the pool address,
    /// the pool is forged.
    ///
    /// **Scope**: a `MerklePaymentProof` carries exactly one `winner_pool`
    /// (the pool the smart contract selected for the batch). Every storing
    /// node that receives the proof independently re-runs this check against
    /// that same pool, so a forged pool is rejected at every node it
    /// reaches.
    ///
    /// **Known limitation — Sybil-grinding**: `midpoint_proof.address()` is a
    /// BLAKE3 hash of attacker-controllable inputs (leaf bytes, tree root,
    /// timestamp). A determined attacker who *also* runs Sybil DHT nodes can
    /// grind the midpoint until it lands in a region where a majority of
    /// their Sybil keys are the true network-closest — at which point this check
    /// passes for the attacker. Closing that gap requires binding the
    /// midpoint to an attacker-uncontrolled value (e.g. a block hash at
    /// payment time or an on-chain VRF) or a Sybil-resistant identity
    /// layer. This defence raises the attack cost from "free" to "run N
    /// Sybil nodes AND grind", which is a meaningful but not complete
    /// improvement.
    async fn verify_merkle_candidate_closeness(
        &self,
        pool: &evmlib::merkle_payments::MerklePaymentCandidatePool,
        pool_hash: PoolHash,
    ) -> Result<()> {
        // Fast path: this node already verified this pool successfully.
        // A batch of 256 chunks shares one winner_pool, so without this cache
        // we'd pay a Kademlia lookup per chunk.
        if self.closeness_pass_cache.lock().get(&pool_hash).is_some() {
            return Ok(());
        }

        // Single-flight: on each attempt, either claim leadership by
        // inserting a fresh `ClosenessSlot`, or wait on an existing leader
        // and read its published result. The leader holds an `Arc` to the
        // slot independent of the LruCache so waiters are still woken if
        // eviction pressure kicked the cache entry.
        //
        // The `notified_owned()` future snapshots the `notify_waiters`
        // counter at the moment of construction (while we hold the lock),
        // which makes the subsequent `.await` race-free: if the leader
        // calls `notify_waiters` between our construction and our poll, the
        // counter has advanced and the future resolves immediately on first
        // poll.
        //
        // Bounded retry: if we're a waiter and the leader gets cancelled or
        // panics (slot.result.get() == None after wake-up), we loop back to
        // claim leadership. `MAX_LEADER_RETRIES` bounds the attempts so
        // adversarial cancellation cascades cannot spin this indefinitely.
        for attempt in 0..=Self::MAX_LEADER_RETRIES {
            // Release the mutex guard explicitly before any await below.
            // Clippy wants `if let ... else` written as `map_or_else`, but
            // any such rewrite re-borrows the locked `inflight` inside the
            // closure and fails the borrow checker — so the lint is
            // silenced here.
            #[allow(clippy::option_if_let_else)]
            let (waiter_slot, leader_slot) = {
                let mut inflight = self.inflight_closeness.lock();
                let chosen = if let Some(existing) = inflight.get(&pool_hash) {
                    (Some(Arc::clone(existing)), None)
                } else {
                    let slot = Arc::new(ClosenessSlot::new());
                    inflight.put(pool_hash, Arc::clone(&slot));
                    (None, Some(slot))
                };
                drop(inflight);
                chosen
            };

            if let Some(slot) = waiter_slot {
                // Build the owned-notified future BEFORE awaiting, so it
                // snapshots the `notify_waiters` counter now. The slot
                // already existed when we locked, so the leader is either
                // running or finished; in both cases the snapshot + counter
                // check ensures we wake up correctly.
                let notified = slot.notified_owned();
                notified.await;

                // Leader published a result — use it directly.
                if let Some(result) = slot.result.get() {
                    return result.clone().map_err(Error::Payment);
                }
                // Leader disappeared without publishing (panic or
                // cancellation). Slot was cleared by the leader's drop
                // guard; loop to become the new leader — unless we've
                // hit the retry bound (see MAX_LEADER_RETRIES).
                if attempt == Self::MAX_LEADER_RETRIES {
                    return Err(Error::Payment(
                        "Merkle candidate pool rejected: closeness leader \
                         repeatedly failed to publish a result (likely \
                         repeated cancellation or panic)."
                            .into(),
                    ));
                }
                continue;
            }

            // Leader path. Drop guard clears the slot and wakes waiters on
            // every exit (success, failure, panic, cancellation).
            let Some(slot) = leader_slot else {
                // Unreachable by construction.
                return Err(Error::Payment(
                    "internal error: neither leader nor waiter in closeness check".into(),
                ));
            };
            let guard = InflightGuard {
                slot_cache: &self.inflight_closeness,
                pool_hash,
                slot,
            };

            let result = self.verify_merkle_candidate_closeness_inner(pool).await;
            guard.publish(&result);
            if result.is_ok() {
                self.closeness_pass_cache.lock().put(pool_hash, ());
            }
            return result;
        }
        // Unreachable: the for-loop body always either `return`s or `continue`s,
        // and the waiter branch's `continue` only runs when `attempt <
        // Self::MAX_LEADER_RETRIES`. The last iteration's waiter branch returns
        // via the retry-bound check; the leader branch always returns.
        Err(Error::Payment(
            "internal error: closeness retry loop exited without returning".into(),
        ))
    }

    /// Inner closeness check: the actual DHT lookup + set-membership test.
    /// Wrapped by [`verify_merkle_candidate_closeness`] with a pass-cache and
    /// single-flight guard so a batch of chunks and a storm of forged PUTs
    /// don't multiply the lookup cost.
    /// Derive each candidate's `PeerId` from its `pub_key` and reject the
    /// pool if any `PeerId` appears more than once.
    ///
    /// This is a pure-validation pre-check, runnable without a `P2PNode`:
    /// catches the case where one real peer's `pub_key` is repeated to
    /// inflate the closeness match count, without paying for a Kademlia
    /// lookup. An honest pool has [`evmlib::merkle_payments::CANDIDATES_PER_POOL`]
    /// distinct candidate `pub_keys` by construction.
    fn derive_distinct_candidate_peer_ids(
        pool: &evmlib::merkle_payments::MerklePaymentCandidatePool,
    ) -> Result<Vec<PeerId>> {
        let mut candidate_peer_ids = Vec::with_capacity(pool.candidate_nodes.len());
        let mut seen = std::collections::HashSet::with_capacity(pool.candidate_nodes.len());
        for candidate in &pool.candidate_nodes {
            let pid = peer_id_from_public_key_bytes(&candidate.pub_key).map_err(|e| {
                Error::Payment(format!(
                    "Invalid ML-DSA public key in merkle candidate: {e}"
                ))
            })?;
            if !seen.insert(pid) {
                return Err(Error::Payment(
                    "Merkle candidate pool rejected: duplicate candidate PeerId. An \
                     honest pool has 16 distinct candidate pub_keys; duplicates would \
                     let a single real peer satisfy the closeness threshold by being \
                     counted multiple times."
                        .into(),
                ));
            }
            candidate_peer_ids.push(pid);
        }
        Ok(candidate_peer_ids)
    }

    /// Pure-logic closeness check: given the pool's candidate peer IDs and
    /// the storer's authoritative network view (closest peers to the pool
    /// midpoint), decide whether the pool passes the
    /// `CANDIDATE_CLOSENESS_REQUIRED`-of-N threshold.
    ///
    /// A candidate counts only if its `PeerId` is one of the peers the
    /// storer's own network lookup returned (exact set membership). This is
    /// the property that makes the gate meaningful: a passing candidate must
    /// be a real, reachable peer the live DHT actually routes to and lists
    /// among the closest — it cannot be a key fabricated off-network. The
    /// leniency in this check is purely the lowered threshold (a majority
    /// rather than near-unanimity), which tolerates the closest-set
    /// divergence between two nodes' views without admitting fabricated keys.
    ///
    /// Extracted from `verify_merkle_candidate_closeness_inner` so tests
    /// can exercise the matching logic without standing up a real DHT.
    /// Mirrors the runtime path exactly: same sparse-network short-circuit,
    /// same set-membership check, same error strings.
    fn check_closeness_match(
        candidate_peer_ids: &[PeerId],
        network_peer_ids: &[PeerId],
        pool_address: &[u8; 32],
    ) -> Result<()> {
        // Sparse-network short-circuit: if the DHT itself returned fewer
        // peers than the closeness threshold, the proof can never pass —
        // not because the candidates are forged, but because we don't
        // have an authoritative view to compare against. Surface this
        // distinct cause so operators can tell "retry once the network
        // settles" apart from "this peer sent a forged pool".
        if network_peer_ids.len() < Self::CANDIDATE_CLOSENESS_REQUIRED {
            debug!(
                "Merkle closeness deferred: network lookup returned {} peers \
                 for pool midpoint {} (need at least {} to verify)",
                network_peer_ids.len(),
                hex::encode(pool_address),
                Self::CANDIDATE_CLOSENESS_REQUIRED,
            );
            return Err(Error::Payment(format!(
                "Merkle candidate pool rejected: authoritative DHT lookup returned \
                 only {} peers, less than the {} required to verify candidate \
                 closeness. Retry once the routing table populates further.",
                network_peer_ids.len(),
                Self::CANDIDATE_CLOSENESS_REQUIRED,
            )));
        }

        // Exact-match membership against the returned closest peers.
        // Candidate `PeerId`s are deduplicated upstream, so each match
        // corresponds to a distinct peer.
        let network_set: std::collections::HashSet<PeerId> =
            network_peer_ids.iter().copied().collect();
        let matched = candidate_peer_ids
            .iter()
            .filter(|pid| network_set.contains(pid))
            .count();

        if matched < Self::CANDIDATE_CLOSENESS_REQUIRED {
            debug!(
                "Merkle closeness rejected: {matched}/{} candidates match the DHT's closest peers \
                 for pool midpoint {} (required: {}, network returned {} peers)",
                candidate_peer_ids.len(),
                hex::encode(pool_address),
                Self::CANDIDATE_CLOSENESS_REQUIRED,
                network_peer_ids.len(),
            );
            return Err(Error::Payment(
                "Merkle candidate pool rejected: candidate pub_keys do not match the \
                 network's closest peers to the pool midpoint address. Pools must be \
                 collected from the pool-address close group, not fabricated off-network."
                    .into(),
            ));
        }

        debug!(
            "Merkle closeness passed: {matched}/{} candidates matched the DHT's closest peers \
             for pool midpoint {}",
            candidate_peer_ids.len(),
            hex::encode(pool_address),
        );
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn verify_merkle_candidate_closeness_inner(
        &self,
        pool: &evmlib::merkle_payments::MerklePaymentCandidatePool,
    ) -> Result<()> {
        // Pre-check: catch malformed/hostile pools (duplicate candidate
        // PeerIds) before paying for the Kademlia lookup. Runs in unit
        // tests without a P2PNode too.
        let candidate_peer_ids = Self::derive_distinct_candidate_peer_ids(pool)?;

        // Release the RwLock guard before any await to avoid holding it
        // across an iterative Kademlia lookup.
        let attached = self.p2p_node.read().as_ref().map(Arc::clone);
        let Some(p2p_node) = attached else {
            // Production must call attach_p2p_node at startup. Fail CLOSED
            // to avoid silently disabling the defence if a startup path
            // regresses and loses the attach call. Unit-test builds that
            // construct a PaymentVerifier directly without exercising merkle
            // verification are opted-in via `test-utils` to fall back to
            // fail-open.
            #[cfg(any(test, feature = "test-utils"))]
            {
                crate::logging::warn!(
                    "PaymentVerifier: no P2PNode attached; merkle pay-yourself \
                     defence SKIPPED (test build). Production startup MUST call \
                     PaymentVerifier::attach_p2p_node."
                );
                return Ok(());
            }
            #[cfg(not(any(test, feature = "test-utils")))]
            {
                crate::logging::error!(
                    "PaymentVerifier: no P2PNode attached; rejecting merkle \
                     payment. This is a node-startup bug — \
                     PaymentVerifier::attach_p2p_node must be called before \
                     any PUT handler runs."
                );
                return Err(Error::Payment(
                    "Merkle candidate pool rejected: verifier is not wired to \
                     the P2P layer; cannot verify candidate closeness."
                        .into(),
                ));
            }
        };

        let pool_address = pool.midpoint_proof.address();
        // Match the client's over-query width. The client's
        // `get_merkle_candidate_pool` queries 2 × `CANDIDATES_PER_POOL` peers
        // and picks the 16 closest *valid responders* — so legitimate pools
        // routinely include peers from positions 17–32 of the network's true
        // ranking when the closer peers are slow or NAT-stuck. The storer
        // must look at the same window or it will reject honest pools with
        // no security benefit.
        //
        // `pool.candidate_nodes` is currently a fixed-size array of length
        // `CANDIDATES_PER_POOL` (= 16), so `.max(...)` always evaluates to
        // `CLOSENESS_LOOKUP_WIDTH` today. The compile-time
        // `const _: () = assert!(WIDTH >= CANDIDATES_PER_POOL)` in the test
        // module pins that invariant. The `.max(...)` form is belt-and-braces
        // for a hypothetical future protocol that grows pool size to a
        // `Vec`-typed candidate set: the storer would scale its lookup with
        // the pool rather than truncating, which would otherwise re-open the
        // K-too-small failure mode.
        let lookup_count = Self::closeness_lookup_count(pool.candidate_nodes.len());
        let network_lookup = p2p_node
            .dht_manager()
            .find_closest_nodes_network(&pool_address.0, lookup_count);
        let network_peers =
            match tokio::time::timeout(Self::CLOSENESS_LOOKUP_TIMEOUT, network_lookup).await {
                Ok(Ok(peers)) => peers,
                Ok(Err(e)) => {
                    debug!(
                        "Merkle closeness network-lookup failed for pool midpoint {}: {e}",
                        hex::encode(pool_address.0),
                    );
                    return Err(Error::Payment(
                        "Merkle candidate pool rejected: could not verify candidate \
                     closeness against the authoritative network view."
                            .into(),
                    ));
                }
                Err(_) => {
                    debug!(
                        "Merkle closeness network-lookup timeout ({:?}) for pool midpoint {}",
                        Self::CLOSENESS_LOOKUP_TIMEOUT,
                        hex::encode(pool_address.0),
                    );
                    return Err(Error::Payment(
                        "Merkle candidate pool rejected: authoritative network lookup \
                     timed out. Retry once the network lookup completes."
                            .into(),
                    ));
                }
            };

        let network_peer_ids: Vec<PeerId> = network_peers.iter().map(|n| n.peer_id).collect();
        Self::check_closeness_match(&candidate_peer_ids, &network_peer_ids, &pool_address.0)
    }

    /// Verify a merkle batch payment proof.
    ///
    /// This verification flow:
    /// 1. Deserialize the `MerklePaymentProof`
    /// 2. Check pool cache for previously verified pool hash
    /// 3. If not cached, query on-chain for payment info
    /// 4. Validate the proof against on-chain data
    /// 5. Cache the pool hash for subsequent chunk verifications in the same batch
    #[allow(clippy::too_many_lines)]
    async fn verify_merkle_payment(
        &self,
        xorname: &XorName,
        proof_bytes: &[u8],
        context: VerificationContext,
    ) -> Result<()> {
        if crate::logging::enabled!(crate::logging::Level::DEBUG) {
            debug!(
                "Verifying merkle payment for {} ({context:?})",
                hex::encode(xorname)
            );
        }

        // Deserialize the merkle proof
        let merkle_proof = deserialize_merkle_proof(proof_bytes)
            .map_err(|e| Error::Payment(format!("Failed to deserialize merkle proof: {e}")))?;

        // Verify the address in the proof matches the xorname being stored
        if merkle_proof.address.0 != *xorname {
            let proof_hex = hex::encode(merkle_proof.address.0);
            let store_hex = hex::encode(xorname);
            return Err(Error::Payment(format!(
                "Merkle proof address mismatch: proof is for {proof_hex}, but storing {store_hex}"
            )));
        }

        let pool_hash = merkle_proof.winner_pool_hash();

        // Run cheap local checks BEFORE expensive on-chain queries.
        // This prevents DoS via garbage proofs that trigger RPC lookups.
        for candidate in &merkle_proof.winner_pool.candidate_nodes {
            if !crate::payment::verify_merkle_candidate_signature(candidate) {
                return Err(Error::Payment(format!(
                    "Invalid ML-DSA-65 signature on merkle candidate node (reward: {})",
                    candidate.reward_address
                )));
            }
        }

        // ADR-0004: every storer re-runs the price-equals-formula-of-count
        // check on every merkle candidate, in every context, before median
        // reconstruction. Runs AFTER signature verification so observe-only
        // telemetry cannot be spoofed by unauthenticated senders. Reject-only
        // when enforcement is enabled; no trust evidence emitted in either
        // mode.
        Self::validate_merkle_candidate_arithmetic(&merkle_proof.winner_pool)?;
        Self::log_off_curve_merkle(&merkle_proof.winner_pool);

        // Pay-yourself defence: the candidate pub_keys must map to peers the
        // live DHT actually considers closest to the pool midpoint. Without
        // this, an attacker can point all 16 reward_address fields at a
        // self-owned wallet and drain their own payment. Every storing node
        // runs this check against the single `winner_pool` in the proof, so a
        // forged pool is rejected everywhere it lands. The pass cache and
        // single-flight keyed on pool_hash collapse the Kademlia lookup cost
        // within a batch and across concurrent PUTs for the same pool.
        //
        self.verify_merkle_candidate_closeness(&merkle_proof.winner_pool, pool_hash)
            .await?;

        // Check pool cache first
        let cached_info = {
            let mut pool_cache = self.pool_cache.lock();
            pool_cache.get(&pool_hash).cloned()
        };

        let payment_info = if let Some(info) = cached_info {
            debug!("Pool cache hit for hash {}", hex::encode(pool_hash));
            info
        } else {
            // Query on-chain for completed merkle payment
            let info =
                payment_vault::get_completed_merkle_payment(&self.config.evm.network, pool_hash)
                    .await
                    .map_err(|e| {
                        let pool_hex = hex::encode(pool_hash);
                        Error::Payment(format!(
                            "Failed to query merkle payment info for pool {pool_hex}: {e}"
                        ))
                    })?;

            let paid_node_addresses: Vec<_> = info
                .paidNodeAddresses
                .iter()
                .map(|pna| (pna.rewardsAddress, usize::from(pna.poolIndex), pna.amount))
                .collect();

            let on_chain_info = OnChainPaymentInfo {
                depth: info.depth,
                merkle_payment_timestamp: info.merklePaymentTimestamp,
                paid_node_addresses,
            };

            // Cache the pool info for subsequent chunks in the same batch
            {
                let mut pool_cache = self.pool_cache.lock();
                pool_cache.put(pool_hash, on_chain_info.clone());
            }

            debug!(
                "Queried on-chain merkle payment info for pool {}: depth={}, timestamp={}, paid_nodes={}",
                hex::encode(pool_hash),
                on_chain_info.depth,
                on_chain_info.merkle_payment_timestamp,
                on_chain_info.paid_node_addresses.len()
            );

            on_chain_info
        };

        // Verify timestamp consistency (signatures already checked above before RPC).
        for candidate in &merkle_proof.winner_pool.candidate_nodes {
            if candidate.merkle_payment_timestamp != payment_info.merkle_payment_timestamp {
                return Err(Error::Payment(format!(
                    "Candidate timestamp mismatch: expected {}, got {} (reward: {})",
                    payment_info.merkle_payment_timestamp,
                    candidate.merkle_payment_timestamp,
                    candidate.reward_address
                )));
            }
        }

        // Get the root from the winner pool's midpoint proof
        let smart_contract_root = merkle_proof.winner_pool.midpoint_proof.root();

        // Verify the cryptographic merkle proofs (address belongs to tree,
        // midpoint belongs to tree, roots match, timestamps valid).
        evmlib::merkle_payments::verify_merkle_proof(
            &merkle_proof.address,
            &merkle_proof.data_proof,
            &merkle_proof.winner_pool.midpoint_proof,
            payment_info.depth,
            smart_contract_root,
            payment_info.merkle_payment_timestamp,
        )
        .map_err(|e| {
            let xorname_hex = hex::encode(xorname);
            Error::Payment(format!(
                "Merkle proof verification failed for {xorname_hex}: {e}"
            ))
        })?;

        // Verify paid node count matches depth
        let expected_depth = payment_info.depth as usize;
        let actual_paid = payment_info.paid_node_addresses.len();
        if actual_paid != expected_depth {
            return Err(Error::Payment(format!(
                "Wrong number of paid nodes: expected {expected_depth}, got {actual_paid}"
            )));
        }

        // Expected per-node payment from the contract formula. ADR-0008: which
        // multiplier is REQUIRED depends on when the receipt was stamped —
        // 3x from the parity boundary onward, the historic 1x before it, since
        // that money was already spent under the old rule. The expiry check
        // above bounds the legacy branch: no receipt older than a week is
        // valid, so the branch is unreachable one week past the boundary.
        let candidate_prices: Vec<Amount> = merkle_proof
            .winner_pool
            .candidate_nodes
            .iter()
            .map(|c| c.price)
            .collect();
        let parity_from = *self.merkle_parity_from.read();
        let required_multiplier =
            merkle_required_multiplier(payment_info.merkle_payment_timestamp, parity_from);
        let expected_per_node_bare =
            merkle_expected_per_node(&candidate_prices, payment_info.depth, 1)?;
        let expected_per_node_parity = merkle_expected_per_node(
            &candidate_prices,
            payment_info.depth,
            PAID_QUOTE_PAYMENT_MULTIPLIER,
        )?;
        let expected_per_node =
            merkle_expected_per_node(&candidate_prices, payment_info.depth, required_multiplier)?;

        // Verify paid node indices, addresses, and amounts against the candidate pool.
        //
        // Each paid node must:
        // 1. Have a valid index within the candidate pool
        // 2. Match the expected reward address at that index
        // 3. Have been paid at least `expected_per_node`, which is the contract
        //    formula `median16(prices) * 2^depth / depth` at the multiplier the
        //    receipt's own timestamp selects (3x from the parity boundary, the
        //    historic 1x before it). Do NOT re-assume the 1x formula here —
        //    read `expected_per_node` rather than recomputing it.
        //
        // Note: unlike single-node payments, merkle proofs are NOT bound to a
        // specific storing node. The contract pays `depth` random nodes from the
        // winner pool; the storing node is whichever close-group peer the client
        // routes the chunk to. There is no local-recipient check here because
        // any node that can verify the merkle proof is allowed to store the chunk.
        // Replay protection comes from the per-address proof binding (each proof
        // is for a specific XorName in the paid tree).
        for (addr, idx, paid_amount) in &payment_info.paid_node_addresses {
            let node = merkle_proof
                .winner_pool
                .candidate_nodes
                .get(*idx)
                .ok_or_else(|| {
                    Error::Payment(format!(
                        "Paid node index {idx} out of bounds for pool size {}",
                        merkle_proof.winner_pool.candidate_nodes.len()
                    ))
                })?;
            if node.reward_address != *addr {
                return Err(Error::Payment(format!(
                    "Paid node address mismatch at index {idx}: expected {addr}, got {}",
                    node.reward_address
                )));
            }
            if *paid_amount < expected_per_node {
                return Err(Error::Payment(format!(
                    "Underpayment for node at index {idx}: paid {paid_amount}, \
                     expected at least {expected_per_node} \
                     (median16 formula, depth={}, {required_multiplier}x required for a \
                     receipt stamped {} vs parity boundary {parity_from})",
                    payment_info.depth, payment_info.merkle_payment_timestamp
                )));
            }
        }

        if crate::logging::enabled!(crate::logging::Level::INFO) {
            info!(
                "Merkle payment verified for {} (pool: {})",
                hex::encode(xorname),
                hex::encode(pool_hash)
            );
        }

        // ADR-0008 parity telemetry, emitted only now: every paid index, reward
        // address and amount above has been validated, so a proof that is
        // rejected later in this function can never enter the rollout signal.
        // Store admissions only, matching the cross-check below — a paid-list
        // receipt reprices no fresh economic decision and would otherwise
        // double-count a batch already measured at its store admission.
        // `log_merkle_parity` itself drops all but the first admission per
        // pool, so a 256-chunk batch contributes one line here, not 256.
        if context.is_store_admission() {
            self.log_merkle_parity(
                pool_hash,
                &payment_info,
                expected_per_node_bare,
                expected_per_node_parity,
                required_multiplier,
            );
        }

        // ADR-0004: route the merkle-batch candidates through the SAME
        // cross-check + first-audit funnel as single-node quotes, AFTER on-chain
        // verification has succeeded (so an unpaid pool cannot drive audits or
        // fetches). Store admissions only (direct PUT + immediate fresh
        // replication, the paths that previously verified under `ClientPut`) —
        // a paid-list receipt's pins have aged out.
        // Amendment 2: only the candidates the contract actually PAID
        // (`paid_node_addresses` indices, verified above) are nominated for
        // first audits; the rest of the pool merely established the median.
        if context.is_store_admission() {
            let paid_indices: std::collections::HashSet<usize> = payment_info
                .paid_node_addresses
                .iter()
                .map(|(_, idx, _)| *idx)
                .collect();
            self.cross_check_merkle_candidates(
                &merkle_proof.winner_pool,
                &merkle_proof.commitment_sidecars,
                &paid_indices,
            )
            .await;
        }

        Ok(())
    }

    /// ADR-0004 cross-check for the merkle-batch path: every candidate carries
    /// the same signed `(committed_key_count, commitment_pin)` binding as a
    /// single-node quote, so each non-baseline candidate is resolved against the
    /// gossip cache (or fetched) and routed into the deterministic first audit,
    /// exactly like [`Self::cross_check_quotes`]. The candidate's peer id is
    /// derived from its `pub_key` (`PeerId = BLAKE3(pub_key)`), matching how the
    /// network binds identities.
    async fn cross_check_merkle_candidates(
        &self,
        pool: &evmlib::merkle_payments::MerklePaymentCandidatePool,
        commitment_sidecars: &[Vec<u8>],
        paid_indices: &std::collections::HashSet<usize>,
    ) {
        let now = std::time::Instant::now();
        let ttl = crate::replication::commitment_state::GOSSIP_ANSWERABILITY_TTL;
        let p2p = self.p2p_node.read().as_ref().map(Arc::clone);
        let monetized_pin_tx = self.monetized_pin_tx.read().as_ref().cloned();
        let cache = self.commitment_cache.read().as_ref().map(Arc::clone);
        // ADR-0004 "the commitment arrived with the quote" for the merkle path:
        // validate sidecars exactly as the single-node path does.
        let sidecar_map = Self::index_valid_sidecars(commitment_sidecars);

        let mut unresolved: Vec<(PeerId, [u8; 32], u32, Vec<u8>)> = Vec::new();
        for (idx, candidate) in pool.candidate_nodes.iter().enumerate() {
            let Some(pin) = candidate.commitment_pin else {
                continue; // baseline candidate pins nothing
            };
            let peer_id = PeerId::from_bytes(*blake3::hash(&candidate.pub_key).as_bytes());

            // ADR-0004 Amendment 2: nominate only the candidates the contract
            // actually paid — the unpaid pool members earned nothing and stay
            // covered by the gossip-lottery audit path. Pre-amendment every
            // pool candidate (16) was nominated per verified proof.
            if paid_indices.contains(&idx) {
                if let Some(ref tx) = monetized_pin_tx {
                    // Bounded queue: drop on full (best-effort, penalty-free;
                    // the peer's next settled payment re-nominates it). Count a
                    // Full drop so ingress saturation is observable; a Closed
                    // channel just means the engine is shutting down.
                    if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) =
                        tx.try_send(crate::replication::MonetizedPinEvent {
                            peer: peer_id,
                            pin,
                            key_count: candidate.committed_key_count,
                            quote_ts: std::time::UNIX_EPOCH
                                .checked_add(std::time::Duration::from_secs(
                                    candidate.merkle_payment_timestamp,
                                ))
                                .unwrap_or(std::time::UNIX_EPOCH),
                        })
                    {
                        crate::replication::note_monetized_ingress_drop();
                    }
                }
            }

            let resolved = match sidecar_map.get(&(peer_id, pin)) {
                Some(c) => Some(c.clone()),
                None => Self::cache_resolve(cache.as_ref(), peer_id, pin, now, ttl).await,
            };
            match resolved {
                Some(commitment) => {
                    let artifact = rmp_serde::to_vec(candidate).unwrap_or_default();
                    Self::handle_cross_check(
                        &peer_id,
                        pin,
                        candidate.committed_key_count,
                        artifact,
                        &commitment,
                        p2p.as_ref(),
                    )
                    .await;
                }
                None => unresolved.push((
                    peer_id,
                    pin,
                    candidate.committed_key_count,
                    rmp_serde::to_vec(candidate).unwrap_or_default(),
                )),
            }
        }

        if unresolved.is_empty() {
            return;
        }
        let Some(p2p) = p2p else {
            return;
        };
        let neg_cache = Arc::clone(&self.pin_fetch_negative_cache);
        tokio::spawn(async move {
            Self::drain_unresolved_pin_fetches(&p2p, &neg_cache, unresolved).await;
        });
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use evmlib::merkle_payments::MerklePaymentCandidatePool;
    use evmlib::PaymentQuote;
    use saorsa_core::MlDsa65;
    use saorsa_pqc::pqc::types::MlDsaSecretKey;
    use saorsa_pqc::pqc::MlDsaOperations;
    use std::time::SystemTime;

    /// Create a verifier for unit tests. EVM is always on, but tests can
    /// pre-populate the cache to bypass on-chain verification.
    fn create_test_verifier() -> PaymentVerifier {
        let config = PaymentVerifierConfig {
            evm: EvmVerifierConfig::default(),
            cache_capacity: 100,
            close_group_size: CLOSE_GROUP_SIZE,
            local_rewards_address: RewardsAddress::new([1u8; 20]),
            price_floor: PriceFloorConfig::default(),
        };
        PaymentVerifier::new(config)
    }

    #[test]
    fn paid_quote_issuer_closeness_width_uses_k() {
        let issuer_closeness_width = PAID_QUOTE_ISSUER_CLOSENESS_WIDTH;
        let k_bucket_size = K_BUCKET_SIZE;
        let close_group_size = CLOSE_GROUP_SIZE;

        assert_eq!(issuer_closeness_width, k_bucket_size);
        assert!(issuer_closeness_width > close_group_size);
    }

    /// 16 candidate prices 100..=1600; the upper median (index 8) is 900.
    fn varied_candidate_prices() -> Vec<Amount> {
        (1..=16u64).map(|i| Amount::from(i * 100)).collect()
    }

    #[test]
    fn merkle_expected_per_node_reproduces_the_contract_formula() {
        // total = median16 x 2^depth = 900 x 16 = 14400, over depth=4 nodes.
        let per_node = merkle_expected_per_node(&varied_candidate_prices(), 4, 1)
            .expect("depth 4 pool is payable");
        assert_eq!(per_node, Amount::from(3_600u64));
    }

    /// 16 identical candidate prices, so the upper median is exactly `median`.
    fn prices_with_median(median: u64) -> Vec<Amount> {
        vec![Amount::from(median); 16]
    }

    /// The parity expectation is the floor of the multiplied total, which is
    /// **not** the bare expectation times the multiplier.
    ///
    /// `expected(m) = floor(m x median x 2^depth / depth)` sits in
    /// `[m x expected(1), m x expected(1) + (m - 1)]`: equal when `depth`
    /// divides the total, up to `m - 1` wei above it when it does not.
    /// Asserting exact equality would encode `floor(3x/d) == 3 x floor(x/d)`,
    /// which is false in general and only happened to hold for the
    /// evenly-dividing case the first version of this test used.
    #[test]
    fn merkle_expected_per_node_scales_within_the_division_remainder() {
        let multiplier = PAID_QUOTE_PAYMENT_MULTIPLIER;

        for median in [1u64, 899, 900, 901, 6_000, 1_000_003] {
            for depth in 1..=8u8 {
                let prices = prices_with_median(median);
                let bare = merkle_expected_per_node(&prices, depth, 1)
                    .expect("bare expectation is payable");
                let parity = merkle_expected_per_node(&prices, depth, multiplier)
                    .expect("parity expectation is payable");

                let scaled_bare = bare * Amount::from(multiplier);
                let slack = Amount::from(multiplier - 1);

                assert!(
                    parity >= scaled_bare && parity <= scaled_bare + slack,
                    "median {median} depth {depth}: parity {parity} must lie in \
                     [{scaled_bare}, {}]",
                    scaled_bare + slack
                );

                // And it is exactly the floor of the multiplied total.
                let leaves = 1u64 << u32::from(depth);
                let expected =
                    Amount::from(median * leaves * multiplier) / Amount::from(u64::from(depth));
                assert_eq!(parity, expected, "median {median} depth {depth}");
            }
        }
    }

    /// Regression for the arithmetic order: the helper multiplies the total and
    /// then divides once, as the contract does. Median 901 at depth 7 is a case
    /// where that differs from scaling a 1x result by one wei, so a refactor
    /// that divided first would fail here.
    #[test]
    fn merkle_expected_per_node_multiplies_before_dividing() {
        let prices = prices_with_median(901);
        let bare = merkle_expected_per_node(&prices, 7, 1).expect("bare expectation is payable");
        let parity = merkle_expected_per_node(&prices, 7, PAID_QUOTE_PAYMENT_MULTIPLIER)
            .expect("parity expectation is payable");

        assert_eq!(bare, Amount::from(16_475u64));
        assert_eq!(parity, Amount::from(49_426u64));
        assert_eq!(
            parity,
            bare * Amount::from(PAID_QUOTE_PAYMENT_MULTIPLIER) + Amount::from(1u64),
            "dividing before multiplying would lose this wei"
        );
    }

    /// The economic invariant ADR-0008 restores: a merkle **leaf** settles
    /// for what the single-node path settles — 3x the median quote — up to
    /// the contract's integer division.
    ///
    /// Leaf, not chunk: the tree pads to `2^ceil(log2(N))` and the contract
    /// charges for every leaf, so a batch whose size is not a power of two
    /// pays a padding premium on top. That premium is a property of the
    /// contract formula, not of the multiplier under test here.
    ///
    /// `amountPerNode = totalAmount / depth` discards a remainder whenever
    /// `depth` does not divide `median x 2^depth` (e.g. depth 7). The loss is
    /// strictly under one wei per paid node, spread across `2^depth` chunks,
    /// so it is economically irrelevant — but the invariant is "within
    /// rounding", not exact equality, and the test says so rather than
    /// picking depths that happen to divide evenly.
    #[test]
    fn merkle_parity_per_chunk_equals_single_node_settlement() {
        let prices = varied_candidate_prices();
        let median = Amount::from(900u64);

        for depth in 1..=8u8 {
            let per_node = merkle_expected_per_node(&prices, depth, PAID_QUOTE_PAYMENT_MULTIPLIER)
                .expect("every supported depth is payable");
            let required_total = per_node * Amount::from(u64::from(depth));

            let leaves = Amount::from(1u64 << u32::from(depth));
            let ideal_total = median * Amount::from(PAID_QUOTE_PAYMENT_MULTIPLIER) * leaves;

            assert!(
                required_total <= ideal_total,
                "at depth {depth} the required total {required_total} must not \
                 exceed the 3x-median ideal {ideal_total}"
            );
            assert!(
                ideal_total - required_total < Amount::from(u64::from(depth)),
                "at depth {depth} the shortfall {} must be pure division \
                 remainder (< depth wei), not a missing multiplier",
                ideal_total - required_total
            );
        }
    }

    #[test]
    fn merkle_expected_per_node_is_zero_at_depth_zero() {
        let per_node = merkle_expected_per_node(&varied_candidate_prices(), 0, 3)
            .expect("depth zero is a valid no-op, not an error");
        assert_eq!(per_node, Amount::ZERO);
    }

    #[test]
    fn merkle_expected_per_node_rejects_an_empty_pool() {
        let Err(err) = merkle_expected_per_node(&[], 4, 3) else {
            panic!("an empty candidate pool has no median and must not be payable");
        };
        let err = err.to_string();
        assert!(err.contains("empty candidate pool"), "got: {err}");
    }

    fn make_signed_quote(
        xorname: XorName,
        price: Amount,
        rewards_seed: u8,
    ) -> (evmlib::EncodedPeerId, PaymentQuote) {
        let ml_dsa = MlDsa65::new();
        let (public_key, secret_key) = ml_dsa.generate_keypair().expect("keygen");
        let pub_key_bytes = public_key.as_bytes().to_vec();
        let peer_id = encoded_peer_id_for_pub_key(&pub_key_bytes);
        // Derive the ADR-0004 binding from the price rather than hardcoding
        // `(0, None)`: a quote priced at `calculate_price(n)` must also claim
        // `committed_key_count = n`, or it charges as though it stored `n` keys
        // while committing to nothing and is rejected by the arithmetic gate
        // before the test's own assertion is reached. Prices that are not on
        // the curve at all (`ZERO`, small literals) keep the baseline shape and
        // stay off-curve, which is what the tests exercising bad prices want.
        let (committed_key_count, commitment_pin) =
            match PaymentVerifier::price_off_curve_diagnostics(&price) {
                None => {
                    let records = derive_records_stored_from_price(price);
                    let count = u32::try_from(records).unwrap_or(u32::MAX);
                    let pin = if count == 0 { None } else { Some([0xA5u8; 32]) };
                    (count, pin)
                }
                Some(_) => (0, None),
            };
        let mut quote = PaymentQuote {
            content: xor_name::XorName(xorname),
            timestamp: SystemTime::now(),
            price,
            rewards_address: RewardsAddress::new([rewards_seed; 20]),
            committed_key_count,
            commitment_pin,
            pub_key: pub_key_bytes,
            signature: Vec::new(),
        };
        let secret_key = MlDsaSecretKey::from_bytes(secret_key.as_bytes()).expect("secret key");
        quote.signature = ml_dsa
            .sign(&secret_key, &quote.bytes_for_sig())
            .expect("sign quote")
            .as_bytes()
            .to_vec();
        (peer_id, quote)
    }

    fn make_signed_legacy_bundle(
        xorname: XorName,
        prices: [Amount; CLOSE_GROUP_SIZE],
    ) -> Vec<(evmlib::EncodedPeerId, PaymentQuote)> {
        prices
            .into_iter()
            .enumerate()
            .map(|(index, price)| {
                let rewards_seed = u8::try_from(index + 1).expect("small test index");
                make_signed_quote(xorname, price, rewards_seed)
            })
            .collect()
    }

    fn price_at_records(records: usize) -> Amount {
        crate::payment::pricing::calculate_price(records)
    }

    fn unique_test_prices() -> [Amount; CLOSE_GROUP_SIZE] {
        [
            price_at_records(0),
            price_at_records(1),
            price_at_records(2),
            price_at_records(3),
            price_at_records(4),
            price_at_records(5),
            price_at_records(6),
        ]
    }

    fn tied_median_test_prices() -> [Amount; CLOSE_GROUP_SIZE] {
        [
            price_at_records(0),
            price_at_records(1),
            price_at_records(2),
            price_at_records(3),
            price_at_records(3),
            price_at_records(4),
            price_at_records(5),
        ]
    }

    fn median_test_candidates(
        peer_quotes: &[(evmlib::EncodedPeerId, PaymentQuote)],
    ) -> Vec<(evmlib::EncodedPeerId, PaymentQuote)> {
        let mut sorted_quotes: Vec<_> = peer_quotes.iter().collect();
        sorted_quotes.sort_by_key(|(_, quote)| quote.price);
        let median_index = median_quote_index(sorted_quotes.len());
        let median_price = sorted_quotes
            .get(median_index)
            .expect("median quote")
            .1
            .price;

        sorted_quotes
            .into_iter()
            .filter(|(_, quote)| quote.price == median_price)
            .map(|(peer_id, quote)| (peer_id.clone(), quote.clone()))
            .collect()
    }

    fn expected_median_payment(peer_quotes: &[(evmlib::EncodedPeerId, PaymentQuote)]) -> Amount {
        let median_price = median_test_candidates(peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .price;
        median_price * Amount::from(PAID_QUOTE_PAYMENT_MULTIPLIER)
    }

    fn mark_k_closest_paid_candidates(
        verifier: &PaymentVerifier,
        peer_quotes: &[(evmlib::EncodedPeerId, PaymentQuote)],
    ) {
        let k_closest_peers = median_test_candidates(peer_quotes)
            .iter()
            .map(|(peer_id, _)| *peer_id.as_bytes())
            .collect();
        verifier.set_paid_quote_k_closest_for_tests(k_closest_peers);
    }

    fn mark_candidate_paid(verifier: &PaymentVerifier, quote: &PaymentQuote, amount: Amount) {
        verifier.set_completed_payment_for_tests(quote.hash(), amount);
    }

    fn mark_all_median_candidates_unpaid(
        verifier: &PaymentVerifier,
        peer_quotes: &[(evmlib::EncodedPeerId, PaymentQuote)],
    ) {
        for (_, quote) in median_test_candidates(peer_quotes) {
            mark_candidate_paid(verifier, &quote, Amount::ZERO);
        }
    }

    #[test]
    fn test_payment_required_for_new_data() {
        let verifier = create_test_verifier();
        let xorname = [1u8; 32];

        // All uncached data requires payment
        let status = verifier.check_payment_required(&xorname, VerificationContext::ClientPut);
        assert_eq!(status, PaymentStatus::PaymentRequired);
    }

    #[test]
    fn test_cache_hit() {
        let verifier = create_test_verifier();
        let xorname = [1u8; 32];

        // Manually add to cache
        verifier.cache.insert(xorname);

        // Should return CachedAsVerified
        let status = verifier.check_payment_required(&xorname, VerificationContext::ClientPut);
        assert_eq!(status, PaymentStatus::CachedAsVerified);
    }

    #[tokio::test]
    async fn test_verify_payment_without_proof_rejected() {
        let verifier = create_test_verifier();
        let xorname = [1u8; 32];

        // No proof provided => should return an error (EVM is always on)
        let result = verifier
            .verify_payment(&xorname, None, VerificationContext::ClientPut)
            .await;
        assert!(
            result.is_err(),
            "Expected Err without proof, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn test_verify_payment_cached() {
        let verifier = create_test_verifier();
        let xorname = [1u8; 32];

        // Add to cache — simulates previously-paid data
        verifier.cache.insert(xorname);

        // Should succeed without payment (cached)
        let result = verifier
            .verify_payment(&xorname, None, VerificationContext::ClientPut)
            .await;
        assert!(result.is_ok());
        assert_eq!(result.expect("cached"), PaymentStatus::CachedAsVerified);
    }

    #[tokio::test]
    async fn test_paid_list_cache_entry_does_not_satisfy_client_put() {
        let verifier = create_test_verifier();
        let xorname = [0xB8u8; 32];
        verifier.cache.insert_paid_list_verified(xorname);

        assert_eq!(
            verifier.check_payment_required(&xorname, VerificationContext::PaidListAdmission),
            PaymentStatus::CachedAsVerified,
            "paid-list lookups must hit a paid-list-verified entry"
        );
        assert_eq!(
            verifier.check_payment_required(&xorname, VerificationContext::ClientPut),
            PaymentStatus::PaymentRequired,
            "client PUT must not fast-path on a paid-list-verified entry"
        );

        let err = verifier
            .verify_payment(&xorname, None, VerificationContext::ClientPut)
            .await
            .expect_err("proof-less client PUT must not ride the paid-list entry");
        assert!(
            format!("{err}").contains("Payment required"),
            "client PUT must still demand payment: {err}"
        );
    }

    #[test]
    fn test_payment_status_can_store() {
        assert!(PaymentStatus::CachedAsVerified.can_store());
        assert!(PaymentStatus::PaymentVerified.can_store());
        assert!(!PaymentStatus::PaymentRequired.can_store());
    }

    #[test]
    fn test_payment_status_is_cached() {
        assert!(PaymentStatus::CachedAsVerified.is_cached());
        assert!(!PaymentStatus::PaymentVerified.is_cached());
        assert!(!PaymentStatus::PaymentRequired.is_cached());
    }

    #[tokio::test]
    async fn test_cache_preload_bypasses_evm() {
        let verifier = create_test_verifier();
        let xorname = [42u8; 32];

        // Not yet cached — should require payment
        assert_eq!(
            verifier.check_payment_required(&xorname, VerificationContext::ClientPut),
            PaymentStatus::PaymentRequired
        );

        // Pre-populate cache (simulates a previous successful payment)
        verifier.cache.insert(xorname);

        // Now the xorname should be cached
        assert_eq!(
            verifier.check_payment_required(&xorname, VerificationContext::ClientPut),
            PaymentStatus::CachedAsVerified
        );
    }

    #[tokio::test]
    async fn test_proof_too_small() {
        let verifier = create_test_verifier();
        let xorname = [1u8; 32];

        // Proof smaller than MIN_PAYMENT_PROOF_SIZE_BYTES
        let small_proof = vec![0u8; MIN_PAYMENT_PROOF_SIZE_BYTES - 1];
        let result = verifier
            .verify_payment(&xorname, Some(&small_proof), VerificationContext::ClientPut)
            .await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("too small"),
            "Error should mention 'too small': {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_proof_too_large() {
        let verifier = create_test_verifier();
        let xorname = [2u8; 32];

        // Proof larger than MAX_PAYMENT_PROOF_SIZE_BYTES
        let large_proof = vec![0u8; MAX_PAYMENT_PROOF_SIZE_BYTES + 1];
        let result = verifier
            .verify_payment(&xorname, Some(&large_proof), VerificationContext::ClientPut)
            .await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("too large"),
            "Error should mention 'too large': {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_proof_at_min_boundary_unknown_tag() {
        let verifier = create_test_verifier();
        let xorname = [3u8; 32];

        // Exactly MIN_PAYMENT_PROOF_SIZE_BYTES with unknown tag — rejected
        let boundary_proof = vec![0xFFu8; MIN_PAYMENT_PROOF_SIZE_BYTES];
        let result = verifier
            .verify_payment(
                &xorname,
                Some(&boundary_proof),
                VerificationContext::ClientPut,
            )
            .await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("Unknown payment proof type tag"),
            "Error should mention unknown tag: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_proof_at_max_boundary_unknown_tag() {
        let verifier = create_test_verifier();
        let xorname = [4u8; 32];

        // Exactly MAX_PAYMENT_PROOF_SIZE_BYTES with unknown tag — rejected
        let boundary_proof = vec![0xFFu8; MAX_PAYMENT_PROOF_SIZE_BYTES];
        let result = verifier
            .verify_payment(
                &xorname,
                Some(&boundary_proof),
                VerificationContext::ClientPut,
            )
            .await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("Unknown payment proof type tag"),
            "Error should mention unknown tag: {err_msg}"
        );
    }

    /// Regression pin for the DEV-01 (2026-07-06) outage: a merkle proof that
    /// ships all 16 ADR-0004 commitment sidecars serializes to ~342 KB, and the
    /// old 256 KB cap size-rejected every merkle PUT as soon as nodes carried
    /// live commitments. The cap must keep accepting that legacy client shape;
    /// a proof of that size must fail on content, never on size.
    #[tokio::test]
    async fn test_sidecar_bearing_merkle_proof_size_is_accepted() {
        const LEGACY_SIDECAR_PROOF_BYTES: usize = 342_171;

        let verifier = create_test_verifier();
        let xorname = [6u8; 32];

        let legacy_sized_proof = vec![0xFFu8; LEGACY_SIDECAR_PROOF_BYTES];
        let result = verifier
            .verify_payment(
                &xorname,
                Some(&legacy_sized_proof),
                VerificationContext::ClientPut,
            )
            .await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            !err_msg.contains("too large"),
            "A {LEGACY_SIDECAR_PROOF_BYTES}-byte proof must not be size-rejected \
             (sidecar-bearing merkle proofs from pre-fix clients): {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_malformed_single_node_proof() {
        let verifier = create_test_verifier();
        let xorname = [5u8; 32];

        // Valid tag (0x01) but garbage payload — should fail deserialization
        let mut garbage = vec![crate::ant_protocol::PROOF_TAG_SINGLE_NODE];
        garbage.extend_from_slice(&[0xAB; 63]);
        let result = verifier
            .verify_payment(&xorname, Some(&garbage), VerificationContext::ClientPut)
            .await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("deserialize") || err_msg.contains("Failed"),
            "Error should mention deserialization failure: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_legacy_paid_median_full_path_accepted() {
        let verifier = create_test_verifier();
        let xorname = [0xA1u8; 32];
        let peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("paid median should verify"),
            PaymentStatus::PaymentVerified
        );
    }

    /// ADR-0004 Amendment 2: a settlement recorded under the median quote's
    /// hash but redirected to a DIFFERENT rewards address must be rejected —
    /// otherwise a client could "pay" its own wallet while the issuer is
    /// treated (and first-audited) as paid without ever being compensated.
    #[tokio::test]
    async fn test_legacy_paid_median_redirected_settlement_rejected() {
        let verifier = create_test_verifier();
        let xorname = [0xA2u8; 32];
        let peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        // Full amount, but recorded for an address that is not the quote's.
        let attacker_address = RewardsAddress::new([0xEEu8; 20]);
        assert_ne!(attacker_address, paid_quote.rewards_address);
        verifier.set_completed_payment_with_address_for_tests(
            paid_quote.hash(),
            expected_amount,
            attacker_address,
        );

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        let err = result.expect_err("redirected settlement must be rejected");
        assert!(
            format!("{err}").contains("redirected"),
            "Error should mention the settlement redirect: {err}"
        );
    }

    #[tokio::test]
    async fn test_legacy_single_quote_proof_accepted() {
        let verifier = create_test_verifier();
        let xorname = [0xB1u8; 32];
        let (peer_id, quote) = make_signed_quote(xorname, price_at_records(0), 1);
        let peer_quotes = vec![(peer_id, quote.clone())];
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        mark_candidate_paid(&verifier, &quote, expected_median_payment(&peer_quotes));

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("single paid quote should verify"),
            PaymentStatus::PaymentVerified
        );
    }

    /// Fixed-count [`crate::payment::quote::CommitmentSource`] standing in for
    /// the receiver's live commitment state in price-floor tests.
    struct FixedFloorSource {
        key_count: u32,
    }

    impl crate::payment::quote::CommitmentSource for FixedFloorSource {
        fn current_binding_for_quote(&self) -> Option<crate::payment::quote::QuoteBinding> {
            self.current_binding_snapshot()
        }

        fn current_binding_snapshot(&self) -> Option<crate::payment::quote::QuoteBinding> {
            Some(crate::payment::quote::QuoteBinding {
                key_count: self.key_count,
                pin: [0u8; 32],
            })
        }

        fn commitment_blob_for_pin(&self, _pin: [u8; 32]) -> Option<Vec<u8>> {
            None
        }
    }

    /// Receiver commitment count for floor tests, chosen so the local price is
    /// comfortably more than double the baseline (the 50% floor then rejects a
    /// baseline-priced settlement). Asserted in each test so a pricing-curve
    /// change fails loudly instead of silently weakening the tests.
    const FLOOR_TEST_LOCAL_KEY_COUNT: u32 = 1_000_000;

    fn floor_test_verifier(enforce: bool) -> PaymentVerifier {
        let verifier = create_test_verifier();
        verifier.attach_local_commitment_source(Arc::new(FixedFloorSource {
            key_count: FLOOR_TEST_LOCAL_KEY_COUNT,
        }));
        verifier.set_price_floor_for_tests(PriceFloorConfig {
            enforce,
            tolerance_percent: PRICE_FLOOR_DEFAULT_TOLERANCE_PERCENT,
        });
        let local_price = price_at_records(FLOOR_TEST_LOCAL_KEY_COUNT as usize);
        assert!(
            local_price > price_at_records(0) * Amount::from(2u64),
            "floor tests need a local price above twice baseline, got {local_price}"
        );
        verifier
    }

    /// The settled amount the floor requires: 3x the tolerated fraction of the
    /// close group's median commitment-bound price.
    fn group_floor_required_amount() -> Amount {
        let tolerated = price_at_records(GROUP_TEST_MEDIAN_KEY_COUNT as usize)
            * Amount::from(PRICE_FLOOR_DEFAULT_TOLERANCE_PERCENT)
            / Amount::from(100u64);
        tolerated * Amount::from(PAID_QUOTE_PAYMENT_MULTIPLIER)
    }

    /// One cheap (baseline-priced) quote paid `settled`: the cheapest-of-K
    /// omission shape a modified client can always produce.
    fn cheap_single_quote_proof(
        verifier: &PaymentVerifier,
        xorname: XorName,
        settled: Amount,
    ) -> Vec<u8> {
        let (peer_id, quote) = make_signed_quote(xorname, price_at_records(0), 1);
        let peer_quotes = vec![(peer_id, quote.clone())];
        mark_k_closest_paid_candidates(verifier, &peer_quotes);
        mark_candidate_paid(verifier, &quote, settled);
        serialize_proof(peer_quotes)
    }

    /// Close-group commitment counts used by the group-median floor tests.
    ///
    /// Exactly [`PRICE_FLOOR_MIN_NEIGHBOUR_COMMITMENTS`] entries, so these tests
    /// sit on the gate rather than comfortably past it: drop one and the floor
    /// must skip. Spread widely enough that the cheapest sits below the tolerated
    /// fraction of the median (asserted in the rejection test), and kept in the
    /// low thousands because each entry builds a real signed merkle commitment.
    const GROUP_TEST_KEY_COUNTS: [u32; 15] = [
        500, 800, 1_100, 1_400, 1_700, 2_000, 2_300, 2_600, 2_900, 3_200, 3_500, 3_800, 4_100,
        4_400, 4_700,
    ];

    /// The LOWER median of [`GROUP_TEST_KEY_COUNTS`] plus this node's own
    /// [`FLOOR_TEST_LOCAL_KEY_COUNT`].
    ///
    /// Sixteen samples, so the lower median is the eighth smallest: `2_600`. The
    /// receiver's own count is an extreme outlier at the top and does not move
    /// it, which is exactly the robustness a median buys. An even sample is
    /// deliberate — it is the case where upper and lower median differ, and the
    /// lower one is what production safety depends on.
    const GROUP_TEST_MEDIAN_KEY_COUNT: u32 = 2_600;

    /// Build a gossip commitment cache holding one fresh commitment per entry of
    /// `key_counts`, attach it, and return the peer ids so the caller can put
    /// them in the K-closest set.
    ///
    /// `age` ages every record equally, for the staleness test.
    fn attach_group_commitments(
        verifier: &PaymentVerifier,
        key_counts: &[u32],
        age: std::time::Duration,
    ) -> Vec<[u8; 32]> {
        use crate::replication::commitment_state::PeerCommitmentRecord;

        let received_at = std::time::Instant::now()
            .checked_sub(age)
            .unwrap_or_else(std::time::Instant::now);
        let mut cache_map = HashMap::new();
        let mut peer_ids = Vec::with_capacity(key_counts.len());
        for (index, count) in key_counts.iter().enumerate() {
            let built = test_built_commitment(*count);
            let mut raw = [0u8; 32];
            // Distinct, stable id per neighbour; the id only has to match
            // between the cache key and the K-closest set.
            raw[0] = u8::try_from(index + 1).unwrap_or(u8::MAX);
            peer_ids.push(raw);
            cache_map.insert(
                PeerId::from_bytes(raw),
                PeerCommitmentRecord::from_verified(built.commitment().clone(), received_at),
            );
        }
        verifier.attach_commitment_cache(Arc::new(tokio::sync::RwLock::new(cache_map)));
        peer_ids
    }

    /// A one-quote proof priced at `quote_records`, settled at `3 x
    /// price(settle_records)`, with the K-closest set covering both the quote
    /// issuer and the supplied close-group neighbours.
    fn group_floor_proof(
        verifier: &PaymentVerifier,
        xorname: XorName,
        quote_records: usize,
        settled: Amount,
        neighbours: &[[u8; 32]],
    ) -> Vec<u8> {
        let (peer_id, quote) = make_signed_quote(xorname, price_at_records(quote_records), 1);
        let mut k_closest: Vec<[u8; 32]> = neighbours.to_vec();
        k_closest.push(*peer_id.as_bytes());
        let peer_quotes = vec![(peer_id, quote.clone())];
        verifier.set_paid_quote_k_closest_for_tests(k_closest);
        mark_candidate_paid(verifier, &quote, settled);
        serialize_proof(peer_quotes)
    }

    fn three_times(price: Amount) -> Amount {
        price * Amount::from(PAID_QUOTE_PAYMENT_MULTIPLIER)
    }

    /// Overwrite the signed key count on cached commitments for `peer_ids`.
    ///
    /// Models a modified node: the honest builder refuses to construct a
    /// commitment at these counts, and building real ones at the protocol cap
    /// costs about a second and 200 MB apiece. The signature no longer matches,
    /// which is fine — the floor reads the cached count and never re-verifies.
    ///
    /// Asserts that every requested mutation landed. Callers assert ADMISSION,
    /// so a helper that silently no-opped would make those tests pass without
    /// ever forging anything.
    async fn forge_key_counts(
        verifier: &PaymentVerifier,
        peer_ids: Option<&[[u8; 32]]>,
        key_count: u32,
    ) {
        use crate::replication::commitment_state::PeerCommitmentRecord;

        let peer_ids = peer_ids.expect("caller must supply a valid peer id slice");
        let cache = verifier
            .commitment_cache
            .read()
            .as_ref()
            .map(Arc::clone)
            .expect("commitment cache must be attached before forging counts");
        let mut mutated = 0usize;
        {
            let mut guard = cache.write().await;
            for raw in peer_ids {
                if let Some(record) = guard.get_mut(&PeerId::from_bytes(*raw)) {
                    if let Some(mut forged) = record.last_commitment().cloned() {
                        forged.key_count = key_count;
                        *record =
                            PeerCommitmentRecord::from_verified(forged, std::time::Instant::now());
                        mutated += 1;
                    }
                }
            }
        }
        assert_eq!(
            mutated,
            peer_ids.len(),
            "every forged count must land, or the test asserting admission proves nothing"
        );
    }

    #[test]
    fn store_admission_contexts_cover_puts_and_fresh_replication_only() {
        assert!(VerificationContext::ClientPut.is_store_admission());
        assert!(VerificationContext::FreshReplication.is_store_admission());
        assert!(!VerificationContext::PaidListAdmission.is_store_admission());
    }

    /// Pins the reference itself: the sample includes this node, the median is
    /// taken over the whole close group, and the receiver's own extreme count
    /// does not move it.
    #[tokio::test]
    async fn group_reference_price_is_the_close_group_median() {
        let verifier = floor_test_verifier(true);
        let xorname = [0xD0u8; 32];
        let neighbours =
            attach_group_commitments(&verifier, &GROUP_TEST_KEY_COUNTS, std::time::Duration::ZERO);
        verifier.set_paid_quote_k_closest_for_tests(neighbours);

        let (reference, sample) = verifier.group_reference_price(&xorname).await;
        let reference = reference.expect("a fully populated group must produce a reference");

        assert_eq!(
            sample.neighbours,
            GROUP_TEST_KEY_COUNTS.len(),
            "the gated count is neighbours only"
        );
        assert_eq!(
            sample.total,
            GROUP_TEST_KEY_COUNTS.len() + 1,
            "the median is taken over the neighbours plus this node's own commitment"
        );
        assert!(
            sample.skip_reason.is_none(),
            "a fully populated group must not report a skip reason"
        );
        assert_eq!(
            reference,
            price_at_records(GROUP_TEST_MEDIAN_KEY_COUNT as usize),
            "the reference must be the group median price, not this node's own"
        );
        assert!(
            reference < price_at_records(FLOOR_TEST_LOCAL_KEY_COUNT as usize),
            "this node's own price is far above the median and must not be the reference"
        );
    }

    /// The production false-rejection case, encoded.
    ///
    /// This receiver holds far more than anyone else in its group, so its own
    /// price is enormous. An honest client paying 3x the GROUP MEDIAN must still
    /// be admitted. Pricing the floor against the receiver's own commitment
    /// rejected exactly this shape on ant-prod-01, 0.377% of honest stores, all
    /// of them on the fullest nodes.
    #[tokio::test]
    async fn price_floor_prices_against_the_group_median_not_the_receiver() {
        let verifier = floor_test_verifier(true);
        let xorname = [0xD1u8; 32];
        let neighbours =
            attach_group_commitments(&verifier, &GROUP_TEST_KEY_COUNTS, std::time::Duration::ZERO);

        let median_price = price_at_records(GROUP_TEST_MEDIAN_KEY_COUNT as usize);
        let own_price = price_at_records(FLOOR_TEST_LOCAL_KEY_COUNT as usize);
        assert!(
            own_price > median_price * Amount::from(2u64),
            "this test is only meaningful when the receiver is far above the group median"
        );

        // Honest: the client paid 3x the median of the quotes it collected.
        let settled = three_times(median_price);
        let proof_bytes = group_floor_proof(
            &verifier,
            xorname,
            GROUP_TEST_MEDIAN_KEY_COUNT as usize,
            settled,
            &neighbours,
        );

        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("an honest median payment must clear the group-median floor"),
            PaymentStatus::PaymentVerified
        );
    }

    /// The attack the floor exists to stop: collect the neighbourhood's quotes,
    /// settle only the cheapest one, submit it as a one-quote proof.
    #[tokio::test]
    async fn price_floor_rejects_cheapest_of_group_payment() {
        let verifier = floor_test_verifier(true);
        let xorname = [0xD2u8; 32];
        let neighbours =
            attach_group_commitments(&verifier, &GROUP_TEST_KEY_COUNTS, std::time::Duration::ZERO);

        let cheapest = GROUP_TEST_KEY_COUNTS.first().copied().unwrap_or(0) as usize;
        let cheapest_price = price_at_records(cheapest);
        let tolerated = price_at_records(GROUP_TEST_MEDIAN_KEY_COUNT as usize)
            * Amount::from(PRICE_FLOOR_DEFAULT_TOLERANCE_PERCENT)
            / Amount::from(100u64);
        assert!(
            cheapest_price < tolerated,
            "the cheapest group price must sit below the tolerated floor for this test to bite"
        );

        let proof_bytes = group_floor_proof(
            &verifier,
            xorname,
            cheapest,
            three_times(cheapest_price),
            &neighbours,
        );

        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("settling only the cheapest group quote must not clear the floor");

        assert!(
            format!("{err}").contains("below the close-group price floor"),
            "Error should name the group price floor: {err}"
        );
    }

    /// The anti-manipulation property: the reference price is built from this
    /// node's own routing view and the neighbours' signed gossip, never from the
    /// bundle. Padding the bundle with cheap quotes (the median-padding shape)
    /// must not move the floor.
    #[tokio::test]
    async fn price_floor_reference_ignores_client_supplied_quotes() {
        let verifier = floor_test_verifier(true);
        let xorname = [0xD3u8; 32];
        let neighbours =
            attach_group_commitments(&verifier, &GROUP_TEST_KEY_COUNTS, std::time::Duration::ZERO);

        // A bundle stuffed with baseline-priced quotes: the client's own median
        // is now the floor price, which is exactly what it would want.
        let cheapest = GROUP_TEST_KEY_COUNTS.first().copied().unwrap_or(0) as usize;
        let mut peer_quotes = Vec::new();
        let mut k_closest: Vec<[u8; 32]> = neighbours.clone();
        for seed in 1..=CLOSE_GROUP_SIZE {
            let seed_u8 = u8::try_from(seed).unwrap_or(u8::MAX);
            let (peer_id, quote) = make_signed_quote(xorname, price_at_records(cheapest), seed_u8);
            k_closest.push(*peer_id.as_bytes());
            peer_quotes.push((peer_id, quote));
        }
        verifier.set_paid_quote_k_closest_for_tests(k_closest);
        // Settle the padded median honestly for that padded bundle.
        for (_, quote) in &peer_quotes {
            mark_candidate_paid(&verifier, quote, three_times(price_at_records(cheapest)));
        }
        let proof_bytes = serialize_proof(peer_quotes);

        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("a bundle padded with cheap quotes must not lower this node's floor");

        assert!(
            format!("{err}").contains("below the close-group price floor"),
            "Error should name the group price floor: {err}"
        );
    }

    /// Too thin a local view must SKIP, never reject. A settled payment cannot
    /// be refunded, so guessing a reference from a handful of peers would burn
    /// user money on a startup or post-churn window.
    ///
    /// One neighbour short of the gate, and built from the DEAREST counts on
    /// purpose: if the gate were deleted, the surviving sample would price the
    /// floor ABOVE the settled amount and the payment would be rejected, so this
    /// test fails rather than passing vacuously. Building it from the cheapest
    /// counts (the obvious choice) would pass either way and prove nothing.
    #[tokio::test]
    async fn price_floor_skips_when_group_view_is_too_thin() {
        let verifier = floor_test_verifier(true);
        let xorname = [0xD4u8; 32];
        let thin: Vec<u32> = GROUP_TEST_KEY_COUNTS
            .iter()
            .rev()
            .copied()
            .take(PRICE_FLOOR_MIN_NEIGHBOUR_COMMITMENTS - 1)
            .collect();
        assert_eq!(thin.len(), PRICE_FLOOR_MIN_NEIGHBOUR_COMMITMENTS - 1);
        let neighbours = attach_group_commitments(&verifier, &thin, std::time::Duration::ZERO);

        // Deep underpayment that this sample, if it were used, would reject.
        let settled = three_times(price_at_records(0));
        let would_be_median = thin.get(thin.len() / 2).copied().unwrap_or_default();
        assert!(
            settled
                < price_at_records(would_be_median as usize)
                    * Amount::from(PRICE_FLOOR_DEFAULT_TOLERANCE_PERCENT)
                    / Amount::from(100u64)
                    * Amount::from(PAID_QUOTE_PAYMENT_MULTIPLIER),
            "the thin sample must price ABOVE the settlement, so deleting the gate fails this test"
        );
        let proof_bytes = group_floor_proof(&verifier, xorname, 0, settled, &neighbours);

        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("a thin group view must skip the floor, not reject"),
            PaymentStatus::PaymentVerified
        );
    }

    /// Exactly ON the gate must evaluate, so the boundary is pinned from both
    /// sides alongside the one-short test above.
    #[tokio::test]
    async fn price_floor_evaluates_at_exactly_the_minimum_sample() {
        let verifier = floor_test_verifier(true);
        let xorname = [0xDAu8; 32];
        assert_eq!(
            GROUP_TEST_KEY_COUNTS.len(),
            PRICE_FLOOR_MIN_NEIGHBOUR_COMMITMENTS,
            "the fixture must sit exactly on the gate for this boundary test"
        );
        let neighbours =
            attach_group_commitments(&verifier, &GROUP_TEST_KEY_COUNTS, std::time::Duration::ZERO);

        let proof_bytes = group_floor_proof(
            &verifier,
            xorname,
            0,
            three_times(price_at_records(0)),
            &neighbours,
        );

        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("exactly at the minimum sample the floor must evaluate and reject");
        assert!(format!("{err}").contains("below the close-group price floor"));
    }

    /// A receiver with no live commitment of its own must skip.
    ///
    /// Such a node prices its OWN quotes at baseline, so holding an incoming
    /// payment to its neighbours' higher median would reject settlements it
    /// would itself have quoted. The gossip cache is fully populated here, so
    /// only the missing own commitment can cause the skip.
    #[tokio::test]
    async fn price_floor_skips_when_this_node_has_no_commitment() {
        let verifier = create_test_verifier();
        verifier.set_price_floor_for_tests(PriceFloorConfig {
            enforce: true,
            tolerance_percent: PRICE_FLOOR_DEFAULT_TOLERANCE_PERCENT,
        });
        let xorname = [0xDBu8; 32];
        let neighbours =
            attach_group_commitments(&verifier, &GROUP_TEST_KEY_COUNTS, std::time::Duration::ZERO);

        let proof_bytes = group_floor_proof(
            &verifier,
            xorname,
            0,
            three_times(price_at_records(0)),
            &neighbours,
        );

        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("a receiver with no commitment of its own must skip the floor"),
            PaymentStatus::PaymentVerified
        );
    }

    /// A neighbour gossiping a count no honest node could hold must be dropped,
    /// not priced against.
    ///
    /// Gossip ingest authenticates the sender but does not bound the count,
    /// while quote validation rejects anything above `MAX_COMMITMENT_KEY_COUNT`.
    /// Without the filter, one such commitment inflates the reference and the
    /// floor becomes a way to reject other people's settled payments.
    #[tokio::test]
    async fn price_floor_ignores_commitments_above_the_protocol_cap() {
        let verifier = floor_test_verifier(true);
        let xorname = [0xDCu8; 32];
        // The honest builder refuses to construct an over-cap commitment, so
        // forge one the way a modified node would: build a valid commitment and
        // overwrite the signed count. Dropping it leaves the sample one short of
        // the gate, so the floor skips — that cardinality change is what this
        // test detects if the filter is removed. One over-cap value alone would
        // NOT move a 16-sample median; inflating the reference that way needs
        // about a quarter of the sample, which is the cardinality bound on
        // `group_reference_price` rather than something this filter fixes.
        let neighbours =
            attach_group_commitments(&verifier, &GROUP_TEST_KEY_COUNTS, std::time::Duration::ZERO);
        let over_cap = crate::replication::commitment::MAX_COMMITMENT_KEY_COUNT + 1;
        {
            let cache = verifier
                .commitment_cache
                .read()
                .as_ref()
                .map(Arc::clone)
                .expect("cache attached above");
            let mut guard = cache.write().await;
            let victim = neighbours.last().copied().unwrap_or_default();
            if let Some(record) = guard.get_mut(&PeerId::from_bytes(victim)) {
                let mut forged = record
                    .last_commitment()
                    .cloned()
                    .expect("fixture record holds a commitment");
                forged.key_count = over_cap;
                *record = crate::replication::commitment_state::PeerCommitmentRecord::from_verified(
                    forged,
                    std::time::Instant::now(),
                );
            }
        }

        let proof_bytes = group_floor_proof(
            &verifier,
            xorname,
            0,
            three_times(price_at_records(0)),
            &neighbours,
        );

        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("an over-cap gossiped count must be dropped, leaving too thin a sample"),
            PaymentStatus::PaymentVerified
        );
    }

    /// Pins the other KNOWN LIMIT: four of fifteen OVERSTATING neighbours push
    /// the reference up far enough to reject an honest payment sitting at the
    /// true group median.
    ///
    /// This is the griefing direction, and the more serious of the two: the
    /// attacker spends nothing and the victim's money is already settled and
    /// unrefundable. Like its understating sibling this test asserts a weakness
    /// deliberately. If a future change improves the bound it will fail and must
    /// be re-derived rather than deleted.
    #[tokio::test]
    async fn group_median_is_griefed_by_four_overstated_commitments() {
        let verifier = floor_test_verifier(true);
        let xorname = [0xE0u8; 32];
        let neighbours =
            attach_group_commitments(&verifier, &GROUP_TEST_KEY_COUNTS, std::time::Duration::ZERO);
        forge_key_counts(&verifier, neighbours.get(..4), MAX_COMMITMENT_KEY_COUNT).await;

        // A completely honest payment, priced at the TRUE group median.
        let honest = three_times(price_at_records(GROUP_TEST_MEDIAN_KEY_COUNT as usize));
        let proof_bytes = group_floor_proof(
            &verifier,
            xorname,
            GROUP_TEST_MEDIAN_KEY_COUNT as usize,
            honest,
            &neighbours,
        );

        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err(
                "KNOWN LIMIT: four overstated neighbours reject an honest at-median payment. \
                 If this now succeeds, the bound improved — re-derive it and update the docs.",
            );
        assert!(format!("{err}").contains("below the close-group price floor"));
    }

    /// Pins the KNOWN LIMIT, so it is a fact in the test suite rather than a
    /// claim in a comment: four of fifteen understating neighbours DISARM the
    /// floor, admitting the cheapest-of-K underpayment it exists to reject.
    ///
    /// This test asserts a weakness on purpose. It is the concrete reason
    /// enforcement stays off, and if a future change improves the bound this
    /// test will fail and must be re-derived rather than quietly deleted.
    #[tokio::test]
    async fn group_median_is_disarmed_by_four_understated_commitments() {
        let verifier = floor_test_verifier(true);
        let xorname = [0xDFu8; 32];
        let mut counts: Vec<u32> = GROUP_TEST_KEY_COUNTS.to_vec();
        for slot in counts.iter_mut().rev().take(4) {
            *slot = 1;
        }
        let neighbours = attach_group_commitments(&verifier, &counts, std::time::Duration::ZERO);

        let proof_bytes = group_floor_proof(
            &verifier,
            xorname,
            0,
            three_times(price_at_records(0)),
            &neighbours,
        );

        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect(
                "KNOWN LIMIT: four understated neighbours disarm the floor. If this now \
                 rejects, the bound improved — re-derive it and update the docs."
            ),
            PaymentStatus::PaymentVerified
        );
    }

    /// The griefing direction: a small minority gossiping OVERSTATED
    /// commitments must not push the reference up far enough to make this node
    /// reject an honest, already settled payment.
    ///
    /// This is the dangerous direction of a false commitment. Understating only
    /// costs a missed underpayment; overstating destroys someone else's money,
    /// and the attacker spends nothing to do it.
    ///
    /// The bound is real but partial, and worth stating precisely rather than
    /// claiming immunity. Each liar shifts the order statistic up by one rank,
    /// so what protects the payment is the tolerance headroom, not the median
    /// itself. In this fixture three liars move the reference `2_600` ->
    /// `3_500` and an at-median payment still clears, by only 1.9%; four move it
    /// to `3_800`
    /// and the same payment is REJECTED (pinned by
    /// `group_median_is_griefed_by_four_overstated_commitments`). The griefing
    /// bound is therefore about a quarter of the sample, the same as the
    /// disarming one — NOT "roughly half", which was the incorrect claim this
    /// policy originally rested on.
    ///
    /// Estimator coverage: this case fails under a 25th percentile, and its
    /// disarming sibling fails under a mean and under the upper median, so the
    /// pair pins the estimator jointly. Neither does so alone.
    #[tokio::test]
    async fn group_median_resists_three_overstated_commitments() {
        let verifier = floor_test_verifier(true);
        let xorname = [0xDDu8; 32];
        // Three of fifteen neighbours claim the protocol maximum. Forged by
        // overwriting the signed count rather than building real 1,000,000-leaf
        // commitments, which cost about a second and 200 MB each.
        let neighbours =
            attach_group_commitments(&verifier, &GROUP_TEST_KEY_COUNTS, std::time::Duration::ZERO);
        forge_key_counts(&verifier, neighbours.get(..3), MAX_COMMITMENT_KEY_COUNT).await;

        // An honest payment at the TRUE group median must still be admitted.
        let honest = three_times(price_at_records(GROUP_TEST_MEDIAN_KEY_COUNT as usize));
        let proof_bytes = group_floor_proof(
            &verifier,
            xorname,
            GROUP_TEST_MEDIAN_KEY_COUNT as usize,
            honest,
            &neighbours,
        );

        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("a minority of overstated commitments must not reject honest payments"),
            PaymentStatus::PaymentVerified
        );
    }

    /// Stale gossip is treated as unknown rather than as a low price, so a peer
    /// going quiet can neither drag the median down nor be counted toward the
    /// minimum sample.
    ///
    /// Every neighbour is stale, so the sample collapses below the gate and the
    /// floor skips instead of pricing against this node's own (huge) count.
    #[tokio::test]
    async fn price_floor_ignores_stale_group_commitments() {
        let verifier = floor_test_verifier(true);
        let xorname = [0xD5u8; 32];
        let stale_age = crate::replication::commitment_state::GOSSIP_ANSWERABILITY_TTL
            + std::time::Duration::from_secs(60);
        let neighbours = attach_group_commitments(&verifier, &GROUP_TEST_KEY_COUNTS, stale_age);

        let proof_bytes = group_floor_proof(
            &verifier,
            xorname,
            0,
            three_times(price_at_records(0)),
            &neighbours,
        );

        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("stale gossip must not be priced against"),
            PaymentStatus::PaymentVerified
        );
    }

    /// A MIXED cache must exclude only the stale entries and price against the
    /// fresh ones.
    ///
    /// The all-stale test above collapses to the sample gate, so it would still
    /// pass if the TTL filter let stale counts through whenever enough fresh
    /// ones existed. This one pins the filter itself, and asserts on the
    /// reference directly rather than end-to-end.
    ///
    /// Going through `verify_payment` would need enough stale entries to move
    /// the median past the tolerance — more neighbours than production can ever
    /// present, since the K-closest scan returns at most 20 including self. The
    /// reference and the gated neighbour count are the precise observations
    /// anyway: if the TTL filter were removed, both would change.
    #[tokio::test]
    async fn price_floor_excludes_only_the_stale_entries_from_a_mixed_cache() {
        use crate::replication::commitment_state::PeerCommitmentRecord;

        let verifier = floor_test_verifier(true);
        let xorname = [0xDEu8; 32];
        let stale_age = crate::replication::commitment_state::GOSSIP_ANSWERABILITY_TTL
            + std::time::Duration::from_secs(60);

        // Fresh: the full fixture, exactly on the gate.
        let fresh =
            attach_group_commitments(&verifier, &GROUP_TEST_KEY_COUNTS, std::time::Duration::ZERO);

        // Stale: four cheap counts, keeping the total within the 19 neighbours a
        // real routing view can supply.
        let stale_counts = [1u32; 4];
        let stale_received = std::time::Instant::now()
            .checked_sub(stale_age)
            .expect("test clock must support the TTL offset");
        let mut all = fresh.clone();
        {
            let cache = verifier
                .commitment_cache
                .read()
                .as_ref()
                .map(Arc::clone)
                .expect("cache attached above");
            let mut guard = cache.write().await;
            for (index, count) in stale_counts.iter().enumerate() {
                let built = test_built_commitment(*count);
                let mut raw = [0u8; 32];
                raw[0] = 0xF0;
                raw[1] = u8::try_from(index).unwrap_or(u8::MAX);
                all.push(raw);
                guard.insert(
                    PeerId::from_bytes(raw),
                    PeerCommitmentRecord::from_verified(built.commitment().clone(), stale_received),
                );
            }
        }
        verifier.set_paid_quote_k_closest_for_tests(all);

        let (reference, sample) = verifier.group_reference_price(&xorname).await;

        assert_eq!(
            sample.neighbours,
            GROUP_TEST_KEY_COUNTS.len(),
            "stale entries must not count toward the gate"
        );
        assert_eq!(
            reference,
            Some(price_at_records(GROUP_TEST_MEDIAN_KEY_COUNT as usize)),
            "the reference must be the fresh-only median; counting the stale cheap \
             entries would drag it below"
        );
    }

    /// Understated commitments pull the reference DOWN and weaken the floor.
    ///
    /// Three adversarially-placed liars leave it standing; four disarm it. The
    /// placement matters and is easy to get wrong: understating a peer that was
    /// already below the median changes nothing, so a test that rewrites the
    /// CHEAPEST entries passes while testing nothing. These rewrite the DEAREST
    /// ones, which is where an attacker would sit, and the count is set to the
    /// largest that still holds rather than to an aspirational majority.
    #[tokio::test]
    async fn group_median_resists_three_understated_commitments() {
        let verifier = floor_test_verifier(true);
        let xorname = [0xD6u8; 32];
        // Three of fifteen neighbours claim to store almost nothing. `1`, not
        // `0`: a commitment over an empty key set cannot be built at all, so one
        // key is the least a peer can honestly (or dishonestly) commit to.
        let mut counts: Vec<u32> = GROUP_TEST_KEY_COUNTS.to_vec();
        for slot in counts.iter_mut().rev().take(3) {
            *slot = 1;
        }
        let neighbours = attach_group_commitments(&verifier, &counts, std::time::Duration::ZERO);

        let cheapest_price = price_at_records(0);
        let proof_bytes = group_floor_proof(
            &verifier,
            xorname,
            0,
            three_times(cheapest_price),
            &neighbours,
        );

        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("a minority of understated commitments must not disarm the floor");

        assert!(
            format!("{err}").contains("below the close-group price floor"),
            "Error should name the group price floor: {err}"
        );
    }

    #[tokio::test]
    async fn test_price_floor_shadow_mode_accepts_below_floor_settlement() {
        let verifier = floor_test_verifier(false);
        let xorname = [0xC1u8; 32];
        let neighbours =
            attach_group_commitments(&verifier, &GROUP_TEST_KEY_COUNTS, std::time::Duration::ZERO);
        let settled = three_times(price_at_records(0));
        assert!(
            settled < group_floor_required_amount(),
            "shadow mode is only meaningful on a settlement that WOULD be rejected"
        );
        let proof_bytes = group_floor_proof(&verifier, xorname, 0, settled, &neighbours);

        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("shadow mode must never reject on the floor"),
            PaymentStatus::PaymentVerified
        );
    }

    #[tokio::test]
    async fn test_price_floor_enforced_rejects_cheapest_of_k_settlement() {
        let verifier = floor_test_verifier(true);
        let xorname = [0xC2u8; 32];
        let neighbours =
            attach_group_commitments(&verifier, &GROUP_TEST_KEY_COUNTS, std::time::Duration::ZERO);
        let settled = three_times(price_at_records(0));
        let proof_bytes = group_floor_proof(&verifier, xorname, 0, settled, &neighbours);

        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("a 3x-baseline settlement must not clear the group-median floor");

        assert!(
            format!("{err}").contains("below the close-group price floor"),
            "Error should name the price floor: {err}"
        );
    }

    #[tokio::test]
    async fn test_price_floor_enforced_accepts_exactly_at_floor_overpayment() {
        // An honest client may OVERPAY a cheap quote to clear stricter
        // receivers: the floor compares the settled amount, not the quote
        // price, and exactly-at-floor must pass.
        let verifier = floor_test_verifier(true);
        let xorname = [0xC3u8; 32];
        let neighbours =
            attach_group_commitments(&verifier, &GROUP_TEST_KEY_COUNTS, std::time::Duration::ZERO);
        let proof_bytes = group_floor_proof(
            &verifier,
            xorname,
            0,
            group_floor_required_amount(),
            &neighbours,
        );

        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("an exactly-at-floor settlement must pass"),
            PaymentStatus::PaymentVerified
        );
    }

    #[tokio::test]
    async fn test_price_floor_enforced_applies_to_fresh_replication() {
        // Fresh replication is the same fresh economic event as a direct PUT;
        // exempting it would let one cheap accepting node fan the proof out
        // around every other storer's floor.
        let verifier = floor_test_verifier(true);
        let xorname = [0xC4u8; 32];
        let neighbours =
            attach_group_commitments(&verifier, &GROUP_TEST_KEY_COUNTS, std::time::Duration::ZERO);
        let settled = three_times(price_at_records(0));
        let proof_bytes = group_floor_proof(&verifier, xorname, 0, settled, &neighbours);

        let err = verifier
            .verify_payment(
                &xorname,
                Some(&proof_bytes),
                VerificationContext::FreshReplication,
            )
            .await
            .expect_err("fresh replication must enforce the same floor as direct PUTs");

        assert!(
            format!("{err}").contains("below the close-group price floor"),
            "Error should name the price floor: {err}"
        );
    }

    #[tokio::test]
    async fn test_price_floor_never_reprices_paid_list_admission() {
        let verifier = floor_test_verifier(true);
        let xorname = [0xC5u8; 32];
        let neighbours =
            attach_group_commitments(&verifier, &GROUP_TEST_KEY_COUNTS, std::time::Duration::ZERO);
        let settled = three_times(price_at_records(0));
        let proof_bytes = group_floor_proof(&verifier, xorname, 0, settled, &neighbours);

        let result = verifier
            .verify_payment(
                &xorname,
                Some(&proof_bytes),
                VerificationContext::PaidListAdmission,
            )
            .await;

        assert_eq!(
            result.expect("paid-list admission reprices no fresh economic decision"),
            PaymentStatus::PaymentVerified
        );
    }

    /// A node that HAS its own commitment but no gossip cache must skip.
    ///
    /// This is the case that actually distinguishes the new behaviour from the
    /// old: under the withdrawn own-price rule this receiver priced the floor at
    /// its own enormous count and rejected the settlement. Now it has no group
    /// view, so it does not evaluate. Using a verifier with no commitment source
    /// at all (the obvious setup) would have passed under both rules and proved
    /// nothing.
    #[tokio::test]
    async fn test_price_floor_without_any_group_view_skips() {
        let verifier = floor_test_verifier(true);
        let xorname = [0xC6u8; 32];
        let settled = three_times(price_at_records(0));
        assert!(
            settled
                < price_at_records(FLOOR_TEST_LOCAL_KEY_COUNT as usize)
                    * Amount::from(PRICE_FLOOR_DEFAULT_TOLERANCE_PERCENT)
                    / Amount::from(100u64)
                    * Amount::from(PAID_QUOTE_PAYMENT_MULTIPLIER),
            "the old own-price rule would have rejected this settlement, so the skip is load-bearing"
        );
        let proof_bytes = cheap_single_quote_proof(&verifier, xorname, settled);

        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("no group view must skip the floor, never reject"),
            PaymentStatus::PaymentVerified
        );
    }

    /// `from_env` must fail CLOSED: a present-but-invalid tolerance can never
    /// leave enforcement on with a tolerance the operator did not specify.
    /// (This test owns the `PRICE_FLOOR_*` env vars — no other test reads them.)
    #[test]
    fn price_floor_from_env_fails_closed_on_invalid_tolerance() {
        // Defaults with nothing set.
        std::env::remove_var(PRICE_FLOOR_ENFORCE_ENV);
        std::env::remove_var(PRICE_FLOOR_TOLERANCE_ENV);
        let cfg = PriceFloorConfig::from_env();
        assert!(!cfg.enforce);
        assert_eq!(cfg.tolerance_percent, PRICE_FLOOR_DEFAULT_TOLERANCE_PERCENT);

        // Enforce on, valid tolerance: honoured.
        std::env::set_var(PRICE_FLOOR_ENFORCE_ENV, "1");
        std::env::set_var(PRICE_FLOOR_TOLERANCE_ENV, "80");
        let cfg = PriceFloorConfig::from_env();
        assert!(cfg.enforce);
        assert_eq!(cfg.tolerance_percent, 80);

        // Enforce on, out-of-range tolerance: enforcement DISABLED (fail closed).
        std::env::set_var(PRICE_FLOOR_TOLERANCE_ENV, "150");
        let cfg = PriceFloorConfig::from_env();
        assert!(
            !cfg.enforce,
            "an out-of-range tolerance must not silently enforce a default"
        );

        // Enforce on, unparseable tolerance: also disabled.
        std::env::set_var(PRICE_FLOOR_TOLERANCE_ENV, "loose");
        let cfg = PriceFloorConfig::from_env();
        assert!(!cfg.enforce);

        std::env::remove_var(PRICE_FLOOR_ENFORCE_ENV);
        std::env::remove_var(PRICE_FLOOR_TOLERANCE_ENV);
    }

    #[tokio::test]
    async fn test_legacy_single_quote_proof_requires_three_x_payment() {
        let verifier = create_test_verifier();
        let xorname = [0xB2u8; 32];
        let (peer_id, quote) = make_signed_quote(xorname, price_at_records(0), 1);
        let peer_quotes = vec![(peer_id, quote.clone())];
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        mark_candidate_paid(&verifier, &quote, quote.price);

        let proof_bytes = serialize_proof(peer_quotes);
        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("single quote paid less than 3x should be rejected");

        assert!(
            format!("{err}").contains("not paid enough"),
            "Error should mention underpayment: {err}"
        );
    }

    #[tokio::test]
    async fn test_legacy_too_many_quotes_rejected() {
        let verifier = create_test_verifier();
        let xorname = [0xB3u8; 32];
        let mut peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        peer_quotes.push(make_signed_quote(xorname, price_at_records(7), 8));

        let proof_bytes = serialize_proof(peer_quotes);
        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("proof with more than close-group quotes should be rejected");

        assert!(
            format!("{err}").contains("at most"),
            "Error should mention max quote count: {err}"
        );
    }

    #[tokio::test]
    async fn test_legacy_structural_majority_price_at_median_accepted() {
        let verifier = create_test_verifier();
        let xorname = [0xA2u8; 32];
        let peer_quotes = make_signed_legacy_bundle(
            xorname,
            [
                crate::payment::pricing::calculate_price(0),
                crate::payment::pricing::calculate_price(100),
                crate::payment::pricing::calculate_price(500),
                crate::payment::pricing::calculate_price(1000),
                crate::payment::pricing::calculate_price(2000),
                crate::payment::pricing::calculate_price(4000),
                crate::payment::pricing::calculate_price(6000),
            ],
        );
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("median-priced verifier should accept"),
            PaymentStatus::PaymentVerified
        );
    }

    #[tokio::test]
    async fn test_legacy_paid_median_issuer_k_closest_rejection() {
        let verifier = create_test_verifier();
        verifier.set_paid_quote_k_closest_for_tests(vec![rand::random()]);
        let xorname = [0xA4u8; 32];
        let peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("out-of-K paid issuer should be rejected");

        assert!(
            format!("{err}").contains("not among this node's local"),
            "Error should mention local K-closest peers: {err}"
        );
    }

    /// A zero-priced median must never be admitted.
    ///
    /// Which check rejects it depends on the ADR-0004 rollout gate. `Amount::ZERO`
    /// is not a point on the pricing curve (the curve's minimum is
    /// `calculate_price(0)`), so with
    /// [`crate::replication::config::QUOTE_ARITHMETIC_RECHECK_ENABLED`] on, the
    /// arithmetic gate rejects the bundle before median selection runs and the
    /// dedicated zero-price check is no longer reachable for single-node quotes.
    /// The gate subsumes it rather than replacing it, so both messages are
    /// accepted here and the invariant under test stays "this is rejected".
    #[tokio::test]
    async fn test_legacy_zero_price_median_rejected() {
        let verifier = create_test_verifier();
        let xorname = [0xA6u8; 32];
        let peer_quotes = make_signed_legacy_bundle(
            xorname,
            [
                Amount::ZERO,
                Amount::ZERO,
                Amount::ZERO,
                Amount::ZERO,
                Amount::from(1u64),
                Amount::from(2u64),
                Amount::from(3u64),
            ],
        );

        let proof_bytes = serialize_proof(peer_quotes);
        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("zero median must be rejected");

        let msg = format!("{err}");
        assert!(
            msg.contains("zero price") || msg.contains("off-curve quote rejected"),
            "Error must reject the zero-priced median, by either the zero-price \
             check or the ADR-0004 arithmetic gate: {msg}"
        );
    }

    #[tokio::test]
    async fn test_legacy_paid_quote_content_mismatch_rejected() {
        let verifier = create_test_verifier();
        let xorname = [0xA7u8; 32];
        let mut peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        let median_index = median_quote_index(peer_quotes.len());
        peer_quotes[median_index].1.content = xor_name::XorName([0xE7u8; 32]);
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);

        let proof_bytes = serialize_proof(peer_quotes);
        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("paid quote content mismatch should be rejected");

        assert!(
            format!("{err}").contains("content address mismatch"),
            "Error should mention content mismatch: {err}"
        );
    }

    #[tokio::test]
    async fn test_legacy_unpaid_quote_content_mismatch_accepted() {
        let verifier = create_test_verifier();
        let xorname = [0xA8u8; 32];
        let mut peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        peer_quotes[0].1.content = xor_name::XorName([0xE8u8; 32]);
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("unpaid content mismatch should be ignored"),
            PaymentStatus::PaymentVerified
        );
    }

    #[tokio::test]
    async fn test_legacy_paid_quote_bad_signature_rejected() {
        let verifier = create_test_verifier();
        let xorname = [0xA9u8; 32];
        let mut peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        let median_index = median_quote_index(peer_quotes.len());
        peer_quotes[median_index].1.signature.push(0xFF);
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let err = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await
            .expect_err("paid bad signature should be rejected");

        assert!(
            format!("{err}").contains("signature verification failed"),
            "Error should mention signature failure: {err}"
        );
    }

    #[tokio::test]
    async fn test_legacy_unpaid_quote_bad_signature_accepted() {
        let verifier = create_test_verifier();
        let xorname = [0xAAu8; 32];
        let mut peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        peer_quotes[0].1.signature.push(0xFF);
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("unpaid bad signature should be ignored"),
            PaymentStatus::PaymentVerified
        );
    }

    #[tokio::test]
    async fn test_legacy_unpaid_peer_binding_mismatch_accepted() {
        let verifier = create_test_verifier();
        let xorname = [0xABu8; 32];
        let mut peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        peer_quotes[0].0 = evmlib::EncodedPeerId::new(rand::random());
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("unpaid peer binding mismatch should be ignored"),
            PaymentStatus::PaymentVerified
        );
    }

    #[tokio::test]
    async fn test_legacy_median_tie_accepts_paid_candidate() {
        let verifier = create_test_verifier();
        let xorname = [0xACu8; 32];
        let peer_quotes = make_signed_legacy_bundle(xorname, tied_median_test_prices());
        mark_k_closest_paid_candidates(&verifier, &peer_quotes);
        mark_all_median_candidates_unpaid(&verifier, &peer_quotes);
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .get(1)
            .expect("second tied median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert_eq!(
            result.expect("one paid tied median candidate should verify"),
            PaymentStatus::PaymentVerified
        );
    }

    #[tokio::test]
    async fn test_legacy_paid_list_admission_enforces_issuer_k_closest() {
        let verifier = create_test_verifier();
        verifier.set_paid_quote_k_closest_for_tests(Vec::new());
        let xorname = [0xB5u8; 32];
        let peer_quotes = make_signed_legacy_bundle(xorname, unique_test_prices());
        let expected_amount = expected_median_payment(&peer_quotes);
        let paid_quote = median_test_candidates(&peer_quotes)
            .first()
            .expect("median candidate")
            .1
            .clone();
        mark_candidate_paid(&verifier, &paid_quote, expected_amount);

        let proof_bytes = serialize_proof(peer_quotes);
        let err = verifier
            .verify_payment(
                &xorname,
                Some(&proof_bytes),
                VerificationContext::PaidListAdmission,
            )
            .await
            .expect_err("paid-list admission must enforce the paid issuer K-closest check");

        assert!(
            format!("{err}").contains("not among this node's local"),
            "Error should mention local K-closest peers: {err}"
        );
    }

    #[test]
    fn test_cache_len_getter() {
        let verifier = create_test_verifier();
        assert_eq!(verifier.cache_len(), 0);

        verifier.cache.insert([10u8; 32]);
        assert_eq!(verifier.cache_len(), 1);

        verifier.cache.insert([20u8; 32]);
        assert_eq!(verifier.cache_len(), 2);
    }

    #[test]
    fn test_cache_stats_after_operations() {
        let verifier = create_test_verifier();
        let xorname = [7u8; 32];

        // Miss
        verifier.check_payment_required(&xorname, VerificationContext::ClientPut);
        let stats = verifier.cache_stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);

        // Insert and hit
        verifier.cache.insert(xorname);
        verifier.check_payment_required(&xorname, VerificationContext::ClientPut);
        let stats = verifier.cache_stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.additions, 1);
    }

    #[tokio::test]
    async fn test_concurrent_cache_lookups() {
        let verifier = std::sync::Arc::new(create_test_verifier());

        // Pre-populate cache for all 10 xornames
        for i in 0..10u8 {
            verifier.cache.insert([i; 32]);
        }

        let mut handles = Vec::new();
        for i in 0..10u8 {
            let v = verifier.clone();
            handles.push(tokio::spawn(async move {
                let xorname = [i; 32];
                v.verify_payment(&xorname, None, VerificationContext::ClientPut)
                    .await
            }));
        }

        for handle in handles {
            let result = handle.await.expect("task panicked");
            assert!(result.is_ok());
            assert_eq!(result.expect("cached"), PaymentStatus::CachedAsVerified);
        }

        assert_eq!(verifier.cache_len(), 10);
    }

    #[test]
    fn test_default_evm_config() {
        let _config = EvmVerifierConfig::default();
        // EVM is always on — default network is ArbitrumOne
    }

    #[test]
    fn test_real_ml_dsa_proof_size_within_limits() {
        use crate::payment::metrics::QuotingMetricsTracker;
        use crate::payment::proof::PaymentProof;
        use crate::payment::quote::{QuoteGenerator, XorName};
        use alloy::primitives::FixedBytes;
        use evmlib::{EncodedPeerId, RewardsAddress};
        use saorsa_core::MlDsa65;
        use saorsa_pqc::pqc::types::MlDsaSecretKey;
        use saorsa_pqc::pqc::MlDsaOperations;

        let ml_dsa = MlDsa65::new();
        let mut peer_quotes = Vec::new();

        for i in 0..5u8 {
            let (public_key, secret_key) = ml_dsa.generate_keypair().expect("keygen");

            let rewards_address = RewardsAddress::new([i; 20]);
            let metrics_tracker = QuotingMetricsTracker::new(0);
            let mut generator = QuoteGenerator::new(rewards_address, metrics_tracker);

            let pub_key_bytes = public_key.as_bytes().to_vec();
            let sk_bytes = secret_key.as_bytes().to_vec();
            generator.set_signer(pub_key_bytes, move |msg| {
                let sk = MlDsaSecretKey::from_bytes(&sk_bytes).expect("sk parse");
                let ml_dsa = MlDsa65::new();
                ml_dsa.sign(&sk, msg).expect("sign").as_bytes().to_vec()
            });

            let content: XorName = [i; 32];
            let quote = generator.create_quote(content, 4096, 0).expect("quote");

            peer_quotes.push((EncodedPeerId::new(rand::random()), quote));
        }

        let proof = PaymentProof {
            proof_of_payment: ProofOfPayment { peer_quotes },
            tx_hashes: vec![FixedBytes::from([0xABu8; 32])],
            commitment_sidecars: vec![],
        };

        let proof_bytes =
            crate::payment::proof::serialize_single_node_proof(&proof).expect("serialize");

        // 7 ML-DSA-65 quotes with ~1952-byte pub keys and ~3309-byte signatures
        // should produce a proof in the 30-80 KB range
        assert!(
            proof_bytes.len() > 20_000,
            "Real 7-quote ML-DSA proof should be > 20 KB, got {} bytes",
            proof_bytes.len()
        );
        assert!(
            proof_bytes.len() < MAX_PAYMENT_PROOF_SIZE_BYTES,
            "Real 7-quote ML-DSA proof ({} bytes) should fit within {} byte limit",
            proof_bytes.len(),
            MAX_PAYMENT_PROOF_SIZE_BYTES
        );
    }

    #[tokio::test]
    async fn test_content_address_mismatch_rejected() {
        use crate::payment::proof::{serialize_single_node_proof, PaymentProof};
        use evmlib::{EncodedPeerId, PaymentQuote, RewardsAddress};
        use std::time::SystemTime;

        let verifier = create_test_verifier();

        // The xorname we're trying to store
        let target_xorname = [0xAAu8; 32];

        // Create a quote for a DIFFERENT xorname
        let wrong_xorname = [0xBBu8; 32];
        let quote = PaymentQuote {
            content: xor_name::XorName(wrong_xorname),
            timestamp: SystemTime::now(),
            // Baseline-priced so the quote is on-curve: this test is about the
            // content binding, and an off-curve price would be rejected by the
            // ADR-0004 arithmetic gate first, never reaching that check.
            price: crate::payment::pricing::calculate_price(0),
            rewards_address: RewardsAddress::new([1u8; 20]),
            committed_key_count: 0,
            commitment_pin: None,
            pub_key: vec![0u8; 64],
            signature: vec![0u8; 64],
        };

        // Build CLOSE_GROUP_SIZE quotes with distinct peer IDs
        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            peer_quotes.push((EncodedPeerId::new(rand::random()), quote.clone()));
        }

        let proof = PaymentProof {
            proof_of_payment: ProofOfPayment { peer_quotes },
            tx_hashes: vec![],
            commitment_sidecars: vec![],
        };

        let proof_bytes = serialize_single_node_proof(&proof).expect("serialize proof");

        let result = verifier
            .verify_payment(
                &target_xorname,
                Some(&proof_bytes),
                VerificationContext::ClientPut,
            )
            .await;

        assert!(result.is_err(), "Should reject mismatched content address");
        let err_msg = format!("{}", result.expect_err("should be error"));
        assert!(
            err_msg.contains("content address mismatch"),
            "Error should mention 'content address mismatch': {err_msg}"
        );
    }

    /// Helper: create a fake quote with the given xorname and timestamp.
    fn make_fake_quote(
        xorname: [u8; 32],
        timestamp: SystemTime,
        rewards_address: RewardsAddress,
    ) -> evmlib::PaymentQuote {
        use evmlib::PaymentQuote;

        PaymentQuote {
            content: xor_name::XorName(xorname),
            timestamp,
            // Baseline quote: `(committed_key_count = 0, commitment_pin = None)`
            // must be priced at `calculate_price(0)` to satisfy the ADR-0004
            // binding rule. An arbitrary placeholder price here is off-curve and
            // is rejected outright once
            // [`crate::replication::config::QUOTE_ARITHMETIC_RECHECK_ENABLED`] is
            // on, which would mask whatever a test actually means to assert.
            price: crate::payment::pricing::calculate_price(0),
            rewards_address,
            committed_key_count: 0,
            commitment_pin: None,
            pub_key: vec![0u8; 64],
            signature: vec![0u8; 64],
        }
    }

    /// Helper: create a fake quote priced on-curve at `records` stored records
    /// (price = `calculate_price(records)`), reusing [`make_fake_quote`] for the
    /// remaining fields. Used by the ADR-0004 arithmetic-gate tests.
    ///
    /// Sets the whole binding, not just the price: ADR-0004 requires `price ==
    /// calculate_price(committed_key_count)` AND the `(n > 0, Some(pin))` /
    /// `(0, None)` shape, so pricing at `records` while leaving the count at `0`
    /// produces a quote that claims to store nothing yet charges as though it
    /// stored `records` keys. That is exactly what the gate rejects.
    fn make_fake_quote_at_records(
        xorname: [u8; 32],
        timestamp: SystemTime,
        rewards_address: RewardsAddress,
        records: usize,
    ) -> evmlib::PaymentQuote {
        let mut quote = make_fake_quote(xorname, timestamp, rewards_address);
        quote.price = crate::payment::pricing::calculate_price(records);
        quote.committed_key_count = u32::try_from(records).unwrap_or(u32::MAX);
        quote.commitment_pin = if records == 0 {
            None
        } else {
            // Any stable non-zero pin: these fixtures never resolve it to a real
            // commitment, they only need the binding shape to be coherent.
            Some([0xA5u8; 32])
        };
        quote
    }

    /// Helper: wrap quotes into a tagged serialized `PaymentProof`.
    fn serialize_proof(peer_quotes: Vec<(evmlib::EncodedPeerId, evmlib::PaymentQuote)>) -> Vec<u8> {
        use crate::payment::proof::{serialize_single_node_proof, PaymentProof};

        let proof = PaymentProof {
            proof_of_payment: ProofOfPayment { peer_quotes },
            tx_hashes: vec![],
            commitment_sidecars: vec![],
        };
        serialize_single_node_proof(&proof).expect("serialize proof")
    }

    #[tokio::test]
    async fn test_old_quote_uses_storage_delta_not_timestamp() {
        use evmlib::{EncodedPeerId, RewardsAddress};
        use std::time::Duration;

        let verifier = create_test_verifier();
        let xorname = [0xCCu8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Create a quote that's 25 hours old (exceeds 24-hour max)
        let old_timestamp = SystemTime::now() - Duration::from_hours(25);
        let quote = make_fake_quote(xorname, old_timestamp, rewards_addr);

        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            peer_quotes.push((EncodedPeerId::new(rand::random()), quote.clone()));
        }

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        let err_msg = format!("{}", result.expect_err("should fail at later check"));
        assert!(
            !err_msg.contains("expired"),
            "Should not reject by timestamp age: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_future_quote_uses_storage_delta_not_timestamp() {
        use evmlib::{EncodedPeerId, RewardsAddress};
        use std::time::Duration;

        let verifier = create_test_verifier();
        let xorname = [0xDDu8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Create a quote with a timestamp 1 hour in the future
        let future_timestamp = SystemTime::now() + Duration::from_hours(1);
        let quote = make_fake_quote(xorname, future_timestamp, rewards_addr);

        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            peer_quotes.push((EncodedPeerId::new(rand::random()), quote.clone()));
        }

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        let err_msg = format!("{}", result.expect_err("should fail at later check"));
        assert!(
            !err_msg.contains("future"),
            "Should not reject by future timestamp: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_quote_within_clock_skew_tolerance_accepted() {
        use evmlib::{EncodedPeerId, RewardsAddress};
        use std::time::Duration;

        let verifier = create_test_verifier();
        let xorname = [0xD1u8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Quote 30 seconds in the future — well within 300s tolerance
        let future_timestamp = SystemTime::now() + Duration::from_secs(30);
        let quote = make_fake_quote(xorname, future_timestamp, rewards_addr);

        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            peer_quotes.push((EncodedPeerId::new(rand::random()), quote.clone()));
        }

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        // Should NOT fail at timestamp check (will fail later at pub_key binding)
        let err_msg = format!("{}", result.expect_err("should fail at later check"));
        assert!(
            !err_msg.contains("future"),
            "Should pass timestamp check (within tolerance), but got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_quote_beyond_clock_skew_still_uses_storage_delta() {
        use evmlib::{EncodedPeerId, RewardsAddress};
        use std::time::Duration;

        let verifier = create_test_verifier();
        let xorname = [0xD2u8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Quote 360 seconds in the future — exceeds 300s tolerance
        let future_timestamp = SystemTime::now() + Duration::from_mins(6);
        let quote = make_fake_quote(xorname, future_timestamp, rewards_addr);

        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            peer_quotes.push((EncodedPeerId::new(rand::random()), quote.clone()));
        }

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        let err_msg = format!("{}", result.expect_err("should fail at later check"));
        assert!(
            !err_msg.contains("future"),
            "Should not reject by future timestamp: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_quote_23h_old_still_accepted() {
        use evmlib::{EncodedPeerId, RewardsAddress};
        use std::time::Duration;

        let verifier = create_test_verifier();
        let xorname = [0xD3u8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Quote 23 hours old — within 24h max age
        let old_timestamp = SystemTime::now() - Duration::from_hours(23);
        let quote = make_fake_quote(xorname, old_timestamp, rewards_addr);

        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            peer_quotes.push((EncodedPeerId::new(rand::random()), quote.clone()));
        }

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        // Should NOT fail at timestamp check (will fail later at pub_key binding)
        let err_msg = format!("{}", result.expect_err("should fail at later check"));
        assert!(
            !err_msg.contains("expired"),
            "Should pass expiry check (23h < 24h), but got: {err_msg}"
        );
    }

    /// Helper: build an `EncodedPeerId` that matches the BLAKE3 hash of an ML-DSA public key.
    fn encoded_peer_id_for_pub_key(pub_key: &[u8]) -> evmlib::EncodedPeerId {
        let ant_peer_id = peer_id_from_public_key_bytes(pub_key).expect("valid ML-DSA pub key");
        evmlib::EncodedPeerId::new(*ant_peer_id.as_bytes())
    }

    #[tokio::test]
    async fn test_wrong_peer_binding_rejected() {
        use evmlib::{EncodedPeerId, RewardsAddress};
        use saorsa_core::MlDsa65;
        use saorsa_pqc::pqc::MlDsaOperations;

        let verifier = create_test_verifier();
        let xorname = [0xFFu8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Generate a real ML-DSA keypair so pub_key is valid
        let ml_dsa = MlDsa65::new();
        let (public_key, _secret_key) = ml_dsa.generate_keypair().expect("keygen");
        let pub_key_bytes = public_key.as_bytes().to_vec();

        // Create a quote with a real pub_key but attach it to a random peer ID
        // whose identity multihash does NOT match BLAKE3(pub_key)
        let mut quote = make_fake_quote(xorname, SystemTime::now(), rewards_addr);
        quote.pub_key = pub_key_bytes;

        // Use random ed25519 peer IDs — they won't match BLAKE3(pub_key)
        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            peer_quotes.push((EncodedPeerId::new(rand::random()), quote.clone()));
        }

        let proof_bytes = serialize_proof(peer_quotes);
        let result = verifier
            .verify_payment(&xorname, Some(&proof_bytes), VerificationContext::ClientPut)
            .await;

        assert!(result.is_err(), "Should reject wrong peer binding");
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("pub_key does not belong to claimed peer"),
            "Error should mention binding mismatch: {err_msg}"
        );
    }

    // =========================================================================
    // VerificationContext tests — both contexts verify fresh proof admissions.
    // Later neighbour-sync repair has no proof-of-payment and is authorized by
    // closest-7 storage quorum or closest-K paid-list quorum instead.
    // =========================================================================

    /// Content binding is required for every fresh proof context. A receipt for
    /// chunk A cannot admit chunk B as either a direct/fresh store or a fresh
    /// paid-list update.
    #[tokio::test]
    async fn test_fresh_contexts_reject_content_mismatch() {
        let verifier = create_test_verifier();
        let stored_xorname = [0xD2u8; 32];
        let quoted_xorname = [0xD3u8; 32];
        let rewards = RewardsAddress::new([1u8; 20]);

        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            let quote = make_fake_quote(quoted_xorname, SystemTime::now(), rewards);
            peer_quotes.push((evmlib::EncodedPeerId::new(rand::random()), quote));
        }
        let proof_bytes = serialize_proof(peer_quotes);

        for context in [
            VerificationContext::ClientPut,
            VerificationContext::FreshReplication,
            VerificationContext::PaidListAdmission,
        ] {
            let err = verifier
                .verify_payment(&stored_xorname, Some(&proof_bytes), context)
                .await
                .expect_err("content binding must hold in every context");
            assert!(
                format!("{err}").contains("content address mismatch"),
                "{context:?} must reject a receipt for a different address: {err}"
            );
        }
    }

    /// The merkle pay-yourself closeness defence (including its duplicate-
    /// candidate pre-check, which runs without a `P2PNode`) applies to every
    /// proof verification context because every context is a fresh admission.
    #[tokio::test]
    async fn test_fresh_contexts_enforce_merkle_closeness() {
        let verifier = create_test_verifier();

        let (mut merkle_proof, _pool_hash, xorname, _timestamp) = make_valid_merkle_proof();

        // 16 copies of one real candidate: every self-signature is valid, but
        // the candidate PeerIds are duplicates — the closeness pre-check
        // rejects this pool on a client PUT.
        let shared = merkle_proof
            .winner_pool
            .candidate_nodes
            .first()
            .expect("candidates")
            .clone();
        for c in &mut merkle_proof.winner_pool.candidate_nodes {
            *c = shared.clone();
        }
        let tagged =
            crate::payment::proof::serialize_merkle_proof(&merkle_proof).expect("serialize");

        for context in [
            VerificationContext::ClientPut,
            VerificationContext::FreshReplication,
            VerificationContext::PaidListAdmission,
        ] {
            let err = verifier
                .verify_payment(&xorname, Some(&tagged), context)
                .await
                .expect_err("duplicate candidate PeerIds must fail fresh admission closeness");
            assert!(
                format!("{err}").contains("duplicate candidate PeerId"),
                "{context:?} must fail at the closeness pre-check: {err}"
            );
        }
    }

    // =========================================================================
    // Merkle-tagged proof tests
    // =========================================================================

    #[tokio::test]
    async fn test_merkle_tagged_proof_invalid_data_rejected() {
        use crate::ant_protocol::PROOF_TAG_MERKLE;

        let verifier = merkle_test_verifier();
        let xorname = [0xA1u8; 32];

        // Build a merkle-tagged proof with garbage body.
        // The tag byte is correct but the body is not valid msgpack.
        let mut merkle_garbage = Vec::with_capacity(64);
        merkle_garbage.push(PROOF_TAG_MERKLE);
        merkle_garbage.extend_from_slice(&[0xAB; 63]);

        let result = verifier
            .verify_payment(
                &xorname,
                Some(&merkle_garbage),
                VerificationContext::ClientPut,
            )
            .await;

        assert!(
            result.is_err(),
            "Should reject merkle proof with invalid body"
        );
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("deserialize") || err_msg.contains("merkle proof"),
            "Error should mention deserialization failure: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_single_node_tagged_proof_deserialization() {
        use crate::payment::proof::serialize_single_node_proof;
        use evmlib::{EncodedPeerId, RewardsAddress};

        let verifier = create_test_verifier();
        let xorname = [0xA2u8; 32];
        let rewards_addr = RewardsAddress::new([1u8; 20]);

        // Build a valid tagged single-node proof
        let quote = make_fake_quote(xorname, SystemTime::now(), rewards_addr);
        let mut peer_quotes = Vec::new();
        for _ in 0..CLOSE_GROUP_SIZE {
            peer_quotes.push((EncodedPeerId::new(rand::random()), quote.clone()));
        }

        let proof = crate::payment::proof::PaymentProof {
            proof_of_payment: ProofOfPayment {
                peer_quotes: peer_quotes.clone(),
            },
            tx_hashes: vec![],
            commitment_sidecars: vec![],
        };

        let tagged_bytes = serialize_single_node_proof(&proof).expect("serialize tagged proof");

        // detect_proof_type should identify it as SingleNode
        assert_eq!(
            crate::payment::proof::detect_proof_type(&tagged_bytes),
            Some(crate::payment::proof::ProofType::SingleNode)
        );

        // verify_payment should process it through the single-node path.
        // It will fail at quote validation (fake pub_key), but we verify
        // it passes the deserialization stage by checking the error type.
        let result = verifier
            .verify_payment(
                &xorname,
                Some(&tagged_bytes),
                VerificationContext::ClientPut,
            )
            .await;

        assert!(result.is_err(), "Should fail at quote validation stage");
        let err_msg = format!("{}", result.expect_err("should fail"));
        // It should NOT be a deserialization error — it should get further
        assert!(
            !err_msg.contains("deserialize"),
            "Should pass deserialization but fail later: {err_msg}"
        );
    }

    #[test]
    fn test_pool_cache_insert_and_lookup() {
        use evmlib::merkle_batch_payment::PoolHash;

        // Verify the pool_cache field exists and works correctly.
        // Insert a pool hash, then verify it's present on lookup.
        let verifier = create_test_verifier();

        let pool_hash: PoolHash = [0xBBu8; 32];
        let payment_info = evmlib::merkle_payments::OnChainPaymentInfo {
            depth: 4,
            merkle_payment_timestamp: 1_700_000_000,
            paid_node_addresses: vec![],
        };

        // Insert into pool cache
        {
            let mut cache = verifier.pool_cache.lock();
            cache.put(pool_hash, payment_info);
        }

        // First lookup — should find it
        {
            let found = verifier.pool_cache.lock().get(&pool_hash).cloned();
            assert!(found.is_some(), "Pool hash should be in cache after insert");
            let info = found.expect("cached info");
            assert_eq!(info.depth, 4);
            assert_eq!(info.merkle_payment_timestamp, 1_700_000_000);
        }

        // Second lookup — same result (no double-query needed)
        {
            let found = verifier.pool_cache.lock().get(&pool_hash).cloned();
            assert!(
                found.is_some(),
                "Pool hash should still be in cache on second lookup"
            );
        }

        // Different pool hash — should NOT be found
        let other_hash: PoolHash = [0xCCu8; 32];
        {
            let found = verifier.pool_cache.lock().get(&other_hash).cloned();
            assert!(found.is_none(), "Unknown pool hash should not be in cache");
        }
    }

    #[tokio::test]
    async fn closeness_pass_cache_short_circuits_second_call() {
        // When a pool_hash is in the closeness_pass_cache, the outer
        // verify_merkle_candidate_closeness must return Ok(()) without
        // running the inner lookup — even if no P2PNode is attached.
        // That second half (no-p2p → would normally fail-closed in release)
        // is the proof the cache short-circuit ran first.
        let verifier = create_test_verifier();
        let pool_hash = [0xAAu8; 32];
        verifier.closeness_pass_cache.lock().put(pool_hash, ());

        // Construct a dummy pool — contents don't matter because the cache
        // hit means we never look at them.
        let pool = MerklePaymentCandidatePool {
            midpoint_proof: fake_midpoint_proof(),
            candidate_nodes: make_candidate_nodes(1_700_000_000),
        };

        let result = verifier
            .verify_merkle_candidate_closeness(&pool, pool_hash)
            .await;
        assert!(
            result.is_ok(),
            "cached pool hash must bypass the inner check and return Ok(()), got: {result:?}"
        );
    }

    #[tokio::test]
    async fn closeness_single_flight_concurrent_readers_share_one_verification() {
        // Two concurrent callers for the same pool_hash should produce the
        // same outcome, and the cache should end up populated exactly once.
        // We use the test-utils fail-open path to short-circuit the inner
        // DHT lookup; the purpose of this test is the single-flight
        // plumbing, not the lookup itself.
        let verifier = Arc::new(create_test_verifier());
        let pool_hash = [0x77u8; 32];
        let pool = MerklePaymentCandidatePool {
            midpoint_proof: fake_midpoint_proof(),
            candidate_nodes: make_candidate_nodes(1_700_000_000),
        };

        let v1 = Arc::clone(&verifier);
        let p1 = pool.clone();
        let v2 = Arc::clone(&verifier);
        let p2 = pool.clone();

        let (r1, r2) = tokio::join!(
            async move { v1.verify_merkle_candidate_closeness(&p1, pool_hash).await },
            async move { v2.verify_merkle_candidate_closeness(&p2, pool_hash).await },
        );

        assert_eq!(r1.is_ok(), r2.is_ok(), "concurrent callers must agree");
        assert!(
            r1.is_ok(),
            "both callers must succeed on the test-utils path"
        );
        assert!(
            verifier
                .closeness_pass_cache
                .lock()
                .get(&pool_hash)
                .is_some(),
            "success path must populate the pass cache"
        );
        assert!(
            verifier.inflight_closeness.lock().get(&pool_hash).is_none(),
            "inflight slot must be cleared after the leader finishes"
        );
    }

    #[tokio::test]
    async fn closeness_waiter_reads_leaders_published_failure() {
        // Prove the waiter path actually surfaces a failure published by a
        // concurrent leader, without running its own inner check. Insert a
        // slot, spawn a waiter (which will park on notified_owned), then
        // publish failure + notify from the outside — simulating what the
        // leader's `publish` + drop-guard pair does.
        let verifier = Arc::new(create_test_verifier());
        let pool_hash = [0x55u8; 32];
        let slot = Arc::new(ClosenessSlot::new());
        verifier
            .inflight_closeness
            .lock()
            .put(pool_hash, Arc::clone(&slot));

        let pool = MerklePaymentCandidatePool {
            midpoint_proof: fake_midpoint_proof(),
            candidate_nodes: make_candidate_nodes(1_700_000_000),
        };

        let verifier_c = Arc::clone(&verifier);
        let pool_c = pool.clone();
        let waiter = tokio::spawn(async move {
            verifier_c
                .verify_merkle_candidate_closeness(&pool_c, pool_hash)
                .await
        });

        // Yield so the waiter can run up to its `notified_owned().await`.
        // A few yields cover both single-threaded and multi-threaded tokio
        // runtimes regardless of scheduling.
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }

        // Simulate the leader's `publish` + drop-guard: publish the result,
        // clear the slot, wake waiters.
        slot.result
            .set(Err("forged pool: not close enough".to_string()))
            .expect("set once");
        verifier.inflight_closeness.lock().pop(&pool_hash);
        slot.notify.notify_waiters();

        let result = waiter.await.expect("task panicked");
        let err = result.expect_err("waiter must return the leader's published failure");
        assert!(
            err.to_string().contains("forged pool"),
            "waiter must surface the leader's error message, got: {err}"
        );
    }

    #[tokio::test]
    async fn closeness_rejects_pool_with_duplicate_candidate_pub_keys() {
        // An attacker who submits 16 copies of the same real peer's pub_key
        // would otherwise satisfy the closeness threshold trivially:
        // that one peer's membership in the DHT-returned set would count
        // 16 times. The dedupe check in verify_merkle_candidate_closeness_inner
        // must reject the pool BEFORE the network lookup runs (so this test
        // works even with no P2PNode attached).
        let verifier = create_test_verifier();
        let pool_hash = [0xDDu8; 32];

        // Build a normal pool, then overwrite every candidate's pub_key
        // with a single shared key so all 16 derive to the same PeerId.
        let mut candidates = make_candidate_nodes(1_700_000_000);
        let shared_pub_key = candidates
            .first()
            .expect("make_candidate_nodes returns CANDIDATES_PER_POOL entries")
            .pub_key
            .clone();
        for c in &mut candidates {
            c.pub_key = shared_pub_key.clone();
        }
        let pool = MerklePaymentCandidatePool {
            midpoint_proof: fake_midpoint_proof(),
            candidate_nodes: candidates,
        };

        let result = verifier
            .verify_merkle_candidate_closeness(&pool, pool_hash)
            .await;
        let err = result.expect_err("duplicate candidate PeerIds must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate candidate PeerId"),
            "rejection must be the duplicate-PeerId branch, got: {msg}"
        );
    }

    /// Build a deterministic but otherwise-unused `MidpointProof` so unit
    /// tests can construct a `MerklePaymentCandidatePool` without spinning
    /// up a real merkle tree. The closeness path only calls `.address()`
    /// on it, which is a pure BLAKE3 of the branch's leaf/root/timestamp —
    /// the values don't need to be tree-valid for these tests.
    fn fake_midpoint_proof() -> evmlib::merkle_payments::MidpointProof {
        // Build a minimal tree of two leaves so we get a real branch.
        let leaves = vec![xor_name::XorName([1u8; 32]), xor_name::XorName([2u8; 32])];
        let tree = evmlib::merkle_payments::MerkleTree::from_xornames(leaves).expect("tree");
        let candidates = tree.reward_candidates(1_700_000_000).expect("candidates");
        candidates.first().expect("at least one").clone()
    }

    // =========================================================================
    // Merkle verification unit tests
    // =========================================================================

    /// Helper: build 16 validly-signed ML-DSA-65 candidate nodes.
    fn make_candidate_nodes(
        timestamp: u64,
    ) -> [evmlib::merkle_payments::MerklePaymentCandidateNode;
           evmlib::merkle_payments::CANDIDATES_PER_POOL] {
        use evmlib::merkle_payments::{MerklePaymentCandidateNode, CANDIDATES_PER_POOL};
        use saorsa_core::MlDsa65;
        use saorsa_pqc::pqc::types::MlDsaSecretKey;
        use saorsa_pqc::pqc::MlDsaOperations;

        std::array::from_fn::<_, CANDIDATES_PER_POOL, _>(|i| {
            let ml_dsa = MlDsa65::new();
            let (pub_key, secret_key) = ml_dsa.generate_keypair().expect("keygen");
            // Baseline candidate: `(committed_key_count = 0, commitment_pin =
            // None)` below, so the price must be `calculate_price(0)` to satisfy
            // the ADR-0004 binding rule. A placeholder price is off-curve and is
            // rejected before the check each test actually exercises.
            let price = crate::payment::pricing::calculate_price(0);
            #[allow(clippy::cast_possible_truncation)]
            let reward_address = RewardsAddress::new([i as u8; 20]);
            let msg = MerklePaymentCandidateNode::bytes_to_sign(
                &price,
                &reward_address,
                timestamp,
                0,
                &None,
            );
            let sk = MlDsaSecretKey::from_bytes(secret_key.as_bytes()).expect("sk");
            let signature = ml_dsa.sign(&sk, &msg).expect("sign").as_bytes().to_vec();

            MerklePaymentCandidateNode {
                pub_key: pub_key.as_bytes().to_vec(),
                price,
                reward_address,
                merkle_payment_timestamp: timestamp,
                committed_key_count: 0,
                commitment_pin: None,
                signature,
            }
        })
    }

    /// Helper: build a valid `MerklePaymentProof` with real ML-DSA-65
    /// signatures. Returns the raw proof, pool hash, xorname, and timestamp.
    fn make_valid_merkle_proof() -> (
        evmlib::merkle_payments::MerklePaymentProof,
        evmlib::merkle_batch_payment::PoolHash,
        [u8; 32],
        u64,
    ) {
        use evmlib::merkle_payments::{MerklePaymentCandidatePool, MerklePaymentProof, MerkleTree};

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs();

        let addresses: Vec<xor_name::XorName> = (0..4u8)
            .map(|i| xor_name::XorName::from_content(&[i]))
            .collect();
        let tree = MerkleTree::from_xornames(addresses.clone()).expect("tree");

        let candidate_nodes = make_candidate_nodes(timestamp);

        let reward_candidates = tree
            .reward_candidates(timestamp)
            .expect("reward candidates");
        let midpoint_proof = reward_candidates
            .first()
            .expect("at least one candidate")
            .clone();

        let pool = MerklePaymentCandidatePool {
            midpoint_proof,
            candidate_nodes,
        };

        let first_address = *addresses.first().expect("first address");
        let address_proof = tree
            .generate_address_proof(0, first_address)
            .expect("proof");

        let merkle_proof = MerklePaymentProof::new(first_address, address_proof, pool);
        let pool_hash = merkle_proof.winner_pool_hash();
        let xorname = first_address.0;

        (merkle_proof, pool_hash, xorname, timestamp)
    }

    /// ADR-0004 Amendment 2: only the PAID (settlement-verified) quote's pin is
    /// nominated for a deterministic first audit; the unpaid bundle quotes are
    /// cross-checked but never enqueue audits.
    #[tokio::test]
    async fn adr0004_first_audit_nominates_only_paid_single_node_quote() {
        use evmlib::{EncodedPeerId, RewardsAddress};

        let verifier = create_test_verifier();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        verifier.attach_monetized_pin_sender(tx);

        let ids: Vec<[u8; 32]> = (1..=3u8).map(|b| [b; 32]).collect();
        let payment = ProofOfPayment {
            peer_quotes: ids
                .iter()
                .enumerate()
                .map(|(i, id)| {
                    let pin_byte = u8::try_from(i).expect("small bundle") + 1;
                    let mut quote = make_fake_quote(
                        [0xD0; 32],
                        SystemTime::now(),
                        RewardsAddress::new([pin_byte; 20]),
                    );
                    quote.commitment_pin = Some([pin_byte; 32]);
                    quote.committed_key_count = 100;
                    (EncodedPeerId::new(*id), quote)
                })
                .collect(),
        };

        // The middle quote is the candidate whose on-chain settlement verified.
        let paid = ids.get(1).copied().expect("paid id");
        verifier.cross_check_quotes(&payment, &[], Some(paid)).await;

        let event = rx.try_recv().expect("the paid quote must be nominated");
        assert_eq!(event.peer, PeerId::from_bytes(paid));
        assert_eq!(event.pin, [2u8; 32]);
        assert!(
            rx.try_recv().is_err(),
            "unpaid bundle quotes must not be nominated for first audits"
        );
    }

    /// ADR-0004 Amendment 2: with no verified paid candidate, nothing is
    /// nominated (defensive: the caller never reaches the cross-check on a
    /// failed verification, but the emission itself must also fail closed).
    #[tokio::test]
    async fn adr0004_first_audit_nominates_nothing_without_paid_peer() {
        use evmlib::{EncodedPeerId, RewardsAddress};

        let verifier = create_test_verifier();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        verifier.attach_monetized_pin_sender(tx);

        let mut quote =
            make_fake_quote([0xD1; 32], SystemTime::now(), RewardsAddress::new([1; 20]));
        quote.commitment_pin = Some([1u8; 32]);
        let payment = ProofOfPayment {
            peer_quotes: vec![(EncodedPeerId::new([1u8; 32]), quote)],
        };

        verifier.cross_check_quotes(&payment, &[], None).await;
        assert!(rx.try_recv().is_err(), "no paid peer, no nomination");
    }

    /// ADR-0004 Amendment 2, merkle path: only the candidates at the
    /// contract-verified PAID indices are nominated; the rest of the pool
    /// merely established the median and must not enqueue audits.
    #[tokio::test]
    async fn adr0004_first_audit_nominates_only_paid_merkle_candidates() {
        use evmlib::merkle_payments::{MerklePaymentCandidatePool, MerkleTree};

        let verifier = create_test_verifier();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        verifier.attach_monetized_pin_sender(tx);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs();
        let mut candidate_nodes = make_candidate_nodes(timestamp);
        for (i, candidate) in candidate_nodes.iter_mut().enumerate() {
            candidate.commitment_pin = Some([u8::try_from(i & 0xFF).expect("byte"); 32]);
            candidate.committed_key_count = 50;
        }
        let addresses: Vec<xor_name::XorName> = (0..4u8)
            .map(|i| xor_name::XorName::from_content(&[i]))
            .collect();
        let tree = MerkleTree::from_xornames(addresses).expect("tree");
        let midpoint_proof = tree
            .reward_candidates(timestamp)
            .expect("reward candidates")
            .first()
            .expect("at least one candidate")
            .clone();
        let pool = MerklePaymentCandidatePool {
            midpoint_proof,
            candidate_nodes,
        };

        let paid_indices: std::collections::HashSet<usize> = [1usize, 3].into_iter().collect();
        verifier
            .cross_check_merkle_candidates(&pool, &[], &paid_indices)
            .await;

        let mut nominated = Vec::new();
        while let Ok(event) = rx.try_recv() {
            nominated.push(event);
        }
        assert_eq!(
            nominated.len(),
            2,
            "only the PAID candidates are nominated, not the whole pool"
        );
        for (event, idx) in nominated.iter().zip([1usize, 3]) {
            let candidate = pool.candidate_nodes.get(idx).expect("paid candidate");
            assert_eq!(
                event.peer,
                PeerId::from_bytes(*blake3::hash(&candidate.pub_key).as_bytes())
            );
            assert_eq!(event.pin, [u8::try_from(idx).expect("byte"); 32]);
        }
    }

    /// Helper: build a minimal valid `MerklePaymentProof` with real ML-DSA-65
    /// signatures. Returns `(xorname, serialized_tagged_proof, pool_hash, timestamp)`.
    /// Verifier for merkle admission tests, pinned to the **enforcing** side of
    /// the ADR-0008 parity boundary.
    ///
    /// Merkle receipts must be stamped within one week of now or they are
    /// expired, so these tests necessarily build near-`now` timestamps. Left on
    /// the production boundary they would sit in the legacy 1x window today and
    /// silently switch to the 3x rule when the wall clock crossed that date,
    /// changing what each assertion means. Pinning to `0` means "every receipt
    /// is post-boundary", which is the rule the release ships with.
    fn merkle_test_verifier() -> PaymentVerifier {
        let verifier = create_test_verifier();
        verifier.set_merkle_parity_from_for_tests(0);
        verifier
    }

    /// Per-node amount a depth-2 pool of baseline-priced candidates must settle
    /// under parity: `median * 2^2 * 3 / 2`, i.e. six times the candidate price.
    ///
    /// Derived from the curve rather than hardcoded: the candidates are priced
    /// at `calculate_price(0)` so they satisfy the ADR-0004 binding rule, and a
    /// literal would silently stop matching the formula if the curve moves.
    fn merkle_parity_per_node_depth2() -> Amount {
        crate::payment::pricing::calculate_price(0) * Amount::from(6u64)
    }

    /// The same pool's historic pre-parity amount: `median * 2^2 / 2`, i.e.
    /// twice the candidate price.
    fn merkle_legacy_per_node_depth2() -> Amount {
        crate::payment::pricing::calculate_price(0) * Amount::from(2u64)
    }

    fn make_valid_merkle_proof_bytes() -> (
        [u8; 32],
        Vec<u8>,
        evmlib::merkle_batch_payment::PoolHash,
        u64,
    ) {
        let (merkle_proof, pool_hash, xorname, timestamp) = make_valid_merkle_proof();
        let tagged = crate::payment::proof::serialize_merkle_proof(&merkle_proof)
            .expect("serialize merkle proof");
        (xorname, tagged, pool_hash, timestamp)
    }

    #[tokio::test]
    async fn test_merkle_address_mismatch_rejected() {
        let verifier = merkle_test_verifier();
        let (_correct_xorname, tagged_proof, _pool_hash, _ts) = make_valid_merkle_proof_bytes();

        // Use a DIFFERENT xorname than what the proof was built for
        let wrong_xorname = [0xFFu8; 32];

        let result = verifier
            .verify_payment(
                &wrong_xorname,
                Some(&tagged_proof),
                VerificationContext::ClientPut,
            )
            .await;

        assert!(
            result.is_err(),
            "Should reject merkle proof address mismatch"
        );
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("address mismatch") || err_msg.contains("Merkle proof address"),
            "Error should mention address mismatch: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_merkle_malformed_body_rejected() {
        let verifier = merkle_test_verifier();
        let xorname = [0xA3u8; 32];

        // Valid merkle tag but truncated/corrupted msgpack body
        let mut bad_proof = vec![crate::ant_protocol::PROOF_TAG_MERKLE];
        bad_proof.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        bad_proof.extend_from_slice(&[0x00; 10]);
        // pad to minimum size
        while bad_proof.len() < MIN_PAYMENT_PROOF_SIZE_BYTES {
            bad_proof.push(0x00);
        }

        let result = verifier
            .verify_payment(&xorname, Some(&bad_proof), VerificationContext::ClientPut)
            .await;

        assert!(result.is_err(), "Should reject malformed merkle body");
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("deserialize") || err_msg.contains("Failed"),
            "Error should mention deserialization: {err_msg}"
        );
    }

    #[test]
    fn test_merkle_proof_serialized_size_within_limits() {
        let (_xorname, tagged_proof, _pool_hash, _ts) = make_valid_merkle_proof_bytes();

        // 16 ML-DSA-65 candidates (~1952 pub key + ~3309 sig each) ≈ 84 KB + tree data
        assert!(
            tagged_proof.len() >= MIN_PAYMENT_PROOF_SIZE_BYTES,
            "Merkle proof ({} bytes) should be >= min {} bytes",
            tagged_proof.len(),
            MIN_PAYMENT_PROOF_SIZE_BYTES
        );
        assert!(
            tagged_proof.len() <= MAX_PAYMENT_PROOF_SIZE_BYTES,
            "Merkle proof ({} bytes) should be <= max {} bytes",
            tagged_proof.len(),
            MAX_PAYMENT_PROOF_SIZE_BYTES
        );
    }

    #[test]
    fn test_merkle_proof_tag_is_correct() {
        let (_xorname, tagged_proof, _pool_hash, _ts) = make_valid_merkle_proof_bytes();

        assert_eq!(
            tagged_proof.first().copied(),
            Some(crate::ant_protocol::PROOF_TAG_MERKLE),
            "First byte must be the merkle tag"
        );
        assert_eq!(
            crate::payment::proof::detect_proof_type(&tagged_proof),
            Some(crate::payment::proof::ProofType::Merkle)
        );
    }

    #[test]
    fn test_pool_cache_eviction() {
        use evmlib::merkle_batch_payment::PoolHash;

        let config = PaymentVerifierConfig {
            evm: EvmVerifierConfig::default(),
            cache_capacity: 100,
            close_group_size: CLOSE_GROUP_SIZE,
            local_rewards_address: RewardsAddress::new([1u8; 20]),
            price_floor: PriceFloorConfig::default(),
        };
        let verifier = PaymentVerifier::new(config);

        // Fill the pool cache to capacity (DEFAULT_POOL_CACHE_CAPACITY = 1000)
        for i in 0..DEFAULT_POOL_CACHE_CAPACITY {
            let mut hash: PoolHash = [0u8; 32];
            // Write index bytes into the hash
            let idx_bytes = i.to_le_bytes();
            for (j, b) in idx_bytes.iter().enumerate() {
                if j < 32 {
                    hash[j] = *b;
                }
            }
            let info = evmlib::merkle_payments::OnChainPaymentInfo {
                depth: 4,
                merkle_payment_timestamp: 1_700_000_000,
                paid_node_addresses: vec![],
            };
            verifier.pool_cache.lock().put(hash, info);
        }

        assert_eq!(
            verifier.pool_cache.lock().len(),
            DEFAULT_POOL_CACHE_CAPACITY
        );

        // Insert one more — should evict the oldest
        let overflow_hash: PoolHash = [0xFFu8; 32];
        let info = evmlib::merkle_payments::OnChainPaymentInfo {
            depth: 8,
            merkle_payment_timestamp: 1_800_000_000,
            paid_node_addresses: vec![],
        };
        verifier.pool_cache.lock().put(overflow_hash, info);

        // Size should still be at capacity (not capacity + 1)
        assert_eq!(
            verifier.pool_cache.lock().len(),
            DEFAULT_POOL_CACHE_CAPACITY
        );

        // The new entry should be present
        let found = verifier.pool_cache.lock().get(&overflow_hash).cloned();
        assert!(
            found.is_some(),
            "Newly inserted pool hash should be present"
        );
        assert_eq!(found.expect("info").depth, 8);
    }

    #[test]
    fn test_pool_cache_concurrent_access() {
        use evmlib::merkle_batch_payment::PoolHash;
        use std::sync::Arc;

        let verifier = Arc::new(create_test_verifier());

        let mut handles = Vec::new();
        for i in 0..20u8 {
            let v = verifier.clone();
            handles.push(std::thread::spawn(move || {
                let hash: PoolHash = [i; 32];
                let info = evmlib::merkle_payments::OnChainPaymentInfo {
                    depth: i,
                    merkle_payment_timestamp: u64::from(i) * 1000,
                    paid_node_addresses: vec![],
                };
                v.pool_cache.lock().put(hash, info);

                // Read back
                let found = v.pool_cache.lock().get(&hash).cloned();
                assert!(found.is_some(), "Entry {i} should be readable after insert");
            }));
        }

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        // All 20 entries should be present (well under 1000 capacity)
        assert_eq!(verifier.pool_cache.lock().len(), 20);
    }

    #[tokio::test]
    async fn test_merkle_tampered_candidate_signature_rejected() {
        let verifier = merkle_test_verifier();

        let (mut merkle_proof, _pool_hash, xorname, timestamp) = make_valid_merkle_proof();

        // Tamper the first candidate's signature
        if let Some(byte) = merkle_proof
            .winner_pool
            .candidate_nodes
            .first_mut()
            .and_then(|c| c.signature.first_mut())
        {
            *byte ^= 0xFF;
        }

        // Recompute pool hash after tampering (signature change alters the hash)
        let tampered_pool_hash = merkle_proof.winner_pool_hash();

        // Pre-populate pool cache so we skip the on-chain query
        {
            let info = evmlib::merkle_payments::OnChainPaymentInfo {
                depth: 4,
                merkle_payment_timestamp: timestamp,
                paid_node_addresses: vec![],
            };
            verifier.pool_cache.lock().put(tampered_pool_hash, info);
        }

        let tagged =
            crate::payment::proof::serialize_merkle_proof(&merkle_proof).expect("serialize");

        let result = verifier
            .verify_payment(&xorname, Some(&tagged), VerificationContext::ClientPut)
            .await;

        assert!(
            result.is_err(),
            "Should reject merkle proof with tampered candidate signature"
        );
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("Invalid ML-DSA-65 signature"),
            "Error should mention invalid signature: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_merkle_timestamp_mismatch_rejected() {
        let verifier = merkle_test_verifier();

        let (xorname, tagged, pool_hash, timestamp) = make_valid_merkle_proof_bytes();

        // Pre-populate pool cache with a DIFFERENT timestamp than the candidates
        {
            let mismatched_ts = timestamp + 9999;
            let info = evmlib::merkle_payments::OnChainPaymentInfo {
                depth: 4,
                merkle_payment_timestamp: mismatched_ts,
                paid_node_addresses: vec![],
            };
            verifier.pool_cache.lock().put(pool_hash, info);
        }

        let result = verifier
            .verify_payment(&xorname, Some(&tagged), VerificationContext::ClientPut)
            .await;

        assert!(
            result.is_err(),
            "Should reject merkle proof with timestamp mismatch"
        );
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("timestamp mismatch"),
            "Error should mention timestamp mismatch: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_merkle_paid_node_index_out_of_bounds_rejected() {
        let verifier = merkle_test_verifier();
        let (xorname, tagged_proof, pool_hash, ts) = make_valid_merkle_proof_bytes();

        // The test tree has 4 addresses → depth 2. We must match the tree depth
        // so verify_merkle_proof passes the depth check, then the paid node
        // index out-of-bounds check fires.
        {
            let info = evmlib::merkle_payments::OnChainPaymentInfo {
                depth: 2,
                merkle_payment_timestamp: ts,
                paid_node_addresses: vec![
                    // First paid node: valid (matches candidate 0, amount clears
                    // the parity formula so the test reaches the index check)
                    (
                        RewardsAddress::new([0u8; 20]),
                        0,
                        merkle_parity_per_node_depth2(),
                    ),
                    // Second paid node: index 999 is way beyond CANDIDATES_PER_POOL (16)
                    (
                        RewardsAddress::new([1u8; 20]),
                        999,
                        merkle_parity_per_node_depth2(),
                    ),
                ],
            };
            verifier.pool_cache.lock().put(pool_hash, info);
        }

        let result = verifier
            .verify_payment(
                &xorname,
                Some(&tagged_proof),
                VerificationContext::ClientPut,
            )
            .await;

        assert!(
            result.is_err(),
            "Should reject paid node index out of bounds"
        );
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("out of bounds"),
            "Error should mention out of bounds: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_merkle_paid_node_address_mismatch_rejected() {
        let verifier = merkle_test_verifier();
        let (xorname, tagged_proof, pool_hash, ts) = make_valid_merkle_proof_bytes();

        // Tree has depth 2, so provide 2 paid node entries.
        // Both use valid indices but the second has a wrong reward address.
        {
            let info = evmlib::merkle_payments::OnChainPaymentInfo {
                depth: 2,
                merkle_payment_timestamp: ts,
                paid_node_addresses: vec![
                    // Index 0 with matching address [0x00; 20], paid enough to
                    // clear the parity formula so the test reaches index 1
                    (
                        RewardsAddress::new([0u8; 20]),
                        0,
                        merkle_parity_per_node_depth2(),
                    ),
                    // Index 1 with WRONG address — candidate 1's address is [0x01; 20]
                    (
                        RewardsAddress::new([0xFF; 20]),
                        1,
                        merkle_parity_per_node_depth2(),
                    ),
                ],
            };
            verifier.pool_cache.lock().put(pool_hash, info);
        }

        let result = verifier
            .verify_payment(
                &xorname,
                Some(&tagged_proof),
                VerificationContext::ClientPut,
            )
            .await;

        assert!(result.is_err(), "Should reject paid node address mismatch");
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("address mismatch"),
            "Error should mention address mismatch: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_merkle_wrong_depth_rejected() {
        let verifier = merkle_test_verifier();
        let (xorname, tagged_proof, pool_hash, ts) = make_valid_merkle_proof_bytes();

        // Pre-populate pool cache with depth=3 but only 1 paid node address
        // (depth must equal paid_node_addresses.len())
        {
            let info = evmlib::merkle_payments::OnChainPaymentInfo {
                depth: 3,
                merkle_payment_timestamp: ts,
                paid_node_addresses: vec![(
                    RewardsAddress::new([0u8; 20]),
                    0,
                    Amount::from(1024u64),
                )],
            };
            verifier.pool_cache.lock().put(pool_hash, info);
        }

        let result = verifier
            .verify_payment(
                &xorname,
                Some(&tagged_proof),
                VerificationContext::ClientPut,
            )
            .await;

        assert!(
            result.is_err(),
            "Should reject mismatched depth vs paid node count"
        );
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("Wrong number of paid nodes")
                || err_msg.contains("verification failed"),
            "Error should mention depth/count mismatch: {err_msg}"
        );
    }

    #[tokio::test]
    async fn test_merkle_underpayment_rejected() {
        let verifier = merkle_test_verifier();
        let (xorname, tagged_proof, pool_hash, ts) = make_valid_merkle_proof_bytes();

        // Tree depth=2, so 2 paid nodes required. Candidates all quote price=1024.
        // Expected per-node: median(1024) * 2^2 / 2 = 2048.
        // Pay only 1 wei per node — far below the expected amount.
        {
            let info = evmlib::merkle_payments::OnChainPaymentInfo {
                depth: 2,
                merkle_payment_timestamp: ts,
                paid_node_addresses: vec![
                    (RewardsAddress::new([0u8; 20]), 0, Amount::from(1u64)),
                    (RewardsAddress::new([1u8; 20]), 1, Amount::from(1u64)),
                ],
            };
            verifier.pool_cache.lock().put(pool_hash, info);
        }

        let result = verifier
            .verify_payment(
                &xorname,
                Some(&tagged_proof),
                VerificationContext::ClientPut,
            )
            .await;

        assert!(
            result.is_err(),
            "Should reject merkle payment where paid amount < expected per-node amount"
        );
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(
            err_msg.contains("Underpayment"),
            "Error should mention underpayment: {err_msg}"
        );
    }

    /// A batch settled at the historic 1x is refused once its receipt is stamped
    /// at or after the parity boundary. This is the fix being active by default:
    /// no flag, no shadow mode.
    #[tokio::test]
    async fn merkle_legacy_1x_settlement_rejected_after_the_parity_boundary() {
        let verifier = merkle_test_verifier(); // boundary pinned at 0 = always enforcing
        let (xorname, tagged_proof, pool_hash, ts) = make_valid_merkle_proof_bytes();

        {
            let info = evmlib::merkle_payments::OnChainPaymentInfo {
                depth: 2,
                merkle_payment_timestamp: ts,
                paid_node_addresses: vec![
                    (
                        RewardsAddress::new([0u8; 20]),
                        0,
                        merkle_legacy_per_node_depth2(),
                    ),
                    (
                        RewardsAddress::new([1u8; 20]),
                        1,
                        merkle_legacy_per_node_depth2(),
                    ),
                ],
            };
            verifier.pool_cache.lock().put(pool_hash, info);
        }

        let err_msg = format!(
            "{}",
            verifier
                .verify_payment(
                    &xorname,
                    Some(&tagged_proof),
                    VerificationContext::ClientPut,
                )
                .await
                .expect_err("a 1x settlement must be refused past the boundary")
        );
        assert!(
            err_msg.contains("Underpayment") && err_msg.contains("3x required"),
            "Error should name the required multiplier: {err_msg}"
        );
    }

    /// A receipt stamped BEFORE the boundary keeps its 1x price. The money was
    /// already spent under the old rule and cannot be refunded, so refusing it
    /// would destroy value. This is the compatibility half of the cutover.
    #[tokio::test]
    async fn merkle_legacy_1x_settlement_accepted_before_the_parity_boundary() {
        let verifier = create_test_verifier();
        let (xorname, tagged_proof, pool_hash, ts) = make_valid_merkle_proof_bytes();
        // Boundary just after this receipt's stamp: the receipt is legacy.
        verifier.set_merkle_parity_from_for_tests(ts + 1);

        {
            let info = evmlib::merkle_payments::OnChainPaymentInfo {
                depth: 2,
                merkle_payment_timestamp: ts,
                paid_node_addresses: vec![
                    (
                        RewardsAddress::new([0u8; 20]),
                        0,
                        merkle_legacy_per_node_depth2(),
                    ),
                    (
                        RewardsAddress::new([1u8; 20]),
                        1,
                        merkle_legacy_per_node_depth2(),
                    ),
                ],
            };
            verifier.pool_cache.lock().put(pool_hash, info);
        }

        let result = verifier
            .verify_payment(
                &xorname,
                Some(&tagged_proof),
                VerificationContext::ClientPut,
            )
            .await;
        assert!(
            result.is_ok(),
            "a receipt stamped before the boundary keeps the 1x rule: {result:?}"
        );
    }

    /// An upgraded client's 3x settlement is accepted on both sides of the
    /// boundary. This is what makes the client-first rollout work: the client
    /// pays 3x from the day it ships, and neither a node that predates the
    /// boundary nor one enforcing past it has any reason to refuse.
    #[tokio::test]
    async fn merkle_parity_settlement_accepted_in_both_regimes() {
        for parity_from in [0u64, u64::MAX] {
            let verifier = create_test_verifier();
            verifier.set_merkle_parity_from_for_tests(parity_from);
            let (xorname, tagged_proof, pool_hash, ts) = make_valid_merkle_proof_bytes();

            {
                let info = evmlib::merkle_payments::OnChainPaymentInfo {
                    depth: 2,
                    merkle_payment_timestamp: ts,
                    paid_node_addresses: vec![
                        (
                            RewardsAddress::new([0u8; 20]),
                            0,
                            merkle_parity_per_node_depth2(),
                        ),
                        (
                            RewardsAddress::new([1u8; 20]),
                            1,
                            merkle_parity_per_node_depth2(),
                        ),
                    ],
                };
                verifier.pool_cache.lock().put(pool_hash, info);
            }

            let result = verifier
                .verify_payment(
                    &xorname,
                    Some(&tagged_proof),
                    VerificationContext::ClientPut,
                )
                .await;
            assert!(
                result.is_ok(),
                "3x must be accepted with boundary {parity_from}: {result:?}"
            );
        }
    }

    /// One chunk's payment proof as the verifier receives it: the stored
    /// address and the tagged, serialized proof bytes.
    type TaggedProof = ([u8; 32], Vec<u8>);

    /// Build valid proofs for several addresses of ONE tree, all resolving to
    /// the same winner pool hash — the shape a real batch upload has, and the
    /// case the ADR-0008 parity telemetry must collapse to a single sample.
    /// Returns `(Vec<(xorname, tagged_proof)>, pool_hash, timestamp)`.
    fn make_valid_merkle_proofs_for_one_pool(
        indices: &[usize],
    ) -> (
        Vec<TaggedProof>,
        evmlib::merkle_batch_payment::PoolHash,
        u64,
    ) {
        use evmlib::merkle_payments::{MerklePaymentCandidatePool, MerklePaymentProof, MerkleTree};

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs();

        let addresses: Vec<xor_name::XorName> = (0..4u8)
            .map(|i| xor_name::XorName::from_content(&[i]))
            .collect();
        let tree = MerkleTree::from_xornames(addresses.clone()).expect("tree");

        let midpoint_proof = tree
            .reward_candidates(timestamp)
            .expect("reward candidates")
            .first()
            .expect("at least one candidate")
            .clone();
        let pool = MerklePaymentCandidatePool {
            midpoint_proof,
            candidate_nodes: make_candidate_nodes(timestamp),
        };

        let mut proofs = Vec::with_capacity(indices.len());
        let mut pool_hash = None;
        for &index in indices {
            let address = *addresses.get(index).expect("address index within the tree");
            let address_proof = tree
                .generate_address_proof(index, address)
                .expect("address proof");
            let proof = MerklePaymentProof::new(address, address_proof, pool.clone());
            let hash = proof.winner_pool_hash();
            match pool_hash {
                None => pool_hash = Some(hash),
                Some(first) => assert_eq!(
                    hash, first,
                    "every address in one tree must share one winner pool"
                ),
            }
            let tagged =
                crate::payment::proof::serialize_merkle_proof(&proof).expect("serialize proof");
            proofs.push((address.0, tagged));
        }

        (proofs, pool_hash.expect("at least one proof"), timestamp)
    }

    /// The depth-2 test pool's on-chain record, settled at 3x parity so the
    /// proof is admitted and the telemetry call site is actually reached.
    fn parity_settled_pool_info(ts: u64) -> evmlib::merkle_payments::OnChainPaymentInfo {
        evmlib::merkle_payments::OnChainPaymentInfo {
            depth: 2,
            merkle_payment_timestamp: ts,
            paid_node_addresses: vec![
                (
                    RewardsAddress::new([0u8; 20]),
                    0,
                    merkle_parity_per_node_depth2(),
                ),
                (
                    RewardsAddress::new([1u8; 20]),
                    1,
                    merkle_parity_per_node_depth2(),
                ),
            ],
        }
    }

    // =========================================================================
    // ADR-0008 parity telemetry: what may enter the rollout signal, and at what
    // cardinality. The signal is read to decide when the pre-boundary (1x)
    // compatibility window has drained, so a sample from a proof that was
    // rejected — or 256 samples from one settlement — would mislead that call.
    // =========================================================================

    /// A proof naming a paid index outside the pool is rejected in the paid-node
    /// loop, before the telemetry call site. Nothing may be measured.
    #[tokio::test]
    async fn parity_telemetry_silent_when_a_paid_index_is_invalid() {
        let verifier = merkle_test_verifier();
        let (xorname, tagged_proof, pool_hash, ts) = make_valid_merkle_proof_bytes();

        {
            let mut info = parity_settled_pool_info(ts);
            // Second entry points past CANDIDATES_PER_POOL (16).
            if let Some(entry) = info.paid_node_addresses.get_mut(1) {
                entry.1 = 999;
            }
            verifier.pool_cache.lock().put(pool_hash, info);
        }

        let result = verifier
            .verify_payment(
                &xorname,
                Some(&tagged_proof),
                VerificationContext::ClientPut,
            )
            .await;

        assert!(
            result.is_err(),
            "an out-of-bounds paid index must be refused"
        );
        assert_eq!(
            verifier.merkle_parity_emission_count(),
            0,
            "a refused proof must not enter the parity signal"
        );
    }

    /// A paid entry whose reward address does not match the candidate at that
    /// index is rejected before the telemetry call site.
    #[tokio::test]
    async fn parity_telemetry_silent_when_a_reward_address_is_wrong() {
        let verifier = merkle_test_verifier();
        let (xorname, tagged_proof, pool_hash, ts) = make_valid_merkle_proof_bytes();

        {
            let mut info = parity_settled_pool_info(ts);
            // Candidate 1's address is [0x01; 20], not [0xFF; 20].
            if let Some(entry) = info.paid_node_addresses.get_mut(1) {
                entry.0 = RewardsAddress::new([0xFF; 20]);
            }
            verifier.pool_cache.lock().put(pool_hash, info);
        }

        let result = verifier
            .verify_payment(
                &xorname,
                Some(&tagged_proof),
                VerificationContext::ClientPut,
            )
            .await;

        assert!(result.is_err(), "a redirected payee must be refused");
        assert_eq!(
            verifier.merkle_parity_emission_count(),
            0,
            "a refused proof must not enter the parity signal"
        );
    }

    /// An underpaid batch is the case the signal most obviously must not
    /// contain: it is rejected, so it never became a store.
    #[tokio::test]
    async fn parity_telemetry_silent_on_underpayment() {
        let verifier = merkle_test_verifier();
        let (xorname, tagged_proof, pool_hash, ts) = make_valid_merkle_proof_bytes();

        {
            let info = evmlib::merkle_payments::OnChainPaymentInfo {
                depth: 2,
                merkle_payment_timestamp: ts,
                paid_node_addresses: vec![
                    (RewardsAddress::new([0u8; 20]), 0, Amount::from(1u64)),
                    (RewardsAddress::new([1u8; 20]), 1, Amount::from(1u64)),
                ],
            };
            verifier.pool_cache.lock().put(pool_hash, info);
        }

        let result = verifier
            .verify_payment(
                &xorname,
                Some(&tagged_proof),
                VerificationContext::ClientPut,
            )
            .await;

        assert!(result.is_err(), "an underpaid batch must be refused");
        assert_eq!(
            verifier.merkle_parity_emission_count(),
            0,
            "a refused proof must not enter the parity signal"
        );
    }

    /// A paid-list admission verifies the same proof but reprices nothing. It
    /// must not be measured, or a batch already sampled at its store admission
    /// would be counted twice.
    #[tokio::test]
    async fn parity_telemetry_silent_for_paid_list_admission() {
        let verifier = merkle_test_verifier();
        let (xorname, tagged_proof, pool_hash, ts) = make_valid_merkle_proof_bytes();
        verifier
            .pool_cache
            .lock()
            .put(pool_hash, parity_settled_pool_info(ts));

        let result = verifier
            .verify_payment(
                &xorname,
                Some(&tagged_proof),
                VerificationContext::PaidListAdmission,
            )
            .await;

        assert!(result.is_ok(), "the proof itself is valid: {result:?}");
        assert_eq!(
            verifier.merkle_parity_emission_count(),
            0,
            "only store admissions may be measured"
        );
    }

    /// Two chunks of one batch are one economic event. The pool hash in the
    /// line makes the stream deduplicable; the first-emission cache is what
    /// keeps the emitted cardinality at one.
    #[tokio::test]
    async fn parity_telemetry_emits_once_for_two_chunks_of_one_pool() {
        let verifier = merkle_test_verifier();
        let (proofs, pool_hash, ts) = make_valid_merkle_proofs_for_one_pool(&[0, 1]);
        verifier
            .pool_cache
            .lock()
            .put(pool_hash, parity_settled_pool_info(ts));

        for (xorname, tagged) in &proofs {
            let result = verifier
                .verify_payment(xorname, Some(tagged), VerificationContext::ClientPut)
                .await;
            assert!(result.is_ok(), "both chunks must be admitted: {result:?}");
        }

        assert_eq!(
            verifier.merkle_parity_emission_count(),
            1,
            "one settlement is one sample, however many chunks it covers"
        );
    }

    /// Deduplication is per pool, not a global mute: a genuinely separate
    /// settlement is a separate sample.
    #[tokio::test]
    async fn parity_telemetry_emits_once_more_for_a_second_pool() {
        let verifier = merkle_test_verifier();

        let (first, first_pool, first_ts) = make_valid_merkle_proofs_for_one_pool(&[0, 1]);
        verifier
            .pool_cache
            .lock()
            .put(first_pool, parity_settled_pool_info(first_ts));
        for (xorname, tagged) in &first {
            verifier
                .verify_payment(xorname, Some(tagged), VerificationContext::ClientPut)
                .await
                .expect("first pool admitted");
        }
        assert_eq!(verifier.merkle_parity_emission_count(), 1);

        // A fresh batch: new candidate keypairs and leaf salts give it a
        // different pool hash. Its chunk is one the first batch did not carry,
        // so this exercises verification rather than the verified-address cache.
        let (second, second_pool, second_ts) = make_valid_merkle_proofs_for_one_pool(&[2]);
        let (second_xorname, second_tagged) = second.first().expect("one proof").clone();
        assert_ne!(first_pool, second_pool, "the second batch is a new pool");
        verifier
            .pool_cache
            .lock()
            .put(second_pool, parity_settled_pool_info(second_ts));
        verifier
            .verify_payment(
                &second_xorname,
                Some(&second_tagged),
                VerificationContext::ClientPut,
            )
            .await
            .expect("second pool admitted");

        assert_eq!(
            verifier.merkle_parity_emission_count(),
            2,
            "a second settlement contributes a second sample"
        );
    }

    /// Concurrent admissions of one batch — the normal case, since a client
    /// PUTs a batch's chunks in parallel — must still emit once. The
    /// check-and-insert is a single locked operation for exactly this reason.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn parity_telemetry_emits_once_under_concurrent_admissions() {
        let verifier = Arc::new(merkle_test_verifier());
        let (proofs, pool_hash, ts) = make_valid_merkle_proofs_for_one_pool(&[0, 1, 2, 3]);
        verifier
            .pool_cache
            .lock()
            .put(pool_hash, parity_settled_pool_info(ts));

        let mut handles = Vec::new();
        for (xorname, tagged) in proofs {
            // Two racing admissions per address, as replication and the direct
            // PUT can both arrive for the same chunk.
            for _ in 0..2 {
                let verifier = Arc::clone(&verifier);
                let tagged = tagged.clone();
                handles.push(tokio::spawn(async move {
                    verifier
                        .verify_payment(&xorname, Some(&tagged), VerificationContext::ClientPut)
                        .await
                }));
            }
        }

        for handle in handles {
            let result = handle.await.expect("task panicked");
            assert!(
                result.is_ok(),
                "every concurrent admission must succeed: {result:?}"
            );
        }

        assert_eq!(
            verifier.merkle_parity_emission_count(),
            1,
            "concurrent admissions of one pool must not race into extra samples"
        );
    }

    /// The first-emission cache is bounded, so a node admitting an unbounded
    /// stream of distinct pools cannot grow it without limit.
    #[test]
    fn parity_telemetry_first_emission_cache_is_bounded() {
        let verifier = create_test_verifier();
        for i in 0..(MERKLE_PARITY_TELEMETRY_CACHE_CAPACITY + 50) {
            let mut hash: PoolHash = [0u8; 32];
            for (j, b) in i.to_le_bytes().iter().enumerate() {
                if let Some(slot) = hash.get_mut(j) {
                    *slot = *b;
                }
            }
            verifier.merkle_parity_logged.lock().put(hash, ());
        }

        assert_eq!(
            verifier.merkle_parity_logged.lock().len(),
            MERKLE_PARITY_TELEMETRY_CACHE_CAPACITY,
            "the telemetry cache must stay at its capacity"
        );
    }

    #[test]
    fn merkle_required_multiplier_switches_exactly_at_the_boundary() {
        let boundary = 1_785_855_600u64;

        assert_eq!(merkle_required_multiplier(boundary - 1, boundary), 1);
        assert_eq!(
            merkle_required_multiplier(boundary, boundary),
            PAID_QUOTE_PAYMENT_MULTIPLIER,
            "the boundary instant itself is enforcing"
        );
        assert_eq!(
            merkle_required_multiplier(boundary + 1, boundary),
            PAID_QUOTE_PAYMENT_MULTIPLIER
        );
    }

    /// The legacy branch cannot outlive the receipt lifetime, which is what
    /// makes the cutover self-completing.
    ///
    /// It bounds backdating rather than preventing it: mid-window, a stamp just
    /// before the boundary is both unexpired and eligible for 1x, so a modified
    /// client can take that route until it expires. Both halves are asserted
    /// here so neither claim drifts.
    #[test]
    fn merkle_legacy_window_closes_one_receipt_lifetime_after_the_boundary() {
        let boundary = 1_785_855_600u64;
        let expiry = evmlib::merkle_payments::MERKLE_PAYMENT_EXPIRATION;

        // Mid-window: a deliberately backdated stamp is still unexpired, and
        // still gets the 1x rule. This route is open for exactly one week.
        let mid_window = boundary + expiry / 2;
        let backdated = boundary - 1;
        assert!(
            mid_window - backdated < expiry,
            "the backdated stamp is still within its lifetime"
        );
        assert_eq!(
            merkle_required_multiplier(backdated, boundary),
            1,
            "backdating is bounded by expiry, not blocked outright"
        );

        // Once now is a full receipt lifetime past the boundary, the oldest
        // still-valid stamp is itself at or after the boundary.
        let now = boundary + expiry;
        let oldest_valid_stamp = now - expiry;
        assert_eq!(
            merkle_required_multiplier(oldest_valid_stamp, boundary),
            PAID_QUOTE_PAYMENT_MULTIPLIER,
            "no unexpired receipt can still claim the 1x rule"
        );
    }

    //
    // These constants are load-bearing for both correctness (the storer
    // must look at the same window the client picks from, otherwise honest
    // pools are rejected) and DoS resistance (the timeout caps lookup
    // amplification per forged pool_hash). Pinning them with tests gives
    // future patches a one-line failure if either is silently changed
    // without updating the security argument in the doc comments.
    //
    // Empirical justification, captured during STG-01 investigation on
    // 2026-05-01:
    //
    //   - 60s timeout cut iterative lookups off after ~7 of 20 iterations
    //     (trace from EWR-3 ant-node-1 in CLOSENESS_LOOKUP_TIMEOUT doc).
    //   - K=16 storer window vs K=32 client over-query produced 73%
    //     false-positive mismatch rejections under realistic load
    //     (115 → 31 client mismatches per 5min after K=32 deploy).
    // =========================================================================

    #[test]
    fn closeness_lookup_timeout_is_240s() {
        // Pin the timeout. If a future change drops it back to 60s the
        // failure mode from the trace in the doc comment will return.
        assert_eq!(
            PaymentVerifier::CLOSENESS_LOOKUP_TIMEOUT,
            std::time::Duration::from_mins(4),
            "CLOSENESS_LOOKUP_TIMEOUT must be 240s; if changing this, update \
             the iteration trace in the doc comment and re-validate on a \
             fresh testnet"
        );
    }

    #[test]
    fn closeness_lookup_width_is_32() {
        // Pin the storer's lookup width. Must equal the client's
        // over-query factor (CANDIDATES_PER_POOL * 2 = 32) so the storer
        // sees the same peers the client legitimately picks from.
        assert_eq!(
            PaymentVerifier::CLOSENESS_LOOKUP_WIDTH,
            2 * evmlib::merkle_payments::CANDIDATES_PER_POOL,
            "CLOSENESS_LOOKUP_WIDTH must equal 2 * CANDIDATES_PER_POOL to \
             match the client's over-query in get_merkle_candidate_pool"
        );
    }

    #[test]
    fn closeness_required_threshold_is_majority() {
        // Pin the threshold so a future change can't silently move it. This
        // is the security knob: a 9/16 majority tolerates closest-set
        // divergence between two nodes' views while still requiring most
        // candidates to be real peers the live DHT lists as closest.
        assert_eq!(
            PaymentVerifier::CANDIDATE_CLOSENESS_REQUIRED,
            9,
            "closeness threshold is a 9/16 majority"
        );
    }

    #[test]
    fn closeness_lookup_count_uses_max_of_width_and_pool_len() {
        // The honest case: a 16-candidate pool must trigger a 32-peer
        // network lookup. This is the K=16-rejects-honest-pool fix from
        // the STG-01 investigation — without it, the storer never
        // observes the peers at network-true positions 17–32 that the
        // client legitimately picks from.
        let standard =
            PaymentVerifier::closeness_lookup_count(evmlib::merkle_payments::CANDIDATES_PER_POOL);
        assert_eq!(
            standard, 32,
            "honest 16-candidate pool must trigger a 32-peer DHT lookup"
        );

        // Future-proof: if a protocol bump ever produces a pool larger
        // than CLOSENESS_LOOKUP_WIDTH, lookup_count must scale with the
        // pool — not truncate to WIDTH. Truncating would let an attacker
        // hide candidates by padding the pool past the storer's window.
        assert_eq!(
            PaymentVerifier::closeness_lookup_count(64),
            64,
            "lookup_count must scale up if pool exceeds CLOSENESS_LOOKUP_WIDTH"
        );

        // Lower bound (also covered by the const-assert below; pin the
        // runtime path too in case the const-assert is ever removed).
        assert_eq!(
            PaymentVerifier::closeness_lookup_count(1),
            PaymentVerifier::CLOSENESS_LOOKUP_WIDTH,
            "lookup_count must never drop below CLOSENESS_LOOKUP_WIDTH"
        );
    }

    // Compile-time invariant: the `closeness_lookup_count` formula relies
    // on WIDTH being ≥ CANDIDATES_PER_POOL so we never request fewer peers
    // than the pool itself contains.
    const _: () = assert!(
        PaymentVerifier::CLOSENESS_LOOKUP_WIDTH >= evmlib::merkle_payments::CANDIDATES_PER_POOL,
        "CLOSENESS_LOOKUP_WIDTH must be ≥ CANDIDATES_PER_POOL",
    );

    // =========================================================================
    // Closeness-match logic tests
    //
    // These tests use the extracted `check_closeness_match` helper to
    // exercise the matching logic directly with synthetic peer-ID sets,
    // without standing up a real DHT. They cover:
    //
    //   - the 9/16 majority threshold (accept at exactly 9, reject below);
    //   - that a candidate counts only via exact membership in the storer's
    //     returned closest peers, so off-network fabrications are rejected;
    //   - the sparse-network short-circuit.
    //
    // Synthetic PeerIds put the tag in `bytes[0]`, so a candidate is in or
    // out of the network's returned set purely by tag value.
    // =========================================================================

    /// Build a deterministic `PeerId` from a single byte tag.
    fn synthetic_peer_id(tag: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = tag;
        PeerId::from_bytes(bytes)
    }

    /// Build a vector of synthetic `PeerId`s tagged with bytes 1..=n.
    fn synthetic_peer_ids(n: u8) -> Vec<PeerId> {
        (1..=n).map(synthetic_peer_id).collect()
    }

    #[test]
    fn closeness_match_passes_when_all_16_candidates_in_top_16() {
        // Trivial case: every candidate is in the network's top-16.
        // Asserts the happy path still works after the refactor.
        let candidates = synthetic_peer_ids(16);
        let network = synthetic_peer_ids(16);
        let pool_address = [0u8; 32];
        let result = PaymentVerifier::check_closeness_match(&candidates, &network, &pool_address);
        assert!(result.is_ok(), "all-in-top-16 pool must pass: {result:?}");
    }

    #[test]
    fn closeness_match_passes_when_candidates_span_positions_1_to_15_and_17() {
        // The client's pool contains 16 candidates, 15 at network-true
        // positions 1..=15 plus one at position 17 (the position-16 peer was
        // unresponsive when the client over-queried). Under K=32 all 16 are
        // exact matches, comfortably ≥ the 9/16 majority.
        let candidates = synthetic_peer_ids(15)
            .into_iter()
            .chain(std::iter::once(synthetic_peer_id(17)))
            .collect::<Vec<_>>();
        // Lookup window = 32, includes position 17.
        let network: Vec<PeerId> = (1..=32).map(synthetic_peer_id).collect();
        let pool_address = [0u8; 32];
        let result = PaymentVerifier::check_closeness_match(&candidates, &network, &pool_address);
        assert!(
            result.is_ok(),
            "pool with one candidate at position 17 must pass: {result:?}"
        );
    }

    #[test]
    fn closeness_match_accepts_honest_skew_via_exact_matches() {
        // Honest skew: the client's 16 candidates span network-true positions
        // {1..=12, 17, 19, 21, 23}. The lookup window of 32 covers all of
        // them, so all 16 are exact matches — trivially ≥ the 9/16 majority.
        let candidates: Vec<PeerId> = (1..=12u8)
            .chain([17u8, 19, 21, 23])
            .map(synthetic_peer_id)
            .collect();
        let pool_address = [0u8; 32];
        let network: Vec<PeerId> = (1..=32).map(synthetic_peer_id).collect();

        let result = PaymentVerifier::check_closeness_match(&candidates, &network, &pool_address);
        assert!(
            result.is_ok(),
            "honest pool fully inside the lookup window must pass: {result:?}"
        );
    }

    #[test]
    fn closeness_match_rejects_forged_pool() {
        // Security floor: a fully-forged pool whose candidate PeerIds are
        // disjoint from the network's returned closest peers must be
        // rejected. The lowered majority threshold must NOT let off-network
        // fabrications pass — every counted candidate has to be a peer the
        // live DHT actually returned.
        let forged_candidates: Vec<PeerId> = (100..=115).map(synthetic_peer_id).collect();
        let network: Vec<PeerId> = (1..=32).map(synthetic_peer_id).collect();
        let pool_address = [0u8; 32];

        let result =
            PaymentVerifier::check_closeness_match(&forged_candidates, &network, &pool_address);
        match result {
            Err(Error::Payment(msg)) => {
                assert!(
                    msg.contains("candidate pub_keys do not match"),
                    "expected forged-pool rejection message, got: {msg}"
                );
            }
            other => {
                panic!("forged pool disjoint from the network set must be rejected: {other:?}")
            }
        }
    }

    #[test]
    fn closeness_match_rejects_pool_below_majority() {
        // Threshold sanity: 8 candidates are exact matches (tags 1..=8) and
        // the other 8 are off-network fabrications (tags 100..=107). 8 < 9
        // → reject.
        let mut candidates = synthetic_peer_ids(8);
        candidates.extend((100..=107).map(synthetic_peer_id)); // 8 fabrications
        let network: Vec<PeerId> = (1..=32).map(synthetic_peer_id).collect();
        let pool_address = [0u8; 32];

        let result = PaymentVerifier::check_closeness_match(&candidates, &network, &pool_address);
        assert!(
            result.is_err(),
            "8 matches < majority of 9/16 must reject: {result:?}"
        );
    }

    #[test]
    fn closeness_match_accepts_at_exactly_majority() {
        // Threshold sanity: exactly 9 candidates are exact matches (tags
        // 1..=9), the other 7 are off-network fabrications (tags 100..=106).
        // 9 ≥ 9 → accept.
        let mut candidates = synthetic_peer_ids(9);
        candidates.extend((100..=106).map(synthetic_peer_id)); // 7 fabrications
        let network: Vec<PeerId> = (1..=32).map(synthetic_peer_id).collect();
        let pool_address = [0u8; 32];

        let result = PaymentVerifier::check_closeness_match(&candidates, &network, &pool_address);
        assert!(
            result.is_ok(),
            "9/16 ≥ majority threshold must accept: {result:?}"
        );
    }

    #[test]
    fn closeness_match_returns_sparse_dht_error_when_lookup_too_small() {
        // The sparse-DHT short-circuit fires when the lookup returned
        // fewer peers than the threshold itself — even an all-matching
        // candidate set can't pass because the storer doesn't have an
        // authoritative view to compare against.
        let candidates = synthetic_peer_ids(16);
        let network = synthetic_peer_ids(8); // < CANDIDATE_CLOSENESS_REQUIRED (9)
        let pool_address = [0u8; 32];

        let result = PaymentVerifier::check_closeness_match(&candidates, &network, &pool_address);
        match result {
            Err(Error::Payment(msg)) => {
                assert!(
                    msg.contains("authoritative DHT lookup returned only 8"),
                    "expected sparse-DHT error message, got: {msg}"
                );
            }
            other => panic!("expected sparse-DHT rejection, got: {other:?}"),
        }
    }

    // ---------- ADR-0004: quote arithmetic re-check ----------

    /// Curve canonicality: any price produced by `calculate_price(n)` is
    /// on-curve by construction. We exercise a spread of `n` covering the
    /// baseline floor (n=0), small counts, the pricing-curve knee
    /// (`n=PRICING_DIVISOR=6000`), and a saturating-arithmetic regime.
    #[test]
    fn adr0004_on_curve_prices_round_trip() {
        for &n in &[0usize, 1, 2, 100, 5999, 6000, 6001, 50_000, 1_000_000] {
            let price = crate::payment::pricing::calculate_price(n);
            assert!(
                PaymentVerifier::quote_price_is_on_curve(&price),
                "calculate_price({n}) = {price} must be on-curve"
            );
        }
    }

    /// Off-curve canonicality: a price one wei above or below an on-curve
    /// point is between two adjacent curve values and must fail the
    /// canonicality predicate. The check IS exact equality, not a tolerance.
    #[test]
    fn adr0004_off_curve_prices_rejected_by_predicate() {
        // n=100 is well above baseline so price ± 1 is non-saturating.
        let on = crate::payment::pricing::calculate_price(100);
        let just_above = on + Amount::from(1u64);
        let just_below = on - Amount::from(1u64);
        assert!(
            !PaymentVerifier::quote_price_is_on_curve(&just_above),
            "price one wei above an on-curve point must be off-curve"
        );
        assert!(
            !PaymentVerifier::quote_price_is_on_curve(&just_below),
            "price one wei below an on-curve point must be off-curve"
        );
    }

    /// A price strictly below the baseline floor is off-curve: the formula's
    /// minimum value is `calculate_price(0) = BASELINE`, so any smaller value
    /// has no corresponding `n`.
    #[test]
    fn adr0004_sub_baseline_price_is_off_curve() {
        let baseline = crate::payment::pricing::calculate_price(0);
        let sub_baseline = baseline - Amount::from(1u64);
        assert!(
            !PaymentVerifier::quote_price_is_on_curve(&sub_baseline),
            "price strictly below baseline must be off-curve"
        );
    }

    /// ADR-0004 storer-side gate: a bundle in which every quote is on-curve
    /// passes the gate **and** the per-quote canonicality predicate. Runs in
    /// every context (no `ClientPut` split): the rule depends only on the
    /// bundle, not on per-peer state. The outer `validate_quote_arithmetic`
    /// short-circuits to `Ok` under the observe-only rollout const, so the
    /// per-quote diagnostics assertion is what proves the bundle is genuinely
    /// on-curve regardless of how the const ships.
    #[test]
    fn adr0004_validate_quote_arithmetic_passes_for_honest_bundle() {
        use evmlib::{EncodedPeerId, RewardsAddress};

        let payment = ProofOfPayment {
            peer_quotes: (0..crate::ant_protocol::CLOSE_GROUP_SIZE)
                .map(|i| {
                    let id: [u8; 32] = rand::random();
                    let byte = u8::try_from(i & 0xFF).unwrap_or(0);
                    let quote = make_fake_quote_at_records(
                        [0xC0u8; 32],
                        SystemTime::now(),
                        RewardsAddress::new([byte; 20]),
                        100 * (i + 1),
                    );
                    (EncodedPeerId::new(id), quote)
                })
                .collect(),
        };
        PaymentVerifier::validate_quote_arithmetic(&payment)
            .expect("honest on-curve bundle must pass the gate (any const value)");
        for (_, quote) in &payment.peer_quotes {
            assert!(
                PaymentVerifier::price_off_curve_diagnostics(&quote.price).is_none(),
                "every quote in honest bundle must be canonically on-curve"
            );
        }
    }

    /// Off-curve quote behaviour follows the rollout gate
    /// [`QUOTE_ARITHMETIC_RECHECK_ENABLED`]. The gate now ships enforcing, so
    /// an off-curve quote must be rejected; the observe-only branch is kept so
    /// the test still documents the semantics if the gate is ever rolled back.
    /// The rejection payload itself is exercised separately by
    /// `adr0004_off_curve_diagnostics_yields_reject_payload`.
    #[test]
    fn adr0004_off_curve_quote_follows_rollout_gate() {
        use evmlib::{EncodedPeerId, RewardsAddress};

        let mut quote = make_fake_quote_at_records(
            [0xC1u8; 32],
            SystemTime::now(),
            RewardsAddress::new([1u8; 20]),
            100,
        );
        // Bump one wei off the curve.
        quote.price += Amount::from(1u64);

        let id: [u8; 32] = rand::random();
        let payment = ProofOfPayment {
            peer_quotes: vec![(EncodedPeerId::new(id), quote)],
        };

        // Both branches of the const-gated split are asserted, so the test
        // keeps its meaning whichever way the gate is set rather than going
        // silently vacuous when it flips.
        if crate::replication::config::QUOTE_ARITHMETIC_RECHECK_ENABLED {
            assert!(
                PaymentVerifier::validate_quote_arithmetic(&payment).is_err(),
                "enforcing rollout must reject off-curve quotes"
            );
        } else {
            assert!(
                PaymentVerifier::validate_quote_arithmetic(&payment).is_ok(),
                "observe-only rollout must not reject off-curve quotes"
            );
        }
    }

    /// Enforcement-branch coverage: the rejection payload (peer id, candidate
    /// `n`, recomputed price) is produced for off-curve prices independently
    /// of the rollout const, so CI exercises the rejection code path even
    /// while [`QUOTE_ARITHMETIC_RECHECK_ENABLED`] ships as `false`. Flipping
    /// the const to `true` then merely wires this diagnostic into the outer
    /// `Err` return, which is what `validate_quote_arithmetic` does.
    #[test]
    fn adr0004_off_curve_diagnostics_yields_reject_payload() {
        let on = crate::payment::pricing::calculate_price(100);
        let off = on + Amount::from(1u64);

        let diag = PaymentVerifier::price_off_curve_diagnostics(&off)
            .expect("off-curve price must produce diagnostics");
        let (candidate_count, recomputed) = diag;
        assert_eq!(candidate_count, 100, "floor candidate must be n=100");
        assert_eq!(
            recomputed, on,
            "recomputed price must equal the floor curve point"
        );
        assert!(
            recomputed < off,
            "off-curve diagnostics' recomputed price must be strictly below the off-curve input"
        );

        // And an on-curve price must produce no diagnostics.
        assert!(
            PaymentVerifier::price_off_curve_diagnostics(&on).is_none(),
            "on-curve price must yield no off-curve diagnostics"
        );
    }

    /// Saturation regime: a price strictly above
    /// `calculate_price(u64::MAX-equivalent saturating ceiling)` is rejected.
    /// We do not have direct access to that ceiling, but `Amount::MAX` is
    /// guaranteed above it (since `calculate_price(usize::MAX)` saturates to
    /// some value strictly less than `Amount::MAX` due to the additive
    /// baseline). The gate must reject it.
    #[test]
    fn adr0004_amount_max_price_is_off_curve() {
        let price = Amount::MAX;
        assert!(
            !PaymentVerifier::quote_price_is_on_curve(&price),
            "Amount::MAX must not be a valid on-curve price"
        );
    }

    /// Merkle gate, predicate-level: the same canonicality rule applies to
    /// `MerklePaymentCandidateNode.price`. We don't construct a full merkle
    /// proof here (the test fixtures for that live elsewhere); we prove the
    /// underlying decision matches the single-node side, so the Merkle gate
    /// inherits the same correctness as `validate_quote_arithmetic`.
    #[test]
    fn adr0004_merkle_candidate_canonicality_matches_single_node() {
        // Every on-curve `n` produces a price the predicate accepts; one wei
        // off produces a price the predicate rejects. This is the entire
        // contract; the Merkle gate's outer wrapper enforces the same const
        // as the single-node gate, so the wrappers are mechanically
        // equivalent.
        for &n in &[0usize, 1, 100, 6000, 1_000_000] {
            let on = crate::payment::pricing::calculate_price(n);
            assert!(
                PaymentVerifier::quote_price_is_on_curve(&on),
                "merkle candidate price for n={n} must be on-curve"
            );
            if n > 0 {
                let off = on + Amount::from(1u64);
                assert!(
                    !PaymentVerifier::quote_price_is_on_curve(&off),
                    "merkle candidate price one wei above n={n} must be off-curve"
                );
            }
        }
    }

    /// Merkle gate, pool-level: build a real signed candidate pool, set every
    /// candidate's price to the same on-curve value, and assert the gate
    /// passes. Then bump one candidate's price one wei off-curve and assert
    /// the per-candidate diagnostics correctly identify it. We use the
    /// diagnostics predicate rather than the outer `validate_merkle_candidate_arithmetic`
    /// because the outer wrapper short-circuits to `Ok` under the observe-only
    /// rollout const; the diagnostics path is what carries the rejection
    /// information when enforcement flips on.
    #[test]
    fn adr0004_merkle_pool_off_curve_candidate_caught_by_diagnostics() {
        use evmlib::merkle_payments::MerklePaymentCandidatePool;

        let timestamp = 1_700_000_000u64;
        let mut candidates = make_candidate_nodes(timestamp);

        // Set every candidate price to calculate_price(500) so the pool is
        // honestly on-curve to start. The binding must move with the price:
        // ADR-0004 requires `price == calculate_price(committed_key_count)`, so
        // repricing at 500 records while leaving the count at 0 would make the
        // pool dishonest rather than honest.
        let on_curve = crate::payment::pricing::calculate_price(500);
        for c in &mut candidates {
            c.price = on_curve;
            c.committed_key_count = 500;
            c.commitment_pin = Some([0xA5u8; 32]);
        }
        let pool = MerklePaymentCandidatePool {
            midpoint_proof: fake_midpoint_proof(),
            candidate_nodes: candidates,
        };
        // The outer wrapper is rollout-gated, but a fully on-curve pool must
        // pass it under any const value because the loop finds no off-curve
        // candidate to reject.
        PaymentVerifier::validate_merkle_candidate_arithmetic(&pool)
            .expect("honest on-curve pool must pass merkle gate (any const value)");
        for c in &pool.candidate_nodes {
            assert!(
                PaymentVerifier::price_off_curve_diagnostics(&c.price).is_none(),
                "every honest candidate must be canonically on-curve"
            );
        }

        // Now bump exactly one candidate off-curve and check that the
        // diagnostics path catches it. (The outer wrapper still short-circuits
        // under observe-only; this proves the underlying detection works
        // independently of the rollout const, exercising the rejection-payload
        // path in CI.)
        let mut tampered = pool;
        tampered.candidate_nodes[3].price += Amount::from(1u64);
        let mut off_curve_seen = 0;
        for c in &tampered.candidate_nodes {
            if PaymentVerifier::price_off_curve_diagnostics(&c.price).is_some() {
                off_curve_seen += 1;
            }
        }
        assert_eq!(
            off_curve_seen, 1,
            "exactly one tampered candidate must register as off-curve"
        );
    }

    // === ADR-0004 binding-shape + cross-check unit tests ===

    use crate::payment::pricing::calculate_price as cp;

    /// Build a real signed commitment over `n` synthetic keys for tests.
    fn test_built_commitment(n: u32) -> crate::replication::commitment_state::BuiltCommitment {
        use saorsa_pqc::api::sig::ml_dsa_65;
        let (pk, sk) = ml_dsa_65().generate_keypair().expect("keypair");
        let pk_bytes = pk.to_bytes();
        let peer_id = blake3::hash(&pk_bytes);
        let entries: Vec<([u8; 32], [u8; 32])> = (0..n)
            .map(|i| {
                let mut k = [0u8; 32];
                k[..4].copy_from_slice(&i.to_le_bytes());
                let mut b = [1u8; 32];
                b[..4].copy_from_slice(&i.to_le_bytes());
                (k, b)
            })
            .collect();
        crate::replication::commitment_state::BuiltCommitment::build(
            entries,
            peer_id.as_bytes(),
            &sk,
            &pk_bytes,
        )
        .expect("build commitment")
    }

    #[test]
    fn binding_baseline_ok_only_at_baseline_price() {
        // (0, None) with calculate_price(0) is the valid baseline.
        assert!(PaymentVerifier::binding_violation(0, None, &cp(0)).is_none());
        // (0, None) with a non-baseline price is REJECTED — this is the BLOCKER
        // bypass the round-1 review found (unpinned quote priced above baseline).
        assert!(PaymentVerifier::binding_violation(0, None, &cp(500)).is_some());
    }

    #[test]
    fn binding_bound_ok_only_with_pin_and_exact_price() {
        let pin = [9u8; 32];
        // (n>0, Some(pin)) priced exactly is valid.
        assert!(PaymentVerifier::binding_violation(500, Some(pin), &cp(500)).is_none());
        // (n>0, Some(pin)) priced for a DIFFERENT count is rejected (on-curve
        // but wrong count — stronger than canonicality).
        assert!(PaymentVerifier::binding_violation(500, Some(pin), &cp(499)).is_some());
    }

    #[test]
    fn binding_rejects_incoherent_shapes() {
        let pin = [9u8; 32];
        // count > 0 but no pin: unauditable.
        assert!(PaymentVerifier::binding_violation(500, None, &cp(500)).is_some());
        // count 0 but a pin: incoherent baseline.
        assert!(PaymentVerifier::binding_violation(0, Some(pin), &cp(0)).is_some());
    }

    #[test]
    fn binding_rejects_count_above_cap() {
        let pin = [9u8; 32];
        let over = crate::replication::commitment::MAX_COMMITMENT_KEY_COUNT + 1;
        assert!(PaymentVerifier::binding_violation(over, Some(pin), &cp(over as usize)).is_some());
    }

    #[test]
    fn cross_check_match_when_pin_and_count_agree() {
        let built = test_built_commitment(12);
        let outcome = PaymentVerifier::cross_check_binding(12, built.hash(), built.commitment());
        assert_eq!(outcome, CrossCheck::Match);
    }

    #[test]
    fn cross_check_mismatch_when_count_inflated() {
        let built = test_built_commitment(12);
        // Quote claims 999 but the pinned commitment attests 12.
        let outcome = PaymentVerifier::cross_check_binding(999, built.hash(), built.commitment());
        assert_eq!(
            outcome,
            CrossCheck::Mismatch {
                quoted_key_count: 999,
                committed_key_count: 12,
            }
        );
    }

    #[test]
    fn cross_check_unresolved_when_pin_wrong() {
        let built = test_built_commitment(12);
        // Pin does not match the supplied commitment's hash: not evidence.
        let outcome = PaymentVerifier::cross_check_binding(12, [0xFFu8; 32], built.commitment());
        assert_eq!(outcome, CrossCheck::PinDoesNotResolve);
    }

    #[test]
    fn fresh_cached_commitment_honours_ttl_boundary() {
        use crate::replication::commitment_state::PeerCommitmentRecord;
        let built = test_built_commitment(5);
        let commitment = built.commitment().clone();
        let pin = built.hash();
        let ttl = std::time::Duration::from_hours(3);
        let now = std::time::Instant::now();

        // Fresh AND matching pin -> resolves to the commitment.
        let fresh = PeerCommitmentRecord::from_verified(commitment.clone(), now);
        assert!(
            PaymentVerifier::fresh_cached_commitment(&fresh, pin, now, ttl).is_some(),
            "a fresh cache entry whose hash matches the pin must resolve"
        );

        // Fresh but a DIFFERENT pin -> treated as not-cached (None), so the
        // caller falls through to fetch the actually-quoted pin instead of
        // mis-resolving against the peer's latest (different) commitment.
        assert!(
            PaymentVerifier::fresh_cached_commitment(&fresh, [0xEEu8; 32], now, ttl).is_none(),
            "a fresh cache entry for a DIFFERENT pin must not resolve (fetch fallback runs)"
        );

        // Stale: received older than the TTL -> treated as unknown (None), the
        // ADR-0004 false-positive guard against an aged cache entry.
        //
        // Advance the comparison clock PAST the TTL rather than subtracting the
        // TTL from `now`: on Windows the monotonic `Instant` epoch can be
        // younger than a multi-hour TTL, so `now.checked_sub(ttl + 1s)`
        // underflows to `None` and panics. `checked_add` from the receipt time
        // is always in range and is equivalent for the age comparison.
        let received_at = now;
        let now_after_ttl = received_at
            .checked_add(ttl + std::time::Duration::from_secs(1))
            .expect("instant in range");
        let stale = PeerCommitmentRecord::from_verified(commitment, received_at);
        assert!(
            PaymentVerifier::fresh_cached_commitment(&stale, pin, now_after_ttl, ttl).is_none(),
            "a cache entry older than the answerability TTL must be treated as unknown"
        );
    }

    #[test]
    fn fetched_commitment_must_be_bound_to_the_queried_peer() {
        // A fetched commitment is accepted only when it is bound to the peer we
        // asked (sender_peer_id == peer_id) and hashes to the requested pin.
        let built = test_built_commitment(8);
        let commitment = built.commitment().clone();
        let pin = built.hash();
        let owner = PeerId::from_bytes(commitment.sender_peer_id);

        // Correct owner + correct pin -> accepted.
        assert!(
            PaymentVerifier::fetched_commitment_is_valid(&commitment, &owner, pin),
            "a peer's own validly-signed commitment, hashing to the pin, must be accepted"
        );

        // Same (validly signed) commitment but attributed to a DIFFERENT peer ->
        // rejected. This is the MAJOR fix: a peer must not be able to answer with
        // someone else's commitment and have it pass as its own.
        let other = PeerId::from_bytes([0xABu8; 32]);
        assert!(
            !PaymentVerifier::fetched_commitment_is_valid(&commitment, &other, pin),
            "another peer's commitment must be rejected for the queried peer"
        );

        // Correct owner but wrong pin -> rejected.
        assert!(
            !PaymentVerifier::fetched_commitment_is_valid(&commitment, &owner, [0u8; 32]),
            "a commitment that does not hash to the requested pin must be rejected"
        );
    }

    #[tokio::test]
    async fn emit_mismatch_evidence_without_p2p_does_not_panic() {
        // Guards the "always best-effort" degrade path: with no P2P handle there
        // is no trust engine to act on, so `emit_mismatch_evidence` must be a
        // no-op that never panics or errors on the payment path. This is a
        // no-panic guard on the degraded path — it does NOT exercise the
        // evidence->action mapping (that needs a live trust engine).
        let built = test_built_commitment(12);
        let evidence = crate::replication::types::FailureEvidence::QuoteCommitmentMismatch {
            peer: PeerId::from_bytes([1u8; 32]),
            pinned_commitment: [2u8; 32],
            quoted_key_count: 999,
            committed_key_count: 12,
            quote_artifact: vec![0xAA; 16],
            commitment: Box::new(built.commitment().clone()),
        };
        // No P2P -> no trust event even if enforce were on; must not panic.
        PaymentVerifier::emit_mismatch_evidence(&evidence, None).await;
    }

    #[test]
    fn valid_sidecar_is_indexed_and_resolves_synchronously() {
        // A valid sidecar blob is indexed under its own (peer, pin) so the
        // cross-check resolves it synchronously — "the commitment arrived with
        // the quote", no gossip-cache hit or fetch needed.
        let built = test_built_commitment(9);
        let commitment = built.commitment().clone();
        let pin = built.hash();
        let owner = PeerId::from_bytes(commitment.sender_peer_id);
        let blob = rmp_serde::to_vec(&commitment).expect("serialize sidecar");

        let map = PaymentVerifier::index_valid_sidecars(std::slice::from_ref(&blob));
        assert!(
            map.contains_key(&(owner, pin)),
            "a valid sidecar must be indexed under its own (peer, pin)"
        );

        // A garbage blob is silently skipped (resolution falls back), never a
        // hard error.
        let map2 = PaymentVerifier::index_valid_sidecars(&[vec![0xFF; 8]]);
        assert!(map2.is_empty(), "an unparseable sidecar must be skipped");
    }
}
