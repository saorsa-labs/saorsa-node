//! ADR-0009 WebRTC Direct browser transport.
//!
//! The listener uses Saorsa's signaling-free WebRTC Direct transport for ICE,
//! DTLS, SCTP, and reliable ordered `DataChannels`. A shared application layer
//! in `saorsa-webrtc` uses ML-KEM-768, ML-DSA-65, and ChaCha20-Poly1305 to bind
//! the node identity and protect every browser RPC without libp2p or Noise.

use crate::ant_protocol::{
    ChunkMessage, ChunkMessageBody, ChunkPutRequest, ChunkPutResponse, ChunkQuoteRequest,
    ChunkQuoteResponse, MAX_CHUNK_SIZE,
};
use crate::browser::{browser_payment_network, BrowserEndpoint, BrowserPaymentNetwork};
use crate::config::WebRtcDirectConfig;
use crate::error::{Error, Result};
use crate::logging::{debug, info, warn};
use crate::payment::{serialize_single_node_proof, PaymentProof};
use crate::storage::AntProtocol;
use evmlib::common::{Amount, TxHash};
use evmlib::{EncodedPeerId, PaymentQuote, ProofOfPayment, RewardsAddress};
use parking_lot::{Mutex, RwLock};
use saorsa_core::identity::NodeIdentity;
use saorsa_core::{DHTNode, MultiAddr, P2PNode, PeerId};
use saorsa_transport::webrtc_direct::{
    WebRtcCertificate, WebRtcDataChannel, WebRtcDirectConnection, WebRtcDirectListener,
};
use saorsa_webrtc::{
    accept_pq_session, decode_pq_frame, encode_response_frame, parse_request_header,
    pq_frame_length, transfer_timeout, BrowserCommitmentArtifact, BrowserNode,
    BrowserQuoteArtifact, BrowserRequest as Request, BrowserRequestBody as RequestBody,
    BrowserResponse as Response, BrowserResponseBody as ResponseBody,
    BrowserResponseStatus as ResponseStatus, PqSession, BROWSER_PROTOCOL_NAME,
    BROWSER_PROTOCOL_VERSION, MAX_BROWSER_HEADER_BYTES, PQ_CLIENT_HELLO_BYTES,
    PQ_ENCRYPTED_OVERHEAD_BYTES, PQ_FRAME_PREFIX_BYTES, WEBRTC_DIRECT_DATA_CHANNEL,
    WEBRTC_WRITE_CHUNK_BYTES,
};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

const MAX_FIND_NODE_RESULTS: usize = 20;
const REQUEST_IDLE_TIMEOUT: Duration = Duration::from_mins(1);
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const AUTOMATIC_PORT_MIN: u32 = 32_768;
const AUTOMATIC_PORT_COUNT: u32 = 65_536 - AUTOMATIC_PORT_MIN;
const TRACKED_SOURCE_MULTIPLIER: usize = 4;
const MIN_TRACKED_SOURCES: usize = 64;
const CONNECTION_CAPACITY_ERROR: &str = "global connection capacity exhausted";
const SOURCE_CONNECTION_CAPACITY_ERROR: &str = "source connection capacity exhausted";
const CHANNEL_CAPACITY_ERROR: &str = "global DataChannel capacity exhausted";
const REQUEST_CAPACITY_ERROR: &str = "global request capacity exhausted";
const REQUEST_RATE_ERROR: &str = "request rate limit exceeded";
const GLOBAL_BYTE_CAPACITY_ERROR: &str = "global in-flight byte capacity exhausted";
const SOURCE_BYTE_CAPACITY_ERROR: &str = "source in-flight byte capacity exhausted";

/// Filename containing the node's canonical browser bootstrap address.
///
/// The file is written below the node root directory after the listener has
/// bound and is safe for deployment tooling to copy or print. Its contents are
/// public bootstrap metadata, not key material.
pub const WEBRTC_DIRECT_MULTIADDR_FILENAME: &str = "webrtc-direct.multiaddr";

/// Resolve the zero-configuration listener values used by ordinary nodes.
///
/// A zero bind port is mapped deterministically from the native QUIC port into
/// the high UDP range. That keeps the complete browser multiaddress stable
/// across restarts and fits the high-port firewall range used by `ant-testnet`.
/// A wildcard bind without an explicit advertised address prefers the public
/// IP observed by the native transport and otherwise uses the IP selected by
/// the host routing table.
pub fn resolve_automatic_config(
    config: &WebRtcDirectConfig,
    native_port: u16,
    observed_ip: Option<IpAddr>,
) -> WebRtcDirectConfig {
    let mut resolved = config.clone();
    if resolved.bind.port() == 0 {
        let port = resolved
            .advertised_addr
            .map_or_else(|| automatic_webrtc_port(native_port), |addr| addr.port());
        resolved.bind.set_port(port);
    }

    if resolved.advertised_addr.is_none() && resolved.bind.ip().is_unspecified() {
        let bind_is_ipv4 = resolved.bind.is_ipv4();
        let advertised_ip = observed_ip
            .filter(|ip| ip.is_ipv4() == bind_is_ipv4 && !ip.is_unspecified())
            .or_else(|| routed_local_ip(bind_is_ipv4))
            .unwrap_or({
                if bind_is_ipv4 {
                    IpAddr::V4(Ipv4Addr::LOCALHOST)
                } else {
                    IpAddr::V6(Ipv6Addr::LOCALHOST)
                }
            });
        resolved.advertised_addr = Some(SocketAddr::new(advertised_ip, resolved.bind.port()));
    }

    resolved
}

fn automatic_webrtc_port(native_port: u16) -> u16 {
    let native = u32::from(native_port);
    let offset = if native < AUTOMATIC_PORT_MIN {
        native
    } else {
        (native - AUTOMATIC_PORT_MIN + AUTOMATIC_PORT_COUNT / 2) % AUTOMATIC_PORT_COUNT
    };
    u16::try_from(AUTOMATIC_PORT_MIN + offset).unwrap_or(u16::MAX)
}

fn routed_local_ip(ipv4: bool) -> Option<IpAddr> {
    let (bind, route_probe) = if ipv4 {
        (
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 9)),
        )
    } else {
        (
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            SocketAddr::from((Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1), 9)),
        )
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(route_probe).ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}

/// Browser endpoints known to one or more listeners in the same process.
///
/// Only the in-process devnet supplies this catalog. Independently deployed
/// nodes discover endpoints exclusively from authenticated DHT address
/// records.
#[derive(Default)]
pub struct BrowserEndpointCatalog {
    endpoints: RwLock<HashMap<PeerId, BrowserEndpoint>>,
}

impl BrowserEndpointCatalog {
    fn insert(&self, peer_id: PeerId, endpoint: BrowserEndpoint) {
        self.endpoints.write().insert(peer_id, endpoint);
    }

    fn get(&self, peer_id: &PeerId) -> Option<BrowserEndpoint> {
        self.endpoints.read().get(peer_id).cloned()
    }
}

/// Fixed-capacity token bucket with a one-second burst allowance.
///
/// The bucket is deliberately constant-space: source churn must not turn the
/// request limiter itself into a memory-exhaustion surface.
struct RequestRateBucket {
    rate_per_second: u128,
    token_units: u128,
    last_refill: Instant,
}

impl RequestRateBucket {
    fn new(rate_per_second: usize) -> Self {
        let rate_per_second = rate_per_second as u128;
        Self {
            rate_per_second,
            token_units: rate_per_second.saturating_mul(1_000_000_000),
            last_refill: Instant::now(),
        }
    }

    fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill);
        self.last_refill = now;
        let capacity = self.rate_per_second.saturating_mul(1_000_000_000);
        let refill = elapsed.as_nanos().saturating_mul(self.rate_per_second);
        self.token_units = self.token_units.saturating_add(refill).min(capacity);
        if self.token_units < 1_000_000_000 {
            return false;
        }
        self.token_units -= 1_000_000_000;
        true
    }
}

/// Atomic byte budget and an RAII reservation within it.
///
/// A custom counter is used instead of a semaphore because WebRTC frames grow
/// incrementally and the accounting must resize without queueing an unbounded
/// number of waiters.
struct ByteBudget {
    limit: usize,
    in_use: AtomicUsize,
}

impl ByteBudget {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            in_use: AtomicUsize::new(0),
        }
    }

    fn try_acquire(
        self: &Arc<Self>,
        amount: usize,
        error: &'static str,
    ) -> ServerResult<ByteReservation> {
        self.in_use
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(amount)
                    .filter(|next| *next <= self.limit)
            })
            .map_err(|_| error.to_string())?;
        Ok(ByteReservation {
            budget: Arc::clone(self),
            amount,
            error,
        })
    }

    #[cfg(test)]
    fn in_use(&self) -> usize {
        self.in_use.load(Ordering::Acquire)
    }
}

struct ByteReservation {
    budget: Arc<ByteBudget>,
    amount: usize,
    error: &'static str,
}

impl ByteReservation {
    fn try_grow(&mut self, amount: usize) -> ServerResult<()> {
        self.budget
            .in_use
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(amount)
                    .filter(|next| *next <= self.budget.limit)
            })
            .map_err(|_| self.error.to_string())?;
        self.amount += amount;
        Ok(())
    }

    fn shrink(&mut self, amount: usize) {
        let released = amount.min(self.amount);
        self.amount -= released;
        self.budget.in_use.fetch_sub(released, Ordering::AcqRel);
    }
}

impl Drop for ByteReservation {
    fn drop(&mut self) {
        self.budget.in_use.fetch_sub(self.amount, Ordering::AcqRel);
    }
}

struct InFlightByteReservation {
    source: ByteReservation,
    global: ByteReservation,
}

impl InFlightByteReservation {
    fn try_grow(&mut self, amount: usize) -> ServerResult<()> {
        self.source.try_grow(amount)?;
        if let Err(error) = self.global.try_grow(amount) {
            self.source.shrink(amount);
            return Err(error);
        }
        Ok(())
    }

    fn resize(&mut self, amount: usize) -> ServerResult<()> {
        if amount > self.source.amount {
            self.try_grow(amount - self.source.amount)
        } else {
            let released = self.source.amount - amount;
            self.source.shrink(released);
            self.global.shrink(released);
            Ok(())
        }
    }
}

struct TrackedBytes {
    bytes: Vec<u8>,
    reservation: InFlightByteReservation,
}

impl TrackedBytes {
    fn reserve_length(&mut self, length: usize) -> ServerResult<()> {
        self.reservation.resize(length)?;
        if self.bytes.capacity() < length {
            self.bytes.reserve_exact(length - self.bytes.len());
        }
        Ok(())
    }
}

struct SourceQuota {
    request_rate: Mutex<RequestRateBucket>,
    bytes: Arc<ByteBudget>,
}

struct SourceEntry {
    active_connections: usize,
    last_seen: Instant,
    quota: Arc<SourceQuota>,
}

#[derive(Default)]
struct SourceAdmissionState {
    sources: HashMap<IpAddr, SourceEntry>,
}

/// Admission and accounting shared by every association on one listener.
struct ListenerResources {
    connection_limit: Arc<Semaphore>,
    channel_limit: Arc<Semaphore>,
    request_limit: Arc<Semaphore>,
    global_request_rate: Mutex<RequestRateBucket>,
    global_bytes: Arc<ByteBudget>,
    source_state: Mutex<SourceAdmissionState>,
    max_connections_per_ip: usize,
    max_requests_per_second_per_ip: usize,
    max_requests_per_second_per_connection: usize,
    max_in_flight_bytes_per_ip: usize,
    max_tracked_sources: usize,
}

impl ListenerResources {
    fn new(config: &WebRtcDirectConfig) -> Arc<Self> {
        Arc::new(Self {
            connection_limit: Arc::new(Semaphore::new(config.max_connections)),
            channel_limit: Arc::new(Semaphore::new(config.max_channels)),
            request_limit: Arc::new(Semaphore::new(config.max_concurrent_requests)),
            global_request_rate: Mutex::new(RequestRateBucket::new(config.max_requests_per_second)),
            global_bytes: Arc::new(ByteBudget::new(config.max_in_flight_bytes)),
            source_state: Mutex::new(SourceAdmissionState::default()),
            max_connections_per_ip: config.max_connections_per_ip,
            max_requests_per_second_per_ip: config.max_requests_per_second_per_ip,
            max_requests_per_second_per_connection: config.max_requests_per_second_per_connection,
            max_in_flight_bytes_per_ip: config.max_in_flight_bytes_per_ip,
            max_tracked_sources: config
                .max_connections
                .saturating_mul(TRACKED_SOURCE_MULTIPLIER)
                .max(MIN_TRACKED_SOURCES),
        })
    }

    fn try_admit_connection(
        self: &Arc<Self>,
        remote_addr: SocketAddr,
    ) -> ServerResult<ConnectionAdmission> {
        let global = Arc::clone(&self.connection_limit)
            .try_acquire_owned()
            .map_err(|_| CONNECTION_CAPACITY_ERROR.to_string())?;
        let ip = canonical_source_ip(remote_addr.ip());
        let source = {
            let mut state = self.source_state.lock();
            if !state.sources.contains_key(&ip) && state.sources.len() >= self.max_tracked_sources {
                let eviction = state
                    .sources
                    .iter()
                    .filter(|(_, entry)| entry.active_connections == 0)
                    .min_by_key(|(_, entry)| entry.last_seen)
                    .map(|(ip, _)| *ip);
                let Some(eviction) = eviction else {
                    return Err(CONNECTION_CAPACITY_ERROR.to_string());
                };
                state.sources.remove(&eviction);
            }

            let entry = state.sources.entry(ip).or_insert_with(|| SourceEntry {
                active_connections: 0,
                last_seen: Instant::now(),
                quota: Arc::new(SourceQuota {
                    request_rate: Mutex::new(RequestRateBucket::new(
                        self.max_requests_per_second_per_ip,
                    )),
                    bytes: Arc::new(ByteBudget::new(self.max_in_flight_bytes_per_ip)),
                }),
            });
            if entry.active_connections >= self.max_connections_per_ip {
                return Err(SOURCE_CONNECTION_CAPACITY_ERROR.to_string());
            }
            entry.active_connections += 1;
            entry.last_seen = Instant::now();
            Arc::clone(&entry.quota)
        };
        let context = Arc::new(ConnectionResources {
            listener: Arc::clone(self),
            source,
            request_rate: Mutex::new(RequestRateBucket::new(
                self.max_requests_per_second_per_connection,
            )),
        });
        Ok(ConnectionAdmission {
            listener: Arc::clone(self),
            ip,
            context,
            _global: global,
        })
    }

    fn release_connection(&self, ip: IpAddr) {
        let mut state = self.source_state.lock();
        if let Some(entry) = state.sources.get_mut(&ip) {
            entry.active_connections = entry.active_connections.saturating_sub(1);
            entry.last_seen = Instant::now();
        }
    }
}

struct ConnectionResources {
    listener: Arc<ListenerResources>,
    source: Arc<SourceQuota>,
    request_rate: Mutex<RequestRateBucket>,
}

impl ConnectionResources {
    fn try_admit_request(&self) -> ServerResult<OwnedSemaphorePermit> {
        let permit = Arc::clone(&self.listener.request_limit)
            .try_acquire_owned()
            .map_err(|_| REQUEST_CAPACITY_ERROR.to_string())?;
        let now = Instant::now();
        if !self.source.request_rate.lock().allow(now)
            || !self.request_rate.lock().allow(now)
            || !self.listener.global_request_rate.lock().allow(now)
        {
            return Err(REQUEST_RATE_ERROR.to_string());
        }
        Ok(permit)
    }

    fn try_reserve_bytes(&self, amount: usize) -> ServerResult<InFlightByteReservation> {
        let source = self
            .source
            .bytes
            .try_acquire(amount, SOURCE_BYTE_CAPACITY_ERROR)?;
        let global = self
            .listener
            .global_bytes
            .try_acquire(amount, GLOBAL_BYTE_CAPACITY_ERROR)?;
        Ok(InFlightByteReservation { source, global })
    }
}

struct ConnectionAdmission {
    listener: Arc<ListenerResources>,
    ip: IpAddr,
    context: Arc<ConnectionResources>,
    _global: OwnedSemaphorePermit,
}

impl Drop for ConnectionAdmission {
    fn drop(&mut self) {
        self.listener.release_connection(self.ip);
    }
}

fn canonical_source_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        IpAddr::V4(ip) => IpAddr::V4(ip),
    }
}

/// A running browser listener and the endpoint clients use to reach it.
pub struct WebRtcDirectServer {
    /// Direct endpoint with its certificate pin embedded in the multiaddress.
    pub endpoint: BrowserEndpoint,
    /// Listener background task.
    pub task: JoinHandle<()>,
}

/// Start the feature-gated browser listener and return its endpoint and task.
pub async fn spawn(
    config: &WebRtcDirectConfig,
    root_dir: &Path,
    p2p: Arc<P2PNode>,
    ant_protocol: Option<Arc<AntProtocol>>,
    evm_network: &evmlib::Network,
    shutdown: CancellationToken,
    endpoint_catalog: Option<Arc<BrowserEndpointCatalog>>,
) -> Result<WebRtcDirectServer> {
    validate_webrtc_config(config)?;
    let certificate_path = certificate_path(config, root_dir);
    let certificate = load_or_generate_certificate(&certificate_path).await?;
    let certificate_sha256 = certificate
        .sha256_digest()
        .map_err(|error| Error::Startup(error.to_string()))?;
    let listener = WebRtcDirectListener::bind(config.bind, certificate)
        .await
        .map_err(|error| {
            Error::Startup(format!("failed to bind WebRTC Direct listener: {error}"))
        })?;
    let local_addr = listener.local_addr();
    let advertised_addr = advertised_addr(config, local_addr)?;
    let peer_id = *p2p.peer_id();
    let identity = Arc::clone(p2p.transport().node_identity());
    let browser_endpoint =
        BrowserEndpoint::new(advertised_addr, peer_id.to_bytes(), certificate_sha256)
            .map_err(|error| Error::Config(error.to_string()))?;
    let supplemental_endpoint = browser_endpoint.multiaddr.parse().map_err(|error| {
        Error::Startup(format!(
            "shared WebRTC endpoint codec produced an invalid transport address: {error}"
        ))
    })?;
    persist_browser_endpoint(root_dir, &browser_endpoint).await?;
    if let Some(catalog) = endpoint_catalog.as_ref() {
        catalog.insert(peer_id, browser_endpoint.clone());
    }
    let state = Arc::new(ServerState {
        config: config.clone(),
        identity,
        p2p: Arc::clone(&p2p),
        ant_protocol,
        payment: browser_payment_network(evm_network),
        endpoint: browser_endpoint.clone(),
        endpoint_catalog,
    });
    let resources = ListenerResources::new(config);

    info!(
        bind = %local_addr,
        multiaddr = %browser_endpoint.multiaddr,
        certificate = %certificate_path.display(),
        "ADR-0009 WebRTC Direct listening"
    );

    let task = tokio::spawn(serve_webrtc(listener, state, resources, shutdown));
    p2p.dht_manager()
        .set_supplemental_self_addresses(vec![supplemental_endpoint])
        .await;
    Ok(WebRtcDirectServer {
        endpoint: browser_endpoint,
        task,
    })
}

async fn persist_browser_endpoint(root_dir: &Path, endpoint: &BrowserEndpoint) -> Result<()> {
    let path = root_dir.join(WEBRTC_DIRECT_MULTIADDR_FILENAME);
    let contents = format!("{}\n", endpoint.multiaddr);
    tokio::fs::write(&path, contents).await.map_err(|error| {
        Error::Startup(format!(
            "failed to write WebRTC Direct endpoint {}: {error}",
            path.display()
        ))
    })
}

fn validate_webrtc_config(config: &WebRtcDirectConfig) -> Result<()> {
    for (name, value) in [
        ("max_connections", config.max_connections),
        ("max_connections_per_ip", config.max_connections_per_ip),
        (
            "max_channels_per_connection",
            config.max_channels_per_connection,
        ),
        ("max_channels", config.max_channels),
        ("max_concurrent_requests", config.max_concurrent_requests),
    ] {
        if value == 0 || value > Semaphore::MAX_PERMITS {
            return Err(Error::Config(format!(
                "webrtc_direct.{name} must be between 1 and {}",
                Semaphore::MAX_PERMITS
            )));
        }
    }
    for (name, value) in [
        ("max_requests_per_second", config.max_requests_per_second),
        (
            "max_requests_per_second_per_ip",
            config.max_requests_per_second_per_ip,
        ),
        (
            "max_requests_per_second_per_connection",
            config.max_requests_per_second_per_connection,
        ),
        ("max_in_flight_bytes", config.max_in_flight_bytes),
        (
            "max_in_flight_bytes_per_ip",
            config.max_in_flight_bytes_per_ip,
        ),
    ] {
        if value == 0 {
            return Err(Error::Config(format!(
                "webrtc_direct.{name} must be greater than zero"
            )));
        }
    }
    if config.max_connections_per_ip >= config.max_connections {
        return Err(Error::Config(
            "webrtc_direct.max_connections_per_ip must be lower than max_connections".to_string(),
        ));
    }
    let source_channel_ceiling = config
        .max_connections_per_ip
        .checked_mul(config.max_channels_per_connection)
        .ok_or_else(|| {
            Error::Config("webrtc_direct per-IP DataChannel ceiling overflows usize".to_string())
        })?;
    if source_channel_ceiling >= config.max_channels {
        return Err(Error::Config(
            "webrtc_direct max_connections_per_ip * max_channels_per_connection must be lower than max_channels"
                .to_string(),
        ));
    }
    if source_channel_ceiling >= config.max_concurrent_requests {
        return Err(Error::Config(
            "webrtc_direct max_connections_per_ip * max_channels_per_connection must be lower than max_concurrent_requests"
                .to_string(),
        ));
    }
    if config.max_requests_per_second_per_connection > config.max_requests_per_second_per_ip {
        return Err(Error::Config(
            "webrtc_direct.max_requests_per_second_per_connection must not exceed max_requests_per_second_per_ip"
                .to_string(),
        ));
    }
    if config.max_requests_per_second_per_ip >= config.max_requests_per_second {
        return Err(Error::Config(
            "webrtc_direct.max_requests_per_second_per_ip must be lower than max_requests_per_second"
                .to_string(),
        ));
    }
    if config.max_in_flight_bytes_per_ip >= config.max_in_flight_bytes {
        return Err(Error::Config(
            "webrtc_direct.max_in_flight_bytes_per_ip must be lower than max_in_flight_bytes"
                .to_string(),
        ));
    }
    if config.max_request_bytes == 0 || config.max_request_bytes > MAX_BROWSER_HEADER_BYTES {
        return Err(Error::Config(format!(
            "webrtc_direct.max_request_bytes must be between 1 and {MAX_BROWSER_HEADER_BYTES}"
        )));
    }
    if config.advertised_addr.is_some_and(|addr| addr.port() == 0) {
        return Err(Error::Config(
            "webrtc_direct.advertised_addr must not use port zero".to_string(),
        ));
    }
    Ok(())
}

fn certificate_path(config: &WebRtcDirectConfig, root_dir: &Path) -> PathBuf {
    match config.certificate_path.as_ref() {
        Some(path) if path.is_absolute() => path.clone(),
        Some(path) => root_dir.join(path),
        None => root_dir.join("webrtc-direct.pem"),
    }
}

async fn load_or_generate_certificate(path: &Path) -> Result<WebRtcCertificate> {
    match tokio::fs::read_to_string(path).await {
        Ok(pem) => WebRtcCertificate::from_pem(&pem).map_err(|error| {
            Error::Startup(format!(
                "failed to load WebRTC certificate {}: {error}",
                path.display()
            ))
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let certificate = WebRtcCertificate::generate().map_err(|error| {
                Error::Startup(format!("failed to generate WebRTC certificate: {error}"))
            })?;
            tokio::fs::write(path, certificate.serialize_pem()).await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
            }
            Ok(certificate)
        }
        Err(error) => Err(error.into()),
    }
}

fn advertised_addr(config: &WebRtcDirectConfig, local_addr: SocketAddr) -> Result<SocketAddr> {
    if let Some(addr) = config.advertised_addr {
        return Ok(addr);
    }
    if local_addr.ip().is_unspecified() {
        return Err(Error::Config(
            "webrtc_direct.advertised_addr is required for a wildcard bind".to_string(),
        ));
    }
    Ok(local_addr)
}

#[allow(clippy::significant_drop_tightening)]
async fn serve_webrtc(
    mut listener: WebRtcDirectListener,
    state: Arc<ServerState>,
    resources: Arc<ListenerResources>,
    shutdown: CancellationToken,
) {
    let mut connection_tasks = JoinSet::new();
    loop {
        let connection = tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            completed = connection_tasks.join_next(), if !connection_tasks.is_empty() => {
                if let Some(Err(error)) = completed {
                    warn!(%error, "WebRTC Direct connection task failed");
                }
                continue;
            }
            // Do not perform another ICE/DTLS/SCTP accept while every
            // application connection slot is occupied. The transport's
            // pending-association queue remains bounded, and completed
            // sessions release a permit before this branch becomes eligible.
            connection = listener.accept(), if resources.connection_limit.available_permits() > 0 => connection,
        };
        match connection {
            Ok(connection) => {
                let remote_addr = connection.remote_addr();
                let admission = match resources.try_admit_connection(remote_addr) {
                    Ok(admission) => admission,
                    Err(error) => {
                        debug!(remote = %remote_addr, %error, "Rejected WebRTC Direct connection");
                        if let Err(close_error) = connection.close().await {
                            debug!(remote = %remote_addr, %close_error, "Failed to close rejected connection");
                        }
                        continue;
                    }
                };
                let connection_resources = Arc::clone(&admission.context);
                let connection_state = Arc::clone(&state);
                let connection_shutdown = shutdown.clone();
                connection_tasks.spawn(async move {
                    let _admission = admission;
                    if let Err(error) = handle_connection(
                        connection,
                        connection_state,
                        connection_resources,
                        connection_shutdown,
                    )
                    .await
                    {
                        debug!(remote = %remote_addr, "WebRTC Direct connection ended: {error}");
                    }
                });
            }
            Err(error) => {
                warn!("WebRTC Direct listener error: {error}");
            }
        }
    }
    if let Err(error) = listener.close().await {
        debug!("WebRTC Direct listener close failed: {error}");
    }
    let drained = tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, async {
        while let Some(result) = connection_tasks.join_next().await {
            if let Err(error) = result {
                debug!(%error, "WebRTC Direct connection task failed during shutdown");
            }
        }
    })
    .await;
    if drained.is_err() {
        warn!("WebRTC Direct connection tasks did not drain before shutdown deadline");
        connection_tasks.abort_all();
        while connection_tasks.join_next().await.is_some() {}
    }
    info!("ADR-0009 WebRTC Direct stopped");
}

async fn handle_connection(
    mut connection: WebRtcDirectConnection,
    state: Arc<ServerState>,
    resources: Arc<ConnectionResources>,
    shutdown: CancellationToken,
) -> ServerResult<()> {
    let remote_addr = connection.remote_addr();
    let channel_shutdown = shutdown.child_token();
    let mut channel_tasks = JoinSet::new();
    let outcome = loop {
        let accepted = tokio::select! {
            biased;
            () = shutdown.cancelled() => break Ok(()),
            completed = channel_tasks.join_next(), if !channel_tasks.is_empty() => {
                if let Some(Err(error)) = completed {
                    debug!(remote = %remote_addr, %error, "WebRTC Direct DataChannel task failed");
                }
                // The v4 protocol uses persistent channels; it has no channel
                // reopen/continuation handshake. Once the last channel ends,
                // close the association promptly instead of retaining a stale
                // per-IP connection slot while waiting for another channel.
                if channel_tasks.is_empty() {
                    break Ok(());
                }
                continue;
            }
            result = connection.accept_data_channel() => result,
        };
        let channel = match accepted {
            Ok(channel) => channel,
            Err(error) => break Err(format!("DataChannel accept failed: {error}")),
        };
        if channel_tasks.len() >= state.config.max_channels_per_connection {
            if let Err(error) = channel.close().await {
                debug!(remote = %remote_addr, %error, "Failed to close excess DataChannel");
            }
            break Err("per-connection DataChannel capacity exhausted".to_string());
        }
        let Ok(channel_permit) = Arc::clone(&resources.listener.channel_limit).try_acquire_owned()
        else {
            if let Err(error) = channel.close().await {
                debug!(remote = %remote_addr, %error, "Failed to close excess DataChannel");
            }
            break Err(CHANNEL_CAPACITY_ERROR.to_string());
        };
        let channel_state = Arc::clone(&state);
        let channel_resources = Arc::clone(&resources);
        let handler_shutdown = channel_shutdown.clone();
        channel_tasks.spawn(async move {
            let _channel_permit = channel_permit;
            if let Err(error) = handle_webrtc_channel(
                &channel,
                channel_state,
                channel_resources,
                handler_shutdown,
            )
            .await
            {
                debug!(remote = %remote_addr, channel = channel.id(), "WebRTC Direct DataChannel ended: {error}");
            }
            if let Err(error) = channel.close().await {
                debug!(remote = %remote_addr, channel = channel.id(), %error, "Failed to close WebRTC Direct DataChannel");
            }
        });
    };

    // Stop every handler before returning its storage/P2P state. Closing the
    // association alone is not a sufficient wake-up guarantee for work that
    // is currently inside an application request.
    channel_shutdown.cancel();
    if let Err(error) = connection.close().await {
        debug!(remote = %remote_addr, %error, "Failed to close WebRTC Direct connection");
    }
    while let Some(result) = channel_tasks.join_next().await {
        if let Err(error) = result {
            debug!(remote = %remote_addr, %error, "WebRTC Direct DataChannel task failed during shutdown");
        }
    }
    outcome
}

#[allow(clippy::significant_drop_tightening, clippy::too_many_lines)]
async fn handle_webrtc_channel(
    channel: &WebRtcDataChannel,
    state: Arc<ServerState>,
    resources: Arc<ConnectionResources>,
    shutdown: CancellationToken,
) -> ServerResult<()> {
    if channel.label() != WEBRTC_DIRECT_DATA_CHANNEL {
        return Err(format!(
            "unsupported DataChannel label {:?}",
            channel.label()
        ));
    }

    let mut pq_session = tokio::select! {
        biased;
        () = shutdown.cancelled() => return Ok(()),
        result = establish_pq_session(channel, &state, &resources) => result?,
    };
    let mut hello_completed = false;
    loop {
        let admitted_result = tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            result = read_webrtc_request(
                channel,
                state.config.max_request_bytes,
                &mut pq_session,
                &resources,
            ) => result,
        };
        let admitted = match admitted_result {
            Ok(request) => request,
            Err(error) if is_quiet_channel_close(&error) => return Ok(()),
            Err(error) => {
                let response = Response::error(0, "invalid_request", error);
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => return Ok(()),
                    result = write_webrtc_response(
                        channel,
                        &mut pq_session,
                        &response,
                        None,
                        &resources,
                    ) => result?,
                }
                return Ok(());
            }
        };
        let AdmittedRequest {
            request,
            content,
            _request_permit,
            _in_flight_bytes,
        } = admitted;
        if request.version != BROWSER_PROTOCOL_VERSION {
            let response = Response::error(
                request.request_id,
                "unsupported_version",
                format!(
                    "protocol version {} is unsupported; expected {BROWSER_PROTOCOL_VERSION}",
                    request.version
                ),
            );
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(()),
                result = write_webrtc_response(
                    channel,
                    &mut pq_session,
                    &response,
                    None,
                    &resources,
                ) => result?,
            }
            continue;
        }

        let is_hello = matches!(&request.body, RequestBody::Hello);
        if !is_hello && !hello_completed {
            let response = Response::error(
                request.request_id,
                "authentication_required",
                "HELLO must initialize this encrypted WebRTC session first".to_string(),
            );
            tokio::select! {
                biased;
                () = shutdown.cancelled() => return Ok(()),
                result = write_webrtc_response(
                    channel,
                    &mut pq_session,
                    &response,
                    None,
                    &resources,
                ) => result?,
            }
            continue;
        }

        let (response, content) = tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            result = process_request(request, content, &state, &resources) => result?,
        };
        if is_hello && matches!(&response.status, ResponseStatus::Ok) {
            hello_completed = true;
        }
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return Ok(()),
            result = write_webrtc_response(
                channel,
                &mut pq_session,
                &response,
                content.as_ref(),
                &resources,
            ) => result?,
        }
    }
}

fn is_quiet_channel_close(error: &str) -> bool {
    matches!(
        error,
        "DataChannel closed"
            | "request idle timeout"
            | "request frame timed out"
            | REQUEST_CAPACITY_ERROR
            | REQUEST_RATE_ERROR
            | GLOBAL_BYTE_CAPACITY_ERROR
            | SOURCE_BYTE_CAPACITY_ERROR
    ) || error.starts_with("PQ session:")
}

async fn establish_pq_session(
    channel: &WebRtcDataChannel,
    state: &ServerState,
    resources: &ConnectionResources,
) -> ServerResult<PqSession> {
    let first_message = receive_first_message(channel, "PQ client hello idle timeout").await?;
    // The post-quantum handshake is deliberately charged to the same work and
    // rate envelopes as an RPC. Otherwise a source could churn channels and
    // force unmetered ML-KEM/ML-DSA work without ever sending a request.
    let _handshake_permit = resources.try_admit_request()?;
    let client_hello = read_pq_payload_after_first(
        first_message,
        channel,
        PQ_CLIENT_HELLO_BYTES,
        "PQ client hello timed out",
        resources,
    )
    .await?;
    let peer_id = *state.p2p.peer_id().to_bytes();
    let public_key = state.identity.public_key().as_bytes();
    let (server_accept, session) =
        accept_pq_session(&client_hello.bytes, &peer_id, public_key, |transcript| {
            state
                .identity
                .sign(transcript)
                .map(|signature| signature.as_bytes().to_vec())
        })
        .map_err(|error| format!("PQ session: {error}"))?;
    write_pq_payload(channel, &server_accept, resources).await?;
    Ok(session)
}

struct AdmittedRequest {
    request: Request,
    content: Vec<u8>,
    _request_permit: OwnedSemaphorePermit,
    _in_flight_bytes: InFlightByteReservation,
}

async fn read_webrtc_request(
    channel: &WebRtcDataChannel,
    max_header_bytes: usize,
    pq_session: &mut PqSession,
    resources: &ConnectionResources,
) -> ServerResult<AdmittedRequest> {
    let first_message = receive_first_message(channel, "request idle timeout").await?;
    // Admission happens as soon as a client starts a frame. Idle persistent
    // channels consume neither request-rate tokens nor request worker slots.
    let request_permit = resources.try_admit_request()?;
    let max_plaintext_bytes = 4 + max_header_bytes + MAX_CHUNK_SIZE;
    let mut encrypted = read_pq_payload_after_first(
        first_message,
        channel,
        max_plaintext_bytes + PQ_ENCRYPTED_OVERHEAD_BYTES,
        "request frame timed out",
        resources,
    )
    .await?;
    let encrypted_len = encrypted.bytes.len();
    // AEAD opening briefly holds ciphertext and plaintext at once. Reserve the
    // second buffer before asking the cryptographic layer to allocate it.
    encrypted.reservation.try_grow(encrypted_len)?;
    let frame = pq_session
        .open(&encrypted.bytes)
        .map_err(|error| format!("PQ session: {error}"))?;
    let TrackedBytes {
        bytes: encrypted_bytes,
        mut reservation,
    } = encrypted;
    drop(encrypted_bytes);
    reservation.resize(frame.len())?;

    let (request, content_offset) =
        parse_request_header(&frame, max_header_bytes).map_err(|error| error.to_string())?;
    let content_len = frame.len() - content_offset;
    let accounted_request_bytes = frame.len();
    // serde owns the parsed header and the body copy below owns the content.
    // Account the copy while the complete plaintext frame is still live, then
    // retain one frame-sized reservation for the parsed request's lifetime.
    reservation.try_grow(content_len)?;
    let content = frame[content_offset..].to_vec();
    drop(frame);
    reservation.resize(accounted_request_bytes)?;
    Ok(AdmittedRequest {
        request,
        content,
        _request_permit: request_permit,
        _in_flight_bytes: reservation,
    })
}

async fn receive_first_message(
    channel: &WebRtcDataChannel,
    idle_timeout_message: &str,
) -> ServerResult<Vec<u8>> {
    let message = tokio::time::timeout(REQUEST_IDLE_TIMEOUT, channel.receive())
        .await
        .map_err(|_| idle_timeout_message.to_string())?
        .map_err(|error| format!("DataChannel message read failed: {error}"))?;
    if message.is_empty() {
        return Err("DataChannel closed".to_string());
    }
    Ok(message)
}

async fn read_pq_payload_after_first(
    first_message: Vec<u8>,
    channel: &WebRtcDataChannel,
    max_payload_bytes: usize,
    frame_timeout_message: &str,
    resources: &ConnectionResources,
) -> ServerResult<TrackedBytes> {
    let frame_started = tokio::time::Instant::now();
    let mut frame_deadline = frame_started + transfer_timeout(PQ_FRAME_PREFIX_BYTES);
    let mut frame = TrackedBytes {
        reservation: resources.try_reserve_bytes(first_message.len())?,
        bytes: first_message,
    };
    let mut expected_length = None;
    let max_frame_bytes = 4usize
        .checked_add(max_payload_bytes)
        .ok_or_else(|| "PQ frame limit overflow".to_string())?;
    loop {
        if frame.bytes.len() > max_frame_bytes {
            return Err(format!(
                "request exceeds the {max_frame_bytes}-byte frame limit"
            ));
        }

        if expected_length.is_none() {
            expected_length = pq_frame_length(&frame.bytes, max_payload_bytes)
                .map_err(|error| format!("PQ session: {error}"))?;
            if let Some(length) = expected_length {
                if frame.bytes.len() > length {
                    return Err("PQ frame contains bytes after its declared payload".to_string());
                }
                // Reserve the complete declared frame before accepting a slow
                // body. A sender cannot make many partial 4 MiB frames consume
                // unaccounted memory during their transfer windows.
                frame.reserve_length(length)?;
                frame_deadline = frame_started + transfer_timeout(length);
            }
        }

        if let Some(length) = expected_length {
            if frame.bytes.len() == length {
                let payload_len = length - PQ_FRAME_PREFIX_BYTES;
                frame.reservation.try_grow(payload_len)?;
                let payload = decode_pq_frame(&frame.bytes, max_payload_bytes)
                    .map_err(|error| format!("PQ session: {error}"))?;
                let TrackedBytes {
                    bytes: encoded_frame,
                    mut reservation,
                } = frame;
                drop(encoded_frame);
                reservation.resize(payload.len())?;
                return Ok(TrackedBytes {
                    bytes: payload,
                    reservation,
                });
            }
        }

        let message = tokio::time::timeout_at(frame_deadline, channel.receive())
            .await
            .map_err(|_| frame_timeout_message.to_string())?
            .map_err(|error| format!("DataChannel message read failed: {error}"))?;
        if message.is_empty() {
            return Err("DataChannel closed".to_string());
        }
        let next_length = frame
            .bytes
            .len()
            .checked_add(message.len())
            .ok_or_else(|| "PQ frame length overflow".to_string())?;
        if next_length > max_frame_bytes
            || expected_length.is_some_and(|length| next_length > length)
        {
            return Err("PQ frame contains bytes after its declared payload".to_string());
        }
        if expected_length.is_none() {
            frame.reserve_length(next_length)?;
        }
        frame.bytes.extend_from_slice(&message);
    }
}

async fn write_webrtc_response(
    channel: &WebRtcDataChannel,
    pq_session: &mut PqSession,
    response: &Response,
    content: Option<&TrackedBytes>,
    resources: &ConnectionResources,
) -> ServerResult<()> {
    // GET content carries its own reservation from before the storage read.
    // This reservation accounts only the new header, plaintext, and ciphertext
    // allocations made while encoding the response.
    let content = content.map_or(&[][..], |tracked| tracked.bytes.as_slice());
    let encode_reservation = 4usize
        .checked_add(MAX_BROWSER_HEADER_BYTES.saturating_mul(2))
        .and_then(|length| length.checked_add(content.len()))
        .ok_or_else(|| "response frame length overflow".to_string())?;
    let mut reservation = resources.try_reserve_bytes(encode_reservation)?;
    let plaintext = encode_response_frame(response, content).map_err(|error| error.to_string())?;
    reservation.resize(plaintext.len())?;
    let encrypted_len = plaintext
        .len()
        .checked_add(PQ_ENCRYPTED_OVERHEAD_BYTES)
        .ok_or_else(|| "encrypted response length overflow".to_string())?;
    reservation.try_grow(encrypted_len)?;
    let encrypted = pq_session
        .seal(&plaintext)
        .map_err(|error| format!("PQ session: {error}"))?;
    drop(plaintext);
    reservation.resize(content.len() + encrypted.len())?;
    write_framed_pq_payload(channel, &encrypted).await
}

async fn write_pq_payload(
    channel: &WebRtcDataChannel,
    payload: &[u8],
    resources: &ConnectionResources,
) -> ServerResult<()> {
    let _reservation = resources.try_reserve_bytes(payload.len())?;
    write_framed_pq_payload(channel, payload).await
}

async fn write_framed_pq_payload(channel: &WebRtcDataChannel, payload: &[u8]) -> ServerResult<()> {
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| "PQ session: payload length does not fit u32".to_string())?;
    let framed_len = PQ_FRAME_PREFIX_BYTES
        .checked_add(payload.len())
        .ok_or_else(|| "PQ response frame length overflow".to_string())?;
    let deadline = tokio::time::Instant::now() + transfer_timeout(framed_len);
    tokio::time::timeout_at(deadline, channel.send(&payload_len.to_be_bytes()))
        .await
        .map_err(|_| "response frame timed out".to_string())?
        .map_err(|error| format!("response message write failed: {error}"))?;
    for chunk in payload.chunks(WEBRTC_WRITE_CHUNK_BYTES) {
        tokio::time::timeout_at(deadline, channel.send(chunk))
            .await
            .map_err(|_| "response frame timed out".to_string())?
            .map_err(|error| format!("response message write failed: {error}"))?;
    }
    Ok(())
}

async fn process_request(
    request: Request,
    content: Vec<u8>,
    state: &ServerState,
    resources: &ConnectionResources,
) -> ServerResult<(Response, Option<TrackedBytes>)> {
    if !matches!(&request.body, RequestBody::PutChunk { .. }) && !content.is_empty() {
        return Ok((
            Response::error(
                request.request_id,
                "unexpected_content",
                "only put_chunk accepts binary request content".to_string(),
            ),
            None,
        ));
    }
    match request.body {
        RequestBody::Hello => {
            let peer_id = state.p2p.peer_id().to_hex();
            Ok((
                Response::ok(
                    request.request_id,
                    ResponseBody::Hello {
                        protocol: BROWSER_PROTOCOL_NAME.to_string(),
                        peer_id,
                        max_chunk_size: MAX_CHUNK_SIZE,
                        endpoint: state.endpoint.clone(),
                        payment: state.payment.clone(),
                        capabilities: vec![
                            "find_node".to_string(),
                            "get_chunk".to_string(),
                            "quote_chunk".to_string(),
                            "put_chunk".to_string(),
                        ],
                    },
                    0,
                ),
                None,
            ))
        }
        RequestBody::FindNode { target, count } => {
            Ok(process_find_node(request.request_id, target, count, state).await)
        }
        RequestBody::GetChunk { address } => {
            process_get_chunk(request.request_id, address, state, resources).await
        }
        RequestBody::QuoteChunk { address, size } => {
            Ok(process_quote_chunk(request.request_id, address, size, state).await)
        }
        RequestBody::PutChunk {
            address,
            quote,
            transaction_hash,
        } => Ok(process_put_chunk(
            request.request_id,
            address,
            *quote,
            transaction_hash,
            content,
            state,
        )
        .await),
    }
}

async fn process_find_node(
    request_id: u64,
    target: String,
    count: Option<usize>,
    state: &ServerState,
) -> (Response, Option<TrackedBytes>) {
    let target_bytes = match decode_32_byte_hex(&target) {
        Ok(bytes) => bytes,
        Err(error) => return (Response::error(request_id, "invalid_target", error), None),
    };
    let count = count
        .unwrap_or(MAX_FIND_NODE_RESULTS)
        .clamp(1, MAX_FIND_NODE_RESULTS);
    let dht = state.p2p.dht_manager();
    let dht_nodes = dht
        .find_closest_nodes_local_with_self(&target_bytes, count)
        .await;
    let mut nodes = Vec::with_capacity(dht_nodes.len());
    for node in dht_nodes {
        let supplemental = dht.supplemental_addresses_for_peer(&node.peer_id).await;
        nodes.push(browser_node_from_dht(
            &node,
            &supplemental,
            state.endpoint_catalog.as_deref(),
        ));
    }
    (
        Response::ok(request_id, ResponseBody::Nodes { target, nodes }, 0),
        None,
    )
}

fn browser_node_from_dht(
    node: &DHTNode,
    supplemental: &[MultiAddr],
    endpoint_catalog: Option<&BrowserEndpointCatalog>,
) -> BrowserNode {
    let addresses = node.addresses_by_priority();
    let discovered_endpoint = supplemental
        .iter()
        .find(|address| {
            address.is_webrtc_direct()
                && address.peer_id().is_some_and(|peer| peer == &node.peer_id)
        })
        .cloned()
        .map(|multiaddr| BrowserEndpoint {
            multiaddr: multiaddr.to_string(),
        });
    BrowserNode {
        webrtc_direct: discovered_endpoint
            .or_else(|| endpoint_catalog.and_then(|catalog| catalog.get(&node.peer_id))),
        peer_id: node.peer_id.to_hex(),
        native_addresses: addresses
            .into_iter()
            .filter(|address| !address.is_webrtc_direct())
            .map(|address| address.to_string())
            .collect(),
        reliability: node.reliability,
    }
}

async fn process_get_chunk(
    request_id: u64,
    address: String,
    state: &ServerState,
    resources: &ConnectionResources,
) -> ServerResult<(Response, Option<TrackedBytes>)> {
    let address_bytes = match decode_32_byte_hex(&address) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Ok((Response::error(request_id, "invalid_address", error), None));
        }
    };
    let Some(ant_protocol) = state.ant_protocol.as_ref() else {
        return Ok((
            Response::error(
                request_id,
                "storage_disabled",
                "chunk storage is disabled on this node".to_string(),
            ),
            None,
        ));
    };

    // The storage API allocates its returned Vec internally, so reserve the
    // largest permitted chunk before awaiting it. This closes the interval in
    // which many concurrent GETs could materialize unaccounted full chunks.
    let mut content_reservation = resources.try_reserve_bytes(MAX_CHUNK_SIZE)?;
    let response = match ant_protocol.storage().get(&address_bytes).await {
        Ok(Some(content)) if content.len() <= MAX_CHUNK_SIZE => {
            let content_length = content.len();
            content_reservation.resize(content_length)?;
            Ok((
                Response::ok(
                    request_id,
                    ResponseBody::Chunk {
                        address,
                        size: content_length,
                    },
                    content_length,
                ),
                Some(TrackedBytes {
                    bytes: content,
                    reservation: content_reservation,
                }),
            ))
        }
        Ok(Some(content)) => Ok((
            Response::error(
                request_id,
                "oversize_chunk",
                format!(
                    "stored content is {} bytes; maximum is {MAX_CHUNK_SIZE}",
                    content.len()
                ),
            ),
            None,
        )),
        Ok(None) => Ok((Response::not_found(request_id, address), None)),
        Err(error) => Ok((
            Response::error(
                request_id,
                "storage_error",
                format!("chunk read failed: {error}"),
            ),
            None,
        )),
    };
    response
}

async fn process_quote_chunk(
    request_id: u64,
    address: String,
    size: u64,
    state: &ServerState,
) -> (Response, Option<TrackedBytes>) {
    let address_bytes = match decode_32_byte_hex(&address) {
        Ok(bytes) => bytes,
        Err(error) => return (Response::error(request_id, "invalid_address", error), None),
    };
    if size > MAX_CHUNK_SIZE as u64 {
        return (
            Response::error(
                request_id,
                "oversize_chunk",
                format!("chunk size {size} exceeds {MAX_CHUNK_SIZE}"),
            ),
            None,
        );
    }
    let Some(ant_protocol) = state.ant_protocol.as_ref() else {
        return (
            Response::error(
                request_id,
                "storage_disabled",
                "chunk storage is disabled on this node".to_string(),
            ),
            None,
        );
    };

    let message = ChunkMessage {
        request_id,
        body: ChunkMessageBody::QuoteRequest(ChunkQuoteRequest::new(address_bytes, size)),
    };
    let response = match handle_ant_message(ant_protocol, &message).await {
        Ok(response) => response,
        Err(error) => return (Response::error(request_id, "quote_failed", error), None),
    };
    match response.body {
        ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Success {
            quote,
            already_stored,
            commitment,
        }) => {
            let quote: PaymentQuote = match rmp_serde::from_slice(&quote) {
                Ok(quote) => quote,
                Err(error) => {
                    return (
                        Response::error(
                            request_id,
                            "invalid_quote",
                            format!("node generated an invalid quote: {error}"),
                        ),
                        None,
                    )
                }
            };
            let artifact = match browser_quote_from_quote(
                state.p2p.peer_id(),
                &quote,
                commitment.as_deref(),
            ) {
                Ok(artifact) => artifact,
                Err(error) => return (Response::error(request_id, "invalid_quote", error), None),
            };
            (
                Response::ok(
                    request_id,
                    ResponseBody::StorageQuote {
                        address,
                        already_stored,
                        quote: artifact,
                    },
                    0,
                ),
                None,
            )
        }
        ChunkMessageBody::QuoteResponse(ChunkQuoteResponse::Error(error)) => (
            Response::error(request_id, "quote_rejected", error.to_string()),
            None,
        ),
        other => (
            Response::error(
                request_id,
                "invalid_quote_response",
                format!("unexpected storage response: {other:?}"),
            ),
            None,
        ),
    }
}

async fn process_put_chunk(
    request_id: u64,
    address: String,
    quote: BrowserQuoteArtifact,
    transaction_hash: String,
    content: Vec<u8>,
    state: &ServerState,
) -> (Response, Option<TrackedBytes>) {
    let address_bytes = match decode_32_byte_hex(&address) {
        Ok(bytes) => bytes,
        Err(error) => return (Response::error(request_id, "invalid_address", error), None),
    };
    let Some(ant_protocol) = state.ant_protocol.as_ref() else {
        return (
            Response::error(
                request_id,
                "storage_disabled",
                "chunk storage is disabled on this node".to_string(),
            ),
            None,
        );
    };
    let proof = match build_payment_proof(address_bytes, quote, &transaction_hash) {
        Ok(proof) => proof,
        Err(error) => {
            return (
                Response::error(request_id, "invalid_payment_proof", error),
                None,
            )
        }
    };

    let message = ChunkMessage {
        request_id,
        body: ChunkMessageBody::PutRequest(ChunkPutRequest::with_payment(
            address_bytes,
            bytes::Bytes::from(content),
            proof,
        )),
    };
    let response = match handle_ant_message(ant_protocol, &message).await {
        Ok(response) => response,
        Err(error) => return (Response::error(request_id, "put_failed", error), None),
    };
    match response.body {
        ChunkMessageBody::PutResponse(ChunkPutResponse::Success { address }) => (
            Response::ok(
                request_id,
                ResponseBody::ChunkStored {
                    address: hex::encode(address),
                    already_stored: false,
                },
                0,
            ),
            None,
        ),
        ChunkMessageBody::PutResponse(ChunkPutResponse::AlreadyExists { address }) => (
            Response::ok(
                request_id,
                ResponseBody::ChunkStored {
                    address: hex::encode(address),
                    already_stored: true,
                },
                0,
            ),
            None,
        ),
        ChunkMessageBody::PutResponse(ChunkPutResponse::PaymentRequired { message }) => (
            Response::error(request_id, "payment_required", message),
            None,
        ),
        ChunkMessageBody::PutResponse(ChunkPutResponse::Error(error)) => (
            Response::error(request_id, "put_rejected", error.to_string()),
            None,
        ),
        other => (
            Response::error(
                request_id,
                "invalid_put_response",
                format!("unexpected storage response: {other:?}"),
            ),
            None,
        ),
    }
}

fn build_payment_proof(
    expected_content: [u8; 32],
    quote: BrowserQuoteArtifact,
    transaction_hash: &str,
) -> ServerResult<Vec<u8>> {
    let (peer_id, payment_quote, commitment) =
        payment_quote_from_browser_quote(quote, expected_content)?;
    let transaction_hash = TxHash::from_str(transaction_hash)
        .map_err(|error| format!("invalid EVM transaction hash: {error}"))?;
    let proof = PaymentProof {
        proof_of_payment: ProofOfPayment {
            peer_quotes: vec![(EncodedPeerId::new(peer_id), payment_quote)],
        },
        tx_hashes: vec![transaction_hash],
        commitment_sidecars: commitment.into_iter().collect(),
    };
    serialize_single_node_proof(&proof)
        .map_err(|error| format!("failed to serialize payment proof: {error}"))
}

async fn handle_ant_message(
    ant_protocol: &AntProtocol,
    message: &ChunkMessage,
) -> ServerResult<ChunkMessage> {
    let encoded = message
        .encode()
        .map_err(|error| format!("storage request encoding failed: {error}"))?;
    let response = ant_protocol
        .try_handle_request(&encoded)
        .await
        .map_err(|error| format!("storage request failed: {error}"))?
        .ok_or_else(|| "storage handler returned no response".to_string())?;
    ChunkMessage::decode(&response)
        .map_err(|error| format!("storage response decoding failed: {error}"))
}

fn decode_32_byte_hex(value: &str) -> ServerResult<[u8; 32]> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(value).map_err(|error| format!("expected hexadecimal: {error}"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("expected 32 bytes, received {}", bytes.len()))
}

type ServerResult<T> = std::result::Result<T, String>;

fn browser_quote_from_quote(
    peer_id: &PeerId,
    quote: &PaymentQuote,
    commitment: Option<&[u8]>,
) -> ServerResult<BrowserQuoteArtifact> {
    let timestamp_secs = quote
        .timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|error| format!("quote timestamp predates the Unix epoch: {error}"))?
        .as_secs();
    let commitment = commitment.map(browser_commitment_from_bytes).transpose()?;
    Ok(BrowserQuoteArtifact {
        peer_id: peer_id.to_hex(),
        content: hex::encode(quote.content.0),
        timestamp_secs,
        price: quote.price.to_string(),
        rewards_address: format!("{:?}", quote.rewards_address),
        public_key: hex::encode(&quote.pub_key),
        signature: hex::encode(&quote.signature),
        committed_key_count: quote.committed_key_count,
        commitment_pin: quote.commitment_pin.map(hex::encode),
        quote_hash: hex::encode(quote.hash()),
        commitment,
    })
}

fn payment_quote_from_browser_quote(
    artifact: BrowserQuoteArtifact,
    expected_content: [u8; 32],
) -> ServerResult<([u8; 32], PaymentQuote, Option<Vec<u8>>)> {
    let peer_id = decode_32_byte_hex(&artifact.peer_id)?;
    let content = decode_32_byte_hex(&artifact.content)?;
    if content != expected_content {
        return Err("payment quote is for a different chunk address".to_string());
    }
    let price = Amount::from_str(&artifact.price)
        .map_err(|error| format!("payment quote has an invalid price: {error}"))?;
    let rewards_address = RewardsAddress::from_str(&artifact.rewards_address)
        .map_err(|error| format!("payment quote has an invalid rewards address: {error}"))?;
    let public_key = hex::decode(&artifact.public_key)
        .map_err(|error| format!("payment quote public key is not hexadecimal: {error}"))?;
    let signature = hex::decode(&artifact.signature)
        .map_err(|error| format!("payment quote signature is not hexadecimal: {error}"))?;
    let commitment_pin = artifact
        .commitment_pin
        .as_deref()
        .map(decode_32_byte_hex)
        .transpose()?;
    let timestamp = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(artifact.timestamp_secs))
        .ok_or_else(|| "payment quote timestamp is out of range".to_string())?;
    let quote = PaymentQuote {
        content: xor_name::XorName(content),
        timestamp,
        price,
        rewards_address,
        pub_key: public_key,
        signature,
        committed_key_count: artifact.committed_key_count,
        commitment_pin,
    };
    if hex::encode(quote.hash()) != artifact.quote_hash.to_ascii_lowercase() {
        return Err("payment quote hash does not match its signed fields".to_string());
    }
    let commitment = artifact
        .commitment
        .map(|artifact| {
            hex::decode(artifact.encoded)
                .map_err(|error| format!("commitment is not hexadecimal: {error}"))
        })
        .transpose()?;
    Ok((peer_id, quote, commitment))
}

fn browser_commitment_from_bytes(encoded: &[u8]) -> ServerResult<BrowserCommitmentArtifact> {
    let commitment: ::ant_protocol::payment::commitment::StorageCommitment =
        rmp_serde::from_slice(encoded)
            .map_err(|error| format!("node generated an invalid commitment: {error}"))?;
    Ok(BrowserCommitmentArtifact {
        encoded: hex::encode(encoded),
        root: hex::encode(commitment.root),
        key_count: commitment.key_count,
        sender_peer_id: hex::encode(commitment.sender_peer_id),
        sender_public_key: hex::encode(commitment.sender_public_key),
        signature: hex::encode(commitment.signature),
    })
}

struct ServerState {
    config: WebRtcDirectConfig,
    identity: Arc<NodeIdentity>,
    p2p: Arc<P2PNode>,
    ant_protocol: Option<Arc<AntProtocol>>,
    payment: BrowserPaymentNetwork,
    endpoint: BrowserEndpoint,
    endpoint_catalog: Option<Arc<BrowserEndpointCatalog>>,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::significant_drop_tightening
)]
mod tests {
    use super::*;

    #[test]
    fn default_resource_limits_preserve_headroom_for_other_sources() {
        let config = WebRtcDirectConfig::default();
        validate_webrtc_config(&config).expect("default resource limits");

        let source_channel_ceiling =
            config.max_connections_per_ip * config.max_channels_per_connection;
        assert!(config.max_connections_per_ip < config.max_connections);
        assert!(source_channel_ceiling < config.max_channels);
        assert!(source_channel_ceiling < config.max_concurrent_requests);
        assert!(config.max_requests_per_second_per_ip < config.max_requests_per_second);
        assert!(config.max_in_flight_bytes_per_ip < config.max_in_flight_bytes);
    }

    #[test]
    fn rejects_resource_limits_that_let_one_ip_exhaust_a_global_pool() {
        let mut config = WebRtcDirectConfig::default();
        config.max_connections_per_ip = config.max_connections;
        assert!(validate_webrtc_config(&config).is_err());

        let mut config = WebRtcDirectConfig::default();
        config.max_channels = config.max_connections_per_ip * config.max_channels_per_connection;
        assert!(validate_webrtc_config(&config).is_err());

        let mut config = WebRtcDirectConfig::default();
        config.max_in_flight_bytes_per_ip = config.max_in_flight_bytes;
        assert!(validate_webrtc_config(&config).is_err());
    }

    #[test]
    fn per_ip_connection_limit_cannot_starve_another_source() {
        let config = WebRtcDirectConfig::default();
        let resources = ListenerResources::new(&config);
        let attacker: SocketAddr = "198.51.100.1:1000".parse().expect("attacker address");
        let honest: SocketAddr = "203.0.113.2:2000".parse().expect("honest address");
        let mut attacker_admissions = Vec::new();

        for port in 0..config.max_connections_per_ip {
            let mut address = attacker;
            address.set_port(u16::try_from(port + 1).expect("test port"));
            attacker_admissions.push(
                resources
                    .try_admit_connection(address)
                    .expect("source share remains"),
            );
        }
        assert_eq!(attacker_admissions.len(), config.max_connections_per_ip);
        assert_eq!(
            resources.try_admit_connection(attacker).err().as_deref(),
            Some(SOURCE_CONNECTION_CAPACITY_ERROR)
        );
        let honest_admission = resources
            .try_admit_connection(honest)
            .expect("another source retains listener headroom");

        drop(attacker_admissions.pop());
        resources
            .try_admit_connection(attacker)
            .expect("released source slot is reusable");
        drop(honest_admission);
    }

    #[test]
    fn ipv4_mapped_ipv6_cannot_bypass_source_accounting() {
        let config = WebRtcDirectConfig::default();
        let resources = ListenerResources::new(&config);
        let v4: SocketAddr = "192.0.2.44:1000".parse().expect("IPv4 address");
        let mapped: SocketAddr = "[::ffff:192.0.2.44]:2000".parse().expect("mapped address");
        let mut admissions = vec![resources
            .try_admit_connection(v4)
            .expect("first connection")];
        for _ in 1..config.max_connections_per_ip {
            admissions.push(
                resources
                    .try_admit_connection(mapped)
                    .expect("mapped source share"),
            );
        }
        assert_eq!(admissions.len(), config.max_connections_per_ip);
        assert_eq!(
            resources.try_admit_connection(mapped).err().as_deref(),
            Some(SOURCE_CONNECTION_CAPACITY_ERROR)
        );
    }

    #[test]
    fn request_token_bucket_refills_without_growing_state() {
        let mut bucket = RequestRateBucket::new(2);
        let start = bucket.last_refill;
        assert!(bucket.allow(start));
        assert!(bucket.allow(start));
        assert!(!bucket.allow(start));
        assert!(bucket.allow(start + Duration::from_millis(500)));
        assert!(!bucket.allow(start + Duration::from_millis(500)));
        assert!(bucket.allow(start + Duration::from_secs(1)));
    }

    #[test]
    fn per_ip_request_rate_leaves_other_sources_admissible() {
        let config = WebRtcDirectConfig {
            max_requests_per_second: 4,
            max_requests_per_second_per_ip: 2,
            max_requests_per_second_per_connection: 2,
            ..WebRtcDirectConfig::default()
        };
        let resources = ListenerResources::new(&config);
        let attacker = resources
            .try_admit_connection("198.51.100.1:1000".parse().expect("attacker"))
            .expect("attacker connection");
        let honest = resources
            .try_admit_connection("203.0.113.2:2000".parse().expect("honest"))
            .expect("honest connection");

        assert!(attacker.context.try_admit_request().is_ok());
        assert!(attacker.context.try_admit_request().is_ok());
        assert_eq!(
            attacker.context.try_admit_request().err().as_deref(),
            Some(REQUEST_RATE_ERROR)
        );
        assert!(honest.context.try_admit_request().is_ok());
    }

    #[test]
    fn reconnecting_does_not_reset_the_source_request_bucket() {
        let config = WebRtcDirectConfig {
            max_requests_per_second: 100,
            max_requests_per_second_per_ip: 1,
            max_requests_per_second_per_connection: 1,
            ..WebRtcDirectConfig::default()
        };
        let resources = ListenerResources::new(&config);
        let address = "198.51.100.1:1000".parse().expect("source");
        let first = resources
            .try_admit_connection(address)
            .expect("first connection");
        assert!(first.context.try_admit_request().is_ok());
        drop(first);

        let replacement = resources
            .try_admit_connection(address)
            .expect("replacement connection");
        assert_eq!(
            replacement.context.try_admit_request().err().as_deref(),
            Some(REQUEST_RATE_ERROR)
        );
    }

    #[test]
    fn inactive_source_rate_state_has_a_hard_bound() {
        let config = WebRtcDirectConfig::default();
        let resources = ListenerResources::new(&config);
        for index in 0..resources.max_tracked_sources + 10 {
            let third = u8::try_from(index / 254).expect("third octet");
            let host = u8::try_from(index % 254 + 1).expect("host octet");
            let address = SocketAddr::from((Ipv4Addr::new(198, 51, third, host), 1000));
            drop(
                resources
                    .try_admit_connection(address)
                    .expect("sequential source"),
            );
        }
        assert_eq!(
            resources.source_state.lock().sources.len(),
            resources.max_tracked_sources
        );
    }

    #[test]
    fn byte_reservations_are_per_source_global_and_raii_released() {
        let config = WebRtcDirectConfig {
            max_in_flight_bytes: 256,
            max_in_flight_bytes_per_ip: 128,
            ..WebRtcDirectConfig::default()
        };
        let resources = ListenerResources::new(&config);
        let attacker = resources
            .try_admit_connection("198.51.100.1:1000".parse().expect("attacker"))
            .expect("attacker connection");
        let honest = resources
            .try_admit_connection("203.0.113.2:2000".parse().expect("honest"))
            .expect("honest connection");

        let attacker_bytes = attacker
            .context
            .try_reserve_bytes(128)
            .expect("attacker source budget");
        assert_eq!(resources.global_bytes.in_use(), 128);
        assert_eq!(
            attacker.context.try_reserve_bytes(1).err().as_deref(),
            Some(SOURCE_BYTE_CAPACITY_ERROR)
        );
        let honest_bytes = honest
            .context
            .try_reserve_bytes(64)
            .expect("another source retains byte headroom");
        assert_eq!(resources.global_bytes.in_use(), 192);

        drop(attacker_bytes);
        drop(honest_bytes);
        assert_eq!(resources.global_bytes.in_use(), 0);
        assert_eq!(attacker.context.source.bytes.in_use(), 0);
        assert_eq!(honest.context.source.bytes.in_use(), 0);
    }

    #[test]
    fn global_byte_rejection_rolls_back_the_source_reservation() {
        let config = WebRtcDirectConfig {
            max_in_flight_bytes: 100,
            max_in_flight_bytes_per_ip: 90,
            ..WebRtcDirectConfig::default()
        };
        let resources = ListenerResources::new(&config);
        let first = resources
            .try_admit_connection("198.51.100.1:1000".parse().expect("first"))
            .expect("first connection");
        let second = resources
            .try_admit_connection("203.0.113.2:2000".parse().expect("second"))
            .expect("second connection");
        let _first_bytes = first
            .context
            .try_reserve_bytes(60)
            .expect("first reservation");

        assert_eq!(
            second.context.try_reserve_bytes(50).err().as_deref(),
            Some(GLOBAL_BYTE_CAPACITY_ERROR)
        );
        assert_eq!(second.context.source.bytes.in_use(), 0);
        assert_eq!(resources.global_bytes.in_use(), 60);
    }

    #[test]
    fn derives_stable_high_port_from_native_port() {
        assert_eq!(automatic_webrtc_port(10_000), 42_768);
        assert_eq!(automatic_webrtc_port(10_001), 42_769);
        assert_eq!(automatic_webrtc_port(32_768), 49_152);
        assert_ne!(automatic_webrtc_port(40_000), 40_000);
    }

    #[test]
    fn resolves_default_public_listener_from_observed_ip() {
        let config = WebRtcDirectConfig::default();
        let resolved = resolve_automatic_config(
            &config,
            10_000,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
        );

        assert_eq!(resolved.bind, "0.0.0.0:42768".parse().expect("bind"));
        assert_eq!(
            resolved.advertised_addr,
            Some("203.0.113.7:42768".parse().expect("advertised"))
        );
    }

    #[test]
    fn explicit_listener_addresses_are_preserved() {
        let config = WebRtcDirectConfig {
            bind: "0.0.0.0:11000".parse().expect("bind"),
            advertised_addr: Some("198.51.100.4:11000".parse().expect("advertised")),
            ..WebRtcDirectConfig::default()
        };

        assert_eq!(
            resolve_automatic_config(&config, 10_000, None).bind,
            config.bind
        );
        assert_eq!(
            resolve_automatic_config(&config, 10_000, None).advertised_addr,
            config.advertised_addr
        );
    }

    #[test]
    fn parses_versioned_requests() {
        let request: Request = serde_json::from_str(
            r#"{"version":4,"request_id":7,"content_length":0,"type":"find_node","target":"0000000000000000000000000000000000000000000000000000000000000000","count":20}"#,
        )
        .expect("valid request");

        assert_eq!(request.version, BROWSER_PROTOCOL_VERSION);
        assert_eq!(request.request_id, 7);
        assert!(matches!(request.body, RequestBody::FindNode { .. }));
    }

    #[test]
    fn validates_fixed_width_hex() {
        assert_eq!(
            decode_32_byte_hex(&"ab".repeat(32)).expect("32 bytes"),
            [0xab; 32]
        );
        assert!(decode_32_byte_hex("abcd").is_err());
        assert!(decode_32_byte_hex(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn payment_quote_hash_vector_uses_evm_keccak256() {
        // Shared with ant-client-web's paymentQuoteHash test. ANT addresses use
        // BLAKE3, but the quote hash paid to the EVM vault is evmlib Keccak-256.
        assert_eq!(
            hex::encode(evmlib::cryptography::hash([0_u8, 1, 2, 3])),
            "d98f2e8134922f73748703c8e7084d42f13d2fa1439936ef5a3abcf5646fe83f"
        );
    }

    #[test]
    fn response_header_declares_raw_content_length() {
        let response = Response::ok(
            42,
            ResponseBody::Chunk {
                address: "11".repeat(32),
                size: 3,
            },
            3,
        );
        let value = serde_json::to_value(response).expect("serialize response");
        assert_eq!(value["version"], 4);
        assert_eq!(value["request_id"], 42);
        assert_eq!(value["status"], "ok");
        assert_eq!(value["content_length"], 3);
        assert_eq!(value["type"], "chunk");
    }

    #[test]
    fn derives_ipv6_advertised_address() {
        let config = WebRtcDirectConfig::default();
        let addr = advertised_addr(&config, "[::1]:23456".parse().expect("socket"))
            .expect("advertised address");
        assert_eq!(addr, "[::1]:23456".parse().expect("socket"));
    }

    #[tokio::test]
    async fn dtls_certificate_is_stable_across_reloads() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("webrtc-direct.pem");
        let first = load_or_generate_certificate(&path)
            .await
            .expect("generate certificate");
        let second = load_or_generate_certificate(&path)
            .await
            .expect("reload certificate");

        assert_eq!(
            first.sha256_digest().expect("first fingerprint"),
            second.sha256_digest().expect("second fingerprint")
        );
        assert!(path.exists());
    }

    #[tokio::test]
    async fn persists_canonical_browser_bootstrap_address() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let peer_id = PeerId::from_bytes([0x42; 32]);
        let endpoint = BrowserEndpoint::new(
            "203.0.113.7:11000".parse().expect("socket address"),
            peer_id.to_bytes(),
            [0x24; 32],
        )
        .expect("browser endpoint");

        persist_browser_endpoint(directory.path(), &endpoint)
            .await
            .expect("persist endpoint");

        let contents =
            tokio::fs::read_to_string(directory.path().join(WEBRTC_DIRECT_MULTIADDR_FILENAME))
                .await
                .expect("read endpoint file");
        assert_eq!(contents, format!("{}\n", endpoint.multiaddr));
    }

    #[test]
    fn find_node_exposes_propagated_webrtc_endpoint_separately() {
        let peer_id = PeerId::from_bytes([0x31; 32]);
        let endpoint = BrowserEndpoint::new(
            "203.0.113.9:42768".parse().expect("socket address"),
            peer_id.to_bytes(),
            [0x52; 32],
        )
        .expect("browser endpoint");
        let native = "/ip4/203.0.113.9/udp/10000/quic"
            .parse()
            .expect("native multiaddress");
        let node = DHTNode {
            peer_id,
            addresses: vec![native],
            address_types: Vec::new(),
            distance: None,
            reliability: 0.75,
        };

        let supplemental = endpoint
            .multiaddr
            .parse()
            .expect("WebRTC Direct multiaddress");
        let browser_node = browser_node_from_dht(&node, std::slice::from_ref(&supplemental), None);

        assert_eq!(browser_node.webrtc_direct, Some(endpoint));
        assert_eq!(
            browser_node.native_addresses,
            vec!["/ip4/203.0.113.9/udp/10000/quic"]
        );
    }

    #[test]
    fn production_find_node_does_not_use_dev_endpoint_catalog() {
        let peer_id = PeerId::from_bytes([0x32; 32]);
        let endpoint = BrowserEndpoint::new(
            "203.0.113.10:42768".parse().expect("socket address"),
            peer_id.to_bytes(),
            [0x53; 32],
        )
        .expect("browser endpoint");
        let node = DHTNode {
            peer_id,
            addresses: Vec::new(),
            address_types: Vec::new(),
            distance: None,
            reliability: 0.75,
        };
        let catalog = BrowserEndpointCatalog::default();
        catalog.insert(peer_id, endpoint.clone());

        let browser_node = browser_node_from_dht(&node, &[], None);

        assert!(browser_node.webrtc_direct.is_none());

        let devnet_node = browser_node_from_dht(&node, &[], Some(&catalog));
        assert_eq!(devnet_node.webrtc_direct, Some(endpoint));
    }
}
