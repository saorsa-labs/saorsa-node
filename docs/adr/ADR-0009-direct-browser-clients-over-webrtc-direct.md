# ADR-0009: Direct browser clients over WebRTC Direct

- **Status:** Proposed
- **Date:** 2026-08-03
- **Last amended:** 2026-09-03
- **Decision owners:** <pending>
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [W3C WebRTC](https://www.w3.org/TR/webrtc/),
  [WebRTC Data Channels](https://www.rfc-editor.org/rfc/rfc8831),
  [libp2p WebRTC Direct](https://github.com/libp2p/specs/blob/master/webrtc/webrtc-direct.md),
  [W3C WebTransport](https://www.w3.org/TR/webtransport/),
  [WebTransport over HTTP/3](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/)

## Context

Web applications must be able to act as full immutable-data clients: they
perform iterative closest-node lookup, download chunks, obtain and verify
storage quotes, pay, and upload chunks themselves. A node must not perform a
whole-network lookup, proxy chunk bytes, or hold a browser user's wallet key.
Ordinary bootstrap peers and end-to-end transport relays remain allowed;
application gateways do not.

The native node endpoint cannot be used by an unmodified browser. It speaks a
Saorsa-specific QUIC application protocol with ML-KEM/ML-DSA raw-public-key
authentication. Browsers do not expose arbitrary UDP or arbitrary QUIC. They
expose browser-controlled transports such as WebRTC and WebTransport, with
authentication and connection-establishment rules that applications cannot
bypass.

Nodes must remain easy to deploy. An operator must not need to acquire or
maintain a DNS name, obtain a public-CA certificate, or configure a signaling
service. Node software must generate and persist any browser-transport
credentials automatically.

Cold bootstrap must also remain decentralized and durable. A web client must
be able to start from a compiled-in list of self-contained, constant
multiaddresses even when that list or the installed web application is months
old. Loading a fresh bootstrap manifest over HTTPS must not be a prerequisite.
A bootstrap address may become unusable because the seed was retired or its
IP, port, or ANT identity actually changed, but it must not expire merely
because a browser transport routinely rotated a short-lived certificate.
Applications therefore ship several independent bootstrap addresses and may
revise them in later releases, but normal certificate maintenance must not
force such a release.

Many ordinary storage nodes also run behind NAT. Browser support must
distinguish an application gateway, which is rejected, from a transport relay
that forwards end-to-end encrypted traffic and is sometimes unavoidable on
the public Internet. The constant bootstrap set itself consists of stable,
publicly reachable seeds; NATed nodes are learned after bootstrap and use
direct ICE where possible or an end-to-end relay path.

This ADR records the intended production architecture and distinguishes it
from the repository's earlier, explicitly non-production WebTransport proof
of concept. That proof validated browser interoperability, request framing,
local DHT access, chunk downloads, and paid immutable uploads. It also exposed
the bootstrap-lifetime problem that caused the production transport decision
to be reconsidered.

## Decision Drivers

- Browsers perform Kademlia iteration and chunk integrity verification.
- Chunk data flows between the browser and the storing node, never through an
  application-level lookup/download gateway.
- A browser can cold-bootstrap from a compiled-in list of constant,
  self-contained multiaddresses without first fetching fresh configuration.
- Bootstrap addresses remain usable across routine node restarts and for
  substantially longer than one month; they do not contain routinely rotating
  certificate pins.
- Operators do not obtain or manage DNS names, public-CA certificates, or a
  node-specific signaling service.
- Browser transport keys and certificates are created and persisted by the
  node software without operator involvement.
- The existing post-quantum node-to-node port and wire protocols remain
  unchanged.
- A public browser protocol is narrow, versioned, bounded, and limited to
  immutable reads plus quote/payment-verified immutable writes.
- Wallet secrets remain inside the browser; nodes receive only normal signed
  quote artifacts, transaction hashes, and encrypted records.
- NATed nodes have an end-to-end direct or relay path without exposing
  plaintext to a signaling or relay peer.
- A 4 MiB chunk is transferred reliably with explicit fragmentation,
  backpressure, cancellation, and bounded buffering.
- Endpoint ownership remains bound to the node's persistent ML-DSA identity,
  and all browser RPC payloads use fresh ML-KEM-derived application keys even
  though WebRTC's DTLS connection establishment remains classical.

## Considered Options

1. **Expose the existing Saorsa QUIC endpoint.** Rejected because browser
   JavaScript cannot create an arbitrary QUIC connection or configure the
   current PQ raw-public-key handshake.
2. **Use HTTP/WebSocket gateways.** Rejected as the production architecture
   because the gateway would perform lookup or carry chunk data for the
   browser. It creates availability, bandwidth, privacy, and censorship
   chokepoints.
3. **Use WebSocket or WebTransport with Web PKI.** A DNS multiaddress and
   ordinary CA certificate can remain constant while certificates renew
   behind the hostname. This gives WebTransport an excellent byte-stream API,
   but it makes every browser-capable node depend on DNS and CA automation and
   therefore violates the deployment requirement.
4. **Use hash-pinned WebTransport with self-signed certificates.** This was the
   original choice and was the transport used by the repository's superseded
   PoC.
   WebTransport request/response streams, QUIC flow control, and cancellation
   fit 4 MiB chunk transfers well. It also needs no DNS or public CA. However,
   WebTransport limits hash-pinned certificates to a two-week validity period.
   Even with overlapping current and next pins, a month-old bootstrap
   multiaddress normally contains only retired pins. A client cannot learn the
   replacements through DHT iteration until one initial connection succeeds.
   Fetching a fresh HTTPS manifest would move bootstrap liveness to a separate
   WebPKI service and violate the constant-list requirement. This option is
   rejected as the production bootstrap and direct-node transport.
5. **Use ordinary signaled WebRTC.** WebRTC provides mature ICE/STUN/TURN NAT
   traversal and does not require the remote DTLS certificate to chain to a
   public CA. Conventional WebRTC nevertheless requires an out-of-band path to
   exchange SDP, ICE candidates, credentials, and certificate fingerprints
   for every connection. Making HTTPS or WebSocket signaling mandatory would
   introduce the DNS, CA, and signaling dependencies this decision excludes.
   Signaled WebRTC remains useful for connections to NATed nodes after the
   browser has already joined the network.
6. **Use libp2p WebRTC Direct.** This proves signaling-free
   browser-to-public-node WebRTC is practical, but it also adds a second peer
   identity, Noise, multistream negotiation, stream emulation, connection
   gating, and libp2p's mux lifecycle on top of DTLS/SCTP. Those layers are not
   used by the ANT RPC protocol, which already authenticates the persistent
   ML-DSA node identity. During the PoC, current JavaScript and Rust libp2p
   releases also disagreed about DataChannel close control (`FIN_ACK`), causing
   later RPCs on an otherwise healthy association to fail with unexpected EOF.
   Carrying vendored compatibility patches for an unnecessary wire stack is
   rejected.
7. **Use a Saorsa-owned WebRTC Direct profile (chosen).** A browser dials a
   public IP and UDP port
   directly, constructs the peer descriptions locally, and establishes an
   ICE-lite + DTLS + SCTP association without a signaling server. The
   multiaddress contains a stable DTLS certificate fingerprint and the
   expected ANT peer ID. Unlike WebTransport's hash-pinned certificate, the
   remote WebRTC certificate is authenticated by its SDP fingerprint and does
   not need routine two-week rotation. The trade-off is a more complex stack
   and a message-oriented DataChannel API that needs bounded application
   framing. Saorsa owns the listener, UDP/ICE association routing, certificate
   lifecycle, endpoint API, and DataChannel profile while using standard
   WebRTC protocol primitives, just as its QUIC implementation owns the
   transport while using audited cryptographic primitives.
8. **Use WebRTC Direct only for bootstrap and WebTransport for data.** This
   would combine stable bootstrap with WebTransport's superior byte streams.
   It is not the initial production choice because every browser-capable node
   would need two browser transports, two endpoint forms, and two independent
   compatibility and resource-control surfaces. It can be reconsidered if
   measured DataChannel performance is inadequate for 4 MiB chunks.

## Decision

We will add a separate WebRTC Direct listener to browser-capable nodes. It is
included and enabled in standard node builds so an ordinary deployment is
browser reachable without deployment-specific flags; custom configuration can
disable it, and minimal native-only builds can omit the default feature.
Browser clients will use it to connect directly, perform one-hop
`FIND_NODE` RPCs iteratively, download chunks with `GET_CHUNK`, and store paid
chunks with the same quote and payment checks as native clients.

The initial transport targets browser-to-public-server WebRTC Direct. It uses
ICE-lite on the node, browser-managed ICE on the client, DTLS for transport
confidentiality and integrity, reliable ordered SCTP DataChannels, and a
mandatory application-layer post-quantum session. That session uses ephemeral
ML-KEM-768 key establishment authenticated by the node's persistent ML-DSA-65
identity, then protects every browser RPC request and response with
ChaCha20-Poly1305. It does not require a DNS name, public-CA certificate, TURN
server, or out-of-band SDP signaling for a directly reachable node.

The transport is implemented and versioned by Saorsa. It does not use libp2p
libraries or wire layers: there is no libp2p peer ID, Noise handshake,
multistream selection, connection gater, protobuf stream envelope, or libp2p
DataChannel close protocol. `saorsa-transport` owns ICE-lite/DTLS/SCTP setup,
the shared UDP association mux, persisted certificates, native diagnostic
dialing, and reliable ordered DataChannels. `saorsa-core` owns only the
validated endpoint/address integration. The standalone `saorsa-webrtc` crate
in the transport workspace owns the portable post-quantum handshake,
encrypted-record layer, browser RPC schema, outer framing, address codec, and
transfer limits. `ant-core` owns the runtime-neutral client algorithms and the
browser WASM facade; `ant-node` owns the bounded browser RPC adapter. The two
sides use the same Rust protocol implementation, while the browser transport
adapter calls `RTCPeerConnection` directly through Web APIs. `ant-protocol`
remains independent of the selected carrier transport; this design uses its
released `2.3.1` API without WebRTC-specific source, feature, or dependency
changes.

The native ML-KEM/ML-DSA transport remains the node-to-node transport and is
not downgraded or replaced. The WebRTC listener has independent connection,
channel, request, timeout, message, and byte limits. Its write surface accepts
only content-addressed chunks accompanied by a verifiable native payment
proof.

### Public-listener resource isolation

The public WebRTC listener has a resource envelope independent from native
QUIC. Browser traffic does not consume the native transport's limits, and
native limits are not relied upon to protect the browser listener. The initial
server defaults are:

| Setting | Default | Scope |
|---|---:|---|
| `max_connections` | 32 | listener |
| `max_connections_per_ip` | 4 | source IP |
| `max_channels_per_connection` | 2 | association |
| `max_channels` | 32 | listener and channel-handler tasks |
| `max_concurrent_requests` | 16 | listener work slots |
| `max_requests_per_second` | 256 | listener work token bucket |
| `max_requests_per_second_per_ip` | 32 | source-IP work token bucket |
| `max_requests_per_second_per_connection` | 16 | association work token bucket |
| `max_in_flight_bytes` | 64 MiB | listener frame memory |
| `max_in_flight_bytes_per_ip` | 16 MiB | source-IP frame memory |
| `max_request_bytes` | 64 KiB | JSON request header |

These are independent controls, not alternative ways to express one shared
ceiling. Configuration fails startup unless every value is nonzero and a
single source retains strict headroom for other sources in each global pool:

- `max_connections_per_ip < max_connections`;
- `max_connections_per_ip * max_channels_per_connection` is lower than both
  `max_channels` and `max_concurrent_requests`;
- the per-IP request rate is lower than the global request rate, and the
  per-connection rate does not exceed the per-IP rate; and
- the per-IP in-flight byte ceiling is lower than the global byte ceiling.

The source key is the observed remote IP; an IPv4-mapped IPv6 address maps to
the same key as its IPv4 form. Per-IP rate and byte state is shared by every
association from that source. Normal reconnects reuse retained rate state, so
reconnecting alone does not refill a depleted bucket. The source table itself
has a hard bound and evicts only the oldest inactive entry, preventing the
limiter from becoming a source-churn memory attack.

Admission is non-queueing above the application bounds. The server stops
starting new transport accepts while all global association slots are in use.
After accept, an association must obtain both its global and per-IP share. A
connection may own at most `max_channels_per_connection` active DataChannels,
and every admitted channel must also own one of the global `max_channels`
permits. Excess channels are closed and terminate the offending association.
The v4 protocol expects persistent channels, so an association is closed when
its last application channel ends rather than retaining a stale connection
slot for a hypothetical channel reopen.

Connection and channel handlers are children of bounded `JoinSet`s rather
than detached tasks. Their semaphore permits and source counters are RAII
guards. Normal shutdown drains connection tasks for five seconds, then aborts
and joins any remainder; closing a connection cancels and joins its
remaining channel tasks. A channel waiting for its next frame has a 60-second
idle deadline. Partial-frame reads and all response writes have total,
size-scaled transfer deadlines, so slow senders and readers cannot retain work
or byte reservations indefinitely.

A request obtains a global work permit only after its first message arrives,
so an idle persistent channel does not consume a request slot. The permit is
held through frame assembly, processing, and response transmission. The
ML-KEM/ML-DSA session handshake consumes the same global, per-IP, and
per-connection rate tokens and the same work permits as an RPC; otherwise
channel churn would provide an unmetered public-key-cryptography path. All
three rate controls are constant-space token buckets with a one-second burst.
Capacity or rate rejection closes the channel or association without sending
an error response that would amplify attacker traffic.

Frame memory is reserved atomically against both the source and listener byte
budgets. Once an outer prefix declares a valid length, the complete frame is
reserved before the listener accepts a slow body. Reservations include
ciphertext/plaintext overlap during authenticated decryption, parsed request
content retained during processing, response serialization and encryption,
and bytes held through response writes. `GET_CHUNK` reserves the maximum chunk
size before asking storage to allocate the result, then shrinks to the actual
size. Outbound frames send the four-byte prefix and bounded payload fragments
without allocating another full-frame copy. Every reservation is released on
success, rejection, cancellation, task abort, or protocol error.

### Stable addresses and transport certificates

The canonical direct address form is:

```text
/ip4/<address>/udp/<port>/webrtc-direct
  /certhash/<stable-sha2-256-multihash>
  /p2p/<ant-peer-id>
```

`ip6` is also valid. Constant bootstrap addresses use literal IP addresses;
DNS is neither required nor used as an authentication mechanism. Certificate
multihashes use unpadded base64url multibase (`u`) and contain exactly a
32-byte SHA-256 digest.

The `/certhash` component is required by WebRTC Direct so the browser can
construct and authenticate the remote DTLS description. It is deliberately a
stable fingerprint, not a temporary WebTransport-style pin. On first startup,
the node generates a P-256 DTLS certificate and stores it beside its persistent
node identity. The certificate has a long validity window and restarts reuse
the same DER bytes, key, and fingerprint. A deterministic, domain-separated
derivation from persistent node key material may be adopted only after
cryptographic review; persistence is the default design. Stable WebRTC Direct
fingerprints across restarts have also been implemented as
[libp2p prior art](https://github.com/libp2p/go-libp2p/pull/3512).

The DTLS transport key is not the ANT identity credential. Compromise of that
key alone must neither authorize browser RPCs nor disclose their plaintext.
The `/certhash` fingerprint and WebRTC SDP authenticate the DTLS connection;
the application session separately authenticates the ANT identity named by the
multiaddress's `/p2p` suffix. These are independent bindings to the same
endpoint rather than a claim that the DTLS transcript is ML-DSA-signed.

Before accepting an application request, the browser sends a versioned,
ephemeral ML-KEM-768 encapsulation public key. The node returns an ML-KEM
ciphertext, its 32-byte peer ID, its complete ML-DSA-65 public key, and an
ML-DSA-65 signature over a domain-separated transcript containing the client
hello, KEM ciphertext, and peer ID. The browser verifies that the response peer
ID matches the multiaddress, that BLAKE3 of the ML-DSA public key equals that
peer ID, and that the transcript signature is valid. Any mismatch aborts and
closes the connection.

Both sides mix the fresh ML-KEM shared secret with the handshake transcript
hash and derive independent client-to-server and server-to-client 256-bit
keys. Every later application frame, including `HELLO`, is authenticated and
encrypted with ChaCha20-Poly1305. Per-direction monotonically increasing
64-bit sequence numbers produce unique nonces and are authenticated as
additional data. Replayed, skipped, reordered, modified, or unauthenticated
records fail closed. Session keys and sequence state are zeroized when the
session is dropped.

This layer gives application payloads post-quantum confidentiality and node
authentication without replacing WebRTC. ICE, DTLS, SCTP, certificate
fingerprints, packet sizes, message timing, connection metadata, and denial of
service exposure remain properties of the classical WebRTC layer. The
additional encryption therefore does not make all transport metadata or
WebRTC connection establishment post-quantum secure.

Routine time-based DTLS certificate rotation is not performed. Rotation is an
exceptional operation associated with transport-key compromise or node
identity replacement and produces a new multiaddress. Designated bootstrap
operators must then retain overlap in the compiled bootstrap set across client
releases. This is equivalent to changing a bootstrap peer's ANT identity, not
ordinary certificate maintenance.

An IP address and port can still change. Constant bootstrap nodes therefore
require stable public addressing and long-lived ANT identities, and clients
ship multiple independently operated seeds. Ordinary nodes are not required
to have stable addresses; their current signed records are learned through the
network.

### Bootstrap and endpoint discovery

The web client contains a constant list of bootstrap `MultiAddr` values. These
entries are trust anchors and have no routine time-based expiry. The list is
sufficient to initiate DHT lookup without fetching a manifest, resolving DNS,
or contacting an application service. A newer application release may add or
retire seeds, but bootstrap does not depend on receiving that release.

The implemented discovery path has two wire-compatible generations backed by
one canonical in-memory address set. The existing Postcard
`PublishAddressSet` operation is frozen: it retains the original closed
`AddressType` enum and carries only the `Quic` projection. Neither WebRTC nor
any future transport is added to that enum or legacy `FIND_NODE` response.

The new address plane uses a separate `/dht/address/2.0.0` topic and complete
replacement records:

```text
PublishAddressSetV2 {
    seq: u64,
    records: [TransportAddressRecord]
}

TransportAddressRecord {
    transport: u16,
    reachability: u16,
    address: bytes
}
```

Known transport identifiers are `Quic = 1` and `WebRtcDirect = 2`. Transport
and reachability are deliberately orthogonal: the known reachability IDs are
Relay, Direct, Unverified, and Lan. WebRTC Direct currently has no relayed
address form, so every WebRTC endpoint is published as `Unverified`; its
reachability is determined by attempting the certificate-pinned browser
connection. Relay acquisition selects `Quic + Direct`; native dialing never
consumes WebRTC records and native QUIC reachability is never reused as WebRTC
evidence.

The identifiers are numeric fields rather than serialized Rust enums and are
never reused. `address` is a bounded, length-delimited payload that is decoded
only after recognizing `transport`. Consequently a V2-aware node can decode,
retain, and forward an unknown future transport or reachability value without
understanding or dialing it. Known records must decode to a multiaddress whose
transport matches the declared identifier; WebRTC records must also contain
the authenticated owner's peer ID.

V2 also defines a matching `FindNodeV2` result carrying complete transport
records. This keeps extension addresses out of the legacy `DHTNode` shape while
allowing sequence-bearing DHT gossip to distribute WebRTC endpoints beyond the
direct recipients of a publish.

Support is advertised by the `addr-v2` capability in the signed identity user
agent. During migration, a new node sends V2 publish and lookup operations to
capable peers and the unchanged V1 operations to older peers. Thus new-to-old
and old-to-new links continue to propagate QUIC addresses, while WebRTC and
future records flow only between upgraded nodes. The V2 topic is separate, so
an old node also ignores an accidentally delivered V2 frame instead of trying
to deserialize an unknown operation.

Reachability classification, relay acquisition, relay loss, and rebinding
mutate the one canonical address set and derive both wire projections from it;
V1 and V2 are not independent sources of truth. Once the network's minimum
supported version guarantees V2, nodes may stop publishing V1. Relay
acquisition continues through the `Quic + Direct` V2 records. Removing V1 is
an explicit compatibility cutoff: pre-V2 nodes will no longer discover or
join that network, and V1 decoding may be removed in a later cleanup release.

The browser accepts a discovered endpoint only when its `/p2p` suffix matches
the returned peer, then proves that binding again through certificate-pinned
DTLS and the authenticated ML-KEM application session. The encrypted `HELLO`
checks the endpoint and protocol metadata after cryptographic session
establishment. A malicious DHT responder can omit an endpoint or make a client
spend a bounded failed dial, but cannot authenticate an endpoint as another
peer.

A later hardening phase may add a separately versioned, independently
cacheable record without changing the existing Postcard `DHTNode` shape:

```text
BrowserEndpointRecord {
    network_id,
    peer_id,
    sequence,
    expires_at,
    webrtc_multiaddrs,
    capabilities,
    protocol_versions,
    max_chunk_size,
    node_public_key,
    ml_dsa_signature
}
```

Such independently cacheable records would expire because IP addresses, ports,
relay allocations, and capabilities can change. That expiry would not apply to
the separately configured bootstrap trust anchors and would not be driven by
routine DTLS certificate rotation.

For that optional record, the ML-DSA signature covers a canonical,
domain-separated encoding. The browser would verify the public-key-to-peer-ID
binding, signature, network ID, monotonic sequence, expiry, capabilities, and
the entire multiaddress before dialing. An address received through an
unauthenticated channel is not made trustworthy merely by containing a
certificate hash.

The multiaddress is the complete dialing input: no separate IP address,
certificate fingerprint, or peer-ID argument is accepted by the browser
client. This prevents those values from being accidentally mixed between
nodes.

The address is represented by the network's native address types rather than
an application-owned string. `saorsa-transport` will own a validated WebRTC
Direct transport component, and `saorsa-core::MultiAddr` will own the
`/p2p/<ant-peer-id>` suffix. Canonical formatting, parsing, and string-based
Serde are the single Rust codec used by endpoint records, bootstrap lists,
`HELLO`, and `FIND_NODE`. `ant-node` must not maintain a second WebRTC Direct
multiaddress or certificate-hash codec.

The native Saorsa QUIC dialer deliberately does not treat a WebRTC Direct
address as a native QUIC dialing candidate. It is a first-class advertised
transport address whose browser stack remains separate from the PQ
node-to-node transport.

For deployment smoke tests, a browser-enabled node also writes its own
canonical address to `<root-dir>/webrtc-direct.multiaddr`. Deployment tooling
may print or copy this public artifact so an operator can paste one seed into
the browser demo without scraping structured logs or running a manifest
service. This is an operability aid, not the endpoint-discovery protocol; peer
endpoints propagate through DHT address sets.

With no explicit listener configuration, the node binds IPv4 wildcard and
maps its native UDP port deterministically into UDP 32768-65535. It advertises
the same-family non-relay external IP observed by the native transport, or the
host routing table's selected IP when no observation is available yet. The
automatic port and persisted certificate make the resulting multiaddress
stable across routine restarts. Explicit bind and advertised addresses remain
available for multi-homed and otherwise unusual deployments.

### WebRTC Direct interoperability status

The signaling-free connection mechanism has prior art in the [libp2p WebRTC
Direct v1 design](https://github.com/libp2p/specs/blob/master/webrtc/webrtc-direct.md):
the browser and public ICE-lite listener derive the descriptions locally, and
the first STUN binding request gives the listener the browser's observed
address and per-association ICE credential. Saorsa uses that standards-based
mechanism as design input, not the libp2p transport, identity, Noise, mux, or
stream wire protocols.

The original Saorsa profile was identified by the ICE credential prefix
`saorsa+webrtc+v1/`. Like the prior v1 mechanism, it replaced the ICE ufrag and
password in the browser-generated local SDP. Browser vendors are restricting
that unsupported SDP-munging behavior, creating a documented [Chrome
compatibility risk](https://github.com/libp2p/go-libp2p/issues/3499).

The implemented v2 profile is identified by `saorsa+webrtc+v2/` and follows the
standards-level technique developed by [WebRTC Direct v2
work](https://github.com/libp2p/specs/pull/715). The browser sets its generated
offer unchanged, reads its effective local ICE password back from
`RTCPeerConnection.localDescription`, and embeds that password after the v2
prefix in the synthetic server answer's ufrag. The first STUN request therefore
carries `saorsa+webrtc+v2/<client-pwd>:<client-ufrag>`. The listener validates
both fragments, recovers the client password, and constructs the matching
association without modifying browser-owned local credentials or using a
signaling service. New browser and native diagnostic dials use v2 with no v1
fallback; the listener accepts v1 during migration.

Production promotion remains conditional on current Chrome, Firefox, and
Safari interoperability tests for this v2 flow. Saorsa does not depend on
libp2p adopting or shipping it. The ANT ML-KEM/ML-DSA application session
remains the only ANT node-identity and application-encryption protocol on the
WebRTC connection; the pinned DTLS fingerprint remains the transport
authentication mechanism. Unknown connection-establishment versions are
rejected.

### Browser protocol and DataChannel framing

The public protocol is not the private Saorsa `WireMessage` or native Postcard
DHT protocol. The application protocol name is `autonomi.web.poc.v4`, its
DataChannel label is `autonomi.web.v4`, and the embedded post-quantum session
has its own independently checked wire version 1. The initial methods are:

- `HELLO`: return and validate protocol, peer, endpoint, capability, chunk-size,
  and payment metadata after the post-quantum session has authenticated the
  node. `HELLO` is no longer a separate cryptographic challenge/response.
- `FIND_NODE`: return up to the local DHT K value, ordered by XOR distance.
  It never initiates a network lookup on the server.
- `GET_CHUNK`: return a locally stored chunk, `not_found`, or a bounded error.
- `QUOTE_CHUNK`: return the node's ordinary ML-DSA-signed storage quote and,
  when present, its commitment sidecar. The browser verifies peer binding,
  quote signature, forced price, commitment signature, and commitment pin
  before paying. Its canonical signed fields use the native byte encoding;
  the EVM-facing `PaymentQuote::hash()` is Keccak-256 over those bytes followed
  by the public key and signature. This must not be confused with the BLAKE3
  hashes used for ANT identities, content addresses, and commitment pins.
- `PUT_CHUNK`: accept raw chunk bytes, the previously verified signed quote,
  and the payment transaction hash. The listener reconstructs the native
  single-node `PaymentProof` and routes the request through the ordinary PUT
  handler, including content-address and on-chain payment verification.
- `PING`: optional liveness method after the proof of concept.

WebRTC DataChannels are messages, not byte streams. One persistent reliable
ordered DataChannel carries a sequence of RPC request/response frames for one
association. Protocol v4 has two framing layers:

1. The plaintext inner frame is a four-byte JSON-header length, a bounded
   versioned JSON header, and the declared raw binary body. Chunk bytes are
   never JSON/base64.
2. The shared post-quantum session seals the complete inner frame as one record.
   The record contains a type tag, a 64-bit sequence number, and
   ChaCha20-Poly1305 ciphertext and authentication tag. A four-byte encrypted
   payload length delimits that record for DataChannel reassembly.

Only the outer encrypted-record length, DataChannel message count, and timing
are visible outside the application session; JSON fields and chunk bytes are
encrypted. The handshake messages use the same bounded outer length prefix but
are not AEAD records because they establish the session keys. Outer frames are
fragmented into DataChannel messages of at most 16 KiB and reassembled before
handshake processing or AEAD opening. No libp2p stream envelope or half-close
control frame exists.

Frames are self-delimiting at both layers. Receivers validate the bounded outer
length before allocation, authenticate and decrypt the exact record, then
validate the inner JSON header and its declared body length. A client serializes
requests on its persistent channel, waits for the complete declared response,
and can then send the next request without closing the channel. Trailing bytes,
channel closure before completion, mismatched lengths, unexpected sequences,
or failed record authentication are protocol errors. Cryptographic errors close
the association. This design directly removes the cross-version `FIN_ACK` and
RESET lifecycle failure observed with the libp2p PoC.

High-level browser operations share a bounded pool of authenticated node
associations. Iterative lookups, quote collection, paid storage, and downloads
reuse the existing DataChannel for a node instead of creating a new
`RTCPeerConnection` for every encrypted record. This is both a performance and
compatibility requirement: the Safari PoC observed later DataChannels timing
out after rapid connection churn even though each earlier caller invoked
`close()`. The pool avoids relying on prompt browser resource reclamation,
serializes concurrent RPCs per node, limits live associations, evicts only idle
entries, and closes every entry when the application closes the client.

The pool belongs to the long-lived browser client and is closed explicitly by
the application. It is not discarded between records or between complete file
operations. The same client also retains learned routing entries and a bounded
negative endpoint cache, so a second chunk lookup does not restart from the
bootstrap list or repeatedly wait on an endpoint that just failed.

### Client API compatibility

`ant-core` keeps its existing native `data::Client` and `ClientConfig` public
API. Existing native Rust applications, including `ant-cli`, continue to
construct and call that client without source changes. Native QUIC, Tokio task
management, wallet integrations, and filesystem behavior remain behind that
facade.

Reusable client algorithms live behind a private runtime-neutral Rust engine.
This includes bounded unordered work scheduling, endpoint failure state, and
the transport-independent iterative lookup driver. The native facade supplies
Tokio/QUIC adapters; the WASM facade supplies browser timers and WebRTC Direct
sessions. Both therefore use the same Rust policies without forcing existing
native callers onto a new trait or configuration type.

The browser and node adapters also consume the same `saorsa-webrtc`
post-quantum session and framing module. Cryptographic transcript construction,
key derivation, sequence handling, record authentication, and frame bounds are
not reimplemented in JavaScript or separately in `ant-node`. Existing native
applications such as `ant-cli` continue through the unchanged native client
path and do not opt into the browser WebRTC wire protocol.

Browser applications instantiate the Rust/WASM `BrowserNetworkClient`. That
facade owns bootstrap, routing, quote preparation, paid storage, downloads,
and random-access reads. JavaScript remains only at browser boundaries that
Rust cannot own directly: DOM events, wallet-provider calls, service-worker
message plumbing, and the browser's WebRTC API bindings.

The sender observes `bufferedAmount`, pauses above the configured high-water
mark, and resumes only after `bufferedamountlow`. Both sides cap total buffered
bytes, validate declared lengths before allocation, support cancellation by
closing the logical RPC channel, and reject bodies that exceed the method
limit. Both sides recompute BLAKE3 and reject content whose hash does not equal
its address.

Browser sessions are not inserted into node routing tables. Wallet secrets,
replication controls, arbitrary topic forwarding, and native DHT messages are
not exposed. Payment happens against the public EVM RPC and contracts: the
browser signs locally, and only the resulting public proof crosses WebRTC.

### Lookup behavior

The browser owns the iterative lookup state machine. The first lookup starts
from the constant WebRTC Direct bootstrap list. Later lookups start from the
closest entries in the Rust client's retained routing view. It queries up to
`ALPHA = 3` unqueried closest endpoints in parallel, merges verified endpoint
records, and stops at convergence or the iteration limit. The implementation
uses the current native `K = 20` behavior.

Native QUIC and browser WebRTC adapters share the same Rust rule for each
parallel query batch: await the first result, accept additional results during
a bounded grace period, and cancel remaining stragglers. A failed endpoint is
suppressed for a cooldown unless the peer publishes a different address; a
successful request clears the failure. This prevents unreachable NAT-side
listeners from adding their full WebRTC opening timeout to every record.

V2 address records carry a reachability field independently from transport
type, but WebRTC Direct currently has no relay transport. Its records are
therefore normalized to `Unverified` rather than borrowing the classification
of a native QUIC socket on another UDP port. One-hop browser `FIND_NODE`
responses expose these authenticated, self-contained endpoints and the browser
handles failed dials through its bounded negative-endpoint cache. If relayed
WebRTC is added later, it requires a distinct address form and selection policy
rather than overloading the direct address.

Every storage node, or a sufficient storage-aware replica set, must expose a
browser endpoint. Filtering native closest results to a sparse browser-only
subset is not considered equivalent to finding the network's actual closest
storage nodes.

### NAT and relays

WebRTC Direct removes the signaling server only for publicly reachable
listeners. It does not make a NATed server directly dialable from a static
address, and this implementation has no WebRTC relay transport. An endpoint
that cannot be reached is simply a failed browser dial and is suppressed by
the negative-endpoint cache. Supporting NATed WebRTC nodes would require a
separate signaling and relay design; it is not represented by the current
reachability field.

### Implemented proof-of-concept slice

The earlier feature-gated WebTransport PoC has been replaced by the
`webrtc-direct` feature. The current slice provides:

- a separate Saorsa-owned WebRTC Direct UDP listener in `saorsa-transport` and
  a browser dialer built directly on `RTCPeerConnection`/`RTCDataChannel`;
- WebRTC endpoint publication as `Unverified`, independent of native QUIC
  reachability, with actual availability determined by a certificate-pinned
  browser dial;
- credential-first STUN routing in the shared UDP mux, so a new association is
  not sent to a stale ICE agent when a browser reuses a source UDP port;
- a generated and persisted DTLS certificate whose fingerprint remains stable
  across restarts;
- native `saorsa-transport` and `saorsa-core::MultiAddr` support for canonical,
  literal-IP `/webrtc-direct/certhash/.../p2p/...` addresses with exactly one
  fingerprint and no DNS form;
- a protocol v4 browser session backed by the shared `saorsa-webrtc`
  post-quantum session v1, which performs ephemeral ML-KEM-768 key
  establishment, authenticates the transcript and ANT peer ID with ML-DSA-65,
  derives direction-separated keys, and protects every later application frame
  with ordered ChaCha20-Poly1305 records;
- a persistent reliable ordered application DataChannel, bounded 16-KiB
  messages, declared-length reassembly, and browser `bufferedAmount`
  backpressure;
- an independent node-side resource envelope with strict global, per-IP, and
  per-association connection/channel/request/rate/byte bounds, owned handler
  tasks, and deadline-bounded frame reads and response writes;
- a bounded browser connection pool that reuses authenticated DataChannels
  across every lookup, quote, and record in one complete upload or download;
- a Rust/WASM random-access reader that resolves the public root DataMap,
  retrieves only encrypted records overlapping the requested plaintext byte
  range, and retains a bounded record cache for read-ahead and seeks;
- a same-origin service-worker adapter that exposes those verified ranges to a
  native browser media element with standard HTTP range semantics, without
  proxying bytes through a bootstrap or application server; and
- the existing local `FIND_NODE`, `GET_CHUNK`, `QUOTE_CHUNK`, and paid
  `PUT_CHUNK` behavior over the new transport.

The WebRTC primitive release currently used by the Rust implementation has a
known AES-256-GCM SRTP construction defect. The Saorsa setting engine therefore
advertises the interoperable AES-128-GCM and AES-128-CM profiles and omits the
broken profile. There is no vendored library patch. The AES-256 profile should
be restored only after upgrading the primitive and adding a regression test.

Literal private and loopback IPs require no library connection-gater exception
because the browser client does not run libp2p. Address parsing still requires
a literal IP, UDP, `/webrtc-direct`, exactly one SHA-256 certificate pin, and
the expected ANT peer ID before constructing an `RTCPeerConnection`.

The local manifest remains test scaffolding for ephemeral loopback ports. The
production client is designed to accept the same endpoint values from a
compiled constant list, without fetching a manifest or resolving DNS.

This implementation currently uses the Saorsa v1 WebRTC
connection-establishment profile and the v4 encrypted application protocol
described above. It is a PoC, not evidence that the production no-mutation gate
has been met. Promotion remains blocked on the cross-browser validation listed
below.

### Local testnet implementation slice

The in-process `ant-devnet` launcher can enable a listener on every node. The
listeners share an in-memory endpoint catalog, allowing each local
`FIND_NODE` answer to attach the self-contained WebRTC Direct multiaddress of
every browser-enabled peer in its routing view before DHT publication has
converged. This catalog is development-only; production lookup uses only the
authenticated V2 DHT endpoint records.

Local testnets may publish a runtime manifest because their loopback addresses
and ephemeral ports are created for each test run. Production bootstrap must
not depend on that mechanism. A local manifest may expose bootstrap
multiaddresses, public-file metadata, public EVM RPC and contract addresses,
and a resolved public root DataMap; it never performs lookup or carries file
bytes and never includes wallet secrets.

At startup the launcher uses `self_encryption 0.36` to produce encrypted file
chunks and the same public MessagePack `DataMap` used by `ant-client`. It
publishes every record through each candidate node's ordinary PUT handler. It
pre-populates the devnet payment cache for those addresses, while
content-address verification, DHT responsibility, payment-cache admission,
LMDB storage, and verified reads remain active.

### Protocol v4 automated validation

Node CI explicitly runs the otherwise ignored five-node WebRTC Direct devnet
integration test. Its native test adapter completes the ML-KEM/ML-DSA
handshake and encrypted `HELLO`, asks a seed for closest nodes, dials an
endpoint from that wire response, performs another lookup on the discovered
node, and keeps each encrypted DataChannel open across multiple requests. It
then downloads and reconstructs a public file, obtains a quote, submits a
payment proof and upload, and reads the result back. The dev-only in-memory
endpoint catalog helps nodes populate their lookup responses; the client no
longer chooses its download peer from that out-of-band catalog.

This harness proves direct endpoint discovery, encrypted session reuse, and
the node request path. It does **not** execute the browser WASM iterative
lookup state machine. `ant-client` CI builds and lints the WASM target and runs
its generated bindings in Node, but browser-side iterative parity remains a
promotion requirement below. Shared `saorsa-webrtc` unit tests additionally
cover record tampering and replay, wrong peer IDs, tampered node signatures,
invalid outer frames, and version mismatch.

Node-side resource tests additionally cover fail-fast headroom invariants,
per-IP association isolation, IPv4-mapped IPv6 normalization, token-bucket
refill, preservation of source rate state across reconnects, bounded inactive
source state, global/per-source byte ceilings, rollback after failed global
reservation, and RAII release. The devnet workflow transfers real encrypted
chunks, but it is not a browser resource-limit or fleet test. The adversarial
browser and fleet tests listed under Validation remain promotion requirements.

There is currently no automated real-browser v4 flow in browser CI. The
historical smoke flow below ran only Chromium and used protocol v3. Therefore
Chrome, Firefox, and Safari interoperability against a matching deployed v4
node fleet, along with cold bootstrap from the production compiled seed list,
remain unmet acceptance criteria rather than claimed results.

### Historical public Internet v3 smoke result

The following results predate the v4 post-quantum record layer. They validate
WebRTC Direct connectivity, decentralized lookup, paid storage, and browser
client behavior, but they do not validate the v4 handshake or encrypted-record
implementation and must be repeated with matching v4 clients and nodes.

On 2026-08-27 a headless Chromium client loaded the local web application and
dialed a literal public-IPv4 WebRTC Direct address on a DigitalOcean-hosted
node. With no browser manifest available, it completed ICE, DTLS, SCTP, the
DataChannel handshake, and the former ML-DSA `HELLO`; the UI then installed
that single address as the Rust network bootstrap seed and completed a
`FIND_NODE` query without page errors. Restarting the remote node left the
complete multiaddress byte-identical and the same browser client reconnected
using the pre-restart value.

The result was repeated with the unchanged stock `ant-testnet` workflow after
WebRTC Direct became a default node feature. A normal 60-node deployment used
no browser-specific build, service, firewall, or advertised-address flags;
bootstrap node 0 automatically published its public IPv4 endpoint on the
derived UDP 42768 port.

Using the pre-V2 address-dissemination prototype, Chromium bootstrapped from
that one address, traversed routing views from dozens of independent peer
processes, obtained four quotes from four non-bootstrap closest nodes, paid
once, and stored all four encrypted records. This verifies that the input
address is a bootstrap seed rather than a storage proxy. Nodes behind the
testnet's deliberate inbound-NAT rules are not reachable through the current
WebRTC Direct transport. Failed direct endpoints are cancelled after the
shared lookup grace period and suppressed by the browser client's negative
cache.

After replacing that prototype with the compatibility-safe V2 address plane,
a five-node headless-Chromium test again started with exactly one WebRTC seed.
It discovered the remaining browser endpoints through `FindNodeV2`, paid for
and stored eight records across the network, read disjoint and suffix media
ranges, and downloaded the verified reconstruction. The V1/V2 wire migration
itself is additionally covered by legacy-decoder and unknown-identifier
round-trip tests.

## Consequences

### Positive

- A web client can bootstrap from months-old constant IP multiaddresses
  without DNS, Web PKI, a fresh manifest, or a signaling server.
- Routine node restarts and certificate maintenance do not change the
  advertised address.
- Operators do not manage DNS names or CA certificate issuance; node software
  creates and persists the browser transport credential.
- Browsers can become application-level full immutable-data clients without a
  lookup, payment, upload, or download gateway.
- Browser-supported videos can start and seek without downloading or
  reconstructing the complete file.
- WebRTC supplies a standardized browser API and an established path toward
  direct ICE and end-to-end relayed connectivity for NATed nodes.
- The stable DTLS fingerprint authenticates transport setup while the shared
  ML-KEM/ML-DSA session independently authenticates the persistent ANT identity
  and protects every application payload.
- A future attacker that records the classical DTLS traffic cannot recover RPC
  or chunk plaintext by later breaking only the DTLS key exchange; application
  confidentiality additionally depends on ML-KEM-768 and 256-bit symmetric
  keys.
- Rust producers and consumers share the network's native `MultiAddr` codec;
  browser WASM parses and validates the same canonical wire syntax.
- Existing native `ant-core` client applications retain their public API while
  native and browser facades share runtime-neutral Rust client policies.
- Existing PQ node networking and compatibility remain isolated.

### Negative / Trade-offs

- Browser-capable nodes run a second UDP listener and an ICE-lite + DTLS + SCTP
  stack in addition to native QUIC.
- DataChannels require application fragmentation, reassembly, flow control,
  and cancellation. They are less natural than WebTransport streams for 4 MiB
  chunks.
- The application session adds an ML-KEM-768/ML-DSA-65 handshake, large
  post-quantum handshake messages, per-record ChaCha20-Poly1305 work, another
  framing layer, and extra copies on top of WebRTC's existing encryption.
- Native media playback needs a small same-origin service-worker bridge because
  a page-owned WebRTC client cannot itself expose an HTTP range URL. The page
  must remain open while playback uses its authenticated associations.
- A stable DTLS transport key has a larger compromise window. Its compromise
  alone cannot authenticate the ANT node or decrypt application records, but
  emergency replacement of a bootstrap fingerprint still requires overlap and
  client-list updates.
- Constant bootstrap peers require stable public IP addresses and ports even
  though ordinary nodes do not.
- Signaling-free WebRTC Direct depends on browser behaviors beyond the basic
  WebRTC API. The implemented v2 profile's Chrome, Firefox, and Safari
  interoperability must be proven before production.
- Direct operation still requires broad browser-endpoint coverage among
  storage nodes. NATed nodes may consume relay bandwidth even though relays
  cannot read their traffic.
- WebRTC connection establishment and certificate authentication are still
  classical. The additional layer protects application contents, not ICE/DTLS/
  SCTP metadata, lengths, timing, availability, or the browser's WebRTC stack.

### Neutral / Operational

- The official web application still needs a secure HTTPS context. Its web
  certificate is unrelated to node deployment and is not a bootstrap
  dependency after the application has been installed.
- Designated bootstrap nodes have stronger uptime and stable-address
  requirements than ordinary storage nodes.
- Origin is policy input, not client authentication. Public listeners enforce
  independent per-IP/session request, channel, rate, and byte quotas; origin
  does not bypass or replace those controls.
- The post-quantum handshake authenticates the node to the browser, not the
  browser user to the node. Client authority remains method-specific; for paid
  storage it comes from the normal wallet signature and payment proof.
- Bootstrap peers do not perform lookup or proxy uploads/downloads; they
  answer the same bounded one-hop RPCs as other browser-capable nodes.
- Application protocol v4 requires matching browser and node deployments;
  plaintext v3 and encrypted v4 peers deliberately fail closed. Native QUIC
  nodes and existing `ant-core`/`ant-cli` callers are unaffected.

## Validation

The decision advances beyond PoC only after all of the following are covered:

- A browser bootstraps with networking disabled for manifest/DNS services and
  only the compiled literal-IP multiaddresses available.
- A bootstrap multiaddress and certificate fingerprint remain byte-identical
  across node restarts and simulated passage of at least one month.
- Documented recovery tests cover certificate compromise, deliberate identity
  rotation, one retired bootstrap seed, and overlap between old and new
  compiled seed lists.
- WebRTC Direct connection establishment works on current Chrome, Firefox,
  and Safari from a real secure context without forbidden SDP mutation. Tests
  explicitly cover the Chrome ICE-credential restriction that breaks v1.
- The browser rejects wrong DTLS fingerprints, wrong peer IDs and public-key
  bindings, malformed or version-mismatched PQ handshakes, invalid ML-DSA
  transcript signatures, modified KEM transcripts, replayed or out-of-order
  records, modified ciphertext, and sequence exhaustion. A v3 plaintext frame
  sent to a v4 endpoint fails closed rather than downgrading.
- Cryptographic tests cover both traffic directions, direction-separated key
  derivation, nonce/sequence uniqueness, transcript domain separation,
  handshake and frame bounds, tampering, replay, reordering, and key cleanup.
- Automated tests cover malformed STUN/SDP/SCTP input, oversized messages,
  excessive channels, slow readers, connection floods, request amplification,
  reconnect churn, task cleanup, and global/per-client byte quotas. Tests must
  also show that one source at each configured ceiling leaves another source
  admissible.
- UDP-mux regression tests cover source-port reuse: a binding request carrying
  a new ICE credential must override a stale address mapping, while binding
  responses and non-STUN traffic continue to use the selected address mapping.
- Browser-side iterative lookup parity tests cover XOR ordering, `K`, `ALPHA`,
  convergence, retained routing entries, grace cancellation, failure cooldown,
  changed endpoints, expired discovered records, and unavailable endpoints.
- Reliable downloads and uploads work at 0 bytes, typical sizes, and 4 MiB,
  with BLAKE3 verification, bounded memory, fragmentation, cancellation, and
  backpressure measurements.
- Media tests cover disjoint, open-ended, and suffix byte ranges, seeks across
  self-encryption chunk boundaries, nested DataMaps, bounded cache behavior,
  invalid/multiple ranges, cancellation, and exact reconstructed bytes.
- Multi-record uploads and concurrent downloads remain within the browser
  connection-pool bound and complete on Safari without accumulating closed
  `RTCPeerConnection` instances.
- Paid-upload tests cover quote/commitment tampering, wrong peers, wrong
  content, missing/failed payments, replay/idempotence, wallet rejection, and
  successful native-client retrieval of browser-created files.
- A fleet test demonstrates that browser endpoint coverage reaches the storage
  nodes selected by native closest-group rules.
- NAT traversal tests measure direct ICE success and exercise an end-to-end
  relay path where DTLS terminates at the NATed node, not the relay.
- Regression tests prove the existing native PQ port and native client
  behavior are unchanged when browser support is disabled.
- Mixed-deployment tests cover v3/v4 incompatibility and confirm that upgrades
  cannot produce a silent plaintext downgrade; deployment documentation treats
  protocol v4 as a coordinated browser-client and node rollout.
- WebRTC and the recorded WebTransport baseline are benchmarked for setup
  latency, CPU and memory, sustained 4 MiB throughput, cancellation, loss
  recovery, and concurrent request behavior before production promotion.
- Review triggers fire when WebRTC Direct v2, browser SDP enforcement, SCTP
  DataChannel behavior, node storage placement, or Saorsa relay APIs change
  materially.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human
review**. Accepted ADRs are immutable: create a new superseding ADR rather than
editing an Accepted ADR.
