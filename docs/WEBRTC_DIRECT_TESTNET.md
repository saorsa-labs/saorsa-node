# Browser-enabled local testnet

This workflow starts a five-node local Autonomi network where every node has a
direct WebRTC Direct endpoint. Startup publishes a default immutable test file
and serves browser bootstrap metadata; the companion site lives in the sibling
`ant-client-web-support` repository.

## Start the node testnet

Rust 1.88 or newer is required by the Saorsa WebRTC Direct transport.

```bash
cargo run --bin ant-devnet -- \
  --preset minimal \
  --base-port 23000 \
  --webrtc-direct \
  --webrtc-direct-base-port 24000 \
  --serve-port 25000 \
  --enable-evm \
  --enable-logging
```

The services are:

| Purpose | Address |
|---|---|
| Native node QUIC | UDP 127.0.0.1:23000-23004 |
| Direct browser WebRTC Direct | UDP 127.0.0.1:24000-24004 |
| Native devnet manifest | http://127.0.0.1:25000/api/devnet-manifest.json |
| Browser bootstrap manifest | http://127.0.0.1:25000/api/browser-manifest.json |
| Manifest service metadata | http://127.0.0.1:25000/api/info |
| Local Anvil JSON-RPC | printed at startup (random loopback port) |

When `--serve-port` is omitted with `--webrtc-direct`, port 25000 is used. Pass
`--public-file /path/to/file` to replace the built-in
`autonomi-browser-testnet.txt`. The generated default is 5 MiB so the demo
necessarily reconstructs multiple storage records. A custom file may be up to
1 GB (1,000,000,000 bytes) in this local in-memory launcher. The practical
limit depends on the browser having enough available memory.

The browser manifest contains every node's self-contained WebRTC Direct
multiaddress, with its certificate SHA-256 multihash and peer ID embedded,
plus the public DataMap address, plaintext file hash, and resolved
reconstruction metadata. The HTTP server provides bootstrap metadata only;
the DataMap and file bytes are read from storage nodes over WebRTC Direct.
Each address string is serialized directly from `saorsa_core::MultiAddr`; the
node does not maintain a browser-specific multiaddress codec.

`--webrtc-direct` requires an explicit payment network. For this local test,
`--enable-evm` starts Anvil and startup prints a **Funded wallet private key**. This
is a disposable local Anvil key for browser upload testing. The browser manifest
contains only public RPC/token/vault configuration and never contains the
key.
If `HELLO.payment.rpc_url` shows `https://arb1.arbitrum.io/rpc`, the devnet was
started without local Anvil; stop it and restart with the command above.

## Start the browser client

In `ant-client-web-support/web`:

```bash
npm ci
npm run dev
```

Open `http://127.0.0.1:5173`. The app automatically loads the browser manifest.
To upload, choose a file, paste the funded private key printed by ant-devnet,
and use **Pay and upload file**. The page self-encrypts locally, verifies node
quotes, signs the approval/payment locally, and sends only encrypted records
and public payment proof to nodes. The key field is cleared immediately. The
result address is placed into the download field automatically.

Use **Download and save file** to fetch the public DataMap and every encrypted
file chunk directly, reconstruct the complete file, validate its whole-file
BLAKE3 hash, and save it under its original filename.

For a browser-supported video, use **Prepare video stream** and then the native
video controls. The Rust/WASM reader fetches and decrypts only records
overlapping the media element's requested byte ranges. A same-origin service
worker provides standard HTTP range responses locally; no file bytes pass
through the manifest server or another gateway.

## Automated verification

```bash
cargo test --test webrtc_direct_devnet -- --ignored
```

This starts Anvil and the five-node network, self-encrypts and publishes a
default public file through normal PUT admission with devnet-prepaid cache
entries, extracts a generated certificate pin from the advertised
multiaddress, retrieves and reconstructs it, then obtains a real signed quote,
pays it on-chain, uploads a fresh record through paid `PUT_CHUNK`, and reads it
back through WebRTC Direct.

## LAN testing

Use `--host <LAN_IPV4>` to advertise the literal LAN address:

```bash
cargo run --bin ant-devnet -- \
  --preset minimal \
  --host 192.168.1.50 \
  --webrtc-direct \
  --serve-port 25000 \
  --enable-evm \
  --enable-logging
```

Expose the client dev server on the LAN with `npm run dev -- --host 0.0.0.0`
and change its manifest URL to
`http://192.168.1.50:25000/api/browser-manifest.json`. Both the native and
WebRTC Direct UDP ranges must be reachable. Do not use this unsigned local
manifest mode on a public network.

## Public Internet smoke testing

The standard `ant-node` build now includes and enables WebRTC Direct, so the
sibling `ant-testnet` tool needs no browser-specific preset or flags. On its
ordinary public droplets, a node maps its native UDP port deterministically
into the existing allowed UDP 32768-65535 range and advertises the external IP
learned by the native transport (falling back to the host's routed IP). Its
persisted DTLS certificate keeps the complete address stable across restarts.

Deploy the normal testnet against this checkout, for example:

```bash
cd ../ant-testnet
python3.11 testnet.py \
  --saorsa-node-repo ../ant-node-web-support \
  deploy
```

`ant-testnet` always keeps bootstrap droplets public. Read node 0's canonical
address using its existing shell command, without modifying the deployment
tool:

```bash
python3.11 testnet.py shell --droplet 0
cat /var/lib/ant/node-0/webrtc-direct.multiaddr
exit
```

Start `ant-client-web-support/web`, paste that address into the demo, and use
**Connect and use as bootstrap**. The operation installs the single address as
the Rust browser client's seed without DNS or a browser manifest. The address
contains only the public DTLS certificate hash and ANT peer ID; it contains no
secret key material. To disable the listener in a custom node configuration,
set `webrtc_direct.enabled = false`. A minimal binary can omit the transport
entirely with `--no-default-features`.

Public listeners apply an independent resource envelope; the native QUIC
limits are not shared with browser traffic. The defaults are:

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

The per-IP ceilings must remain strictly below their corresponding global
ceilings. The product of the per-IP connection and per-connection channel
limits must also remain below both global channel and request concurrency.
Invalid combinations fail node startup instead of silently removing the
headroom reserved for other clients. IPv4-mapped IPv6 sources share the IPv4
source's quota. Rate buckets permit a one-second burst; overload closes the
offending channel or association without queueing more handler tasks. PQ
handshakes consume the same work slots and rate tokens as RPCs, and response
writes use size-scaled deadlines so slow readers release their reservations.

Each node publishes its certificate-pinned WebRTC Direct multiaddress through
Saorsa's extensible V2 address plane as transport `WebRtcDirect`, independently
of its reachability class. Its signed identity capability selects V2 when the
remote peer supports it; older peers continue receiving the unchanged V1
`Quic` address projection. `FindNodeV2` returns browser endpoints separately
from QUIC addresses, and the browser verifies the peer-ID and certificate
binding during HELLO.
Consequently one pasted address is enough to enter the network and discover
the browser endpoints of closest peers across independently deployed
processes. Native QUIC dialing ignores the supplemental transport entry.

The 2026-08-27 public smoke run used the former protocol v3 and headless
Chromium only. From one bootstrap address it traversed multiple independent
nodes, obtained four storage quotes from non-bootstrap closest nodes,
submitted one payment, and stored all four encrypted records. It is historical
connectivity evidence, not v4 or cross-browser acceptance evidence. Nodes
behind the testnet's deliberate inbound-NAT rules remain unreachable without
relayed WebRTC, so their 10-second DataChannel timeouts currently make this
smoke path slower than an all-public fleet.
