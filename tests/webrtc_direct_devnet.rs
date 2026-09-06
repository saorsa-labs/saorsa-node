//! Live ADR-0009 local-devnet protocol test.

use ant_node::devnet::{Devnet, DevnetConfig};
use ant_node::BrowserEndpoint;
use ant_protocol::MAX_CHUNK_SIZE;
use bytes::Bytes;
use evmlib::common::{Amount, QuoteHash};
use evmlib::wallet::Wallet;
use evmlib::RewardsAddress;
use saorsa_transport::transport::{WebRtcCertificateHash, WebRtcDirectAddr};
use saorsa_transport::webrtc_direct::{WebRtcDataChannel, WebRtcDirectClient};
use saorsa_webrtc::{
    decode_pq_frame, encode_pq_frame, pq_frame_length, PqClientHandshake, PqSession,
    BROWSER_PROTOCOL_NAME, BROWSER_PROTOCOL_VERSION, PQ_ENCRYPTED_OVERHEAD_BYTES,
    PQ_SERVER_ACCEPT_BYTES, WEBRTC_DIRECT_DATA_CHANNEL, WEBRTC_WRITE_CHUNK_BYTES,
};
use self_encryption::{DataMap, EncryptedChunk};
use serde_json::{json, Value};
use std::error::Error;
use std::io;
use std::str::FromStr;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts a five-node local network"]
#[serial_test::serial]
#[allow(clippy::too_many_lines)]
async fn seeded_public_file_downloads_and_paid_uploads_over_direct_node_endpoints(
) -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let evm_testnet = evmlib::testnet::Testnet::new().await?;
    let evm_network = evm_testnet.to_network();
    let wallet = Wallet::new_from_private_key(
        evm_network.clone(),
        &evm_testnet.default_wallet_private_key()?,
    )?;
    let mut config = DevnetConfig::minimal();
    config.base_port = 0;
    config.webrtc_direct = true;
    config.webrtc_direct_base_port = 0;
    config.data_dir = temp.path().join("browser-devnet");
    config.spawn_delay = std::time::Duration::from_millis(20);
    config.evm_network = Some(evm_network);

    let mut devnet = Devnet::new(config).await?;
    devnet.start().await?;

    let content = b"browser devnet integration file";
    let public_file = devnet
        .publish_public_file(
            "browser-devnet.txt".to_string(),
            "text/plain".to_string(),
            content,
        )
        .await?;
    let endpoints = devnet.browser_endpoints();
    assert_eq!(endpoints.len(), 5);
    assert!(public_file.replicas > 0);

    let endpoint = endpoints
        .first()
        .ok_or_else(|| io::Error::other("browser-enabled devnet returned no direct endpoints"))?;
    let parsed_endpoint = endpoint.endpoint.parse().map_err(io::Error::other)?;
    let mut seed_client = BrowserRpcClient::connect(&endpoint.endpoint).await?;
    let (hello, hello_content) = seed_client
        .rpc(
            json!({
                "version": BROWSER_PROTOCOL_VERSION,
                "request_id": 5,
                "type": "hello",
            }),
            &[],
        )
        .await?;
    assert_eq!(hello["status"], "ok");
    assert_eq!(hello["protocol"], BROWSER_PROTOCOL_NAME);
    assert_eq!(
        hello["payment"]["rpc_url"].as_str(),
        Some(evm_testnet.to_network().rpc_url().as_str())
    );
    assert_eq!(hello["peer_id"], parsed_endpoint.peer_id);
    assert_eq!(
        hello["endpoint"]["multiaddr"],
        endpoint.endpoint.multiaddr.clone()
    );
    assert!(hello_content.is_empty());

    let (closest, closest_content) = seed_client
        .rpc(
            json!({
                "version": BROWSER_PROTOCOL_VERSION,
                "request_id": 6,
                "type": "find_node",
                "target": public_file.address,
                "count": 20,
            }),
            &[],
        )
        .await?;
    assert_eq!(closest["status"], "ok");
    assert_eq!(closest["type"], "nodes");
    assert_eq!(closest["target"], public_file.address);
    assert!(closest_content.is_empty());
    let discovered = closest["nodes"]
        .as_array()
        .and_then(|nodes| {
            nodes.iter().find(|node| {
                node["webrtc_direct"]["multiaddr"]
                    .as_str()
                    .is_some_and(|addr| addr != endpoint.endpoint.multiaddr)
            })
        })
        .ok_or_else(|| io::Error::other("FIND_NODE returned no browser endpoint"))?;
    let discovered_peer = discovered["peer_id"]
        .as_str()
        .ok_or_else(|| io::Error::other("FIND_NODE node omitted its peer ID"))?;
    let download_endpoint: BrowserEndpoint =
        serde_json::from_value(discovered["webrtc_direct"].clone())?;
    let parsed_download = download_endpoint.parse().map_err(io::Error::other)?;
    assert_eq!(parsed_download.peer_id, discovered_peer);
    let mut download_client = BrowserRpcClient::connect(&download_endpoint).await?;
    let (download_hello, _) = download_client
        .rpc(
            json!({
                "version": BROWSER_PROTOCOL_VERSION,
                "request_id": 7,
                "type": "hello",
            }),
            &[],
        )
        .await?;
    assert_eq!(download_hello["peer_id"], discovered_peer);
    let (next_hop, next_hop_content) = download_client
        .rpc(
            json!({
                "version": BROWSER_PROTOCOL_VERSION,
                "request_id": 8,
                "type": "find_node",
                "target": public_file.address,
                "count": 20,
            }),
            &[],
        )
        .await?;
    assert_eq!(next_hop["status"], "ok");
    assert_eq!(next_hop["type"], "nodes");
    assert!(next_hop["nodes"]
        .as_array()
        .is_some_and(|nodes| !nodes.is_empty()));
    assert!(next_hop_content.is_empty());
    let (header, data_map_bytes) = download_client
        .rpc(
            json!({
                "version": BROWSER_PROTOCOL_VERSION,
                "request_id": 9,
                "type": "get_chunk",
                "address": public_file.address,
            }),
            &[],
        )
        .await?;

    assert_eq!(header["status"], "ok");
    assert_eq!(header["type"], "chunk");
    assert_eq!(data_map_bytes.len(), public_file.data_map_size);
    let data_map: DataMap = rmp_serde::from_slice(&data_map_bytes)?;
    assert_eq!(data_map.original_file_size(), content.len());
    assert_eq!(public_file.chunks.len(), data_map.infos().len());

    let mut encrypted_chunks = Vec::new();
    for (index, chunk) in public_file.chunks.iter().enumerate() {
        let request_id = u64::try_from(index)?.saturating_add(10);
        let (chunk_header, chunk_bytes) = download_client
            .rpc(
                json!({
                    "version": BROWSER_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "type": "get_chunk",
                    "address": chunk.dst_hash,
                }),
                &[],
            )
            .await?;
        assert_eq!(chunk_header["status"], "ok");
        assert_eq!(chunk_header["type"], "chunk");
        encrypted_chunks.push(EncryptedChunk {
            content: Bytes::from(chunk_bytes),
        });
    }
    let decrypted = self_encryption::decrypt(&data_map, &encrypted_chunks)?;
    assert_eq!(decrypted, content.as_slice());

    let upload_content = b"paid browser WebRtcDirect upload";
    let upload_address = hex::encode(blake3::hash(upload_content).as_bytes());
    let (quote_header, quote_content) = download_client
        .rpc(
            json!({
                "version": BROWSER_PROTOCOL_VERSION,
                "request_id": 50,
                "type": "quote_chunk",
                "address": upload_address,
                "size": upload_content.len(),
            }),
            &[],
        )
        .await?;
    assert_eq!(quote_header["status"], "ok");
    assert_eq!(quote_header["type"], "storage_quote");
    assert_eq!(quote_header["already_stored"], false);
    assert!(quote_content.is_empty());
    let quote = quote_header["quote"].clone();
    let quote_hash = QuoteHash::from_str(required_string(&quote, "quote_hash")?)?;
    let rewards_address = RewardsAddress::from_str(required_string(&quote, "rewards_address")?)?;
    let price = Amount::from_str(required_string(&quote, "price")?)?;
    let (payments, _) = wallet
        .pay_for_quotes([(quote_hash, rewards_address, price * Amount::from(3))])
        .await
        .map_err(|error| io::Error::other(format!("storage payment failed: {error:?}")))?;
    let transaction_hash = payments
        .get(&quote_hash)
        .ok_or_else(|| io::Error::other("payment returned no transaction hash for quote"))?;

    let (put_header, put_content) = download_client
        .rpc(
            json!({
                "version": BROWSER_PROTOCOL_VERSION,
                "request_id": 51,
                "type": "put_chunk",
                "address": upload_address,
                "quote": quote,
                "transaction_hash": format!("{transaction_hash:?}"),
            }),
            upload_content,
        )
        .await?;
    assert_eq!(put_header["status"], "ok");
    assert_eq!(put_header["type"], "chunk_stored");
    assert_eq!(put_header["address"], upload_address);
    assert!(put_content.is_empty());

    let (uploaded_header, uploaded_content) = download_client
        .rpc(
            json!({
                "version": BROWSER_PROTOCOL_VERSION,
                "request_id": 52,
                "type": "get_chunk",
                "address": upload_address,
            }),
            &[],
        )
        .await?;
    assert_eq!(uploaded_header["status"], "ok");
    assert_eq!(uploaded_content, upload_content);
    assert!(seed_client.requests_sent() >= 2);
    assert!(download_client.requests_sent() >= 6);

    download_client.close().await?;
    seed_client.close().await?;

    devnet.shutdown().await?;
    Ok(())
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, io::Error> {
    value[field]
        .as_str()
        .ok_or_else(|| io::Error::other(format!("quote omitted {field}")))
}

struct BrowserRpcClient {
    client: WebRtcDirectClient,
    pq_session: PqSession,
    requests_sent: usize,
}

impl BrowserRpcClient {
    async fn connect(endpoint: &BrowserEndpoint) -> Result<Self, Box<dyn Error>> {
        let parsed = endpoint.parse().map_err(io::Error::other)?;
        let direct_addr = WebRtcDirectAddr::new(
            parsed.socket_addr().map_err(io::Error::other)?,
            WebRtcCertificateHash::new(parsed.certificate_hash),
        )?;
        let client = WebRtcDirectClient::dial(&direct_addr, WEBRTC_DIRECT_DATA_CHANNEL)
            .await
            .map_err(|error| io::Error::other(format!("WebRTC Direct dial failed: {error}")))?;
        let expected_peer_id = parsed.peer_id_bytes().map_err(io::Error::other)?;
        let pq_session = establish_pq_session(client.data_channel(), &expected_peer_id).await?;
        Ok(Self {
            client,
            pq_session,
            requests_sent: 0,
        })
    }

    async fn rpc(
        &mut self,
        request: Value,
        content: &[u8],
    ) -> Result<(Value, Vec<u8>), Box<dyn Error>> {
        let request_type = request["type"].as_str().unwrap_or("unknown").to_string();
        let result = rpc_stream(
            self.client.data_channel(),
            &mut self.pq_session,
            request,
            content,
        )
        .await
        .map_err(|error| {
            io::Error::other(format!("WebRTC Direct {request_type} RPC failed: {error}"))
        })?;
        self.requests_sent += 1;
        Ok(result)
    }

    const fn requests_sent(&self) -> usize {
        self.requests_sent
    }

    async fn close(self) -> Result<(), Box<dyn Error>> {
        self.client.close().await?;
        Ok(())
    }
}

async fn rpc_stream(
    channel: &WebRtcDataChannel,
    pq_session: &mut PqSession,
    mut request: Value,
    content: &[u8],
) -> Result<(Value, Vec<u8>), Box<dyn Error>> {
    request["content_length"] = json!(content.len());
    let request_header = serde_json::to_vec(&request)?;
    let request_header_len = u32::try_from(request_header.len())?;
    let mut request_frame = Vec::with_capacity(4 + request_header.len() + content.len());
    request_frame.extend_from_slice(&request_header_len.to_be_bytes());
    request_frame.extend_from_slice(&request_header);
    request_frame.extend_from_slice(content);
    let encrypted = pq_session.seal(&request_frame)?;
    send_pq_payload(channel, &encrypted).await?;

    let encrypted = read_pq_payload(
        channel,
        4 + 64 * 1024 + MAX_CHUNK_SIZE + PQ_ENCRYPTED_OVERHEAD_BYTES,
    )
    .await?;
    let frame = pq_session.open(&encrypted)?;
    if frame.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "response is truncated").into());
    }
    let header_len = u32::from_be_bytes(frame[0..4].try_into()?) as usize;
    let content_offset = 4usize
        .checked_add(header_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "header length overflow"))?;
    if frame.len() < content_offset {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "response header is truncated").into(),
        );
    }
    let header: Value = serde_json::from_slice(&frame[4..content_offset])?;
    let content_length = header["content_length"]
        .as_u64()
        .and_then(|length| usize::try_from(length).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid content length"))?;
    let expected = content_offset
        .checked_add(content_length)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "response length overflow"))?;
    if frame.len() != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WebRtcDirect response length does not match its header",
        )
        .into());
    }
    Ok((header, frame[content_offset..].to_vec()))
}

async fn establish_pq_session(
    channel: &WebRtcDataChannel,
    expected_peer_id: &[u8; 32],
) -> Result<PqSession, Box<dyn Error>> {
    let (handshake, client_hello) = PqClientHandshake::start()?;
    send_pq_payload(channel, &client_hello).await?;
    let server_accept = read_pq_payload(channel, PQ_SERVER_ACCEPT_BYTES).await?;
    Ok(handshake.finish(&server_accept, expected_peer_id)?)
}

async fn send_pq_payload(
    channel: &WebRtcDataChannel,
    payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    let frame = encode_pq_frame(payload)?;
    for chunk in frame.chunks(WEBRTC_WRITE_CHUNK_BYTES) {
        channel.send(chunk).await?;
    }
    Ok(())
}

async fn read_pq_payload(
    channel: &WebRtcDataChannel,
    max_payload_bytes: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut frame = Vec::new();
    let expected = loop {
        let message = channel.receive().await?;
        if message.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "WebRtcDirect PQ frame channel closed",
            )
            .into());
        }
        frame.extend_from_slice(&message);
        if let Some(expected) = pq_frame_length(&frame, max_payload_bytes)? {
            if frame.len() > expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WebRtcDirect PQ frame has trailing bytes",
                )
                .into());
            }
            if frame.len() == expected {
                break expected;
            }
        }
    };
    debug_assert_eq!(frame.len(), expected);
    Ok(decode_pq_frame(&frame, max_payload_bytes)?)
}
