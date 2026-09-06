//! ant-devnet CLI entry point.
//!
//! Runs a local devnet for testing. By default all nodes bind loopback
//! (`127.0.0.1`), so only the host machine can reach them.
//!
//! Three opt-in flags extend this to a **LAN / external-devnet** scenario for
//! testing from another device (a phone, a simulator, a second machine). All
//! default off — omitting them reproduces the original loopback behavior:
//!
//! - `--host <ipv4>`: bind `0.0.0.0` and advertise this LAN IP in the manifest's
//!   bootstrap addresses, so other devices on the LAN can connect.
//! - `--evm-network arbitrum-sepolia`: verify payments against the real deployed
//!   Arbitrum Sepolia contracts (no local Anvil, empty wallet key) — exercises
//!   the external-signer payment flow.
//! - `--serve-port <port>`: expose the manifest over a small read-only HTTP API
//!   (`GET /api/devnet-manifest.json` + `/api/info`) so devices fetch it instead
//!   of copying files.
//!
//! ```text
//! # single-machine, local Anvil (unchanged default behavior)
//! ant-devnet --preset small --enable-evm
//!
//! # LAN devnet backed by Arbitrum Sepolia, manifest served over HTTP
//! ant-devnet --preset small --host 192.168.1.100 \
//!     --evm-network arbitrum-sepolia --serve-port 25000
//! ```

#![cfg_attr(not(feature = "logging"), allow(unused_variables))]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod cli;

use ant_node::devnet::{Devnet, DevnetConfig, DevnetEvmInfo, DevnetManifest};
use ant_node::BrowserDevnetManifest;
use clap::Parser;
use cli::Cli;

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    #[cfg(feature = "logging")]
    if cli.enable_logging {
        use tracing_subscriber::{fmt, prelude::*, EnvFilter};

        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level));

        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(filter)
            .init();
    }

    ant_node::logging::info!("ant-devnet v{}", env!("CARGO_PKG_VERSION"));

    let mut config =
        cli.preset
            .as_deref()
            .map_or_else(DevnetConfig::default, |preset| match preset {
                "minimal" => DevnetConfig::minimal(),
                "small" => DevnetConfig::small(),
                _ => DevnetConfig::default(),
            });

    if let Some(count) = cli.nodes {
        config.node_count = count;
    }
    if let Some(bootstrap) = cli.bootstrap_count {
        config.bootstrap_count = bootstrap;
    }
    if let Some(base_port) = cli.base_port {
        config.base_port = base_port;
    }
    if let Some(dir) = cli.data_dir {
        config.data_dir = dir;
    }
    config.cleanup_data_dir = !cli.no_cleanup;
    if let Some(delay_ms) = cli.spawn_delay_ms {
        config.spawn_delay = std::time::Duration::from_millis(delay_ms);
    }
    if let Some(timeout_secs) = cli.stabilization_timeout_secs {
        config.stabilization_timeout = std::time::Duration::from_secs(timeout_secs);
    }

    #[cfg(not(feature = "webrtc-direct"))]
    if cli.webrtc_direct {
        return Err(color_eyre::eyre::eyre!(
            "--webrtc-direct requires a binary built with --features webrtc-direct"
        ));
    }

    // A non-unicast --host would stamp unreachable bootstrap addresses into the
    // manifest (LAN mode would fail non-obviously), so reject it early.
    if let Some(host) = cli
        .host
        .filter(|h| h.is_loopback() || h.is_unspecified() || h.is_multicast() || h.is_broadcast())
    {
        return Err(color_eyre::eyre::eyre!(
            "--host must be a routable unicast LAN IPv4 (got {host}); \
             loopback/unspecified/multicast/broadcast are not reachable bootstrap addresses"
        ));
    }
    config.advertise_ip = cli.host;
    config.webrtc_direct = cli.webrtc_direct;
    if let Some(base_port) = cli.webrtc_direct_base_port {
        config.webrtc_direct_base_port = base_port;
    }
    let ResolvedEvm {
        manifest: evm_info,
        local_testnet: _local_evm_testnet,
    } = resolve_evm_info(
        cli.evm_network.as_deref(),
        cli.enable_evm,
        cli.host,
        &mut config,
    )
    .await?;

    let mut devnet = Devnet::new(config).await?;
    devnet.start().await?;

    let created_at = chrono::Utc::now().to_rfc3339();

    #[cfg(feature = "webrtc-direct")]
    let browser_manifest = if cli.webrtc_direct {
        let (name, content_type, content) = load_public_file(cli.public_file.as_deref()).await?;
        let public_file = devnet
            .publish_public_file(name, content_type, &content)
            .await?;
        let network_id = format!("local-devnet-{}-{}", devnet.config().base_port, created_at);
        Some(BrowserDevnetManifest::new(
            network_id,
            created_at.clone(),
            devnet.browser_endpoints(),
            devnet.browser_payment_network(),
            vec![public_file],
        ))
    } else {
        None
    };

    #[cfg(not(feature = "webrtc-direct"))]
    let browser_manifest: Option<BrowserDevnetManifest> = None;

    let manifest = DevnetManifest {
        base_port: devnet.config().base_port,
        node_count: devnet.config().node_count,
        bootstrap: devnet.bootstrap_addrs(),
        data_dir: devnet.config().data_dir.clone(),
        created_at,
        evm: evm_info,
    };

    let json = serde_json::to_string_pretty(&manifest)?;
    let browser_json = browser_manifest
        .as_ref()
        .map(serde_json::to_string_pretty)
        .transpose()?;
    if let Some(path) = cli.manifest {
        tokio::fs::write(&path, &json).await?;
        ant_node::logging::info!("Wrote manifest to {}", path.display());
    } else {
        println!("{json}");
    }

    // Optional read-only HTTP API so LAN devices fetch the manifest instead of
    // copying files (GET /api/devnet-manifest.json + /api/info).
    let serve_port = cli
        .serve_port
        .or_else(|| cli.webrtc_direct.then_some(25_000));
    if let Some(port) = serve_port {
        serve_manifest_api(
            port,
            cli.host,
            &manifest,
            json.clone(),
            browser_manifest.as_ref(),
            browser_json,
        )?;
    }

    ant_node::logging::info!("Devnet running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;

    devnet.shutdown().await?;
    Ok(())
}

#[cfg(feature = "webrtc-direct")]
async fn load_public_file(
    path: Option<&std::path::Path>,
) -> color_eyre::Result<(String, String, Vec<u8>)> {
    const DEFAULT_NAME: &str = "autonomi-browser-testnet.txt";
    const DEFAULT_SEED: &[u8] = include_bytes!("../../../assets/browser-devnet-public.txt");
    const DEFAULT_SIZE: usize = 5 * 1024 * 1024;
    const MAX_FILE_SIZE: u64 = 1_000_000_000;

    let Some(path) = path else {
        let mut content = Vec::with_capacity(DEFAULT_SIZE);
        while content.len() < DEFAULT_SIZE {
            content.extend_from_slice(DEFAULT_SEED);
        }
        content.truncate(DEFAULT_SIZE);
        return Ok((
            DEFAULT_NAME.to_string(),
            "text/plain; charset=utf-8".to_string(),
            content,
        ));
    };

    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            color_eyre::eyre::eyre!(
                "--public-file must identify a file with a valid UTF-8 filename"
            )
        })?
        .to_string();
    let file_size = tokio::fs::metadata(path)
        .await
        .map_err(|error| {
            color_eyre::eyre::eyre!("failed to inspect public file {}: {error}", path.display())
        })?
        .len();
    if file_size > MAX_FILE_SIZE {
        return Err(color_eyre::eyre::eyre!(
            "--public-file is {file_size} bytes; the browser devnet limit is {MAX_FILE_SIZE} bytes"
        ));
    }
    let content = tokio::fs::read(path).await.map_err(|error| {
        color_eyre::eyre::eyre!("failed to read public file {}: {error}", path.display())
    })?;
    let content_type = match path
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("txt" | "md" | "csv") => "text/plain; charset=utf-8",
        Some("json") => "application/json",
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("pdf") => "application/pdf",
        _ => "application/octet-stream",
    }
    .to_string();

    Ok((name, content_type, content))
}

/// Resolve which EVM backing the devnet uses, updating `config` accordingly:
/// an **external** network (`--evm-network`, e.g. Arbitrum Sepolia verified
/// against the real deployed contracts, no embedded wallet key); a **local
/// Anvil** chain (`--enable-evm`); or **none**. External takes precedence.
struct ResolvedEvm {
    manifest: Option<DevnetEvmInfo>,
    // Retain ownership until main exits so the Anvil child is terminated on
    // normal shutdown instead of being orphaned.
    local_testnet: Option<evmlib::testnet::Testnet>,
}

async fn resolve_evm_info(
    evm_network: Option<&str>,
    enable_evm: bool,
    host: Option<std::net::Ipv4Addr>,
    config: &mut DevnetConfig,
) -> color_eyre::Result<ResolvedEvm> {
    if let Some(net_name) = evm_network {
        let network = match net_name {
            "arbitrum-sepolia" => evmlib::Network::ArbitrumSepoliaTest,
            other => {
                return Err(color_eyre::eyre::eyre!(
                    "Unsupported --evm-network {other} (supported: arbitrum-sepolia)"
                ))
            }
        };
        let rpc_url = network.rpc_url().to_string();
        let token_addr = format!("{:?}", network.payment_token_address());
        let vault_addr = format!("{:?}", network.payment_vault_address());
        ant_node::logging::info!(
            "Using external EVM network {net_name}: rpc={rpc_url} token={token_addr} vault={vault_addr}"
        );
        config.evm_network = Some(network);
        Ok(ResolvedEvm {
            manifest: Some(DevnetEvmInfo {
                rpc_url,
                wallet_private_key: String::new(),
                payment_token_address: token_addr,
                payment_vault_address: vault_addr,
            }),
            local_testnet: None,
        })
    } else if enable_evm {
        // Anvil binds — and evmlib publishes in the manifest's `rpc_url` —
        // the address in `ANVIL_IP_ADDR`, defaulting to localhost. A LAN
        // devnet must expose the chain the way it exposes the nodes, or the
        // published `rpc_url` is unreachable from every other device —
        // exactly the audience `--host` serves (external signers can join
        // and download, but not pay). An explicit `ANVIL_IP_ADDR` wins.
        if let Some(anvil_ip) = anvil_ip_for_lan(host, std::env::var_os("ANVIL_IP_ADDR")) {
            ant_node::logging::info!(
                "Binding Anvil to {anvil_ip} (via ANVIL_IP_ADDR) so LAN clients \
                 can reach the manifest's rpc_url"
            );
            std::env::set_var("ANVIL_IP_ADDR", anvil_ip);
        }
        ant_node::logging::info!("Starting local Anvil blockchain for EVM payment enforcement...");
        let testnet = evmlib::testnet::Testnet::new()
            .await
            .map_err(|e| color_eyre::eyre::eyre!("Failed to start Anvil testnet: {e}"))?;
        let network = testnet.to_network();
        let wallet_key = testnet
            .default_wallet_private_key()
            .map_err(|e| color_eyre::eyre::eyre!("Failed to get wallet key: {e}"))?;

        let (rpc_url, token_addr, vault_addr) = match &network {
            evmlib::Network::Custom(custom) => (
                custom.rpc_url_http.to_string(),
                format!("{:?}", custom.payment_token_address),
                format!("{:?}", custom.payment_vault_address),
            ),
            _ => {
                return Err(color_eyre::eyre::eyre!(
                    "Anvil testnet returned non-Custom network"
                ))
            }
        };

        config.evm_network = Some(network);

        ant_node::logging::info!("Anvil blockchain running at {rpc_url}");
        ant_node::logging::info!("Funded wallet private key: {wallet_key}");

        Ok(ResolvedEvm {
            manifest: Some(DevnetEvmInfo {
                rpc_url,
                wallet_private_key: wallet_key,
                payment_token_address: token_addr,
                payment_vault_address: vault_addr,
            }),
            local_testnet: Some(testnet),
        })
    } else {
        Ok(ResolvedEvm {
            manifest: None,
            local_testnet: None,
        })
    }
}

/// Build the `/api/info` payload for `manifest` and start the read-only HTTP
/// server on `port`. `host` is the advertised LAN IP when set, otherwise a
/// best-effort local-IP guess is used for the URLs it reports.
fn serve_manifest_api(
    port: u16,
    host: Option<std::net::Ipv4Addr>,
    manifest: &DevnetManifest,
    manifest_json: String,
    browser_manifest: Option<&BrowserDevnetManifest>,
    browser_manifest_json: Option<String>,
) -> color_eyre::Result<()> {
    let host_ip = host.map_or_else(|| "127.0.0.1".to_string(), |i| i.to_string());
    let evm_block = manifest.evm.as_ref().map_or(serde_json::Value::Null, |e| {
        let loopback = e.rpc_url.contains("127.0.0.1") || e.rpc_url.contains("localhost");
        serde_json::json!({
            "rpc_url": e.rpc_url,
            "network": if loopback { "local-anvil" } else { "external" },
            "reachable_from_lan": !loopback,
            "note": if loopback {
                format!(
                    "Anvil binds loopback on the host — bridge it (socat \
                     TCP-LISTEN:8545,fork,bind=0.0.0.0 TCP:127.0.0.1:<anvil-port>) \
                     and use http://{host_ip}:8545/."
                )
            } else {
                "Public RPC — reachable directly from any device.".to_string()
            },
        })
    });
    let bootstrap = serde_json::to_value(&manifest.bootstrap)?;
    let browser_manifest_url =
        browser_manifest.map(|_| format!("http://{host_ip}:{port}/api/browser-manifest.json"));
    let public_files = browser_manifest.map_or_else(Vec::new, |browser| browser.files.clone());
    let info = serde_json::json!({
        "host_ip": host_ip,
        "manifest_url": format!("http://{host_ip}:{port}/api/devnet-manifest.json"),
        "browser_manifest_url": browser_manifest_url,
        "node_count": manifest.node_count as u64,
        "bootstrap": bootstrap,
        "public_files": public_files,
        "evm": evm_block,
    });
    let info_json = serde_json::to_string_pretty(&info)?;
    // Bind synchronously so a failure (e.g. the port is already in use)
    // propagates to the caller instead of the devnet silently coming up
    // without its manifest API.
    let bind_ip = host.map_or(std::net::Ipv4Addr::LOCALHOST, |_| {
        std::net::Ipv4Addr::UNSPECIFIED
    });
    let listener = std::net::TcpListener::bind((bind_ip, port)).map_err(|e| {
        color_eyre::eyre::eyre!("failed to bind manifest API on {bind_ip}:{port}: {e}")
    })?;
    ant_node::logging::info!(
        "manifest API on http://{host_ip}:{port}/api/devnet-manifest.json (+ /api/info)"
    );
    if browser_manifest.is_some() {
        ant_node::logging::info!(
            "browser app manifest: http://{host_ip}:{port}/api/browser-manifest.json"
        );
    }
    spawn_manifest_server(listener, manifest_json, info_json, browser_manifest_json);
    Ok(())
}

/// Run a tiny read-only HTTP server on `listener` (its own thread) exposing the
/// manifest over the LAN. GET-only, open CORS; hand-rolled HTTP/1.1 so there's
/// no new dependency. Connections are handled **inline, one at a time** — the
/// payloads are tiny and a devnet serves a handful of LAN devices, so a single
/// thread bounds resource use (no per-connection thread to exhaust). Each
/// connection gets a read timeout so a slow/idle client can't stall the loop.
/// The thread is detached and dies when the process exits on Ctrl+C.
fn spawn_manifest_server(
    listener: std::net::TcpListener,
    manifest_json: String,
    info_json: String,
    browser_manifest_json: Option<String>,
) {
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let mut tokens = req.split_whitespace();
            let method = tokens.next().unwrap_or("");
            let raw = tokens.next().unwrap_or("/");
            let path = raw.split('?').next().unwrap_or("/").trim_end_matches('/');
            // Read-only API — only GET is allowed; anything else is 405.
            let (status, body) = if method == "GET" {
                match path {
                    "/api/devnet-manifest.json" => ("200 OK", manifest_json.as_str()),
                    "/api/browser-manifest.json" => browser_manifest_json.as_deref().map_or(
                        (
                            "404 Not Found",
                            "{\"error\":\"browser manifest not enabled\"}",
                        ),
                        |body| ("200 OK", body),
                    ),
                    "/api/info" => ("200 OK", info_json.as_str()),
                    "" | "/api" => (
                        "200 OK",
                        "{\"service\":\"ant-devnet manifest API\",\
                         \"endpoints\":[\"/api/devnet-manifest.json\",\
                         \"/api/browser-manifest.json\",\"/api/info\"]}",
                    ),
                    _ => ("404 Not Found", "{\"error\":\"not found\"}"),
                }
            } else {
                (
                    "405 Method Not Allowed",
                    "{\"error\":\"method not allowed\"}",
                )
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\
                 Access-Control-Allow-Origin: *\r\nCache-Control: no-store\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
}

/// The Anvil bind/publish address a LAN devnet should use: the `--host` IP,
/// unless the operator set `ANVIL_IP_ADDR` explicitly (their override wins),
/// or there is no `--host` (loopback devnet — keep Anvil's localhost
/// default). Returns the value to write into `ANVIL_IP_ADDR`, or `None` to
/// leave the environment untouched.
fn anvil_ip_for_lan(
    host: Option<std::net::Ipv4Addr>,
    existing_override: Option<std::ffi::OsString>,
) -> Option<String> {
    match (host, existing_override) {
        (Some(host), None) => Some(host.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::anvil_ip_for_lan;
    use std::net::Ipv4Addr;

    #[test]
    fn lan_host_becomes_anvil_ip() {
        assert_eq!(
            anvil_ip_for_lan(Some(Ipv4Addr::new(192, 168, 0, 61)), None),
            Some("192.168.0.61".to_string())
        );
    }

    #[test]
    fn explicit_override_wins() {
        assert_eq!(
            anvil_ip_for_lan(
                Some(Ipv4Addr::new(192, 168, 0, 61)),
                Some("10.0.0.9".into())
            ),
            None
        );
    }

    #[test]
    fn loopback_devnet_keeps_anvil_default() {
        assert_eq!(anvil_ip_for_lan(None, None), None);
        assert_eq!(anvil_ip_for_lan(None, Some("10.0.0.9".into())), None);
    }
}
