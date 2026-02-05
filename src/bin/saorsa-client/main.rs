//! saorsa-client CLI entry point.

mod cli;

use bytes::Bytes;
use clap::Parser;
use cli::{Cli, ClientCommand};
use saorsa_core::P2PNode;
use saorsa_node::client::{QuantumClient, QuantumConfig, XorName};
use saorsa_node::devnet::DevnetManifest;
use saorsa_node::error::Error;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Length of an `XorName` address in bytes.
const XORNAME_BYTE_LEN: usize = 32;

/// Default replica count for client chunk operations.
const DEFAULT_CLIENT_REPLICA_COUNT: u8 = 1;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level));

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    info!("saorsa-client v{}", env!("CARGO_PKG_VERSION"));

    let bootstrap = resolve_bootstrap(&cli)?;
    let node = create_client_node(bootstrap).await?;
    let client = QuantumClient::new(QuantumConfig {
        timeout_secs: cli.timeout_secs,
        replica_count: DEFAULT_CLIENT_REPLICA_COUNT,
        encrypt_data: false,
    })
    .with_node(node);

    match cli.command {
        ClientCommand::Put { file } => {
            let content = read_input(file)?;
            let address = client.put_chunk(Bytes::from(content)).await?;
            println!("{}", hex::encode(address));
        }
        ClientCommand::Get { address, out } => {
            let addr = parse_address(&address)?;
            let result = client.get_chunk(&addr).await?;
            match result {
                Some(chunk) => write_output(&chunk.content, out)?,
                None => {
                    return Err(color_eyre::eyre::eyre!(
                        "Chunk not found for address {address}"
                    ));
                }
            }
        }
    }

    Ok(())
}

fn resolve_bootstrap(cli: &Cli) -> color_eyre::Result<Vec<std::net::SocketAddr>> {
    if !cli.bootstrap.is_empty() {
        return Ok(cli.bootstrap.clone());
    }

    if let Some(ref manifest_path) = cli.devnet_manifest {
        let data = std::fs::read_to_string(manifest_path)?;
        let manifest: DevnetManifest = serde_json::from_str(&data)?;
        return Ok(manifest.bootstrap);
    }

    Err(color_eyre::eyre::eyre!(
        "No bootstrap peers provided. Use --bootstrap or --devnet-manifest."
    ))
}

async fn create_client_node(bootstrap: Vec<std::net::SocketAddr>) -> Result<Arc<P2PNode>, Error> {
    let mut core_config = saorsa_core::NodeConfig::new()
        .map_err(|e| Error::Config(format!("Failed to create core config: {e}")))?;
    core_config.listen_addr = "0.0.0.0:0"
        .parse()
        .map_err(|e| Error::Config(format!("Invalid listen addr: {e}")))?;
    core_config.listen_addrs = vec![core_config.listen_addr];
    core_config.enable_ipv6 = false;
    core_config.bootstrap_peers = bootstrap;

    let node = P2PNode::new(core_config)
        .await
        .map_err(|e| Error::Network(format!("Failed to create P2P node: {e}")))?;
    node.start()
        .await
        .map_err(|e| Error::Network(format!("Failed to start P2P node: {e}")))?;

    Ok(Arc::new(node))
}

fn parse_address(address: &str) -> color_eyre::Result<XorName> {
    let bytes = hex::decode(address)?;
    if bytes.len() != XORNAME_BYTE_LEN {
        return Err(color_eyre::eyre::eyre!(
            "Invalid address length: expected {} bytes, got {}",
            XORNAME_BYTE_LEN,
            bytes.len()
        ));
    }
    let mut out = [0u8; XORNAME_BYTE_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn read_input(file: Option<PathBuf>) -> color_eyre::Result<Vec<u8>> {
    if let Some(path) = file {
        return Ok(std::fs::read(path)?);
    }

    let mut buf = Vec::new();
    std::io::stdin().read_to_end(&mut buf)?;
    Ok(buf)
}

fn write_output(content: &Bytes, out: Option<PathBuf>) -> color_eyre::Result<()> {
    if let Some(path) = out {
        std::fs::write(path, content)?;
        return Ok(());
    }

    let mut stdout = std::io::stdout();
    stdout.write_all(content)?;
    Ok(())
}
