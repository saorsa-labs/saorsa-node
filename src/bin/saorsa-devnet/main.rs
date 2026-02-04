//! saorsa-devnet CLI entry point.

mod cli;

use clap::Parser;
use cli::Cli;
use saorsa_node::devnet::{Devnet, DevnetConfig, DevnetManifest};
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

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

    info!("saorsa-devnet v{}", env!("CARGO_PKG_VERSION"));

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
    config.cleanup_data_dir = cli.cleanup;
    if let Some(delay_ms) = cli.spawn_delay_ms {
        config.spawn_delay = std::time::Duration::from_millis(delay_ms);
    }
    if let Some(timeout_secs) = cli.stabilization_timeout_secs {
        config.stabilization_timeout = std::time::Duration::from_secs(timeout_secs);
    }

    let mut devnet = Devnet::new(config).await?;
    devnet.start().await?;

    let manifest = DevnetManifest {
        base_port: devnet.config().base_port,
        node_count: devnet.config().node_count,
        bootstrap: devnet.bootstrap_addrs(),
        data_dir: devnet.config().data_dir.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let json = serde_json::to_string_pretty(&manifest)?;
    if let Some(path) = cli.manifest {
        tokio::fs::write(&path, &json).await?;
        info!("Wrote manifest to {}", path.display());
    } else {
        println!("{json}");
    }

    info!("Devnet running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;

    devnet.shutdown().await?;
    Ok(())
}
