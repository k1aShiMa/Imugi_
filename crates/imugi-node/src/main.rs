mod connect;
mod forward;
mod sysinfo;
mod tls;
 
use anyhow::{Context, Result};
use clap::Parser;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
 
#[derive(Parser, Debug)]
#[command(name = "imugi-node", about = "Imugi_ Linux node", version)]
struct Args {
    /// Proxy address to connect back to (ip:port)
    #[arg(short, long)]
    proxy: SocketAddr,
 
    /// Retry interval on disconnect in seconds (0 = no retry)
    #[arg(long, default_value = "10")]
    retry: u64,
 
    /// Accept any TLS certificate — for lab use, no cert pinning
    #[arg(long)]
    accept_any_cert: bool,
 
    /// Proxy cert fingerprint for pinning (hex from proxy startup output)
    #[arg(long, value_name = "HEX")]
    fingerprint: Option<String>,
 
    #[arg(long, default_value = "info")]
    log: String,
}
 
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
 
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&args.log)),
        )
        .with_target(false)
        .compact()
        .init();
 
    let tls_config = Arc::new(
        tls::build_client_config(args.accept_any_cert, args.fingerprint.as_deref())
            .context("TLS client config")?,
    );
 
    loop {
        match run_once(args.proxy, tls_config.clone()).await {
            Ok(_)  => info!("Session ended cleanly"),
            Err(e) => error!("Session error: {:#}", e),
        }
 
        if args.retry == 0 { break; }
        warn!("Reconnecting in {}s...", args.retry);
        tokio::time::sleep(Duration::from_secs(args.retry)).await;
    }
 
    Ok(())
}
 
async fn run_once(proxy_addr: SocketAddr, tls_config: Arc<rustls::ClientConfig>) -> Result<()> {
    let session = connect::connect(proxy_addr, tls_config)
        .await
        .context("Connect + handshake")?;
 
    info!("Tunnel active — session {}", session.session_id);
 
    // Pass the routes the proxy told us about down to the forwarding loop
    forward::run_forwarding(session.tls, session.routes)
        .await
        .context("Forwarding loop")?;
 
    Ok(())
}