mod certs;
mod session;
mod tun;
mod tunnel;
mod ui;
 
use anyhow::{Context, Result};
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
 
#[derive(Parser, Debug)]
#[command(name = "imugi-proxy", about = "Imugi_ reverse pivot proxy", version)]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:4444")]
    listen: SocketAddr,
 
    #[arg(long, default_value = "imugi0")]
    tun_name: String,
 
    #[arg(long, default_value = "240.0.0.1")]
    tun_addr: String,
 
    #[arg(long, default_value = "255.255.255.0")]
    tun_mask: String,
 
    /// Routes to add at startup (repeatable): -r 10.10.110.0/24
    #[arg(short, long, value_name = "CIDR")]
    route: Vec<String>,
 
    #[arg(long)]
    cert: Option<PathBuf>,
 
    #[arg(long)]
    key: Option<PathBuf>,
 
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
 
    if unsafe { libc::geteuid() } != 0 {
        warn!("Not running as root — TUN creation will fail. Use: sudo imugi-proxy");
    }
 
    // TLS
    let (cert_pem, key_pem) = match (&args.cert, &args.key) {
        (Some(c), Some(k)) => {
            let cert = std::fs::read_to_string(c).context("Read cert")?;
            let key  = std::fs::read_to_string(k).context("Read key")?;
            info!("Loaded TLS cert from {}", c.display());
            (cert, key)
        }
        (None, None) => {
            info!("Generating self-signed TLS cert...");
            let gen = certs::generate_self_signed("imugi-proxy").context("Cert gen")?;
            info!("Cert fingerprint (embed in node): {}", gen.fingerprint);
            (gen.cert_pem, gen.key_pem)
        }
        _ => anyhow::bail!("Provide both --cert and --key, or neither"),
    };
 
    let tls_config = certs::build_tls_server_config(&cert_pem, &key_pem)?;
 
    // IP forwarding + TUN
    tun::enable_ip_forwarding()?;
    info!("Creating TUN '{}' at {}", args.tun_name, args.tun_addr);
    let tun_dev = tun::TunDevice::new(&args.tun_name, &args.tun_addr, &args.tun_mask)?;
    let tun = Arc::new(Mutex::new(tun_dev));
 
    let sessions = session::new_session_map();
 
    info!("Ready — listening for nodes on {}", args.listen);
 
    // Tunnel listener task
    let t_sessions = sessions.clone();
    let t_tun      = tun.clone();
    let t_routes   = args.route.clone();
    let tunnel_handle = tokio::spawn(async move {
        if let Err(e) = tunnel::run_proxy(args.listen, tls_config, t_sessions, t_tun, t_routes).await {
            tracing::error!("Tunnel: {:#}", e);
        }
    });
 
    ui::run_ui(sessions, tun).await;
 
    tunnel_handle.abort();
    Ok(())
}