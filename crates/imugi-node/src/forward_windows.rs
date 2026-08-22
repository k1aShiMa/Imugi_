/// Packet forwarding loop — Windows node side.
///
/// Uses tun2 which wraps the WinTun driver internally.
/// tun2 handles all the wintun session management — we just Read/Write.
///
/// Requirements on the target:
///   - wintun.dll alongside the binary (from https://wintun.net/ amd64)
///   - Administrator rights (for TUN adapter creation)

use anyhow::{bail, Context, Result};
use imugi_common::{decode_len, encode_packet, DATA_HEADER_LEN};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

const TUN_NAME: &str    = "imugi-node";
const TUN_ADDR: &str    = "240.0.0.2";
const TUN_NETMASK: &str = "255.255.255.0";
const MTU: usize        = 1500;

struct NodeTun {
    inner: tun2::AsyncDevice,
}

impl NodeTun {
    fn new() -> Result<Self> {
        let mut config = tun2::Configuration::default();
        config
            .tun_name(TUN_NAME)
            .address(TUN_ADDR.parse::<Ipv4Addr>().unwrap())
            .netmask(TUN_NETMASK.parse::<Ipv4Addr>().unwrap())
            .mtu(MTU as u16)
            .up();

        let dev = tun2::create_as_async(&config)
            .context("Failed to create TUN adapter — need Administrator + wintun.dll present")?;

        info!("Node TUN '{}' up at {}", TUN_NAME, TUN_ADDR);
        Ok(NodeTun { inner: dev })
    }

    async fn read_packet(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; MTU + 4];
        let n = self.inner.read(&mut buf).await.context("TUN read")?;
        if n == 0 { bail!("TUN EOF"); }
        buf.truncate(n);
        Ok(buf)
    }

    async fn write_packet(&mut self, pkt: &[u8]) -> Result<()> {
        self.inner.write_all(pkt).await.context("TUN write")
    }

    fn add_route(&self, subnet: &str) -> Result<()> {
        // subnet: "10.10.110.0/24"
        let (net, prefix) = subnet.split_once('/').unwrap_or((subnet, "24"));
        let prefix: u32 = prefix.parse().unwrap_or(24);
        let mask = prefix_to_mask(prefix);

        let out = std::process::Command::new("route")
            .args(["add", net, "mask", &mask, TUN_ADDR])
            .output()
            .context("route add")?;

        if !out.status.success() {
            let e = String::from_utf8_lossy(&out.stderr);
            if !e.to_lowercase().contains("exists") {
                bail!("route add {}: {}", subnet, e.trim());
            }
        }
        info!("Route added: {} via {}", subnet, TUN_ADDR);
        Ok(())
    }
}

pub async fn run_forwarding(
    tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    routes: Vec<String>,
) -> Result<()> {
    let mut tun = NodeTun::new()?;

    for subnet in &routes {
        if let Err(e) = tun.add_route(subnet) {
            warn!("Could not add route {}: {}", subnet, e);
        }
    }

    let (mut tls_rx, mut tls_tx) = tokio::io::split(tls);

    // Channel: TLS reader → TUN writer
    let (to_tun_tx,   mut to_tun_rx)   = mpsc::channel::<Vec<u8>>(256);
    // Channel: TUN reader → TLS writer
    let (from_tun_tx, mut from_tun_rx) = mpsc::channel::<Vec<u8>>(256);

    // TLS reader → to_tun channel
    tokio::spawn(async move {
        let mut header = [0u8; DATA_HEADER_LEN];
        loop {
            match tls_rx.read_exact(&mut header).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    info!("Proxy disconnected");
                    break;
                }
                Err(e) => { warn!("TLS read: {}", e); break; }
            }
            let len = decode_len(&header);
            if len == 0 || len > 65535 { warn!("Bad len {}", len); continue; }
            let mut pkt = vec![0u8; len];
            if tls_rx.read_exact(&mut pkt).await.is_err() { break; }
            if to_tun_tx.send(pkt).await.is_err() { break; }
        }
    });

    // from_tun channel → TLS writer
    tokio::spawn(async move {
        while let Some(pkt) = from_tun_rx.recv().await {
            let framed = encode_packet(&pkt);
            if tls_tx.write_all(&framed).await.is_err() { break; }
        }
    });

    // Single task owns TUN — select! between read and write
    loop {
        tokio::select! {
            result = tun.read_packet() => {
                match result {
                    Ok(pkt) => { if from_tun_tx.send(pkt).await.is_err() { break; } }
                    Err(e)  => { error!("TUN read: {}", e); break; }
                }
            }
            pkt = to_tun_rx.recv() => {
                match pkt {
                    Some(p) => { if let Err(e) = tun.write_packet(&p).await {
                        error!("TUN write: {}", e);
                    }}
                    None => break,
                }
            }
        }
    }

    Ok(())
}

fn prefix_to_mask(prefix: u32) -> String {
    if prefix == 0 { return "0.0.0.0".to_string(); }
    let mask = !0u32 << (32 - prefix.min(32));
    let b = mask.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}