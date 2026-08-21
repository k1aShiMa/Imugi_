/// Packet forwarding loop — Linux node side.
///
/// Uses a TUN interface on the node side too (same as the proxy) instead of
/// raw sockets. This is the correct approach:
///
///   - No capture loop (TUN only sees packets explicitly routed to it)
///   - No ethernet header stripping needed (TUN gives raw IP)
///   - No accidental capture of unrelated traffic
///   - Requires the same CAP_NET_ADMIN as creating a TUN on the proxy
///
/// The proxy adds routes pointing at its TUN. The node adds routes on the
/// target pointing at the node's TUN. Packets flow naturally.

use anyhow::{bail, Context, Result};
use imugi_common::{decode_len, encode_packet, DATA_HEADER_LEN};
use std::net::Ipv4Addr;
use std::process::Command;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};

const TUN_NAME: &str = "imugi-node0";
const TUN_ADDR: &str = "240.0.0.2";   // proxy is 240.0.0.1, node is 240.0.0.2
const TUN_NETMASK: &str = "255.255.255.0";
const MTU: usize = 1500;

struct NodeTun {
    name: String,
    inner: tun::AsyncDevice,
}

impl NodeTun {
    fn new() -> Result<Self> {
        let mut config = tun::Configuration::default();
        config
            .name(TUN_NAME)
            .address(TUN_ADDR.parse::<Ipv4Addr>().unwrap())
            .netmask(TUN_NETMASK.parse::<Ipv4Addr>().unwrap())
            .mtu(MTU as i32)
            .up();

        #[cfg(target_os = "linux")]
        config.platform(|p| {
            p.packet_information(false); // raw IP, no PI header
        });

        let dev = tun::create_as_async(&config)
            .context("Failed to create node TUN — need CAP_NET_ADMIN or root")?;

        info!("Node TUN '{}' up at {}", TUN_NAME, TUN_ADDR);
        Ok(NodeTun { name: TUN_NAME.to_owned(), inner: dev })
    }

    async fn read_packet(&mut self) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; MTU + 4];
        let n = self.inner.read(&mut buf).await.context("Node TUN read")?;
        if n == 0 { bail!("Node TUN EOF"); }
        buf.truncate(n);
        Ok(buf)
    }

    async fn write_packet(&mut self, pkt: &[u8]) -> Result<()> {
        self.inner.write_all(pkt).await.context("Node TUN write")
    }

    /// Route a target subnet through this TUN so traffic to it hits the tunnel.
    fn add_route(&self, subnet: &str) -> Result<()> {
        let out = Command::new("ip")
            .args(["route", "add", subnet, "dev", &self.name])
            .output()
            .context("ip route add")?;
        if !out.status.success() {
            let e = String::from_utf8_lossy(&out.stderr);
            if !e.contains("File exists") {
                bail!("ip route add {}: {}", subnet, e.trim());
            }
        }
        info!("Node route added: {} via {}", subnet, self.name);
        Ok(())
    }
}

pub async fn run_forwarding(
    tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    // Subnets the proxy told us to route — traffic to these goes into the tunnel
    routes: Vec<String>,
) -> Result<()> {
    let mut tun = NodeTun::new()?;

    for subnet in &routes {
        // Best-effort — if it fails the user can add manually
        if let Err(e) = tun.add_route(subnet) {
            warn!("Could not add route {}: {}", subnet, e);
        }
    }

    let (mut tls_rx, mut tls_tx) = tokio::io::split(tls);

    let (to_tun_tx, mut to_tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
    let (from_tun_tx, mut from_tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

    // TLS reader → to_tun channel
    let tls_reader_handle = tokio::spawn(async move {
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
            if len == 0 || len > 65535 { continue; }
            let mut pkt = vec![0u8; len];
            if tls_rx.read_exact(&mut pkt).await.is_err() { break; }
            if to_tun_tx.send(pkt).await.is_err() { break; }
        }
    });

    // from_tun channel → TLS writer
    let tls_writer_handle = tokio::spawn(async move {
        while let Some(pkt) = from_tun_rx.recv().await {
            let framed = encode_packet(&pkt);
            if tls_tx.write_all(&framed).await.is_err() { break; }
        }
    });

    // TUN read/write loop (single task owns the TUN device — no locking needed)
    loop {
        tokio::select! {
            // TUN → proxy
            pkt = tun.read_packet() => {
                match pkt {
                    Ok(p) => { if from_tun_tx.send(p).await.is_err() { break; } }
                    Err(e) => { error!("TUN read: {}", e); break; }
                }
            }
            // proxy → TUN
            pkt = to_tun_rx.recv() => {
                match pkt {
                    Some(p) => {
                        if let Err(e) = tun.write_packet(&p).await {
                            error!("TUN write: {}", e);
                        }
                    }
                    None => break,
                }
            }
        }
    }

    tls_reader_handle.abort();
    tls_writer_handle.abort();
    Ok(())
}