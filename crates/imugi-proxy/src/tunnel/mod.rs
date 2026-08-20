/// Core tunnel engine.
///
/// Listens for incoming agent TLS connections, performs the handshake,
/// then runs the bidirectional packet forwarding loop between the TUN
/// interface and the agent's TCP data stream.
 
use crate::{
    session::{register_session, SessionMap, SessionState},
    tun::TunDevice,
};
use imugi_common::{NodeHello, NodeMsg, ProxyCmd, DATA_HEADER_LEN, MAGIC};
use anyhow::{bail, Context, Result};
use rustls::ServerConfig;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
 
pub const CHAN_BUF: usize = 512;
 
/// Main entry point: spawn the listener and the TUN forwarding loop.
pub async fn run_proxy(
    bind_addr: SocketAddr,
    tls_config: Arc<ServerConfig>,
    sessions: SessionMap,
    tun: Arc<tokio::sync::Mutex<TunDevice>>,
    routes: Vec<String>,
) -> Result<()> {
    // Apply routes to the TUN device
    {
        let dev = tun.lock().await;
        for route in &routes {
            dev.add_route(route).context("Failed to add route")?;
        }
    }
 
    let listener = TcpListener::bind(bind_addr)
        .await
        .context("Failed to bind listener")?;
    info!("Proxy listening on {}", bind_addr);
 
    let acceptor = TlsAcceptor::from(tls_config);
 
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("Accept error: {}", e);
                continue;
            }
        };
 
        info!("Incoming connection from {}", peer);
 
        let acceptor = acceptor.clone();
        let sessions = sessions.clone();
        let tun = tun.clone();
 
        tokio::spawn(async move {
            if let Err(e) = handle_agent(stream, peer, acceptor, sessions, tun).await {
                error!("Agent {} error: {:#}", peer, e);
            }
        });
    }
}
 
async fn handle_agent(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    sessions: SessionMap,
    tun: Arc<tokio::sync::Mutex<TunDevice>>,
) -> Result<()> {
    // --- TLS handshake ---
    let mut tls = acceptor
        .accept(stream)
        .await
        .context("TLS handshake failed")?;
 
    // --- Magic + version check ---
    let mut magic = [0u8; 4];
    tls.read_exact(&mut magic).await.context("Read magic")?;
    if &magic != MAGIC {
        bail!("Bad magic from {}", peer);
    }
    let ver = tls.read_u8().await.context("Read version")?;
    if ver != imugi_common::VERSION {
        bail!("Version mismatch: got {}, want {}", ver, imugi_common::VERSION);
    }
 
    // --- Read NodeHello ---
    let hello: NodeHello = read_json_msg(&mut tls).await.context("Read NodeHello")?;
    info!(
        "Agent hello: host={} user={} ifaces={}",
        hello.hostname,
        hello.username,
        hello.interfaces.len()
    );
 
    // --- Create channels ---
    // to_agent: proxy TUN reader -> agent writer
    let (to_agent_tx, mut to_agent_rx) = mpsc::channel::<Vec<u8>>(CHAN_BUF);
    // from_agent: agent reader -> proxy TUN writer
    let (from_agent_tx, mut from_agent_rx) = mpsc::channel::<Vec<u8>>(CHAN_BUF);
 
    let session_id = register_session(&sessions, hello, to_agent_tx.clone(), from_agent_tx.clone()).await;
 
    // --- Send Ready ---
    let ready = NodeMsg::Ready {
        session_id: session_id.clone(),
    };
    write_json_msg(&mut tls, &ready)
        .await
        .context("Write Ready")?;
 
    // --- Send StartTunnel ---
    let start = ProxyCmd::StartTunnel {
        session_id: session_id.clone(),
    };
    write_json_msg(&mut tls, &start)
        .await
        .context("Write StartTunnel")?;
 
    // Mark session active
    if let Some(entry) = sessions.get(&session_id) {
        entry.value().lock().await.state = SessionState::Active;
    }
 
    info!("Tunnel active for session {}", session_id);
 
    // --- Split TLS stream into read/write halves ---
    let (mut tls_rx, mut tls_tx) = tokio::io::split(tls);
 
    // Spawn TUN reader -> agent writer
    let tun_clone = tun.clone();
    let to_agent_tx_clone = to_agent_tx.clone();
    tokio::spawn(async move {
        loop {
            let pkt = {
                let mut dev = tun_clone.lock().await;
                match dev.read_packet().await {
                    Ok(p) => p,
                    Err(e) => {
                        error!("TUN read: {}", e);
                        break;
                    }
                }
            };
            if to_agent_tx_clone.send(pkt).await.is_err() {
                break;
            }
        }
    });
 
    // Spawn agent writer — drains to_agent channel -> tls_tx
    tokio::spawn(async move {
        while let Some(pkt) = to_agent_rx.recv().await {
            let framed = imugi_common::encode_packet(&pkt);
            if tls_tx.write_all(&framed).await.is_err() {
                break;
            }
        }
    });
 
    // Spawn TUN writer — drains from_agent channel -> TUN
    tokio::spawn(async move {
        while let Some(pkt) = from_agent_rx.recv().await {
            let mut dev = tun.lock().await;
            if dev.write_packet(&pkt).await.is_err() {
                break;
            }
        }
    });
 
    // This task: agent reader — reads length-prefixed packets from tls_rx -> from_agent_tx
    let mut header = [0u8; DATA_HEADER_LEN];
    loop {
        match tls_rx.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                info!("Agent {} disconnected", peer);
                break;
            }
            Err(e) => {
                warn!("Agent {} read error: {}", peer, e);
                break;
            }
        }
 
        let len = imugi_common::decode_len(&header);
        if len == 0 || len > 65535 {
            warn!("Suspicious packet len {} from {}", len, peer);
            continue;
        }
 
        let mut pkt = vec![0u8; len];
        if tls_rx.read_exact(&mut pkt).await.is_err() {
            break;
        }
 
        if from_agent_tx.send(pkt).await.is_err() {
            break;
        }
    }
 
    // Mark dead
    if let Some(entry) = sessions.get(&session_id) {
        entry.value().lock().await.state = SessionState::Dead;
    }
    info!("Session {} closed", session_id);
    Ok(())
}
 
/// Read a length-prefixed JSON message.
async fn read_json_msg<T, R>(reader: &mut R) -> Result<T>
where
    T: for<'de> serde::Deserialize<'de>,
    R: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 1024 * 64 {
        bail!("JSON message too large: {}", len);
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}
 
/// Write a length-prefixed JSON message.
async fn write_json_msg<T, W>(writer: &mut W, msg: &T) -> Result<()>
where
    T: serde::Serialize,
    W: AsyncWriteExt + Unpin,
{
    let json = serde_json::to_vec(msg)?;
    let len = json.len() as u32;
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(&json).await?;
    Ok(())
}