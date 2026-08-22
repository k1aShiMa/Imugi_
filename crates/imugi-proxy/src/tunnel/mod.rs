/// Core tunnel engine — TLS listener, node handshake, packet forwarding.
 
use crate::{
    session::{register_session, SessionMap, SessionState},
    tun::TunDevice,
};
use imugi_common::{
    decode_len, encode_packet, NodeHello, NodeMsg, ProxyCmd,
    DATA_HEADER_LEN, MAGIC, VERSION,
};
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
 
pub async fn run_proxy(
    bind_addr: SocketAddr,
    tls_config: Arc<ServerConfig>,
    sessions: SessionMap,
    tun: Arc<tokio::sync::Mutex<TunDevice>>,
    routes: Vec<String>,
) -> Result<()> {
    // Add routes to the proxy TUN at startup
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
            Err(e) => { error!("Accept error: {}", e); continue; }
        };
 
        info!("Incoming connection from {}", peer);
 
        let acceptor  = acceptor.clone();
        let sessions  = sessions.clone();
        let tun       = tun.clone();
        let routes    = routes.clone();
 
        tokio::spawn(async move {
            if let Err(e) = handle_node(stream, peer, acceptor, sessions, tun, routes).await {
                error!("Node {} error: {:#}", peer, e);
            }
        });
    }
}
 
async fn handle_node(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    sessions: SessionMap,
    tun: Arc<tokio::sync::Mutex<TunDevice>>,
    routes: Vec<String>,
) -> Result<()> {
    // TLS handshake
    let mut tls = acceptor.accept(stream).await.context("TLS handshake failed")?;
 
    // Magic + version
    let mut magic = [0u8; 4];
    tls.read_exact(&mut magic).await.context("Read magic")?;
    if &magic != MAGIC {
        bail!("Bad magic from {}", peer);
    }
    let ver = tls.read_u8().await.context("Read version")?;
    if ver != VERSION {
        bail!("Version mismatch: got {}, want {}", ver, VERSION);
    }
 
    // NodeHello
    let hello: NodeHello = read_json_msg(&mut tls).await.context("Read NodeHello")?;
    info!(
        "Node hello: host={} user={} os={} ifaces={}",
        hello.hostname, hello.username, hello.os, hello.interfaces.len()
    );
 
    // Channels: TUN reader → node writer, node reader → TUN writer
    let (to_node_tx,   mut to_node_rx)   = mpsc::channel::<Vec<u8>>(CHAN_BUF);
    let (from_node_tx, mut from_node_rx) = mpsc::channel::<Vec<u8>>(CHAN_BUF);
 
    let session_id = register_session(
        &sessions, hello, to_node_tx.clone(), from_node_tx.clone()
    ).await;
 
    // Ready
    write_json_msg(&mut tls, &NodeMsg::Ready { session_id: session_id.clone() })
        .await.context("Write Ready")?;
 
    // StartTunnel — tell the node which routes to add on its side
    write_json_msg(&mut tls, &ProxyCmd::StartTunnel {
        session_id: session_id.clone(),
        routes: routes.clone(),
    }).await.context("Write StartTunnel")?;
 
    if let Some(entry) = sessions.get(&session_id) {
        entry.value().lock().await.state = SessionState::Active;
    }
    info!("Tunnel active — session {} routes={:?}", session_id, routes);
 
    let (mut tls_rx, mut tls_tx) = tokio::io::split(tls);
 
    // TUN reader → node writer
    let tun_r = tun.clone();
    let to_node_tx2 = to_node_tx.clone();
    tokio::spawn(async move {
        loop {
            let pkt = {
                let mut dev = tun_r.lock().await;
                match dev.read_packet().await {
                    Ok(p) => p,
                    Err(e) => { error!("TUN read: {}", e); break; }
                }
            };
            if to_node_tx2.send(pkt).await.is_err() { break; }
        }
    });
 
    // Node writer — drains to_node_rx → tls_tx
    tokio::spawn(async move {
        while let Some(pkt) = to_node_rx.recv().await {
            let framed = encode_packet(&pkt);
            if tls_tx.write_all(&framed).await.is_err() { break; }
        }
    });
 
    // TUN writer — drains from_node_rx → TUN
    tokio::spawn(async move {
        while let Some(pkt) = from_node_rx.recv().await {
            let mut dev = tun.lock().await;
            if dev.write_packet(&pkt).await.is_err() { break; }
        }
    });
 
    // Node reader — length-prefixed packets from tls_rx → from_node_tx
    let mut header = [0u8; DATA_HEADER_LEN];
    loop {
        match tls_rx.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                info!("Node {} disconnected", peer);
                break;
            }
            Err(e) => { warn!("Node {} read error: {}", peer, e); break; }
        }
 
        let len = decode_len(&header);
        if len == 0 || len > 65535 {
            warn!("Bad packet len {} from {}", len, peer);
            continue;
        }
 
        let mut pkt = vec![0u8; len];
        if tls_rx.read_exact(&mut pkt).await.is_err() { break; }
        if from_node_tx.send(pkt).await.is_err() { break; }
    }
 
    if let Some(entry) = sessions.get(&session_id) {
        entry.value().lock().await.state = SessionState::Dead;
    }
    info!("Session {} closed", session_id);
    Ok(())
}
 
async fn read_json_msg<T, R>(reader: &mut R) -> Result<T>
where
    T: for<'de> serde::Deserialize<'de>,
    R: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 65536 { bail!("JSON message too large: {}", len); }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}
 
async fn write_json_msg<T, W>(writer: &mut W, msg: &T) -> Result<()>
where
    T: serde::Serialize,
    W: AsyncWriteExt + Unpin,
{
    let json = serde_json::to_vec(msg)?;
    writer.write_all(&(json.len() as u32).to_le_bytes()).await?;
    writer.write_all(&json).await?;
    Ok(())
}