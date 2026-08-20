/// TLS connect-back to the proxy and protocol handshake.
 
use crate::sysinfo;
use anyhow::{bail, Context, Result};
use imugi_common::{NodeHello, NodeMsg, ProxyCmd, MAGIC, VERSION};
use rustls::{ClientConfig, ServerName};
use std::{net::SocketAddr, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tracing::info;
use uuid::Uuid;
 
/// Established tunnel session returned after a successful handshake.
pub struct TunnelSession {
    pub session_id: String,
    pub tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
}
 
/// Connect to the proxy, perform the Imugi_ handshake, return the live stream.
pub async fn connect(proxy_addr: SocketAddr, tls_config: Arc<ClientConfig>) -> Result<TunnelSession> {
    info!("Connecting to proxy at {}", proxy_addr);
 
    let tcp = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .context("TCP connect failed")?;
 
    // SNI name matches what the proxy cert was generated with
    let server_name = ServerName::try_from("imugi-proxy")
        .context("Invalid SNI name")?;
 
    let connector = TlsConnector::from(tls_config);
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake failed")?;
 
    info!("TLS handshake OK");
 
    // Send magic + version
    tls.write_all(MAGIC).await.context("Write magic")?;
    tls.write_u8(VERSION).await.context("Write version")?;
 
    // Build and send NodeHello
    let hello = NodeHello {
        version: VERSION,
        hostname: sysinfo::get_hostname(),
        username: sysinfo::get_username(),
        os: "linux".to_string(),
        interfaces: sysinfo::get_interfaces(),
        node_id: Uuid::new_v4().to_string(),
    };
 
    info!(
        "Sending hello: host={} user={} ifaces={}",
        hello.hostname, hello.username, hello.interfaces.len()
    );
    write_json_msg(&mut tls, &hello).await.context("Write NodeHello")?;
 
    // Read Ready
    let ready: NodeMsg = read_json_msg(&mut tls).await.context("Read Ready")?;
    let session_id = match ready {
        NodeMsg::Ready { session_id } => session_id,
        NodeMsg::Error { msg } => bail!("Proxy error: {}", msg),
        _ => bail!("Unexpected message from proxy"),
    };
    info!("Session assigned: {}", session_id);
 
    // Read StartTunnel
    let cmd: ProxyCmd = read_json_msg(&mut tls).await.context("Read StartTunnel")?;
    match cmd {
        ProxyCmd::StartTunnel { .. } => info!("Tunnel started"),
        ProxyCmd::Shutdown => bail!("Proxy sent shutdown before tunnel started"),
        _ => bail!("Unexpected command from proxy"),
    }
 
    Ok(TunnelSession { session_id, tls })
}
 
pub async fn read_json_msg<T, R>(reader: &mut R) -> Result<T>
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
 
pub async fn write_json_msg<T, W>(writer: &mut W, msg: &T) -> Result<()>
where
    T: serde::Serialize,
    W: AsyncWriteExt + Unpin,
{
    let json = serde_json::to_vec(msg)?;
    writer.write_all(&(json.len() as u32).to_le_bytes()).await?;
    writer.write_all(&json).await?;
    Ok(())
}