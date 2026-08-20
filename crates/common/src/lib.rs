/// Imugi_ wire protocol — shared between imugi-proxy and imugi-node.
///
/// Control channel  : length-prefixed (4 bytes LE) JSON messages.
/// Data channel     : length-prefixed (4 bytes LE) raw IP packet bytes.
/// Both channels run multiplexed over the same TLS connection.
 
use serde::{Deserialize, Serialize};
 
// ── Constants ────────────────────────────────────────────────────────────────
 
pub const MAGIC: &[u8; 4] = b"IMGI";
pub const VERSION: u8 = 1;
pub const MAX_PACKET: usize = 65535;
pub const DATA_HEADER_LEN: usize = 4;
 
// ── Handshake ────────────────────────────────────────────────────────────────
 
/// First message sent by the node after TLS handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHello {
    pub version: u8,
    pub hostname: String,
    pub username: String,
    pub os: String,
    /// All network interfaces visible from the node.
    pub interfaces: Vec<NodeInterface>,
    pub node_id: String,
}
 
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInterface {
    pub name: String,
    /// Addresses in CIDR notation, e.g. "192.168.2.10/24"
    pub addrs: Vec<String>,
}
 
// ── Control messages ─────────────────────────────────────────────────────────
 
/// Proxy → Node
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ProxyCmd {
    /// Assign session and start forwarding.
    StartTunnel { session_id: String },
    /// Graceful shutdown.
    Shutdown,
    /// Keepalive.
    Ping { seq: u64 },
}
 
/// Node → Proxy
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum NodeMsg {
    /// Proxy accepted the node; tunnel is ready.
    Ready { session_id: String },
    Pong { seq: u64 },
    Error { msg: String },
}
 
// ── Packet framing ───────────────────────────────────────────────────────────
 
/// Encode a raw IP packet for the data channel: [4-byte LE len][packet bytes].
pub fn encode_packet(pkt: &[u8]) -> bytes::Bytes {
    let mut buf = bytes::BytesMut::with_capacity(DATA_HEADER_LEN + pkt.len());
    buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
    buf.extend_from_slice(pkt);
    buf.freeze()
}
 
/// Decode the 4-byte length header from a data channel frame.
pub fn decode_len(header: &[u8; 4]) -> usize {
    u32::from_le_bytes(*header) as usize
}
 
// ── JSON message framing helpers ─────────────────────────────────────────────
 
/// Serialize a value to a length-prefixed JSON frame.
pub fn frame_json<T: Serialize>(msg: &T) -> anyhow::Result<bytes::Bytes> {
    let json = serde_json::to_vec(msg)?;
    let mut buf = bytes::BytesMut::with_capacity(4 + json.len());
    buf.extend_from_slice(&(json.len() as u32).to_le_bytes());
    buf.extend_from_slice(&json);
    Ok(buf.freeze())
}