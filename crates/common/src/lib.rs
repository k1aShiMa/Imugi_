/// Imugi_ wire protocol — shared between imugi-proxy and imugi-node.
 
use serde::{Deserialize, Serialize};
 
pub const MAGIC: &[u8; 4] = b"IMGI";
pub const VERSION: u8 = 1;
pub const MAX_PACKET: usize = 65535;
pub const DATA_HEADER_LEN: usize = 4;
 
// ── Handshake ────────────────────────────────────────────────────────────────
 
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHello {
    pub version: u8,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub interfaces: Vec<NodeInterface>,
    pub node_id: String,
}
 
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInterface {
    pub name: String,
    pub addrs: Vec<String>,
}
 
// ── Control messages ─────────────────────────────────────────────────────────
 
/// Proxy → Node
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ProxyCmd {
    /// Tell the node which subnets to route into the tunnel.
    /// The node creates a TUN, adds these routes via it, and starts forwarding.
    StartTunnel {
        session_id: String,
        /// Subnets the node should route through its local TUN
        /// e.g. ["10.10.110.0/24", "192.168.2.0/24"]
        routes: Vec<String>,
    },
    Shutdown,
    Ping { seq: u64 },
}
 
/// Node → Proxy
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum NodeMsg {
    Ready { session_id: String },
    Pong { seq: u64 },
    Error { msg: String },
}
 
// ── Packet framing ───────────────────────────────────────────────────────────
 
/// Encode a raw IP packet: [4-byte LE len][packet bytes]
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
 
/// Serialize a value to a length-prefixed JSON frame.
pub fn frame_json<T: Serialize>(msg: &T) -> anyhow::Result<bytes::Bytes> {
    let json = serde_json::to_vec(msg)?;
    let mut buf = bytes::BytesMut::with_capacity(4 + json.len());
    buf.extend_from_slice(&(json.len() as u32).to_le_bytes());
    buf.extend_from_slice(&json);
    Ok(buf.freeze())
}