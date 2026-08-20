/// Session state for each connected agent.

use crate::protocol::{AgentHello, AgentInterface};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;
use uuid::Uuid;

/// A packet queued for sending to a specific agent's data channel.
pub type RawPacket = Vec<u8>;

#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    /// Agent connected, sent Hello, waiting for operator to start tunnel
    Connected,
    /// Tunnel is active, routing traffic
    Active,
    /// Agent disconnected or error
    Dead,
}

#[derive(Debug)]
pub struct Session {
    pub id: String,
    pub hello: AgentHello,
    pub state: SessionState,
    /// Proxy sends packets here → agent data channel writer picks them up
    pub to_agent_tx: mpsc::Sender<RawPacket>,
    /// Agent data channel reader sends packets here → TUN writer picks them up
    pub from_agent_tx: mpsc::Sender<RawPacket>,
}

/// Global session registry — keyed by session_id.
pub type SessionMap = Arc<DashMap<String, Arc<tokio::sync::Mutex<Session>>>>;

pub fn new_session_map() -> SessionMap {
    Arc::new(DashMap::new())
}

/// Register a new agent session. Returns session_id and the from_agent receiver.
pub async fn register_session(
    sessions: &SessionMap,
    hello: AgentHello,
    to_agent_tx: mpsc::Sender<RawPacket>,
    from_agent_tx: mpsc::Sender<RawPacket>,
) -> String {
    let id = Uuid::new_v4().to_string();

    info!(
        "New agent registered: id={} host={} user={}",
        id, hello.hostname, hello.username
    );

    let session = Session {
        id: id.clone(),
        hello,
        state: SessionState::Connected,
        to_agent_tx,
        from_agent_tx,
    };

    sessions.insert(id.clone(), Arc::new(tokio::sync::Mutex::new(session)));
    id
}

/// List all live sessions for the UI.
pub async fn list_sessions(sessions: &SessionMap) -> Vec<SessionSummary> {
    let mut out = Vec::new();
    for entry in sessions.iter() {
        let s = entry.value().lock().await;
        out.push(SessionSummary {
            id: s.id.clone(),
            hostname: s.hello.hostname.clone(),
            username: s.hello.username.clone(),
            interfaces: s.hello.interfaces.clone(),
            state: s.state.clone(),
        });
    }
    out
}

#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub id: String,
    pub hostname: String,
    pub username: String,
    pub interfaces: Vec<AgentInterface>,
    pub state: SessionState,
}
