//! Shared state between the egui UI thread and the async MITM proxy tasks.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::oneshot;

/// Traffic scheme of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
    Tcp,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
            Scheme::Tcp => "tcp",
        }
    }
}

/// Lifecycle state of a history entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryState {
    /// Waiting for the response (or intercepted request pending).
    InFlight,
    /// Intercepted and waiting for a user decision.
    Intercepting,
    /// Request/response pair complete.
    Complete,
    /// Dropped by the user in the Intercept tab.
    Dropped,
    /// Forwarding failed.
    Error,
}

/// A captured request/response pair (or raw TCP chunks).
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    pub id: u64,
    /// Epoch milliseconds.
    pub time: u64,
    pub source: Option<SocketAddr>,
    /// host:port or full URL of the destination.
    pub destination: String,
    pub scheme: Scheme,
    pub method: String,
    /// Origin-form path (+query) of the request.
    pub path: String,
    pub host: String,
    pub status: Option<u16>,
    pub resp_len: Option<usize>,
    pub mime: Option<String>,
    pub extension: Option<String>,
    pub title: Option<String>,
    /// Number of query-string parameters in the request target.
    pub params: usize,
    /// True when the request or response was modified in Intercept.
    pub edited: bool,
    /// True for HTTPS entries (Burp's TLS column).
    pub tls: bool,
    /// Resolved origin server IP, when known.
    pub server_ip: Option<String>,
    /// Number of request cookies.
    pub cookies: usize,
    /// Free-form user note (editable in the history table).
    pub notes: String,
    /// Owning process name (TUN mode only), e.g. "chrome.exe".
    pub process: Option<String>,
    /// Raw request bytes as captured (updated when edited via Intercept).
    pub req_raw: Vec<u8>,
    pub resp_raw: Option<Vec<u8>>,
    pub state: EntryState,
    /// True when this entry is a raw TCP session (non-HTTP).
    pub is_tcp: bool,
    /// Human readable error, if any.
    pub error: Option<String>,
}

impl HistoryEntry {
    pub fn url(&self) -> String {
        if self.is_tcp {
            format!("tcp://{}", self.destination)
        } else {
            format!(
                "{}://{}{}",
                self.scheme.as_str(),
                self.destination,
                self.path
            )
        }
    }
}

/// What the user decided to do with an intercepted message.
pub enum Decision {
    Drop,
    /// Forward, optionally replacing the raw bytes (edited by the user).
    Forward(Vec<u8>),
}

/// One message parked in the Intercept tab awaiting a user decision.
pub struct PendingItem {
    pub id: u64,
    /// Corresponding history entry id.
    pub entry_id: u64,
    /// True for requests, false for responses.
    pub is_request: bool,
    /// host:port for display.
    pub destination: String,
    /// Editable copy of the raw message.
    pub raw: Vec<u8>,
    /// Channel back to the async interceptor (UI takes and sends).
    pub tx: std::sync::Mutex<Option<oneshot::Sender<Decision>>>,
    /// Epoch ms when parked.
    pub time: u64,
    pub is_tcp: bool,
    /// True for parked WebSocket payload messages.
    pub is_ws: bool,
    /// WS direction (client perspective) when `is_ws`.
    pub ws_dir: Option<WsDir>,
    /// WS opcode label ("text", "binary", ...) when `is_ws`.
    pub ws_opcode: String,
}

/// Proxy settings (persisted to finch.json).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxySettings {
    pub listen_port: u16,
    pub upstream_proxy: Option<String>,
    /// Intercept requests by default (runtime toggles live in the UI).
    pub history_limit: usize,
    /// Concurrency of Intruder attacks.
    pub attack_concurrency: usize,
    /// Host blacklist: one regex per entry, matched against the CONNECT
    /// target / request Host. Empty = allow everything.
    #[serde(default)]
    pub host_blacklist: Vec<String>,
    /// AI assistant configuration (OpenAI-compatible endpoint).
    #[serde(default)]
    pub ai: AiSettings,
    /// Configured MCP servers.
    #[serde(default)]
    pub mcp_servers: Vec<McpServerConfig>,
    /// TUN mode process filter: capture only flows whose owning process name
    /// contains one of these entries (case-insensitive). Empty = capture all
    /// processes (Finch itself is always excluded from the proxy path).
    #[serde(default)]
    pub tun_process_filter: Vec<String>,
}

/// OpenAI-compatible chat endpoint settings.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AiSettings {
    /// e.g. "https://api.openai.com" (the /v1/chat/completions path is appended).
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub model: String,
    #[serde(default = "default_ai_system_prompt")]
    pub system_prompt: String,
    #[serde(default = "default_ai_temperature")]
    pub temperature: f32,
}

impl Default for AiSettings {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            api_key: String::new(),
            model: String::new(),
            system_prompt: default_ai_system_prompt(),
            temperature: 0.4,
        }
    }
}

fn default_ai_system_prompt() -> String {
    "You are Finch's AI pentest assistant embedded in a Burp Suite style proxy.      You can inspect captured traffic and send raw HTTP requests through the proxy      engine using the provided tools. Help the user analyze requests, find      vulnerabilities and verify findings. Be concise and technical."
        .to_string()
}

fn default_ai_temperature() -> f32 {
    0.4
}

/// One configured MCP server.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct McpServerConfig {
    pub name: String,
    #[serde(default)]
    pub transport: McpTransportConfig,
}

/// stdio spawns a local process; http talks JSON-RPC over Streamable HTTP.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum McpTransportConfig {
    /// Local subprocess: command + args.
    Stdio {
        #[serde(default)]
        command: String,
        #[serde(default)]
        args: Vec<String>,
    },
    /// Remote Streamable HTTP endpoint URL.
    Http {
        #[serde(default)]
        url: String,
        #[serde(default)]
        headers: Vec<(String, String)>,
    },
}

impl Default for McpTransportConfig {
    fn default() -> Self {
        McpTransportConfig::Http {
            url: String::new(),
            headers: Vec::new(),
        }
    }
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            listen_port: 8080,
            upstream_proxy: None,
            history_limit: 10000,
            attack_concurrency: 10,
            host_blacklist: Vec::new(),
            ai: AiSettings::default(),
            mcp_servers: Vec::new(),
            tun_process_filter: Vec::new(),
        }
    }
}

/// State shared between the UI and the proxy runtime.
pub struct SharedState {
    /// Newest entry at the back.
    pub history: Mutex<VecDeque<Arc<Mutex<HistoryEntry>>>>,
    /// Messages parked in the Intercept tab.
    pub pending: Mutex<Vec<Arc<PendingItem>>>,
    /// Intercept request toggle (Intercept is on/off).
    pub intercept_req: AtomicBool,
    /// Intercept responses toggle.
    pub intercept_resp: AtomicBool,
    /// Intercept WebSocket messages toggle.
    pub intercept_ws: AtomicBool,
    /// Optional substring filter; empty = intercept everything.
    pub intercept_filter: Mutex<String>,
    /// TUN mode runtime state (UI toggle + status line).
    pub tun_enabled: AtomicBool,
    /// Last TUN event/error for the Options card, e.g. adapter info.
    pub tun_status: Mutex<String>,
    /// TUN flow attribution: the local port Finch used when dialing the
    /// proxy on behalf of a TUN flow -> owning process name + insert time.
    /// The interceptor reads this by the client source port to tag history
    /// entries. Entries expire after ~2 minutes.
    pub tun_proc_map: Mutex<HashMap<u16, (String, std::time::Instant)>>,
    /// TUN flow decisions for the TUN tab (newest first, capped): one line
    /// per TCP flow — process, target and the path taken (proxy/direct).
    pub tun_events: Mutex<std::collections::VecDeque<String>>,
    /// session_id (mitm correlation) -> ids of this connection's requests
    /// awaiting their response, in request order (FIFO). HTTP/1.1 answers
    /// requests in order, so popping the front pairs each response with the
    /// right request — including pipelined ones.
    pub session_map: Mutex<HashMap<u128, VecDeque<u64>>>,
    /// Captured WebSocket sessions (newest at the back).
    pub ws_sessions: Mutex<Vec<Arc<Mutex<WsSession>>>>,
    /// session_id (mitm correlation) -> session handle.
    pub ws_session_map: Mutex<HashMap<u128, Arc<Mutex<WsSession>>>>,
    /// hostname -> resolved IP (None = lookup failed). Avoids repeated DNS.
    pub dns_cache: Mutex<HashMap<String, Option<String>>>,
    pub next_id: AtomicU64,
    /// Set by the app so async tasks can wake the UI.
    pub ui_ctx: OnceLock<egui::Context>,
    pub settings: Mutex<ProxySettings>,
    /// Short-lived status message for the status bar.
    pub status: Mutex<String>,
    /// The live mitm proxy (kept for CA export).
    pub proxy: Mutex<Option<Arc<crate::mitm::MitmProxy>>>,
    /// Handle to the spawned proxy task (for restarts).
    pub proxy_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub proxy_listening: AtomicBool,
}

impl SharedState {
    pub fn new(settings: ProxySettings) -> Arc<Self> {
        Arc::new(Self {
            history: Mutex::new(VecDeque::new()),
            pending: Mutex::new(Vec::new()),
            intercept_req: AtomicBool::new(false),
            intercept_resp: AtomicBool::new(false),
            intercept_ws: AtomicBool::new(false),
            intercept_filter: Mutex::new(String::new()),
            tun_enabled: AtomicBool::new(false),
            tun_status: Mutex::new(String::new()),
            tun_proc_map: Mutex::new(HashMap::new()),
            tun_events: Mutex::new(std::collections::VecDeque::new()),
            session_map: Mutex::new(HashMap::new()),
            ws_sessions: Mutex::new(Vec::new()),
            ws_session_map: Mutex::new(HashMap::new()),
            dns_cache: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            ui_ctx: OnceLock::new(),
            settings: Mutex::new(settings),
            status: Mutex::new(String::from("Starting...")),
            proxy: Mutex::new(None),
            proxy_task: Mutex::new(None),
            proxy_listening: AtomicBool::new(false),
        })
    }

    pub fn next_entry_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Wake the UI (call from any thread).
    pub fn wake(&self) {
        if let Some(ctx) = self.ui_ctx.get() {
            ctx.request_repaint();
        }
    }

    pub fn set_status(&self, msg: impl Into<String>) {
        *self.status.lock().unwrap() = msg.into();
        self.wake();
    }

    pub fn push_history(&self, entry: HistoryEntry) -> Arc<Mutex<HistoryEntry>> {
        let arc = Arc::new(Mutex::new(entry));
        let limit = self.settings.lock().unwrap().history_limit;
        let mut hist = self.history.lock().unwrap();
        while hist.len() >= limit {
            hist.pop_front();
        }
        hist.push_back(arc.clone());
        arc
    }

    /// Push a message into the Intercept queue and return its pending id.
    pub fn push_pending(&self, item: PendingItem) -> u64 {
        let id = item.id;
        self.pending.lock().unwrap().push(Arc::new(item));
        self.wake();
        id
    }

    pub fn remove_pending(&self, id: u64) {
        self.pending.lock().unwrap().retain(|p| p.id != id);
        self.wake();
    }

    /// Register a WebSocket handshake so later frames can be attributed.
    pub fn create_ws_session(
        &self,
        session_id: u128,
        url: String,
        destination: String,
        tls: bool,
        time: u64,
    ) {
        let session = WsSession {
            id: self.next_entry_id(),
            url,
            destination,
            tls,
            time,
            state: WsSessionState::Open,
            messages: Vec::new(),
        };
        let arc = Arc::new(Mutex::new(session));
        {
            let mut sessions = self.ws_sessions.lock().unwrap();
            let limit = self.settings.lock().unwrap().history_limit;
            while sessions.len() >= limit {
                sessions.remove(0);
            }
            sessions.push(arc.clone());
        }
        self.ws_session_map.lock().unwrap().insert(session_id, arc);
        self.wake();
    }

    /// Append a captured WebSocket message to its session (if still tracked).
    pub fn push_ws_message(
        &self,
        session_id: u128,
        direction: WsDir,
        opcode: String,
        payload: Vec<u8>,
        time: u64,
    ) {
        let session = self
            .ws_session_map
            .lock()
            .unwrap()
            .get(&session_id)
            .cloned();
        if let Some(session) = session {
            let entry = WsMessageEntry {
                direction,
                opcode,
                size: payload.len(),
                payload,
                time,
            };
            let mut s = session.lock().unwrap();
            // Cap per-session message log to keep memory bounded.
            const MAX_WS_MESSAGES: usize = 5000;
            if s.messages.len() >= MAX_WS_MESSAGES {
                s.messages.remove(0);
            }
            s.messages.push(entry);
            drop(s);
            self.wake();
        }
    }

    /// Mark a WebSocket session as finished (connection closed or failed).
    pub fn finish_ws_session(&self, session_id: u128, state: WsSessionState) {
        let session = self
            .ws_session_map
            .lock()
            .unwrap()
            .get(&session_id)
            .cloned();
        if let Some(session) = session {
            session.lock().unwrap().state = state;
            self.wake();
        }
    }

    /// Drop all captured WebSocket sessions.
    pub fn clear_ws_sessions(&self) {
        self.ws_sessions.lock().unwrap().clear();
        self.ws_session_map.lock().unwrap().clear();
        self.wake();
    }
}

/// Direction of a captured WebSocket message (from the client's perspective).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsDir {
    /// Client -> origin server.
    Out,
    /// Origin server -> client.
    In,
}

impl WsDir {
    pub fn as_str(self) -> &'static str {
        match self {
            WsDir::Out => "↑",
            WsDir::In => "↓",
        }
    }
}

/// Lifecycle of a captured WebSocket session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsSessionState {
    Open,
    Closed,
    Error,
}

impl WsSessionState {
    pub fn as_str(self) -> &'static str {
        match self {
            WsSessionState::Open => "open",
            WsSessionState::Closed => "closed",
            WsSessionState::Error => "error",
        }
    }
}

/// One captured WebSocket message (payload unmasked).
#[derive(Debug, Clone)]
pub struct WsMessageEntry {
    pub direction: WsDir,
    /// "text" / "binary" / "ping" / "pong" / "close" / ...
    pub opcode: String,
    pub payload: Vec<u8>,
    /// Epoch ms.
    pub time: u64,
    pub size: usize,
}

/// One captured WebSocket connection (handshake + message log).
#[derive(Debug)]
pub struct WsSession {
    pub id: u64,
    /// ws(s)://host/path of the handshake.
    pub url: String,
    pub destination: String,
    pub tls: bool,
    /// Epoch ms of the handshake.
    pub time: u64,
    pub state: WsSessionState,
    pub messages: Vec<WsMessageEntry>,
}

/// Formatter: epoch ms -> local "HH:MM:SS".
pub fn format_time(epoch_ms: u64) -> String {
    chrono::DateTime::from_timestamp_millis(epoch_ms as i64)
        .map(|dt| dt.with_timezone(&chrono::Local::now().timezone()))
        .map(|dt| dt.format("%H:%M:%S").to_string())
        .unwrap_or_default()
}
