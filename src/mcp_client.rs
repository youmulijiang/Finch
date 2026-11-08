//! Minimal MCP (Model Context Protocol) client: JSON-RPC 2.0 over stdio
//! (local subprocess) or Streamable HTTP. Implements the handshake
//! (`initialize` → `notifications/initialized`), `tools/list` and
//! `tools/call`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

/// A tool advertised by an MCP server.
#[derive(Debug, Clone)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    /// JSON schema of the arguments (raw value; empty object when absent).
    pub schema: Value,
}

/// Connection state shown in the UI.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum McpStatus {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Error,
}

/// A live connection to one MCP server.
pub struct McpConnection {
    pub name: String,
    pub transport: crate::state::McpTransportConfig,
    pub status: McpStatus,
    pub error: Option<String>,
    pub tools: Vec<McpTool>,
    /// stdio child process (dropped => killed).
    child: Option<Child>,
    /// stdio stdin writer.
    stdin: Option<tokio::process::ChildStdin>,
    /// stdio reader buffer (line-based JSON-RPC).
    reader: Option<BufReader<tokio::process::ChildStdout>>,
    /// HTTP session id (Streamable HTTP `Mcp-Session-Id` header).
    session_id: Option<String>,
    /// Streamable HTTP endpoint.
    http_url: Option<String>,
    /// Extra HTTP headers for the Streamable HTTP transport.
    http_headers: Vec<(String, String)>,
    next_id: AtomicU64,
}

impl McpConnection {
    pub fn new(name: String, transport: crate::state::McpTransportConfig) -> Self {
        Self {
            name,
            transport,
            status: McpStatus::Disconnected,
            error: None,
            tools: Vec::new(),
            child: None,
            stdin: None,
            reader: None,
            session_id: None,
            http_url: None,
            http_headers: Vec::new(),
            next_id: AtomicU64::new(1),
        }
    }

    async fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Perform the handshake and fetch the tool list.
    pub async fn connect(&mut self) -> Result<(), String> {
        self.status = McpStatus::Connecting;
        self.error = None;
        match self.transport.clone() {
            crate::state::McpTransportConfig::Stdio { command, args } => {
                self.connect_stdio(&command, &args).await
            }
            crate::state::McpTransportConfig::Http { url, headers } => {
                self.connect_http(&url, &headers).await
            }
        }
    }

    async fn connect_stdio(&mut self, command: &str, args: &[String]) -> Result<(), String> {
        let mut child = Command::new(command)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn '{command}' failed: {e}"))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = child.stdout.take().ok_or("no stdout")?;
        self.child = Some(child);
        self.stdin = Some(stdin);
        self.reader = Some(BufReader::new(stdout));

        let result = self.handshake().await;
        if result.is_ok() {
            self.status = McpStatus::Connected;
        } else {
            self.status = McpStatus::Error;
            self.error = result.as_ref().err().cloned();
            self.shutdown();
        }
        result
    }

    async fn connect_http(
        &mut self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<(), String> {
        self.http_url = Some(url.to_string());
        self.http_headers = headers.to_vec();
        let result = self.handshake().await;
        if result.is_ok() {
            self.status = McpStatus::Connected;
        } else {
            self.status = McpStatus::Error;
            self.error = result.as_ref().err().cloned();
        }
        result
    }

    /// `initialize` + `notifications/initialized` + `tools/list`.
    async fn handshake(&mut self) -> Result<(), String> {
        let id = self.next_id().await;
        let init = json!({
            "jsonrpc": "2.0", "id": id, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "finch", "version": env!("CARGO_PKG_VERSION")}
            }
        });
        let resp = self.request(init).await?;
        // Server info / capabilities ignored; send the initialized notification.
        let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        self.send_notification(note).await?;
        let _ = resp;

        self.refresh_tools().await
    }

    /// Re-fetch `tools/list`.
    pub async fn refresh_tools(&mut self) -> Result<(), String> {
        let id = self.next_id().await;
        let req = json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": {}});
        let resp = self.request(req).await?;
        let tools = resp
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
            .cloned()
            .unwrap_or_default();
        self.tools = tools
            .iter()
            .map(|t| McpTool {
                name: t
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string(),
                description: t
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                schema: t.get("inputSchema").cloned().unwrap_or(json!({})),
            })
            .collect();
        Ok(())
    }

    /// Call a tool and return its text content (or an error string).
    pub async fn call_tool(&mut self, name: &str, args: Value) -> Result<String, String> {
        let id = self.next_id().await;
        let req = json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": name, "arguments": args}
        });
        let resp = self.request(req).await?;
        if let Some(err) = resp.get("error") {
            return Err(format!("MCP error: {err}"));
        }
        let content = resp
            .pointer("/result/content")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();
        let mut text = String::new();
        for part in content {
            if part.get("type").and_then(|t| t.as_str()) == Some("text") {
                if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(t);
                }
            }
        }
        if text.is_empty() {
            // Fall back to the raw JSON result.
            text = resp
                .get("result")
                .map(|r| r.to_string())
                .unwrap_or_default();
        }
        Ok(text)
    }

    /// Send one JSON-RPC request and await its matching response.
    async fn request(&mut self, req: Value) -> Result<Value, String> {
        match &self.transport {
            crate::state::McpTransportConfig::Stdio { .. } => self.request_stdio(req).await,
            crate::state::McpTransportConfig::Http { .. } => self.request_http(req).await,
        }
    }

    async fn request_stdio(&mut self, req: Value) -> Result<Value, String> {
        let line = serde_json::to_string(&req).map_err(|e| e.to_string())?;
        let stdin = self.stdin.as_mut().ok_or("not connected")?;
        stdin
            .write_all(line.as_bytes())
            .await
            .map_err(|e| format!("write failed: {e}"))?;
        stdin.write_all(b"\n").await.map_err(|e| e.to_string())?;
        stdin.flush().await.map_err(|e| e.to_string())?;

        let want_id = req.get("id").cloned();
        let reader = self.reader.as_mut().ok_or("not connected")?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let mut line = String::new();
            let n = tokio::time::timeout_at(deadline, reader.read_line(&mut line))
                .await
                .map_err(|_| "timeout waiting for MCP response".to_string())?
                .map_err(|e| format!("read failed: {e}"))?;
            if n == 0 {
                return Err("MCP server closed stdout".into());
            }
            let v: Value = match serde_json::from_str(line.trim()) {
                Ok(v) => v,
                Err(_) => continue, // skip non-JSON noise
            };
            // Skip notifications / responses to other requests.
            if v.get("id") == want_id.as_ref() {
                return Ok(v);
            }
        }
    }

    async fn request_http(&mut self, req: Value) -> Result<Value, String> {
        let url = self.http_url.clone().ok_or("not connected")?;
        let body = serde_json::to_string(&req).map_err(|e| e.to_string())?;
        let (status, headers, text) =
            http_post_json(&url, &body, &self.http_headers, self.session_id.as_deref()).await?;
        if !status.is_success() {
            return Err(format!("HTTP {status}: {}", truncate(&text, 300)));
        }
        if let Some(sid) = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("mcp-session-id"))
            .map(|(_, v)| v.clone())
        {
            self.session_id = Some(sid);
        }
        // Streamable HTTP may answer with SSE; extract the data: payload.
        let payload = extract_json_payload(&text)?;
        Ok(payload)
    }

    async fn send_notification(&mut self, note: Value) -> Result<(), String> {
        match &self.transport {
            crate::state::McpTransportConfig::Stdio { .. } => {
                let line = serde_json::to_string(&note).map_err(|e| e.to_string())?;
                let stdin = self.stdin.as_mut().ok_or("not connected")?;
                stdin
                    .write_all(line.as_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
                stdin.write_all(b"\n").await.map_err(|e| e.to_string())?;
                stdin.flush().await.map_err(|e| e.to_string())?;
                Ok(())
            }
            crate::state::McpTransportConfig::Http { .. } => {
                let url = self.http_url.clone().ok_or("not connected")?;
                let body = serde_json::to_string(&note).map_err(|e| e.to_string())?;
                let (status, _, text) =
                    http_post_json(&url, &body, &self.http_headers, self.session_id.as_deref())
                        .await?;
                if !status.is_success() {
                    return Err(format!("HTTP {status}: {}", truncate(&text, 200)));
                }
                Ok(())
            }
        }
    }

    pub fn shutdown(&mut self) {
        self.stdin = None; // dropping closes the pipe
        self.reader = None;
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
        }
        self.status = McpStatus::Disconnected;
        self.session_id = None;
    }
}

/// HTTP POST helper running on the tokio runtime via slinger.
async fn http_post_json(
    url: &str,
    body: &str,
    headers: &[(String, String)],
    session: Option<&str>,
) -> Result<(http::StatusCode, Vec<(String, String)>, String), String> {
    let client = slinger::Client::builder()
        .timeout(Some(Duration::from_secs(30)))
        .build()
        .map_err(|e| e.to_string())?;
    let mut builder = client
        .post(url.parse::<http::Uri>().map_err(|e| e.to_string())?)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream");
    if let Some(sid) = session {
        builder = builder.header("Mcp-Session-Id", sid);
    }
    for (k, v) in headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let resp = builder
        .body(body.as_bytes().to_vec())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status_code();
    let resp_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let text = resp.text().unwrap_or_default();
    Ok((status, resp_headers, text))
}

/// Extract a JSON-RPC payload from a raw body (plain JSON or SSE lines).
fn extract_json_payload(text: &str) -> Result<Value, String> {
    if let Ok(v) = serde_json::from_str::<Value>(text.trim()) {
        return Ok(v);
    }
    // SSE: take the last data: line containing an id (a response).
    for line in text.lines().rev() {
        if let Some(data) = line.strip_prefix("data:") {
            if let Ok(v) = serde_json::from_str::<Value>(data.trim()) {
                if v.get("id").is_some() || v.get("result").is_some() {
                    return Ok(v);
                }
            }
        }
    }
    Err(format!(
        "no JSON-RPC payload in response: {}",
        truncate(text, 200)
    ))
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}...", &s[..n])
    }
}

/// Synchronous one-shot helper for tests: connect, list tools, call a tool.
pub async fn quick_call(
    transport: crate::state::McpTransportConfig,
    name: &str,
    args: Value,
) -> Result<(Vec<McpTool>, String), String> {
    let name_owned = name.to_string();
    let mut conn = McpConnection::new(name_owned, transport);
    conn.connect().await?;
    let tools = conn.tools.clone();
    let result = conn.call_tool(name, args).await;
    conn.shutdown();
    result.map(|r| (tools, r))
}
