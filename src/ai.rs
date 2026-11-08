//! AI assistant: OpenAI-compatible chat client (function calling) with a
//! tool-execution loop that combines Finch built-in tools and MCP tools.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;

use serde_json::{Value, json};

use crate::state::SharedState;

// ---------------------------------------------------------------- data model

/// One chat message in the UI-visible conversation.
#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatRole {
    User,
    Assistant,
    /// A tool result rendered into the conversation.
    Tool,
    /// System / error note.
    Notice,
}

impl ChatRole {
    pub fn as_str(self) -> &'static str {
        match self {
            ChatRole::User => "user",
            ChatRole::Assistant => "assistant",
            ChatRole::Tool => "tool",
            ChatRole::Notice => "notice",
        }
    }
}

/// A Finch built-in tool callable by the model.
pub struct BuiltinTool {
    pub name: &'static str,
    pub description: &'static str,
    /// JSON schema of the `parameters` object.
    pub schema: Value,
}

pub fn builtin_tools() -> &'static [BuiltinTool] {
    static TOOLS: OnceLock<Vec<BuiltinTool>> = OnceLock::new();
    TOOLS.get_or_init(|| vec![
    BuiltinTool {
        name: "send_http_request",
        description:
            "Send a raw HTTP request through Finch's engine and return the response (status, headers, body). Use for active testing.",
        schema: json!({
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Full target URL, e.g. http://example.com:8080 (scheme determines http/https)"},
                "raw": {"type": "string", "description": "Raw HTTP/1.1 request including headers and optional body. The request line and Host header are corrected to match target_url."}
            },
            "required": ["target_url", "raw"]
        }),
    },
    BuiltinTool {
        name: "list_history",
        description: "List recently captured proxy traffic entries (id, method, URL, status, length, mime).",
        schema: json!({
            "type": "object",
            "properties": {
                "filter": {"type": "string", "description": "Optional substring filter on the URL"},
                "limit": {"type": "integer", "description": "Max entries to return (default 20)"}
            }
        }),
    },
    BuiltinTool {
        name: "get_history_entry",
        description: "Get the full raw request and response of one captured entry by id.",
        schema: json!({
            "type": "object",
            "properties": {"id": {"type": "integer", "description": "History entry id"}},
            "required": ["id"]
        }),
    },
    BuiltinTool {
        name: "list_ws_sessions",
        description: "List captured WebSocket sessions (id, url, state, message count).",
        schema: json!({"type": "object", "properties": {}}),
    },
    BuiltinTool {
        name: "get_ws_messages",
        description: "Get the captured messages of one WebSocket session by id (direction, opcode, payload text).",
        schema: json!({
            "type": "object",
            "properties": {"id": {"type": "integer", "description": "WS session id"}},
            "required": ["id"]
        }),
    },
    ])
}

/// OpenAI `tools` array from the built-in tools plus the MCP tools.
pub fn tool_definitions(mcp_tools: &[(String, String, Value)]) -> Value {
    let mut tools: Vec<Value> = builtin_tools()
        .iter()
        .map(|t| {
            json!({
                "type": "function",
                "function": {"name": t.name, "description": t.description, "parameters": t.schema}
            })
        })
        .collect();
    for (name, description, schema) in mcp_tools {
        tools.push(json!({
            "type": "function",
            "function": {"name": name, "description": description, "parameters": schema}
        }));
    }
    Value::Array(tools)
}

// ------------------------------------------------------------------ client

/// One assistant tool call requested by the model.
#[derive(Debug, Clone)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    /// Arguments as a JSON object string.
    pub arguments: String,
}

/// Parsed assistant turn: text content + optional tool calls.
#[derive(Debug, Default)]
pub struct AssistantTurn {
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
}

/// POST /v1/chat/completions and parse the first choice.
pub async fn chat_completion(
    base_url: &str,
    api_key: &str,
    model: &str,
    temperature: f32,
    messages: &[Value],
    tools: Option<&Value>,
) -> Result<AssistantTurn, String> {
    let url = format!("{}/v1/chat/completions", base_url.trim_end_matches('/'));
    let mut body = json!({
        "model": model,
        "temperature": temperature,
        "messages": messages,
    });
    if let Some(t) = tools {
        body["tools"] = t.clone();
    }
    let (status, text) = http_post_json(
        &url,
        &body.to_string(),
        &[
            ("Authorization".to_string(), format!("Bearer {api_key}")),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
    )
    .await?;
    if !status.is_success() {
        return Err(format!("LLM API {status}: {}", truncate(&text, 400)));
    }
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("bad JSON: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("LLM API error: {err}"));
    }
    let choice = v
        .pointer("/choices/0")
        .ok_or_else(|| format!("no choices in response: {}", truncate(&text, 300)))?;
    let content = choice
        .pointer("/message/content")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_string();
    let mut tool_calls = Vec::new();
    if let Some(calls) = choice
        .pointer("/message/tool_calls")
        .and_then(|t| t.as_array())
    {
        for call in calls {
            let function = call.get("function").cloned().unwrap_or(Value::Null);
            tool_calls.push(ToolCall {
                id: call
                    .get("id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("call_0")
                    .to_string(),
                name: function
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("?")
                    .to_string(),
                arguments: function
                    .get("arguments")
                    .and_then(|a| a.as_str())
                    .unwrap_or("{}")
                    .to_string(),
            });
        }
    }
    Ok(AssistantTurn {
        content,
        tool_calls,
    })
}

async fn http_post_json(
    url: &str,
    body: &str,
    headers: &[(String, String)],
) -> Result<(http::StatusCode, String), String> {
    let client = slinger::Client::builder()
        .timeout(Some(std::time::Duration::from_secs(120)))
        .build()
        .map_err(|e| e.to_string())?;
    let mut builder = client.post(url.parse::<http::Uri>().map_err(|e| e.to_string())?);
    for (k, v) in headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let resp = builder
        .body(body.as_bytes().to_vec())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = resp.status_code();
    let text = resp.text().unwrap_or_default();
    Ok((status, text))
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}...", &s[..n])
    }
}

// -------------------------------------------------------------- built-in tools

/// Execute a Finch built-in tool by name with JSON arguments.
pub async fn execute_builtin(
    shared: &Arc<SharedState>,
    name: &str,
    args: &Value,
) -> Result<String, String> {
    match name {
        "send_http_request" => {
            let url = args
                .get("target_url")
                .and_then(|v| v.as_str())
                .ok_or("missing target_url")?;
            let raw = args
                .get("raw")
                .and_then(|v| v.as_str())
                .ok_or("missing raw")?;
            let bytes = normalize_request(url, raw)?;
            let (scheme, authority) = split_url(url)?;
            let result = crate::engine::send_raw(
                &scheme,
                &authority,
                &bytes,
                std::time::Duration::from_secs(30),
            )
            .await;
            let mut out = String::new();
            match result.status {
                Some(st) => out.push_str(&format!("HTTP {st}\n")),
                None => {
                    out.push_str(&format!(
                        "REQUEST FAILED: {}\n",
                        result.error.clone().unwrap_or_default()
                    ));
                }
            }
            for (k, v) in &result.headers {
                out.push_str(&format!("{k}: {v}\n"));
            }
            out.push('\n');
            let body = String::from_utf8_lossy(&result.body);
            out.push_str(&truncate(&body, 8000));
            Ok(out)
        }
        "list_history" => {
            let filter = args
                .get("filter")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
            let hist = shared.history.lock().unwrap();
            let mut out = String::from("id | method | url | status | len | mime\n");
            let mut count = 0;
            for e in hist.iter().rev() {
                let e = e.lock().unwrap();
                if !filter.is_empty() && !e.url().to_lowercase().contains(&filter) {
                    continue;
                }
                out.push_str(&format!(
                    "{} | {} | {} | {} | {} | {}\n",
                    e.id,
                    e.method,
                    e.url(),
                    e.status.map(|s| s.to_string()).unwrap_or("-".into()),
                    e.resp_len.map(|l| l.to_string()).unwrap_or("-".into()),
                    e.mime.clone().unwrap_or_default(),
                ));
                count += 1;
                if count >= limit {
                    break;
                }
            }
            Ok(out)
        }
        "get_history_entry" => {
            let id = args
                .get("id")
                .and_then(|v| v.as_u64())
                .ok_or("missing id")?;
            let hist = shared.history.lock().unwrap();
            let entry = hist
                .iter()
                .find(|e| e.lock().unwrap().id == id)
                .ok_or_else(|| format!("no entry {id}"))?;
            let e = entry.lock().unwrap();
            let mut out = String::from("=== REQUEST ===\n");
            out.push_str(&String::from_utf8_lossy(&e.req_raw));
            if let Some(resp) = &e.resp_raw {
                out.push_str("\n=== RESPONSE ===\n");
                out.push_str(&truncate(&String::from_utf8_lossy(resp), 12000));
            }
            Ok(out)
        }
        "list_ws_sessions" => {
            let sessions = shared.ws_sessions.lock().unwrap();
            let mut out = String::from("id | url | state | messages\n");
            for s in sessions.iter() {
                let s = s.lock().unwrap();
                out.push_str(&format!(
                    "{} | {} | {} | {}\n",
                    s.id,
                    s.url,
                    s.state.as_str(),
                    s.messages.len()
                ));
            }
            Ok(out)
        }
        "get_ws_messages" => {
            let id = args
                .get("id")
                .and_then(|v| v.as_u64())
                .ok_or("missing id")?;
            let sessions = shared.ws_sessions.lock().unwrap();
            let session = sessions
                .iter()
                .find(|s| s.lock().unwrap().id == id)
                .ok_or_else(|| format!("no ws session {id}"))?;
            let s = session.lock().unwrap();
            let mut out = String::new();
            for (i, m) in s.messages.iter().enumerate() {
                out.push_str(&format!(
                    "#{} {} {} ({} bytes): {}\n",
                    i + 1,
                    m.direction.as_str(),
                    m.opcode,
                    m.size,
                    truncate(&String::from_utf8_lossy(&m.payload), 500),
                ));
            }
            Ok(out)
        }
        other => Err(format!("unknown built-in tool '{other}'")),
    }
}

/// Split `scheme://authority/...` into (scheme, authority).
fn split_url(url: &str) -> Result<(String, String), String> {
    let (scheme, rest) = if let Some(r) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("wss://"))
    {
        ("https", r)
    } else if let Some(r) = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("ws://"))
    {
        ("http", r)
    } else {
        return Err("target_url must start with http:// or https://".into());
    };
    let authority = match rest.find('/') {
        Some(i) => &rest[..i],
        None => rest,
    };
    if authority.is_empty() {
        return Err("target_url has empty authority".into());
    }
    Ok((scheme.to_string(), authority.to_string()))
}

/// Rewrite the raw request so its request line is origin-form with the path
/// from `target_url` and the Host header matches the authority.
fn normalize_request(target_url: &str, raw: &str) -> Result<Vec<u8>, String> {
    let (_, authority) = split_url(target_url)?;
    let path = match target_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .find('/')
    {
        Some(i) => target_url[target_url.find("://").unwrap() + 3 + i..].to_string(),
        None => "/".to_string(),
    };
    let (head, body) = match raw.find("\r\n\r\n") {
        Some(pos) => (&raw[..pos + 4], &raw[pos + 4..]),
        None => (raw, ""),
    };
    let mut out_lines: Vec<String> = Vec::new();
    let mut host_done = false;
    for (i, line) in head.split_inclusive("\r\n").enumerate() {
        let line = line.trim_end_matches("\r\n");
        if i == 0 {
            let mut parts = line.split_whitespace();
            let method = parts.next().unwrap_or("GET");
            let _ = parts.next();
            out_lines.push(format!("{method} {path} HTTP/1.1"));
        } else if line.to_ascii_lowercase().starts_with("host:") {
            out_lines.push(format!("Host: {authority}"));
            host_done = true;
        } else if line.is_empty() {
            if !host_done {
                out_lines.push(format!("Host: {authority}"));
                host_done = true;
            }
            out_lines.push(String::new());
        } else {
            out_lines.push(line.to_string());
        }
    }
    if !host_done {
        out_lines.insert(1, format!("Host: {authority}"));
    }
    let mut out = out_lines.join("\r\n");
    if !out.ends_with("\r\n\r\n") {
        out.push_str("\r\n\r\n");
    }
    out.push_str(body);
    Ok(out.into_bytes())
}

// ------------------------------------------------------------------ agent loop

type McpCaller = Arc<
    dyn Fn(String, Value) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>>
        + Send
        + Sync,
>;

/// Run the agent loop: chat -> tool calls -> tool results -> ... until the
/// model answers without tool calls or the step budget runs out.
/// `on_event` receives UI updates; returns the full message list (for follow-ups).
pub async fn agent_loop(
    shared: Arc<SharedState>,
    prior: Vec<Value>,
    mcp_tools: Arc<Vec<(String, String, Value)>>,
    call_mcp: McpCaller,
    mut on_event: impl FnMut(ChatRole, String),
) -> Result<Vec<Value>, String> {
    let (base_url, api_key, model, system_prompt, temperature) = {
        let s = shared.settings.lock().unwrap();
        (
            s.ai.base_url.clone(),
            s.ai.api_key.clone(),
            s.ai.model.clone(),
            s.ai.system_prompt.clone(),
            s.ai.temperature,
        )
    };
    if base_url.trim().is_empty() || model.trim().is_empty() {
        return Err("AI is not configured: set Base URL and Model in Settings first".into());
    }
    let tools = tool_definitions(&mcp_tools);
    let mut messages = vec![json!({"role": "system", "content": system_prompt})];
    messages.extend(prior);

    const MAX_STEPS: usize = 8;
    for _ in 0..MAX_STEPS {
        let turn = chat_completion(
            &base_url,
            &api_key,
            &model,
            temperature,
            &messages,
            Some(&tools),
        )
        .await?;
        if turn.tool_calls.is_empty() {
            on_event(ChatRole::Assistant, turn.content.clone());
            messages.push(json!({"role": "assistant", "content": turn.content}));
            return Ok(messages);
        }
        // Assistant message with tool_calls, then each tool result.
        let mut assistant_msg = json!({"role": "assistant", "content": turn.content});
        assistant_msg["tool_calls"] = Value::Array(
            turn.tool_calls
                .iter()
                .map(|c| {
                    json!({
                        "id": c.id,
                        "type": "function",
                        "function": {"name": c.name, "arguments": c.arguments}
                    })
                })
                .collect(),
        );
        messages.push(assistant_msg);
        for call in &turn.tool_calls {
            on_event(ChatRole::Notice, format!("→ tool {}", call.name));
            let args: Value = serde_json::from_str(&call.arguments).unwrap_or(json!({}));
            let result: Result<String, String> =
                if builtin_tools().iter().any(|t| t.name == call.name) {
                    execute_builtin(&shared, &call.name, &args).await
                } else {
                    (call_mcp)(call.name.clone(), args).await
                };
            let text = match result {
                Ok(t) => t,
                Err(e) => format!("tool error: {e}"),
            };
            on_event(
                ChatRole::Tool,
                format!("{} → {}", call.name, truncate(&text, 1500)),
            );
            messages.push(json!({
                "role": "tool",
                "tool_call_id": call.id,
                "content": text
            }));
        }
    }
    Err("tool-call budget exhausted (8 steps) — stopping".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_assistant_turn() {
        let body = r#"{
            "choices": [{
                "message": {
                    "content": "thinking...",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "list_history", "arguments": "{\"limit\": 5}"}
                    }]
                }
            }]
        }"#;
        let v: Value = serde_json::from_str(body).unwrap();
        let choice = v.pointer("/choices/0").unwrap();
        assert_eq!(
            choice.pointer("/message/content").and_then(|c| c.as_str()),
            Some("thinking...")
        );
        assert_eq!(
            choice
                .pointer("/message/tool_calls/0/function/name")
                .and_then(|n| n.as_str()),
            Some("list_history")
        );
    }

    #[test]
    fn splits_url() {
        assert_eq!(
            split_url("http://example.com:8080/a?b=1").unwrap().1,
            "example.com:8080"
        );
        assert_eq!(split_url("https://example.com").unwrap().1, "example.com");
        assert!(split_url("ftp://x").is_err());
    }

    #[test]
    fn normalizes_request_line_and_host() {
        let out = String::from_utf8(
            normalize_request(
                "http://example.com:8080/admin?x=1",
                "GET /wrong HTTP/1.1\r\nHost: old.host\r\nCookie: a=b\r\n\r\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert!(out.starts_with("GET /admin?x=1 HTTP/1.1\r\n"));
        assert!(out.contains("Host: example.com:8080\r\n"));
        assert!(out.contains("Cookie: a=b\r\n"));
    }

    #[test]
    fn tool_definitions_include_builtin_and_mcp() {
        let mcp = vec![("mcp_tool".to_string(), "desc".to_string(), json!({}))];
        let defs = tool_definitions(&mcp);
        let arr = defs.as_array().unwrap();
        assert_eq!(arr.len(), builtin_tools().len() + 1);
        let s = serde_json::to_string(&defs).unwrap();
        assert!(s.contains("send_http_request"));
        assert!(s.contains("mcp_tool"));
    }
}
