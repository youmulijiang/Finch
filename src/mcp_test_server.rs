//! A minimal MCP stdio test server embedded in the Finch binary
//! (`finch --mcp-test-server`). Speaks JSON-RPC 2.0 line-delimited on
//! stdio: initialize, tools/list and one echo tool. Used by
//! tests/mcp_stdio.rs to exercise the MCP client end-to-end.

use std::io::{BufRead, Write};

use serde_json::{Value, json};

pub fn run_stdio() {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let Some(method) = msg.get("method").and_then(|m| m.as_str()) else {
            continue;
        };
        let id = msg.get("id").cloned();
        let resp = match method {
            "initialize" => json!({
                "jsonrpc": "2.0", "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "finch-test-server", "version": "0.0.1"}
                }
            }),
            "tools/list" => json!({
                "jsonrpc": "2.0", "id": id,
                "result": {"tools": [{
                    "name": "echo",
                    "description": "Echo the given text back",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"text": {"type": "string"}},
                        "required": ["text"]
                    }
                }]}
            }),
            "tools/call" => {
                let name = msg
                    .pointer("/params/name")
                    .and_then(|t| t.as_str())
                    .unwrap_or("");
                if name != "echo" {
                    if let Some(id) = id {
                        let _ = writeln!(
                            out,
                            "{}",
                            json!({
                                "jsonrpc": "2.0", "id": id,
                                "error": {"code": -32602, "message": format!("unknown tool {name}")}
                            })
                        );
                        let _ = out.flush();
                    }
                    continue;
                }
                let text = msg
                    .pointer("/params/arguments/text")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string();
                json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {"content": [{"type": "text", "text": format!("echo: {text}")}]}
                })
            }
            other => {
                if let Some(id) = id {
                    json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": {"code": -32601, "message": format!("unknown method {other}")}
                    })
                } else {
                    continue;
                }
            }
        };
        let _ = writeln!(out, "{resp}");
        let _ = out.flush();
    }
}
