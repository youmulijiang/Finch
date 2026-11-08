//! End-to-end test of the MCP stdio client: spawn the Finch binary itself
//! as a minimal MCP server (`finch --mcp-test-server`) and run the full
//! initialize -> tools/list -> tools/call flow through `McpConnection`.

use std::process::Stdio;

use serde_json::json;

#[tokio::test]
async fn mcp_stdio_full_flow() {
    let exe = env!("CARGO_BIN_EXE_finch");
    let transport = finch::state::McpTransportConfig::Stdio {
        command: exe.to_string(),
        args: vec!["--mcp-test-server".to_string()],
    };

    let mut conn = finch::mcp_client::McpConnection::new("test".into(), transport);

    // Handshake + tools/list.
    conn.connect().await.expect("connect failed");
    assert_eq!(conn.tools.len(), 1, "expected the echo tool");
    assert_eq!(conn.tools[0].name, "echo");
    assert!(conn.tools[0].description.contains("Echo"));
    assert_eq!(conn.status, finch::mcp_client::McpStatus::Connected);

    // tools/call.
    let out = conn
        .call_tool("echo", json!({"text": "hello mcp"}))
        .await
        .expect("call failed");
    assert_eq!(out, "echo: hello mcp");

    // A second call on the same connection.
    let out = conn
        .call_tool("echo", json!({"text": "again"}))
        .await
        .expect("second call failed");
    assert_eq!(out, "echo: again");

    conn.shutdown();
    assert_eq!(conn.status, finch::mcp_client::McpStatus::Disconnected);
}

#[tokio::test]
async fn mcp_stdio_error_on_unknown_tool() {
    let exe = env!("CARGO_BIN_EXE_finch");
    let transport = finch::state::McpTransportConfig::Stdio {
        command: exe.to_string(),
        args: vec!["--mcp-test-server".to_string()],
    };
    let mut conn = finch::mcp_client::McpConnection::new("test".into(), transport);
    conn.connect().await.expect("connect failed");
    let err = conn
        .call_tool("does_not_exist", json!({}))
        .await
        .expect_err("expected an error");
    assert!(err.contains("MCP error"), "got: {err}");
    conn.shutdown();
}

#[test]
fn quick_call_helper_works() {
    let exe = env!("CARGO_BIN_EXE_finch");
    let transport = finch::state::McpTransportConfig::Stdio {
        command: exe.to_string(),
        args: vec!["--mcp-test-server".to_string()],
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (tools, result) = rt
        .block_on(finch::mcp_client::quick_call(
            transport,
            "echo",
            json!({"text": "quick"}),
        ))
        .unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(result, "echo: quick");
}
