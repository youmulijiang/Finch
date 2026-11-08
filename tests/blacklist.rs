//! End-to-end tests for the host blacklist: regex patterns configured on the
//! engine must refuse blocked hosts with 403 while allowing everything else
//! (both plaintext GET and CONNECT tunnels).

use std::sync::{Arc, Mutex};

use finch::mitm::{MitmConfig, MitmProxy};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Tiny HTTP server echoing a fixed 200 response.
async fn spawn_http_server() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let first = req.lines().next().unwrap_or("");
                let body = format!("ok: {first}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

async fn spawn_proxy(blocked: &[&str]) -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);
    let config = MitmConfig {
        ca_storage_path: std::env::temp_dir().join(format!("finch-blacklist-ca-{port}")),
        interceptor_timeout_secs: 5,
        blocked_hosts: blocked.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    let proxy = MitmProxy::new(config).await.unwrap();
    tokio::spawn(async move {
        let _ = proxy.start(&format!("127.0.0.1:{port}")).await;
    });
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return port;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("proxy did not start");
}

/// Send raw bytes through the proxy, read the full response.
async fn roundtrip(proxy_port: u16, request: &str) -> String {
    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .unwrap();
    client.write_all(request.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = client.read(&mut buf).await {
        if n == 0 {
            break;
        }
        resp.extend_from_slice(&buf[..n]);
    }
    String::from_utf8_lossy(&resp).to_string()
}

#[tokio::test]
async fn blacklist_blocks_matching_and_allows_rest() {
    let origin_port = spawn_http_server().await;
    let proxy_port = spawn_proxy(&["^blocked\\.example\\.(com|org)$", "ads?\\.tracker\\..*"]).await;

    // Blocked host (exact regex) -> 403, and the origin never sees it.
    let resp = roundtrip(
        proxy_port,
        &format!("GET http://blocked.example.com/x HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n"),
    )
    .await;
    assert!(resp.contains("403"), "expected 403, got: {resp}");

    // Blocked host via wildcard regex.
    let resp = roundtrip(
        proxy_port,
        &format!("GET http://ads.tracker.net/pixel HTTP/1.1\r\nHost: ads.tracker.net\r\n\r\n"),
    )
    .await;
    assert!(resp.contains("403"), "expected 403, got: {resp}");

    // A host matching neither pattern is proxied normally.
    let resp = roundtrip(
        proxy_port,
        &format!("GET http://127.0.0.1:{origin_port}/ok HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
    )
    .await;
    assert!(resp.contains("200"), "expected 200, got: {resp}");
    assert!(
        resp.contains("ok: GET"),
        "expected origin echo, got: {resp}"
    );

    // Case where the pattern is a suffix-ish match on the CONNECT target.
    let resp = roundtrip(
        proxy_port,
        "CONNECT blocked.example.com:443 HTTP/1.1\r\nHost: blocked.example.com:443\r\n\r\n",
    )
    .await;
    assert!(
        resp.contains("403"),
        "expected 403 for CONNECT, got: {resp}"
    );
}

#[tokio::test]
async fn empty_blacklist_passes_everything() {
    let origin_port = spawn_http_server().await;
    let proxy_port = spawn_proxy(&[]).await;
    let resp = roundtrip(
        proxy_port,
        &format!("GET http://127.0.0.1:{origin_port}/x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
    )
    .await;
    assert!(resp.contains("200"), "expected 200, got: {resp}");
}
