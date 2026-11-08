//! End-to-end tests: real slinger-mitm proxy + FinchInterceptor + a local
//! test HTTP server, exercising capture, intercept-forward, drop and
//! response interception.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use finch::interceptor::FinchInterceptor;
use finch::mitm::{MitmConfig, MitmProxy};
use finch::state::{Decision, EntryState, SharedState};

/// A tiny HTTP server that records the request line it received and replies
/// with an echo response.
async fn spawn_test_server(seen: Arc<Mutex<Vec<String>>>) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            let seen = seen.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 16384];
                let n = match sock.read(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let first_line = req.lines().next().unwrap_or("").to_string();
                seen.lock().unwrap().push(first_line.clone());
                let body = format!("hello from test server | got: {first_line}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    port
}

/// Start a Finch MITM proxy on a free port.
async fn spawn_proxy(shared: Arc<SharedState>) -> u16 {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::TRACE)
        .with_test_writer()
        .try_init();
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let config = MitmConfig {
        ca_storage_path: std::env::temp_dir().join(format!("finch-test-ca-{port}")),
        interceptor_timeout_secs: 10,
        ..Default::default()
    };
    let proxy = Arc::new(MitmProxy::new(config).await.unwrap());
    let handler = proxy.interceptor_handler();
    handler
        .write()
        .await
        .add_interceptor(Arc::new(FinchInterceptor {
            shared: shared.clone(),
            timeout_secs: 10,
        }));
    tokio::spawn(async move {
        let _ = proxy.start(&format!("127.0.0.1:{port}")).await;
    });
    // Give the listener a moment.
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    port
}

/// Send a browser-like absolute-form request through the proxy and return
/// (status, head, body). Empty response means the proxy closed without data.
async fn browser_request(
    proxy_port: u16,
    url: &str,
    method: &str,
    body: Option<&str>,
) -> (u16, String, Vec<u8>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let uri: http::Uri = url.parse().unwrap();
    let authority = uri.authority().unwrap().to_string();
    let pq = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".into());
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect to proxy");
    let crlf = "\r\n";
    let mut req = format!(
        "{method} http://{authority}{pq} HTTP/1.1{crlf}Host: {authority}{crlf}User-Agent: finch-e2e{crlf}Accept: */*{crlf}"
    );
    if let Some(b) = body {
        req.push_str(&format!(
            "Content-Type: application/x-www-form-urlencoded{crlf}Content-Length: {}{crlf}{crlf}{b}",
            b.len()
        ));
    } else {
        req.push_str(crlf);
    }
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    let _ = stream.read_to_end(&mut resp).await;
    if resp.is_empty() {
        return (0, String::new(), Vec::new());
    }
    let needle = b"\r\n\r\n";
    let head_end = resp
        .windows(4)
        .position(|w| w == needle)
        .map(|i| i + 4)
        .unwrap_or(0);
    let head = String::from_utf8_lossy(&resp[..head_end]).to_string();
    let status: u16 = head
        .lines()
        .next()
        .unwrap_or("HTTP/1.1 0 x")
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, head, resp[head_end..].to_vec())
}

fn wait_for<F: Fn() -> bool>(cond: F, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

fn last_entry(shared: &Arc<SharedState>) -> finch::state::HistoryEntry {
    let hist = shared.history.lock().unwrap();
    let last = hist.back().expect("history entry");
    last.lock().unwrap().clone()
}

// --------------------------------------------------------------- tests

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passthrough_http_capture() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let target_port = spawn_test_server(seen.clone()).await;
    let shared = SharedState::new(Default::default());
    let proxy_port = spawn_proxy(shared.clone()).await;

    let (status, _head, body) = browser_request(
        proxy_port,
        &format!("http://127.0.0.1:{target_port}/hello-e2e?x=1"),
        "GET",
        None,
    )
    .await;
    eprintln!(
        "DIAG status={status} body_len={} seen={:?}",
        body.len(),
        seen.lock().unwrap()
    );
    eprintln!(
        "DIAG raw={:?}",
        String::from_utf8_lossy(&body[..body.len().min(150)])
    );
    eprintln!("DIAG history_len={}", shared.history.lock().unwrap().len());
    eprintln!("DIAG pending={}", shared.pending.lock().unwrap().len());
    assert_eq!(status, 200, "status line");
    assert!(String::from_utf8_lossy(&body).contains("hello from test server"));

    assert!(
        wait_for(
            || matches!(last_entry(&shared).state, EntryState::Complete),
            Duration::from_secs(5)
        ),
        "entry never completed"
    );
    let entry = last_entry(&shared);
    assert_eq!(entry.method, "GET");
    assert_eq!(entry.host, format!("127.0.0.1:{target_port}"));
    assert!(entry.path.contains("/hello-e2e"));
    assert_eq!(entry.status, Some(200));
    assert!(entry.mime.as_deref().unwrap_or("").starts_with("text/html"));
    // Raw request contains the essential pieces.
    let req_text = String::from_utf8_lossy(&entry.req_raw).to_string();
    assert!(
        req_text.starts_with("GET /hello-e2e?x=1 HTTP/1.1"),
        "raw req: {req_text}"
    );
    // Raw response contains body.
    let resp_text = String::from_utf8_lossy(entry.resp_raw.as_deref().unwrap_or(b"")).to_string();
    assert!(
        resp_text.contains("hello from test server"),
        "raw resp: {resp_text}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn intercept_request_forward_edited() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let target_port = spawn_test_server(seen.clone()).await;
    let shared = SharedState::new(Default::default());
    shared
        .intercept_req
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let proxy_port = spawn_proxy(shared.clone()).await;

    let send_task = tokio::spawn(async move {
        browser_request(
            proxy_port,
            &format!("http://127.0.0.1:{target_port}/original"),
            "GET",
            None,
        )
        .await
    });

    // Wait for the intercept queue.
    assert!(
        wait_for(
            || !shared.pending.lock().unwrap().is_empty(),
            Duration::from_secs(5)
        ),
        "request never parked in the intercept queue"
    );

    // Edit the request line: /original -> /edited-by-user
    let item = shared.pending.lock().unwrap().first().cloned().unwrap();
    let raw = String::from_utf8_lossy(&item.raw).to_string();
    let edited = raw.replace("/original", "/edited-by-user");
    let tx = item.tx.lock().unwrap().take().expect("decision channel");
    let _ = tx.send(Decision::Forward(edited.into_bytes()));

    let (status, _head, body) = send_task.await.unwrap();
    assert_eq!(status, 200);
    assert!(
        String::from_utf8_lossy(&body).contains("got: GET /edited-by-user"),
        "server must see the edited path"
    );

    assert!(wait_for(
        || matches!(last_entry(&shared).state, EntryState::Complete),
        Duration::from_secs(5)
    ));
    let entry = last_entry(&shared);
    assert!(entry.path.contains("/edited-by-user"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn intercept_request_drop() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let target_port = spawn_test_server(seen.clone()).await;
    let shared = SharedState::new(Default::default());
    shared
        .intercept_req
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let proxy_port = spawn_proxy(shared.clone()).await;

    let send_task = tokio::spawn(async move {
        browser_request(
            proxy_port,
            &format!("http://127.0.0.1:{target_port}/dropme"),
            "GET",
            None,
        )
        .await
    });

    assert!(
        wait_for(
            || !shared.pending.lock().unwrap().is_empty(),
            Duration::from_secs(5)
        ),
        "request never parked"
    );
    let item = shared.pending.lock().unwrap().first().cloned().unwrap();
    let tx = item.tx.lock().unwrap().take().unwrap();
    let _ = tx.send(Decision::Drop);

    // The client should see an empty connection (dropped without response).
    let (status, _head, _body) = send_task.await.unwrap();
    assert_eq!(status, 0, "dropped request must not produce a response");

    assert!(wait_for(
        || matches!(last_entry(&shared).state, EntryState::Dropped),
        Duration::from_secs(5)
    ));
    // The server must never have seen the request.
    assert!(
        seen.lock().unwrap().is_empty(),
        "dropped request reached the server"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn intercept_response_edit() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let target_port = spawn_test_server(seen.clone()).await;
    let shared = SharedState::new(Default::default());
    shared
        .intercept_resp
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let proxy_port = spawn_proxy(shared.clone()).await;

    let send_task = tokio::spawn(async move {
        browser_request(
            proxy_port,
            &format!("http://127.0.0.1:{target_port}/resp"),
            "GET",
            None,
        )
        .await
    });

    assert!(
        wait_for(
            || !shared.pending.lock().unwrap().is_empty(),
            Duration::from_secs(5)
        ),
        "response never parked"
    );
    let item = shared.pending.lock().unwrap().first().cloned().unwrap();
    assert!(!item.is_request, "response kind");
    let raw = String::from_utf8_lossy(&item.raw).to_string();
    // Tamper with the body.
    let edited = raw.replace("hello from test server", "HIJACKED-BY-FINCH");
    let tx = item.tx.lock().unwrap().take().unwrap();
    let _ = tx.send(Decision::Forward(edited.into_bytes()));

    let (status, _head, body) = send_task.await.unwrap();
    assert_eq!(status, 200);
    assert!(
        String::from_utf8_lossy(&body).contains("HIJACKED-BY-FINCH"),
        "client must receive the edited response body"
    );

    assert!(wait_for(
        || matches!(last_entry(&shared).state, EntryState::Complete),
        Duration::from_secs(5)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn post_with_body_is_captured() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let target_port = spawn_test_server(seen.clone()).await;
    let shared = SharedState::new(Default::default());
    let proxy_port = spawn_proxy(shared.clone()).await;

    let (status, _head, _body) = browser_request(
        proxy_port,
        &format!("http://127.0.0.1:{target_port}/submit"),
        "POST",
        Some("k=v&n=42"),
    )
    .await;
    assert_eq!(status, 200);

    assert!(wait_for(
        || matches!(last_entry(&shared).state, EntryState::Complete),
        Duration::from_secs(5)
    ));
    let entry = last_entry(&shared);
    assert_eq!(entry.method, "POST");
    let req_text = String::from_utf8_lossy(&entry.req_raw).to_string();
    assert!(req_text.contains("k=v&n=42"), "body in raw req: {req_text}");
    assert!(req_text.to_lowercase().contains("content-length: 8"));
}

// --------------------------------------------------- unit-ish helpers

#[test]
fn dest_scheme_detection() {
    assert!(!finch::http_msg::dest_is_tls("http://example.com/path"));
    assert!(finch::http_msg::dest_is_tls("https://example.com/path"));
    assert!(finch::http_msg::dest_is_tls("example.com:443"));
}

#[test]
fn raw_request_rebuild_absolutizes() {
    let raw = b"GET /x?q=1 HTTP/1.1\r\nHost: h\r\nX: y\r\n\r\nbody";
    let req = finch::http_msg::rebuild_request(raw, "http://t.local:9000/base", false).unwrap();
    assert_eq!(req.uri().to_string(), "http://t.local:9000/x?q=1");
    assert_eq!(req.method().as_str(), "GET");
    assert_eq!(req.body().map(|b| b.len()), Some(4));

    let raw = b"POST /p HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    let req2 = finch::http_msg::rebuild_request(raw, "h.local:443", true).unwrap();
    assert_eq!(req2.uri().to_string(), "https://h.local:443/p");
    // Content-Length auto-updated to the actual body length.
    assert_eq!(req2.headers().get("content-length").unwrap(), "5");
}

#[test]
fn roundtrip_request_serialization() {
    let raw = "GET /abc?z=9 HTTP/1.1\r\nHost: demo.local\r\nAccept: */*\r\n\r\nPAYLOAD";
    let req = finch::http_msg::rebuild_request(raw.as_bytes(), "demo.local:80", false).unwrap();
    let bytes: bytes::Bytes = (&req).into();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("GET /abc?z=9 HTTP/1.1"));
    assert!(text.contains("host: demo.local"));
    assert!(text.contains("PAYLOAD"));
}

// --------------------------------------------------- hyper engine tests

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hyper_engine_sends_raw_request() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let target_port = spawn_test_server(seen.clone()).await;

    let raw = format!(
        "POST /engine-check HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\nContent-Type: text/plain\r\n\r\nengine-body"
    );
    let res = finch::engine::send_raw(
        "http",
        &format!("127.0.0.1:{target_port}"),
        raw.as_bytes(),
        Duration::from_secs(10),
    )
    .await;

    assert!(res.error.is_none(), "engine error: {:?}", res.error);
    assert_eq!(res.status, Some(200));
    assert!(String::from_utf8_lossy(&res.body).contains("got: POST /engine-check"));
    assert!(
        seen.lock()
            .unwrap()
            .first()
            .map(|l| l.contains("/engine-check"))
            .unwrap_or(false)
    );
    // Raw response serialization round trip.
    let raw_resp = res.to_raw();
    assert!(String::from_utf8_lossy(&raw_resp).starts_with("HTTP/1.1 200 OK"));
}
