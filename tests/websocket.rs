//! End-to-end WebSocket capture + interception tests: an echo origin server
//! (hand-rolled RFC6455) behind the embedded MITM proxy; hand-rolled clients
//! connect through the proxy. Asserts capture, per-message edit and drop.

use std::sync::{Arc, Mutex};

use finch::mitm::interceptor::{WsDirection, WsMessage};
use finch::mitm::{Interceptor, MitmConfig, MitmProxy, WsOpcode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct WsCapture {
    messages: Mutex<Vec<WsMessage>>,
}

#[async_trait::async_trait]
impl Interceptor for WsCapture {
    async fn intercept_ws_message(
        &self,
        message: WsMessage,
    ) -> finch::mitm::Result<Option<WsMessage>> {
        self.messages.lock().unwrap().push(message.clone());
        Ok(Some(message))
    }
}

// ------------------------------------------------------------- frame helpers

fn masked_frame(opcode: u8, payload: &[u8], fin: bool) -> Vec<u8> {
    let mut out = vec![if fin { 0x80 | opcode } else { opcode }];
    let mask = [0x2a, 0x4b, 0x71, 0x0d];
    if payload.len() < 126 {
        out.push(0x80 | payload.len() as u8);
    } else {
        out.push(0x80 | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        out.push(b ^ mask[i % 4]);
    }
    out
}

/// Read one frame, unmasking if needed; returns (opcode, payload).
async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> (u8, Vec<u8>) {
    let mut head = [0u8; 2];
    r.read_exact(&mut head).await.unwrap();
    let opcode = head[0] & 0x0F;
    let masked = head[1] & 0x80 != 0;
    let len = (head[1] & 0x7F) as usize;
    let mask = if masked {
        let mut m = [0u8; 4];
        r.read_exact(&mut m).await.unwrap();
        Some(m)
    } else {
        None
    };
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await.unwrap();
    if let Some(m) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= m[i % 4];
        }
    }
    (opcode, payload)
}

// ------------------------------------------------------------ origin server

async fn spawn_echo_server() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                // Read the upgrade request head.
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap();
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                assert!(
                    head.to_lowercase().contains("upgrade: websocket"),
                    "bad handshake: {head}"
                );
                // Reply 101 (accept value not verified by our test client).
                sock.write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
                )
                .await
                .unwrap();

                // Echo frames back until a close arrives.
                loop {
                    let (opcode, payload) = read_frame(&mut sock).await;
                    if opcode == 0x8 {
                        // Echo close, then stop.
                        let _ = sock.write_all(&[0x88, 0x00]).await;
                        return;
                    }
                    let echo = masked_frame(opcode, &payload, true);
                    sock.write_all(&echo).await.unwrap();
                }
            });
        }
    });
    port
}

// -------------------------------------------------------------- proxy setup

async fn spawn_proxy_on_free_port(proxy: MitmProxy) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    tokio::spawn(async move {
        let _ = proxy.start(&format!("127.0.0.1:{port}")).await;
    });
    // Wait until the proxy is accepting connections (the probe connection
    // just fails to parse and is closed by the proxy — harmless).
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

async fn handshake(client: &mut tokio::net::TcpStream, origin_port: u16) {
    let req = format!(
        "GET http://127.0.0.1:{origin_port}/ws HTTP/1.1\r\n\
         Host: 127.0.0.1:{origin_port}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    client.write_all(req.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = client.read(&mut buf).await.unwrap();
        assert!(n > 0, "connection closed during handshake");
        resp.extend_from_slice(&buf[..n]);
        if resp.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&resp).to_string();
    assert!(head.contains("101"), "expected 101, got: {head}");
}

#[tokio::test]
async fn websocket_frames_are_captured() {
    let capture = Arc::new(WsCapture::default());
    let origin_port = spawn_echo_server().await;

    let config = MitmConfig {
        ca_storage_path: std::env::temp_dir().join("finch-ws-test-ca"),
        interceptor_timeout_secs: 5,
        ..Default::default()
    };
    let proxy = MitmProxy::new(config).await.unwrap();
    proxy
        .interceptor_handler()
        .write()
        .await
        .add_interceptor(capture.clone());
    let proxy_port = spawn_proxy_on_free_port(proxy).await;

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .unwrap();
    handshake(&mut client, origin_port).await;

    // --- send a text frame, expect the echo
    client
        .write_all(&masked_frame(0x1, b"hello ws", true))
        .await
        .unwrap();
    let (op, payload) = read_frame(&mut client).await;
    assert_eq!(op, 0x1);
    assert_eq!(payload, b"hello ws");

    // --- send a binary frame
    client
        .write_all(&masked_frame(0x2, &[1, 2, 3, 4, 5], true))
        .await
        .unwrap();
    let (op, payload) = read_frame(&mut client).await;
    assert_eq!(op, 0x2);
    assert_eq!(payload, vec![1, 2, 3, 4, 5]);

    // --- fragmented text: "frag" + "ment" (echoed frame by frame)
    client
        .write_all(&masked_frame(0x1, b"frag", false))
        .await
        .unwrap();
    client
        .write_all(&masked_frame(0x0, b"ment", true))
        .await
        .unwrap();
    let (op, payload) = read_frame(&mut client).await;
    assert_eq!(op, 0x1);
    assert_eq!(payload, b"frag");
    let (op, payload) = read_frame(&mut client).await;
    assert_eq!(op, 0x0);
    assert_eq!(payload, b"ment");

    // --- close
    client
        .write_all(&masked_frame(0x8, &[], true))
        .await
        .unwrap();
    let _ = read_frame(&mut client).await;

    // --- assert captured messages
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let msgs = capture.messages.lock().unwrap();
    let outgoing: Vec<&WsMessage> = msgs
        .iter()
        .filter(|m| m.direction == WsDirection::Outgoing)
        .collect();
    let incoming: Vec<&WsMessage> = msgs
        .iter()
        .filter(|m| m.direction == WsDirection::Incoming)
        .collect();

    let out_texts: Vec<&[u8]> = outgoing
        .iter()
        .filter(|m| m.opcode == WsOpcode::Text)
        .map(|m| m.payload.as_slice())
        .collect();
    assert!(
        out_texts.contains(&b"hello ws".as_slice()),
        "out: {out_texts:?}"
    );
    assert!(out_texts.contains(&b"fragment".as_slice()));

    let in_texts: Vec<&[u8]> = incoming
        .iter()
        .filter(|m| m.opcode == WsOpcode::Text)
        .map(|m| m.payload.as_slice())
        .collect();
    assert!(
        in_texts.contains(&b"hello ws".as_slice()),
        "in: {in_texts:?}"
    );

    let in_bin: Vec<&&WsMessage> = incoming
        .iter()
        .filter(|m| m.opcode == WsOpcode::Binary)
        .collect();
    assert!(in_bin.iter().any(|m| m.payload == vec![1, 2, 3, 4, 5]));

    // Close frames should have been observed from the server side.
    assert!(incoming.iter().any(|m| m.opcode == WsOpcode::Close));
}

/// Interceptor that modifies the first outgoing text message and drops the
/// second, passing everything else through (exercises edit + drop decisions).
struct EditingInterceptor {
    rules: Mutex<std::collections::VecDeque<Option<Vec<u8>>>>,
}

#[async_trait::async_trait]
impl Interceptor for EditingInterceptor {
    async fn intercept_ws_message(
        &self,
        message: WsMessage,
    ) -> finch::mitm::Result<Option<WsMessage>> {
        if message.direction == WsDirection::Outgoing && message.opcode == WsOpcode::Text {
            if let Some(decision) = self.rules.lock().unwrap().pop_front() {
                return Ok(decision.map(|payload| WsMessage { payload, ..message }));
            }
        }
        Ok(Some(message))
    }
}

#[tokio::test]
async fn ws_intercept_edit_and_drop() {
    let origin_port = spawn_echo_server().await;

    let config = MitmConfig {
        ca_storage_path: std::env::temp_dir().join("finch-ws-test-ca"),
        interceptor_timeout_secs: 5,
        ..Default::default()
    };
    let proxy = MitmProxy::new(config).await.unwrap();
    proxy
        .interceptor_handler()
        .write()
        .await
        .add_interceptor(Arc::new(EditingInterceptor {
            rules: Mutex::new(
                [
                    Some(b"HELLO EDITED".to_vec()), // first text: edit
                    None,                           // second text: drop
                ]
                .into_iter()
                .collect(),
            ),
        }));
    let proxy_port = spawn_proxy_on_free_port(proxy).await;

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .unwrap();
    handshake(&mut client, origin_port).await;

    // 1. Edited message: the origin receives and echoes the modified bytes
    //    (the proxy re-masks the rewritten client frame per RFC6455).
    client
        .write_all(&masked_frame(0x1, b"hello", true))
        .await
        .unwrap();
    let (op, payload) = read_frame(&mut client).await;
    assert_eq!(op, 0x1);
    assert_eq!(
        payload, b"HELLO EDITED",
        "edited payload must reach the origin"
    );

    // 2. Dropped message: no echo comes back; the stream stays usable.
    client
        .write_all(&masked_frame(0x1, b"dropme", true))
        .await
        .unwrap();

    // 3. Next message proves the pipe still works after a drop.
    client
        .write_all(&masked_frame(0x1, b"third", true))
        .await
        .unwrap();
    let (op, payload) = read_frame(&mut client).await;
    assert_eq!(op, 0x1);
    assert_eq!(payload, b"third", "stream must survive a dropped message");
}
