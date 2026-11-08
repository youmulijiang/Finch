//! hyper-based HTTP engine used by Repeater and Intruder.
//!
//! Raw request bytes are parsed with httparse, rebuilt as an
//! `http::Request` and dispatched through hyper's legacy client with
//! rustls TLS support.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

pub type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// A sent request's outcome.
#[derive(Debug, Clone, Default)]
pub struct SendResult {
    pub status: Option<u16>,
    pub reason: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub duration_ms: u128,
    pub error: Option<String>,
}

impl SendResult {
    /// Serialize back to raw HTTP response bytes.
    pub fn to_raw(&self) -> Vec<u8> {
        if let Some(code) = self.status {
            let mut out = Vec::new();
            out.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", code, self.reason).as_bytes());
            for (k, v) in &self.headers {
                if k.eq_ignore_ascii_case("content-length")
                    || k.eq_ignore_ascii_case("transfer-encoding")
                {
                    continue;
                }
                out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
            }
            out.extend_from_slice(
                format!("Content-Length: {}\r\n\r\n", self.body.len()).as_bytes(),
            );
            out.extend_from_slice(&self.body);
            out
        } else {
            Vec::new()
        }
    }
}

fn clients() -> &'static (HttpsClient, HttpsClient) {
    static CLIENTS: OnceLock<(HttpsClient, HttpsClient)> = OnceLock::new();
    CLIENTS.get_or_init(|| {
        let with_roots = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("native root certs")
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .build(with_roots);
        // Second identical client reserved for future per-feature tuning.
        let with_roots2 = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("native root certs")
            .https_or_http()
            .enable_http1()
            .build();
        let client2 = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .build(with_roots2);
        (client, client2)
    })
}

/// Send raw HTTP request bytes to `scheme://authority`.
///
/// Returns `SendResult` with `error` set when the exchange failed.
pub async fn send_raw(scheme: &str, authority: &str, raw: &[u8], timeout: Duration) -> SendResult {
    let started = Instant::now();
    let mut out = SendResult::default();

    let (method, uri_path, headers, body) = match parse_for_hyper(raw) {
        Ok(parsed) => parsed,
        Err(e) => {
            out.error = Some(e);
            out.duration_ms = started.elapsed().as_millis();
            return out;
        }
    };

    let uri = format!("{}://{}{}", scheme, authority, uri_path);
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(&uri)
        .version(hyper::Version::HTTP_11);
    for (k, v) in &headers {
        builder = builder.header(k, v);
    }
    let req = match builder.body(Full::new(Bytes::from(body))) {
        Ok(r) => r,
        Err(e) => {
            out.error = Some(format!("build request: {e}"));
            out.duration_ms = started.elapsed().as_millis();
            return out;
        }
    };

    let (client, _) = clients();
    match tokio::time::timeout(timeout, client.request(req)).await {
        Err(_) => {
            out.error = Some("timeout".into());
        }
        Ok(Err(e)) => {
            out.error = Some(e.to_string());
        }
        Ok(Ok(resp)) => {
            out.version = format!("{:?}", resp.version()).replace("HTTP/", "HTTP/");
            out.status = Some(resp.status().as_u16());
            out.reason = resp.status().canonical_reason().unwrap_or("").to_string();
            for (k, v) in resp.headers() {
                if let Ok(v) = v.to_str() {
                    out.headers.push((k.as_str().to_string(), v.to_string()));
                }
            }
            let body: Result<Bytes, _> = resp.into_body().collect().await.map(|c| c.to_bytes());
            match body {
                Ok(b) => out.body = b.to_vec(),
                Err(e) => out.error = Some(format!("read body: {e}")),
            }
        }
    }
    out.duration_ms = started.elapsed().as_millis();
    out
}

type ParsedRaw = (hyper::Method, String, Vec<(String, String)>, Vec<u8>);

/// Parse raw bytes into hyper-compatible parts.
fn parse_for_hyper(raw: &[u8]) -> Result<ParsedRaw, String> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    let head_len = match req.parse(raw) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Err("incomplete request head".into()),
        Err(e) => return Err(format!("parse error: {e}")),
    };
    let method = hyper::Method::from_bytes(req.method.ok_or("no method")?.as_bytes())
        .map_err(|e| format!("bad method: {e}"))?;
    let path = req.path.ok_or("no path")?.to_string();
    let mut hdrs: Vec<(String, String)> = Vec::new();
    for h in req.headers {
        if h.name.eq_ignore_ascii_case("content-length") {
            continue; // hyper sets it from the body
        }
        if let Ok(v) = std::str::from_utf8(h.value) {
            hdrs.push((h.name.to_string(), v.to_string()));
        }
    }
    let body = raw[head_len..].to_vec();
    Ok((method, path, hdrs, body))
}

/// Extract the default payload position: the request body, when present.
pub fn default_payload_markers(raw: &str) -> String {
    // Wrap the whole body in § markers if there is one.
    if let Some(idx) = raw.find("\r\n\r\n") {
        let (head, body) = raw.split_at(idx + 4);
        if body.is_empty() {
            raw.to_string()
        } else {
            format!("{head}§{body}§")
        }
    } else {
        raw.to_string()
    }
}
