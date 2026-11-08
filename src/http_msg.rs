//! Helpers to convert between raw HTTP byte streams and slinger request/response
//! structures, plus small display helpers (MIME, title, hex view, gzip).

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version};

/// Parsed raw HTTP message head.
pub struct RawHead {
    pub first_line: String,
    pub version: Version,
    pub headers: Vec<(String, String)>,
    /// Offset of the body inside the raw buffer.
    pub body_start: usize,
}

fn parse_version(s: &str) -> Version {
    match s {
        "HTTP/0.9" => Version::HTTP_09,
        "HTTP/1.0" => Version::HTTP_10,
        "HTTP/1.1" => Version::HTTP_11,
        "HTTP/2.0" | "HTTP/2" => Version::HTTP_2,
        "HTTP/3.0" | "HTTP/3" => Version::HTTP_3,
        _ => Version::HTTP_11,
    }
}

/// Extract the protocol token ("HTTP/1.1") from a first line.
fn version_of(first_line: &str) -> Version {
    first_line
        .split_whitespace()
        .last()
        .map(parse_version)
        .unwrap_or(Version::HTTP_11)
}

/// Parse an HTTP request head (request line + headers) out of raw bytes.
pub fn parse_request_head(raw: &[u8]) -> Option<(Method, String, RawHead)> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(raw) {
        Ok(httparse::Status::Complete(head_len)) => {
            let method = Method::from_bytes(req.method?.as_bytes()).ok()?;
            let uri = req.path?.to_string();
            let first_line = raw
                .split(|&b| b == b'\n')
                .next()
                .map(|l| String::from_utf8_lossy(l).trim_end().to_string())
                .unwrap_or_default();
            let version = version_of(&first_line);
            let hdrs = req
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_string(),
                        String::from_utf8_lossy(h.value).to_string(),
                    )
                })
                .collect();
            Some((
                method,
                uri,
                RawHead {
                    first_line,
                    version,
                    headers: hdrs,
                    body_start: head_len,
                },
            ))
        }
        _ => None,
    }
}

/// Parse an HTTP response head (status line + headers) out of raw bytes.
pub fn parse_response_head(raw: &[u8]) -> Option<(StatusCode, RawHead)> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut resp = httparse::Response::new(&mut headers);
    match resp.parse(raw) {
        Ok(httparse::Status::Complete(head_len)) => {
            let code = resp.code.unwrap_or(200);
            let status = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
            let first_line = raw
                .split(|&b| b == b'\n')
                .next()
                .map(|l| String::from_utf8_lossy(l).trim_end().to_string())
                .unwrap_or_default();
            let version = version_of(&first_line);
            let hdrs = resp
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_string(),
                        String::from_utf8_lossy(h.value).to_string(),
                    )
                })
                .collect();
            Some((
                status,
                RawHead {
                    first_line,
                    version,
                    headers: hdrs,
                    body_start: head_len,
                },
            ))
        }
        _ => None,
    }
}

/// Rebuild a `slinger::Request` from an edited raw request.
///
/// `destination`/`scheme` are used to absolutize origin-form request targets:
/// - HTTPS entries have `destination = "host:port"`; HTTP proxy entries have an
///   absolute-form destination such as `http://host:port/orig-path`.
pub fn rebuild_request(
    raw: &[u8],
    destination: &str,
    scheme_is_tls: bool,
) -> Option<slinger::Request> {
    let (method, uri, head) = parse_request_head(raw)?;
    let abs_uri = absolutize(destination, scheme_is_tls, &uri);
    let body = raw.get(head.body_start..).unwrap_or(&[]).to_vec();
    let req = slinger::Request::from_http_parts(
        method.as_str(),
        &abs_uri,
        head.version,
        head.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        body,
    )
    .ok()?;
    // Keep the user's Host header authoritative: remove nothing, serialization
    // in slinger only adds Host when missing.
    Some(req)
}

/// Resolve the request target against the capture context.
pub fn absolutize(destination: &str, scheme_is_tls: bool, uri: &str) -> String {
    if uri.contains("://") {
        return uri.to_string();
    }
    let path = if uri.starts_with('/') {
        uri.to_string()
    } else {
        format!("/{uri}")
    };
    if let Ok(base) = destination.parse::<http::Uri>() {
        if let (Some(scheme), Some(auth)) = (base.scheme_str(), base.authority()) {
            return format!("{}://{}{}", scheme, auth, path);
        }
    }
    let scheme = if scheme_is_tls { "https" } else { "http" };
    format!("{scheme}://{destination}{path}")
}

/// Extract the authority (host:port) from a destination string that may be
/// either an absolute URL or a bare host:port.
pub fn dest_authority(destination: &str) -> String {
    if let Ok(uri) = destination.parse::<http::Uri>() {
        if let Some(auth) = uri.authority() {
            return auth.to_string();
        }
    }
    destination.to_string()
}

/// Strip the port from an authority ("host:port", "http://host:port/path",
/// "[::1]:443") and return just the host.
pub fn host_only(authority: &str) -> String {
    // Bare IPv6 literals ("::1") are accepted before URI parsing, which would
    // otherwise mistake the first colon for a scheme separator.
    if authority.parse::<std::net::IpAddr>().is_ok() {
        return authority.to_string();
    }
    if let Ok(uri) = authority.parse::<http::Uri>() {
        if let Some(host) = uri.host() {
            return host.trim_matches(['[', ']']).to_string();
        }
    }
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return host.to_string();
        }
    }
    authority.to_string()
}

/// Return the host as a textual IP when the authority is already an IP literal.
pub fn ip_literal(authority: &str) -> Option<String> {
    host_only(authority)
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| ip.to_string())
}

/// Number of query-string parameters in an origin-form target.
pub fn query_param_count(target: &str) -> usize {
    target
        .split_once('?')
        .map(|(_, query)| query.split('&').filter(|p| !p.is_empty()).count())
        .unwrap_or(0)
}

/// File extension from a URL path (lowercased, without the dot).
pub fn extension_of(target: &str) -> Option<String> {
    let path = target.split('?').next().unwrap_or(target);
    let last = path.rsplit('/').next().unwrap_or("");
    let (_, ext) = last.rsplit_once('.')?;
    if ext.is_empty() || ext.len() > 10 || !ext.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

/// Count request cookies across all `Cookie` headers.
pub fn cookie_count(raw: &[u8]) -> usize {
    parse_request_head(raw)
        .map(|(_, _, head)| {
            head.headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
                .map(|(_, v)| v.split(';').filter(|s| !s.trim().is_empty()).count())
                .sum()
        })
        .unwrap_or(0)
}

/// Guess whether the destination context is TLS (for absolutizing).
/// HTTPS captures come through CONNECT/SOCKS5 tunnels so the destination is a
/// bare `host:port`; plain HTTP proxy requests carry an absolute-form URL.
pub fn dest_is_tls(destination: &str) -> bool {
    match destination.parse::<http::Uri>() {
        Ok(uri) => match uri.scheme_str() {
            Some("http") => false,
            // Authority-form (no scheme) => CONNECT/SOCKS5 tunnel => TLS.
            _ => true,
        },
        Err(_) => true,
    }
}

/// Rebuild a `slinger::Response` in place from edited raw bytes.
/// Returns Err(reason) when the raw text cannot be parsed.
pub fn rebuild_response_into(resp: &mut slinger::Response, raw: &[u8]) -> Result<(), String> {
    let (status, head) = parse_response_head(raw).ok_or("Cannot parse response head")?;
    let body = raw.get(head.body_start..).unwrap_or(&[]).to_vec();
    resp.version = head.version;
    resp.status_code = status;
    let mut map = HeaderMap::new();
    for (k, v) in &head.headers {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            map.append(name, val);
        }
    }
    resp.headers = map;
    resp.body = if body.is_empty() {
        None
    } else {
        Some(slinger::Body::from(body))
    };
    Ok(())
}

/// Extract `<title>` (best effort) for the history table.
pub fn extract_title(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    let lower = text.to_lowercase();
    let start = lower.find("<title")?;
    let after = &text[start..];
    let gt = after.find('>')?;
    let rest = &after[gt + 1..];
    let end = rest.to_lowercase().find("</title>")?;
    let title = rest[..end].trim();
    if title.is_empty() {
        None
    } else {
        Some(title.chars().take(120).collect())
    }
}

/// Best-effort display text of a body (lossy UTF-8).
pub fn body_display(body: &[u8]) -> String {
    // Cap very large bodies for the egui text pipeline.
    const CAP: usize = 512 * 1024;
    let (bytes, truncated) = if body.len() > CAP {
        (&body[..CAP], true)
    } else {
        (body, false)
    };
    let mut text = String::from_utf8_lossy(bytes).to_string();
    if truncated {
        text.push_str("\n\n... [truncated for display]");
    }
    text
}

/// Hex dump for the Hex viewer tab.
pub fn hex_dump(body: &[u8], max_bytes: usize) -> String {
    let mut out = String::new();
    let max_chunks = max_bytes.div_ceil(16);
    for (i, chunk) in body.chunks(16).take(max_chunks).enumerate() {
        let mut hex = String::new();
        let mut ascii = String::new();
        for &b in chunk {
            hex.push_str(&format!("{b:02x} "));
            ascii.push(if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            });
        }
        for _ in chunk.len()..16 {
            hex.push_str("   ");
        }
        out.push_str(&format!("{i:08x}  {hex} |{ascii}|\n"));
    }
    if body.len() > max_bytes {
        out.push_str(&format!("... [{} more bytes]\n", body.len() - max_bytes));
    }
    out
}

/// Decompress gzip/deflate bodies for the Pretty view (never mutates the
/// stored raw bytes).
pub fn decompress_for_display(content_encoding: Option<&str>, body: &[u8]) -> Option<Vec<u8>> {
    match content_encoding?.to_ascii_lowercase().as_str() {
        "gzip" | "x-gzip" => {
            let mut out = Vec::new();
            let mut dec = flate2::read::MultiGzDecoder::new(body);
            use std::io::Read;
            dec.read_to_end(&mut out).ok()?;
            Some(out)
        }
        "deflate" => {
            // Try zlib-wrapped, then raw deflate.
            let mut out = Vec::new();
            use std::io::Read;
            if flate2::read::ZlibDecoder::new(body)
                .read_to_end(&mut out)
                .is_ok()
                && !out.is_empty()
            {
                return Some(out);
            }
            out.clear();
            flate2::read::DeflateDecoder::new(body)
                .read_to_end(&mut out)
                .ok()?;
            Some(out)
        }
        _ => None,
    }
}

/// Convenience: header lookup case-insensitive.
pub fn header_get<'a>(headers: &'a HeaderMap<HeaderValue>, name: &str) -> Option<&'a HeaderValue> {
    headers.get(name)
}

/// Raw bytes of a slinger request/response.
pub fn request_raw(req: &slinger::Request) -> Vec<u8> {
    Bytes::from(req).to_vec()
}

pub fn response_raw(resp: &slinger::Response) -> Vec<u8> {
    Bytes::from(resp).to_vec()
}

/// Pretty-print JSON if the body is JSON.
pub fn json_pretty(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    serde_json::to_string_pretty(&v).ok()
}

/// Best-effort MIME from Content-Type.
pub fn mime_of(content_type: Option<&str>) -> Option<String> {
    let ct = content_type?;
    let mime = ct.split(';').next()?.trim().to_ascii_lowercase();
    if mime.is_empty() { None } else { Some(mime) }
}

/// Short display name of a MIME type, like Burp's MIME column.
pub fn mime_short(mime: &str) -> &'static str {
    if mime.contains("html") {
        "HTML"
    } else if mime.contains("json") {
        "JSON"
    } else if mime.contains("javascript") {
        "Script"
    } else if mime.contains("css") {
        "CSS"
    } else if mime.starts_with("image/") {
        "Image"
    } else if mime.starts_with("text/") {
        "Text"
    } else if mime.contains("xml") {
        "XML"
    } else if mime.contains("octet-stream") {
        "Bin"
    } else {
        "Other"
    }
}
