//! Finch's traffic interceptor: bridges slinger-mitm's async interception hooks
//! to the egui UI (history + intercept queue).

use std::sync::Arc;

use crate::mitm::{Interceptor, MitmRequest, MitmResponse};
use bytes::Bytes;
use tokio::sync::oneshot;

use crate::http_msg;
use crate::state::{
    Decision, EntryState, HistoryEntry, PendingItem, Scheme, SharedState, WsDir, WsSessionState,
};

pub struct FinchInterceptor {
    pub shared: Arc<SharedState>,
    /// Auto-release timeout for parked intercepts, mirroring the mitm layer's
    /// `interceptor_timeout_secs`. The internal wait fires one second earlier
    /// so this interceptor cleans up (queue item + entry state) before the
    /// generic outer timeout would strand them as zombies. The production
    /// proxy passes an effectively infinite value, keeping the
    /// wait-for-the-user behavior.
    pub timeout_secs: u64,
}

impl FinchInterceptor {
    fn matches_filter(&self, url: &str) -> bool {
        let filter = self.shared.intercept_filter.lock().unwrap().clone();
        filter.is_empty() || url.to_lowercase().contains(&filter.to_lowercase())
    }

    fn scheme_of(&self, is_http: bool, destination: &str) -> Scheme {
        if !is_http {
            Scheme::Tcp
        } else if http_msg::dest_is_tls(destination) {
            Scheme::Https
        } else {
            Scheme::Http
        }
    }
}

impl FinchInterceptor {
    /// Filter check for a WebSocket session by its URL.
    fn ws_matches_filter(&self, session_id: u128) -> bool {
        let url = self
            .shared
            .ws_session_map
            .lock()
            .unwrap()
            .get(&session_id)
            .map(|s| s.lock().unwrap().url.clone())
            .unwrap_or_default();
        self.matches_filter(&url)
    }
}

/// Best-effort detection of a WebSocket upgrade request from its raw head.
fn raw_is_ws_upgrade(raw: &[u8]) -> bool {
    match http_msg::parse_request_head(raw) {
        Some((http::Method::GET, _, head)) => {
            let upgrade = head
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("upgrade"))
                .map(|(_, v)| v.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false);
            let connection = head
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("connection"))
                .map(|(_, v)| v.to_lowercase().contains("upgrade"))
                .unwrap_or(false);
            upgrade && connection
        }
        _ => false,
    }
}

/// Resolve the origin host in the background (cached) and fill `server_ip`.
fn prime_dns(
    shared: &Arc<SharedState>,
    entry: Arc<std::sync::Mutex<HistoryEntry>>,
    authority: String,
) {
    let host = http_msg::host_only(&authority);
    if host.is_empty() {
        return;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        entry.lock().unwrap().server_ip = Some(ip.to_string());
        return;
    }
    let cached = shared.dns_cache.lock().unwrap().get(&host).cloned();
    if let Some(cached) = cached {
        entry.lock().unwrap().server_ip = cached;
        return;
    }
    let shared = shared.clone();
    tokio::spawn(async move {
        let ip = tokio::net::lookup_host((host.as_str(), 0u16))
            .await
            .ok()
            .and_then(|mut addrs| addrs.next())
            .map(|addr| addr.ip().to_string());
        shared
            .dns_cache
            .lock()
            .unwrap()
            .insert(host.clone(), ip.clone());
        entry.lock().unwrap().server_ip = ip;
        shared.wake();
    });
}

#[async_trait::async_trait]
impl Interceptor for FinchInterceptor {
    async fn intercept_request(
        &self,
        mut request: MitmRequest,
    ) -> crate::mitm::Result<Option<MitmRequest>> {
        let shared = &self.shared;
        let raw = http_msg::request_raw(request.request());
        let is_http = request.is_http();
        let destination = request.destination().to_string();
        let session_id = request.session_id();
        let now_ms = request.timestamp();

        let (method, path, host, mime) = if is_http {
            match http_msg::parse_request_head(&raw) {
                Some((m, uri, head)) => {
                    let base = http_msg::absolutize(
                        &destination,
                        http_msg::dest_is_tls(&destination),
                        &uri,
                    );
                    let parsed = base.parse::<http::Uri>().ok();
                    let host = parsed
                        .as_ref()
                        .and_then(|u| u.authority())
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| http_msg::dest_authority(&destination));
                    let path = parsed
                        .as_ref()
                        .map(|u| {
                            u.path_and_query()
                                .map(|p| p.as_str().to_string())
                                .unwrap_or_else(|| "/".into())
                        })
                        .unwrap_or_else(|| uri.clone());
                    let ct = head
                        .headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                        .map(|(_, v)| v.clone());
                    (m.to_string(), path, host, http_msg::mime_of(ct.as_deref()))
                }
                None => (
                    "?".into(),
                    "/".into(),
                    http_msg::dest_authority(&destination),
                    None,
                ),
            }
        } else {
            ("TCP".into(), String::new(), destination.clone(), None)
        };

        let url = if is_http {
            format!(
                "{}://{}{}",
                if http_msg::dest_is_tls(&destination) {
                    "https"
                } else {
                    "http"
                },
                host,
                path
            )
        } else {
            format!("tcp://{destination}")
        };

        // Intercept decision: only HTTP messages are parked (raw TCP chunks
        // would break most protocols).
        let intercepting = is_http
            && shared
                .intercept_req
                .load(std::sync::atomic::Ordering::Relaxed)
            && self.matches_filter(&url);

        let entry = HistoryEntry {
            id: shared.next_entry_id(),
            time: now_ms,
            source: request.source(),
            destination: destination.clone(),
            scheme: self.scheme_of(is_http, &destination),
            method: method.clone(),
            path: path.clone(),
            host: host.clone(),
            status: None,
            resp_len: None,
            mime: mime.clone(),
            extension: http_msg::extension_of(&path),
            title: None,
            params: http_msg::query_param_count(&path),
            edited: false,
            tls: is_http && http_msg::dest_is_tls(&destination),
            server_ip: http_msg::ip_literal(&host),
            cookies: http_msg::cookie_count(&raw),
            notes: String::new(),
            req_raw: raw.clone(),
            resp_raw: None,
            state: if intercepting {
                EntryState::Intercepting
            } else {
                EntryState::InFlight
            },
            is_tcp: !is_http,
            error: None,
        };
        let entry_arc = shared.push_history(entry);
        shared
            .session_map
            .lock()
            .unwrap()
            .entry(session_id)
            .or_default()
            .push_back(entry_arc.lock().unwrap().id);
        if is_http {
            // WebSocket handshake: open a capture session for its frames.
            let tls = http_msg::dest_is_tls(&destination);
            if raw_is_ws_upgrade(&raw) {
                shared.create_ws_session(
                    session_id,
                    format!("ws{}://{}{}", if tls { "s" } else { "" }, host, path),
                    destination.clone(),
                    tls,
                    now_ms,
                );
            }
            prime_dns(shared, entry_arc.clone(), host.clone());
        }
        shared.wake();

        if !intercepting {
            return Ok(Some(request));
        }

        // Park in the Intercept tab and wait for the user's decision.
        let (tx, rx) = oneshot::channel();
        let pending_id = shared.push_pending(PendingItem {
            id: shared.next_entry_id(),
            entry_id: entry_arc.lock().unwrap().id,
            is_request: true,
            destination: destination.clone(),
            raw: raw.clone(),
            tx: std::sync::Mutex::new(Some(tx)),
            time: now_ms,
            is_tcp: false,
            is_ws: false,
            ws_dir: None,
            ws_opcode: String::new(),
        });

        // Park until the user decides, but bail out one second before the
        // mitm layer's own timeout would: the outer timeout strands the
        // parked item in the queue and the entry in `Intercepting` forever.
        let wait = std::time::Duration::from_secs(self.timeout_secs.saturating_sub(1));
        let decision = match tokio::time::timeout(wait, rx).await {
            Ok(decision) => decision,
            Err(_) => {
                // Timed out: pass the original request through, but clean up.
                shared.remove_pending(pending_id);
                let mut e = entry_arc.lock().unwrap();
                if e.state == EntryState::Intercepting {
                    e.state = EntryState::InFlight;
                }
                drop(e);
                shared.set_status("Intercept timed out; request forwarded unchanged");
                shared.wake();
                return Ok(Some(request));
            }
        };
        shared.remove_pending(pending_id);

        match decision {
            Ok(Decision::Forward(edited)) => {
                // A stale decision from a timed-out zombie task must not
                // rewrite an entry whose lifecycle already moved on.
                if entry_arc.lock().unwrap().state != EntryState::Intercepting {
                    shared.wake();
                    return Ok(Some(request));
                }
                    if edited != raw {
                        if let Some(mut new_req) = http_msg::rebuild_request(
                            &edited,
                            &destination,
                            http_msg::dest_is_tls(&destination),
                        ) {
                        // Auto-update Content-Length when the user changed the
                        // body. Insert the header even if it was absent, and
                        // drop Transfer-Encoding so the framing stays honest.
                        let body_len = new_req.body.as_ref().map(|b| b.len()).unwrap_or(0);
                        new_req.headers.remove(http::header::TRANSFER_ENCODING);
                        if let Ok(v) = http::HeaderValue::from_str(&body_len.to_string()) {
                            new_req.headers.insert(http::header::CONTENT_LENGTH, v);
                        }
                        // Refresh the entry metadata from the edited request.
                        {
                            let mut e = entry_arc.lock().unwrap();
                            e.method = new_req.method().to_string();
                            if let Some(pq) = new_req.uri().path_and_query() {
                                e.path = pq.as_str().to_string();
                            }
                            if let Some(auth) = new_req.uri().authority() {
                                e.host = auth.to_string();
                            }
                            e.edited = true;
                            e.params = http_msg::query_param_count(&e.path);
                            e.extension = http_msg::extension_of(&e.path);
                            e.cookies = http_msg::cookie_count(&edited);
                            e.server_ip = http_msg::ip_literal(&e.host);
                            e.req_raw = edited;
                        }
                        request.request = new_req;
                    }
                    // The edited Host may differ: refresh the server IP too.
                    let host_now = entry_arc.lock().unwrap().host.clone();
                    prime_dns(shared, entry_arc.clone(), host_now);
                }
                entry_arc.lock().unwrap().state = EntryState::InFlight;
                shared.wake();
                Ok(Some(request))
            }
            Ok(Decision::Drop) => {
                let mut e = entry_arc.lock().unwrap();
                if e.state == EntryState::Intercepting {
                    e.state = EntryState::Dropped;
                    e.error = Some("Dropped by user".into());
                }
                drop(e);
                shared.wake();
                Ok(None)
            }
            Err(_) => {
                // Channel closed (should not happen) - pass through unchanged.
                entry_arc.lock().unwrap().state = EntryState::InFlight;
                shared.wake();
                Ok(Some(request))
            }
        }
    }

    async fn intercept_response(
        &self,
        mut response: MitmResponse,
    ) -> crate::mitm::Result<Option<MitmResponse>> {
        let shared = &self.shared;
        let raw = http_msg::response_raw(response.response());
        let is_http = response.is_http();
        let now_ms = response.timestamp();

        // Pair this response with the connection's oldest unanswered request
        // (HTTP/1.1 responses arrive in request order).
        let entry_id = {
            let mut map = shared.session_map.lock().unwrap();
            match map.get_mut(&response.session_id()) {
                Some(q) => {
                    let id = q.pop_front();
                    if q.is_empty() {
                        map.remove(&response.session_id());
                    }
                    id
                }
                None => None,
            }
        };

        // Locate or create the history entry.
        let entry_arc = match entry_id {
            Some(id) => shared
                .history
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|e| e.lock().unwrap().id == id)
                .cloned(),
            None => None,
        };

        let (status, resp_len, mime, title) = if is_http {
            match http_msg::parse_response_head(&raw) {
                Some((code, head)) => {
                    let ct = head
                        .headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                        .map(|(_, v)| v.clone());
                    let mime = http_msg::mime_of(ct.as_deref());
                    let title = if mime.as_deref().map(|m| m.contains("html")).unwrap_or(false) {
                        http_msg::extract_title(&raw[head.body_start.min(raw.len())..])
                    } else {
                        None
                    };
                    (Some(code.as_u16()), raw.len(), mime, title)
                }
                None => (None, raw.len(), None, None),
            }
        } else {
            (None, raw.len(), None, None)
        };
        // 101 Switching Protocols: tag the history entry so the UI can
        // identify the WebSocket handshake.
        let mime = if status == Some(101) {
            Some("websocket".to_string())
        } else {
            mime
        };

        let url_for_filter = entry_arc
            .as_ref()
            .map(|e| {
                let e = e.lock().unwrap();
                e.url()
            })
            .unwrap_or_default();

        let intercepting = is_http
            && shared
                .intercept_resp
                .load(std::sync::atomic::Ordering::Relaxed)
            && self.matches_filter(&url_for_filter);

        match entry_arc {
            Some(entry) => {
                {
                    let mut e = entry.lock().unwrap();
                    e.status = status.or(e.status);
                    e.resp_len = Some(resp_len);
                    if mime.is_some() {
                        e.mime = mime.clone();
                    }
                    if title.is_some() {
                        e.title = title.clone();
                    }
                    if is_http {
                        e.resp_raw = Some(raw.clone());
                    } else {
                        // Raw TCP: append chunks so the entry accumulates the session.
                        match &mut e.resp_raw {
                            Some(prev) => prev.extend_from_slice(&raw),
                            None => e.resp_raw = Some(raw.clone()),
                        }
                    }
                    e.state = if intercepting {
                        EntryState::Intercepting
                    } else {
                        EntryState::Complete
                    };
                }
                shared.wake();

                if !intercepting {
                    return Ok(Some(response));
                }

                let (tx, rx) = oneshot::channel();
                let pending_id = shared.push_pending(PendingItem {
                    id: shared.next_entry_id(),
                    entry_id: entry.lock().unwrap().id,
                    is_request: false,
                    destination: response.source().to_string(),
                    raw: raw.clone(),
                    tx: std::sync::Mutex::new(Some(tx)),
                    time: now_ms,
                    is_tcp: false,
                    is_ws: false,
                    ws_dir: None,
                    ws_opcode: String::new(),
                });

                // Same internal-timeout contract as the request side.
                let wait = std::time::Duration::from_secs(self.timeout_secs.saturating_sub(1));
                let decision = match tokio::time::timeout(wait, rx).await {
                    Ok(decision) => decision,
                    Err(_) => {
                        shared.remove_pending(pending_id);
                        let mut e = entry.lock().unwrap();
                        if e.state == EntryState::Intercepting {
                            e.state = EntryState::Complete;
                        }
                        drop(e);
                        shared.set_status("Intercept timed out; response forwarded unchanged");
                        shared.wake();
                        return Ok(Some(response));
                    }
                };
                shared.remove_pending(pending_id);

                match decision {
                    Ok(Decision::Forward(edited)) => {
                        {
                            let mut e = entry.lock().unwrap();
                            if e.state != EntryState::Intercepting {
                                // Stale decision from a timed-out zombie task:
                                // the response already flowed through, so the
                                // entry must not be rewritten.
                                drop(e);
                                shared.wake();
                                return Ok(Some(response));
                            }
                            if edited != raw {
                                if http_msg::rebuild_response_into(response.response_mut(), &edited)
                                    .is_ok()
                                {
                                    e.resp_len = Some(edited.len());
                                    e.resp_raw = Some(edited);
                                    e.edited = true;
                                }
                            }
                            e.state = EntryState::Complete;
                        }
                        shared.wake();
                        Ok(Some(response))
                    }
                    Ok(Decision::Drop) => {
                        let mut e = entry.lock().unwrap();
                        if e.state == EntryState::Intercepting {
                            e.state = EntryState::Dropped;
                            e.error = Some("Response dropped by user".into());
                        }
                        drop(e);
                        shared.wake();
                        Ok(None)
                    }
                    Err(_) => {
                        entry.lock().unwrap().state = EntryState::Complete;
                        shared.wake();
                        Ok(Some(response))
                    }
                }
            }
            None => {
                // Response without a tracked request: record it standalone.
                let entry = HistoryEntry {
                    id: shared.next_entry_id(),
                    time: now_ms,
                    source: None,
                    destination: response.source().to_string(),
                    scheme: Scheme::Tcp,
                    method: "TCP".into(),
                    path: String::new(),
                    host: response.source().to_string(),
                    status,
                    resp_len: Some(resp_len),
                    mime,
                    extension: None,
                    title,
                    params: 0,
                    edited: false,
                    tls: false,
                    server_ip: http_msg::ip_literal(&response.source().to_string()),
                    cookies: 0,
                    notes: String::new(),
                    req_raw: Vec::new(),
                    resp_raw: Some(raw),
                    state: EntryState::Complete,
                    is_tcp: true,
                    error: None,
                };
                shared.push_history(entry);
                shared.wake();
                Ok(Some(response))
            }
        }
    }

    async fn intercept_ws_message(
        &self,
        message: crate::mitm::WsMessage,
    ) -> crate::mitm::Result<Option<crate::mitm::WsMessage>> {
        let shared = &self.shared;
        let (dir, ws_dir) = match message.direction {
            crate::mitm::WsDirection::Outgoing => (WsDir::Out, Some(WsDir::Out)),
            crate::mitm::WsDirection::Incoming => (WsDir::In, Some(WsDir::In)),
        };
        let opcode = message.opcode.as_str().to_string();
        let is_close = message.opcode == crate::mitm::WsOpcode::Close;
        shared.push_ws_message(
            message.session_id,
            dir,
            opcode.clone(),
            message.payload.clone(),
            message.timestamp,
        );
        if is_close {
            shared.finish_ws_session(message.session_id, WsSessionState::Closed);
        }

        // Intercept decision: park the message payload for the user unless
        // the session URL is excluded by the filter.
        let intercepting = shared
            .intercept_ws
            .load(std::sync::atomic::Ordering::Relaxed)
            && self.ws_matches_filter(message.session_id);
        if !intercepting {
            return Ok(Some(message));
        }

        let (tx, rx) = oneshot::channel();
        let pending_id = shared.push_pending(PendingItem {
            id: shared.next_entry_id(),
            entry_id: 0,
            is_request: false,
            destination: message.destination.clone(),
            raw: message.payload.clone(),
            tx: std::sync::Mutex::new(Some(tx)),
            time: message.timestamp,
            is_tcp: false,
            is_ws: true,
            ws_dir,
            ws_opcode: opcode,
        });

        // Same internal-timeout contract as the request/response paths.
        let wait = std::time::Duration::from_secs(self.timeout_secs.saturating_sub(1));
        let decision = match tokio::time::timeout(wait, rx).await {
            Ok(decision) => decision,
            Err(_) => {
                shared.remove_pending(pending_id);
                shared.set_status("WS intercept timed out; message forwarded unchanged");
                shared.wake();
                return Ok(Some(message));
            }
        };
        shared.remove_pending(pending_id);
        match decision {
            Ok(Decision::Forward(edited)) => {
                shared.set_status(format!("WS message forwarded ({} bytes)", edited.len()));
                Ok(Some(crate::mitm::WsMessage {
                    payload: edited,
                    ..message
                }))
            }
            Ok(Decision::Drop) => {
                shared.set_status("WS message dropped");
                Ok(None)
            }
            Err(_) => Ok(Some(message)),
        }
    }
}

// Silence unused warnings for Body/Bytes re-exports used above via helpers.
#[allow(unused)]
fn _assertions() {
    fn _body_from_bytes(_: Bytes) {}
}
