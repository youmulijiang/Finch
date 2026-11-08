//! MITM Proxy server implementation

use crate::mitm::ca::CertificateManager;
use crate::mitm::error::{Error, Result};
use crate::mitm::interceptor::{
    InterceptorHandler, MitmRequest, MitmResponse, WsDirection, WsMessage,
};
use crate::mitm::proxy::MitmConfig;
use crate::mitm::websocket;
use bytes::Bytes;
use http::Method;
use slinger::{Client, Request};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Proxy server implementation
pub struct ProxyServer {
    config: MitmConfig,
    cert_manager: Arc<CertificateManager>,
    interceptor_handler: Arc<RwLock<InterceptorHandler>>,
    client: Client,
}

struct TunnelRouteContext {
    peer_addr: SocketAddr,
    cert_manager: Arc<CertificateManager>,
    interceptor: Arc<RwLock<InterceptorHandler>>,
    client: Client,
    upstream_proxy: Option<slinger::Proxy>,
    protocol_tag: &'static str,
}

struct ConnectionContext {
    peer_addr: SocketAddr,
    cert_manager: Arc<CertificateManager>,
    interceptor: Arc<RwLock<InterceptorHandler>>,
    client: Client,
    upstream_proxy: Option<slinger::Proxy>,
    /// Host blacklist regex patterns.
    blocked_hosts: Arc<Vec<String>>,
}

impl ConnectionContext {
    fn into_tunnel(self, protocol_tag: &'static str) -> TunnelRouteContext {
        TunnelRouteContext {
            peer_addr: self.peer_addr,
            cert_manager: self.cert_manager,
            interceptor: self.interceptor,
            client: self.client,
            upstream_proxy: self.upstream_proxy,
            protocol_tag,
        }
    }
}

impl ProxyServer {
    /// Create a new proxy server
    pub fn new(
        config: MitmConfig,
        cert_manager: Arc<CertificateManager>,
        interceptor_handler: Arc<RwLock<InterceptorHandler>>,
    ) -> Result<Self> {
        let client = if let Some(proxy) = &config.upstream_proxy {
            // Enable HTTP keep-alive so the connector can reuse TCP connections
            Client::builder()
                .timeout(Some(Duration::from_secs(60)))
                .keepalive(true)
                .proxy(proxy.clone())
                .build()
                .map_err(|e| {
                    Error::proxy_error(format!(
                        "Failed to build client with proxy {}: {}",
                        proxy.uri(),
                        e
                    ))
                })?
        } else {
            // Use a client configured to reuse connections (keep-alive)
            Client::builder()
                .keepalive(true)
                .build()
                .map_err(|e| Error::proxy_error(format!("Failed to build default client: {}", e)))?
        };
        Ok(Self {
            config,
            cert_manager,
            interceptor_handler,
            client,
        })
    }

    /// Run the proxy server
    pub async fn run(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| Error::proxy_error(format!("Failed to bind to {}: {}", addr, e)))?;
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let cert_manager = self.cert_manager.clone();
                    let interceptor = self.interceptor_handler.clone();
                    let client = self.client.clone();
                    let upstream_proxy = self.config.upstream_proxy.clone();
                    let blocked_hosts = Arc::new(self.config.blocked_hosts.clone());

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(
                            stream,
                            peer_addr,
                            cert_manager,
                            interceptor,
                            client,
                            upstream_proxy,
                            blocked_hosts,
                        )
                        .await
                        {
                            tracing::error!("[MITM] Error handling connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("[MITM] Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// Handle a client connection
    async fn handle_connection(
        stream: TcpStream,
        peer_addr: SocketAddr,
        cert_manager: Arc<CertificateManager>,
        interceptor: Arc<RwLock<InterceptorHandler>>,
        client: Client,
        upstream_proxy: Option<slinger::Proxy>,
        blocked_hosts: Arc<Vec<String>>,
    ) -> Result<()> {
        // Read the first byte to determine protocol
        let mut first_byte = [0u8; 1];
        stream.peek(&mut first_byte).await?;

        let ctx = ConnectionContext {
            peer_addr,
            cert_manager,
            interceptor,
            client,
            upstream_proxy,
            blocked_hosts,
        };

        Self::handle_http_connection(stream, ctx).await
    }

    async fn handle_http_connection(stream: TcpStream, ctx: ConnectionContext) -> Result<()> {
        let mut reader = BufReader::new(stream);
        let request = Request::from_http_reader(&mut reader).await?;

        // Host blacklist: CONNECT targets and plaintext request hosts.
        let config_for_check = MitmConfig {
            blocked_hosts: ctx.blocked_hosts.as_ref().clone(),
            ..MitmConfig::default()
        };
        let check_host = if request.method() == Method::CONNECT {
            // CONNECT targets are host:port; match patterns against the host.
            let uri = request.uri().to_string();
            uri.split_once(':')
                .map(|(h, _)| h)
                .unwrap_or(&uri)
                .to_string()
        } else {
            request
                .headers()
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
                .unwrap_or_else(|| request.uri().host().unwrap_or("").to_string())
        };
        if config_for_check.host_is_blocked(&check_host) {
            tracing::info!("[MITM] Host '{check_host}' blocked by blacklist");
            let mut stream = reader.into_inner();
            let body = format!("Finch: host '{check_host}' is blacklisted");
            let resp = format!(
                "HTTP/1.1 403 Forbidden
Content-Type: text/plain
Content-Length: {}
Connection: close

{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).await?;
            stream.flush().await.map_err(Error::Io)?;
            return Ok(());
        }

        if request.method() == Method::CONNECT {
            let uri = request.uri().to_string();
            let mut stream = reader.into_inner();

            // Send HTTP/1.1 200 Connection Established first, then auto-detect
            // the underlying protocol to decide how to handle the tunnel.
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            stream.flush().await.map_err(Error::Io)?;

            return Self::handle_tunnel_route(stream, &uri, ctx.into_tunnel("CONNECT")).await;
        }

        Self::handle_http_request(
            request,
            reader,
            ctx.interceptor,
            ctx.client,
            ctx.upstream_proxy,
        )
        .await
    }

    /// Shared tunnel routing for SOCKS5 and HTTP CONNECT.
    async fn handle_tunnel_route(
        stream: TcpStream,
        target_addr: &str,
        ctx: TunnelRouteContext,
    ) -> Result<()> {
        if Self::peek_tls_client_hello(&stream, ctx.protocol_tag).await {
            let (domain, port) = Self::parse_host_port(target_addr)?;
            return Self::accept_tls_and_handle(
                stream,
                &domain,
                port,
                false,
                ctx.cert_manager,
                ctx.interceptor,
                ctx.client,
                ctx.upstream_proxy,
            )
            .await;
        }

        let has_interceptors = ctx.interceptor.read().await.has_interceptors();
        let socket = slinger::Socket::new(slinger::StreamWrapper::Tcp(stream), None, None);

        if has_interceptors {
            Self::handle_tcp_tunnel_with_interception(
                socket,
                target_addr,
                ctx.peer_addr,
                ctx.interceptor,
                ctx.upstream_proxy,
            )
            .await
        } else {
            Self::tcp_tunnel(socket, target_addr, false, ctx.upstream_proxy).await
        }
    }

    async fn peek_tls_client_hello(stream: &TcpStream, protocol_tag: &str) -> bool {
        // A TLS ClientHello is client-first and starts with TLS record prefix 0x16 0x03.
        let mut peek_buf = [0u8; 5];
        let peeked = match tokio::time::timeout(
            Duration::from_millis(100),
            stream.peek(&mut peek_buf),
        )
        .await
        {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                tracing::debug!(
                    "[MITM {}] Peek failed, defaulting to TCP tunnel: {}",
                    protocol_tag,
                    e
                );
                0
            }
            Err(_) => {
                tracing::debug!(
                    "[MITM {}] Peek timed out, defaulting to TCP tunnel",
                    protocol_tag
                );
                0
            }
        };

        Self::is_tls_client_hello(&peek_buf[..peeked])
    }

    /// Returns `true` when `bytes` begins with a TLS handshake record header.
    ///
    /// A TLS record starts with:
    ///   byte 0  – content type 0x16 (Handshake)
    ///   byte 1  – major version 0x03 (TLS 1.0 / 1.1 / 1.2 / 1.3)
    ///
    /// This two-byte signature is sufficient to distinguish any TLS handshake
    /// (including ClientHello) from plaintext HTTP, SSH banners, raw TCP data,
    /// and virtually every other protocol.
    fn is_tls_client_hello(bytes: &[u8]) -> bool {
        bytes.len() >= 2 && bytes[0] == 0x16 && bytes[1] == 0x03
    }

    /// Accept TLS on an incoming stream (using certs from CertificateManager) and handle HTTPS requests over it.
    /// If `send_response` is true, send an HTTP/1.1 200 Connection Established before performing the TLS handshake
    async fn accept_tls_and_handle(
        mut client_stream: TcpStream,
        domain: &str,
        port: u16,
        send_response: bool,
        cert_manager: Arc<CertificateManager>,
        interceptor: Arc<RwLock<InterceptorHandler>>,
        slinger_client: Client,
        upstream_proxy: Option<slinger::Proxy>,
    ) -> Result<()> {
        if send_response {
            client_stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            client_stream
                .flush() // ensure response fully sent
                .await
                .map_err(Error::Io)?;
        }

        // Generate server certificate for this domain
        let (cert_chain, key) = cert_manager.get_server_cert(domain).await?;
        // Create TLS acceptor
        let tls_config = Self::create_tls_server_config(cert_chain, key)?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        // Perform TLS handshake with client
        let tls_stream = acceptor
            .accept(client_stream)
            .await
            .map_err(|e| Error::tls_error(format!("TLS handshake failed: {}", e)))?;
        let domain_with_port = format!("{}:{}", domain, port);
        Self::handle_https_stream(
            tls_stream,
            domain_with_port,
            interceptor,
            slinger_client,
            upstream_proxy,
        )
        .await
    }

    /// Generic TCP tunnel helper. If `send_response` is true, sends HTTP/1.1 200 before tunneling.
    async fn tcp_tunnel(
        mut client_stream: slinger::Socket,
        uri: &str,
        send_response: bool,
        upstream_proxy: Option<slinger::Proxy>,
    ) -> Result<()> {
        // Connect to target server (through upstream proxy if configured)
        let target_socket = Self::connect_to_target(uri, upstream_proxy.as_ref()).await?;

        if send_response {
            client_stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
        }

        let (mut client_read, mut client_write) = tokio::io::split(client_stream);
        let (mut target_read, mut target_write) = tokio::io::split(target_socket);

        let client_to_target = tokio::io::copy(&mut client_read, &mut target_write);
        let target_to_client = tokio::io::copy(&mut target_read, &mut client_write);

        tokio::select! {
            _ = client_to_target => {},
            _ = target_to_client => {},
        }

        Ok(())
    }

    /// TCP tunnel with interception capability for raw TCP traffic.
    /// This method intercepts both request and response data, passes them through
    /// the interceptors, and forwards the (potentially modified) data.
    async fn handle_tcp_tunnel_with_interception(
        client_stream: slinger::Socket,
        target_addr: &str,
        peer_addr: SocketAddr,
        interceptor: Arc<RwLock<InterceptorHandler>>,
        upstream_proxy: Option<slinger::Proxy>,
    ) -> Result<()> {
        use uuid::Uuid;

        // Generate a session ID for this TCP connection using UUID
        // All requests and responses for this connection will share this session_id
        let connection_session_id = Uuid::new_v4().as_u128();

        // Connect to target server (through upstream proxy if configured)
        let target_socket = Self::connect_to_target(target_addr, upstream_proxy.as_ref()).await?;

        let (mut client_read, mut client_write) = tokio::io::split(client_stream);
        let (mut target_read, mut target_write) = tokio::io::split(target_socket);

        let target_addr_clone = target_addr.to_string();
        let target_addr_clone2 = target_addr.to_string();
        let interceptor_clone = interceptor.clone();

        // Client to target with interception
        let client_to_target = tokio::spawn(async move {
            let mut buffer = vec![0u8; 8192];
            loop {
                match client_read.read(&mut buffer).await {
                    Ok(0) => break, // Connection closed
                    Ok(n) => {
                        let data = Bytes::copy_from_slice(&buffer[..n]);
                        let mut request =
                            MitmRequest::raw_tcp_with_source(peer_addr, &target_addr_clone, data);
                        // Override the auto-generated session_id with the connection's session_id
                        request.set_session_id(connection_session_id);

                        // Process through interceptors
                        let handler = interceptor_clone.read().await;
                        match handler.process_request(request).await {
                            Ok(Some(modified_request)) => {
                                // Forward modified data to target
                                if let Some(body) = modified_request.body() {
                                    if let Err(e) = target_write.write_all(body.as_ref()).await {
                                        tracing::error!(
                                            "[MITM TCP] Error writing to target: {}",
                                            e
                                        );
                                        break;
                                    }
                                }
                            }
                            Ok(None) => {
                                // Request blocked by interceptor
                                tracing::debug!("[MITM TCP] Request blocked by interceptor");
                            }
                            Err(e) => {
                                tracing::error!("[MITM TCP] Error processing request: {}", e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("[MITM TCP] Error reading from client: {}", e);
                        break;
                    }
                }
            }
        });

        // Target to client with interception
        let target_to_client = tokio::spawn(async move {
            let mut buffer = vec![0u8; 8192];
            loop {
                match target_read.read(&mut buffer).await {
                    Ok(0) => break, // Connection closed
                    Ok(n) => {
                        let data = Bytes::copy_from_slice(&buffer[..n]);
                        // Use the same connection_session_id to correlate with requests
                        let response = MitmResponse::raw_tcp_with_destination(
                            connection_session_id,
                            &target_addr_clone2,
                            peer_addr,
                            data,
                        );

                        // Process through interceptors
                        let handler = interceptor.read().await;
                        match handler.process_response(response).await {
                            Ok(Some(modified_response)) => {
                                // Forward modified data to client
                                if let Some(body) = modified_response.body() {
                                    if let Err(e) = client_write.write_all(body.as_ref()).await {
                                        tracing::error!(
                                            "[MITM TCP] Error writing to client: {}",
                                            e
                                        );
                                        break;
                                    }
                                }
                            }
                            Ok(None) => {
                                // Response blocked by interceptor
                                tracing::debug!("[MITM TCP] Response blocked by interceptor");
                            }
                            Err(e) => {
                                tracing::error!("[MITM TCP] Error processing response: {}", e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("[MITM TCP] Error reading from target: {}", e);
                        break;
                    }
                }
            }
        });

        tokio::select! {
            _ = client_to_target => {},
            _ = target_to_client => {},
        }

        Ok(())
    }

    /// Connect to `target_addr` (in `"host:port"` format) routing through the
    /// upstream proxy when configured.  Delegates to slinger's own
    /// [`ConnectorBuilder`] and [`Connector::connect_with_uri`] so that HTTP
    /// CONNECT and SOCKS5/SOCKS5h proxy logic is not duplicated here.
    async fn connect_to_target(
        target_addr: &str,
        upstream_proxy: Option<&slinger::Proxy>,
    ) -> Result<slinger::Socket> {
        // Build a plain-text URI from the host:port string. Using the `http`
        // scheme ensures slinger treats this as a raw TCP target and does **not**
        // initiate a TLS upgrade after the proxy tunnel is established.
        let uri = format!("http://{}", target_addr)
            .parse::<http::Uri>()
            .map_err(|e| {
                Error::connection_error(format!("Invalid target address '{}': {}", target_addr, e))
            })?;

        let connector = slinger::ConnectorBuilder::default()
            .proxy(upstream_proxy.cloned())
            .build()
            .map_err(|e| Error::connection_error(format!("Failed to build connector: {}", e)))?;

        connector.connect_with_uri(&uri).await.map_err(Into::into)
    }

    /// Returns Some(response_bytes) if there is a response to write back to the caller, or None if
    /// the interceptor chain dropped the request/response.
    async fn forward_request_via_client(
        interceptor: Arc<RwLock<InterceptorHandler>>,
        client: &Client,
        request: Request,
        destination: &str,
    ) -> Result<Option<Vec<u8>>> {
        let handler = interceptor.read().await;
        let mitm_request = MitmRequest::new(destination, request);
        // Store the session_id to correlate with the response
        let session_id = mitm_request.session_id();
        if let Some(modified_req) = handler.process_request(mitm_request).await? {
            let inner_req = modified_req.request();
            let uri = inner_req.uri().clone();
            let method = inner_req.method().clone();
            let headers = inner_req.headers().clone();
            let body_data = if let Some(body) = inner_req.body() {
                body.to_vec()
            } else {
                Vec::new()
            };
            let mut req_builder = client.request(method, uri);
            for (name, value) in headers.iter() {
                req_builder = req_builder.header(name, value);
            }
            req_builder = req_builder.body(body_data);
            match req_builder.send().await {
                Ok(response) => {
                    // Pass the session_id from request to response for correlation
                    let mitm_response = MitmResponse::new(session_id, destination, response);
                    if let Some(final_response) = handler.process_response(mitm_response).await? {
                        let response_bytes = Bytes::from(final_response.response()).to_vec();
                        return Ok(Some(response_bytes));
                    }
                }
                Err(_e) => {
                    return Ok(Some(b"HTTP/1.1 502 Bad Gateway\r\n\r\n".to_vec()));
                }
            }
        }
        Ok(None)
    }

    /// Handle HTTPS requests over TLS connection
    async fn handle_https_stream<S>(
        tls_stream: S,
        domain: String,
        interceptor: Arc<RwLock<InterceptorHandler>>,
        client: Client,
        upstream_proxy: Option<slinger::Proxy>,
    ) -> Result<()>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        // `from_http_reader` requires a BufReader; reclaim the inner stream afterwards for writing.
        let mut reader = BufReader::new(tls_stream);
        let request_result = Request::from_http_reader(&mut reader).await;
        let mut tls_stream = reader.into_inner();

        let mut request = match request_result {
            Ok(req) => req,
            Err(e) => {
                tracing::debug!("[MITM HTTPS] Failed to parse request: {}", e);
                return Ok(());
            }
        };

        // WebSocket upgrade: take over the raw stream instead of the one-shot
        // HTTP forward (which would close the connection after the 101).
        if websocket::is_upgrade_request(request.method(), request.headers()) {
            return Self::handle_websocket_upgrade(
                tls_stream,
                request,
                domain.clone(),
                interceptor,
                upstream_proxy,
            )
            .await;
        }

        // Fix relative URI to be absolute (e.g., /path -> https://domain/path)
        if request.uri().host().is_none() {
            let pq = request
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or("/");
            let absolute_uri = format!("https://{}{}", domain, pq)
                .parse::<http::Uri>()
                .map_err(|e| Error::invalid_request(format!("Invalid URI: {}", e)))?;
            *request.uri_mut() = absolute_uri;
        }

        if let Some(response_bytes) =
            Self::forward_request_via_client(interceptor, &client, request, &domain).await?
        {
            tls_stream.write_all(&response_bytes).await?;
        }

        Ok(())
    }

    /// Handle HTTP request (non-HTTPS)
    async fn handle_http_request<R>(
        request: Request,
        reader: BufReader<R>,
        interceptor: Arc<RwLock<InterceptorHandler>>,
        client: Client,
        upstream_proxy: Option<slinger::Proxy>,
    ) -> Result<()>
    where
        R: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        let uri = request.uri().to_string();

        // WebSocket upgrade: take over the raw stream instead of the one-shot
        // HTTP forward (which would close the connection after the 101).
        if websocket::is_upgrade_request(request.method(), request.headers()) {
            let stream = reader.into_inner();
            return Self::handle_websocket_upgrade(
                stream,
                request,
                uri.clone(),
                interceptor,
                upstream_proxy,
            )
            .await;
        }

        // Process through interceptors and forward
        if let Some(response_bytes) =
            Self::forward_request_via_client(interceptor, &client, request, &uri).await?
        {
            let mut stream = reader.into_inner();
            stream.write_all(&response_bytes).await?;
        }

        Ok(())
    }

    /// Handle a WebSocket upgrade end-to-end:
    /// 1. run the handshake request/response through the interceptors,
    /// 2. open a raw connection to the origin and exchange the handshake bytes,
    /// 3. pipe both directions while capturing frames for `intercept_ws_message`.
    async fn handle_websocket_upgrade<S>(
        mut client_stream: S,
        request: Request,
        destination: String,
        interceptor: Arc<RwLock<InterceptorHandler>>,
        upstream_proxy: Option<slinger::Proxy>,
    ) -> Result<()>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        // For plain HTTP the destination may be an absolute URL; the origin
        // connection needs host:port.
        let target = if let Some(auth) = request.uri().authority() {
            auth.to_string()
        } else {
            destination.clone()
        };

        // 1. Run the handshake through the interceptors (history + intercept).
        let handler = interceptor.read().await;
        let (session_id, raw_request) = {
            let mitm_req = MitmRequest::new(destination.clone(), request);
            let session_id = mitm_req.session_id();
            let processed = handler.process_request(mitm_req).await?;
            let raw = match processed {
                Some(req) => Bytes::from(req.request()).to_vec(),
                // Blocked by the interceptor: just close.
                None => return Ok(()),
            };
            (session_id, raw)
        };
        drop(handler);

        // 2. Connect to the origin (through the upstream proxy when configured).
        let origin = Self::connect_to_target(&target, upstream_proxy.as_ref()).await?;
        let mut origin = origin;
        origin.write_all(&raw_request).await?;
        origin.flush().await.map_err(Error::Io)?;

        // 3. Read the origin's response head.
        let head = Self::read_http_head(&mut origin).await?;

        // Build a display response for the interceptors.
        let (version, status, headers) = Self::parse_response_head(&head);
        let upgraded = status.as_u16() == 101;
        {
            let response = slinger::Response {
                version,
                status_code: status,
                headers,
                ..Default::default()
            };
            let handler = interceptor.read().await;
            let mitm_resp = MitmResponse::new(session_id, destination.clone(), response);
            let _ = handler.process_response(mitm_resp).await?;
        }

        // 4. Hand the handshake response back to the client, byte-for-byte.
        client_stream.write_all(&head).await?;
        client_stream.flush().await.map_err(Error::Io)?;

        if !upgraded {
            // Handshake rejected (e.g. 4xx): nothing to tunnel.
            return Ok(());
        }

        // 5. Pipe both directions, decoding frames for capture.
        let (mut client_read, mut client_write) = tokio::io::split(client_stream);
        let (mut origin_read, mut origin_write) = tokio::io::split(origin);

        let c2s = Self::ws_pipe(
            &mut client_read,
            &mut origin_write,
            WsDirection::Outgoing,
            session_id,
            destination.clone(),
            interceptor.clone(),
        );
        let s2c = Self::ws_pipe(
            &mut origin_read,
            &mut client_write,
            WsDirection::Incoming,
            session_id,
            destination.clone(),
            interceptor.clone(),
        );
        // Runs until either side closes; both pipes then finish.
        let _ = tokio::join!(c2s, s2c);

        Ok(())
    }

    /// Copy bytes from `reader` to `writer`, decoding WebSocket frames on the
    /// way and reporting each complete message to the interceptors.
    async fn ws_pipe<R, W>(
        reader: &mut R,
        writer: &mut W,
        direction: WsDirection,
        session_id: u128,
        destination: String,
        interceptor: Arc<RwLock<InterceptorHandler>>,
    ) -> Result<()>
    where
        R: AsyncReadExt + Unpin,
        W: AsyncWriteExt + Unpin,
    {
        let mut buf = [0u8; 16 * 1024];
        let mut frame_reader = websocket::MessageReader::new();
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            // Process complete messages first: the interceptor may drop or modify
            // them, so bytes are only written after the decision. Every received
            // byte appears in exactly one message's `wire` (or stays buffered for
            // the next frame), so concatenating the forwarded wires preserves the
            // byte stream.
            let mut out: Vec<u8> = Vec::new();
            for msg in frame_reader.feed(&buf[..n]) {
                match msg {
                    Ok(msg) => {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0);
                        let handler = interceptor.read().await;
                        let decision = handler
                            .process_ws_message(WsMessage {
                                session_id,
                                destination: destination.clone(),
                                direction,
                                opcode: msg.opcode,
                                payload: msg.payload.clone(),
                                timestamp: now,
                            })
                            .await;
                        drop(handler);
                        match decision {
                            Ok(Some(m)) => {
                                if m.payload == msg.payload {
                                    // Unmodified: forward the original wire bytes verbatim
                                    // (preserves exact framing, e.g. extension data).
                                    out.extend_from_slice(&msg.wire);
                                } else {
                                    // Modified: re-encode as a single frame. Client->origin
                                    // traffic must be masked per RFC6455.
                                    let mask_key: [u8; 4] = rand::random();
                                    let mask = direction == WsDirection::Outgoing;
                                    out.extend_from_slice(&websocket::encode_frame(
                                        m.opcode, &m.payload, mask, mask_key,
                                    ));
                                }
                            }
                            Ok(None) => {} // dropped by the interceptor
                            Err(_) => {
                                // Interceptor errored: fail open, forward as captured.
                                out.extend_from_slice(&msg.wire);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("[MITM WS] malformed frame stream: {e:?}");
                    }
                }
            }
            if !out.is_empty() {
                writer.write_all(&out).await?;
            }
            writer.flush().await.map_err(Error::Io)?;
        }
        Ok(())
    }

    /// Read bytes until the end of the HTTP head (double CRLF). The remaining
    /// body bytes stay buffered inside `reader`.
    async fn read_http_head<R>(reader: &mut R) -> Result<Vec<u8>>
    where
        R: AsyncReadExt + Unpin,
    {
        let mut head = Vec::with_capacity(1024);
        let mut buf = [0u8; 1024];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            head.extend_from_slice(&buf[..n]);
            if let Some(pos) = find_head_end(&head) {
                head.truncate(pos);
                return Ok(head);
            }
            if head.len() > 256 * 1024 {
                return Err(Error::invalid_request("response head too large"));
            }
        }
        Ok(head)
    }

    /// Parse a raw HTTP/1.x response head into version, status and headers.
    fn parse_response_head(raw: &[u8]) -> (http::Version, http::StatusCode, http::HeaderMap) {
        let mut version = http::Version::HTTP_11;
        let mut status = http::StatusCode::OK;
        let mut headers = http::HeaderMap::new();
        let mut headers_raw = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers_raw);
        if let Ok(code) = response.parse(raw) {
            if code.is_complete() {
                version = match response.version {
                    Some(0) => http::Version::HTTP_10,
                    _ => http::Version::HTTP_11,
                };
                if let Some(c) = response
                    .code
                    .and_then(|c| http::StatusCode::from_u16(c).ok())
                {
                    status = c;
                }
                for h in response.headers {
                    if let (Ok(name), Ok(v)) = (
                        http::HeaderName::from_bytes(h.name.as_bytes()),
                        http::HeaderValue::from_bytes(h.value),
                    ) {
                        headers.append(name, v);
                    }
                }
            }
        }
        (version, status, headers)
    }

    /// Create TLS server configuration
    fn create_tls_server_config(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<ServerConfig> {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| Error::tls_error(format!("Failed to create TLS config: {}", e)))?;

        Ok(config)
    }

    /// Parse host and port from URI
    fn parse_host_port(uri: &str) -> Result<(String, u16)> {
        let parts: Vec<&str> = uri.split(':').collect();
        if parts.len() != 2 {
            return Err(Error::invalid_request(format!("Invalid URI: {}", uri)));
        }

        let host = parts[0].to_string();
        let port = parts[1]
            .parse::<u16>()
            .map_err(|_| Error::invalid_request(format!("Invalid port: {}", parts[1])))?;

        Ok((host, port))
    }
}

/// Regex-based host blacklist check for the engine config.
impl MitmConfig {
    /// True when `host` matches any blacklist pattern. Invalid patterns are
    /// ignored (fail open).
    pub fn host_is_blocked(&self, host: &str) -> bool {
        if self.blocked_hosts.is_empty() || host.is_empty() {
            return false;
        }
        if let Ok(set) = regex::RegexSet::new(&self.blocked_hosts) {
            set.is_match(host)
        } else {
            false
        }
    }
}

/// Byte offset just past the `\r\n\r\n` terminator of an HTTP head, if present.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
}
