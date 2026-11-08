//! MITM Proxy configuration and main proxy implementation

use crate::mitm::ca::CertificateManager;
use crate::mitm::error::Result;
use crate::mitm::interceptor::InterceptorHandler;
use crate::mitm::server::ProxyServer;
use slinger::Proxy;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Configuration for MITM proxy
#[derive(Clone)]
pub struct MitmConfig {
    /// Path to store CA certificates
    pub ca_storage_path: PathBuf,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Interceptor timeout in seconds. Each interceptor is given this duration
    /// to process a request/response; if it exceeds the timeout it will be
    /// skipped to avoid blocking the proxy.
    pub interceptor_timeout_secs: u64,
    /// Optional upstream proxy (supports HTTP, HTTPS, SOCKS5, SOCKS5h)
    /// Example: "<socks5h://127.0.0.1:1080>" or "<http://proxy.example.com:8080>"
    pub upstream_proxy: Option<Proxy>,
    /// Host blacklist: regex patterns matched against the CONNECT target or
    /// the plaintext request's Host. A match refuses the connection with 403.
    pub blocked_hosts: Vec<String>,
}

impl Default for MitmConfig {
    fn default() -> Self {
        Self {
            ca_storage_path: PathBuf::from(".slinger-mitm"),
            max_connections: 1000,
            connection_timeout: 30,
            // Default interceptor timeout: 60 seconds
            interceptor_timeout_secs: 60,
            upstream_proxy: None,
            blocked_hosts: Vec::new(),
        }
    }
}

/// MITM Proxy main struct
pub struct MitmProxy {
    config: MitmConfig,
    cert_manager: Arc<CertificateManager>,
    interceptor_handler: Arc<RwLock<InterceptorHandler>>,
}

impl MitmProxy {
    /// Create a new MITM proxy with the given configuration
    pub async fn new(config: MitmConfig) -> Result<Self> {
        let cert_manager = Arc::new(CertificateManager::new(&config.ca_storage_path).await?);
        let interceptor_handler = Arc::new(RwLock::new(
            InterceptorHandler::new().with_timeout(config.interceptor_timeout_secs),
        ));

        Ok(Self {
            config,
            cert_manager,
            interceptor_handler,
        })
    }

    /// Get the CA certificate in PEM format (async).
    pub async fn ca_cert_pem(&self) -> Result<String> {
        self.cert_manager.ca_cert_pem().await
    }

    /// Get the CA certificate path
    pub fn ca_cert_path(&self) -> PathBuf {
        self.cert_manager.ca_cert_path()
    }

    /// Get a reference to the interceptor handler
    pub fn interceptor_handler(&self) -> Arc<RwLock<InterceptorHandler>> {
        self.interceptor_handler.clone()
    }

    /// Start the MITM proxy server on the given address
    pub async fn start(&self, addr: &str) -> Result<()> {
        let server = ProxyServer::new(
            self.config.clone(),
            self.cert_manager.clone(),
            self.interceptor_handler.clone(),
        )?;
        server.run(addr).await
    }
}
