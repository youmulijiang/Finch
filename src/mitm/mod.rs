//! Embedded MITM proxy engine (extracted from slinger-mitm and trimmed to
//! what Finch uses: HTTP/HTTPS interception + raw TCP tunnels + WebSocket
//! upgrade takeover with frame-level capture).

pub mod ca;
pub mod error;
pub mod interceptor;
pub mod proxy;
pub mod server;
pub mod websocket;

pub use ca::{CertificateAuthority, CertificateManager};
pub use error::{Error, Result};
pub use interceptor::{
    Interceptor, InterceptorHandler, MitmRequest, MitmResponse, WsDirection, WsMessage,
};
pub use proxy::{MitmConfig, MitmProxy};
pub use websocket::WsOpcode;
