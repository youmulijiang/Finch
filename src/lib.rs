//! Finch library: intercepting proxy engine + egui UI.
//!
//! Layout:
//! - `state`      shared UI/proxy state (history, intercept queue, settings)
//! - `interceptor` slinger-mitm interceptor bridging traffic to the UI
//! - `http_msg`   raw HTTP <-> slinger structures helpers
//! - `engine`     hyper-based HTTP client (Repeater / Intruder)
//! - `proxy_ctrl` proxy lifecycle + settings persistence
//! - `ui`         Burp-like egui interface

pub mod ai;
pub mod app;
pub mod engine;
pub mod http_msg;
pub mod interceptor;
pub mod mcp_client;
pub mod mcp_test_server;
pub mod mitm;
pub mod proxy_ctrl;
pub mod state;
pub mod ui;
