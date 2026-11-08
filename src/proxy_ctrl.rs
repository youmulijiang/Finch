//! Proxy lifecycle: start / restart the slinger-mitm proxy on the tokio
//! runtime, CA export, settings persistence.

use std::path::PathBuf;
use std::sync::Arc;

use crate::mitm::{InterceptorHandler, MitmConfig, MitmProxy};

use crate::interceptor::FinchInterceptor;
use crate::state::{ProxySettings, SharedState};

/// Base data dir: next to the executable (portable), fallback to CWD.
pub fn data_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let d = dir.join("finch-data");
            if std::fs::create_dir_all(&d).is_ok() {
                return d;
            }
        }
    }
    let d = PathBuf::from("finch-data");
    let _ = std::fs::create_dir_all(&d);
    d
}

fn ca_dir() -> PathBuf {
    let d = data_dir().join("ca");
    let _ = std::fs::create_dir_all(&d);
    d
}

pub fn settings_path() -> PathBuf {
    data_dir().join("finch.json")
}

pub fn load_settings() -> ProxySettings {
    std::fs::read(settings_path())
        .ok()
        .and_then(|data| serde_json::from_slice(&data).ok())
        .unwrap_or_default()
}

pub fn save_settings(settings: &ProxySettings) {
    if let Ok(json) = serde_json::to_string_pretty(settings) {
        let _ = std::fs::write(settings_path(), json);
    }
}

/// (Re)start the MITM proxy with the current settings. Aborts any previous
/// instance. Runs fully on the tokio runtime.
pub fn restart_proxy(rt: &tokio::runtime::Runtime, shared: Arc<SharedState>) {
    // Abort previous task.
    if let Some(task) = shared.proxy_task.lock().unwrap().take() {
        task.abort();
    }
    shared
        .proxy_listening
        .store(false, std::sync::atomic::Ordering::Relaxed);
    shared.proxy.lock().unwrap().take();

    let (port, upstream) = {
        let s = shared.settings.lock().unwrap();
        (s.listen_port, s.upstream_proxy.clone())
    };
    let addr = format!("127.0.0.1:{port}");

    // Pre-check the port so bind errors surface immediately in the UI.
    match std::net::TcpListener::bind(&addr) {
        Ok(l) => drop(l),
        Err(e) => {
            shared.set_status(format!("Cannot bind {addr}: {e}"));
            return;
        }
    }

    rt.spawn(async move {
        let blocked_hosts = {
            let s = shared.settings.lock().unwrap();
            s.host_blacklist.clone()
        };
        let mut config = MitmConfig {
            ca_storage_path: ca_dir(),
            blocked_hosts,
            // Effectively infinite: parked intercepts wait for the user.
            interceptor_timeout_secs: u64::MAX / 4,
            ..Default::default()
        };
        if let Some(up) = upstream.as_deref().filter(|s| !s.trim().is_empty()) {
            match slinger::Proxy::parse(up.trim()) {
                Ok(p) => config.upstream_proxy = Some(p),
                Err(e) => {
                    shared.set_status(format!("Bad upstream proxy '{up}': {e}"));
                    return;
                }
            }
        }

        match MitmProxy::new(config).await {
            Ok(proxy) => {
                let proxy = Arc::new(proxy);
                // Register the UI interceptor.
                let handler: Arc<tokio::sync::RwLock<InterceptorHandler>> =
                    proxy.interceptor_handler();
                {
                    let mut h = handler.write().await;
                    h.add_interceptor(Arc::new(FinchInterceptor {
                        shared: shared.clone(),
                        timeout_secs: u64::MAX / 4,
                    }));
                }
                *shared.proxy.lock().unwrap() = Some(proxy.clone());
                shared.set_status(format!("Proxy listening on {addr}"));
                shared
                    .proxy_listening
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                if let Err(e) = proxy.start(&addr).await {
                    shared
                        .proxy_listening
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                    shared.set_status(format!("Proxy stopped: {e}"));
                }
            }
            Err(e) => shared.set_status(format!("Failed to init MITM proxy: {e}")),
        }
    });
}

/// Fetch the CA certificate PEM (async on the runtime).
pub fn ca_pem(rt: &tokio::runtime::Runtime, shared: &Arc<SharedState>) -> Option<String> {
    let proxy = shared.proxy.lock().unwrap().clone()?;
    let pem = rt.block_on(proxy.ca_cert_pem()).ok()?;
    Some(pem)
}

/// Open a URL in the default browser with the proxy configured (Windows
/// browsers with a --proxy-server flag, best effort).
pub fn open_browser_with_proxy(port: u16) -> Result<(), String> {
    let candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ];
    for exe in candidates {
        if std::path::Path::new(exe).exists() {
            let arg = format!("--proxy-server=http://127.0.0.1:{port}");
            let res = std::process::Command::new(exe)
                .arg(&arg)
                .arg("about:blank")
                .spawn();
            return match res {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            };
        }
    }
    Err("No Edge/Chrome found; configure your browser proxy manually".into())
}
