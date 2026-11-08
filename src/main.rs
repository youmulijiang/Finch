//! Finch - a compact Burp Suite style intercepting proxy built with
//! egui + hyper + slinger-mitm.

use std::sync::Arc;

use finch::app::FinchApp;
use finch::proxy_ctrl;
use finch::state::SharedState;

fn main() -> eframe::Result {
    // Hidden flag: run as a minimal stdio MCP test server (used by
    // tests/mcp_stdio.rs to exercise the MCP client end-to-end).
    if std::env::args().any(|a| a == "--mcp-test-server") {
        finch::mcp_test_server::run_stdio();
        return Ok(());
    }

    // 0. Logging to stderr (set RUST_LOG=debug/trace for diagnostics).
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::INFO)
        .with_writer(std::io::stderr)
        .try_init();

    // 1. Tokio runtime (multi thread) for the proxy + engine.
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime"),
    );
    finch::app::init_runtime(rt.clone());

    // 2. Shared state + settings.
    let settings = proxy_ctrl::load_settings();
    let shared = SharedState::new(settings);

    // 3. Start the MITM proxy.
    proxy_ctrl::restart_proxy(&rt, shared.clone());

    // 3b. Elevation relaunch: `--elevated-tun` means this instance was just
    // restarted via UAC from the TUN tab — wait for the listener (the old
    // instance may still hold the port for a moment), then auto-enable TUN.
    if std::env::args().any(|a| a == "--elevated-tun") {
        let rt2 = rt.clone();
        let shared2 = shared.clone();
        rt.spawn(async move {
            for _ in 0..20 {
                if shared2
                    .proxy_listening
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            if !shared2
                .proxy_listening
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                proxy_ctrl::restart_proxy(&rt2, shared2.clone());
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            match finch::tun::start(shared2.clone()) {
                Ok(()) => shared2.set_status("TUN mode enabled (elevated relaunch)"),
                Err(e) => {
                    *shared2.tun_status.lock().unwrap() = e.clone();
                    shared2.set_status(format!("TUN autostart failed: {e}"));
                }
            }
        });
    }

    // 4. egui app.
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 640.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("Finch - intercepting proxy"),
        ..Default::default()
    };

    let shared_for_app = shared.clone();
    eframe::run_native(
        "Finch",
        options,
        Box::new(move |cc| {
            let _ = shared_for_app.ui_ctx.set(cc.egui_ctx.clone());
            // On-demand system fonts: fills in CJK etc. that the bundled
            // fonts lack.
            cc.egui_ctx.add_font_provider(std::sync::Arc::new(
                egui_system_font_provider::SystemFontProvider::new(),
            ));
            // Finch dark theme + shared widget styles.
            finch::ui::theme::apply(&cc.egui_ctx);
            Ok(Box::new(FinchApp::new(shared_for_app.clone())))
        }),
    )
}
