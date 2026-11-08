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
