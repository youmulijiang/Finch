//! Headless UI smoke tests: drive the egui widgets through `Context::run`
//! without opening a window. Catches column/table and split-layout panics.

use finch::state::{EntryState, HistoryEntry, PendingItem, Scheme, SharedState};
use finch::ui::{
    Actions,
    proxy::{ProxyUi, SubTab},
};

fn sample_entry() -> HistoryEntry {
    HistoryEntry {
        id: 1,
        time: 1_700_000_000_000,
        source: None,
        destination: "example.com:443".into(),
        scheme: Scheme::Https,
        method: "GET".into(),
        path: "/index.html?foo=1&bar=2".into(),
        host: "example.com".into(),
        status: Some(200),
        resp_len: Some(1234),
        mime: Some("text/html".into()),
        extension: Some("html".into()),
        title: Some("Example".into()),
        params: 2,
        edited: true,
        tls: true,
        server_ip: Some("93.184.216.34".into()),
        cookies: 2,
        notes: "note".into(),
        process: Some("sample.exe".into()),
        req_raw: b"GET /index.html?foo=1&bar=2 HTTP/1.1\r\nHost: example.com\r\nCookie: a=1; b=2\r\n\r\n"
            .to_vec(),
        resp_raw: Some(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><title>Example</title></html>"
                .to_vec(),
        ),
        state: EntryState::Complete,
        is_tcp: false,
        error: None,
    }
}

#[test]
fn history_table_and_split_render_without_panicking() {
    let shared = SharedState::new(Default::default());
    shared.push_history(sample_entry());

    let mut proxy = ProxyUi {
        sub_tab: SubTab::History,
        selected_entry: Some(1),
        sort_col: Some(7),
        ..Default::default()
    };
    let mut actions = Actions::default();

    let ctx = egui::Context::default();
    let mut raw = egui::RawInput::default();
    raw.screen_rect = Some(egui::Rect::from_min_size(
        egui::Pos2::ZERO,
        egui::vec2(1200.0, 700.0),
    ));

    // Two frames: the first runs table sizing passes, the second the settled
    // layout (including the resizable split and notes text edit).
    let mut output = None;
    for _ in 0..2 {
        let mut frame = ctx.run_ui(raw.clone(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                finch::ui::proxy::show(ui, &shared, &mut proxy, &mut actions);
            });
        });
        frame.textures_delta.clear();
        output = Some(frame);
    }

    // Regression guard: the table card must not eat the whole viewport. Both
    // pane headings must be laid out inside the visible 1200x700 area so the
    // request/response panels stay below the table.
    let mut saw_request = false;
    let mut saw_response = false;
    for clipped in &output.unwrap().shapes {
        if let egui::Shape::Text(text) = &clipped.shape {
            let value = text.galley.text();
            if value == "Request" && text.pos.y < 680.0 {
                saw_request = true;
            }
            if value == "Response" && text.pos.y < 680.0 {
                saw_response = true;
            }
        }
    }
    assert!(
        saw_request && saw_response,
        "request/response panes should be visible below the history table"
    );
}

#[test]
fn tun_tab_renders_process_list_without_panicking() {
    let shared = SharedState::new(Default::default());
    // Pre-hijack one process name so the table renders the "Stop hijack"
    // state on the matching row.
    shared.settings.lock().unwrap().tun_process_filter =
        vec!["sample.exe".to_string()];

    let mut proxy = ProxyUi {
        sub_tab: SubTab::Tun,
        tun_rows: vec![
            (4242u32, "sample.exe".to_string()),
            (1234u32, "other.exe".to_string()),
        ],
        tun_rows_at: Some(std::time::Instant::now()),
        ..Default::default()
    };
    let mut actions = Actions::default();

    let ctx = egui::Context::default();
    let mut raw = egui::RawInput::default();
    raw.screen_rect = Some(egui::Rect::from_min_size(
        egui::Pos2::ZERO,
        egui::vec2(1200.0, 700.0),
    ));
    for _ in 0..2 {
        let mut frame = ctx.run_ui(raw.clone(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                finch::ui::proxy::show(ui, &shared, &mut proxy, &mut actions);
            });
        });
        frame.textures_delta.clear();
    }
}

/// Run `draw` for two frames inside a 1200x700 central panel and collect the
/// drawn text galley contents.
fn draw_two_frames(mut draw: impl FnMut(&mut egui::Ui)) -> Vec<String> {
    let ctx = egui::Context::default();
    let mut raw = egui::RawInput::default();
    raw.screen_rect = Some(egui::Rect::from_min_size(
        egui::Pos2::ZERO,
        egui::vec2(1200.0, 700.0),
    ));
    let mut texts = Vec::new();
    let mut frame: Option<egui::FullOutput> = None;
    for _ in 0..2 {
        let f = ctx.run_ui(raw.clone(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| draw(ui));
        });
        if let Some(prev) = frame.as_mut() {
            prev.textures_delta.clear();
        }
        frame = Some(f);
    }
    let mut out = frame.unwrap();
    // Keep the last frame's shapes but drop its texture deltas cleanly.
    out.textures_delta.clear();
    for clipped in &out.shapes {
        if let egui::Shape::Text(text) = &clipped.shape {
            texts.push(text.galley.text().to_string());
        }
    }
    texts
}

#[test]
fn intercept_queue_and_editor_render_without_panicking() {
    let shared = SharedState::new(Default::default());
    let (tx, _rx) = tokio::sync::oneshot::channel();
    shared.push_pending(PendingItem {
        id: 7,
        entry_id: 1,
        is_request: true,
        destination: "example.com:443".into(),
        raw: b"GET /login?user=a HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        tx: std::sync::Mutex::new(Some(tx)),
        time: 1_700_000_000_000,
        is_tcp: false,
        is_ws: false,
        ws_dir: None,
        ws_opcode: String::new(),
    });

    let mut proxy = ProxyUi {
        sub_tab: SubTab::Intercept,
        selected_pending: Some(7),
        ..Default::default()
    };
    let mut actions = Actions::default();

    let texts = draw_two_frames(|ui| {
        finch::ui::proxy::show(ui, &shared, &mut proxy, &mut actions);
    });
    let joined = texts.join("\n");
    assert!(joined.contains("Queued: 1"), "queue counter missing");
    assert!(joined.contains("example.com:443"), "queue row missing");
    assert!(
        joined.contains("Request #7"),
        "packet editor header missing"
    );
    assert!(
        joined.contains("GET /login?user=a HTTP/1.1"),
        "raw packet should be shown in the editor"
    );
}

#[test]
fn intruder_queue_and_detail_popup_render_without_panicking() {
    use finch::ui::intruder::{AttackMode, AttackResult, AttackTask, IntruderUi};

    let shared = SharedState::new(Default::default());
    let mut intruder = IntruderUi {
        target: "http://example.com".into(),
        template: "GET /?a=§1§ HTTP/1.1\r\nHost: example.com\r\n\r\n".into(),
        mode: AttackMode::Sniper,
        sets: vec![finch::ui::intruder::PayloadSet {
            items: vec!["admin".into(), "test-payload".into()],
            file: None,
        }],
        ..Default::default()
    };
    intruder.tasks.push(AttackTask {
        id: 1,
        mode: AttackMode::Sniper,
        https: false,
        authority: "example.com".into(),
        template: intruder.template.clone(),
        total: 2,
        done: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(2)),
        results: std::sync::Arc::new(std::sync::Mutex::new(vec![AttackResult {
            index: 0,
            payloads: vec!["§0§ admin".into()],
            result: finch::engine::SendResult {
                status: Some(200),
                reason: "OK".into(),
                body: b"hello".to_vec(),
                ..Default::default()
            },
        }])),
        rx: None,
        stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        running: false,
        finished: true,
        selected: None,
        viewer: finch::ui::viewer::MessageView::new(false),
    });
    intruder.active_task = Some(0);
    intruder.detail_open = true;

    let texts = draw_two_frames(|ui| {
        finch::ui::intruder::show(ui, &shared, &mut intruder);
    });
    let joined = texts.join("\n");
    // Mode dropdown options only render when opened; check visible chrome.
    for label in [
        "Sniper attack",
        "Target",
        "Positions",
        "Payloads",
        "Payload configuration",
        "Payload processing",
        "Start attack",
        "admin",
        "test-payload",
    ] {
        assert!(joined.contains(label), "missing UI element: {label}");
    }
}

#[test]
fn repeater_symmetric_panes_render_without_panicking() {
    let shared = SharedState::new(Default::default());
    let mut rep = finch::ui::repeater::RepeaterUi::default();
    rep.tabs[0].authority = "example.com".into();
    rep.tabs[0].req_view.edit = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".into();

    let texts = draw_two_frames(|ui| {
        finch::ui::repeater::show(ui, &shared, &mut rep);
    });
    let joined = texts.join("\n");
    assert!(joined.contains("Request"), "request pane missing");
    assert!(joined.contains("Response"), "response pane missing");
    assert!(joined.contains("Repeat 1"), "session tab missing");
    assert!(joined.contains("+"), "new-session button missing");
    assert!(
        joined.contains("GET / HTTP/1.1"),
        "request text should be visible"
    );
}

#[test]
fn repeater_history_navigation_and_multi_tabs() {
    use finch::engine::SendResult;
    let shared = SharedState::new(Default::default());
    let mut rep = finch::ui::repeater::RepeaterUi::default();

    // Simulate three sent requests in session 1.
    for body in [b"a".as_slice(), b"bb", b"ccc"] {
        rep.tabs[0].history.push(SendResult {
            status: Some(200),
            reason: "OK".into(),
            body: body.to_vec(),
            ..Default::default()
        });
    }
    rep.tabs[0].history_pos = 2;
    rep.tabs[0].result_raw = rep.tabs[0].history[2].to_raw();

    // Navigate back twice, then forward once.
    assert!(rep.tabs[0].navigate(-1));
    assert!(rep.tabs[0].navigate(-1));
    assert!(!rep.tabs[0].navigate(-1), "cannot go past the first entry");
    assert!(rep.tabs[0].navigate(1));
    assert_eq!(rep.tabs[0].history_pos, 1);

    // A second session is independent; rendering both tabs must not panic.
    rep.new_session();
    rep.tabs[1].authority = "example.org".into();
    rep.tabs[1].req_view.edit = "GET /two HTTP/1.1\r\nHost: example.org\r\n\r\n".into();

    // Rendering session 1 shows its history position indicator.
    rep.active = 0;
    let texts = draw_two_frames(|ui| {
        finch::ui::repeater::show(ui, &shared, &mut rep);
    });
    let joined = texts.join("\n");
    assert!(joined.contains("Repeat 2"), "second tab missing");
    assert!(joined.contains("2/3"), "history position indicator missing");

    // Rendering session 2 shows its own request.
    rep.active = 1;
    let texts = draw_two_frames(|ui| {
        finch::ui::repeater::show(ui, &shared, &mut rep);
    });
    let joined = texts.join("\n");
    assert!(
        joined.contains("GET /two HTTP/1.1"),
        "active session request should be visible"
    );
}

#[test]
fn decoder_recipe_pipeline_renders_without_panicking() {
    use finch::ui::decoder::{BlockMode, DecoderUi, OpKind, Step, StepParams, run_pipeline};

    let mut dec = DecoderUi::default();
    dec.input = "hello finch".into();
    dec.steps.push(Step::new(OpKind::Base64Encode));
    dec.steps.push(Step {
        kind: OpKind::AesCrypt {
            enc: true,
            mode: BlockMode::Ecb,
        },
        enabled: true,
        params: StepParams {
            key: "00112233445566778899aabbccddeeff".into(),
            ..Default::default()
        },
    });
    dec.selected.set(2);

    // The engine result the UI displays must be the AES ciphertext.
    let results = run_pipeline(dec.input.as_bytes(), &dec.steps);
    assert!(
        results[1].error.is_none(),
        "AES step failed: {:?}",
        results[1].error
    );
    // Step 1 base64-encodes the 11-byte input into 16 chars; step 2 pads that
    // to 32 bytes of AES-ECB ciphertext.
    assert_eq!(results[0].data.len(), 16, "base64 of 11 bytes -> 16 chars");
    assert_eq!(
        results[1].data.len(),
        32,
        "PKCS7-padded 16-byte input -> 32-byte ciphertext"
    );

    let texts = draw_two_frames(|ui| {
        finch::ui::decoder::show(ui, &mut dec);
    });
    let joined = texts.join("\n");
    for label in [
        "Input",
        "Operations",
        "Output",
        // First rows of the operation library are scrolled into view.
        "Base64 Encode",
        "Base64 Decode",
        "hello finch",
    ] {
        assert!(joined.contains(label), "missing UI element: {label}");
    }
}

#[test]
fn comparer_live_diff_renders_without_panicking() {
    let mut cmp = finch::ui::comparer::ComparerUi::default();
    cmp.left = "gwe\nafd\n".into();
    cmp.right = "sdfdsfcqwe\nqwe\nafds\n".into();

    let texts = draw_two_frames(|ui| {
        finch::ui::comparer::show(ui, &mut cmp);
    });
    let joined = texts.join("\n");
    for label in ["Original", "Modified", "Data compare", "+", "-", "gwe"] {
        assert!(joined.contains(label), "missing comparer element: {label}");
    }
    // A second frame with a taller viewport must not panic either.
    let _ = draw_two_frames(|ui| {
        finch::ui::comparer::show(ui, &mut cmp);
    });

    // Cell kinds: the diff engine marks afd->afds as a replace.
    let (rows, added, removed, truncated) =
        finch::ui::comparer::compute_rows_for_test("gwe\nafd\n", "sdfdsfcqwe\nqwe\nafds\n");
    assert!(!truncated);
    assert_eq!(removed, 2, "both original lines should be replaced/removed");
    assert_eq!(added, 3, "all three right lines should be inserted");
    assert!(
        rows.iter()
            .any(|r| r.left.kind == finch::ui::comparer::CellKind::Del)
    );
    assert!(
        rows.iter()
            .any(|r| r.right.kind == finch::ui::comparer::CellKind::Ins)
    );
    assert!(
        rows.iter()
            .any(|r| r.left.kind == finch::ui::comparer::CellKind::Empty)
    );
}

#[test]
fn notes_list_and_editor_render_without_panicking() {
    let mut notes_ui = finch::ui::notes::NotesUi::default();
    notes_ui.notes.push(finch::ui::notes::Note {
        id: 1,
        title: "Findings".into(),
        body: "SQLi at /login\nuser=' or 1=1--".into(),
        updated: 1_700_000_000_000,
    });
    notes_ui.selected = Some(0);
    notes_ui.split = 0.35;
    notes_ui.loaded = true; // skip disk load; keep the in-memory note
    notes_ui.next_id = 2;

    let texts = draw_two_frames(|ui| {
        finch::ui::notes::show(ui, &mut notes_ui);
    });
    let joined = texts.join("\n");
    for label in ["New note", "Findings", "Title", "SQLi at /login"] {
        assert!(joined.contains(label), "missing notes element: {label}");
    }
}

#[test]
fn ws_intercept_and_panel_render_without_panicking() {
    let shared = SharedState::new(Default::default());

    // A captured WebSocket session with one message.
    shared.create_ws_session(
        42,
        "ws://echo.example/ws".into(),
        "echo.example:80".into(),
        false,
        1_700_000_000_000,
    );
    shared.push_ws_message(
        42,
        finch::state::WsDir::Out,
        "text".into(),
        b"hello ws".to_vec(),
        1_700_000_000_001,
    );

    // A parked WebSocket message in the Intercept queue.
    let (tx, _rx) = tokio::sync::oneshot::channel();
    shared.push_pending(PendingItem {
        id: 9,
        entry_id: 0,
        is_request: false,
        destination: "echo.example:80".into(),
        raw: b"hello ws".to_vec(),
        tx: std::sync::Mutex::new(Some(tx)),
        time: 1_700_000_000_001,
        is_tcp: false,
        is_ws: true,
        ws_dir: Some(finch::state::WsDir::Out),
        ws_opcode: "text".into(),
    });

    // --- Intercept tab shows the WS message and editor
    let mut proxy = ProxyUi {
        sub_tab: SubTab::Intercept,
        selected_pending: Some(9),
        ..Default::default()
    };
    let mut actions = Actions::default();
    let texts = draw_two_frames(|ui| {
        finch::ui::proxy::show(ui, &shared, &mut proxy, &mut actions);
    });
    let joined = texts.join(
        "
",
    );
    assert!(joined.contains("WS"), "WS type marker missing");
    assert!(joined.contains("echo.example:80"), "WS queue row missing");
    assert!(joined.contains("hello ws"), "WS payload should be shown");

    // --- WebSockets sub-tab shows the session and message
    let mut proxy = ProxyUi {
        sub_tab: SubTab::WebSockets,
        ..Default::default()
    };
    let texts = draw_two_frames(|ui| {
        finch::ui::proxy::show(ui, &shared, &mut proxy, &mut actions);
    });
    let joined = texts.join(
        "
",
    );
    assert!(
        joined.contains("ws://echo.example/ws"),
        "session row missing"
    );
    assert!(joined.contains("hello ws"), "message preview missing");
}

#[test]
fn ai_and_mcp_panels_render_without_panicking() {
    let shared = SharedState::new(Default::default());

    // --- AI panel
    let mut ai = finch::ui::ai::AiUi::default();
    ai.auto_scroll = true;
    ai.chat.push(finch::ai::ChatMessage {
        role: finch::ai::ChatRole::User,
        content: "analyze the login form".into(),
    });
    ai.chat.push(finch::ai::ChatMessage {
        role: finch::ai::ChatRole::Assistant,
        content: "Try SQLi on the username field.".into(),
    });
    let mut mcp_ui = finch::ui::mcp::McpUi::default();
    let texts = draw_two_frames(|ui| {
        finch::ui::ai::show(ui, &shared, &mut ai, &mut mcp_ui);
    });
    let joined = texts.join(
        "
",
    );
    assert!(
        joined.contains("analyze the login form"),
        "user msg missing"
    );
    assert!(joined.contains("Try SQLi"), "assistant msg missing");
    assert!(joined.contains("Send"), "chat input row missing");

    // --- MCP panel with one configured server
    shared
        .settings
        .lock()
        .unwrap()
        .mcp_servers
        .push(finch::state::McpServerConfig {
            name: "local-test".into(),
            transport: finch::state::McpTransportConfig::Stdio {
                command: "cmd".into(),
                args: vec!["/c".into(), "echo".into()],
            },
        });
    let mut mcp = finch::ui::mcp::McpUi::default();
    let texts = draw_two_frames(|ui| {
        finch::ui::mcp::show_panel(ui, &shared, &mut mcp);
    });
    let joined = texts.join(
        "
",
    );
    assert!(joined.contains("local-test"), "server row missing");
    assert!(joined.contains("stdio"), "transport missing");
    assert!(joined.contains("disconnected"), "status missing");
}
