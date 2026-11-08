//! MCP tab: manage Model Context Protocol servers (stdio subprocess or
//! Streamable HTTP), inspect their tools and call them manually.
//!
//! Background work reports back over std::sync::mpsc channels that the UI
//! polls each frame — no shared mutable state.

use std::sync::{Arc, mpsc};

use egui::RichText;

use crate::mcp_client::{McpConnection, McpStatus, McpTool};
use crate::state::{McpTransportConfig, SharedState};

/// One configured server as shown in the UI.
#[derive(Default)]
struct ServerRow {
    name: String,
    transport: Option<McpTransportConfig>,
    status: McpStatus,
    error: Option<String>,
    tools: Vec<McpTool>,
}

#[derive(Default)]
pub struct McpUi {
    rows: Vec<ServerRow>,
    pub selected: Option<usize>,
    /// Background connect probes (name, result) awaiting pickup.
    pending: Vec<mpsc::Receiver<(String, Result<Vec<McpTool>, String>)>>,
    // --- add dialog ---
    add_open: bool,
    add_name: String,
    add_kind: usize, // 0 = stdio, 1 = http
    add_command: String,
    add_args: String,
    add_url: String,
    add_error: Option<String>,
    // --- manual tool call ---
    selected_tool: Option<String>,
    call_args: String,
    call_result: Option<(bool, String)>,
    call_pending: Vec<mpsc::Receiver<Result<String, String>>>,
}

impl McpUi {
    fn row_for(&mut self, name: &str) -> Option<&mut ServerRow> {
        self.rows.iter_mut().find(|r| r.name == name)
    }

    /// Poll background tasks and fold their results into the rows.
    fn poll(&mut self) {
        let drained: Vec<mpsc::Receiver<(String, Result<Vec<McpTool>, String>)>> =
            std::mem::take(&mut self.pending);
        self.pending = Vec::new();
        let mut still_pending = Vec::new();
        for rx in drained {
            match rx.try_recv() {
                Ok((name, res)) => {
                    if let Some(row) = self.row_for(&name) {
                        // Only apply if the user hasn't disconnected in the
                        // meantime (a late probe result must not override).
                        if row.status != McpStatus::Connecting {
                            continue;
                        }
                        match res {
                            Ok(tools) => {
                                row.tools = tools;
                                row.status = McpStatus::Connected;
                                row.error = None;
                            }
                            Err(e) => {
                                row.status = McpStatus::Error;
                                row.error = Some(e);
                            }
                        }
                    }
                }
                Err(mpsc::TryRecvError::Empty) => still_pending.push(rx),
                Err(mpsc::TryRecvError::Disconnected) => {}
            }
        }
        self.pending = still_pending;

        let mut call_pending = std::mem::take(&mut self.call_pending);
        for rx in call_pending.drain(..) {
            match rx.try_recv() {
                Ok(res) => {
                    self.call_result = Some(match res {
                        Ok(t) => (true, t),
                        Err(e) => (false, e),
                    });
                }
                Err(mpsc::TryRecvError::Empty) => self.call_pending.push(rx),
                Err(mpsc::TryRecvError::Disconnected) => {}
            }
        }
    }
}

/// Panel entry (also embedded in the AI tab).
pub fn show_panel(ui: &mut egui::Ui, shared: &Arc<SharedState>, m: &mut McpUi) {
    m.poll();

    // Keep rows aligned with the configured servers.
    let configs: Vec<(String, McpTransportConfig)> = {
        let s = shared.settings.lock().unwrap();
        s.mcp_servers
            .iter()
            .map(|c| (c.name.clone(), c.transport.clone()))
            .collect()
    };
    m.rows.retain(|r| configs.iter().any(|(n, _)| n == &r.name));
    for (name, transport) in &configs {
        if !m.rows.iter().any(|r| r.name == *name) {
            m.rows.push(ServerRow {
                name: name.clone(),
                transport: Some(transport.clone()),
                status: McpStatus::Disconnected,
                error: None,
                tools: Vec::new(),
            });
        }
    }
    if let Some(sel) = m.selected {
        if sel >= m.rows.len() {
            m.selected = None;
        }
    }

    // Toolbar
    ui.horizontal(|ui| {
        if theme_button(ui, true, "Add server") {
            m.add_open = true;
            m.add_name.clear();
            m.add_command.clear();
            m.add_args.clear();
            m.add_url.clear();
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let connected = m
                .rows
                .iter()
                .filter(|r| r.status == McpStatus::Connected)
                .count();
            ui.label(
                RichText::new(format!("{connected} / {} connected", configs.len()))
                    .size(11.5)
                    .color(muted()),
            );
        });
    });
    ui.add_space(6.0);

    // Server table
    egui_extras::TableBuilder::new(ui)
        .id_salt("mcp_servers")
        .striped(true)
        .sense(egui::Sense::click())
        .column(egui_extras::Column::initial(160.0).resizable(true))
        .column(egui_extras::Column::initial(90.0))
        .column(egui_extras::Column::remainder().at_least(160.0))
        .column(egui_extras::Column::initial(70.0))
        .column(egui_extras::Column::initial(110.0))
        .header(20.0, |mut h| {
            for name in ["Name", "Transport", "Endpoint / Command", "Tools", "Status"] {
                h.col(|ui| {
                    ui.label(RichText::new(name).size(11.0).color(muted()));
                });
            }
        })
        .body(|mut body| {
            for (idx, row) in m.rows.iter().enumerate() {
                body.row(22.0, |mut r| {
                    r.set_selected(m.selected == Some(idx));
                    let endpoint = match &row.transport {
                        Some(McpTransportConfig::Stdio { command, args }) => {
                            if args.is_empty() {
                                command.clone()
                            } else {
                                format!("{command} {}", args.join(" "))
                            }
                        }
                        Some(McpTransportConfig::Http { url, .. }) => url.clone(),
                        None => String::new(),
                    };
                    r.col(|ui| {
                        ui.label(RichText::new(&row.name).size(12.0));
                    });
                    r.col(|ui| {
                        let label = match &row.transport {
                            Some(McpTransportConfig::Stdio { .. }) => "stdio",
                            Some(McpTransportConfig::Http { .. }) | None => "http",
                        };
                        ui.label(RichText::new(label).size(12.0).color(accent()));
                    });
                    r.col(|ui| {
                        ui.add(egui::Label::new(RichText::new(endpoint).size(12.0)).truncate());
                    });
                    r.col(|ui| {
                        ui.label(RichText::new(row.tools.len().to_string()).size(12.0));
                    });
                    r.col(|ui| {
                        let (text, color) = match row.status {
                            McpStatus::Connected => ("connected", ok_color()),
                            McpStatus::Connecting => ("connecting...", warn()),
                            McpStatus::Error => ("error", bad()),
                            McpStatus::Disconnected => ("disconnected", muted()),
                        };
                        ui.label(RichText::new(text).size(12.0).color(color));
                    });
                    if r.response().clicked() {
                        m.selected = Some(idx);
                    }
                });
            }
        });
    ui.add_space(6.0);

    // Selected server panel
    if let Some(idx) = m.selected {
        let (name, transport) = {
            let row = &m.rows[idx];
            (row.name.clone(), row.transport.clone())
        };
        let status = m.rows[idx].status;
        ui.horizontal(|ui| {
            let connected = status == McpStatus::Connected;
            if theme_button(
                ui,
                !connected && !matches!(status, McpStatus::Connecting),
                "Connect",
            ) {
                let (tx, rx) = mpsc::channel();
                m.pending.push(rx);
                let name2 = name.clone();
                let transport2 = transport.clone().unwrap_or_default();
                let repaint = ui.ctx().clone();
                crate::app::runtime().spawn(async move {
                    let mut conn = McpConnection::new(name2.clone(), transport2);
                    let res = conn.connect().await.map(|_| conn.tools.clone());
                    conn.shutdown();
                    let _ = tx.send((name2, res));
                    repaint.request_repaint();
                });
                if let Some(row) = m.row_for(&name) {
                    row.status = McpStatus::Connecting;
                    row.error = None;
                }
            }
            if theme_button(ui, true, "Disconnect") {
                if let Some(row) = m.row_for(&name) {
                    row.status = McpStatus::Disconnected;
                    row.tools.clear();
                }
            }
            if theme_button(ui, true, "Remove") {
                {
                    // Locate by name: `idx` indexes m.rows, which can drift
                    // out of sync with the config list (duplicate names, or
                    // an external reorder) and delete the wrong server.
                    let s = shared.settings.lock().unwrap();
                    let mut servers = s.mcp_servers.clone();
                    drop(s);
                    servers.retain(|c| c.name != name);
                    shared.settings.lock().unwrap().mcp_servers = servers;
                }
                crate::proxy_ctrl::save_settings(&shared.settings.lock().unwrap().clone());
                m.rows.retain(|r| r.name != name);
                m.selected = None;
            }
            if let Some(row) = m.row_for(&name) {
                if let Some(err) = &row.error {
                    ui.label(RichText::new(err).size(11.0).color(bad()));
                }
            }
        });
        ui.add_space(6.0);

        // Tools + manual call.
        let tools = m.rows[idx].tools.clone();
        if tools.is_empty() {
            ui.label(
                RichText::new("Connect the server to list its tools.")
                    .size(11.5)
                    .color(muted()),
            );
        } else {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Tool:").size(12.0));
                egui::ComboBox::from_id_salt("mcp_tool_select")
                    .width(280.0)
                    .selected_text(m.selected_tool.as_deref().unwrap_or("select a tool"))
                    .show_ui(ui, |ui| {
                        for t in &tools {
                            ui.selectable_value(
                                &mut m.selected_tool,
                                Some(t.name.clone()),
                                &t.name,
                            );
                        }
                    });
            });
            if let Some(t) = tools
                .iter()
                .find(|t| Some(&t.name) == m.selected_tool.as_ref())
            {
                ui.label(RichText::new(&t.description).size(11.5).color(muted()));
                ui.label(
                    RichText::new(format!("schema: {}", t.schema))
                        .size(10.5)
                        .color(muted()),
                );
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Args JSON:").size(12.0));
                ui.add(
                    egui::TextEdit::singleline(&mut m.call_args)
                        .hint_text("{}")
                        .desired_width(ui.available_width() - 100.0)
                        .font(egui::TextStyle::Monospace),
                );
                let tool_in_server = m
                    .selected_tool
                    .as_ref()
                    .map(|sel| tools.iter().any(|t| &t.name == sel))
                    .unwrap_or(false);
                if theme_button(ui, tool_in_server, "Call") {
                    if let Some(tool) = m.selected_tool.clone() {
                        let args: serde_json::Value =
                            serde_json::from_str(if m.call_args.trim().is_empty() {
                                "{}"
                            } else {
                                &m.call_args
                            })
                            .unwrap_or(serde_json::json!({}));
                        let (tx, rx) = mpsc::channel();
                        m.call_pending.push(rx);
                        let transport2 = transport.clone().unwrap_or_default();
                        let repaint = ui.ctx().clone();
                        crate::app::runtime().spawn(async move {
                            let result = call_with_fresh_connection(transport2, &tool, args).await;
                            let _ = tx.send(result);
                            repaint.request_repaint();
                        });
                        m.call_result = None;
                    }
                }
            });
            if let Some((ok, text)) = &m.call_result {
                ui.add_space(4.0);
                egui::Frame::new()
                    .stroke(egui::Stroke::new(1.0, muted()))
                    .corner_radius(4.0)
                    .inner_margin(6.0)
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .max_height(220.0)
                            .id_salt("mcp_call_result")
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(text).monospace().size(12.0).color(if *ok {
                                        ok_color()
                                    } else {
                                        bad()
                                    }),
                                );
                            });
                    });
            }
        }
    }

    draw_add_window(ui, shared, m);
}

/// Fresh connection per call: simple and avoids long-lived child processes
/// held by the UI layer.
async fn call_with_fresh_connection(
    transport: McpTransportConfig,
    tool: &str,
    args: serde_json::Value,
) -> Result<String, String> {
    let mut conn = McpConnection::new("manual".into(), transport);
    if let Err(e) = conn.connect().await {
        // A stdio child process may already be spawned; never leak it.
        conn.shutdown();
        return Err(e);
    }
    let out = conn.call_tool(tool, args).await;
    conn.shutdown();
    out
}

// --------------------------------------------------------------- add dialog

fn draw_add_window(ui: &mut egui::Ui, shared: &Arc<SharedState>, m: &mut McpUi) {
    if !m.add_open {
        return;
    }
    let mut open = m.add_open;
    egui::Window::new(RichText::new("Add MCP server").size(13.0).strong())
        .open(&mut open)
        .default_width(480.0)
        .show(ui.ctx(), |ui| {
            egui::Grid::new("mcp_add_grid")
                .num_columns(2)
                .spacing([8.0, 6.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("Name").size(12.0));
                    ui.add(
                        egui::TextEdit::singleline(&mut m.add_name)
                            .desired_width(300.0)
                            .hint_text("my-server"),
                    );
                    ui.end_row();

                    ui.label(RichText::new("Transport").size(12.0));
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut m.add_kind, 0, "stdio");
                        ui.selectable_value(&mut m.add_kind, 1, "http");
                    });
                    ui.end_row();

                    if m.add_kind == 0 {
                        ui.label(RichText::new("Command").size(12.0));
                        ui.add(
                            egui::TextEdit::singleline(&mut m.add_command)
                                .desired_width(300.0)
                                .hint_text("npx"),
                        );
                        ui.end_row();
                        ui.label(RichText::new("Args (space separated)").size(12.0));
                        ui.add(
                            egui::TextEdit::singleline(&mut m.add_args)
                                .desired_width(300.0)
                                .hint_text("-y @modelcontextprotocol/server-everything"),
                        );
                        ui.end_row();
                    } else {
                        ui.label(RichText::new("URL").size(12.0));
                        ui.add(
                            egui::TextEdit::singleline(&mut m.add_url)
                                .desired_width(300.0)
                                .hint_text("http://127.0.0.1:3000/mcp"),
                        );
                        ui.end_row();
                    }
                });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if theme_button(ui, !m.add_name.trim().is_empty(), "Save") {
                    let name = m.add_name.trim().to_string();
                    // Reject duplicates: rows and the config list are matched
                    // by name elsewhere, so duplicate names desync them.
                    let dup = shared
                        .settings
                        .lock()
                        .unwrap()
                        .mcp_servers
                        .iter()
                        .any(|c| c.name == name);
                    if dup {
                        m.add_error = Some(format!("A server named '{name}' already exists."));
                    } else {
                        m.add_error = None;
                        let transport = if m.add_kind == 0 {
                            McpTransportConfig::Stdio {
                                command: m.add_command.trim().to_string(),
                                args: m
                                    .add_args
                                    .split_whitespace()
                                    .map(|s| s.to_string())
                                    .collect(),
                            }
                        } else {
                            McpTransportConfig::Http {
                                url: m.add_url.trim().to_string(),
                                headers: Vec::new(),
                            }
                        };
                        shared.settings.lock().unwrap().mcp_servers.push(
                            crate::state::McpServerConfig { name, transport },
                        );
                        crate::proxy_ctrl::save_settings(
                            &shared.settings.lock().unwrap().clone(),
                        );
                        m.add_open = false;
                    }
                }
                if theme_button(ui, true, "Cancel") {
                    m.add_open = false;
                }
            });
            if let Some(err) = &m.add_error {
                ui.add_space(4.0);
                ui.label(RichText::new(err).size(11.5).color(bad()));
            }
        });
    m.add_open = open;
}

// ------------------------------------------------------------------ helpers

fn muted() -> egui::Color32 {
    egui::Color32::from_rgb(0x8a, 0x92, 0x9e)
}
fn accent() -> egui::Color32 {
    egui::Color32::from_rgb(0x7a, 0xb4, 0xff)
}
fn ok_color() -> egui::Color32 {
    egui::Color32::from_rgb(0x7a, 0xd8, 0x9c)
}
fn warn() -> egui::Color32 {
    egui::Color32::from_rgb(0xd8, 0xa5, 0x5a)
}
fn bad() -> egui::Color32 {
    egui::Color32::from_rgb(0xff, 0x77, 0x77)
}

fn theme_button(ui: &mut egui::Ui, enabled: bool, label: &str) -> bool {
    ui.add_enabled(enabled, egui::Button::new(RichText::new(label).size(12.0)))
        .clicked()
}
