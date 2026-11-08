//! WebSockets sub-tab: captured WebSocket sessions and their frames
//! (read-only view, like Burp's WebSockets history).

use std::sync::Arc;

use egui::RichText;
use egui_extras::Column;

use crate::state::{SharedState, WsDir, WsSession, WsSessionState};
use crate::ui::theme::{self, ButtonKind, EmptyState};
use crate::ui::viewer::MessageView;

pub struct WsPanelUi {
    pub filter: String,
    /// Selected session id.
    pub selected_session: Option<u64>,
    /// Selected message index within the session.
    pub selected_msg: Option<usize>,
    pub follow: bool,
    /// Last session id shown (resets viewer on change).
    pub last_session: Option<u64>,
    pub viewer: MessageView,
    /// Sessions table vs message panes.
    pub vsplit: f32,
    /// Message list vs detail viewer.
    pub msg_vsplit: f32,
}

impl Default for WsPanelUi {
    fn default() -> Self {
        Self {
            filter: String::new(),
            selected_session: None,
            selected_msg: None,
            follow: true,
            last_session: None,
            viewer: MessageView::new_raw(false),
            vsplit: 0.32,
            msg_vsplit: 0.5,
        }
    }
}

/// Human readable byte size ("1.2 KB").
fn fmt_size(n: usize) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    }
}

fn session_matches(filter: &str, s: &WsSession) -> bool {
    if filter.is_empty() {
        return true;
    }
    let f = filter.to_lowercase();
    s.url.to_lowercase().contains(&f)
        || s.messages.iter().any(|m| {
            String::from_utf8_lossy(&m.payload)
                .to_lowercase()
                .contains(&f)
        })
}

fn state_color(state: WsSessionState) -> egui::Color32 {
    match state {
        WsSessionState::Open => theme::SUCCESS,
        WsSessionState::Closed => theme::MUTED,
        WsSessionState::Error => theme::DANGER,
    }
}

pub fn show(
    ui: &mut egui::Ui,
    shared: &Arc<SharedState>,
    p: &mut WsPanelUi,
    actions: &mut crate::ui::Actions,
) {
    let total = shared.ws_sessions.lock().unwrap().len();
    let sessions: Vec<Arc<std::sync::Mutex<WsSession>>> = shared
        .ws_sessions
        .lock()
        .unwrap()
        .iter()
        .filter(|s| session_matches(&p.filter, &s.lock().unwrap()))
        .cloned()
        .collect();

    // Toolbar
    ui.horizontal(|ui| {
        ui.label(RichText::new("Filter").size(12.0).color(theme::MUTED));
        ui.add(
            egui::TextEdit::singleline(&mut p.filter)
                .desired_width(360.0)
                .hint_text("url or message text"),
        );
        if theme::button(ui, !p.filter.is_empty(), "Clear", ButtonKind::Secondary).clicked() {
            p.filter.clear();
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if theme::button(ui, total > 0, "Clear", ButtonKind::Secondary).clicked() {
                shared.clear_ws_sessions();
                p.selected_session = None;
                p.selected_msg = None;
                p.last_session = None;
            }
            ui.add_space(8.0);
            ui.checkbox(
                &mut p.follow,
                RichText::new("Follow new traffic")
                    .size(12.0)
                    .color(theme::MUTED),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new(format!("{} / {total} sessions", sessions.len()))
                    .size(11.5)
                    .color(theme::MUTED),
            );
        });
    });
    ui.add_space(8.0);

    if sessions.is_empty() {
        let _ = theme::empty_state(
            ui,
            &EmptyState::new(
                "No WebSocket sessions",
                "Connect a WebSocket client through the proxy — sessions appear here in real time.",
            ),
        );
        return;
    }

    // Resolve the selected session (default: last one while following).
    let selected = p
        .selected_session
        .and_then(|id| {
            sessions
                .iter()
                .find(|s| s.lock().unwrap().id == id)
                .cloned()
        })
        .or_else(|| {
            if p.follow {
                sessions.last().cloned()
            } else {
                None
            }
        });
    if let Some(sel) = &selected {
        let id = sel.lock().unwrap().id;
        if p.selected_session != Some(id) {
            p.selected_session = Some(id);
            p.selected_msg = None;
        }
    }
    // Cell-based selection so both split panes can read/write without
    // fighting over `&mut p` (written back below).
    let sel_session = std::cell::Cell::new(p.selected_session);
    let sel_msg = std::cell::Cell::new(p.selected_msg);

    // Reset the viewer when the session changes.
    if p.last_session != p.selected_session {
        p.viewer = MessageView::new_raw(false);
        p.last_session = p.selected_session;
    }

    theme::v_split_panes(
        ui,
        &mut p.vsplit,
        |ui| {
            // ---- sessions table ----
            egui_extras::TableBuilder::new(ui)
                .id_salt("ws_sessions_table")
                .striped(true)
                .resizable(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::initial(70.0))
                .column(Column::initial(64.0))
                .column(Column::remainder().at_least(120.0).resizable(true))
                .column(Column::initial(64.0))
                .column(Column::initial(60.0))
                .header(20.0, |mut header| {
                    for name in ["Time", "State", "URL", "Messages", "Size"] {
                        header.col(|ui| {
                            ui.label(RichText::new(name).size(11.5).strong().color(theme::MUTED));
                        });
                    }
                })
                .body(|mut body| {
                    for s in &sessions {
                        let (id, time, state, url, msgs, size) = {
                            let s = s.lock().unwrap();
                            (
                                s.id,
                                s.time,
                                s.state,
                                s.url.clone(),
                                s.messages.len(),
                                s.messages.iter().map(|m| m.size).sum::<usize>(),
                            )
                        };
                        let selected_row = sel_session.get() == Some(id);
                        body.row(22.0, |mut row| {
                            row.col(|ui| {
                                if ui
                                    .selectable_label(selected_row, crate::state::format_time(time))
                                    .clicked()
                                {
                                    sel_session.set(Some(id));
                                    sel_msg.set(None);
                                }
                            });
                            row.col(|ui| {
                                theme::status_dot(ui, state_color(state));
                                ui.label(
                                    RichText::new(state.as_str())
                                        .size(11.5)
                                        .color(state_color(state)),
                                );
                            });
                            row.col(|ui| {
                                if ui.selectable_label(selected_row, url).clicked() {
                                    sel_session.set(Some(id));
                                    sel_msg.set(None);
                                }
                            });
                            row.col(|ui| {
                                ui.label(RichText::new(msgs.to_string()).size(11.5));
                            });
                            row.col(|ui| {
                                ui.label(
                                    RichText::new(fmt_size(size)).size(11.5).color(theme::MUTED),
                                );
                            });
                        });
                    }
                });
        },
        |ui| {
            // ---- messages of the selected session ----
            let Some(sel) = selected else {
                return;
            };
            let messages: Vec<crate::state::WsMessageEntry> = sel.lock().unwrap().messages.clone();
            if messages.is_empty() {
                theme::hint(ui, "No frames captured yet.");
                return;
            }
            if sel_msg.get().is_none() {
                sel_msg.set(Some(messages.len() - 1));
            }

            theme::v_split_panes(
                ui,
                &mut p.msg_vsplit,
                |ui| {
                    let table = egui_extras::TableBuilder::new(ui)
                        .id_salt("ws_messages_table")
                        .striped(true)
                        .resizable(true)
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(Column::initial(36.0))
                        .column(Column::initial(28.0))
                        .column(Column::initial(60.0))
                        .column(Column::initial(64.0))
                        .column(Column::remainder().at_least(120.0));
                    table
                        .header(20.0, |mut header| {
                            for name in ["#", "Dir", "Opcode", "Size", "Payload"] {
                                header.col(|ui| {
                                    ui.label(
                                        RichText::new(name).size(11.5).strong().color(theme::MUTED),
                                    );
                                });
                            }
                        })
                        .body(|mut body| {
                            let start = if p.follow {
                                // Only render the tail while following to stay cheap.
                                messages.len().saturating_sub(300)
                            } else {
                                0
                            };
                            for (i, m) in messages.iter().enumerate().skip(start) {
                                let selected_row = sel_msg.get() == Some(i);
                                let dir_color = match m.direction {
                                    WsDir::Out => theme::ACCENT,
                                    WsDir::In => theme::SUCCESS,
                                };
                                let preview_len = m.payload.len().min(200);
                                let preview = String::from_utf8_lossy(&m.payload[..preview_len])
                                    .chars()
                                    .take(120)
                                    .collect::<String>();
                                body.row(20.0, |mut row| {
                                    row.col(|ui| {
                                        if ui
                                            .selectable_label(selected_row, (i + 1).to_string())
                                            .clicked()
                                        {
                                            sel_msg.set(Some(i));
                                        }
                                    });
                                    row.col(|ui| {
                                        ui.label(
                                            RichText::new(m.direction.as_str())
                                                .size(12.0)
                                                .color(dir_color),
                                        );
                                    });
                                    row.col(|ui| {
                                        ui.label(
                                            RichText::new(&m.opcode).size(11.5).color(theme::MUTED),
                                        );
                                    });
                                    row.col(|ui| {
                                        ui.label(
                                            RichText::new(fmt_size(m.size))
                                                .size(11.5)
                                                .color(theme::MUTED),
                                        );
                                    });
                                    row.col(|ui| {
                                        if ui.selectable_label(selected_row, preview).clicked() {
                                            sel_msg.set(Some(i));
                                        }
                                    });
                                });
                            }
                        });
                },
                |ui| {
                    // ---- detail viewer ----
                    let idx = sel_msg.get().unwrap_or(0);
                    if let Some(m) = messages.get(idx) {
                        let title = format!(
                            "{} {} · {} · {}",
                            m.direction.as_str(),
                            m.opcode,
                            fmt_size(m.size),
                            crate::state::format_time(m.time),
                        );
                        ui.label(RichText::new(title).size(11.5).color(theme::MUTED));
                        // Salt with the message index so edit state (cursor,
                        // scroll) doesn't leak between different messages.
                        p.viewer.show(
                            ui,
                            egui::Id::unique(("ws_detail", sel_session.get(), idx)),
                            &m.payload,
                        );
                        if let Some(pa) = p.viewer.action {
                            actions.send_pane(
                                pa,
                                crate::state::Scheme::Tcp,
                                sel.lock().unwrap().destination.clone(),
                                m.payload.clone(),
                            );
                        }
                    }
                },
            );
        },
    );

    p.selected_session = sel_session.get();
    p.selected_msg = sel_msg.get();
}
