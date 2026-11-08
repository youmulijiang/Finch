//! Proxy tab: Intercept / HTTP history / Options — mirrors Burp's Proxy tab.

use std::sync::Arc;

use egui::{Color32, RichText, ScrollArea};
use egui_extras::Column;

use crate::http_msg;
use crate::state::{Decision, EntryState, HistoryEntry, PendingItem, SharedState};
use crate::ui::theme::{self, ButtonKind, EmptyState};
use crate::ui::viewer::ReqRespViewer;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SubTab {
    Intercept,
    History,
    WebSockets,
    Tun,
    Options,
}

pub struct ProxyUi {
    pub sub_tab: SubTab,
    // --- Intercept ---
    pub req_view: crate::ui::viewer::MessageView,
    pub resp_view: crate::ui::viewer::MessageView,
    /// Editor for intercepted WebSocket payloads (Raw kind).
    pub ws_view: crate::ui::viewer::MessageView,
    /// Pending item currently shown in the editor (reset views on change).
    pub last_pending_id: Option<u64>,
    /// Queue row the user clicked (falls back to the first item).
    pub selected_pending: Option<u64>,
    /// Latest user edit of the currently displayed pending message.
    pub edited: Option<Vec<u8>>,
    // --- History ---
    pub filter: String,
    pub selected_entry: Option<u64>,
    pub viewer: ReqRespViewer,
    pub auto_scroll: bool,
    /// Last measured width of the history table (resets column widths on resize).
    pub history_table_width: f32,
    /// Horizontal split fraction of the request/response panes below the table.
    pub history_split: f32,
    /// Vertical split fraction: history table height vs the packet viewer below.
    pub history_vsplit: f32,
    /// Column index used to sort the history table, and its direction.
    pub sort_col: Option<usize>,
    pub sort_asc: bool,
    // --- Options ---
    /// Edit buffers; `None` = not yet seeded from the live settings. Using
    /// Option (instead of empty-string) means the user can clear a field.
    pub upstream_edit: Option<String>,
    pub intercept_filter_edit: Option<String>,
    pub blacklist_edit: Option<String>,
    // --- TUN ---
    /// Process list for the TUN tab: (pid, process name), refreshed while
    /// the tab is visible.
    pub tun_rows: Vec<(u32, String)>,
    /// Last refresh time of `tun_rows` (throttled to ~1.5 s).
    pub tun_rows_at: Option<std::time::Instant>,
    /// Client-side name filter for the TUN process list.
    pub tun_list_filter: String,
    // --- WebSockets ---
    pub ws: crate::ui::websocket::WsPanelUi,
    /// True while a Notes cell has keyboard focus (set during the previous
    /// frame's table render); re-sorting by the Notes column is frozen so the
    /// row being edited never jumps under the caret.
    pub notes_editing: bool,
}

impl Default for ProxyUi {
    fn default() -> Self {
        Self {
            sub_tab: SubTab::Intercept,
            req_view: crate::ui::viewer::MessageView::new(true),
            resp_view: crate::ui::viewer::MessageView::new(true),
            ws_view: crate::ui::viewer::MessageView::new_raw(true),
            last_pending_id: None,
            selected_pending: None,
            edited: None,
            filter: String::new(),
            selected_entry: None,
            viewer: ReqRespViewer::default(),
            auto_scroll: true,
            history_table_width: 0.0,
            history_split: 0.5,
            history_vsplit: 0.45,
            sort_col: None,
            sort_asc: true,
            upstream_edit: None,
            intercept_filter_edit: None,
            blacklist_edit: None,
            tun_rows: Vec::new(),
            tun_rows_at: None,
            tun_list_filter: String::new(),
            ws: crate::ui::websocket::WsPanelUi::default(),
            notes_editing: false,
        }
    }
}

pub fn show(
    ui: &mut egui::Ui,
    shared: &Arc<SharedState>,
    p: &mut ProxyUi,
    actions: &mut crate::ui::Actions,
) {
    match p.sub_tab {
        SubTab::Intercept => show_intercept(ui, shared, p, actions),
        SubTab::History => show_history(ui, shared, p, actions),
        SubTab::WebSockets => crate::ui::websocket::show(ui, shared, &mut p.ws, actions),
        SubTab::Tun => show_tun(ui, shared, p),
        SubTab::Options => show_options(ui, shared, p),
    }
}

// ---------------------------------------------------------------- Intercept

/// Intercept tab: a packet queue on top (captured while interception is on)
/// and an editable packet pane below — select a packet, edit it, forward it.
fn show_intercept(
    ui: &mut egui::Ui,
    shared: &Arc<SharedState>,
    p: &mut ProxyUi,
    actions: &mut crate::ui::Actions,
) {
    let mut on = shared
        .intercept_req
        .load(std::sync::atomic::Ordering::Relaxed);
    let mut on_resp = shared
        .intercept_resp
        .load(std::sync::atomic::Ordering::Relaxed);

    let queue: Vec<Arc<PendingItem>> = shared.pending.lock().unwrap().clone();
    let has_items = !queue.is_empty();

    // Toolbar: capture toggles + queue size + decision buttons.
    ui.horizontal(|ui| {
        if theme::toggle_with_state(ui, &mut on, "Intercept is on", "Intercept is off") {
            shared
                .intercept_req
                .store(on, std::sync::atomic::Ordering::Relaxed);
        }
        ui.add_space(10.0);
        if theme::toggle(ui, &mut on_resp) {
            shared
                .intercept_resp
                .store(on_resp, std::sync::atomic::Ordering::Relaxed);
        }
        ui.label(RichText::new("Responses").size(12.5).color(theme::MUTED));
        ui.add_space(10.0);
        let mut on_ws = shared
            .intercept_ws
            .load(std::sync::atomic::Ordering::Relaxed);
        if theme::toggle(ui, &mut on_ws) {
            shared
                .intercept_ws
                .store(on_ws, std::sync::atomic::Ordering::Relaxed);
        }
        ui.label(RichText::new("WebSockets").size(12.5).color(theme::MUTED));

        ui.add_space(14.0);
        ui.label(
            RichText::new(format!("Queued: {}", queue.len()))
                .size(12.5)
                .color(theme::MUTED),
        );
        ui.add_space(2.0);

        // Resolve the packet the buttons act on: the selected row, or the
        // oldest queued packet when nothing is selected.
        let action_item: Option<Arc<PendingItem>> = p
            .selected_pending
            .and_then(|id| queue.iter().find(|q| q.id == id).cloned())
            .or_else(|| queue.first().cloned());

        if theme::button(ui, has_items, "Forward", ButtonKind::Primary).clicked() {
            if let Some(item) = action_item.clone() {
                decide(shared, p, &item, true);
            }
        }
        if theme::button(ui, has_items, "Drop", ButtonKind::Danger).clicked() {
            if let Some(item) = action_item {
                decide(shared, p, &item, false);
            }
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if theme::button(ui, has_items, "Drop all", ButtonKind::Danger).clicked() {
                for item in &queue {
                    send_decision(item, Decision::Drop);
                }
                // Empty the queue right away: tasks waiting on the dropped
                // decisions remove their own entries as they wake up, but a
                // connection that is never polled again would leave the item
                // stuck in the queue forever.
                shared.pending.lock().unwrap().clear();
                shared.wake();
                p.selected_pending = None;
            }
        });
    });
    ui.add_space(8.0);

    if !has_items {
        p.last_pending_id = None;
        p.edited = None;
        p.selected_pending = None;
        let (title, subtitle, cta) = if on {
            (
                "Intercept is on",
                "Waiting for client traffic through the proxy...",
                "Turn off intercept",
            )
        } else if on_resp {
            (
                "Intercepting responses",
                "Waiting for server responses...",
                "Turn off intercept",
            )
        } else {
            (
                "Intercept is off",
                "Turn on interception to pause requests at the proxy.",
                "Turn on intercept",
            )
        };
        let clicked = theme::empty_state(ui, &EmptyState::new(title, subtitle).with_cta(cta, true));
        if clicked {
            let (new_req, new_resp) = if on {
                (false, on_resp)
            } else if on_resp {
                (false, false)
            } else {
                (true, false)
            };
            shared
                .intercept_req
                .store(new_req, std::sync::atomic::Ordering::Relaxed);
            shared
                .intercept_resp
                .store(new_resp, std::sync::atomic::Ordering::Relaxed);
        }
        return;
    }

    // Keep the selection valid: default to the oldest queued packet.
    if p.selected_pending.is_none() || !queue.iter().any(|q| Some(q.id) == p.selected_pending) {
        p.selected_pending = queue.first().map(|q| q.id);
    }
    let selected: Arc<PendingItem> = queue
        .iter()
        .find(|q| Some(q.id) == p.selected_pending)
        .cloned()
        .expect("selection validated above");

    // ---- Top half: the packet queue table ----
    let table_h = (ui.available_height() * 0.45).max(120.0);
    let mut clicked_id: Option<u64> = None;
    theme::card_with_margin(ui, 8.0, |ui| {
        ui.set_height(table_h - 16.0);
        ui.visuals_mut().selection.bg_fill = theme::ACCENT_ROW;
        egui_extras::TableBuilder::new(ui)
            .id_salt("intercept_queue")
            .striped(true)
            .vscroll(true)
            .sense(egui::Sense::click())
            .stick_to_bottom(true)
            .column(Column::initial(44.0))
            .column(Column::initial(88.0))
            .column(Column::initial(190.0).resizable(true))
            .column(Column::initial(64.0))
            .column(Column::remainder().at_least(120.0).resizable(true))
            .column(Column::initial(70.0))
            .column(Column::initial(70.0))
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .header(22.0, |mut h| {
                for name in ["#", "Type", "Host", "Method", "Path", "Bytes", "Time"] {
                    h.col(|ui| {
                        ui.label(RichText::new(name).size(11.0).color(theme::MUTED));
                    });
                }
            })
            .body(|mut body| {
                for item in &queue {
                    body.row(22.0, |mut row| {
                        row.set_selected(p.selected_pending == Some(item.id));
                        row.col(|ui| {
                            ui.label(
                                RichText::new(item.id.to_string())
                                    .monospace()
                                    .size(11.5)
                                    .color(theme::MUTED),
                            );
                        });
                        row.col(|ui| {
                            let (kind, color) = if item.is_ws {
                                let dir = match item.ws_dir {
                                    Some(crate::state::WsDir::In) => "\u{2193}",
                                    _ => "\u{2191}",
                                };
                                (format!("WS {dir} {}", item.ws_opcode), theme::SUCCESS)
                            } else if item.is_request {
                                ("Request".to_string(), theme::ACCENT)
                            } else {
                                ("Response".to_string(), theme::WARNING)
                            };
                            ui.label(RichText::new(kind).size(12.0).color(color));
                        });
                        row.col(|ui| {
                            ui.add(
                                egui::Label::new(RichText::new(&item.destination).size(12.0))
                                    .truncate(),
                            );
                        });
                        row.col(|ui| {
                            let method = if item.is_ws {
                                "-".into()
                            } else if item.is_request {
                                http_msg::parse_request_head(&item.raw)
                                    .map(|(m, _, _)| m.to_string())
                                    .unwrap_or_else(|| "?".into())
                            } else {
                                "-".into()
                            };
                            ui.label(RichText::new(method).size(12.0));
                        });
                        row.col(|ui| {
                            let path = if item.is_ws {
                                String::new()
                            } else if item.is_request {
                                http_msg::parse_request_head(&item.raw)
                                    .map(|(_, u, _)| u)
                                    .unwrap_or_default()
                            } else {
                                String::new()
                            };
                            ui.add(egui::Label::new(RichText::new(path).size(12.0)).truncate());
                        });
                        row.col(|ui| {
                            ui.label(
                                RichText::new(format_bytes(item.raw.len()))
                                    .monospace()
                                    .size(11.5),
                            );
                        });
                        row.col(|ui| {
                            ui.label(
                                RichText::new(crate::state::format_time(item.time))
                                    .monospace()
                                    .size(11.5)
                                    .color(theme::MUTED),
                            );
                        });
                        if row.response().clicked() {
                            clicked_id = Some(item.id);
                        }
                    });
                }
            });
    });
    ui.add_space(4.0);

    if let Some(id) = clicked_id {
        p.selected_pending = Some(id);
    }

    // ---- Bottom half: the selected packet's raw message (editable) ----
    if p.last_pending_id != Some(selected.id) {
        // Reset editors for the newly selected packet.
        p.req_view = crate::ui::viewer::MessageView::new(true);
        p.resp_view = crate::ui::viewer::MessageView::new(true);
        p.ws_view = crate::ui::viewer::MessageView::new_raw(true);
        p.edited = None;
        p.last_pending_id = Some(selected.id);
    }
    let kind = if selected.is_ws {
        let dir = match selected.ws_dir {
            Some(crate::state::WsDir::In) => "in",
            _ => "out",
        };
        format!("WS {dir} {}", selected.ws_opcode)
    } else if selected.is_request {
        "Request".to_string()
    } else {
        "Response".to_string()
    };
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(format!("{kind} #{}", selected.id))
                .size(12.5)
                .strong()
                .color(theme::ACCENT),
        );
        ui.label(
            RichText::new(format!(
                "to {}   ({} bytes)",
                selected.destination,
                selected.raw.len()
            ))
            .size(12.5)
            .color(theme::MUTED),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                RichText::new("Edit the message above, then Forward to release it")
                    .size(11.0)
                    .color(theme::MUTED),
            );
        });
    });
    ui.add_space(6.0);

    let mut pane_action: Option<crate::ui::viewer::PaneAction> = None;
    let edited = if selected.is_ws {
        p.ws_view.sync(&selected.raw);
        let shown = p
            .ws_view
            .show(
                ui,
                egui::Id::unique(("intercept_ws", selected.id)),
                &selected.raw,
            );
        pane_action = p.ws_view.action;
        shown
    } else if selected.is_request {
        p.req_view.sync(&selected.raw);
        let shown = p
            .req_view
            .show(
                ui,
                egui::Id::unique(("intercept_req", selected.id)),
                &selected.raw,
            );
        pane_action = pane_action.or(p.req_view.action);
        shown
    } else {
        p.resp_view.sync(&selected.raw);
        let shown = p
            .resp_view
            .show(
                ui,
                egui::Id::unique(("intercept_resp", selected.id)),
                &selected.raw,
            );
        pane_action = pane_action.or(p.resp_view.action);
        shown
    };
    // Viewer menu: send the (edited) packet to another tab.
    if let Some(pa) = pane_action {
        let raw = edited.clone().unwrap_or_else(|| selected.raw.clone());
        let (scheme, authority) = if selected.is_ws {
            (crate::state::Scheme::Tcp, selected.destination.clone())
        } else {
            (
                if selected.is_request {
                    crate::state::Scheme::Http
                } else {
                    crate::state::Scheme::Tcp
                },
                selected.destination.clone(),
            )
        };
        actions.send_pane(pa, scheme, authority, raw);
    }
    // Track the latest edit so Forward uses it.
    if edited.is_some() {
        p.edited = edited;
    }
}

fn send_decision(item: &Arc<PendingItem>, decision: Decision) {
    if let Some(tx) = item.tx.lock().unwrap().take() {
        let _ = tx.send(decision);
    }
}

fn decide(shared: &Arc<SharedState>, p: &mut ProxyUi, item: &Arc<PendingItem>, forward: bool) {
    let decision = if forward {
        let bytes = p.edited.take().unwrap_or_else(|| item.raw.clone());
        Decision::Forward(bytes)
    } else {
        Decision::Drop
    };
    send_decision(item, decision);
    shared.wake();
}

// ---------------------------------------------------------------- History

struct RowFilter {
    text: String,
}

impl RowFilter {
    fn matches(&self, e: &HistoryEntry) -> bool {
        if self.text.is_empty() {
            return true;
        }
        let t = self.text.to_lowercase();
        for tok in t.split_whitespace() {
            let hit = if let Some(rest) = tok.strip_prefix("status:") {
                e.status
                    .map(|s| s.to_string().contains(rest))
                    .unwrap_or(false)
            } else if let Some(rest) = tok.strip_prefix("host:") {
                e.host.to_lowercase().contains(rest)
            } else if let Some(rest) = tok.strip_prefix("process:") {
                e.process
                    .as_deref()
                    .map(|p| p.to_lowercase().contains(rest))
                    .unwrap_or(false)
            } else if let Some(rest) = tok.strip_prefix("mime:") {
                e.mime.as_deref().map(|m| m.contains(rest)).unwrap_or(false)
            } else {
                e.url().to_lowercase().contains(tok)
                    || e.method.to_lowercase().contains(tok)
                    || e.title
                        .as_deref()
                        .map(|s| s.to_lowercase().contains(tok))
                        .unwrap_or(false)
            };
            if !hit {
                return false;
            }
        }
        true
    }
}

fn show_history(
    ui: &mut egui::Ui,
    shared: &Arc<SharedState>,
    p: &mut ProxyUi,
    actions: &mut crate::ui::Actions,
) {
    // Filtered + sorted entries first: the toolbar shows the match count.
    let total = shared.history.lock().unwrap().len();
    let filter = RowFilter {
        text: p.filter.clone(),
    };
    let mut entries: Vec<Arc<std::sync::Mutex<HistoryEntry>>> = shared
        .history
        .lock()
        .unwrap()
        .iter()
        .filter(|e| filter.matches(&e.lock().unwrap()))
        .cloned()
        .collect();
    if let Some(col) = p.sort_col {
        // While the user types into a Notes cell, skip the re-sort: every
        // keystroke would otherwise reorder the rows under the caret.
        if !(col == 12 && p.notes_editing) {
            sort_entries(&mut entries, col, p.sort_asc);
        }
    }

    // Toolbar
    ui.horizontal(|ui| {
        ui.label(RichText::new("Filter").size(12.0).color(theme::MUTED));
        ui.add(
            egui::TextEdit::singleline(&mut p.filter)
                .desired_width(420.0)
                .hint_text("text, status:404, host:example.com, mime:json, process:chrome"),
        );
        if theme::button(ui, !p.filter.is_empty(), "Clear", ButtonKind::Secondary).clicked() {
            p.filter.clear();
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if theme::button(ui, total > 0, "Clear history", ButtonKind::Secondary).clicked() {
                shared.history.lock().unwrap().clear();
                // Stale session->entry mappings would make late responses on
                // live connections show up as bogus "TCP" entries.
                shared.session_map.lock().unwrap().clear();
                p.selected_entry = None;
            }
            ui.add_space(8.0);
            ui.checkbox(
                &mut p.auto_scroll,
                RichText::new("Follow new traffic")
                    .size(12.0)
                    .color(theme::MUTED),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new(format!("{} / {total} entries", entries.len()))
                    .size(11.5)
                    .color(theme::MUTED),
            );
        });
    });
    ui.add_space(8.0);

    if entries.is_empty() {
        let clicked = if total == 0 {
            theme::empty_state(
                ui,
                &EmptyState::new(
                    "No traffic yet",
                    "Point your browser at the proxy to start capturing requests.",
                )
                .with_cta("Open browser via proxy", true),
            )
        } else {
            theme::empty_state(
                ui,
                &EmptyState::new(
                    "No matching entries",
                    "Nothing in the history matches the current filter.",
                )
                .with_cta("Clear filter", true),
            )
        };
        if clicked {
            if total == 0 {
                let port = shared.settings.lock().unwrap().listen_port;
                match crate::proxy_ctrl::open_browser_with_proxy(port) {
                    Ok(()) => shared.set_status("Browser launched with proxy"),
                    Err(e) => shared.set_status(e),
                }
            } else {
                p.filter.clear();
            }
        }
        return;
    }

    // Vertical split: table on top, packet viewer below, draggable divider
    // between them (stored fraction, so it never drifts across frames).
    let total_h = ui.available_height().max(320.0);
    let frac_lo = (120.0 / total_h).clamp(0.05, 0.9);
    let frac_hi = ((total_h - 150.0) / total_h).clamp(frac_lo, 0.95);
    let vsplit = p.history_vsplit.clamp(frac_lo, frac_hi);
    p.history_vsplit = vsplit;
    let table_area = total_h * vsplit;
    let mut clicked: Option<u64> = None;
    let current_sort = p.sort_col;
    let current_asc = p.sort_asc;
    let mut clicked_col: Option<usize> = None;
    // Any Notes editor focused during this frame's table render?
    let notes_focused = std::cell::Cell::new(false);

    theme::card_with_margin(ui, 8.0, |ui| {
        // Pin the table card height: the inner horizontal ScrollArea fills
        // its parent, so a min-height-only card would consume the whole page
        // and push the request/response panes off-screen.
        ui.set_height((table_area - 16.0).max(120.0));
        ui.visuals_mut().selection.bg_fill = theme::ACCENT_ROW;
        // Burp-style: all columns stay available via horizontal scrolling
        // instead of squeezing them into the window. Pin an explicit width so
        // the scroll area's unbounded content width cannot blow up the
        // table's remainder column.
        let card_w = ui.available_width();
        ScrollArea::horizontal()
            .id_salt("history_hscroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_width(card_w.max(1300.0));
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.spacing_mut().interact_size.y = 18.0;
                let avail = ui.available_width();
                let table = egui_extras::TableBuilder::new(ui)
                    .id_salt("history_table")
                    .striped(true)
                    .vscroll(true)
                    .sense(egui::Sense::click())
                    .stick_to_bottom(p.auto_scroll)
                    .column(Column::initial(36.0))
                    .column(Column::initial(62.0))
                    .column(Column::initial(130.0).resizable(true))
                    .column(Column::initial(58.0))
                    .column(Column::remainder().at_least(180.0).resizable(true))
                    .column(Column::initial(48.0))
                    .column(Column::initial(48.0))
                    .column(Column::initial(74.0))
                    .column(Column::initial(56.0))
                    .column(Column::initial(72.0))
                    .column(Column::initial(62.0))
                    .column(Column::initial(130.0).resizable(true))
                    .column(Column::initial(96.0).resizable(true))
                    .column(Column::initial(32.0))
                    .column(Column::initial(100.0).resizable(true))
                    .column(Column::initial(54.0))
                    .column(Column::initial(90.0).resizable(true))
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center));
                if (avail - p.history_table_width).abs() > 1.0 {
                    table.reset();
                    p.history_table_width = avail;
                }
                table
                    .header(22.0, |mut h| {
                        let names = [
                            "#",
                            "Time",
                            "Host",
                            "Method",
                            "URL",
                            "Params",
                            "Edited",
                            "Status code",
                            "Length",
                            "MIME type",
                            "Extension",
                            "Title",
                            "Notes",
                            "TLS",
                            "IP",
                            "Cookies",
                            "Process",
                        ];
                        for (idx, name) in names.iter().enumerate() {
                            h.col(|ui| {
                                let sorted = current_sort == Some(idx);
                                let arrow = if sorted {
                                    if current_asc { " ▲" } else { " ▼" }
                                } else {
                                    ""
                                };
                                let color = if sorted { theme::TEXT } else { theme::MUTED };
                                let label = format!("{name}{arrow}");
                                if ui
                                    .selectable_label(
                                        false,
                                        RichText::new(label).size(11.0).color(color),
                                    )
                                    .clicked()
                                {
                                    clicked_col = Some(idx);
                                }
                            });
                        }
                    })
                    .body(|body| {
                        // `rows` only builds the visible rows, keeping large
                        // histories responsive.
                        body.rows(22.0, entries.len(), |mut row| {
                            let entry_arc = &entries[row.index()];
                            let mut entry = entry_arc.lock().unwrap();
                            row.set_selected(p.selected_entry == Some(entry.id));
                            row.col(|ui| {
                                ui.label(
                                    RichText::new(entry.id.to_string())
                                        .monospace()
                                        .size(11.5)
                                        .color(theme::MUTED),
                                );
                            });
                            row.col(|ui| {
                                ui.label(
                                    RichText::new(crate::state::format_time(entry.time))
                                        .monospace()
                                        .size(11.5)
                                        .color(theme::MUTED),
                                );
                            });
                            row.col(|ui| {
                                ui.add(
                                    egui::Label::new(RichText::new(&entry.host).size(12.0))
                                        .truncate(),
                                );
                            });
                            row.col(|ui| {
                                ui.label(RichText::new(&entry.method).size(12.0));
                            });
                            row.col(|ui| {
                                let label = if entry.is_tcp {
                                    format!("[TCP] {} bytes", entry.req_raw.len())
                                } else {
                                    entry.path.clone()
                                };
                                ui.add(
                                    egui::Label::new(RichText::new(label).size(12.0)).truncate(),
                                );
                            });
                            row.col(|ui| {
                                if entry.params > 0 {
                                    ui.label(RichText::new(entry.params.to_string()).size(12.0));
                                } else {
                                    ui.label(RichText::new("-").size(12.0).color(theme::MUTED));
                                }
                            });
                            row.col(|ui| {
                                if entry.edited {
                                    ui.label(RichText::new("✓").size(12.0).color(theme::ACCENT));
                                } else {
                                    ui.label(RichText::new("-").size(12.0).color(theme::MUTED));
                                }
                            });
                            row.col(|ui| {
                                if entry.state == EntryState::Dropped {
                                    ui.label(RichText::new("DROP").size(11.5).color(theme::DANGER));
                                } else if let Some(st) = entry.status {
                                    ui.label(
                                        RichText::new(st.to_string())
                                            .size(12.0)
                                            .color(status_color(st)),
                                    );
                                } else if entry.state == EntryState::Intercepting {
                                    ui.label(RichText::new("INT").size(11.5).color(theme::WARNING));
                                } else {
                                    ui.label(RichText::new("-").size(12.0).color(theme::MUTED));
                                }
                            });
                            row.col(|ui| {
                                if let Some(l) = entry.resp_len {
                                    ui.label(RichText::new(format_bytes(l)).monospace().size(11.5));
                                } else {
                                    ui.label(RichText::new("-").size(12.0).color(theme::MUTED));
                                }
                            });
                            row.col(|ui| {
                                if let Some(m) = &entry.mime {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(http_msg::mime_short(m)).size(11.5),
                                        )
                                        .truncate(),
                                    );
                                } else {
                                    ui.label(RichText::new("-").size(12.0).color(theme::MUTED));
                                }
                            });
                            row.col(|ui| {
                                if let Some(ext) = &entry.extension {
                                    ui.label(RichText::new(ext).size(11.5));
                                } else {
                                    ui.label(RichText::new("-").size(12.0).color(theme::MUTED));
                                }
                            });
                            row.col(|ui| {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(entry.title.clone().unwrap_or_default())
                                            .size(12.0),
                                    )
                                    .truncate(),
                                );
                            });
                            row.col(|ui| {
                                let note_id = entry.id;
                                let notes_resp = ui.add(
                                    egui::TextEdit::singleline(&mut entry.notes)
                                        .id_salt(("hist_notes", note_id))
                                        .font(egui::FontId::proportional(11.5))
                                        .text_color(theme::TEXT)
                                        .margin(egui::Margin::symmetric(0, 0))
                                        .frame(egui::Frame::NONE)
                                        .desired_width(ui.available_width()),
                                );
                                if notes_resp.has_focus() {
                                    notes_focused.set(true);
                                }
                            });
                            row.col(|ui| {
                                if entry.tls {
                                    ui.label(RichText::new("✓").size(12.0).color(theme::SUCCESS));
                                } else {
                                    ui.label(RichText::new("-").size(12.0).color(theme::MUTED));
                                }
                            });
                            row.col(|ui| match &entry.server_ip {
                                Some(ip) => {
                                    ui.add(
                                        egui::Label::new(RichText::new(ip).monospace().size(11.5))
                                            .truncate(),
                                    );
                                }
                                None => {
                                    ui.label(RichText::new("-").size(12.0).color(theme::MUTED));
                                }
                            });
                            row.col(|ui| {
                                if entry.cookies > 0 {
                                    ui.label(RichText::new(entry.cookies.to_string()).size(12.0));
                                } else {
                                    ui.label(RichText::new("-").size(12.0).color(theme::MUTED));
                                }
                            });
                            row.col(|ui| {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(
                                            entry.process.clone().unwrap_or_default(),
                                        )
                                        .size(11.5),
                                    )
                                    .truncate(),
                                );
                            });
                            let row_resp = row.response();
                            if row_resp.clicked() || row_resp.container_secondary_clicked() {
                                clicked = Some(entry.id);
                            }
                            let _ = row_resp.container_context_menu(|ui| {
                                entry_menu(ui, &entry, actions, shared)
                            });
                        });
                    });
            });
    });

    // Feed the focus snapshot back for the next frame's sort decision.
    p.notes_editing = notes_focused.get();

    if let Some(col) = clicked_col {
        if p.sort_col == Some(col) {
            p.sort_asc = !p.sort_asc;
        } else {
            p.sort_col = Some(col);
            p.sort_asc = true;
        }
    }

    // Draggable divider between the history table and the packet viewer.
    let (drect, dresp) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 6.0), egui::Sense::drag());
    let dresp = dresp.on_hover_cursor(egui::CursorIcon::ResizeVertical);
    let color = if dresp.hovered() || dresp.dragged() {
        theme::ACCENT
    } else {
        theme::STROKE
    };
    let y = drect.center().y;
    ui.painter().line_segment(
        [egui::pos2(drect.left(), y), egui::pos2(drect.right(), y)],
        egui::Stroke::new(1.0, color),
    );
    if dresp.dragged() {
        p.history_vsplit = (vsplit + dresp.drag_delta().y / total_h).clamp(frac_lo, frac_hi);
    }
    ui.add_space(6.0);

    // Selected entry viewer. Drop a dangling selection (the entry may have
    // been trimmed by the history limit or removed elsewhere) so the pane
    // shows the placeholder instead of a stale id.
    let selected = entries
        .iter()
        .find(|e| Some(e.lock().unwrap().id) == p.selected_entry)
        .cloned();
    if selected.is_none() {
        p.selected_entry = None;
    }

    if let Some(entry_arc) = selected {
        let entry = entry_arc.lock().unwrap();
        let viewer_id = egui::Id::unique("hist_viewer").with(entry.id);

        // Horizontal split with a draggable divider. Using a stored fraction
        // (instead of a resizable Panel) keeps the divider from creeping to
        // the left across frames.
        let total_w = ui.available_width();
        let handle_w = 6.0;
        let usable = (total_w - handle_w).max(1.0);
        let min_frac = (180.0 / usable).min(0.45);
        let frac = p.history_split.clamp(min_frac, 1.0 - min_frac);
        let left_w = usable * frac;
        let right_w = usable - left_w;
        let pane_h = ui.available_height().max(160.0);
        let mut new_split = p.history_split;
        let mut pane_action: Option<crate::ui::viewer::PaneAction> = None;

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;

            let left = ui.allocate_ui_with_layout(
                egui::vec2(left_w, pane_h),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.label(
                        RichText::new("Request")
                            .size(12.0)
                            .strong()
                            .color(theme::ACCENT),
                    );
                    ui.add_space(4.0);
                    let shown = p.viewer.req.show(ui, viewer_id.with("req"), &entry.req_raw);
                    pane_action = pane_action.or(p.viewer.req.action);
                    let _ = shown;
                },
            );
            left.response
                .container_context_menu(|ui| entry_menu(ui, &entry, actions, shared));

            let (rect, resp) =
                ui.allocate_exact_size(egui::vec2(handle_w, pane_h), egui::Sense::drag());
            let resp = resp.on_hover_cursor(egui::CursorIcon::ResizeHorizontal);
            let color = if resp.hovered() || resp.dragged() {
                theme::ACCENT
            } else {
                theme::STROKE
            };
            let x = rect.center().x;
            ui.painter().line_segment(
                [egui::pos2(x, rect.top()), egui::pos2(x, rect.bottom())],
                egui::Stroke::new(1.0, color),
            );
            if resp.dragged() {
                new_split = (frac + resp.drag_delta().x / usable).clamp(min_frac, 1.0 - min_frac);
            }

            let right = ui.allocate_ui_with_layout(
                egui::vec2(right_w, pane_h),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.label(
                        RichText::new("Response")
                            .size(12.0)
                            .strong()
                            .color(theme::ACCENT),
                    );
                    ui.add_space(4.0);
                    if let Some(resp) = entry.resp_raw.as_deref() {
                        p.viewer.resp.show(ui, viewer_id.with("resp"), resp);
                        pane_action = pane_action.or(p.viewer.resp.action);
                    } else {
                        ui.vertical_centered(|ui| {
                            ui.add_space(((ui.available_height() - 24.0) * 0.5).max(8.0));
                            ui.label(
                                RichText::new("No response captured")
                                    .size(12.5)
                                    .color(theme::MUTED),
                            );
                        });
                    }
                },
            );
            right
                .response
                .container_context_menu(|ui| entry_menu(ui, &entry, actions, shared));
        });
        p.history_split = new_split;
        // Viewer menu: send the pane's message to another tab.
        if let Some(pa) = pane_action {
            let e = entry_arc.lock().unwrap();
            let (scheme, authority, raw) = match pa {
                crate::ui::viewer::PaneAction::SendToRepeater
                | crate::ui::viewer::PaneAction::SendToIntruder => (
                    e.scheme,
                    http_msg::dest_authority(&e.destination),
                    e.req_raw.clone(),
                ),
                _ => {
                    // Decoder/Comparer act on whichever pane was used.
                    let raw = if p.viewer.resp.action.is_some() {
                        e.resp_raw.clone().unwrap_or_default()
                    } else {
                        e.req_raw.clone()
                    };
                    (e.scheme, http_msg::dest_authority(&e.destination), raw)
                }
            };
            actions.send_pane(pa, scheme, authority, raw);
        }
    } else {
        ui.vertical_centered(|ui| {
            ui.add_space(((ui.available_height() - 40.0) * 0.5).max(8.0));
            ui.label(
                RichText::new("Select an entry above to inspect it")
                    .size(12.5)
                    .color(theme::MUTED),
            );
        });
    }

    if let Some(id) = clicked {
        p.selected_entry = Some(id);
        p.viewer = ReqRespViewer::default();
    }
}

/// Sort the filtered history rows by a column index (Burp-style header sort).
fn sort_entries(entries: &mut [Arc<std::sync::Mutex<HistoryEntry>>], col: usize, asc: bool) {
    entries.sort_by(|a, b| {
        let a = a.lock().unwrap();
        let b = b.lock().unwrap();
        let ord = match col {
            0 => a.id.cmp(&b.id),
            1 => a.time.cmp(&b.time),
            2 => a.host.to_lowercase().cmp(&b.host.to_lowercase()),
            3 => a.method.cmp(&b.method),
            4 => a.path.to_lowercase().cmp(&b.path.to_lowercase()),
            5 => a.params.cmp(&b.params),
            6 => a.edited.cmp(&b.edited),
            7 => a.status.cmp(&b.status),
            8 => a.resp_len.cmp(&b.resp_len),
            9 => a.mime.cmp(&b.mime),
            10 => a.extension.cmp(&b.extension),
            11 => a.title.cmp(&b.title),
            12 => a.notes.to_lowercase().cmp(&b.notes.to_lowercase()),
            13 => a.tls.cmp(&b.tls),
            14 => a.server_ip.cmp(&b.server_ip),
            16 => a.process.cmp(&b.process),
            _ => a.cookies.cmp(&b.cookies),
        };
        if asc { ord } else { ord.reverse() }
    });
}

/// One flat entry inside an entry context menu.
fn menu_item(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.selectable_label(false, RichText::new(text).size(12.5))
}

/// Context-menu actions shared by history rows and the request/response panes.
fn entry_menu(
    ui: &mut egui::Ui,
    entry: &HistoryEntry,
    actions: &mut crate::ui::Actions,
    shared: &Arc<SharedState>,
) {
    ui.set_min_width(190.0);

    if menu_item(ui, "Send to Repeater").clicked() {
        actions.to_repeater = Some(crate::ui::TabPayload {
            scheme: entry.scheme,
            authority: http_msg::dest_authority(&entry.destination),
            raw: entry.req_raw.clone(),
        });
    }
    if menu_item(ui, "Send to Intruder").clicked() {
        actions.to_intruder = Some(crate::ui::TabPayload {
            scheme: entry.scheme,
            authority: http_msg::dest_authority(&entry.destination),
            raw: entry.req_raw.clone(),
        });
    }
    ui.separator();
    if menu_item(ui, "Copy request").clicked() {
        ui.ctx()
            .copy_text(String::from_utf8_lossy(&entry.req_raw).to_string());
        shared.set_status("Request copied to clipboard");
    }
    let has_response = entry.resp_raw.is_some();
    if ui
        .add_enabled_ui(has_response, |ui| menu_item(ui, "Copy response"))
        .inner
        .clicked()
    {
        ui.ctx().copy_text(
            String::from_utf8_lossy(entry.resp_raw.as_deref().unwrap_or(b"")).to_string(),
        );
        shared.set_status("Response copied to clipboard");
    }
    if menu_item(ui, "Copy URL").clicked() {
        ui.ctx().copy_text(entry.url());
        shared.set_status("URL copied to clipboard");
    }
    ui.separator();
    if menu_item(ui, "Save exchange...").clicked() {
        if let Some(path) = rfd::FileDialog::new()
            .set_file_name("finch-entry.txt")
            .save_file()
        {
            let mut blob = entry.req_raw.clone();
            blob.extend_from_slice(&[13, 10, 13, 10]);
            blob.extend_from_slice(b"=== RESPONSE ===");
            blob.extend_from_slice(&[13, 10, 13, 10]);
            blob.extend_from_slice(entry.resp_raw.as_deref().unwrap_or(b""));
            let _ = std::fs::write(path, blob);
            shared.set_status("Entry saved");
        }
    }
}

pub fn status_color(status: u16) -> Color32 {
    match status {
        200..=299 => theme::SUCCESS,
        300..=399 => theme::ACCENT,
        400..=499 => theme::WARNING,
        _ => theme::DANGER,
    }
}

pub fn format_bytes(len: usize) -> String {
    if len >= 1_048_576 {
        format!("{:.1} MB", len as f64 / 1_048_576.0)
    } else if len >= 1024 {
        format!("{:.1} KB", len as f64 / 1024.0)
    } else {
        format!("{len} B")
    }
}

// ---------------------------------------------------------------- Options

// ---------------------------------------------------------------- Tun tab

/// TUN sub-tab: adapter on/off plus a live process list (PID, name, action)
/// where each row can be toggled for hijacking through the proxy.
fn show_tun(ui: &mut egui::Ui, shared: &Arc<SharedState>, p: &mut ProxyUi) {
    let enabled = shared.tun_enabled.load(std::sync::atomic::Ordering::Relaxed);

    // ---- Control bar -------------------------------------------------
    ui.horizontal(|ui| {
        if theme::button(
            ui,
            true,
            if enabled { "Disable TUN" } else { "Enable TUN" },
            if enabled {
                ButtonKind::Danger
            } else {
                ButtonKind::Primary
            },
        )
        .clicked()
        {
            if enabled {
                crate::tun::stop(shared.clone());
                shared.set_status("TUN mode disabled");
            } else {
                match crate::tun::start(shared.clone()) {
                    Ok(()) => shared.set_status("TUN mode enabled"),
                    Err(e) => {
                        *shared.tun_status.lock().unwrap() = e.clone();
                        shared.set_status(format!("TUN failed: {e}"));
                    }
                }
            }
        }
        theme::status_dot(
            ui,
            if enabled {
                theme::SUCCESS
            } else {
                theme::MUTED
            },
        );
        let status = shared.tun_status.lock().unwrap().clone();
        ui.add(
            egui::Label::new(
                RichText::new(if status.is_empty() {
                    if enabled {
                        "starting...".to_string()
                    } else {
                        "off".to_string()
                    }
                } else {
                    status
                })
                .size(11.5)
                .monospace()
                .color(if enabled { theme::SUCCESS } else { theme::MUTED }),
            )
            .truncate(),
        );
    });
    ui.add_space(2.0);
    theme::hint(
        ui,
        "Routes IPv4 through a virtual adapter (FinchTun, 10.10.0.2). Flows of hijacked \
         processes are sent through Finch's proxy and appear in HTTP history with their \
         process name; everything else (incl. all UDP/DNS) is relayed directly. Requires \
         running Finch as administrator; wintun.dll is downloaded on first enable. IPv4 only — \
         IPv6 stays on the physical interface. Turn TUN off before closing Finch.",
    );
    ui.add_space(8.0);

    // ---- Hijack list summary ------------------------------------------
    ui.horizontal(|ui| {
        ui.label(RichText::new("Processes").size(12.0).strong());
        let filter_len = shared.settings.lock().unwrap().tun_process_filter.len();
        ui.label(
            RichText::new(if filter_len == 0 {
                "no process hijacked — traffic is only relayed".to_string()
            } else {
                format!("{filter_len} hijacked (by name)")
            })
            .size(11.5)
            .color(if filter_len > 0 {
                theme::ACCENT
            } else {
                theme::MUTED
            }),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if theme::button(ui, filter_len > 0, "Clear hijack list", ButtonKind::Secondary)
                .clicked()
            {
                shared.settings.lock().unwrap().tun_process_filter.clear();
                crate::proxy_ctrl::save_settings(&shared.settings.lock().unwrap().clone());
                shared.set_status("TUN hijack list cleared");
            }
            ui.add_space(8.0);
            ui.label(RichText::new("Filter").size(12.0).color(theme::MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut p.tun_list_filter)
                    .desired_width(180.0)
                    .hint_text("name contains..."),
            );
        });
    });
    ui.add_space(4.0);

    // ---- Process list --------------------------------------------------
    // Refresh the enumeration at most every 1.5 s while the tab is open.
    let stale = p
        .tun_rows_at
        .map(|t| t.elapsed() >= std::time::Duration::from_millis(1500))
        .unwrap_or(true);
    if stale {
        p.tun_rows = crate::tun::list_network_processes();
        p.tun_rows_at = Some(std::time::Instant::now());
    }
    let needle = p.tun_list_filter.to_lowercase();
    let shown: Vec<(u32, String)> = p
        .tun_rows
        .iter()
        .filter(|(_, name)| needle.is_empty() || name.to_lowercase().contains(&needle))
        .cloned()
        .collect();

    let table_h = ui.available_height().max(160.0);
    egui::Frame::new()
        .stroke(egui::Stroke::new(1.0, theme::STROKE))
        .corner_radius(4.0)
        .inner_margin(6.0)
        .show(ui, |ui| {
            ui.set_height(table_h.min(560.0));
            if shown.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    ui.label(
                        RichText::new(if p.tun_rows.is_empty() {
                            "No processes with network sockets found."
                        } else {
                            "No process matches the filter."
                        })
                        .size(12.0)
                        .color(theme::MUTED),
                    );
                });
                return;
            }
            let table = egui_extras::TableBuilder::new(ui)
                .id_salt("tun_process_table")
                .striped(true)
                .vscroll(true)
                .column(Column::initial(80.0).resizable(true)) // PID
                .column(Column::remainder().at_least(160.0).resizable(true)) // Name
                .column(Column::initial(120.0)); // Action
            table
                .header(20.0, |mut h| {
                    h.col(|ui| {
                        ui.label(RichText::new("PID").size(11.0).color(theme::MUTED));
                    });
                    h.col(|ui| {
                        ui.label(RichText::new("Process").size(11.0).color(theme::MUTED));
                    });
                    h.col(|ui| {
                        ui.label(
                            RichText::new("Action")
                                .size(11.0)
                                .color(theme::MUTED),
                        );
                    });
                })
                .body(|body| {
                    body.rows(20.0, shown.len(), |mut row| {
                        let (pid, name) = &shown[row.index()];
                        let filter = shared.settings.lock().unwrap().tun_process_filter.clone();
                        let hijacked = crate::tun::process_matches(&filter, name);

                        row.col(|ui| {
                            ui.label(
                                RichText::new(pid.to_string())
                                    .monospace()
                                    .size(11.5)
                                    .color(theme::MUTED),
                            );
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(name).size(12.0));
                        });
                        row.col(|ui| {
                            let label = if hijacked {
                                RichText::new("Stop hijack").size(11.5).color(theme::DANGER)
                            } else {
                                RichText::new("Hijack").size(11.5)
                            };
                            if ui
                                .add_enabled(true, egui::Button::new(label))
                                .clicked()
                            {
                                toggle_hijack(shared, name, hijacked);
                            }
                        });
                    });
                });
        });
}

/// Add/remove `name` in the persisted hijack filter. The engine reads the
/// list per flow, so changes apply immediately (also for future TUN runs —
/// the list survives restarts).
fn toggle_hijack(shared: &Arc<SharedState>, name: &str, currently_hijacked: bool) {
    let mut settings = shared.settings.lock().unwrap();
    if currently_hijacked {
        // Drop every fragment that matches this process name.
        let lower = name.to_lowercase();
        settings
            .tun_process_filter
            .retain(|f| !lower.contains(&f.trim().to_lowercase()));
    } else if !settings.tun_process_filter.iter().any(|f| {
        let f = f.trim().to_lowercase();
        !f.is_empty() && name.to_lowercase().contains(&f)
    }) {
        settings.tun_process_filter.push(name.to_string());
    }
    let n = settings.tun_process_filter.len();
    drop(settings);
    crate::proxy_ctrl::save_settings(&shared.settings.lock().unwrap().clone());
    shared.set_status(format!(
        "{} {} ({} hijacked)",
        if currently_hijacked {
            "Stopped hijacking"
        } else {
            "Hijacking"
        },
        name,
        n
    ));
}

fn show_options(ui: &mut egui::Ui, shared: &Arc<SharedState>, p: &mut ProxyUi) {
    ScrollArea::vertical().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.add_space(2.0);

        // --- Intercept -------------------------------------------------
        theme::card(ui, |ui| {
            theme::card_title(ui, "Intercept");
            ui.add_space(6.0);
            egui::Grid::new("intercept_opts")
                .num_columns(2)
                .spacing([16.0, 10.0])
                .show(ui, |ui| {
                    let mut on_req = shared
                        .intercept_req
                        .load(std::sync::atomic::Ordering::Relaxed);
                    ui.label(RichText::new("Client requests").color(theme::TEXT));
                    ui.horizontal(|ui| {
                        if theme::toggle(ui, &mut on_req) {
                            shared
                                .intercept_req
                                .store(on_req, std::sync::atomic::Ordering::Relaxed);
                        }
                        ui.label(
                            RichText::new(if on_req { "on" } else { "off" })
                                .size(11.5)
                                .color(if on_req { theme::SUCCESS } else { theme::MUTED }),
                        );
                    });
                    ui.end_row();

                    let mut on_resp = shared
                        .intercept_resp
                        .load(std::sync::atomic::Ordering::Relaxed);
                    ui.label(RichText::new("Server responses").color(theme::TEXT));
                    ui.horizontal(|ui| {
                        if theme::toggle(ui, &mut on_resp) {
                            shared
                                .intercept_resp
                                .store(on_resp, std::sync::atomic::Ordering::Relaxed);
                        }
                        ui.label(
                            RichText::new(if on_resp { "on" } else { "off" })
                                .size(11.5)
                                .color(if on_resp {
                                    theme::SUCCESS
                                } else {
                                    theme::MUTED
                                }),
                        );
                    });
                    ui.end_row();

                    if p.intercept_filter_edit.is_none() {
                        p.intercept_filter_edit = Some(shared.intercept_filter.lock().unwrap().clone());
                    }
                    ui.label(RichText::new("URL filter").color(theme::TEXT));
                    if let Some(edit) = p.intercept_filter_edit.as_mut() {
                        if ui
                            .add(
                                egui::TextEdit::singleline(edit)
                                    .desired_width(320.0)
                                    .hint_text("substring; empty = intercept everything"),
                            )
                            .lost_focus()
                        {
                            *shared.intercept_filter.lock().unwrap() = edit.clone();
                        }
                    }
                    ui.end_row();
                });
        });

        ui.add_space(8.0);

        // --- Connection ------------------------------------------------
        theme::card(ui, |ui| {
            theme::card_title(ui, "Connection");
            ui.add_space(6.0);
            egui::Grid::new("conn_opts")
                .num_columns(2)
                .spacing([16.0, 10.0])
                .show(ui, |ui| {
                    let listening = shared
                        .proxy_listening
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let port = shared.settings.lock().unwrap().listen_port;
                    ui.label(RichText::new("Listener").color(theme::TEXT));
                    ui.horizontal(|ui| {
                        theme::status_dot(
                            ui,
                            if listening {
                                theme::SUCCESS
                            } else {
                                theme::DANGER
                            },
                        );
                        ui.label(
                            RichText::new(format!("127.0.0.1:{port}"))
                                .monospace()
                                .size(12.0)
                                .color(theme::TEXT),
                        );
                        ui.label(
                            RichText::new(if listening { "running" } else { "stopped" })
                                .size(11.5)
                                .color(if listening {
                                    theme::SUCCESS
                                } else {
                                    theme::DANGER
                                }),
                        );
                    });
                    ui.end_row();

                    ui.label(RichText::new("Upstream proxy").color(theme::TEXT));
                    if p.upstream_edit.is_none() {
                        p.upstream_edit = Some(
                            shared
                                .settings
                                .lock()
                                .unwrap()
                                .upstream_proxy
                                .clone()
                                .unwrap_or_default(),
                        );
                    }
                    if let Some(edit) = p.upstream_edit.as_mut() {
                        ui.add(
                            egui::TextEdit::singleline(edit)
                                .desired_width(320.0)
                                .hint_text(
                                    "http://127.0.0.1:1080 or socks5h://user:pass@host:1080",
                                ),
                        );
                    }
                    ui.end_row();
                });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if theme::button(ui, true, "Apply & restart proxy", ButtonKind::Secondary).clicked()
                {
                    {
                        let mut s = shared.settings.lock().unwrap();
                        let up = p.upstream_edit.as_deref().unwrap_or("").trim().to_string();
                        s.upstream_proxy = if up.is_empty() { None } else { Some(up) };
                    }
                    crate::proxy_ctrl::save_settings(&shared.settings.lock().unwrap().clone());
                    crate::proxy_ctrl::restart_proxy(&crate::app::runtime(), shared.clone());
                }
            });
        });

        ui.add_space(8.0);

        // --- Host blacklist ---------------------------------------------
        theme::card(ui, |ui| {
            theme::card_title(ui, "Host blacklist");
            ui.add_space(6.0);
            theme::hint(
                ui,
                "One regular expression per line. Requests to matching hosts are refused with 403 (applies to CONNECT tunnels and plaintext requests).",
            );
            ui.add_space(6.0);
            if p.blacklist_edit.is_none() {
                p.blacklist_edit = Some(
                    shared
                        .settings
                        .lock()
                        .unwrap()
                        .host_blacklist
                        .join("
"),
                );
            }
            if let Some(edit) = p.blacklist_edit.as_mut() {
            ui.add(
                egui::TextEdit::multiline(edit)
                    .id_salt("host_blacklist_edit")
                    .desired_width(ui.available_width().min(560.0))
                    .desired_rows(4)
                    .font(egui::TextStyle::Monospace)
                    .hint_text(".*\\.evil\\.com\n(^|\\.)tracker\\..*"),
            );
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if theme::button(ui, true, "Apply blacklist & restart proxy", ButtonKind::Secondary)
                    .clicked()
                {
                    let patterns: Vec<String> = p
                        .blacklist_edit
                        .as_deref()
                        .unwrap_or("")
                        .lines()
                        .map(|l| l.trim().to_string())
                        .filter(|l| !l.is_empty())
                        .collect();
                    // Validate regexes before applying.
                    let invalid: Vec<&String> = patterns
                        .iter()
                        .filter(|pat| regex::Regex::new(pat).is_err())
                        .collect();
                    if !invalid.is_empty() {
                        shared.set_status(format!(
                            "Invalid regex ignored: {}",
                            invalid
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                    }
                    {
                        let mut s = shared.settings.lock().unwrap();
                        s.host_blacklist = patterns
                            .into_iter()
                            .filter(|pat| regex::Regex::new(pat).is_ok())
                            .collect();
                    }
                    crate::proxy_ctrl::save_settings(&shared.settings.lock().unwrap().clone());
                    crate::proxy_ctrl::restart_proxy(&crate::app::runtime(), shared.clone());
                }
                let count = shared.settings.lock().unwrap().host_blacklist.len();
                ui.label(
                    RichText::new(format!("{count} pattern(s) active"))
                        .size(11.5)
                        .color(theme::MUTED),
                );
            });
        });

        ui.add_space(8.0);

        // --- TLS -------------------------------------------------------
        theme::card(ui, |ui| {
            theme::card_title(ui, "TLS certificates");
            ui.add_space(6.0);
            let ca_dir = crate::proxy_ctrl::data_dir().join("ca");
            ui.label(
                RichText::new(format!("CA storage: {}", ca_dir.display()))
                    .size(11.5)
                    .color(theme::MUTED),
            );
            theme::hint(
                ui,
                "Install ca.pem into your OS/browser trust store to avoid TLS warnings.",
            );
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if theme::button(ui, true, "Export CA certificate...", ButtonKind::Secondary)
                    .clicked()
                {
                    if let Some(path) = rfd::FileDialog::new().set_file_name("ca.pem").save_file() {
                        let rt = crate::app::runtime();
                        if let Some(pem) = crate::proxy_ctrl::ca_pem(rt, shared) {
                            let _ = std::fs::write(path, pem);
                            shared.set_status("CA certificate exported");
                        }
                    }
                }
                if theme::button(ui, true, "Open browser via proxy", ButtonKind::Primary).clicked()
                {
                    let port = shared.settings.lock().unwrap().listen_port;
                    match crate::proxy_ctrl::open_browser_with_proxy(port) {
                        Ok(()) => shared.set_status("Browser launched with proxy"),
                        Err(e) => shared.set_status(e),
                    }
                }
            });
        });

        ui.add_space(8.0);

        // --- History ---------------------------------------------------
        theme::card(ui, |ui| {
            theme::card_title(ui, "History");
            ui.add_space(6.0);
            egui::Grid::new("hist_opts")
                .num_columns(2)
                .spacing([16.0, 10.0])
                .show(ui, |ui| {
                    let mut limit = shared.settings.lock().unwrap().history_limit;
                    ui.label(RichText::new("History limit (entries)").color(theme::TEXT));
                    if ui
                        .add(egui::DragValue::new(&mut limit).range(100..=200000))
                        .changed()
                    {
                        shared.settings.lock().unwrap().history_limit = limit;
                    }
                    ui.end_row();
                });
        });
        ui.add_space(8.0);
    });
}
