//! Request/response message viewer with Raw / Headers / Hex / JSON tabs,
//! shared by Proxy history, Intercept, Target, Repeater and Intruder.

use egui::{RichText, ScrollArea, TextStyle};

use crate::http_msg;
use crate::ui::theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgTab {
    Raw,
    Headers,
    Hex,
    Json,
}

/// Payload semantics of a pane: drives which menu entries make sense.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PaneKind {
    /// A full HTTP message (request/response): can be sent to Repeater /
    /// Intruder.
    #[default]
    Http,
    /// A raw payload (e.g. WebSocket frame body): Decoder/Comparer only.
    Raw,
}

/// Cross-tab actions triggered from a pane's menu (consumed by the caller).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneAction {
    SendToRepeater,
    SendToIntruder,
    SendToDecoder,
    SendToComparer,
}

impl MsgTab {
    fn label(self) -> &'static str {
        match self {
            MsgTab::Raw => "Raw",
            MsgTab::Headers => "Headers",
            MsgTab::Hex => "Hex",
            MsgTab::Json => "JSON",
        }
    }
    pub const REQ_TABS: [MsgTab; 2] = [MsgTab::Raw, MsgTab::Headers];
    pub const RESP_TABS: [MsgTab; 4] = [MsgTab::Raw, MsgTab::Headers, MsgTab::Hex, MsgTab::Json];
}

/// Stateful viewer for one message (request or response).
pub struct MessageView {
    pub tab: MsgTab,
    /// Editable text cache (kept in sync with raw when not dirty).
    pub edit: String,
    pub dirty: bool,
    pub editable: bool,
    pub kind: PaneKind,
    /// Menu action triggered this frame (clear after reading).
    pub action: Option<PaneAction>,
}

impl Default for MessageView {
    fn default() -> Self {
        Self {
            tab: MsgTab::Raw,
            edit: String::new(),
            dirty: false,
            editable: false,
            kind: PaneKind::Http,
            action: None,
        }
    }
}

impl MessageView {
    pub fn new(editable: bool) -> Self {
        Self {
            editable,
            ..Default::default()
        }
    }

    /// Raw payload pane (WebSocket bodies and friends): Hex always available,
    /// no Send to Repeater/Intruder.
    pub fn new_raw(editable: bool) -> Self {
        Self {
            editable,
            kind: PaneKind::Raw,
            ..Default::default()
        }
    }

    /// Sync cached text with new raw bytes unless the user has local edits.
    pub fn sync(&mut self, raw: &[u8]) {
        if !self.dirty {
            self.edit = String::from_utf8_lossy(raw).to_string();
        }
    }

    /// Draw the message. Returns `Some(edited_bytes)` when the editable text
    /// differs from the given raw bytes.
    pub fn show(&mut self, ui: &mut egui::Ui, id: egui::Id, raw: &[u8]) -> Option<Vec<u8>> {
        let mut edited = None;
        self.action = None;
        ui.vertical(|ui| {
            // Tabs: flat text with an accent underline on the active one.
            let tabs: &[MsgTab] = if self.editable {
                &MsgTab::REQ_TABS
            } else {
                &MsgTab::RESP_TABS
            };
            let items: Vec<(MsgTab, &str)> = tabs.iter().map(|t| (*t, t.label())).collect();
            ui.horizontal(|ui| {
                theme::underline_tabs(ui, &mut self.tab, &items);
                if self.dirty {
                    ui.label(RichText::new("(edited)").size(11.5).color(theme::WARNING));
                }
            });
            ui.add_space(4.0);

            // Right-click anywhere on the pane opens the function menu.
            let pane = ui.scope(|ui| {
                theme::card_with_margin(ui, 6.0, |ui| {
                    ui.set_min_height(ui.available_height());
                    match self.tab {
                        MsgTab::Raw => {
                            if self.editable {
                                let before = self.edit.clone();
                                // Fill the card: size the editor from the card's
                                // height so no blank space is left inside it.
                                let fill = theme::fill_rows(ui, ui.available_height());
                                ScrollArea::vertical()
                                    .auto_shrink([false, false])
                                    .id_salt(id)
                                    .show(ui, |ui| {
                                        let text_edit = egui::TextEdit::multiline(&mut self.edit)
                                            .id_salt(id.with("edit"))
                                            .font(TextStyle::Monospace)
                                            .desired_width(ui.available_width())
                                            .desired_rows(fill);
                                        ui.add(text_edit);
                                    });
                                if self.edit != before {
                                    self.dirty = true;
                                }
                                // Report edits immediately (Burp edits in place).
                                if self.dirty {
                                    edited = Some(self.edit.clone().into_bytes());
                                }
                            } else {
                                self.show_readonly(ui, id, raw, false);
                            }
                        }
                        MsgTab::Headers => {
                            ScrollArea::vertical()
                                .auto_shrink([false, false])
                                .id_salt(id)
                                .show(ui, |ui| {
                                    let text = head_section(raw);
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(text).monospace().size(12.5),
                                        )
                                        .wrap()
                                        .selectable(true),
                                    );
                                });
                        }
                        MsgTab::Hex => {
                            ScrollArea::vertical()
                                .auto_shrink([false, false])
                                .id_salt(id)
                                .show(ui, |ui| {
                                    let body = http_msg::body_display(
                                        &raw[body_offset(raw).min(raw.len())..],
                                    );
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(hex_of(raw)).monospace().size(11.5),
                                        )
                                        .wrap()
                                        .selectable(true),
                                    );
                                    let _ = body;
                                });
                        }
                        MsgTab::Json => {
                            ScrollArea::vertical()
                                .auto_shrink([false, false])
                                .id_salt(id)
                                .show(ui, |ui| {
                                    let text = pretty_body(raw);
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(text).monospace().size(12.5),
                                        )
                                        .wrap()
                                        .selectable(true),
                                    );
                                });
                        }
                    }
                });
            });
            pane.response.context_menu(|ui| self.menu_items(ui, raw));
        });
        edited
    }

    /// Right-click menu items: Copy / Save / Send to ....
    /// Sets `self.action` for the cross-tab entries.
    fn menu_items(&mut self, ui: &mut egui::Ui, raw: &[u8]) {
        if ui.button("Copy").clicked() {
            ui.close();
            ui.ctx().copy_text(String::from_utf8_lossy(raw).to_string());
        }
        if ui.button("Save to file...").clicked() {
            ui.close();
            save_to_file(raw);
        }
        ui.separator();
        if self.kind == PaneKind::Http {
            if ui.button("Send to Repeater").clicked() {
                ui.close();
                self.action = Some(PaneAction::SendToRepeater);
            }
            if ui.button("Send to Intruder").clicked() {
                ui.close();
                self.action = Some(PaneAction::SendToIntruder);
            }
        }
        if ui.button("Send to Decoder").clicked() {
            ui.close();
            self.action = Some(PaneAction::SendToDecoder);
        }
        if ui.button("Send to Comparer").clicked() {
            ui.close();
            self.action = Some(PaneAction::SendToComparer);
        }
    }

    fn show_readonly(&mut self, ui: &mut egui::Ui, id: egui::Id, raw: &[u8], pretty: bool) {
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .id_salt(id)
            .show(ui, |ui| {
                let text = if pretty {
                    pretty_body(raw)
                } else {
                    String::from_utf8_lossy(raw).to_string()
                };
                // Cap huge text for responsiveness.
                let text = http_msg::body_display(text.as_bytes());
                ui.add(
                    egui::Label::new(RichText::new(text).monospace().size(12.5))
                        .wrap()
                        .selectable(true),
                );
            });
    }
}

/// Ask the user for a destination and write the raw bytes to disk.
fn save_to_file(raw: &[u8]) {
    if let Some(path) = rfd::FileDialog::new()
        .set_file_name("message.bin")
        .save_file()
    {
        let _ = std::fs::write(path, raw);
    }
}

fn body_offset(raw: &[u8]) -> usize {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(0)
}

fn hex_of(raw: &[u8]) -> String {
    let body = &raw[body_offset(raw).min(raw.len())..];
    http_msg::hex_dump(body, 512 * 1024)
}

fn head_section(raw: &[u8]) -> String {
    let off = body_offset(raw);
    String::from_utf8_lossy(&raw[..off.min(raw.len())]).to_string()
}

fn pretty_body(raw: &[u8]) -> String {
    let off = body_offset(raw);
    let head = String::from_utf8_lossy(&raw[..off.min(raw.len())]).to_string();
    let body = &raw[off.min(raw.len())..];

    // Decompress when needed for display only.
    let content_encoding = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-encoding:"))
        .and_then(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()));
    let decompressed = http_msg::decompress_for_display(content_encoding.as_deref(), body);
    let body: &[u8] = decompressed.as_deref().unwrap_or(body);

    let text = if let Some(json) = http_msg::json_pretty(body) {
        json
    } else {
        http_msg::body_display(body)
    };
    format!("{head}\n{text}")
}

/// Combined request+response viewer (side by side with a draggable splitter),
/// like Burp's history bottom panel.
pub struct ReqRespViewer {
    pub req: MessageView,
    pub resp: MessageView,
    /// Height fraction for the request pane (top).
    pub split: f32,
}

impl Default for ReqRespViewer {
    fn default() -> Self {
        Self {
            req: MessageView::new(false),
            resp: MessageView::new(false),
            split: 0.5,
        }
    }
}

impl ReqRespViewer {
    /// Draw request + response panes. Returns the pane menu action triggered
    /// this frame, if any.
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        id: egui::Id,
        req_raw: &[u8],
        resp_raw: Option<&[u8]>,
    ) -> Option<PaneAction> {
        let available = ui.available_height();
        let top_h = (available * self.split).max(120.0);
        let mut action = None;

        ui.label(
            RichText::new("Request")
                .size(12.0)
                .strong()
                .color(theme::ACCENT),
        );
        ui.add_space(4.0);
        ui.scope(|ui| {
            ui.set_height((top_h - 40.0).max(60.0));
            self.req.show(ui, id.with("req"), req_raw);
        });
        if self.req.action.is_some() {
            action = self.req.action;
        }

        ui.add_space(8.0);

        ui.label(
            RichText::new("Response")
                .size(12.0)
                .strong()
                .color(theme::ACCENT),
        );
        ui.add_space(4.0);
        ui.scope(|ui| {
            ui.set_height((available * (1.0 - self.split) - 56.0).max(60.0));
            if let Some(resp) = resp_raw {
                self.resp.show(ui, id.with("resp"), resp);
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        RichText::new("No response yet")
                            .size(12.5)
                            .color(theme::MUTED),
                    );
                });
            }
        });
        if action.is_none() {
            action = self.resp.action;
        }
        action
    }
}
