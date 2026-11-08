//! Repeater tab: multiple repeat sessions; each edits a request and resends
//! it through the hyper engine. Session responses are kept as a navigable
//! history (◀ back / ▶ forward) instead of a list strip.

use std::cell::Cell;
use std::sync::mpsc;

use egui::RichText;

use crate::engine::{self, SendResult};
use crate::state::{Scheme, SharedState};
use crate::ui::theme::{self, ButtonKind, EmptyState};
use crate::ui::viewer::MessageView;

/// One repeat session: target, editable request, navigable response history.
#[derive(Default)]
pub struct RepeatSession {
    pub https: bool,
    pub authority: String,
    /// Editable request viewer (Raw/Headers tabs, like the response side).
    pub req_view: MessageView,
    pub resp_view: MessageView,
    pub result: Option<SendResult>,
    pub result_raw: Vec<u8>,
    pub rx: Option<mpsc::Receiver<SendResult>>,
    pub sending: bool,
    /// Responses of this session, navigable with ◀ / ▶.
    pub history: Vec<SendResult>,
    /// Current position into `history`.
    pub history_pos: usize,
}

impl RepeatSession {
    pub fn navigate(&mut self, delta: isize) -> bool {
        let new_pos = self.history_pos as isize + delta;
        if new_pos < 0 || new_pos as usize >= self.history.len() {
            return false;
        }
        self.history_pos = new_pos as usize;
        self.result = Some(self.history[self.history_pos].clone());
        self.result_raw = self.history[self.history_pos].to_raw();
        self.resp_view = MessageView::new(false);
        true
    }
}

pub struct RepeaterUi {
    /// Open repeat sessions (one per tab).
    pub tabs: Vec<RepeatSession>,
    /// Index of the active session.
    pub active: usize,
    /// Width fraction of the request pane (draggable divider).
    pub split: f32,
}

impl Default for RepeaterUi {
    fn default() -> Self {
        Self {
            tabs: vec![RepeatSession::default()],
            active: 0,
            split: 0.5,
        }
    }
}

impl RepeaterUi {
    pub fn new_session(&mut self) {
        self.tabs.push(RepeatSession::default());
        self.active = self.tabs.len() - 1;
    }

    pub fn load(&mut self, payload: &crate::ui::TabPayload) {
        if self.tabs.is_empty() {
            self.new_session();
        }
        self.active = self.active.min(self.tabs.len() - 1);
        let tab = &mut self.tabs[self.active];
        tab.https = payload.scheme == Scheme::Https;
        tab.authority = payload.authority.clone();
        tab.req_view = MessageView::new(true);
        tab.req_view.edit = String::from_utf8_lossy(&payload.raw).to_string();
        tab.resp_view = MessageView::new(false);
        tab.result = None;
        tab.result_raw.clear();
        tab.history.clear();
        tab.history_pos = 0;
        // Drop any in-flight send channel: a late response from the previous
        // payload must not be recorded against the newly loaded request.
        tab.rx = None;
        tab.sending = false;
    }
}

fn send_session(tab: &mut RepeatSession) {
    if tab.sending || tab.authority.trim().is_empty() || tab.req_view.edit.trim().is_empty() {
        return;
    }
    let raw = tab.req_view.edit.clone().into_bytes();
    let authority = tab.authority.trim().to_string();
    let scheme = if tab.https { "https" } else { "http" }.to_string();
    let (tx, rx) = mpsc::channel();
    tab.rx = Some(rx);
    tab.sending = true;
    crate::app::runtime().spawn(async move {
        let res = engine::send_raw(
            &scheme,
            &authority,
            &raw,
            std::time::Duration::from_secs(30),
        )
        .await;
        let _ = tx.send(res);
    });
}

pub fn show(ui: &mut egui::Ui, shared: &std::sync::Arc<SharedState>, r: &mut RepeaterUi) {
    // Poll every session: responses may arrive while another tab is active.
    for tab in &mut r.tabs {
        if let Some(rx) = &tab.rx {
            loop {
                match rx.try_recv() {
                    Ok(res) => {
                        tab.sending = false;
                        // Browser-style history: a new response after
                        // navigating back truncates the "future" entries.
                        if tab.history_pos + 1 < tab.history.len() {
                            tab.history.truncate(tab.history_pos + 1);
                        }
                        tab.history.push(res.clone());
                        tab.history_pos = tab.history.len() - 1;
                        tab.result = Some(res.clone());
                        tab.result_raw = res.to_raw();
                        tab.resp_view = MessageView::new(false);
                        shared.wake();
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        tab.rx = None;
                        break;
                    }
                }
            }
        }
    }

    if r.tabs.is_empty() {
        r.new_session();
    }
    r.active = r.active.min(r.tabs.len() - 1);

    // ---- Session tabs: [Repeat 1 ×] [Repeat 2 ×] [+] ----
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        for i in 0..r.tabs.len() {
            let active = r.active == i;
            if ui
                .selectable_label(
                    active,
                    RichText::new(format!("Repeat {}", i + 1)).size(12.5),
                )
                .clicked()
            {
                r.active = i;
            }
            if r.tabs.len() > 1 {
                let _ = ui
                    .add(
                        egui::Button::new(RichText::new("×").size(11.0).color(theme::MUTED))
                            .small(),
                    )
                    .clicked()
                    .then(|| {
                        r.tabs.remove(i);
                        r.active = r.active.min(r.tabs.len().saturating_sub(1));
                    });
                ui.add_space(4.0);
            }
        }
        if ui
            .add(egui::Button::new(RichText::new("+").size(13.0)).small())
            .clicked()
        {
            r.new_session();
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                RichText::new(format!("{} session(s)", r.tabs.len()))
                    .size(11.5)
                    .color(theme::MUTED),
            );
        });
    });
    ui.add_space(4.0);

    // ---- Toolbar for the active session ----
    let tab = &mut r.tabs[r.active];
    let can_send =
        !tab.authority.trim().is_empty() && !tab.sending && !tab.req_view.edit.trim().is_empty();
    let can_back = tab.history_pos > 0;
    let can_fwd = tab.history_pos + 1 < tab.history.len();
    let pos_label = format!(
        "{}/{}",
        if tab.history.is_empty() {
            0
        } else {
            tab.history_pos + 1
        },
        tab.history.len()
    );
    let mut nav: isize = 0;
    let send_clicked = Cell::new(false);

    ui.horizontal(|ui| {
        ui.label(RichText::new("Target").size(12.0).color(theme::MUTED));
        theme::segmented(ui, &mut tab.https, &[(false, "http"), (true, "https")]);
        ui.add(
            egui::TextEdit::singleline(&mut tab.authority)
                .id_salt(("repeat_authority", r.active))
                .desired_width(240.0)
                .hint_text("host:port"),
        );
        ui.add_space(4.0);
        if theme::button(ui, can_send, "Send", ButtonKind::Primary).clicked() {
            send_session(tab);
        }
        if tab.sending {
            ui.spinner();
            ui.label(RichText::new("sending...").size(11.5).color(theme::MUTED));
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if let Some(res) = &tab.result {
                if let Some(st) = res.status {
                    ui.label(
                        RichText::new(format!("{} {}", st, res.reason))
                            .color(crate::ui::proxy::status_color(st))
                            .strong(),
                    );
                } else if let Some(e) = &res.error {
                    ui.label(RichText::new(format!("Error: {e}")).color(theme::DANGER));
                }
                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!("{} ms · {}", res.duration_ms, res.body.len()))
                        .size(11.5)
                        .color(theme::MUTED),
                );
                ui.add_space(8.0);
            }
            // History navigation: ◀ back / ▶ forward.
            if theme::button(ui, can_fwd, "▶", ButtonKind::Secondary).clicked() {
                nav = 1;
            }
            ui.label(RichText::new(pos_label).size(11.5).color(theme::MUTED));
            if theme::button(ui, can_back, "◀", ButtonKind::Secondary).clicked() {
                nav = -1;
            }
        });
    });
    ui.add_space(8.0);

    if nav != 0 {
        tab.navigate(nav);
    }
    if send_clicked.get() {
        send_session(tab);
    }

    let pane_h = ui.available_height().max(160.0);

    // Symmetric request/response panes with a draggable, drift-free divider.
    let RepeatSession {
        req_view,
        resp_view,
        result_raw,
        sending,
        authority,
        ..
    } = tab;
    let req_nonempty = !req_view.edit.trim().is_empty();
    // Snapshot of the current request bytes: the editable Raw tab edits
    // `req_view.edit` directly, while the Headers tab reads from these bytes.
    let req_bytes = req_view.edit.clone().into_bytes();

    theme::h_split_panes(
        ui,
        &mut r.split,
        pane_h,
        |ui| {
            ui.label(
                RichText::new("Request")
                    .size(12.0)
                    .strong()
                    .color(theme::ACCENT),
            );
            ui.add_space(4.0);
            // MessageView draws its own card which fills the remaining height.
            req_view.show(ui, egui::Id::unique("repeater_req"), &req_bytes);
        },
        |ui| {
            ui.label(
                RichText::new("Response")
                    .size(12.0)
                    .strong()
                    .color(theme::ACCENT),
            );
            ui.add_space(4.0);
            ui.scope(|ui| {
                ui.set_height((pane_h - 24.0).max(80.0));
                if *sending {
                    ui.vertical_centered(|ui| {
                        ui.add_space(((ui.available_height() - 60.0) * 0.5).max(8.0));
                        ui.spinner();
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new("Waiting for response...")
                                .size(12.5)
                                .color(theme::MUTED),
                        );
                    });
                } else if result_raw.is_empty() {
                    let clicked = theme::empty_state(
                        ui,
                        &EmptyState::new(
                            "No response yet",
                            "Edit the request on the left, then send it to the target.",
                        )
                        .with_cta("Send", req_nonempty && !authority.trim().is_empty()),
                    );
                    if clicked {
                        send_clicked.set(true);
                    }
                } else {
                    resp_view.show(ui, egui::Id::unique("repeater_resp"), result_raw);
                }
            });
        },
    );
}
