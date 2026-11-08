//! Finch application shell: top tab bar (Burp-like), status bar, global
//! runtime accessor.

use std::sync::{Arc, OnceLock};

use egui::RichText;

use crate::state::SharedState;
use crate::ui::{
    Actions, ai::AiUi, comparer::ComparerUi, decoder::DecoderUi, intruder::IntruderUi, mcp::McpUi,
    notes::NotesUi, proxy::ProxyUi, repeater::RepeaterUi, settings::SettingsUi, target::TargetUi,
    theme,
};

/// Global tokio runtime (set in main before the app starts).
static RUNTIME: OnceLock<Arc<tokio::runtime::Runtime>> = OnceLock::new();

pub fn runtime() -> &'static Arc<tokio::runtime::Runtime> {
    RUNTIME.get().expect("runtime not initialized")
}

pub fn init_runtime(rt: Arc<tokio::runtime::Runtime>) {
    let _ = RUNTIME.set(rt);
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TopTab {
    Proxy,
    Target,
    Repeater,
    Intruder,
    Decoder,
    Comparer,
    Notes,
    AI,
    Settings,
}

pub struct FinchApp {
    pub shared: Arc<SharedState>,
    pub tab: TopTab,
    pub proxy: ProxyUi,
    pub target: TargetUi,
    pub repeater: RepeaterUi,
    pub intruder: IntruderUi,
    pub decoder: DecoderUi,
    pub comparer: ComparerUi,
    pub notes: NotesUi,
    pub ai: AiUi,
    pub mcp: McpUi,
    pub settings: SettingsUi,
}

impl FinchApp {
    pub fn new(shared: Arc<SharedState>) -> Self {
        Self {
            shared,
            tab: TopTab::Proxy,
            proxy: ProxyUi::default(),
            target: TargetUi::default(),
            repeater: RepeaterUi::default(),
            intruder: IntruderUi::default(),
            decoder: DecoderUi::load(),
            comparer: ComparerUi::new(),
            notes: NotesUi::default(),
            ai: AiUi::default(),
            mcp: McpUi::default(),
            settings: SettingsUi::default(),
        }
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("finch_topbar").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("{} Finch", theme::LOGO))
                        .strong()
                        .size(16.0)
                        .color(theme::ACCENT),
                );
                ui.add_space(10.0);
                theme::underline_tabs(
                    ui,
                    &mut self.tab,
                    &[
                        (TopTab::Proxy, "Proxy"),
                        (TopTab::Target, "Target"),
                        (TopTab::Repeater, "Repeater"),
                        (TopTab::Intruder, "Intruder"),
                        (TopTab::Decoder, "Decoder"),
                        (TopTab::Comparer, "Comparer"),
                        (TopTab::Notes, "Notes"),
                        (TopTab::AI, "AI"),
                        (TopTab::Settings, "Settings"),
                    ],
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let pending = self.shared.pending.lock().unwrap().len();
                    if pending > 0 {
                        ui.label(
                            RichText::new(format!("⚠ {pending} intercepted"))
                                .size(12.0)
                                .color(theme::WARNING),
                        );
                    }
                });
            });
            ui.add_space(4.0);
        });
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("finch_statusbar")
            .show_separator_line(false)
            .show(ui, |ui| {
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    let listening = self
                        .shared
                        .proxy_listening
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let status = self.shared.status.lock().unwrap().clone();
                    theme::status_dot(
                        ui,
                        if listening {
                            theme::SUCCESS
                        } else {
                            theme::DANGER
                        },
                    );
                    ui.label(RichText::new(status).size(11.5).color(if listening {
                        theme::TEXT
                    } else {
                        theme::DANGER
                    }));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let hist = self.shared.history.lock().unwrap().len();
                        ui.label(
                            RichText::new(format!("history: {hist}"))
                                .size(11.5)
                                .color(theme::MUTED),
                        );
                        ui.add_space(12.0);
                        let port = self.shared.settings.lock().unwrap().listen_port;
                        ui.label(
                            RichText::new(format!("127.0.0.1:{port}"))
                                .size(11.5)
                                .color(theme::MUTED),
                        );
                    });
                });
                ui.add_space(2.0);
            });
    }
}

impl eframe::App for FinchApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Keep polling ~10fps even without input (proxy pushes state from
        // other threads and calls request_repaint, this is just a fallback).
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(100));

        self.top_bar(ui);
        self.status_bar(ui);

        let mut actions = Actions::default();

        egui::CentralPanel::default().show(ui, |ui| {
            match self.tab {
                TopTab::Proxy => {
                    // Segmented sub-navigation (Intercept / HTTP history / Options).
                    ui.add_space(2.0);
                    theme::segmented(
                        ui,
                        &mut self.proxy.sub_tab,
                        &[
                            (crate::ui::proxy::SubTab::Intercept, "Intercept"),
                            (crate::ui::proxy::SubTab::History, "HTTP history"),
                            (crate::ui::proxy::SubTab::WebSockets, "WebSockets"),
                            (crate::ui::proxy::SubTab::Tun, "TUN"),
                            (crate::ui::proxy::SubTab::Options, "Options"),
                        ],
                    );
                    ui.add_space(8.0);
                    crate::ui::proxy::show(ui, &self.shared, &mut self.proxy, &mut actions);
                }
                TopTab::Target => crate::ui::target::show(ui, &self.shared, &mut self.target),
                TopTab::Repeater => crate::ui::repeater::show(ui, &self.shared, &mut self.repeater),
                TopTab::Intruder => crate::ui::intruder::show(ui, &self.shared, &mut self.intruder),
                TopTab::Decoder => crate::ui::decoder::show(ui, &mut self.decoder),
                TopTab::Comparer => crate::ui::comparer::show(ui, &mut self.comparer),
                TopTab::Notes => crate::ui::notes::show(ui, &mut self.notes),
                TopTab::AI => crate::ui::ai::show(ui, &self.shared, &mut self.ai, &mut self.mcp),
                TopTab::Settings => crate::ui::settings::show(ui, &self.shared, &mut self.settings),
            }
        });

        // Consume cross-tab actions.
        if let Some(p) = actions.to_repeater.take() {
            self.repeater.load(&p);
            self.tab = TopTab::Repeater;
        }
        if let Some(p) = actions.to_intruder.take() {
            self.intruder.load(&p);
            self.tab = TopTab::Intruder;
        }
        if let Some(p) = actions.to_decoder.take() {
            self.decoder.input = String::from_utf8_lossy(&p.raw).to_string();
            self.tab = TopTab::Decoder;
        }
        if let Some(p) = actions.to_comparer.take() {
            let text = String::from_utf8_lossy(&p.raw).to_string();
            if self.comparer.left.trim().is_empty() {
                self.comparer.left = text;
            } else {
                self.comparer.right = text;
            }
            self.tab = TopTab::Comparer;
        }
    }

    fn save(&mut self, _storage: &mut dyn eframe::Storage) {
        crate::proxy_ctrl::save_settings(&self.shared.settings.lock().unwrap().clone());
        self.decoder.save();
    }
}
