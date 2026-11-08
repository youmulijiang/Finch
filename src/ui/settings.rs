//! Settings tab: listener, TLS CA, upstream proxy, data locations.

use std::sync::Arc;

use egui::{RichText, ScrollArea};

use crate::state::SharedState;
use crate::ui::theme::{self, ButtonKind};

#[derive(Default)]
pub struct SettingsUi {
    pub port_edit: u16,
    pub upstream_edit: String,
    pub loaded: bool,
    // --- AI ---
    pub ai_base_url: String,
    pub ai_api_key: String,
    pub ai_model: String,
    pub ai_system_prompt: String,
    pub ai_test_status: Arc<std::sync::Mutex<Option<(bool, String)>>>,
    pub ai_loaded: bool,
}

impl SettingsUi {
    fn loaded_ai(&self) -> bool {
        self.ai_loaded
    }
}

pub fn show(ui: &mut egui::Ui, shared: &Arc<SharedState>, s: &mut SettingsUi) {
    if !s.loaded {
        let st = shared.settings.lock().unwrap();
        s.port_edit = st.listen_port;
        s.upstream_edit = st.upstream_proxy.clone().unwrap_or_default();
        s.loaded = true;
    }

    ScrollArea::vertical().show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.add_space(2.0);

        // --- Proxy listener -------------------------------------------
        theme::card(ui, |ui| {
            theme::card_title(ui, "Proxy listener");
            ui.add_space(6.0);
            egui::Grid::new("settings_listener")
                .num_columns(2)
                .spacing([16.0, 10.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("Listen port").color(theme::TEXT));
                    ui.add(egui::DragValue::new(&mut s.port_edit).range(1..=65535));
                    ui.end_row();

                    let running = shared
                        .proxy_listening
                        .load(std::sync::atomic::Ordering::Relaxed);
                    ui.label(RichText::new("Status").color(theme::TEXT));
                    ui.horizontal(|ui| {
                        theme::status_dot(
                            ui,
                            if running {
                                theme::SUCCESS
                            } else {
                                theme::DANGER
                            },
                        );
                        ui.label(
                            RichText::new(if running { "running" } else { "stopped" })
                                .size(11.5)
                                .color(if running {
                                    theme::SUCCESS
                                } else {
                                    theme::DANGER
                                }),
                        );
                    });
                    ui.end_row();
                });
            ui.add_space(8.0);
            if theme::button(ui, true, "Restart proxy", ButtonKind::Secondary).clicked() {
                shared.settings.lock().unwrap().listen_port = s.port_edit;
                crate::proxy_ctrl::save_settings(&shared.settings.lock().unwrap().clone());
                crate::proxy_ctrl::restart_proxy(&crate::app::runtime(), shared.clone());
            }
        });

        ui.add_space(8.0);

        // --- Upstream proxy -------------------------------------------
        theme::card(ui, |ui| {
            theme::card_title(ui, "Upstream proxy");
            theme::hint(
                ui,
                "Chain all outgoing proxy traffic through an upstream HTTP/SOCKS5 proxy.",
            );
            ui.add_space(6.0);
            ui.add(
                egui::TextEdit::singleline(&mut s.upstream_edit)
                    .desired_width(420.0)
                    .hint_text("http://127.0.0.1:1080 or socks5h://user:pass@host:1080"),
            );
            ui.add_space(8.0);
            if theme::button(ui, true, "Apply", ButtonKind::Secondary).clicked() {
                let up = s.upstream_edit.trim().to_string();
                shared.settings.lock().unwrap().upstream_proxy = if up.is_empty() {
                    None
                } else {
                    Some(up)
                };
                crate::proxy_ctrl::save_settings(&shared.settings.lock().unwrap().clone());
                crate::proxy_ctrl::restart_proxy(&crate::app::runtime(), shared.clone());
            }
        });

        ui.add_space(8.0);

        // --- TLS / CA --------------------------------------------------
        theme::card(ui, |ui| {
            theme::card_title(ui, "TLS / CA certificate");
            ui.add_space(6.0);
            let ca_dir = crate::proxy_ctrl::data_dir().join("ca");
            ui.label(
                RichText::new(format!("CA directory: {}", ca_dir.display()))
                    .size(11.5)
                    .color(theme::MUTED),
            );
            theme::hint(
                ui,
                "The proxy generates a root CA on first start. Export ca.pem and trust it to intercept HTTPS.",
            );
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if theme::button(ui, true, "Export CA...", ButtonKind::Secondary).clicked() {
                    if let Some(path) = rfd::FileDialog::new().set_file_name("ca.pem").save_file() {
                        let rt = crate::app::runtime();
                        if let Some(pem) = crate::proxy_ctrl::ca_pem(rt, shared) {
                            let _ = std::fs::write(path, pem);
                            shared.set_status("CA exported");
                        } else {
                            shared.set_status("CA not ready yet");
                        }
                    }
                }
                if theme::button(ui, true, "Copy CA PEM", ButtonKind::Secondary).clicked() {
                    let rt = crate::app::runtime();
                    if let Some(pem) = crate::proxy_ctrl::ca_pem(rt, shared) {
                        ui.ctx().copy_text(pem);
                        shared.set_status("CA PEM copied");
                    }
                }
            });
            ui.add_space(4.0);
            theme::hint(ui, "Windows install hint: certutil -addstore -user Root ca.pem");
        });

        ui.add_space(8.0);

        // --- Intruder --------------------------------------------------
        theme::card(ui, |ui| {
            theme::card_title(ui, "Intruder");
            ui.add_space(6.0);
            egui::Grid::new("settings_intruder")
                .num_columns(2)
                .spacing([16.0, 10.0])
                .show(ui, |ui| {
                    let mut conc = shared.settings.lock().unwrap().attack_concurrency;
                    ui.label(RichText::new("Attack concurrency").color(theme::TEXT));
                    if ui.add(egui::DragValue::new(&mut conc).range(1..=64)).changed() {
                        shared.settings.lock().unwrap().attack_concurrency = conc;
                        crate::proxy_ctrl::save_settings(
                            &shared.settings.lock().unwrap().clone(),
                        );
                    }
                    ui.end_row();
                });
        });

        ui.add_space(8.0);

        // --- AI --------------------------------------------------------
        theme::card(ui, |ui| {
            theme::card_title(ui, "AI assistant (OpenAI-compatible)");
            ui.add_space(6.0);
            if !s.loaded_ai() {
                let st = shared.settings.lock().unwrap();
                s.ai_base_url = st.ai.base_url.clone();
                s.ai_api_key = st.ai.api_key.clone();
                s.ai_model = st.ai.model.clone();
                s.ai_system_prompt = st.ai.system_prompt.clone();
                s.loaded = s.loaded || true;
                s.ai_loaded = true;
            }
            egui::Grid::new("settings_ai")
                .num_columns(2)
                .spacing([16.0, 10.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("Base URL").color(theme::TEXT));
                    ui.add(
                        egui::TextEdit::singleline(&mut s.ai_base_url)
                            .desired_width(360.0)
                            .hint_text("https://api.openai.com"),
                    );
                    ui.end_row();

                    ui.label(RichText::new("API key").color(theme::TEXT));
                    ui.add(
                        egui::TextEdit::singleline(&mut s.ai_api_key)
                            .password(true)
                            .desired_width(360.0),
                    );
                    ui.end_row();

                    ui.label(RichText::new("Model").color(theme::TEXT));
                    ui.add(
                        egui::TextEdit::singleline(&mut s.ai_model)
                            .desired_width(360.0)
                            .hint_text("gpt-4o-mini / deepseek-chat / llama3 ..."),
                    );
                    ui.end_row();

                    ui.label(RichText::new("System prompt").color(theme::TEXT));
                    ui.add(
                        egui::TextEdit::multiline(&mut s.ai_system_prompt)
                            .desired_width(360.0)
                            .desired_rows(3),
                    );
                    ui.end_row();
                });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if theme::button(ui, true, "Save AI settings", ButtonKind::Secondary).clicked() {
                    let mut st = shared.settings.lock().unwrap();
                    st.ai.base_url = s.ai_base_url.trim().to_string();
                    st.ai.api_key = s.ai_api_key.trim().to_string();
                    st.ai.model = s.ai_model.trim().to_string();
                    st.ai.system_prompt = s.ai_system_prompt.clone();
                    drop(st);
                    crate::proxy_ctrl::save_settings(&shared.settings.lock().unwrap().clone());
                    shared.set_status("AI settings saved");
                }
                if theme::button(ui, true, "Test connection", ButtonKind::Secondary).clicked() {
                    // Persist first so the test uses the shown values (same
                    // fields as "Save AI settings", incl. system prompt).
                    {
                        let mut st = shared.settings.lock().unwrap();
                        st.ai.base_url = s.ai_base_url.trim().to_string();
                        st.ai.api_key = s.ai_api_key.trim().to_string();
                        st.ai.model = s.ai_model.trim().to_string();
                        st.ai.system_prompt = s.ai_system_prompt.clone();
                    }
                    crate::proxy_ctrl::save_settings(&shared.settings.lock().unwrap().clone());
                    let shared = shared.clone();
                    let status_slot = s.ai_test_status.clone();
                    crate::app::runtime().spawn(async move {
                        let (base, key, model) = {
                            let st = shared.settings.lock().unwrap();
                            (
                                st.ai.base_url.clone(),
                                st.ai.api_key.clone(),
                                st.ai.model.clone(),
                            )
                        };
                        let msgs = vec![serde_json::json!({"role": "user", "content": "ping"})];
                        let res = crate::ai::chat_completion(&base, &key, &model, 0.0, &msgs, None).await;
                        let ok = res.is_ok();
                        *status_slot.lock().unwrap() = Some((
                            ok,
                            match res {
                                Ok(t) => format!("OK: {}", t.content),
                                Err(e) => e,
                            },
                        ));
                    });
                }
                if let Some((ok, text)) = s.ai_test_status.lock().unwrap().as_ref() {
                    ui.label(
                        RichText::new(text)
                            .size(11.5)
                            .color(if *ok { theme::SUCCESS } else { theme::DANGER }),
                    );
                }
            });
        });

        ui.add_space(8.0);

        // --- Data ------------------------------------------------------
        theme::card(ui, |ui| {
            theme::card_title(ui, "Data");
            ui.add_space(6.0);
            ui.label(
                RichText::new(format!(
                    "Config: {}",
                    crate::proxy_ctrl::settings_path().display()
                ))
                .size(11.5)
                .color(theme::MUTED),
            );
            ui.label(
                RichText::new(
                    "Engine: hyper (HTTP client) + slinger-mitm (MITM proxy) + egui (UI)",
                )
                .size(11.5)
                .color(theme::MUTED),
            );
            ui.add_space(4.0);
            theme::hint(
                ui,
                "Finch v0.1.0 - a compact Burp Suite style intercepting proxy in Rust.",
            );
        });
        ui.add_space(8.0);
    });
}
