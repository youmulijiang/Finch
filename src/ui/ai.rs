//! AI tab: conversational pentest assistant. Chat with an OpenAI-compatible
//! model; the model can call Finch built-in tools and MCP tools via the
//! agent loop (src/ai.rs).

use std::sync::{Arc, Mutex};

use egui::RichText;

use crate::ai::{ChatMessage, ChatRole, agent_loop};
use crate::state::SharedState;
use crate::ui::mcp::{self, McpUi};

pub struct AiUi {
    pub chat: Vec<ChatMessage>,
    pub input: String,
    /// True while the agent loop is running in the background.
    pub busy: bool,
    /// Pending result of a background agent run (role, text) pairs.
    pub events: Arc<Mutex<Vec<(ChatRole, String)>>>,
    /// Finished message list from the last run (OpenAI format for follow-ups).
    pub thread: Arc<Mutex<Option<Vec<serde_json::Value>>>>,
    /// Set when a run finishes (success or error).
    pub done: Arc<std::sync::atomic::AtomicBool>,
    pub error: Arc<Mutex<Option<String>>>,
    pub auto_scroll: bool,
    /// Chat pane width fraction of the split (persistent drag).
    pub split_frac: f32,
}

impl Default for AiUi {
    fn default() -> Self {
        Self {
            chat: Vec::new(),
            input: String::new(),
            busy: false,
            events: Arc::new(Mutex::new(Vec::new())),
            thread: Arc::new(Mutex::new(None)),
            done: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            error: Arc::new(Mutex::new(None)),
            auto_scroll: true,
            split_frac: 0.62,
        }
    }
}

impl AiUi {
    pub fn send(&mut self, shared: &Arc<SharedState>) {
        let text = self.input.trim().to_string();
        if text.is_empty() || self.busy {
            return;
        }
        self.input.clear();
        self.chat.push(ChatMessage {
            role: ChatRole::User,
            content: text.clone(),
        });

        let prior = self.thread.lock().unwrap().take().unwrap_or_default();
        let mut history = prior.clone();
        history.push(serde_json::json!({"role": "user", "content": text}));

        self.busy = true;
        self.done.store(false, std::sync::atomic::Ordering::Relaxed);
        self.error.lock().unwrap().take();
        self.events.lock().unwrap().clear();

        let shared = shared.clone();
        let events = self.events.clone();
        let done = self.done.clone();
        let error_slot = self.error.clone();
        let thread_slot = self.thread.clone();
        crate::app::runtime().spawn(async move {
            // MCP tools are discovered by connecting to each configured
            // server; each tool call uses a fresh connection (simple and
            // avoids UI-owned child processes).
            let servers: Vec<crate::state::McpTransportConfig> = shared
                .settings
                .lock()
                .unwrap()
                .mcp_servers
                .iter()
                .map(|c| c.transport.clone())
                .collect();
            let mut mcp_tools: Vec<(String, String, serde_json::Value)> = Vec::new();
            for transport in &servers {
                let mut conn =
                    crate::mcp_client::McpConnection::new("ai".into(), transport.clone());
                if conn.connect().await.is_ok() {
                    for t in &conn.tools {
                        mcp_tools.push((t.name.clone(), t.description.clone(), t.schema.clone()));
                    }
                }
                conn.shutdown();
            }
            let mcp_tools = Arc::new(mcp_tools);

            let call_mcp: std::sync::Arc<
                dyn Fn(
                        String,
                        serde_json::Value,
                    ) -> std::pin::Pin<
                        Box<dyn std::future::Future<Output = Result<String, String>> + Send>,
                    > + Send
                    + Sync,
            > = Arc::new(move |name, args| {
                let servers = servers.clone();
                Box::pin(async move {
                    for transport in servers.iter() {
                        let mut conn =
                            crate::mcp_client::McpConnection::new("ai".into(), transport.clone());
                        if conn.connect().await.is_ok() && conn.tools.iter().any(|t| t.name == name)
                        {
                            let out = conn.call_tool(&name, args).await;
                            conn.shutdown();
                            return out;
                        }
                        conn.shutdown();
                    }
                    Err(format!("no MCP server provides tool '{name}'"))
                })
            });
            let on_event = |role: ChatRole, text: String| {
                events.lock().unwrap().push((role, text));
                if let Some(ctx) = shared.ui_ctx.get() {
                    ctx.request_repaint();
                }
            };
            let result = agent_loop(shared.clone(), history, mcp_tools, call_mcp, on_event).await;
            match result {
                Ok(messages) => {
                    *thread_slot.lock().unwrap() = Some(messages);
                }
                Err(e) => {
                    // Restore the prior thread so the next send keeps the
                    // conversation context the UI still displays.
                    *thread_slot.lock().unwrap() = Some(prior);
                    *error_slot.lock().unwrap() = Some(e);
                }
            }
            done.store(true, std::sync::atomic::Ordering::Relaxed);
            if let Some(ctx) = shared.ui_ctx.get() {
                ctx.request_repaint();
            }
        });
    }

    /// Drain background events into the visible chat.
    pub fn poll(&mut self) {
        let mut ev = self.events.lock().unwrap();
        for (role, text) in ev.drain(..) {
            match role {
                ChatRole::Assistant => self.chat.push(ChatMessage {
                    role: ChatRole::Assistant,
                    content: text,
                }),
                ChatRole::Tool => self.chat.push(ChatMessage {
                    role: ChatRole::Tool,
                    content: text,
                }),
                ChatRole::Notice => {} // tool-start notices are transient
                ChatRole::User => {}
            }
        }
        if self.done.load(std::sync::atomic::Ordering::Relaxed) && self.busy {
            self.busy = false;
            if let Some(e) = self.error.lock().unwrap().take() {
                self.chat.push(ChatMessage {
                    role: ChatRole::Notice,
                    content: e,
                });
            }
        }
    }
}

pub fn show(ui: &mut egui::Ui, shared: &Arc<SharedState>, ai: &mut AiUi, mcp: &mut McpUi) {
    ai.poll();

    // ---- Split: chat (left ~60%) | MCP servers (right ~40%) ----
    let total_w = ui.available_width();
    let handle_w = 6.0;
    let usable = (total_w - handle_w).max(1.0);
    let min_frac = (300.0 / usable).min(0.5);
    let frac = ai.split_frac.clamp(min_frac, 1.0 - min_frac);
    let left_w = usable * frac;
    let right_w = usable - left_w;
    let pane_h = ui.available_height().max(200.0);
    let mut new_split = frac;

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;

        ui.allocate_ui_with_layout(
            egui::vec2(left_w, pane_h),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.set_width(left_w);
                draw_chat(ui, shared, ai);
            },
        );

        // Draggable divider.
        let (rect, resp) =
            ui.allocate_exact_size(egui::vec2(handle_w, pane_h), egui::Sense::drag());
        let resp = resp.on_hover_cursor(egui::CursorIcon::ResizeHorizontal);
        let color = if resp.hovered() || resp.dragged() {
            egui::Color32::from_rgb(0x7a, 0xb4, 0xff)
        } else {
            egui::Color32::from_rgb(0x44, 0x4a, 0x54)
        };
        let x = rect.center().x;
        ui.painter().line_segment(
            [egui::pos2(x, rect.top()), egui::pos2(x, rect.bottom())],
            egui::Stroke::new(1.0, color),
        );
        if resp.dragged() {
            new_split = (frac + resp.drag_delta().x / usable).clamp(min_frac, 1.0 - min_frac);
        }

        ui.allocate_ui_with_layout(
            egui::vec2(right_w, pane_h),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.set_width(right_w);
                // MCP configuration is part of the AI module.
                mcp::show_panel(ui, shared, mcp);
            },
        );
    });
    ai.split_frac = new_split;
}

/// The chat column (toolbar + log + input).
fn draw_chat(ui: &mut egui::Ui, shared: &Arc<SharedState>, ai: &mut AiUi) {
    // Toolbar
    ui.horizontal(|ui| {
        let model = shared.settings.lock().unwrap().ai.model.clone();
        ui.label(
            RichText::new(if model.is_empty() {
                "no model configured (Settings → AI)".to_string()
            } else {
                format!("model: {model}")
            })
            .size(11.5)
            .color(theme_color_muted()),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if theme_button(ui, !ai.busy && !ai.chat.is_empty(), "Clear chat") {
                ai.chat.clear();
                *ai.thread.lock().unwrap() = None;
            }
            let servers = shared.settings.lock().unwrap().mcp_servers.len();
            ui.label(
                RichText::new(format!(
                    "{} builtin tools, {servers} MCP server(s)",
                    crate::ai::builtin_tools().len()
                ))
                .size(11.5)
                .color(theme_color_muted()),
            );
        });
    });
    ui.add_space(6.0);

    // Chat log: fixed to the space above the input row so the input row
    // stays visible (ScrollArea would otherwise swallow the full height).
    let log_h = (ui.available_height() - 40.0).max(80.0);
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), log_h),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .id_salt("ai_chat_log")
        .stick_to_bottom(ai.auto_scroll)
        .show(ui, |ui| {
            if ai.chat.is_empty() {
                ui.add_space(ui.available_height() * 0.4);
                ui.vertical_centered(|ui| {
                    ui.label(
                        RichText::new("AI pentest assistant")
                            .size(15.0)
                            .strong()
                            .color(egui::Color32::from_rgb(0xd8, 0xde, 0xe6)),
                    );
                    ui.label(
                        RichText::new(
                            "Ask about captured traffic, or instruct the model to send test requests via tools.",
                        )
                        .size(12.0)
                        .color(theme_color_muted()),
                    );
                });
                return;
            }
            for msg in &ai.chat {
                let (label, color) = match msg.role {
                    ChatRole::User => ("You", egui::Color32::from_rgb(0x7a, 0xb4, 0xff)),
                    ChatRole::Assistant => ("AI", egui::Color32::from_rgb(0x7a, 0xd8, 0x9c)),
                    ChatRole::Tool => ("Tool", egui::Color32::from_rgb(0xd8, 0xa5, 0x5a)),
                    ChatRole::Notice => ("", egui::Color32::from_rgb(0xff, 0x77, 0x77)),
                };
                if msg.role == ChatRole::Notice {
                    ui.label(RichText::new(&msg.content).size(11.5).color(color));
                    continue;
                }
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(label).size(11.5).strong().color(color));
                    ui.label(
                        RichText::new(&msg.content)
                            .size(12.5)
                            .color(egui::Color32::from_rgb(0xd4, 0xd8, 0xde)),
                    );
                });
                ui.add_space(2.0);
            }
            if ai.busy {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(
                        RichText::new("thinking / calling tools...")
                            .size(11.5)
                            .color(theme_color_muted()),
                    );
                });
            }
        });
        }); // log region

    ui.add_space(6.0);

    // Input row
    ui.horizontal(|ui| {
        let send_enabled = !ai.busy && !ai.input.trim().is_empty();
        let response = ui.add(
            egui::TextEdit::singleline(&mut ai.input)
                .hint_text("Ask the assistant... (Enter to send)")
                .desired_width(ui.available_width() - 110.0),
        );
        let enter = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if theme_button(ui, send_enabled, "Send") || (enter && send_enabled) {
            ai.send(shared);
        }
    });
}

fn theme_color_muted() -> egui::Color32 {
    egui::Color32::from_rgb(0x8a, 0x92, 0x9e)
}

fn theme_button(ui: &mut egui::Ui, enabled: bool, label: &str) -> bool {
    ui.add_enabled(enabled, egui::Button::new(RichText::new(label).size(12.0)))
        .clicked()
}
