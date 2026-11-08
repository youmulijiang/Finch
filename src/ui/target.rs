//! Target tab: site map tree + scope settings.

use std::collections::BTreeMap;
use std::sync::Arc;

use egui::{RichText, ScrollArea};

use crate::state::{HistoryEntry, SharedState};
use crate::ui::theme::{self, EmptyState};
use crate::ui::viewer::ReqRespViewer;

pub struct TargetUi {
    pub selected_entry: Option<u64>,
    pub viewer: ReqRespViewer,
    pub scope: String,
    pub only_in_scope: bool,
    /// Width fraction of the site map pane (draggable, stored so the divider
    /// never drifts across frames).
    pub split: f32,
}

impl Default for TargetUi {
    fn default() -> Self {
        Self {
            selected_entry: None,
            viewer: ReqRespViewer::default(),
            scope: String::new(),
            only_in_scope: false,
            split: 0.45,
        }
    }
}

impl TargetUi {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Recursive site map node.
struct Node {
    children: BTreeMap<String, Node>,
    /// (entry id, display label)
    entries: Vec<(u64, String)>,
}

impl Node {
    fn new() -> Self {
        Self {
            children: BTreeMap::new(),
            entries: Vec::new(),
        }
    }

    fn insert(&mut self, segments: &[&str], entry_id: u64, leaf_label: String) {
        if segments.is_empty() {
            self.entries.push((entry_id, leaf_label));
            return;
        }
        let head = segments[0];
        let node = self
            .children
            .entry(head.to_string())
            .or_insert_with(Node::new);
        node.insert(&segments[1..], entry_id, leaf_label);
    }
}

pub fn show(ui: &mut egui::Ui, shared: &Arc<SharedState>, t: &mut TargetUi) {
    let entries: Vec<Arc<std::sync::Mutex<HistoryEntry>>> =
        shared.history.lock().unwrap().iter().cloned().collect();

    // Scope helpers.
    let scope_hosts: Vec<String> = t
        .scope
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let in_scope = |host: &str| -> bool {
        if scope_hosts.is_empty() {
            return true;
        }
        scope_hosts.iter().any(|s| host.to_lowercase().contains(s))
    };

    // Build tree grouped by host.
    let mut hosts: BTreeMap<String, Node> = BTreeMap::new();
    for e in &entries {
        let entry = e.lock().unwrap();
        if t.only_in_scope && !in_scope(&entry.host) {
            continue;
        }
        if entry.is_tcp {
            let key = format!("tcp://{}", entry.destination);
            let node = hosts.entry(key.clone()).or_insert_with(Node::new);
            node.entries
                .push((entry.id, format!("{} B", entry.req_raw.len())));
            continue;
        }
        let host = entry.host.clone();
        let node = hosts.entry(host.clone()).or_insert_with(Node::new);
        let path = entry.path.trim_start_matches('/');
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let leaf = segments
            .last()
            .map(|s| format!("{} {}", entry.method, s))
            .unwrap_or_else(|| format!("{} /", entry.method));
        node.insert(&segments, entry.id, leaf);
    }

    if entries.is_empty() {
        let clicked = theme::empty_state(
            ui,
            &EmptyState::new(
                "No traffic yet",
                "Traffic captured by the proxy will appear here as a host/path tree.",
            )
            .with_cta("Open browser via proxy", true),
        );
        if clicked {
            let port = shared.settings.lock().unwrap().listen_port;
            match crate::proxy_ctrl::open_browser_with_proxy(port) {
                Ok(()) => shared.set_status("Browser launched with proxy"),
                Err(e) => shared.set_status(e),
            }
        }
        return;
    }
    if hosts.is_empty() {
        let clicked = theme::empty_state(
            ui,
            &EmptyState::new(
                "Nothing in scope",
                "No captured requests match the scope hosts filter.",
            )
            .with_cta("Show all hosts", true),
        );
        if clicked {
            t.only_in_scope = false;
        }
        return;
    }

    // Drift-free split: site map on the left, viewer on the right. Split the
    // field borrows so both panes can render in one frame.
    let TargetUi {
        selected_entry,
        viewer: viewer_state,
        scope,
        only_in_scope,
        split,
    } = t;
    let pane_h = ui.available_height().max(160.0);
    let sel: Option<(String, Vec<u8>, Option<Vec<u8>>, u64)> = {
        let selected = entries
            .iter()
            .find(|e| Some(e.lock().unwrap().id) == *selected_entry)
            .cloned();
        selected.map(|entry_arc| {
            let entry = entry_arc.lock().unwrap();
            (
                entry.url(),
                entry.req_raw.clone(),
                entry.resp_raw.clone(),
                entry.id,
            )
        })
    };

    theme::h_split_panes(
        ui,
        split,
        pane_h,
        |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Site map")
                        .size(13.0)
                        .strong()
                        .color(theme::TEXT_BRIGHT),
                );
                ui.add_space(12.0);
                ui.label(RichText::new("Scope").size(12.0).color(theme::MUTED));
                ui.add(
                    egui::TextEdit::singleline(scope)
                        .id_salt("target_scope")
                        .desired_width(220.0)
                        .hint_text("example.com, api.example.org"),
                );
                ui.checkbox(
                    only_in_scope,
                    RichText::new("Only in-scope")
                        .size(12.0)
                        .color(theme::MUTED),
                );
            });
            ui.add_space(8.0);
            theme::card_with_margin(ui, 8.0, |ui| {
                ui.set_height((pane_h - 64.0).max(120.0));
                ScrollArea::vertical().id_salt("sitemap").show(ui, |ui| {
                    for (host, node) in &hosts {
                        egui::CollapsingHeader::new(
                            RichText::new(format!("{host}  ({})", count_entries(node))).strong(),
                        )
                        .id_salt(("sitmap-host", host.as_str()))
                        .default_open(true)
                        .show(ui, |ui| {
                            render_node(ui, node, &format!("h/{host}"), selected_entry);
                        });
                    }
                });
            });
        },
        |ui| match &sel {
            Some((url, req_raw, resp_raw, id)) => {
                ui.label(RichText::new(url).size(12.0).color(theme::ACCENT));
                ui.add_space(8.0);
                viewer_state.show(
                    ui,
                    egui::Id::unique("target_viewer").with(*id),
                    req_raw,
                    resp_raw.as_deref(),
                );
            }
            None => {
                ui.vertical_centered(|ui| {
                    ui.add_space(((ui.available_height() - 40.0) * 0.5).max(8.0));
                    ui.label(
                        RichText::new("Select a request in the site map")
                            .size(12.5)
                            .color(theme::MUTED),
                    );
                });
            }
        },
    );
}

fn count_entries(node: &Node) -> usize {
    node.entries.len() + node.children.values().map(count_entries).sum::<usize>()
}

fn render_node(ui: &mut egui::Ui, node: &Node, path: &str, selected: &mut Option<u64>) {
    for (child_name, child) in &node.children {
        let label = if child_name.is_empty() {
            "/"
        } else {
            child_name.as_str()
        };
        let n = count_entries(child);
        egui::CollapsingHeader::new(RichText::new(format!("{label} ({n})")))
            .id_salt(("sitmap-node", path.to_owned() + "/" + child_name))
            .default_open(false)
            .show(ui, |ui| {
                render_node(ui, child, &format!("{path}/{child_name}"), selected);
            });
    }
    for (entry_id, label) in &node.entries {
        if ui
            .selectable_label(*selected == Some(*entry_id), label)
            .clicked()
        {
            *selected = Some(*entry_id);
        }
    }
}
