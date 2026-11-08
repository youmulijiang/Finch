//! Notes tab: free-form scratch notes for the operator, persisted to
//! `finch-data/notes.json`. Left: searchable note list; right: title + body
//! editor that fills the pane. Edits save to disk immediately.

use std::path::PathBuf;

use egui::{RichText, ScrollArea};
use serde::{Deserialize, Serialize};

use crate::ui::theme::{self, ButtonKind, EmptyState};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Note {
    pub id: u64,
    pub title: String,
    pub body: String,
    /// Epoch ms of the last update.
    pub updated: u64,
}

#[derive(Default)]
pub struct NotesUi {
    pub notes: Vec<Note>,
    /// Index into `notes` of the note open in the editor.
    pub selected: Option<usize>,
    pub next_id: u64,
    pub search: String,
    /// Width fraction of the note list pane.
    pub split: f32,
    pub loaded: bool,
}

impl NotesUi {
    /// Create a fresh note and open it in the editor.
    pub fn new_note(&mut self) {
        let now = now_ms();
        self.notes.push(Note {
            id: self.next_id,
            title: String::new(),
            body: String::new(),
            updated: now,
        });
        self.next_id += 1;
        self.selected = Some(self.notes.len() - 1);
        self.search.clear();
        save_notes(&self.notes);
    }

    fn delete_selected(&mut self) {
        if let Some(idx) = self.selected.take() {
            if idx < self.notes.len() {
                self.notes.remove(idx);
            }
            if self.notes.is_empty() {
                self.selected = None;
            } else {
                self.selected = Some(idx.min(self.notes.len() - 1));
            }
            save_notes(&self.notes);
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn notes_path() -> PathBuf {
    crate::proxy_ctrl::data_dir().join("notes.json")
}

fn load_notes() -> Vec<Note> {
    std::fs::read(notes_path())
        .ok()
        .and_then(|data| serde_json::from_slice(&data).ok())
        .unwrap_or_default()
}

fn save_notes(notes: &[Note]) {
    if let Ok(json) = serde_json::to_string_pretty(notes) {
        let _ = std::fs::write(notes_path(), json);
    }
}

fn format_updated(epoch_ms: u64) -> String {
    chrono::DateTime::from_timestamp_millis(epoch_ms as i64)
        .map(|dt| {
            dt.with_timezone(&chrono::Local::now().timezone())
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_default()
}

pub fn show(ui: &mut egui::Ui, n: &mut NotesUi) {
    // Lazy-load from disk on first frame.
    if !n.loaded {
        n.loaded = true;
        n.notes = load_notes();
        n.next_id = n.notes.iter().map(|x| x.id).max().unwrap_or(0) + 1;
        n.selected = (!n.notes.is_empty()).then_some(0);
        if n.split <= 0.0 {
            n.split = 0.35;
        }
    }

    // ---- Toolbar ----
    ui.horizontal(|ui| {
        if theme::button(ui, true, "New note", ButtonKind::Primary).clicked() {
            n.new_note();
        }
        if theme::button(ui, n.selected.is_some(), "Delete", ButtonKind::Danger).clicked() {
            n.delete_selected();
        }
        ui.add_space(8.0);
        ui.label(RichText::new("Search").size(12.0).color(theme::MUTED));
        ui.add(
            egui::TextEdit::singleline(&mut n.search)
                .desired_width(240.0)
                .hint_text("title or body text"),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(
                RichText::new(format!("{} note(s)", n.notes.len()))
                    .size(11.5)
                    .color(theme::MUTED),
            );
        });
    });
    ui.add_space(8.0);

    // Keep the selection valid.
    if let Some(idx) = n.selected {
        if idx >= n.notes.len() {
            // No eager `len() - 1` here: an empty list must not underflow.
            n.selected = if n.notes.is_empty() {
                None
            } else {
                Some(n.notes.len() - 1)
            };
        }
    }

    if n.notes.is_empty() {
        let clicked = theme::empty_state(
            ui,
            &EmptyState::new(
                "No notes yet",
                "Keep request targets, findings and to-dos here.",
            )
            .with_cta("New note", true),
        );
        if clicked {
            n.new_note();
        }
        return;
    }

    let pane_h = ui.available_height().max(200.0);

    // Split field borrows so both panes render in one frame.
    let NotesUi {
        notes,
        selected,
        search,
        ..
    } = n;
    let sel_idx = (*selected).unwrap_or(0).min(notes.len() - 1);
    // Borrow split: the list pane renders an owned snapshot, the editor works
    // on a clone of the selected note; both are written back after the panes.
    let list_snapshot = notes.clone();
    let mut edited_note = notes[sel_idx].clone();
    let edited_id = edited_note.id;
    let dirty = std::cell::Cell::new(false);

    theme::h_split_panes(
        ui,
        &mut n.split,
        pane_h,
        |ui| {
            // ---- Left: note list ----
            theme::card_with_margin(ui, 6.0, |ui| {
                ui.set_height(pane_h - 8.0);
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .id_salt("notes_list")
                    .show(ui, |ui| {
                        let q = search.trim().to_lowercase();
                        for (idx, note) in list_snapshot.iter().enumerate().rev() {
                            if !q.is_empty()
                                && !note.title.to_lowercase().contains(&q)
                                && !note.body.to_lowercase().contains(&q)
                            {
                                continue;
                            }
                            let selected_row = *selected == Some(idx);
                            let title = if note.title.trim().is_empty() {
                                "Untitled".to_string()
                            } else {
                                note.title.clone()
                            };
                            let preview = note
                                .body
                                .lines()
                                .next()
                                .unwrap_or("")
                                .chars()
                                .take(60)
                                .collect::<String>();
                            let resp = ui
                                .allocate_ui_with_layout(
                                    egui::vec2(ui.available_width(), 44.0),
                                    egui::Layout::top_down(egui::Align::Min),
                                    |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(
                                                RichText::new(title).size(12.5).strong().color(
                                                    if selected_row {
                                                        theme::TEXT_BRIGHT
                                                    } else {
                                                        theme::TEXT
                                                    },
                                                ),
                                            );
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| {
                                                    ui.label(
                                                        RichText::new(format_updated(note.updated))
                                                            .size(10.5)
                                                            .color(theme::MUTED),
                                                    );
                                                },
                                            );
                                        });
                                        if !preview.is_empty() {
                                            ui.label(
                                                RichText::new(preview)
                                                    .size(11.0)
                                                    .color(theme::MUTED),
                                            );
                                        }
                                    },
                                )
                                .response;
                            let bg = if selected_row {
                                theme::ACCENT_ROW
                            } else if resp.hovered() {
                                theme::CARD_HOVER
                            } else {
                                egui::Color32::TRANSPARENT
                            };
                            if bg != egui::Color32::TRANSPARENT {
                                ui.painter().rect_filled(resp.rect, 6.0, bg);
                            }
                            if resp.clicked() {
                                *selected = Some(idx);
                            }
                        }
                    });
            });
        },
        |ui| {
            // ---- Right: editor (local clone; written back after the frame) ----
            let note = &mut edited_note;
            ui.horizontal(|ui| {
                ui.label(RichText::new("Title").size(12.0).color(theme::MUTED));
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut note.title)
                        .id_salt(("note_title", note.id))
                        .desired_width(ui.available_width())
                        .hint_text("note title"),
                );
                if resp.changed() {
                    note.updated = now_ms();
                    dirty.set(true);
                }
            });
            ui.add_space(4.0);

            let body_h = (pane_h - 40.0).max(100.0);
            theme::card_with_margin(ui, 6.0, |ui| {
                ui.set_height(body_h);
                let fill = theme::fill_rows(ui, body_h);
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .id_salt(("note_body", note.id))
                    .show(ui, |ui| {
                        let resp = ui.add(
                            egui::TextEdit::multiline(&mut note.body)
                                .id_salt(("note_body_edit", note.id))
                                .font(egui::TextStyle::Monospace)
                                .desired_width(ui.available_width())
                                .desired_rows(fill),
                        );
                        if resp.changed() {
                            note.updated = now_ms();
                            dirty.set(true);
                        }
                    });
            });
        },
    );

    // Write editor changes back to the model and persist.
    if dirty.get() {
        if let Some(slot) = notes.iter_mut().find(|x| x.id == edited_id) {
            *slot = edited_note;
        }
        save_notes(notes);
    }
}
