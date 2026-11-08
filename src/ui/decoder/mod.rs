//! Decoder tab: CyberChef-style recipe pipeline.
//!
//! Left pane: searchable operation library + the recipe (drag-reorderable
//! steps with per-step parameters). Right pane: per-step results with
//! text / hex / base64 views. The pipeline recomputes every frame while the
//! tab is open; all ops are in-memory byte transforms, well below frame time.

mod ops;

use base64::Engine as _;
use std::cell::Cell;

use egui::{Color32, RichText, ScrollArea};
use serde::{Deserialize, Serialize};

use crate::ui::theme::{self, ButtonKind};

pub use ops::{
    BlockMode, KeyEncoding, OP_ENTRIES, OpEntry, OpKind, Step, StepParams, StepResult, run_pipeline,
};

use ops::Category;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum OpView {
    #[default]
    Text,
    Hex,
    Base64,
}

#[derive(Default)]
pub struct DecoderUi {
    pub input: String,
    pub steps: Vec<Step>,
    pub results: Vec<StepResult>,
    /// 0 = input, n = result of step n. Cell: both panes mutate it.
    pub selected: Cell<usize>,
    pub view: OpView,
    pub lib_search: String,
    /// Column 1 (Operations) width fraction.
    pub split_frac: f32,
    /// Recipe column width fraction (of the space right of column 1).
    pub col2_frac: f32,
    /// Operation currently being dragged from the library (cross-column DnD).
    pub drag_op: Cell<Option<OpKind>>,
    /// Drop zone: the recipe column's screen rect, published each frame.
    pub drop_zone: Cell<Option<egui::Rect>>,
}

// ---------------------------------------------------------------- persistence

#[derive(Serialize, Deserialize, Default)]
struct Persisted {
    #[serde(default)]
    steps: Vec<Step>,
    #[serde(default)]
    input: String,
    #[serde(default)]
    split_frac: f32,
    #[serde(default)]
    col2_frac: f32,
}

impl DecoderUi {
    /// Load the last recipe from finch-data/decoder.json (missing or broken
    /// file falls back to the default state, mirroring finch.json handling).
    pub fn load() -> Self {
        let path = crate::proxy_ctrl::data_dir().join("decoder.json");
        let p: Persisted = std::fs::read(&path)
            .ok()
            .and_then(|data| serde_json::from_slice(&data).ok())
            .unwrap_or_default();
        Self {
            input: p.input,
            steps: p.steps,
            split_frac: if p.split_frac > 0.05 {
                p.split_frac
            } else {
                0.17
            },
            col2_frac: if p.col2_frac > 0.05 {
                p.col2_frac
            } else {
                0.45
            },
            ..DecoderUi::default()
        }
    }

    pub fn save(&self) {
        let p = Persisted {
            steps: self.steps.clone(),
            input: self.input.clone(),
            split_frac: self.split_frac,
            col2_frac: self.col2_frac,
        };
        if let Ok(json) = serde_json::to_string_pretty(&p) {
            let path = crate::proxy_ctrl::data_dir().join("decoder.json");
            let _ = std::fs::write(path, json);
        }
    }
}

// ---------------------------------------------------------------- entry

/// CyberChef-style three-column layout:
/// `Operations | Recipe (+ step parameters) | Input / Output`.
/// Columns 1|2+3 and 2|3 are separated by drift-free draggable dividers.
pub fn show(ui: &mut egui::Ui, d: &mut DecoderUi) {
    // Recompute the pipeline every frame while the tab is open: all ops are
    // in-memory byte transforms, cheap at UI text scales.
    d.results = run_pipeline(d.input.as_bytes(), &d.steps);
    d.selected.set(d.selected.get().min(d.steps.len()));

    // Split borrow so the column closures can each mutate their own fields.
    let DecoderUi {
        input,
        steps,
        results,
        selected,
        view,
        lib_search,
        split_frac,
        col2_frac,
        drag_op,
        drop_zone,
        ..
    } = d;
    let pane_h = ui.available_height() - 4.0;
    let mut to_add: Option<OpKind> = None;
    theme::h_split_panes(
        ui,
        split_frac,
        pane_h,
        |ui| ops_column(ui, lib_search, drag_op, drop_zone, &mut to_add, selected),
        |ui| {
            theme::h_split_panes(
                ui,
                col2_frac,
                pane_h,
                |ui| recipe_column(ui, steps, selected, drag_op, drop_zone),
                |ui| io_column(ui, input, results, selected, view),
            );
        },
    );
    // Append an operation picked in the ops column (steps is owned by the
    // recipe column during layout, so the click is queued and applied here).
    if let Some(kind) = to_add {
        steps.push(Step::new(kind));
        selected.set(steps.len()); // focus the new step
    }
}

// ---------------------------------------------------------------- column 1

fn ops_column(
    ui: &mut egui::Ui,
    lib_search: &mut String,
    drag_op: &Cell<Option<OpKind>>,
    drop_zone: &Cell<Option<egui::Rect>>,
    to_add: &mut Option<OpKind>,
    _selected: &Cell<usize>,
) {
    ScrollArea::vertical()
        .id_salt("decoder_ops_col")
        .show(ui, |ui| {
            theme::card_with_margin(ui, 8.0, |ui| {
                theme::card_title(ui, "Operations");
                theme::hint(ui, "click or drag into Recipe");
                ui.add_space(2.0);
                let search = egui::TextEdit::singleline(lib_search)
                    .id_salt("decoder_lib_search")
                    .hint_text("Search…")
                    .desired_width(ui.available_width());
                ui.add(search);
                ui.add_space(4.0);
                op_library(ui, lib_search, drag_op, drop_zone, to_add);
            });
        });
}

// ---------------------------------------------------------------- column 2

fn recipe_column(
    ui: &mut egui::Ui,
    steps: &mut Vec<Step>,
    selected: &Cell<usize>,
    drag_op: &Cell<Option<OpKind>>,
    drop_zone: &Cell<Option<egui::Rect>>,
) {
    // Publish this column as the drop target, then highlight it while an
    // operation from the library is dragged over it.
    let col_rect = ui.available_rect_before_wrap();
    drop_zone.set(Some(col_rect));
    let dragging = drag_op.get().is_some();
    let hovering_drop = dragging
        && ui
            .input(|i| i.pointer.latest_pos())
            .map(|p| col_rect.contains(p))
            .unwrap_or(false);
    if hovering_drop {
        ui.painter().rect_stroke(
            col_rect.shrink(1.0),
            8.0,
            egui::Stroke::new(2.0, theme::ACCENT),
            egui::StrokeKind::Inside,
        );
    }

    ScrollArea::vertical()
        .id_salt("decoder_recipe_col")
        .show(ui, |ui| {
            theme::card_with_margin(ui, 8.0, |ui| {
                ui.horizontal(|ui| {
                    theme::card_title(ui, "Recipe");
                    theme::hint(ui, "drag to reorder · click to edit");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::button(ui, !steps.is_empty(), "Clear", ButtonKind::Secondary)
                            .clicked()
                        {
                            steps.clear();
                            selected.set(0);
                        }
                    });
                });
                ui.add_space(2.0);
                if steps.is_empty() {
                    theme::hint(
                        ui,
                        if dragging {
                            "Release here to add the operation."
                        } else {
                            "Empty — click or drag an operation from the left column."
                        },
                    );
                } else {
                    recipe_list(ui, steps, selected);
                }
            });
        });
}

fn op_library(
    ui: &mut egui::Ui,
    search: &str,
    drag_op: &Cell<Option<OpKind>>,
    drop_zone: &Cell<Option<egui::Rect>>,
    to_add: &mut Option<OpKind>,
) {
    let q = search.trim().to_lowercase();
    let mut last_cat: Option<Category> = None;
    for entry in OP_ENTRIES {
        if !q.is_empty() && !entry.label.to_lowercase().contains(&q) {
            continue;
        }
        if Some(entry.category) != last_cat {
            ui.add_space(2.0);
            ui.label(
                RichText::new(entry.category.label().to_uppercase())
                    .size(10.5)
                    .color(theme::MUTED),
            );
            last_cat = Some(entry.category);
        }
        drag_row(ui, entry, drag_op, drop_zone, to_add);
    }
}

/// One hand-painted library row: click to append, drag into the Recipe
/// column to drop it there (CyberChef-style cross-column drag and drop).
fn drag_row(
    ui: &mut egui::Ui,
    entry: &OpEntry,
    drag_op: &Cell<Option<OpKind>>,
    drop_zone: &Cell<Option<egui::Rect>>,
    to_add: &mut Option<OpKind>,
) {
    let kind = entry.default;
    let row_h = 22.0;
    let (rect, resp) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), row_h),
        egui::Sense::click_and_drag(),
    );
    let resp = resp.on_hover_cursor(egui::CursorIcon::Grab);

    // Hover / active-drag background, painted before the content.
    let dragging_this = drag_op.get() == Some(kind) && resp.dragged();
    if dragging_this || resp.hovered() {
        let bg = if dragging_this {
            theme::ACCENT_SOFT
        } else {
            Color32::from_rgba_unmultiplied(255, 255, 255, 8)
        };
        ui.painter().rect_filled(rect, 4.0, bg);
    }

    // Drag handle: three dot pairs hinting the row can be dragged.
    let p = ui.painter();
    let cy = rect.center().y;
    for i in 0..3u32 {
        let y = cy - 5.0 + i as f32 * 5.0;
        p.circle_filled(egui::pos2(rect.left() + 6.0, y), 1.2, theme::DIM);
        p.circle_filled(egui::pos2(rect.left() + 11.0, y), 1.2, theme::DIM);
    }

    let text_color = if resp.hovered() || dragging_this {
        theme::TEXT_BRIGHT
    } else {
        theme::TEXT
    };
    p.text(
        egui::pos2(rect.left() + 20.0, cy),
        egui::Align2::LEFT_CENTER,
        entry.label,
        egui::FontId::proportional(12.5),
        text_color,
    );

    if resp.clicked() {
        *to_add = Some(kind);
    }
    if resp.drag_started() {
        drag_op.set(Some(kind));
    }
    if resp.dragged() && drag_op.get() == Some(kind) {
        paint_drag_preview(ui, entry.label);
    }
    if resp.drag_stopped() && drag_op.get() == Some(kind) {
        drag_op.set(None);
        let over_recipe = ui
            .input(|i| i.pointer.interact_pos())
            .map(|pos| drop_zone.get().map(|r| r.contains(pos)).unwrap_or(false))
            .unwrap_or(false);
        if over_recipe {
            *to_add = Some(kind);
        }
    }
}

/// Floating op-name tag that follows the pointer while dragging.
fn paint_drag_preview(ui: &mut egui::Ui, label: &str) {
    let Some(pos) = ui.input(|i| i.pointer.latest_pos()) else {
        return;
    };
    let painter = ui.ctx().layer_painter(egui::LayerId::new(
        egui::Order::Tooltip,
        egui::Id::unique("decoder_drag_preview"),
    ));
    let text = format!("+ {label}");
    let pad = 6.0;
    let galley_w = 7.0 * text.len() as f32;
    let rect = egui::Rect::from_min_size(
        pos + egui::vec2(10.0, 10.0),
        egui::vec2(galley_w + pad * 2.0, 22.0),
    );
    painter.rect_filled(rect, 6.0, theme::CARD);
    painter.rect_stroke(
        rect,
        6.0,
        egui::Stroke::new(1.0, theme::ACCENT),
        egui::StrokeKind::Inside,
    );
    painter.text(
        rect.left_center() + egui::vec2(pad, 0.0),
        egui::Align2::LEFT_CENTER,
        &text,
        egui::FontId::proportional(12.5),
        theme::TEXT_BRIGHT,
    );
}

fn recipe_list(ui: &mut egui::Ui, steps: &mut Vec<Step>, selected: &Cell<usize>) {
    let mut to_delete: Option<usize> = None;
    let mut to_select: Option<usize> = None;

    let dnd_id = ui.make_persistent_id("decoder_recipe");
    let selected_idx = selected.get();
    let response = egui_dnd::dnd(ui, dnd_id).show_vec(steps, |ui, step, handle, state| {
        let idx = state.index;
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                // Painted drag handle: three dot pairs, no font dependency.
                handle.ui(ui, |ui| {
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(14.0, 16.0), egui::Sense::hover());
                    let p = ui.painter();
                    for i in 0..3u32 {
                        let y = rect.top() + 3.0 + i as f32 * 5.0;
                        p.circle_filled(egui::pos2(rect.left() + 4.0, y), 1.2, theme::DIM);
                        p.circle_filled(egui::pos2(rect.left() + 10.0, y), 1.2, theme::DIM);
                    }
                });
                let name = if step.enabled {
                    RichText::new(format!("{}. {}", idx + 1, step.kind.name())).size(12.5)
                } else {
                    RichText::new(format!("{}. {} (disabled)", idx + 1, step.kind.name()))
                        .size(12.5)
                        .color(theme::MUTED)
                };
                if ui
                    .selectable_label(selected_idx == idx + 1, name)
                    .on_hover_text("Click to show configuration")
                    .clicked()
                {
                    to_select = Some(idx);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .button(RichText::new("✕").size(11.0).color(theme::DANGER))
                        .on_hover_text("Remove step")
                        .clicked()
                    {
                        to_delete = Some(idx);
                    }
                    if theme::toggle(ui, &mut step.enabled) {
                        ui.ctx().request_repaint();
                    }
                });
            }); // ui.horizontal

            // Detailed inline configuration BELOW the title row, so long
            // config rows never widen the item and squeeze column 3.
            if selected_idx == idx + 1 {
                step_editor_inline(ui, step, idx);
            }
        }); // ui.vertical
    }); // show_vec item closure

    if let Some(update) = response.update {
        egui_dnd::utils::shift_vec(update.from, update.to, steps);
        // Keep the dragged step selected across the reorder, and remap the
        // selection of steps that merely shifted position (selected is
        // 1-based: 0 = input).
        let sel = selected.get();
        if sel != 0 {
            let sel0 = sel - 1;
            let new0 = if sel0 == update.from {
                update.to
            } else if update.from < sel0 && sel0 <= update.to {
                sel0 - 1
            } else if update.to <= sel0 && sel0 < update.from {
                sel0 + 1
            } else {
                sel0
            };
            selected.set(new0 + 1);
        }
        // Defer a same-frame delete until after the reorder: the captured
        // index refers to the pre-drag order.
        if let Some(i) = to_delete {
            let mut new_idx = i;
            if i == update.from {
                new_idx = update.to;
            } else if update.from < i && i <= update.to {
                new_idx = i - 1;
            } else if update.to <= i && i < update.from {
                new_idx = i + 1;
            }
            steps.remove(new_idx);
            selected.set(0);
        }
    } else {
        if let Some(i) = to_select {
            selected.set(i + 1);
        }
        if let Some(i) = to_delete {
            steps.remove(i);
            selected.set(0);
        }
    }
}

/// Compact dropdown helper shared by the inline step editor.
fn combo<T: PartialEq + Copy>(
    ui: &mut egui::Ui,
    id_salt: (&'static str, usize),
    current: &mut T,
    options: &[(T, &str)],
) {
    let sel = options
        .iter()
        .find(|(v, _)| *v == *current)
        .map(|(_, l)| *l)
        .unwrap_or("?");
    egui::ComboBox::from_id_salt(id_salt)
        .selected_text(sel)
        .show_ui(ui, |ui| {
            for (v, label) in options {
                ui.selectable_value(current, *v, *label);
            }
        });
}

/// Detailed inline configuration for the selected recipe step, rendered
/// inside its recipe card: direction / mode dropdowns for crypto ops plus
/// key, IV and AAD inputs with format picker.
fn step_editor_inline(ui: &mut egui::Ui, step: &mut Step, idx: usize) {
    ui.add_space(4.0);
    let kind = step.kind;
    let p = &mut step.params;

    // Direction / mode dropdowns mutate the step's OpKind in place, so the
    // engine and the step title stay in sync without touching the model.
    match &mut step.kind {
        OpKind::AesCrypt { enc, mode } | OpKind::Sm4Crypt { enc, mode } => {
            direction_mode(ui, idx, enc, Some(mode));
        }
        OpKind::DesCrypt {
            enc,
            triple: _,
            mode,
        } => {
            direction_mode(ui, idx, enc, Some(mode));
        }
        OpKind::AesGcmCrypt { enc } => {
            direction_mode(ui, idx, enc, None);
        }
        _ => {}
    }

    if kind.needs_key() {
        ui.add_space(2.0);
        ui.label(RichText::new("Key").size(11.5).color(theme::MUTED));
        ui.horizontal(|ui| {
            let edit = egui::TextEdit::singleline(&mut p.key)
                .id_salt(("decoder_key", idx))
                .font(egui::TextStyle::Monospace)
                .desired_width(ui.available_width() - 120.0);
            ui.add(edit);
            ui.label(RichText::new("Format").size(11.5).color(theme::MUTED));
            combo(
                ui,
                ("decoder_keyenc", idx),
                &mut p.key_enc,
                &[(KeyEncoding::Hex, "Hex"), (KeyEncoding::Utf8, "UTF-8")],
            );
        });
    }
    if kind.needs_iv() {
        ui.add_space(2.0);
        ui.label(
            RichText::new(if kind.is_gcm() { "Nonce" } else { "IV" })
                .size(11.5)
                .color(theme::MUTED),
        );
        let edit = egui::TextEdit::singleline(&mut p.iv)
            .id_salt(("decoder_iv", idx))
            .font(egui::TextStyle::Monospace)
            .desired_width(ui.available_width());
        ui.add(edit);
    }
    if kind.is_gcm() {
        ui.add_space(2.0);
        ui.label(
            RichText::new("AAD (optional)")
                .size(11.5)
                .color(theme::MUTED),
        );
        let edit = egui::TextEdit::singleline(&mut p.aad)
            .id_salt(("decoder_aad", idx))
            .font(egui::TextStyle::Monospace)
            .desired_width(ui.available_width());
        ui.add(edit);
    }
    if kind.needs_key() || kind.needs_iv() {
        ui.label(
            RichText::new(key_hint(kind, p.key_enc))
                .size(10.5)
                .color(theme::DIM),
        );
    }
}

fn direction_mode(ui: &mut egui::Ui, idx: usize, enc: &mut bool, mode: Option<&mut BlockMode>) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("Direction").size(11.5).color(theme::MUTED));
        combo(
            ui,
            ("decoder_dir", idx),
            enc,
            &[(true, "Encrypt"), (false, "Decrypt")],
        );
        if let Some(mode) = mode {
            ui.add_space(8.0);
            ui.label(RichText::new("Mode").size(11.5).color(theme::MUTED));
            combo(
                ui,
                ("decoder_mode", idx),
                mode,
                &[(BlockMode::Cbc, "CBC"), (BlockMode::Ecb, "ECB")],
            );
        }
    });
}

fn key_hint(kind: OpKind, enc: KeyEncoding) -> String {
    let (name, lens) = match kind {
        OpKind::AesCrypt { .. } => ("AES", "16 / 24 / 32"),
        OpKind::Sm4Crypt { .. } => ("SM4", "16"),
        OpKind::DesCrypt { triple, .. } => {
            if triple {
                ("3DES", "24")
            } else {
                ("DES", "8")
            }
        }
        OpKind::Rc4Crypt => ("RC4", "1..256"),
        OpKind::AesGcmCrypt { .. } => ("AES-GCM", "16 / 32"),
        OpKind::JwtSign | OpKind::JwtVerify => ("JWT HS256 secret", "any length"),
        _ => ("", ""),
    };
    let suffix = match enc {
        KeyEncoding::Hex => "hex chars (×2 per byte)",
        KeyEncoding::Utf8 => "raw bytes as UTF-8 text",
    };
    format!("{name} key length: {lens} bytes — as {suffix}")
}

// ---------------------------------------------------------------- column 3

/// Input (top) and Output (bottom), like CyberChef's right column.
fn io_column(
    ui: &mut egui::Ui,
    input: &mut String,
    results: &[StepResult],
    selected: &Cell<usize>,
    view: &mut OpView,
) {
    ScrollArea::vertical()
        .id_salt("decoder_io_col")
        .show(ui, |ui| {
            theme::card_with_margin(ui, 8.0, |ui| {
                ui.horizontal(|ui| {
                    theme::card_title(ui, "Input");
                    theme::hint(ui, &format!("{} bytes", input.len()));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::button(ui, true, "Clear", ButtonKind::Secondary).clicked() {
                            input.clear();
                        }
                    });
                });
                let edit = egui::TextEdit::multiline(input)
                    .id_salt("decoder_input")
                    .font(egui::TextStyle::Monospace)
                    .desired_width(ui.available_width())
                    .desired_rows(7);
                ui.add(edit);
            });
            ui.add_space(6.0);

            theme::card_with_margin(ui, 8.0, |ui| {
                ui.horizontal(|ui| {
                    theme::card_title(ui, "Output");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        theme::segmented(
                            ui,
                            view,
                            &[
                                (OpView::Text, "Text"),
                                (OpView::Hex, "Hex"),
                                (OpView::Base64, "Base64"),
                            ],
                        );
                    });
                });
                ui.add_space(4.0);

                // Step selector row: In, 1, 2, 3...
                ui.horizontal_wrapped(|ui| {
                    step_button(ui, 0, "In", selected.get(), selected);
                    for (i, res) in results.iter().enumerate() {
                        let label = if res.error.is_some() {
                            format!("{} ⚠", i + 1)
                        } else {
                            format!("{}", i + 1)
                        };
                        step_button(ui, i + 1, &label, selected.get(), selected);
                    }
                });
                ui.add_space(6.0);

                let (data, error) = match selected.get() {
                    0 => (input.as_bytes().to_vec(), None),
                    n => match results.get(n - 1) {
                        Some(res) => (res.data.clone(), res.error.clone()),
                        None => (Vec::new(), None),
                    },
                };

                if let Some(err) = error {
                    ui.label(
                        RichText::new(format!("⚠ {err}"))
                            .size(12.0)
                            .color(theme::DANGER),
                    );
                    ui.add_space(4.0);
                }

                let rendered = render(&data, *view);
                ui.horizontal(|ui| {
                    theme::hint(
                        ui,
                        &format!(
                            "{} bytes · step {} of {}",
                            data.len(),
                            selected.get(),
                            results.len()
                        ),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::button(ui, !rendered.is_empty(), "Copy", ButtonKind::Secondary)
                            .clicked()
                        {
                            ui.ctx().copy_text(rendered.clone());
                        }
                    });
                });
                let mut rendered = rendered;
                let edit = egui::TextEdit::multiline(&mut rendered)
                    .id_salt("decoder_output")
                    .font(egui::TextStyle::Monospace)
                    .desired_width(ui.available_width())
                    .desired_rows(14);
                ui.add(edit);
            });
        });
}

fn step_button(ui: &mut egui::Ui, idx: usize, label: &str, current: usize, selected: &Cell<usize>) {
    let kind = if current == idx {
        ButtonKind::Primary
    } else {
        ButtonKind::Secondary
    };
    if theme::button(ui, true, label, kind).clicked() {
        selected.set(idx);
    }
}

fn render(data: &[u8], view: OpView) -> String {
    match view {
        OpView::Text => String::from_utf8_lossy(data).into_owned(),
        OpView::Hex => data
            .chunks(32)
            .map(hex::encode)
            .collect::<Vec<_>>()
            .join("\n"),
        OpView::Base64 => BASE64.encode(data),
    }
}
