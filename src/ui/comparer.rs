//! Comparer tab: live side-by-side diff of two texts.
//!
//! Both texts are diffed every frame (similar crate), so the comparison
//! renders in real time while the user edits. Each pane can be toggled
//! between Diff view (coloured rows with line numbers and +/− markers) and
//! Edit mode (a plain multiline editor). In Diff view the two panes are one
//! aligned row table sharing a single scroll, like a merge tool.

use egui::{Align2, Color32, FontId, Pos2, RichText, ScrollArea, Stroke, Vec2};
use similar::{DiffTag, TextDiff};

use crate::ui::theme::{self, ButtonKind};

/// Row height of the diff view.
const LINE_H: f32 = 20.0;
/// Width of the line-number gutter.
const GUTTER_W: f32 = 44.0;
/// Width of the +/− sign column.
const SIGN_W: f32 = 16.0;
/// Diff is skipped beyond this many lines per side (a plain numbered view is
/// shown instead so the tab never stalls).
const MAX_DIFF_LINES: usize = 20_000;
/// Hard cap on rendered rows (the diff table is culled poorly for huge texts).
const MAX_RENDER_ROWS: usize = 5_000;

const DEL_BG: Color32 = Color32::from_rgb(0x42, 0x24, 0x28);
const INS_BG: Color32 = Color32::from_rgb(0x26, 0x39, 0x2a);
const PAD_BG: Color32 = Color32::from_rgb(0x17, 0x19, 0x1f);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CellKind {
    #[default]
    Same,
    /// Line only in the original (left, red).
    Del,
    /// Line only in the modified (right, green).
    Ins,
    /// Padding where the other side has a line this side lacks (hatched).
    Empty,
}

#[derive(Clone, Debug, Default)]
pub struct Cell {
    pub kind: CellKind,
    /// 1-based line number (0 = padding cell).
    pub no: usize,
    pub text: String,
}

impl Cell {
    fn same(no: usize, line: &str) -> Self {
        Self {
            kind: CellKind::Same,
            no,
            text: clean_line(line),
        }
    }
    fn del(no: usize, line: &str) -> Self {
        Self {
            kind: CellKind::Del,
            no,
            text: clean_line(line),
        }
    }
    fn ins(no: usize, line: &str) -> Self {
        Self {
            kind: CellKind::Ins,
            no,
            text: clean_line(line),
        }
    }
    fn empty() -> Self {
        Self {
            kind: CellKind::Empty,
            no: 0,
            text: String::new(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DiffRow {
    pub left: Cell,
    pub right: Cell,
}

pub struct ComparerUi {
    pub left: String,
    pub right: String,
    /// Left pane's width fraction, stored so the divider never drifts.
    pub split_frac: f32,
    /// Height fraction of the editors zone vs the live diff table below.
    pub vsplit: f32,
}

impl Default for ComparerUi {
    fn default() -> Self {
        Self {
            left: String::new(),
            right: String::new(),
            split_frac: 0.5,
            vsplit: 0.55,
        }
    }
}

impl ComparerUi {
    pub fn new() -> Self {
        Self::default()
    }
}

fn clean_line(line: &str) -> String {
    let t = line.trim_end_matches('\n').trim_end_matches('\r');
    let t = t.replace('\t', "    ");
    if t.chars().count() > 400 {
        let s: String = t.chars().take(400).collect();
        format!("{s}…")
    } else {
        t
    }
}

/// Diff the two texts into aligned display rows. Runs on every frame so the
/// view updates in real time; returns (rows, added, removed, truncated).
fn compute_rows(left: &str, right: &str) -> (Vec<DiffRow>, usize, usize, bool) {
    let lv: Vec<&str> = left.split_inclusive('\n').collect();
    let rv: Vec<&str> = right.split_inclusive('\n').collect();
    let mut rows = Vec::new();
    let (mut added, mut removed) = (0usize, 0usize);

    let truncated = lv.len() > MAX_DIFF_LINES || rv.len() > MAX_DIFF_LINES;
    if truncated {
        // Too big to diff cheaply: plain numbered view, no colouring.
        let n = lv.len().max(rv.len()).min(MAX_RENDER_ROWS);
        for k in 0..n {
            rows.push(DiffRow {
                left: lv
                    .get(k)
                    .map(|l| Cell::same(k + 1, l))
                    .unwrap_or_else(Cell::empty),
                right: rv
                    .get(k)
                    .map(|l| Cell::same(k + 1, l))
                    .unwrap_or_else(Cell::empty),
            });
        }
        return (rows, added, removed, true);
    }

    if !lv.is_empty() || !rv.is_empty() {
        let diff = TextDiff::from_lines(left, right);
        for op in diff.ops() {
            let or = op.old_range();
            let nr = op.new_range();
            match op.tag() {
                DiffTag::Equal => {
                    for k in 0..or.len() {
                        rows.push(DiffRow {
                            left: Cell::same(or.start + k + 1, lv[or.start + k]),
                            right: Cell::same(nr.start + k + 1, rv[nr.start + k]),
                        });
                    }
                }
                DiffTag::Delete => {
                    removed += or.len();
                    for k in 0..or.len() {
                        rows.push(DiffRow {
                            left: Cell::del(or.start + k + 1, lv[or.start + k]),
                            right: Cell::empty(),
                        });
                    }
                }
                DiffTag::Insert => {
                    added += nr.len();
                    for k in 0..nr.len() {
                        rows.push(DiffRow {
                            left: Cell::empty(),
                            right: Cell::ins(nr.start + k + 1, rv[nr.start + k]),
                        });
                    }
                }
                DiffTag::Replace => {
                    removed += or.len();
                    added += nr.len();
                    for k in 0..or.len().max(nr.len()) {
                        rows.push(DiffRow {
                            left: (k < or.len())
                                .then(|| Cell::del(or.start + k + 1, lv[or.start + k]))
                                .unwrap_or_else(Cell::empty),
                            right: (k < nr.len())
                                .then(|| Cell::ins(nr.start + k + 1, rv[nr.start + k]))
                                .unwrap_or_else(Cell::empty),
                        });
                    }
                }
            }
        }
    }
    (rows, added, removed, false)
}

/// Test hook around `compute_rows`.
pub fn compute_rows_for_test(left: &str, right: &str) -> (Vec<DiffRow>, usize, usize, bool) {
    compute_rows(left, right)
}

pub fn show(ui: &mut egui::Ui, c: &mut ComparerUi) {
    // Snapshot + live diff. The snapshots decouple the row data from the
    // mutable text fields so edit panes can borrow them while rendering.
    let left_snap = c.left.clone();
    let right_snap = c.right.clone();
    let (rows, added, removed, truncated) = compute_rows(&left_snap, &right_snap);

    let ComparerUi {
        left,
        right,
        split_frac,
        vsplit,
        ..
    } = c;

    // ---- Toolbar: live stats + swap/clear ----
    ui.horizontal(|ui| {
        ui.label(
            RichText::new("Data compare")
                .size(13.0)
                .strong()
                .color(theme::TEXT_BRIGHT),
        );
        ui.add_space(8.0);
        ui.label(
            RichText::new(format!("+{added}"))
                .color(theme::SUCCESS)
                .strong(),
        );
        ui.label(
            RichText::new(format!("-{removed}"))
                .color(theme::DANGER)
                .strong(),
        );
        if truncated {
            theme::hint(ui, "(text too large for diff — showing plain view)");
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if theme::button(ui, true, "Clear", ButtonKind::Secondary).clicked() {
                left.clear();
                right.clear();
            }
            ui.add_space(4.0);
            if theme::button(ui, true, "Swap", ButtonKind::Secondary).clicked() {
                std::mem::swap(left, right);
            }
        });
    });
    ui.add_space(6.0);

    // ---- Column geometry (shared by the editors and the diff table) ----
    let handle_w = 6.0;
    let usable = (ui.available_width() - handle_w).max(1.0);
    let min_frac = (140.0 / usable).min(0.45);
    let f = if min_frac < 1.0 - min_frac {
        split_frac.clamp(min_frac, 1.0 - min_frac)
    } else {
        0.5
    };
    let left_w = usable * f;
    let right_w = usable - left_w;

    // ---- Vertical zones: editors on top, live diff below ----
    let body_h = ui.available_height().max(300.0);
    let v = vsplit.clamp(0.15, 0.85);
    *vsplit = v;
    let header_h = 24.0;
    let edit_h = (body_h * v - header_h - 6.0).max(120.0);

    // Pane titles + draggable vertical divider.
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        pane_title(ui, left_w, "Original", left.len());

        let (hrect, hresp) =
            ui.allocate_exact_size(Vec2::new(handle_w, header_h), egui::Sense::drag());
        let hresp = hresp.on_hover_cursor(egui::CursorIcon::ResizeHorizontal);
        let color = if hresp.hovered() || hresp.dragged() {
            theme::ACCENT
        } else {
            theme::STROKE
        };
        let x = hrect.center().x;
        ui.painter().line_segment(
            [Pos2::new(x, hrect.top()), Pos2::new(x, hrect.bottom())],
            Stroke::new(1.0, color),
        );
        if hresp.dragged() {
            *split_frac = (f + hresp.drag_delta().x / usable).clamp(min_frac, 1.0 - min_frac);
        }

        pane_title(ui, right_w, "Modified", right.len());
    });
    ui.add_space(2.0);

    // Both editors are always visible and fill their zone completely; text
    // longer than the box scrolls inside it.
    theme::h_split_panes(
        ui,
        split_frac,
        edit_h,
        |ui| {
            editor_pane(ui, left, "comparer_left", edit_h);
        },
        |ui| {
            editor_pane(ui, right, "comparer_right", edit_h);
        },
    );

    // Draggable horizontal divider between the editors and the diff table.
    let (drect, dresp) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 6.0), egui::Sense::drag());
    let dresp = dresp.on_hover_cursor(egui::CursorIcon::ResizeVertical);
    let color = if dresp.hovered() || dresp.dragged() {
        theme::ACCENT
    } else {
        theme::STROKE
    };
    let y = drect.center().y;
    ui.painter().line_segment(
        [Pos2::new(drect.left(), y), Pos2::new(drect.right(), y)],
        Stroke::new(1.0, color),
    );
    if dresp.dragged() {
        *vsplit = (v + dresp.drag_delta().y / body_h).clamp(0.15, 0.85);
    }
    ui.add_space(2.0);

    // Live diff: one aligned row table sharing a single scroll.
    paired_view(ui, &rows, left_w, handle_w, right_w, usable, split_frac);
}

/// One pane title with a byte count.
fn pane_title(ui: &mut egui::Ui, width: f32, title: &str, bytes: usize) {
    ui.allocate_ui_with_layout(
        Vec2::new(width, 24.0),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.label(
                RichText::new(title)
                    .size(12.0)
                    .strong()
                    .color(theme::ACCENT),
            );
            ui.label(
                RichText::new(crate::ui::proxy::format_bytes(bytes))
                    .size(11.0)
                    .color(theme::MUTED),
            );
        },
    );
}

/// A full-height editor pane: the TextEdit fills the box exactly; content
/// longer than the box scrolls (never overflows or leaves blank space).
fn editor_pane(ui: &mut egui::Ui, text: &mut String, id: &'static str, zone_h: f32) {
    theme::card_with_margin(ui, 4.0, |ui| {
        let inner = (zone_h - 8.0).max(60.0);
        ui.set_height(inner);
        // Fill the box exactly: rows from the measured monospace line height;
        // content beyond the box scrolls inside it.
        let rows = theme::fill_rows(ui, inner);
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .id_salt(id)
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(text)
                        .id_salt((id, "edit"))
                        .font(egui::TextStyle::Monospace)
                        .desired_width(ui.available_width())
                        .desired_rows(rows),
                );
            });
    });
}

/// Aligned side-by-side diff table with a draggable column divider in the
/// row gap.
fn paired_view(
    ui: &mut egui::Ui,
    rows: &[DiffRow],
    left_w: f32,
    handle_w: f32,
    right_w: f32,
    usable: f32,
    split_frac: &mut f32,
) {
    if rows.is_empty() {
        theme::empty_state(
            ui,
            &theme::EmptyState::new(
                "Nothing to compare",
                "Type or paste text in the editors above — the diff renders live.",
            ),
        );
        return;
    }
    ScrollArea::vertical()
        .auto_shrink([false, false])
        .id_salt("comparer_paired")
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            let shown = rows.len().min(MAX_RENDER_ROWS);
            for row in &rows[..shown] {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    paint_cell(ui, left_w, &row.left);

                    // The row gap doubles as a draggable column divider.
                    let (grect, gresp) =
                        ui.allocate_exact_size(Vec2::new(handle_w, LINE_H), egui::Sense::drag());
                    let gresp = gresp.on_hover_cursor(egui::CursorIcon::ResizeHorizontal);
                    let color = if gresp.hovered() || gresp.dragged() {
                        theme::ACCENT
                    } else {
                        theme::STROKE
                    };
                    ui.painter().line_segment(
                        [
                            Pos2::new(grect.center().x, grect.top()),
                            Pos2::new(grect.center().x, grect.bottom()),
                        ],
                        Stroke::new(1.0, color),
                    );
                    if gresp.dragged() {
                        *split_frac = (*split_frac + gresp.drag_delta().x / usable).clamp(0.1, 0.9);
                    }

                    paint_cell(ui, right_w, &row.right);
                });
            }
            if rows.len() > shown {
                ui.label(
                    RichText::new(format!("… {} more lines not rendered", rows.len() - shown))
                        .size(11.5)
                        .color(theme::MUTED),
                );
            }
        });
}

/// Paint one diff cell: line number gutter, +/− sign, content; coloured row
/// background for deletions/insertions, hatched padding for empty cells.
fn paint_cell(ui: &mut egui::Ui, width: f32, cell: &Cell) {
    let (rect, resp) =
        ui.allocate_exact_size(Vec2::new(width.max(0.0), LINE_H), egui::Sense::hover());
    let painter = ui.painter();

    match cell.kind {
        CellKind::Del => {
            painter.rect_filled(rect, 0.0, DEL_BG);
        }
        CellKind::Ins => {
            painter.rect_filled(rect, 0.0, INS_BG);
        }
        CellKind::Empty => {
            // Diagonal hatch, clipped to the cell — the "missing line" padding.
            let hp = painter.with_clip_rect(rect);
            let stroke = Stroke::new(1.0, Color32::from_rgba_unmultiplied(255, 255, 255, 10));
            let mut x = rect.left() - rect.height();
            while x < rect.right() {
                hp.line_segment(
                    [
                        Pos2::new(x, rect.bottom()),
                        Pos2::new(x + rect.height(), rect.top()),
                    ],
                    stroke,
                );
                x += 8.0;
            }
        }
        CellKind::Same => {
            if resp.hovered() {
                painter.rect_filled(rect, 0.0, theme::CARD_HOVER);
            }
        }
    }

    let cy = rect.center().y;
    if cell.no > 0 {
        painter.text(
            Pos2::new(rect.left() + GUTTER_W - 6.0, cy),
            Align2::RIGHT_CENTER,
            format!("{:>4}", cell.no),
            FontId::monospace(11.0),
            theme::MUTED,
        );
    }
    let (sign, color) = match cell.kind {
        CellKind::Del => ("−", theme::DANGER),
        CellKind::Ins => ("+", theme::SUCCESS),
        _ => (" ", theme::MUTED),
    };
    painter.text(
        Pos2::new(rect.left() + GUTTER_W + SIGN_W * 0.5, cy),
        Align2::CENTER_CENTER,
        sign,
        FontId::monospace(12.0),
        color,
    );
    if !cell.text.is_empty() {
        painter.text(
            Pos2::new(rect.left() + GUTTER_W + SIGN_W + 4.0, cy),
            Align2::LEFT_CENTER,
            &cell.text,
            FontId::monospace(12.0),
            theme::TEXT,
        );
    }

    resp.context_menu(|ui| {
        ui.set_min_width(140.0);
        if cell.no > 0
            && ui
                .selectable_label(false, RichText::new("Copy line").size(12.5))
                .clicked()
        {
            ui.ctx().copy_text(cell.text.clone());
        }
    });
}
