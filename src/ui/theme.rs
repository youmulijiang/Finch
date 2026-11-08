//! Finch visual theme: a compact dark "modern editor" look with a single
//! accent colour, plus the small set of custom widgets used across the tabs
//! (underline tabs, segmented control, iOS-style toggle, three button tiers,
//! cards and empty states).
//!
//! Keeping these in one place means every tab shares the same visual rules:
//! no horizontal separators, weak 1px card outlines, 8px gaps.

use std::sync::Arc;

use egui::{
    Color32, CornerRadius, CursorIcon, FontId, Galley, Margin, Response, RichText, Sense, Stroke,
    StrokeKind, TextWrapMode, Ui, Vec2, WidgetText,
};

// ---------------------------------------------------------------- palette

/// App background (window/canvas).
pub const BG: Color32 = Color32::from_rgb(0x14, 0x16, 0x1b);
/// Raised surfaces: cards, panels, segmented container.
pub const CARD: Color32 = Color32::from_rgb(0x18, 0x1b, 0x21);
/// Slightly raised card (hover, table header row).
pub const CARD_HOVER: Color32 = Color32::from_rgb(0x1e, 0x20, 0x27);
/// Weak 1px outline used on cards and controls.
pub const STROKE: Color32 = Color32::from_rgb(0x26, 0x2a, 0x33);
/// Stronger outline for hovered controls.
pub const STROKE_STRONG: Color32 = Color32::from_rgb(0x3a, 0x41, 0x50);
/// Primary body text.
pub const TEXT: Color32 = Color32::from_rgb(0xc8, 0xcd, 0xd6);
/// Selected / hovered text.
pub const TEXT_BRIGHT: Color32 = Color32::from_rgb(0xed, 0xf0, 0xf5);
/// Secondary / auxiliary text (headers, hints, status bar info).
pub const MUTED: Color32 = Color32::from_rgb(0x7f, 0x86, 0x94);
/// Disabled text.
pub const DIM: Color32 = Color32::from_rgb(0x50, 0x55, 0x60);

/// Accent (primary actions, selected indicators).
pub const ACCENT: Color32 = Color32::from_rgb(0x6c, 0x9e, 0xff);
pub const ACCENT_HOVER: Color32 = Color32::from_rgb(0x84, 0xb0, 0xff);
pub const ACCENT_PRESSED: Color32 = Color32::from_rgb(0x5a, 0x8a, 0xe6);
/// Accent at 12% for segmented-control selection.
pub const ACCENT_SOFT: Color32 = Color32::from_rgba_premultiplied(13, 19, 31, 0x1f);
/// Accent at 15% for selected table rows.
pub const ACCENT_ROW: Color32 = Color32::from_rgba_premultiplied(16, 24, 38, 0x26);
/// Text on top of an accent fill.
pub const ON_ACCENT: Color32 = Color32::from_rgb(0x10, 0x13, 0x18);

pub const DANGER: Color32 = Color32::from_rgb(0xf0, 0x71, 0x78);
pub const SUCCESS: Color32 = Color32::from_rgb(0x7d, 0xd3, 0xa0);
pub const WARNING: Color32 = Color32::from_rgb(0xe0, 0xaf, 0x68);

/// The product mark, reused as the empty-state icon.
pub const LOGO: &str = "🦜";

// ---------------------------------------------------------------- theme

/// Install the Finch look on the egui context (call once at startup).
pub fn apply(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);

    let mut v = egui::Visuals::dark();
    v.panel_fill = BG;
    v.window_fill = CARD;
    v.extreme_bg_color = Color32::from_rgb(0x10, 0x12, 0x16);
    v.faint_bg_color = Color32::from_rgb(0x1e, 0x20, 0x27); // zebra rows (#1E2027)
    v.window_stroke = Stroke::new(1.0, STROKE);
    v.window_corner_radius = CornerRadius::same(10);
    v.menu_corner_radius = CornerRadius::same(8);
    v.hyperlink_color = ACCENT;
    v.warn_fg_color = WARNING;
    v.error_fg_color = DANGER;
    v.selection.bg_fill = Color32::from_rgba_premultiplied(32, 47, 76, 0x4d);
    v.selection.stroke = Stroke::new(1.0, ACCENT);

    v.widgets.noninteractive.bg_fill = CARD;
    v.widgets.noninteractive.weak_bg_fill = CARD;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, STROKE);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    v.widgets.noninteractive.corner_radius = CornerRadius::same(6);

    v.widgets.inactive.bg_fill = Color32::from_rgb(0x1c, 0x1f, 0x26);
    v.widgets.inactive.weak_bg_fill = Color32::from_rgb(0x1c, 0x1f, 0x26);
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, STROKE);
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    v.widgets.inactive.corner_radius = CornerRadius::same(6);

    v.widgets.hovered.bg_fill = Color32::from_rgb(0x23, 0x28, 0x31);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(0x23, 0x28, 0x31);
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, STROKE_STRONG);
    v.widgets.hovered.fg_stroke = Stroke::new(1.0, TEXT_BRIGHT);
    v.widgets.hovered.corner_radius = CornerRadius::same(6);

    v.widgets.active.bg_fill = Color32::from_rgb(0x2b, 0x31, 0x3c);
    v.widgets.active.weak_bg_fill = Color32::from_rgb(0x2b, 0x31, 0x3c);
    v.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT);
    v.widgets.active.fg_stroke = Stroke::new(1.0, TEXT_BRIGHT);
    v.widgets.active.corner_radius = CornerRadius::same(6);

    v.widgets.open.bg_fill = Color32::from_rgb(0x23, 0x28, 0x31);
    v.widgets.open.weak_bg_fill = Color32::from_rgb(0x23, 0x28, 0x31);
    v.widgets.open.bg_stroke = Stroke::new(1.0, STROKE_STRONG);
    v.widgets.open.fg_stroke = Stroke::new(1.0, TEXT_BRIGHT);
    v.widgets.open.corner_radius = CornerRadius::same(6);

    ctx.set_visuals_of(egui::Theme::Dark, v.clone());
    // The app is always dark; mirror the palette into the light slot so any
    // system-theme switch can never leak light widgets into the window.
    ctx.set_visuals_of(egui::Theme::Light, v);

    ctx.all_styles_mut(|style| {
        style.visuals.striped = true;
        style.spacing.item_spacing = Vec2::new(8.0, 6.0);
        style.spacing.button_padding = Vec2::new(10.0, 4.0);
        style.spacing.interact_size.y = 24.0;
        style.spacing.scroll.bar_width = 6.0;
        style.spacing.scroll.handle_min_length = 24.0;
        style.spacing.scroll.floating = true;
        style
            .text_styles
            .insert(egui::TextStyle::Body, FontId::proportional(13.0));
        style
            .text_styles
            .insert(egui::TextStyle::Button, FontId::proportional(13.0));
        style
            .text_styles
            .insert(egui::TextStyle::Small, FontId::proportional(11.0));
        style
            .text_styles
            .insert(egui::TextStyle::Heading, FontId::proportional(17.0));
        style
            .text_styles
            .insert(egui::TextStyle::Monospace, FontId::monospace(12.0));
    });
}

// ---------------------------------------------------------------- helpers

fn galley(ui: &Ui, text: &str, size: f32) -> Arc<Galley> {
    WidgetText::from(RichText::new(text).size(size)).into_galley(
        ui,
        Some(TextWrapMode::Extend),
        f32::INFINITY,
        FontId::proportional(size),
    )
}

/// Paint a galley centred in `rect`.
fn paint_centered(ui: &Ui, rect: egui::Rect, galley: &Arc<Galley>, color: Color32) {
    let pos = rect.center() - galley.size() / 2.0;
    ui.painter().galley(pos, galley.clone(), color);
}

fn pointer(resp: &Response) -> Response {
    if resp.hovered() {
        resp.ctx.set_cursor_icon(CursorIcon::PointingHand);
    }
    resp.clone()
}

/// Scale a colour's alpha (used for the unified disabled state).
fn fade(color: Color32, opacity: f32) -> Color32 {
    let a = (color.a() as f32 * opacity).round().clamp(0.0, 255.0) as u8;
    Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), a)
}

// ---------------------------------------------------------------- tabs

/// Flat text tab row with a 2px accent underline under the selected item.
/// Hover changes only the text colour. Returns true when the tab changed.
pub fn underline_tabs<T: PartialEq + Copy>(
    ui: &mut Ui,
    current: &mut T,
    items: &[(T, &str)],
) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 2.0;
        for (value, label) in items {
            let selected = *current == *value;
            let galley = galley(ui, label, 14.0);
            let size = Vec2::new(galley.size().x + 16.0, 30.0);
            let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
            let resp = pointer(&resp);

            let color = if selected {
                TEXT_BRIGHT
            } else if resp.hovered() {
                TEXT
            } else {
                MUTED
            };
            paint_centered(ui, rect, &galley, color);

            if selected {
                let line = egui::Rect::from_min_size(
                    egui::pos2(rect.center().x - galley.size().x / 2.0, rect.bottom() - 2.0),
                    Vec2::new(galley.size().x, 2.0),
                );
                ui.painter().rect_filled(line, 1.0, ACCENT);
            }

            if resp.clicked() && !selected {
                *current = *value;
                changed = true;
            }
        }
    });
    changed
}

/// Segmented control: a stroked rounded container where the selected segment
/// gets a 12% accent fill and accent text. Returns true when the tab changed.
pub fn segmented<T: PartialEq + Copy>(ui: &mut Ui, current: &mut T, items: &[(T, &str)]) -> bool {
    let mut changed = false;
    egui::Frame::new()
        .fill(CARD)
        .corner_radius(8)
        .stroke(Stroke::new(1.0, STROKE))
        .inner_margin(Margin::same(2))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.x = 2.0;
            ui.horizontal(|ui| {
                for (value, label) in items {
                    let selected = *current == *value;
                    let galley = galley(ui, label, 12.5);
                    let size = Vec2::new(galley.size().x + 22.0, 24.0);
                    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
                    let resp = pointer(&resp);

                    let color = if selected {
                        ACCENT
                    } else if resp.hovered() {
                        TEXT_BRIGHT
                    } else {
                        MUTED
                    };

                    if selected {
                        ui.painter().rect_filled(rect, 6.0, ACCENT_SOFT);
                    } else if resp.hovered() {
                        ui.painter().rect_filled(
                            rect,
                            6.0,
                            Color32::from_rgba_unmultiplied(255, 255, 255, 8),
                        );
                    }
                    paint_centered(ui, rect, &galley, color);

                    if resp.clicked() && !selected {
                        *current = *value;
                        changed = true;
                    }
                }
            });
        });
    changed
}

// ---------------------------------------------------------------- toggle

/// iOS-style toggle: 36x20 capsule with an animated knob.
/// Returns true when the user flipped it.
pub fn toggle(ui: &mut Ui, on: &mut bool) -> bool {
    let size = Vec2::new(36.0, 20.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let resp = pointer(&resp);

    let t = ui
        .ctx()
        .animate_bool_with_time(resp.id.with("finch_toggle"), *on, 0.12);
    if t > 0.0 && t < 1.0 {
        ui.ctx().request_repaint();
    }

    let off_track = Color32::from_rgb(0x35, 0x3a, 0x45);
    let track = off_track.lerp_to_gamma(ACCENT, t);
    let radius = rect.height() / 2.0;
    ui.painter().rect_filled(rect, radius, track);

    let knob_x = egui::lerp((rect.left() + 10.0)..=(rect.right() - 10.0), t);
    let knob = egui::pos2(knob_x, rect.center().y);
    ui.painter()
        .circle_filled(knob, 8.0, Color32::from_rgb(0xf5, 0xf7, 0xfa));

    let clicked = resp.clicked();
    if clicked {
        *on = !*on;
        ui.ctx().request_repaint();
    }
    clicked
}

/// Toggle plus an "on/off" label with a coloured dot, used by Intercept.
pub fn toggle_with_state(ui: &mut Ui, on: &mut bool, on_text: &str, off_text: &str) -> bool {
    let changed = toggle(ui, on);
    ui.add_space(2.0);
    let color = if *on { SUCCESS } else { DANGER };
    status_dot(ui, color);
    ui.label(
        RichText::new(if *on { on_text } else { off_text })
            .size(12.5)
            .color(if *on { TEXT } else { MUTED }),
    );
    changed
}

// ---------------------------------------------------------------- buttons

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ButtonKind {
    /// Accent fill with dark text (Forward, Send, Start attack).
    Primary,
    /// Weak outline (Options apply/export actions).
    Secondary,
    /// Red outline (Drop, Drop all, Stop).
    Danger,
}

/// Three-tier button with a unified disabled state (40% opacity).
pub fn button(ui: &mut Ui, enabled: bool, label: &str, kind: ButtonKind) -> Response {
    let galley = galley(ui, label, 13.0);
    let size = Vec2::new(galley.size().x + 24.0, 28.0);
    let (rect, resp) = ui.allocate_exact_size(
        size,
        if enabled {
            Sense::click()
        } else {
            Sense::hover()
        },
    );
    let resp = if enabled {
        pointer(&resp)
    } else {
        resp.clone()
    };

    let hovered = enabled && resp.hovered();
    let pressed = enabled && resp.is_pointer_button_down_on();

    let (fill, stroke, fg) = match kind {
        ButtonKind::Primary => {
            let fill = if pressed {
                ACCENT_PRESSED
            } else if hovered {
                ACCENT_HOVER
            } else {
                ACCENT
            };
            (fill, Stroke::NONE, ON_ACCENT)
        }
        ButtonKind::Secondary => {
            let fill = if pressed {
                Color32::from_rgba_unmultiplied(255, 255, 255, 16)
            } else if hovered {
                Color32::from_rgba_unmultiplied(255, 255, 255, 10)
            } else {
                Color32::TRANSPARENT
            };
            let stroke = Stroke::new(1.0, if hovered { STROKE_STRONG } else { STROKE });
            let fg = if hovered { TEXT_BRIGHT } else { TEXT };
            (fill, stroke, fg)
        }
        ButtonKind::Danger => {
            let fill = if pressed {
                Color32::from_rgba_unmultiplied(240, 113, 120, 32)
            } else if hovered {
                Color32::from_rgba_unmultiplied(240, 113, 120, 20)
            } else {
                Color32::TRANSPARENT
            };
            let stroke = Stroke::new(
                1.0,
                if hovered {
                    DANGER
                } else {
                    DANGER.gamma_multiply(0.6)
                },
            );
            (fill, stroke, DANGER)
        }
    };

    let opacity = if enabled { 1.0 } else { 0.4 };
    let fill = fade(fill, opacity);
    let stroke = Stroke::new(stroke.width, fade(stroke.color, opacity));
    let fg = fade(fg, opacity);

    let painter = ui.painter();
    if fill.a() > 0 {
        painter.rect_filled(rect, 6.0, fill);
    }
    if stroke.width > 0.0 && stroke.color.a() > 0 {
        painter.rect_stroke(rect, 6.0, stroke, StrokeKind::Inside);
    }
    paint_centered(ui, rect, &galley, fg);

    resp
}

// ---------------------------------------------------------------- layout

/// Horizontal two-pane split with a draggable divider (used by Repeater and
/// other side-by-side panes). `frac` is the left pane's fraction of the
/// usable width, stored by the caller so the divider never drifts across
/// frames (a resizable Panel would).
pub fn h_split_panes(
    ui: &mut Ui,
    frac: &mut f32,
    pane_h: f32,
    left: impl FnOnce(&mut Ui),
    right: impl FnOnce(&mut Ui),
) {
    let handle_w = 6.0;
    let usable = (ui.available_width() - handle_w).max(1.0);
    let min_frac = (180.0 / usable).min(0.45);
    let f = frac.clamp(min_frac, 1.0 - min_frac);
    let left_w = usable * f;
    let right_w = usable - left_w;

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;

        ui.allocate_ui_with_layout(
            Vec2::new(left_w, pane_h),
            egui::Layout::top_down(egui::Align::Min),
            left,
        );

        let (rect, resp) = ui.allocate_exact_size(Vec2::new(handle_w, pane_h), Sense::drag());
        let resp = resp.on_hover_cursor(CursorIcon::ResizeHorizontal);
        let color = if resp.hovered() || resp.dragged() {
            ACCENT
        } else {
            STROKE
        };
        let x = rect.center().x;
        ui.painter().line_segment(
            [egui::pos2(x, rect.top()), egui::pos2(x, rect.bottom())],
            Stroke::new(1.0, color),
        );
        if resp.dragged() {
            *frac = (f + resp.drag_delta().x / usable).clamp(min_frac, 1.0 - min_frac);
        }

        ui.allocate_ui_with_layout(
            Vec2::new(right_w, pane_h),
            egui::Layout::top_down(egui::Align::Min),
            right,
        );
    });
}

/// Vertical two-pane split with a draggable divider (Input/Output in the
/// Decoder's third column). Same drift-free contract as [`h_split_panes`]:
/// `frac` is the top pane's fraction of the usable height, stored by the
/// caller. The two panes together fill the available height.
pub fn v_split_panes(
    ui: &mut Ui,
    frac: &mut f32,
    top: impl FnOnce(&mut Ui),
    bottom: impl FnOnce(&mut Ui),
) {
    let handle_h = 6.0;
    let usable = (ui.available_height() - handle_h).max(1.0);
    let min_frac = (80.0 / usable).min(0.8);
    let f = frac.clamp(min_frac, 1.0 - min_frac);
    let top_h = usable * f;
    let bottom_h = usable - top_h;
    let avail_w = ui.available_width();

    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 0.0;

        ui.allocate_ui_with_layout(
            Vec2::new(avail_w, top_h),
            egui::Layout::top_down(egui::Align::Min),
            top,
        );

        let (rect, resp) = ui.allocate_exact_size(Vec2::new(avail_w, handle_h), Sense::drag());
        let resp = resp.on_hover_cursor(CursorIcon::ResizeVertical);
        let color = if resp.hovered() || resp.dragged() {
            ACCENT
        } else {
            STROKE
        };
        let y = rect.center().y;
        ui.painter().line_segment(
            [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
            Stroke::new(1.0, color),
        );
        if resp.dragged() {
            *frac = (f + resp.drag_delta().y / usable).clamp(min_frac, 1.0 - min_frac);
        }

        ui.allocate_ui_with_layout(
            Vec2::new(avail_w, bottom_h),
            egui::Layout::top_down(egui::Align::Min),
            bottom,
        );
    });
}

/// A card surface: weak 1px outline, 8px radius, no separators needed.
pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    card_with_margin(ui, 12.0, add)
}

pub fn card_with_margin<R>(ui: &mut Ui, margin: f32, add: impl FnOnce(&mut Ui) -> R) -> R {
    // Measure before opening the frame: the frame's content ui can be
    // narrower than the parent (e.g. after right-aligned toolbars), which
    // would otherwise leave tables and form rows short of the card edge.
    let full_width = ui.available_width();
    egui::Frame::new()
        .fill(CARD)
        .corner_radius(8)
        .stroke(Stroke::new(1.0, STROKE))
        .inner_margin(Margin::same(margin as i8))
        .show(ui, |ui| {
            ui.set_min_width((full_width - margin * 2.0).max(0.0));
            add(ui)
        })
        .inner
}

/// Card section title, e.g. "Intercept", "Connection", "TLS".
pub fn card_title(ui: &mut Ui, title: &str) {
    ui.label(RichText::new(title).size(13.0).strong().color(TEXT_BRIGHT));
}

/// Small auxiliary label (hints, table headers).
pub fn hint(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).size(11.5).color(MUTED));
}

/// Height of one 12px monospace text row — used to size multiline editors so
/// they fill their card exactly (see `fill_rows`).
pub fn mono_row_h(ui: &Ui) -> f32 {
    ui.painter()
        .layout_no_wrap("0".to_owned(), FontId::monospace(12.0), TEXT)
        .size()
        .y
}

/// Number of monospace rows that fit `height` pixels (leaving ~14px for the
/// TextEdit frame), so an editor fills its card without overflowing.
pub fn fill_rows(ui: &Ui, height: f32) -> usize {
    (((height - 14.0) / mono_row_h(ui).max(1.0)).floor().max(4.0)) as usize
}

/// Coloured status dot.
pub fn status_dot(ui: &mut Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(10.0, 10.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.0, color);
}

/// Centred empty state: big logo, title, subtitle and at most one CTA.
/// Returns true when the CTA was clicked.
pub struct EmptyState<'a> {
    pub title: &'a str,
    pub subtitle: &'a str,
    /// (label, enabled)
    pub cta: Option<(&'a str, bool)>,
}

impl<'a> EmptyState<'a> {
    pub fn new(title: &'a str, subtitle: &'a str) -> Self {
        Self {
            title,
            subtitle,
            cta: None,
        }
    }

    pub fn with_cta(mut self, label: &'a str, enabled: bool) -> Self {
        self.cta = Some((label, enabled));
        self
    }
}

pub fn empty_state(ui: &mut Ui, state: &EmptyState<'_>) -> bool {
    let mut clicked = false;
    ui.vertical_centered(|ui| {
        let top = ((ui.available_height() - 190.0) * 0.5).max(12.0);
        ui.add_space(top);
        ui.label(RichText::new(LOGO).size(48.0));
        ui.add_space(10.0);
        ui.label(
            RichText::new(state.title)
                .size(16.0)
                .strong()
                .color(TEXT_BRIGHT),
        );
        if !state.subtitle.is_empty() {
            ui.add_space(4.0);
            ui.label(RichText::new(state.subtitle).size(12.5).color(MUTED));
        }
        if let Some((label, enabled)) = state.cta {
            ui.add_space(16.0);
            if button(ui, enabled, label, ButtonKind::Primary).clicked() {
                clicked = true;
            }
        }
    });
    clicked
}
