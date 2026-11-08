//! Intruder tab: Burp-style fuzzing with the four classic attack modes
//! (Sniper, Battering ram, Pitchfork, Cluster bomb).
//!
//! Layout mirrors Burp's Intruder: a left pane (~70%) with the attack-mode
//! bar, Target row, Positions buttons and a highlighted request editor with
//! a status bar; a right pane (~30%) titled "Payloads" with the payload
//! position/type summary, a collapsible "Payload configuration" section and
//! a collapsible "Payload processing" section. Finished attacks open in the
//! results detail window.

use std::sync::Arc;
use std::sync::mpsc;

use egui::{Color32, RichText};
use egui_extras::Column;

use crate::engine::{self, SendResult};
use crate::state::{Scheme, SharedState};
use crate::ui::decoder::{OP_ENTRIES, OpKind, Step, run_pipeline};
use crate::ui::theme::{self, ButtonKind};

// ---------------------------------------------------------------- attack model

/// The four classic Burp Intruder attack modes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AttackMode {
    /// One position at a time cycles through one payload set.
    #[default]
    Sniper,
    /// The same payload goes into every marked position at once.
    BatteringRam,
    /// Position *i* walks payload set *i*; one request per payload index.
    Pitchfork,
    /// Cartesian product of one payload set per position.
    ClusterBomb,
}

impl AttackMode {
    pub const ALL: [AttackMode; 4] = [
        AttackMode::Sniper,
        AttackMode::BatteringRam,
        AttackMode::Pitchfork,
        AttackMode::ClusterBomb,
    ];

    pub fn label(self) -> &'static str {
        match self {
            AttackMode::Sniper => "Sniper attack",
            AttackMode::BatteringRam => "Battering ram",
            AttackMode::Pitchfork => "Pitchfork",
            AttackMode::ClusterBomb => "Cluster bomb",
        }
    }

    /// Number of payload sets this mode consumes (one per position, or one shared).
    fn sets_needed(self, positions: usize) -> usize {
        match self {
            AttackMode::Sniper | AttackMode::BatteringRam => 1,
            AttackMode::Pitchfork | AttackMode::ClusterBomb => positions.max(1),
        }
    }
}

/// One payload list (manual paste or loaded from a dictionary file).
#[derive(Clone, Debug, Default)]
pub struct PayloadSet {
    pub items: Vec<String>,
    /// Display name of the dictionary the set was loaded from, if any.
    pub file: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AttackResult {
    pub index: usize,
    /// Payloads substituted into the marked positions (display form).
    pub payloads: Vec<String>,
    pub result: SendResult,
}

/// One queued/running/finished attack.
pub struct AttackTask {
    pub id: u64,
    pub mode: AttackMode,
    pub https: bool,
    pub authority: String,
    /// Template with § markers (for display / re-loading into the editor).
    pub template: String,
    pub total: usize,
    pub done: Arc<std::sync::atomic::AtomicUsize>,
    pub results: Arc<std::sync::Mutex<Vec<AttackResult>>>,
    pub rx: Option<mpsc::Receiver<AttackResult>>,
    pub stop: Arc<std::sync::atomic::AtomicBool>,
    pub running: bool,
    pub finished: bool,
    pub selected: Option<usize>,
    pub viewer: crate::ui::viewer::MessageView,
}

impl AttackTask {
    fn status_label(&self) -> (&'static str, egui::Color32) {
        if self.running {
            ("Running", theme::ACCENT)
        } else if self.finished {
            ("Finished", theme::SUCCESS)
        } else {
            ("Stopped", theme::WARNING)
        }
    }
}

/// One payload-processing rule (reuses the Decoder op pipeline).
pub type ProcessingRule = Step;

pub struct IntruderUi {
    /// Full target URL, e.g. `http://localhost:80`.
    pub target: String,
    pub update_host: bool,
    /// Raw request with § markers.
    pub template: String,
    pub mode: AttackMode,
    /// Payload sets; Sniper/Battering ram use set 0, Pitchfork/Cluster bomb
    /// use one set per marked position.
    pub sets: Vec<PayloadSet>,
    /// 0 = "All payload positions" (shared set 0); i = position i's set.
    pub payload_position: usize,
    /// Currently edited payload set (derived from payload_position).
    pub active_set: usize,
    /// Only "Simple list" is implemented; kept as an index for the dropdown.
    pub payload_type: usize,
    /// Status-bar search term (counts + highlights matches).
    pub search: String,
    /// Last known editor cursor (for Add § wrapping the selection).
    pub edit_cursor: Option<egui::text::CCursorRange>,
    // --- payload configuration ---
    pub selected_item: Option<usize>,
    pub add_item: String,
    // --- payload processing ---
    pub rules: Vec<ProcessingRule>,
    pub selected_rule: Option<usize>,
    pub rule_edit_open: bool,
    pub rule_edit_idx: usize,
    pub rule_edit_key: String,
    pub rule_edit_iv: String,
    // --- attack queue ---
    pub tasks: Vec<AttackTask>,
    pub active_task: Option<usize>,
    /// Whether the attack-detail popup window is open.
    pub detail_open: bool,
    pub next_task_id: u64,
    /// Left pane width fraction of the workbench split (persistent drag).
    pub split_frac: f32,
}

impl Default for IntruderUi {
    fn default() -> Self {
        Self {
            target: String::new(),
            update_host: true,
            template: String::new(),
            mode: AttackMode::default(),
            sets: Vec::new(),
            payload_position: 0,
            active_set: 0,
            payload_type: 0,
            search: String::new(),
            edit_cursor: None,
            selected_item: None,
            add_item: String::new(),
            rules: Vec::new(),
            selected_rule: None,
            rule_edit_open: false,
            rule_edit_idx: 0,
            rule_edit_key: String::new(),
            rule_edit_iv: String::new(),
            tasks: Vec::new(),
            active_task: None,
            detail_open: false,
            next_task_id: 0,
            split_frac: 0.70,
        }
    }
}

impl IntruderUi {
    pub fn load(&mut self, payload: &crate::ui::TabPayload) {
        self.target = format!(
            "{}://{}",
            if payload.scheme == Scheme::Https {
                "https"
            } else {
                "http"
            },
            payload.authority
        );
        let raw = String::from_utf8_lossy(&payload.raw).to_string();
        self.template = engine::default_payload_markers(&raw);
        self.active_task = None;
        self.detail_open = false;
    }

    /// Extract §-marked positions as (start,end) spans into a marker-free string.
    fn positions(template: &str) -> (String, Vec<(usize, usize)>) {
        let mut clean = String::new();
        let mut spans = Vec::new();
        let parts = template.split('§');
        // parts alternate: outside, inside, outside, inside...
        let mut inside = false;
        for part in parts {
            if inside {
                let start = clean.len();
                clean.push_str(part);
                spans.push((start, clean.len()));
            } else {
                clean.push_str(part);
            }
            inside = !inside;
        }
        // An unclosed trailing `§` would otherwise swallow the rest of the
        // request as one giant payload position; treat that tail as plain text.
        if template.matches('§').count() % 2 == 1 {
            spans.pop();
        }
        (clean, spans)
    }

    /// Grow the payload-set list to what the current mode needs.
    fn sync_set_count(&mut self, positions: usize) {
        let needed = self.mode.sets_needed(positions).max(1);
        while self.sets.len() < needed {
            self.sets.push(PayloadSet::default());
        }
        let new_active = if self.payload_position > 0 {
            (self.payload_position - 1).min(self.sets.len() - 1)
        } else if self.active_set >= self.sets.len() {
            self.sets.len() - 1
        } else {
            self.active_set
        };
        if new_active != self.active_set {
            // Selection is an index into the active set; reset it when the
            // user switches to a different set so Remove never deletes the
            // wrong item.
            self.active_set = new_active;
            self.selected_item = None;
        }
    }
}

/// Payload items backing position `pos` (out-of-range positions reuse the last set).
fn set_items<'a>(sets: &'a [PayloadSet], pos: usize) -> &'a [String] {
    if sets.is_empty() {
        return &[];
    }
    &sets[pos.min(sets.len() - 1)].items
}

/// Total request count for an attack configuration.
fn combo_total(mode: AttackMode, positions: usize, sets: &[PayloadSet]) -> usize {
    if positions == 0 {
        return 0;
    }
    match mode {
        AttackMode::Sniper => set_items(sets, 0).len() * positions,
        AttackMode::BatteringRam => set_items(sets, 0).len(),
        AttackMode::Pitchfork => (0..positions)
            .map(|p| set_items(sets, p).len())
            .min()
            .unwrap_or(0),
        AttackMode::ClusterBomb => (0..positions)
            .map(|p| set_items(sets, p).len())
            .product::<usize>()
            .min(1_000_000), // safety cap on runaway products
    }
}

/// Payloads for combination `idx`: one entry per position, `None` = keep original.
fn combo_payloads(
    mode: AttackMode,
    positions: usize,
    sets: &[PayloadSet],
    idx: usize,
) -> Vec<Option<String>> {
    let mut out: Vec<Option<String>> = vec![None; positions];
    match mode {
        AttackMode::Sniper => {
            let n = set_items(sets, 0).len().max(1);
            let pos = (idx / n).min(positions - 1);
            let j = idx % n;
            // Sniper always uses set 0; a stale set from a previous mode must
            // not be picked up for position > 0.
            if let Some(p) = set_items(sets, 0).get(j) {
                out[pos] = Some(p.clone());
            }
        }
        AttackMode::BatteringRam => {
            if let Some(p) = set_items(sets, 0).get(idx) {
                for slot in out.iter_mut() {
                    *slot = Some(p.clone());
                }
            }
        }
        AttackMode::Pitchfork => {
            for pos in 0..positions {
                if let Some(p) = set_items(sets, pos).get(idx) {
                    out[pos] = Some(p.clone());
                }
            }
        }
        AttackMode::ClusterBomb => {
            let mut rem = idx;
            for pos in 0..positions {
                let items = set_items(sets, pos);
                let n = items.len().max(1);
                if let Some(p) = items.get(rem % n) {
                    out[pos] = Some(p.clone());
                }
                rem /= n;
            }
        }
    }
    out
}

/// Rebuild raw request bytes by substituting payloads into the marked spans.
fn build_request(clean: &str, spans: &[(usize, usize)], payloads: &[Option<String>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(clean.len());
    let mut cursor = 0usize;
    for (i, (start, end)) in spans.iter().enumerate() {
        out.extend_from_slice(&clean.as_bytes()[cursor..*start]);
        match &payloads[i] {
            Some(p) => out.extend_from_slice(p.as_bytes()),
            None => out.extend_from_slice(&clean.as_bytes()[*start..*end]),
        }
        cursor = *end;
    }
    out.extend_from_slice(&clean.as_bytes()[cursor.min(clean.len())..]);
    out
}

/// Replace the `Host` header (or insert one) with `authority`.
fn set_host_header(req: &[u8], authority: &str) -> Vec<u8> {
    let head_end = req
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(req.len());
    let head = String::from_utf8_lossy(&req[..head_end]).to_string();
    let body = &req[head_end..];
    let mut out = Vec::with_capacity(req.len() + authority.len() + 8);
    let mut replaced = false;
    for (i, line) in head.split_inclusive("\r\n").enumerate() {
        if !replaced && line.to_ascii_lowercase().starts_with("host:") {
            out.extend_from_slice(format!("Host: {authority}\r\n").as_bytes());
            replaced = true;
        } else if !replaced && i > 0 && line == "\r\n" {
            out.extend_from_slice(format!("Host: {authority}\r\n\r\n").as_bytes());
            replaced = true;
        } else {
            out.extend_from_slice(line.as_bytes());
        }
    }
    if !replaced {
        out.extend_from_slice(format!("Host: {authority}\r\n").as_bytes());
    }
    out.extend_from_slice(body);
    out
}

/// Parse the Target URL into (https, host:port).
fn parse_target(t: &str) -> (bool, String) {
    let t = t.trim();
    let (https, rest) = if let Some(r) = t.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = t.strip_prefix("http://") {
        (false, r)
    } else {
        (false, t)
    };
    // Drop any path component; authority is host[:port].
    let authority = rest.split('/').next().unwrap_or(rest).to_string();
    (https, authority)
}

// ---------------------------------------------------------------- UI

pub fn show(ui: &mut egui::Ui, shared: &Arc<SharedState>, i: &mut IntruderUi) {
    poll_tasks(shared, i);

    let (clean, spans) = IntruderUi::positions(&i.template);
    // Sync sets first so newly-created empty sets participate in the count.
    i.sync_set_count(spans.len());
    let total = combo_total(i.mode, spans.len(), &i.sets);

    // ---- Left 70% / right 30% split with a draggable divider ----
    let total_w = ui.available_width();
    let handle_w = 6.0;
    let usable = (total_w - handle_w).max(1.0);
    let min_frac = (300.0 / usable).min(0.45);
    let frac = i.split_frac.clamp(min_frac, 1.0 - min_frac);
    let left_w = usable * frac;
    let right_w = usable - left_w;
    let pane_h = ui.available_height().max(200.0);
    let mut new_split = frac;

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;

        let left = ui.allocate_ui_with_layout(
            egui::vec2(left_w, pane_h),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.set_width(left_w);
                draw_left(ui, shared, i, &clean, &spans, total);
            },
        );

        // Draggable divider.
        let (rect, resp) =
            ui.allocate_exact_size(egui::vec2(handle_w, pane_h), egui::Sense::drag());
        let resp = resp.on_hover_cursor(egui::CursorIcon::ResizeHorizontal);
        let color = if resp.hovered() || resp.dragged() {
            theme::ACCENT
        } else {
            theme::STROKE
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
                draw_payloads_panel(ui, shared, i, spans.len(), total);
            },
        );
        let _ = left;
    });
    i.split_frac = new_split;
}

// ------------------------------------------------------------- left column

fn draw_left(
    ui: &mut egui::Ui,
    shared: &Arc<SharedState>,
    i: &mut IntruderUi,
    clean: &str,
    spans: &[(usize, usize)],
    total: usize,
) {
    // ---- Top bar: attack mode dropdown + Start attack ----
    ui.horizontal(|ui| {
        egui::ComboBox::from_id_salt("intruder_mode")
            .width(ui.available_width() - 160.0)
            .selected_text(i.mode.label())
            .show_ui(ui, |ui| {
                for m in AttackMode::ALL {
                    ui.selectable_value(&mut i.mode, m, m.label());
                }
            });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let ready =
                !parse_target(&i.target).1.is_empty() && !i.template.trim().is_empty() && total > 0;
            if theme::button(ui, ready, "▶ Start attack", ButtonKind::Primary).clicked() {
                start_attack(shared, i, clean, spans);
            }
        });
    });
    ui.add_space(6.0);

    // ---- Target row ----
    ui.horizontal(|ui| {
        ui.label(RichText::new("Target").size(12.5).color(theme::TEXT));
        ui.add(
            egui::TextEdit::singleline(&mut i.target)
                .desired_width(ui.available_width() - 230.0)
                .hint_text("http://localhost:80"),
        );
        ui.add_space(6.0);
        ui.checkbox(
            &mut i.update_host,
            RichText::new("Update Host header to match target").size(12.0),
        );
    });
    ui.add_space(6.0);

    // ---- Positions row ----
    ui.horizontal(|ui| {
        ui.label(RichText::new("Positions").size(12.5).color(theme::TEXT));
        ui.add_space(8.0);
        if theme::button(ui, true, "Add §", ButtonKind::Secondary).clicked() {
            add_marker_at_cursor(ui, i);
        }
        if theme::button(
            ui,
            i.template.contains('§'),
            "Clear §",
            ButtonKind::Secondary,
        )
        .clicked()
        {
            i.template = i.template.replace('§', "");
        }
        if theme::button(ui, true, "Auto §", ButtonKind::Secondary).clicked() {
            i.template = engine::default_payload_markers(&i.template.replace('§', ""));
        }
    });
    ui.add_space(6.0);

    // ---- Request editor (fills the space above the status bar) ----
    let editor_h = (ui.available_height() - 40.0).max(120.0);
    theme::card_with_margin(ui, 4.0, |ui| {
        ui.set_height(editor_h);
        let fill = theme::fill_rows(ui, editor_h);
        let search = i.search.clone();
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .id_salt("intruder_template")
            .show(ui, |ui| {
                let mut layouter = |ui: &egui::Ui, buf: &dyn egui::TextBuffer, wrap_width: f32| {
                    let job = highlight_layout(ui, buf.as_str(), wrap_width, &search);
                    ui.painter().layout_job(job)
                };
                let out = egui::TextEdit::multiline(&mut i.template)
                    .id_salt("intruder_template_edit")
                    .font(egui::TextStyle::Monospace)
                    .desired_width(ui.available_width())
                    .desired_rows(fill)
                    .layouter(&mut layouter)
                    .show(ui);
                // Remember the cursor so Add § can wrap the selection.
                i.edit_cursor = out.cursor_range;
            });
    });

    // ---- Status bar: icons, search, highlight/position/length counters ----
    ui.add_space(2.0);
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        ui.add_enabled(false, egui::Button::new(RichText::new("?").size(12.0)));
        ui.add_enabled(false, egui::Button::new(RichText::new("⚙").size(12.0)));
        ui.add_enabled(false, egui::Button::new(RichText::new("←").size(12.0)));
        ui.add_enabled(false, egui::Button::new(RichText::new("→").size(12.0)));
        ui.add(
            egui::TextEdit::singleline(&mut i.search)
                .desired_width(ui.available_width() - 330.0)
                .hint_text("Search"),
        );
        let highlights = if i.search.trim().is_empty() {
            0
        } else {
            count_matches(clean, &i.search)
        };
        ui.label(
            RichText::new(format!("{highlights} highlights"))
                .size(11.5)
                .color(theme::MUTED),
        );
        ui.label(
            RichText::new(format!("{} payload positions", spans.len()))
                .size(11.5)
                .color(theme::MUTED),
        );
        ui.label(
            RichText::new(format!("Length: {}", clean.len()))
                .size(11.5)
                .color(theme::MUTED),
        );
    });

    // ---- Attacks queue (kept from the previous design; collapsible) ----
    egui::CollapsingHeader::new(RichText::new("Attacks").size(12.5))
        .default_open(false)
        .show(ui, |ui| {
            draw_task_queue(ui, i);
        });
    draw_detail_window(ui, i);
}

/// Wrap the editor selection (or insert an empty pair at the cursor) in §.
fn add_marker_at_cursor(_ui: &mut egui::Ui, i: &mut IntruderUi) {
    let Some(range) = i.edit_cursor else {
        return;
    };
    let (a, b) = (range.primary.index.0, range.secondary.index.0);
    let (char_start, char_end) = if a <= b { (a, b) } else { (b, a) };
    let text = &mut i.template;
    // CCursor.index counts characters, not bytes.
    let byte_of = |char_idx: usize| -> usize {
        text.char_indices()
            .nth(char_idx)
            .map(|(byte, _)| byte)
            .unwrap_or(text.len())
    };
    let start = byte_of(char_start);
    let end = byte_of(char_end).max(start);
    if start == end {
        text.insert(start, '§');
        text.insert(end + 1, '§');
    } else {
        text.insert(end, '§');
        text.insert(start, '§');
    }
}

/// True when the given line buffer (including its newline) is blank.
fn trim_eq(chunk: &str) -> bool {
    chunk
        .trim_end_matches([0x0d as char, 0x0a as char])
        .trim()
        .is_empty()
}

/// Count case-insensitive occurrences of `needle` in `haystack`.
fn count_matches(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    let h = haystack.to_lowercase();
    let n = needle.to_lowercase();
    h.matches(&n).count()
}

/// Syntax-highlighted layout for the request editor: request-line method,
/// header names, §payload§ spans (accent) and search matches (orange).
fn highlight_layout(
    ui: &egui::Ui,
    text: &str,
    wrap_width: f32,
    search: &str,
) -> egui::text::LayoutJob {
    use egui::text::LayoutJob;
    let font = egui::TextStyle::Monospace.resolve(ui.style());
    let default_color = ui.style().visuals.text_color();
    let header_color = Color32::from_rgb(0x56, 0x9c, 0xd6);
    let search_color = Color32::from_rgb(0xff, 0xa5, 0x00);

    // Precompute search-match byte ranges.
    let mut match_ranges: Vec<(usize, usize)> = Vec::new();
    if !search.is_empty() {
        let hay = text.to_lowercase();
        let needle = search.to_lowercase();
        let mut from = 0usize;
        while let Some(pos) = hay[from..].find(&needle) {
            let start = from + pos;
            match_ranges.push((start, start + needle.len()));
            from = start + needle.len().max(1);
        }
    }
    let in_match = |idx: usize| match_ranges.iter().any(|(s, e)| idx >= *s && idx < *e);

    let mut job = LayoutJob::default();
    let mut chunk = String::new();
    let mut cur_color = default_color;
    let mut inside_marker = false;

    // Header-name coloring: blue from line start (after the request line)
    // until the ':' of each header line.
    let mut line_is_first = true;
    let mut line_is_header = false;
    let mut after_colon = false;
    let mut col = 0usize;

    for (idx, c) in text.char_indices() {
        let clen = c.len_utf8();
        let color = {
            if c == '§' || inside_marker {
                theme::ACCENT
            } else if in_match(idx) {
                search_color
            } else if line_is_first {
                // Method token of the request line.
                if col == 0 {
                    if let Some(sp) = text[idx..].find(' ') {
                        if idx < sp {
                            header_color
                        } else {
                            default_color
                        }
                    } else {
                        default_color
                    }
                } else {
                    default_color
                }
            } else if !line_is_first && line_is_header && !after_colon {
                if c == ':' { header_color } else { header_color }
            } else {
                default_color
            }
        };
        if c == '\n' {
            chunk.push(c);
            line_is_first = false;
            // Blank line ends the header block (body lines stay default).
            line_is_header = !trim_eq(&chunk);
            after_colon = false;
            col = 0;
            continue;
        }
        if c == '§' {
            inside_marker = !inside_marker;
        }
        if c == ':' && line_is_header && !after_colon {
            after_colon = true;
        }
        if color != cur_color {
            let fmt = egui::TextFormat::simple(font.clone(), cur_color);
            job.append(chunk.as_str(), 0.0, fmt);
            cur_color = color;
        }
        chunk.push(c);
        col += 1;
        let _ = clen;
    }
    let fmt = egui::TextFormat::simple(font, cur_color);
    job.append(&chunk, 0.0, fmt);
    job.wrap = egui::text::TextWrapping {
        max_width: wrap_width,
        ..Default::default()
    };
    job
}

// ----------------------------------------------------------- payloads panel

fn draw_payloads_panel(
    ui: &mut egui::Ui,
    shared: &Arc<SharedState>,
    i: &mut IntruderUi,
    positions: usize,
    total: usize,
) {
    ui.label(
        RichText::new("Payloads")
            .size(14.0)
            .strong()
            .color(theme::TEXT_BRIGHT),
    );
    ui.add_space(6.0);

    let set_idx = i.active_set.min(i.sets.len().saturating_sub(1));
    let payload_count = i.sets.get(set_idx).map(|s| s.items.len()).unwrap_or(0);

    // ---- Section 1: position / type / counts ----
    egui::Grid::new("intruder_payload_summary")
        .num_columns(2)
        .spacing([8.0, 5.0])
        .show(ui, |ui| {
            ui.label(RichText::new("Payload position:").size(12.0));
            let selected = if i.payload_position == 0 {
                "All payload positions".to_string()
            } else {
                format!("Payload position {}", i.payload_position)
            };
            egui::ComboBox::from_id_salt("intruder_payload_position")
                .width(ui.available_width() - 16.0)
                .selected_text(selected)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut i.payload_position, 0, "All payload positions");
                    for p in 1..=positions {
                        ui.selectable_value(
                            &mut i.payload_position,
                            p,
                            format!("Payload position {p}"),
                        );
                    }
                });
            ui.end_row();

            ui.label(RichText::new("Payload type:").size(12.0));
            egui::ComboBox::from_id_salt("intruder_payload_type")
                .width(ui.available_width() - 16.0)
                .selected_text("Simple list")
                .show_ui(ui, |ui| {
                    ui.set_min_width(160.0);
                    ui.selectable_value(&mut i.payload_type, 0, "Simple list");
                });
            ui.end_row();

            ui.label(RichText::new("Payload count:").size(12.0));
            ui.label(RichText::new(payload_count.to_string()).size(12.0));
            ui.end_row();

            ui.label(RichText::new("Request count:").size(12.0));
            ui.label(RichText::new(total.to_string()).size(12.0));
            ui.end_row();
        });
    ui.add_space(8.0);

    // ---- Section 2: payload configuration ----
    egui::CollapsingHeader::new(RichText::new("Payload configuration").size(12.5))
        .default_open(true)
        .show(ui, |ui| {
            ui.label(
                RichText::new(
                    "This payload type lets you configure a simple list of strings that are used as payloads.",
                )
                .size(11.5)
                .color(theme::MUTED),
            );
            ui.add_space(6.0);

            let set = &mut i.sets[set_idx];
            ui.horizontal(|ui| {
                // Button column.
                ui.vertical(|ui| {
                    let bw = 110.0;
                    if ui
                        .add_sized([bw, 20.0], egui::Button::new(RichText::new("Paste").size(12.0)))
                        .clicked()
                    {
                        if let Ok(text) = arboard::Clipboard::new().and_then(|mut c| c.get_text())
                        {
                            set.items.extend(
                                text.lines()
                                    .map(|l| l.trim_end_matches('\r').to_string())
                                    .filter(|l| !l.trim().is_empty()),
                            );
                        }
                    }
                    if ui
                        .add_sized([bw, 20.0], egui::Button::new(RichText::new("Load...").size(12.0)))
                        .clicked()
                    {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            match std::fs::read_to_string(&path) {
                                Ok(text) => {
                                    set.items.extend(
                                        text.lines()
                                            .map(|l| l.trim_end_matches('\r').to_string())
                                            .filter(|l| !l.trim().is_empty()),
                                    );
                                    set.file = Some(
                                        path.file_name()
                                            .map(|f| f.to_string_lossy().to_string())
                                            .unwrap_or_else(|| "file".into()),
                                    );
                                }
                                Err(e) => shared.set_status(format!("Load failed: {e}")),
                            }
                        }
                    }
                    let can_remove = i.selected_item.is_some();
                    if ui
                        .add_enabled(
                            can_remove,
                            egui::Button::new(RichText::new("Remove").size(12.0)),
                        )
                        .clicked()
                    {
                        if let Some(sel) = i.selected_item.take() {
                            if sel < set.items.len() {
                                set.items.remove(sel);
                            }
                        }
                    }
                    if ui
                        .add_enabled(
                            !set.items.is_empty(),
                            egui::Button::new(RichText::new("Remove all").size(12.0)),
                        )
                        .clicked()
                    {
                        set.items.clear();
                        set.file = None;
                        i.selected_item = None;
                    }
                    if ui
                        .add_sized([bw, 20.0], egui::Button::new(RichText::new("Clear").size(12.0)))
                        .clicked()
                    {
                        set.items.clear();
                        set.file = None;
                        i.selected_item = None;
                    }
                    if ui
                        .add_sized(
                            [bw, 20.0],
                            egui::Button::new(RichText::new("Deduplicate").size(12.0)),
                        )
                        .clicked()
                    {
                        let mut seen = std::collections::HashSet::new();
                        set.items.retain(|it| seen.insert(it.clone()));
                        i.selected_item = None;
                    }
                });

                // Items list panel: wrapped chips, click to select.
                let list_h = ui.available_height().max(120.0);
                egui::Frame::new()
                    .stroke(egui::Stroke::new(1.0, theme::STROKE))
                    .corner_radius(4.0)
                    .inner_margin(6.0)
                    .show(ui, |ui| {
                        ui.set_height(list_h.min(180.0));
                        // The panel sits inside a `ui.horizontal`; force the
                        // list content back to vertical (one item per row).
                        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .id_salt("intruder_items")
                            .show(ui, |ui| {
                                ui.spacing_mut().item_spacing.y = 2.0;
                                for (idx, item) in set.items.iter().enumerate() {
                                    let selected = i.selected_item == Some(idx);
                                    let w = ui.available_width();
                                    let btn = egui::Button::new(
                                        RichText::new(item).monospace().size(12.0),
                                    )
                                    .fill(if selected {
                                        theme::ACCENT_ROW
                                    } else {
                                        Color32::TRANSPARENT
                                    })
                                    .stroke(egui::Stroke::NONE)
                                    .truncate();
                                    if ui.add_sized([w, 18.0], btn).clicked() {
                                        i.selected_item = Some(idx);
                                    }
                                }
                            });
                        }); // vertical layout
                    });
            });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui
                    .add_sized([110.0, 20.0], egui::Button::new(RichText::new("Add").size(12.0)))
                    .clicked()
                {
                    let item = i.add_item.trim().to_string();
                    if !item.is_empty() {
                        set.items.push(item);
                        i.add_item.clear();
                    }
                }
                ui.add(
                    egui::TextEdit::singleline(&mut i.add_item)
                        .hint_text("Enter a new item")
                        .desired_width(ui.available_width()),
                );
            });
            ui.add_space(4.0);
            egui::ComboBox::from_id_salt("intruder_add_from_list")
                .width(ui.available_width())
                .selected_text("Add from list...")
                .show_ui(ui, |ui| {
                    for (name, list) in builtin_lists() {
                        if ui.selectable_label(false, name).clicked() {
                            let n = list.len();
                            set.items.extend(list);
                            ui.close();
                            shared.set_status(format!("Added {n} payloads from {name}"));
                        }
                    }
                });
        });

    ui.add_space(8.0);

    // ---- Section 3: payload processing ----
    egui::CollapsingHeader::new(RichText::new("Payload processing").size(12.5))
        .default_open(true)
        .show(ui, |ui| {
            ui.label(
                RichText::new(
                    "You can define rules to perform various processing tasks on each payload before it is used.",
                )
                .size(11.5)
                .color(theme::MUTED),
            );
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    let bw = 110.0;
                    if ui
                        .add_sized([bw, 20.0], egui::Button::new(RichText::new("Add").size(12.0)))
                        .clicked()
                    {
                        let kind = OP_ENTRIES
                            .first()
                            .map(|e| e.default)
                            .unwrap_or(OpKind::Base64Encode);
                        i.rules.push(Step::new(kind));
                        i.selected_rule = Some(i.rules.len() - 1);
                    }
                    let has = matches!(i.selected_rule, Some(sel) if sel < i.rules.len());
                    if ui
                        .add_enabled(
                            has,
                            egui::Button::new(RichText::new("Edit").size(12.0)),
                        )
                        .clicked()
                    {
                        if let Some(sel) = i.selected_rule {
                            if let Some(rule) = i.rules.get(sel) {
                                i.rule_edit_idx = OP_ENTRIES
                                    .iter()
                                    .position(|e| e.label == op_label(&rule.kind))
                                    .unwrap_or(0);
                                i.rule_edit_key = rule.params.key.clone();
                                i.rule_edit_iv = rule.params.iv.clone();
                                i.rule_edit_open = true;
                            }
                        }
                    }
                    if ui
                        .add_enabled(
                            has,
                            egui::Button::new(RichText::new("Remove").size(12.0)),
                        )
                        .clicked()
                    {
                        if let Some(sel) = i.selected_rule.take() {
                            if sel < i.rules.len() {
                                i.rules.remove(sel);
                            }
                        }
                    }
                    if ui
                        .add_enabled(has, egui::Button::new(RichText::new("Up").size(12.0)))
                        .clicked()
                    {
                        if let Some(sel) = i.selected_rule {
                            if sel > 0 {
                                i.rules.swap(sel - 1, sel);
                                i.selected_rule = Some(sel - 1);
                            }
                        }
                    }
                });

                // Rules list panel: wrapped chips (checkbox = Enabled).
                let rules_h = ui.available_height().max(90.0);
                egui::Frame::new()
                    .stroke(egui::Stroke::new(1.0, theme::STROKE))
                    .corner_radius(4.0)
                    .inner_margin(6.0)
                    .show(ui, |ui| {
                        ui.set_height(rules_h.min(160.0));
                        // Force vertical layout (panel is inside ui.horizontal).
                        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .id_salt("intruder_rules")
                            .show(ui, |ui| {
                                ui.spacing_mut().item_spacing.y = 2.0;
                                for (idx, rule) in i.rules.iter_mut().enumerate() {
                                    let selected = i.selected_rule == Some(idx);
                                    ui.horizontal(|ui| {
                                        if ui.checkbox(&mut rule.enabled, "").clicked() {
                                            i.selected_rule = Some(idx);
                                        }
                                        let w = ui.available_width();
                                        let btn = egui::Button::new(
                                            RichText::new(op_label(&rule.kind)).size(12.0),
                                        )
                                        .fill(if selected {
                                            theme::ACCENT_ROW
                                        } else {
                                            Color32::TRANSPARENT
                                        })
                                        .stroke(egui::Stroke::NONE)
                                        .truncate();
                                        if ui.add_sized([w, 18.0], btn).clicked() {
                                            i.selected_rule = Some(idx);
                                        }
                                    });
                                }
                            });
                        }); // vertical layout
                    });
            });
        });

    draw_rule_edit_window(ui, i);
}

fn op_label(kind: &OpKind) -> &'static str {
    OP_ENTRIES
        .iter()
        .find(|e| e.default == *kind)
        .map(|e| e.label)
        .unwrap_or("Custom")
}

/// Modal editor for one processing rule.
fn draw_rule_edit_window(ui: &mut egui::Ui, i: &mut IntruderUi) {
    if !i.rule_edit_open {
        return;
    }
    let Some(sel) = i.selected_rule else {
        i.rule_edit_open = false;
        return;
    };
    let Some(rule) = i.rules.get_mut(sel) else {
        i.rule_edit_open = false;
        return;
    };
    let mut open = i.rule_edit_open;
    egui::Window::new(
        RichText::new(format!("Edit rule {}", sel + 1))
            .size(13.0)
            .strong(),
    )
    .open(&mut open)
    .default_width(420.0)
    .show(ui.ctx(), |ui| {
        egui::Grid::new("intruder_rule_edit")
            .num_columns(2)
            .spacing([8.0, 5.0])
            .show(ui, |ui| {
                ui.label(RichText::new("Rule type").size(12.0));
                egui::ComboBox::from_id_salt("intruder_rule_kind")
                    .selected_text(op_label(&rule.kind))
                    .width(240.0)
                    .show_ui(ui, |ui| {
                        for (idx, entry) in OP_ENTRIES.iter().enumerate() {
                            if ui
                                .selectable_label(i.rule_edit_idx == idx, entry.label)
                                .clicked()
                            {
                                i.rule_edit_idx = idx;
                            }
                        }
                    });
                ui.end_row();

                let needs_key = OP_ENTRIES[i.rule_edit_idx].default.needs_key();
                if needs_key {
                    ui.label(RichText::new("Key").size(12.0));
                    ui.add(egui::TextEdit::singleline(&mut i.rule_edit_key).desired_width(240.0));
                    ui.end_row();
                }
                if OP_ENTRIES[i.rule_edit_idx].default.needs_iv() {
                    ui.label(RichText::new("IV / nonce").size(12.0));
                    ui.add(egui::TextEdit::singleline(&mut i.rule_edit_iv).desired_width(240.0));
                    ui.end_row();
                }
            });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if theme::button(ui, true, "Save", ButtonKind::Primary).clicked() {
                if let Some(entry) = OP_ENTRIES.get(i.rule_edit_idx) {
                    rule.kind = entry.default;
                }
                rule.params.key = i.rule_edit_key.clone();
                rule.params.iv = i.rule_edit_iv.clone();
                i.rule_edit_open = false;
            }
            if theme::button(ui, true, "Cancel", ButtonKind::Secondary).clicked() {
                i.rule_edit_open = false;
            }
        });
    });
    i.rule_edit_open = open;
}

/// Built-in dictionaries for "Add from list...". Returns (name, items).
fn builtin_lists() -> Vec<(&'static str, Vec<String>)> {
    vec![
        ("Numbers 1-100", (1..=100).map(|n| n.to_string()).collect()),
        (
            "Common params",
            [
                "admin", "id", "user", "page", "q", "debug", "redirect", "url", "token", "file",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        ),
        (
            "SQLi basics",
            [
                "' OR '1'='1",
                "1' ORDER BY 1--",
                "1;DROP TABLE users",
                "admin'--",
                "' UNION SELECT NULL--",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        ),
        (
            "XSS basics",
            [
                "<script>alert(1)</script>",
                "<svg src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<img src=x onerror=alert(1)>",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        ),
        (
            "Common dirs",
            [
                "admin", "backup", "config", "debug", ".git", "wp-admin", "api", "test", "old",
                "dev",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        ),
    ]
}

// ------------------------------------------------------------- attack queue

/// Drain finished results from every running attack task.
fn poll_tasks(shared: &Arc<SharedState>, i: &mut IntruderUi) {
    for task in i.tasks.iter_mut() {
        let mut disconnected = false;
        if let Some(rx) = &task.rx {
            loop {
                match rx.try_recv() {
                    Ok(res) => {
                        task.results.lock().unwrap().push(res);
                        task.done.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        shared.wake();
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }
        if disconnected {
            task.rx = None;
            task.running = false;
            // A manually stopped attack must not be reported as "Finished".
            task.finished = !task.stop.load(std::sync::atomic::Ordering::Relaxed);
        }
    }
}

fn draw_task_queue(ui: &mut egui::Ui, i: &mut IntruderUi) {
    ui.horizontal(|ui| {
        let has_task = i.active_task.is_some();
        if theme::button(ui, has_task, "Details", ButtonKind::Primary).clicked() {
            i.detail_open = true;
        }
        if theme::button(ui, has_task, "Stop", ButtonKind::Danger).clicked() {
            if let Some(t) = i.active_task.and_then(|idx| i.tasks.get_mut(idx)) {
                // Only raise the flag; poll_tasks flips running/finished when
                // the worker actually winds down.
                t.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        }
        if theme::button(ui, has_task, "Remove", ButtonKind::Secondary).clicked() {
            if let Some(idx) = i.active_task {
                if i.tasks[idx].finished {
                    i.tasks.remove(idx);
                    i.active_task = None;
                    i.detail_open = false;
                }
            }
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let running = i.tasks.iter().filter(|t| t.running).count();
            ui.label(
                RichText::new(format!("{} task(s), {running} running", i.tasks.len()))
                    .size(11.5)
                    .color(theme::MUTED),
            );
        });
    });
    ui.add_space(2.0);

    theme::card_with_margin(ui, 8.0, |ui| {
        ui.set_min_height(120.0);
        if i.tasks.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(24.0);
                ui.label(
                    RichText::new(
                        "No attacks yet — configure the template and payloads above, then Start attack.",
                    )
                    .size(12.0)
                    .color(theme::MUTED),
                );
            });
            return;
        }
        egui_extras::TableBuilder::new(ui)
            .id_salt("intruder_tasks")
            .striped(true)
            .vscroll(true)
            .sense(egui::Sense::click())
            .column(Column::initial(50.0))
            .column(Column::initial(110.0))
            .column(Column::initial(180.0).resizable(true))
            .column(Column::initial(110.0))
            .column(Column::remainder().at_least(80.0))
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .header(22.0, |mut h| {
                for name in ["#", "Mode", "Target", "Progress", "Status"] {
                    h.col(|ui| {
                        ui.label(RichText::new(name).size(11.0).color(theme::MUTED));
                    });
                }
            })
            .body(|mut body| {
                for (idx, task) in i.tasks.iter().enumerate().rev() {
                    body.row(22.0, |mut row| {
                        row.set_selected(i.active_task == Some(idx));
                        let (status, color) = task.status_label();
                        let done = task.done.load(std::sync::atomic::Ordering::Relaxed);
                        row.col(|ui| {
                            ui.monospace(format!("#{}", task.id));
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(task.mode.label()).size(12.0));
                        });
                        row.col(|ui| {
                            let scheme = if task.https { "https" } else { "http" };
                            ui.add(
                                egui::Label::new(
                                    RichText::new(format!("{scheme}://{}", task.authority))
                                        .size(12.0),
                                )
                                .truncate(),
                            );
                        });
                        row.col(|ui| {
                            ui.monospace(format!("{done}/{}", task.total));
                        });
                        row.col(|ui| {
                            ui.label(RichText::new(status).size(12.0).color(color));
                        });
                        if row.response().clicked() {
                            i.active_task = Some(idx);
                        }
                        if row.response().double_clicked() {
                            i.active_task = Some(idx);
                            i.detail_open = true;
                        }
                    });
                }
            });
    });
}

/// Popup panel (egui Window) showing the selected attack's results in detail.
fn draw_detail_window(ui: &mut egui::Ui, i: &mut IntruderUi) {
    if !i.detail_open {
        return;
    }
    let Some(idx) = i.active_task else {
        i.detail_open = false;
        return;
    };
    let Some(task) = i.tasks.get_mut(idx) else {
        i.detail_open = false;
        return;
    };

    let (status, color) = task.status_label();
    let mut open = i.detail_open;
    let mut selected = task.selected;
    let results = task.results.clone();
    let stop = task.stop.clone();
    let running = task.running;
    let title = format!(
        "Attack #{} — {} — {}://{} — {}",
        task.id,
        task.mode.label(),
        if task.https { "https" } else { "http" },
        task.authority,
        status
    );

    egui::Window::new(RichText::new(title).size(13.5).strong())
        .open(&mut open)
        .default_size([980.0, 620.0])
        .show(ui.ctx(), |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("{} responses", results.lock().unwrap().len()))
                        .size(11.5)
                        .color(theme::MUTED),
                );
                if running {
                    ui.spinner();
                }
                if theme::button(ui, running, "Stop attack", ButtonKind::Danger).clicked() {
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(status).size(12.0).color(color));
                });
            });
            ui.add_space(4.0);

            let guard = results.lock().unwrap();
            egui_extras::TableBuilder::new(ui)
                .id_salt(("intruder_results", task.id))
                .striped(true)
                .vscroll(true)
                .sense(egui::Sense::click())
                .column(Column::initial(46.0))
                .column(Column::remainder().at_least(120.0).resizable(true))
                .column(Column::initial(56.0))
                .column(Column::initial(70.0))
                .column(Column::initial(64.0))
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .header(22.0, |mut h| {
                    for name in ["#", "Payload", "Status", "Length", "Time"] {
                        h.col(|ui| {
                            ui.label(RichText::new(name).size(11.0).color(theme::MUTED));
                        });
                    }
                })
                .body(|mut body| {
                    for (row_idx, r) in guard.iter().enumerate() {
                        body.row(22.0, |mut row| {
                            row.set_selected(selected == Some(row_idx));
                            row.col(|ui| {
                                ui.monospace(format!("{}", r.index));
                            });
                            row.col(|ui| {
                                let shown = r
                                    .payloads
                                    .iter()
                                    .map(|p| p.replace('\r', "\\r").replace('\n', "\\n"))
                                    .collect::<Vec<_>>()
                                    .join(" | ");
                                ui.label(shown);
                            });
                            row.col(|ui| {
                                if let Some(st) = r.result.status {
                                    ui.label(
                                        RichText::new(st.to_string())
                                            .color(crate::ui::proxy::status_color(st)),
                                    );
                                } else {
                                    ui.label(RichText::new("ERR").color(theme::DANGER));
                                }
                            });
                            row.col(|ui| {
                                ui.monospace(crate::ui::proxy::format_bytes(r.result.body.len()));
                            });
                            row.col(|ui| {
                                ui.monospace(format!("{}ms", r.result.duration_ms));
                            });
                            if row.response().clicked() {
                                selected = Some(row_idx);
                            }
                        });
                    }
                });

            if let Some(sel) = selected {
                if let Some(r) = guard.get(sel) {
                    ui.add_space(6.0);
                    let raw = r.result.to_raw();
                    if r.result.status.is_none() {
                        ui.label(
                            RichText::new(
                                r.result
                                    .error
                                    .clone()
                                    .unwrap_or_else(|| "request failed".into()),
                            )
                            .color(theme::DANGER),
                        );
                    }
                    task.viewer.sync(&raw);
                    task.viewer.show(
                        ui,
                        egui::Id::unique("intruder_detail_resp")
                            .with(task.id)
                            .with(sel),
                        &raw,
                    );
                }
            }
        });

    task.selected = selected;
    i.detail_open = open;
}

// ---------------------------------------------------------------- execution

/// Apply the enabled processing rules to one payload string.
fn apply_processing(rules: &[ProcessingRule], payloads: &mut [Option<String>]) {
    let enabled: Vec<Step> = rules.iter().filter(|r| r.enabled).cloned().collect();
    if enabled.is_empty() {
        return;
    }
    for slot in payloads.iter_mut().flatten() {
        let results = run_pipeline(slot.as_bytes(), &enabled);
        if let Some(last) = results.last() {
            if last.error.is_none() {
                *slot = String::from_utf8_lossy(&last.data).to_string();
            }
        }
    }
}

fn start_attack(
    shared: &Arc<SharedState>,
    i: &mut IntruderUi,
    clean: &str,
    spans: &[(usize, usize)],
) {
    if spans.is_empty() {
        return;
    }
    let mode = i.mode;
    let sets = i.sets.clone();
    let total = combo_total(mode, spans.len(), &sets);
    if total == 0 {
        return;
    }
    let (https, authority) = parse_target(&i.target);
    if authority.is_empty() {
        return;
    }
    let update_host = i.update_host;
    let rules = i.rules.clone();

    let scheme = if https { "https" } else { "http" }.to_string();
    let concurrency = shared.settings.lock().unwrap().attack_concurrency.max(1);
    let clean = clean.to_string();
    let spans = spans.to_vec();

    let (tx, rx) = mpsc::channel();
    let task = AttackTask {
        id: i.next_task_id,
        mode,
        https,
        authority: authority.clone(),
        template: i.template.clone(),
        total,
        done: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        results: Arc::new(std::sync::Mutex::new(Vec::new())),
        rx: Some(rx),
        stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        running: true,
        finished: false,
        selected: None,
        viewer: crate::ui::viewer::MessageView::new(false),
    };
    i.next_task_id += 1;
    i.tasks.push(task);
    i.active_task = Some(i.tasks.len() - 1);

    let stop = i.tasks.last().unwrap().stop.clone();

    crate::app::runtime().spawn(async move {
        let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let mut handles = Vec::new();
        'outer: for idx in 0..total {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                break 'outer;
            }
            let mut payloads = combo_payloads(mode, spans.len(), &sets, idx);
            apply_processing(&rules, &mut payloads);
            let mut bytes = build_request(&clean, &spans, &payloads);
            if update_host {
                bytes = set_host_header(&bytes, &authority);
            }
            // Display form: position-tagged payloads that were substituted.
            let labels: Vec<String> = payloads
                .iter()
                .zip(spans.iter())
                .filter_map(|(p, (s, _))| p.as_ref().map(|v| format!("§{s}§ {v}")))
                .collect();

            let permit = sem.clone().acquire_owned().await;
            let tx = tx.clone();
            let scheme = scheme.clone();
            let authority = authority.clone();
            let handle = tokio::spawn(async move {
                let _permit = permit;
                let res = engine::send_raw(
                    &scheme,
                    &authority,
                    &bytes,
                    std::time::Duration::from_secs(20),
                )
                .await;
                let _ = tx.send(AttackResult {
                    index: idx,
                    payloads: labels,
                    result: res,
                });
            });
            handles.push(handle);
        }
        drop(tx);
        for h in handles {
            let _ = h.await;
        }
    });
}
