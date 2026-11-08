//! UI module: Burp-like tab layout.

pub mod ai;
pub mod comparer;
pub mod decoder;
pub mod intruder;
pub mod mcp;
pub mod notes;
pub mod proxy;
pub mod repeater;
pub mod settings;
pub mod target;
pub mod theme;
pub mod viewer;
pub mod websocket;

use crate::state::Scheme;
use crate::ui::viewer::PaneAction;

/// Data passed when "Send to ..." is used.
pub struct TabPayload {
    pub scheme: Scheme,
    pub authority: String,
    pub raw: Vec<u8>,
}

/// One-shot cross-tab actions, consumed by the app each frame.
#[derive(Default)]
pub struct Actions {
    pub to_repeater: Option<TabPayload>,
    pub to_intruder: Option<TabPayload>,
    pub to_decoder: Option<TabPayload>,
    pub to_comparer: Option<TabPayload>,
}

impl Actions {
    /// Translate a viewer pane menu action into a cross-tab action.
    pub fn send_pane(
        &mut self,
        action: PaneAction,
        scheme: Scheme,
        authority: String,
        raw: Vec<u8>,
    ) {
        let payload = TabPayload {
            scheme,
            authority,
            raw,
        };
        match action {
            PaneAction::SendToRepeater => self.to_repeater = Some(payload),
            PaneAction::SendToIntruder => self.to_intruder = Some(payload),
            PaneAction::SendToDecoder => self.to_decoder = Some(payload),
            PaneAction::SendToComparer => self.to_comparer = Some(payload),
        }
    }
}
