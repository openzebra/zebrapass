//! Single lines of the share screen that depend on what is saved or heard.

use local::Offer;
use ratatui::text::{Line, Span};

use crate::app::flows::unlocked::Unlocked;
use crate::ui::screens::sync::INDENT;
use crate::ui::theme::Theme;

/// What the hold toggle does now, and its key.
pub(super) fn hold_gloss(state: &Unlocked) -> &'static str {
    if state
        .info
        .prefs
        .as_ref()
        .is_some_and(|prefs| prefs.p2p_hold)
    {
        "announced  ·  t stops  ·  v adds"
    } else {
        "t announces me  ·  v adds"
    }
}

pub(super) fn observed_line(state: &Unlocked, theme: &Theme) -> Option<Line<'static>> {
    let (text, style) = match state.p2p.as_deref()?.observed.as_ref()? {
        Offer::Public(address) if state.advertised() == Some(address.as_ref()) => return None,
        Offer::Public(address) => (
            format!("your router sees {address}  ·  o to use it"),
            theme.text(),
        ),
        Offer::Local(address) => (
            format!("seen at {address}  ·  this machine, cannot be offered"),
            theme.muted(),
        ),
        Offer::Unusable => return None,
    };
    Some(Line::from(vec![
        Span::styled(format!("{INDENT}{:<14}", "seen"), theme.muted()),
        Span::styled(text, style),
    ]))
}
