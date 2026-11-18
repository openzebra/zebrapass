//! Node, address, relay, and identity status lines on the share screen.

use local::{Listen, Offer};
use ratatui::text::{Line, Span};

use crate::app::flows::unlocked::Unlocked;
use crate::ui::screens::sync::{INDENT, node_text};
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
        Offer::Public(address) => (format!("your router sees {address} · o"), theme.text()),
        Offer::Local(address) => (
            format!("{address} · this machine, cannot be offered"),
            theme.muted(),
        ),
        Offer::Unusable => return None,
    };
    Some(Line::from(vec![
        Span::styled(format!("{INDENT}{:<6}", "seen"), theme.muted()),
        Span::styled(text, style),
    ]))
}

/// All node, restore address, offering, observed, relay, and identity lines.
pub(super) fn build_node_lines(state: &Unlocked, theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = Vec::with_capacity(6);
    let (text, up) = node_text(state, theme);
    let style = if up { theme.accent() } else { theme.muted() };
    lines.push(Line::from(vec![
        Span::styled(format!("{INDENT}node  "), theme.muted()),
        Span::styled(text, style),
    ]));
    if let Some(address) = state.p2p.as_deref().and_then(|p2p| p2p.reachable.first()) {
        lines.push(Line::from(vec![
            Span::styled(format!("{INDENT}restore from  "), theme.muted()),
            Span::styled(format!("{address} · new device"), theme.text()),
        ]));
    }
    if let Some(address) = state
        .advertised()
        .filter(|_| matches!(state.listen_mode(), Listen::Lan | Listen::Beacon))
    {
        lines.push(Line::from(vec![
            Span::styled(format!("{INDENT}offering  "), theme.muted()),
            Span::styled(address.to_owned(), theme.text()),
        ]));
    }
    lines.extend(observed_line(state, theme));
    if let Some(saved) = state
        .p2p
        .as_deref()
        .map(|p2p| p2p.relays.len())
        .filter(|n| *n > 0)
    {
        lines.push(Line::from(vec![
            Span::styled(format!("{INDENT}relays  "), theme.muted()),
            Span::styled(
                format!("{saved} saved · {}", hold_gloss(state)),
                theme.text(),
            ),
        ]));
    }
    if state.identity_is_old() {
        lines.push(Line::from(vec![
            Span::styled(format!("{INDENT}identity  "), theme.muted()),
            Span::styled(
                "old format, cannot serve your devices · u to upgrade",
                theme.warn(),
            ),
        ]));
    }
    lines
}
