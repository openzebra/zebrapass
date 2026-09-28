//! Sync: no server exists yet, so this view only describes what sync will
//! do and which account and device it will sign as. Nothing leaves the
//! device.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::unlocked::Unlocked;
use crate::app::keymap::Scope;
use crate::ui::layout::{body_and_hints, centered};
use crate::ui::screens::home::header;
use crate::ui::widgets::chrome::{hint_bar, panel, pq_badge};
use crate::ui::widgets::fingerprint::grouped_hex;

/// Draw the sync view.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &Unlocked, ctx: &Ctx) {
    let theme = &ctx.theme;
    let [top, rest] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(area);
    header(frame, top, state, "sync", ctx);
    let [body, hints] = body_and_hints(rest);
    let card = centered(body, body.width.min(84), 16);
    let block = panel(" Sync ", theme);
    let inner = block.inner(card);
    frame.render_widget(block, card);
    let field = |name: &str, value: String| {
        Line::from(vec![
            Span::styled(format!("    {name:<10}"), theme.muted()),
            Span::styled(value, theme.text()),
        ])
    };
    let lines = vec![
        Line::from(vec![
            Span::styled("  Server   ", theme.strong()),
            Span::styled(
                format!("{} not connected", theme.glyphs.fail),
                theme.muted(),
            ),
            Span::styled("  ·  sync servers are coming soon", theme.muted()),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  Your vault stays on this device. When sync arrives, each change",
            theme.text(),
        )),
        Line::from(Span::styled(
            "  is uploaded as one encrypted record, signed by this device:",
            theme.text(),
        )),
        Line::from(""),
        field("account", grouped_hex(&state.info.client_id, 4)),
        field("device", grouped_hex(&state.info.origin, 4)),
        field("vault", grouped_hex(&state.info.vault_id, 4)),
        Line::from(vec![
            Span::styled(format!("    {:<10}", "signature"), theme.muted()),
            Span::styled("ML-DSA-65 ", theme.text()),
            pq_badge(theme),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "  The server only ever sees ciphertext and public signatures.",
            theme.muted(),
        )),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
    hint_bar(frame, hints, Scope::Sync, "", ctx);
}
