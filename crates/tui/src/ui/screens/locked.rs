//! Locked overlay.

use ratatui::layout::{Alignment, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::gate::{LockReason, LockedState};
use crate::app::idle::clock;
use crate::ui::layout::centered;
use crate::ui::widgets::chrome::panel;
use crate::ui::widgets::stripes::rule;

/// Draw the locked card.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &LockedState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let card = centered(area, area.width.min(66), 9);
    let block = panel("", theme);
    let inner = block.inner(card);
    frame.render_widget(block, card);
    let why = match state.reason {
        LockReason::Idle(after) => format!("locked (idle {})", clock(after)),
        LockReason::Manual => String::from("locked"),
        LockReason::Focus => String::from("locked (terminal lost focus)"),
        LockReason::Suspend => String::from("locked (suspend)"),
    };
    let stripes = Span::styled(
        rule(theme.glyphs, inner.width.saturating_sub(2)),
        theme.zebra(),
    );
    let lines = vec![
        Line::from(stripes.clone()),
        Line::from(""),
        Line::from(Span::styled(
            format!("{}  {why}", theme.glyphs.lock),
            theme.strong(),
        )),
        Line::from(Span::styled(
            format!(
                "keys wiped from memory {} clipboard cleared",
                theme.glyphs.dot
            ),
            theme.muted(),
        )),
        Line::from(Span::styled("press any key to unlock", theme.accent())),
        Line::from(""),
        Line::from(stripes),
    ];
    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), inner);
}
