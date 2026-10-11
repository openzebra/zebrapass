//! The device addresses an owner typed, with the field that adds one.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::addresses::Addresses;
use crate::app::flows::unlocked::Unlocked;
use crate::ui::layout::centered;
use crate::ui::widgets::chrome::{modal, row_style};
use crate::ui::widgets::field::text_line;

/// Draw the list centered over `area`.
pub fn draw(frame: &mut Frame<'_>, area: Rect, list: &Addresses, state: &Unlocked, ctx: &Ctx) {
    let theme = &ctx.theme;
    let rows: Vec<&str> = state
        .manual_devices()
        .map(|entry| &*entry.address)
        .collect();
    let height = u16::try_from(rows.len().max(1) + 8).unwrap_or(12);
    let inner = modal(frame, centered(area, 64, height), "Device addresses", theme);
    let mut lines = vec![Line::from(Span::styled(
        " Another device of this account, as ip:port.",
        theme.muted(),
    ))];
    if rows.is_empty() {
        lines.push(Line::from(Span::styled(" none added", theme.muted())));
    }
    lines.extend(rows.iter().enumerate().map(|(index, address)| {
        let chosen = index == list.cursor;
        let pointer = if chosen { theme.glyphs.pointer } else { " " };
        Line::from(Span::styled(
            format!(" {pointer} {address}"),
            row_style(chosen, theme),
        ))
    }));
    lines.push(Line::from(""));
    match list.input.as_ref() {
        Some(input) => {
            let mut field = vec![Span::styled(" address ", theme.muted())];
            field.extend(text_line(input, inner.width.saturating_sub(10), true, theme).spans);
            lines.push(Line::from(field));
            lines.push(Line::from(Span::styled(
                " Enter save    Esc cancel",
                theme.muted(),
            )));
        }
        None => lines.push(Line::from(Span::styled(
            " a add    Del remove    Esc close",
            theme.muted(),
        ))),
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}
