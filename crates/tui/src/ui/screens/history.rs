//! Record history.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::history::HistoryState;
use crate::app::keymap::Scope;
use crate::ui::layout::body_and_hints;
use crate::ui::screens::detail::draw_rows;
use crate::ui::widgets::chrome::{ago, hint_bar, modal, panel, row_style};
use crate::ui::widgets::fingerprint::grouped_hex;
use crate::vault::create::unix_ms;

/// Draw the history view.
pub fn draw(frame: &mut Frame<'_>, area: Rect, history: &HistoryState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let [body, hints] = body_and_hints(area);
    let block = panel(
        format!(" History {} {} ", theme.glyphs.dot, history.title),
        theme,
    );
    let inner = block.inner(body);
    frame.render_widget(block, body);
    let now = unix_ms();
    let mut lines = vec![Line::from(Span::styled(
        format!("  {:<7}{:<12}{:<16}{}", "rev", "when", "device", "change"),
        theme.strong(),
    ))];
    lines.extend(history.rows.iter().enumerate().map(|(index, row)| {
        let chosen = index == history.selected;
        let pointer = if chosen { theme.glyphs.pointer } else { " " };
        Line::from(vec![
            Span::styled(
                format!("{pointer} {:<6}", row.revision),
                row_style(chosen, theme),
            ),
            Span::styled(format!("{:<12}", ago(now, row.timestamp_ms)), theme.muted()),
            Span::styled(
                format!("{:<16}", grouped_hex(&row.origin, 2)),
                theme.muted(),
            ),
            Span::styled(row.change.clone(), theme.text()),
        ])
    }));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Enter view (masked) · R restore this revision (creates a new one)",
        theme.muted(),
    )));
    frame.render_widget(Paragraph::new(lines), inner);
    if let Some(detail) = history.view.as_deref() {
        let [_, right] =
            Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
                .areas(inner);
        let rect = Rect {
            height: right.height.min(18),
            ..right
        };
        let inside = modal(
            frame,
            rect,
            &format!("revision {} (read-only)", detail.revision),
            theme,
        );
        draw_rows(frame, inside, detail, false, false, ctx);
    }
    hint_bar(frame, hints, Scope::History, "", ctx);
}
