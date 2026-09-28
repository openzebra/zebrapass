//! The CSV column step: header, target, and a sample where it is safe.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::import::ImportState;
use crate::app::keymap::Scope;
use crate::ui::layout::{body_and_hints, centered};
use crate::ui::screens::create::titled;
use crate::ui::widgets::chrome::{hint_bar, panel, row_style};
use crate::ui::widgets::list::{fit, window_start};

/// Draw the column step.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &ImportState, ctx: &Ctx) {
    let Some(columns) = state.columns.as_deref() else {
        return;
    };
    let theme = &ctx.theme;
    let [body, hints] = body_and_hints(area);
    let rows = u16::try_from(columns.columns.len()).unwrap_or(u16::MAX);
    let card = centered(body, body.width.min(100), rows.saturating_add(9).max(12));
    let block = panel(titled("CSV columns", (3, 4), card.width, ctx), theme);
    let inner = block.inner(card);
    frame.render_widget(block, card);
    let [intro, _, head, list, error] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(inner);
    frame.render_widget(
        Paragraph::new(Span::styled(
            format!(
                "  Read as {}. Choose what each column holds; ←/→ changes it.",
                columns.mapping.preset.label()
            ),
            theme.muted(),
        )),
        intro,
    );
    let width = usize::from(inner.width).saturating_sub(8);
    let header_width = width * 3 / 10;
    let target_width = width * 3 / 10;
    let sample_width = width.saturating_sub(header_width + target_width);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw("    "),
            Span::styled(fit("Column", header_width), theme.strong()),
            Span::styled(fit("Imported as", target_width), theme.strong()),
            Span::styled(fit("First row", sample_width), theme.strong()),
        ])),
        head,
    );
    let height = usize::from(list.height);
    let start = window_start(columns.cursor, height);
    let lines: Vec<Line<'_>> = columns
        .columns
        .iter()
        .zip(columns.mapping.targets.iter())
        .enumerate()
        .skip(start)
        .take(height)
        .map(|(index, (column, target))| {
            let chosen = index == columns.cursor;
            let pointer = if chosen { theme.glyphs.pointer } else { " " };
            let arrows = if chosen { "‹ " } else { "  " };
            let sample = column
                .sample(*target)
                .map_or_else(|| String::from("(hidden)"), str::to_owned);
            Line::from(vec![
                Span::styled(format!("  {pointer} "), theme.accent()),
                Span::styled(fit(&column.header, header_width), row_style(chosen, theme)),
                Span::styled(
                    fit(&format!("{arrows}{} ›", target.label()), target_width),
                    if chosen { theme.accent() } else { theme.text() },
                ),
                Span::styled(fit(&sample, sample_width), theme.muted()),
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), list);
    if let Some(message) = state.error.as_deref() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!("    {} {message}", theme.glyphs.fail),
                theme.danger(),
            )),
            error,
        );
    }
    hint_bar(frame, hints, Scope::ImportMapping, "", ctx);
}
