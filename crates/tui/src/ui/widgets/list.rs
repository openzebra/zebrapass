//! Virtualized record list: only the rows that fit are built.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::ui::widgets::chrome::{age, row_style};
use crate::vault::create::unix_ms;
use crate::vault::records::{RecordKind, Summary};

/// First row to draw so that `selected` stays visible in `height` rows.
#[must_use]
pub const fn window_start(selected: usize, height: usize) -> usize {
    if height == 0 {
        0
    } else {
        selected.saturating_sub(height - 1)
    }
}

/// Truncate `text` to `width` characters with an ellipsis.
#[must_use]
pub fn fit(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        let mut out = text.to_owned();
        out.extend(std::iter::repeat_n(' ', width - text.chars().count()));
        out
    } else {
        let mut out: String = text.chars().take(width.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// Draw `rows` (indexes into `cache`) with `selected` highlighted.
pub fn draw(
    frame: &mut Frame<'_>,
    area: Rect,
    cache: &[Summary],
    rows: &[usize],
    selected: usize,
    focused: bool,
    ctx: &Ctx,
) {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let height = usize::from(area.height);
    let start = window_start(selected, height);
    let now = unix_ms();
    let width = usize::from(area.width);
    let name_width = width.saturating_sub(22).max(8) * 3 / 5;
    let user_width = width.saturating_sub(name_width + 12);
    let lines: Vec<Line<'_>> = rows
        .iter()
        .enumerate()
        .skip(start)
        .take(height)
        .filter_map(|(position, index)| cache.get(*index).map(|summary| (position, summary)))
        .map(|(position, summary)| {
            let chosen = position == selected;
            let style = row_style(chosen && focused, theme);
            let pointer = if chosen { glyphs.pointer } else { " " };
            let kind = match summary.kind {
                RecordKind::Login => glyphs.login,
                RecordKind::Note => glyphs.note,
                RecordKind::Unreadable => glyphs.attention,
            };
            let kind_style = if summary.kind == RecordKind::Unreadable {
                theme.danger()
            } else {
                theme.muted()
            };
            let star = if summary.favorite { glyphs.star } else { " " };
            Line::from(vec![
                Span::styled(format!("{pointer}{star}"), theme.accent()),
                Span::styled(format!("{kind} "), kind_style),
                Span::styled(fit(summary.display_title(), name_width), style),
                Span::styled(
                    format!(" {}", fit(&summary.username, user_width)),
                    theme.muted(),
                ),
                Span::styled(
                    format!("{:>4}", age(now, summary.timestamp_ms)),
                    theme.muted(),
                ),
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

#[cfg(test)]
mod tests {
    use super::{fit, window_start};

    #[test]
    fn window_keeps_selection_visible() {
        assert_eq!(window_start(0, 10), 0);
        assert_eq!(window_start(9, 10), 0);
        assert_eq!(window_start(15, 10), 6);
        assert_eq!(fit("GitHub", 4), "Git…");
        assert_eq!(fit("Git", 5), "Git  ");
    }
}
