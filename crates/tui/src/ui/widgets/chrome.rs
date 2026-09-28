//! Frame pieces every screen shares: panels, buttons, the hint bar, step
//! dots, radios, and the "terminal too small" card.

use ratatui::layout::{Alignment, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::keymap::{hints, label, Scope};
use crate::ui::layout::{centered, MIN_HEIGHT, MIN_WIDTH};
use crate::ui::theme::Theme;

/// A rounded panel with a title.
#[must_use]
pub fn panel<'a>(title: impl Into<Line<'a>>, theme: &Theme) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.muted())
        .title(title.into().style(theme.strong()))
        .style(theme.base())
}

/// A panel for alarms: thick danger border.
#[must_use]
pub fn danger_panel<'a>(title: impl Into<Line<'a>>, theme: &Theme) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(theme.danger())
        .title(title.into().style(theme.danger()))
        .style(theme.base())
}

/// Clear `area` and draw a modal panel; returns the inner area.
pub fn modal(frame: &mut Frame<'_>, area: Rect, title: &str, theme: &Theme) -> Rect {
    frame.render_widget(Clear, area);
    let block = panel(format!(" {title} "), theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    inner
}

/// A button. The primary one is the only bright element of a screen.
pub fn button(
    frame: &mut Frame<'_>,
    area: Rect,
    text: &str,
    primary: bool,
    focused: bool,
    theme: &Theme,
) {
    let (border, style, kind) = if primary {
        (theme.accent(), theme.strong(), BorderType::Thick)
    } else if focused {
        (theme.accent(), theme.text(), BorderType::Plain)
    } else {
        (theme.muted(), theme.text(), BorderType::Plain)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(kind)
        .border_style(border);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(text.to_owned(), style)))
            .alignment(Alignment::Center)
            .block(block),
        area,
    );
}

/// The bottom hint bar for `scope`, with optional right-aligned text.
pub fn hint_bar(frame: &mut Frame<'_>, area: Rect, scope: Scope, right: &str, ctx: &Ctx) {
    let theme = &ctx.theme;
    let mut spans = Vec::new();
    let mut used = 1usize;
    let limit = usize::from(area.width).saturating_sub(right.chars().count() + 2);
    spans.push(Span::raw(" "));
    for binding in hints(scope) {
        let key = label(binding.key, theme.ascii);
        let cost = key.chars().count() + binding.hint.chars().count() + 3;
        if used + cost > limit {
            break;
        }
        used += cost;
        spans.push(Span::styled(key, theme.strong()));
        spans.push(Span::styled(format!(" {}  ", binding.hint), theme.muted()));
    }
    let pad = usize::from(area.width).saturating_sub(used + right.chars().count() + 1);
    spans.push(Span::raw(" ".repeat(pad)));
    spans.push(Span::styled(right.to_owned(), theme.muted()));
    frame.render_widget(Paragraph::new(Line::from(spans)).style(theme.panel()), area);
}

/// `● ● ○ ○  2 of 4`.
#[must_use]
pub fn step_dots(step: usize, total: usize, theme: &Theme) -> Span<'static> {
    let dots: Vec<&str> = (0..total)
        .map(|index| {
            if index < step {
                theme.glyphs.on
            } else {
                theme.glyphs.off
            }
        })
        .collect();
    Span::styled(
        format!("{}  {step} of {total}", dots.join(" ")),
        theme.muted(),
    )
}

/// `(●)` or `( )`.
#[must_use]
pub fn radio(on: bool, theme: &Theme) -> String {
    format!("({})", if on { theme.glyphs.on } else { " " })
}

/// `[x]` or `[ ]`.
#[must_use]
pub const fn checkbox(on: bool) -> &'static str {
    if on {
        "[x]"
    } else {
        "[ ]"
    }
}

/// The `PQ` badge.
#[must_use]
pub fn pq_badge(theme: &Theme) -> Span<'static> {
    Span::styled(" PQ ", theme.pq())
}

/// Style for a focusable row.
#[must_use]
pub const fn row_style(selected: bool, theme: &Theme) -> Style {
    if selected {
        theme.selected()
    } else {
        theme.text()
    }
}

/// The card shown when the terminal is smaller than every layout.
pub fn too_small(frame: &mut Frame<'_>, area: Rect, theme: &Theme) {
    frame.render_widget(Paragraph::new("").style(theme.base()), area);
    let card = centered(area, area.width.min(44), area.height.min(6));
    let text = vec![
        Line::from(Span::styled("Terminal too small", theme.warn())),
        Line::from(Span::styled(
            format!(
                "need {MIN_WIDTH}x{MIN_HEIGHT}, have {}x{}",
                area.width, area.height
            ),
            theme.muted(),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .block(panel("", theme)),
        card,
    );
}

/// `just now` or `2d ago`.
#[must_use]
pub fn ago(now_ms: u64, then_ms: u64) -> String {
    match age(now_ms, then_ms).as_str() {
        "now" => String::from("just now"),
        short => format!("{short} ago"),
    }
}

/// Relative age of a unix-millisecond time: `2d`, `5w`, `1y`.
#[must_use]
pub fn age(now_ms: u64, then_ms: u64) -> String {
    let secs = now_ms.saturating_sub(then_ms) / 1000;
    match secs {
        0..60 => String::from("now"),
        60..3600 => format!("{}m", secs / 60),
        3600..86_400 => format!("{}h", secs / 3600),
        86_400..1_209_600 => format!("{}d", secs / 86_400),
        1_209_600..31_536_000 => format!("{}w", secs / 604_800),
        _ => format!("{}y", secs / 31_536_000),
    }
}
