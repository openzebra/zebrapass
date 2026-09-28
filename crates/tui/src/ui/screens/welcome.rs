//! First run: the banner and the two ways in.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::gate::WelcomeState;
use crate::app::keymap::Scope;
use crate::ui::layout::{body_and_hints, centered};
use crate::ui::widgets::chrome::{button, hint_bar, pq_badge};
use crate::ui::widgets::stripes::scrolling_rule;

const LETTER_ROWS: usize = 5;

/// Block letters for Z E B R A P S, five rows of six cells.
const fn letter(ch: char) -> [&'static str; LETTER_ROWS] {
    match ch {
        'Z' => ["██████", "   ██ ", "  ██  ", " ██   ", "██████"],
        'E' => ["██████", "██    ", "█████ ", "██    ", "██████"],
        'B' => ["█████ ", "██  ██", "█████ ", "██  ██", "█████ "],
        'R' => ["█████ ", "██  ██", "█████ ", "██ ██ ", "██  ██"],
        'A' => [" ████ ", "██  ██", "██████", "██  ██", "██  ██"],
        'P' => ["█████ ", "██  ██", "█████ ", "██    ", "██    "],
        'S' => [" █████", "██    ", " ████ ", "    ██", "█████ "],
        _ => ["      "; LETTER_ROWS],
    }
}

/// The banner rows for `word`.
#[must_use]
pub fn banner(word: &str, ascii: bool) -> Vec<String> {
    (0..LETTER_ROWS)
        .map(|row| {
            let line = word
                .chars()
                .map(|ch| letter(ch).get(row).copied().unwrap_or(""))
                .collect::<Vec<_>>()
                .join(" ");
            if ascii {
                line.replace('█', "#")
            } else {
                line
            }
        })
        .collect()
}

/// Draw the welcome screen.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &WelcomeState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let [body, hints] = body_and_hints(area);
    let tick = if theme.anim { ctx.tick / 2 } else { 0 };
    let card = centered(body, body.width.min(96), 17);
    let [rule_top, logo, rule_bottom, tagline, _, buttons, _, badges] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(5),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(card);
    let rule_width = card.width.saturating_sub(8);
    for (rect, offset) in [(rule_top, 0), (rule_bottom, 3)] {
        frame.render_widget(
            Paragraph::new(Span::styled(
                scrolling_rule(theme.glyphs, rule_width, tick + offset),
                theme.zebra(),
            ))
            .alignment(Alignment::Center),
            rect,
        );
    }
    let rows: Vec<Line<'_>> = if logo.width >= 70 {
        banner("ZEBRAPASS", theme.ascii)
            .into_iter()
            .map(|row| Line::from(Span::styled(row, theme.strong())))
            .collect()
    } else {
        vec![
            Line::from(""),
            Line::from(""),
            Line::from(Span::styled("Z E B R A P A S S", theme.strong())),
        ]
    };
    frame.render_widget(Paragraph::new(rows).alignment(Alignment::Center), logo);
    let dot = theme.glyphs.dot;
    frame.render_widget(
        Paragraph::new(Span::styled(
            format!("quantum-safe {dot} envelope-encrypted {dot} per-record sync"),
            theme.muted(),
        ))
        .alignment(Alignment::Center),
        tagline,
    );
    let pair = centered(buttons, buttons.width.min(64), 3);
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(pair);
    let create = format!("{}  Create a new vault", theme.glyphs.spark);
    let restore = format!("{}  Restore from phrase", theme.glyphs.recovery);
    button(frame, left, &create, !state.restore, !state.restore, theme);
    button(frame, right, &restore, state.restore, state.restore, theme);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            pq_badge(theme),
            Span::styled(
                format!(
                    " ML-KEM hybrid  {dot}  ML-DSA  {dot}  AEGIS-256 + Kuznyechik  {dot}  Argon2id"
                ),
                theme.muted(),
            ),
        ]))
        .alignment(Alignment::Center),
        badges,
    );
    hint_bar(
        frame,
        hints,
        Scope::Welcome,
        concat!("v", env!("CARGO_PKG_VERSION"), " · no net "),
        ctx,
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, reason = "tests may index")]

    use super::banner;

    #[test]
    fn banner_rows_are_even() {
        let rows = banner("ZEBRAPASS", true);
        assert_eq!(rows.len(), 5);
        assert!(rows
            .iter()
            .all(|row| row.chars().count() == rows[0].chars().count()));
    }
}
