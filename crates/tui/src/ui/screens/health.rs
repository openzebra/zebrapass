//! Vault health dashboard.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::panels::{health_rows, HealthRow};
use crate::app::flows::unlocked::Unlocked;
use crate::app::keymap::Scope;
use crate::ui::layout::body_and_hints;
use crate::ui::screens::home::header;
use crate::ui::widgets::chrome::{hint_bar, panel, row_style};
use crate::ui::widgets::meter::bar;

/// Draw the health view.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &Unlocked, cursor: usize, ctx: &Ctx) {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let [top, rest] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(area);
    header(frame, top, state, "health", ctx);
    let [body, hints] = body_and_hints(rest);
    let block = panel(" Vault health ", theme);
    let inner = block.inner(body);
    frame.render_widget(block, body);
    let Some(report) = state.health.as_deref() else {
        frame.render_widget(
            Paragraph::new(Span::styled("  Not computed yet.", theme.muted())),
            inner,
        );
        return;
    };
    let score_style = match report.score {
        0..50 => theme.danger(),
        50..80 => theme.warn(),
        _ => theme.accent(),
    };
    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("      score  ", theme.text()),
            Span::styled(
                bar(f64::from(report.score) / 100.0, 20, glyphs),
                score_style,
            ),
            Span::styled(format!("  {} / 100", report.score), score_style),
        ]),
        Line::from(""),
    ];
    let title = |id: &u32| {
        state
            .cache
            .iter()
            .find(|summary| summary.id == *id)
            .map_or_else(
                || format!("#{id}"),
                |summary| summary.display_title().to_owned(),
            )
    };
    let with_password = report.with_password.max(1);
    for (index, row) in health_rows(report).iter().enumerate() {
        let chosen = index == cursor;
        let pointer = if chosen { glyphs.pointer } else { " " };
        let line = match row {
            HealthRow::Weak => Line::from(vec![
                Span::styled(
                    format!(
                        " {pointer} {} Weak (<50 bits)   {:>4}   ",
                        glyphs.attention,
                        report.weak.len()
                    ),
                    row_style(chosen, theme),
                ),
                Span::styled(
                    bar(ratio(report.weak.len(), with_password), 10, glyphs),
                    theme.warn(),
                ),
                Span::styled("   Enter review · g regenerate", theme.muted()),
            ]),
            HealthRow::Reused(group) => {
                let ids = report.reused.get(*group).map_or(&[][..], |ids| &**ids);
                let names: Vec<String> = ids.iter().take(4).map(title).collect();
                Line::from(vec![
                    Span::styled(
                        format!(
                            " {pointer} {} Reused group {} ({})  ",
                            glyphs.attention,
                            group + 1,
                            ids.len()
                        ),
                        row_style(chosen, theme),
                    ),
                    Span::styled(names.join(&format!(" {} ", glyphs.dot)), theme.muted()),
                ])
            }
            HealthRow::Old => Line::from(vec![Span::styled(
                format!(
                    " {pointer} {} Old (>365 days)  {:>4}",
                    glyphs.attention,
                    report.old.len()
                ),
                row_style(chosen, theme),
            )]),
        };
        lines.push(line);
    }
    lines.push(Line::from(Span::styled(
        format!("   {} Unique             {:>4}", glyphs.ok, report.unique),
        theme.accent(),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "   Computed in memory only. Nothing is stored or sent. Reuse is found by constant-time comparison.",
        theme.muted(),
    )));
    frame.render_widget(Paragraph::new(lines), inner);
    hint_bar(frame, hints, Scope::Health, "", ctx);
}

fn ratio(part: usize, whole: usize) -> f64 {
    let part = f64::from(u32::try_from(part).unwrap_or(u32::MAX));
    let whole = f64::from(u32::try_from(whole).unwrap_or(u32::MAX)).max(1.0);
    part / whole
}
