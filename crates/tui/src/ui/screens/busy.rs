//! Progress while the worker runs: the "herd". Argon2id cannot report
//! progress, and the step list is static text on purpose: showing which
//! internal step failed would be an oracle.

use ratatui::layout::{Alignment, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::ctx::{Ctx, Pending, Task};
use crate::ui::layout::centered;
use crate::ui::theme::Glyphs;
use crate::ui::widgets::chrome::modal;
use crate::ui::widgets::stripes::herd_row;

/// Draw the progress card.
pub fn draw(frame: &mut Frame<'_>, area: Rect, pending: Pending, ctx: &Ctx) {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let card = centered(area, area.width.min(68), 14);
    let inner = modal(frame, card, pending.task.title(), theme);
    let tick = if theme.anim { ctx.tick } else { 0 };
    let herd_width = inner.width.saturating_sub(8);
    let mut lines: Vec<Line<'_>> = (0..3)
        .map(|row| {
            Line::from(Span::styled(
                herd_row(glyphs, herd_width, row, tick),
                theme.zebra(),
            ))
        })
        .collect();
    lines.push(Line::from(""));
    let steps = steps(pending.task, glyphs);
    let step_width = steps
        .iter()
        .map(|(step, _)| step.chars().count())
        .max()
        .unwrap_or(0)
        + 3;
    let detail_width = steps
        .iter()
        .map(|(_, detail)| detail.chars().count())
        .max()
        .unwrap_or(0);
    lines.extend(steps.into_iter().map(|(step, detail)| {
        Line::from(vec![
            Span::styled(format!("{step:<step_width$}"), theme.text()),
            Span::styled(format!("{detail:<detail_width$}"), theme.muted()),
        ])
    }));
    lines.push(Line::from(""));
    let elapsed = ctx
        .now
        .saturating_duration_since(pending.since)
        .as_secs_f64();
    let cancel = if pending.task.cancellable() {
        format!(" {} Esc cancel", glyphs.dot)
    } else {
        String::new()
    };
    lines.push(Line::from(Span::styled(
        format!("elapsed {elapsed:.1} s{cancel}"),
        theme.muted(),
    )));
    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), inner);
}

/// What the job does, as fixed text.
fn steps(task: Task, glyphs: &Glyphs) -> Vec<(String, String)> {
    let pair = |step: &str, detail: String| (step.to_owned(), detail);
    match task {
        Task::Unlock(cost) => vec![
            pair(
                "Stretching password",
                cost.map_or_else(
                    || String::from("Argon2id"),
                    |(m_kib, t, p)| {
                        let dot = glyphs.dot;
                        format!(
                            "Argon2id {dot} {} MiB {dot} t={t} {dot} p={p}",
                            m_kib / 1024
                        )
                    },
                ),
            ),
            pair(
                "Unwrapping vault key",
                format!("{} → {}", glyphs.kek, glyphs.vk),
            ),
            pair("Verifying commitment", String::from("HMAC before decrypt")),
        ],
        Task::Create | Task::Restore => vec![
            pair(
                "Sealing the vault key",
                String::from("Argon2id + AEGIS-256 wraps"),
            ),
            pair(
                "Writing atomically",
                String::from("temp file, fsync, rename"),
            ),
            pair("Recording rollback cursor", String::from("local.meta")),
        ],
        Task::Rotate => vec![
            pair("Drawing a new vault key", String::from("OS CSPRNG")),
            pair("Re-sealing every frame", String::from("per-record keys")),
            pair(
                "Re-wrapping every factor",
                String::from("ML-KEM hybrid / Argon2id"),
            ),
        ],
        Task::Save | Task::Factor | Task::Health | Task::Import => {
            vec![pair(task.title(), String::new())]
        }
    }
}
