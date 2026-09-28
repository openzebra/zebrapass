//! Import review: counts, warnings, and the item list with include marks.
//! Only text fields are shown; secrets never reach this screen.

use import::ItemKind;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::import::{ImportState, Preview};
use crate::app::keymap::Scope;
use crate::ui::layout::{body_and_hints, centered};
use crate::ui::screens::create::titled;
use crate::ui::theme::Theme;
use crate::ui::widgets::chrome::{checkbox, hint_bar, panel, row_style};
use crate::ui::widgets::list::{fit, window_start};

/// Kinds in display order with their plural nouns.
const KINDS: [(ItemKind, &str); 5] = [
    (ItemKind::Login, "logins"),
    (ItemKind::Note, "notes"),
    (ItemKind::Card, "cards"),
    (ItemKind::Identity, "identities"),
    (ItemKind::SshKey, "SSH keys"),
];

/// Draw the review step.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &ImportState, ctx: &Ctx) {
    let Some(preview) = state.preview.as_deref() else {
        return;
    };
    let theme = &ctx.theme;
    let [body, hints] = body_and_hints(area);
    let card = centered(
        body,
        body.width.min(110),
        body.height.saturating_sub(2).max(12),
    );
    let title = format!("Review · {}", state.source().label());
    let block = panel(titled(&title, (3, 3), card.width, ctx), theme);
    let inner = block.inner(card);
    frame.render_widget(block, card);
    let summary = summary_lines(preview, theme);
    let height = u16::try_from(summary.len()).unwrap_or(u16::MAX);
    let [head, _, list, _, footer] = Layout::vertical([
        Constraint::Length(height),
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);
    frame.render_widget(Paragraph::new(summary), head);
    draw_rows(frame, list, preview, ctx);
    let count = preview.count();
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("  {count} of {} selected", preview.rows.len()),
                theme.muted(),
            ),
            Span::styled("  ·  Enter creates a new vault with them", theme.muted()),
        ])),
        footer,
    );
    hint_bar(frame, hints, Scope::ImportPreview, "", ctx);
}

fn summary_lines(preview: &Preview, theme: &Theme) -> Vec<Line<'static>> {
    let glyphs = theme.glyphs;
    let report = &preview.parsed.report;
    let mut kinds = vec![Span::styled(
        format!("  {} items  ", preview.rows.len()),
        theme.strong(),
    )];
    for (kind, noun) in KINDS {
        let count = report.kinds.get(kind.index()).copied().unwrap_or(0);
        if count > 0 {
            kinds.push(Span::styled(format!(" {} ", glyphs.dot), theme.accent()));
            kinds.push(Span::styled(format!("{count} {noun}"), theme.text()));
        }
    }
    let mut lines = vec![Line::from(kinds)];
    if let Some(mapping) = preview.parsed.mapping.as_ref() {
        lines.push(note(
            &format!("columns read as a {} export", mapping.preset.label()),
            glyphs.ok,
            theme.accent(),
        ));
    }
    if !report.skipped.is_empty() {
        let reasons: Vec<&str> = report
            .skipped
            .iter()
            .map(|skip| skip.reason.label())
            .collect();
        let mut unique = reasons.clone();
        unique.sort_unstable();
        unique.dedup();
        lines.push(note(
            &format!("{} left out ({})", reasons.len(), unique.join(", ")),
            glyphs.attention,
            theme.warn(),
        ));
    }
    let dropped: Vec<String> = [
        (report.attachments, "attachments"),
        (report.passkeys, "passkeys"),
        (report.linked_fields, "linked fields"),
    ]
    .iter()
    .filter(|(count, _)| *count > 0)
    .map(|(count, noun)| format!("{count} {noun}"))
    .collect();
    if !dropped.is_empty() {
        lines.push(note(
            &format!("{} can't be imported", dropped.join(", ")),
            glyphs.attention,
            theme.warn(),
        ));
    }
    if report.history > 0 {
        lines.push(note(
            &format!("password history of {} items is not kept", report.history),
            glyphs.attention,
            theme.muted(),
        ));
    }
    if preview.bad_totp > 0 {
        lines.push(note(
            &format!("{} TOTP secrets won't produce codes here", preview.bad_totp),
            glyphs.attention,
            theme.warn(),
        ));
    }
    lines
}

fn note(text: &str, glyph: &str, style: ratatui::style::Style) -> Line<'static> {
    Line::from(Span::styled(format!("  {glyph} {text}"), style))
}

fn draw_rows(frame: &mut Frame<'_>, area: Rect, preview: &Preview, ctx: &Ctx) {
    let theme = &ctx.theme;
    let height = usize::from(area.height);
    let start = window_start(preview.cursor, height);
    let width = usize::from(area.width).saturating_sub(10);
    let title_width = width * 2 / 5;
    let user_width = width * 3 / 10;
    let tags_width = width.saturating_sub(title_width + user_width);
    let lines: Vec<Line<'_>> = preview
        .rows
        .iter()
        .zip(&preview.included)
        .enumerate()
        .skip(start)
        .take(height)
        .map(|(position, (row, on))| {
            let chosen = position == preview.cursor;
            let pointer = if chosen { theme.glyphs.pointer } else { " " };
            let style = if *on {
                row_style(chosen, theme)
            } else if chosen {
                theme.selected()
            } else {
                theme.muted()
            };
            Line::from(vec![
                Span::styled(format!(" {pointer} "), theme.accent()),
                Span::styled(format!("{} ", checkbox(*on)), style),
                Span::styled(fit(row.display_title(), title_width), style),
                Span::styled(fit(&row.username, user_width), theme.muted()),
                Span::styled(fit(&row.tags, tags_width), theme.muted()),
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}
