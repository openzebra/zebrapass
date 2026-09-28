//! Sync: the transport is not built; the signed-frame seam is shown and
//! file export/import works through it.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::unlocked::Unlocked;
use crate::app::keymap::Scope;
use crate::ui::layout::body_and_hints;
use crate::ui::screens::home::header;
use crate::ui::widgets::chrome::{hint_bar, panel, pq_badge, row_style};
use crate::ui::widgets::fingerprint::grouped_hex;

/// Draw the sync view.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &Unlocked, cursor: usize, ctx: &Ctx) {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let [top, rest] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(area);
    header(frame, top, state, "sync", ctx);
    let [body, hints] = body_and_hints(rest);
    let block = panel(" Sync ", theme);
    let inner = block.inner(body);
    frame.render_widget(block, body);
    let [transport, _, frame_box, _, lists] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(1),
        Constraint::Length(11),
        Constraint::Length(1),
        Constraint::Min(3),
    ])
    .areas(inner);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled("  Server transport     ", theme.text()),
                Span::styled(format!("{} not built yet", glyphs.fail), theme.danger()),
                Span::styled("   (TODO sync-server)", theme.muted()),
            ]),
            Line::from(Span::styled(
                "  Each change becomes ONE signed record frame:",
                theme.muted(),
            )),
        ]),
        transport,
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.muted());
    let framed = Rect {
        x: frame_box.x + 2,
        width: frame_box.width.saturating_sub(4).min(84),
        ..frame_box
    };
    let box_inner = block.inner(framed);
    frame.render_widget(block, framed);
    frame.render_widget(Paragraph::new(signed_frame_lines(state, ctx)), box_inner);
    draw_lists(frame, lists, state, cursor, ctx);
    hint_bar(frame, hints, Scope::Sync, "", ctx);
}

/// The outer fields a sync signature binds, from the last export when there
/// is one.
fn signed_frame_lines(state: &Unlocked, ctx: &Ctx) -> Vec<Line<'static>> {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let field = |name: &str, value: String| {
        Line::from(vec![
            Span::styled(format!(" {name:<12}"), theme.muted()),
            Span::styled(value, theme.text()),
        ])
    };
    let context = String::from_utf8_lossy(session::SYNC_CTX).into_owned();
    let mut lines = vec![
        field("context", context),
        field("vault", grouped_hex(&state.info.vault_id, 4)),
        field("client", grouped_hex(&state.info.client_id, 4)),
        field("device", grouped_hex(&state.info.origin, 4)),
    ];
    if let Some(preview) = state.last_export {
        lines.push(field(
            "record",
            format!(
                "#{:04}   revision {}   key generation {}",
                preview.record_id, preview.revision, preview.key_generation
            ),
        ));
        lines.push(field("hash(ct)", grouped_hex(&preview.content_hash, 4)));
        lines.push(field("layout", format!("msg v{}", preview.msg_version)));
        let verdict = if preview.verified {
            Span::styled(format!("{} self-verified", glyphs.ok), theme.accent())
        } else {
            Span::styled(format!("{} did not verify", glyphs.fail), theme.danger())
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<12}", "signature"), theme.muted()),
            Span::styled("ML-DSA-65 ", theme.text()),
            pq_badge(theme),
            Span::raw(" "),
            verdict,
        ]));
    } else {
        lines.push(field("record", String::from("(signed on export)")));
        lines.push(field(
            "hash(ct)",
            String::from("SHA-256 of the sealed frame"),
        ));
        lines.push(field("layout", format!("msg v{}", session::MSG_VERSION)));
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<12}", "signature"), theme.muted()),
            Span::styled("ML-DSA-65 ", theme.text()),
            pq_badge(theme),
        ]));
    }
    lines
}

/// Pending changes and the last import result.
fn draw_lists(frame: &mut Frame<'_>, lists: Rect, state: &Unlocked, cursor: usize, ctx: &Ctx) {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let [pending, imported] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(lists);
    let mut left = vec![Line::from(Span::styled(
        format!("  Pending local changes: {}", state.pending_sync.len()),
        theme.strong(),
    ))];
    left.extend(state.pending_sync.iter().enumerate().map(|(index, id)| {
        let title = state
            .cache
            .iter()
            .find(|summary| summary.id == *id)
            .map_or("(deleted)", |summary| summary.display_title());
        Line::from(Span::styled(
            format!("    #{id:04} {title}"),
            row_style(index == cursor, theme),
        ))
    }));
    left.push(Line::from(Span::styled(
        "  x export pending · X export all · i import",
        theme.muted(),
    )));
    frame.render_widget(Paragraph::new(left), pending);
    let mut right = vec![Line::from(Span::styled("  Last import", theme.strong()))];
    match state.import.as_deref() {
        Some(report) => right.extend(report.outcomes.iter().map(|(id, outcome)| match outcome {
            Ok(revision) => Line::from(Span::styled(
                format!("    {} #{id:04} revision {revision}", glyphs.ok),
                theme.accent(),
            )),
            Err(reason) => Line::from(Span::styled(
                format!("    {} #{id:04} {reason}", glyphs.fail),
                theme.danger(),
            )),
        })),
        None => right.push(Line::from(Span::styled(
            "    none this session",
            theme.muted(),
        ))),
    }
    frame.render_widget(Paragraph::new(right), imported);
}
