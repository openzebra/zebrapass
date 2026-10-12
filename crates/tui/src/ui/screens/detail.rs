//! Record detail: text fields in clear, secrets as fixed-width stripes until
//! revealed. Also used, read-only, for historical revisions.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::home::{Detail, Pane, RowKind};
use crate::app::flows::unlocked::Unlocked;
use crate::secure::reveal::RevealKey;
use crate::secure::strength::estimate;
use crate::secure::totp::Totp;
use crate::ui::screens::p2p_status::strip as strip_text;
use crate::ui::widgets::chrome::ago;
use crate::ui::widgets::list::fit;
use crate::ui::widgets::meter::strength_spans;
use crate::ui::widgets::stripes::{mask, MASK_CELLS};
use crate::vault::create::unix_ms;

/// Draw the detail pane of the home view.
pub fn draw_pane(frame: &mut Frame<'_>, area: Rect, state: &Unlocked, ctx: &Ctx) {
    let theme = &ctx.theme;
    let focused = state.home.pane == Pane::Detail;
    let title = state
        .selected()
        .map_or_else(String::new, |summary| summary.display_title().to_owned());
    let back = if state.home.stacked {
        format!("{} ", theme.glyphs.arrows[2])
    } else {
        String::new()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(if focused {
            theme.accent()
        } else {
            theme.muted()
        })
        .title(Span::styled(format!(" {back}{title} "), theme.strong()));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let [strip, inner] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);
    frame.render_widget(
        Paragraph::new(Span::styled(
            fit(
                &format!(" {}", strip_text(state, theme)),
                usize::from(strip.width),
            ),
            theme.muted(),
        )),
        strip,
    );
    match state.home.detail.as_deref() {
        Some(detail) => draw_rows(frame, inner, detail, focused, true, ctx),
        None => frame.render_widget(
            Paragraph::new(Span::styled(" Select a record.", theme.muted())),
            inner,
        ),
    }
}

/// The current TOTP code, masked until revealed, with its countdown. The
/// stored secret itself is never drawn.
fn totp_span(field: &[u8], shown: bool, ctx: &Ctx) -> Span<'static> {
    let theme = &ctx.theme;
    let Ok(totp) = Totp::try_from(field) else {
        return Span::styled("cannot make codes from this secret", theme.warn());
    };
    let now = unix_ms() / 1000;
    let left = totp.remaining(now);
    if shown {
        let code = totp.code(now);
        let (head, tail) = code.split_at(code.len() / 2);
        Span::styled(format!("{head} {tail}  {left:>2}s"), theme.warn())
    } else {
        let glyphs = theme.glyphs;
        Span::styled(
            format!("{} {}  {left:>2}s", mask(glyphs, 3), mask(glyphs, 3)),
            theme.zebra(),
        )
    }
}

/// Cells of the copy hint column.
const HINT_CELLS: usize = 10;

/// Narrowest and widest label column.
const LABEL_CELLS: std::ops::RangeInclusive<usize> = 8..=18;

/// The label column: as wide as the longest label, within [`LABEL_CELLS`]
/// and a third of the pane.
fn label_width(detail: &Detail, width: usize) -> usize {
    let longest = detail
        .rows
        .iter()
        .map(|row| row.label.chars().count())
        .max()
        .unwrap_or(0);
    longest
        .clamp(*LABEL_CELLS.start(), *LABEL_CELLS.end())
        .min((width / 3).max(*LABEL_CELLS.start()))
}

/// Draw the rows of `detail`. `copy_hints` adds the copy keys on the right.
pub fn draw_rows(
    frame: &mut Frame<'_>,
    area: Rect,
    detail: &Detail,
    focused: bool,
    copy_hints: bool,
    ctx: &Ctx,
) {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let width = usize::from(area.width);
    let label_width = label_width(detail, width);
    let value_width = width.saturating_sub(label_width + HINT_CELLS + 4).max(8);
    let mut lines = vec![Line::from("")];
    for (index, row) in detail.rows.iter().enumerate() {
        let chosen = focused && index == detail.cursor;
        let pointer = if chosen { glyphs.pointer } else { " " };
        let shown = detail.reveal.is_shown(RevealKey(u32::from(row.tag)));
        let data = detail.doc.data(row.tag).ok().flatten().unwrap_or_default();
        let value: Span<'_> = match (row.kind, shown) {
            (RowKind::Totp, _) => totp_span(data, shown, ctx),
            (RowKind::Text, _) | (RowKind::Secret, true) => {
                let text = String::from_utf8_lossy(data);
                let clipped: String = text
                    .chars()
                    .map(|ch| if ch.is_control() { ' ' } else { ch })
                    .take(value_width)
                    .collect();
                Span::styled(clipped, if shown { theme.warn() } else { theme.text() })
            }
            (RowKind::Secret, false) => Span::styled(mask(glyphs, MASK_CELLS), theme.zebra()),
        };
        let used = value.content.chars().count();
        let hint = match (copy_hints, row.copy_key, row.kind) {
            (true, _, _) if chosen => String::from("Enter copy"),
            (true, Some(key), RowKind::Text) if key == 'o' => format!("{key} show"),
            (true, Some(key), _) => format!("{key} copy"),
            (true, None, RowKind::Secret | RowKind::Totp) => String::from("Space show"),
            _ => String::new(),
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("{pointer} {} ", fit(&row.label, label_width)),
                if chosen {
                    theme.accent()
                } else {
                    theme.muted()
                },
            ),
            value,
            Span::raw(" ".repeat(value_width.saturating_sub(used) + 1)),
            Span::styled(hint, theme.muted()),
        ]));
        if row.tag == record::TAG_PASSWORD && !data.is_empty() {
            let mut spans = vec![Span::raw(" ".repeat(label_width + 3))];
            spans.extend(strength_spans(estimate(data), 10, theme));
            lines.push(Line::from(spans));
        }
    }
    if detail.rows.is_empty() {
        lines.push(Line::from(Span::styled("  (no fields)", theme.muted())));
    }
    if let Some(left) = detail.reveal.remaining(ctx.now, ctx.reveal_after) {
        lines.push(Line::from(Span::styled(
            format!("  revealed {} hides in {}s", glyphs.dot, left.as_secs() + 1),
            theme.warn(),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!(
            "  rev {} {} edited {} {} h history",
            detail.revision,
            glyphs.dot,
            ago(unix_ms(), detail.timestamp_ms),
            glyphs.dot
        ),
        theme.muted(),
    )));
    frame.render_widget(Paragraph::new(lines), area);
}
