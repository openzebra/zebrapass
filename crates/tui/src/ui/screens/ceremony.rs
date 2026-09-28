//! Create wizard steps 2 and 3: the phrase one row at a time, then three
//! picks to prove it was written down. There is no copy action here.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::ceremony::{words, CeremonyFocus, Verify, CARDS, PER_ROW, ROWS};
use crate::app::flows::create::{CreateState, Step};
use crate::app::keymap::Scope;
use crate::ui::layout::{body_and_hints, centered};
use crate::ui::screens::create::titled;
use crate::ui::widgets::chrome::{button, checkbox, hint_bar, panel};
use crate::ui::widgets::stripes::mask;

/// Mask cells per hidden word.
const WORD_MASK: u16 = 8;

/// Draw the ceremony or the verify step.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &CreateState, ctx: &Ctx) {
    match (state.step, state.verify.as_deref()) {
        (Step::Verify, Some(verify)) => draw_verify(frame, area, verify, ctx),
        _ => draw_phrase(frame, area, state, ctx),
    }
}

/// Width of one grid cell: `01 ` + word + two spaces.
const CELL: u16 = 3 + WORD_MASK + 2;

fn draw_phrase(frame: &mut Frame<'_>, area: Rect, state: &CreateState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let [body, hints] = body_and_hints(area);
    let card = centered(body, body.width.min(84), 22);
    let block = panel(
        titled("Your recovery phrase", (2, 4), card.width, ctx),
        theme,
    );
    let inner = block.inner(card);
    frame.render_widget(block, card);
    // Every word must be reachable at every width: a phrase row that does
    // not fit is wrapped over several lines, and still revealed as one.
    let room = inner.width.saturating_sub(8);
    let per_line = usize::from((room / CELL).clamp(1, 5));
    let lines_per_row = PER_ROW.div_ceil(per_line);
    let grid_height = u16::try_from(ROWS * lines_per_row + 2).unwrap_or(12);
    let [warning, grid, footer] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(grid_height),
        Constraint::Min(3),
    ])
    .areas(inner);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                "  This phrase IS your vault. Anyone with it can restore everything.",
                theme.warn(),
            )),
            Line::from(Span::styled(
                "  Write it on paper. Never screenshot it. It won't be shown again.",
                theme.text(),
            )),
        ])
        .wrap(ratatui::widgets::Wrap { trim: false }),
        warning,
    );
    let grid_width = (CELL * u16::try_from(per_line).unwrap_or(1) + 4).min(grid.width);
    let grid_rect = centered(grid, grid_width, grid_height);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(if state.ceremony.focus == CeremonyFocus::Grid {
            theme.accent()
        } else {
            theme.muted()
        });
    let grid_inner = block.inner(grid_rect);
    frame.render_widget(block, grid_rect);
    let phrase_words: Vec<&str> = state
        .phrase
        .as_deref()
        .map(|phrase| words(phrase).collect())
        .unwrap_or_default();
    let mut lines: Vec<Line<'_>> = Vec::with_capacity(ROWS * lines_per_row);
    for row in 0..ROWS {
        let shown = state.ceremony.row_shown(row);
        for part in 0..lines_per_row {
            let pointer = if row == state.ceremony.row && part == 0 {
                theme.glyphs.pointer
            } else {
                " "
            };
            let mut spans = vec![Span::styled(format!("{pointer} "), theme.accent())];
            let first = part * per_line;
            for column in first..(first + per_line).min(PER_ROW) {
                let index = row * PER_ROW + column;
                let Some(word) = phrase_words.get(index) else {
                    continue;
                };
                spans.push(Span::styled(format!("{:02} ", index + 1), theme.muted()));
                if shown {
                    let width = usize::from(WORD_MASK);
                    spans.push(Span::styled(format!("{word:<width$}  "), theme.warn()));
                } else {
                    spans.push(Span::styled(
                        format!("{}  ", mask(theme.glyphs, usize::from(WORD_MASK))),
                        theme.zebra(),
                    ));
                }
            }
            lines.push(Line::from(spans));
        }
    }
    frame.render_widget(Paragraph::new(lines), grid_inner);
    draw_footer(frame, footer, state, ctx);
    hint_bar(frame, hints, Scope::Ceremony, "", ctx);
}

fn draw_verify(frame: &mut Frame<'_>, area: Rect, verify: &Verify, ctx: &Ctx) {
    let theme = &ctx.theme;
    let [body, hints] = body_and_hints(area);
    let card = centered(body, body.width.min(84), 18);
    let block = panel(titled("Prove you saved it", (3, 4), card.width, ctx), theme);
    let inner = block.inner(card);
    frame.render_widget(block, card);
    let [_, cards, message, note] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(10),
        Constraint::Length(2),
        Constraint::Min(1),
    ])
    .areas(inner);
    let shake = verify.shake(ctx.now);
    let shifted = Rect {
        x: cards.x.saturating_add_signed(shake),
        ..cards
    };
    let columns = Layout::horizontal([Constraint::Ratio(1, 3); CARDS]).split(shifted);
    for (card, rect) in columns.iter().enumerate() {
        let [title, list] =
            Layout::vertical([Constraint::Length(2), Constraint::Min(3)]).areas(*rect);
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!("   Pick word #{}", verify.position(card)),
                theme.strong(),
            )),
            title,
        );
        let focused = card == verify.card && verify.confirmed <= card;
        let done = card < verify.confirmed;
        let border = if focused {
            theme.accent()
        } else {
            theme.muted()
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(border);
        let box_rect = Rect {
            x: list.x + 2,
            width: list.width.saturating_sub(4).min(18),
            height: 6,
            ..list
        };
        let inner = block.inner(box_rect);
        frame.render_widget(block, box_rect);
        let lines: Vec<Line<'_>> = if done {
            vec![Line::from(Span::styled(
                format!("{} picked", theme.glyphs.ok),
                theme.accent(),
            ))]
        } else if focused {
            verify
                .choices(card)
                .iter()
                .enumerate()
                .map(|(index, word)| {
                    let chosen = index == verify.pick(card);
                    let pointer = if chosen { theme.glyphs.pointer } else { " " };
                    let style = if chosen {
                        theme.selected()
                    } else {
                        theme.text()
                    };
                    Line::from(Span::styled(format!("{pointer} {word}"), style))
                })
                .collect()
        } else {
            vec![Line::from(Span::styled(theme.glyphs.cursor, theme.muted()))]
        };
        frame.render_widget(Paragraph::new(lines), inner);
    }
    if verify.failed {
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!("   {} Not quite. Check your paper.", theme.glyphs.fail),
                theme.danger(),
            )),
            message,
        );
    }
    frame.render_widget(
        Paragraph::new(Span::styled(
            "   Positions come from the OS CSPRNG. Decoys are BIP39 words.",
            theme.muted(),
        )),
        note,
    );
    hint_bar(frame, hints, Scope::Verify, "", ctx);
}

/// The "written" box, the continue button, and how reveal works.
fn draw_footer(frame: &mut Frame<'_>, footer: Rect, state: &CreateState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let ceremony = &state.ceremony;
    let reveal = if ctx.caps.key_release {
        "Hold Space on the grid to reveal the marked row."
    } else {
        "Space on the grid reveals the marked row for 5 s."
    };
    let focused = ceremony.focus == CeremonyFocus::Written;
    let pointer = if focused { theme.glyphs.pointer } else { " " };
    let [text, action] =
        Layout::horizontal([Constraint::Min(20), Constraint::Length(18)]).areas(footer);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(
                format!(" {pointer} {} I wrote it down", checkbox(ceremony.written)),
                if focused {
                    theme.selected()
                } else if ceremony.written {
                    theme.accent()
                } else {
                    theme.text()
                },
            )),
            Line::from(Span::styled(format!("   {reveal}"), theme.muted())),
            Line::from(Span::styled(
                "   One row at a time: all 24 words never share the screen.",
                theme.muted(),
            )),
        ])
        .wrap(ratatui::widgets::Wrap { trim: false }),
        text,
    );
    let rect = Rect {
        x: action.x + 2,
        width: action.width.saturating_sub(4),
        height: 3.min(action.height),
        ..action
    };
    button(
        frame,
        rect,
        "Continue →",
        ceremony.written,
        ceremony.focus == CeremonyFocus::Continue,
        theme,
    );
}
