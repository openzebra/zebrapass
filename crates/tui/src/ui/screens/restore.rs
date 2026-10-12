//! Restore from phrase: masked word grid with autocomplete, passphrase,
//! optional vault file and device address, and name. Then the enroll step.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::restore::{RestoreField, RestoreState, RestoreStep, REVEAL_LAST};
use crate::app::keymap::Scope;
use crate::secure::phrase_input::{PhraseInput, MAX_WORDS};
use crate::ui::layout::{body_and_hints, centered};
use crate::ui::screens::create::titled;
use crate::ui::theme::Theme;
use crate::ui::widgets::chrome::{button, hint_bar, panel};
use crate::ui::widgets::field::{block_cursor, boxed, secret_line, text_line};
use crate::ui::widgets::stripes::mask;

/// Words per grid row.
const PER_ROW: usize = 8;

/// The word grid: finished words masked, the current word visible (unless
/// hidden), the last word revealed on request.
#[must_use]
pub fn word_grid<'a>(
    phrase: &PhraseInput,
    focused: bool,
    hide_current: bool,
    reveal_last: bool,
    theme: &Theme,
) -> Vec<Line<'a>> {
    let mut lines = Vec::new();
    let mut spans: Vec<Span<'a>> = Vec::new();
    let count = phrase.count();
    for index in 0..=count.min(MAX_WORDS - 1) {
        if index > 0 && index % PER_ROW == 0 {
            lines.push(Line::from(std::mem::take(&mut spans)));
        }
        spans.push(Span::styled(format!("{:02} ", index + 1), theme.muted()));
        if index < count {
            let last = index + 1 == count;
            match phrase.word(index).filter(|_| last && reveal_last) {
                Some(word) => spans.push(Span::styled(format!("{word:<8} "), theme.warn())),
                None => spans.push(Span::styled(
                    format!("{}     ", mask(theme.glyphs, 4)),
                    theme.zebra(),
                )),
            }
        } else {
            let current = String::from_utf8_lossy(phrase.current()).into_owned();
            let shown = if hide_current {
                mask(theme.glyphs, current.chars().count().min(1) * 4)
            } else {
                current
            };
            spans.push(Span::styled(shown, theme.text()));
            if focused {
                spans.push(block_cursor("", theme));
            }
        }
    }
    lines.push(Line::from(spans));
    lines
}

/// Most slot grid columns on the restore screen.
const SLOT_COLUMNS: usize = 6;

/// Cells of one slot: ` 01 ` and the word.
const SLOT_CELLS: u16 = 4 + WORD_CELLS;

/// Slot columns that fit `width` inner cells.
fn slot_columns(width: u16) -> usize {
    usize::from(width / SLOT_CELLS).clamp(1, SLOT_COLUMNS)
}

/// All 24 slots at once: finished words masked, the current word with the
/// cursor, and empty slots as dots, so progress reads at a glance.
fn slot_grid<'a>(
    state: &RestoreState,
    columns: usize,
    focused: bool,
    theme: &Theme,
) -> Vec<Line<'a>> {
    let phrase = &state.phrase;
    let count = phrase.count();
    let reveal_last = state.reveal.is_shown(REVEAL_LAST);
    let slot = usize::from(WORD_CELLS);
    (0..MAX_WORDS)
        .collect::<Vec<_>>()
        .chunks(columns)
        .map(|row| {
            let mut spans = Vec::with_capacity(row.len() * 3);
            for index in row.iter().copied() {
                spans.push(Span::styled(format!(" {:02} ", index + 1), theme.muted()));
                if index < count {
                    let revealed = phrase
                        .word(index)
                        .filter(|_| reveal_last && index + 1 == count);
                    spans.push(revealed.map_or_else(
                        || Span::styled(format!("{:<slot$}", mask(theme.glyphs, 5)), theme.zebra()),
                        |word| Span::styled(format!("{word:<slot$}"), theme.warn()),
                    ));
                } else if index == count && count < MAX_WORDS {
                    let typed = String::from_utf8_lossy(phrase.current()).into_owned();
                    let shown = if state.hide_current {
                        mask(theme.glyphs, typed.chars().count().min(1) * 4)
                    } else {
                        typed
                    };
                    let used = shown.chars().count();
                    spans.push(Span::styled(shown, theme.text()));
                    if focused {
                        spans.push(block_cursor("", theme));
                    }
                    let pad = slot.saturating_sub(used + usize::from(focused));
                    spans.push(Span::raw(" ".repeat(pad)));
                } else {
                    spans.push(Span::styled(format!("{:<slot$}", "·····"), theme.muted()));
                }
            }
            Line::from(spans)
        })
        .collect()
}

/// Mask and word width inside one slot.
const WORD_CELLS: u16 = 8;

/// Draw the restore screen.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &RestoreState, ctx: &Ctx) {
    if state.step == RestoreStep::Enroll {
        crate::ui::screens::enroll::draw(frame, area, &state.enroll, (2, 2), ctx);
        return;
    }
    let theme = &ctx.theme;
    let [body, hints] = body_and_hints(area);
    let card = centered(body, body.width.min(86), 30);
    let block = panel(
        titled("Restore from phrase", (1, 2), card.width, ctx),
        theme,
    );
    let inner = block.inner(card);
    frame.render_widget(block, card);
    let columns = slot_columns(inner.width.saturating_sub(6));
    let grid_rows = u16::try_from(MAX_WORDS.div_ceil(columns)).unwrap_or(24);
    let [phrase_head, grid, suggest, _, source_head, sources, source_status_row, details, footer] =
        Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(grid_rows + 2),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(4),
            Constraint::Min(3),
        ])
        .areas(inner);
    section(
        frame,
        phrase_head,
        "1",
        "Recovery phrase",
        &progress(state, ctx),
        ctx,
    );
    draw_words(frame, grid, suggest, state, columns, ctx);
    draw_source(frame, [source_head, sources, source_status_row], state, ctx);
    draw_details(frame, details, state, ctx);
    draw_footer(frame, footer, state, ctx);
    hint_bar(frame, hints, Scope::Restore, "", ctx);
}

/// The optional vault file: empty means the network brings the vault.
fn draw_source(
    frame: &mut Frame<'_>,
    [head, boxed_area, status]: [Rect; 3],
    state: &RestoreState,
    ctx: &Ctx,
) {
    let theme = &ctx.theme;
    section(
        frame,
        head,
        "2",
        "Vault file (optional)",
        "empty → sync over the network",
        ctx,
    );
    let focus = state.field == RestoreField::Source;
    let rect = Rect {
        x: boxed_area.x + 2,
        width: boxed_area.width.saturating_sub(4),
        ..boxed_area
    };
    boxed(
        frame,
        rect,
        text_line(&state.source, rect.width.saturating_sub(2), focus, theme),
        focus,
        theme,
    );
    frame.render_widget(Paragraph::new(file_hint(state, theme)), status);
}

/// What is known about the vault file: nothing to say when it is empty.
fn file_hint<'a>(state: &RestoreState, theme: &Theme) -> Span<'a> {
    if state.source.value().trim().is_empty() {
        return Span::styled(
            "    your vault arrives from your other device once this one is unlocked",
            theme.muted(),
        );
    }
    state.source_factors.map_or_else(
        || {
            Span::styled(
                format!("    {} no vault file at this path", theme.glyphs.fail),
                theme.warn(),
            )
        },
        |factors| {
            Span::styled(
                format!(
                    "    {} ZebraPass vault · {factors} unlock factor(s)",
                    theme.glyphs.ok
                ),
                theme.accent(),
            )
        },
    )
}

/// `3 / 24 words` plus a short bar.
fn progress(state: &RestoreState, ctx: &Ctx) -> String {
    let count = state.phrase.count();
    let filled = count * 12 / MAX_WORDS;
    let (on, off) = if ctx.theme.ascii {
        ("#", "-")
    } else {
        ("▰", "▱")
    };
    format!(
        "{count:>2} / {MAX_WORDS} words  {}{}",
        on.repeat(filled),
        off.repeat(12 - filled)
    )
}

/// A numbered section heading with a muted note at the right.
fn section(frame: &mut Frame<'_>, area: Rect, number: &str, title: &str, note: &str, ctx: &Ctx) {
    let theme = &ctx.theme;
    let head = format!("  {number}  {title}");
    let pad =
        usize::from(area.width).saturating_sub(head.chars().count() + note.chars().count() + 2);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(head, theme.strong()),
            Span::raw(" ".repeat(pad)),
            Span::styled(note.to_owned(), theme.muted()),
        ])),
        area,
    );
}

/// The slot grid and its suggestions.
fn draw_words(
    frame: &mut Frame<'_>,
    grid: Rect,
    suggest: Rect,
    state: &RestoreState,
    columns: usize,
    ctx: &Ctx,
) {
    let theme = &ctx.theme;
    let focused = state.field == RestoreField::Phrase;
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(if focused {
            theme.accent()
        } else {
            theme.muted()
        });
    let rect = Rect {
        x: grid.x + 2,
        width: grid.width.saturating_sub(4),
        ..grid
    };
    let grid_inner = block.inner(rect);
    frame.render_widget(block, rect);
    // A short terminal cannot hold every row: scroll so the slot being
    // typed stays visible.
    let current_row = state.phrase.count().min(MAX_WORDS - 1) / columns;
    let visible = usize::from(grid_inner.height).max(1);
    let skip = (current_row + 1).saturating_sub(visible);
    let lines = slot_grid(state, columns, focused, theme);
    frame.render_widget(
        Paragraph::new(lines.into_iter().skip(skip).collect::<Vec<_>>()),
        grid_inner,
    );
    let suggestions = state.phrase.suggestions(4);
    let line = if !focused || state.hide_current {
        Line::from("")
    } else if state.phrase.current().is_empty() {
        Line::from(Span::styled(
            "    type a word · Space next · Tab accept · Ctrl-R reveal last",
            theme.muted(),
        ))
    } else {
        let mut spans = vec![Span::styled("    ", theme.muted())];
        for (index, word) in suggestions.iter().enumerate() {
            let (style, pointer) = if index == 0 {
                (theme.selected(), theme.glyphs.pointer)
            } else {
                (theme.text(), " ")
            };
            spans.push(Span::styled(format!("{pointer} {word}  "), style));
        }
        spans.push(Span::styled("Tab accept", theme.muted()));
        Line::from(spans)
    };
    frame.render_widget(Paragraph::new(line), suggest);
}

/// Name on this device and the optional passphrase, side by side.
fn draw_details(frame: &mut Frame<'_>, area: Rect, state: &RestoreState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let [labels, boxes] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(3)]).areas(area);
    let columns = [Constraint::Percentage(50), Constraint::Percentage(50)];
    let [name_label, pass_label] = Layout::horizontal(columns).areas(labels);
    let [name_box, pass_box] = Layout::horizontal(columns).areas(boxes);
    let label = |text: &'static str| Paragraph::new(Span::styled(text, theme.strong()));
    frame.render_widget(label("  3  Name on this device"), name_label);
    frame.render_widget(
        label(if pass_label.width >= 34 {
            "  Passphrase (optional 25th word)"
        } else {
            "  Passphrase (optional)"
        }),
        pass_label,
    );
    let inset = |rect: Rect| Rect {
        x: rect.x + 2,
        width: rect.width.saturating_sub(4),
        ..rect
    };
    let name_focus = state.field == RestoreField::Name;
    let name_rect = inset(name_box);
    boxed(
        frame,
        name_rect,
        text_line(
            &state.name,
            name_rect.width.saturating_sub(2),
            name_focus,
            theme,
        ),
        name_focus,
        theme,
    );
    let pass_focus = state.field == RestoreField::Passphrase;
    boxed(
        frame,
        inset(pass_box),
        secret_line(&state.passphrase, pass_focus, false, theme),
        pass_focus,
        theme,
    );
}

/// The last problem and the continue button.
fn draw_footer(frame: &mut Frame<'_>, area: Rect, state: &RestoreState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let [message, action] =
        Layout::horizontal([Constraint::Min(10), Constraint::Length(18)]).areas(area);
    if let Some(problem) = state.error {
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!("  {} {problem}", theme.glyphs.fail),
                theme.danger(),
            ))
            .wrap(ratatui::widgets::Wrap { trim: true }),
            Rect {
                y: message.y + 1,
                ..message
            },
        );
    }
    let ready = state.phrase.plausible();
    let rect = Rect {
        x: action.x + 1,
        width: action.width.saturating_sub(3),
        height: 3.min(action.height),
        ..action
    };
    button(frame, rect, "Continue →", ready, false, theme);
}
