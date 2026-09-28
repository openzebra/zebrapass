//! Restore from phrase: masked word grid with autocomplete, passphrase,
//! vault file, and name. Then the enroll step.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::restore::{RestoreField, RestoreState, RestoreStep, REVEAL_LAST};
use crate::app::keymap::Scope;
use crate::secure::phrase_input::{PhraseInput, MAX_WORDS};
use crate::ui::layout::{body_and_hints, centered};
use crate::ui::theme::Theme;
use crate::ui::widgets::chrome::{hint_bar, panel};
use crate::ui::widgets::field::{boxed, secret_line, text_line};
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
                spans.push(Span::styled(theme.glyphs.cursor, theme.accent()));
            }
        }
    }
    lines.push(Line::from(spans));
    lines
}

/// Draw the restore screen.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &RestoreState, ctx: &Ctx) {
    if state.step == RestoreStep::Enroll {
        crate::ui::screens::enroll::draw(frame, area, &state.enroll, (2, 2), ctx);
        return;
    }
    let theme = &ctx.theme;
    let [body, hints] = body_and_hints(area);
    let card = centered(body, body.width.min(86), 26);
    let block = panel(" Restore from phrase ", theme);
    let inner = block.inner(card);
    frame.render_widget(block, card);
    let [grid, suggest, status, pass_label, pass, file_label, file, name_row, error] =
        Layout::vertical([
            Constraint::Length(5),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .areas(inner);
    draw_words(frame, grid, suggest, status, state, ctx);
    let label = |text: &'static str| Paragraph::new(Span::styled(text, theme.strong()));
    frame.render_widget(label("   Passphrase (optional, \"25th word\")"), pass_label);
    let pass_focus = state.field == RestoreField::Passphrase;
    let pass_rect = Rect {
        x: pass.x + 2,
        width: pass.width.min(40),
        ..pass
    };
    boxed(
        frame,
        pass_rect,
        secret_line(&state.passphrase, pass_focus, false, theme),
        pass_focus,
        theme,
    );
    frame.render_widget(
        label("   Vault file (backup or copy from another device)"),
        file_label,
    );
    let file_focus = state.field == RestoreField::Source;
    let file_rect = Rect {
        x: file.x + 2,
        width: file.width.saturating_sub(4),
        ..file
    };
    boxed(
        frame,
        file_rect,
        text_line(
            &state.source,
            file_rect.width.saturating_sub(2),
            file_focus,
            theme,
        ),
        file_focus,
        theme,
    );
    let [name_label, name_box] =
        Layout::horizontal([Constraint::Length(16), Constraint::Length(40)]).areas(name_row);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled("   Name", theme.strong())),
        ]),
        name_label,
    );
    let name_focus = state.field == RestoreField::Name;
    boxed(
        frame,
        name_box,
        text_line(
            &state.name,
            name_box.width.saturating_sub(2),
            name_focus,
            theme,
        ),
        name_focus,
        theme,
    );
    if let Some(message) = state.error {
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!("   {} {message}", theme.glyphs.fail),
                theme.danger(),
            )),
            error,
        );
    }
    hint_bar(frame, hints, Scope::Restore, "", ctx);
}

/// The word grid, its suggestions, and the count line.
fn draw_words(
    frame: &mut Frame<'_>,
    grid: Rect,
    suggest: Rect,
    status: Rect,
    state: &RestoreState,
    ctx: &Ctx,
) {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let focused = state.field == RestoreField::Phrase;
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(if focused {
            theme.accent()
        } else {
            theme.muted()
        });
    let grid_inner = block.inner(grid);
    frame.render_widget(block, grid);
    let lines = word_grid(
        &state.phrase,
        focused,
        state.hide_current,
        state.reveal.is_shown(REVEAL_LAST),
        theme,
    );
    frame.render_widget(Paragraph::new(lines), grid_inner);
    let suggestions = state.phrase.suggestions(4);
    if focused
        && !state.phrase.current().is_empty()
        && !state.hide_current
        && !suggestions.is_empty()
    {
        let mut spans = vec![Span::styled("   suggestions: ", theme.muted())];
        for (index, word) in suggestions.iter().enumerate() {
            let (style, pointer) = if index == 0 {
                (theme.selected(), glyphs.pointer)
            } else {
                (theme.text(), " ")
            };
            spans.push(Span::styled(format!("{pointer} {word}  "), style));
        }
        spans.push(Span::styled(
            format!("({} match, Tab to accept)", suggestions.len()),
            theme.muted(),
        ));
        frame.render_widget(
            Paragraph::new(vec![Line::from(""), Line::from(spans)]),
            suggest,
        );
    }
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("   {} / 24 words     ", state.phrase.count()),
                theme.text(),
            ),
            Span::styled(
                format!("{} all words in wordlist     ", glyphs.ok),
                theme.accent(),
            ),
            Span::styled("checksum: checked on restore", theme.muted()),
        ])),
        status,
    );
}
