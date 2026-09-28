//! "How will you unlock on this device?" — factor cards and the password.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::enroll::{
    EnrollFactor, EnrollFocus, EnrollState, REVEAL_NEW, REVEAL_REPEAT,
};
use crate::app::keymap::Scope;
use crate::ui::layout::{body_and_hints, centered};
use crate::ui::screens::create::titled;
use crate::ui::widgets::chrome::{hint_bar, panel};
use crate::ui::widgets::field::{boxed, secret_line};
use crate::ui::widgets::meter::strength_spans;
use crate::vault::chip::Chips;

/// Draw the enroll step with its wizard position `step`.
pub fn draw(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &EnrollState,
    step: (usize, usize),
    ctx: &Ctx,
) {
    let theme = &ctx.theme;
    let [body, hints] = body_and_hints(area);
    let card = centered(body, body.width.min(84), 24);
    let block = panel(
        titled("How will you unlock on this device?", step, card.width, ctx),
        theme,
    );
    let inner = block.inner(card);
    frame.render_widget(block, card);
    let [cards, _, password, strength, repeat, message] = Layout::vertical([
        Constraint::Length(8),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Min(1),
    ])
    .areas(inner);
    draw_cards(frame, cards, state, ctx);
    if state.factor == EnrollFactor::Password {
        let new_focus = state.focus == EnrollFocus::Password;
        let revealed = state.reveal.is_shown(REVEAL_NEW);
        labeled_secret(
            frame,
            password,
            "New password",
            secret_line(&state.password, new_focus, revealed, theme),
            new_focus,
            ctx,
        );
        let mut spans = vec![Span::styled("   Strength       ", theme.text())];
        spans.extend(strength_spans(state.strength(), 10, theme));
        frame.render_widget(Paragraph::new(Line::from(spans)), strength);
        let repeat_focus = state.focus == EnrollFocus::Repeat;
        let revealed = state.reveal.is_shown(REVEAL_REPEAT);
        let field = labeled_secret(
            frame,
            repeat,
            "Repeat",
            secret_line(&state.repeat, repeat_focus, revealed, theme),
            repeat_focus,
            ctx,
        );
        let verdict = match state.matches() {
            Some(true) => Span::styled(format!("  {} matches", theme.glyphs.ok), theme.accent()),
            Some(false) => Span::styled(format!("  {} differs", theme.glyphs.fail), theme.danger()),
            None => Span::raw(""),
        };
        let verdict_rect = Rect {
            x: field.right(),
            y: field.y + 1,
            width: repeat.right().saturating_sub(field.right()),
            height: 1,
        };
        frame.render_widget(Paragraph::new(verdict), verdict_rect);
    } else if state.factor == EnrollFactor::Device {
        let where_ = ctx.chips.keyring().kind();
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    format!("   New device keys (X25519 + ML-KEM-768) go to the {where_}."),
                    theme.text(),
                )),
                Line::from(Span::styled(
                    "   On this device you unlock with Enter; nothing to type.",
                    theme.muted(),
                )),
                Line::from(Span::styled(
                    "   Other devices restore with the phrase and enroll their own.",
                    theme.muted(),
                )),
            ]),
            Rect {
                height: password.height + strength.height + repeat.height,
                ..password
            },
        );
    }
    draw_notes(frame, message, state, ctx);
    hint_bar(frame, hints, Scope::Enroll, "", ctx);
}

/// A label on the left and a boxed secret on the right; returns the box.
fn labeled_secret(
    frame: &mut Frame<'_>,
    row: Rect,
    label: &str,
    line: Line<'_>,
    focused: bool,
    ctx: &Ctx,
) -> Rect {
    let theme = &ctx.theme;
    let [left, right] =
        Layout::horizontal([Constraint::Length(17), Constraint::Min(10)]).areas(row);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(format!("   {label:<14}"), theme.text())),
        ]),
        left,
    );
    let field = Rect {
        width: right.width.min(40),
        ..right
    };
    boxed(frame, field, line, focused, theme);
    field
}

/// The factor cards.
fn draw_cards(frame: &mut Frame<'_>, area: Rect, state: &EnrollState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let chip_note = if Chips::available() {
        "dev backend"
    } else {
        "not built yet"
    };
    let keyring = ctx.chips.keyring();
    let device_note = if keyring.persistent() {
        ""
    } else {
        "lost on quit"
    };
    let specs: [(EnrollFactor, String, &str, &str, &str); 4] = [
        (
            EnrollFactor::Password,
            format!("{} Password", glyphs.password),
            "Argon2id → KEK",
            "works everywhere",
            "",
        ),
        (
            EnrollFactor::Device,
            format!("{} This device", glyphs.device),
            "X25519 + ML-KEM",
            keyring.kind(),
            device_note,
        ),
        (
            EnrollFactor::Chip,
            format!("{} Secure chip", glyphs.chip),
            "P-256 + ML-KEM",
            "bound to this box",
            chip_note,
        ),
        (
            EnrollFactor::HwKey,
            format!("{} Hardware key", glyphs.hw_key),
            "FIDO2 PRF",
            "",
            "coming soon",
        ),
    ];
    let columns = Layout::horizontal([Constraint::Ratio(1, 4); 4]).split(area);
    for ((factor, title, primitive, detail, note), rect) in specs.iter().zip(columns.iter()) {
        let chosen = state.factor == *factor;
        let focused = chosen && state.focus == EnrollFocus::Cards;
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(if focused {
                BorderType::Thick
            } else {
                BorderType::Rounded
            })
            .border_style(if chosen {
                theme.accent()
            } else {
                theme.muted()
            });
        let mut lines = vec![
            Line::from(Span::styled(title.clone(), theme.strong())),
            Line::from(""),
            Line::from(Span::styled(*primitive, theme.text())),
            Line::from(Span::styled(*detail, theme.muted())),
        ];
        let note_style = if matches!(*factor, EnrollFactor::Password | EnrollFactor::Device) {
            theme.accent()
        } else {
            theme.warn()
        };
        if !note.is_empty() {
            lines.push(Line::from(Span::styled(*note, note_style)));
        }
        frame.render_widget(Paragraph::new(lines).block(block), *rect);
    }
}

/// Validation message and the keep-existing hint.
fn draw_notes(frame: &mut Frame<'_>, area: Rect, state: &EnrollState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let mut notes = Vec::new();
    if let Some(text) = state.message {
        notes.push(Line::from(Span::styled(
            format!("   {} {text}", theme.glyphs.attention),
            theme.warn(),
        )));
    }
    if state.existing_password && state.factor == EnrollFactor::Password {
        notes.push(Line::from(Span::styled(
            "   This vault already has a password: leave both empty to keep it.",
            theme.muted(),
        )));
    }
    frame.render_widget(Paragraph::new(notes), area);
}
