//! Unlock screen: vault card, factor chips from the public wrap directory,
//! the factor input, one uniform error, and the backoff stripe.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::unlock::{Mode, RecoveryField, UnlockState, MAX_BACKOFF, REVEAL_PASSWORD};
use crate::app::keymap::Scope;
use crate::ui::layout::{body_and_hints, centered};
use crate::ui::screens::restore::word_grid;
use crate::ui::widgets::chrome::{hint_bar, modal, row_style};
use crate::ui::widgets::field::{boxed, secret_line};
use crate::ui::widgets::fingerprint::{grouped_hex, stripe_print};
use crate::ui::widgets::meter::bar;
use crate::ui::widgets::stripes::rule;
use crate::vault::discover::VaultRef;

fn vault_title(vault: Option<&VaultRef>) -> String {
    vault.and_then(|vault| vault.vault_id).map_or_else(
        || String::from("Vault"),
        |id| format!("Vault {}", grouped_hex(&id, 2)),
    )
}

/// Draw the unlock screen.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &UnlockState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let [body, hints] = body_and_hints(area);
    let recovery = state.mode == Mode::Recovery;
    let input_height = if recovery { 9 } else { 3 };
    // Tall enough: the striped vault card and breathing room; otherwise one
    // title line and no gaps, so nothing overlaps at 60x20.
    let roomy = body.height >= input_height + 17;
    let (head, gap) = if roomy { (6, 1) } else { (1, 0) };
    let height = head + 1 + input_height + 4 + gap * 4;
    let card = centered(body, body.width.min(96), height);
    let [header, _, chips, _, input, _, error, _, print] = Layout::vertical([
        Constraint::Length(head),
        Constraint::Length(gap),
        Constraint::Length(1),
        Constraint::Length(gap),
        Constraint::Length(input_height),
        Constraint::Length(gap),
        Constraint::Length(2),
        Constraint::Length(gap),
        Constraint::Length(1),
    ])
    .areas(card);
    let title = format!("{}  {}", glyphs.vk, vault_title(state.vault()));
    let subtitle = state.directory.as_ref().map_or_else(
        |error| error.message().to_owned(),
        |_| String::from("locked"),
    );
    if roomy {
        draw_card(frame, header, &title, &subtitle, ctx);
    } else {
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(title, theme.strong()),
                Span::styled(format!("  {} {subtitle}", glyphs.dot), theme.muted()),
            ]))
            .alignment(Alignment::Center),
            header,
        );
    }
    frame.render_widget(
        Paragraph::new(chips_line(state, card.width >= 90, ctx)).alignment(Alignment::Center),
        chips,
    );
    draw_input(frame, input, state, ctx);
    frame.render_widget(
        Paragraph::new(error_lines(state, ctx)).alignment(Alignment::Center),
        error,
    );
    if let Some(id) = state.vault().and_then(|vault| vault.vault_id) {
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("vault  ", theme.muted()),
                Span::styled(stripe_print(&id, glyphs), theme.zebra()),
                Span::styled(format!("  {}", grouped_hex(&id, 4)), theme.muted()),
            ]))
            .alignment(Alignment::Center),
            print,
        );
    }
    hint_bar(frame, hints, Scope::Unlock, "", ctx);
    if let Some(cursor) = state.picker {
        draw_picker(frame, body, state, cursor, ctx);
    }
}

fn draw_input(frame: &mut Frame<'_>, area: Rect, state: &UnlockState, ctx: &Ctx) {
    let theme = &ctx.theme;
    match state.mode {
        Mode::Password => {
            let revealed = state.reveal.is_shown(REVEAL_PASSWORD);
            secret_box(
                frame,
                area,
                "Password  ",
                secret_line(&state.password, true, revealed, theme),
                ctx,
            );
        }
        Mode::Device => {
            secret_box(
                frame,
                area,
                "Device PIN  ",
                secret_line(&state.pin, true, false, theme),
                ctx,
            );
        }
        Mode::Recovery => {
            let [words, pass] =
                Layout::vertical([Constraint::Length(5), Constraint::Length(4)]).areas(area);
            let grid = centered(words, words.width.min(84), 5);
            let focused = state.recovery_field == RecoveryField::Phrase;
            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(" recovery phrase ")
                .border_style(if focused {
                    theme.accent()
                } else {
                    theme.muted()
                });
            let inner = block.inner(grid);
            frame.render_widget(block, grid);
            frame.render_widget(
                Paragraph::new(word_grid(&state.phrase, focused, false, false, theme)),
                inner,
            );
            let pass_focus = state.recovery_field == RecoveryField::Passphrase;
            let [label, field] =
                Layout::horizontal([Constraint::Length(14), Constraint::Length(36)])
                    .flex(ratatui::layout::Flex::Center)
                    .areas(Rect {
                        height: 3.min(pass.height),
                        y: pass.y + 1,
                        ..pass
                    });
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from(""),
                    Line::from(Span::styled("Passphrase  ", theme.muted())),
                ])
                .alignment(Alignment::Right),
                label,
            );
            boxed(
                frame,
                field,
                secret_line(&state.passphrase, pass_focus, false, theme),
                pass_focus,
                theme,
            );
        }
    }
}

fn draw_picker(frame: &mut Frame<'_>, area: Rect, state: &UnlockState, cursor: usize, ctx: &Ctx) {
    let theme = &ctx.theme;
    let height = u16::try_from(state.vaults.len().min(10) + 2).unwrap_or(12);
    let rect = centered(area, 56, height);
    frame.render_widget(Clear, rect);
    let inner = modal(frame, rect, "Choose a vault", theme);
    let lines: Vec<Line<'_>> = state
        .vaults
        .iter()
        .enumerate()
        .map(|(index, vault)| {
            let chosen = index == cursor;
            let pointer = if chosen { theme.glyphs.pointer } else { " " };
            let print = vault
                .vault_id
                .map(|id| stripe_print(&id, theme.glyphs))
                .unwrap_or_default();
            Line::from(vec![
                Span::styled(format!("{pointer} "), theme.accent()),
                Span::styled(
                    format!("{:<22}", vault_title(Some(vault))),
                    row_style(chosen, theme),
                ),
                Span::styled(print, theme.zebra()),
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

/// The striped vault card.
fn draw_card(frame: &mut Frame<'_>, header: Rect, title: &str, subtitle: &str, ctx: &Ctx) {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let frame_width = 34u16.min(header.width);
    let box_rect = centered(header, frame_width, 6);
    let stripes = Span::styled(rule(glyphs, frame_width), theme.zebra());
    let side = |text: Span<'static>| {
        Line::from(vec![
            Span::styled(glyphs.mask, theme.zebra()),
            text,
            Span::styled(glyphs.mask, theme.zebra()),
        ])
    };
    let inner_width = usize::from(frame_width.saturating_sub(2));
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(stripes.clone()),
            side(Span::raw(" ".repeat(inner_width))),
            side(Span::styled(
                format!("{title:^inner_width$}"),
                theme.strong(),
            )),
            side(Span::styled(
                format!("{subtitle:^inner_width$}"),
                theme.muted(),
            )),
            Line::from(stripes),
        ]),
        box_rect,
    );
}

/// A right-aligned label and a boxed secret, centered in `area`.
fn secret_box(frame: &mut Frame<'_>, area: Rect, label: &str, line: Line<'_>, ctx: &Ctx) {
    let theme = &ctx.theme;
    let [label_rect, field] = Layout::horizontal([Constraint::Length(14), Constraint::Length(36)])
        .flex(ratatui::layout::Flex::Center)
        .areas(area);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(label.to_owned(), theme.text())),
        ])
        .alignment(Alignment::Right),
        label_rect,
    );
    boxed(frame, field, line, true, theme);
}

/// Which factor kinds the vault has: glyph, word, and dot (never color alone).
fn chips_line(state: &UnlockState, wide: bool, ctx: &Ctx) -> Line<'static> {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let found = state.presence();
    let chip = |glyph: &'static str, name: &'static str, on: bool| {
        vec![
            Span::styled(
                format!("{glyph} {name} "),
                if on { theme.text() } else { theme.muted() },
            ),
            Span::styled(
                if on { glyphs.on } else { glyphs.off },
                if on { theme.accent() } else { theme.muted() },
            ),
            Span::raw(if wide { "   " } else { " " }),
        ]
    };
    let mut spans = vec![Span::styled(
        if wide {
            "factors on this vault:   "
        } else {
            "factors: "
        },
        theme.muted(),
    )];
    spans.extend(chip(
        glyphs.password,
        if wide { "password" } else { "pw" },
        found.password,
    ));
    spans.extend(chip(
        glyphs.device,
        if wide { "device" } else { "dev" },
        found.devices > 0,
    ));
    spans.extend(chip(glyphs.hw_key, "key", found.hw_keys > 0));
    spans.extend(chip(glyphs.recovery, "phrase", found.recovery));
    Line::from(spans)
}

/// The uniform error and the backoff bar.
fn error_lines(state: &UnlockState, ctx: &Ctx) -> Vec<Line<'static>> {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let mut lines = Vec::new();
    if let Some(error) = state.error {
        let attempt = if state.attempts > 0 {
            format!("   (attempt {})", state.attempts)
        } else {
            String::new()
        };
        lines.push(Line::from(Span::styled(
            format!("{} {}{attempt}", glyphs.fail, error.message()),
            theme.danger(),
        )));
    }
    if let Some(at) = state.retry_at.filter(|at| *at > ctx.now) {
        let left = at.saturating_duration_since(ctx.now).as_secs_f64();
        let fraction = left / MAX_BACKOFF.as_secs_f64();
        lines.push(Line::from(vec![
            Span::styled(bar(fraction.min(1.0), 20, glyphs), theme.warn()),
            Span::styled(format!("  next attempt in {left:.0}s"), theme.muted()),
        ]));
    }
    lines
}
