//! Unlock screen: one balanced card with storage, factor, secret, and actions.

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph};
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::unlock::{Mode, UnlockFocus, UnlockState, MAX_BACKOFF, REVEAL_PASSWORD};
use crate::app::keymap::Scope;
use crate::ui::layout::{body_and_hints, centered};
use crate::ui::widgets::chrome::{button, hint_bar, modal, panel, row_style};
use crate::ui::widgets::field::{boxed, secret_line_with_placeholder};
use crate::ui::widgets::fingerprint::{grouped_hex, stripe_print};
use crate::ui::widgets::meter::bar;
use crate::ui::widgets::stripes::rule;
use crate::vault::discover::VaultRef;

const CARD_WIDTH: u16 = 64;
const CONTROL_WIDTH: u16 = 44;

fn vault_title(vault: Option<&VaultRef>) -> String {
    vault.and_then(|vault| vault.vault_id).map_or_else(
        || String::from("Vault"),
        |id| format!("Vault {}", grouped_hex(&id, 2)),
    )
}

/// Draw the unlock screen.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &UnlockState, ctx: &Ctx) {
    let [body, hints] = body_and_hints(area);
    let roomy = body.height >= 23;
    let card = centered(
        body,
        body.width.min(CARD_WIDTH),
        if roomy { 23 } else { 19 },
    );
    let block = panel("", &ctx.theme);
    let inner = block.inner(card);
    frame.render_widget(block, card);
    if roomy {
        draw_roomy(frame, inner, state, ctx);
    } else {
        draw_compact(frame, inner, state, ctx);
    }
    hint_bar(frame, hints, Scope::Unlock, "", ctx);
    if let Some(cursor) = state.picker {
        draw_picker(frame, body, state, cursor, ctx);
    }
}

fn draw_roomy(frame: &mut Frame<'_>, area: Rect, state: &UnlockState, ctx: &Ctx) {
    let [brand, _, title, subtitle, _, storage, _, factors, _, input, error, actions] =
        Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Length(3),
        ])
        .areas(area);
    draw_brand(frame, brand, "quantum-safe", ctx);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!("{}  Unlock your vault", ctx.theme.glyphs.vk),
            ctx.theme.strong(),
        )))
        .alignment(Alignment::Center),
        title,
    );
    let subtitle_text = state.directory.as_ref().map_or_else(
        |error| error.message().to_owned(),
        |_| String::from("This storage is locked"),
    );
    frame.render_widget(
        Paragraph::new(Span::styled(subtitle_text, ctx.theme.muted())).alignment(Alignment::Center),
        subtitle,
    );
    draw_storage(frame, storage, state, ctx);
    draw_factors(frame, factors, state, ctx);
    draw_input(frame, input, state, ctx);
    draw_error(frame, error, state, ctx);
    draw_actions(frame, actions, state, ctx);
}

fn draw_compact(frame: &mut Frame<'_>, area: Rect, state: &UnlockState, ctx: &Ctx) {
    let [brand, storage, _, factors, _, input, error, _, actions] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(3),
    ])
    .areas(area);
    draw_brand(frame, brand, "locked", ctx);
    draw_storage(frame, storage, state, ctx);
    draw_factors(frame, factors, state, ctx);
    draw_input(frame, input, state, ctx);
    draw_error(frame, error, state, ctx);
    draw_actions(frame, actions, state, ctx);
}

fn draw_brand(frame: &mut Frame<'_>, area: Rect, right: &str, ctx: &Ctx) {
    let theme = &ctx.theme;
    let [left, badge] =
        Layout::horizontal([Constraint::Min(0), Constraint::Length(14)]).areas(area);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(rule(theme.glyphs, 4), theme.zebra()),
            Span::styled(" ZEBRAPASS", theme.strong()),
        ])),
        left,
    );
    frame.render_widget(
        Paragraph::new(Span::styled(format!("{right} "), theme.muted()))
            .alignment(Alignment::Right),
        badge,
    );
}

fn draw_storage(frame: &mut Frame<'_>, area: Rect, state: &UnlockState, ctx: &Ctx) {
    let label = if state.vaults.is_empty() {
        String::from("Storage")
    } else {
        format!(
            "Storage {}/{}  ·  {}",
            state.current + 1,
            state.vaults.len(),
            vault_title(state.vault())
        )
    };
    button(
        frame,
        area,
        &label,
        false,
        state.focus == UnlockFocus::Storage,
        &ctx.theme,
    );
}

fn draw_factors(frame: &mut Frame<'_>, area: Rect, state: &UnlockState, ctx: &Ctx) {
    let modes = state.modes();
    let Ok(count) = u32::try_from(modes.len()) else {
        return;
    };
    if count == 0 {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "No supported unlock factors",
                ctx.theme.danger(),
            ))
            .alignment(Alignment::Center),
            area,
        );
        return;
    }
    let rect = centered(area, area.width.min(CONTROL_WIDTH), 3);
    let constraints = vec![Constraint::Ratio(1, count); modes.len()];
    let rects = Layout::horizontal(constraints).split(rect);
    for (mode, spot) in modes.iter().zip(rects.iter()) {
        let label = match mode {
            Mode::Device => format!("{} Device PIN", ctx.theme.glyphs.device),
            Mode::Password => format!("{} Password", ctx.theme.glyphs.password),
        };
        let selected = *mode == state.mode;
        button(
            frame,
            *spot,
            &label,
            selected,
            selected && state.focus == UnlockFocus::Factor,
            &ctx.theme,
        );
    }
}

fn draw_input(frame: &mut Frame<'_>, area: Rect, state: &UnlockState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let input_focus = state.focus == UnlockFocus::Input;
    match state.mode {
        Mode::Password => {
            let revealed = state.reveal.is_shown(REVEAL_PASSWORD);
            secret_box(
                frame,
                area,
                "",
                secret_line_with_placeholder(
                    &state.password,
                    input_focus,
                    revealed,
                    "Enter password",
                    theme,
                ),
                input_focus,
                ctx,
            );
        }
        Mode::Device => {
            secret_box(
                frame,
                area,
                "Device PIN  ",
                secret_line_with_placeholder(
                    &state.pin,
                    input_focus,
                    false,
                    "Enter device PIN",
                    theme,
                ),
                input_focus,
                ctx,
            );
        }
    }
}

fn draw_actions(frame: &mut Frame<'_>, area: Rect, state: &UnlockState, ctx: &Ctx) {
    let rect = centered(area, area.width.min(CONTROL_WIDTH), 3);
    let [unlock, new] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(rect);
    let unlock_focus = state.focus == UnlockFocus::Unlock;
    button(
        frame,
        unlock,
        "Unlock",
        unlock_focus,
        unlock_focus,
        &ctx.theme,
    );
    button(
        frame,
        new,
        "New",
        false,
        state.focus == UnlockFocus::New,
        &ctx.theme,
    );
}

fn draw_error(frame: &mut Frame<'_>, area: Rect, state: &UnlockState, ctx: &Ctx) {
    frame.render_widget(
        Paragraph::new(error_lines(state, ctx)).alignment(Alignment::Center),
        area,
    );
}

fn draw_picker(frame: &mut Frame<'_>, area: Rect, state: &UnlockState, cursor: usize, ctx: &Ctx) {
    let theme = &ctx.theme;
    let height = u16::try_from(state.vaults.len().min(10) + 2).unwrap_or(12);
    let rect = centered(area, 56, height);
    frame.render_widget(Clear, rect);
    let inner = modal(frame, rect, "Choose a storage", theme);
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

fn secret_box(
    frame: &mut Frame<'_>,
    area: Rect,
    label: &str,
    line: Line<'_>,
    focused: bool,
    ctx: &Ctx,
) {
    let theme = &ctx.theme;
    if label.is_empty() {
        let [field] = Layout::horizontal([Constraint::Length(CONTROL_WIDTH)])
            .flex(ratatui::layout::Flex::Center)
            .areas(area);
        boxed(frame, field, line, focused, theme);
        return;
    }
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
    boxed(frame, field, line, focused, theme);
}

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
