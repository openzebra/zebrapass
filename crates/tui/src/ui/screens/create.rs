//! Create wizard, step 1 of 4: name, Argon2id cost, body cipher. Later steps
//! delegate to the ceremony and enroll screens.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::create::{
    cipher_info, profile_info, CreateState, SetupField, Step, CIPHERS, PROFILES,
};
use crate::cli::Flags;
use crate::ui::layout::{body_and_hints, centered, row};
use crate::ui::widgets::chrome::{button, hint_bar, panel, radio, step_dots};
use crate::ui::widgets::field::{boxed, text_line};

/// Draw the wizard.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &CreateState, ctx: &Ctx) {
    match state.step {
        Step::Setup => setup(frame, area, state, ctx),
        Step::Ceremony | Step::Verify => {
            crate::ui::screens::ceremony::draw(frame, area, state, ctx);
        }
        Step::Enroll => crate::ui::screens::enroll::draw(frame, area, &state.enroll, (4, 4), ctx),
    }
}

/// Title line with the step dots at the right.
#[must_use]
pub fn titled<'a>(title: &str, step: (usize, usize), width: u16, ctx: &Ctx) -> Line<'a> {
    let theme = &ctx.theme;
    let dots = step_dots(step.0, step.1, theme);
    // " title " + fill + " " + dots + " " must fit between the two corners.
    let used = title.chars().count() + dots.content.chars().count() + 6;
    let fill = if theme.ascii { "-" } else { "─" };
    Line::from(vec![
        Span::styled(format!(" {title} "), theme.strong()),
        Span::styled(
            fill.repeat(usize::from(width).saturating_sub(used)),
            theme.muted(),
        ),
        Span::raw(" "),
        dots,
        Span::raw(" "),
    ])
}

fn timing(index: usize, ctx: &Ctx) -> String {
    if !ctx.flags.has(Flags::BENCH) {
        return String::new();
    }
    ctx.timings.get(index).copied().flatten().map_or_else(
        || String::from("measuring…"),
        |time| format!("≈ {:.1} s here", time.as_secs_f64()),
    )
}

fn setup(frame: &mut Frame<'_>, area: Rect, state: &CreateState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let [body, hints] = body_and_hints(area);
    let card = centered(body, body.width.min(82), 22);
    let block = panel(titled("New vault", (1, 4), card.width, ctx), theme);
    let inner = block.inner(card);
    frame.render_widget(block, card);
    let [name_label, name_box, _, cost, _, cipher, next] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(5),
        Constraint::Min(3),
    ])
    .areas(inner);
    frame.render_widget(
        Paragraph::new(Span::styled("  Vault name", theme.strong())),
        name_label,
    );
    let wide = inner.width >= 76;
    let [input, note] =
        Layout::horizontal([Constraint::Length(48.min(inner.width)), Constraint::Min(0)])
            .areas(name_box);
    let focused = state.field == SetupField::Name;
    boxed(
        frame,
        input,
        text_line(&state.name, input.width.saturating_sub(2), focused, theme),
        focused,
        theme,
    );
    if wide {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled("  stored in local meta only", theme.muted())),
            ]),
            note,
        );
    }
    frame.render_widget(Paragraph::new(cost_lines(state, wide, ctx)), cost);
    frame.render_widget(Paragraph::new(cipher_lines(state, wide, ctx)), cipher);
    if let Some(spot) = row(next, 0) {
        let rect = Rect {
            x: spot.right().saturating_sub(16),
            y: spot.y,
            width: 14,
            height: 3.min(next.height),
        };
        button(frame, rect, "Next  →", true, true, theme);
    }
    hint_bar(frame, hints, crate::app::keymap::Scope::Setup, "", ctx);
}

/// Argon2id profile radios with their timing estimates.
fn cost_lines(state: &CreateState, wide: bool, ctx: &Ctx) -> Vec<Line<'static>> {
    let theme = &ctx.theme;
    let mut cost_lines = vec![Line::from(Span::styled(
        "  Unlock cost (Argon2id)",
        if state.field == SetupField::Profile {
            theme.accent()
        } else {
            theme.strong()
        },
    ))];
    cost_lines.extend(PROFILES.iter().enumerate().map(|(index, profile)| {
        let (name, detail) = profile_info(*profile);
        let tag = if index == 0 && wide {
            "recommended"
        } else {
            ""
        };
        let time = if wide {
            format!("{:<16}", timing(index, ctx))
        } else {
            String::new()
        };
        Line::from(vec![
            Span::styled(
                format!("   {} {name:<8}", radio(index == state.profile, theme)),
                theme.text(),
            ),
            Span::styled(format!("{detail:<22}"), theme.muted()),
            Span::styled(time, theme.muted()),
            Span::styled(tag, theme.accent()),
        ])
    }));
    cost_lines
}

/// Body cipher radios; unavailable algorithms say so.
fn cipher_lines(state: &CreateState, wide: bool, ctx: &Ctx) -> Vec<Line<'static>> {
    let theme = &ctx.theme;
    let mut cipher_lines = vec![Line::from(Span::styled(
        "  Body cipher",
        if state.field == SetupField::Cipher {
            theme.accent()
        } else {
            theme.strong()
        },
    ))];
    cipher_lines.extend(CIPHERS.iter().enumerate().map(|(index, alg)| {
        let (name, detail, available) = cipher_info(*alg);
        let style = if available {
            theme.text()
        } else {
            theme.muted()
        };
        let tag = match (index, available) {
            (0, _) => "default",
            (_, false) => "unavailable",
            _ => "",
        };
        let detail = if wide {
            format!("{detail:<32}")
        } else {
            String::new()
        };
        let tag = if wide || !available { tag } else { "" };
        Line::from(vec![
            Span::styled(
                format!("   {} {name:<24}", radio(index == state.cipher, theme)),
                style,
            ),
            Span::styled(detail, theme.muted()),
            Span::styled(
                tag,
                if available {
                    theme.accent()
                } else {
                    theme.warn()
                },
            ),
        ])
    }));
    cipher_lines
}
