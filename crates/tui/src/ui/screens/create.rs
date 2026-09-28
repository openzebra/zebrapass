//! Create wizard, step 1 of 4: name and unlock cost. The encryption stack is
//! fixed and only described. Later steps delegate to the ceremony and enroll
//! screens.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::create::{estimate, profile_info, CreateState, SetupField, Step, PROFILES};
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

fn timing(profile: session::KdfProfile, ctx: &Ctx) -> String {
    if !ctx.flags.has(Flags::BENCH) {
        return String::new();
    }
    ctx.kdf_fast.map_or_else(
        || String::from("measuring…"),
        |fast| format!("≈ {:.1} s", estimate(fast, profile).as_secs_f64()),
    )
}

fn setup(frame: &mut Frame<'_>, area: Rect, state: &CreateState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let [body, hints] = body_and_hints(area);
    let card = centered(body, body.width.min(82), 22);
    let block = panel(titled("New vault", (1, 4), card.width, ctx), theme);
    let inner = block.inner(card);
    frame.render_widget(block, card);
    let [name_label, name_box, _, cost, _, crypto, next] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(5),
        Constraint::Length(1),
        Constraint::Length(4),
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
                Line::from(Span::styled("  shown on this device only", theme.muted())),
            ]),
            note,
        );
    }
    frame.render_widget(Paragraph::new(cost_lines(state, wide, ctx)), cost);
    frame.render_widget(Paragraph::new(crypto_lines(wide, ctx)), crypto);
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

/// Unlock-cost radios: how long opening the vault takes on this machine.
fn cost_lines(state: &CreateState, wide: bool, ctx: &Ctx) -> Vec<Line<'static>> {
    let theme = &ctx.theme;
    let mut lines = vec![Line::from(Span::styled(
        "  Unlock time (Argon2id)",
        if state.field == SetupField::Profile {
            theme.accent()
        } else {
            theme.strong()
        },
    ))];
    lines.extend(PROFILES.iter().enumerate().map(|(index, profile)| {
        let (name, detail, summary) = profile_info(*profile);
        let chosen = index == state.profile;
        let mut spans = vec![
            Span::styled(
                format!("   {} {name:<9}", radio(chosen, theme)),
                if chosen { theme.accent() } else { theme.text() },
            ),
            Span::styled(format!("{:<10}", timing(*profile, ctx)), theme.text()),
        ];
        if wide {
            spans.push(Span::styled(format!("{detail:<17}"), theme.muted()));
            spans.push(Span::styled(summary, theme.muted()));
        }
        Line::from(spans)
    }));
    lines
}

/// The fixed encryption stack every vault uses.
fn crypto_lines(wide: bool, ctx: &Ctx) -> Vec<Line<'static>> {
    let theme = &ctx.theme;
    let ok = theme.glyphs.ok;
    let rows: [(&str, &str); 3] = [
        (
            "Records",
            "AEGIS-256 inside Kuznyechik-CTR + HMAC, keys per layer",
        ),
        ("Devices", "ML-KEM-768 + P-256 hybrid key wraps"),
        ("Sync", "ML-DSA-65 signatures on every upload"),
    ];
    let mut lines = vec![Line::from(Span::styled("  Encryption", theme.strong()))];
    lines.extend(rows.iter().map(|(label, detail)| {
        let mut spans = vec![Span::styled(format!("   {ok} {label:<9}"), theme.accent())];
        if wide {
            spans.push(Span::styled(*detail, theme.muted()));
        }
        Line::from(spans)
    }));
    lines
}
