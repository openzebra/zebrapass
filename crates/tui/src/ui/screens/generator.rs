//! Password generator lab.

use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::generator::GeneratorState;
use crate::secure::generator::{crack_time_label, CharSets, GenMode};
use crate::ui::layout::centered;
use crate::ui::theme::Theme;
use crate::ui::widgets::chrome::{button, checkbox, modal, radio};
use crate::ui::widgets::meter::{bar, filled};

/// Draw the generator overlay.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &GeneratorState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let card = centered(area, area.width.min(86), 20);
    let inner = modal(frame, card, "Generator", theme);
    let [modes, _, value, entropy, _, length, sets, _, buttons] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(4),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(3),
    ])
    .areas(inner);
    frame.render_widget(Paragraph::new(mode_line(state, theme)), modes);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.accent());
    let shown = String::from_utf8_lossy(&state.value);
    frame.render_widget(
        Paragraph::new(Span::styled(shown, theme.strong()))
            .wrap(Wrap { trim: false })
            .block(block),
        Rect {
            x: value.x + 2,
            width: value.width.saturating_sub(4),
            ..value
        },
    );
    frame.render_widget(Paragraph::new(entropy_line(state, theme)), entropy);
    frame.render_widget(Paragraph::new(length_line(state, theme)), length);
    if state.spec.mode == GenMode::Chars {
        frame.render_widget(Paragraph::new(sets_line(state, theme)), sets);
    }
    let [a, b, c] = Layout::horizontal([
        Constraint::Length(14),
        Constraint::Length(16),
        Constraint::Length(24),
    ])
    .flex(Flex::Center)
    .areas(buttons);
    button(frame, a, "r reroll", false, false, theme);
    button(frame, b, "c copy", false, false, theme);
    let use_label = if state.target.is_some() {
        "Enter use in form"
    } else {
        "Enter copy & close"
    };
    button(frame, c, use_label, true, true, theme);
}

fn mode_line(state: &GeneratorState, theme: &Theme) -> Line<'static> {
    let mut spans = vec![Span::styled("  Mode   ", theme.strong())];
    for mode in [GenMode::Chars, GenMode::Passphrase, GenMode::Pin] {
        spans.push(Span::styled(
            format!(
                "{} {}   ",
                radio(mode == state.spec.mode, theme),
                mode.label()
            ),
            theme.text(),
        ));
    }
    Line::from(spans)
}

fn entropy_line(state: &GeneratorState, theme: &Theme) -> Line<'static> {
    let bits = state.spec.entropy_bits();
    Line::from(vec![
        Span::styled("  entropy  ", theme.muted()),
        Span::styled(bar(bits / 160.0, 25, theme.glyphs), theme.accent()),
        Span::styled(format!("  {bits:.0} bits    "), theme.text()),
        Span::styled(
            format!("time-to-crack: {}", crack_time_label(bits)),
            theme.muted(),
        ),
    ])
}

fn length_line(state: &GeneratorState, theme: &Theme) -> Line<'static> {
    let glyphs = theme.glyphs;
    let range = state.spec.mode.lengths();
    let track = 30usize;
    let span = f64::from(range.end() - range.start()).max(1.0);
    let knob = filled(
        f64::from(state.spec.length - range.start()) / span,
        track - 1,
    );
    let slider: String = (0..track)
        .map(|cell| {
            if cell == knob {
                glyphs.track[1]
            } else {
                glyphs.track[0]
            }
        })
        .collect();
    let unit = match state.spec.mode {
        GenMode::Chars => "chars",
        GenMode::Passphrase => "words",
        GenMode::Pin => "digits",
    };
    Line::from(vec![
        Span::styled("  Length   ", theme.muted()),
        Span::styled(format!("{} ", glyphs.arrows[2]), theme.accent()),
        Span::styled(slider, theme.text()),
        Span::styled(
            format!(" {}  {} {unit}", glyphs.arrows[3], state.spec.length),
            theme.accent(),
        ),
    ])
}

fn sets_line(state: &GeneratorState, theme: &Theme) -> Line<'static> {
    let sets = [
        (CharSets::LOWER, "a-z"),
        (CharSets::UPPER, "A-Z"),
        (CharSets::DIGITS, "0-9"),
        (CharSets::SYMBOLS, "symbols"),
        (CharSets::NO_LOOKALIKE, "avoid look-alikes (0O1lI)"),
    ];
    let mut spans = vec![Span::raw("  ")];
    spans.extend(sets.iter().enumerate().map(|(index, (bit, label))| {
        let on = state.spec.sets.has(*bit);
        Span::styled(
            format!("{}{} {label}   ", index + 1, checkbox(on)),
            if on { theme.text() } else { theme.muted() },
        )
    }));
    Line::from(spans)
}
