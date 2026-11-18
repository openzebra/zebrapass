//! Real bordered and compact pill buttons for the share and members screens.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};

use crate::app::flows::share_nav::ShareButton;
use crate::ui::theme::{Theme, ThemeName};

/// Visual tone of an interactive button.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ButtonTone {
    /// Primary CTA button (accent-framed or filled when focused).
    Primary,
    /// Standard interactive action.
    Normal,
    /// Active toggle or currently offered action.
    Active,
    /// Attention-needed action (e.g. upgrade or rekey after leave).
    Warn,
    /// Destructive action (leave/delete copy/remove).
    Danger,
    /// Currently unavailable action (still clickable/focusable, dims visually).
    Muted,
}

/// Specification for rendering one interactive button.
#[derive(Clone, Copy, Debug)]
pub struct ButtonSpec<Id = ShareButton> {
    /// Logical identifier used for focus matching.
    pub id: Id,
    /// Leading glyph from `Theme::glyphs`.
    pub glyph: &'static str,
    /// Full label when space permits.
    pub label: &'static str,
    /// Compact label for narrower cells.
    pub short_label: &'static str,
    /// Shortcut key displayed inside `[k]`.
    pub key: &'static str,
    /// Visual tone.
    pub tone: ButtonTone,
}

/// Render a horizontal row of evenly sized buttons (`boxed` = 3 rows, else 1-row pill).
pub fn draw_button_row<Id: Copy + Eq>(
    frame: &mut Frame<'_>,
    area: Rect,
    buttons: &[ButtonSpec<Id>],
    focused: Option<Id>,
    boxed: bool,
    theme: &Theme,
) {
    if buttons.is_empty() || area.width == 0 || area.height == 0 {
        return;
    }
    let count = buttons.len();
    let gap = u16::from(usize::from(area.width) >= count * 10);
    let mut constraints = Vec::with_capacity(count * 2);
    for idx in 0..count {
        if idx > 0 && gap > 0 {
            constraints.push(Constraint::Length(gap));
        }
        constraints.push(Constraint::Fill(1));
    }
    let slots = Layout::horizontal(constraints).split(area);
    let mut slot_idx = 0usize;
    for (idx, spec) in buttons.iter().enumerate() {
        if idx > 0 && gap > 0 {
            slot_idx += 1;
        }
        if let Some(&slot) = slots.get(slot_idx) {
            let is_focused = focused.is_some_and(|id| id == spec.id);
            if boxed && area.height >= 3 {
                draw_boxed(frame, slot, spec, is_focused, theme);
            } else {
                draw_pill(frame, slot, spec, is_focused, theme);
            }
        }
        slot_idx += 1;
    }
}

fn draw_boxed<Id>(
    frame: &mut Frame<'_>,
    area: Rect,
    spec: &ButtonSpec<Id>,
    focused: bool,
    theme: &Theme,
) {
    let border_type = match (theme.ascii, focused) {
        (true, _) => BorderType::Plain,
        (false, true) => BorderType::Thick,
        (false, false) => BorderType::Rounded,
    };
    let border_style = if focused {
        focus_border_style(spec.tone, theme)
    } else {
        idle_border_style(spec.tone, theme)
    };
    let inner_w = usize::from(area.width.saturating_sub(2));
    let line = button_content(spec, inner_w, focused, theme);
    let fill = if focused {
        focus_fill_style(spec.tone, theme)
    } else {
        theme.base()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(border_type)
        .border_style(border_style)
        .style(fill);
    frame.render_widget(
        Paragraph::new(line)
            .alignment(Alignment::Center)
            .block(block),
        area,
    );
}

fn draw_pill<Id>(
    frame: &mut Frame<'_>,
    area: Rect,
    spec: &ButtonSpec<Id>,
    focused: bool,
    theme: &Theme,
) {
    let line = button_content(spec, usize::from(area.width), focused, theme);
    let bg = if focused {
        focus_fill_style(spec.tone, theme)
    } else {
        theme.panel()
    };
    frame.render_widget(
        Paragraph::new(line).alignment(Alignment::Center).style(bg),
        area,
    );
}

fn button_content<Id>(
    spec: &ButtonSpec<Id>,
    max_width: usize,
    focused: bool,
    theme: &Theme,
) -> Line<'static> {
    let key_badge = format!("[{}]", spec.key);
    let full_len =
        spec.glyph.chars().count() + 1 + spec.label.chars().count() + 1 + key_badge.chars().count();
    let short_len = spec.glyph.chars().count()
        + 1
        + spec.short_label.chars().count()
        + 1
        + key_badge.chars().count();
    let label = if full_len <= max_width {
        spec.label
    } else if short_len <= max_width {
        spec.short_label
    } else {
        let lead = if focused { theme.glyphs.pointer } else { "" };
        return Line::from(Span::styled(
            format!("{lead}{} {key_badge}", spec.short_label),
            if focused {
                focus_fill_style(spec.tone, theme)
            } else {
                idle_label_style(spec.tone, theme)
            },
        ));
    };

    if focused {
        let style = focus_fill_style(spec.tone, theme);
        return Line::from(vec![
            Span::styled(format!("{} ", spec.glyph), style),
            Span::styled(format!("{label} "), style),
            Span::styled(key_badge, style),
        ]);
    }

    let glyph_style = match spec.tone {
        ButtonTone::Primary | ButtonTone::Active => theme.accent(),
        ButtonTone::Warn => theme.warn(),
        ButtonTone::Danger => theme.danger(),
        ButtonTone::Normal => theme.text(),
        ButtonTone::Muted => theme.muted(),
    };
    let text_style = idle_label_style(spec.tone, theme);
    let key_style = if spec.tone == ButtonTone::Muted {
        theme.muted()
    } else {
        theme.accent()
    };
    Line::from(vec![
        Span::styled(format!("{} ", spec.glyph), glyph_style),
        Span::styled(format!("{label} "), text_style),
        Span::styled(key_badge, key_style),
    ])
}

const fn idle_border_style(tone: ButtonTone, theme: &Theme) -> Style {
    match tone {
        ButtonTone::Primary | ButtonTone::Active => theme.accent(),
        ButtonTone::Warn => theme.warn(),
        ButtonTone::Normal | ButtonTone::Danger | ButtonTone::Muted => theme.muted(),
    }
}

const fn idle_label_style(tone: ButtonTone, theme: &Theme) -> Style {
    match tone {
        ButtonTone::Primary => theme.strong(),
        ButtonTone::Active => theme.accent(),
        ButtonTone::Warn => theme.warn(),
        ButtonTone::Normal | ButtonTone::Danger => theme.text(),
        ButtonTone::Muted => theme.muted(),
    }
}

const fn focus_border_style(tone: ButtonTone, theme: &Theme) -> Style {
    match tone {
        ButtonTone::Danger => theme.danger(),
        ButtonTone::Warn => theme.warn(),
        ButtonTone::Primary | ButtonTone::Active | ButtonTone::Normal | ButtonTone::Muted => {
            theme.accent()
        }
    }
}

const fn focus_fill_style(tone: ButtonTone, theme: &Theme) -> Style {
    if matches!(theme.name, ThemeName::Mono) {
        return Style::new().add_modifier(Modifier::REVERSED.union(Modifier::BOLD));
    }
    let bg = match tone {
        ButtonTone::Danger => theme.palette.danger,
        ButtonTone::Warn => theme.palette.warn,
        ButtonTone::Primary | ButtonTone::Active | ButtonTone::Normal | ButtonTone::Muted => {
            theme.palette.accent
        }
    };
    Style::new()
        .fg(theme.palette.bg)
        .bg(bg)
        .add_modifier(Modifier::BOLD)
}
