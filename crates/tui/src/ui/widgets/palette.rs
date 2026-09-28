//! Command palette and help overlays.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::action::Action;
use crate::app::ctx::Ctx;
use crate::app::flows::palette::PaletteState;
use crate::app::keymap::{in_scope, label, Scope, KEYMAP, SCOPES};
use crate::ui::layout::centered;
use crate::ui::widgets::chrome::{modal, row_style};
use crate::ui::widgets::field::text_line;

/// Glyph shown next to a palette entry.
const fn icon(action: Action, ctx: &Ctx) -> &'static str {
    let glyphs = ctx.theme.glyphs;
    match action {
        Action::RotateVaultKey => glyphs.rotate,
        Action::ChangePassword | Action::DropRecovery => glyphs.password,
        Action::RevokeFactor | Action::OpenDevices | Action::EnrollDevice => glyphs.device,
        Action::OpenSync | Action::ExportFrames | Action::ExportAll | Action::ImportFrames => {
            glyphs.sync
        }
        Action::Lock | Action::Quit => glyphs.lock,
        Action::OpenFactors => glyphs.vk,
        _ => glyphs.dot,
    }
}

/// The key bound to `action` anywhere, for the right column.
fn shortcut(action: Action, ctx: &Ctx) -> String {
    KEYMAP
        .iter()
        .find(|binding| binding.action == action && binding.scope == Scope::Home)
        .or_else(|| KEYMAP.iter().find(|binding| binding.action == action))
        .map(|binding| label(binding.key, ctx.theme.ascii).into_owned())
        .unwrap_or_default()
}

/// Draw the palette.
pub fn draw_palette(frame: &mut Frame<'_>, area: Rect, palette: &PaletteState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let matches = palette.matches();
    let height = u16::try_from(matches.len().min(12) + 4).unwrap_or(16);
    let rect = centered(area, 60, height);
    let inner = modal(
        frame,
        rect,
        &format!("{} command", theme.glyphs.command),
        theme,
    );
    let width = inner.width;
    let mut query = text_line(&palette.query, width.saturating_sub(2), true, theme);
    query.spans.insert(0, Span::styled("> ", theme.accent()));
    let rule = if theme.ascii { "-" } else { "─" };
    let mut lines = vec![
        query,
        Line::from(Span::styled(rule.repeat(usize::from(width)), theme.muted())),
    ];
    let start = palette.selected.saturating_sub(11);
    for (position, (action, text, section)) in matches.iter().enumerate().skip(start).take(12) {
        let chosen = position == palette.selected;
        let pointer = if chosen { theme.glyphs.pointer } else { " " };
        let key = shortcut(*action, ctx);
        let right = format!("{:>9} {:>8}", section.label(), key);
        let room = usize::from(width).saturating_sub(right.chars().count() + 6);
        let name: String = text.chars().take(room).collect();
        lines.push(Line::from(vec![
            Span::styled(format!("{pointer} {} ", icon(*action, ctx)), theme.accent()),
            Span::styled(format!("{name:<room$}"), row_style(chosen, theme)),
            Span::styled(right, theme.muted()),
        ]));
    }
    if matches.is_empty() {
        lines.push(Line::from(Span::styled(
            "  no matching command",
            theme.muted(),
        )));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Draw the cheat sheet, generated from the keymap.
pub fn draw_help(frame: &mut Frame<'_>, area: Rect, scroll: u16, current: Scope, ctx: &Ctx) {
    let theme = &ctx.theme;
    let rect = centered(
        area,
        area.width.saturating_sub(4).min(160),
        area.height.saturating_sub(2),
    );
    let inner = modal(frame, rect, "Keys · generated from the live keymap", theme);
    let mut entries: Vec<Line<'_>> = Vec::new();
    let ordered =
        std::iter::once(current).chain(SCOPES.iter().copied().filter(|scope| *scope != current));
    for scope in ordered {
        let bindings: Vec<_> = in_scope(scope).collect();
        if bindings.is_empty() {
            continue;
        }
        entries.push(Line::from(Span::styled(scope.title(), theme.accent())));
        for binding in bindings {
            entries.push(Line::from(vec![
                Span::styled(
                    format!("  {:<12}", label(binding.key, theme.ascii)),
                    theme.strong(),
                ),
                Span::styled(binding.action.describe(), theme.text()),
            ]));
        }
        entries.push(Line::from(""));
    }
    let columns = if inner.width >= 90 { 2 } else { 1 };
    let per_column = entries.len().div_ceil(columns);
    let column_width = inner.width / u16::try_from(columns).unwrap_or(1);
    for column in 0..columns {
        let slice: Vec<Line<'_>> = entries
            .iter()
            .skip(column * per_column)
            .take(per_column)
            .cloned()
            .collect();
        let rect = Rect {
            x: inner.x + column_width * u16::try_from(column).unwrap_or(0),
            y: inner.y,
            width: column_width,
            height: inner.height,
        };
        frame.render_widget(
            Paragraph::new(slice)
                .wrap(ratatui::widgets::Wrap { trim: false })
                .scroll((scroll, 0)),
            rect,
        );
    }
}
