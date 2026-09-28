//! Settings.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::panels::{Setting, SettingsState, SETTINGS};
use crate::app::flows::unlocked::Unlocked;
use crate::app::idle::clock;
use crate::app::keymap::Scope;
use crate::cli::Flags;
use crate::ui::layout::body_and_hints;
use crate::ui::screens::home::header;
use crate::ui::widgets::chrome::{checkbox, hint_bar, panel, row_style};

fn describe(setting: Setting, state: &Unlocked, ctx: &Ctx) -> (&'static str, String) {
    match setting {
        Setting::Theme => ("Theme", ctx.theme.name.label().to_owned()),
        Setting::Animation => (
            "Animations",
            checkbox(ctx.flags.has(Flags::ANIM)).to_owned(),
        ),
        Setting::Ascii => (
            "ASCII glyphs",
            checkbox(ctx.flags.has(Flags::ASCII)).to_owned(),
        ),
        Setting::AutoLock => ("Auto-lock after", clock(ctx.idle.after())),
        Setting::ClipClear => (
            "Clear clipboard after",
            format!("{} s", ctx.clipboard.clear_after().as_secs()),
        ),
        Setting::FocusLock => (
            "Lock on focus loss",
            checkbox(ctx.flags.has(Flags::FOCUS_LOCK)).to_owned(),
        ),
        Setting::Name => ("Vault name (this device)", state.info.label.clone()),
        Setting::ClearHistory => ("Clear history", String::from("drop old revisions…")),
    }
}

/// Draw settings.
pub fn draw(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &Unlocked,
    settings: &SettingsState,
    ctx: &Ctx,
) {
    let theme = &ctx.theme;
    let [top, rest] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(area);
    header(frame, top, state, "settings", ctx);
    let [body, hints] = body_and_hints(rest);
    let block = panel(" Settings ", theme);
    let inner = block.inner(body);
    frame.render_widget(block, body);
    let mut lines = vec![Line::from("")];
    lines.extend(SETTINGS.iter().enumerate().map(|(index, setting)| {
        let chosen = index == settings.selected;
        let (name, value) = describe(*setting, state, ctx);
        let pointer = if chosen { theme.glyphs.pointer } else { " " };
        Line::from(vec![
            Span::styled(format!("  {pointer} {name:<28}"), row_style(chosen, theme)),
            Span::styled(value, if chosen { theme.accent() } else { theme.text() }),
        ])
    }));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Settings last for this run; start-up defaults come from command-line flags (--help).",
        theme.muted(),
    )));
    frame.render_widget(Paragraph::new(lines), inner);
    hint_bar(frame, hints, Scope::Settings, "", ctx);
}
