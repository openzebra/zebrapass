//! Security alert. There is deliberately no "open anyway".

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::gate::AlertState;
use crate::app::keymap::Scope;
use crate::ui::layout::{body_and_hints, centered};
use crate::ui::widgets::chrome::{button, danger_panel, hint_bar};
use crate::ui::widgets::stripes::sparse_rule;
use crate::vault::error::UnlockError;

fn explanation(kind: UnlockError) -> Vec<String> {
    match kind {
        UnlockError::Rollback { seen, disk } => vec![
            String::from("This vault file is OLDER than the last version this device has seen."),
            String::new(),
            format!("   last seen    generation {seen}"),
            format!("   on disk      generation {disk}"),
            String::new(),
            String::from("Someone (or a backup/sync tool) may have replaced it to undo changes"),
            String::from("such as a device revocation. ZebraPass refused to open it."),
        ],
        UnlockError::Conflict { generation } => vec![
            String::from("This vault file has the SAME generation as the one this device last"),
            format!("accepted (generation {generation}), but different contents."),
            String::new(),
            String::from(
                "Two diverging copies exist, or the file was forged. ZebraPass refused to open it.",
            ),
        ],
        UnlockError::MetaMissing => vec![
            String::from("The credentials were right, but this device's rollback record for the"),
            String::from("vault is missing or unreadable, so an older file could not be detected."),
            String::new(),
            String::from("If you did not delete it yourself, treat the vault file as suspect."),
        ],
        UnlockError::Denied
        | UnlockError::NeedsPassword
        | UnlockError::NeedsHwKey
        | UnlockError::NotAVault
        | UnlockError::Peer(_)
        | UnlockError::WrongVault
        | UnlockError::Io => vec![String::from(kind.message())],
    }
}

/// Draw the alert.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &AlertState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let [body, hints] = body_and_hints(area);
    let card = centered(body, body.width.min(86), 20);
    let block = danger_panel(
        format!(" {} SECURITY ALERT ", theme.glyphs.attention),
        theme,
    );
    let inner = block.inner(card);
    frame.render_widget(block, card);
    let [top, text, location, buttons, note, bottom] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(6),
        Constraint::Length(2),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);
    let rule = Span::styled(sparse_rule(theme.glyphs, inner.width), theme.danger());
    frame.render_widget(Paragraph::new(rule.clone()), top);
    frame.render_widget(Paragraph::new(rule), bottom);
    let lines: Vec<Line<'_>> = explanation(state.kind)
        .into_iter()
        .map(|line| Line::from(Span::styled(format!("  {line}"), theme.text())))
        .collect();
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), text);
    if state.show_location {
        let path = state.vault.paths.vault_file.display().to_string();
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("  file  ", theme.muted()),
                Span::styled(path, theme.warn()),
            ]))
            .wrap(Wrap { trim: false }),
            location,
        );
    }
    let [a, b, c] = Layout::horizontal([Constraint::Ratio(1, 3); 3]).areas(buttons);
    button(
        frame,
        a,
        "Show file location",
        false,
        state.choice == 0,
        theme,
    );
    button(
        frame,
        b,
        "Restore from phrase",
        false,
        state.choice == 1,
        theme,
    );
    button(frame, c, "Quit", false, state.choice == 2, theme);
    frame.render_widget(
        Paragraph::new(Span::styled(
            "  Opening it anyway is not offered. A restore from the phrase is the override.",
            theme.muted(),
        )),
        note,
    );
    hint_bar(frame, hints, Scope::Alert, "", ctx);
}
