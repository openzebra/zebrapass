//! The confirmation screens of the share flow: remove, change a role,
//! replace the key, leave, and join.

use memberlog::Role;
use ratatui::text::{Line, Span};
use sharing::Fingerprint;

use crate::app::flows::share_leave::LeaveMode;
use crate::ui::screens::sync::{blank, heading, print_lines, role_gloss, role_name, say, INDENT};
use crate::ui::theme::Theme;

pub(super) fn remove_confirm_lines(
    print: &Fingerprint,
    role: Role,
    vault_name: &str,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        blank(),
        heading(&format!("remove from «{vault_name}»"), theme),
    ];
    lines.extend(print_lines(print, role_name(role), theme));
    lines.push(blank());
    for text in [
        "They keep what they have already seen. Nothing written from now on",
        "opens for them: the vault gets a new key, and everyone else",
        "receives it when their device next connects.",
    ] {
        lines.push(say(text, theme.text()));
    }
    lines.push(blank());
    lines.push(say("Enter removes · Esc cancels", theme.warn()));
    lines
}

pub(super) fn role_confirm_lines(
    print: &Fingerprint,
    from: Role,
    to: Role,
    vault_name: &str,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        blank(),
        heading(&format!("change a role in «{vault_name}»"), theme),
    ];
    lines.extend(print_lines(print, role_name(from), theme));
    lines.push(blank());
    lines.push(Line::from(vec![
        Span::styled(format!("{INDENT}{:<14}", "new role"), theme.muted()),
        Span::styled(format!("◂ {} ▸", role_name(to)), theme.accent()),
        Span::styled(format!("  {}", role_gloss(to)), theme.muted()),
    ]));
    lines.push(blank());
    for text in [
        "The vault keeps its key. Someone made a reader can still read what",
        "they could before; their changes are refused from now on. To shut",
        "someone out of new data, remove them instead.",
    ] {
        lines.push(say(text, theme.text()));
    }
    lines.push(blank());
    lines.push(say("Enter changes · Esc cancels", theme.warn()));
    lines
}

pub(super) fn rekey_confirm_lines(vault_name: &str, theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = vec![
        blank(),
        heading(&format!("new key for «{vault_name}»"), theme),
    ];
    for text in [
        "Nobody is removed. The vault gets a new key, and what is written from",
        "now on is closed to anyone who only holds the old one, such as",
        "someone who left. Everyone else receives the new key when their",
        "device next connects.",
    ] {
        lines.push(say(text, theme.text()));
    }
    lines.push(blank());
    lines.push(say("Enter replaces the key · Esc cancels", theme.warn()));
    lines
}

pub(super) fn leave_confirm_lines(
    mode: LeaveMode,
    vault_name: &str,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let mut lines = vec![blank()];
    let (title, text, confirm): (&str, &[&str], &str) = match mode {
        LeaveMode::Leave => (
            "leave",
            &[
                "You are signed out of the member list. This device stays online",
                "until a member has fetched that, then deletes its copy. If no",
                "one comes, press d again to delete it now; an owner can then",
                "remove you. The key is not replaced by leaving: ask an owner.",
            ],
            "Enter leaves · Esc cancels",
        ),
        LeaveMode::Forget => (
            "delete this copy of",
            &[
                "This deletes the vault from this device without telling the",
                "members. If you are still listed, an owner can remove you.",
            ],
            "Enter deletes · Esc cancels",
        ),
    };
    lines.push(heading(&format!("{title} «{vault_name}»"), theme));
    for line in text {
        lines.push(say(*line, theme.text()));
    }
    lines.push(blank());
    lines.push(say(confirm, theme.warn()));
    lines
}

pub(super) fn join_confirm_lines(opened: &sharing::Opened, theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = vec![
        blank(),
        heading(&format!("invitation to «{}»", opened.name), theme),
        say(
            format!("{:<14}{}", "vault number", opened.number),
            theme.strong(),
        ),
    ];
    lines.extend(print_lines(&opened.inviter, "from", theme));
    lines.push(blank());
    lines.push(say(
        "Ask the sender to read their fingerprint aloud. It must match.",
        theme.text(),
    ));
    lines.push(say("Enter joins · Esc cancels", theme.muted()));
    lines
}
