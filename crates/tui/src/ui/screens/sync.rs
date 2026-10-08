//! Share: your key, your shared vaults, and one prompt at a time.
//!
//! No frames, one quiet column; the fingerprints are the only thing drawn
//! large, because they are what two people compare aloud.

use local::Listen;
use memberlog::Role;
use p2p_net::FetchError;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use sharing::Fingerprint;

use crate::app::ctx::Ctx;
use crate::app::flows::share::{ShareState, Step};
use crate::app::flows::unlocked::Unlocked;
use crate::app::keymap::Scope;
use crate::ui::input::TextInput;
use crate::ui::layout::{body_and_hints, centered};
use crate::ui::screens::home::header;
use crate::ui::screens::sync_confirm::{
    join_confirm_lines, leave_confirm_lines, rekey_confirm_lines, remove_confirm_lines,
    role_confirm_lines,
};
use crate::ui::theme::Theme;
use crate::ui::widgets::chrome::hint_bar;
use crate::ui::widgets::field::text_line;
use crate::ui::widgets::fingerprint::stripe_print;
use crate::vault::shared::{SharedItem, Status};

pub(super) const INDENT: &str = "  ";

pub(super) fn blank() -> Line<'static> {
    Line::from("")
}

pub(super) fn heading(text: &str, theme: &Theme) -> Line<'static> {
    Line::from(Span::styled(format!("{INDENT}{text}"), theme.muted()))
}

pub(super) fn say(text: impl Into<String>, style: Style) -> Line<'static> {
    Line::from(Span::styled(format!("{INDENT}{}", text.into()), style))
}

/// A fingerprint as a stripe-print and two lines of grouped hex.
pub(super) fn print_lines(print: &Fingerprint, label: &str, theme: &Theme) -> Vec<Line<'static>> {
    let text = print.to_string();
    let (first, second) = text.split_at(text.len().min(24));
    let second = second.trim_start();
    let lead = if label.is_empty() {
        INDENT.to_owned()
    } else {
        format!("{INDENT}{label:<14}")
    };
    vec![
        Line::from(vec![
            Span::styled(lead.clone(), theme.muted()),
            Span::styled(stripe_print(print.bytes(), theme.glyphs), theme.accent()),
            Span::styled(format!("  {first}"), theme.strong()),
        ]),
        Line::from(Span::styled(
            format!("{}{second}", " ".repeat(lead.chars().count() + 18)),
            theme.strong(),
        )),
    ]
}

pub(super) const fn role_name(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Writer => "writer",
        Role::Reader => "reader",
    }
}

pub(super) const fn role_gloss(role: Role) -> &'static str {
    match role {
        Role::Reader => "can read",
        Role::Writer => "can read and edit",
        Role::Owner => "can also add people",
    }
}

fn people(count: usize) -> String {
    match count {
        0 | 1 => String::from("just you"),
        more => format!("you + {}", more - 1),
    }
}

const fn reason_word(reason: FetchError) -> &'static str {
    match reason {
        FetchError::Unreachable => "offline",
        FetchError::Refused => "refused",
        FetchError::Failed => "no answer",
    }
}

fn status(item: &SharedItem, fetching: bool, theme: &Theme) -> Span<'static> {
    let glyphs = theme.glyphs;
    match (&item.status, item.waiting) {
        (Status::Ready(_), _) if item.my_role.is_none() => Span::styled(
            format!("{} left · d deletes this copy now", glyphs.attention),
            theme.warn(),
        ),
        (Status::Ready(_), _) if item.my_role == Some(Role::Owner) && item.leaves > 0 => {
            Span::styled(
                format!("{} someone left · k replaces the key", glyphs.attention),
                theme.warn(),
            )
        }
        (Status::Ready(_), _) if item.stale => {
            Span::styled(format!("{} new key, updating", glyphs.sync), theme.warn())
        }
        (Status::Ready(_), Some(reason)) => Span::styled(
            format!("{} synced · {}", glyphs.ok, reason_word(reason)),
            theme.accent(),
        ),
        (Status::Ready(_), None) => Span::styled(format!("{} synced", glyphs.ok), theme.accent()),
        (Status::Unavailable, _) => {
            Span::styled(format!("{} did not verify", glyphs.fail), theme.danger())
        }
        (Status::Pending, Some(reason)) => Span::styled(
            format!("{} {} · r retries", glyphs.attention, reason_word(reason)),
            theme.warn(),
        ),
        (Status::Pending, None) if fetching => {
            Span::styled(format!("{} syncing", glyphs.sync), theme.warn())
        }
        (Status::Pending, None) => Span::styled("… waiting", theme.muted()),
    }
}

fn node_line(state: &Unlocked, theme: &Theme) -> Line<'static> {
    let mode = match state.listen_mode() {
        Listen::Lan => "local network",
        Listen::Local => "this device only",
        Listen::Off => "fetch only",
    };
    let (text, style) = match state.p2p.as_deref().map(|p2p| p2p.service.local_addr()) {
        Some(Some(addr)) => (
            format!("{} listening {addr} · {mode}", theme.glyphs.on),
            theme.accent(),
        ),
        Some(None) => (format!("not listening · {mode}"), theme.muted()),
        None => (format!("stopped · {mode}"), theme.muted()),
    };
    Line::from(vec![
        Span::styled(format!("{INDENT}{:<14}", "node"), theme.muted()),
        Span::styled(text, style),
    ])
}

fn overview(state: &Unlocked, share: &ShareState, theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = vec![blank(), heading("your key", theme)];
    match &share.me {
        Some(me) => {
            lines.extend(print_lines(&me.print, "", theme));
            lines.push(say(
                "Enter copies it. Give it to whoever adds you.",
                theme.muted(),
            ));
        }
        None => lines.push(say(
            "This vault has no sync identity. Restore it with its recovery phrase to share.",
            theme.warn(),
        )),
    }
    lines.push(blank());
    lines.push(heading("shared", theme));
    if state.shared.is_empty() {
        lines.push(say("none yet · n makes one, j joins one", theme.muted()));
    }
    let fetching = state
        .p2p
        .as_deref()
        .is_some_and(|p2p| p2p.service.status().fetching > 0);
    for (index, item) in state.shared.iter().enumerate() {
        let chosen = index == share.cursor;
        let pointer = if chosen { theme.glyphs.pointer } else { " " };
        let role = item.my_role.map_or("", role_name);
        let row_style = if chosen { theme.strong() } else { theme.text() };
        lines.push(Line::from(vec![
            Span::styled(format!("{INDENT}{pointer} "), theme.accent()),
            Span::styled(
                format!("{:<16}", crate::ui::widgets::list::fit(item.name(), 16)),
                row_style,
            ),
            Span::styled(format!("{role:<8}"), theme.muted()),
            Span::styled(format!("{:<12}", people(item.people)), theme.muted()),
            status(item, fetching, theme),
        ]));
    }
    lines.push(blank());
    lines.push(node_line(state, theme));
    if let Some(address) = state.p2p.as_deref().and_then(|p2p| p2p.reachable.first()) {
        lines.push(Line::from(vec![
            Span::styled(format!("{INDENT}{:<14}", "restore from"), theme.muted()),
            Span::styled(format!("{address}  type it on a new device"), theme.text()),
        ]));
    }
    if let Some(address) = state
        .advertised()
        .filter(|_| matches!(state.listen_mode(), Listen::Lan))
    {
        lines.push(Line::from(vec![
            Span::styled(format!("{INDENT}{:<14}", "offering"), theme.muted()),
            Span::styled(address.to_owned(), theme.text()),
        ]));
    }
    lines
}

fn prompt(title: &str, hint: &str, theme: &Theme) -> Vec<Line<'static>> {
    vec![
        blank(),
        heading(title, theme),
        say(hint, theme.text()),
        blank(),
        say(
            format!("{} waiting for the paste…", theme.glyphs.pointer),
            theme.accent(),
        ),
    ]
}

fn name_lines(input: &TextInput, width: u16, theme: &Theme) -> Vec<Line<'static>> {
    let mut line = vec![Span::styled(format!("{INDENT}name  "), theme.muted())];
    line.extend(
        text_line(input, width.saturating_sub(10), true, theme)
            .spans
            .into_iter()
            .map(|span| Span::styled(span.content.into_owned(), span.style)),
    );
    vec![
        blank(),
        heading("new shared vault", theme),
        Line::from(line),
        blank(),
        say("Enter makes it, and you become its owner.", theme.muted()),
    ]
}

fn advertise_lines(input: &TextInput, width: u16, theme: &Theme) -> Vec<Line<'static>> {
    let mut line = vec![Span::styled(format!("{INDENT}address  "), theme.muted())];
    line.extend(
        text_line(input, width.saturating_sub(12), true, theme)
            .spans
            .into_iter()
            .map(|span| Span::styled(span.content.into_owned(), span.style)),
    );
    vec![
        blank(),
        heading("public address", theme),
        say(
            "Behind a router with a forwarded port? Write the address the world",
            theme.text(),
        ),
        say(
            "sees, as ip:port. Members are told to reach you there. Empty clears it.",
            theme.text(),
        ),
        blank(),
        Line::from(line),
        blank(),
        say("Enter saves · Esc cancels", theme.muted()),
    ]
}

fn add_confirm_lines(
    card: &sharing::ContactCard,
    role: Role,
    vault_name: &str,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let mut lines = vec![blank(), heading(&format!("add to «{vault_name}»"), theme)];
    lines.extend(print_lines(&card.fingerprint(), "their key", theme));
    lines.push(blank());
    lines.push(say(
        "Ask them to read their own fingerprint aloud. It must match.",
        theme.text(),
    ));
    lines.push(blank());
    lines.push(Line::from(vec![
        Span::styled(format!("{INDENT}{:<14}", "role"), theme.muted()),
        Span::styled(format!("◂ {} ▸", role_name(role)), theme.accent()),
        Span::styled(format!("  {}", role_gloss(role)), theme.muted()),
    ]));
    lines
}

fn add_done_lines(
    invitation: &str,
    print: &Fingerprint,
    number: &str,
    vault_name: &str,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        blank(),
        heading(
            &format!("they are in {} {vault_name}", theme.glyphs.ok),
            theme,
        ),
        say(
            "Give them this invitation. It opens only on their device.",
            theme.text(),
        ),
        blank(),
        say(format!("{:<14}{number}", "vault number"), theme.strong()),
    ];
    lines.extend(print_lines(print, "their key", theme));
    lines.push(blank());
    lines.push(say(
        format!(
            "{:<14}{} KB · Enter copies it",
            "invitation",
            invitation.len().div_ceil(1024)
        ),
        theme.muted(),
    ));
    lines
}

fn pick_lines(
    state: &Unlocked,
    vault: usize,
    pick: usize,
    action: &str,
    vault_name: &str,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let mut lines = vec![blank(), heading(&format!("{action} «{vault_name}»"), theme)];
    for (index, person) in state.people(vault).iter().enumerate() {
        let chosen = index == pick;
        let pointer = if chosen { theme.glyphs.pointer } else { " " };
        let print = person.print.to_string();
        let short = print.get(..14).unwrap_or(&print).to_owned();
        lines.push(Line::from(vec![
            Span::styled(format!("{INDENT}{pointer} "), theme.accent()),
            Span::styled(
                stripe_print(person.print.bytes(), theme.glyphs),
                theme.accent(),
            ),
            Span::styled(
                format!("  {short}  "),
                if chosen { theme.strong() } else { theme.text() },
            ),
            Span::styled(role_name(person.role), theme.muted()),
        ]));
    }
    lines.push(blank());
    lines.push(say(
        "Pick by the fingerprint you compared when you added them.",
        theme.muted(),
    ));
    lines
}

fn step_lines(
    state: &Unlocked,
    share: &ShareState,
    width: u16,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let vault_name = state
        .shared
        .get(share.cursor)
        .map_or(String::new(), |item| item.name().to_owned());
    match &share.step {
        Step::Overview => overview(state, share, theme),
        Step::Name(input) => name_lines(input, width, theme),
        Step::PasteCard => prompt(
            &format!("add someone to «{vault_name}»"),
            "Ask them to open Share and press Enter. Then paste their key here.",
            theme,
        ),
        Step::AddConfirm { card, role } => add_confirm_lines(card, *role, &vault_name, theme),
        Step::AddDone {
            invitation,
            print,
            number,
        } => add_done_lines(invitation, print, number, &vault_name, theme),
        Step::PickPerson(pick) => pick_lines(
            state,
            share.cursor,
            *pick,
            "remove from",
            &vault_name,
            theme,
        ),
        Step::PickRole(pick) => pick_lines(
            state,
            share.cursor,
            *pick,
            "change a role in",
            &vault_name,
            theme,
        ),
        Step::RoleConfirm {
            print, from, to, ..
        } => role_confirm_lines(print, *from, *to, &vault_name, theme),
        Step::RemoveConfirm { print, role, .. } => {
            remove_confirm_lines(print, *role, &vault_name, theme)
        }
        Step::LeaveConfirm(mode) => leave_confirm_lines(*mode, &vault_name, theme),
        Step::RekeyConfirm => rekey_confirm_lines(&vault_name, theme),
        Step::Advertise(input) => advertise_lines(input, width, theme),
        Step::PasteInvite => prompt(
            "join a shared vault",
            "Paste the invitation you were given.",
            theme,
        ),
        Step::JoinConfirm(opened) => join_confirm_lines(opened, theme),
    }
}

/// Draw the share screen.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &Unlocked, share: &ShareState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let [top, rest] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(area);
    header(frame, top, state, "share", ctx);
    let [body, hints] = body_and_hints(rest);
    let column = centered(body, body.width.min(76), body.height);
    let lines = step_lines(state, share, column.width, theme);
    frame.render_widget(Paragraph::new(lines).style(theme.base()), column);
    let scope = if matches!(share.step, Step::Overview) {
        Scope::Sync
    } else {
        Scope::Share
    };
    hint_bar(frame, hints, scope, "", ctx);
}
