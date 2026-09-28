//! Restore or import: the choice of source and the export file. The review
//! step lives in `import_preview`.

use import::Source;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::import::{Choice, FileHint, ImportState, ImportStep, CHOICES};
use crate::app::keymap::Scope;
use crate::ui::layout::{body_and_hints, centered};
use crate::ui::screens::create::titled;
use crate::ui::widgets::chrome::{hint_bar, panel, row_style};
use crate::ui::widgets::field::{boxed, text_line};

/// Steps shown in the title dots.
const STEPS: usize = 3;

/// Draw the wizard.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &ImportState, ctx: &Ctx) {
    match state.step {
        ImportStep::Source => source(frame, area, state, ctx),
        ImportStep::File => file(frame, area, state, ctx),
        ImportStep::Preview => crate::ui::screens::import_preview::draw(frame, area, state, ctx),
    }
}

fn source(frame: &mut Frame<'_>, area: Rect, state: &ImportState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let [body, hints] = body_and_hints(area);
    let card = centered(body, body.width.min(100), 18);
    let block = panel(
        titled("Restore or import", (1, STEPS), card.width, ctx),
        theme,
    );
    let inner = block.inner(card);
    frame.render_widget(block, card);
    let [intro, _, main] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
    ])
    .areas(inner);
    frame.render_widget(
        Paragraph::new(Span::styled(
            "  Bring back a ZebraPass vault, or start a new one from another password manager.",
            theme.muted(),
        )),
        intro,
    );
    let [list, guide] =
        Layout::horizontal([Constraint::Length(48), Constraint::Min(20)]).areas(main);
    let rows = CHOICES.iter().enumerate().map(|(index, choice)| {
        let chosen = index == state.cursor;
        let pointer = if chosen { theme.glyphs.pointer } else { " " };
        let (label, note, available) = match choice {
            Choice::Phrase => ("ZebraPass recovery phrase", "24 words", true),
            Choice::From(source) => (source.label(), short_format(*source), source.supported()),
        };
        let style = if available {
            row_style(chosen, theme)
        } else if chosen {
            theme.selected()
        } else {
            theme.muted()
        };
        let note = if available { note } else { "soon" };
        Line::from(vec![
            Span::styled(format!(" {pointer} "), theme.accent()),
            Span::styled(format!("{label:<27}"), style),
            Span::styled(format!("{note:<10}"), theme.muted()),
        ])
    });
    let with_gap: Vec<Line<'_>> = rows
        .enumerate()
        .flat_map(|(index, line)| {
            let gap = (index == 0).then(|| Line::from(""));
            std::iter::once(line).chain(gap)
        })
        .collect();
    frame.render_widget(Paragraph::new(with_gap), list);
    let guide_block = Block::default()
        .borders(Borders::LEFT)
        .border_style(theme.muted());
    let guide_inner = guide_block.inner(guide);
    frame.render_widget(guide_block, guide);
    let choice = CHOICES.get(state.cursor).copied().unwrap_or(Choice::Phrase);
    let lines: Vec<Line<'_>> = guidance(choice)
        .iter()
        .map(|(text, tone)| {
            let style = match tone {
                Tone::Head => theme.strong(),
                Tone::Step => theme.text(),
                Tone::Warn => theme.warn(),
                Tone::Note => theme.muted(),
            };
            Line::from(Span::styled(format!(" {text}"), style))
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        guide_inner,
    );
    hint_bar(frame, hints, Scope::Import, "", ctx);
}

fn file(frame: &mut Frame<'_>, area: Rect, state: &ImportState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let [body, hints] = body_and_hints(area);
    let card = centered(body, body.width.min(90), 14);
    let chosen = state.source();
    let title = format!("Import from {}", chosen.label());
    let block = panel(titled(&title, (2, STEPS), card.width, ctx), theme);
    let inner = block.inner(card);
    frame.render_widget(block, card);
    let [label, input, status, error, _, notes] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
    ])
    .areas(inner);
    frame.render_widget(
        Paragraph::new(Span::styled(
            format!("  Export file ({})", short_format(chosen)),
            theme.strong(),
        )),
        label,
    );
    let rect = Rect {
        x: input.x + 2,
        width: input.width.saturating_sub(4),
        ..input
    };
    boxed(
        frame,
        rect,
        text_line(&state.path, rect.width.saturating_sub(2), true, theme),
        true,
        theme,
    );
    let hint = match state.hint {
        FileHint::Missing if state.path.is_empty() => Span::styled(
            "    type or paste the path · ~ means your home folder",
            theme.muted(),
        ),
        FileHint::Missing => Span::styled(
            format!("    {} no readable file at this path", glyphs.fail),
            theme.warn(),
        ),
        FileHint::Found(Some(found), size) if found == chosen => Span::styled(
            format!(
                "    {} {} export · {}",
                glyphs.ok,
                found.label(),
                human_size(size)
            ),
            theme.accent(),
        ),
        FileHint::Found(Some(found), size) => Span::styled(
            format!(
                "    {} looks like {} ({}); Esc to choose it",
                glyphs.attention,
                found.label(),
                human_size(size)
            ),
            theme.warn(),
        ),
        FileHint::Found(None, size) => Span::styled(
            format!(
                "    {} unknown format · {} · reading it may fail",
                glyphs.attention,
                human_size(size)
            ),
            theme.warn(),
        ),
    };
    frame.render_widget(Paragraph::new(hint), status);
    if let Some(message) = state.error.as_deref() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                format!("    {} {message}", glyphs.fail),
                theme.danger(),
            )),
            error,
        );
    }
    let lines = vec![
        Line::from(Span::styled(
            "  Nothing is written yet: you review every item first, then create the vault.",
            theme.muted(),
        )),
        Line::from(Span::styled(
            "  The file is only read. Delete it afterwards: it holds your passwords in plain text.",
            theme.muted(),
        )),
    ];
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), notes);
    hint_bar(frame, hints, Scope::ImportFile, "", ctx);
}

#[derive(Clone, Copy)]
enum Tone {
    Head,
    Step,
    Warn,
    Note,
}

/// How to get the file out of the other app.
const fn guidance(choice: Choice) -> &'static [(&'static str, Tone)] {
    match choice {
        Choice::Phrase => &[
            ("Restore a ZebraPass vault", Tone::Head),
            ("", Tone::Note),
            ("You need the vault file (a backup or a", Tone::Step),
            ("copy from another device) and its", Tone::Step),
            ("24-word recovery phrase.", Tone::Step),
        ],
        Choice::From(Source::BitwardenJson) => &[
            ("From Bitwarden", Tone::Head),
            ("", Tone::Note),
            ("Tools → Export vault", Tone::Step),
            ("File format: .json", Tone::Step),
            ("Not the \"password protected\" .json.", Tone::Warn),
            ("", Tone::Note),
            ("Logins, notes, cards, identities, SSH keys,", Tone::Note),
            ("custom fields, TOTP and folders come along.", Tone::Note),
            ("Attachments and passkeys can't be exported.", Tone::Note),
        ],
        Choice::From(Source::Kdbx) => &[
            ("From KeePass / KeePassXC", Tone::Head),
            ("", Tone::Note),
            ("Opening .kdbx directly is coming soon.", Tone::Warn),
            ("For now: Database → Export → CSV,", Tone::Step),
            ("then choose CSV here.", Tone::Step),
        ],
        Choice::From(Source::KeepassXml) => &[
            ("From a KeePass XML export", Tone::Head),
            ("", Tone::Note),
            ("XML import is coming soon.", Tone::Warn),
            ("For now: export as CSV and choose CSV.", Tone::Step),
        ],
        Choice::From(Source::EnpassJson) => &[
            ("From Enpass", Tone::Head),
            ("", Tone::Note),
            ("Enpass .json import is coming soon.", Tone::Warn),
            ("For now: File → Export → .csv,", Tone::Step),
            ("then choose CSV here.", Tone::Step),
        ],
        Choice::From(Source::Csv) => &[
            ("From a CSV export", Tone::Head),
            ("", Tone::Note),
            ("Chrome: Settings → Passwords → Export", Tone::Step),
            ("Firefox: about:logins → ⋯ → Export", Tone::Step),
            ("Safari: File → Export → Passwords", Tone::Step),
            ("1Password, LastPass, Proton Pass,", Tone::Step),
            ("Dashlane, Bitwarden: Export → CSV", Tone::Step),
            ("", Tone::Note),
            ("Columns are recognized from the header.", Tone::Note),
        ],
    }
}

const fn short_format(source: Source) -> &'static str {
    match source {
        Source::BitwardenJson | Source::EnpassJson => ".json",
        Source::Kdbx => ".kdbx",
        Source::KeepassXml => ".xml",
        Source::Csv => ".csv",
    }
}

/// `412 KB`, `3.1 MB`.
fn human_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * KB;
    if bytes >= MB {
        format!("{}.{} MB", bytes / MB, bytes % MB * 10 / MB)
    } else if bytes >= KB {
        format!("{} KB", bytes / KB)
    } else {
        format!("{bytes} B")
    }
}
