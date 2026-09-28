//! Dialog rendering.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::dialog::{ConfirmKind, Dialog, ADD_FACTOR};
use crate::app::flows::form::{Form, FormFocus, FormKind};
use crate::secure::secret_input::SecretInput;
use crate::ui::layout::centered;
use crate::ui::screens::restore::word_grid;
use crate::ui::widgets::chrome::{modal, row_style};
use crate::ui::widgets::field::{secret_line, text_line};
use crate::ui::widgets::meter::bar;

/// `text` word-wrapped to `width` columns, each line indented by one space.
fn wrapped(text: &str, width: u16) -> Vec<String> {
    let room = usize::from(width.saturating_sub(2)).max(8);
    let mut out = Vec::new();
    let mut line = String::from(" ");
    for word in text.split(' ') {
        if line.chars().count() + word.chars().count() > room && line.len() > 1 {
            out.push(std::mem::replace(&mut line, String::from(" ")));
        }
        if line.len() > 1 {
            line.push(' ');
        }
        line.push_str(word);
    }
    out.push(line);
    out
}

/// A dialog wide enough for `lines` (plus margins), within `area`.
fn fitted(area: Rect, title: &str, lines: &[String], height: u16) -> Rect {
    let longest = lines
        .iter()
        .map(|line| line.chars().count())
        .chain(std::iter::once(title.chars().count() + 4))
        .max()
        .unwrap_or(40);
    let width = u16::try_from(longest + 6)
        .unwrap_or(u16::MAX)
        .clamp(44, area.width.saturating_sub(2));
    centered(area, width, height)
}

/// Draw `dialog` centered over `area`.
pub fn draw(frame: &mut Frame<'_>, area: Rect, dialog: &Dialog, ctx: &Ctx) {
    let theme = &ctx.theme;
    match dialog {
        Dialog::Info(info) => {
            let rect = fitted(area, &info.title, &info.body, 3);
            let body: Vec<String> = info
                .body
                .iter()
                .flat_map(|line| wrapped(line, rect.width.saturating_sub(2)))
                .collect();
            let height = u16::try_from(body.len() + 5).unwrap_or(10);
            let inner = modal(
                frame,
                fitted(area, &info.title, &info.body, height),
                &info.title,
                theme,
            );
            let mut lines: Vec<Line<'_>> = body
                .into_iter()
                .map(|line| Line::from(Span::styled(line, theme.text())))
                .collect();
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                " Enter / Esc close",
                theme.muted(),
            )));
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        }
        Dialog::Confirm(confirm) => {
            let danger = matches!(
                confirm.kind,
                ConfirmKind::Delete(_)
                    | ConfirmKind::RemoveWrap(_)
                    | ConfirmKind::RemovePassword
                    | ConfirmKind::ClearHistory
            );
            let rect = fitted(area, &confirm.title, &confirm.body, 3);
            let body: Vec<String> = confirm
                .body
                .iter()
                .flat_map(|line| wrapped(line, rect.width.saturating_sub(2)))
                .collect();
            let height = u16::try_from(body.len() + 5).unwrap_or(10);
            let inner = modal(
                frame,
                fitted(area, &confirm.title, &confirm.body, height),
                &confirm.title,
                theme,
            );
            let mut lines: Vec<Line<'_>> = body
                .into_iter()
                .map(|line| Line::from(Span::styled(line, theme.text())))
                .collect();
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled(
                    " Enter ",
                    if danger {
                        theme.danger()
                    } else {
                        theme.accent()
                    },
                ),
                Span::styled("confirm    ", theme.text()),
                Span::styled("Esc ", theme.strong()),
                Span::styled("cancel", theme.text()),
            ]));
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        }
        Dialog::AddFactor(cursor) => {
            let inner = modal(frame, centered(area, 52, 8), "Add a factor", theme);
            let lines: Vec<Line<'_>> = ADD_FACTOR
                .iter()
                .enumerate()
                .map(|(index, label)| {
                    let chosen = index == *cursor;
                    let pointer = if chosen { theme.glyphs.pointer } else { " " };
                    Line::from(Span::styled(
                        format!(" {pointer} {label}"),
                        row_style(chosen, theme),
                    ))
                })
                .collect();
            frame.render_widget(Paragraph::new(lines), inner);
        }
        Dialog::Form(form) => draw_form(frame, area, form, ctx),
    }
}

fn secret_row<'a>(
    label: &str,
    input: &'a SecretInput,
    focus: FormFocus,
    form: &Form,
    ctx: &Ctx,
) -> Line<'a> {
    let theme = &ctx.theme;
    let focused = form.focus == focus;
    let revealed = form.reveal.is_shown(Form::reveal_key(focus));
    let mut spans = vec![Span::styled(
        format!(" {label:<18}"),
        if focused {
            theme.accent()
        } else {
            theme.muted()
        },
    )];
    spans.extend(secret_line(input, focused, revealed, theme).spans);
    Line::from(spans)
}

fn draw_form(frame: &mut Frame<'_>, area: Rect, form: &Form, ctx: &Ctx) {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let height = u16::try_from(
        form.body.len() + form.order().len() * 2 + if form.phrase.is_some() { 12 } else { 7 },
    )
    .unwrap_or(24);
    let inner = modal(
        frame,
        centered(area, area.width.min(92), height.min(area.height)),
        &form.title,
        theme,
    );
    let mut lines: Vec<Line<'_>> = form
        .body
        .iter()
        .map(|line| Line::from(Span::styled(format!(" {line}"), theme.text())))
        .collect();
    lines.push(Line::from(""));
    if let Some(phrase) = form.phrase.as_ref() {
        let focused = form.focus == FormFocus::Phrase;
        lines.push(Line::from(Span::styled(
            format!(" recovery phrase  {} / 24 words", phrase.count()),
            if focused {
                theme.accent()
            } else {
                theme.muted()
            },
        )));
        lines.extend(
            word_grid(phrase, focused, false, false, theme)
                .into_iter()
                .map(|mut line| {
                    line.spans.insert(0, Span::raw(" "));
                    line
                }),
        );
        lines.push(Line::from(""));
    }
    if let Some(input) = form.passphrase.as_ref() {
        lines.push(secret_row(
            "passphrase (opt.)",
            input,
            FormFocus::Passphrase,
            form,
            ctx,
        ));
    }
    if let Some(input) = form.current.as_ref() {
        lines.push(secret_row(
            "current password",
            input,
            FormFocus::Current,
            form,
            ctx,
        ));
    }
    if let Some(input) = form.new.as_ref() {
        lines.push(secret_row("new password", input, FormFocus::New, form, ctx));
    }
    if let Some(input) = form.repeat.as_ref() {
        lines.push(secret_row("repeat", input, FormFocus::Repeat, form, ctx));
    }
    if let Some(input) = form.text.as_ref() {
        let label = if form.kind == FormKind::DropRecovery {
            "type DROP"
        } else {
            "name"
        };
        {
            let focused = form.focus == FormFocus::Text;
            let mut spans = vec![Span::styled(
                format!(" {label:<18}"),
                if focused {
                    theme.accent()
                } else {
                    theme.muted()
                },
            )];
            spans.extend(text_line(input, inner.width.saturating_sub(22), focused, theme).spans);
            lines.push(Line::from(spans));
        }
    }
    lines.push(Line::from(""));
    lines.push(confirm_line(form, ctx));
    if let Some(error) = form.error.as_deref() {
        lines.push(Line::from(Span::styled(
            format!(" {} {error}", glyphs.fail),
            theme.danger(),
        )));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

/// How to confirm: the hold bar for dangerous forms, Enter otherwise.
fn confirm_line(form: &Form, ctx: &Ctx) -> Line<'static> {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    form.hold.map_or_else(
        || {
            Line::from(Span::styled(
                " Enter confirm · Tab next field · Ctrl-R reveal · Esc cancel",
                theme.muted(),
            ))
        },
        |hold| {
            let verb = match form.kind {
                FormKind::Revoke(_) => "revoke",
                FormKind::DropRecovery => "drop",
                FormKind::Rotate
                | FormKind::ChangePassword
                | FormKind::AddPassword
                | FormKind::Rename => "rotate",
            };
            let how = if ctx.caps.key_release {
                format!(" Hold ENTER to {verb}  ")
            } else if hold.awaiting_second_press() {
                String::from(" Press ENTER again to confirm  ")
            } else {
                format!(" Press ENTER, wait for the bar, press again to {verb}  ")
            };
            Line::from(vec![
                Span::styled(how, theme.danger()),
                Span::styled(bar(hold.progress(ctx.now), 20, glyphs), theme.danger()),
                Span::styled("  1.5 s", theme.muted()),
            ])
        },
    )
}
