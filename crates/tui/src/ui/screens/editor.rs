//! Record editor: one row per field, secrets masked, live size and field
//! counters against the record limits.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::app::flows::editor::{EditorState, Part, Value, ADD_KINDS};
use crate::app::flows::unlocked::Unlocked;
use crate::app::keymap::Scope;
use crate::secure::reveal::RevealKey;
use crate::secure::strength::estimate;
use crate::ui::layout::body_and_hints;
use crate::ui::screens::home::header;
use crate::ui::theme::Theme;
use crate::ui::widgets::chrome::{checkbox, hint_bar, panel};
use crate::ui::widgets::field::{secret_line, text_line};
use crate::ui::widgets::meter::{bar, size_label, strength_spans};

/// Draw the editor.
pub fn draw(frame: &mut Frame<'_>, area: Rect, state: &Unlocked, editor: &EditorState, ctx: &Ctx) {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    let [top, rest] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(area);
    header(frame, top, state, "editing", ctx);
    let [body, hints] = body_and_hints(rest);
    let unsaved = if editor.dirty {
        format!(" unsaved {} ", glyphs.on)
    } else {
        String::new()
    };
    let title = Line::from(vec![
        Span::styled(
            format!(" Edit {} {} ", glyphs.dot, editor.title),
            theme.strong(),
        ),
        Span::styled(unsaved, theme.warn()),
    ]);
    let block = panel(title, theme);
    let inner = block.inner(body);
    frame.render_widget(block, body);
    let [fields, footer] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(3)]).areas(inner);
    let [list, aside] =
        Layout::horizontal([Constraint::Min(40), Constraint::Length(24)]).areas(fields);
    let focus = editor.focused();
    let (mut lines, focus_line) = field_lines(editor, list.width.saturating_sub(16), theme);
    lines.push(Line::from(""));
    lines.push(add_line(editor, theme));
    let height = usize::from(list.height);
    let scroll = focus_line.saturating_sub(height.saturating_sub(3));
    frame.render_widget(
        Paragraph::new(lines).scroll((u16::try_from(scroll).unwrap_or(0), 0)),
        list,
    );
    let secret_focus = focus.is_some_and(|(index, part)| {
        part == Part::Value
            && matches!(
                editor.fields.get(index).map(|field| &field.value),
                Some(Value::Secret(_))
            )
    });
    if secret_focus {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled("Ctrl-G  generate", theme.text())),
                Line::from(Span::styled("Ctrl-R  reveal 5 s", theme.text())),
                Line::from(Span::styled("secret field", theme.muted())),
            ])
            .block(panel("", theme)),
            Rect {
                height: 5.min(aside.height),
                ..aside
            },
        );
    }
    let size = editor.estimated_size();
    let fraction = f64::from(u32::try_from(size).unwrap_or(u32::MAX))
        / f64::from(u32::try_from(record::MAX_DOC_LEN).unwrap_or(1));
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    format!("  size {} / 1 MiB  ", size_label(size)),
                    theme.muted(),
                ),
                Span::styled(bar(fraction, 10, glyphs), theme.muted()),
                Span::styled(
                    format!(
                        "      fields {} / {}",
                        editor.field_count(),
                        record::MAX_FIELDS
                    ),
                    theme.muted(),
                ),
            ]),
        ]),
        footer,
    );
    hint_bar(frame, hints, Scope::Editor, "", ctx);
}

/// One line per field (plus a strength line under the password) and the
/// index of the focused line.
fn field_lines<'a>(
    editor: &'a EditorState,
    value_width: u16,
    theme: &Theme,
) -> (Vec<Line<'a>>, usize) {
    let glyphs = theme.glyphs;
    let focus = editor.focused();
    let stops = editor.stops();
    let mut lines: Vec<Line<'a>> = Vec::with_capacity(editor.fields.len() + 1);
    let mut focus_line = 0usize;
    for (index, field) in editor.fields.iter().enumerate() {
        let name_focused = focus == Some((index, Part::Name));
        let value_focused = focus == Some((index, Part::Value));
        if name_focused || value_focused {
            focus_line = lines.len();
        }
        let stop = stops
            .iter()
            .position(|stop| *stop == (index, Part::Value))
            .unwrap_or(usize::MAX);
        let revealed = editor
            .reveal
            .is_shown(RevealKey(u32::try_from(stop).unwrap_or(u32::MAX)));
        let marker = if name_focused || value_focused {
            glyphs.pointer
        } else {
            " "
        };
        let label_style = if value_focused || name_focused {
            theme.accent()
        } else {
            theme.muted()
        };
        let mut spans = vec![Span::styled(format!("{marker} "), theme.accent())];
        match field.name.as_ref() {
            Some(name) => {
                let name_line = if name.is_empty() && !name_focused {
                    Line::from(Span::styled("(name)", theme.muted()))
                } else {
                    text_line(name, 10, name_focused, theme)
                };
                let used = name_line.width();
                spans.extend(name_line.spans);
                spans.push(Span::raw(" ".repeat(11usize.saturating_sub(used))));
            }
            None => spans.push(Span::styled(format!("{:<11}", field.label), label_style)),
        }
        spans.push(Span::styled(
            if theme.ascii { "| " } else { "│ " },
            theme.muted(),
        ));
        let value = match &field.value {
            Value::Text(input) => text_line(input, value_width, value_focused, theme),
            Value::Secret(input) => secret_line(input, value_focused, revealed, theme),
            Value::Toggle(on) => Line::from(Span::styled(
                checkbox(*on),
                if value_focused {
                    theme.accent()
                } else {
                    theme.text()
                },
            )),
        };
        spans.extend(value.spans);
        lines.push(Line::from(spans));
        if let (Value::Secret(input), record::TAG_PASSWORD) = (&field.value, field.tag) {
            if !input.is_empty() {
                let mut strength = vec![Span::raw("               ")];
                strength.extend(strength_spans(estimate(input.expose()), 10, theme));
                lines.push(Line::from(strength));
            }
        }
    }
    (lines, focus_line)
}

/// The "+ Add field" line, as a menu while it is open.
fn add_line(editor: &EditorState, theme: &Theme) -> Line<'static> {
    editor.add_menu.map_or_else(
        || {
            Line::from(Span::styled(
                "  + Add field  Ctrl-N  ( text │ secret │ totp )",
                theme.muted(),
            ))
        },
        |cursor| {
            let mut spans = vec![Span::styled("  + Add field  ( ", theme.accent())];
            for (index, kind) in ADD_KINDS.iter().enumerate() {
                let style = if index == cursor {
                    theme.selected()
                } else {
                    theme.text()
                };
                spans.push(Span::styled(*kind, style));
                spans.push(Span::styled(
                    if index + 1 < ADD_KINDS.len() {
                        " │ "
                    } else {
                        " )"
                    },
                    theme.muted(),
                ));
            }
            spans.push(Span::styled(
                format!("   name {} 64 chars", if theme.ascii { "<=" } else { "≤" }),
                theme.muted(),
            ));
            Line::from(spans)
        },
    )
}
