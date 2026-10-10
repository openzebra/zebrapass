//! The prompt that takes a relay slot.

use ratatui::text::{Line, Span};

use crate::ui::input::TextInput;
use crate::ui::screens::sync::{blank, heading, say, INDENT};
use crate::ui::theme::Theme;
use crate::ui::widgets::field::text_line;

pub(super) fn relay_lines(input: &TextInput, width: u16, theme: &Theme) -> Vec<Line<'static>> {
    let mut line = vec![Span::styled(format!("{INDENT}relay  "), theme.muted())];
    line.extend(
        text_line(input, width.saturating_sub(10), true, theme)
            .spans
            .into_iter()
            .map(|span| Span::styled(span.content.into_owned(), span.style)),
    );
    vec![
        blank(),
        heading("add a relay", theme),
        say(
            "Paste the relay address another device shows, written ip:port/slot.",
            theme.text(),
        ),
        blank(),
        Line::from(line),
        blank(),
        say(
            "Enter saves it; check-ins try it after the direct addresses.",
            theme.muted(),
        ),
    ]
}
