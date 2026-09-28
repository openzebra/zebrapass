//! Rendering of text and secret inputs.
//!
//! A secret renders as a fixed-width stripe run, so its length never shows.
//! Plaintext is written into the frame only while a reveal is active.

use std::borrow::Cow;

use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::Frame;

use crate::secure::secret_input::{SecretInput, PHASES};
use crate::ui::input::TextInput;
use crate::ui::theme::{Glyphs, Theme};
use crate::ui::widgets::stripes::MASK_CELLS;

/// A text input as one line, scrolled so the cursor stays visible.
#[must_use]
pub fn text_line<'a>(input: &'a TextInput, width: u16, focused: bool, theme: &Theme) -> Line<'a> {
    let value = input.value();
    let cursor = input.cursor();
    let room = usize::from(width.saturating_sub(1)).max(1);
    let head_chars = value.get(..cursor).map_or(0, |head| head.chars().count());
    let skip = head_chars.saturating_sub(room);
    let start = value
        .char_indices()
        .nth(skip)
        .map_or(value.len(), |(index, _)| index);
    let visible = value.get(start..).unwrap_or("");
    let mut spans = Vec::with_capacity(3);
    if focused {
        let split = cursor.saturating_sub(start).min(visible.len());
        let (before, after) = visible.split_at_checked(split).unwrap_or((visible, ""));
        let under = after.chars().next().map_or(0, char::len_utf8);
        let (under, rest) = after.split_at_checked(under).unwrap_or(("", after));
        spans.push(Span::styled(before, theme.text()));
        spans.push(block_cursor(under, theme));
        spans.push(Span::styled(rest, theme.text()));
    } else {
        spans.push(Span::styled(visible, theme.text()));
    }
    Line::from(spans)
}

/// A secret input as one line: stripes, or plaintext while revealed.
#[must_use]
pub fn secret_line<'a>(
    input: &'a SecretInput,
    focused: bool,
    revealed: bool,
    theme: &Theme,
) -> Line<'a> {
    let mut spans = Vec::with_capacity(2);
    if revealed {
        let shown: Cow<'a, str> = String::from_utf8_lossy(input.expose());
        spans.push(Span::styled(shown, theme.warn()));
    } else if !input.is_empty() {
        spans.push(Span::styled(
            typing_mask(theme.glyphs, input.phase()),
            theme.zebra(),
        ));
    }
    if focused {
        spans.push(block_cursor("", theme));
    }
    Line::from(spans)
}

const _: () = assert!(PHASES as usize == MASK_CELLS);

/// The fixed-width mask of an input with a two-cell wave at `phase`: the
/// wave moves on every edit, the width never changes.
#[must_use]
pub fn typing_mask(glyphs: &Glyphs, phase: u8) -> String {
    let at = usize::from(phase) % MASK_CELLS;
    (0..MASK_CELLS)
        .map(|cell| {
            if cell == at || cell == (at + 1) % MASK_CELLS {
                glyphs.mask_alt
            } else {
                glyphs.mask
            }
        })
        .collect()
}

/// The vim-style block cursor over `under`, or over an empty cell at the end
/// of the text. It covers a cell instead of inserting one, so the text
/// around it never shifts.
#[must_use]
pub fn block_cursor<'a>(under: &'a str, theme: &Theme) -> Span<'a> {
    Span::styled(if under.is_empty() { " " } else { under }, theme.cursor())
}

/// Draw `line` inside a bordered box.
pub fn boxed(frame: &mut Frame<'_>, area: Rect, line: Line<'_>, focused: bool, theme: &Theme) {
    let border: Style = if focused {
        theme.accent()
    } else {
        theme.muted()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border);
    frame.render_widget(Paragraph::new(line).block(block), area);
}

#[cfg(test)]
mod tests {
    use super::typing_mask;
    use crate::ui::theme::{Theme, ThemeName};
    use crate::ui::widgets::stripes::MASK_CELLS;

    #[test]
    fn typing_mask_keeps_its_width_at_every_phase() {
        for ascii in [false, true] {
            let theme = Theme::new(ThemeName::Mono, ascii, false);
            let masks: Vec<String> = (0..12)
                .map(|phase| typing_mask(theme.glyphs, phase))
                .collect();
            for mask in &masks {
                assert_eq!(mask.chars().count(), MASK_CELLS);
                assert_eq!(mask.matches(theme.glyphs.mask_alt).count(), 2);
            }
            assert_ne!(masks[0], masks[1]);
        }
    }
}
