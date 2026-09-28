//! Breakpoints and the few rectangle helpers every screen shares.

use ratatui::layout::{Constraint, Layout, Rect};

/// Smallest usable terminal width.
pub const MIN_WIDTH: u16 = 60;
/// Smallest usable terminal height.
pub const MIN_HEIGHT: u16 = 20;

/// Width class of the terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Breakpoint {
    /// `≥ 120` columns: three panes.
    Wide,
    /// `80..120` columns: two panes.
    Medium,
    /// `< 80` columns: one pane with stack navigation.
    Narrow,
}

impl From<u16> for Breakpoint {
    fn from(width: u16) -> Self {
        match width {
            120.. => Self::Wide,
            80..=119 => Self::Medium,
            _ => Self::Narrow,
        }
    }
}

/// Whether `area` is too small for any screen.
#[must_use]
pub const fn too_small(area: Rect) -> bool {
    area.width < MIN_WIDTH || area.height < MIN_HEIGHT
}

/// A `width × height` rectangle centered in `area`, clipped to it.
#[must_use]
pub fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

/// Split a full-screen area into body and a one-line hint bar.
#[must_use]
pub fn body_and_hints(area: Rect) -> [Rect; 2] {
    Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(area)
}

/// The inner area of a bordered block.
#[must_use]
pub const fn inner(area: Rect) -> Rect {
    Rect {
        x: area.x.saturating_add(1),
        y: area.y.saturating_add(1),
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(2),
    }
}

/// One row of `area` at offset `row`, or `None` when it falls outside.
#[must_use]
pub const fn row(area: Rect, row: u16) -> Option<Rect> {
    if row < area.height {
        Some(Rect {
            x: area.x,
            y: area.y + row,
            width: area.width,
            height: 1,
        })
    } else {
        None
    }
}
