//! Short-lived notices in the bottom-right corner, plus the clipboard
//! countdown.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::app::ctx::Ctx;
use crate::ui::widgets::meter::bar;

/// Tone of a notice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// Neutral.
    Info,
    /// Done.
    Success,
    /// Needs attention.
    Warn,
    /// Failed or dangerous.
    Danger,
}

/// One notice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Toast {
    /// Text (never a secret).
    pub text: Box<str>,
    /// Tone.
    pub tone: Tone,
    /// Hide at.
    pub until: Instant,
}

/// Visible notices, newest last.
#[derive(Clone, Debug, Default)]
pub struct Toasts {
    items: VecDeque<Toast>,
}

const MAX_TOASTS: usize = 3;

impl Toasts {
    /// Show `text` with `tone`.
    pub fn push(&mut self, tone: Tone, text: impl Into<Box<str>>, now: Instant) {
        let life = match tone {
            Tone::Info | Tone::Success => Duration::from_secs(4),
            Tone::Warn | Tone::Danger => Duration::from_secs(7),
        };
        let text = text.into();
        if let Some(last) = self
            .items
            .back_mut()
            .filter(|last| last.text == text && last.tone == tone)
        {
            last.until = now + life;
            return;
        }
        if self.items.len() == MAX_TOASTS {
            self.items.pop_front();
        }
        self.items.push_back(Toast {
            text,
            tone,
            until: now + life,
        });
    }

    /// Drop expired notices.
    pub fn tick(&mut self, now: Instant) {
        self.items.retain(|toast| toast.until > now);
    }

    /// Forget every notice.
    pub fn clear(&mut self) {
        self.items.clear();
    }

    /// Notices, oldest first.
    #[must_use]
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &Toast> {
        self.items.iter()
    }
}

/// Draw notices and the clipboard countdown over `area`.
pub fn draw(frame: &mut Frame<'_>, area: Rect, ctx: &Ctx) {
    let theme = &ctx.theme;
    let glyphs = theme.glyphs;
    // Stay above the hint bar and inside the pane borders.
    let mut bottom = area.bottom().saturating_sub(2);
    if let Some((label, left)) = ctx.clipboard.countdown(ctx.now) {
        let total = ctx.clipboard.clear_after().as_secs_f64().max(1.0);
        let fraction = left.as_secs_f64() / total;
        let lines = vec![
            Line::from(vec![
                Span::styled(format!("{} ", glyphs.ok), theme.accent()),
                Span::styled(format!("{label} copied"), theme.text()),
            ]),
            Line::from(vec![
                Span::styled(bar(fraction, 18, glyphs), theme.accent()),
                Span::styled(format!("  clears {}s", left.as_secs()), theme.muted()),
            ]),
        ];
        bottom = place(frame, area, bottom, lines, theme.accent(), ctx);
    }
    for toast in ctx.toasts.iter().rev() {
        let (glyph, style) = match toast.tone {
            Tone::Info => (glyphs.dot, theme.text()),
            Tone::Success => (glyphs.ok, theme.accent()),
            Tone::Warn => (glyphs.attention, theme.warn()),
            Tone::Danger => (glyphs.fail, theme.danger()),
        };
        let line = Line::from(vec![
            Span::styled(format!("{glyph} "), style),
            Span::styled(toast.text.to_string(), theme.text()),
        ]);
        bottom = place(frame, area, bottom, vec![line], style, ctx);
        if bottom <= area.y + 2 {
            break;
        }
    }
}

fn place(
    frame: &mut Frame<'_>,
    area: Rect,
    bottom: u16,
    lines: Vec<Line<'static>>,
    border: ratatui::style::Style,
    ctx: &Ctx,
) -> u16 {
    let text_width = lines.iter().map(Line::width).max().unwrap_or(0);
    let width = u16::try_from(text_width + 4)
        .unwrap_or(u16::MAX)
        .min(area.width.saturating_sub(4));
    let height = u16::try_from(lines.len() + 2).unwrap_or(3);
    if bottom < area.y + height || width < 8 {
        return bottom;
    }
    let rect = Rect {
        x: area.right().saturating_sub(width + 2),
        y: bottom - height,
        width,
        height,
    };
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border)
        .style(ctx.theme.panel());
    frame.render_widget(Paragraph::new(lines).block(block), rect);
    rect.y
}
