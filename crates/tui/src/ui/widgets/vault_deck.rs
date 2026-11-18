//! Lock-screen vault card carousel: foreground identity card and neighbor peeks.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Flex, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::symbols::border;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::ui::theme::{Glyphs, Theme, ThemeName};
use crate::ui::widgets::fingerprint::stripe_print;
use crate::ui::widgets::vault_card::{
    card_codename, card_tint, card_tint_dim, short_tag, sigil_rows,
};
use crate::vault::factors::Presence;

/// Outer width of the foreground vault card.
pub const CARD_FACE_WIDTH: u16 = 46;

/// Height of the vault card deck.
pub const CARD_DECK_HEIGHT: u16 = 5;

const RIGHT_PANE_COLS: usize = 34;

const ASCII_ROUNDED: border::Set = border::Set {
    top_left: "+",
    top_right: "+",
    bottom_left: "+",
    bottom_right: "+",
    vertical_left: "|",
    vertical_right: "|",
    horizontal_top: "-",
    horizontal_bottom: "-",
};

const ASCII_FOCUSED: border::Set = border::Set {
    top_left: "+",
    top_right: "+",
    bottom_left: "+",
    bottom_right: "+",
    vertical_left: "|",
    vertical_right: "|",
    horizontal_top: "=",
    horizontal_bottom: "=",
};

/// Public metadata rendered on the foreground vault card.
#[derive(Clone, Copy, Debug)]
pub struct CardSummary {
    /// Key generation from the wrap directory, when readable.
    pub generation: Option<u64>,
    /// Position in the deck (`0..total`).
    pub index: usize,
    /// Number of vaults in the deck.
    pub total: usize,
    /// Enrolled factors visible in the wrap directory.
    pub presence: Presence,
    /// Public 128-bit vault identifier, when known.
    pub id: Option<[u8; 16]>,
    /// Adjacent left card id (when `total > 1`).
    pub prev_id: Option<[u8; 16]>,
    /// Adjacent right card id (when `total > 1`).
    pub next_id: Option<[u8; 16]>,
    /// Whether this was the last vault unlocked on this device.
    pub last_unlocked: bool,
    /// Whether the card control holds keyboard focus.
    pub focused: bool,
}

/// Draw the single vault card or multi-card carousel deck into `area`.
pub fn draw_deck(frame: &mut Frame<'_>, area: Rect, summary: &CardSummary, theme: &Theme) {
    if summary.total <= 1 || area.width < CARD_FACE_WIDTH + 12 {
        let [card_rect] = Layout::horizontal([Constraint::Length(CARD_FACE_WIDTH.min(area.width))])
            .flex(Flex::Center)
            .areas(area);
        draw_active_card(frame, card_rect, summary, theme);
        return;
    }
    let roomy_peek = area.width >= CARD_FACE_WIDTH + 16;
    let peek_w: u16 = if roomy_peek { 8 } else { 6 };
    let [left_peek, active_rect, right_peek] = Layout::horizontal([
        Constraint::Length(peek_w),
        Constraint::Length(CARD_FACE_WIDTH),
        Constraint::Length(peek_w),
    ])
    .flex(Flex::Center)
    .areas(area);

    draw_peek(
        frame,
        left_peek,
        summary.prev_id.as_ref(),
        true,
        summary.focused,
        theme,
    );
    draw_active_card(frame, active_rect, summary, theme);
    draw_peek(
        frame,
        right_peek,
        summary.next_id.as_ref(),
        false,
        summary.focused,
        theme,
    );
}

fn draw_active_card(frame: &mut Frame<'_>, area: Rect, summary: &CardSummary, theme: &Theme) {
    let id = summary.id.as_ref();
    let tint = card_tint(id, theme);
    let border_style = if summary.focused {
        tint.add_modifier(Modifier::BOLD)
    } else if matches!(theme.name, ThemeName::Mono) {
        theme.muted()
    } else {
        tint
    };
    let set = match (theme.ascii, summary.focused) {
        (true, true) => ASCII_FOCUSED,
        (true, false) => ASCII_ROUNDED,
        (false, true) => border::DOUBLE,
        (false, false) => border::ROUNDED,
    };
    let header_badge = if summary.total > 1 {
        Span::styled(" VAULT CARD ", border_style)
    } else {
        Span::styled(" VAULT CARD ", theme.muted())
    };
    let mut block = Block::default()
        .borders(Borders::ALL)
        .border_set(set)
        .border_style(border_style)
        .title_top(Line::from(header_badge));
    if summary.last_unlocked {
        let badge = format!(" {} LAST UNLOCKED ", theme.glyphs.star);
        block = block.title_top(
            Line::from(Span::styled(badge, tint.add_modifier(Modifier::BOLD)))
                .alignment(Alignment::Right),
        );
    }
    if let Some(bottom) = card_footer(summary.total, summary.focused, theme) {
        block = block.title_bottom(bottom.alignment(Alignment::Right));
    }
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let [s0, s1, s2] = sigil_rows(id, theme.ascii);
    let divider = if theme.ascii { " | " } else { " │ " };
    let pane_w = usize::from(inner.width)
        .saturating_sub(10)
        .min(RIGHT_PANE_COLS);

    let r0 = title_row(id, tint, pane_w, theme);
    let r1 = barcode_and_factors_row(id, summary, pane_w, theme);
    let r2 = meta_and_dots_row(summary, tint, pane_w, theme);

    let lines: Vec<Line<'_>> = [(s0, r0), (s1, r1), (s2, r2)]
        .into_iter()
        .map(|(sigil, mut right)| {
            let mut spans = Vec::with_capacity(right.len() + 4);
            spans.push(Span::raw(" "));
            spans.push(Span::styled(sigil, tint));
            spans.push(Span::styled(divider, theme.muted()));
            spans.append(&mut right);
            Line::from(spans)
        })
        .collect();

    frame.render_widget(Paragraph::new(lines), inner);
}

fn card_footer(total: usize, focused: bool, theme: &Theme) -> Option<Line<'static>> {
    match (focused, total > 1, theme.ascii) {
        (true, true, false) => Some(Line::from(Span::styled(
            " ←/→ · h/l flip · Enter deck ",
            theme.accent(),
        ))),
        (true, true, true) => Some(Line::from(Span::styled(
            " Lt/Rt - h/l flip - Enter deck ",
            theme.accent(),
        ))),
        (true, false, _) => Some(Line::from(Span::styled(" selected ", theme.accent()))),
        (false, true, false) => Some(Line::from(Span::styled(
            " ←/→ · Ctrl-N/P switch ",
            theme.muted(),
        ))),
        (false, true, true) => Some(Line::from(Span::styled(
            " Lt/Rt - Ctrl-N/P switch ",
            theme.muted(),
        ))),
        (false, false, _) => None,
    }
}

fn title_row<'a>(id: Option<&[u8; 16]>, tint: Style, width: usize, theme: &Theme) -> Vec<Span<'a>> {
    let vk = format!("{} ", theme.glyphs.vk);
    let name = card_codename(id);
    let tag = short_tag(id);
    two_columns(
        vec![Span::styled(vk, tint), Span::styled(name, theme.strong())],
        vec![Span::styled(tag, theme.muted())],
        width,
    )
}

fn barcode_and_factors_row<'a>(
    id: Option<&[u8; 16]>,
    summary: &CardSummary,
    width: usize,
    theme: &Theme,
) -> Vec<Span<'a>> {
    let bar = stripe_bar(id, theme.glyphs);
    let left = vec![Span::styled(bar, theme.zebra())];
    let right = if summary.generation.is_none() {
        vec![Span::styled("unreadable", theme.danger())]
    } else {
        let full = factor_chips(summary.presence, theme.glyphs, false);
        let chosen = if 8 + 1 + full.chars().count() <= width {
            full
        } else {
            factor_chips(summary.presence, theme.glyphs, true)
        };
        vec![Span::styled(chosen, theme.text())]
    };
    two_columns(left, right, width)
}

fn meta_and_dots_row<'a>(
    summary: &CardSummary,
    tint: Style,
    width: usize,
    theme: &Theme,
) -> Vec<Span<'a>> {
    let glyphs = theme.glyphs;
    let meta = summary.generation.map_or_else(
        || String::from("locked vault"),
        |generation| {
            if summary.presence.recovery {
                format!("gen {generation} {} {} phrase", glyphs.dot, glyphs.recovery)
            } else {
                format!("gen {generation} {} sealed", glyphs.dot)
            }
        },
    );
    let right = deck_dots(summary.index, summary.total, tint, theme);
    two_columns(vec![Span::styled(meta, theme.muted())], right, width)
}

fn factor_chips(presence: Presence, glyphs: &Glyphs, compact: bool) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(3);
    if presence.owned_devices > 0 {
        parts.push(if compact {
            glyphs.device.to_owned()
        } else {
            format!("{} device", glyphs.device)
        });
    } else if presence.devices > 0 {
        parts.push(if compact {
            glyphs.device.to_owned()
        } else {
            format!("{} {} dev", glyphs.device, presence.devices)
        });
    }
    if presence.password {
        parts.push(if compact {
            glyphs.password.to_owned()
        } else {
            format!("{} pass", glyphs.password)
        });
    }
    if presence.hw_keys > 0 {
        parts.push(if compact {
            glyphs.hw_key.to_owned()
        } else {
            format!("{} key", glyphs.hw_key)
        });
    }
    if parts.is_empty() {
        return String::from("no factor");
    }
    let sep = if compact {
        " ".to_owned()
    } else {
        format!(" {} ", glyphs.dot)
    };
    parts.join(&sep)
}

fn deck_dots<'a>(index: usize, total: usize, tint: Style, theme: &Theme) -> Vec<Span<'a>> {
    let glyphs = theme.glyphs;
    if total <= 1 {
        return vec![Span::styled("solo card", theme.muted())];
    }
    let window = total.min(5);
    let start = index
        .saturating_sub(window / 2)
        .min(total.saturating_sub(window));
    let mut spans = Vec::with_capacity(window * 2 + 2);
    if start > 0 {
        spans.push(Span::styled(format!("{} ", glyphs.dot), theme.muted()));
    }
    for offset in 0..window {
        if offset > 0 {
            spans.push(Span::raw(" "));
        }
        let pos = start + offset;
        if pos == index {
            spans.push(Span::styled(glyphs.on, tint.add_modifier(Modifier::BOLD)));
        } else {
            spans.push(Span::styled(glyphs.off, theme.muted()));
        }
    }
    if start + window < total {
        spans.push(Span::styled(format!(" {}", glyphs.dot), theme.muted()));
    }
    spans
}

fn stripe_bar(id: Option<&[u8; 16]>, glyphs: &Glyphs) -> String {
    let bytes = id.map_or(&[0xA5, 0x5A][..], |arr| arr.as_slice());
    stripe_print(bytes, glyphs).chars().take(8).collect()
}

fn two_columns<'a>(left: Vec<Span<'a>>, right: Vec<Span<'a>>, width: usize) -> Vec<Span<'a>> {
    let left_len: usize = left.iter().map(|span| span.content.chars().count()).sum();
    let right_len: usize = right.iter().map(|span| span.content.chars().count()).sum();
    let gap = width.saturating_sub(left_len + right_len).max(1);
    let mut out = Vec::with_capacity(left.len() + right.len() + 1);
    out.extend(left);
    out.push(Span::raw(" ".repeat(gap)));
    out.extend(right);
    out
}

fn draw_peek(
    frame: &mut Frame<'_>,
    area: Rect,
    neighbor_id: Option<&[u8; 16]>,
    is_left: bool,
    focused: bool,
    theme: &Theme,
) {
    let dim = card_tint_dim(neighbor_id, theme);
    let arrow = if focused {
        theme.accent()
    } else {
        theme.muted()
    };
    let [s0, s1, s2] = sigil_rows(neighbor_id, theme.ascii);
    let slice_edge = |row: &str| -> String {
        if is_left {
            row.chars().take(3).collect()
        } else {
            row.chars().skip(2).take(3).collect()
        }
    };
    let edges = [slice_edge(&s0), slice_edge(&s1), slice_edge(&s2)];
    let wide = area.width >= 8;
    let lines = if is_left {
        peek_left_lines(&edges, wide, dim, arrow, theme.ascii)
    } else {
        peek_right_lines(&edges, wide, dim, arrow, theme.ascii)
    };
    frame.render_widget(Paragraph::new(lines), area);
}

fn peek_left_lines<'a>(
    [e0, e1, e2]: &[String; 3],
    wide: bool,
    dim: Style,
    arrow: Style,
    ascii: bool,
) -> Vec<Line<'a>> {
    let (tl, bl, v, h, ptr) = if ascii {
        ("+", "+", "|", "-", "<")
    } else {
        ("╭", "╰", "│", "─", "←")
    };
    let pad = if wide { "  " } else { "" };
    let mid_bar = if wide { format!("{v} ") } else { String::new() };
    vec![
        Line::from(Span::styled(format!("{pad}{tl}{}", h.repeat(5)), dim)),
        Line::from(Span::styled(format!("{pad}{v} {e0} "), dim)),
        Line::from(vec![
            Span::styled(format!("{ptr} "), arrow),
            Span::styled(format!("{mid_bar}{e1} "), dim),
        ]),
        Line::from(Span::styled(format!("{pad}{v} {e2} "), dim)),
        Line::from(Span::styled(format!("{pad}{bl}{}", h.repeat(5)), dim)),
    ]
}

fn peek_right_lines<'a>(
    [e0, e1, e2]: &[String; 3],
    wide: bool,
    dim: Style,
    arrow: Style,
    ascii: bool,
) -> Vec<Line<'a>> {
    let (tr, br, v, h, ptr) = if ascii {
        ("+", "+", "|", "-", ">")
    } else {
        ("╮", "╯", "│", "─", "→")
    };
    let pad = if wide { "  " } else { "" };
    let mid_bar = if wide { format!(" {v}") } else { String::new() };
    vec![
        Line::from(Span::styled(format!("{}{tr}{pad}", h.repeat(5)), dim)),
        Line::from(Span::styled(format!(" {e0} {v}{pad}"), dim)),
        Line::from(vec![
            Span::styled(format!(" {e1}{mid_bar}"), dim),
            Span::styled(format!(" {ptr}"), arrow),
        ]),
        Line::from(Span::styled(format!(" {e2} {v}{pad}"), dim)),
        Line::from(Span::styled(format!("{}{br}{pad}", h.repeat(5)), dim)),
    ]
}
