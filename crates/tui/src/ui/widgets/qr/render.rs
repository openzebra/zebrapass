//! Terminal half-block QR renderer with quiet-zone and theme contrast support.

use ratatui::Frame;
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::{Ecc, QrMatrix, encode};
use crate::ui::layout::centered;
use crate::ui::theme::{Theme, ThemeName};

const QR_DARK: Color = Color::Rgb(0x0E, 0x0F, 0x11);
const QR_LIGHT: Color = Color::Rgb(0xF7, 0xF7, 0xF5);

/// Encode and render `primary_uri` (or `fallback_uri` if tighter room requires)
/// inside `area`, returning whichever URI was drawn when the QR fits.
pub fn draw_qr_card(
    frame: &mut Frame<'_>,
    area: Rect,
    primary_uri: &str,
    fallback_uri: &str,
    theme: &Theme,
) -> Option<String> {
    if area.width < 10 || area.height < 6 {
        let msg = if area.width >= 21 {
            "Enlarge window for QR"
        } else {
            "Resize for QR"
        };
        render_notice(frame, area, msg, theme);
        return None;
    }
    if theme.ascii {
        render_notice(frame, area, "QR needs Unicode mode", theme);
        return None;
    }
    let Some((matrix, quiet, chosen_uri)) = select_fitting(area, primary_uri, fallback_uri) else {
        let msg = if area.width >= 21 {
            "Enlarge window for QR"
        } else {
            "Resize for QR"
        };
        render_notice(frame, area, msg, theme);
        return None;
    };

    let full = matrix.size() + quiet * 2;
    let width = u16::try_from(full).unwrap_or(u16::MAX);
    let height = u16::try_from(full.div_ceil(2)).unwrap_or(u16::MAX);
    let target = centered(area, width, height);
    let mono = matches!(theme.name, ThemeName::Mono);
    let style = if mono {
        Style::new()
    } else {
        Style::new().fg(QR_DARK).bg(QR_LIGHT)
    };
    let module_at = |qx: usize, qy: usize| -> bool {
        if qx < quiet || qy < quiet {
            return false;
        }
        let mx = qx - quiet;
        let my = qy - quiet;
        if mx >= matrix.size() || my >= matrix.size() {
            return false;
        }
        matrix.get(mx, my)
    };

    let mut lines = Vec::with_capacity(full.div_ceil(2));
    for row_pair in (0..full).step_by(2) {
        let mut line = String::with_capacity(full * 3);
        for col in 0..full {
            let top = module_at(col, row_pair);
            let bottom = if row_pair + 1 < full {
                module_at(col, row_pair + 1)
            } else {
                false
            };
            let ch = if mono {
                match (top, bottom) {
                    (false, false) => '█',
                    (false, true) => '▀',
                    (true, false) => '▄',
                    (true, true) => ' ',
                }
            } else {
                match (top, bottom) {
                    (true, true) => '█',
                    (true, false) => '▀',
                    (false, true) => '▄',
                    (false, false) => ' ',
                }
            };
            line.push(ch);
        }
        lines.push(Line::from(Span::styled(line, style)));
    }
    frame.render_widget(Paragraph::new(lines), target);
    Some(chosen_uri)
}

fn select_fitting(
    area: Rect,
    primary_uri: &str,
    fallback_uri: &str,
) -> Option<(QrMatrix, usize, String)> {
    let mut candidates = Vec::with_capacity(4);
    candidates.push((primary_uri, Ecc::Medium));
    candidates.push((primary_uri, Ecc::Low));
    if fallback_uri != primary_uri {
        candidates.push((fallback_uri, Ecc::Medium));
        candidates.push((fallback_uri, Ecc::Low));
    }
    for (uri, ecc) in candidates {
        let Some(matrix) = encode(uri.as_bytes(), ecc) else {
            continue;
        };
        if let Some(quiet) = best_quiet(matrix.size(), area) {
            return Some((matrix, quiet, uri.to_owned()));
        }
    }
    None
}

fn best_quiet(size: usize, area: Rect) -> Option<usize> {
    let w = usize::from(area.width);
    let h = usize::from(area.height);
    [4usize, 3, 2].into_iter().find(|&q| {
        let full = size + q * 2;
        full <= w && full.div_ceil(2) <= h
    })
}

fn render_notice(frame: &mut Frame<'_>, area: Rect, msg: &str, theme: &Theme) {
    let rect = centered(area, area.width, 1);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(msg.to_owned(), theme.muted())))
            .alignment(Alignment::Center),
        rect,
    );
}
