//! Bars: strength, size, countdowns, hold progress.

use ratatui::style::Style;
use ratatui::text::Span;

use crate::secure::strength::{Strength, StrengthLabel};
use crate::ui::theme::{Glyphs, Theme};

/// Filled cells for `fraction` of `width`.
#[must_use]
pub fn filled(fraction: f64, width: usize) -> usize {
    let width_f = f64::from(u32::try_from(width).unwrap_or(u32::MAX));
    let cells = (fraction.clamp(0.0, 1.0) * width_f).round();
    // `cells` is within `0..=width` after the clamp above.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let cells = cells as usize;
    cells.min(width)
}

/// A `width`-cell bar filled to `fraction`.
#[must_use]
pub fn bar(fraction: f64, width: usize, glyphs: &Glyphs) -> String {
    let on = filled(fraction, width);
    let mut out = String::with_capacity(width * 3);
    (0..width).for_each(|cell| {
        out.push_str(if cell < on {
            glyphs.bar_on
        } else {
            glyphs.bar_off
        });
    });
    out
}

/// Style for a strength class.
#[must_use]
pub const fn strength_style(label: StrengthLabel, theme: &Theme) -> Style {
    match label {
        StrengthLabel::VeryWeak | StrengthLabel::Weak => theme.danger(),
        StrengthLabel::Fair => theme.warn(),
        StrengthLabel::Good | StrengthLabel::Strong | StrengthLabel::Excellent => theme.accent(),
    }
}

/// `▰▰▰▰▱ good · 71 bits`.
#[must_use]
pub fn strength_spans(strength: Strength, width: usize, theme: &Theme) -> Vec<Span<'static>> {
    let style = strength_style(strength.label, theme);
    vec![
        Span::styled(
            bar(f64::from(strength.bits) / 128.0, width, theme.glyphs),
            style,
        ),
        Span::styled(format!(" {} ", strength.label.word()), style),
        Span::styled(format!("{} bits", strength.bits), theme.muted()),
    ]
}

/// Bytes as `1.2 KiB`.
#[must_use]
pub fn size_label(bytes: usize) -> String {
    let kib = f64::from(u32::try_from(bytes).unwrap_or(u32::MAX)) / 1024.0;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if kib < 1024.0 {
        format!("{kib:.1} KiB")
    } else {
        format!("{:.1} MiB", kib / 1024.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{filled, size_label};

    #[test]
    fn fills_and_sizes() {
        assert_eq!(filled(0.5, 10), 5);
        assert_eq!(filled(2.0, 10), 10);
        assert_eq!(filled(-1.0, 10), 0);
        assert_eq!(size_label(1229), "1.2 KiB");
    }
}
