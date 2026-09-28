//! Zebra stripes: the masked-secret glyph run, the "herd" animation, and
//! decorative rules. Anything striped holds a secret or stands for one.

use crate::ui::theme::Glyphs;

/// A masked secret is always this wide, whatever its length.
pub const MASK_CELLS: usize = 12;

/// `cells` mask glyphs.
#[must_use]
pub fn mask(glyphs: &Glyphs, cells: usize) -> String {
    glyphs.mask.repeat(cells)
}

/// A full-width stripe rule.
#[must_use]
pub fn rule(glyphs: &Glyphs, width: u16) -> String {
    mask(glyphs, usize::from(width))
}

/// A sparse rule: `▚ ▚ ▚ …`.
#[must_use]
pub fn sparse_rule(glyphs: &Glyphs, width: u16) -> String {
    (0..width)
        .map(|column| if column % 2 == 0 { glyphs.mask } else { " " })
        .collect()
}

/// A scrolling rule for the welcome banner: shifts one cell per `tick`.
#[must_use]
pub fn scrolling_rule(glyphs: &Glyphs, width: u16, tick: u64) -> String {
    let phase = usize::try_from(tick % 6).unwrap_or(0);
    (0..usize::from(width))
        .map(|column| {
            if (column + phase) % 6 == 5 {
                " "
            } else {
                glyphs.mask
            }
        })
        .collect()
}

/// One row of the herd: stripe runs of 2..=8 cells with 1..=2 cell gaps,
/// laid out from a small deterministic generator and drifting with `tick`.
#[must_use]
pub fn herd_row(glyphs: &Glyphs, width: u16, row: u16, tick: u64) -> String {
    let width = usize::from(width);
    let drift = usize::try_from(tick / 2).unwrap_or(0);
    let shift = if row % 2 == 0 {
        drift
    } else {
        width.saturating_sub(drift % width.max(1))
    };
    let mut cells = Vec::with_capacity(width * 2);
    let mut state = u64::from(row).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    while cells.len() < width * 2 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let run = 2 + usize::try_from(state % 7).unwrap_or(0);
        let gap = 1 + usize::try_from((state >> 8) % 2).unwrap_or(0);
        cells.extend(std::iter::repeat_n(true, run));
        cells.extend(std::iter::repeat_n(false, gap));
    }
    (0..width)
        .map(|column| {
            let index = (column + shift) % cells.len().max(1);
            if cells.get(index).copied().unwrap_or(false) {
                glyphs.mask
            } else {
                " "
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{herd_row, mask, MASK_CELLS};
    use crate::ui::theme::{Theme, ThemeName};

    #[test]
    fn mask_width_is_fixed_and_herd_moves() {
        let theme = Theme::new(ThemeName::Mono, true, true);
        assert_eq!(mask(theme.glyphs, MASK_CELLS).len(), MASK_CELLS);
        let a = herd_row(theme.glyphs, 40, 0, 0);
        let b = herd_row(theme.glyphs, 40, 0, 8);
        assert_eq!(a.chars().count(), 40);
        assert_ne!(a, b);
    }
}
