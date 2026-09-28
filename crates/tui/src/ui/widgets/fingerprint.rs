//! Stripe-prints of public identifiers: bit 1 → `▐`, bit 0 → `▌` over the
//! first 16 bits, plus grouped hex. A rendering of public bytes, not a hash.

use crate::ui::theme::Glyphs;

/// Bits drawn in a stripe-print.
pub const PRINT_BITS: usize = 16;

/// The stripe-print of `bytes`.
#[must_use]
pub fn stripe_print(bytes: &[u8], glyphs: &Glyphs) -> String {
    (0..PRINT_BITS)
        .map(|bit| {
            let byte = bytes.get(bit / 8).copied().unwrap_or(0);
            if byte & (0x80 >> (bit % 8)) == 0 {
                glyphs.bit_zero
            } else {
                glyphs.bit_one
            }
        })
        .collect()
}

/// `7F3A-19C2-E04B-88D1`: `groups` groups of two bytes.
#[must_use]
pub fn grouped_hex(bytes: &[u8], groups: usize) -> String {
    use std::fmt::Write as _;
    bytes.chunks(2).take(groups).enumerate().fold(
        String::with_capacity(groups * 5),
        |mut out, (index, pair)| {
            if index > 0 {
                out.push('-');
            }
            for byte in pair {
                let _ = write!(out, "{byte:02X}");
            }
            out
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{grouped_hex, stripe_print};
    use crate::ui::theme::{Theme, ThemeName};

    #[test]
    fn prints_bits_and_groups() {
        let theme = Theme::new(ThemeName::Mono, true, false);
        assert_eq!(
            stripe_print(&[0b1000_0001, 0xFF], theme.glyphs),
            "|::::::|||||||||"
        );
        assert_eq!(grouped_hex(&[0x7F, 0x3A, 0x19, 0xC2, 0xE0], 2), "7F3A-19C2");
    }
}
