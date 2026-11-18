//! Deterministic visual identity for a vault's public `vault_id`.
//!
//! Before a vault unlocks, `local.meta` is sealed under the vault key, so only
//! the public `vault_id` and `WrapDirectory` are visible. Each `vault_id` maps
//! deterministically to a mineral-constellation codename, a 5×3 symmetric zebra
//! sigil, and a theme-aware jewel tint. Pure presentation over public bytes.

use ratatui::style::{Color, Modifier, Style};

use crate::ui::theme::{Theme, ThemeName};
use crate::ui::widgets::fingerprint::grouped_hex;

const MINERALS: [&str; 32] = [
    "Amber", "Onyx", "Jade", "Cobalt", "Silver", "Quartz", "Garnet", "Topaz", "Opal", "Ruby",
    "Beryl", "Coral", "Jasper", "Zircon", "Spinel", "Basalt", "Flint", "Mica", "Slate", "Ivory",
    "Bronze", "Copper", "Prism", "Nacre", "Agate", "Lapis", "Pyrite", "Citrine", "Peridot",
    "Sable", "Chrome", "Velvet",
];

const CONSTELLATIONS: [&str; 32] = [
    "Orion", "Lyra", "Cygnus", "Draco", "Vela", "Vega", "Carina", "Perseus", "Pegasus", "Phoenix",
    "Taurus", "Hydra", "Cetus", "Pavo", "Aquila", "Auriga", "Corvus", "Norma", "Pictor", "Tucana",
    "Dorado", "Lynx", "Lepus", "Musca", "Ara", "Mensa", "Pyxis", "Volans", "Rigel", "Sirius",
    "Altair", "Polaris",
];

const DARK_JEWELS: [(u8, u8, u8); 8] = [
    (0xFF, 0xCA, 0x64),
    (0x7C, 0xFF, 0xB2),
    (0x6E, 0xD8, 0xFF),
    (0xB4, 0x96, 0xFF),
    (0xFF, 0x8A, 0xA8),
    (0x56, 0xE3, 0xC8),
    (0xD2, 0xDE, 0xEB),
    (0xFF, 0xA6, 0x73),
];

const LIGHT_JEWELS: [(u8, u8, u8); 8] = [
    (0x9E, 0x5A, 0x00),
    (0x0B, 0x7A, 0x43),
    (0x0F, 0x5E, 0x9C),
    (0x5B, 0x3E, 0xC8),
    (0xA8, 0x24, 0x4D),
    (0x0A, 0x6E, 0x63),
    (0x36, 0x45, 0x59),
    (0x9C, 0x41, 0x14),
];

const fn mix_public_id(id: &[u8; 16]) -> u64 {
    let &[
        b0,
        b1,
        b2,
        b3,
        b4,
        b5,
        b6,
        b7,
        b8,
        b9,
        b10,
        b11,
        b12,
        b13,
        b14,
        b15,
    ] = id;
    let lo = u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7]);
    let hi = u64::from_le_bytes([b8, b9, b10, b11, b12, b13, b14, b15]);
    let mut mixed = lo ^ hi.rotate_left(29) ^ 0x9E37_79B9_7F4A_7C15;
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    mixed ^ (mixed >> 31)
}

/// Memorable mineral + constellation codename for `id`, or `"Local Vault"`.
#[must_use]
pub fn card_codename(id: Option<&[u8; 16]>) -> String {
    let Some(bytes) = id else {
        return String::from("Local Vault");
    };
    let traits = mix_public_id(bytes);
    let mineral_idx = usize::try_from(traits & 0x1F).unwrap_or(0);
    let star_idx = usize::try_from((traits >> 5) & 0x1F).unwrap_or(0);
    let mineral = MINERALS.get(mineral_idx).copied().unwrap_or("Amber");
    let star = CONSTELLATIONS.get(star_idx).copied().unwrap_or("Orion");
    format!("{mineral} {star}")
}

/// Short hex tag (`754C-9E75`), or `"local"` when `id` is absent.
#[must_use]
pub fn short_tag(id: Option<&[u8; 16]>) -> String {
    id.map_or_else(|| String::from("local"), |bytes| grouped_hex(bytes, 2))
}

/// Three rows of 5 mirror-symmetric cells forming a unique zebra sigil.
#[must_use]
pub fn sigil_rows(id: Option<&[u8; 16]>, ascii: bool) -> [String; 3] {
    let (dot, stripe, solid) = if ascii {
        ('.', '=', '#')
    } else {
        ('·', '▚', '█')
    };
    let Some(bytes) = id else {
        return [
            format!("{dot}{stripe}{solid}{stripe}{dot}"),
            format!("{stripe}{solid}{dot}{solid}{stripe}"),
            format!("{dot}{stripe}{solid}{stripe}{dot}"),
        ];
    };
    let bits = mix_public_id(bytes) >> 13;
    let mut half = [[dot; 3]; 3];
    let mut solids = 0usize;
    for (row_idx, row_cells) in half.iter_mut().enumerate() {
        for (col_idx, slot) in row_cells.iter_mut().enumerate() {
            let shift = (row_idx * 3 + col_idx) * 2;
            let cell = match (bits >> shift) & 0b11 {
                0 => dot,
                1 => stripe,
                _ => {
                    solids += 1;
                    solid
                }
            };
            *slot = cell;
        }
    }
    let [_, [_, _, center], _] = &mut half;
    if solids == 0 {
        *center = solid;
    } else if solids == 9 {
        *center = stripe;
    }
    half.map(|[c0, c1, c2]| {
        let mut line = String::with_capacity(15);
        for ch in [c0, c1, c2, c1, c0] {
            line.push(ch);
        }
        line
    })
}

/// Foreground jewel style for a vault card.
#[must_use]
pub fn card_tint(id: Option<&[u8; 16]>, theme: &Theme) -> Style {
    match theme.name {
        ThemeName::Mono => Style::new().add_modifier(Modifier::BOLD),
        ThemeName::StripesDark => {
            let (r, g, b) = jewel_rgb(id, &DARK_JEWELS, (0x7C, 0xFF, 0xB2));
            Style::new().fg(Color::Rgb(r, g, b))
        }
        ThemeName::StripesLight => {
            let (r, g, b) = jewel_rgb(id, &LIGHT_JEWELS, (0x0B, 0x8A, 0x4C));
            Style::new().fg(Color::Rgb(r, g, b))
        }
    }
}

/// Dimmed jewel style for background peek cards in the carousel.
#[must_use]
pub fn card_tint_dim(id: Option<&[u8; 16]>, theme: &Theme) -> Style {
    match theme.name {
        ThemeName::Mono => Style::new().add_modifier(Modifier::DIM),
        ThemeName::StripesDark => {
            let (r, g, b) = jewel_rgb(id, &DARK_JEWELS, (0x7C, 0xFF, 0xB2));
            Style::new().fg(Color::Rgb(
                blend(r, 0x17, 42),
                blend(g, 0x19, 42),
                blend(b, 0x1C, 42),
            ))
        }
        ThemeName::StripesLight => {
            let (r, g, b) = jewel_rgb(id, &LIGHT_JEWELS, (0x0B, 0x8A, 0x4C));
            Style::new().fg(Color::Rgb(
                blend(r, 0xB8, 45),
                blend(g, 0xBA, 45),
                blend(b, 0xBE, 45),
            ))
        }
    }
}

const fn blend(fg: u8, bg: u8, weight_pct: u16) -> u8 {
    let fg_wide = u16::from_le_bytes([fg, 0]);
    let bg_wide = u16::from_le_bytes([bg, 0]);
    let mixed = (fg_wide * weight_pct + bg_wide * (100 - weight_pct)) / 100;
    let [lo, _] = mixed.to_le_bytes();
    lo
}

fn jewel_rgb(
    id: Option<&[u8; 16]>,
    table: &[(u8, u8, u8); 8],
    fallback: (u8, u8, u8),
) -> (u8, u8, u8) {
    let Some(bytes) = id else {
        return fallback;
    };
    let idx = usize::try_from((mix_public_id(bytes) >> 10) & 0x07).unwrap_or(0);
    table.get(idx).copied().unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, reason = "tests may index")]

    use super::{card_codename, short_tag, sigil_rows};

    #[test]
    fn codenames_and_sigils_are_deterministic_and_symmetric() {
        let a = [
            0x75, 0x4C, 0x9E, 0x75, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ];
        let b = [
            0x75, 0x4C, 0x9E, 0x75, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13,
        ];
        assert_eq!(card_codename(Some(&a)), card_codename(Some(&a)));
        assert_ne!(card_codename(Some(&a)), card_codename(Some(&b)));
        assert_eq!(short_tag(Some(&a)), "754C-9E75");
        assert_eq!(card_codename(None), "Local Vault");

        for ascii in [false, true] {
            let rows = sigil_rows(Some(&a), ascii);
            for row in &rows {
                let chars: Vec<char> = row.chars().collect();
                assert_eq!(chars.len(), 5);
                assert_eq!(chars[0], chars[4]);
                assert_eq!(chars[1], chars[3]);
            }
        }
        assert_ne!(sigil_rows(Some(&a), false), sigil_rows(Some(&b), false));
    }
}
