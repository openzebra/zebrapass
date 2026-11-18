#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "tests may unwrap and index"
)]

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::layout::Rect;

use super::data::{SPECS_LOW, SPECS_MED, gf_mul};
use super::render::draw_qr_card;
use super::{Ecc, QrMatrix, encode};
use crate::ui::theme::{Theme, ThemeName};

#[test]
fn gf_arithmetic_sanity() {
    assert_eq!(gf_mul(0x57, 0x02), 0xAE);
    assert_eq!(gf_mul(0x80, 0x02), 0x1D);
    assert_eq!(gf_mul(0x01, 0xFF), 0xFF);
}

#[test]
fn format_and_version_bits_match_iso_vectors() {
    let m1 = encode(b"A", Ecc::Low).unwrap();
    let format_copy1 = read_format_copy1(&m1);
    let format_copy2 = read_format_copy2(&m1);
    assert_eq!(format_copy1, format_copy2);
    assert_eq!(format_copy1 >> 13, 0b11);
    assert_eq!(decode_format_bits(format_copy1).unwrap().0, Ecc::Low);

    let m7 = encode(&[b'x'; 140], Ecc::Low).unwrap();
    assert_eq!(m7.size(), 45);
    assert_eq!(read_version_copy1(&m7), 0x07C94);
    assert_eq!(read_version_copy2(&m7), 0x07C94);

    let m8 = encode(&[b'x'; 160], Ecc::Low).unwrap();
    assert_eq!(m8.size(), 49);
    assert_eq!(read_version_copy1(&m8), 0x085BC);
    assert_eq!(read_version_copy2(&m8), 0x085BC);

    let m9 = encode(&[b'x'; 200], Ecc::Low).unwrap();
    assert_eq!(m9.size(), 53);
    assert_eq!(read_version_copy1(&m9), 0x09A99);
    assert_eq!(read_version_copy2(&m9), 0x09A99);

    let m10 = encode(&[b'x'; 240], Ecc::Low).unwrap();
    assert_eq!(m10.size(), 57);
    assert_eq!(read_version_copy1(&m10), 0x0A4D3);
    assert_eq!(read_version_copy2(&m10), 0x0A4D3);
}

#[test]
fn round_trips_payloads_through_independent_decoder_across_versions_1_to_10() {
    let bare_url = b"zebrapass://share?v=1&fp=22DC4AB1C6185D3C8EB29186E81067067558EA48";
    let ipv4_url = b"zebrapass://share?v=1&fp=22DC4AB1C6185D3C8EB29186E81067067558EA48&addr=192.168.15.150%3A7447";
    let ipv6_url = b"zebrapass://share?v=1&fp=22DC4AB1C6185D3C8EB29186E81067067558EA48&addr=%5B2804%3A7f2%3Ac011%3Ad6d0%3A918b%3A7082%3A49d6%3Ad038%5D%3A7447";

    let mut samples: Vec<Vec<u8>> = vec![
        b"hi".to_vec(),
        bare_url.to_vec(),
        ipv4_url.to_vec(),
        ipv6_url.to_vec(),
    ];
    for len in [10, 17, 25, 42, 62, 84, 106, 122, 150, 180, 214, 270] {
        samples.push(
            (0..len)
                .map(|i| u8::try_from((i * 13 + 7) % 256).unwrap())
                .collect(),
        );
    }

    for payload in &samples {
        for ecc in [Ecc::Low, Ecc::Medium] {
            if let Some(matrix) = encode(payload, ecc) {
                let decoded = decode_and_verify(&matrix, ecc);
                assert_eq!(&decoded, payload, "len={} ecc={ecc:?}", payload.len());
            }
        }
    }
    assert!(encode(&[0u8; 300], Ecc::Low).is_none());
}

#[test]
fn render_card_handles_normal_compact_mono_ascii_and_small_areas() {
    let bare = "zebrapass://share?v=1&fp=22DC4AB1C6185D3C8EB29186E81067067558EA48";
    let with_addr = "zebrapass://share?v=1&fp=22DC4AB1C6185D3C8EB29186E81067067558EA48&addr=192.168.15.150%3A7447";

    let render_once = |w: u16, h: u16, theme: Theme| -> (Option<String>, String) {
        let backend = TestBackend::new(w, h);
        let mut term = Terminal::new(backend).unwrap();
        let mut chosen = None;
        term.draw(|f| {
            chosen = draw_qr_card(f, Rect::new(0, 0, w, h), with_addr, bare, &theme);
        })
        .unwrap();
        let buf = term.backend().buffer().clone();
        let text: String = (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        (chosen, text)
    };

    let dark = Theme::new(ThemeName::StripesDark, false, false);
    let (chosen, text) = render_once(48, 25, dark);
    assert_eq!(chosen.as_deref(), Some(with_addr));
    assert!(text.contains('▀') || text.contains('▄') || text.contains('█'));

    // Tighter width where fallback bare URL fits (V4=33+4=37 vs V5=37+4=41).
    let (chosen_tight, _) = render_once(38, 22, dark);
    assert_eq!(chosen_tight.as_deref(), Some(bare));

    // Too small: renders graceful notice.
    let (chosen_tiny, tiny_text) = render_once(20, 10, dark);
    assert!(chosen_tiny.is_none());
    assert!(tiny_text.contains("Resize for QR"));
    let (chosen_narrow, narrow_text) = render_once(28, 10, dark);
    assert!(chosen_narrow.is_none());
    assert!(narrow_text.contains("Enlarge window for QR"));

    // Mono theme renders inverted half-blocks cleanly.
    let mono = Theme::new(ThemeName::Mono, false, false);
    let (chosen_mono, mono_text) = render_once(48, 25, mono);
    assert_eq!(chosen_mono.as_deref(), Some(with_addr));
    assert!(mono_text.contains('▀') || mono_text.contains('▄'));

    // ASCII mode reports Unicode needed.
    let ascii = Theme::new(ThemeName::StripesDark, true, false);
    let (chosen_ascii, ascii_text) = render_once(48, 25, ascii);
    assert!(chosen_ascii.is_none());
    assert!(ascii_text.contains("QR needs Unicode mode"));
}

// --- Independent QR verification decoder (tests only) ---

fn read_format_copy1(m: &QrMatrix) -> u32 {
    let mut bits = 0u32;
    for i in 0..6 {
        if m.get(8, i) {
            bits |= 1 << i;
        }
    }
    if m.get(8, 7) {
        bits |= 1 << 6;
    }
    if m.get(8, 8) {
        bits |= 1 << 7;
    }
    if m.get(7, 8) {
        bits |= 1 << 8;
    }
    for i in 9..15 {
        if m.get(14 - i, 8) {
            bits |= 1 << i;
        }
    }
    bits
}

fn read_format_copy2(m: &QrMatrix) -> u32 {
    let mut bits = 0u32;
    let s = m.size();
    for i in 0..8 {
        if m.get(s - 1 - i, 8) {
            bits |= 1 << i;
        }
    }
    for i in 8..15 {
        if m.get(8, s - 15 + i) {
            bits |= 1 << i;
        }
    }
    bits
}

fn read_version_copy1(m: &QrMatrix) -> u32 {
    let s = m.size();
    let mut bits = 0u32;
    for i in 0..18usize {
        if m.get(s - 11 + i % 3, i / 3) {
            bits |= 1 << i;
        }
    }
    bits
}

fn read_version_copy2(m: &QrMatrix) -> u32 {
    let s = m.size();
    let mut bits = 0u32;
    for i in 0..18usize {
        if m.get(i / 3, s - 11 + i % 3) {
            bits |= 1 << i;
        }
    }
    bits
}

fn decode_format_bits(raw: u32) -> Option<(Ecc, u32)> {
    let unmasked = raw ^ 0x5412;
    let data = unmasked >> 10;
    let mut rem = data;
    for _ in 0..10 {
        rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    }
    if ((data << 10) | rem) != unmasked {
        return None;
    }
    let ecc = match data >> 3 {
        1 => Ecc::Low,
        0 => Ecc::Medium,
        _ => return None,
    };
    Some((ecc, data & 7))
}

fn decode_and_verify(m: &QrMatrix, expected_ecc: Ecc) -> Vec<u8> {
    let size = m.size();
    let version = (size - 17) / 4;
    let c1 = read_format_copy1(m);
    let c2 = read_format_copy2(m);
    assert_eq!(c1, c2, "format copies mismatch");
    assert!(m.get(8, size - 8), "missing dark module");
    let (ecc, mask) = decode_format_bits(c1).expect("invalid BCH format info");
    assert_eq!(ecc, expected_ecc);
    if version >= 7 {
        assert_eq!(read_version_copy1(m), read_version_copy2(m));
    }

    let spec = match ecc {
        Ecc::Low => SPECS_LOW[version - 1],
        Ecc::Medium => SPECS_MED[version - 1],
    };

    // Build function-module mask independently via Canvas.
    let mut func = super::Canvas::new(size);
    func.draw_function_patterns(spec);

    // Read codewords via zig-zag and apply mask.
    let total_cw = spec.total_data + (spec.g1_blocks + spec.g2_blocks) * spec.ec_per_block;
    let mut bits = Vec::with_capacity(total_cw * 8);
    let mut right = size.cast_signed() - 1;
    while right >= 1 {
        if right == 6 {
            right = 5;
        }
        for vert in 0..size {
            for j in 0..2isize {
                let x = usize::try_from(right - j).unwrap();
                let upward = ((right + 1) & 2) == 0;
                let y = if upward { size - 1 - vert } else { vert };
                if !func.is_function(x, y) && bits.len() < total_cw * 8 {
                    let invert = match mask {
                        0 => (x + y).is_multiple_of(2),
                        1 => y.is_multiple_of(2),
                        2 => x.is_multiple_of(3),
                        3 => (x + y).is_multiple_of(3),
                        4 => (x / 3 + y / 2).is_multiple_of(2),
                        5 => (x * y) % 2 + (x * y) % 3 == 0,
                        6 => ((x * y) % 2 + (x * y) % 3).is_multiple_of(2),
                        _ => ((x + y) % 2 + (x * y) % 3).is_multiple_of(2),
                    };
                    bits.push(m.get(x, y) ^ invert);
                }
            }
        }
        right -= 2;
    }

    let codewords: Vec<u8> = bits
        .chunks(8)
        .map(|b| b.iter().fold(0u8, |acc, &bit| (acc << 1) | u8::from(bit)))
        .collect();
    assert_eq!(codewords.len(), total_cw);

    // De-interleave data and EC blocks and verify RS syndromes == 0 at alpha^0..alpha^(ec-1).
    let total_blocks = spec.g1_blocks + spec.g2_blocks;
    let mut data_blocks: Vec<Vec<u8>> = (0..total_blocks)
        .map(|idx| {
            let len = if idx < spec.g1_blocks {
                spec.g1_data
            } else {
                spec.g2_data
            };
            Vec::with_capacity(len)
        })
        .collect();

    let mut cw_idx = 0usize;
    let max_data = spec.g1_data.max(spec.g2_data);
    for round in 0..max_data {
        for (b_idx, block) in data_blocks.iter_mut().enumerate() {
            let cap = if b_idx < spec.g1_blocks {
                spec.g1_data
            } else {
                spec.g2_data
            };
            if round < cap {
                block.push(codewords[cw_idx]);
                cw_idx += 1;
            }
        }
    }

    let mut ec_blocks = vec![Vec::with_capacity(spec.ec_per_block); total_blocks];
    for _ in 0..spec.ec_per_block {
        for ec_block in &mut ec_blocks {
            ec_block.push(codewords[cw_idx]);
            cw_idx += 1;
        }
    }

    for (d_blk, e_blk) in data_blocks.iter().zip(ec_blocks.iter()) {
        let mut full = d_blk.clone();
        full.extend_from_slice(e_blk);
        let mut root = 1u8;
        for power in 0..spec.ec_per_block {
            let mut eval = 0u8;
            for &coef in &full {
                eval = gf_mul(eval, root) ^ coef;
            }
            assert_eq!(eval, 0, "RS syndrome non-zero at alpha^{power}");
            root = gf_mul(root, 2);
        }
    }

    let flat: Vec<u8> = data_blocks.into_iter().flatten().collect();
    assert_eq!(flat.len(), spec.total_data);
    let mut stream = Vec::with_capacity(flat.len() * 8);
    for b in flat {
        for s in (0..8).rev() {
            stream.push(((b >> s) & 1) != 0);
        }
    }
    let read_n = |pos: &mut usize, n: usize| -> usize {
        let mut v = 0usize;
        for _ in 0..n {
            v = (v << 1) | usize::from(stream[*pos]);
            *pos += 1;
        }
        v
    };
    let mut pos = 0usize;
    assert_eq!(read_n(&mut pos, 4), 0b0100, "expected byte mode");
    let len = read_n(&mut pos, if version >= 10 { 16 } else { 8 });
    (0..len)
        .map(|_| u8::try_from(read_n(&mut pos, 8)).unwrap())
        .collect()
}
