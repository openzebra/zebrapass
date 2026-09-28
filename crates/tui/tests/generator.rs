//! Generator: lengths, alphabets, exact entropy, and no visible bias.

#![allow(
    clippy::multiple_crate_versions,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_precision_loss,
    reason = "tests may unwrap and index; ratatui pulls duplicate transitive crates"
)]

use tui::secure::generator::{alphabet, generate, CharSets, GenMode, GenSpec};

#[test]
fn every_mode_respects_length_and_alphabet() {
    let chars = GenSpec::default();
    let value = generate(&chars).unwrap();
    assert_eq!(value.len(), usize::from(chars.length));
    let allowed = alphabet(chars.sets);
    assert!(value.iter().all(|byte| allowed.contains(byte)));

    let pin = GenSpec::for_mode(GenMode::Pin);
    let value = generate(&pin).unwrap();
    assert_eq!(value.len(), 6);
    assert!(value.iter().all(u8::is_ascii_digit));

    let words = GenSpec::for_mode(GenMode::Passphrase);
    let value = generate(&words).unwrap();
    let text = std::str::from_utf8(&value).unwrap();
    assert_eq!(text.split('-').count(), 6);
}

#[test]
fn entropy_is_length_times_log2_alphabet() {
    let chars = GenSpec::default();
    let size = alphabet(chars.sets).len() as f64;
    assert!(24.0f64.mul_add(-size.log2(), chars.entropy_bits()).abs() < 1e-9);
    assert!((GenSpec::for_mode(GenMode::Passphrase).entropy_bits() - 66.0).abs() < 1e-9);
    assert!(
        6.0f64
            .mul_add(
                -10f64.log2(),
                GenSpec::for_mode(GenMode::Pin).entropy_bits()
            )
            .abs()
            < 1e-9
    );
    let fewer = GenSpec {
        sets: CharSets::default().toggle(CharSets::SYMBOLS),
        ..chars
    };
    assert!(fewer.entropy_bits() < chars.entropy_bits());
}

#[test]
fn characters_are_not_visibly_biased() {
    // Chi-square over the 90-symbol default alphabet, 48 000 draws. 89
    // degrees of freedom; p = 0.0001 is about 151.
    let spec = GenSpec::default();
    let allowed = alphabet(spec.sets);
    let mut counts = vec![0u32; allowed.len()];
    for _ in 0..2_000 {
        for byte in generate(&spec).unwrap().iter() {
            let slot = allowed.iter().position(|symbol| symbol == byte).unwrap();
            counts[slot] += 1;
        }
    }
    let total: u32 = counts.iter().sum();
    let expected = f64::from(total) / counts.len() as f64;
    let chi: f64 = counts
        .iter()
        .map(|count| (f64::from(*count) - expected).powi(2) / expected)
        .sum();
    assert!(chi < 151.0, "chi-square {chi}");
}
