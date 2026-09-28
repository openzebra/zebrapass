//! Password, passphrase, and PIN generation from the OS CSPRNG.
//!
//! Indexes are drawn by rejection sampling, so every symbol is exactly
//! uniform. A failing OS RNG is an error for the caller to show; nothing
//! retries in a loop or falls back to weaker randomness.

use std::ops::RangeInclusive;

use zeroize::{Zeroize, Zeroizing};

/// The OS random source failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntropyError;

/// What to generate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenMode {
    /// Random characters from the selected sets.
    Chars,
    /// Random BIP39 words (11 bits each).
    Passphrase,
    /// Random digits.
    Pin,
}

impl GenMode {
    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Chars => "Random chars",
            Self::Passphrase => "Passphrase (BIP39 words)",
            Self::Pin => "PIN",
        }
    }

    /// Next mode in cycle order.
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Chars => Self::Passphrase,
            Self::Passphrase => Self::Pin,
            Self::Pin => Self::Chars,
        }
    }

    /// Allowed length (characters, words, or digits).
    #[must_use]
    pub const fn lengths(self) -> RangeInclusive<u16> {
        match self {
            Self::Chars => 8..=128,
            Self::Passphrase | Self::Pin => 4..=12,
        }
    }

    /// Default length.
    #[must_use]
    pub const fn default_length(self) -> u16 {
        match self {
            Self::Chars => 24,
            Self::Passphrase | Self::Pin => 6,
        }
    }
}

/// Character-set switches, packed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CharSets(u8);

impl CharSets {
    /// `a-z`.
    pub const LOWER: u8 = 1;
    /// `A-Z`.
    pub const UPPER: u8 = 1 << 1;
    /// `0-9`.
    pub const DIGITS: u8 = 1 << 2;
    /// Punctuation.
    pub const SYMBOLS: u8 = 1 << 3;
    /// Drop `0 O o 1 l I |`.
    pub const NO_LOOKALIKE: u8 = 1 << 4;
    /// The four character classes, in toggle order.
    pub const CLASSES: [u8; 4] = [Self::LOWER, Self::UPPER, Self::DIGITS, Self::SYMBOLS];

    /// Whether `bit` is set.
    #[must_use]
    pub const fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// Flip `bit`. The last character class cannot be switched off.
    #[must_use]
    pub const fn toggle(self, bit: u8) -> Self {
        let next = Self(self.0 ^ bit);
        let classes = Self::LOWER | Self::UPPER | Self::DIGITS | Self::SYMBOLS;
        if next.0 & classes == 0 {
            self
        } else {
            next
        }
    }
}

impl Default for CharSets {
    fn default() -> Self {
        Self(Self::LOWER | Self::UPPER | Self::DIGITS | Self::SYMBOLS)
    }
}

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!#$%&()*+,-./:;<=>?@[]^_{|}~";
const LOOKALIKE: &[u8] = b"0Oo1lI|";
/// Joins passphrase words.
pub const WORD_SEPARATOR: u8 = b'-';

/// A complete generator request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenSpec {
    /// Characters, words, or digits.
    pub length: u16,
    /// What to generate.
    pub mode: GenMode,
    /// Character sets for [`GenMode::Chars`].
    pub sets: CharSets,
}

impl Default for GenSpec {
    fn default() -> Self {
        Self::for_mode(GenMode::Chars)
    }
}

impl GenSpec {
    /// Defaults for `mode`.
    #[must_use]
    pub fn for_mode(mode: GenMode) -> Self {
        Self {
            length: mode.default_length(),
            mode,
            sets: CharSets::default(),
        }
    }

    /// Change the length by `delta`, clamped to the mode's range.
    pub fn nudge(&mut self, delta: i32) {
        let range = self.mode.lengths();
        let next = i32::from(self.length).saturating_add(delta);
        let clamped = next.clamp(i32::from(*range.start()), i32::from(*range.end()));
        self.length = u16::try_from(clamped).unwrap_or_else(|_| *range.start());
    }

    /// Switch mode and reset the length to its default.
    pub fn next_mode(&mut self) {
        *self = Self {
            sets: self.sets,
            ..Self::for_mode(self.mode.next())
        };
    }

    /// Exact entropy of one draw in bits: `length × log2(alphabet)`.
    #[must_use]
    pub fn entropy_bits(&self) -> f64 {
        let per_symbol = match self.mode {
            GenMode::Chars => {
                let size = u32::try_from(alphabet(self.sets).len()).unwrap_or(0);
                f64::from(size).log2()
            }
            GenMode::Passphrase => f64::from(u32::try_from(seed::EN.len()).unwrap_or(0)).log2(),
            GenMode::Pin => f64::from(10u32).log2(),
        };
        f64::from(self.length) * per_symbol
    }
}

/// The symbols [`GenMode::Chars`] draws from.
#[must_use]
pub fn alphabet(sets: CharSets) -> Vec<u8> {
    let classes = [
        (CharSets::LOWER, LOWER),
        (CharSets::UPPER, UPPER),
        (CharSets::DIGITS, DIGITS),
        (CharSets::SYMBOLS, SYMBOLS),
    ];
    classes
        .iter()
        .filter(|(bit, _)| sets.has(*bit))
        .flat_map(|(_, chars)| chars.iter().copied())
        .filter(|ch| !sets.has(CharSets::NO_LOOKALIKE) || !LOOKALIKE.contains(ch))
        .collect()
}

/// Generate one value for `spec`.
///
/// # Errors
///
/// [`EntropyError`] when the OS RNG fails.
pub fn generate(spec: &GenSpec) -> Result<Zeroizing<Vec<u8>>, EntropyError> {
    let mut rng = OsDraw::default();
    match spec.mode {
        GenMode::Chars => pick_symbols(&alphabet(spec.sets), spec.length, &mut rng),
        GenMode::Pin => pick_symbols(DIGITS, spec.length, &mut rng),
        GenMode::Passphrase => {
            let count = usize::from(spec.length);
            let longest = seed::EN.iter().map(|word| word.len()).max().unwrap_or(0);
            let mut out = Zeroizing::new(Vec::with_capacity(count * (longest + 1)));
            for index in 0..count {
                if index > 0 {
                    out.push(WORD_SEPARATOR);
                }
                let word = seed::EN
                    .get(rng.below(seed::EN.len())?)
                    .ok_or(EntropyError)?;
                out.extend_from_slice(word.as_bytes());
            }
            Ok(out)
        }
    }
}

fn pick_symbols(
    alphabet: &[u8],
    length: u16,
    rng: &mut OsDraw,
) -> Result<Zeroizing<Vec<u8>>, EntropyError> {
    let mut out = Zeroizing::new(Vec::with_capacity(usize::from(length)));
    for _ in 0..length {
        let symbol = alphabet
            .get(rng.below(alphabet.len())?)
            .copied()
            .ok_or(EntropyError)?;
        out.push(symbol);
    }
    Ok(out)
}

/// A uniform index in `0..bound` from the OS CSPRNG.
///
/// # Errors
///
/// [`EntropyError`] when the OS RNG fails or `bound` is zero.
pub fn random_below(bound: usize) -> Result<usize, EntropyError> {
    OsDraw::default().below(bound)
}

/// Buffered OS randomness, wiped on drop.
struct OsDraw {
    pool: [u8; 64],
    used: usize,
}

impl Default for OsDraw {
    fn default() -> Self {
        Self {
            pool: [0u8; 64],
            used: 0,
        }
    }
}

impl Drop for OsDraw {
    fn drop(&mut self) {
        self.pool.zeroize();
    }
}

impl OsDraw {
    /// Rejection sampling rejects less than half of all draws, so 64 draws
    /// all rejected has probability below 2^-64: treat it as a broken RNG.
    const MAX_DRAWS: usize = 64;

    fn next_u32(&mut self) -> Result<u32, EntropyError> {
        if self.used == 0 || self.used + 4 > self.pool.len() {
            getrandom::fill(&mut self.pool).map_err(|_| EntropyError)?;
            self.used = 0;
        }
        let bytes: [u8; 4] = self
            .pool
            .get(self.used..self.used + 4)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(EntropyError)?;
        if let Some(slot) = self.pool.get_mut(self.used..self.used + 4) {
            slot.zeroize();
        }
        self.used += 4;
        Ok(u32::from_le_bytes(bytes))
    }

    fn below(&mut self, bound: usize) -> Result<usize, EntropyError> {
        let bound = u64::try_from(bound)
            .ok()
            .filter(|bound| (1..=1 << 32).contains(bound))
            .ok_or(EntropyError)?;
        let space = 1u64 << 32;
        let zone = space - space % bound;
        for _ in 0..Self::MAX_DRAWS {
            let draw = u64::from(self.next_u32()?);
            if draw < zone {
                return usize::try_from(draw % bound).map_err(|_| EntropyError);
            }
        }
        Err(EntropyError)
    }
}

/// Human scale for "how long would guessing take", at 10^12 guesses per
/// second and half the key space on average.
#[must_use]
pub fn crack_time_label(bits: f64) -> &'static str {
    const MINUTE: f64 = 60.0;
    const DAY: f64 = 86_400.0;
    const YEAR: f64 = 31_557_600.0;
    let seconds = (bits - 1.0).exp2() / 1e12;
    match seconds {
        s if s < 1.0 => "instant",
        s if s < MINUTE * 60.0 => "minutes",
        s if s < DAY * 30.0 => "days",
        s if s < YEAR * 100.0 => "years",
        s if s < YEAR * 1e6 => "millennia",
        s if s < YEAR * 13.8e9 => "millions of years",
        _ => "heat death",
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "tests may unwrap and index"
    )]

    use super::{alphabet, generate, random_below, CharSets, GenMode, GenSpec};

    #[test]
    fn chars_respect_length_and_alphabet() {
        let spec = GenSpec::default();
        let value = generate(&spec).unwrap();
        assert_eq!(value.len(), 24);
        let allowed = alphabet(spec.sets);
        assert!(value.iter().all(|byte| allowed.contains(byte)));
    }

    #[test]
    fn lookalikes_are_dropped_and_last_class_stays() {
        let sets = CharSets::default().toggle(CharSets::NO_LOOKALIKE);
        let allowed = alphabet(sets);
        assert!(!allowed.contains(&b'0') && !allowed.contains(&b'l') && !allowed.contains(&b'|'));
        let only_digits = CharSets::default()
            .toggle(CharSets::LOWER)
            .toggle(CharSets::UPPER)
            .toggle(CharSets::SYMBOLS);
        assert_eq!(only_digits.toggle(CharSets::DIGITS), only_digits);
    }

    #[test]
    fn passphrase_uses_bip39_words() {
        let spec = GenSpec::for_mode(GenMode::Passphrase);
        let value = generate(&spec).unwrap();
        let text = std::str::from_utf8(&value).unwrap();
        let words: Vec<&str> = text.split('-').collect();
        assert_eq!(words.len(), 6);
        assert!(words.iter().all(|word| seed::EN.contains(word)));
        assert!((spec.entropy_bits() - 66.0).abs() < 1e-9);
    }

    #[test]
    fn index_draws_are_not_visibly_biased() {
        // Chi-square smoke test over 10 buckets, 20k draws; 9 degrees of
        // freedom, p = 0.0001 critical value ≈ 33.7.
        let mut counts = [0u32; 10];
        for _ in 0..20_000 {
            counts[random_below(10).unwrap()] += 1;
        }
        let expected = 2_000.0;
        let chi: f64 = counts
            .iter()
            .map(|count| (f64::from(*count) - expected).powi(2) / expected)
            .sum();
        assert!(chi < 33.7, "chi-square {chi}");
    }

    #[test]
    fn nudge_clamps_to_the_mode_range() {
        let mut spec = GenSpec::for_mode(GenMode::Pin);
        spec.nudge(100);
        assert_eq!(spec.length, 12);
        spec.nudge(-100);
        assert_eq!(spec.length, 4);
    }
}
