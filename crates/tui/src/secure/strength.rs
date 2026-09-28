//! Local password-strength estimate. Not cryptography and not a guarantee:
//! a character-class entropy estimate with penalties for repeats and
//! sequences, computed in place over the secret bytes.

/// Coarse strength class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StrengthLabel {
    /// Below 28 bits.
    VeryWeak,
    /// Below 50 bits.
    Weak,
    /// Below 60 bits.
    Fair,
    /// Below 80 bits.
    Good,
    /// Below 100 bits.
    Strong,
    /// 100 bits and up.
    Excellent,
}

impl StrengthLabel {
    /// Display word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::VeryWeak => "very weak",
            Self::Weak => "weak",
            Self::Fair => "fair",
            Self::Good => "good",
            Self::Strong => "strong",
            Self::Excellent => "excellent",
        }
    }
}

/// Entropy estimate below which the health view flags a password as weak.
pub const WEAK_BITS: u16 = 50;

/// An estimate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Strength {
    /// Estimated bits.
    pub bits: u16,
    /// Class of `bits`.
    pub label: StrengthLabel,
}

impl From<u16> for StrengthLabel {
    fn from(bits: u16) -> Self {
        match bits {
            0..28 => Self::VeryWeak,
            28..WEAK_BITS => Self::Weak,
            WEAK_BITS..60 => Self::Fair,
            60..80 => Self::Good,
            80..100 => Self::Strong,
            _ => Self::Excellent,
        }
    }
}

/// Estimate the strength of `secret`.
#[must_use]
pub fn estimate(secret: &[u8]) -> Strength {
    let pool = pool_size(secret);
    let per_char = f64::from(pool).log2();
    let mut previous: Option<u32> = None;
    let bits: f64 = decode(secret)
        .map(|code| {
            let cost = match previous {
                Some(prev) if prev == code || prev.abs_diff(code) == 1 => 1.0,
                _ => per_char,
            };
            previous = Some(code);
            cost
        })
        .sum();
    let rounded = bits.round().clamp(0.0, f64::from(u16::MAX));
    // Clamped into `0..=u16::MAX` above, so the conversion cannot truncate.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let bits = rounded as u16;
    Strength {
        bits,
        label: StrengthLabel::from(bits),
    }
}

/// Characters as code points, without allocating. Invalid UTF-8 bytes
/// count as themselves.
fn decode(secret: &[u8]) -> impl Iterator<Item = u32> + '_ {
    secret.utf8_chunks().flat_map(|chunk| {
        chunk
            .valid()
            .chars()
            .map(u32::from)
            .chain(chunk.invalid().iter().map(|byte| u32::from(*byte)))
    })
}

fn pool_size(secret: &[u8]) -> u32 {
    let mut lower = false;
    let mut upper = false;
    let mut digit = false;
    let mut symbol = false;
    let mut other = false;
    for code in decode(secret) {
        match char::from_u32(code) {
            Some('a'..='z') => lower = true,
            Some('A'..='Z') => upper = true,
            Some('0'..='9') => digit = true,
            Some(ch) if ch.is_ascii_punctuation() || ch == ' ' => symbol = true,
            _ => other = true,
        }
    }
    [
        (lower, 26),
        (upper, 26),
        (digit, 10),
        (symbol, 33),
        (other, 100),
    ]
    .iter()
    .filter(|(present, _)| *present)
    .map(|(_, size)| size)
    .sum::<u32>()
    .max(1)
}

#[cfg(test)]
mod tests {
    use super::{estimate, StrengthLabel};

    #[test]
    fn repeats_and_sequences_are_cheap() {
        assert!(estimate(b"aaaaaaaaaaaa").bits < 20);
        assert!(estimate(b"abcdefghijkl").bits < 20);
        assert_eq!(estimate(b"").label, StrengthLabel::VeryWeak);
    }

    #[test]
    fn mixed_long_passwords_score_high() {
        let strong = estimate(b"k7#Qm2^vR9!pLx@4wZ$e8Nb&");
        assert!(strong.bits > 100, "{}", strong.bits);
        assert_eq!(strong.label, StrengthLabel::Excellent);
    }
}
