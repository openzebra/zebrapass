//! BIP39 seed phrase validation and seed derivation.

use std::borrow::Cow;

use pqbip39::mnemonic::Mnemonic;
use secrecy::{ExposeSecret, SecretBox, SecretString};

use crate::en_words::EN;
use crate::rng::OsFill;

/// A validated BIP39 seed phrase and the 64-byte BIP39 seed it derives.
///
/// The phrase is stored normalized; the seed is derived once at
/// construction with the given passphrase and kept for the lifetime of
/// the value. Both are wiped on drop.
///
/// `Debug` never prints phrase or seed material.
#[derive(Debug)]
pub struct SeedPhrase {
    phrase: SecretString,
    seed: SecretBox<[u8; 64]>,
}

impl SeedPhrase {
    /// Generate a fresh 24-word phrase with an empty passphrase.
    ///
    /// # Errors
    ///
    /// `os entropy failed` when the OS RNG fails.
    pub fn generate_24() -> anyhow::Result<Self> {
        let mnemonic = Mnemonic::generate(&mut OsFill, &EN, 24)
            .map_err(|_| anyhow::anyhow!("os entropy failed"))?;
        let passphrase = SecretString::new(String::new().into_boxed_str());
        Self::from_mnemonic(&mnemonic, &passphrase)
    }

    /// Parse a phrase: 12 to 24 words from the wordlist with a valid
    /// checksum, normalized, then derive its seed with `passphrase`.
    ///
    /// Restore stays permissive so vaults created before the 24-word
    /// policy remain recoverable; every new vault comes from
    /// [`SeedPhrase::generate_24`] (256-bit entropy).
    ///
    /// # Errors
    ///
    /// `invalid seed phrase` for a wrong word count, a word outside the
    /// wordlist, or a checksum mismatch; `seed derivation failed` when the
    /// PBKDF2 seed cannot be built (practically unreachable for a valid
    /// phrase).
    pub fn parse(phrase: &SecretString, passphrase: &SecretString) -> anyhow::Result<Self> {
        // The parser expects the canonical spelling: normalize case,
        // Unicode form, and whitespace first.
        let mut normalized = Cow::Borrowed(phrase.expose_secret());
        Mnemonic::normalize_utf8_cow(&mut normalized);
        let normalized = SecretString::new(normalized.into_owned().into_boxed_str());
        let mnemonic =
            Mnemonic::parse_str(&EN, &normalized).map_err(|_| anyhow::anyhow!("invalid seed phrase"))?;
        Self::from_mnemonic(&mnemonic, passphrase)
    }

    fn from_mnemonic(mnemonic: &Mnemonic, passphrase: &SecretString) -> anyhow::Result<Self> {
        let phrase = mnemonic.to_phrase();
        let seed = mnemonic
            .to_seed(passphrase)
            .map_err(|_| anyhow::anyhow!("seed derivation failed"))?;
        Ok(Self { phrase, seed })
    }

    /// The 64-byte BIP39 seed (PBKDF2-HMAC-SHA512, 2048 rounds).
    #[must_use]
    pub fn seed(&self) -> &[u8; 64] {
        self.seed.expose_secret()
    }

    /// The normalized phrase: NFKD, lowercase, single-spaced.
    #[must_use]
    pub fn phrase_normalized(&self) -> &str {
        self.phrase.expose_secret()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests may unwrap")]

    use secrecy::{ExposeSecret, SecretString};

    use super::SeedPhrase;

    const ABANDON_12: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    const ABANDON_24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn secret(text: &str) -> SecretString {
        SecretString::new(text.to_owned().into_boxed_str())
    }

    #[test]
    fn bip39_vector_abandon_about_with_trezor() {
        // BIP39 test vector: all-zero 128-bit entropy, passphrase "TREZOR".
        let phrase = SeedPhrase::parse(&secret(ABANDON_12), &secret("TREZOR")).unwrap();
        let expected = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
                        1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
            .replace(['\n', ' '], "");
        assert_eq!(hex::encode(phrase.seed()), expected);
        // An empty passphrase derives a different seed for the same phrase.
        let plain = SeedPhrase::parse(&secret(ABANDON_12), &secret("")).unwrap();
        assert_ne!(hex::encode(plain.seed()), expected);
    }

    #[test]
    fn zero_entropy_expands_to_twenty_four_words() {
        let mnemonic = pqbip39::mnemonic::Mnemonic::from_entropy(&crate::en_words::EN, &[0u8; 32])
            .unwrap();
        let phrase = mnemonic.to_phrase();
        assert_eq!(phrase.expose_secret(), ABANDON_24);
        // The derived phrase parses back to the same seed.
        let parsed = SeedPhrase::parse(&phrase, &secret("")).unwrap();
        let direct = SeedPhrase::parse(&secret(ABANDON_24), &secret("")).unwrap();
        assert_eq!(parsed.seed(), direct.seed());
    }

    #[test]
    fn parse_normalizes_whitespace_and_unicode() {
        // pqbip39 normalizes NFKD and any whitespace run; it does not fold
        // case (BIP39 words are lowercase, uppercase input is invalid).
        let messy = "  abandon  abandon\tabandon abandon abandon abandon \n\
                     abandon abandon abandon abandon abandon about  ";
        let messy = SeedPhrase::parse(&secret(messy), &secret("")).unwrap();
        let canonical = SeedPhrase::parse(&secret(ABANDON_12), &secret("")).unwrap();
        assert_eq!(messy.seed(), canonical.seed());
        assert_eq!(messy.phrase_normalized(), ABANDON_12);
        // Uppercase input is not a valid canonical phrase.
        let upper = ABANDON_12.to_uppercase();
        assert!(SeedPhrase::parse(&secret(&upper), &secret("")).is_err());
    }

    #[test]
    fn checksum_and_wordlist_enforced() {
        // Last word replaced: checksum must fail.
        let bad_checksum =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert_eq!(
            SeedPhrase::parse(&secret(bad_checksum), &secret("")).unwrap_err().to_string(),
            "invalid seed phrase"
        );
        // A word outside the wordlist.
        let not_a_word =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zebraa";
        assert_eq!(
            SeedPhrase::parse(&secret(not_a_word), &secret("")).unwrap_err().to_string(),
            "invalid seed phrase"
        );
        // Too few words (11).
        let too_few =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(
            SeedPhrase::parse(&secret(too_few), &secret("")).unwrap_err().to_string(),
            "invalid seed phrase"
        );
    }

    #[test]
    fn generated_phrases_are_twenty_four_fresh_words() {
        let a = SeedPhrase::generate_24().unwrap();
        let b = SeedPhrase::generate_24().unwrap();
        for phrase in [&a, &b] {
            let words: Vec<&str> = phrase.phrase_normalized().split(' ').collect();
            assert_eq!(words.len(), 24);
            assert!(words.iter().all(|word| crate::en_words::EN.contains(word)));
        }
        assert_ne!(a.seed(), b.seed());
    }
}
