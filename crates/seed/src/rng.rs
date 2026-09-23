//! OS-backed randomness for `pqbip39`.

use pqbip39::rng::Rng;

/// Fills buffers from the OS RNG.
#[derive(Debug, Default)]
pub struct OsFill;

impl Rng for OsFill {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // `Rng` is infallible, so the OS RNG is retried until it succeeds.
        // A persistently failing OS RNG is a broken system: hanging is
        // safer than sealing a vault under predictable entropy.
        while getrandom::fill(dest).is_err() {}
    }
}
