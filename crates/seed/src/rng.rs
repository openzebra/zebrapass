//! OS-backed randomness for `pqbip39`.

use pqbip39::rng::Rng;

/// Fills buffers from the OS RNG.
#[derive(Debug, Default)]
pub struct OsFill;

impl Rng for OsFill {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // `Rng` is infallible, so the OS RNG is retried until it succeeds;
        // the thread yields between attempts so a transient storm does not
        // busy-burn a core. A persistently failing OS RNG is a broken
        // system: hanging is safer than sealing a vault under predictable
        // entropy, and there is no panic-free way to surface the failure
        // through the trait.
        while getrandom::fill(dest).is_err() {
            std::thread::yield_now();
        }
    }
}
