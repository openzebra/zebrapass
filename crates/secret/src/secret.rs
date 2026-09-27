use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Owned secret that is wiped on drop.
///
/// [`Debug`] prints `[REDACTED]` and never the wrapped bytes.
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    /// Wraps `value`. Dropping the result wipes this copy.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Borrows the secret bytes.
    #[must_use]
    pub const fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> ZeroizeOnDrop for Secret<T> {}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use zeroize::Zeroize;

    use super::Secret;

    struct TrackedBytes {
        bytes: Rc<Cell<[u8; 4]>>,
    }

    impl Zeroize for TrackedBytes {
        fn zeroize(&mut self) {
            self.bytes.set([0; 4]);
        }
    }

    #[test]
    fn debug_redacts_and_expose_returns_bytes() {
        let raw = [0x5Au8; 32];
        let secret = Secret::new(raw);
        assert_eq!(secret.expose(), &raw);
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
        assert!(!format!("{secret:?}").contains("90"));
    }

    #[test]
    fn drop_zeroizes_observed_bytes() {
        let bytes = Rc::new(Cell::new([0x11, 0x22, 0x33, 0x44]));
        {
            let _secret = Secret(TrackedBytes {
                bytes: Rc::clone(&bytes),
            });
        }
        assert_eq!(bytes.get(), [0; 4]);
    }
}
