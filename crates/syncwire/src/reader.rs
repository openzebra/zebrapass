//! Bounds-checked cursor over untrusted bytes. Every read is length-checked;
//! callers bound each declared length before it is used.

use anyhow::{anyhow, Result};

/// A cursor that only moves forward and never reads past the end.
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Start reading `bytes`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// The next `len` bytes.
    ///
    /// # Errors
    ///
    /// `truncated sync wire` when fewer than `len` bytes remain.
    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let (head, tail) = self
            .rest
            .split_at_checked(len)
            .ok_or_else(|| anyhow!("truncated sync wire"))?;
        self.rest = tail;
        Ok(head)
    }

    /// The next `N` bytes as an array.
    ///
    /// # Errors
    ///
    /// `truncated sync wire` when fewer than `N` bytes remain.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_| anyhow!("truncated sync wire"))
    }

    /// A big-endian `u16`.
    ///
    /// # Errors
    ///
    /// `truncated sync wire` when fewer than 2 bytes remain.
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    /// A big-endian `u32`.
    ///
    /// # Errors
    ///
    /// `truncated sync wire` when fewer than 4 bytes remain.
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// A big-endian `u64`.
    ///
    /// # Errors
    ///
    /// `truncated sync wire` when fewer than 8 bytes remain.
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    /// A `u16` length then that many bytes, at most `max`.
    ///
    /// # Errors
    ///
    /// `sync wire length over limit` when the length exceeds `max`;
    /// `truncated sync wire` when the bytes are missing.
    pub fn bytes_u16(&mut self, max: usize) -> Result<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.bounded(len, max)
    }

    /// A `u32` length then that many bytes, at most `max`.
    ///
    /// # Errors
    ///
    /// `sync wire length over limit` when the length exceeds `max`;
    /// `truncated sync wire` when the bytes are missing.
    pub fn bytes_u32(&mut self, max: usize) -> Result<&'a [u8]> {
        let len = usize::try_from(self.u32()?).map_err(|_| anyhow!("sync wire length"))?;
        self.bounded(len, max)
    }

    /// Require that every byte was consumed.
    ///
    /// # Errors
    ///
    /// `trailing bytes in sync wire` when bytes remain.
    pub fn finish(self) -> Result<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(anyhow!("trailing bytes in sync wire"))
        }
    }

    fn bounded(&mut self, len: usize, max: usize) -> Result<&'a [u8]> {
        if len > max {
            return Err(anyhow!("sync wire length over limit"));
        }
        self.take(len)
    }
}
