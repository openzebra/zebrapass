//! Clipboard through the OSC 52 terminal escape.
//!
//! `ESC ] 52 ; c ; <base64> BEL` asks the terminal to set its clipboard. It
//! needs no native library and works over SSH. Every copy arms a timer; on
//! timeout, lock, or quit an empty payload clears the clipboard again. The
//! escape bytes are queued in an outbox the run loop writes to the terminal,
//! so the app state stays testable. All buffers are zeroizing.

use std::io::Write;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

const OSC52_PREFIX: &[u8] = b"\x1b]52;c;";
const OSC52_SUFFIX: &[u8] = b"\x07";
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Why a copy did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyError {
    /// This terminal most likely ignores OSC 52 (or the feature is off).
    Unavailable,
    /// More than terminals accept in one escape sequence.
    TooLarge,
}

/// Most bytes one copy carries; terminals drop or cut longer sequences.
const MAX_PAYLOAD: usize = 75_000;

/// Clipboard state and the escape sequences waiting to be written.
pub struct Clipboard {
    supported: bool,
    clear_after: Duration,
    armed: Option<(Instant, &'static str, Duration)>,
    outbox: Vec<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for Clipboard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The outbox holds copied secrets: never print it.
        f.debug_struct("Clipboard")
            .field("supported", &self.supported)
            .field("armed", &self.armed.is_some())
            .field("clear_after", &self.clear_after)
            .field("queued", &self.outbox.len())
            .finish_non_exhaustive()
    }
}

impl Clipboard {
    /// A clipboard that clears `clear_after` a copy.
    #[must_use]
    pub const fn new(supported: bool, clear_after: Duration) -> Self {
        Self {
            supported: supported && cfg!(feature = "osc52"),
            clear_after,
            armed: None,
            outbox: Vec::new(),
        }
    }

    /// Whether copying can work in this terminal.
    #[must_use]
    pub const fn supported(&self) -> bool {
        self.supported
    }

    /// Change the clear delay for future copies.
    pub const fn set_clear_after(&mut self, clear_after: Duration) {
        self.clear_after = clear_after;
    }

    /// The clear delay.
    #[must_use]
    pub const fn clear_after(&self) -> Duration {
        self.clear_after
    }

    /// Queue `secret` for the clipboard and arm the clear timer.
    ///
    /// # Errors
    ///
    /// [`CopyError::Unavailable`] when OSC 52 is not supported here.
    pub fn copy(
        &mut self,
        secret: &[u8],
        label: &'static str,
        now: Instant,
    ) -> Result<(), CopyError> {
        self.copy_for(secret, label, now, self.clear_after)
    }

    /// As [`Clipboard::copy`], clearing after `clear_after` instead of the
    /// usual delay.
    ///
    /// # Errors
    ///
    /// As [`Clipboard::copy`].
    pub fn copy_for(
        &mut self,
        secret: &[u8],
        label: &'static str,
        now: Instant,
        clear_after: Duration,
    ) -> Result<(), CopyError> {
        if !self.supported {
            return Err(CopyError::Unavailable);
        }
        if secret.len() > MAX_PAYLOAD {
            return Err(CopyError::TooLarge);
        }
        self.outbox.push(osc52(secret));
        self.armed = Some((now, label, clear_after));
        Ok(())
    }

    /// Clear the clipboard now if a copy is still armed. Returns `true` when
    /// a clear was queued.
    pub fn clear_if_armed(&mut self) -> bool {
        if self.armed.take().is_some() {
            self.outbox.push(osc52(&[]));
            true
        } else {
            false
        }
    }

    /// Clear on timeout. Returns `true` when a clear was queued.
    pub fn tick(&mut self, now: Instant) -> bool {
        match self.armed {
            Some((since, _, clear_after))
                if now.saturating_duration_since(since) >= clear_after =>
            {
                self.clear_if_armed()
            }
            _ => false,
        }
    }

    /// Label of the armed copy, the time left before it clears and the delay
    /// it was armed with.
    #[must_use]
    pub fn countdown(&self, now: Instant) -> Option<(&'static str, Duration, Duration)> {
        self.armed.map(|(since, label, clear_after)| {
            (
                label,
                clear_after.saturating_sub(now.saturating_duration_since(since)),
                clear_after,
            )
        })
    }

    /// Escape sequences to write, oldest first.
    pub fn take_outbox(&mut self) -> Vec<Zeroizing<Vec<u8>>> {
        std::mem::take(&mut self.outbox)
    }

    /// Queued sequences without draining them (tests).
    #[must_use]
    pub fn outbox(&self) -> &[Zeroizing<Vec<u8>>] {
        &self.outbox
    }
}

/// The OSC 52 sequence that sets the clipboard to `payload` (empty clears).
#[must_use]
pub fn osc52(payload: &[u8]) -> Zeroizing<Vec<u8>> {
    let encoded = payload.len().div_ceil(3) * 4;
    let mut out = Zeroizing::new(Vec::with_capacity(
        OSC52_PREFIX.len() + encoded + OSC52_SUFFIX.len(),
    ));
    out.extend_from_slice(OSC52_PREFIX);
    base64_into(payload, &mut out);
    out.extend_from_slice(OSC52_SUFFIX);
    out
}

/// Standard padded base64. Not cryptography: a transport encoding for the
/// terminal escape, written here so the secret never passes through a
/// dependency's own buffers.
fn base64_into(input: &[u8], out: &mut Vec<u8>) {
    for chunk in input.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let triple = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let symbols = [18u32, 12, 6, 0].map(|shift| {
            let index = usize::try_from((triple >> shift) & 0x3F).unwrap_or(0);
            BASE64.get(index).copied().unwrap_or(b'=')
        });
        let keep = chunk.len() + 1;
        for (position, symbol) in symbols.into_iter().enumerate() {
            out.push(if position < keep { symbol } else { b'=' });
        }
    }
}

/// Best guess whether the terminal honors OSC 52, from `TERM` and
/// `TERM_PROGRAM`. Apple Terminal and the Linux console ignore it.
#[must_use]
pub fn osc52_likely(term: Option<&str>, term_program: Option<&str>) -> bool {
    if matches!(term_program, Some("Apple_Terminal")) {
        return false;
    }
    match term {
        None | Some("" | "dumb" | "linux") => false,
        Some(_) => true,
    }
}

/// Decode standard padded base64 into a zeroizing buffer.
#[must_use]
pub fn base64_decode(input: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if input.is_empty() {
        return Some(Zeroizing::new(Vec::new()));
    }
    if input.len() % 4 != 0 {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity((input.len() / 4) * 3));
    for chunk in input.chunks_exact(4) {
        let c0 = decode_b64_digit(chunk.first().copied()?)?;
        let c1 = decode_b64_digit(chunk.get(1).copied()?)?;
        let byte2 = chunk.get(2).copied()?;
        let byte3 = chunk.get(3).copied()?;

        let pad2 = byte2 == b'=';
        let pad3 = byte3 == b'=';

        if pad2 && !pad3 {
            return None;
        }

        let c2 = if pad2 { 0 } else { decode_b64_digit(byte2)? };
        let c3 = if pad3 { 0 } else { decode_b64_digit(byte3)? };

        let triple =
            (u32::from(c0) << 18) | (u32::from(c1) << 12) | (u32::from(c2) << 6) | u32::from(c3);

        let b0 = u8::try_from((triple >> 16) & 0xFF).ok()?;
        out.push(b0);

        if !pad2 {
            let b1 = u8::try_from((triple >> 8) & 0xFF).ok()?;
            out.push(b1);
        }
        if !pad3 {
            let b2 = u8::try_from(triple & 0xFF).ok()?;
            out.push(b2);
        }
    }
    Some(out)
}

const fn decode_b64_digit(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Extract and decode the raw payload from an OSC 52 sequence.
/// Returns `Some(empty)` for a clear sequence (`\x1b]52;c;\x07` or `\x1b]52;c;\x1b\\`).
#[must_use]
pub fn extract_osc52_payload(sequence: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let body = sequence.strip_prefix(OSC52_PREFIX)?;
    let raw = body
        .strip_suffix(OSC52_SUFFIX)
        .or_else(|| body.strip_suffix(b"\x1b\\"))?;
    if raw.is_empty() {
        return Some(Zeroizing::new(Vec::new()));
    }
    base64_decode(raw)
}

/// Synchronize a flushed OSC 52 sequence with native desktop clipboards
/// (Wayland / X11) when available.
pub fn sync_system_clipboard(sequence: &[u8]) {
    let Some(payload) = extract_osc52_payload(sequence) else {
        return;
    };
    if payload.is_empty() {
        clear_system_clipboard();
    } else {
        copy_system_clipboard(&payload);
    }
}

#[cfg(unix)]
fn copy_system_clipboard(secret: &[u8]) {
    if std::env::var_os("WAYLAND_DISPLAY").is_some() && copy_wayland(secret).is_ok() {
        return;
    }
    if std::env::var_os("DISPLAY").is_some() {
        let _ = copy_x11(secret);
    }
}

#[cfg(not(unix))]
fn copy_system_clipboard(_secret: &[u8]) {}

#[cfg(unix)]
fn clear_system_clipboard() {
    if std::env::var_os("WAYLAND_DISPLAY").is_some() && clear_wayland().is_ok() {
        return;
    }
    if std::env::var_os("DISPLAY").is_some() {
        let _ = clear_x11();
    }
}

#[cfg(not(unix))]
fn clear_system_clipboard() {}

#[cfg(unix)]
fn copy_wayland(secret: &[u8]) -> std::io::Result<()> {
    let mut child = std::process::Command::new("wl-copy")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(secret)?;
    }
    let _ = child.wait()?;
    Ok(())
}

#[cfg(unix)]
fn clear_wayland() -> std::io::Result<()> {
    let mut child = std::process::Command::new("wl-copy")
        .arg("--clear")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let _ = child.wait()?;
    Ok(())
}

#[cfg(unix)]
fn copy_x11(secret: &[u8]) -> std::io::Result<()> {
    let mut child = std::process::Command::new("xclip")
        .args(["-selection", "clipboard"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(secret)?;
    }
    let _ = child.wait()?;
    Ok(())
}

#[cfg(unix)]
fn clear_x11() -> std::io::Result<()> {
    let mut child = std::process::Command::new("xclip")
        .args(["-selection", "clipboard"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    drop(child.stdin.take());
    let _ = child.wait()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::unwrap_used,
        reason = "tests may index and unwrap"
    )]

    use std::time::{Duration, Instant};

    use super::{base64_decode, extract_osc52_payload, osc52, osc52_likely, Clipboard};

    #[test]
    fn base64_matches_rfc4648_vectors() {
        let cases: [(&[u8], &[u8]); 7] = [
            (b"", b""),
            (b"f", b"Zg=="),
            (b"fo", b"Zm8="),
            (b"foo", b"Zm9v"),
            (b"foob", b"Zm9vYg=="),
            (b"fooba", b"Zm9vYmE="),
            (b"foobar", b"Zm9vYmFy"),
        ];
        for (input, expected) in cases {
            let sequence = osc52(input);
            let body = &sequence[7..sequence.len() - 1];
            assert_eq!(body, expected);
        }
    }

    #[test]
    fn copy_arms_and_timeout_clears() {
        let start = Instant::now();
        let mut clip = Clipboard::new(true, Duration::from_secs(20));
        clip.copy(b"secret", "password", start).unwrap_or(());
        assert!(!clip.tick(start + Duration::from_secs(5)));
        assert!(clip.tick(start + Duration::from_secs(20)));
        let out = clip.take_outbox();
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].as_slice(), b"\x1b]52;c;\x07");
        assert!(!clip.clear_if_armed());
    }

    #[test]
    fn a_copy_can_clear_sooner_or_later_than_the_usual_delay() {
        let start = Instant::now();
        let mut clip = Clipboard::new(true, Duration::from_secs(20));
        clip.copy_for(b"phrase", "phrase", start, Duration::from_secs(25))
            .unwrap_or(());
        assert!(!clip.tick(start + Duration::from_secs(24)));
        let (_, left, total) = clip.countdown(start + Duration::from_secs(5)).unwrap();
        assert_eq!(
            (left, total),
            (Duration::from_secs(20), Duration::from_secs(25))
        );
        assert!(clip.tick(start + Duration::from_secs(25)));
        assert_eq!(
            clip.take_outbox().pop().unwrap().as_slice(),
            b"\x1b]52;c;\x07"
        );
    }

    #[test]
    fn detection_rejects_known_non_supporters() {
        assert!(!osc52_likely(
            Some("xterm-256color"),
            Some("Apple_Terminal")
        ));
        assert!(!osc52_likely(Some("linux"), None));
        assert!(osc52_likely(Some("xterm-kitty"), None));
    }

    #[test]
    fn base64_decode_roundtrips_vectors() {
        let cases: [&[u8]; 7] = [b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"];
        for input in cases {
            let encoded = osc52(input);
            let body = &encoded[7..encoded.len() - 1];
            let decoded = base64_decode(body).expect("valid base64");
            assert_eq!(decoded.as_slice(), input);
        }
    }

    #[test]
    fn extract_osc52_payload_decodes_and_identifies_clear() {
        let seq = osc52(b"my-password");
        let decoded = extract_osc52_payload(&seq).expect("valid sequence");
        assert_eq!(decoded.as_slice(), b"my-password");

        let clear_bel = osc52(&[]);
        let cleared = extract_osc52_payload(&clear_bel).expect("valid clear");
        assert!(cleared.is_empty());

        let clear_st = b"\x1b]52;c;\x1b\\";
        let cleared_st = extract_osc52_payload(clear_st).expect("valid ST clear");
        assert!(cleared_st.is_empty());

        assert!(extract_osc52_payload(b"invalid").is_none());
        assert!(extract_osc52_payload(b"\x1b]52;c;invalid!\x07").is_none());
    }
}
