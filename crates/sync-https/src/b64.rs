//! Bounded RFC 4648 base64 encoding for WebSocket handshakes and HTTP Proxy
//! authentication headers.

const STD_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `input` as standard RFC 4648 base64 with `=` padding.
#[must_use]
pub fn encode_standard(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    let out_len = input.len().div_ceil(3).saturating_mul(4);
    let mut out = Vec::with_capacity(out_len);
    for chunk in input.chunks(3) {
        let b0 = usize::from(*chunk.first().unwrap_or(&0));
        let b1 = usize::from(*chunk.get(1).unwrap_or(&0));
        let b2 = usize::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        if let Some(&c) = STD_ALPHABET.get((n >> 18) & 0x3F) {
            out.push(c);
        }
        if let Some(&c) = STD_ALPHABET.get((n >> 12) & 0x3F) {
            out.push(c);
        }
        if chunk.len() > 1 {
            if let Some(&c) = STD_ALPHABET.get((n >> 6) & 0x3F) {
                out.push(c);
            }
        } else {
            out.push(b'=');
        }
        if chunk.len() > 2 {
            if let Some(&c) = STD_ALPHABET.get(n & 0x3F) {
                out.push(c);
            }
        } else {
            out.push(b'=');
        }
    }
    String::from_utf8(out).unwrap_or_default()
}
