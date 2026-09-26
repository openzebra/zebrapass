//! Fuzz target: arbitrary wrap-directory bytes must not panic inside
//! `parse_entry` (all kinds, wrong lengths, unknown kinds, KDF floors).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // One entry per fuzz input; trailing bytes are ignored by the parser.
    let _ = container::parse_entry(data, 0);
});
