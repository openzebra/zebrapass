//! Fuzz target: arbitrary frame logs must not panic inside the index
//! decoder (`spans`/`decode_frames`).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = frame::decode_frames(data);
    let _ = frame::spans(data);
});
