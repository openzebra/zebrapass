//! Fuzz target: arbitrary bytes must not panic inside `VaultFile` parsing.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let file = container::VaultFile::new(data.to_vec());
    let _ = file.parse();
});
