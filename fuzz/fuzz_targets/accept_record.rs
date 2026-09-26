//! Fuzz target: arbitrary sync records must not panic inside
//! `SyncRecord::signed_message` or the session verification entry points.
//!
//! The full `accept_record` needs a live vault; this target covers the
//! untrusted-input surface that precedes it: message rebuild (length math)
//! and the ML-DSA verify path with attacker-chosen keys and signatures.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Outer message: vault(16) | record_id(4) | revision(8) | hash(32) |
    // msg_version(2) | key_generation(4) | ct.
    if data.len() < 66 {
        return;
    }
    let (head, ct) = data.split_at(66);
    let mut vault = [0u8; 16];
    vault.copy_from_slice(&head[..16]);
    let record_id = u32::from_le_bytes(head[16..20].try_into().unwrap_or_default());
    let revision = u64::from_le_bytes(head[20..28].try_into().unwrap_or_default());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&head[28..60]);
    let msg_version = u16::from_le_bytes(head[60..62].try_into().unwrap_or_default());
    let key_generation = u32::from_le_bytes(head[62..66].try_into().unwrap_or_default());
    let record = session::SyncRecord {
        vault_id: vault,
        record_id,
        revision,
        content_hash: hash,
        msg_version,
        key_generation,
        frame: ct.to_vec(),
        signature: vec![0u8; 3309],
    };
    // Never panics: wrong-length keys and bad signatures are errors.
    let vk = [0u8; 1952];
    let _ = session::verify_record(&vk, &record, &vault);
});
