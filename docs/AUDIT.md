# Zebrapass kernel audit

Date: 2026-09-26. Scope: the Rust workspace at this revision (12 crates, production sources only; `en_words.rs` not reviewed line by line). Method: read of the crypto and session paths, `cargo test --workspace`, `cargo clippy --workspace --all-targets`, and a throwaway release probe against `ntrulp 0.2.7` (probe removed; tree left clean).

This is an audit of the kernel against the product brief, not a rewrite. PearPass was not used as a line-by-line spec: `pearpass-app-desktop` does not vendor its vault. The vault lives in `@tetherto/pearpass-lib-vault-core`, which is not checked out here.

## Verdict

The local vault is a coherent envelope-encryption design and the tests pass. It is not yet the kernel described in the brief.

- A crafted device or chip wrap panics the process inside `ntrulp` before any authentication check. Reproduced.
- The post-quantum leg is not a KEM. It is an unaudited textbook NTRU encrypt of 32 bytes. Tampered ciphertexts decrypt without error.
- There is no signature key, so a server cannot verify that a sync write belongs to the vault owner.
- One record edit re-encrypts and rewrites the entire vault body. Per-record sync is not possible on this layout.
- The 64-byte "user id" is a P-256 point derived from a 32-byte scalar. It is not a 512-bit id, and the code itself says it is not an authentication mechanism.
- Hardware-key wrap bytes exist, but session unlock and key rotation refuse them.

What is solid: BIP39 seed handling, Argon2id profiles, HKDF domain separation, AEGIS-256 frame seals, HMAC commit over the whole file, atomic writes, zeroize of the vault key, and the absence of `unwrap` / `dyn` in production code.

## What was executed

- `cargo test --workspace`: 261 passed, 0 failed, 11 suites.
- `cargo clippy --workspace --all-targets`: 3 warnings, all in test modules or a private-module style lint. Production code is clean under `clippy::pedantic` deny, `unwrap_used` deny, `expect_used` deny, `panic` deny, `indexing_slicing` deny, `unsafe_code` deny.
- Largest production files stay under 500 lines. `record/src/doc.rs` is 537 only because tests start at line 360.
- No `Box<dyn>` / `&dyn` in `crates/*/src`.
- `panic = "deny"` in `Cargo.toml` is a lint. It does not stop a dependency from panicking at runtime.

## How the kernel actually works

1. The BIP39 seed (`[u8; 64]`, via `pqbip39 0.2.0`) is the password-wrap secret. `session::create` seals the random 32-byte vault key under Argon2id(seed). Generation starts at 1.
2. Unlock tries master, device, or chip credentials, derives `k_body`, `k_bmac`, `k_commit` with HKDF-SHA512, verifies HMAC-SHA256 over `header || wrap directory || body`, then decrypts the whole body into `session.records`.
3. A record write appends one AEGIS-256 frame, then `write_records` (`session/src/rotate.rs:48`) encrypts the concatenated frame list as one body and rewrites the file. Generation increments. The commit is recomputed.
4. Device wrap: X25519 plus `ntrulp` encrypt. Chip wrap: P-256 ECDH (the platform computes it) plus the same `ntrulp` encrypt. PRF wrap: HKDF of a 32-byte YubiKey HMAC response. Session does not accept a PRF factor.
5. `user_id(seed)` is `P-256(HKDF-SHA512(seed, info = "zebrapass/identity/v1"))` with the `0x04` prefix stripped. Nothing in the workspace signs with that scalar, and nothing outside `kdf` calls `identity_seed`.

That is a local password manager with extra wrap slots. It is not a quantum-safe sync client.

## C1 — `ntrulp` panics on a short ciphertext

Severity: critical. A file the parser accepts crashes the process during unlock or rotation. No secret is required beyond a device or chip wrap the attacker can edit, which any copy of the vault file provides.

`decrypt_shared` forwards the ciphertext with no length check:

```rust
// crates/pq/src/ntrup.rs:59
pub fn decrypt_shared(sk: &[u8], ciphertext: &[u8]) -> anyhow::Result<Secret<[u8; 32]>> {
    let opened = decrypt(sk, ciphertext)?;
    ...
}
```

`ntrulp 0.2.7` then does this in `src/compress/r3.rs`:

```rust
pub fn r3_split_w_chunks(chunks: &[&[u8]]) -> R3 {
    let mut out = [0u8; P];
    for (i, chunk) in chunks.iter().enumerate() {
        out[i * 16..(i + 1) * 16].copy_from_slice(&chunk); // panics if chunk < 16
    }
    ...
}
```

Release probe, this machine, `ntrulp 0.2.7`, ciphertext produced by our own `encrypt_shared` is 2578 bytes:

| input | result |
|---|---|
| flip byte 0, 5, or 100 of a real ciphertext | `Ok`, same 32-byte secret |
| flip the last byte | `Ok`, different 32-byte secret |
| append 7 bytes | `Ok`, same secret (trailing bytes ignored) |
| 0, 3, or 8 zero bytes | panic in `r3.rs:44` |
| 16, 17, 40, 1000 zero bytes | no panic, `Err` |

The container invites the panic. The shortest legal device payload is one ciphertext byte:

```rust
// crates/container/src/limits.rs:84
/// Shortest device payload: prefix, one ciphertext byte, suffix.
pub const DEVICE_PAYLOAD_MIN: usize = DEVICE_PREFIX_LEN + 1 + DEVICE_SUFFIX_LEN;
```

Both open paths call `decrypt_shared` on that slice: `wraps/src/device.rs:161` and `wraps/src/chip.rs:102`. `parse_chip` (`container/src/wrap_entry.rs:399`) derives `ct_len` the same way, from `entry_len` minus a fixed prefix and suffix.

Example: take a vault file that has a device wrap, set that entry's ciphertext field to 8 bytes, and leave the AEGIS tag as zeros. `unlock` with the device keys parses the entry, calls `decrypt_shared`, and aborts inside the dependency. The AEGIS tag is never checked. `catch_unwind` is the wrong fix: it hides a broken primitive and is useless once this is linked into a UI that must not abort.

Fix: in `decrypt_shared` and in `parse_device` / `parse_chip`, accept only the length `encrypt_shared` actually emits (2578 today). Reject everything else before calling `ntrulp`. Then replace the primitive (C2). Add a regression test that a 1-byte and an 8-byte ciphertext return `Err`, in debug and release.

## C2 — the "PQ KEM" is not a KEM, and it is not quantum-safe

Severity: high for the security claim, critical if a future caller uses `decrypt_shared` as a KEM.

`encrypt_shared` draws 32 random bytes and calls `ntrulp::ntru::std_cipher::bytes_encrypt`. That is NTRU public-key encryption of a plaintext, not Streamlined NTRU Prime and not ML-KEM. A KEM draws the secret inside the encapsulation and binds it to the ciphertext. This API lets the caller choose the plaintext, returns `Ok` on modified ciphertexts, and ignores extra trailing bytes (probe above).

The wrap papering over this is good, and it should stay. `device_ikm` hashes both shared secrets and the ciphertext into the AEGIS key, so a malleation that changes the NTRU plaintext also changes `k_dev`, and the AEGIS tag fails. The vault key does not fall out of a flipped NTRU ciphertext today. Two things still fail:

- Availability: C1. Authentication never runs.
- The quantum claim. X25519 (`device.rs`) and P-256 (`chip.rs`, `ec/src/lib.rs`) are the classical legs. A cryptographically relevant quantum computer breaks both. The only other leg is this NTRU encrypt, from crate `ntrulp 0.2.7`, which has no IND-CCA proof, no ciphertext commitment, and a panic on short input. Shipping that as "quantum-safe" is a false claim.

Fix: encapsulate with ML-KEM-768 or ML-KEM-1024 (or the real sntrup761 KEM API, not `bytes_encrypt`). Hybrid as `KDF(ss_classical || ss_pq || ciphertexts || pubs)`. Treat every KEM failure as wrap failure. Do not encrypt a caller-chosen 32-byte secret. Pin public-key, secret-key, and ciphertext lengths in the parser to the chosen algorithm, and give that algorithm its own wrap version so today's files can be rejected or migrated on purpose.

## H1 — no signature, so the server cannot check ownership

Severity: high against the brief. Not exploitable locally, because there is no server.

The brief requires a 512-bit client id derived from the seed, and a signature on every create/update that the server can verify without the vault key. The kernel has neither.

`seed/src/identity.rs` says so:

```rust
/// identity on every device. This is a derivation identifier, not an
/// authentication mechanism.
pub fn user_id(seed: &[u8; 64]) -> anyhow::Result<[u8; 64]> {
    let scalar = identity_seed(seed)?;
    let (_sk, point) = ec::pair_from_scalar(&scalar)?;
    Ok(point)
}
```

`identity_seed` expands to 32 bytes (`kdf/src/derive.rs`, `OUTPUT_LEN`). `pair_from_scalar` (`ec/src/lib.rs:70`) turns that into an uncompressed P-256 point and drops the `0x04` byte. The 64 bytes are `x || y`. Free entropy is the 256-bit scalar, not 512 bits. `y` is redundant given `x` and a sign bit. A workspace search shows `user_id` / `identity_seed` / `pair_from_scalar` are not used by session, local, or wraps. There is no ML-DSA, SLH-DSA, Ed25519, or any `sign` function.

A P-256 Schnorr or ECDSA signature under this scalar would also fail the quantum requirement: Shor's algorithm recovers the scalar from the public point. It would not recover the BIP39 seed (HKDF is one-way), but the sync authenticator would be forgeable. The scalar must not become the sync key.

Fix, as a new module, not bolted onto `user_id`:

- `client_id`: 64 bytes, `HKDF-SHA512(seed, info = "zebrapass/client-id/v1")`. This is the opaque id. It is not a public key.
- `sync_sk`: an ML-DSA-65 (or ML-DSA-87) key from a separate info, `"zebrapass/sync-sign/v1"`. The server stores the verification key, registered once at restore, itself signed by a key the server already trusts or by a first-time enrollment the product defines.
- Request body: `vault_id || record_id || revision || content_hash || ciphertext`. Sign that. The server checks the signature and that `revision` is strictly newer. It never needs the vault key.

Keep `user_id` only if some caller needs a P-256 point. Do not use it as the sync id.

## H2 — one record edit rewrites the whole vault

Severity: high against the sync requirement. The brief says a one-record update must not upload the whole store.

`append_frame` (`session/src/records.rs:303`) decrypts nothing new; it copies `session.records` (the entire plaintext frame list, already resident since unlock) and appends one frame. `write_records` then does this:

```rust
// crates/session/src/rotate.rs:56
let body = encrypt_records(
    session.body_alg,
    &parsed.header,
    session.k_body.expose(),
    session.k_bmac.expose(),
    records,
)?;
```

`encrypt_records` (`session/src/create.rs:207`) draws one nonce and seals that concatenation as a single AEAD body. Unlock decrypts that body before any record is read (`session/src/unlock.rs`, `decrypt_body` into the session). The per-frame AEGIS seal is real (`frame/src/seal.rs`, 32-byte nonce, header bytes as AAD), and `frame_key` is per record (`kdf/src/derive.rs`, info `brby/v2/frame-key` plus the record id). That inner layer is the right seed for sync. The outer body AEAD throws it away: a server that stores the file can only accept a new full body.

Fix: make the frame the sync object. Persist frames as separate length-delimited blobs, or as an append-only log of frames, each already sealed under `frame_key(vault, record_id)`. Uploading record 7 revision 4 sends that frame plus the signature from H1. Do not re-encrypt sibling records. Keep the file commit, but commit a list of frame hashes, not one ciphertext of everything. Conflict rule is already sketched in `accept_seen` (generation plus commit tag); move that rule to `(record_id, revision)` so two devices can edit different records without a false conflict.

`Seen` is only an argument to `unlock`. If the app does not persist it, a replaced older file unlocks. Persist `(generation, commit_tag)` in the local meta file, which is already sealed under `local_meta_key`.

## H3 — hardware key is a wrap format, not a session factor

Severity: medium. The brief allows a TODO, but the session layer currently cannot grow a hardware factor without an API break, and rotation deletes the possibility.

`wraps/src/prf.rs` can seal and open a wrap from a 32-byte HMAC-secret response. `UnlockCreds` (`session/src/unlock.rs:19`) has `master`, `device`, and `chip` only. `reencrypt_body` returns `prf wrap present but physical key support is not built` (`session/src/rotate.rs:87`). A vault that once gained a YubiKey wrap cannot be rotated by this kernel.

Fix: add `prf: Option<(&PrfPublics, &[u8; 32])>` to `UnlockCreds` and thread it through rotation, even if the platform call that produces the 32 bytes stays unimplemented. Returning a typed `FactorUnavailable` is fine. Refusing to rotate a file that contains a known wrap kind is not.

## What is correct

- Envelope shape matches the brief. One random vault key, many wraps, associated data bound to the header (`password_wad`, `device_wad`, `chip_wad`, `prf_wad`). Commit is HMAC-SHA256 over `header || wrap directory || body` (`session/src/create.rs`, `mac_commit`), checked before the body decrypt. A flipped body byte becomes a commit failure, not a body-auth failure.
- Argon2id parameters are in the right range. Desktop 256 MiB, t=3, p=4. Mobile 64 MiB, t=3, p=2, which is the RFC 9106 second recommendation. The header stores m/t/p. The parser floor is 19 MiB and t=2 (`container/src/limits.rs:92`). An attacker cannot downgrade those fields: they sit under the commit HMAC.
- Password open runs Argon2 before comparing the tag, and a wrong seed and a corrupt tag return the same error (`wraps/src/password.rs`). Good.
- Frame AAD is the whole header: kind, record id, revision, origin device, timestamp, algorithm, nonce, length (`frame/src/header.rs`). Swapping two frames fails the tag. Frame keys differ per record id.
- Kuznyechik-CTR is not used raw. `aead/src/kuz_ctr.rs` is encrypt-then-MAC with HMAC-SHA256 and a separate `k_bmac`. `KuzMgm` is rejected before Argon2 (`session/src/create.rs`).
- Atomic replace lives in `local/src/atomic.rs` (temp file, `sync_all`, rename, mode `0o600`). Local metadata is a sealed frame under `local_meta_key(vk, vault_id)`, not a plaintext sidecar.
- Secrets: vault key, body keys, and the NTRU secret key are `Secret<...>`. Device open zeroizes `ss_x`. The identity scalar is zeroized in `user_id`'s callee. Production code has no `unwrap`, `expect`, `todo!`, or `unimplemented!`.
- Domain labels are unique (`brby/v2/body-enc`, `body-mac`, `commit`, `device-wrap`, `chip-wrap`, `prf-wrap`, `frame-key`, `local-meta`, plus `zebrapass/identity/v1`). The mixed prefix is ugly, not ambiguous.
- Coding rules that were checked: no trait objects, no production panic macros, files split by crate, clippy pedantic denied and clean outside tests. `record/src/doc.rs` looks over 500 lines only with its tests included.

## Smaller issues

- `device_ikm` builds a plain `Vec<u8>` of both shared secrets. `Vec` drop does not zero. The HKDF output is wrapped; the input keying material is not. Return `Secret<Vec<u8>>` or zero the buffer before drop. Same pattern anywhere `ikm_concat` output is a `Vec`.
- Errors are `anyhow` strings (`"corrupted length"`, `"commit mismatch"`, `"rollback"`). They do not leak secrets, which is right, but a kernel that must grow sync and hardware factors needs a typed error enum. Strings will get matched by callers and then break.
- `INFO_IDENTITY` says `zebrapass/...` while every other label says `brby/v2/...`. Pick one prefix before the format is frozen.
- `fresh_pair` (`ec/src/lib.rs`) loops up to 8 times on a rejected scalar. Fine, and it returns `Err` instead of panicking. The same cannot be said of `ntrulp`.
- Rollback protection is optional. `accept_seen` does the right comparison, then only if the caller passes `Seen`. Persist it.
- The seed remains a permanent password wrap. That is correct for recovery. The brief's "phrase only to restore a new device" is an application policy: daily unlock must use device or chip keys and must not prompt for the phrase. The kernel allows that. It does not enforce it, and there is no separate user-password factor distinct from the seed. A device PIN would be a new wrap kind or a second password wrap with its own KDF salt. Do not reuse the seed wrap for a PIN.

## Order of work

1. Reject any `ntrulp` ciphertext whose length is not 2578, in `decrypt_shared` and in the wrap parser. Add the panic regression test. This is a one-file fix and it removes the crash.
2. Replace `bytes_encrypt` with ML-KEM (hybrid with the existing X25519 / P-256 leg). New wrap version. Do not call the result quantum-safe until this lands.
3. Add `client_id` (64 uniform bytes) and an ML-DSA sync key, derived from the seed under distinct infos. No server code required to land the keys and a `sign_record` function.
4. Stop sealing the frame list as one body. Store frames individually so a sync request is one frame plus one signature.
5. Add the PRF factor to `UnlockCreds` and to rotation so a hardware key does not brick `reencrypt_body`.
6. Persist `Seen` in local meta. Replace `anyhow` at the session boundary with a typed error.

Until 1 and 2 land, do not describe this kernel as quantum-safe. Until 3 and 4 land, do not describe it as ready to sync.

## Status addendum (updated at the same date)

Findings by the order of work above:

1. **Fixed at `d7cb98d`** — `ntrulp` is gone entirely. Device and chip wraps encapsulate with ML-KEM-768 (`ml-kem 0.3.x`, ciphertext exactly 1088 bytes, id `0xC002`); retired `0xC001` is rejected. A wrong-length ciphertext fails in `pq` before the crate runs.
2. **Fixed at `d7cb98d`** — the PQ leg is now a real KEM, hybridized with X25519 for device wraps. Sync signing is ML-DSA-65 (`crates/pq/src/sign.rs`).
3. **Fixed in this tree** — `kdf::client_id` (64 bytes, `brby/v2/client-id`) and `kdf::sync_seed` (32-byte `Secret`, `brby/v2/sync-sign`), both HKDF-SHA512 from the seed. `session::sync_sig` signs one record payload with length-prefixed fields; `seed::client_id` is exported beside (not replacing) `user_id`, which remains a P-256 point and is documented as non-authenticating.
4. **Fixed in this tree** — `BodyAlg::Frames` (`0xA004`): the body is `u32le length || sealed frame` records (`frame/src/log.rs`). New vaults are created as `0xA004`; `0xA001`/`0xA003` still open. The commit HMAC still covers the whole body, so a flipped frame still fails unlock. `session::sync_export::export_record` returns one record's latest frame plus its revision and ML-DSA signature; `newer(local, remote)` is the strict-revision conflict rule.
5. **Fixed in this tree** — `UnlockCreds::prf` restores the hardware-key factor in the order chip → prf → device → master; `rotate::reencrypt_body` and `change_master` reseal PRF wraps (the latter requires the response, else `prf factor required`); `session::devices::add_prf_unlock` appends a PRF grant. The `physical key support is not built` refusal is gone.
6. **Fixed in this tree** — `LocalMeta.seen` (`SeenCursor`, tags `0x0205`/`0x0206`) persists the accepted generation + commit tag; `local::mark_seen` records it after every unlock/write; a stale file fails `rollback` even when the caller passes no `Seen` (`crates/local/tests/rollback.rs`). Session-boundary strings are now `SessionError` variants (`rollback`, `conflict`, `commit mismatch`, `prf factor required`, `no usable wrap`) with the old strings as their `Display`.

Current gates: `cargo test --workspace` 127 passed / 0 failed across all suites; `cargo clippy --workspace --all-targets` clean in production code (only the pre-existing transitive `multiple-crate-versions` notice). The "quantum-safe" and "sync-ready" claims from the verdict above are now unblocked, with the caveats that no sync server exists and `BodyAlg::Aegis256` files are not auto-migrated to frames (they still open; a future `rewrap_body` may rewrite them).
