# AGENTS.md — ZebraPass Core

You are working on the cryptographic kernel of a quantum-safe password manager.
The code you write protects user secrets. Correctness and secret hygiene come before performance.
The rules below are strict. If a rule seems to conflict with a security requirement, security wins, and you should say so in your reply rather than in the code.

---

## 0. Project Map

### 0.1 Product model
1. A **BIP39 phrase** is the root secret. It is used **only** to create a vault or restore one on a new device.
2. After a restore, each device enrolls its own unlock factor: password, this device (P-256 + ML-KEM keys in a PIN-sealed `device.key` file, or a secure chip in native apps), or later a hardware key (FIDO2 PRF / YubiKey). Device keys never go to the OS keychain.
3. **Envelope encryption.** One random vault key (VK) encrypts the data. The VK is wrapped by N independent KEKs (master, password, device, PRF). Adding or removing a factor never re-encrypts the data. Revoking a device **rotates the VK**.
4. **Quantum-safe.** Symmetric keys are 256-bit. Key exchange uses a hybrid of ML-KEM and a classical EC share. Signatures use ML-DSA.
5. **Sync is per record.** A single signed record frame goes to the server, never the whole vault.
6. **Client ID** is `[u8; 64]`, derived one-way from the seed with HKDF-SHA512 and a domain-separated label.
7. **Every upload is signed.** The server verifies it with public data only.
8. The server transport and hardware keys are TODO. Their seams already exist, so extend them and never bypass them.

### 0.2 Workspace crates (dependency direction: top → bottom)

| Crate | Responsibility |
|---|---|
| `session` | Public API: `create`, `unlock`, records CRUD, devices, rotation/revoke, `export_record` / `accept_record`, sync signatures |
| `local` | On-device storage: atomic writes, local meta, rollback `seen` state, the PIN-sealed device key file |
| `platform` | Secure-chip seam for native apps (`ChipBackend`; `SoftwareChip` for tests). Terminal apps cannot reach the Secure Enclave |
| `container` | Vault file wire format: static header, wrap directory, wrap entries (`password`, `password_human`, `chip` = device, `prf`); kind `0x0002` is retired, commitment tag, parse limits |
| `wraps` | KEK derivation and VK wrap/unwrap per factor (`password`, `password_human`, `chip` = device, `prf`) and wrap AD construction (`wad`) |
| `frame` | Per-record encrypted frames (AEGIS-256, header as AD), frame index, append log |
| `record` | Plaintext document model, tags, size limits |
| `kdf` | Argon2id, HKDF-SHA512, all key-derivation labels (`INFO_*`), KDF profiles |
| `aead` | Body ciphers: AEGIS-256 and Kuznyechik-CTR + HMAC (encrypt-then-MAC), `BodyAlg` |
| `pq` | ML-KEM (hybrid KEM) and ML-DSA (sync signing, device certificates) |
| `ec` | Classical EC share for the hybrid KEM |
| `seed` | BIP39 phrase, wordlist, entropy RNG, identity |
| `secret` | `Secret<T>` (zeroizing, redacted `Debug`) and constant-time compare (`ct_eq`) |

### 0.3 Cryptographic primitives (the only ones allowed)

| Purpose | Primitive |
|---|---|
| Password stretching | **Argon2id** v0x13, parameters bounded by a known `KdfProfile` (`Fast` 64 MiB, `Balanced` 256 MiB, `Strong` 1 GiB) |
| Key derivation | **HKDF-SHA512**, unique `INFO_*` label per key, length-framed variable parts |
| Record / frame encryption | **Cascade** (frame alg `0xA005`): **AEGIS-256** (random 256-bit nonce) inside **Kuznyechik-CTR + HMAC** (random 128-bit IV, encrypt-then-MAC, constant-time tag check). Each layer has its own HKDF key from the frame key; both authenticate the full header as AD; the outer MAC is checked first. Legacy AEGIS-256-only frames (`0xA001`) still open and are re-sealed as cascade frames on rotation |
| Alternate body cipher | **Kuznyechik-CTR + HMAC** for whole-body legacy vaults. New vaults always use per-record frames |
| TOTP codes | **HMAC-SHA1** (RFC 6238) for one-time codes only, never for keys or integrity |
| File commitment | **HMAC** over the whole file (or the chained frame digest), checked **before** decryption |
| Frame log integrity | Chained **SHA-256** fold |
| Key encapsulation (device wraps) | **ML-KEM** hybrid with the EC share. The combiner must bind both shared secrets, ciphertexts and public keys |
| Signatures (sync, device certs) | **ML-DSA** with context strings `SYNC_CTX` / `DEVICE_CERT_CTX` |
| Randomness | OS CSPRNG (`getrandom`). Failure is an error, never a retry loop or fallback |

Never add a primitive, mode, or library without an explicit request. Never implement cryptographic algorithms by hand.

### 0.4 Key hierarchy
```
BIP39 phrase ──► seed[64] ──HKDF──► master KEK ─┐
                         ├──HKDF──► client_id[64]│
                         └──HKDF──► account sign key (certifies device keys)
password ──Argon2id──► password KEK ────────────┤
device file|chip ──(P-256+ML-KEM)──► KEK ───────┤
hardware key ──(PRF, TODO)──► KEK ──────────────┤
                                                 ▼
                                  wrap(VK) with AD = header ‖ wrap metadata
VK ──HKDF(vault_id)──► k_body, k_bmac, k_commit (+ frame keys)
```

---

## 1. Secrets & Zeroization (security rules — mandatory)

- **Every secret lives in `secret::Secret<T>`.** This covers keys, seeds, phrases, passwords, KEKs, the VK, shared secrets, decrypted plaintext, and Argon2/HKDF output. Never hold a secret in a bare `[u8; N]`, `Vec<u8>` or `String` beyond the single expression that produces it.
- **Use the `zeroize` crate.** Temporary buffers must be `zeroize::Zeroizing<T>`. Types that own secret material derive or implement `Zeroize` + `ZeroizeOnDrop`.
- **Write secrets into their final home.** Prefer APIs that fill `&mut [u8]` inside a `Secret`/`Zeroizing`. Do not create a stack array and then move a copy of it (`[u8; N]` is `Copy`, so the original stays in memory).
- **Never `Clone` a secret type.** Don't implement `Clone`/`Copy` for secret wrappers. Share secrets by reference (`&Secret<T>`), and call `.expose()` at the narrowest scope.
- **Never log or format secrets.** `Debug` must be redacted, and secret types never get `Display`. No secret in an error message, panic text, or `format!`.
- **Compare in constant time.** Tags, commitments, MACs and ID comparisons go through `secret::ct_eq*` / `subtle`. Never compare them with `==`.
- **Errors must not act as oracles.** Authentication failures return one uniform error, with no difference between a wrong key and a wrong tag. Check the commitment **before** decrypting anything.
- **Treat untrusted input as hostile.** Every length, count and cost parameter parsed from a file or the network is bounded by a `limits.rs` constant **before** allocating memory or running a KDF.
- **Nonces are random** (≥192-bit for AEGIS) and generated in exactly one place per primitive. Never reuse a nonce, never use a counter-derived nonce under the same key, and never accept a caller-supplied nonce in a public API.
- **Domain-separate everything.** Each derived key has a unique constant label. Variable parts of an info string or signed message are length-prefixed (`u16/u32 BE len ‖ bytes`). Never concatenate raw variable data.
- **Authenticate all context.** Every AEAD call binds its header, algorithm id, version, vault_id and wrap metadata as AD. Algorithm ids come from an allow-list. Downgrades are rejected.
- **Fail closed.** Unsupported algorithms, unknown wrap kinds, and unbuilt hardware paths return an error. Never silently skip them.
- **Every sync upload is signed.** The signed message (`MSG_VERSION` 2) binds the domain ‖ server origin ‖ client_id ‖ device_id ‖ vault_id ‖ record_id ‖ revision ‖ prev_hash ‖ hash(ciphertext) ‖ msg_version ‖ key_generation. Version 1 still verifies but is never signed or accepted.
- **Unsafe code is forbidden** in crypto crates: `#![forbid(unsafe_code)]`.
- **Every security fix ships with a regression test.** Examples: tamper a byte and expect failure; roll back and expect `rollback`; revoke and expect the old key to fail.

---

## 2. Memory Efficiency & Optimal Data Structures
- **Use `Box` to keep large values off the stack.** It prevents stack bloat, larger frames, and expensive stack copies.
- **Shrink collections that won't grow.** Once a `Vec`/`String` reaches its final size, convert it to `Box<[T]>` / `Box<str>` with `.into_boxed_slice()` / `.into_boxed_str()`. This saves 8 bytes (the capacity field).
- **Order struct fields by alignment.** Go from largest to smallest (`u64`/`usize` → `u32` → `u16` → `u8`/`bool`) to avoid padding.
- **Keep enum variants balanced.** Box the payload of any variant that is much larger than the others.
- **Use niche optimization.** Prefer `Option<Box<T>>`, `Option<NonZeroU32>` and `Option<&T>`, which fit in one word.
- **Never duplicate memory.** Avoid `.clone()` / `.to_owned()` / `.to_vec()` unless a value really needs its own lifetime. Move or borrow instead.
- **Pre-allocate capacity.** Use `Vec::with_capacity` / `HashMap::with_capacity` whenever the size is known or can be estimated.
- **Use `Cow<'a, str>`** when data may be borrowed or owned.
- **Don't wrap references in `&Option`.** Use `Option<&str>` / `Option<&T>`, never `&Option<String>` / `&Option<T>`.

## 3. Strict Safety & Zero Panics
- **No panic paths in production code.** No `.unwrap()`, `.expect()`, `panic!`, `todo!`, `unimplemented!`, `unreachable!`. (Tests may use them.)
- **Use strict error handling.** Return `Result<T, E>` with `?`, and handle errors exhaustively at boundaries.
- **Index safely.** Use `.get()` / `.get_mut()` / `split_at_checked` / `chunks_exact` / `try_into` for fixed arrays. Do arithmetic on untrusted sizes with `checked_*`.
- **Mark unfinished work as a comment.** Write `// TODO(hw-key)` / `// TODO(sync-server)` and return an error at runtime. Never write `todo!()`.

## 4. Type System & Dispatch
- **Prefer static dispatch.** Default to `impl Trait` / generics in argument and return positions.
- **Allow `Box<dyn Trait>` only when truly needed:** heterogeneous collections or genuine runtime dispatch. Never use it in crypto hot paths.
- **Derive standard traits.** Derive or implement `Default`, `Debug` (redacted for secrets), `PartialEq`, `Eq`. Never derive `PartialEq` on secret types; implement constant-time equality instead.
- **Use newtypes.** Distinct IDs and keys get distinct types (`VaultId`, `DeviceId`, `ClientId`, `RecordId`), so they can't be mixed up.

## 5. Control Flow & Idiomatic Patterns
- **Don't repeat yourself.** Extract shared logic into functions or declarative macros. Examples: one length-framing helper, one AD builder, one wrap/unwrap path for all factors.
- **Prefer declarative iterators** (`iter/map/filter/fold/try_fold/collect`) over imperative loops.
- **Match exhaustively.** Use `match` / `if let`, no deep `if / else if` chains, and no `_ =>` wildcard on security-relevant enums (algorithms, wrap kinds).
- **Use the conversion traits** `From` / `TryFrom` / `Into` / `TryInto` for conversions and parsing, instead of ad-hoc `to_*` / `from_*`.

## 6. Lifetimes & Low-Level Optimization
- **Keep mutability minimal.** Use the narrowest possible `mut` scope.
- **Compute at compile time.** Use `const fn`, and `const` assertions for size invariants (e.g. that a length fits in `u16`).
- **Use precise lifetimes.** Use `'static` only for true binary-embedded data. Otherwise use `'_` or named lifetimes.
- **Clippy must pass cleanly.** Code passes `#![warn(clippy::pedantic, clippy::nursery, clippy::cargo)]` with zero warnings.

## 7. Structure & Files
- **Production files stay under 500 lines.** This is enforced by `scripts/check_line_limit.py`. Test files are exempt.
- **Split by abstraction.** One concept per file, and one crate per layer (see §0.2). Keep dependencies downward only.
- **Change the wire format carefully.** Any format change bumps its version constant, keeps the old parser, and adds a golden test in `crates/container/tests/wire.rs`.

## 8. Clean Code & Comments
- **Write self-documenting code.** Use expressive names and strict types. Avoid inline comments, except for short security-invariant notes where the reason isn't obvious.
- **Leave no artifact or meta references.** Never write finding or plan IDs (`#1`, `C1`, `H3`, `§5`), report names, or AI-generation notes in source code.

## 9. Required checks before finishing any task
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings -W clippy::pedantic -W clippy::nursery
cargo test --workspace --all-features
python3 scripts/check_line_limit.py
```
All four must pass. If one can't pass, report it explicitly and don't hide it.
