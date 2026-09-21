/// Argon2id or HKDF failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KdfError {
    /// Parameters are outside the floor or the ceiling, or the KDF rejected them.
    KdfParamsRejected,
    /// The password is empty. Argon2 was not called.
    EmptyPassword,
}
