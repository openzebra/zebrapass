//! Vault file header, wrap directory, and commit.

mod commit;
mod error;
mod header;
mod limits;
mod wrap_dir;
mod wrap_entry;

pub use commit::{assemble, Parsed, VaultFile};
pub use error::FormatError;
pub use header::StaticHeader;
pub use limits::{
    BODY_AEGIS256, BODY_KUZ_CTR_HMAC, BODY_KUZ_MGM, COMMIT_LEN, DEVICE_PAYLOAD_LEN,
    DEVICE_RECORD_LEN, DOMAIN_BODY, DOMAIN_WRAP_DEVICE, DOMAIN_WRAP_PASSWORD, HEADER_LEN,
    KDF_ARGON2ID, KDF_M_KIB_MAX, KDF_M_KIB_MIN, KDF_P_MAX, KDF_P_MIN, KDF_T_MAX, KDF_T_MIN,
    KEM_SNTRUP1277, KIND_DEVICE, KIND_PASSWORD, MAGIC, PASSWORD_PAYLOAD_LEN, PASSWORD_RECORD_LEN,
    SNTRUP_CT_LEN, VERSION, WRAP_AEGIS256,
};
pub use wrap_dir::{encode_wrap_dir, WrapDir};
pub use wrap_entry::{
    encode_device_entry, encode_password_entry, DeviceWrap, PasswordWrap, WrapEntry,
};
