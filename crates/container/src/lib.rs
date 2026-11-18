//! Vault file header, wrap directory, and commit.

mod commit;
mod header;
mod limits;
mod wrap_dir;
mod wrap_entry;
mod wrap_human;

pub use commit::{Parsed, VaultFile, assemble};
pub use header::StaticHeader;
pub use limits::{
    BODY_AEGIS256, BODY_FRAMES, BODY_KUZ_CTR_HMAC, BODY_KUZ_MGM, COMMIT_LEN, DOMAIN_BODY,
    DOMAIN_WRAP_CHIP, DOMAIN_WRAP_PASSWORD, DOMAIN_WRAP_PRF, HEADER_LEN, KDF_ARGON2ID,
    KDF_M_KIB_MAX, KDF_M_KIB_MIN, KDF_P_MAX, KDF_P_MIN, KDF_T_MAX, KDF_T_MIN, KIND_CHIP,
    KIND_PASSWORD, KIND_PASSWORD_HUMAN, KIND_PRF, MAGIC, PASSWORD_PAYLOAD_LEN, PASSWORD_RECORD_LEN,
    VERSION, WRAP_AEGIS256,
};
pub use wrap_dir::{WrapDir, encode_wrap_dir};
pub use wrap_entry::{
    ChipWrap, PasswordWrap, PrfWrap, WrapEntry, encode_chip_entry, encode_password_entry,
    encode_prf_entry, parse_entry,
};
pub use wrap_human::{HumanKdf, HumanPasswordWrap, encode_human_password_entry};
