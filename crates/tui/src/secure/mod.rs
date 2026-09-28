//! Secret-handling building blocks for the UI: zeroizing inputs, reveal
//! timing, the OSC 52 clipboard, the generator, TOTP codes, and local
//! analyses.

pub mod clipboard;
pub mod generator;
pub mod health;
pub mod phrase_input;
pub mod reveal;
pub mod secret_input;
pub mod strength;
pub mod totp;
