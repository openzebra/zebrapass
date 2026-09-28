//! Terminal interface for `ZebraPass`.
//!
//! The TUI adds no cryptography: every key operation goes through `session`,
//! `local`, and `seed`. Secrets typed or opened here live in zeroizing
//! buffers, are masked by default, and are dropped when the vault locks.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(
    clippy::multiple_crate_versions,
    reason = "ratatui 0.29 transitively pulls two unicode-width and windows-sys majors"
)]

pub mod app;
pub mod cli;
pub mod secure;
pub mod ui;
pub mod vault;

pub use app::event::run;
pub use app::App;
