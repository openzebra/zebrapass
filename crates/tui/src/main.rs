//! `zebrapass`: the `ZebraPass` terminal password manager.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic, clippy::nursery, clippy::cargo)]
#![allow(
    clippy::multiple_crate_versions,
    reason = "ratatui 0.29 transitively pulls two unicode-width and windows-sys majors"
)]

use std::process::ExitCode;

use tui::cli::{self, Command};

fn main() -> ExitCode {
    let no_color = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
    match cli::parse(std::env::args_os().skip(1), no_color) {
        Ok(Command::Run(config)) => match tui::run(&config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                // Errors at this boundary are terminal and storage failures;
                // no code path puts secret material in them.
                eprintln!("zebrapass: {error}");
                ExitCode::FAILURE
            }
        },
        Ok(Command::Help) => {
            print!("{}", cli::USAGE);
            ExitCode::SUCCESS
        }
        Ok(Command::Version) => {
            println!("zebrapass {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("zebrapass: {message}\n\n{}", cli::USAGE);
            ExitCode::from(2)
        }
    }
}
