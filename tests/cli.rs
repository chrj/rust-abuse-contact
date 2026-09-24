//! The `abuse-contact` command, run as a process.
//!
//! These tests cover what the command does before it asks a source, so they need no
//! network. The unit tests in `src/main.rs` cover the output.

#![cfg(feature = "cli")]

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_abuse-contact"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn help_shows_the_usage() {
    let output = run(&["--help"]);

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.starts_with("Usage: abuse-contact [--json] [TARGET]...\n"),
        "{stdout}"
    );
}

#[test]
fn version_shows_the_version_of_the_crate() {
    let output = run(&["-V"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        concat!("abuse-contact ", env!("CARGO_PKG_VERSION"), "\n")
    );
}

#[test]
fn an_unknown_option_is_a_usage_error() {
    let output = run(&["--yaml", "8.8.8.8"]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"");
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "abuse-contact: the option --yaml is not known. Run abuse-contact --help to see \
         the options\n"
    );
}
