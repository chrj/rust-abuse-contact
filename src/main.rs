//! The `abuse-contact` command. It finds where to report abuse for IP addresses and
//! domain names.
//!
//! It needs the `cli` feature:
//!
//! ```sh
//! cargo install abuse-contact --features cli
//! ```

use std::fmt;
use std::io::{self, BufRead, IsTerminal, Write};
use std::net::IpAddr;
use std::process::ExitCode;

use abuse_contact::{Client, DomainName, Error, Finder, Found, Query, Resolver};
use serde_json::json;

const USAGE: &str = "\
Usage: abuse-contact [--json] [TARGET]...

Finds where to report abuse for an IP address or a domain name.

Give each target as an argument. With no argument, the command reads one target
from each line of standard input. It skips empty lines and lines that start with #.

Options:
  --json         Write one JSON object for each target, one object on each line
  -h, --help     Show this help
  -V, --version  Show the version

Output:
  Each contact is one line: the target, the address, the scope and the source,
  divided by tabs. A source that did not answer goes to standard error.

Exit status:
  0  Each target was looked up. A source that did not answer does not change this.
  1  A target could not be looked up
  2  The command line is not correct
";

/// The exit status for a command line that is not correct.
const USAGE_STATUS: u8 = 2;

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    Help,
    Version,
    Lookup {
        format: Format,
        targets: Vec<String>,
    },
}

/// How the command writes what it found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    /// One line for each contact, with the fields divided by tabs.
    Text,
    /// One JSON object for each target.
    Json,
}

/// A command line that is not correct. The message says what to change.
#[derive(Debug, PartialEq, Eq)]
struct UsageError(String);

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A failure to read the targets or to write the results.
#[derive(Debug)]
enum IoError {
    Read(io::Error),
    Write(io::Error),
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let command = match args().and_then(parse_args) {
        Ok(command) => command,
        Err(usage) => {
            eprintln!("abuse-contact: {usage}");
            return ExitCode::from(USAGE_STATUS);
        }
    };

    let (format, targets) = match command {
        Command::Help => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Command::Version => {
            println!("abuse-contact {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Command::Lookup { format, targets } => (format, targets),
    };

    // With no target and a terminal on standard input, the command waits for input
    // that the user does not know to type.
    if targets.is_empty() && io::stdin().is_terminal() {
        eprintln!(
            "abuse-contact: give a target, or send targets to standard input. \
             Run abuse-contact --help to see the usage"
        );
        return ExitCode::from(USAGE_STATUS);
    }

    let finder = match build_finder().await {
        Ok(finder) => finder,
        Err(error) => {
            eprintln!("abuse-contact: {error}");
            return ExitCode::FAILURE;
        }
    };

    let mut out = io::stdout().lock();
    let mut err = io::stderr();
    let result = if targets.is_empty() {
        run(&finder, format, stdin_targets(), &mut out, &mut err).await
    } else {
        let targets = targets.into_iter().map(Ok);
        run(&finder, format, targets, &mut out, &mut err).await
    };

    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        // A reader such as `head` closed the pipe. It has what it wants.
        Err(IoError::Write(error)) if error.kind() == io::ErrorKind::BrokenPipe => {
            ExitCode::SUCCESS
        }
        Err(IoError::Write(error)) => {
            eprintln!("abuse-contact: cannot write the results: {error}");
            ExitCode::FAILURE
        }
        Err(IoError::Read(error)) => {
            eprintln!("abuse-contact: cannot read the targets from standard input: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Returns the arguments after the name of the command.
fn args() -> Result<Vec<String>, UsageError> {
    std::env::args_os()
        .skip(1)
        .map(|arg| {
            arg.into_string().map_err(|arg| {
                UsageError(format!(
                    "the argument {} is not UTF-8. Give each target as text",
                    arg.to_string_lossy()
                ))
            })
        })
        .collect()
}

/// Reads what the command line asks for.
fn parse_args(args: Vec<String>) -> Result<Command, UsageError> {
    let mut format = Format::Text;
    let mut targets = Vec::new();

    for arg in args {
        // A target never starts with a hyphen: an address starts with a digit or a
        // colon, and a domain name cannot start with a hyphen.
        if !arg.starts_with('-') {
            targets.push(arg);
            continue;
        }
        match arg.as_str() {
            "--json" => format = Format::Json,
            "-h" | "--help" => return Ok(Command::Help),
            "-V" | "--version" => return Ok(Command::Version),
            _ => {
                return Err(UsageError(format!(
                    "the option {arg} is not known. Run abuse-contact --help to see the options"
                )));
            }
        }
    }

    Ok(Command::Lookup { format, targets })
}

/// Returns the target on one line of input, or `None` for an empty line or a comment.
fn target_of(line: &str) -> Option<&str> {
    let line = line.trim();
    (!line.is_empty() && !line.starts_with('#')).then_some(line)
}

/// Reads a target as an IP address, and else as a domain name.
fn parse_target(target: &str) -> Result<Query, Error> {
    match target.parse::<IpAddr>() {
        Ok(ip) => Ok(Query::Ip(ip)),
        Err(_) => Ok(Query::Domain(target.parse::<DomainName>()?)),
    }
}

/// Returns the targets on standard input, one for each line.
fn stdin_targets() -> impl Iterator<Item = io::Result<String>> {
    io::stdin().lock().lines().filter_map(|line| match line {
        Ok(line) => target_of(&line).map(|target| Ok(target.to_owned())),
        Err(error) => Some(Err(error)),
    })
}

async fn build_finder() -> Result<Finder, Error> {
    Ok(Finder::new(Client::new().await?, Resolver::new()?))
}

/// Looks up each target and writes what it found, one target at a time.
///
/// The targets share the finder, so a second target in a known network is answered
/// from its cache. Returns whether each target was looked up.
async fn run(
    finder: &Finder,
    format: Format,
    targets: impl IntoIterator<Item = io::Result<String>>,
    out: &mut impl Write,
    err: &mut impl Write,
) -> Result<bool, IoError> {
    let mut all_looked_up = true;

    for target in targets {
        let target = target.map_err(IoError::Read)?;
        let found = match parse_target(&target) {
            Ok(query) => finder.lookup(query).await,
            Err(error) => Err(error),
        };
        all_looked_up &= found.is_ok();

        match format {
            Format::Text => write_text(out, err, &target, &found),
            Format::Json => writeln!(out, "{}", to_json(&target, &found)),
        }
        .and_then(|()| out.flush())
        .map_err(IoError::Write)?;
    }

    Ok(all_looked_up)
}

/// Writes one line for each contact to `out`, and each failure to `err`.
fn write_text(
    out: &mut impl Write,
    err: &mut impl Write,
    target: &str,
    found: &Result<Found, Error>,
) -> io::Result<()> {
    let found = match found {
        Ok(found) => found,
        Err(error) => return writeln!(err, "{target}: {error}"),
    };

    for contact in &found.contacts {
        writeln!(
            out,
            "{target}\t{}\t{}\t{}",
            contact.email, contact.scope, contact.source
        )?;
    }
    for failure in &found.failures {
        writeln!(err, "{target}: {failure}")?;
    }
    if found.contacts.is_empty() && found.failures.is_empty() {
        writeln!(err, "{target}: no source gave an abuse contact")?;
    }
    Ok(())
}

/// Returns what was found for one target as a JSON object.
///
/// Each object has the same four keys, so a reader does not need to test for a
/// missing one. `error` is `null` when the target was looked up.
fn to_json(target: &str, found: &Result<Found, Error>) -> serde_json::Value {
    let found = match found {
        Ok(found) => found,
        Err(error) => {
            return json!({
                "target": target,
                "contacts": [],
                "failures": [],
                "error": error.to_string(),
            });
        }
    };

    let contacts: Vec<_> = found
        .contacts
        .iter()
        .map(|contact| {
            json!({
                "email": contact.email.as_str(),
                "scope": contact.scope.to_string(),
                "source": contact.source.to_string(),
            })
        })
        .collect();
    let failures: Vec<_> = found
        .failures
        .iter()
        .map(|failure| {
            json!({
                "origin": failure.origin.to_string(),
                "error": failure.error.to_string(),
            })
        })
        .collect();

    json!({
        "target": target,
        "contacts": contacts,
        "failures": failures,
        "error": null,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use abuse_contact::{Contact, EmailAddress, Failure, Origin, Scope, Source};

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn found() -> Found {
        Found {
            contacts: vec![
                Contact {
                    email: EmailAddress::new("network-abuse@example.com").unwrap(),
                    scope: Scope::Network,
                    source: Source::Rdap {
                        server: "rdap.arin.net".to_owned(),
                    },
                },
                Contact {
                    email: EmailAddress::new("noc@example.org").unwrap(),
                    scope: Scope::Network,
                    source: Source::Abusix,
                },
            ],
            failures: Vec::new(),
        }
    }

    fn abusix_timeout() -> Failure {
        Failure {
            origin: Origin::Abusix,
            error: Error::Dns {
                name: "8.8.8.8.abuse-contacts.abusix.zone.".to_owned(),
                source: "timed out".into(),
            },
        }
    }

    fn not_public() -> Error {
        Error::NotPublic {
            target: "10.0.0.1".to_owned(),
        }
    }

    #[test]
    fn parse_args_reads_the_options_and_the_targets() {
        let lookup = |format, targets: &[&str]| Command::Lookup {
            format,
            targets: strings(targets),
        };
        let tests = [
            ("no arguments", vec![], Ok(lookup(Format::Text, &[]))),
            (
                "two targets",
                vec!["8.8.8.8", "example.com"],
                Ok(lookup(Format::Text, &["8.8.8.8", "example.com"])),
            ),
            (
                "json after a target",
                vec!["8.8.8.8", "--json"],
                Ok(lookup(Format::Json, &["8.8.8.8"])),
            ),
            ("short help", vec!["-h"], Ok(Command::Help)),
            (
                "help after a target",
                vec!["8.8.8.8", "--help"],
                Ok(Command::Help),
            ),
            ("short version", vec!["-V"], Ok(Command::Version)),
            ("long version", vec!["--version"], Ok(Command::Version)),
            (
                "an unknown option",
                vec!["--yaml"],
                Err(UsageError(
                    "the option --yaml is not known. Run abuse-contact --help to see the options"
                        .to_owned(),
                )),
            ),
        ];

        for (name, args, want) in tests {
            assert_eq!(parse_args(strings(&args)), want, "{name}");
        }
    }

    #[test]
    fn target_of_skips_empty_lines_and_comments() {
        let tests = [
            ("8.8.8.8", Some("8.8.8.8")),
            ("  example.com \r", Some("example.com")),
            ("", None),
            ("   ", None),
            ("# from the mail log", None),
            ("  # indented", None),
        ];

        for (line, want) in tests {
            assert_eq!(target_of(line), want, "{line:?}");
        }
    }

    #[test]
    fn parse_target_reads_an_address_and_else_a_domain() {
        assert_eq!(
            parse_target("8.8.8.8").unwrap(),
            Query::Ip("8.8.8.8".parse().unwrap())
        );
        assert_eq!(
            parse_target("2001:db8::1").unwrap(),
            Query::Ip("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            parse_target("Example.COM").unwrap(),
            Query::Domain("example.com".parse().unwrap())
        );
        assert!(
            matches!(parse_target("not a name"), Err(Error::Validation(_))),
            "{:?}",
            parse_target("not a name")
        );
    }

    fn text(found: &Result<Found, Error>) -> (String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        write_text(&mut out, &mut err, "8.8.8.8", found).unwrap();
        (
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn write_text_writes_one_line_for_each_contact() {
        let (out, err) = text(&Ok(found()));

        assert_eq!(
            out,
            "8.8.8.8\tnetwork-abuse@example.com\tnetwork\trdap.arin.net\n\
             8.8.8.8\tnoc@example.org\tnetwork\tabusix\n"
        );
        assert_eq!(err, "");
    }

    #[test]
    fn write_text_writes_a_failure_to_standard_error() {
        let mut found = found();
        found.failures.push(abusix_timeout());

        let (out, err) = text(&Ok(found));

        assert_eq!(out.lines().count(), 2, "{out}");
        assert!(
            err.starts_with("8.8.8.8: Abusix did not answer: the DNS lookup for "),
            "{err}"
        );
    }

    #[test]
    fn write_text_says_when_no_source_gave_a_contact() {
        let (out, err) = text(&Ok(Found::default()));

        assert_eq!(out, "");
        assert_eq!(err, "8.8.8.8: no source gave an abuse contact\n");
    }

    #[test]
    fn write_text_writes_a_target_that_was_not_looked_up_to_standard_error() {
        let (out, err) = text(&Err(not_public()));

        assert_eq!(out, "");
        assert!(
            err.starts_with("8.8.8.8: 10.0.0.1 is a private, reserved or documentation address"),
            "{err}"
        );
    }

    #[test]
    fn to_json_gives_the_contacts_and_the_failures() {
        let mut found = found();
        found.failures.push(abusix_timeout());

        let value = to_json("8.8.8.8", &Ok(found));

        assert_eq!(value["target"], "8.8.8.8");
        assert_eq!(
            value["contacts"],
            json!([
                {"email": "network-abuse@example.com", "scope": "network", "source": "rdap.arin.net"},
                {"email": "noc@example.org", "scope": "network", "source": "abusix"},
            ])
        );
        assert_eq!(value["failures"][0]["origin"], "Abusix");
        assert!(
            value["failures"][0]["error"].as_str().unwrap().starts_with(
                "the DNS lookup for 8.8.8.8.abuse-contacts.abusix.zone. did not finish"
            ),
            "{value}"
        );
        assert_eq!(value["error"], json!(null));
    }

    #[test]
    fn to_json_gives_the_error_of_a_target_that_was_not_looked_up() {
        let value = to_json("10.0.0.1", &Err(not_public()));

        assert_eq!(value["target"], "10.0.0.1");
        assert_eq!(value["contacts"], json!([]));
        assert_eq!(value["failures"], json!([]));
        assert!(
            value["error"]
                .as_str()
                .unwrap()
                .starts_with("10.0.0.1 is a private, reserved or documentation address"),
            "{value}"
        );
    }
}
