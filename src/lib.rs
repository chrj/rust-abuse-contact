//! Find where to report abuse for an IP address or a domain name.
//!
//! The contact lives in a different place for each kind of target, and the answers
//! are not interchangeable. The registrar of a domain can suspend the name. The
//! network that holds an IP address can take the host off the air. The operator of
//! the domain runs the service. A report goes to the one that can act on it, so this
//! crate returns every contact it finds with the scope it covers, and leaves the
//! choice to you.
//!
//! # Sources
//!
//! | Source | Target | What it gives |
//! | --- | --- | --- |
//! | RDAP | IP, domain | The contact the registry publishes |
//! | Abusix | IP | The contact for the network, over DNS |
//! | abuse.net | domain | The contact the operator registered, over DNS |
//! | RFC 2142 | domain | `abuse@` at the domain, a guess |
//!
//! # Reading a result
//!
//! ```
//! use abuse_contact::{Contact, EmailAddress, Scope, Source, rank};
//!
//! let found = vec![
//!     Contact {
//!         email: EmailAddress::new("abuse@example.com")?,
//!         scope: Scope::Domain,
//!         source: Source::Rfc2142,
//!     },
//!     Contact {
//!         email: EmailAddress::new("registrar-abuse@example.net")?,
//!         scope: Scope::Registrar,
//!         source: Source::Rdap { server: "rdap.example.net".to_owned() },
//!     },
//! ];
//!
//! // The registry answer comes first. The guess comes last.
//! let ranked = rank(found);
//! assert_eq!(ranked[0].scope, Scope::Registrar);
//!
//! // Pick by what you want to happen, not by what is first.
//! let takedown = ranked.iter().find(|c| c.scope == Scope::Registrar);
//! assert!(takedown.is_some());
//! # Ok::<(), abuse_contact::ValidationError>(())
//! ```
//!
//! # Design
//!
//! Values that go out are checked when you build them. [`DomainName`] refuses a name
//! that no registry can hold, so a lookup that is certain to find nothing never
//! reaches the network.
//!
//! Values that come back are not checked the same way. A change on a registry side
//! must not turn a working lookup into a parse error, so [`rdap::Response`] reads the
//! few fields an abuse lookup needs and ignores the rest.
//!
//! One value that comes back is refused: a registry that hides contact data puts a
//! placeholder such as `DATA REDACTED` in the email field. [`EmailAddress`] rejects
//! it, so the placeholder never reaches a mail queue.
//!
//! A domain takes one request, not two. The registry record names the registrar and
//! carries its abuse address under the registrar entity, so one lookup is enough.
//! [`rdap::Response::related_href`] gives the registrar record for the details the
//! registry leaves out, such as the abuse telephone number.
//!
//! Registries do not agree on where the abuse entity goes, or on whether to publish
//! one. ARIN puts it under the registrant and again at the top level. RIPE, APNIC and
//! LACNIC put it at the top level. APNIC marks the abuse mailbox with `pref` and lists
//! a help desk beside it. registro.br marks one entity both technical and abuse and
//! gives it no address. AFRINIC publishes no abuse entity at all. The reader walks the
//! whole tree, sorts by preference, and returns each address one time.
//!
//! RDAP therefore does not answer everywhere. For AFRINIC space and for registro.br
//! space, DNS is the only source that gives an address. Ask more than one source.
//!
//! # Fetching a record
//!
//! `Client` picks the server from the IANA bootstrap registries and fetches the
//! record. It needs the `http` feature, which is on by default, and its own
//! documentation shows a lookup.
//!
//! Turn the default features off with `default-features = false` to take the readers
//! alone, with no HTTP stack and no resolver. Then fetch with the client you already
//! have and call
//! [`rdap::Response::abuse_contacts`], [`dns::contacts_from_txt`] and [`rank`] on what
//! comes back.
//!
//! # Asking the DNS sources
//!
//! `Resolver` asks the Abusix and abuse.net zones, and checks that a domain takes mail
//! before it gives `abuse@` at the domain. It needs the `dns` feature, which is on by
//! default. For AFRINIC space, where RDAP publishes no abuse entity, Abusix is the only
//! source that answers.
//!
//! # Asking every source
//!
//! `Finder` asks every source for a target at the same time, and gives the contacts
//! ordered by [`rank`]. A source that fails does not fail the lookup: its error is
//! returned beside the contacts from the sources that answered. It needs the `http`
//! and `dns` features.

#![forbid(unsafe_code)]

pub mod bootstrap;
pub mod dns;
pub mod rdap;

#[cfg(feature = "http")]
mod client;
mod contact;
#[cfg(feature = "http")]
mod destination;
mod error;
#[cfg(all(feature = "http", feature = "dns"))]
mod finder;
mod nat64;
mod query;
#[cfg(feature = "dns")]
mod resolver;

#[cfg(feature = "http")]
pub use client::{Client, MAX_BOOTSTRAP_BYTES, MAX_RECORD_BYTES, Record};
pub use contact::{Contact, EmailAddress, Scope, Source, rank};
#[cfg(feature = "http")]
pub use destination::Destinations;
pub use error::{Error, ValidationError};
#[cfg(all(feature = "http", feature = "dns"))]
pub use finder::{Failure, Finder, Found, Origin};
pub use query::{DomainName, Query, is_public};
#[cfg(feature = "dns")]
pub use resolver::Resolver;
