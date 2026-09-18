//! One lookup that asks every source that answers for a target.

use std::fmt;
use std::net::IpAddr;

use crate::client::{Client, Record};
use crate::contact::{Contact, Scope, rank};
use crate::error::Error;
use crate::query::{DomainName, Query};
use crate::resolver::Resolver;

/// Asks every source for a target, at the same time, and merges the answers.
///
/// An IP address goes to RDAP and Abusix. A domain name goes to RDAP, abuse.net and
/// RFC 2142.
///
/// ```no_run
/// use abuse_contact::{Client, Finder, Resolver};
///
/// # async fn run() -> Result<(), abuse_contact::Error> {
/// let finder = Finder::new(Client::new().await?, Resolver::new()?);
///
/// let found = finder.lookup("196.216.2.1".parse::<std::net::IpAddr>().unwrap()).await?;
/// for contact in &found.contacts {
///     println!("{} ({:?})", contact.email, contact.scope);
/// }
/// for failure in &found.failures {
///     eprintln!("{failure}");
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Finder {
    client: Client,
    resolver: Resolver,
}

impl Finder {
    /// Returns a finder that asks RDAP with this client and DNS with this resolver.
    pub fn new(client: Client, resolver: Resolver) -> Self {
        Self { client, resolver }
    }

    /// Asks every source for the target and returns what they found.
    ///
    /// A source that fails does not fail the lookup. Its error is in
    /// [`Found::failures`], and the contacts from the other sources are still given.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotPublic`] for a private or reserved address. No source is
    /// asked for it.
    pub async fn lookup(&self, query: impl Into<Query>) -> Result<Found, Error> {
        match query.into() {
            Query::Ip(ip) => self.lookup_ip(ip).await,
            Query::Domain(domain) => Ok(self.lookup_domain(&domain).await),
        }
    }

    async fn lookup_ip(&self, ip: IpAddr) -> Result<Found, Error> {
        // Each source makes this check too. Make it here as well, so that a query
        // that no source can answer is an error and not two failures.
        let ip = crate::query::unmap(ip);
        if !crate::is_public(ip) {
            return Err(Error::NotPublic {
                target: ip.to_string(),
            });
        }

        let (rdap, abusix) = tokio::join!(self.client.lookup_ip(ip), self.resolver.abusix(ip));

        Ok(merge([
            (
                Origin::Rdap,
                rdap.map(|record| contacts(record, Scope::Network)),
            ),
            (Origin::Abusix, abusix),
        ]))
    }

    async fn lookup_domain(&self, domain: &DomainName) -> Found {
        let (rdap, abuse_net, rfc2142) = tokio::join!(
            self.client.lookup_domain(domain),
            self.resolver.abuse_net(domain),
            self.resolver.rfc2142(domain),
        );

        merge([
            (
                Origin::Rdap,
                rdap.map(|record| contacts(record, Scope::Registrar)),
            ),
            (Origin::AbuseNet, abuse_net),
            (Origin::Rfc2142, rfc2142.map(Vec::from_iter)),
        ])
    }
}

/// What a lookup found: the contacts, and the sources that did not answer.
#[derive(Debug, Default)]
pub struct Found {
    /// The contacts from every source that answered, ordered by [`rank`].
    pub contacts: Vec<Contact>,
    /// The sources that did not answer, with the reason.
    ///
    /// A source that answered with no contact is not here. Check this list before
    /// you read an empty [`Found::contacts`] as "no contact is published".
    pub failures: Vec<Failure>,
}

/// A source that did not answer.
#[derive(Debug)]
pub struct Failure {
    /// The source that failed.
    pub origin: Origin,
    /// Why it failed.
    pub error: Error,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} did not answer: {}", self.origin, self.error)
    }
}

/// A source that [`Finder`] asks.
///
/// [`crate::Source`] names where a contact came from, and for RDAP it names the
/// server that answered. A source that failed can have no server to name, so a
/// failure names the source with this.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Origin {
    /// RDAP, from the server the bootstrap registry names.
    Rdap,
    /// The Abusix `abuse-contacts` DNS zone.
    Abusix,
    /// The abuse.net `contacts` DNS zone.
    AbuseNet,
    /// The MX and address lookups that decide whether `abuse@` at the domain is given.
    Rfc2142,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Origin::Rdap => "RDAP",
            Origin::Abusix => "Abusix",
            Origin::AbuseNet => "abuse.net",
            Origin::Rfc2142 => "the RFC 2142 check",
        })
    }
}

/// Returns the contacts in a record. A registry that holds no record gives none.
fn contacts(record: Option<Record>, scope: Scope) -> Vec<Contact> {
    record
        .map(|record| record.abuse_contacts(scope))
        .unwrap_or_default()
}

/// Joins what each source gave into one ranked list, and keeps the failures beside it.
fn merge(answers: impl IntoIterator<Item = (Origin, Result<Vec<Contact>, Error>)>) -> Found {
    let mut contacts = Vec::new();
    let mut failures = Vec::new();

    for (origin, answer) in answers {
        match answer {
            Ok(found) => contacts.extend(found),
            Err(error) => failures.push(Failure { origin, error }),
        }
    }

    Found {
        contacts: rank(contacts),
        failures,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::{EmailAddress, Source};

    fn contact(email: &str, scope: Scope, source: Source) -> Contact {
        Contact {
            email: EmailAddress::new(email).unwrap(),
            scope,
            source,
        }
    }

    fn timeout(name: &str) -> Error {
        Error::Dns {
            name: name.to_owned(),
            source: "timed out".into(),
        }
    }

    #[test]
    fn a_failed_source_keeps_the_contacts_of_the_others() {
        let rdap = contact(
            "abuse@registrar.example",
            Scope::Registrar,
            Source::Rdap {
                server: "rdap.example".to_owned(),
            },
        );

        let found = merge([
            (Origin::Rdap, Ok(vec![rdap])),
            (
                Origin::AbuseNet,
                Err(timeout("example.com.contacts.abuse.net.")),
            ),
        ]);

        let emails: Vec<&str> = found.contacts.iter().map(|c| c.email.as_str()).collect();
        assert_eq!(emails, ["abuse@registrar.example"]);
        assert_eq!(found.failures.len(), 1);
        assert_eq!(found.failures[0].origin, Origin::AbuseNet);
    }

    #[test]
    fn the_contacts_are_ranked_and_a_repeat_is_dropped() {
        let found = merge([
            (
                Origin::Abusix,
                Ok(vec![contact(
                    "abuse@example.net",
                    Scope::Network,
                    Source::Abusix,
                )]),
            ),
            (
                Origin::Rdap,
                Ok(vec![contact(
                    "abuse@example.net",
                    Scope::Network,
                    Source::Rdap {
                        server: "rdap.example".to_owned(),
                    },
                )]),
            ),
        ]);

        assert_eq!(
            found.contacts,
            [contact(
                "abuse@example.net",
                Scope::Network,
                Source::Rdap {
                    server: "rdap.example".to_owned()
                },
            )]
        );
        assert_eq!(found.failures.len(), 0);
    }

    #[test]
    fn every_source_failing_gives_no_contacts_and_every_failure() {
        let found = merge([
            (Origin::Rdap, Err(timeout("rdap.example"))),
            (Origin::Abusix, Err(timeout("abusix.example"))),
        ]);

        assert_eq!(found.contacts, []);
        let origins: Vec<Origin> = found.failures.iter().map(|f| f.origin).collect();
        assert_eq!(origins, [Origin::Rdap, Origin::Abusix]);
    }

    #[test]
    fn a_failure_says_which_source_failed_and_why() {
        let failure = Failure {
            origin: Origin::Rdap,
            error: Error::NoServer {
                target: "example.invalid".to_owned(),
            },
        };

        assert!(
            failure
                .to_string()
                .starts_with("RDAP did not answer: no RDAP server answers for example.invalid"),
            "{failure}"
        );
    }
}
