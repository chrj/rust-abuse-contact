//! One lookup that asks every source that answers for a target.

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;

use crate::cache::Cache;
use crate::client::Client;
use crate::contact::{Contact, Scope, rank};
use crate::error::Error;
use crate::query::{DomainName, Query};
use crate::resolver::Resolver;

/// The most hosts of one domain that the finder asks the network sources about.
///
/// Each host costs an RDAP request and an Abusix lookup. A domain with many addresses
/// is usually one service in one or two networks, so the first few are enough.
const MAX_HOSTS: usize = 4;

/// Asks every source for a target, at the same time, and merges the answers.
///
/// An IP address goes to RDAP and Abusix. A domain name goes to RDAP, abuse.net and
/// RFC 2142. The finder also looks up the addresses of the domain, and asks RDAP and
/// Abusix about the network of each host. Thus a domain also gets the contact that
/// can take its host off the air.
///
/// The finder holds the RDAP answers in a [`Cache`], so it does not ask a registry
/// about the same network or the same domain again. [`Finder::with_cache`] sets how
/// long an answer is held.
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
    cache: Cache,
}

impl Finder {
    /// Returns a finder that asks RDAP with this client and DNS with this resolver.
    ///
    /// It holds the RDAP answers in [`Cache::default`].
    pub fn new(client: Client, resolver: Resolver) -> Self {
        Self {
            client,
            resolver,
            cache: Cache::default(),
        }
    }

    /// Returns the finder with the RDAP answers held in this cache.
    ///
    /// Keep a clone of the cache to read its size or to clear it.
    pub fn with_cache(self, cache: Cache) -> Self {
        Self { cache, ..self }
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

        let (rdap, abusix) = tokio::join!(self.rdap_ip(ip), self.resolver.abusix(ip));

        Ok(merge([(Origin::Rdap, rdap), (Origin::Abusix, abusix)]))
    }

    async fn lookup_domain(&self, domain: &DomainName) -> Found {
        let (rdap, abuse_net, rfc2142, hosts) = tokio::join!(
            self.rdap_domain(domain),
            self.resolver.abuse_net(domain),
            self.resolver.rfc2142(domain),
            self.host_networks(domain),
        );

        merge(
            [
                (Origin::Rdap, rdap),
                (Origin::AbuseNet, abuse_net),
                (Origin::Rfc2142, rfc2142.map(Vec::from_iter)),
            ]
            .into_iter()
            .chain(hosts),
        )
    }

    /// Returns what RDAP and Abusix give for the network of each host of a domain.
    ///
    /// The hosts are asked one after the other, so a second host in the network of
    /// the first is answered from the cache. A host at a private address has no
    /// network to report to, and is skipped.
    async fn host_networks(
        &self,
        domain: &DomainName,
    ) -> Vec<(Origin, Result<Vec<Contact>, Error>)> {
        let addresses = match self.resolver.addresses(domain).await {
            Ok(addresses) => addresses,
            Err(error) => return vec![(Origin::Host, Err(error))],
        };

        let mut answers = Vec::new();
        for ip in public_hosts(addresses) {
            let (rdap, abusix) = tokio::join!(self.rdap_ip(ip), self.resolver.abusix(ip));
            answers.push((Origin::Rdap, rdap));
            answers.push((Origin::Abusix, abusix));
        }
        answers
    }

    /// Returns the RDAP contacts for an address, from the cache when it holds them.
    ///
    /// The answer is held for the range the registry gives. A registry that holds no
    /// record, or gives no range that holds the address, gives nothing to hold.
    async fn rdap_ip(&self, ip: IpAddr) -> Result<Vec<Contact>, Error> {
        if let Some(contacts) = self.cache.network(ip) {
            return Ok(contacts);
        }

        let Some(record) = self.client.lookup_ip(ip).await? else {
            return Ok(Vec::new());
        };
        let contacts = record.abuse_contacts(Scope::Network);

        if let Some(range) = record.response.range()
            && range.contains(&ip)
        {
            self.cache.put_network(range, contacts.clone());
        }
        Ok(contacts)
    }

    /// Returns the RDAP contacts for a domain, from the cache when it holds them.
    ///
    /// A registry that holds no record is held too: the name is not registered.
    async fn rdap_domain(&self, domain: &DomainName) -> Result<Vec<Contact>, Error> {
        if let Some(contacts) = self.cache.domain(domain) {
            return Ok(contacts);
        }

        let contacts = self
            .client
            .lookup_domain(domain)
            .await?
            .map(|record| record.abuse_contacts(Scope::Registrar))
            .unwrap_or_default();

        self.cache.put_domain(domain.clone(), contacts.clone());
        Ok(contacts)
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
#[non_exhaustive]
pub enum Origin {
    /// RDAP, from the server the bootstrap registry names.
    Rdap,
    /// The Abusix `abuse-contacts` DNS zone.
    Abusix,
    /// The abuse.net `contacts` DNS zone.
    AbuseNet,
    /// The MX and address lookups that decide whether `abuse@` at the domain is given.
    Rfc2142,
    /// The address lookup that finds the hosts of a domain.
    Host,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Origin::Rdap => "RDAP",
            Origin::Abusix => "Abusix",
            Origin::AbuseNet => "abuse.net",
            Origin::Rfc2142 => "the RFC 2142 check",
            Origin::Host => "the address lookup of the domain",
        })
    }
}

/// Returns the hosts to ask the network sources about: the public addresses, each
/// one time, and at most [`MAX_HOSTS`] of them.
fn public_hosts(addresses: impl IntoIterator<Item = IpAddr>) -> Vec<IpAddr> {
    let mut seen = HashSet::new();
    addresses
        .into_iter()
        .map(crate::query::unmap)
        .filter(|ip| crate::is_public(*ip) && seen.insert(*ip))
        .take(MAX_HOSTS)
        .collect()
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

    fn ips(values: &[&str]) -> Vec<IpAddr> {
        values.iter().map(|value| value.parse().unwrap()).collect()
    }

    #[test]
    fn public_hosts_keeps_each_public_address_one_time() {
        let tests = [
            ("no addresses", vec![], vec![]),
            ("a repeat", vec!["8.8.8.8", "8.8.8.8"], vec!["8.8.8.8"]),
            (
                "a private and a loopback address",
                vec!["10.0.0.1", "8.8.8.8", "127.0.0.1", "::1"],
                vec!["8.8.8.8"],
            ),
            (
                "an IPv4 address in IPv6 form",
                vec!["::ffff:8.8.8.8", "8.8.8.8"],
                vec!["8.8.8.8"],
            ),
            (
                "more than the limit",
                vec!["8.8.8.1", "8.8.8.2", "8.8.8.3", "8.8.8.4", "8.8.8.5"],
                vec!["8.8.8.1", "8.8.8.2", "8.8.8.3", "8.8.8.4"],
            ),
            (
                "a private address does not count toward the limit",
                vec!["10.0.0.1", "8.8.8.1", "8.8.8.2", "8.8.8.3", "8.8.8.4"],
                vec!["8.8.8.1", "8.8.8.2", "8.8.8.3", "8.8.8.4"],
            ),
        ];

        for (name, given, want) in tests {
            assert_eq!(public_hosts(ips(&given)), ips(&want), "{name}");
        }
    }

    #[test]
    fn public_hosts_stops_reading_at_the_limit() {
        let mut read = 0;
        let addresses = ips(&["10.0.0.1", "8.8.8.1", "8.8.8.1", "8.8.8.2", "8.8.8.3"])
            .into_iter()
            .chain(ips(&["8.8.8.4", "8.8.8.5", "8.8.8.6"]))
            .inspect(|_| read += 1);

        let hosts = public_hosts(addresses);

        assert_eq!(hosts, ips(&["8.8.8.1", "8.8.8.2", "8.8.8.3", "8.8.8.4"]));
        assert_eq!(read, 6);
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
