//! The DNS sources: the Abusix and abuse.net zones, and the mail host of a domain.
//!
//! [`crate::dns`] builds the names to ask for and reads the answers. This module asks.

use std::net::{IpAddr, SocketAddr};

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;

use crate::contact::{Contact, Scope, Source};
use crate::dns;
use crate::error::Error;
use crate::query::DomainName;

/// Looks up the DNS sources.
///
/// Build one and keep it. It holds the resolver configuration and a cache of answers.
///
/// ```no_run
/// use abuse_contact::Resolver;
///
/// # async fn run() -> Result<(), abuse_contact::Error> {
/// let resolver = Resolver::new()?;
///
/// // AFRINIC publishes no abuse contact in RDAP. Abusix has one.
/// for contact in resolver.abusix("196.216.2.1".parse().unwrap()).await? {
///     println!("{} ({:?})", contact.email, contact.scope);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Resolver {
    inner: TokioResolver,
}

impl Resolver {
    /// Returns a resolver that uses the resolver configuration of the system.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Dns`] when the system configuration cannot be read.
    pub fn new() -> Result<Self, Error> {
        let inner = TokioResolver::builder_tokio()
            .and_then(|builder| builder.build())
            .map_err(|source| dns_error("the system resolver configuration", source))?;

        Ok(Self { inner })
    }

    /// Returns a resolver that asks these nameservers, over UDP and TCP.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Dns`] when the resolver cannot be built.
    pub fn with_nameservers(nameservers: &[SocketAddr]) -> Result<Self, Error> {
        let servers = nameservers
            .iter()
            .map(|address| {
                let mut server = NameServerConfig::udp_and_tcp(address.ip());
                for connection in &mut server.connections {
                    connection.port = address.port();
                }
                server
            })
            .collect();

        let config = ResolverConfig::from_parts(None, Vec::new(), servers);
        let inner = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .build()
            .map_err(|source| dns_error("the nameservers given", source))?;

        Ok(Self { inner })
    }

    /// Returns the contacts Abusix gives for the network that holds an address.
    ///
    /// Abusix answers for AFRINIC space, where RDAP publishes no abuse entity.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotPublic`] for a private or reserved address, and
    /// [`Error::Dns`] when the lookup does not finish.
    pub async fn abusix(&self, ip: IpAddr) -> Result<Vec<Contact>, Error> {
        // The zone has no record for the IPv6 spelling of an IPv4 address, and a
        // private address has no network to report to.
        let ip = crate::query::unmap(ip);
        if !crate::is_public(ip) {
            return Err(Error::NotPublic {
                target: ip.to_string(),
            });
        }

        let records = self.txt(&dns::abusix_name(ip)).await?;
        Ok(dns::contacts_from_txt(
            &records,
            Scope::Network,
            Source::Abusix,
        ))
    }

    /// Returns the contacts abuse.net gives for a domain.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Dns`] when the lookup does not finish.
    pub async fn abuse_net(&self, domain: &DomainName) -> Result<Vec<Contact>, Error> {
        // A long domain with the zone appended is longer than DNS allows. The zone
        // cannot hold that name, and the resolver refuses to ask for it.
        let name = dns::abuse_net_name(domain);
        if name.len() > DomainName::MAX_BYTES {
            return Ok(Vec::new());
        }

        let records = self.txt(&name).await?;
        Ok(dns::contacts_from_txt(
            &records,
            Scope::Domain,
            Source::AbuseNet,
        ))
    }

    /// Returns `abuse@` at the domain, when the domain takes mail.
    ///
    /// RFC 2142 requires the mailbox, and many domains do not have it, so the address
    /// is a guess. A domain that takes no mail cannot have it at all, and gives `None`:
    /// a name that does not exist, a null MX, or no MX and no address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Dns`] when a lookup does not finish.
    pub async fn rfc2142(&self, domain: &DomainName) -> Result<Option<Contact>, Error> {
        let name = absolute(domain.as_str());

        let exchanges: Vec<String> = match self.inner.mx_lookup(name.as_str()).await {
            Ok(lookup) => lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::MX(mx) => Some(mx.exchange.to_string()),
                    _ => None,
                })
                .collect(),
            Err(error) if error.is_nx_domain() => return Ok(None),
            Err(error) if error.is_no_records_found() => Vec::new(),
            Err(source) => return Err(dns_error(&name, source)),
        };

        let takes_mail = if exchanges.is_empty() {
            // RFC 5321 section 5.1: with no MX, mail goes to the address of the domain.
            self.has_address(&name).await?
        } else {
            dns::names_a_mail_host(exchanges.iter().map(String::as_str))
        };
        if !takes_mail {
            return Ok(None);
        }

        dns::rfc2142_contact(domain).map(Some).map_err(Error::from)
    }

    /// Returns the TXT records at a name, each as one string.
    ///
    /// A name that does not exist, or has no TXT records, gives no records. That is
    /// an answer, not a failure. A record that is not UTF-8 is dropped.
    async fn txt(&self, name: &str) -> Result<Vec<String>, Error> {
        let name = absolute(name);

        match self.inner.txt_lookup(name.as_str()).await {
            Ok(lookup) => Ok(lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::TXT(txt) => txt_value(&txt.txt_data),
                    _ => None,
                })
                .collect()),
            Err(error) if error.is_no_records_found() => Ok(Vec::new()),
            Err(source) => Err(dns_error(&name, source)),
        }
    }

    /// Returns whether a name has an IPv4 or IPv6 address.
    async fn has_address(&self, name: &str) -> Result<bool, Error> {
        match self.inner.lookup_ip(name).await {
            Ok(lookup) => Ok(lookup.iter().next().is_some()),
            Err(error) if error.is_no_records_found() => Ok(false),
            Err(source) => Err(dns_error(name, source)),
        }
    }
}

/// Returns the name with one trailing dot, so the resolver asks for it as it is.
///
/// Without the dot, a name that does not exist is asked for again with each search
/// domain of the system appended, and a zone of the local network could answer.
fn absolute(name: &str) -> String {
    format!("{}.", name.trim_end_matches('.'))
}

/// Joins the character strings of one TXT record into its value.
///
/// A value longer than 255 bytes is sent as more than one string, and the strings
/// together are the value. A string can end in the middle of a character, so the
/// bytes are joined before they are read as UTF-8. Returns `None` when the value is
/// not UTF-8.
fn txt_value(strings: &[Box<[u8]>]) -> Option<String> {
    String::from_utf8(strings.concat()).ok()
}

/// Returns the error for a lookup that did not finish.
fn dns_error(name: &str, source: NetError) -> Error {
    Error::Dns {
        name: name.to_owned(),
        source: Box::new(source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_gets_the_trailing_dot_that_keeps_it_from_a_search_domain() {
        assert_eq!(
            absolute("229.132.16.104.abuse-contacts.abusix.zone"),
            "229.132.16.104.abuse-contacts.abusix.zone."
        );
        assert_eq!(absolute("example.com."), "example.com.");
    }

    #[test]
    fn the_strings_of_a_record_join_into_its_value() {
        let strings: Vec<Box<[u8]>> = vec![
            b"arin-contact@google.com,".to_vec().into_boxed_slice(),
            b"network-abuse@google.com".to_vec().into_boxed_slice(),
        ];

        assert_eq!(
            txt_value(&strings),
            Some("arin-contact@google.com,network-abuse@google.com".to_owned())
        );
    }

    #[test]
    fn a_character_split_across_two_strings_is_kept_whole() {
        // "\xc3\xa6" is "æ" in UTF-8.
        let strings: Vec<Box<[u8]>> = vec![
            b"abuse@ex\xc3".to_vec().into_boxed_slice(),
            b"\xa6mple.com".to_vec().into_boxed_slice(),
        ];

        assert_eq!(txt_value(&strings), Some("abuse@exæmple.com".to_owned()));
    }

    #[test]
    fn a_record_that_is_not_utf8_has_no_value() {
        let strings: Vec<Box<[u8]>> = vec![b"abuse@\xffexample.com".to_vec().into_boxed_slice()];

        assert_eq!(txt_value(&strings), None);
    }
}
