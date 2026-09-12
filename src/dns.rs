//! The DNS sources: Abusix, abuse.net, and the RFC 2142 fallback.
//!
//! Every function here builds a name to ask for, or reads what came back. None of
//! them talk to a resolver. The caller does the lookup and brings the answer, so the
//! part that decides what an answer means runs in a test without a network.

use std::net::IpAddr;

use crate::contact::{Contact, EmailAddress, Scope, Source};
use crate::query::DomainName;

/// The Abusix zone that maps an IP address to the contact for its network.
pub const ABUSIX_ZONE: &str = "abuse-contacts.abusix.zone";

/// The abuse.net zone that maps a domain to the contact its operator registered.
pub const ABUSE_NET_ZONE: &str = "contacts.abuse.net";

const HEX: [u8; 16] = *b"0123456789abcdef";

/// Returns the name to ask Abusix for this address.
///
/// The address goes in backwards, the way a blocklist zone wants it: octets for v4,
/// nibbles for v6.
///
/// ```
/// use abuse_contact::dns::abusix_name;
///
/// assert_eq!(
///     abusix_name("104.16.132.229".parse().unwrap()),
///     "229.132.16.104.abuse-contacts.abusix.zone"
/// );
/// ```
pub fn abusix_name(ip: IpAddr) -> String {
    let mut name = String::new();

    match ip {
        IpAddr::V4(v4) => {
            for octet in v4.octets().iter().rev() {
                name.push_str(&octet.to_string());
                name.push('.');
            }
        }
        IpAddr::V6(v6) => {
            for byte in v6.octets().iter().rev() {
                name.push(HEX[(byte & 0x0f) as usize] as char);
                name.push('.');
                name.push(HEX[(byte >> 4) as usize] as char);
                name.push('.');
            }
        }
    }

    name.push_str(ABUSIX_ZONE);
    name
}

/// Returns the name to ask abuse.net for this domain.
///
/// ```
/// use abuse_contact::dns::abuse_net_name;
///
/// let domain = "google.com".parse().unwrap();
/// assert_eq!(abuse_net_name(&domain), "google.com.contacts.abuse.net");
/// ```
pub fn abuse_net_name(domain: &DomainName) -> String {
    format!("{}.{}", domain.as_str(), ABUSE_NET_ZONE)
}

/// Returns the address RFC 2142 says every domain must accept reports at.
///
/// This is a guess. The RFC requires the mailbox, and many domains do not have it.
/// Treat a contact from here as the last thing to try.
///
/// # Errors
///
/// Returns [`crate::ValidationError`] when `abuse@` at this domain is not a usable
/// address.
pub fn rfc2142_contact(domain: &DomainName) -> Result<Contact, crate::ValidationError> {
    Ok(Contact {
        email: EmailAddress::new(format!("abuse@{}", domain.as_str()))?,
        scope: Scope::Domain,
        source: Source::Rfc2142,
    })
}

/// Reads the addresses out of the TXT records a zone returned.
///
/// A record can hold more than one address, joined by commas. A value that is not an
/// address is dropped: these zones are a best effort, and one bad record must not
/// lose the good ones beside it.
pub fn contacts_from_txt(records: &[String], scope: Scope, source: Source) -> Vec<Contact> {
    records
        .iter()
        .flat_map(|record| record.split(','))
        .filter_map(|value| EmailAddress::new(value).ok())
        .map(|email| Contact {
            email,
            scope,
            source: source.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_abusix_name_for_v4() {
        assert_eq!(
            abusix_name("104.16.132.229".parse().unwrap()),
            "229.132.16.104.abuse-contacts.abusix.zone"
        );
    }

    #[test]
    fn builds_the_abusix_name_for_v6() {
        assert_eq!(
            abusix_name("2001:4860:4860::8888".parse().unwrap()),
            "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.\
             abuse-contacts.abusix.zone"
        );
    }

    #[test]
    fn builds_the_abuse_net_name() {
        let domain = "Google.com.".parse().unwrap();

        assert_eq!(abuse_net_name(&domain), "google.com.contacts.abuse.net");
    }

    #[test]
    fn builds_the_rfc2142_address() {
        let domain = "example.com".parse().unwrap();
        let contact = rfc2142_contact(&domain).unwrap();

        assert_eq!(contact.email.as_str(), "abuse@example.com");
        assert_eq!(contact.scope, Scope::Domain);
        assert_eq!(contact.source, Source::Rfc2142);
    }

    #[test]
    fn splits_a_record_that_holds_more_than_one_address() {
        let records = vec!["arin-contact@google.com,network-abuse@google.com".to_owned()];

        let got = contacts_from_txt(&records, Scope::Network, Source::Abusix);
        let emails: Vec<&str> = got.iter().map(|c| c.email.as_str()).collect();

        assert_eq!(
            emails,
            ["arin-contact@google.com", "network-abuse@google.com"]
        );
    }

    #[test]
    fn drops_a_record_that_is_not_an_address() {
        let records = vec!["not-an-address".to_owned(), "abuse@example.com".to_owned()];

        let got = contacts_from_txt(&records, Scope::Network, Source::Abusix);
        let emails: Vec<&str> = got.iter().map(|c| c.email.as_str()).collect();

        assert_eq!(emails, ["abuse@example.com"]);
    }

    #[test]
    fn returns_nothing_when_the_zone_had_no_records() {
        assert_eq!(
            contacts_from_txt(&[], Scope::Network, Source::Abusix),
            Vec::new()
        );
    }
}
