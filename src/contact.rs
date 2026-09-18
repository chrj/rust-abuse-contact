//! What a lookup returns: an address, what it governs, and where it came from.

use std::collections::HashSet;
use std::fmt;

use crate::error::ValidationError;

/// An email address that accepts abuse reports.
///
/// The constructor rejects the placeholder strings that registries send in place of
/// a real address, so a caller never mails `DATA REDACTED`.
///
/// ```
/// use abuse_contact::{EmailAddress, ValidationError};
///
/// assert!(EmailAddress::new("abuse@example.com").is_ok());
/// assert!(matches!(
///     EmailAddress::new("DATA REDACTED"),
///     Err(ValidationError::RedactedEmail { .. })
/// ));
/// ```
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EmailAddress(String);

/// Strings registries put in a contact field when they hide the real value.
const PLACEHOLDERS: [&str; 3] = ["REDACTED", "NOT DISCLOSED", "PLEASE QUERY"];

/// Addresses a source returns when it has no contact for the network.
///
/// One address stands for every network in the region, so it cannot be the contact
/// of any one of them. Verified against six LACNIC networks in four countries, which
/// all gave the same answer.
const WITHHELD: [&str; 1] = ["removed@lacnic.net"];

impl EmailAddress {
    /// Wraps an address that a source gave for abuse reports.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::RedactedEmail`] if the value is a registry
    /// placeholder, and [`ValidationError::InvalidEmail`] if it is not shaped like an
    /// address.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into().trim().to_owned();

        let upper = value.to_uppercase();
        if PLACEHOLDERS.iter().any(|p| upper.contains(p)) {
            return Err(ValidationError::RedactedEmail { value });
        }

        let lower = value.to_lowercase();
        if WITHHELD.contains(&lower.as_str()) {
            return Err(ValidationError::WithheldEmail { value });
        }

        let problem = Self::problem(&value);
        if let Some(problem) = problem {
            return Err(ValidationError::InvalidEmail { value, problem });
        }

        Ok(Self(value))
    }

    /// Returns what is wrong with the value, or `None` when it is usable.
    ///
    /// This is a shape check, not a proof that the mailbox exists. It rejects what
    /// cannot be an address so a bad value fails here and not in the mail queue.
    fn problem(value: &str) -> Option<&'static str> {
        if value.is_empty() {
            return Some("it is empty");
        }
        if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Some("it has a space or a control character");
        }

        let mut parts = value.split('@');
        let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
            return Some("it must have one \"@\"");
        };

        if local.is_empty() {
            return Some("there is nothing before the \"@\"");
        }
        if domain.is_empty() {
            return Some("there is nothing after the \"@\"");
        }
        if !domain.contains('.') {
            return Some("the part after the \"@\" is not a domain name");
        }

        None
    }

    /// Returns the address.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What the contact has authority over.
///
/// The three are not interchangeable. A phishing site needs the registrar to suspend
/// the name and the network to take down the host. Pick by what you want to happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// The network that holds the IP address. This contact can null-route it.
    Network,
    /// The registrar of the domain name. This contact can suspend the name.
    Registrar,
    /// The operator of the domain itself. This contact runs the service.
    Domain,
}

/// Where a contact came from.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    /// An RDAP entity with the `abuse` role, from the server named here.
    Rdap {
        /// The RDAP server that answered.
        server: String,
    },
    /// The Abusix `abuse-contacts` DNS zone.
    Abusix,
    /// The abuse.net `contacts` DNS zone.
    AbuseNet,
    /// `abuse@` at the domain, as RFC 2142 requires.
    Rfc2142,
}

impl Source {
    /// Returns how much weight to give a contact from this source, highest first.
    ///
    /// RDAP comes first because a registry publishes it and keeps it current, but it
    /// does not answer everywhere: one regional registry publishes no abuse entity.
    /// RFC 2142 comes last because the address is a guess: the RFC says the mailbox
    /// must exist, and many domains do not honour that.
    fn rank(&self) -> u8 {
        match self {
            Source::Rdap { .. } => 0,
            Source::Abusix => 1,
            Source::AbuseNet => 2,
            Source::Rfc2142 => 3,
        }
    }
}

/// One address that accepts reports, with what it governs and where it was found.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Contact {
    /// The address to write to.
    pub email: EmailAddress,
    /// What this contact has authority over.
    pub scope: Scope,
    /// Where the address came from.
    pub source: Source,
}

/// Sorts contacts by source rank, then by address, and drops repeats.
///
/// The same address often comes from more than one source. The caller wants a list
/// to read from the top, not the same mailbox four times.
pub fn rank(mut contacts: Vec<Contact>) -> Vec<Contact> {
    contacts.sort_by(|a, b| {
        a.source
            .rank()
            .cmp(&b.source.rank())
            .then_with(|| a.scope.cmp(&b.scope))
            .then_with(|| a.email.cmp(&b.email))
    });
    // After the sort, the first contact for an address and scope is the one from the
    // best source. A repeat can come after contacts from the same source, so it is not
    // always next to the first one.
    let mut seen = HashSet::new();
    contacts.retain(|contact| seen.insert((contact.email.clone(), contact.scope)));
    contacts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(email: &str, scope: Scope, source: Source) -> Contact {
        Contact {
            email: EmailAddress::new(email).unwrap(),
            scope,
            source,
        }
    }

    #[test]
    fn accepts_a_plain_address() {
        assert_eq!(
            EmailAddress::new("network-abuse@google.com")
                .unwrap()
                .as_str(),
            "network-abuse@google.com"
        );
    }

    #[test]
    fn trims_surrounding_space() {
        assert_eq!(
            EmailAddress::new("  abuse@example.com\n").unwrap().as_str(),
            "abuse@example.com"
        );
    }

    #[test]
    fn rejects_registry_placeholders() {
        for value in [
            "DATA REDACTED",
            "REDACTED FOR PRIVACY",
            "Not Disclosed",
            "please query the RDDS service of the Registrar of Record",
        ] {
            assert!(
                matches!(
                    EmailAddress::new(value),
                    Err(ValidationError::RedactedEmail { .. })
                ),
                "expected {value:?} to be rejected as a placeholder"
            );
        }
    }

    #[test]
    fn rejects_the_address_a_source_sends_when_it_has_no_contact() {
        for value in ["removed@lacnic.net", "REMOVED@LACNIC.NET"] {
            assert!(
                matches!(
                    EmailAddress::new(value),
                    Err(ValidationError::WithheldEmail { .. })
                ),
                "expected {value:?} to be rejected"
            );
        }
    }

    #[test]
    fn keeps_a_real_address_at_the_same_domain() {
        assert!(EmailAddress::new("ipadmin@lacnic.net").is_ok());
    }

    #[test]
    fn rejects_values_that_are_not_addresses() {
        for value in [
            "",
            "abuse",
            "abuse@",
            "@example.com",
            "a@b@c.com",
            "abuse@localhost",
        ] {
            assert!(
                matches!(
                    EmailAddress::new(value),
                    Err(ValidationError::InvalidEmail { .. })
                ),
                "expected {value:?} to be rejected"
            );
        }
    }

    #[test]
    fn rank_puts_rdap_first_and_rfc2142_last() {
        let ranked = rank(vec![
            contact("abuse@example.com", Scope::Domain, Source::Rfc2142),
            contact("noc@example.com", Scope::Network, Source::Abusix),
            contact(
                "registrar-abuse@example.com",
                Scope::Registrar,
                Source::Rdap {
                    server: "rdap.example.com".to_owned(),
                },
            ),
        ]);

        let got: Vec<&str> = ranked.iter().map(|c| c.email.as_str()).collect();

        assert_eq!(
            got,
            [
                "registrar-abuse@example.com",
                "noc@example.com",
                "abuse@example.com"
            ]
        );
    }

    #[test]
    fn rank_drops_the_same_address_in_the_same_scope() {
        let ranked = rank(vec![
            contact("abuse@example.com", Scope::Network, Source::Abusix),
            contact("abuse@example.com", Scope::Network, Source::AbuseNet),
        ]);

        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].source, Source::Abusix);
    }

    #[test]
    fn rank_drops_a_repeat_with_another_address_between() {
        let rdap = || Source::Rdap {
            server: "rdap.example".to_owned(),
        };
        let ranked = rank(vec![
            contact("abuse@example.com", Scope::Network, Source::Abusix),
            contact("abuse@example.com", Scope::Network, rdap()),
            contact("noc@example.com", Scope::Network, rdap()),
        ]);

        assert_eq!(
            ranked,
            [
                contact("abuse@example.com", Scope::Network, rdap()),
                contact("noc@example.com", Scope::Network, rdap()),
            ]
        );
    }

    #[test]
    fn rank_keeps_the_same_address_in_a_different_scope() {
        let ranked = rank(vec![
            contact("abuse@example.com", Scope::Network, Source::Abusix),
            contact("abuse@example.com", Scope::Domain, Source::Rfc2142),
        ]);

        assert_eq!(ranked.len(), 2);
    }
}
