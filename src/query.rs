//! What you can ask about.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::error::ValidationError;

/// A domain name to look up.
///
/// The constructor checks the shape only. A name that no registry holds is a lookup
/// that finds nothing, not a value this type refuses.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainName(String);

impl DomainName {
    /// The longest a domain name can be, in bytes.
    pub const MAX_BYTES: usize = 253;

    /// Wraps a domain name.
    ///
    /// The name is lowercased, and one trailing dot is removed.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::EmptyDomain`] for an empty name, and
    /// [`ValidationError::InvalidDomain`] when the name cannot be a domain name.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        let trimmed = value.trim().trim_end_matches('.').to_lowercase();

        if trimmed.is_empty() {
            return Err(ValidationError::EmptyDomain);
        }

        if let Some(problem) = Self::problem(&trimmed) {
            return Err(ValidationError::InvalidDomain {
                value: trimmed,
                problem,
            });
        }

        Ok(Self(trimmed))
    }

    /// Returns what is wrong with the name, or `None` when it is usable.
    fn problem(value: &str) -> Option<&'static str> {
        if value.len() > Self::MAX_BYTES {
            return Some("it is longer than 253 bytes");
        }
        if !value.contains('.') {
            return Some("it has no dot, so it is not a full domain name");
        }
        if value.split('.').any(|label| label.is_empty()) {
            return Some("it has an empty label");
        }
        if value.split('.').any(|label| label.len() > 63) {
            return Some("it has a label longer than 63 bytes");
        }
        if value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '@' || c == '/')
        {
            return Some("it has a character that cannot be in a domain name");
        }

        None
    }

    /// Returns the name, lowercased and without a trailing dot.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for DomainName {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The thing you want the abuse contact for.
///
/// The variant picks the sources. An IP address reaches the regional registry and the
/// blocklist zones. A domain name reaches the registry, then the registrar it names.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Query {
    /// An IP address, v4 or v6.
    Ip(IpAddr),
    /// A domain name.
    Domain(DomainName),
}

impl From<IpAddr> for Query {
    fn from(ip: IpAddr) -> Self {
        Query::Ip(ip)
    }
}

impl From<DomainName> for Query {
    fn from(domain: DomainName) -> Self {
        Query::Domain(domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercases_and_drops_the_trailing_dot() {
        assert_eq!(
            DomainName::new("Example.COM.").unwrap().as_str(),
            "example.com"
        );
    }

    #[test]
    fn rejects_an_empty_name() {
        assert_eq!(DomainName::new("   "), Err(ValidationError::EmptyDomain));
        assert_eq!(DomainName::new("."), Err(ValidationError::EmptyDomain));
    }

    #[test]
    fn rejects_names_that_cannot_be_domains() {
        for value in [
            "localhost",
            "a..b.com",
            "a b.com",
            "user@example.com",
            "example.com/path",
        ] {
            assert!(
                matches!(
                    DomainName::new(value),
                    Err(ValidationError::InvalidDomain { .. })
                ),
                "expected {value:?} to be rejected"
            );
        }
    }

    #[test]
    fn rejects_a_name_over_the_length_limit() {
        let long = format!("{}.com", "a".repeat(250));

        assert!(matches!(
            DomainName::new(long),
            Err(ValidationError::InvalidDomain {
                problem: "it is longer than 253 bytes",
                ..
            })
        ));
    }
}
