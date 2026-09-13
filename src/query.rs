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

/// Returns whether the public registries describe this address.
///
/// A private, reserved or documentation address sits inside a range that a regional
/// registry still holds a record for. Asking about `192.168.1.1` returns the record
/// for the reserved block, whose abuse contact is IANA. That address is a real one and
/// a wrong one: nobody at IANA can act on a host inside your network, and a report
/// sent there is noise.
///
/// ```
/// use abuse_contact::is_public;
///
/// assert!(is_public("8.8.8.8".parse().unwrap()));
/// assert!(!is_public("192.168.1.1".parse().unwrap()));
/// ```
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => is_public_v6(ip),
    }
}

/// Returns whether an IPv4 address is one the registries describe.
///
/// The ranges come from the IANA IPv4 Special-Purpose Address Registry. The standard
/// library covers most of them, and the rest are written out here because their
/// helpers are not on stable Rust.
fn is_public_v4(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();

    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_documentation()
        || ip.is_broadcast()
        || ip.is_multicast()
        // 100.64.0.0/10, the shared range for carrier-grade NAT.
        || (a == 100 && (64..128).contains(&b))
        // 192.0.0.0/24, IETF protocol assignments.
        || (a == 192 && b == 0 && ip.octets()[2] == 0)
        // 198.18.0.0/15, for benchmarking.
        || (a == 198 && (b == 18 || b == 19))
        // 240.0.0.0/4, reserved.
        || a >= 240)
}

/// Returns whether an IPv6 address is one the registries describe.
fn is_public_v6(ip: std::net::Ipv6Addr) -> bool {
    let segments = ip.segments();

    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        // fc00::/7, unique local addresses.
        || (segments[0] & 0xfe00) == 0xfc00
        // fe80::/10, link-local addresses.
        || (segments[0] & 0xffc0) == 0xfe80
        // 2001:db8::/32, for documentation.
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

#[cfg(test)]
mod public_tests {
    use super::*;

    #[test]
    fn a_routable_address_is_public() {
        for value in [
            "8.8.8.8",
            "193.0.6.139",
            "1.1.1.1",
            "2001:4860:4860::8888",
            "2c00::1",
        ] {
            assert!(is_public(value.parse().unwrap()), "{value} must be public");
        }
    }

    #[test]
    fn an_address_the_registries_do_not_describe_is_not_public() {
        for value in [
            "0.0.0.0",         // unspecified
            "10.1.2.3",        // private
            "172.16.0.1",      // private
            "192.168.1.1",     // private
            "127.0.0.1",       // loopback
            "169.254.1.1",     // link-local
            "100.64.0.1",      // carrier-grade NAT
            "192.0.0.1",       // protocol assignments
            "192.0.2.1",       // documentation
            "198.18.0.1",      // benchmarking
            "198.51.100.1",    // documentation
            "203.0.113.1",     // documentation
            "240.0.0.1",       // reserved
            "255.255.255.255", // broadcast
            "224.0.0.1",       // multicast
            "::",              // unspecified
            "::1",             // loopback
            "fc00::1",         // unique local
            "fd12:3456::1",    // unique local
            "fe80::1",         // link-local
            "2001:db8::1",     // documentation
            "ff02::1",         // multicast
        ] {
            assert!(
                !is_public(value.parse().unwrap()),
                "{value} must not be public"
            );
        }
    }
}
