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
    ///
    /// A label holds letters, digits and hyphens only, and does not start or end with
    /// a hyphen. The name goes into a URL path as it is, so a character outside that
    /// set is a lookup for the wrong name: `foo?.com` asks for `foo` and sends `.com`
    /// as a query.
    fn problem(value: &str) -> Option<&'static str> {
        if value.len() > Self::MAX_BYTES {
            return Some("it is longer than 253 bytes");
        }
        if !value.is_ascii() {
            return Some(
                "it has a character outside ASCII. Write an international name in its \
                 xn-- form",
            );
        }
        if !value.contains('.') {
            return Some("it has no dot, so it is not a full domain name");
        }

        for label in value.split('.') {
            if label.is_empty() {
                return Some("it has an empty label");
            }
            if label.len() > 63 {
                return Some("it has a label longer than 63 bytes");
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Some("it has a character other than a letter, a digit, a hyphen or a dot");
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Some("a label starts or ends with a hyphen");
            }
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
    fn rejects_a_character_that_would_change_the_url() {
        // Each of these puts URL syntax into the path and asks for another name.
        for value in [
            "foo?.com",
            "foo#x.com",
            "foo%2f.com",
            "foo&x.com",
            "foo;x.com",
            "foo+x.com",
        ] {
            assert_eq!(
                DomainName::new(value),
                Err(ValidationError::InvalidDomain {
                    value: value.to_owned(),
                    problem: "it has a character other than a letter, a digit, a hyphen or a dot",
                }),
                "expected {value:?} to be rejected"
            );
        }
    }

    #[test]
    fn rejects_an_international_name_and_says_to_use_the_ascii_form() {
        assert_eq!(
            DomainName::new("bücher.de"),
            Err(ValidationError::InvalidDomain {
                value: "bücher.de".to_owned(),
                problem: "it has a character outside ASCII. Write an international name in \
                          its xn-- form",
            })
        );
    }

    #[test]
    fn accepts_the_ascii_form_of_an_international_name() {
        assert_eq!(
            DomainName::new("xn--bcher-kva.de").unwrap().as_str(),
            "xn--bcher-kva.de"
        );
    }

    #[test]
    fn rejects_a_label_that_starts_or_ends_with_a_hyphen() {
        for value in ["-example.com", "example-.com", "example.-com"] {
            assert!(
                matches!(
                    DomainName::new(value),
                    Err(ValidationError::InvalidDomain {
                        problem: "a label starts or ends with a hyphen",
                        ..
                    })
                ),
                "expected {value:?} to be rejected"
            );
        }
    }

    #[test]
    fn accepts_a_hyphen_inside_a_label() {
        assert_eq!(
            DomainName::new("my-shop.example.co.uk").unwrap().as_str(),
            "my-shop.example.co.uk"
        );
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
/// An IPv4 address written as IPv6, such as `::ffff:10.0.0.1`, is judged as the IPv4
/// address it carries. Without that, the IPv6 spelling of a private address would pass.
///
/// ```
/// use abuse_contact::is_public;
///
/// assert!(is_public("8.8.8.8".parse().unwrap()));
/// assert!(!is_public("192.168.1.1".parse().unwrap()));
/// assert!(!is_public("::ffff:192.168.1.1".parse().unwrap()));
/// ```
pub fn is_public(ip: IpAddr) -> bool {
    let ip = unmap(ip);
    let reserved = match ip {
        IpAddr::V4(_) => RESERVED_V4,
        IpAddr::V6(_) => RESERVED_V6,
    };

    !reserved
        .iter()
        .any(|&(network, length)| crate::prefix::contains(network, length, ip))
}

/// Returns the IPv4 address an IPv4-mapped IPv6 address carries, or the address as
/// it was.
///
/// `::ffff:8.8.8.8` and `8.8.8.8` are one host. The IPv6 registry holds no record for
/// the mapped form, so both the check and the lookup use the IPv4 form.
pub(crate) fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Writes an IPv4 network for the tables below.
const fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
}

/// Writes an IPv6 network for the tables below, from its first four segments.
const fn v6(a: u16, b: u16, c: u16, d: u16) -> IpAddr {
    IpAddr::V6(std::net::Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
}

/// IPv4 ranges that no public registry describes a host in.
///
/// From the IANA IPv4 Special-Purpose Address Registry: every range it marks as not
/// globally reachable.
const RESERVED_V4: &[(IpAddr, u8)] = &[
    (v4(0, 0, 0, 0), 8),       // "this network"
    (v4(10, 0, 0, 0), 8),      // private
    (v4(100, 64, 0, 0), 10),   // shared address space, for carrier-grade NAT
    (v4(127, 0, 0, 0), 8),     // loopback
    (v4(169, 254, 0, 0), 16),  // link-local
    (v4(172, 16, 0, 0), 12),   // private
    (v4(192, 0, 0, 0), 24),    // IETF protocol assignments
    (v4(192, 0, 2, 0), 24),    // documentation
    (v4(192, 88, 99, 0), 24),  // 6to4 relay anycast, deprecated
    (v4(192, 168, 0, 0), 16),  // private
    (v4(198, 18, 0, 0), 15),   // benchmarking
    (v4(198, 51, 100, 0), 24), // documentation
    (v4(203, 0, 113, 0), 24),  // documentation
    (v4(224, 0, 0, 0), 4),     // multicast
    (v4(240, 0, 0, 0), 4),     // reserved, and the broadcast address
];

/// IPv6 ranges that no public registry describes a host in.
///
/// From the IANA IPv6 Special-Purpose Address Registry: every range it marks as not
/// globally reachable, except `::ffff:0:0/96`. An address in that range carries an
/// IPv4 address, and [`unmap`] turns it into IPv4 before this table is read, so it is
/// judged by the IPv4 table instead.
const RESERVED_V6: &[(IpAddr, u8)] = &[
    (IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 128), // unspecified
    (IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 128),   // loopback
    (v6(0x64, 0xff9b, 1, 0), 48),                       // local-use IPv4/IPv6 translation
    (v6(0x100, 0, 0, 0), 64),                           // discard-only
    (v6(0x2001, 0, 0, 0), 23), // IETF protocol assignments, with benchmarking
    (v6(0x2001, 0xdb8, 0, 0), 32), // documentation
    (v6(0x2002, 0, 0, 0), 16), // 6to4
    (v6(0x3fff, 0, 0, 0), 20), // documentation
    (v6(0x5f00, 0, 0, 0), 16), // segment routing
    (v6(0xfc00, 0, 0, 0), 7),  // unique local
    (v6(0xfe80, 0, 0, 0), 10), // link-local
    (v6(0xff00, 0, 0, 0), 8),  // multicast
];

#[cfg(test)]
mod public_tests {
    use super::*;

    fn public(value: &str) -> bool {
        is_public(value.parse().unwrap())
    }

    #[test]
    fn a_routable_address_is_public() {
        for value in [
            "8.8.8.8",
            "193.0.6.139",
            "1.1.1.1",
            "2001:4860:4860::8888",
            "2c00::1",
            // 64:ff9b::/96 is globally reachable, unlike its local-use neighbour.
            "64:ff9b::808:808",
            // Inside 2001:200::/23, an APNIC allocation just past the IETF block.
            "2001:200::1",
        ] {
            assert!(public(value), "{value} must be public");
        }
    }

    #[test]
    fn every_reserved_ipv4_range_is_refused() {
        for value in [
            "0.1.2.3", // "this network", past 0.0.0.0 itself
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!public(value), "{value} must not be public");
        }
    }

    #[test]
    fn every_reserved_ipv6_range_is_refused() {
        for value in [
            "::",
            "::1",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",   // Teredo
            "2001:2::1", // benchmarking
            "2001:db8::1",
            "2002::1",
            "3fff::1",
            "5f00::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(!public(value), "{value} must not be public");
        }
    }

    #[test]
    fn the_edges_of_a_reserved_range_are_exact() {
        // 172.16.0.0/12 runs to 172.31.255.255.
        assert!(!public("172.16.0.0"));
        assert!(!public("172.31.255.255"));
        assert!(public("172.15.255.255"));
        assert!(public("172.32.0.0"));

        // 100.64.0.0/10 runs to 100.127.255.255.
        assert!(!public("100.127.255.255"));
        assert!(public("100.128.0.0"));
        assert!(public("100.63.255.255"));

        // 2001::/23 ends at 2001:1ff:ffff:..., and 2001:200:: is outside it.
        assert!(!public("2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff"));
        assert!(public("2001:200::"));
    }

    #[test]
    fn an_ipv4_address_written_as_ipv6_is_judged_as_ipv4() {
        // The IPv6 spelling of a private address must not get past the check.
        assert!(!public("::ffff:10.0.0.1"));
        assert!(!public("::ffff:192.168.1.1"));
        assert!(!public("::ffff:127.0.0.1"));
        // The IPv6 spelling of a public address stays public.
        assert!(public("::ffff:8.8.8.8"));
    }

    #[test]
    fn unmap_gives_the_ipv4_address_a_mapped_address_carries() {
        assert_eq!(
            unmap("::ffff:8.8.8.8".parse().unwrap()),
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            unmap("2001:4860::8888".parse().unwrap()),
            "2001:4860::8888".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            unmap("8.8.8.8".parse().unwrap()),
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
    }
}
