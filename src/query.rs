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
/// An IPv4 address written as IPv6 is judged as the IPv4 address it carries. That is
/// an IPv4-mapped address such as `::ffff:10.0.0.1`, and an address under the NAT64
/// well-known prefix such as `64:ff9b::a00:1`. Without that, the IPv6 spelling of a
/// private address would pass.
///
/// ```
/// use abuse_contact::is_public;
///
/// assert!(is_public("8.8.8.8".parse().unwrap()));
/// assert!(!is_public("192.168.1.1".parse().unwrap()));
/// assert!(!is_public("::ffff:192.168.1.1".parse().unwrap()));
/// assert!(!is_public("64:ff9b::a9fe:a9fe".parse().unwrap()));
/// // A globally reachable anycast address inside a reserved block.
/// assert!(is_public("192.0.0.9".parse().unwrap()));
/// ```
pub fn is_public(ip: IpAddr) -> bool {
    let ip = unmap(ip);
    let table = match ip {
        IpAddr::V4(_) => SPECIAL_V4,
        IpAddr::V6(_) => SPECIAL_V6,
    };

    // An address in no special-purpose range is an ordinary allocation.
    most_specific(table, ip).is_none_or(|reach| reach == Reach::Global)
}

/// Returns the reach of the most specific range in the table that holds the address.
///
/// The registry nests ranges: `192.0.0.9/32` is globally reachable inside
/// `192.0.0.0/24`, which is not. The most specific row is the one that applies.
fn most_specific(table: &[(&str, Reach)], ip: IpAddr) -> Option<Reach> {
    table
        .iter()
        .filter_map(|&(range, reach)| {
            let (network, length) = crate::prefix::parse_range(range)?;
            crate::prefix::contains(network, length, ip).then_some((length, reach))
        })
        .max_by_key(|&(length, _)| length)
        .map(|(_, reach)| reach)
}

/// Returns the IPv4 address an IPv6 address carries in a fixed place, or the address
/// as it was.
///
/// Two forms carry one in a place that does not depend on the network: an IPv4-mapped
/// address such as `::ffff:8.8.8.8`, and an address under the NAT64 well-known prefix
/// such as `64:ff9b::808:808`. Each is one host with `8.8.8.8`, and no registry holds
/// a record for the IPv6 form, so both the check and the lookup use the IPv4 form.
pub(crate) fn unmap(ip: IpAddr) -> IpAddr {
    let IpAddr::V6(v6) = ip else {
        return ip;
    };

    if let Some(v4) = v6.to_ipv4_mapped() {
        return IpAddr::V4(v4);
    }

    let (prefix, length) = crate::nat64::WELL_KNOWN_PREFIX;
    if crate::prefix::contains(IpAddr::V6(prefix), length, ip)
        && let Some(v4) = crate::nat64::embedded_ipv4(v6, length)
    {
        return IpAddr::V4(v4);
    }

    ip
}

/// Whether the special-purpose registry marks a range as globally reachable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reach {
    /// The registry says `True`. A registry describes hosts in the range.
    Global,
    /// The registry says `False`, `N/A`, or gives no answer for a deprecated range.
    ///
    /// `N/A` is on ranges such as 6to4 and Teredo, which carry another address inside
    /// them. The range has no single owner to report to, so it is not public here.
    NotGlobal,
}

use Reach::{Global, NotGlobal};

/// The IANA IPv4 Special-Purpose Address Registry, one row per address block.
///
/// Copied from `iana-ipv4-special-registry-1.csv`. The last row is not in that
/// registry: it is the multicast range, from the multicast address registry.
const SPECIAL_V4: &[(&str, Reach)] = &[
    ("0.0.0.0/8", NotGlobal),
    ("0.0.0.0/32", NotGlobal),
    ("10.0.0.0/8", NotGlobal),
    ("100.64.0.0/10", NotGlobal),
    ("127.0.0.0/8", NotGlobal),
    ("169.254.0.0/16", NotGlobal),
    ("172.16.0.0/12", NotGlobal),
    ("192.0.0.0/24", NotGlobal),
    ("192.0.0.0/29", NotGlobal),
    ("192.0.0.8/32", NotGlobal),
    ("192.0.0.9/32", Global),
    ("192.0.0.10/32", Global),
    ("192.0.0.170/32", NotGlobal),
    ("192.0.0.171/32", NotGlobal),
    ("192.0.2.0/24", NotGlobal),
    ("192.31.196.0/24", Global),
    ("192.52.193.0/24", Global),
    ("192.88.99.0/24", NotGlobal), // deprecated, no answer in the registry
    ("192.88.99.2/32", NotGlobal),
    ("192.168.0.0/16", NotGlobal),
    ("192.175.48.0/24", Global),
    ("198.18.0.0/15", NotGlobal),
    ("198.51.100.0/24", NotGlobal),
    ("203.0.113.0/24", NotGlobal),
    ("240.0.0.0/4", NotGlobal),
    ("255.255.255.255/32", NotGlobal),
    ("224.0.0.0/4", NotGlobal),
];

/// The IANA IPv6 Special-Purpose Address Registry, one row per address block.
///
/// Copied from `iana-ipv6-special-registry-1.csv`, with two rows left out and one
/// added. `::ffff:0:0/96` and `64:ff9b::/96` are left out: [`unmap`] turns an address
/// in either into IPv4 before this table is read, so the IPv4 table judges it. The last
/// row is not in that registry: it is the multicast range, from the multicast address
/// registry.
const SPECIAL_V6: &[(&str, Reach)] = &[
    ("::1/128", NotGlobal),
    ("::/128", NotGlobal),
    ("64:ff9b:1::/48", NotGlobal),
    ("100::/64", NotGlobal),
    ("100:0:0:1::/64", NotGlobal),
    ("2001::/23", NotGlobal),
    ("2001::/32", NotGlobal), // Teredo, N/A in the registry
    ("2001:1::1/128", Global),
    ("2001:1::2/128", Global),
    ("2001:1::3/128", Global),
    ("2001:2::/48", NotGlobal),
    ("2001:3::/32", Global),
    ("2001:4:112::/48", Global),
    ("2001:10::/28", NotGlobal), // deprecated, no answer in the registry
    ("2001:20::/28", Global),
    ("2001:30::/28", Global),
    ("2001:db8::/32", NotGlobal),
    ("2002::/16", NotGlobal), // 6to4, N/A in the registry
    ("2620:4f:8000::/48", Global),
    ("3fff::/20", NotGlobal),
    ("5f00::/16", NotGlobal),
    ("fc00::/7", NotGlobal),
    ("fe80::/10", NotGlobal),
    ("ff00::/8", NotGlobal),
];

#[cfg(test)]
mod public_tests {
    use super::*;

    fn public(value: &str) -> bool {
        is_public(value.parse().unwrap())
    }

    #[test]
    fn every_row_of_the_tables_is_a_range() {
        // most_specific skips a row it cannot read. This keeps that from happening.
        for &(range, _) in SPECIAL_V4.iter().chain(SPECIAL_V6) {
            assert!(
                crate::prefix::parse_range(range).is_some(),
                "{range:?} is not a range"
            );
        }
    }

    #[test]
    fn every_row_is_of_the_family_of_its_table() {
        for &(range, _) in SPECIAL_V4 {
            let (network, _) = crate::prefix::parse_range(range).unwrap();
            assert!(network.is_ipv4(), "{range} is in the IPv4 table");
        }
        for &(range, _) in SPECIAL_V6 {
            let (network, _) = crate::prefix::parse_range(range).unwrap();
            assert!(network.is_ipv6(), "{range} is in the IPv6 table");
        }
    }

    #[test]
    fn a_routable_address_is_public() {
        for value in [
            "8.8.8.8",
            "193.0.6.139",
            "1.1.1.1",
            "2001:4860:4860::8888",
            "2c00::1",
            "64:ff9b::808:808",
            "2001:200::1",
        ] {
            assert!(public(value), "{value} must be public");
        }
    }

    #[test]
    fn every_ipv4_range_that_is_not_globally_reachable_is_refused() {
        for value in [
            "0.1.2.3",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.0.8",
            "192.0.0.11",
            "192.0.0.170",
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
    fn every_ipv6_range_that_is_not_globally_reachable_is_refused() {
        for value in [
            "::",
            "::1",
            "64:ff9b:1::1",
            "100::1",
            "100:0:0:1::1",
            "2001::1",
            "2001:1::4",
            "2001:2::1",
            "2001:10::1",
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
    fn a_globally_reachable_ipv4_address_inside_a_reserved_block_is_public() {
        // 192.0.0.0/24 is not globally reachable, but these two anycast addresses are.
        assert!(public("192.0.0.9"), "Port Control Protocol anycast");
        assert!(public("192.0.0.10"), "TURN anycast");
    }

    #[test]
    fn a_globally_reachable_ipv6_range_inside_the_ietf_block_is_public() {
        // 2001::/23 is not globally reachable, but each of these is.
        for (value, name) in [
            ("2001:1::1", "Port Control Protocol anycast"),
            ("2001:1::2", "TURN anycast"),
            ("2001:1::3", "DNS-SD Service Registration Protocol anycast"),
            ("2001:3::1", "AMT"),
            ("2001:4:112::1", "AS112-v6"),
            ("2001:20::1", "ORCHIDv2"),
            ("2001:30::1", "Drone Remote ID"),
        ] {
            assert!(public(value), "{value} ({name}) must be public");
        }
    }

    #[test]
    fn the_edges_of_a_reserved_range_are_exact() {
        assert!(!public("172.16.0.0"));
        assert!(!public("172.31.255.255"));
        assert!(public("172.15.255.255"));
        assert!(public("172.32.0.0"));

        assert!(!public("100.127.255.255"));
        assert!(public("100.128.0.0"));
        assert!(public("100.63.255.255"));

        assert!(!public("2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff"));
        assert!(public("2001:200::"));

        // The edges of a globally reachable range inside a reserved one.
        assert!(public("2001:3::"));
        assert!(public("2001:3:ffff:ffff:ffff:ffff:ffff:ffff"));
        assert!(!public("2001:4::"));
    }

    #[test]
    fn an_address_under_the_nat64_well_known_prefix_is_judged_as_ipv4() {
        // A DNS64 network answers these for a name whose only address is the IPv4 one
        // inside, and its NAT64 gateway connects to that IPv4 address.
        assert!(
            !public("64:ff9b::a9fe:a9fe"),
            "169.254.169.254, cloud metadata"
        );
        assert!(!public("64:ff9b::7f00:1"), "127.0.0.1");
        assert!(!public("64:ff9b::a00:1"), "10.0.0.1");
        assert!(public("64:ff9b::808:808"), "8.8.8.8");
    }

    #[test]
    fn unmap_reads_the_nat64_well_known_prefix() {
        assert_eq!(
            unmap("64:ff9b::808:808".parse().unwrap()),
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
        // The local-use NAT64 prefix is not read here: its layout depends on the network.
        assert_eq!(
            unmap("64:ff9b:1::808:808".parse().unwrap()),
            "64:ff9b:1::808:808".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn an_ipv4_address_written_as_ipv6_is_judged_as_ipv4() {
        assert!(!public("::ffff:10.0.0.1"));
        assert!(!public("::ffff:192.168.1.1"));
        assert!(!public("::ffff:127.0.0.1"));
        assert!(public("::ffff:8.8.8.8"));
        assert!(public("::ffff:192.0.0.9"));
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
