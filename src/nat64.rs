//! IPv4 addresses carried inside IPv6 addresses by NAT64, as RFC 6052 describes.
//!
//! On a network with DNS64, a name that has only an IPv4 address resolves to an IPv6
//! address: a NAT64 prefix with the IPv4 address inside it. The network translates a
//! connection to that IPv6 address back to the IPv4 one. An address check that reads
//! only the IPv6 address sees a public prefix and passes a connection that ends at a
//! private IPv4 address. The functions here find the IPv4 address inside.
//!
//! Reading the well-known prefix needs nothing from the network, and the address check
//! uses it in every build. Learning a prefix the network chose, and reading an address
//! under it, is for the resolver of the client, so it needs the `http` feature.

use std::net::{Ipv4Addr, Ipv6Addr};

/// The NAT64 well-known prefix, `64:ff9b::/96`, from RFC 6052.
///
/// Every network that uses it puts the IPv4 address in the last 32 bits, so an
/// address under it is read without learning anything about the network.
pub(crate) const WELL_KNOWN_PREFIX: (Ipv6Addr, u8) =
    (Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96);

#[cfg(feature = "http")]
/// The name RFC 7050 gives for learning the NAT64 prefix of a network.
pub(crate) const DISCOVERY_NAME: &str = "ipv4only.arpa";

#[cfg(feature = "http")]
/// The two IPv4 addresses `ipv4only.arpa` has, from RFC 7050.
const DISCOVERY_ADDRESSES: [Ipv4Addr; 2] =
    [Ipv4Addr::new(192, 0, 0, 170), Ipv4Addr::new(192, 0, 0, 171)];

#[cfg(feature = "http")]
/// The prefix lengths RFC 6052 allows.
const PREFIX_LENGTHS: [u8; 6] = [32, 40, 48, 56, 64, 96];

/// Returns the IPv4 address inside an address, for a NAT64 prefix of this length.
///
/// RFC 6052 section 2.2 places the 32 bits of the IPv4 address after the prefix, and
/// for a prefix shorter than 96 bits it skips bits 64 to 71, which must be zero. The
/// byte positions below are that layout. A length RFC 6052 does not allow gives
/// `None`, and so does a shorter prefix whose bits 64 to 71 are not zero.
pub(crate) fn embedded_ipv4(address: Ipv6Addr, length: u8) -> Option<Ipv4Addr> {
    let b = address.octets();

    // Byte 8 holds bits 64 to 71. It sits inside the IPv4 address for every length
    // but 96, and it must be zero.
    if length < 96 && b[8] != 0 {
        return None;
    }

    let v4 = match length {
        32 => [b[4], b[5], b[6], b[7]],
        40 => [b[5], b[6], b[7], b[9]],
        48 => [b[6], b[7], b[9], b[10]],
        56 => [b[7], b[9], b[10], b[11]],
        64 => [b[9], b[10], b[11], b[12]],
        96 => [b[12], b[13], b[14], b[15]],
        _ => return None,
    };

    Some(Ipv4Addr::from(v4))
}

#[cfg(feature = "http")]
/// Returns the NAT64 prefixes that the IPv6 addresses of `ipv4only.arpa` show.
///
/// RFC 7050 section 3: an IPv6 address for that name is a NAT64 prefix with one of
/// the two known IPv4 addresses inside. Where one of them sits gives the length, and
/// the bits before it give the prefix. An address with neither inside shows no prefix.
pub(crate) fn prefixes_from_discovery(addresses: &[Ipv6Addr]) -> Vec<(Ipv6Addr, u8)> {
    let mut prefixes = Vec::new();

    for &address in addresses {
        for length in PREFIX_LENGTHS {
            let Some(v4) = embedded_ipv4(address, length) else {
                continue;
            };
            if !DISCOVERY_ADDRESSES.contains(&v4) {
                continue;
            }
            let prefix = (keep_prefix(address, length), length);
            if !prefixes.contains(&prefix) {
                prefixes.push(prefix);
            }
        }
    }

    prefixes
}

#[cfg(feature = "http")]
/// Returns the address with every bit after the prefix set to zero.
fn keep_prefix(address: Ipv6Addr, length: u8) -> Ipv6Addr {
    let bits = u128::from(address);
    let mask = u128::MAX.checked_shl(u32::from(128 - length)).unwrap_or(0);
    Ipv6Addr::from(bits & mask)
}

#[cfg(feature = "http")]
/// Returns every IPv4 address that a connection to this address can end at.
///
/// The well-known prefix is always read. A discovered prefix is read when it holds
/// the address. An address under no NAT64 prefix carries no IPv4 address, and the
/// list is empty.
pub(crate) fn translations(address: Ipv6Addr, discovered: &[(Ipv6Addr, u8)]) -> Vec<Ipv4Addr> {
    std::iter::once(WELL_KNOWN_PREFIX)
        .chain(discovered.iter().copied())
        .filter(|&(prefix, length)| {
            crate::prefix::contains(
                std::net::IpAddr::V6(prefix),
                length,
                std::net::IpAddr::V6(address),
            )
        })
        .filter_map(|(_, length)| embedded_ipv4(address, length))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v6(value: &str) -> Ipv6Addr {
        value.parse().unwrap()
    }

    const EXAMPLE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 33);

    #[test]
    fn reads_the_ipv4_address_at_every_length_in_the_rfc_examples() {
        // RFC 6052 section 2.4 gives these for 192.0.2.33.
        for (address, length) in [
            ("2001:db8:c000:221::", 32),
            ("2001:db8:1c0:2:21::", 40),
            ("2001:db8:122:c000:2:2100::", 48),
            ("2001:db8:122:3c0:0:221::", 56),
            ("2001:db8:122:344:c0:2:2100:0", 64),
            ("2001:db8:122:344::192.0.2.33", 96),
            ("64:ff9b::192.0.2.33", 96),
        ] {
            assert_eq!(
                embedded_ipv4(v6(address), length),
                Some(EXAMPLE),
                "{address}/{length}"
            );
        }
    }

    #[test]
    fn a_length_rfc_6052_does_not_allow_reads_nothing() {
        for length in [0, 24, 33, 72, 128] {
            assert_eq!(embedded_ipv4(v6("2001:db8::"), length), None, "/{length}");
        }
    }

    #[test]
    fn a_short_prefix_with_bits_64_to_71_set_reads_nothing() {
        // Byte 8 is 0xff, which RFC 6052 does not allow under a prefix shorter than 96.
        let address = v6("2001:db8:c000:221:ff00::");

        assert_eq!(embedded_ipv4(address, 32), None);
        assert_eq!(embedded_ipv4(address, 96), Some(Ipv4Addr::new(0, 0, 0, 0)));
    }

    #[cfg(feature = "http")]
    #[test]
    fn learns_the_prefix_from_the_answer_for_ipv4only_arpa() {
        // A network with the prefix 2001:db8:122:344::/96 answers these two.
        let answer = [
            v6("2001:db8:122:344::192.0.0.170"),
            v6("2001:db8:122:344::192.0.0.171"),
        ];

        assert_eq!(
            prefixes_from_discovery(&answer),
            vec![(v6("2001:db8:122:344::"), 96)]
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn learns_a_prefix_shorter_than_96() {
        // 192.0.0.170 under 2001:db8:100::/40, laid out as RFC 6052 section 2.2 says.
        let answer = [v6("2001:db8:1c0:0:aa::")];

        assert_eq!(
            prefixes_from_discovery(&answer),
            vec![(v6("2001:db8:100::"), 40)]
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn an_answer_with_no_known_address_inside_shows_no_prefix() {
        assert_eq!(
            prefixes_from_discovery(&[v6("2001:db8::1")]),
            Vec::<(Ipv6Addr, u8)>::new()
        );
        assert_eq!(prefixes_from_discovery(&[]), Vec::<(Ipv6Addr, u8)>::new());
    }

    #[cfg(feature = "http")]
    #[test]
    fn the_well_known_prefix_is_read_without_discovery() {
        // 169.254.169.254, the cloud metadata address, behind 64:ff9b::/96.
        assert_eq!(
            translations(v6("64:ff9b::a9fe:a9fe"), &[]),
            vec![Ipv4Addr::new(169, 254, 169, 254)]
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn a_discovered_prefix_is_read_for_an_address_under_it() {
        let discovered = [(v6("2001:db8:122:344::"), 96)];

        assert_eq!(
            translations(v6("2001:db8:122:344::a9fe:a9fe"), &discovered),
            vec![Ipv4Addr::new(169, 254, 169, 254)]
        );
    }

    #[cfg(feature = "http")]
    #[test]
    fn an_address_under_no_nat64_prefix_carries_no_ipv4_address() {
        let discovered = [(v6("2001:db8:122:344::"), 96)];

        assert_eq!(
            translations(v6("2001:4860:4860::8888"), &discovered),
            Vec::<Ipv4Addr>::new()
        );
    }
}
