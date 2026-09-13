//! Address prefix arithmetic, shared by the bootstrap reader and the address checks.

use std::net::IpAddr;

/// Reads a range written as `network/length`, such as `10.0.0.0/8` or `2001:db8::/32`.
///
/// Returns `None` for text in another shape.
pub(crate) fn parse_range(range: &str) -> Option<(IpAddr, u8)> {
    let (network, length) = range.split_once('/')?;
    Some((network.parse().ok()?, length.parse().ok()?))
}

/// Returns whether the network of this length holds the address.
///
/// A network of the other address family never holds it. A length past the width of
/// the family holds nothing, so a malformed range cannot match by accident.
pub(crate) fn contains(network: IpAddr, length: u8, ip: IpAddr) -> bool {
    match (network, ip) {
        (IpAddr::V4(network), IpAddr::V4(ip)) if length <= 32 => same_prefix(
            u128::from(u32::from(network)),
            u128::from(u32::from(ip)),
            length,
            32,
        ),
        (IpAddr::V6(network), IpAddr::V6(ip)) if length <= 128 => {
            same_prefix(u128::from(network), u128::from(ip), length, 128)
        }
        _ => false,
    }
}

/// Returns whether two values agree on their first `length` bits out of `width`.
fn same_prefix(network: u128, ip: u128, length: u8, width: u8) -> bool {
    // A shift by the full width of u128 overflows, and a zero-length prefix holds
    // every address, so that case answers before the shift.
    if length == 0 {
        return true;
    }
    let shift = u32::from(width - length);
    network >> shift == ip >> shift
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn reads_a_range() {
        assert_eq!(parse_range("10.0.0.0/8"), Some((ip("10.0.0.0"), 8)));
        assert_eq!(parse_range("2001:db8::/32"), Some((ip("2001:db8::"), 32)));
    }

    #[test]
    fn a_range_in_another_shape_reads_as_nothing() {
        for text in [
            "10.0.0.0",
            "10.0.0.0/",
            "/8",
            "10.0.0.0/eight",
            "not-a-range",
        ] {
            assert_eq!(parse_range(text), None, "{text:?}");
        }
    }

    #[test]
    fn a_network_holds_an_address_inside_it() {
        assert!(contains(ip("10.0.0.0"), 8, ip("10.255.1.2")));
        assert!(contains(ip("2001:db8::"), 32, ip("2001:db8:ffff::1")));
    }

    #[test]
    fn a_network_does_not_hold_an_address_outside_it() {
        assert!(!contains(ip("10.0.0.0"), 8, ip("11.0.0.0")));
        assert!(!contains(ip("2001:db8::"), 32, ip("2001:db9::1")));
    }

    #[test]
    fn the_boundaries_of_a_network_are_inside_it() {
        assert!(contains(ip("172.16.0.0"), 12, ip("172.16.0.0")));
        assert!(contains(ip("172.16.0.0"), 12, ip("172.31.255.255")));
        assert!(!contains(ip("172.16.0.0"), 12, ip("172.32.0.0")));
        assert!(!contains(ip("172.16.0.0"), 12, ip("172.15.255.255")));
    }

    #[test]
    fn a_zero_length_network_holds_every_address_of_its_family() {
        assert!(contains(ip("0.0.0.0"), 0, ip("203.0.113.9")));
        assert!(contains(ip("::"), 0, ip("2c00::1")));
    }

    #[test]
    fn a_full_length_network_holds_one_address() {
        assert!(contains(ip("255.255.255.255"), 32, ip("255.255.255.255")));
        assert!(!contains(ip("255.255.255.255"), 32, ip("255.255.255.254")));
    }

    #[test]
    fn a_network_of_the_other_family_holds_nothing() {
        assert!(!contains(ip("0.0.0.0"), 0, ip("::1")));
        assert!(!contains(ip("::"), 0, ip("8.8.8.8")));
    }

    #[test]
    fn a_length_past_the_width_holds_nothing() {
        assert!(!contains(ip("10.0.0.0"), 33, ip("10.0.0.0")));
        assert!(!contains(ip("::"), 129, ip("::")));
    }
}
