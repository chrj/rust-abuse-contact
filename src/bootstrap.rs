//! The IANA bootstrap registries, which say who answers for an address or a name.
//!
//! IANA publishes three files. Two map an address range to the RDAP server of the
//! regional registry that holds it, and one maps a top-level domain to the server of
//! its registry. RFC 9224 gives the format and the matching rules.
//!
//! Nothing here fetches. A [`Registry`] is read from bytes you already have, so the
//! rules that pick a server run in a test without a network.

use std::net::IpAddr;

use serde::Deserialize;

use crate::query::DomainName;

/// Where IANA publishes the registry for IPv4 addresses.
pub const IPV4_URL: &str = "https://data.iana.org/rdap/ipv4.json";

/// Where IANA publishes the registry for IPv6 addresses.
pub const IPV6_URL: &str = "https://data.iana.org/rdap/ipv6.json";

/// Where IANA publishes the registry for domain names.
pub const DNS_URL: &str = "https://data.iana.org/rdap/dns.json";

/// One bootstrap registry file.
///
/// A file holds services. A service is a pair: the keys it answers for, and the
/// servers that answer. A key is an address range in one file and a domain suffix in
/// another.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Registry {
    /// Each entry is `[[key, ...], [url, ...]]`, the shape RFC 9224 gives.
    #[serde(default)]
    services: Vec<Vec<Vec<String>>>,
}

impl Registry {
    /// Reads a registry from the bytes of a bootstrap file.
    ///
    /// # Errors
    ///
    /// Returns the parse error when the bytes are not a bootstrap file.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Returns the base URL of the server that answers for this address.
    ///
    /// The most specific range wins, as RFC 9224 requires. A registry holding both
    /// `10.0.0.0/8` and `10.1.0.0/16` answers the second for an address in it.
    pub fn server_for_ip(&self, ip: IpAddr) -> Option<&str> {
        let mut best: Option<(u8, &str)> = None;

        for (keys, urls) in self.services() {
            for key in keys {
                let Some(length) = prefix_length_containing(key, ip) else {
                    continue;
                };
                if best.is_some_and(|(found, _)| found >= length) {
                    continue;
                }
                if let Some(url) = preferred(urls) {
                    best = Some((length, url));
                }
            }
        }

        best.map(|(_, url)| url)
    }

    /// Returns the base URL of the server that answers for this name.
    ///
    /// The longest run of labels wins. A registry holding both `uk` and `co.uk`
    /// answers the second for `example.co.uk`.
    pub fn server_for_domain(&self, domain: &DomainName) -> Option<&str> {
        let name = domain.as_str();
        let mut best: Option<(usize, &str)> = None;

        for (keys, urls) in self.services() {
            for key in keys {
                let key = key.trim_matches('.').to_lowercase();
                if !suffix_matches(name, &key) {
                    continue;
                }
                let labels = key.split('.').count();
                if best.is_some_and(|(found, _)| found >= labels) {
                    continue;
                }
                if let Some(url) = preferred(urls) {
                    best = Some((labels, url));
                }
            }
        }

        best.map(|(_, url)| url)
    }

    /// Returns each service as its keys and its servers.
    ///
    /// A service in a shape RFC 9224 does not describe is skipped, so one bad entry
    /// does not lose the rest of the file.
    fn services(&self) -> impl Iterator<Item = (&Vec<String>, &Vec<String>)> {
        self.services
            .iter()
            .filter_map(|entry| Some((entry.first()?, entry.get(1)?)))
    }
}

/// Returns the prefix length when the range holds the address, and `None` otherwise.
///
/// A range of another address family never holds it.
fn prefix_length_containing(range: &str, ip: IpAddr) -> Option<u8> {
    let (network, length) = range.split_once('/')?;
    let length: u8 = length.parse().ok()?;

    match (network.parse().ok()?, ip) {
        (IpAddr::V4(network), IpAddr::V4(ip)) if length <= 32 => {
            same_prefix(u32::from(network), u32::from(ip), length, 32).then_some(length)
        }
        (IpAddr::V6(network), IpAddr::V6(ip)) if length <= 128 => {
            same_prefix(u128::from(network), u128::from(ip), length, 128).then_some(length)
        }
        _ => None,
    }
}

/// Returns whether two addresses agree on their first `length` bits.
fn same_prefix<T>(network: T, ip: T, length: u8, bits: u8) -> bool
where
    T: std::ops::Shr<u32, Output = T> + PartialEq,
{
    // A shift by the full width is undefined, and a zero-length prefix holds every
    // address, so that case answers before the shift.
    if length == 0 {
        return true;
    }
    network >> u32::from(bits - length) == ip >> u32::from(bits - length)
}

/// Returns whether the name sits at or under the suffix.
///
/// `example.com` matches `com`, and `com` matches `com`. `mycom` does not, because a
/// suffix match runs on whole labels.
fn suffix_matches(name: &str, suffix: &str) -> bool {
    if suffix.is_empty() {
        return false;
    }
    let Some(rest) = name.strip_suffix(suffix) else {
        return false;
    };
    rest.is_empty() || rest.ends_with('.')
}

/// Returns the server to use out of the servers a service lists.
///
/// RFC 9224 asks for HTTPS where a service offers it. A few registries list only
/// HTTP, and the crate uses those rather than refusing to answer for them.
fn preferred(urls: &[String]) -> Option<&str> {
    urls.iter()
        .find(|url| url.starts_with("https://"))
        .or_else(|| urls.first())
        .map(String::as_str)
}

/// The three registries together.
///
/// Hold one of these for as long as the process runs. IANA changes the files rarely,
/// and the answer for an address does not move between them.
#[derive(Clone, Debug, Default)]
pub struct Bootstrap {
    /// The registry for IPv4 addresses.
    pub ipv4: Registry,
    /// The registry for IPv6 addresses.
    pub ipv6: Registry,
    /// The registry for domain names.
    pub dns: Registry,
}

impl Bootstrap {
    /// Returns the base URL of the server that answers for this address.
    pub fn server_for_ip(&self, ip: IpAddr) -> Option<&str> {
        match ip {
            IpAddr::V4(_) => self.ipv4.server_for_ip(ip),
            IpAddr::V6(_) => self.ipv6.server_for_ip(ip),
        }
    }

    /// Returns the base URL of the server that answers for this name.
    pub fn server_for_domain(&self, domain: &DomainName) -> Option<&str> {
        self.dns.server_for_domain(domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry(json: &str) -> Registry {
        Registry::from_slice(json.as_bytes()).unwrap()
    }

    const IPV4: &str = r#"{"version":"1.0","services":[
      [["41.0.0.0/8","102.0.0.0/8"],["https://rdap.afrinic.net/rdap/"]],
      [["1.0.0.0/8","27.0.0.0/8"],["https://rdap.apnic.net/"]],
      [["8.0.0.0/8"],["https://rdap.arin.net/registry/","http://rdap.arin.net/registry/"]]
    ]}"#;

    const DNS: &str = r#"{"version":"1.0","services":[
      [["com","net"],["https://rdap.verisign.com/com/v1/"]],
      [["kg"],["http://rdap.cctld.kg/"]],
      [["uk"],["https://rdap.nominet.uk/uk/"]],
      [["co.uk"],["https://rdap.example.co.uk/"]]
    ]}"#;

    #[test]
    fn finds_the_server_for_an_ipv4_address() {
        assert_eq!(
            registry(IPV4).server_for_ip("8.8.8.8".parse().unwrap()),
            Some("https://rdap.arin.net/registry/")
        );
    }

    #[test]
    fn finds_the_server_for_a_second_registry() {
        assert_eq!(
            registry(IPV4).server_for_ip("27.1.2.3".parse().unwrap()),
            Some("https://rdap.apnic.net/")
        );
    }

    #[test]
    fn gives_nothing_for_an_address_no_service_holds() {
        assert_eq!(
            registry(IPV4).server_for_ip("192.0.2.1".parse().unwrap()),
            None
        );
    }

    #[test]
    fn prefers_the_https_server() {
        // The ARIN entry lists HTTPS first and HTTP second.
        let ipv4 = registry(IPV4);

        let found = ipv4.server_for_ip("8.8.8.8".parse().unwrap());

        assert_eq!(found, Some("https://rdap.arin.net/registry/"));
    }

    #[test]
    fn uses_an_http_server_when_a_registry_lists_no_other() {
        let domain = "example.kg".parse().unwrap();

        assert_eq!(
            registry(DNS).server_for_domain(&domain),
            Some("http://rdap.cctld.kg/")
        );
    }

    #[test]
    fn takes_the_most_specific_range() {
        let wide_and_narrow = registry(
            r#"{"services":[
                 [["10.0.0.0/8"],["https://wide.example/"]],
                 [["10.1.0.0/16"],["https://narrow.example/"]]
               ]}"#,
        );

        assert_eq!(
            wide_and_narrow.server_for_ip("10.1.2.3".parse().unwrap()),
            Some("https://narrow.example/")
        );
        assert_eq!(
            wide_and_narrow.server_for_ip("10.2.2.3".parse().unwrap()),
            Some("https://wide.example/")
        );
    }

    #[test]
    fn takes_the_longest_run_of_labels() {
        let domain = "shop.example.co.uk".parse().unwrap();

        assert_eq!(
            registry(DNS).server_for_domain(&domain),
            Some("https://rdap.example.co.uk/")
        );
    }

    #[test]
    fn matches_a_suffix_on_whole_labels() {
        // "mycom" ends with the letters of "com" but is not under it.
        let domain = "mycom".parse::<DomainName>();

        assert!(domain.is_err(), "a name with no dot is not a domain");
        assert!(!suffix_matches("mycom", "com"));
        assert!(suffix_matches("example.com", "com"));
        assert!(suffix_matches("com", "com"));
    }

    #[test]
    fn finds_the_server_for_an_ipv6_address() {
        let ipv6 = registry(
            r#"{"services":[
                 [["2001:4200::/23","2c00::/12"],["https://rdap.afrinic.net/rdap/"]],
                 [["2001:4800::/23"],["https://rdap.arin.net/registry/"]]
               ]}"#,
        );

        assert_eq!(
            ipv6.server_for_ip("2c00::1".parse().unwrap()),
            Some("https://rdap.afrinic.net/rdap/")
        );
    }

    #[test]
    fn an_address_of_another_family_matches_nothing() {
        assert_eq!(
            registry(IPV4).server_for_ip("2c00::1".parse().unwrap()),
            None
        );
    }

    #[test]
    fn a_zero_length_prefix_holds_every_address() {
        let catch_all = registry(r#"{"services":[[["0.0.0.0/0"],["https://any.example/"]]]}"#);

        assert_eq!(
            catch_all.server_for_ip("203.0.113.9".parse().unwrap()),
            Some("https://any.example/")
        );
    }

    #[test]
    fn skips_a_service_in_a_shape_the_format_does_not_describe() {
        let mixed = registry(
            r#"{"services":[
                 [["8.0.0.0/8"]],
                 [["not-a-range"],["https://bad.example/"]],
                 [["8.0.0.0/8"],["https://good.example/"]]
               ]}"#,
        );

        assert_eq!(
            mixed.server_for_ip("8.8.8.8".parse().unwrap()),
            Some("https://good.example/")
        );
    }

    #[test]
    fn reads_an_empty_registry() {
        assert_eq!(
            registry("{}").server_for_ip("8.8.8.8".parse().unwrap()),
            None
        );
    }

    #[test]
    fn bootstrap_picks_the_registry_by_address_family() {
        let bootstrap = Bootstrap {
            ipv4: registry(IPV4),
            ipv6: registry(r#"{"services":[[["2c00::/12"],["https://v6.example/"]]]}"#),
            dns: registry(DNS),
        };

        assert_eq!(
            bootstrap.server_for_ip("8.8.8.8".parse().unwrap()),
            Some("https://rdap.arin.net/registry/")
        );
        assert_eq!(
            bootstrap.server_for_ip("2c00::1".parse().unwrap()),
            Some("https://v6.example/")
        );
    }
}
