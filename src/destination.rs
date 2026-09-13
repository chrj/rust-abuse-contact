//! Where the client may connect.
//!
//! A registry sends links, and a server sends redirects. Both come from outside the
//! process, and either can point at an address inside it: a loopback service, a
//! private network, or a cloud metadata endpoint on `169.254.169.254`. The checks here
//! stop the client from making such a request for a registry.

use std::error::Error as StdError;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use reqwest::Url;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// The most redirects the client follows for one request.
pub(crate) const MAX_REDIRECTS: usize = 5;

/// Which addresses the client may connect to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Destinations {
    /// Public addresses only.
    ///
    /// The client refuses an address written in a URL that is not public, and a name
    /// that resolves to any address that is not public. On a network with NAT64, it
    /// also reads the IPv4 address inside an IPv6 address, because the connection
    /// ends there.
    ///
    /// The client connects directly and ignores proxy settings from the environment.
    /// A proxy resolves names where this check cannot see them.
    #[default]
    Public,

    /// Any address.
    ///
    /// Use it for a registry mirror on your own network, or a test server on
    /// `127.0.0.1`. Do not use it to read records from registries you do not run.
    Any,
}

/// A request the client did not send.
#[derive(Debug)]
pub(crate) struct Refusal {
    pub(crate) reason: String,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl StdError for Refusal {}

impl Refusal {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// Checks a URL before a request goes to it.
///
/// A name in the URL is not checked here. It is checked when it resolves, in
/// [`PublicResolver`], because only then are its addresses known.
pub(crate) fn check_url(url: &Url, destinations: Destinations) -> Result<(), Refusal> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Refusal::new(format!(
            "the scheme \"{}\" is not HTTP or HTTPS",
            url.scheme()
        )));
    }

    if destinations == Destinations::Any {
        return Ok(());
    }

    let Some(host) = url.host_str() else {
        return Err(Refusal::new("the URL names no host"));
    };

    // The URL parser writes an IPv6 host in brackets, and writes an IPv4 host in the
    // dotted form even when the URL spelled it another way, such as `2130706433`.
    let literal = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);

    match literal.parse::<IpAddr>() {
        Ok(ip) if !crate::is_public(ip) => Err(Refusal::new(format!(
            "{ip} is a private, reserved or documentation address, and a registry record \
             must not point inside your network"
        ))),
        _ => Ok(()),
    }
}

/// Checks a redirect before the client follows it.
///
/// `previous` holds the URLs of the request so far, the first one included.
pub(crate) fn check_redirect(
    url: &Url,
    previous: &[Url],
    destinations: Destinations,
) -> Result<(), Refusal> {
    if previous.len() > MAX_REDIRECTS {
        return Err(Refusal::new(format!(
            "the server sent more than {MAX_REDIRECTS} redirects"
        )));
    }

    // A redirect from HTTPS to HTTP sends the rest of the request where anybody on the
    // path can read and change it.
    let from_https = previous.last().is_some_and(|last| last.scheme() == "https");
    if from_https && url.scheme() == "http" {
        return Err(Refusal::new("the server redirected from HTTPS to HTTP"));
    }

    check_url(url, destinations)
}

/// Returns the redirect policy for a client.
pub(crate) fn redirect_policy(destinations: Destinations) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        match check_redirect(attempt.url(), attempt.previous(), destinations) {
            Ok(()) => attempt.follow(),
            Err(refusal) => attempt.error(refusal),
        }
    })
}

/// Resolves names, and refuses a name with an address that is not public.
///
/// The client connects to the addresses this returns and no others, so a name cannot
/// resolve to a public address for the check and a private one for the connection.
#[derive(Debug)]
pub(crate) struct PublicResolver;

impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();

        Box::pin(async move {
            // The port is a placeholder. The client puts the port of the URL in its place.
            let found: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();

            // The NAT64 prefix matters only to an IPv6 address, so it is learned only then.
            let nat64 = if found.iter().any(SocketAddr::is_ipv6) {
                discover_nat64().await.ok()
            } else {
                Some(Vec::new())
            };

            match usable_addresses(&host, &found, nat64.as_deref()) {
                Ok(usable) => Ok(Box::new(usable.into_iter()) as Addrs),
                Err(refusal) => Err(Box::new(refusal) as Box<dyn StdError + Send + Sync>),
            }
        })
    }
}

/// Learns the NAT64 prefixes of this network, as RFC 7050 describes.
///
/// A network without DNS64 answers `ipv4only.arpa` with IPv4 addresses only, and this
/// gives no prefix.
async fn discover_nat64() -> std::io::Result<Vec<(Ipv6Addr, u8)>> {
    let answer: Vec<Ipv6Addr> = tokio::net::lookup_host((crate::nat64::DISCOVERY_NAME, 0))
        .await?
        .filter_map(|address| match address.ip() {
            IpAddr::V6(v6) => Some(v6),
            IpAddr::V4(_) => None,
        })
        .collect();

    Ok(crate::nat64::prefixes_from_discovery(&answer))
}

/// Returns the addresses of a name to connect to, or why the name is refused.
///
/// `nat64` holds the NAT64 prefixes of the network, or `None` when they could not be
/// learned.
///
/// One address that is not public refuses the whole name. A name that points at a
/// public and a private address is a trick to pass a check with one and connect to
/// the other, and a registry has no reason to publish a private address.
///
/// An IPv6 address that the NAT64 gateway could translate, and that cannot be checked
/// because the prefixes are unknown, is not used. A name left with no address is
/// refused.
pub(crate) fn usable_addresses(
    host: &str,
    found: &[SocketAddr],
    nat64: Option<&[(Ipv6Addr, u8)]>,
) -> Result<Vec<SocketAddr>, Refusal> {
    let mut usable = Vec::new();
    let mut unchecked = false;

    for &address in found {
        let ip = address.ip();
        if !crate::is_public(ip) {
            // An IPv6 address that carries an IPv4 one is judged by the IPv4 one, so
            // the reason names both.
            let inner = crate::query::unmap(ip);
            let reason = if inner == ip {
                format!("{host} resolves to {ip}, which is not a public address")
            } else {
                format!(
                    "{host} resolves to {ip}, which is {inner}, and that is not a public address"
                )
            };
            return Err(Refusal::new(reason));
        }

        let IpAddr::V6(v6) = ip else {
            usable.push(address);
            continue;
        };

        // The well-known prefix is read by is_public. A prefix this network chose can
        // only be read when it is known.
        let Some(prefixes) = nat64 else {
            unchecked = true;
            continue;
        };
        if let Some(v4) = crate::nat64::translations(v6, prefixes)
            .into_iter()
            .find(|&v4| !crate::is_public(IpAddr::V4(v4)))
        {
            return Err(Refusal::new(format!(
                "{host} resolves to {ip}, which the NAT64 gateway of this network \
                 translates to {v4}, and that is not a public address"
            )));
        }
        usable.push(address);
    }

    if !usable.is_empty() {
        return Ok(usable);
    }
    if unchecked {
        return Err(Refusal::new(format!(
            "{host} has only IPv6 addresses, and the NAT64 prefix of this network could \
             not be learned to check them. Check that ipv4only.arpa resolves"
        )));
    }
    Err(Refusal::new(format!("{host} resolves to no address")))
}

/// Returns the refusal inside an HTTP error, when the error came from one.
///
/// The resolver and the redirect policy report through the HTTP client, which wraps
/// what they return. The refusal is somewhere down the chain of sources.
pub(crate) fn refusal_in(error: &reqwest::Error) -> Option<&Refusal> {
    let mut source = StdError::source(error);
    while let Some(inner) = source {
        if let Some(refusal) = inner.downcast_ref::<Refusal>() {
            return Some(refusal);
        }
        source = inner.source();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(value: &str) -> Url {
        Url::parse(value).unwrap()
    }

    #[test]
    fn a_public_url_passes() {
        for value in [
            "https://rdap.arin.net/registry/ip/8.8.8.8",
            "http://rdap.cctld.kg/domain/example.kg",
            "https://8.8.8.8/",
            "https://[2001:4860:4860::8888]/",
        ] {
            assert!(
                check_url(&url(value), Destinations::Public).is_ok(),
                "{value}"
            );
        }
    }

    #[test]
    fn an_address_that_is_not_public_is_refused() {
        for value in [
            "http://127.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1:8080/",
            "http://[::1]/",
            "http://[fe80::1]/",
            "http://[::ffff:127.0.0.1]/",
        ] {
            let refusal = check_url(&url(value), Destinations::Public).unwrap_err();
            assert!(
                refusal
                    .reason
                    .contains("private, reserved or documentation"),
                "{value}: {}",
                refusal.reason
            );
        }
    }

    #[test]
    fn an_address_spelled_another_way_is_read_as_the_address() {
        // 2130706433 and 0x7f.1 are both 127.0.0.1.
        for value in ["http://2130706433/", "http://0x7f.1/", "http://127.1/"] {
            assert!(
                check_url(&url(value), Destinations::Public).is_err(),
                "{value} must be refused"
            );
        }
    }

    #[test]
    fn a_scheme_other_than_http_is_refused_whatever_the_destinations() {
        for destinations in [Destinations::Public, Destinations::Any] {
            for value in [
                "file:///etc/passwd",
                "ftp://example.com/",
                "gopher://example.com/",
            ] {
                let refusal = check_url(&url(value), destinations).unwrap_err();
                assert!(refusal.reason.contains("is not HTTP or HTTPS"), "{value}");
            }
        }
    }

    #[test]
    fn a_name_passes_the_url_check_and_is_checked_when_it_resolves() {
        assert!(check_url(&url("http://localhost/"), Destinations::Public).is_ok());
    }

    #[test]
    fn any_allows_an_address_that_is_not_public() {
        assert!(check_url(&url("http://127.0.0.1:9/"), Destinations::Any).is_ok());
    }

    #[test]
    fn a_redirect_to_an_address_that_is_not_public_is_refused() {
        let previous = [url("https://rdap.example.net/ip/8.8.8.8")];

        assert!(
            check_redirect(
                &url("https://169.254.169.254/"),
                &previous,
                Destinations::Public
            )
            .is_err()
        );
    }

    #[test]
    fn a_redirect_from_https_to_http_is_refused() {
        let previous = [url("https://rdap.example.net/ip/8.8.8.8")];

        let refusal = check_redirect(
            &url("http://rdap.example.net/ip/8.8.8.8"),
            &previous,
            Destinations::Any,
        )
        .unwrap_err();

        assert_eq!(refusal.reason, "the server redirected from HTTPS to HTTP");
    }

    #[test]
    fn a_redirect_from_http_to_https_is_followed() {
        let previous = [url("http://rdap.example.net/ip/8.8.8.8")];

        assert!(
            check_redirect(
                &url("https://rdap.example.net/ip/8.8.8.8"),
                &previous,
                Destinations::Public
            )
            .is_ok()
        );
    }

    #[test]
    fn stops_after_the_redirect_limit() {
        let hop = url("https://rdap.example.net/");
        let at_limit = vec![hop.clone(); MAX_REDIRECTS];
        let past_limit = vec![hop.clone(); MAX_REDIRECTS + 1];

        assert!(check_redirect(&hop, &at_limit, Destinations::Public).is_ok());
        assert_eq!(
            check_redirect(&hop, &past_limit, Destinations::Public)
                .unwrap_err()
                .reason,
            "the server sent more than 5 redirects"
        );
    }

    fn addresses(values: &[&str]) -> Vec<SocketAddr> {
        values.iter().map(|value| value.parse().unwrap()).collect()
    }

    #[test]
    fn a_name_with_only_public_addresses_is_used_as_it_resolved() {
        let found = addresses(&["8.8.8.8:0", "[2001:4860::8888]:0"]);

        assert_eq!(
            usable_addresses("rdap.example.net", &found, Some(&[])).unwrap(),
            found
        );
    }

    #[test]
    fn one_address_that_is_not_public_refuses_the_whole_name() {
        let found = addresses(&["8.8.8.8:0", "169.254.169.254:0"]);

        let refusal = usable_addresses("evil.example", &found, Some(&[])).unwrap_err();

        assert_eq!(
            refusal.reason,
            "evil.example resolves to 169.254.169.254, which is not a public address"
        );
    }

    #[test]
    fn an_address_under_the_nat64_well_known_prefix_is_refused_without_discovery() {
        // DNS64 answers this for a name whose A record is 169.254.169.254.
        let found = addresses(&["[64:ff9b::a9fe:a9fe]:0"]);

        let refusal = usable_addresses("evil.example", &found, None).unwrap_err();

        assert_eq!(
            refusal.reason,
            "evil.example resolves to 64:ff9b::a9fe:a9fe, which is 169.254.169.254, and that \
             is not a public address"
        );
    }

    #[test]
    fn an_address_under_a_discovered_nat64_prefix_is_judged_by_the_ipv4_address_inside() {
        // The prefix must be an ordinary public one. Under a documentation prefix such
        // as 2001:db8::/32 the address is refused before the NAT64 check is reached.
        let prefixes = [("2c00:64::".parse().unwrap(), 96)];
        assert!(crate::is_public("2c00:64::a9fe:a9fe".parse().unwrap()));

        let refused = usable_addresses(
            "evil.example",
            &addresses(&["[2c00:64::a9fe:a9fe]:0"]),
            Some(&prefixes),
        )
        .unwrap_err();
        assert_eq!(
            refused.reason,
            "evil.example resolves to 2c00:64::a9fe:a9fe, which the NAT64 gateway of this \
             network translates to 169.254.169.254, and that is not a public address"
        );

        let public = addresses(&["[2c00:64::808:808]:0"]);
        assert_eq!(
            usable_addresses("rdap.example.net", &public, Some(&prefixes)).unwrap(),
            public
        );
    }

    #[test]
    fn an_ipv6_address_is_not_used_when_the_nat64_prefix_cannot_be_learned() {
        // The IPv4 address can be checked, so the name still has a usable address.
        let found = addresses(&["8.8.8.8:0", "[2001:4860::8888]:0"]);

        assert_eq!(
            usable_addresses("rdap.example.net", &found, None).unwrap(),
            addresses(&["8.8.8.8:0"])
        );
    }

    #[test]
    fn a_name_with_only_ipv6_addresses_that_cannot_be_checked_is_refused() {
        let found = addresses(&["[2001:4860::8888]:0"]);

        let refusal = usable_addresses("rdap.example.net", &found, None).unwrap_err();

        assert!(
            refusal
                .reason
                .contains("NAT64 prefix of this network could not be learned"),
            "{}",
            refusal.reason
        );
    }

    #[test]
    fn a_name_with_no_address_is_refused() {
        let refusal = usable_addresses("rdap.example.net", &[], Some(&[])).unwrap_err();

        assert_eq!(refusal.reason, "rdap.example.net resolves to no address");
    }
}
