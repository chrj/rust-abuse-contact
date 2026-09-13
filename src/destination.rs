//! Where the client may connect.
//!
//! A registry sends links, and a server sends redirects. Both come from outside the
//! process, and either can point at an address inside it: a loopback service, a
//! private network, or a cloud metadata endpoint on `169.254.169.254`. The checks here
//! stop the client from making such a request for a registry.

use std::error::Error as StdError;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use reqwest::Url;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// The most redirects the client follows for one request.
pub(crate) const MAX_REDIRECTS: usize = 5;

/// Which addresses the client may connect to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Destinations {
    /// Public addresses only.
    ///
    /// The client refuses an address written in a URL that is not public, and drops
    /// every address a name resolves to that is not public. A name with no public
    /// address is refused.
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
            "{ip} is a private, reserved or documentation address"
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

/// Resolves names, and keeps only the public addresses.
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
            let found = tokio::net::lookup_host((host.as_str(), 0)).await?;

            let public = public_addresses(found);
            if public.is_empty() {
                let refusal = Refusal::new(format!("{host} resolves to no public address"));
                return Err(Box::new(refusal) as Box<dyn StdError + Send + Sync>);
            }

            Ok(Box::new(public.into_iter()) as Addrs)
        })
    }
}

/// Returns the addresses that are public, in the order they came.
pub(crate) fn public_addresses(found: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    found
        .into_iter()
        .filter(|address| crate::is_public(address.ip()))
        .collect()
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

    #[test]
    fn keeps_only_the_public_addresses_of_a_name() {
        let found: Vec<SocketAddr> = ["127.0.0.1:0", "8.8.8.8:0", "[::1]:0", "[2001:4860::8888]:0"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();

        let kept = public_addresses(found);

        assert_eq!(
            kept,
            vec![
                "8.8.8.8:0".parse::<SocketAddr>().unwrap(),
                "[2001:4860::8888]:0".parse::<SocketAddr>().unwrap(),
            ]
        );
    }
}
