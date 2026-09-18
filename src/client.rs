//! The RDAP client.
//!
//! The client picks the server from the IANA bootstrap registries and fetches the
//! record. It returns the record with the server that answered, and
//! [`Record::abuse_contacts`] reads the contacts out of it.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::bootstrap::{Bootstrap, DNS_URL, IPV4_URL, IPV6_URL, Registry};
use crate::contact::{Contact, Scope};
use crate::destination::{self, Destinations, PublicResolver};
use crate::error::Error;
use crate::query::{DomainName, Query};
use crate::rdap::Response;

/// How long to wait for one request.
const TIMEOUT: Duration = Duration::from_secs(30);

/// What the crate calls itself to a registry.
///
/// Registries ask for an agent that names the caller, and some refuse a request
/// without one.
const USER_AGENT: &str = concat!("abuse-contact/", env!("CARGO_PKG_VERSION"));

/// The media type an RDAP server answers with.
const RDAP_MEDIA_TYPE: &str = "application/rdap+json";

/// The most the client reads of a record, in bytes.
///
/// The largest record in the test fixtures is 95 KiB: a LACNIC network that lists the
/// name servers of 63 reverse DNS zones. The limit leaves room for a larger network
/// and stops a server that sends without end.
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;

/// The most the client reads of a bootstrap registry, in bytes.
///
/// The largest registry, for domain names, is 71 KiB.
pub const MAX_BOOTSTRAP_BYTES: usize = 4 * 1024 * 1024;

/// Fetches RDAP records.
///
/// Build one and keep it. It holds the bootstrap registries and a connection pool,
/// and both are wasted when a client is built for one lookup.
///
/// The client connects to public addresses only, unless it is built with
/// [`Destinations::Any`]. A record and a redirect come from outside the process, and
/// this keeps either from sending the client to a service inside your network.
///
/// ```no_run
/// use abuse_contact::{Client, Scope, rank};
///
/// # async fn run() -> Result<(), abuse_contact::Error> {
/// let client = Client::new().await?;
///
/// if let Some(record) = client.lookup_ip("8.8.8.8".parse().unwrap()).await? {
///     for contact in rank(record.abuse_contacts(Scope::Network)) {
///         println!("{} ({:?})", contact.email, contact.scope);
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Client {
    http: reqwest::Client,
    bootstrap: Bootstrap,
    destinations: Destinations,
}

impl Client {
    /// Fetches the three bootstrap registries and returns a client.
    ///
    /// This makes three requests to IANA. Build the client one time. The client
    /// connects to public addresses only.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] when a registry cannot be fetched,
    /// [`Error::TooLarge`] when one is past [`MAX_BOOTSTRAP_BYTES`], and
    /// [`Error::Decode`] when one is not a bootstrap file.
    pub async fn new() -> Result<Self, Error> {
        let destinations = Destinations::Public;
        let http = Self::http_client(destinations)?;
        let bootstrap = Bootstrap {
            ipv4: fetch_registry(&http, IPV4_URL).await?,
            ipv6: fetch_registry(&http, IPV6_URL).await?,
            dns: fetch_registry(&http, DNS_URL).await?,
        };

        Ok(Self {
            http,
            bootstrap,
            destinations,
        })
    }

    /// Returns a client that uses registries you already hold.
    ///
    /// Use this to keep the registries between runs, so a short-lived process does
    /// not fetch them again. Give [`Destinations::Public`] unless every server in the
    /// registries is one you run.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] when the HTTP client cannot be built.
    pub fn with_bootstrap(bootstrap: Bootstrap, destinations: Destinations) -> Result<Self, Error> {
        Ok(Self {
            http: Self::http_client(destinations)?,
            bootstrap,
            destinations,
        })
    }

    /// Returns the registries this client holds.
    pub fn bootstrap(&self) -> &Bootstrap {
        &self.bootstrap
    }

    /// Fetches the record for an address or a name.
    ///
    /// Returns `None` when the registry holds no record for it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotPublic`] for a private or reserved address,
    /// [`Error::NoServer`] when no registry answers for the target, and the errors of
    /// [`Client::fetch`].
    pub async fn lookup(&self, query: impl Into<Query>) -> Result<Option<Record>, Error> {
        match query.into() {
            Query::Ip(ip) => self.lookup_ip(ip).await,
            Query::Domain(domain) => self.lookup_domain(&domain).await,
        }
    }

    /// Fetches the record for an address.
    ///
    /// # Errors
    ///
    /// The same errors as [`Client::lookup`].
    pub async fn lookup_ip(&self, ip: IpAddr) -> Result<Option<Record>, Error> {
        // The IPv6 registry holds no record for `::ffff:8.8.8.8`, so ask about the
        // IPv4 address it carries. The check and the lookup must use the same form.
        let ip = crate::query::unmap(ip);
        let target = ip.to_string();

        // A private address sits in a block a registry describes, so the bootstrap
        // finds a server and the answer names IANA. Stop before that happens.
        if !crate::is_public(ip) {
            return Err(Error::NotPublic { target });
        }

        let server = self
            .bootstrap
            .server_for_ip(ip)
            .ok_or_else(|| Error::NoServer {
                target: target.clone(),
            })?;

        self.fetch(&record_url(server, "ip", &target), &target)
            .await
    }

    /// Fetches the record for a name.
    ///
    /// The record names the registrar and carries its abuse address. Follow
    /// [`Response::related_href`] on [`Record::response`] with [`Client::fetch`] only
    /// when you want what the registry leaves out.
    ///
    /// # Errors
    ///
    /// The same errors as [`Client::lookup`].
    pub async fn lookup_domain(&self, domain: &DomainName) -> Result<Option<Record>, Error> {
        let target = domain.as_str().to_owned();
        let server = self
            .bootstrap
            .server_for_domain(domain)
            .ok_or_else(|| Error::NoServer {
                target: target.clone(),
            })?;

        self.fetch(&record_url(server, "domain", &target), &target)
            .await
    }

    /// Fetches one RDAP record by its URL.
    ///
    /// Use it to follow a link out of a record you already hold. The URL is used as it
    /// is given, so it must come from a record and not from outside input.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Refused`] when the URL, or a redirect from it, goes where the
    /// client does not connect, [`Error::Transport`] when the request does not
    /// complete, [`Error::Status`] when the server refuses, [`Error::TooLarge`] when the
    /// body is past [`MAX_RECORD_BYTES`], and [`Error::Decode`] when the body is not
    /// RDAP.
    pub async fn fetch(&self, url: &str, target: &str) -> Result<Option<Record>, Error> {
        let parsed = reqwest::Url::parse(url).map_err(|problem| Error::Refused {
            server: url.to_owned(),
            reason: format!("it is not a URL: {problem}"),
        })?;
        destination::check_url(&parsed, self.destinations).map_err(|refusal| Error::Refused {
            server: url.to_owned(),
            reason: refusal.reason,
        })?;

        let answer = self
            .http
            .get(parsed)
            .header(reqwest::header::ACCEPT, RDAP_MEDIA_TYPE)
            .send()
            .await
            .map_err(|source| request_error(url, source))?;

        // Read where the answer came from before the body is read, which uses up the
        // answer. After a redirect this is the last server, not the first.
        let url_answered = answer.url().clone();

        let status = answer.status();
        // A registry answers 404 when it holds no record. That is an answer, not a
        // failure, and a caller asking several sources must not stop on it.
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(Error::Status {
                server: url.to_owned(),
                status: status.as_u16(),
                target: target.to_owned(),
            });
        }

        let body = read_capped(answer, url, MAX_RECORD_BYTES).await?;

        let response = serde_json::from_slice(&body).map_err(|source| Error::Decode {
            server: url.to_owned(),
            source,
        })?;

        Ok(Some(Record {
            response,
            server: server_of(&url_answered),
            url: url_answered.into(),
        }))
    }

    /// Builds the HTTP client the crate uses.
    fn http_client(destinations: Destinations) -> Result<reqwest::Client, Error> {
        let mut builder = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(TIMEOUT)
            .redirect(destination::redirect_policy(destinations));

        if destinations == Destinations::Public {
            // A proxy resolves names where the resolver cannot drop private addresses,
            // so a public-only client does not use one.
            builder = builder.dns_resolver(Arc::new(PublicResolver)).no_proxy();
        }

        builder.build().map_err(|source| Error::Transport {
            server: "the HTTP client".to_owned(),
            source: Box::new(source),
        })
    }
}

/// A record the client fetched, with the server that answered.
#[derive(Clone, Debug)]
pub struct Record {
    /// The record.
    pub response: Response,
    /// The server that answered: the host, with the port when the URL names one.
    ///
    /// After a redirect this is the last server, which is the one that sent the record.
    pub server: String,
    /// The URL that answered, after every redirect.
    pub url: String,
}

impl Record {
    /// Returns every abuse contact in the record, each one time.
    ///
    /// The source of each contact names the server that answered.
    pub fn abuse_contacts(&self, scope: Scope) -> Vec<Contact> {
        self.response.abuse_contacts(scope, &self.server)
    }
}

/// Returns the server part of a URL: the host, with the port when the URL names one.
///
/// A URL for the default port of its scheme names no port.
fn server_of(url: &reqwest::Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}

/// Joins a server base URL, the kind of record, and the target.
///
/// A base URL in the registry ends with a slash, but not every entry does, so the
/// join does not trust it.
fn record_url(server: &str, kind: &str, target: &str) -> String {
    format!("{}/{kind}/{target}", server.trim_end_matches('/'))
}

/// Returns the error for a request that did not complete.
///
/// The resolver and the redirect policy report a refusal through the HTTP client. It
/// comes back here as a transport error, and is turned back into [`Error::Refused`].
fn request_error(url: &str, source: reqwest::Error) -> Error {
    match destination::refusal_in(&source) {
        Some(refusal) => Error::Refused {
            server: url.to_owned(),
            reason: refusal.reason.clone(),
        },
        None => Error::Transport {
            server: url.to_owned(),
            source: Box::new(source),
        },
    }
}

/// Fetches one bootstrap registry.
async fn fetch_registry(http: &reqwest::Client, url: &str) -> Result<Registry, Error> {
    let answer = http
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|source| request_error(url, source))?;

    let body = read_capped(answer, url, MAX_BOOTSTRAP_BYTES).await?;

    Registry::from_slice(&body).map_err(|source| Error::Decode {
        server: url.to_owned(),
        source,
    })
}

/// Reads a body, and stops with [`Error::TooLarge`] past `limit` bytes.
///
/// The body is read in chunks and counted as it arrives. `Content-Length` alone does
/// not bound it: a chunked answer does not send one, and a server can send more than
/// it announced.
async fn read_capped(
    mut answer: reqwest::Response,
    url: &str,
    limit: usize,
) -> Result<Vec<u8>, Error> {
    let too_large = || Error::TooLarge {
        server: url.to_owned(),
        limit,
    };

    // A server that announces too much is refused before any of the body is read.
    if answer
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(too_large());
    }

    let mut body = Vec::new();
    while let Some(chunk) = answer.chunk().await.map_err(|source| Error::Transport {
        server: url.to_owned(),
        source: Box::new(source),
    })? {
        if body.len() + chunk.len() > limit {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_a_base_url_that_ends_with_a_slash() {
        assert_eq!(
            record_url("https://rdap.arin.net/registry/", "ip", "8.8.8.8"),
            "https://rdap.arin.net/registry/ip/8.8.8.8"
        );
    }

    #[test]
    fn joins_a_base_url_that_does_not_end_with_a_slash() {
        assert_eq!(
            record_url("https://rdap.example.net", "domain", "example.com"),
            "https://rdap.example.net/domain/example.com"
        );
    }

    #[test]
    fn the_server_of_a_url_is_its_host() {
        let url = |value: &str| reqwest::Url::parse(value).unwrap();

        assert_eq!(
            server_of(&url("https://rdap.arin.net/registry/ip/8.8.8.8")),
            "rdap.arin.net"
        );
        assert_eq!(
            server_of(&url("https://rdap.arin.net:443/registry/")),
            "rdap.arin.net"
        );
        assert_eq!(
            server_of(&url("http://127.0.0.1:8080/ip/8.8.8.8")),
            "127.0.0.1:8080"
        );
        assert_eq!(
            server_of(&url("https://[2001:db8::1]:8443/")),
            "[2001:db8::1]:8443"
        );
    }

    #[test]
    fn names_the_crate_and_its_version_to_a_registry() {
        assert!(USER_AGENT.starts_with("abuse-contact/"));
    }
}
