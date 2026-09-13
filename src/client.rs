//! The RDAP client.
//!
//! The client picks the server from the IANA bootstrap registries and fetches the
//! record. It does not decide what the record means: give the answer to
//! [`Response::abuse_contacts`](crate::rdap::Response::abuse_contacts).

use std::net::IpAddr;
use std::time::Duration;

use crate::bootstrap::{Bootstrap, DNS_URL, IPV4_URL, IPV6_URL, Registry};
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

/// Fetches RDAP records.
///
/// Build one and keep it. It holds the bootstrap registries and a connection pool,
/// and both are wasted when a client is built for one lookup.
///
/// ```no_run
/// use abuse_contact::{Client, Scope, rank};
///
/// # async fn run() -> Result<(), abuse_contact::Error> {
/// let client = Client::new().await?;
///
/// if let Some(response) = client.lookup_ip("8.8.8.8".parse().unwrap()).await? {
///     for contact in rank(response.abuse_contacts(Scope::Network, "rdap.arin.net")) {
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
}

impl Client {
    /// Fetches the three bootstrap registries and returns a client.
    ///
    /// This makes three requests to IANA. Build the client one time.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] when a registry cannot be fetched, and
    /// [`Error::Decode`] when one is not a bootstrap file.
    pub async fn new() -> Result<Self, Error> {
        let http = Self::http_client()?;
        let bootstrap = Bootstrap {
            ipv4: fetch_registry(&http, IPV4_URL).await?,
            ipv6: fetch_registry(&http, IPV6_URL).await?,
            dns: fetch_registry(&http, DNS_URL).await?,
        };

        Ok(Self { http, bootstrap })
    }

    /// Returns a client that uses registries you already hold.
    ///
    /// Use this to keep the registries between runs, so a short-lived process does
    /// not fetch them again.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] when the HTTP client cannot be built.
    pub fn with_bootstrap(bootstrap: Bootstrap) -> Result<Self, Error> {
        Ok(Self {
            http: Self::http_client()?,
            bootstrap,
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
    /// [`Error::NoServer`] when no registry answers for the target,
    /// [`Error::Transport`] when the request does not complete, [`Error::Status`]
    /// when the server refuses, and [`Error::Decode`] when the body is not RDAP.
    pub async fn lookup(&self, query: impl Into<Query>) -> Result<Option<Response>, Error> {
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
    pub async fn lookup_ip(&self, ip: IpAddr) -> Result<Option<Response>, Error> {
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
    /// [`Response::related_href`](crate::rdap::Response::related_href) with
    /// [`Client::fetch`] only when you want what the registry leaves out.
    ///
    /// # Errors
    ///
    /// The same errors as [`Client::lookup`].
    pub async fn lookup_domain(&self, domain: &DomainName) -> Result<Option<Response>, Error> {
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
    /// Returns [`Error::Transport`] when the request does not complete,
    /// [`Error::Status`] when the server refuses, and [`Error::Decode`] when the body
    /// is not RDAP.
    pub async fn fetch(&self, url: &str, target: &str) -> Result<Option<Response>, Error> {
        let answer = self
            .http
            .get(url)
            .header(reqwest::header::ACCEPT, RDAP_MEDIA_TYPE)
            .send()
            .await
            .map_err(|source| Error::Transport {
                server: url.to_owned(),
                source: Box::new(source),
            })?;

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

        let body = answer.text().await.map_err(|source| Error::Transport {
            server: url.to_owned(),
            source: Box::new(source),
        })?;

        serde_json::from_str(&body)
            .map(Some)
            .map_err(|source| Error::Decode {
                server: url.to_owned(),
                source,
            })
    }

    /// Builds the HTTP client the crate uses.
    fn http_client() -> Result<reqwest::Client, Error> {
        reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(TIMEOUT)
            .build()
            .map_err(|source| Error::Transport {
                server: "the HTTP client".to_owned(),
                source: Box::new(source),
            })
    }
}

/// Joins a server base URL, the kind of record, and the target.
///
/// A base URL in the registry ends with a slash, but not every entry does, so the
/// join does not trust it.
fn record_url(server: &str, kind: &str, target: &str) -> String {
    format!("{}/{kind}/{target}", server.trim_end_matches('/'))
}

/// Fetches one bootstrap registry.
async fn fetch_registry(http: &reqwest::Client, url: &str) -> Result<Registry, Error> {
    let body = http
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|source| Error::Transport {
            server: url.to_owned(),
            source: Box::new(source),
        })?
        .text()
        .await
        .map_err(|source| Error::Transport {
            server: url.to_owned(),
            source: Box::new(source),
        })?;

    Registry::from_slice(body.as_bytes()).map_err(|source| Error::Decode {
        server: url.to_owned(),
        source,
    })
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
    fn names_the_crate_and_its_version_to_a_registry() {
        assert!(USER_AGENT.starts_with("abuse-contact/"));
    }
}
