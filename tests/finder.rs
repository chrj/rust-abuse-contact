//! One lookup across every source, against an RDAP server and a DNS server this test
//! starts.
//!
//! The tests need no network. They check which sources a target reaches, how the
//! answers merge, and that a source that fails does not lose the answers of the others.

#![cfg(all(feature = "http", feature = "dns"))]

mod common;

use abuse_contact::bootstrap::{Bootstrap, Registry};
use abuse_contact::{Client, Destinations, Error, Finder, Origin, Scope, Source};
use common::{Held, Server, emails};
use hickory_proto::rr::RecordType;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// An IP record with one abuse contact at the top level.
const IP_RECORD: &str = r#"{
  "entities": [{
    "roles": ["abuse"],
    "vcardArray": ["vcard", [["email", {}, "text", "network-abuse@example.com"]]]
  }]
}"#;

/// A domain record with the abuse contact of the registrar under the registrar.
const DOMAIN_RECORD: &str = r#"{
  "entities": [{
    "roles": ["registrar"],
    "entities": [{
      "roles": ["abuse"],
      "vcardArray": ["vcard", [["email", {}, "text", "registrar-abuse@example.net"]]]
    }]
  }]
}"#;

/// Returns a finder that asks this RDAP server and this DNS server.
///
/// The RDAP server listens on 127.0.0.1, which a public-only client refuses, so the
/// client takes [`Destinations::Any`].
fn finder_for(rdap: &MockServer, dns: &Server) -> Finder {
    let services = format!(
        r#"{{"services":[[["0.0.0.0/0"],["{uri}"]],[["::/0"],["{uri}"]],[["com"],["{uri}"]]]}}"#,
        uri = rdap.uri()
    );
    let registry = Registry::from_slice(services.as_bytes()).unwrap();
    let client = Client::with_bootstrap(
        Bootstrap {
            ipv4: registry.clone(),
            ipv6: registry.clone(),
            dns: registry,
        },
        Destinations::Any,
    )
    .unwrap();

    Finder::new(client, dns.resolver())
}

async fn rdap_answers(record_path: &str, response: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(record_path))
        .respond_with(response)
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn an_address_gets_the_contacts_of_rdap_and_abusix_ranked() {
    let rdap = rdap_answers(
        "/ip/8.8.8.8",
        ResponseTemplate::new(200).set_body_string(IP_RECORD),
    )
    .await;
    let dns = Server::start(vec![(
        "8.8.8.8.abuse-contacts.abusix.zone",
        RecordType::TXT,
        Held::Txt(vec![vec!["network-abuse@example.com,abuse@example.net"]]),
    )])
    .await;

    let found = finder_for(&rdap, &dns)
        .lookup("8.8.8.8".parse::<std::net::IpAddr>().unwrap())
        .await
        .unwrap();

    // The address both sources give is kept once, from RDAP.
    assert_eq!(
        emails(&found.contacts),
        ["network-abuse@example.com", "abuse@example.net"]
    );
    assert!(matches!(found.contacts[0].source, Source::Rdap { .. }));
    assert_eq!(found.contacts[1].source, Source::Abusix);
    assert!(
        found.contacts.iter().all(|c| c.scope == Scope::Network),
        "{:?}",
        found.contacts
    );
    assert_eq!(found.failures.len(), 0);
}

#[tokio::test]
async fn a_failing_zone_keeps_the_rdap_answer() {
    let rdap = rdap_answers(
        "/ip/8.8.8.8",
        ResponseTemplate::new(200).set_body_string(IP_RECORD),
    )
    .await;
    let dns = Server::start(vec![(
        "8.8.8.8.abuse-contacts.abusix.zone",
        RecordType::TXT,
        Held::ServFail,
    )])
    .await;

    let found = finder_for(&rdap, &dns)
        .lookup("8.8.8.8".parse::<std::net::IpAddr>().unwrap())
        .await
        .unwrap();

    assert_eq!(emails(&found.contacts), ["network-abuse@example.com"]);
    assert_eq!(found.failures.len(), 1);
    assert_eq!(found.failures[0].origin, Origin::Abusix);
    assert!(
        matches!(found.failures[0].error, Error::Dns { .. }),
        "{:?}",
        found.failures[0].error
    );
}

#[tokio::test]
async fn a_private_address_is_an_error_and_asks_no_source() {
    let rdap = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(IP_RECORD))
        .expect(0)
        .mount(&rdap)
        .await;
    let dns = Server::start(Vec::new()).await;

    let error = finder_for(&rdap, &dns)
        .lookup("10.0.0.1".parse::<std::net::IpAddr>().unwrap())
        .await
        .unwrap_err();

    match error {
        Error::NotPublic { target } => assert_eq!(target, "10.0.0.1"),
        other => panic!("expected NotPublic, got {other:?}"),
    }
    assert_eq!(dns.asked(), Vec::new());
}

#[tokio::test]
async fn a_domain_gets_the_contacts_of_rdap_abuse_net_and_rfc2142_ranked() {
    let rdap = rdap_answers(
        "/domain/example.com",
        ResponseTemplate::new(200).set_body_string(DOMAIN_RECORD),
    )
    .await;
    let dns = Server::start(vec![
        (
            "example.com.contacts.abuse.net",
            RecordType::TXT,
            Held::Txt(vec![vec!["security@example.com"]]),
        ),
        (
            "example.com",
            RecordType::MX,
            Held::Mx(vec![(10, "mx1.example.com.")]),
        ),
    ])
    .await;

    let found = finder_for(&rdap, &dns)
        .lookup("example.com".parse::<abuse_contact::DomainName>().unwrap())
        .await
        .unwrap();

    assert_eq!(
        emails(&found.contacts),
        [
            "registrar-abuse@example.net",
            "security@example.com",
            "abuse@example.com"
        ]
    );
    let scopes: Vec<Scope> = found.contacts.iter().map(|c| c.scope).collect();
    assert_eq!(scopes, [Scope::Registrar, Scope::Domain, Scope::Domain]);
    assert_eq!(found.failures.len(), 0);
}

#[tokio::test]
async fn a_failing_registry_keeps_the_dns_answers() {
    let rdap = rdap_answers("/domain/example.com", ResponseTemplate::new(500)).await;
    let dns = Server::start(vec![(
        "example.com.contacts.abuse.net",
        RecordType::TXT,
        Held::Txt(vec![vec!["security@example.com"]]),
    )])
    .await;

    let found = finder_for(&rdap, &dns)
        .lookup("example.com".parse::<abuse_contact::DomainName>().unwrap())
        .await
        .unwrap();

    // example.com is not in the zone, so RFC 2142 finds no mail host and gives nothing.
    assert_eq!(emails(&found.contacts), ["security@example.com"]);
    assert_eq!(found.failures.len(), 1);
    assert_eq!(found.failures[0].origin, Origin::Rdap);
    assert!(
        matches!(found.failures[0].error, Error::Status { status: 500, .. }),
        "{:?}",
        found.failures[0].error
    );
}

#[tokio::test]
async fn a_registry_that_holds_no_record_is_not_a_failure() {
    let rdap = rdap_answers("/domain/example.com", ResponseTemplate::new(404)).await;
    let dns = Server::start(Vec::new()).await;

    let found = finder_for(&rdap, &dns)
        .lookup("example.com".parse::<abuse_contact::DomainName>().unwrap())
        .await
        .unwrap();

    assert_eq!(emails(&found.contacts), Vec::<&str>::new());
    assert_eq!(found.failures.len(), 0);
}
