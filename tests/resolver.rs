//! The DNS sources, against a DNS server this test starts.
//!
//! The tests need no network and no live zone. Each one gives the server the records
//! it holds, and checks what the resolver makes of the answers.

#![cfg(feature = "dns")]

mod common;

use std::net::{IpAddr, Ipv4Addr};

use abuse_contact::{Error, Scope, Source};
use common::{Held, Server, emails};
use hickory_proto::rr::RecordType;

#[tokio::test]
async fn reads_the_abusix_contacts_for_an_address() {
    let server = Server::start(vec![(
        "229.132.16.104.abuse-contacts.abusix.zone",
        RecordType::TXT,
        Held::Txt(vec![vec!["abuse@cloudflare.com"]]),
    )])
    .await;

    let contacts = server
        .resolver()
        .abusix("104.16.132.229".parse().unwrap())
        .await
        .unwrap();

    assert_eq!(emails(&contacts), ["abuse@cloudflare.com"]);
    assert_eq!(contacts[0].scope, Scope::Network);
    assert_eq!(contacts[0].source, Source::Abusix);
}

#[tokio::test]
async fn asks_the_zone_for_the_reversed_address_once() {
    // The resolver here has no search domains, so this cannot show that a name is
    // kept from one. The unit test of `absolute` in src/resolver.rs covers that.
    let server = Server::start(vec![]).await;

    let _ = server
        .resolver()
        .abusix("104.16.132.229".parse().unwrap())
        .await;

    assert_eq!(
        server.asked(),
        [(
            "229.132.16.104.abuse-contacts.abusix.zone.".to_owned(),
            RecordType::TXT
        )]
    );
}

#[tokio::test]
async fn splits_a_record_that_holds_more_than_one_address() {
    let server = Server::start(vec![(
        "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.abuse-contacts.abusix.zone",
        RecordType::TXT,
        Held::Txt(vec![vec!["arin-contact@google.com,network-abuse@google.com"]]),
    )])
    .await;

    let contacts = server
        .resolver()
        .abusix("2001:4860:4860::8888".parse().unwrap())
        .await
        .unwrap();

    assert_eq!(
        emails(&contacts),
        ["arin-contact@google.com", "network-abuse@google.com"]
    );
}

#[tokio::test]
async fn joins_the_strings_of_a_long_record() {
    // A value over 255 bytes comes as more than one string.
    let server = Server::start(vec![(
        "229.132.16.104.abuse-contacts.abusix.zone",
        RecordType::TXT,
        Held::Txt(vec![vec!["abuse@cloud", "flare.com"]]),
    )])
    .await;

    let contacts = server
        .resolver()
        .abusix("104.16.132.229".parse().unwrap())
        .await
        .unwrap();

    assert_eq!(emails(&contacts), ["abuse@cloudflare.com"]);
}

#[tokio::test]
async fn a_name_the_zone_does_not_hold_gives_no_contacts() {
    let server = Server::start(vec![]).await;

    let contacts = server
        .resolver()
        .abusix("104.16.132.229".parse().unwrap())
        .await
        .unwrap();

    assert!(contacts.is_empty());
}

#[tokio::test]
async fn the_address_abusix_gives_for_a_withheld_lacnic_contact_is_dropped() {
    let server = Server::start(vec![(
        "1.14.3.200.abuse-contacts.abusix.zone",
        RecordType::TXT,
        Held::Txt(vec![vec!["removed@lacnic.net"]]),
    )])
    .await;

    let contacts = server
        .resolver()
        .abusix("200.3.14.1".parse().unwrap())
        .await
        .unwrap();

    assert!(contacts.is_empty(), "got {:?}", emails(&contacts));
}

#[tokio::test]
async fn a_private_address_is_refused_before_a_query_goes_out() {
    let server = Server::start(vec![]).await;

    for target in ["192.168.1.1", "::ffff:10.0.0.1", "64:ff9b::a9fe:a9fe"] {
        let error = server
            .resolver()
            .abusix(target.parse::<IpAddr>().unwrap())
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::NotPublic { .. }),
            "{target}: expected not public, got {error:?}"
        );
    }

    assert!(server.asked().is_empty());
}

#[tokio::test]
async fn a_server_failure_is_an_error_and_not_an_empty_answer() {
    // A zone that fails must not look like a zone that holds no contact.
    let server = Server::start(vec![(
        "229.132.16.104.abuse-contacts.abusix.zone",
        RecordType::TXT,
        Held::ServFail,
    )])
    .await;

    let error = server
        .resolver()
        .abusix("104.16.132.229".parse().unwrap())
        .await
        .unwrap_err();

    match error {
        Error::Dns { name, .. } => assert_eq!(name, "229.132.16.104.abuse-contacts.abusix.zone."),
        other => panic!("expected a DNS error, got {other:?}"),
    }
}

#[tokio::test]
async fn reads_the_abuse_net_contacts_for_a_domain() {
    let server = Server::start(vec![(
        "google.com.contacts.abuse.net",
        RecordType::TXT,
        Held::Txt(vec![vec!["abuse@google.com"]]),
    )])
    .await;

    let contacts = server
        .resolver()
        .abuse_net(&"google.com".parse().unwrap())
        .await
        .unwrap();

    assert_eq!(emails(&contacts), ["abuse@google.com"]);
    assert_eq!(contacts[0].scope, Scope::Domain);
    assert_eq!(contacts[0].source, Source::AbuseNet);
}

#[tokio::test]
async fn a_domain_too_long_for_the_abuse_net_zone_gives_no_contacts() {
    let server = Server::start(Vec::new()).await;
    // 253 bytes, the longest a domain can be. With the zone appended, the name is
    // longer than DNS allows, so the zone cannot hold it.
    let domain = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "b".repeat(61));
    assert_eq!(domain.len(), 253);

    let contacts = server
        .resolver()
        .abuse_net(&domain.parse().unwrap())
        .await
        .unwrap();

    assert_eq!(emails(&contacts), Vec::<&str>::new());
    assert_eq!(server.asked(), Vec::new());
}

#[tokio::test]
async fn a_domain_with_an_mx_gives_abuse_at_the_domain() {
    let server = Server::start(vec![(
        "example.com",
        RecordType::MX,
        Held::Mx(vec![(10, "mx1.example.com.")]),
    )])
    .await;

    let contact = server
        .resolver()
        .rfc2142(&"example.com".parse().unwrap())
        .await
        .unwrap()
        .expect("the domain takes mail");

    assert_eq!(contact.email.as_str(), "abuse@example.com");
    assert_eq!(contact.scope, Scope::Domain);
    assert_eq!(contact.source, Source::Rfc2142);
}

#[tokio::test]
async fn a_domain_with_a_null_mx_gives_nothing() {
    let server = Server::start(vec![(
        "example.com",
        RecordType::MX,
        Held::Mx(vec![(0, ".")]),
    )])
    .await;

    let found = server
        .resolver()
        .rfc2142(&"example.com".parse().unwrap())
        .await
        .unwrap();

    assert!(found.is_none());
}

#[tokio::test]
async fn a_domain_with_no_mx_but_an_address_takes_mail_at_that_address() {
    // RFC 5321 section 5.1: with no MX, mail goes to the address of the domain.
    let server = Server::start(vec![(
        "example.com",
        RecordType::A,
        Held::A(Ipv4Addr::new(93, 184, 215, 14)),
    )])
    .await;

    let found = server
        .resolver()
        .rfc2142(&"example.com".parse().unwrap())
        .await
        .unwrap();

    assert_eq!(
        found.map(|c| c.email.to_string()),
        Some("abuse@example.com".to_owned())
    );
}

#[tokio::test]
async fn a_domain_that_does_not_exist_gives_nothing() {
    let server = Server::start(vec![]).await;

    let found = server
        .resolver()
        .rfc2142(&"no-such-domain.example".parse().unwrap())
        .await
        .unwrap();

    assert!(found.is_none());
}
