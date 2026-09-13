//! The RDAP client, against a server this test starts.
//!
//! The tests need no network and no live registry. They check what the client does
//! with each answer a registry can give.

#![cfg(feature = "http")]

use abuse_contact::bootstrap::{Bootstrap, Registry};
use abuse_contact::{Client, Error, Scope};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// An answer with one abuse contact, in the shape ARIN uses.
const RECORD: &str = r#"{
  "entities": [{
    "roles": ["registrant"],
    "entities": [{
      "roles": ["abuse"],
      "vcardArray": ["vcard", [["email", {}, "text", "network-abuse@example.com"]]]
    }]
  }]
}"#;

/// Returns a client whose registries send every lookup to this server.
fn client_for(server: &MockServer) -> Client {
    let services = format!(
        r#"{{"services":[[["0.0.0.0/0"],["{uri}"]],[["::/0"],["{uri}"]],[["com"],["{uri}"]]]}}"#,
        uri = server.uri()
    );
    let registry = Registry::from_slice(services.as_bytes()).unwrap();

    Client::with_bootstrap(Bootstrap {
        ipv4: registry.clone(),
        ipv6: registry.clone(),
        dns: registry,
    })
    .unwrap()
}

#[tokio::test]
async fn fetches_and_reads_an_ip_record() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ip/8.8.8.8"))
        .and(header("accept", "application/rdap+json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(RECORD))
        .expect(1)
        .mount(&server)
        .await;

    let response = client_for(&server)
        .lookup_ip("8.8.8.8".parse().unwrap())
        .await
        .unwrap()
        .expect("the server answered with a record");

    let contacts = response.abuse_contacts(Scope::Network, "test");

    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].email.as_str(), "network-abuse@example.com");
}

#[tokio::test]
async fn fetches_a_domain_record() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/domain/example.com"))
        .respond_with(ResponseTemplate::new(200).set_body_string(RECORD))
        .expect(1)
        .mount(&server)
        .await;

    let found = client_for(&server)
        .lookup_domain(&"Example.COM.".parse().unwrap())
        .await
        .unwrap();

    assert!(found.is_some(), "the server answered with a record");
}

#[tokio::test]
async fn a_registry_that_holds_no_record_gives_nothing() {
    // 404 is an answer: the registry has no record. It must not stop a caller that
    // is asking several sources.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let found = client_for(&server)
        .lookup_ip("8.8.8.8".parse().unwrap())
        .await
        .unwrap();

    assert!(found.is_none());
}

#[tokio::test]
async fn a_server_that_refuses_gives_the_status() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;

    let error = client_for(&server)
        .lookup_ip("8.8.8.8".parse().unwrap())
        .await
        .unwrap_err();

    match error {
        Error::Status { status, target, .. } => {
            assert_eq!(status, 429);
            assert_eq!(target, "8.8.8.8");
        }
        other => panic!("expected a status error, got {other:?}"),
    }
}

#[tokio::test]
async fn a_body_that_is_not_rdap_gives_a_decode_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>down for maintenance"))
        .mount(&server)
        .await;

    let error = client_for(&server)
        .lookup_ip("8.8.8.8".parse().unwrap())
        .await
        .unwrap_err();

    assert!(
        matches!(error, Error::Decode { .. }),
        "expected a decode error, got {error:?}"
    );
}

#[tokio::test]
async fn an_address_no_registry_holds_names_itself_in_the_error() {
    let empty = Client::with_bootstrap(Bootstrap::default()).unwrap();

    let error = empty
        .lookup_ip("8.8.8.8".parse().unwrap())
        .await
        .unwrap_err();

    match &error {
        Error::NoServer { target } => assert_eq!(target, "8.8.8.8"),
        other => panic!("expected no server, got {other:?}"),
    }

    let message = error.to_string();
    assert!(message.contains("8.8.8.8"), "message was: {message}");
}

#[tokio::test]
async fn a_private_address_is_refused_before_a_request_goes_out() {
    // A registry holds a record for the block a private address sits in, and that
    // record names IANA. Answering with it sends reports to somebody who cannot act.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(RECORD))
        .expect(0)
        .mount(&server)
        .await;

    for target in ["192.168.1.1", "127.0.0.1", "10.0.0.1", "fe80::1"] {
        let error = client_for(&server)
            .lookup_ip(target.parse().unwrap())
            .await
            .unwrap_err();

        match &error {
            Error::NotPublic { target: named } => assert_eq!(named, target),
            other => panic!("expected {target} to be refused, got {other:?}"),
        }

        // The message must say what to do instead.
        let message = error.to_string();
        assert!(message.contains(target), "message was: {message}");
        assert!(message.contains("public address"), "message was: {message}");
    }
}

#[tokio::test]
async fn follows_a_link_out_of_a_record() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rdap/v1/domain/EXAMPLE.COM"))
        .respond_with(ResponseTemplate::new(200).set_body_string(RECORD))
        .expect(1)
        .mount(&server)
        .await;

    let url = format!("{}/rdap/v1/domain/EXAMPLE.COM", server.uri());

    let found = client_for(&server)
        .fetch(&url, "example.com")
        .await
        .unwrap();

    assert!(found.is_some());
}
