//! The RDAP client, against a server this test starts.
//!
//! The tests need no network and no live registry. They check what the client does
//! with each answer a registry can give.

#![cfg(feature = "http")]

use abuse_contact::bootstrap::{Bootstrap, Registry};
use abuse_contact::{Client, Destinations, Error, MAX_RECORD_BYTES, Scope};
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
///
/// The server listens on 127.0.0.1, which a public-only client refuses, so these
/// clients take [`Destinations::Any`].
fn client_for(server: &MockServer) -> Client {
    let services = format!(
        r#"{{"services":[[["0.0.0.0/0"],["{uri}"]],[["::/0"],["{uri}"]],[["com"],["{uri}"]]]}}"#,
        uri = server.uri()
    );
    let registry = Registry::from_slice(services.as_bytes()).unwrap();

    Client::with_bootstrap(
        Bootstrap {
            ipv4: registry.clone(),
            ipv6: registry.clone(),
            dns: registry,
        },
        Destinations::Any,
    )
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
    let empty = Client::with_bootstrap(Bootstrap::default(), Destinations::Public).unwrap();

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

    for target in ["192.168.1.1", "127.0.0.1", "10.0.0.1", "fe80::1", "0.1.2.3"] {
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
async fn an_ipv4_address_written_as_ipv6_is_looked_up_as_ipv4() {
    // The IPv6 registry holds no record for the mapped form, so the request must go
    // out for the IPv4 address it carries.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ip/8.8.8.8"))
        .respond_with(ResponseTemplate::new(200).set_body_string(RECORD))
        .expect(1)
        .mount(&server)
        .await;

    let found = client_for(&server)
        .lookup_ip("::ffff:8.8.8.8".parse().unwrap())
        .await
        .unwrap();

    assert!(found.is_some(), "the lookup went out for 8.8.8.8");
}

#[tokio::test]
async fn the_ipv6_spelling_of_a_private_address_is_refused() {
    // Without unmapping, ::ffff:10.0.0.1 passes a check that only reads IPv6 ranges.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(RECORD))
        .expect(0)
        .mount(&server)
        .await;

    let error = client_for(&server)
        .lookup_ip("::ffff:10.0.0.1".parse().unwrap())
        .await
        .unwrap_err();

    match error {
        // The error names the IPv4 form, which is the address that was judged.
        Error::NotPublic { target } => assert_eq!(target, "10.0.0.1"),
        other => panic!("expected the mapped private address to be refused, got {other:?}"),
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

/// Returns a public-only client with no registries, for requests made by URL.
fn public_client() -> Client {
    Client::with_bootstrap(Bootstrap::default(), Destinations::Public).unwrap()
}

/// Returns the reason when the error is a refusal, and fails the test otherwise.
fn refusal(error: Error) -> String {
    match error {
        Error::Refused { reason, .. } => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_link_to_an_address_that_is_not_public_is_refused() {
    // A registry record can hold any link. None of these may be requested.
    for url in [
        "http://127.0.0.1:9/rdap/domain/example.com",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]:9/",
        "http://[::ffff:10.0.0.1]/",
        "http://2130706433/",
    ] {
        let reason = refusal(public_client().fetch(url, "example.com").await.unwrap_err());
        assert!(
            reason.contains("private, reserved or documentation"),
            "{url}: {reason}"
        );
    }
}

#[tokio::test]
async fn a_link_with_a_scheme_other_than_http_is_refused() {
    for url in ["file:///etc/passwd", "ftp://example.com/"] {
        let reason = refusal(public_client().fetch(url, "example.com").await.unwrap_err());
        assert!(reason.contains("is not HTTP or HTTPS"), "{url}: {reason}");
    }
}

#[tokio::test]
async fn a_name_that_resolves_only_to_loopback_is_refused() {
    // The URL names a host, so the URL check passes it. The resolver drops the
    // loopback address, and the refusal must reach the caller as a refusal.
    let reason = refusal(
        public_client()
            .fetch("http://localhost:9/rdap/domain/example.com", "example.com")
            .await
            .unwrap_err(),
    );

    assert_eq!(reason, "localhost resolves to no public address");
}

#[tokio::test]
async fn a_server_that_redirects_without_end_is_stopped() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/ip/8.8.8.8"))
        .mount(&server)
        .await;

    let reason = refusal(
        client_for(&server)
            .lookup_ip("8.8.8.8".parse().unwrap())
            .await
            .unwrap_err(),
    );

    assert_eq!(reason, "the server sent more than 5 redirects");
}

#[tokio::test]
async fn a_redirect_to_a_scheme_other_than_http_is_refused() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "ftp://example.com/"))
        .mount(&server)
        .await;

    let reason = refusal(
        client_for(&server)
            .lookup_ip("8.8.8.8".parse().unwrap())
            .await
            .unwrap_err(),
    );

    assert!(reason.contains("is not HTTP or HTTPS"), "{reason}");
}

#[tokio::test]
async fn a_body_that_announces_more_than_the_limit_is_refused() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b' '; MAX_RECORD_BYTES + 1]))
        .mount(&server)
        .await;

    let error = client_for(&server)
        .lookup_ip("8.8.8.8".parse().unwrap())
        .await
        .unwrap_err();

    match error {
        Error::TooLarge { limit, .. } => assert_eq!(limit, MAX_RECORD_BYTES),
        other => panic!("expected too large, got {other:?}"),
    }
}

#[tokio::test]
async fn a_chunked_body_past_the_limit_is_refused_while_it_streams() {
    // A chunked answer has no Content-Length, so only counting the chunks bounds it.
    // The server here sends chunks until the client stops reading.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 1024];
        let _ = socket.read(&mut request).await;

        let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        if socket.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        let chunk = format!("{:x}\r\n{}\r\n", 64 * 1024, " ".repeat(64 * 1024));
        // The client closes the connection when it passes the limit, and the next
        // write fails. That ends the task.
        for _ in 0..64 {
            if socket.write_all(chunk.as_bytes()).await.is_err() {
                return;
            }
        }
    });

    let services = format!(r#"{{"services":[[["0.0.0.0/0"],["http://{address}/"]]]}}"#);
    let client = Client::with_bootstrap(
        Bootstrap {
            ipv4: Registry::from_slice(services.as_bytes()).unwrap(),
            ..Bootstrap::default()
        },
        Destinations::Any,
    )
    .unwrap();

    let error = client
        .lookup_ip("8.8.8.8".parse().unwrap())
        .await
        .unwrap_err();

    assert!(
        matches!(error, Error::TooLarge { limit, .. } if limit == MAX_RECORD_BYTES),
        "expected too large, got {error:?}"
    );
    server.abort();
}
