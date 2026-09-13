//! The DNS sources, against a DNS server this test starts.
//!
//! The tests need no network and no live zone. Each one gives the server the records
//! it holds, and checks what the resolver makes of the answers.

#![cfg(feature = "dns")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use abuse_contact::{Error, Resolver, Scope, Source};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, MX, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

/// What the server holds at one name, for one record type.
#[derive(Clone)]
enum Held {
    /// TXT records. Each inner list is the strings of one record.
    Txt(Vec<Vec<&'static str>>),
    /// MX records, as preference and host.
    Mx(Vec<(u16, &'static str)>),
    /// An IPv4 address.
    A(Ipv4Addr),
    /// A server failure for this name.
    ServFail,
}

/// A DNS server on a local port. It stops when it is dropped.
struct Server {
    address: SocketAddr,
    asked: Arc<Mutex<Vec<(String, RecordType)>>>,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    /// Starts a server that holds these records. A name it holds nothing at does not
    /// exist. A name it holds another type at has no records of the type asked for.
    async fn start(zone: Vec<(&'static str, RecordType, Held)>) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&asked);

        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 1500];
            loop {
                let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                let Ok(query) = Message::from_vec(&buffer[..length]) else {
                    continue;
                };
                let answer = answer(&query, &zone, &log);
                if socket.send_to(&answer, peer).await.is_err() {
                    return;
                }
            }
        });

        Self {
            address,
            asked,
            task,
        }
    }

    fn resolver(&self) -> Resolver {
        Resolver::with_nameservers(&[self.address]).unwrap()
    }

    /// Returns the names the server was asked for, in order.
    fn asked(&self) -> Vec<(String, RecordType)> {
        self.asked.lock().unwrap().clone()
    }
}

/// Builds the answer to one query from the records the server holds.
fn answer(
    query: &Message,
    zone: &[(&'static str, RecordType, Held)],
    log: &Mutex<Vec<(String, RecordType)>>,
) -> Vec<u8> {
    let mut response = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;

    let Some(question) = query.queries.first() else {
        response.metadata.response_code = ResponseCode::FormErr;
        return response.to_vec().unwrap();
    };
    response.queries.push(question.clone());

    let asked_name = question.name.to_ascii().to_lowercase();
    let asked_type = question.query_type;
    log.lock().unwrap().push((asked_name.clone(), asked_type));

    let at_name: Vec<_> = zone
        .iter()
        .filter(|(name, _, _)| format!("{}.", name.trim_end_matches('.')) == asked_name)
        .collect();

    if at_name.is_empty() {
        response.metadata.response_code = ResponseCode::NXDomain;
        return response.to_vec().unwrap();
    }

    for (_, record_type, held) in at_name {
        if *record_type != asked_type {
            continue;
        }
        let owner = question.name.clone();
        match held {
            Held::ServFail => {
                response.metadata.response_code = ResponseCode::ServFail;
                return response.to_vec().unwrap();
            }
            Held::Txt(records) => {
                for strings in records {
                    let data = TXT::new(strings.iter().map(|s| (*s).to_owned()).collect());
                    response
                        .answers
                        .push(Record::from_rdata(owner.clone(), 60, RData::TXT(data)));
                }
            }
            Held::Mx(records) => {
                for (preference, host) in records {
                    let data = MX::new(*preference, host.parse::<Name>().unwrap());
                    response
                        .answers
                        .push(Record::from_rdata(owner.clone(), 60, RData::MX(data)));
                }
            }
            Held::A(ip) => {
                response
                    .answers
                    .push(Record::from_rdata(owner.clone(), 60, RData::A(A(*ip))));
            }
        }
    }

    response.to_vec().unwrap()
}

fn emails(contacts: &[abuse_contact::Contact]) -> Vec<&str> {
    contacts
        .iter()
        .map(|contact| contact.email.as_str())
        .collect()
}

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
