//! The DNS server the resolver tests start, shared by every test that needs one.
//!
//! Each test file builds this module on its own, and not every file uses every item.

#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use abuse_contact::Resolver;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, MX, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

/// What the server holds at one name, for one record type.
#[derive(Clone)]
pub enum Held {
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
pub struct Server {
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
    pub async fn start(zone: Vec<(&'static str, RecordType, Held)>) -> Self {
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

    pub fn resolver(&self) -> Resolver {
        Resolver::with_nameservers(&[self.address]).unwrap()
    }

    /// Returns the names the server was asked for, in order.
    pub fn asked(&self) -> Vec<(String, RecordType)> {
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

pub fn emails(contacts: &[abuse_contact::Contact]) -> Vec<&str> {
    contacts
        .iter()
        .map(|contact| contact.email.as_str())
        .collect()
}
