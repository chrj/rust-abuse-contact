//! Finds the abuse contact for an address or a name, over the live registries.
//!
//! ```sh
//! cargo run --example lookup -- 8.8.8.8
//! cargo run --example lookup -- example.com
//! ```

use std::net::IpAddr;

use abuse_contact::{Client, DomainName, Query, Scope, rank};

#[tokio::main]
async fn main() {
    // The default report for a returned error prints Debug, which hides the message
    // the error carries. Print the message instead, because it says what to do next.
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let Some(target) = std::env::args().nth(1) else {
        eprintln!("give an IP address or a domain name");
        std::process::exit(2);
    };

    // The variant picks the sources, so read the argument as an address first.
    let (query, scope) = match target.parse::<IpAddr>() {
        Ok(ip) => (Query::Ip(ip), Scope::Network),
        Err(_) => (
            Query::Domain(target.parse::<DomainName>()?),
            Scope::Registrar,
        ),
    };

    let client = Client::new().await?;

    let Some(response) = client.lookup(query).await? else {
        println!("{target}: the registry holds no record");
        return Ok(());
    };

    let contacts = rank(response.abuse_contacts(scope, "rdap"));
    if contacts.is_empty() {
        println!("{target}: the record carries no abuse contact");
        if let Some(href) = response.related_href() {
            println!("  the registrar record is at {href}");
        }
        return Ok(());
    }

    for contact in contacts {
        println!("{target}: {} ({:?})", contact.email, contact.scope);
    }

    Ok(())
}
