//! Finds the abuse contacts for an address or a name, from every live source.
//!
//! ```sh
//! cargo run --example lookup -- 8.8.8.8
//! cargo run --example lookup -- example.com
//! ```

use std::net::IpAddr;

use abuse_contact::{Client, DomainName, Finder, Query, Resolver};

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
    let query = match target.parse::<IpAddr>() {
        Ok(ip) => Query::Ip(ip),
        Err(_) => Query::Domain(target.parse::<DomainName>()?),
    };

    let finder = Finder::new(Client::new().await?, Resolver::new()?);
    let found = finder.lookup(query).await?;

    for failure in &found.failures {
        eprintln!("{target}: {failure}");
    }

    if found.contacts.is_empty() {
        println!("{target}: no source gave an abuse contact");
        return Ok(());
    }

    for contact in &found.contacts {
        println!(
            "{target}: {} ({:?}, from {:?})",
            contact.email, contact.scope, contact.source
        );
    }

    Ok(())
}
