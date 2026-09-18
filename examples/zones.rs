//! Asks the DNS sources for an address or a name, over the live zones.
//!
//! ```sh
//! cargo run --example zones -- 196.216.2.1
//! cargo run --example zones -- google.com
//! ```

use std::net::IpAddr;

use abuse_contact::{DomainName, Resolver};

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

    let resolver = Resolver::new()?;

    // An address has one DNS source. A name has two.
    let contacts = match target.parse::<IpAddr>() {
        Ok(ip) => resolver.abusix(ip).await?,
        Err(_) => {
            let domain = target.parse::<DomainName>()?;
            let mut found = resolver.abuse_net(&domain).await?;
            found.extend(resolver.rfc2142(&domain).await?);
            found
        }
    };

    if contacts.is_empty() {
        println!("{target}: no DNS source holds a contact");
    }
    for contact in contacts {
        println!(
            "{target}: {} ({:?}, from {:?})",
            contact.email, contact.scope, contact.source
        );
    }

    Ok(())
}
