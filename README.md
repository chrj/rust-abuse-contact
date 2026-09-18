# abuse-contact

[![crates.io](https://img.shields.io/crates/v/abuse-contact.svg)](https://crates.io/crates/abuse-contact)
[![docs.rs](https://docs.rs/abuse-contact/badge.svg)](https://docs.rs/abuse-contact)
[![CI](https://github.com/chrj/rust-abuse-contact/actions/workflows/ci.yml/badge.svg)](https://github.com/chrj/rust-abuse-contact/actions/workflows/ci.yml)

Find where to report abuse for an IP address or a domain name.

The contact is in a different place for each kind of target, and the answers are not
interchangeable. The registrar of a domain can suspend the name. The network that
holds an IP address can take the host off the air. The operator of the domain runs the
service. A report goes to the one that can act on it, so this crate returns every
contact it finds with the scope it covers, and leaves the choice to you.

## Install

```sh
cargo add abuse-contact
```

## Find the contacts

```rust
use abuse_contact::{Client, Finder, Resolver};

let finder = Finder::new(Client::new().await?, Resolver::new()?);

let found = finder.lookup("196.216.2.1".parse::<std::net::IpAddr>()?).await?;
for contact in &found.contacts {
    println!("{} ({:?})", contact.email, contact.scope);
}
for failure in &found.failures {
    eprintln!("{failure}");
}
```

`Finder` asks every source for the target at the same time. An IP address goes to
RDAP and Abusix. A domain name goes to RDAP, abuse.net and RFC 2142. The contacts come
back ordered by `rank`, and an address that two sources give is kept one time.

A source that fails does not fail the lookup. Its error is in `failures`, beside the
contacts from the sources that answered. Check `failures` before you read an empty
`contacts` as "no contact is published". A private or reserved address is an error,
and no source is asked about it.

There is a runnable version of this:

```sh
cargo run --example lookup -- 8.8.8.8
cargo run --example lookup -- example.com
```

## Caching

The regional registries limit how often you can ask. `Finder` holds each RDAP answer
in a `Cache` for one hour, so it does not ask a registry about the same network or the
same domain again.

An answer for an address is held for the whole range the registry returned, so it
answers for every other address in that range. When two held ranges hold an address,
the narrower one answers. An answer for a domain is held for the name. A failed
lookup is not held.

```rust
use std::time::Duration;

use abuse_contact::{Cache, Client, Finder, Resolver};

let cache = Cache::new(Duration::from_secs(10 * 60));
let finder = Finder::new(Client::new().await?, Resolver::new()?).with_cache(cache.clone());

// The cache drops an answer whose time is over when it stores the next one. It sets
// no other limit on its size. Set your own:
if cache.len() > 10_000 {
    cache.clear();
}
```

`Cache::new(Duration::ZERO)` holds nothing.

DNS answers are held by the resolver, for the TTL of each record. A name that does
not exist is held for the time its zone gives for that.

A registry can give a large range to one holder and a small part of it to another,
with its own abuse contact. When the cache holds only the large range, it answers for
an address in the small one with the contact of the large one. Use a shorter hold when
that matters to you.

## Features

`Client` fetches RDAP and sits behind the `http` feature. `Resolver` asks the DNS
sources and sits behind the `dns` feature. `Finder` needs both. Both are on by
default. Turn them off to take the readers alone, with no HTTP stack and no resolver:

```sh
cargo add abuse-contact --no-default-features
```

## Ask the DNS sources

```rust
use abuse_contact::Resolver;

let resolver = Resolver::new()?;

// AFRINIC publishes no abuse contact in RDAP. Abusix has one.
let network = resolver.abusix("196.216.2.1".parse()?).await?;

let domain = "example.com".parse()?;
let operator = resolver.abuse_net(&domain).await?;
let guess = resolver.rfc2142(&domain).await?;
```

A name that a zone does not hold gives no contacts, not an error. A lookup that gets
no answer, such as a server failure, is an error, so a failing zone does not look like
a zone with nothing to say.

`rfc2142` gives `abuse@` at the domain only when the domain takes mail: it has an MX
record that names a host, or no MX record and an address of its own. A domain with a
null MX, RFC 7505, gives `None`.

There is a runnable version of this:

```sh
cargo run --example zones -- 196.216.2.1
cargo run --example zones -- google.com
```

## Fetch an RDAP record

```rust
use abuse_contact::{Client, Scope, rank};

let client = Client::new().await?;

if let Some(record) = client.lookup_ip("8.8.8.8".parse()?).await? {
    for contact in rank(record.abuse_contacts(Scope::Network)) {
        println!("{} ({:?})", contact.email, contact.scope);
    }
}
```

The record carries the server that answered, after any redirect, and each contact
names it as its source.

The client reads at most 1 MiB of a record and 4 MiB of a bootstrap registry. A server
that sends more is refused, so it cannot use up the memory of the process.

A private or reserved address is refused. A regional registry holds a record for the
block such an address sits in, and that record names IANA. Answering with it gives a
contact that cannot act on a host inside your own network. The ranges come from the
IANA special-purpose address registries.

## What the client connects to

A record holds links, and a server sends redirects. Either can point at a service
inside your own network, such as a cloud metadata endpoint. The client connects to
public addresses only. It refuses such a link or redirect, and it refuses a name that
resolves to any address that is not public. On a network with NAT64, it reads the IPv4
address inside an IPv6 address, because the connection ends there. It does not use a
proxy from the environment, because a proxy resolves names where that check cannot
see them.

The client also refuses a redirect from HTTPS to HTTP, and stops after five redirects.

Build a client with `Destinations::Any` only for a registry mirror that you run.

## Sources

| Source | Target | What it gives |
| --- | --- | --- |
| RDAP | IP, domain | The contact the registry publishes |
| Abusix | IP | The contact for the network, over DNS |
| abuse.net | domain | The contact the operator registered, over DNS |
| RFC 2142 | domain | `abuse@` at the domain, a guess |

## Read an RDAP answer

```rust
use abuse_contact::{Scope, rank};
use abuse_contact::rdap::Response;

let response: Response = serde_json::from_str(body)?;

for contact in rank(response.abuse_contacts(Scope::Network, "rdap.arin.net")) {
    println!("{} ({:?})", contact.email, contact.scope);
}
```

## Read a DNS answer

```rust
use abuse_contact::dns::{abusix_name, contacts_from_txt};
use abuse_contact::{Scope, Source};

// Ask your resolver for the TXT records at this name.
let name = abusix_name("104.16.132.229".parse()?);
assert_eq!(name, "229.132.16.104.abuse-contacts.abusix.zone");

let contacts = contacts_from_txt(&records, Scope::Network, Source::Abusix);
```

## What the registries do

Every row below came from a captured answer. The answers are in `tests/fixtures/` and
the tests in `tests/real_responses.rs` run against them.

| Registry | Where the abuse entity is | Gives an address |
| --- | --- | --- |
| ARIN | Under the registrant, and again at the top level | Yes |
| RIPE | Top level | Yes |
| APNIC | Top level, with `pref` on the abuse mailbox | Yes |
| LACNIC | Top level | Yes |
| AFRINIC | There is no abuse entity | **No** |
| registro.br | Top level, marked technical and abuse | **No, the jCard holds no email** |
| Verisign (.com) | Under the registrar | Yes |

Read that table as the reason the other sources exist. RDAP answers for five of the
seven. For AFRINIC and for registro.br it gives nothing, and DNS is the only source
left. A lookup that reads RDAP alone is blind in those two regions.

There are more traps than places to look.

ARIN sends the same abuse entity twice, at two depths. `abuse_contacts` returns each
address one time.

APNIC puts a help desk and an abuse mailbox on one entity and marks the abuse mailbox
`pref: 1`. Reading jCard in document order gives the help desk. The reader sorts by
preference, so the marked address comes first.

registro.br marks one entity both `technical` and `abuse`, so a reader that matches a
single role misses it.

A registry that hides contact data puts a fixed string in the email field. In the
captured answer it is `DATA REDACTED`, beside real addresses in the same response.
`EmailAddress` rejects it.

Abusix answers for AFRINIC space, where RDAP does not. For LACNIC space it answers
`removed@lacnic.net` for every network: six networks in four countries all gave that
one address, so it marks a contact that was withdrawn rather than naming a mailbox.
`EmailAddress` rejects it as `WithheldEmail`.

LACNIC RDAP does not withhold. It gives the address of the holder: thirteen networks
in nine countries gave twelve different addresses. `ipadmin@lacnic.net` comes back only
for networks that LACNIC holds itself, so it is a real contact for those networks and
not a marker.

jCard is positional. A property is an array with the name first, the parameters
second, and the value fourth, as in `["email", {"pref": "1"}, "text", "a@b.com"]`. A
property in another shape is skipped, because position is all jCard gives.

## Design

Values that go out are checked when you build them. `DomainName` refuses a name that
no registry can hold, so a lookup that is certain to find nothing never starts.

Values that come back are not checked the same way. A change on a registry side must
not turn a working lookup into a parse error, so `rdap::Response` reads the few fields
an abuse lookup needs and ignores the rest.

`Scope` is what makes the result usable. `Scope::Registrar` is who suspends a domain,
`Scope::Network` is who takes the host off the air. A crate that returns one address
and calls it "the" contact throws away the only thing you need to decide where to
write.

The crate finds contacts. It does not send mail.

## Next

The open work is on the [issue tracker](https://github.com/chrj/rust-abuse-contact/issues).

## Tests

```sh
cargo test
```

The tests read captured answers from disk. They need no network.

## License

MIT. See [LICENSE](LICENSE).
