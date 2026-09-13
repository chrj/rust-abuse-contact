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

## State

RDAP is fetched. `Client` picks the server from the IANA bootstrap registries and
returns the record.

The DNS zones are not fetched yet. `dns` builds the names to ask for and reads the
answers, but nothing asks. For AFRINIC space, where RDAP publishes no abuse entity,
those zones are the only source that answers.

The client sits behind the `http` feature, which is on by default. Turn it off to take
the readers alone, with no HTTP stack:

```sh
cargo add abuse-contact --no-default-features
```

## Look up an address

```rust
use abuse_contact::{Client, Scope, rank};

let client = Client::new().await?;

if let Some(response) = client.lookup_ip("8.8.8.8".parse()?).await? {
    for contact in rank(response.abuse_contacts(Scope::Network, "rdap.arin.net")) {
        println!("{} ({:?})", contact.email, contact.scope);
    }
}
```

There is a runnable version of this:

```sh
cargo run --example lookup -- 8.8.8.8
cargo run --example lookup -- example.com
```

A private or reserved address is refused. A regional registry holds a record for the
block such an address sits in, and that record names IANA. Answering with it gives a
contact that cannot act on a host inside your own network. The ranges come from the
IANA special-purpose address registries.

## What the client connects to

A record holds links, and a server sends redirects. Either can point at a service
inside your own network, such as a cloud metadata endpoint. The client connects to
public addresses only: it refuses such a link or redirect, and it drops every private
address a name resolves to. It does not use a proxy from the environment, because a
proxy resolves names where that check cannot see them.

The client also refuses a redirect from HTTPS to HTTP, and stops after five redirects.
It reads at most 1 MiB of a record and 4 MiB of a bootstrap registry.

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
| LACNIC | Top level | Yes, one for the registry |
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
