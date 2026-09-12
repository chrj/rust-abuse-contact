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

The part that decides what an answer means is written and tested. The part that
fetches an answer is not: it needs an HTTP client for RDAP and a resolver for the DNS
zones. Until then, fetch with the client you already have and give the result to this
crate.

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

1. An HTTP client for RDAP, with the IANA bootstrap registry to pick the server.
2. A resolver for the Abusix and abuse.net zones.
3. A cache. The regional registries limit how often you can ask, and a report run
   asks about the same networks again and again.

## Tests

```sh
cargo test
```

The tests read captured answers from disk. They need no network.

## License

MIT. See [LICENSE](LICENSE).
