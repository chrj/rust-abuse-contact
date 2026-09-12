//! The parser, run against responses captured from the live registries.
//!
//! The fixtures in `tests/fixtures/` came from ARIN, RIPE, Verisign and the
//! Cloudflare registrar. They hold the shapes that a hand-written fixture gets
//! wrong: the abuse entity sits in a different place at each registry, and the
//! registry record for a domain carries no address at all.

use abuse_contact::rdap::Response;
use abuse_contact::{Scope, Source, rank};

fn load(name: &str) -> Response {
    let path = format!("{}/tests/fixtures/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn emails(response: &Response, scope: Scope) -> Vec<String> {
    response
        .abuse_contacts(scope, "rdap.test")
        .iter()
        .map(|c| c.email.to_string())
        .collect()
}

#[test]
fn reads_the_abuse_contact_from_an_arin_answer() {
    // ARIN puts the abuse entity under the registrant.
    assert_eq!(
        emails(&load("arin-ip"), Scope::Network),
        ["network-abuse@google.com"]
    );
}

#[test]
fn reads_the_abuse_contact_from_a_ripe_answer() {
    // RIPE puts the abuse entity at the top level.
    assert_eq!(emails(&load("ripe-ip"), Scope::Network), ["abuse@ripe.net"]);
}

#[test]
fn reads_the_abuse_contact_for_a_second_arin_network() {
    // This answer holds the same abuse entity twice, at two depths. It must come
    // back one time.
    assert_eq!(
        emails(&load("arin-cloudflare-ip"), Scope::Network),
        ["abuse@cloudflare.com"]
    );
}

#[test]
fn a_registry_domain_answer_carries_the_registrar_abuse_contact() {
    // Verisign nests the abuse entity under the registrar entity. One request is
    // enough for the address.
    assert_eq!(
        emails(&load("registry-domain"), Scope::Registrar),
        ["registrar-abuse@cloudflare.com"]
    );
}

#[test]
fn a_registry_domain_answer_points_at_the_registrar() {
    assert_eq!(
        load("registry-domain").related_href(),
        Some("https://rdap.cloudflare.com/rdap/v1/domain/CLOUDFLARE.COM")
    );
}

#[test]
fn the_registrar_answer_carries_the_abuse_contact() {
    assert_eq!(
        emails(&load("registrar-domain"), Scope::Registrar),
        ["registrar-abuse@cloudflare.com"]
    );
}

#[test]
fn the_registrar_answer_drops_every_redacted_contact() {
    let found = emails(&load("registrar-domain"), Scope::Registrar);

    assert!(
        !found.iter().any(|e| e.to_uppercase().contains("REDACTED")),
        "a redacted placeholder reached the caller: {found:?}"
    );
}

#[test]
fn both_hops_for_a_domain_give_the_same_address_one_time() {
    let registry = load("registry-domain");
    assert!(registry.related_href().is_some(), "no registrar to follow");

    // The second hop is what the caller would fetch from that link. It gives the
    // same address, so a caller that makes both requests must not report twice.
    let registrar = load("registrar-domain");

    let mut found = registry.abuse_contacts(Scope::Registrar, "rdap.verisign.com");
    found.extend(registrar.abuse_contacts(Scope::Registrar, "rdap.cloudflare.com"));

    let ranked = rank(found);

    assert_eq!(ranked.len(), 1);
    assert_eq!(ranked[0].email.as_str(), "registrar-abuse@cloudflare.com");
    assert_eq!(
        ranked[0].source,
        Source::Rdap {
            server: "rdap.verisign.com".to_owned()
        }
    );
}

// --- The other regional registries -------------------------------------------
//
// Each registry puts the abuse contact somewhere else, and two of them do not
// publish one at all. A caller that reads RDAP alone is blind in those two regions.

#[test]
fn reads_the_preferred_address_from_an_apnic_answer() {
    // APNIC lists a help desk beside the abuse mailbox and marks the abuse one
    // `pref: 1`. Document order gives the help desk, so preference must win.
    let found = emails(&load("apnic-ip"), Scope::Network);

    assert_eq!(found.first().map(String::as_str), Some("abuse@apnic.net"));
}

#[test]
fn reads_the_abuse_contact_from_a_lacnic_answer() {
    assert_eq!(
        emails(&load("lacnic-ip"), Scope::Network),
        ["ipadmin@lacnic.net"]
    );
}

#[test]
fn an_afrinic_answer_has_no_abuse_contact() {
    // AFRINIC publishes technical, administrative and registrant entities, and no
    // entity with the abuse role. RDAP cannot answer for this region.
    assert_eq!(
        emails(&load("afrinic-ip"), Scope::Network),
        Vec::<String>::new()
    );
}

#[test]
fn a_registro_br_abuse_entity_carries_no_address() {
    // registro.br marks an entity both technical and abuse, but its jCard holds a
    // name and a language and no email at all.
    assert_eq!(
        emails(&load("registrobr-ip"), Scope::Network),
        Vec::<String>::new()
    );
}

#[test]
fn every_captured_answer_is_read_without_an_error() {
    // The point is that none of these panic or fail to parse, whatever they hold.
    for name in [
        "arin-ip",
        "arin-cloudflare-ip",
        "ripe-ip",
        "apnic-ip",
        "lacnic-ip",
        "afrinic-ip",
        "registrobr-ip",
        "registry-domain",
        "registrar-domain",
    ] {
        let response = load(name);
        let found = response.abuse_contacts(Scope::Network, "rdap.test");

        for contact in &found {
            assert!(
                contact.email.as_str().contains('@'),
                "{name} gave something that is not an address: {:?}",
                contact.email
            );
        }
    }
}
