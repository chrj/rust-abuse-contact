//! The RDAP source: the response types, and how to find the abuse contact in one.
//!
//! This module holds the smallest part of RDAP that an abuse lookup needs: entities,
//! their jCard, and the links. Fields this crate does not read are ignored, so a new
//! field on the registry side does not turn a working lookup into a parse error.

use std::net::IpAddr;
use std::ops::RangeInclusive;

use serde::Deserialize;

use crate::contact::{Contact, EmailAddress, Scope, Source};

/// An RDAP response, cut down to what an abuse lookup reads.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Response {
    /// The contacts attached to this object.
    #[serde(default)]
    pub entities: Vec<Entity>,
    /// Links to other records, including the registrar record for a domain.
    #[serde(default)]
    pub links: Vec<Link>,
    /// The first address of the network, on an IP record.
    ///
    /// This is kept as it came, so a value that is not a string does not stop the
    /// rest of the record from being read. [`Response::range`] reads it.
    #[serde(rename = "startAddress")]
    pub start_address: Option<serde_json::Value>,
    /// The last address of the network, on an IP record.
    #[serde(rename = "endAddress")]
    pub end_address: Option<serde_json::Value>,
}

/// A contact on an RDAP object.
///
/// An entity holds entities of its own. The abuse contact sits at the top level at
/// some registries and under the registrant or the registrar at others, so a reader
/// must walk the whole tree.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Entity {
    /// What this entity is: `abuse`, `registrant`, `technical`, and others.
    #[serde(default)]
    pub roles: Vec<String>,
    /// The registry handle, useful in a log line.
    pub handle: Option<String>,
    /// The contact details, as jCard.
    #[serde(rename = "vcardArray")]
    pub vcard_array: Option<serde_json::Value>,
    /// Entities under this one.
    #[serde(default)]
    pub entities: Vec<Entity>,
}

/// A link from one RDAP record to another.
#[derive(Clone, Debug, Deserialize)]
pub struct Link {
    /// What the target is to this record. `related` points at the registrar.
    pub rel: Option<String>,
    /// Where the target is.
    pub href: Option<String>,
}

/// Reads an address out of a JSON value, when the value is a string that holds one.
fn address(value: &serde_json::Value) -> Option<IpAddr> {
    value.as_str()?.parse().ok()
}

/// The role an entity carries when it accepts abuse reports.
const ABUSE_ROLE: &str = "abuse";

impl Response {
    /// Returns the addresses the network covers, on an IP record.
    ///
    /// Returns `None` when the record gives no range, or a range that cannot be read:
    /// an end that is not an address, two ends in different families, or an end
    /// before the start.
    pub fn range(&self) -> Option<RangeInclusive<IpAddr>> {
        let start = address(self.start_address.as_ref()?)?;
        let end = address(self.end_address.as_ref()?)?;

        let same_family = start.is_ipv4() == end.is_ipv4();
        (same_family && start <= end).then_some(start..=end)
    }

    /// Returns the registrar record for a domain, when the registry names one.
    ///
    /// The registry record usually carries the abuse address of the registrar, under
    /// the registrar entity. Read the registrar record when you want the details the
    /// registry leaves out, such as the abuse telephone number. It is a second
    /// request, so make it only when you need it.
    pub fn related_href(&self) -> Option<&str> {
        self.links
            .iter()
            .find(|link| link.rel.as_deref() == Some("related"))
            .and_then(|link| link.href.as_deref())
    }

    /// Returns every abuse contact in the response, each one time.
    ///
    /// A value that is not an address, or that is a registry placeholder, is dropped.
    ///
    /// One registry puts the same abuse entity at the top level and again under the
    /// registrant, so a walk of the tree finds it twice. The repeat says nothing, and
    /// this method drops it.
    pub fn abuse_contacts(&self, scope: Scope, server: &str) -> Vec<Contact> {
        let mut contacts = Vec::new();
        collect(&self.entities, scope, server, &mut contacts);

        let mut seen = std::collections::HashSet::new();
        contacts.retain(|contact| seen.insert(contact.email.clone()));
        contacts
    }
}

/// Walks the entity tree and collects the addresses of every entity with the abuse
/// role.
fn collect(entities: &[Entity], scope: Scope, server: &str, out: &mut Vec<Contact>) {
    for entity in entities {
        if entity.roles.iter().any(|role| role == ABUSE_ROLE) {
            out.extend(
                emails(entity.vcard_array.as_ref())
                    .into_iter()
                    .filter_map(|value| EmailAddress::new(value).ok())
                    .map(|email| Contact {
                        email,
                        scope,
                        source: Source::Rdap {
                            server: server.to_owned(),
                        },
                    }),
            );
        }

        collect(&entity.entities, scope, server, out);
    }
}

/// The preference of a vCard property that names none.
///
/// RFC 6350 gives such a property the lowest preference, so it sorts last.
const DEFAULT_PREF: u32 = 100;

/// Reads the email values out of a jCard, most preferred first.
///
/// jCard is a pair: the string `vcard`, then the properties. Each property is an
/// array where the name is first, the parameters second, and the value fourth, as in
/// `["email", {"pref": "1"}, "text", "abuse@example.com"]`. A property in another
/// shape is skipped rather than read by position, because position is all jCard
/// gives.
///
/// One registry lists a help desk and an abuse mailbox on the same entity and marks
/// the abuse mailbox `pref: 1`. Reading in document order gives the help desk, so the
/// values come back in preference order instead.
fn emails(vcard_array: Option<&serde_json::Value>) -> Vec<&str> {
    let Some(properties) = vcard_array
        .and_then(|v| v.get(1))
        .and_then(|v| v.as_array())
    else {
        return Vec::new();
    };

    let mut found: Vec<(u32, &str)> = properties
        .iter()
        .filter_map(|property| property.as_array())
        .filter(|property| property.first().and_then(|n| n.as_str()) == Some("email"))
        .filter_map(|property| {
            let value = property.get(3).and_then(|value| value.as_str())?;
            Some((preference(property.get(1)), value))
        })
        .collect();

    // A stable sort keeps document order among values of equal preference.
    found.sort_by_key(|(pref, _)| *pref);
    found.into_iter().map(|(_, value)| value).collect()
}

/// Returns the `pref` parameter of a jCard property.
///
/// Registries write it as a string and as a number, so both are read.
fn preference(parameters: Option<&serde_json::Value>) -> u32 {
    let Some(pref) = parameters.and_then(|p| p.get("pref")) else {
        return DEFAULT_PREF;
    };

    if let Some(text) = pref.as_str() {
        return text.parse().unwrap_or(DEFAULT_PREF);
    }

    pref.as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(DEFAULT_PREF)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ARIN answer for an IP address. The abuse entity is under the registrant.
    const ARIN_IP: &str = r#"{
      "entities": [{
        "handle": "GOGL",
        "roles": ["registrant"],
        "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Google LLC"]]],
        "entities": [{
          "handle": "ABUSE5250-ARIN",
          "roles": ["abuse"],
          "vcardArray": ["vcard", [
            ["fn", {}, "text", "Abuse"],
            ["email", {}, "text", "network-abuse@google.com"],
            ["tel", {"type": ["work", "voice"]}, "text", "+1-650-253-0000"]
          ]]
        }, {
          "handle": "ZG39-ARIN",
          "roles": ["administrative", "technical"],
          "vcardArray": ["vcard", [["email", {}, "text", "arin-contact@google.com"]]]
        }]
      }]
    }"#;

    /// A RIPE answer for an IP address. The abuse entity is at the top level.
    const RIPE_IP: &str = r#"{
      "entities": [{
        "handle": "MDIR-RIPE",
        "roles": ["administrative"],
        "vcardArray": ["vcard", [["fn", {}, "text", "Managing Director"]]]
      }, {
        "handle": "OPS4-RIPE",
        "roles": ["abuse"],
        "vcardArray": ["vcard", [
          ["fn", {}, "text", "RIPE NCC Operations"],
          ["email", {}, "text", "abuse@ripe.net"]
        ]]
      }]
    }"#;

    /// A registry answer for a domain. The abuse entity is under the registrar.
    const REGISTRY_DOMAIN: &str = r#"{
      "entities": [{
        "roles": ["registrar"],
        "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc."]]],
        "entities": [{
          "roles": ["abuse"],
          "vcardArray": ["vcard", [["email", {}, "text", "registrar-abuse@cloudflare.com"]]]
        }]
      }],
      "links": [
        {"rel": "self", "href": "https://rdap.verisign.com/com/v1/domain/cloudflare.com"},
        {"rel": "related", "href": "https://rdap.cloudflare.com/rdap/v1/domain/CLOUDFLARE.COM"}
      ]
    }"#;

    /// A registrar answer. The abuse entity is under the registrar, and every other
    /// contact is redacted.
    const REGISTRAR_DOMAIN: &str = r#"{
      "entities": [{
        "roles": ["registrar"],
        "vcardArray": ["vcard", [["email", {}, "text", "registrar-admin@cloudflare.com"]]],
        "entities": [{
          "roles": ["abuse"],
          "vcardArray": ["vcard", [
            ["fn", {}, "text", "Cloudflare Registrar Abuse"],
            ["email", {}, "text", "registrar-abuse@cloudflare.com"]
          ]]
        }]
      }, {
        "roles": ["registrant"],
        "vcardArray": ["vcard", [
          ["fn", {}, "text", "DATA REDACTED"],
          ["email", {}, "text", "DATA REDACTED"]
        ]]
      }]
    }"#;

    fn parse(json: &str) -> Response {
        serde_json::from_str(json).unwrap()
    }

    fn emails_of(response: &Response, scope: Scope) -> Vec<String> {
        response
            .abuse_contacts(scope, "rdap.example.net")
            .iter()
            .map(|c| c.email.to_string())
            .collect()
    }

    #[test]
    fn finds_an_abuse_entity_nested_under_the_registrant() {
        assert_eq!(
            emails_of(&parse(ARIN_IP), Scope::Network),
            ["network-abuse@google.com"]
        );
    }

    #[test]
    fn finds_an_abuse_entity_at_the_top_level() {
        assert_eq!(
            emails_of(&parse(RIPE_IP), Scope::Network),
            ["abuse@ripe.net"]
        );
    }

    #[test]
    fn ignores_entities_without_the_abuse_role() {
        let contacts = emails_of(&parse(ARIN_IP), Scope::Network);

        assert!(!contacts.contains(&"arin-contact@google.com".to_owned()));
    }

    #[test]
    fn finds_an_abuse_entity_nested_under_the_registrar() {
        assert_eq!(
            emails_of(&parse(REGISTRY_DOMAIN), Scope::Registrar),
            ["registrar-abuse@cloudflare.com"]
        );
    }

    #[test]
    fn returns_a_repeated_abuse_entity_one_time() {
        let response = parse(
            r#"{"entities":[
                 {"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","a@example.com"]]]},
                 {"roles":["registrant"],"entities":[
                   {"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","a@example.com"]]]}
                 ]}
               ]}"#,
        );

        assert_eq!(emails_of(&response, Scope::Network), ["a@example.com"]);
    }

    #[test]
    fn a_registry_domain_record_points_at_the_registrar() {
        assert_eq!(
            parse(REGISTRY_DOMAIN).related_href(),
            Some("https://rdap.cloudflare.com/rdap/v1/domain/CLOUDFLARE.COM")
        );
    }

    #[test]
    fn finds_the_registrar_abuse_contact_and_drops_the_redacted_one() {
        assert_eq!(
            emails_of(&parse(REGISTRAR_DOMAIN), Scope::Registrar),
            ["registrar-abuse@cloudflare.com"]
        );
    }

    #[test]
    fn records_which_server_answered() {
        let contacts = parse(RIPE_IP).abuse_contacts(Scope::Network, "rdap.db.ripe.net");

        assert_eq!(
            contacts[0].source,
            Source::Rdap {
                server: "rdap.db.ripe.net".to_owned()
            }
        );
    }

    #[test]
    fn reads_the_preferred_address_first() {
        // APNIC lists a help desk and an abuse mailbox, and marks the abuse one.
        let response = parse(
            r#"{"entities":[{"roles":["abuse"],"vcardArray":["vcard",[
                 ["email", {}, "text", "helpdesk@apnic.net"],
                 ["email", {"pref": "1"}, "text", "abuse@apnic.net"]
               ]]}]}"#,
        );

        assert_eq!(
            emails_of(&response, Scope::Network),
            ["abuse@apnic.net", "helpdesk@apnic.net"]
        );
    }

    #[test]
    fn reads_a_numeric_pref() {
        let response = parse(
            r#"{"entities":[{"roles":["abuse"],"vcardArray":["vcard",[
                 ["email", {}, "text", "second@example.com"],
                 ["email", {"pref": 1}, "text", "first@example.com"]
               ]]}]}"#,
        );

        assert_eq!(
            emails_of(&response, Scope::Network),
            ["first@example.com", "second@example.com"]
        );
    }

    #[test]
    fn keeps_document_order_when_no_property_names_a_preference() {
        let response = parse(
            r#"{"entities":[{"roles":["abuse"],"vcardArray":["vcard",[
                 ["email", {}, "text", "one@example.com"],
                 ["email", {}, "text", "two@example.com"]
               ]]}]}"#,
        );

        assert_eq!(
            emails_of(&response, Scope::Network),
            ["one@example.com", "two@example.com"]
        );
    }

    #[test]
    fn finds_an_entity_that_carries_the_abuse_role_beside_another() {
        // registro.br marks one entity both technical and abuse.
        let response = parse(
            r#"{"entities":[{"roles":["technical","abuse"],"vcardArray":["vcard",[
                 ["email", {}, "text", "noc@example.com"]
               ]]}]}"#,
        );

        assert_eq!(emails_of(&response, Scope::Network), ["noc@example.com"]);
    }

    #[test]
    fn an_abuse_entity_without_an_address_gives_nothing() {
        // registro.br publishes an abuse entity whose jCard holds only a name.
        let response = parse(
            r#"{"entities":[{"roles":["technical","abuse"],"vcardArray":["vcard",[
                 ["fn", {}, "text", "Frederico Augusto de Carvalho Neves"],
                 ["lang", {}, "language-tag", "pt"]
               ]]}]}"#,
        );

        assert_eq!(emails_of(&response, Scope::Network), Vec::<String>::new());
    }

    #[test]
    fn reads_an_empty_response() {
        let response = parse("{}");

        assert_eq!(response.abuse_contacts(Scope::Network, "x"), Vec::new());
        assert_eq!(response.related_href(), None);
    }

    #[test]
    fn skips_a_jcard_property_in_a_shape_it_does_not_know() {
        let response = parse(
            r#"{"entities":[{"roles":["abuse"],"vcardArray":["vcard",[
                 ["email"],
                 ["email", {}, "text", ["abuse@example.com"]],
                 ["email", {}, "text", "good@example.com"]
               ]]}]}"#,
        );

        assert_eq!(emails_of(&response, Scope::Network), ["good@example.com"]);
    }

    #[test]
    fn reads_the_range_of_a_network() {
        let response =
            parse(r#"{"startAddress": "8.8.8.0", "endAddress": "8.8.8.255", "entities": []}"#);

        assert_eq!(
            response.range(),
            Some("8.8.8.0".parse().unwrap()..="8.8.8.255".parse().unwrap())
        );
    }

    #[test]
    fn a_range_that_cannot_be_read_is_none() {
        for json in [
            // A domain record carries no range.
            r#"{}"#,
            r#"{"startAddress": "8.8.8.0"}"#,
            r#"{"startAddress": "8.8.8.0", "endAddress": "not an address"}"#,
            // The two ends are in different families.
            r#"{"startAddress": "8.8.8.0", "endAddress": "2001:db8::ff"}"#,
            // The range ends before it starts.
            r#"{"startAddress": "8.8.8.255", "endAddress": "8.8.8.0"}"#,
            // The field is not a string. The rest of the record is still read.
            r#"{"startAddress": 1, "endAddress": 2}"#,
        ] {
            assert_eq!(parse(json).range(), None, "{json}");
        }
    }
}
