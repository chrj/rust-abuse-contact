//! The RDAP answers a [`crate::Finder`] holds, so it does not ask a registry again.

use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::contact::Contact;
use crate::query::DomainName;

/// The RDAP answers a finder holds, and for how long.
///
/// The regional registries limit how often you can ask, and a run that reports a
/// spam wave asks about the same few networks again and again. An answer for an
/// address is held for the whole network range the registry returned, so it also
/// answers for every other address in that range. An answer for a domain is held for
/// that name.
///
/// A clone shares the answers with the original. Give a clone to
/// [`crate::Finder::with_cache`] and keep one to call [`Cache::clear`].
///
/// The cache drops an answer when its time is over, the next time it stores one. It
/// sets no other limit on its size. Read [`Cache::len`] and call [`Cache::clear`]
/// when you want one.
///
/// DNS answers are not held here. The resolver holds them for the TTL of the record.
#[derive(Clone, Debug)]
pub struct Cache {
    hold: Duration,
    entries: Arc<Mutex<Entries>>,
}

impl Cache {
    /// How long [`Cache::default`] holds an answer.
    pub const DEFAULT_HOLD: Duration = Duration::from_secs(60 * 60);

    /// Returns an empty cache that holds each answer for this long.
    ///
    /// A hold of zero holds nothing, so every lookup asks the registry.
    pub fn new(hold: Duration) -> Self {
        Self {
            hold,
            entries: Arc::default(),
        }
    }

    /// Returns how many answers the cache holds, including answers whose time is over
    /// and that it has not dropped yet.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Returns whether the cache holds no answers.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drops every answer.
    pub fn clear(&self) {
        *self.lock() = Entries::default();
    }

    /// Returns the contacts held for the network that holds this address.
    pub(crate) fn network(&self, ip: IpAddr) -> Option<Vec<Contact>> {
        self.lock().network(ip, Instant::now())
    }

    /// Holds the contacts for a network range.
    pub(crate) fn put_network(&self, range: RangeInclusive<IpAddr>, contacts: Vec<Contact>) {
        let now = Instant::now();
        self.lock()
            .put_network(range, contacts, now, now + self.hold);
    }

    /// Returns the contacts held for a domain.
    pub(crate) fn domain(&self, domain: &DomainName) -> Option<Vec<Contact>> {
        self.lock().domain(domain, Instant::now())
    }

    /// Holds the contacts for a domain.
    pub(crate) fn put_domain(&self, domain: DomainName, contacts: Vec<Contact>) {
        let now = Instant::now();
        self.lock()
            .put_domain(domain, contacts, now, now + self.hold);
    }

    fn lock(&self) -> MutexGuard<'_, Entries> {
        // A panic while the lock was held cannot leave an entry half written: each
        // change is one push or one insert. The answers are still good to use.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Default for Cache {
    /// Returns an empty cache that holds each answer for [`Cache::DEFAULT_HOLD`].
    fn default() -> Self {
        Self::new(Self::DEFAULT_HOLD)
    }
}

/// The answers, and the time each one is good until.
#[derive(Debug, Default)]
struct Entries {
    networks: Vec<(RangeInclusive<IpAddr>, Held)>,
    domains: HashMap<DomainName, Held>,
}

#[derive(Debug)]
struct Held {
    contacts: Vec<Contact>,
    until: Instant,
}

impl Held {
    fn is_live(&self, now: Instant) -> bool {
        now < self.until
    }
}

impl Entries {
    fn len(&self) -> usize {
        self.networks.len() + self.domains.len()
    }

    /// Returns the contacts of the narrowest live range that holds the address.
    ///
    /// Ranges can nest: a registry gives a large block to one holder, and a small
    /// part of it to another. The narrowest range is the one the registry gives for
    /// an address inside it.
    fn network(&self, ip: IpAddr, now: Instant) -> Option<Vec<Contact>> {
        self.networks
            .iter()
            .filter(|(range, held)| range.contains(&ip) && held.is_live(now))
            .min_by_key(|(range, _)| width(range))
            .map(|(_, held)| held.contacts.clone())
    }

    fn put_network(
        &mut self,
        range: RangeInclusive<IpAddr>,
        contacts: Vec<Contact>,
        now: Instant,
        until: Instant,
    ) {
        self.drop_expired(now);
        self.networks.retain(|(held, _)| *held != range);
        self.networks.push((range, Held { contacts, until }));
    }

    fn domain(&self, domain: &DomainName, now: Instant) -> Option<Vec<Contact>> {
        self.domains
            .get(domain)
            .filter(|held| held.is_live(now))
            .map(|held| held.contacts.clone())
    }

    fn put_domain(
        &mut self,
        domain: DomainName,
        contacts: Vec<Contact>,
        now: Instant,
        until: Instant,
    ) {
        self.drop_expired(now);
        self.domains.insert(domain, Held { contacts, until });
    }

    fn drop_expired(&mut self, now: Instant) {
        self.networks.retain(|(_, held)| held.is_live(now));
        self.domains.retain(|_, held| held.is_live(now));
    }
}

/// Returns how many addresses a range covers, less one.
fn width(range: &RangeInclusive<IpAddr>) -> u128 {
    number(*range.end()) - number(*range.start())
}

fn number(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::{EmailAddress, Scope, Source};

    const HOUR: Duration = Duration::from_secs(60 * 60);

    fn contacts(email: &str) -> Vec<Contact> {
        vec![Contact {
            email: EmailAddress::new(email).unwrap(),
            scope: Scope::Network,
            source: Source::Rdap {
                server: "rdap.example".to_owned(),
            },
        }]
    }

    fn range(start: &str, end: &str) -> RangeInclusive<IpAddr> {
        start.parse().unwrap()..=end.parse().unwrap()
    }

    fn emails(found: Option<Vec<Contact>>) -> Option<Vec<String>> {
        found.map(|contacts| contacts.iter().map(|c| c.email.to_string()).collect())
    }

    #[test]
    fn a_range_answers_for_every_address_in_it() {
        let now = Instant::now();
        let mut entries = Entries::default();
        entries.put_network(
            range("8.8.8.0", "8.8.8.255"),
            contacts("abuse@example.com"),
            now,
            now + HOUR,
        );

        for ip in ["8.8.8.0", "8.8.8.8", "8.8.8.255"] {
            assert_eq!(
                emails(entries.network(ip.parse().unwrap(), now)),
                Some(vec!["abuse@example.com".to_owned()]),
                "{ip}"
            );
        }
        for ip in ["8.8.7.255", "8.8.9.0", "::ffff:808:808"] {
            assert_eq!(entries.network(ip.parse().unwrap(), now), None, "{ip}");
        }
    }

    #[test]
    fn the_narrowest_range_answers_for_an_address_in_two() {
        let now = Instant::now();
        let mut entries = Entries::default();
        entries.put_network(
            range("8.8.8.0", "8.8.8.7"),
            contacts("customer@example.com"),
            now,
            now + HOUR,
        );
        entries.put_network(
            range("8.8.0.0", "8.8.255.255"),
            contacts("isp@example.com"),
            now,
            now + HOUR,
        );

        assert_eq!(
            emails(entries.network("8.8.8.1".parse().unwrap(), now)),
            Some(vec!["customer@example.com".to_owned()])
        );
        assert_eq!(
            emails(entries.network("8.8.9.1".parse().unwrap(), now)),
            Some(vec!["isp@example.com".to_owned()])
        );
    }

    #[test]
    fn an_answer_whose_time_is_over_is_not_given() {
        let now = Instant::now();
        let mut entries = Entries::default();
        entries.put_network(
            range("8.8.8.0", "8.8.8.255"),
            contacts("abuse@example.com"),
            now,
            now + HOUR,
        );
        let domain: DomainName = "example.com".parse().unwrap();
        entries.put_domain(
            domain.clone(),
            contacts("abuse@example.com"),
            now,
            now + HOUR,
        );

        let later = now + HOUR;
        assert_eq!(entries.network("8.8.8.8".parse().unwrap(), later), None);
        assert_eq!(entries.domain(&domain, later), None);
    }

    #[test]
    fn storing_an_answer_drops_the_answers_whose_time_is_over() {
        let now = Instant::now();
        let mut entries = Entries::default();
        entries.put_network(
            range("8.8.8.0", "8.8.8.255"),
            contacts("old@example.com"),
            now,
            now + HOUR,
        );
        entries.put_domain(
            "old.example".parse().unwrap(),
            contacts("old@example.com"),
            now,
            now + HOUR,
        );

        let later = now + HOUR;
        entries.put_domain(
            "new.example".parse().unwrap(),
            contacts("new@example.com"),
            later,
            later + HOUR,
        );

        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn storing_the_same_range_again_replaces_it() {
        let now = Instant::now();
        let mut entries = Entries::default();
        for email in ["old@example.com", "new@example.com"] {
            entries.put_network(
                range("8.8.8.0", "8.8.8.255"),
                contacts(email),
                now,
                now + HOUR,
            );
        }

        assert_eq!(entries.len(), 1);
        assert_eq!(
            emails(entries.network("8.8.8.8".parse().unwrap(), now)),
            Some(vec!["new@example.com".to_owned()])
        );
    }

    #[test]
    fn a_hold_of_zero_holds_nothing() {
        let cache = Cache::new(Duration::ZERO);
        cache.put_network(range("8.8.8.0", "8.8.8.255"), contacts("abuse@example.com"));

        assert_eq!(cache.network("8.8.8.8".parse().unwrap()), None);
    }

    #[test]
    fn a_clone_shares_the_answers_and_clear_drops_them() {
        let cache = Cache::default();
        let clone = cache.clone();
        clone.put_domain(
            "example.com".parse().unwrap(),
            contacts("abuse@example.com"),
        );

        assert_eq!(cache.len(), 1);
        cache.clear();
        assert!(clone.is_empty());
    }

    #[test]
    fn measures_the_width_of_a_range() {
        assert_eq!(width(&range("8.8.8.0", "8.8.8.255")), 255);
        assert_eq!(width(&range("2001:db8::", "2001:db8::ffff")), 0xffff);
    }
}
