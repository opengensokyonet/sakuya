//! The first-round branch table, end to end, and the classification interface

use std::sync::Arc;
use std::sync::atomic::Ordering;

use sakuya_wire::header::v1::{self, LongPacketType};

use super::support::{
    Domain, Judging, Recorder, ResetProbe, binding, cid, initial, link, long, nonempty,
    other_version, register, register_forms, short, version_negotiation,
};
use crate::claim::DatagramDelivery;
use crate::route::{FirstPacketInterpretation, MatchAssociation, PacketForms};

fn long_interpretation(packet_type: LongPacketType) -> FirstPacketInterpretation {
    FirstPacketInterpretation::Long {
        version: v1::VERSION,
        packet_type,
    }
}

/// One entry of each association for `label`'s connection ID, and one
/// zero-length entry of `binding`.
struct Entries {
    local: Arc<Recorder>,
    initial: Arc<Recorder>,
    zero: Arc<Recorder>,
    _registrations: Vec<crate::route::RouteEntryRegistration<super::support::Target>>,
}

fn entries(domain: &Domain, label: u8, binding: &sakuya_link::BindingId) -> Entries {
    let local = Recorder::new(1, Judging::Reject);
    let initial = Recorder::new(2, Judging::Reject);
    let zero = Recorder::new(3, Judging::Reject);
    let registrations = vec![
        register(
            domain.index(),
            MatchAssociation::LocalCid(nonempty(&cid(label))),
            &local,
        ),
        register(
            domain.index(),
            MatchAssociation::InitialDcid(nonempty(&cid(label))),
            &initial,
        ),
        register(
            domain.index(),
            MatchAssociation::ZeroCid(binding.clone()),
            &zero,
        ),
    ];
    Entries {
        local,
        initial,
        zero,
        _registrations: registrations,
    }
}

fn counts(entries: &Entries) -> [usize; 3] {
    [
        entries.local.delivery_count(),
        entries.initial.delivery_count(),
        entries.zero.delivery_count(),
    ]
}

#[test]
fn stateless_reset_hit_ends_ordinary_routing() {
    let domain = Domain::new(&[8]);
    let binding = binding();
    let entries = entries(&domain, 1, &binding);
    // The token is the tail of the whole datagram, past its first packet.
    let mut datagram = long(LongPacketType::Handshake, &cid(1), &[], 40);
    datagram.extend(short(&cid(1), 30));
    let token: [u8; 16] = datagram[datagram.len() - 16..].try_into().unwrap();
    let probe = ResetProbe::default();
    let registration = domain.resets.register(token, probe.clone());

    domain.route(datagram.clone(), &link(&binding));
    assert_eq!(counts(&entries), [0, 0, 0]);
    assert_eq!(probe.0.load(Ordering::SeqCst), 1);

    drop(registration);
    domain.route(datagram, &link(&binding));
    assert_eq!(probe.0.load(Ordering::SeqCst), 1);
    assert_eq!(counts(&entries), [1, 0, 0]);
}

#[test]
fn datagram_shorter_than_a_token_is_never_a_reset() {
    let domain = Domain::new(&[8]);
    let binding = binding();
    let entries = entries(&domain, 1, &binding);
    let datagram = short(&cid(1), 2);
    assert!(datagram.len() < 16);
    let mut token = [0; 16];
    token[16 - datagram.len()..].copy_from_slice(&datagram);
    let probe = ResetProbe::default();
    let _registration = domain.resets.register(token, probe.clone());
    domain.route(datagram, &link(&binding));
    assert_eq!(probe.0.load(Ordering::SeqCst), 0);
    assert_eq!(counts(&entries), [1, 0, 0]);
}

#[test]
fn unreadable_first_packet_is_released_without_guessing() {
    let domain = Domain::new(&[0]);
    let binding = binding();
    let entries = entries(&domain, 1, &binding);
    let link = link(&binding);

    domain.route(Vec::new(), &link);
    // A long header that ends inside its connection IDs.
    domain.route(vec![0xc0, 0, 0, 0, 1, 8, 1, 1], &link);
    // A version 1 Initial whose Length field points past the datagram.
    let mut truncated = initial(&cid(1), &cid(9));
    truncated.truncate(100);
    domain.route(truncated, &link);
    // A version 1 destination connection ID longer than 20 bytes.
    domain.route(long(LongPacketType::Handshake, &[7; 21], &[], 4), &link);
    assert_eq!(counts(&entries), [0, 0, 0]);
    assert_eq!(domain.versions.0.lock().unwrap().len(), 0);
}

#[test]
fn acceptable_initial_competes_under_both_associations_and_reflows() {
    let mut domain = Domain::new(&[8]);
    let binding = binding();
    let entries = entries(&domain, 1, &binding);
    domain.route(initial(&cid(1), &cid(9)), &link(&binding));
    assert_eq!(counts(&entries), [1, 1, 0]);
    assert_eq!(
        entries.local.interpretations(),
        [long_interpretation(LongPacketType::Initial)]
    );
    // Both candidates exit; the datagram is handed off, not processed inline.
    assert!(entries.local.settle().is_empty());
    assert!(domain.next_work().is_none());
    assert!(entries.initial.settle().is_empty());
    let work = domain
        .next_work()
        .expect("the last exit hands the datagram off");
    assert_eq!(work.offered_len(), 2);
    assert_eq!(work.initial().dcid().as_bytes(), cid(1));
    assert_eq!(work.initial().scid().as_bytes(), cid(9));
}

#[test]
fn acceptable_initial_with_one_entry_still_competes() {
    let mut domain = Domain::new(&[8]);
    let binding = binding();
    let only = Recorder::new(1, Judging::Reject);
    let _registration = register(
        domain.index(),
        MatchAssociation::InitialDcid(nonempty(&cid(1))),
        &only,
    );
    domain.route(initial(&cid(1), &cid(9)), &link(&binding));
    assert!(matches!(only.interpretations()[..], [_]));
    assert!(only.settle().is_empty());
    assert_eq!(only.claim_calls(), 1, "the sole participant still judges");
    assert_eq!(domain.drain(), 1);
}

#[test]
fn initial_the_domain_does_not_accept_goes_to_existing_entries_only() {
    let mut domain = Domain::new(&[8]);
    let binding = binding();
    let only = Recorder::new(1, Judging::Reject);
    let registration = register(
        domain.index(),
        MatchAssociation::InitialDcid(nonempty(&cid(1))),
        &only,
    );
    // Too small for a server to accept.
    let small = long(LongPacketType::Initial, &cid(1), &cid(9), 40);
    domain.route(small.clone(), &link(&binding));
    assert!(matches!(only.take()[..], [DatagramDelivery::Exclusive(_)]));
    drop(registration);
    domain.route(small, &link(&binding));
    assert!(domain.next_work().is_none());
    assert_eq!(domain.factory.shared().prepared.load(Ordering::SeqCst), 0);
}

#[test]
fn zero_rtt_uses_existing_local_and_initial_entries_and_never_creates() {
    let mut domain = Domain::new(&[8]);
    let binding = binding();
    let entries = entries(&domain, 1, &binding);
    domain.route(
        long(LongPacketType::ZeroRtt, &cid(1), &cid(9), 40),
        &link(&binding),
    );
    assert_eq!(counts(&entries), [1, 1, 0]);
    entries.local.settle();
    entries.initial.settle();
    domain.route(
        long(LongPacketType::ZeroRtt, &cid(2), &cid(9), 1200),
        &link(&binding),
    );
    assert!(domain.next_work().is_none());
    assert_eq!(domain.factory.shared().prepared.load(Ordering::SeqCst), 0);
}

#[test]
fn handshake_and_retry_use_local_entries_only() {
    let domain = Domain::new(&[8]);
    let binding = binding();
    let entries = entries(&domain, 1, &binding);
    domain.route(
        long(LongPacketType::Handshake, &cid(1), &cid(9), 40),
        &link(&binding),
    );
    domain.route(
        long(LongPacketType::Retry, &cid(1), &cid(9), 0),
        &link(&binding),
    );
    assert_eq!(counts(&entries), [2, 0, 0]);
    assert_eq!(
        entries.local.interpretations(),
        [
            long_interpretation(LongPacketType::Handshake),
            long_interpretation(LongPacketType::Retry)
        ]
    );
}

#[test]
fn explicit_zero_length_long_header_uses_the_whole_binding_bucket() {
    let domain = Domain::new(&[8]);
    let binding = binding();
    let entries = entries(&domain, 1, &binding);
    let other = Recorder::new(4, Judging::Reject);
    let _other = register(
        domain.index(),
        MatchAssociation::ZeroCid(super::support::binding()),
        &other,
    );
    domain.route(
        long(LongPacketType::Handshake, &[], &cid(9), 40),
        &link(&binding),
    );
    assert_eq!(counts(&entries), [0, 0, 1]);
    assert_eq!(other.delivery_count(), 0);
}

#[test]
fn version_negotiation_goes_to_existing_client_entries() {
    let domain = Domain::new(&[8]);
    let binding = binding();
    let entries = entries(&domain, 1, &binding);
    domain.route(version_negotiation(&cid(1), &cid(9)), &link(&binding));
    assert_eq!(counts(&entries), [1, 0, 0]);
    assert_eq!(
        entries.local.interpretations(),
        [FirstPacketInterpretation::VersionNegotiation]
    );
    // A destination connection ID that no version 1 entry can have.
    domain.route(version_negotiation(&[1; 40], &cid(9)), &link(&binding));
    assert_eq!(counts(&entries), [1, 0, 0]);
}

#[test]
fn unsupported_version_goes_to_the_version_service_only() {
    let domain = Domain::new(&[8]);
    let binding = binding();
    let entries = entries(&domain, 1, &binding);
    domain.route(other_version(0x6b33_43cf, &cid(1)), &link(&binding));
    assert_eq!(counts(&entries), [0, 0, 0]);
    assert_eq!(*domain.versions.0.lock().unwrap(), [0x6b33_43cf]);
}

#[test]
fn unsupported_version_without_a_service_is_released() {
    use crate::route::{ConnectionIdLengths, DatagramRouter, RouteIndex};

    let index = RouteIndex::<super::support::Target>::new();
    let router = DatagramRouter::new(Arc::clone(&index), ConnectionIdLengths::new(&[8]).unwrap());
    let binding = binding();
    let local = Recorder::new(1, Judging::Reject);
    let _registration = register(
        &index,
        MatchAssociation::LocalCid(nonempty(&cid(1))),
        &local,
    );
    router.route(super::support::datagram(
        other_version(7, &cid(1)),
        &link(&binding),
    ));
    assert_eq!(local.delivery_count(), 0);
}

#[test]
fn short_header_offers_zero_length_and_non_empty_readings_side_by_side() {
    let domain = Domain::new(&[8, 0]);
    let binding = binding();
    let entries = entries(&domain, 1, &binding);
    domain.route(short(&cid(1), 30), &link(&binding));
    assert_eq!(counts(&entries), [1, 0, 1]);
    assert_eq!(
        entries.local.interpretations(),
        [FirstPacketInterpretation::Short { dcid_len: 8 }]
    );
    assert_eq!(
        entries.zero.interpretations(),
        [FirstPacketInterpretation::Short { dcid_len: 0 }]
    );
}

#[test]
fn zero_length_is_never_an_implicit_short_header_fallback() {
    let domain = Domain::new(&[8]);
    let binding = binding();
    let entries = entries(&domain, 1, &binding);
    // No local entry for this connection ID, and too short for the length.
    domain.route(short(&cid(2), 30), &link(&binding));
    domain.route(vec![0x41, 1, 1, 1], &link(&binding));
    assert_eq!(counts(&entries), [0, 0, 0]);
}

#[test]
fn repeated_recognizer_lengths_give_one_chance_per_entry() {
    let domain = Domain::new(&[8, 8, 0]);
    let binding = binding();
    let first = Recorder::new(1, Judging::Reject);
    let second = Recorder::new(2, Judging::Reject);
    let _first = register(
        domain.index(),
        MatchAssociation::LocalCid(nonempty(&cid(4))),
        &first,
    );
    let _second = register(
        domain.index(),
        MatchAssociation::LocalCid(nonempty(&cid(4))),
        &second,
    );
    domain.route(short(&cid(4), 30), &link(&binding));
    assert_eq!(first.delivery_count(), 1);
    assert_eq!(second.delivery_count(), 1);
}

#[test]
fn matcher_forms_and_version_limit_where_an_entry_applies() {
    let domain = Domain::new(&[8]);
    let binding = binding();
    let short_only = Recorder::new(1, Judging::Reject);
    let other_version = Recorder::new(2, Judging::Reject);
    let _short_only = register_forms(
        domain.index(),
        MatchAssociation::LocalCid(nonempty(&cid(5))),
        PacketForms::SHORT,
        &short_only,
    );
    let _other_version = domain.index().register(
        crate::route::RouteMatcher::new(
            MatchAssociation::LocalCid(nonempty(&cid(5))),
            PacketForms::ALL,
            2,
        ),
        Arc::clone(&other_version) as Arc<super::support::Target>,
    );
    domain.route(
        long(LongPacketType::Handshake, &cid(5), &[], 40),
        &link(&binding),
    );
    assert_eq!(short_only.delivery_count(), 0);
    assert_eq!(other_version.delivery_count(), 0);
    domain.route(short(&cid(5), 30), &link(&binding));
    assert_eq!(short_only.delivery_count(), 1);
    assert_eq!(
        other_version.delivery_count(),
        1,
        "short headers carry no version"
    );
}

#[test]
fn coalesced_datagram_routes_by_its_first_packet_and_delivers_it_whole() {
    let domain = Domain::new(&[8]);
    let binding = binding();
    let local = Recorder::new(1, Judging::Accept);
    let _registration = register(
        domain.index(),
        MatchAssociation::LocalCid(nonempty(&cid(1))),
        &local,
    );
    let mut datagram = long(LongPacketType::Handshake, &cid(1), &[], 40);
    let first_len = datagram.len();
    datagram.extend(short(&cid(1), 30));
    let total = datagram.len();
    domain.route(datagram, &link(&binding));
    let owned = local.settle();
    assert_eq!(owned.len(), 1);
    assert_eq!(owned[0].payload().len(), total);
    assert!(total > first_len);
}
