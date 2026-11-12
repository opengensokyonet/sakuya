//! The first-round branch table, end to end, and the classification interface

use std::sync::Arc;
use std::sync::atomic::Ordering;

use sakuya_link::Link as _;
use sakuya_wire::connection_id::StatelessResetToken;
use sakuya_wire::v1::header::LongPacketType;
use sakuya_wire::version::Version;

use super::support::{
    Domain, Factory, Judging, Local, Recorder, ResetProbe, cid, dcid_len, initial, lengths, link,
    local_end, long, nonempty, other_version, register, register_forms, short, version_negotiation,
};
use crate::claim::delivery::DatagramDelivery;
use crate::route::association::{MatchAssociation, PacketForms};
use crate::route::interpretation::FirstPacketInterpretation;

fn long_interpretation(packet_type: LongPacketType) -> FirstPacketInterpretation {
    FirstPacketInterpretation::Long {
        version: Version::V1,
        packet_type,
    }
}

/// One entry of each association for `label`'s connection ID, and one
/// zero-length entry of the local end `end`.
struct Entries {
    local: Arc<Recorder>,
    initial: Arc<Recorder>,
    zero: Arc<Recorder>,
    _registrations: Vec<
        crate::route::index::RouteEntryRegistration<super::support::Target, super::support::Local>,
    >,
}

fn entries(domain: &Domain, label: u8, end: &Local) -> Entries {
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
        register(domain.index(), MatchAssociation::ZeroCid(*end), &zero),
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
    let end = local_end();
    let entries = entries(&domain, 1, &end);
    // The token is the tail of the whole datagram, past its first packet.
    let mut datagram = long(LongPacketType::Handshake, &cid(1), &[], 40);
    datagram.extend(short(&cid(1), 30));
    let token: [u8; 16] = datagram[datagram.len() - 16..].try_into().unwrap();
    let probe = ResetProbe::default();
    let arrival = link(&end);
    let registration = domain.resets.register(
        arrival.id().peer,
        StatelessResetToken::new(token),
        probe.clone(),
    );

    domain.route(datagram.clone(), &arrival);
    assert_eq!(counts(&entries), [0, 0, 0]);
    assert_eq!(probe.0.load(Ordering::SeqCst), 1);

    drop(registration);
    domain.route(datagram, &arrival);
    assert_eq!(probe.0.load(Ordering::SeqCst), 1);
    assert_eq!(counts(&entries), [1, 0, 0]);
}

#[test]
fn datagram_shorter_than_a_token_is_never_a_reset() {
    let domain = Domain::new(&[8]);
    let end = local_end();
    let entries = entries(&domain, 1, &end);
    let datagram = short(&cid(1), 2);
    assert!(datagram.len() < 16);
    let mut token = [0; 16];
    token[16 - datagram.len()..].copy_from_slice(&datagram);
    let probe = ResetProbe::default();
    let arrival = link(&end);
    let _registration = domain.resets.register(
        arrival.id().peer,
        StatelessResetToken::new(token),
        probe.clone(),
    );
    domain.route(datagram, &arrival);
    assert_eq!(probe.0.load(Ordering::SeqCst), 0);
    assert_eq!(counts(&entries), [1, 0, 0]);
}

#[test]
fn unreadable_first_packet_is_released_without_guessing() {
    let domain = Domain::new(&[0]);
    let end = local_end();
    let entries = entries(&domain, 1, &end);
    let link = link(&end);

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
    let end = local_end();
    let entries = entries(&domain, 1, &end);
    domain.route(initial(&cid(1), &cid(9)), &link(&end));
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
    let end = local_end();
    let only = Recorder::new(1, Judging::Reject);
    let _registration = register(
        domain.index(),
        MatchAssociation::InitialDcid(nonempty(&cid(1))),
        &only,
    );
    domain.route(initial(&cid(1), &cid(9)), &link(&end));
    assert!(matches!(only.interpretations()[..], [_]));
    assert!(only.settle().is_empty());
    assert_eq!(only.claim_calls(), 1, "the sole participant still judges");
    assert_eq!(domain.drain(), 1);
}

#[test]
fn initial_the_domain_does_not_accept_goes_to_existing_entries_only() {
    let mut domain = Domain::new(&[8]);
    let end = local_end();
    let only = Recorder::new(1, Judging::Reject);
    let registration = register(
        domain.index(),
        MatchAssociation::InitialDcid(nonempty(&cid(1))),
        &only,
    );
    // Too small for a server to accept.
    let small = long(LongPacketType::Initial, &cid(1), &cid(9), 40);
    domain.route(small.clone(), &link(&end));
    assert!(matches!(only.take()[..], [DatagramDelivery::Exclusive(_)]));
    drop(registration);
    domain.route(small, &link(&end));
    assert!(domain.next_work().is_none());
    assert_eq!(domain.factory.shared().prepared.load(Ordering::SeqCst), 0);
}

#[test]
fn zero_rtt_uses_existing_local_and_initial_entries_and_never_creates() {
    let mut domain = Domain::new(&[8]);
    let end = local_end();
    let entries = entries(&domain, 1, &end);
    domain.route(
        long(LongPacketType::ZeroRtt, &cid(1), &cid(9), 40),
        &link(&end),
    );
    assert_eq!(counts(&entries), [1, 1, 0]);
    entries.local.settle();
    entries.initial.settle();
    domain.route(
        long(LongPacketType::ZeroRtt, &cid(2), &cid(9), 1200),
        &link(&end),
    );
    assert!(domain.next_work().is_none());
    assert_eq!(domain.factory.shared().prepared.load(Ordering::SeqCst), 0);
}

#[test]
fn handshake_and_retry_use_local_entries_only() {
    let domain = Domain::new(&[8]);
    let end = local_end();
    let entries = entries(&domain, 1, &end);
    domain.route(
        long(LongPacketType::Handshake, &cid(1), &cid(9), 40),
        &link(&end),
    );
    domain.route(
        long(LongPacketType::Retry, &cid(1), &cid(9), 0),
        &link(&end),
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
fn explicit_zero_length_long_header_uses_the_whole_local_end_bucket() {
    let domain = Domain::new(&[8]);
    let end = local_end();
    let entries = entries(&domain, 1, &end);
    let other = Recorder::new(4, Judging::Reject);
    let _other = register(
        domain.index(),
        MatchAssociation::ZeroCid(super::support::local_end()),
        &other,
    );
    domain.route(
        long(LongPacketType::Handshake, &[], &cid(9), 40),
        &link(&end),
    );
    assert_eq!(counts(&entries), [0, 0, 1]);
    assert_eq!(other.delivery_count(), 0);
}

#[test]
fn zero_length_entry_follows_the_local_end_not_the_peer() {
    let domain = Domain::new(&[0]);
    let end = local_end();
    let entries = entries(&domain, 1, &end);
    let (first, second) = (link(&end), link(&end));
    assert_ne!(first.id().peer, second.id().peer);
    let elsewhere = link(&local_end());
    // The peer changed, the local end did not: the registration is found.
    domain.route(short(&[], 30), &first);
    domain.route(short(&[], 30), &second);
    assert_eq!(counts(&entries), [0, 0, 2]);
    // Another local end finds nothing.
    domain.route(short(&[], 30), &elsewhere);
    assert_eq!(counts(&entries), [0, 0, 2]);
}

#[test]
fn version_negotiation_goes_to_existing_client_entries() {
    let domain = Domain::new(&[8]);
    let end = local_end();
    let entries = entries(&domain, 1, &end);
    domain.route(version_negotiation(&cid(1), &cid(9)), &link(&end));
    assert_eq!(counts(&entries), [1, 0, 0]);
    assert_eq!(
        entries.local.interpretations(),
        [FirstPacketInterpretation::VersionNegotiation]
    );
    // A destination connection ID that no version 1 entry can have.
    domain.route(version_negotiation(&[1; 40], &cid(9)), &link(&end));
    assert_eq!(counts(&entries), [1, 0, 0]);
}

#[test]
fn unsupported_version_goes_to_the_version_service_only() {
    let domain = Domain::new(&[8]);
    let end = local_end();
    let entries = entries(&domain, 1, &end);
    domain.route(
        other_version(Version::new(0x6b33_43cf), &cid(1)),
        &link(&end),
    );
    assert_eq!(counts(&entries), [0, 0, 0]);
    assert_eq!(
        *domain.versions.0.lock().unwrap(),
        [Version::new(0x6b33_43cf)]
    );
}

#[test]
fn unsupported_version_without_a_service_is_released() {
    use std::num::NonZeroUsize;

    use crate::claim::queue::DatagramDeliveryQueue;
    use crate::route::acceptance::InitialAcceptance;
    use crate::route::index::RouteIndex;
    use crate::route::router::DatagramRouter;

    let index = RouteIndex::<super::support::Target, Local>::new();
    let reflow = DatagramDeliveryQueue::new(NonZeroUsize::MIN).unwrap();
    let router = DatagramRouter::new(Arc::clone(&index), lengths(&[8])).with_initial_acceptance(
        InitialAcceptance::new(Factory::new(), Arc::new(reflow.poster())),
    );
    let end = local_end();
    let local = Recorder::new(1, Judging::Reject);
    let _registration = register(
        &index,
        MatchAssociation::LocalCid(nonempty(&cid(1))),
        &local,
    );
    router.route(super::support::datagram(
        other_version(Version::new(7), &cid(1)),
        &link(&end),
    ));
    assert_eq!(local.delivery_count(), 0);
}

#[test]
fn short_header_offers_zero_length_and_non_empty_readings_side_by_side() {
    let domain = Domain::new(&[8, 0]);
    let end = local_end();
    let entries = entries(&domain, 1, &end);
    domain.route(short(&cid(1), 30), &link(&end));
    assert_eq!(counts(&entries), [1, 0, 1]);
    assert_eq!(
        entries.local.interpretations(),
        [FirstPacketInterpretation::Short {
            dcid_len: dcid_len(8)
        }]
    );
    assert_eq!(
        entries.zero.interpretations(),
        [FirstPacketInterpretation::Short {
            dcid_len: dcid_len(0)
        }]
    );
}

#[test]
fn zero_length_is_never_an_implicit_short_header_fallback() {
    let domain = Domain::new(&[8]);
    let end = local_end();
    let entries = entries(&domain, 1, &end);
    // No local entry for this connection ID, and too short for the length.
    domain.route(short(&cid(2), 30), &link(&end));
    domain.route(vec![0x41, 1, 1, 1], &link(&end));
    assert_eq!(counts(&entries), [0, 0, 0]);
}

#[test]
fn repeated_recognizer_lengths_give_one_chance_per_entry() {
    let domain = Domain::new(&[8, 8, 0]);
    let end = local_end();
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
    domain.route(short(&cid(4), 30), &link(&end));
    assert_eq!(first.delivery_count(), 1);
    assert_eq!(second.delivery_count(), 1);
}

#[test]
fn matcher_forms_and_version_limit_where_an_entry_applies() {
    let domain = Domain::new(&[8]);
    let end = local_end();
    let short_only = Recorder::new(1, Judging::Reject);
    let other_version = Recorder::new(2, Judging::Reject);
    let _short_only = register_forms(
        domain.index(),
        MatchAssociation::LocalCid(nonempty(&cid(5))),
        PacketForms::SHORT,
        &short_only,
    );
    let _other_version = domain.index().register(
        crate::route::association::RouteMatcher::new(
            MatchAssociation::LocalCid(nonempty(&cid(5))),
            PacketForms::ALL,
            Version::new(2),
        ),
        Arc::clone(&other_version) as Arc<super::support::Target>,
    );
    domain.route(
        long(LongPacketType::Handshake, &cid(5), &[], 40),
        &link(&end),
    );
    assert_eq!(short_only.delivery_count(), 0);
    assert_eq!(other_version.delivery_count(), 0);
    domain.route(short(&cid(5), 30), &link(&end));
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
    let end = local_end();
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
    domain.route(datagram, &link(&end));
    let owned = local.settle();
    assert_eq!(owned.len(), 1);
    assert_eq!(owned[0].payload().len(), total);
    assert!(total > first_len);
}

#[test]
fn unclaimed_short_header_with_a_non_empty_dcid_goes_to_the_reset_service() {
    let mut domain = Domain::new(&[8]);
    let end = local_end();
    let datagram = short(&cid(7), 30);
    domain.route(datagram.clone(), &link(&end));
    assert_eq!(*domain.unclaimed.0.lock().unwrap(), [datagram]);
    assert!(domain.next_work().is_none());
}

#[test]
fn short_header_whose_candidates_all_exit_is_released() {
    let domain = Domain::new(&[8]);
    let end = local_end();
    let entries = entries(&domain, 1, &end);
    domain.route(short(&cid(1), 30), &link(&end));
    assert_eq!(counts(&entries), [1, 0, 0]);
    assert!(domain.unclaimed.0.lock().unwrap().is_empty());
}

#[test]
fn unclaimed_short_header_read_only_as_zero_length_is_released() {
    let domain = Domain::new(&[0]);
    let end = local_end();
    domain.route(short(&[], 30), &link(&end));
    assert!(domain.unclaimed.0.lock().unwrap().is_empty());
}

#[test]
fn unclaimed_short_header_with_any_non_empty_reading_goes_to_the_reset_service() {
    let domain = Domain::new(&[0, 8]);
    let end = local_end();
    domain.route(short(&cid(7), 30), &link(&end));
    assert_eq!(domain.unclaimed.0.lock().unwrap().len(), 1);
}

#[test]
fn short_header_too_short_for_any_reading_is_released() {
    let domain = Domain::new(&[8]);
    let end = local_end();
    // The first byte and four bytes of a destination connection ID.
    let mut datagram = short(&cid(7), 30);
    datagram.truncate(5);
    domain.route(datagram, &link(&end));
    assert!(domain.unclaimed.0.lock().unwrap().is_empty());
}
