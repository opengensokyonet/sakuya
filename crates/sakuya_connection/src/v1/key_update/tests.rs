//! Initiating key updates before 1-RTT packets are started, and the checks
//! of ACK frames and of the peer's updates.

use core::time::Duration;

use frunk_core::hlist;
use sakuya_packet_protection::{
    backend::{AeadAlgorithm, KdfAlgorithm, ring::RingBackend},
    secret::TrafficSecret,
};
use sakuya_wire::v1::header::KeyPhase;

use super::*;
use crate::{
    take::TakenPositions,
    v1::{
        keys::OneRttSendKeys,
        receive::{ReceiveGeneration, open_one_rtt},
    },
};

const AEAD: AeadAlgorithm = AeadAlgorithm::Aes128Gcm;

/// Three quarters of the confidentiality limit of AES-GCM.
const DUE: u64 = 3 << 21;

/// The confidentiality limit of AES-GCM.
const LIMIT: u64 = 1 << 23;

/// The probe timeout the tests measure the wait in.
const PTO: Duration = Duration::from_millis(100);

fn secret(byte: u8) -> TrafficSecret {
    TrafficSecret::new(KdfAlgorithm::HkdfSha256, &[byte; 32]).unwrap()
}

fn pn(number: u64) -> PacketNumber {
    PacketNumber::new(number).unwrap()
}

fn ms(millis: u64) -> Duration {
    Duration::from_millis(millis)
}

/// What the lineage of a sending call holds of the key update, as its
/// components.
struct Sending {
    keys: OneRttKeys<RingBackend, Duration>,
    usage: AeadUsage,
    confirmation: HandshakeConfirmation,
    numbers: KeyPhaseNumbers,
}

impl Sending {
    /// 1-RTT keys of `aead` installed as a client does, `sealed` packets
    /// sealed with generation 0, the handshake as `confirmation` says.
    fn new(aead: AeadAlgorithm, sealed: u64, confirmation: HandshakeConfirmation) -> Self {
        let mut keys = OneRttKeys::NotYet;
        keys.install(RingBackend, aead, secret(1), secret(2));
        Self {
            keys,
            usage: AeadUsage::having_sealed(sealed),
            confirmation,
            numbers: KeyPhaseNumbers::new(),
        }
    }

    /// Prepare the packet `number` at `now`; what came of it, whether the
    /// probe timeout was asked for, and the positions taken mutably: 0 for
    /// the keys, 1 for the usage, 3 for the numbers.
    fn prepare(
        &mut self,
        number: u64,
        now: Duration,
    ) -> (Result<(), AeadLimitReachedError>, bool, Vec<usize>) {
        let mut taken = TakenPositions::default();
        let mut asked = false;
        let result = {
            let mut lineage = Lineage::new(
                hlist![
                    &mut self.keys,
                    &mut self.usage,
                    &mut self.confirmation,
                    &mut self.numbers
                ],
                &mut taken,
            );
            prepare_one_rtt_packet::<RingBackend, _, _, _, _, _, _, _>(
                &mut lineage,
                pn(number),
                now,
                || {
                    asked = true;
                    PTO
                },
            )
        };
        (result, asked, taken.drain().collect())
    }

    /// An ACK frame up to `largest` arrived at `at` in a packet opened with
    /// `opened_with`.
    fn ack(&mut self, opened_with: u64, largest: u64, at: Duration) -> Result<(), KeyUpdateError> {
        let mut taken = TakenPositions::default();
        let mut lineage = Lineage::new(hlist![&mut self.keys, &mut self.numbers], &mut taken);
        ack_received::<RingBackend, _, _, _, _>(&mut lineage, Some(opened_with), pn(largest), at)
    }

    fn send(&self) -> &OneRttSendKeys<RingBackend> {
        self.keys.send().unwrap()
    }

    fn send_generation(&self) -> u64 {
        self.send().generation().generation()
    }

    fn confirmed_at(&self) -> Option<Duration> {
        match &self.keys {
            OneRttKeys::Live(keys) => keys.send_confirmed_at(),
            _ => None,
        }
    }
}

/// The peer's keys to the keys of [`Sending`].
fn peer() -> OneRttKeys<RingBackend, Duration> {
    let mut keys = OneRttKeys::NotYet;
    keys.install(RingBackend, AEAD, secret(2), secret(1));
    keys
}

/// A short header packet of `number`, with a 1-byte Destination Connection
/// ID and a 2-byte Packet Number field, carrying a PING and PADDING, sealed
/// with the current sending generation of `keys` and its Key Phase.
fn sealed(keys: &OneRttSendKeys<RingBackend>, number: u64) -> Vec<u8> {
    let key_phase = match keys.key_phase() {
        KeyPhase::Zero => 0,
        KeyPhase::One => 0x04,
    };
    let mut packet = vec![0x41 | key_phase, 0x07];
    packet.extend_from_slice(&u16::try_from(number).unwrap().to_be_bytes());
    packet.extend_from_slice(&[0x01; 20]);
    packet.extend_from_slice(&[0; 16]);
    keys.packet().seal(pn(number), &mut packet, 4).unwrap();
    keys.header().apply(&mut packet, 2).unwrap();
    packet
}

#[test]
fn below_three_quarters_of_the_limit_nothing_is_initiated() {
    let mut sending = Sending::new(AEAD, DUE - 1, HandshakeConfirmation::Confirmed);
    let (result, asked, taken) = sending.prepare(5, ms(10));
    assert!(result.is_ok());
    assert!(!asked);
    // the first packet of the generation is noted, and nothing else taken
    assert_eq!(taken, [3]);
    assert_eq!(sending.send_generation(), 0);
    assert_eq!(sending.numbers.lowest_sent(0), Some(pn(5)));
    // the packets that follow take nothing
    let (_, _, taken) = sending.prepare(6, ms(11));
    assert!(taken.is_empty());
    assert_eq!(sending.numbers.lowest_sent(0), Some(pn(5)));
}

#[test]
fn at_three_quarters_the_first_update_is_initiated_and_the_peer_opens_it() {
    let mut peer = peer();
    let mut sending = Sending::new(AEAD, DUE - 1, HandshakeConfirmation::Confirmed);
    sending.prepare(3, ms(10)).0.unwrap();
    let before = sealed(sending.send(), 3);
    sending.usage.sealed();
    let (result, asked, taken) = sending.prepare(4, ms(11));
    assert!(result.is_ok());
    // the first generation waits for no acknowledgment
    assert!(!asked);
    assert_eq!(taken, [0, 1, 3]);
    assert_eq!(sending.send_generation(), 1);
    assert_eq!(sending.send().key_phase(), KeyPhase::One);
    assert_eq!(sending.usage.sealed_with_current(), 0);
    assert_eq!(sending.confirmed_at(), None);
    assert_eq!(
        (
            sending.numbers.lowest_sent(0),
            sending.numbers.lowest_sent(1)
        ),
        (Some(pn(3)), Some(pn(4)))
    );
    // receiving goes on with generation 0 until the peer answers
    assert_eq!(sending.keys.receive().unwrap().current().generation(), 0);

    // the peer opens the packet before with its current generation, and
    // the update with the next one, by Key Phase and packet number alone
    let receive = peer.receive().unwrap();
    let mut packet = before;
    let (_, generation) = open_one_rtt(receive, None, &mut packet, 2, None).unwrap();
    assert_eq!(generation, ReceiveGeneration::Current);
    let mut packet = sealed(sending.send(), 4);
    let (opened, generation) =
        open_one_rtt(receive, Some(pn(3)), &mut packet, 2, Some(pn(3))).unwrap();
    assert_eq!(
        (opened.number, generation),
        (pn(4), ReceiveGeneration::Next)
    );
    let promotion = peer.promote_next().unwrap();
    assert_eq!((promotion.generation, promotion.send_updated), (1, true));
}

#[test]
fn chacha20_poly1305_never_initiates() {
    let mut sending = Sending::new(
        AeadAlgorithm::ChaCha20Poly1305,
        LIMIT * 4,
        HandshakeConfirmation::Confirmed,
    );
    let (result, asked, _) = sending.prepare(0, ms(10));
    assert!(result.is_ok());
    assert!(!asked);
    assert_eq!(sending.send_generation(), 0);
}

#[test]
fn no_update_before_the_handshake_is_confirmed() {
    let mut sending = Sending::new(AEAD, DUE, HandshakeConfirmation::NotConfirmed);
    let (result, _, taken) = sending.prepare(0, ms(10));
    assert!(result.is_ok());
    assert_eq!(taken, [3]);
    assert_eq!(sending.send_generation(), 0);
    // at the limit the keys may seal no more
    sending.usage = AeadUsage::having_sealed(LIMIT);
    let (result, _, taken) = sending.prepare(1, ms(11));
    assert!(matches!(
        result,
        Err(AeadLimitReachedError::ConfidentialityLimitReached)
    ));
    assert!(taken.is_empty());
    assert_eq!(sending.send_generation(), 0);
    // a server whose keys only send has no confirmed handshake either
    let mut keys = OneRttKeys::<_, Duration>::NotYet;
    keys.install_send(RingBackend, AEAD, secret(1));
    sending.keys = keys;
    sending.confirmation = HandshakeConfirmation::Confirmed;
    assert!(matches!(
        sending.prepare(1, ms(12)).0,
        Err(AeadLimitReachedError::ConfidentialityLimitReached)
    ));
}

#[test]
fn a_second_update_waits_for_an_acknowledgment_then_three_probe_timeouts() {
    let mut sending = Sending::new(AEAD, DUE, HandshakeConfirmation::Confirmed);
    sending.prepare(10, ms(10)).0.unwrap();
    assert_eq!(sending.send_generation(), 1);
    sending.usage = AeadUsage::having_sealed(DUE);
    // nothing of generation 1 is acknowledged yet
    let (result, asked, _) = sending.prepare(11, ms(20));
    assert!(result.is_ok());
    assert!(!asked);
    assert_eq!(sending.send_generation(), 1);
    // an acknowledgment of a packet of generation 0 confirms nothing
    sending.ack(0, 9, ms(30)).unwrap();
    assert_eq!(sending.confirmed_at(), None);
    // one of generation 1, in a packet of generation 1, does
    sending.keys.promote_next().unwrap();
    sending.ack(1, 10, ms(40)).unwrap();
    assert_eq!(sending.confirmed_at(), Some(ms(40)));
    // a later one keeps the instant
    sending.ack(1, 11, ms(45)).unwrap();
    assert_eq!(sending.confirmed_at(), Some(ms(40)));
    // three probe timeouts from the acknowledgment
    let (result, asked, _) = sending.prepare(12, ms(339));
    assert!(result.is_ok());
    assert!(asked);
    assert_eq!(sending.send_generation(), 1);
    let (result, _, taken) = sending.prepare(13, ms(340));
    assert!(result.is_ok());
    assert_eq!(taken, [0, 1, 3]);
    assert_eq!(sending.send_generation(), 2);
    assert_eq!(sending.numbers.lowest_sent(2), Some(pn(13)));
    assert_eq!(sending.confirmed_at(), None);
}

#[test]
fn at_the_limit_an_unacknowledged_update_closes_and_an_acknowledged_one_does_not_wait() {
    let mut sending = Sending::new(AEAD, DUE, HandshakeConfirmation::Confirmed);
    sending.prepare(10, ms(10)).0.unwrap();
    sending.usage = AeadUsage::having_sealed(LIMIT - 1);
    assert!(sending.prepare(11, ms(20)).0.is_ok());
    sending.usage.sealed();
    let (result, _, taken) = sending.prepare(12, ms(21));
    assert!(matches!(
        result,
        Err(AeadLimitReachedError::ConfidentialityLimitReached)
    ));
    assert!(taken.is_empty());
    assert_eq!(sending.send_generation(), 1);
    // acknowledged: the limit does not wait the three probe timeouts
    sending.keys.promote_next().unwrap();
    sending.ack(1, 10, ms(30)).unwrap();
    assert_eq!(sending.confirmed_at(), Some(ms(30)));
    let (result, asked, _) = sending.prepare(12, ms(31));
    assert!(result.is_ok());
    assert!(!asked);
    assert_eq!(sending.send_generation(), 2);
    assert_eq!(sending.usage.sealed_with_current(), 0);
}

#[test]
fn an_ack_under_older_keys_of_a_newer_packet_is_a_key_update_error() {
    let mut sending = Sending::new(AEAD, DUE, HandshakeConfirmation::Confirmed);
    sending.prepare(3, ms(10)).0.unwrap();
    sending.prepare(4, ms(10)).0.unwrap();
    // packet 3 was sealed with generation 1; the peer answers with
    // generation 0 still
    assert!(sending.ack(0, 2, ms(20)).is_ok());
    let error = sending.ack(0, 3, ms(21)).unwrap_err();
    assert!(matches!(
        error,
        KeyUpdateError::AckWithOldKeys { largest, lowest_newer }
            if largest == pn(3) && lowest_newer == pn(3)
    ));
    assert_eq!(sending.confirmed_at(), None);
    // under the newer keys it is an acknowledgment
    sending.keys.promote_next().unwrap();
    assert!(sending.ack(1, 4, ms(22)).is_ok());
    assert_eq!(sending.confirmed_at(), Some(ms(22)));
}

#[test]
fn a_second_update_of_the_peer_before_its_first_was_acknowledged_is_a_key_update_error() {
    let mut keys = peer();
    let mut numbers = KeyPhaseNumbers::new();
    let promotion = keys.promote_next().unwrap();
    assert!(check_peer_update(&numbers, promotion, pn(5)).is_ok());
    numbers.promoted(promotion.generation, pn(5));
    let promotion = keys.promote_next().unwrap();
    assert!(matches!(
        check_peer_update(&numbers, promotion, pn(6)),
        Err(KeyUpdateError::ConsecutiveUpdates { trigger, number })
            if trigger == pn(5) && number == pn(6)
    ));
    // once an ACK frame for the trigger was sent, the peer may update again
    numbers.ack_frame_sent(pn(5));
    assert!(check_peer_update(&numbers, promotion, pn(6)).is_ok());
}

#[test]
fn the_answer_to_this_sides_update_is_not_checked() {
    let mut keys = peer();
    let mut numbers = KeyPhaseNumbers::new();
    // the peer updated to generation 1, and nothing acknowledged packet 5
    let promotion = keys.promote_next().unwrap();
    numbers.promoted(promotion.generation, pn(5));
    // this side updates to generation 2, and the peer answers
    keys.initiate_update();
    let promotion = keys.promote_next().unwrap();
    assert!(!promotion.send_updated);
    assert!(check_peer_update(&numbers, promotion, pn(8)).is_ok());
}
