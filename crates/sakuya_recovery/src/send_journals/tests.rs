use super::*;
use core::time::Duration;

type Journals = DequeSendJournals<Duration, &'static str, u8>;

fn pn(value: u64) -> PacketNumber {
    PacketNumber::new(value).unwrap()
}

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

/// Seal one packet with a single frame on `link_path`.
fn seal(journals: &mut Journals, link_path: u8, summary: &'static str) -> DequeSealedPacket {
    let mut attempt = journals.start_attempt(link_path);
    attempt.record_frame(summary, true, true);
    attempt.seal(1200, false).unwrap()
}

fn numbers<'a>(packets: impl Iterator<Item = SentPacketRecord<Duration, &'a str, u8>>) -> Vec<u64> {
    packets.map(|p| p.number.get()).collect()
}

#[test]
fn the_first_packet_number_is_zero() {
    let mut journals = Journals::new();
    assert_eq!(journals.next_packet_number(), pn(0));
    let attempt = journals.start_attempt(1);
    assert_eq!(attempt.packet_number(), pn(0));
}

#[test]
fn an_attempt_without_a_frame_seals_to_nothing_and_takes_no_number() {
    let mut journals = Journals::new();
    let attempt = journals.start_attempt(1);
    assert_eq!(attempt.seal(1200, false), None);
    assert_eq!(journals.next_packet_number(), pn(0));
    // the next packet still gets 0
    let sealed = seal(&mut journals, 1, "a");
    assert_eq!(sealed, DequeSealedPacket { number: pn(0) });
}

#[test]
fn sealing_a_packet_with_frames_records_it_and_advances_the_number() {
    let mut journals = Journals::new();
    let mut attempt = journals.start_attempt(3);
    attempt.record_frame("crypto", true, true);
    attempt.record_frame("ack", false, false);
    let sealed = attempt.seal(1100, true).unwrap();
    assert_eq!(journals.next_packet_number(), pn(1));
    let record = journals.sent(sealed, ms(5)).clone();
    assert_eq!(
        record,
        SentPacketRecord {
            number: pn(0),
            link_path: 3,
            state: SentPacketState::Sent(ms(5)),
            bytes: 1100,
            ack_eliciting: true,
            in_flight: true,
            pmtu_probe: true,
            summaries: vec!["crypto", "ack"],
        }
    );
}

#[test]
fn a_packet_with_only_ack_frames_is_neither_ack_eliciting_nor_in_flight() {
    let mut journals = Journals::new();
    let mut attempt = journals.start_attempt(1);
    attempt.record_frame("ack", false, false);
    let sealed = attempt.seal(50, false).unwrap();
    let record = journals.sent(sealed, ms(1));
    assert!(!record.ack_eliciting);
    assert!(!record.in_flight);
}

#[test]
fn a_sealed_packet_waits_in_the_sealed_state() {
    let mut journals = Journals::new();
    let _sealed = seal(&mut journals, 1, "a");
    let taken: Vec<_> = journals.take_acknowledged(&(pn(0)..=pn(0))).collect();
    assert_eq!(taken[0].state, SentPacketState::Sealed);
}

#[test]
fn packet_numbers_increase_with_each_sealed_packet() {
    let mut journals = Journals::new();
    let a = seal(&mut journals, 1, "a");
    let b = seal(&mut journals, 1, "b");
    assert_eq!(a.number, pn(0));
    assert_eq!(b.number, pn(1));
    assert_eq!(journals.next_packet_number(), pn(2));
}

#[test]
fn an_unknown_send_result_marks_the_record_lost_without_a_send_time() {
    let mut journals = Journals::new();
    let sealed = seal(&mut journals, 1, "a");
    let record = journals.send_result_unknown(sealed, ms(90));
    assert_eq!(
        record.state,
        SentPacketState::Lost {
            sent_at: None,
            retain_until: ms(90)
        }
    );
}

#[test]
fn acknowledging_a_range_takes_sent_and_lost_records() {
    let mut journals = Journals::new();
    let a = seal(&mut journals, 1, "a");
    let b = seal(&mut journals, 1, "b");
    let c = seal(&mut journals, 1, "c");
    let d = seal(&mut journals, 1, "d");
    journals.sent(a, ms(1));
    journals.sent(b, ms(2));
    journals.send_result_unknown(c, ms(50));
    journals.sent(d, ms(4));
    journals.declare_lost(pn(1), ms(60)).unwrap();

    let taken: Vec<_> = journals.take_acknowledged(&(pn(1)..=pn(2))).collect();
    assert_eq!(taken.len(), 2);
    assert_eq!(taken[0].number, pn(1));
    assert!(matches!(
        taken[0].state,
        SentPacketState::Lost {
            sent_at: Some(_),
            ..
        }
    ));
    assert_eq!(taken[1].number, pn(2));
    assert!(matches!(
        taken[1].state,
        SentPacketState::Lost { sent_at: None, .. }
    ));
    // the others stay
    assert_eq!(
        numbers(journals.take_acknowledged(&(pn(0)..=pn(9)))),
        [0, 3]
    );
}

#[test]
fn acknowledging_a_range_without_records_takes_nothing() {
    let mut journals = Journals::new();
    let a = seal(&mut journals, 1, "a");
    journals.sent(a, ms(1));
    assert_eq!(journals.take_acknowledged(&(pn(4)..=pn(6))).count(), 0);
    assert_eq!(journals.take_acknowledged(&(pn(3)..=pn(2))).count(), 0);
}

#[test]
fn declaring_a_sent_packet_lost_keeps_its_send_time() {
    let mut journals = Journals::new();
    let a = seal(&mut journals, 1, "a");
    journals.sent(a, ms(7));
    let record = journals.declare_lost(pn(0), ms(70)).unwrap();
    assert_eq!(
        record.state,
        SentPacketState::Lost {
            sent_at: Some(ms(7)),
            retain_until: ms(70)
        }
    );
}

#[test]
fn only_a_sent_packet_can_be_declared_lost() {
    let mut journals = Journals::new();
    let a = seal(&mut journals, 1, "a");
    let b = seal(&mut journals, 1, "b");
    let c = seal(&mut journals, 1, "c");
    journals.sent(b, ms(1));
    journals.send_result_unknown(c, ms(50));
    // a is sealed, c is already lost, 9 does not exist
    assert_eq!(journals.declare_lost(pn(0), ms(9)), None);
    assert_eq!(journals.declare_lost(pn(2), ms(9)), None);
    assert_eq!(journals.declare_lost(pn(9), ms(9)), None);
    assert!(journals.declare_lost(pn(1), ms(9)).is_some());
    // declaring twice does nothing the second time
    assert_eq!(journals.declare_lost(pn(1), ms(99)), None);
    let _ = a;
}

#[test]
fn ending_a_link_path_takes_its_sealed_and_sent_records_only() {
    let mut journals = Journals::new();
    let p0 = seal(&mut journals, 1, "sent on 1");
    let p1 = seal(&mut journals, 2, "sent on 2");
    let p2 = seal(&mut journals, 1, "sealed on 1");
    let p3 = seal(&mut journals, 1, "lost on 1");
    let p4 = seal(&mut journals, 1, "unknown on 1");
    let p5 = seal(&mut journals, 2, "lost on 2");
    journals.sent(p0, ms(1));
    journals.sent(p1, ms(2));
    journals.sent(p3, ms(4));
    journals.send_result_unknown(p4, ms(80));
    journals.sent(p5, ms(6));
    journals.declare_lost(pn(3), ms(80)).unwrap();
    journals.declare_lost(pn(5), ms(80)).unwrap();
    let _ = p2;

    let taken: Vec<_> = journals.take_link_path(&1).collect();
    assert_eq!(
        taken.iter().map(|p| p.number.get()).collect::<Vec<_>>(),
        [0, 2]
    );
    assert_eq!(taken[0].state, SentPacketState::Sent(ms(1)));
    assert_eq!(taken[1].state, SentPacketState::Sealed);

    // the lost records of link path 1 are gone; link path 2 is untouched
    let rest: Vec<_> = journals.take_acknowledged(&(pn(0)..=pn(9))).collect();
    assert_eq!(
        rest.iter()
            .map(|p| (p.number.get(), p.link_path))
            .collect::<Vec<_>>(),
        [(1, 2), (5, 2)]
    );
    assert!(matches!(rest[1].state, SentPacketState::Lost { .. }));
}

#[test]
fn ending_a_link_path_without_records_takes_nothing() {
    let mut journals = Journals::new();
    let a = seal(&mut journals, 1, "a");
    journals.sent(a, ms(1));
    assert_eq!(journals.take_link_path(&9).count(), 0);
    assert_eq!(journals.take_acknowledged(&(pn(0)..=pn(0))).count(), 1);
}

#[test]
fn expired_lost_records_are_discarded_and_the_rest_stay() {
    let mut journals = Journals::new();
    let a = seal(&mut journals, 1, "lost, retained to 50");
    let b = seal(&mut journals, 1, "lost, retained to 100");
    let c = seal(&mut journals, 1, "sent");
    let d = seal(&mut journals, 1, "sealed");
    journals.send_result_unknown(a, ms(50));
    journals.send_result_unknown(b, ms(100));
    journals.sent(c, ms(3));
    let _ = d;

    journals.discard_expired(ms(49));
    assert_eq!(journals.take_acknowledged(&(pn(0)..=pn(0))).count(), 1);

    let mut journals2 = Journals::new();
    let a = seal(&mut journals2, 1, "a");
    let b = seal(&mut journals2, 1, "b");
    let c = seal(&mut journals2, 1, "c");
    let d = seal(&mut journals2, 1, "d");
    journals2.send_result_unknown(a, ms(50));
    journals2.send_result_unknown(b, ms(100));
    journals2.sent(c, ms(3));
    let _ = d;
    journals2.discard_expired(ms(50));
    assert_eq!(
        numbers(journals2.take_acknowledged(&(pn(0)..=pn(9)))),
        [1, 2, 3]
    );
}
