use super::*;
use core::time::Duration;

type Journals = ReceiveJournals<Duration>;

fn pn(value: u64) -> PacketNumber {
    PacketNumber::new(value).unwrap()
}

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn receive(journals: &mut Journals, number: u64) {
    let admission = journals.admit(pn(number)).expect("not a duplicate");
    journals.record(admission, ms(number), None);
}

fn ranges(journals: &Journals) -> Vec<(u64, u64)> {
    journals
        .ranges()
        .iter()
        .map(|r| (r.start().get(), r.end().get()))
        .collect()
}

#[test]
fn a_new_packet_is_admitted_with_its_number() {
    let journals = Journals::new();
    let admission = journals.admit(pn(7)).unwrap();
    assert_eq!(admission.number(), pn(7));
}

#[test]
fn a_recorded_packet_is_a_duplicate() {
    let mut journals = Journals::new();
    receive(&mut journals, 4);
    assert_eq!(journals.admit(pn(4)), None);
    assert!(journals.admit(pn(3)).is_some());
}

#[test]
fn an_admission_that_is_dropped_records_nothing() {
    let journals = Journals::new();
    let _ = journals.admit(pn(2));
    assert!(journals.ranges().is_empty());
    assert!(journals.admit(pn(2)).is_some());
}

#[test]
fn a_packet_below_the_floor_is_a_duplicate() {
    let mut journals = Journals::new();
    for n in [1, 2, 3] {
        receive(&mut journals, n);
    }
    journals.on_ack_written();
    journals.acknowledged_up_to(pn(3));
    assert_eq!(journals.admit(pn(0)), None);
    assert_eq!(journals.admit(pn(3)), None);
    assert!(journals.admit(pn(4)).is_some());
}

#[test]
fn adjacent_packets_form_one_range() {
    let mut journals = Journals::new();
    receive(&mut journals, 5);
    receive(&mut journals, 6);
    receive(&mut journals, 4);
    assert_eq!(ranges(&journals), [(4, 6)]);
}

#[test]
fn a_packet_between_two_ranges_joins_them() {
    let mut journals = Journals::new();
    for n in [1, 2, 4, 5] {
        receive(&mut journals, n);
    }
    assert_eq!(ranges(&journals), [(4, 5), (1, 2)]);
    receive(&mut journals, 3);
    assert_eq!(ranges(&journals), [(1, 5)]);
}

#[test]
fn packets_with_gaps_stay_apart_largest_first() {
    let mut journals = Journals::new();
    for n in [2, 10, 6] {
        receive(&mut journals, n);
    }
    assert_eq!(ranges(&journals), [(10, 10), (6, 6), (2, 2)]);
}

#[test]
fn a_descending_arrival_extends_the_range_downwards() {
    let mut journals = Journals::new();
    for n in [9, 8, 7] {
        receive(&mut journals, n);
    }
    assert_eq!(ranges(&journals), [(7, 9)]);
}

#[test]
fn the_largest_follows_the_largest_packet_number() {
    let mut journals = Journals::new();
    assert_eq!(journals.largest(), None);
    receive(&mut journals, 5);
    receive(&mut journals, 3);
    assert_eq!(journals.largest(), Some((pn(5), ms(5))));
    receive(&mut journals, 6);
    assert_eq!(journals.largest(), Some((pn(6), ms(6))));
}

#[test]
fn a_packet_without_ecn_information_counts_nothing() {
    let mut journals = Journals::new();
    let admission = journals.admit(pn(0)).unwrap();
    journals.record(admission, ms(0), None);
    assert_eq!(journals.ecn_counts(), None);
}

#[test]
fn ecn_counts_start_at_the_first_packet_with_information() {
    let mut journals = Journals::new();
    receive(&mut journals, 0);
    assert_eq!(journals.ecn_counts(), None);
    let admission = journals.admit(pn(1)).unwrap();
    journals.record(admission, ms(1), Some(EcnCodepoint::Ect0));
    assert_eq!(
        journals.ecn_counts(),
        Some(&ReceivedEcnCounts {
            ect0: 1,
            ect1: 0,
            ce: 0
        })
    );
    // a later packet without information leaves the counts alone
    receive(&mut journals, 2);
    assert_eq!(journals.ecn_counts().unwrap().ect0, 1);
}

#[test]
fn not_ect_makes_the_counts_exist_without_counting() {
    let mut journals = Journals::new();
    let admission = journals.admit(pn(0)).unwrap();
    journals.record(admission, ms(0), Some(EcnCodepoint::NotEct));
    assert_eq!(journals.ecn_counts(), Some(&ReceivedEcnCounts::default()));
}

#[test]
fn each_codepoint_counts_in_its_own_field() {
    let mut counts = ReceivedEcnCounts::default();
    counts.add(EcnCodepoint::Ect0);
    counts.add(EcnCodepoint::Ect1);
    counts.add(EcnCodepoint::Ect1);
    counts.add(EcnCodepoint::Ce);
    counts.add(EcnCodepoint::Ce);
    counts.add(EcnCodepoint::Ce);
    counts.add(EcnCodepoint::NotEct);
    assert_eq!(
        counts,
        ReceivedEcnCounts {
            ect0: 1,
            ect1: 2,
            ce: 3
        }
    );
}

#[test]
fn the_default_limit_is_32_ranges() {
    assert_eq!(MaxAckRanges::default().get().get(), 32);
    assert_eq!(MaxAckRanges::DEFAULT, MaxAckRanges::default());
}

#[test]
fn an_acknowledged_ack_raises_the_floor_when_everything_was_reported() {
    let mut journals = Journals::new();
    for n in [1, 2, 3, 5] {
        receive(&mut journals, n);
    }
    journals.on_ack_written();
    journals.acknowledged_up_to(pn(5));
    assert_eq!(ranges(&journals), []);
    assert_eq!(journals.admit(pn(5)), None);
    assert!(journals.admit(pn(6)).is_some());
}

#[test]
fn the_floor_does_not_pass_a_packet_the_written_ack_did_not_report() {
    let mut journals = Journals::new();
    for n in [1, 2, 3, 5] {
        receive(&mut journals, n);
    }
    journals.on_ack_written();
    // 4 arrives after the ACK frame with ranges [1-3, 5] was written
    receive(&mut journals, 4);
    journals.acknowledged_up_to(pn(5));
    // the floor rises through 3 only; 4 and 5 stay in the ranges
    assert_eq!(ranges(&journals), [(4, 5)]);
    assert_eq!(journals.admit(pn(3)), None);
    assert_eq!(journals.admit(pn(4)), None);
    assert!(journals.admit(pn(6)).is_some());
}

#[test]
fn an_acknowledgment_below_the_unreported_packets_is_applied_as_given() {
    let mut journals = Journals::new();
    for n in [1, 2, 3, 5] {
        receive(&mut journals, n);
    }
    journals.on_ack_written();
    receive(&mut journals, 4);
    // 4 joined [1-3] and [5] into [1-5]; the floor rises through 2 only
    journals.acknowledged_up_to(pn(2));
    assert_eq!(ranges(&journals), [(3, 5)]);
    assert_eq!(journals.admit(pn(1)), None);
    assert_eq!(journals.admit(pn(2)), None);
}

#[test]
fn nothing_below_an_unreported_packet_zero_leaves_the_floor_alone() {
    let mut journals = Journals::new();
    receive(&mut journals, 0);
    journals.acknowledged_up_to(pn(10));
    assert_eq!(ranges(&journals), [(0, 0)]);
}

#[test]
fn unreported_packets_are_reported_again_after_the_next_ack_is_written() {
    let mut journals = Journals::new();
    receive(&mut journals, 1);
    journals.on_ack_written();
    receive(&mut journals, 2);
    journals.on_ack_written();
    journals.acknowledged_up_to(pn(2));
    assert_eq!(ranges(&journals), []);
}

#[test]
fn a_lower_floor_request_does_not_lower_the_floor() {
    let mut journals = Journals::new();
    for n in [1, 2, 3] {
        receive(&mut journals, n);
    }
    journals.on_ack_written();
    journals.acknowledged_up_to(pn(3));
    journals.acknowledged_up_to(pn(1));
    assert_eq!(journals.admit(pn(2)), None);
}

#[test]
fn the_floor_cuts_a_range_that_straddles_it() {
    let mut journals = Journals::new();
    for n in [1, 2, 3, 4, 5] {
        receive(&mut journals, n);
    }
    journals.on_ack_written();
    journals.acknowledged_up_to(pn(2));
    assert_eq!(ranges(&journals), [(3, 5)]);
}

#[test]
fn a_packet_recorded_below_a_floor_raised_meanwhile_is_not_inserted() {
    let mut journals = Journals::new();
    for n in [1, 2, 3] {
        receive(&mut journals, n);
    }
    let admission = journals.admit(pn(0)).unwrap();
    journals.on_ack_written();
    journals.acknowledged_up_to(pn(3));
    journals.record(admission, ms(9), None);
    assert_eq!(ranges(&journals), []);
}

#[test]
fn the_run_below_starts_where_the_received_packets_start() {
    let mut journals = Journals::new();
    for n in [1, 3, 4] {
        receive(&mut journals, n);
    }
    assert_eq!(journals.received_run_below(pn(4)), Some(pn(3)));
    assert_eq!(journals.received_run_below(pn(5)), Some(pn(3)));
}

#[test]
fn the_run_below_is_none_when_the_previous_packet_is_missing() {
    let mut journals = Journals::new();
    for n in [1, 3, 4] {
        receive(&mut journals, n);
    }
    // 2 did not arrive
    assert_eq!(journals.received_run_below(pn(3)), None);
    assert_eq!(journals.received_run_below(pn(6)), None);
}

#[test]
fn the_run_below_zero_is_none() {
    let mut journals = Journals::new();
    receive(&mut journals, 0);
    assert_eq!(journals.received_run_below(pn(0)), None);
}

#[test]
fn the_run_below_counts_packets_below_the_floor_as_received() {
    let mut journals = Journals::new();
    for n in [1, 2, 3] {
        receive(&mut journals, n);
    }
    journals.on_ack_written();
    journals.acknowledged_up_to(pn(3));
    assert_eq!(journals.received_run_below(pn(2)), Some(pn(0)));
    assert_eq!(journals.received_run_below(pn(4)), Some(pn(0)));
}

#[test]
fn a_run_that_reaches_the_floor_starts_at_zero() {
    let mut journals = Journals::new();
    for n in [1, 2, 3, 5, 6] {
        receive(&mut journals, n);
    }
    journals.on_ack_written();
    journals.acknowledged_up_to(pn(3));
    assert_eq!(ranges(&journals), [(5, 6)]);
    assert_eq!(journals.received_run_below(pn(7)), Some(pn(5)));
    // 4 is missing: it is at the floor but was never received
    assert_eq!(journals.received_run_below(pn(5)), None);
}

#[test]
fn the_limit_drops_the_oldest_ranges_and_raises_the_floor() {
    let mut journals = Journals::new();
    for n in [1, 3, 5, 7] {
        receive(&mut journals, n);
    }
    journals.limit(MaxAckRanges::new(NonZeroUsize::new(2).unwrap()));
    assert_eq!(ranges(&journals), [(7, 7), (5, 5)]);
    // the floor is 4, above the dropped ranges [1] and [3]
    assert_eq!(journals.admit(pn(1)), None);
    assert_eq!(journals.admit(pn(3)), None);
    assert!(journals.admit(pn(4)).is_some());
    assert!(journals.admit(pn(6)).is_some());
}

#[test]
fn a_limit_that_is_not_exceeded_changes_nothing() {
    let mut journals = Journals::new();
    for n in [1, 3] {
        receive(&mut journals, n);
    }
    let before = journals.clone();
    journals.limit(MaxAckRanges::new(NonZeroUsize::new(2).unwrap()));
    assert_eq!(journals, before);
}

#[test]
fn the_limit_keeps_the_largest_packet() {
    let mut journals = Journals::new();
    for n in [1, 3, 5] {
        receive(&mut journals, n);
    }
    journals.limit(MaxAckRanges::new(NonZeroUsize::new(1).unwrap()));
    assert_eq!(journals.largest(), Some((pn(5), ms(5))));
}
