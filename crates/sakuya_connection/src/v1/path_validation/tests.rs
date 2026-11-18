use core::time::Duration;

use super::{PathValidation, PathValidationConclusion, Progress};

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// A validation with a challenge due, as a candidate starts.
fn due() -> PathValidation<Duration> {
    let mut validation = PathValidation::default();
    let _ = validation.challenge_due();
    validation
}

/// Write a challenge with `data` into a datagram sealed with `len` bytes
/// and accepted at `at`, timed with `resend_after` and `abandon_after`.
fn send(
    validation: &mut PathValidation<Duration>,
    data: u8,
    len: usize,
    at: Duration,
    resend_after: Duration,
    abandon_after: Duration,
) {
    validation.written([data; 8]);
    validation.datagram_sealed(len);
    validation.timed(at, resend_after, abandon_after);
    validation.accepted(at);
}

#[test]
fn a_response_over_the_link_path_validates_address_and_mtu_with_its_rtt() {
    let mut validation = due();
    assert!(validation.is_due());
    send(&mut validation, 1, 1200, ms(10), ms(100), ms(3000));
    assert!(!validation.is_due());
    assert_eq!(validation.untimed_attempt(), None);
    assert_eq!(validation.deadline(), Some(ms(110)));
    assert_eq!(
        validation.responded([1; 8], true, ms(40)),
        Some(PathValidationConclusion::Validated {
            initial_rtt: Some(ms(30))
        })
    );
    assert_eq!(
        validation.take_conclusion(),
        Some(PathValidationConclusion::Validated {
            initial_rtt: Some(ms(30))
        })
    );
    // done: nothing is due or awaited
    assert!(!validation.is_validating());
    assert_eq!(validation.deadline(), None);
}

#[test]
fn a_response_over_another_link_path_validates_without_an_rtt() {
    let mut validation = due();
    send(&mut validation, 1, 1200, ms(10), ms(100), ms(3000));
    assert_eq!(
        validation.responded([1; 8], false, ms(40)),
        Some(PathValidationConclusion::Validated { initial_rtt: None })
    );
}

#[test]
fn a_response_that_echoes_no_challenge_concludes_nothing() {
    let mut validation = due();
    send(&mut validation, 1, 1200, ms(10), ms(100), ms(3000));
    assert_eq!(validation.responded([2; 8], true, ms(40)), None);
    assert_eq!(validation.take_conclusion(), None);
    assert!(validation.is_validating());
}

#[test]
fn a_challenge_not_expanded_validates_the_address_only_and_a_second_validation_follows() {
    let mut validation = due();
    // held to 180 bytes by the anti-amplification limit
    send(&mut validation, 1, 180, ms(10), ms(100), ms(3000));
    assert_eq!(
        validation.responded([1; 8], true, ms(40)),
        Some(PathValidationConclusion::Validated {
            initial_rtt: Some(ms(30))
        })
    );
    assert_eq!(validation.progress, Progress::Address);
    // the second one starts at once, with an instant to give up of its own
    assert!(validation.is_due());
    assert_eq!(validation.abandon_at(), None);
    send(&mut validation, 2, 1200, ms(50), ms(100), ms(3000));
    assert_eq!(validation.untimed_attempt(), None);
    assert_eq!(validation.abandon_at(), Some(ms(3050)));
    // the second validation concludes nothing more for the rules
    let _ = validation.take_conclusion();
    assert_eq!(validation.responded([2; 8], true, ms(80)), None);
    assert_eq!(validation.take_conclusion(), None);
    assert!(!validation.is_validating());
}

#[test]
fn the_second_validation_that_gives_up_fails() {
    let mut validation = due();
    send(&mut validation, 1, 180, ms(10), ms(100), ms(3000));
    let _ = validation.responded([1; 8], true, ms(40));
    let _ = validation.take_conclusion();
    send(&mut validation, 2, 1200, ms(50), ms(100), ms(3000));
    assert!(!validation.expired(ms(150)));
    assert!(validation.is_due());
    assert!(validation.expired(ms(3050)));
    assert_eq!(
        validation.take_conclusion(),
        Some(PathValidationConclusion::Failed)
    );
}

#[test]
fn the_next_challenge_comes_due_and_the_validation_gives_up_at_the_first_ones_instant() {
    let mut validation = due();
    send(&mut validation, 1, 1200, ms(0), ms(1000), ms(3000));
    assert!(!validation.expired(ms(999)));
    assert!(!validation.is_due());
    assert!(!validation.expired(ms(1000)));
    assert!(validation.is_due());
    assert_eq!(validation.resend_at(), None);
    send(&mut validation, 2, 1200, ms(1000), ms(2000), ms(9000));
    assert_eq!(validation.untimed_attempt(), None);
    // the instant to give up stays the first challenge's
    assert_eq!(validation.abandon_at(), Some(ms(3000)));
    assert_eq!(validation.deadline(), Some(ms(3000)));
    assert!(validation.expired(ms(3000)));
    assert_eq!(
        validation.take_conclusion(),
        Some(PathValidationConclusion::Failed)
    );
    assert!(!validation.is_validating());
}

#[test]
fn a_late_response_to_an_earlier_challenge_still_validates() {
    let mut validation = due();
    send(&mut validation, 1, 1200, ms(0), ms(1000), ms(3000));
    let _ = validation.expired(ms(1000));
    send(&mut validation, 2, 1200, ms(1000), ms(2000), ms(3000));
    assert!(matches!(
        validation.responded([1; 8], true, ms(1100)),
        Some(PathValidationConclusion::Validated {
            initial_rtt: Some(rtt)
        }) if rtt == ms(1100)
    ));
}

#[test]
fn four_challenges_are_kept_and_a_fifth_forgets_the_oldest() {
    let mut validation = due();
    for data in 1..=5 {
        let _ = validation.challenge_due();
        send(&mut validation, data, 1200, ms(0), ms(1000), ms(9000));
    }
    assert_eq!(validation.responded([1; 8], true, ms(10)), None);
    assert!(validation.responded([2; 8], true, ms(10)).is_some());
}

#[test]
fn the_timing_counts_from_the_datagram_accepted() {
    let mut validation = due();
    validation.written([1; 8]);
    validation.datagram_sealed(1200);
    // timed when written, accepted later
    validation.timed(ms(0), ms(1000), ms(3000));
    assert_eq!(validation.resend_at(), Some(ms(1000)));
    validation.accepted(ms(50));
    assert_eq!(validation.resend_at(), Some(ms(1050)));
    assert_eq!(validation.abandon_at(), Some(ms(3000)));
    // the RTT counts from the acceptance
    assert_eq!(
        validation.responded([1; 8], true, ms(80)),
        Some(PathValidationConclusion::Validated {
            initial_rtt: Some(ms(30))
        })
    );
}

#[test]
fn a_challenge_not_accepted_yet_validates_without_an_rtt() {
    let mut validation = due();
    validation.written([1; 8]);
    validation.datagram_sealed(1200);
    validation.timed(ms(0), ms(1000), ms(3000));
    assert_eq!(
        validation.responded([1; 8], true, ms(80)),
        Some(PathValidationConclusion::Validated { initial_rtt: None })
    );
}

#[test]
fn a_challenge_due_while_validating_sends_another_and_starts_nothing_new() {
    let mut validation = due();
    send(&mut validation, 1, 1200, ms(0), ms(1000), ms(3000));
    let _ = validation.challenge_due();
    assert!(validation.is_due());
    assert_eq!(validation.abandon_at(), Some(ms(3000)));
    // a finished validation starts anew
    let _ = validation.responded([1; 8], true, ms(10));
    assert!(!validation.is_validating());
    let _ = validation.challenge_due();
    assert_eq!(validation.abandon_at(), None);
    assert!(validation.is_due());
}

#[test]
fn a_dropped_validation_concludes_nothing() {
    let mut validation = due();
    send(&mut validation, 1, 1200, ms(0), ms(1000), ms(3000));
    validation.dropped();
    assert!(!validation.is_validating());
    assert_eq!(validation.deadline(), None);
    assert_eq!(validation.take_conclusion(), None);
}
