use super::{EcnContext, EcnValidationOutcome, ect0_testing_marking};
use crate::rtt::RttEstimate;
use core::time::Duration;
use sakuya_link::EcnMarking;

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn context(outcome: EcnValidationOutcome, marked: u64, now: u64) -> EcnContext<Duration> {
    EcnContext {
        now: ms(now),
        outcome,
        marked_since_start: marked,
        started_at: ms(100),
        rtt: RttEstimate::initial(ms(40)),
        pto: ms(100),
    }
}

#[test]
fn the_test_marks_ten_packets() {
    use EcnValidationOutcome::Unvalidated;
    assert_eq!(
        ect0_testing_marking(&context(Unvalidated, 9, 150)),
        EcnMarking::Ect0
    );
    assert_eq!(
        ect0_testing_marking(&context(Unvalidated, 10, 150)),
        EcnMarking::NotEct
    );
}

#[test]
fn the_test_lasts_three_probe_timeouts() {
    use EcnValidationOutcome::Unvalidated;
    // Started at 100 ms, PTO 100 ms: until 400 ms.
    assert_eq!(
        ect0_testing_marking(&context(Unvalidated, 2, 399)),
        EcnMarking::Ect0
    );
    assert_eq!(
        ect0_testing_marking(&context(Unvalidated, 2, 400)),
        EcnMarking::NotEct
    );
}

#[test]
fn a_capable_path_keeps_marking() {
    assert_eq!(
        ect0_testing_marking(&context(EcnValidationOutcome::Capable, 500, 10_000)),
        EcnMarking::Ect0
    );
    assert_eq!(
        ect0_testing_marking(&context(EcnValidationOutcome::Failed, 0, 150)),
        EcnMarking::NotEct
    );
}
