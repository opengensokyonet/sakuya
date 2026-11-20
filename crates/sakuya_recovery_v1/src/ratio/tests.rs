use super::{Ratio, ZeroDenominatorError, duration_from_nanos};
use core::time::Duration;

#[test]
fn a_zero_denominator_is_rejected() {
    assert_eq!(Ratio::new(3, 0), Err(ZeroDenominatorError { numerator: 3 }));
}

#[test]
fn a_ratio_multiplies_before_it_divides() {
    let nine_eighths = Ratio::literal(9, 8);
    assert_eq!(
        nine_eighths.of_duration(Duration::from_millis(40)),
        Duration::from_millis(45)
    );
    // 7 × 1/2 is 3.5, rounded down; dividing first would give 3 as well,
    // but 7 × 5/4 is 8.75, where dividing first would give 5.
    assert_eq!(Ratio::literal(1, 2).of_bytes(7), 3);
    assert_eq!(Ratio::literal(5, 4).of_bytes(7), 8);
}

#[test]
fn results_saturate() {
    assert_eq!(Ratio::literal(2, 1).of_bytes(usize::MAX), usize::MAX);
    assert_eq!(
        Ratio::literal(2, 1).of_duration(Duration::MAX),
        Duration::MAX
    );
    assert_eq!(duration_from_nanos(u128::MAX), Duration::MAX);
}

#[test]
fn below_one_is_strict() {
    assert!(Ratio::literal(1, 2).is_below_one());
    assert!(!Ratio::literal(2, 2).is_below_one());
}
