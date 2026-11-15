use super::BlockedSignal;

#[test]
fn one_frame_per_limit() {
    let mut signal = BlockedSignal::default();
    assert_eq!(signal.wanted(), None);
    signal.on_blocked(10u32);
    assert_eq!(signal.wanted(), Some(10));
    signal.on_blocked(10);
    assert_eq!(signal.wanted(), Some(10));
    signal.on_sent(10);
    assert_eq!(signal.wanted(), None);
    // Blocked again at the same limit: nothing more is wanted.
    signal.on_blocked(10);
    assert_eq!(signal.wanted(), None);
}

#[test]
fn a_higher_limit_clears_the_intent_and_allows_a_new_one() {
    let mut signal = BlockedSignal::default();
    signal.on_blocked(10u32);
    signal.on_limit_raised(20);
    assert_eq!(signal, BlockedSignal::Quiet);
    signal.on_blocked(20);
    signal.on_sent(20);
    signal.on_limit_raised(30);
    signal.on_blocked(30);
    assert_eq!(signal.wanted(), Some(30));
}

#[test]
fn stale_limits_change_nothing() {
    let mut signal = BlockedSignal::default();
    signal.on_blocked(20u32);
    signal.on_blocked(10);
    assert_eq!(signal.wanted(), Some(20));
    signal.on_sent(10);
    assert_eq!(signal.wanted(), Some(20));
    signal.on_limit_raised(20);
    assert_eq!(signal.wanted(), Some(20));
    signal.on_sent(20);
    signal.on_blocked(10);
    assert_eq!(signal, BlockedSignal::Signalled(20));
    // Blocked at a higher limit than the signalled one: a new frame.
    signal.on_blocked(30);
    assert_eq!(signal.wanted(), Some(30));
}
