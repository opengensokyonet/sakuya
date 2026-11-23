use super::flow_control::{AdmissionGrantError, AdmissionGuard, WriteAttempt};
use super::test_support::v;
use sakuya_var_int::VarInt;

#[test]
fn admission_guards_are_checked_at_construction() {
    let attempt = WriteAttempt {
        offset: v(10),
        requested: v(50),
        stream_available: v(40),
        write_limit_remaining: None,
        connection_available: v(1000),
        ceiling: v(40),
    };
    let guard = AdmissionGuard::new(&attempt, v(40)).unwrap();
    assert_eq!((guard.offset(), guard.granted()), (v(10), v(40)));
    let Err(AdmissionGrantError::AboveCeiling { source }) = AdmissionGuard::new(&attempt, v(41))
    else {
        panic!("a grant above the ceiling is rejected");
    };
    assert_eq!((source.granted(), source.ceiling()), (v(41), v(40)));
    assert_eq!(
        AdmissionGuard::new(&attempt, VarInt::ZERO),
        Err(AdmissionGrantError::Zero)
    );
}
