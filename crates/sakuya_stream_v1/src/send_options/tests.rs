use super::destination::{
    AnyActiveLinkPath, DestinationFallback, SendDestination, StreamSendDestination, Unfulfilled,
};
use super::urgency::{SendUrgency, Urgency, UrgencyOutOfRangeError};
use super::{NoSendOptions, SendOptions};

#[test]
fn urgency_takes_zero_to_seven_and_defaults_to_three() {
    for value in 0..=7 {
        assert_eq!(Urgency::new(value).unwrap().get(), value);
    }
    let error: UrgencyOutOfRangeError = Urgency::new(8).unwrap_err();
    assert_eq!(error.value(), 8);
    assert_eq!(Urgency::try_from(255).unwrap_err().value(), 255);
    assert_eq!(Urgency::default().get(), 3);
    assert_eq!(u8::from(Urgency::default()), 3);
}

/// A smaller urgency orders first, and an urgency gives itself as the
/// parameter the default strategy reads.
#[test]
fn smaller_urgency_orders_first() {
    let high = Urgency::new(1).unwrap();
    let low = Urgency::new(6).unwrap();
    assert!(high < low);
    assert_eq!(high.urgency(), high);
}

/// Any active link path has nothing narrower to fall back from: every
/// failure keeps it as the current destination.
#[test]
fn any_active_link_path_stays_where_it_is() {
    let mut destination = AnyActiveLinkPath;
    assert_eq!(
        destination.on_unfulfilled(Unfulfilled::Rejected),
        DestinationFallback::Degraded
    );
    assert_eq!(
        destination.on_unfulfilled(Unfulfilled::Ended),
        DestinationFallback::Degraded
    );
    assert_eq!(destination.on_lost(), DestinationFallback::Degraded);
    assert_eq!(destination.current(), AnyActiveLinkPath);
}

#[test]
fn send_options_hold_parameters_and_destination() {
    let mut options = SendOptions::new(Urgency::default(), AnyActiveLinkPath);
    assert_eq!(*options.parameters(), Urgency::default());
    *options.parameters_mut() = Urgency::new(0).unwrap();
    assert_eq!(options.destination(), &AnyActiveLinkPath);
    let copy = options;
    assert_eq!(copy, options);
    assert_eq!(
        options.into_parts(),
        (Urgency::new(0).unwrap(), AnyActiveLinkPath)
    );
    assert_eq!(NoSendOptions, NoSendOptions);
}
