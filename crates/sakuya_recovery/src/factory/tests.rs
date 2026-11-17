use super::{
    CubicRecoveryFactory, CubicRecoveryFactoryConfig, LendCongestion, NewRenoRecoveryFactory,
    NewRenoRecoveryFactoryConfig, PacedNewReno, PacerInitialWindowMismatchError, RecoveryFactory,
};
use crate::{
    congestion::{
        CongestionContext, CongestionController, InFlightPacket, InitialWindow, cubic::CubicConfig,
        new_reno::NewRenoConfig,
    },
    pacing::{Pacer, PacingInput, RECOMMENDED_PACING_GAIN, TokenBucketPacerConfig},
    pmtu::{BinarySearchPmtuPolicyConfig, PmtuPolicy},
    pto::PtoPolicy,
    rtt::RttEstimate,
    rtt::RttEstimator,
};
use core::{num::NonZeroUsize, time::Duration};
use sakuya_link::{BindingId, Link, LinkId, OutgoingDatagram, SendAcceptance};

#[derive(Clone, Debug)]
struct TestLink(LinkId<(), ()>);

impl Link for TestLink {
    type Local = ();
    type Peer = ();
    type Payload = Vec<u8>;
    type Instant = Duration;
    type MaxDatagramSizeError = ();
    type SendError = ();
    type RecvError = ();
    type Recv<'a> =
        core::future::Pending<Result<sakuya_link::ReceivedDatagram<Self::Payload, Self>, ()>>;
    type Ended = core::future::Pending<()>;
    type Send<'a> = core::future::Pending<Result<SendAcceptance<Duration>, ()>>;
    type MaxDatagramSizeChanged = core::future::Pending<()>;
    fn id(&self) -> &LinkId<(), ()> {
        &self.0
    }
    fn may_mark_ecn(&self) -> bool {
        false
    }
    fn max_datagram_size(&self) -> Result<usize, ()> {
        Ok(1452)
    }
    fn recv(&self) -> Self::Recv<'_> {
        core::future::pending()
    }
    fn ended(&self) -> Self::Ended {
        core::future::pending()
    }
    fn send<'a>(&self, _batch: &'a [OutgoingDatagram]) -> Self::Send<'a> {
        core::future::pending()
    }
    fn max_datagram_size_changed(&self) -> Self::MaxDatagramSizeChanged {
        core::future::pending()
    }
}

fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

fn link() -> TestLink {
    TestLink(LinkId::new::<()>((), (), &BindingId::new()))
}

fn factory() -> NewRenoRecoveryFactory<LinkId<(), ()>> {
    RecoveryFactory::<TestLink>::new(&NewRenoRecoveryFactoryConfig::recommended(ms(1)))
}

/// What the caller's fixed code does with a lent access: generic over the
/// factory, as the connection's code is.
fn window_left<F, O>(factory: &mut F, part: &mut F::Part, others: &O, in_flight: usize) -> usize
where
    F: LendCongestion<Duration, O>,
{
    let mut access = factory.lend(part, others);
    access.refill(
        ms(0),
        PacingInput {
            window: access.window(),
            smoothed_rtt: ms(40),
            max_datagram_size: 1200,
        },
    );
    let _ = access.on_duplicate_initial_crypto();
    access.window().saturating_sub(in_flight)
}

#[test]
fn the_first_link_path_starts_from_the_initial_rtt() {
    let mut factory = factory();
    let (rtt, _, pmtu) = RecoveryFactory::<TestLink>::create(&mut factory, &link(), None);
    assert_eq!(RttEstimator::<Duration>::estimate(&rtt).smoothed, ms(333));
    assert_eq!(PmtuPolicy::<TestLink>::conclusion(&pmtu), 1200);
}

#[test]
fn a_measured_initial_rtt_is_used() {
    let mut factory = factory();
    let (rtt, _, _) = RecoveryFactory::<TestLink>::create(&mut factory, &link(), Some(ms(20)));
    let estimate = RttEstimator::<Duration>::estimate(&rtt);
    assert_eq!(estimate.smoothed, ms(20));
    assert_eq!(estimate.variation, ms(10));
    assert_eq!(estimate.min, Duration::ZERO);
}

#[test]
fn a_link_path_part_is_lent_as_it_is() {
    let mut factory = factory();
    let (_, mut part, _) = RecoveryFactory::<TestLink>::create(&mut factory, &link(), None);
    assert_eq!(window_left(&mut factory, &mut part, &(), 4800), 7200);
    // The lend went to the part itself: what it changed stays.
    assert!(!PtoPolicy::<Duration>::on_duplicate_initial_crypto(
        &mut part
    ));
    assert_eq!(Pacer::<Duration>::allowance(&part), 12000);
}

#[test]
fn the_deadline_of_a_part_is_its_pacers_next_release() {
    let mut factory = factory();
    let (_, mut part, _) = RecoveryFactory::<TestLink>::create(&mut factory, &link(), None);
    let deadline = |factory: &NewRenoRecoveryFactory<LinkId<(), ()>>,
                    part: &PacedNewReno<Duration>| {
        LendCongestion::<Duration, ()>::next_deadline(factory, part)
    };
    // A full bucket holds nothing back.
    let _ = window_left(&mut factory, &mut part, &(), 0);
    assert_eq!(deadline(&factory, &part), None);
    // Spent, it is released again once a full datagram is earned back.
    let access = LendCongestion::<Duration, ()>::lend(&mut factory, &mut part, &());
    access.on_charged(12000);
    let release = deadline(&factory, &part).expect("a release after spending");
    assert!(release > ms(0));
    assert_eq!(Some(release), Pacer::<Duration>::next_release(&part));
}

#[test]
fn the_pacer_must_share_the_initial_window() {
    let pacer = TokenBucketPacerConfig::new(
        ms(1),
        InitialWindow::new(20, 30000),
        NonZeroUsize::new(256).unwrap(),
        RECOMMENDED_PACING_GAIN,
    )
    .unwrap();
    let result = NewRenoRecoveryFactoryConfig::new(
        ms(333),
        NewRenoConfig::RECOMMENDED,
        pacer,
        BinarySearchPmtuPolicyConfig::RECOMMENDED,
    );
    assert_eq!(
        result,
        Err(PacerInitialWindowMismatchError {
            pacer: InitialWindow::new(20, 30000),
            congestion_controller: InitialWindow::RECOMMENDED,
        })
    );
}

fn cubic_factory() -> CubicRecoveryFactory<LinkId<(), ()>> {
    RecoveryFactory::<TestLink>::new(&CubicRecoveryFactoryConfig::default())
}

#[test]
fn a_cubic_link_path_part_is_lent_as_it_is() {
    let mut factory = cubic_factory();
    let (rtt, mut part, _) = RecoveryFactory::<TestLink>::create(&mut factory, &link(), None);
    assert_eq!(RttEstimator::<Duration>::estimate(&rtt).smoothed, ms(333));
    assert_eq!(window_left(&mut factory, &mut part, &(), 4800), 7200);
    // A loss through the lent access reduces the part's window by 0.7.
    let access = LendCongestion::<Duration, ()>::lend(&mut factory, &mut part, &());
    let sent_state = access.on_packet_sealed(1200, false, ms(10));
    let packet = InFlightPacket {
        bytes: 1200,
        sent_at: ms(10),
        app_limited: false,
        sent_state,
    };
    let context = CongestionContext {
        now: ms(50),
        bytes_in_flight: 0,
        rtt: RttEstimate::initial(ms(40)),
        rtt_sampled: false,
        max_datagram_size: 1200,
    };
    let _ = access.on_lost([packet].into_iter(), &context);
    assert_eq!(CongestionController::<Duration>::window(&part), 8400);
    assert_eq!(
        LendCongestion::<Duration, ()>::next_deadline(&factory, &part),
        None
    );
}

#[test]
fn the_cubic_pacer_must_share_the_initial_window() {
    let pacer = TokenBucketPacerConfig::new(
        ms(1),
        InitialWindow::new(20, 30000),
        NonZeroUsize::new(256).unwrap(),
        RECOMMENDED_PACING_GAIN,
    )
    .unwrap();
    let result = CubicRecoveryFactoryConfig::new(
        ms(333),
        CubicConfig::RECOMMENDED,
        pacer,
        BinarySearchPmtuPolicyConfig::RECOMMENDED,
    );
    assert_eq!(
        result,
        Err(PacerInitialWindowMismatchError {
            pacer: InitialWindow::new(20, 30000),
            congestion_controller: InitialWindow::RECOMMENDED,
        })
    );
}
