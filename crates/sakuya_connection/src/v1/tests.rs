use core::time::Duration;

use sakuya_packet_protection::{
    backend::ring::RingBackend,
    initial::{INITIAL_AEAD, InitialSecrets},
};
use sakuya_wire::connection_id::ConnectionId;

use super::{
    amplification::{AddressValidation, AntiAmplification, AntiAmplificationFactor},
    idle::IdleTimeout,
    keys::{
        DirectionKeys, HandshakeKeys, InitialKeys, LevelKeys, OneRttKeys, ZeroRttReceiving,
        ZeroRttSending,
    },
    parameters::{LocalTransportParameters, PeerTransportParameters},
    role::LinkPathRole,
};

fn level_keys() -> LevelKeys<RingBackend> {
    let cid = ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]).unwrap();
    let secrets = InitialSecrets::derive(&RingBackend, &cid);
    LevelKeys {
        send: DirectionKeys::derive(&RingBackend, INITIAL_AEAD, &secrets.server),
        receive: DirectionKeys::derive(&RingBackend, INITIAL_AEAD, &secrets.client),
    }
}

fn direction_keys() -> DirectionKeys<RingBackend> {
    level_keys().send
}

#[test]
fn initial_keys_lose_the_sending_half_then_go() {
    let mut initial = InitialKeys::Live(level_keys());
    assert!(initial.send().is_some() && initial.receive().is_some());
    initial.keep_receive_only();
    assert!(initial.send().is_none() && initial.receive().is_some());
    initial.keep_receive_only();
    assert!(matches!(initial, InitialKeys::ReceiveOnly(_)));
    initial.discard();
    assert!(initial.receive().is_none());
    initial.keep_receive_only();
    assert!(matches!(initial, InitialKeys::Discarded));
}

#[test]
fn handshake_keys_that_never_came_are_discarded_on_close() {
    let mut handshake = HandshakeKeys::<RingBackend>::NotYet;
    handshake.keep_receive_only();
    assert!(matches!(handshake, HandshakeKeys::Discarded));
    let mut handshake = HandshakeKeys::NotYet;
    handshake.install(level_keys());
    assert!(handshake.send().is_some() && handshake.receive().is_some());
    handshake.keep_receive_only();
    assert!(handshake.send().is_none() && handshake.receive().is_some());
}

#[test]
fn a_server_gets_one_rtt_keys_in_two_halves() {
    let mut one_rtt = OneRttKeys::NotYet;
    one_rtt.install_send(direction_keys());
    assert!(one_rtt.send().is_some() && one_rtt.receive().is_none());
    one_rtt.install_receive(direction_keys());
    assert!(matches!(one_rtt, OneRttKeys::Live(_)));
}

#[test]
fn one_rtt_keys_without_a_receiving_half_are_discarded_on_close() {
    let mut one_rtt = OneRttKeys::NotYet;
    one_rtt.install_send(direction_keys());
    one_rtt.keep_receive_only();
    assert!(matches!(one_rtt, OneRttKeys::Discarded));
    let mut one_rtt = OneRttKeys::NotYet;
    one_rtt.install(level_keys());
    one_rtt.keep_receive_only();
    assert!(matches!(one_rtt, OneRttKeys::ReceiveOnly(_)));
}

#[test]
fn zero_rtt_receive_keys_retire_once() {
    let mut zero_rtt = ZeroRttReceiving::<RingBackend, u64>::None;
    assert_eq!(zero_rtt.deadline(), None);
    zero_rtt.open(direction_keys());
    zero_rtt.retire_at(30);
    zero_rtt.retire_at(50);
    assert_eq!(zero_rtt.deadline(), Some(30));
    assert!(zero_rtt.receive().is_some());
    zero_rtt.discard();
    assert!(zero_rtt.receive().is_none() && zero_rtt.deadline().is_none());
}

#[test]
fn zero_rtt_send_keys_close_only_when_offered() {
    let mut zero_rtt = ZeroRttSending::<RingBackend>::None;
    zero_rtt.close();
    assert!(matches!(zero_rtt, ZeroRttSending::None));
    zero_rtt.open(direction_keys());
    assert!(zero_rtt.send().is_some());
    zero_rtt.close();
    assert!(matches!(zero_rtt, ZeroRttSending::Closed));
}

#[test]
fn anti_amplification_factor_is_one_to_three() {
    assert!(AntiAmplificationFactor::new(0).is_err());
    assert!(AntiAmplificationFactor::new(4).is_err());
    assert_eq!(AntiAmplificationFactor::new(2).unwrap().get(), 2);
    assert_eq!(AntiAmplificationFactor::default().get(), 3);
}

#[test]
fn credit_is_received_times_factor_less_sent() {
    let mut limit = AntiAmplification::new(AntiAmplificationFactor::default());
    let not_validated = AddressValidation::NotValidated;
    assert_eq!(limit.credit(not_validated), Some(0));
    limit.received(1200);
    assert_eq!(limit.credit(not_validated), Some(3600));
    limit.sent(3000);
    assert_eq!(limit.credit(not_validated), Some(600));
    limit.sent(1000);
    assert_eq!(limit.credit(not_validated), Some(0));
    assert_eq!(limit.credit(AddressValidation::Validated), None);
}

#[test]
fn credit_growth_wakes_the_waiters_once() {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Wake, Waker},
    };
    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let count = Arc::new(Count(AtomicUsize::new(0)));
    let waker = Waker::from(count.clone());
    let mut limit = AntiAmplification::new(AntiAmplificationFactor::default());
    limit.wait(&waker);
    limit.wait(&waker);
    limit.received(100);
    limit.received(100);
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
}

#[test]
fn draining_keeps_a_closing_end_time() {
    let mut role = LinkPathRole::Active;
    assert_eq!(role.end_time(), None);
    role.close(30);
    role.close(40);
    assert_eq!(role, LinkPathRole::Closing(30));
    role.drain(50);
    assert_eq!(role, LinkPathRole::Draining(30));
    let mut role = LinkPathRole::Settling(10);
    assert!(role.has_recovery());
    role.drain(50);
    assert_eq!(role, LinkPathRole::Draining(50));
    assert!(!role.has_recovery());
}

fn ms(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

#[test]
fn idle_timeout_is_the_smaller_advertised_and_at_least_three_ptos() {
    let mut idle = IdleTimeout::<core::time::Duration>::new(Some(ms(30_000)));
    assert_eq!(idle.timeout(), Some(ms(30_000)));
    idle.set_peer(Some(ms(10_000)));
    assert_eq!(idle.timeout(), Some(ms(10_000)));
    idle.set_peer(Some(Duration::ZERO));
    assert_eq!(idle.timeout(), Some(ms(30_000)));
    idle.set_probe_timeout(ms(11_000));
    assert_eq!(idle.timeout(), Some(ms(33_000)));
    let mut none = IdleTimeout::<core::time::Duration>::new(None);
    none.set_peer(None);
    assert_eq!(none.deadline(), None);
}

#[test]
fn idle_timer_restarts_on_the_first_ack_eliciting_send_only() {
    let mut idle = IdleTimeout::new(Some(ms(1000)));
    assert_eq!(idle.deadline(), None, "the timer has not started");
    idle.ack_eliciting_sent(ms(100));
    assert_eq!(idle.deadline(), Some(ms(1100)));
    idle.ack_eliciting_sent(ms(200));
    assert_eq!(idle.deadline(), Some(ms(1100)));
    idle.packet_processed(ms(300));
    assert_eq!(idle.deadline(), Some(ms(1300)));
    idle.ack_eliciting_sent(ms(400));
    assert_eq!(idle.deadline(), Some(ms(1400)));
}

#[test]
fn peer_parameters_are_remembered_then_known() {
    let mut peer = PeerTransportParameters::NotYet;
    assert_eq!(peer.slots(), None);
    peer.remember(1);
    assert_eq!((peer.slots(), peer.known()), (Some(&1), None));
    peer.set_known(2);
    assert_eq!(peer.known(), Some(&2));
}

#[test]
fn local_parameters_are_settled_when_sent() {
    let mut local = LocalTransportParameters::Configured(10);
    assert_eq!(local.sent(), None);
    local.send_with(|configured| configured + 1);
    assert_eq!((local.sent(), local.configured()), (Some(&11), None));
}

mod recovery {
    use super::super::recovery::{LinkPathCongestionState, max_datagram_size_in_use};
    use core::time::Duration;
    use sakuya_recovery::{
        congestion::{CongestionController, new_reno::NewReno, new_reno::NewRenoConfig},
        pacing::{PacedCongestionController, TokenBucketPacer, TokenBucketPacerConfig},
        rtt::RttEstimate,
    };

    #[test]
    fn the_size_in_use_is_the_smallest_limit_but_not_below_1200() {
        // the conclusion, the peer's limit and the link's limit
        assert_eq!(max_datagram_size_in_use(1500, None, Some(1452)), 1452);
        assert_eq!(max_datagram_size_in_use(1400, Some(1350), Some(1452)), 1350);
        assert_eq!(max_datagram_size_in_use(1400, None, Some(9000)), 1400);
        // a link below 1200 is raised to it; one that cannot tell gives 1200
        assert_eq!(max_datagram_size_in_use(1400, None, Some(1000)), 1200);
        assert_eq!(max_datagram_size_in_use(1400, None, None), 1200);
    }

    #[test]
    fn the_window_left_is_none_once_probes_went_past_it() {
        let controller: PacedCongestionController<NewReno<Duration>, TokenBucketPacer<Duration>> =
            PacedCongestionController::new(
                NewReno::new(NewRenoConfig::RECOMMENDED, 1200),
                TokenBucketPacer::new(TokenBucketPacerConfig::recommended(Duration::from_millis(
                    1,
                ))),
            );
        let state = LinkPathCongestionState::<Duration>::new();
        assert_eq!(state.window_left(&controller), controller.window());
        assert_eq!(state.bytes_in_flight(), 0);
        let mut controller = controller;
        let rtt = RttEstimate::initial(Duration::from_millis(333));
        // the first refill fills the bucket
        let allowance = state.pacing_allowance(&mut controller, Duration::ZERO, &rtt, 1200);
        assert!(allowance >= 12000, "{allowance}");
    }
}
