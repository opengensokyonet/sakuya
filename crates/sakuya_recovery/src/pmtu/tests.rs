use super::{
    BinarySearchPmtuPolicy, BinarySearchPmtuPolicyConfig, InitialSizeBelowMinimumError, PmtuPolicy,
    PmtuProbeFailure,
};
use core::{
    num::{NonZeroU8, NonZeroU32, NonZeroUsize},
    time::Duration,
};
use sakuya_link::{BindingId, Link, LinkId, OutgoingDatagram, SendAcceptance};
use std::{cell::Cell, rc::Rc};

/// A link whose shared conclusion follows the rules of the two records.
#[derive(Clone, Debug)]
struct SharingLink {
    id: LinkId<(), ()>,
    shared: Rc<Cell<usize>>,
}

impl SharingLink {
    fn new() -> Self {
        Self {
            id: LinkId::new::<()>((), (), &BindingId::new()),
            shared: Rc::new(Cell::new(1200)),
        }
    }

    /// Another connection over the same logical link changed the shared
    /// conclusion.
    fn set_shared(&self, size: usize) {
        self.shared.set(size);
    }
}

impl Link for SharingLink {
    type Local = ();
    type Peer = ();
    type Payload = Vec<u8>;
    type Instant = Duration;
    type MaxDatagramSizeError = ();
    type SendError = ();
    type Send<'a> = core::future::Pending<Result<SendAcceptance<Duration>, ()>>;
    type MaxDatagramSizeChanged = core::future::Pending<()>;
    fn id(&self) -> &LinkId<(), ()> {
        &self.id
    }
    fn may_mark_ecn(&self) -> bool {
        false
    }
    fn max_datagram_size(&self) -> Result<usize, ()> {
        Ok(1452)
    }
    fn send<'a>(&self, _batch: &'a [OutgoingDatagram]) -> Self::Send<'a> {
        core::future::pending()
    }
    fn max_datagram_size_changed(&self) -> Self::MaxDatagramSizeChanged {
        core::future::pending()
    }
    fn datagram_size_conclusion(&self) -> usize {
        self.shared.get()
    }
    fn record_datagram_size_confirmed(&self, size: usize) {
        self.shared.set(self.shared.get().max(size));
    }
    fn record_datagram_size_lowered(&self, size: usize) {
        self.shared.set(self.shared.get().min(size.max(1200)));
    }
}

type Policy = BinarySearchPmtuPolicy<Duration, (), ()>;

fn secs(value: u64) -> Duration {
    Duration::from_secs(value)
}

fn policy() -> Policy {
    BinarySearchPmtuPolicy::new(BinarySearchPmtuPolicyConfig::RECOMMENDED)
}

fn start(policy: &mut Policy, link: &SharingLink, ceiling: Option<usize>) {
    PmtuPolicy::<SharingLink>::on_datagram_start(policy, link, ceiling);
}

fn probe(policy: &Policy) -> Option<usize> {
    PmtuPolicy::<SharingLink>::probe_size(policy)
}

fn conclusion(policy: &Policy) -> usize {
    PmtuPolicy::<SharingLink>::conclusion(policy)
}

fn acked(policy: &mut Policy, size: usize, now: Duration) {
    PmtuPolicy::<SharingLink>::on_probe_acked(policy, size, now);
}

fn lost(policy: &mut Policy, size: usize, now: Duration) {
    PmtuPolicy::<SharingLink>::on_probe_failed(policy, size, PmtuProbeFailure::Lost, now);
}

fn deadline(policy: &Policy) -> Option<Duration> {
    PmtuPolicy::<SharingLink>::next_deadline(policy)
}

fn packets(policy: &mut Policy, acked: &[usize], lost: &[usize], now: Duration) {
    PmtuPolicy::<SharingLink>::on_packets(policy, acked.iter().copied(), lost.iter().copied(), now);
}

#[test]
fn an_initial_size_below_1200_is_rejected() {
    let result = BinarySearchPmtuPolicyConfig::new(
        1199,
        NonZeroU8::new(3).unwrap(),
        NonZeroUsize::new(20).unwrap(),
        secs(600),
        NonZeroU32::new(3).unwrap(),
    );
    assert_eq!(
        result,
        Err(InitialSizeBelowMinimumError { initial_size: 1199 })
    );
}

#[test]
fn the_search_halves_the_range_to_the_ceiling() {
    let link = SharingLink::new();
    let mut policy = policy();
    let mut probed = Vec::new();
    for second in 1..10 {
        start(&mut policy, &link, Some(1452));
        let Some(size) = probe(&policy) else { break };
        probed.push(size);
        acked(&mut policy, size, secs(second));
    }
    assert_eq!(probed, [1326, 1389, 1421, 1437]);
    assert_eq!(conclusion(&policy), 1437);
    // 15 bytes left below the ceiling: no search upward later.
    assert_eq!(deadline(&policy), None);
    // The confirmed size reaches the link at the next datagram.
    start(&mut policy, &link, Some(1452));
    assert_eq!(link.datagram_size_conclusion(), 1437);
}

#[test]
fn a_size_lost_three_times_is_given_up() {
    let link = SharingLink::new();
    let mut policy = policy();
    start(&mut policy, &link, Some(1452));
    assert_eq!(probe(&policy), Some(1326));
    lost(&mut policy, 1326, secs(1));
    PmtuPolicy::<SharingLink>::on_probe_failed(
        &mut policy,
        1326,
        PmtuProbeFailure::Unsent,
        secs(1),
    );
    lost(&mut policy, 1326, secs(2));
    assert_eq!(probe(&policy), Some(1326));
    lost(&mut policy, 1326, secs(3));
    // The range is 1200 to 1325 now.
    assert_eq!(probe(&policy), Some(1263));
    acked(&mut policy, 1263, secs(4));
    assert_eq!(probe(&policy), Some(1294));
    acked(&mut policy, 1294, secs(5));
    assert_eq!(probe(&policy), Some(1310));
    acked(&mut policy, 1310, secs(6));
    assert_eq!(probe(&policy), None);
    // 142 bytes below the ceiling: search again in 600 s.
    assert_eq!(deadline(&policy), Some(secs(606)));
    PmtuPolicy::<SharingLink>::on_deadline(&mut policy, secs(606));
    assert_eq!(deadline(&policy), None);
    assert_eq!(probe(&policy), Some(1381));
}

#[test]
fn no_ceiling_means_no_probe() {
    let link = SharingLink::new();
    let mut policy = policy();
    start(&mut policy, &link, None);
    assert_eq!(probe(&policy), None);
}

#[test]
fn a_ceiling_that_rises_after_the_search_searches_again_later() {
    let link = SharingLink::new();
    let mut policy = policy();
    start(&mut policy, &link, Some(1200));
    packets(&mut policy, &[1200], &[], secs(1));
    assert_eq!(deadline(&policy), None);
    start(&mut policy, &link, Some(1452));
    packets(&mut policy, &[1200], &[], secs(2));
    assert_eq!(deadline(&policy), Some(secs(602)));
}

#[test]
fn three_batches_with_large_losses_are_a_black_hole() {
    let link = SharingLink::new();
    link.set_shared(1452);
    let mut policy = policy();
    start(&mut policy, &link, Some(1452));
    assert_eq!(conclusion(&policy), 1452);

    packets(&mut policy, &[], &[1452, 1452], secs(1));
    packets(&mut policy, &[60], &[1452], secs(2));
    assert_eq!(conclusion(&policy), 1452);
    packets(&mut policy, &[], &[1452], secs(3));
    assert_eq!(conclusion(&policy), 1200);
    // Searching again at once, and the link learns at the next datagram.
    start(&mut policy, &link, Some(1452));
    assert_eq!(link.datagram_size_conclusion(), 1200);
    assert_eq!(probe(&policy), Some(1326));
}

#[test]
fn a_large_packet_acknowledged_resets_the_count() {
    let link = SharingLink::new();
    link.set_shared(1452);
    let mut policy = policy();
    start(&mut policy, &link, Some(1452));
    packets(&mut policy, &[], &[1452], secs(1));
    packets(&mut policy, &[], &[1452], secs(2));
    packets(&mut policy, &[1452], &[1452], secs(3));
    packets(&mut policy, &[], &[1452], secs(4));
    packets(&mut policy, &[], &[1452], secs(5));
    assert_eq!(conclusion(&policy), 1452);
}

#[test]
fn the_conclusion_never_goes_below_1200() {
    let link = SharingLink::new();
    let mut policy = policy();
    start(&mut policy, &link, Some(1452));
    for second in 1..10 {
        packets(&mut policy, &[], &[1300], secs(second));
    }
    assert_eq!(conclusion(&policy), 1200);
}

#[test]
fn a_changed_shared_conclusion_is_adopted() {
    let link = SharingLink::new();
    let mut policy = policy();
    start(&mut policy, &link, Some(1452));
    link.set_shared(1400);
    start(&mut policy, &link, Some(1452));
    assert_eq!(conclusion(&policy), 1400);
    assert_eq!(probe(&policy), Some(1426));
    // Lowered by another connection: adopted, and the search starts over.
    link.set_shared(1200);
    start(&mut policy, &link, Some(1452));
    assert_eq!(conclusion(&policy), 1200);
    assert_eq!(probe(&policy), Some(1326));
}

#[test]
fn a_new_logical_link_gets_the_conclusion() {
    let old = SharingLink::new();
    old.set_shared(1452);
    let mut policy = policy();
    start(&mut policy, &old, Some(1452));
    let new = SharingLink::new();
    start(&mut policy, &new, Some(1452));
    assert_eq!(new.datagram_size_conclusion(), 1452);
    assert_eq!(conclusion(&policy), 1452);
}
