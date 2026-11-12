//! Shared fixtures: a recording deliverer and its judgment, a tracked datagram
//! and manual polling

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use sakuya_wire::connection_id::ConnectionIdLength;

use crate::claim::candidate::DatagramClaimCandidate;
use crate::claim::candidate::{DatagramClaimAccess, DatagramClaimOutcome};
use crate::claim::deliverer::DatagramDeliverer;
use crate::claim::delivery::{DatagramDelivery, ExclusiveDatagramDelivery};
use crate::claim::erased::SendDatagramDeliverer;
use crate::claim::finish::UnclaimedHandoff;
use crate::claim::group::prepare_claim;
use crate::claim::route_match::DatagramRouteMatchInfo;
use crate::claim::shared::DatagramFinishPolicy;
use crate::route::association::MatchAssociation;
use crate::route::interpretation::FirstPacketInterpretation;

/// This side's end of the links the tests pretend datagrams arrive on.
pub(super) type Local = u32;

/// A datagram that counts how often it is dropped.
#[derive(Debug)]
pub(super) struct TestDatagram {
    bytes: Vec<u8>,
    drops: Arc<AtomicUsize>,
}

impl TestDatagram {
    pub(super) fn new(bytes: &[u8]) -> (Self, Arc<AtomicUsize>) {
        let drops = Arc::new(AtomicUsize::new(0));
        (
            Self {
                bytes: bytes.to_vec(),
                drops: drops.clone(),
            },
            drops,
        )
    }
}

impl AsRef<[u8]> for TestDatagram {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for TestDatagram {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

/// How a [`Probe`]'s judgment decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Judging {
    Reject,
    Accept,
    Abandon,
    PanicBeforeTake,
    PanicAfterTake,
}

/// What every probe receives.
pub(super) type Delivery = DatagramDelivery<TestDatagram, Local, UnclaimedSink>;

/// What every probe's candidate is.
pub(super) type Candidate = DatagramClaimCandidate<TestDatagram, Local, UnclaimedSink>;

/// A deliverer that keeps every delivery, together with the judgment its
/// receiver passes to attempts.
///
/// The deliverer itself only stores deliveries; [`judgment`](Self::judgment)
/// stands for the receiver's state, which the deliverer never sees.
pub(super) struct Probe {
    judging: Mutex<Judging>,
    claim_calls: AtomicUsize,
    deliveries: Mutex<Vec<Delivery>>,
}

impl Probe {
    pub(super) fn new(judging: Judging) -> Arc<Self> {
        Arc::new(Self {
            judging: Mutex::new(judging),
            claim_calls: AtomicUsize::new(0),
            deliveries: Mutex::new(Vec::new()),
        })
    }

    pub(super) fn judge_with(&self, judging: Judging) {
        *self.judging.lock().unwrap() = judging;
    }

    /// How many judgments of this probe ran.
    pub(super) fn claim_calls(&self) -> usize {
        self.claim_calls.load(Ordering::SeqCst)
    }

    /// A judgment that counts its call and decides by the current mode.
    ///
    /// Claiming and abandoning both carry the number of the call.
    pub(super) fn judgment(
        self: &Arc<Self>,
    ) -> impl for<'access> FnOnce(
        DatagramClaimAccess<'access, TestDatagram>,
        &DatagramRouteMatchInfo<Local>,
    ) -> DatagramClaimOutcome<'access, usize, usize, TestDatagram>
    + Send
    + 'static {
        let probe = Arc::clone(self);
        move |access, _route| {
            let call = probe.claim_calls.fetch_add(1, Ordering::SeqCst) + 1;
            assert!(!access.bytes().is_empty());
            let judging = *probe.judging.lock().unwrap();
            match judging {
                Judging::Reject => DatagramClaimOutcome::Unclaimed(access),
                Judging::Accept => DatagramClaimOutcome::Claimed(access.into_exclusive(), call),
                Judging::Abandon => DatagramClaimOutcome::Abandoned(call),
                Judging::PanicBeforeTake => panic!("simulated judgment panic"),
                Judging::PanicAfterTake => {
                    let _datagram = access.into_exclusive();
                    panic!("simulated panic after taking the datagram")
                }
            }
        }
    }

    /// Takes the single delivery this probe received.
    pub(super) fn take_delivery(&self) -> Delivery {
        let mut deliveries = self.deliveries.lock().unwrap();
        assert_eq!(deliveries.len(), 1, "expected exactly one delivery");
        deliveries.pop().unwrap()
    }

    pub(super) fn delivery_count(&self) -> usize {
        self.deliveries.lock().unwrap().len()
    }

    pub(super) fn take_candidate(&self) -> Candidate {
        match self.take_delivery() {
            DatagramDelivery::Competing(candidate) => candidate,
            DatagramDelivery::Exclusive(_) => panic!("expected a competing delivery"),
        }
    }

    pub(super) fn take_exclusive(&self) -> ExclusiveDatagramDelivery<TestDatagram, Local> {
        match self.take_delivery() {
            DatagramDelivery::Exclusive(delivery) => delivery,
            DatagramDelivery::Competing(_) => panic!("expected an exclusive delivery"),
        }
    }
}

impl DatagramDeliverer<TestDatagram, Local> for Probe {
    type Handoff = UnclaimedSink;

    fn deliver(&self, delivery: Delivery) {
        self.deliveries.lock().unwrap().push(delivery);
    }
}

/// Collects the datagrams handed off under the on-unclaimed policy.
#[derive(Clone, Default)]
pub(super) struct UnclaimedSink(Arc<Mutex<Vec<TestDatagram>>>);

impl UnclaimedHandoff<TestDatagram> for UnclaimedSink {
    fn hand_off(self, datagram: TestDatagram) {
        self.0.lock().unwrap().push(datagram);
    }
}

impl UnclaimedSink {
    pub(super) fn policy(&self) -> DatagramFinishPolicy<Self> {
        DatagramFinishPolicy::OnUnclaimed(self.clone())
    }

    pub(super) fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    pub(super) fn take(&self) -> Vec<TestDatagram> {
        std::mem::take(&mut self.0.lock().unwrap())
    }
}

/// Match information for a candidate; the claim mechanism does not read it.
pub(super) fn route_info() -> DatagramRouteMatchInfo<Local> {
    DatagramRouteMatchInfo::new(
        MatchAssociation::ZeroCid(7),
        FirstPacketInterpretation::Short {
            dcid_len: ConnectionIdLength::ZERO,
        },
    )
}

/// Prepares and dispatches one datagram to `probes`, in order.
pub(super) fn route(
    datagram: TestDatagram,
    finish: DatagramFinishPolicy<UnclaimedSink>,
    probes: &[&Arc<Probe>],
) {
    let entries = probes
        .iter()
        .map(|probe| {
            let erased: Arc<dyn SendDatagramDeliverer<TestDatagram, Local, UnclaimedSink>> =
                Arc::clone(probe) as _;
            (erased, route_info())
        })
        .collect::<Vec<_>>();
    prepare_claim(datagram, finish, entries).dispatch();
}

/// Counts wakes.
#[derive(Default)]
pub(super) struct WakeCount(AtomicUsize);

impl WakeCount {
    pub(super) fn waker() -> (Arc<Self>, Waker) {
        let count = Arc::new(Self::default());
        let waker = Waker::from(count.clone());
        (count, waker)
    }

    pub(super) fn get(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Polls once with `waker`.
pub(super) fn poll_with<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(waker))
}

/// Polls once and expects completion.
pub(super) fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match poll_with(future.as_mut(), Waker::noop()) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("expected the attempt to complete without waiting"),
    }
}

/// Runs a future to completion on the current thread, parking while pending.
pub(super) fn block_on<F: Future>(future: F) -> F::Output {
    struct Unpark(std::thread::Thread);

    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }

    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut future = std::pin::pin!(future);
    loop {
        if let Poll::Ready(output) = poll_with(future.as_mut(), &waker) {
            return output;
        }
        std::thread::park();
    }
}

pub(super) fn drops(counter: &AtomicUsize) -> usize {
    counter.load(Ordering::SeqCst)
}
