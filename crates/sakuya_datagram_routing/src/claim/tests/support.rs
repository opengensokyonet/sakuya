//! Shared fixtures: a recording deliverer, a tracked datagram and manual polling

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use crate::claim::group::prepare_claim;
use crate::claim::shared::{DatagramFinishPolicy, OfferedRouteHistory, ReflowContinuation};
use crate::claim::{
    DatagramClaimAccess, DatagramClaimCandidate, DatagramClaimOutcome, DatagramDeliverer,
    DatagramDelivery, DatagramRouteMatchInfo, DatagramView, ExclusiveDatagramDelivery,
    SendDatagramDeliverer, UnclaimedWork,
};

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

/// How a [`Probe`] judges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Judging {
    Reject,
    Accept,
    PanicBeforeTake,
    PanicAfterTake,
}

/// The private state of a [`Probe`] candidate.
pub(super) struct ProbeState {
    /// How many judgments used this state.
    pub(super) judgments: usize,
    on_drop: Option<Box<dyn FnOnce() + Send>>,
    drops: Arc<AtomicUsize>,
}

impl Drop for ProbeState {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
        if let Some(on_drop) = self.on_drop.take() {
            on_drop();
        }
    }
}

/// A deliverer that records every call and keeps every delivery.
pub(super) struct Probe {
    judging: Mutex<Judging>,
    panic_in_factory: Mutex<bool>,
    state_on_drop: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    pub(super) factory_calls: AtomicUsize,
    pub(super) claim_calls: AtomicUsize,
    pub(super) state_drops: Arc<AtomicUsize>,
    deliveries: Mutex<Vec<DatagramDelivery<TestDatagram, Probe>>>,
}

impl Probe {
    pub(super) fn new(judging: Judging) -> Arc<Self> {
        Arc::new(Self {
            judging: Mutex::new(judging),
            panic_in_factory: Mutex::new(false),
            state_on_drop: Mutex::new(None),
            factory_calls: AtomicUsize::new(0),
            claim_calls: AtomicUsize::new(0),
            state_drops: Arc::new(AtomicUsize::new(0)),
            deliveries: Mutex::new(Vec::new()),
        })
    }

    pub(super) fn judge_with(&self, judging: Judging) {
        *self.judging.lock().unwrap() = judging;
    }

    pub(super) fn panic_in_factory(&self) {
        *self.panic_in_factory.lock().unwrap() = true;
    }

    /// Runs `on_drop` when the next state this probe creates is dropped.
    pub(super) fn on_state_drop(&self, on_drop: impl FnOnce() + Send + 'static) {
        *self.state_on_drop.lock().unwrap() = Some(Box::new(on_drop));
    }

    pub(super) fn factory_calls(&self) -> usize {
        self.factory_calls.load(Ordering::SeqCst)
    }

    pub(super) fn claim_calls(&self) -> usize {
        self.claim_calls.load(Ordering::SeqCst)
    }

    /// Takes the single delivery this probe received.
    pub(super) fn take_delivery(&self) -> DatagramDelivery<TestDatagram, Probe> {
        let mut deliveries = self.deliveries.lock().unwrap();
        assert_eq!(deliveries.len(), 1, "expected exactly one delivery");
        deliveries.pop().unwrap()
    }

    pub(super) fn delivery_count(&self) -> usize {
        self.deliveries.lock().unwrap().len()
    }

    pub(super) fn take_candidate(&self) -> DatagramClaimCandidate<TestDatagram, Probe> {
        match self.take_delivery() {
            DatagramDelivery::Competing(candidate) => candidate,
            DatagramDelivery::Exclusive(_) => panic!("expected a competing delivery"),
        }
    }

    pub(super) fn take_exclusive(&self) -> ExclusiveDatagramDelivery<TestDatagram, Probe> {
        match self.take_delivery() {
            DatagramDelivery::Exclusive(delivery) => delivery,
            DatagramDelivery::Competing(_) => panic!("expected an exclusive delivery"),
        }
    }
}

impl DatagramDeliverer<TestDatagram> for Probe {
    type DelivererDatagramState = ProbeState;

    fn new_datagram_state(
        &self,
        datagram: DatagramView<'_>,
        _route: &DatagramRouteMatchInfo,
    ) -> ProbeState {
        self.factory_calls.fetch_add(1, Ordering::SeqCst);
        assert!(!datagram.bytes().is_empty());
        assert!(
            !*self.panic_in_factory.lock().unwrap(),
            "simulated factory panic"
        );
        ProbeState {
            judgments: 0,
            on_drop: self.state_on_drop.lock().unwrap().take(),
            drops: self.state_drops.clone(),
        }
    }

    fn try_claim<'access>(
        &self,
        access: DatagramClaimAccess<'access, TestDatagram>,
        _route: &DatagramRouteMatchInfo,
        mut state: ProbeState,
    ) -> DatagramClaimOutcome<'access, TestDatagram, ProbeState> {
        self.claim_calls.fetch_add(1, Ordering::SeqCst);
        state.judgments += 1;
        assert!(!access.bytes().is_empty());
        let judging = *self.judging.lock().unwrap();
        match judging {
            Judging::Reject => DatagramClaimOutcome::Unclaimed { access, state },
            Judging::Accept => DatagramClaimOutcome::Claimed {
                datagram: access.into_exclusive(),
                state,
            },
            Judging::PanicBeforeTake => panic!("simulated judgment panic"),
            Judging::PanicAfterTake => {
                let _datagram = access.into_exclusive();
                panic!("simulated panic after taking the datagram")
            }
        }
    }

    fn deliver(&self, delivery: DatagramDelivery<TestDatagram, Self>) {
        self.deliveries.lock().unwrap().push(delivery);
    }
}

/// Collects the work handed off under the on-unclaimed policy.
#[derive(Clone, Default)]
pub(super) struct UnclaimedSink(Arc<Mutex<Vec<UnclaimedWork<TestDatagram>>>>);

impl UnclaimedSink {
    pub(super) fn policy(&self) -> DatagramFinishPolicy<TestDatagram> {
        let sink = self.0.clone();
        DatagramFinishPolicy::OnUnclaimed {
            handoff: Box::new(move |work| sink.lock().unwrap().push(work)),
            offered: OfferedRouteHistory::new(),
            continuation: ReflowContinuation::new(),
        }
    }

    pub(super) fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    pub(super) fn take(&self) -> Vec<UnclaimedWork<TestDatagram>> {
        std::mem::take(&mut self.0.lock().unwrap())
    }
}

/// Prepares and dispatches one datagram to `probes`, in order.
pub(super) fn route(
    datagram: TestDatagram,
    finish: DatagramFinishPolicy<TestDatagram>,
    probes: &[&Arc<Probe>],
) {
    let entries = probes
        .iter()
        .map(|probe| {
            let erased: Arc<dyn SendDatagramDeliverer<TestDatagram>> = Arc::clone(probe) as _;
            (erased, DatagramRouteMatchInfo::new())
        })
        .collect();
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
