use std::{
    num::NonZeroUsize,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use sakuya_datagram_routing::route::router::VersionService;
use sakuya_link::{ArrivalFacts, BindingId, Link, ReceivedDatagram};
use sakuya_wire::version::Version;

use super::NegotiatingVersionService;
use crate::test_link::TestLink;

/// A long header of version `0x1a2a3a4a` with a 3-byte destination and a
/// 2-byte source connection ID, padded to `len` bytes.
fn datagram(len: usize, link: &TestLink) -> ReceivedDatagram<Vec<u8>, TestLink> {
    let mut bytes = vec![0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 3, 1, 2, 3, 2, 9, 8];
    bytes.resize(len, 0);
    ReceivedDatagram::new(bytes, ArrivalFacts::new(link.clone(), Duration::ZERO, None))
}

fn link() -> TestLink {
    TestLink::new(4433, "192.0.2.1:5000".parse().unwrap(), &BindingId::new())
}

const VERSION: Version = Version::new(0x1a2a_3a4a);

/// Counts its wakes.
struct CountingWaker(std::sync::atomic::AtomicUsize);

impl Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[test]
fn a_large_enough_datagram_queues_a_response_and_wakes_the_driver() {
    let (service, queue) = NegotiatingVersionService::new(NonZeroUsize::new(4).unwrap());
    let counter = Arc::new(CountingWaker(0.into()));
    let waker = Waker::from(Arc::clone(&counter));
    let mut cx = Context::from_waker(&waker);
    assert!(queue.poll_pop(&mut cx).is_pending());

    let link = link();
    service.unsupported_version(VERSION, datagram(1200, &link));
    assert_eq!(counter.0.load(std::sync::atomic::Ordering::Relaxed), 1);
    let Poll::Ready(pending) = queue.poll_pop(&mut cx) else {
        panic!("nothing queued");
    };
    assert_eq!(pending.client_dcid.as_bytes(), [1, 2, 3]);
    assert_eq!(pending.client_scid.as_bytes(), [9, 8]);
    assert_eq!(pending.client_version, VERSION);
    assert_eq!(pending.link.id(), link.id());
    assert!(queue.is_empty());
}

#[test]
fn a_small_datagram_is_released() {
    let (service, queue) = NegotiatingVersionService::new(NonZeroUsize::new(4).unwrap());
    service.unsupported_version(VERSION, datagram(1199, &link()));
    assert!(queue.is_empty());
    assert_eq!(queue.dropped(), 0);
}

#[test]
fn a_full_queue_counts_the_dropped_response() {
    let (service, queue) = NegotiatingVersionService::new(NonZeroUsize::new(2).unwrap());
    let link = link();
    for _ in 0..3 {
        service.unsupported_version(VERSION, datagram(1200, &link));
    }
    assert_eq!(queue.len(), 2);
    assert_eq!(queue.dropped(), 1);
}
