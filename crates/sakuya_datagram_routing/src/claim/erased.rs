//! Erased deliverers for route tables that hold different deliverer types
//!
//! This is the one deliberate erasure boundary of the crate. A route table
//! stores deliverers of different Rust types side by side, chosen at run time
//! by whoever registers them, so the table cannot name them in its type. The
//! erasure happens at registration, by coercing `Arc<Deliverer>` into one of
//! the trait objects below; what is erased is the concrete deliverer together
//! with its `deliver`. Deliveries name only the datagram and the routing
//! domain's handoff, never the deliverer, so routing builds them without
//! knowing the concrete type and passes them through the erased object. No
//! route key is used to recover a type.
//!
//! Both trait objects name the [handoff](DatagramDeliverer::Handoff) of their
//! routing domain, which defaults to [`ReleaseUnclaimed`]; every deliverer in
//! one table uses that handoff.
//!
//! Erasure keeps instance identity: each `Arc` is its own target, so two
//! deliverers of the same Rust type stay two targets.

use super::deliverer::DatagramDeliverer;
use super::delivery::DatagramDelivery;
use super::finish::{ReleaseUnclaimed, UnclaimedHandoff};

pub(super) mod sealed {
    use super::super::delivery::DatagramDelivery;
    use super::super::finish::UnclaimedHandoff;

    /// Dispatch into the concrete deliverer behind an erased one.
    pub trait DispatchDelivery<Inner, Handoff: UnclaimedHandoff<Inner>> {
        /// Delivers through the concrete deliverer's `deliver`.
        fn dispatch_delivery(&self, delivery: DatagramDelivery<Inner, Handoff>);
    }
}

impl<Inner, Deliverer: DatagramDeliverer<Inner>> sealed::DispatchDelivery<Inner, Deliverer::Handoff>
    for Deliverer
{
    fn dispatch_delivery(&self, delivery: DatagramDelivery<Inner, Deliverer::Handoff>) {
        self.deliver(delivery);
    }
}

/// A deliverer of any type, for a route table used on one thread.
///
/// Every [`DatagramDeliverer`] implements it for its
/// [handoff](DatagramDeliverer::Handoff); use it only as a trait object,
/// `Arc<dyn ErasedDatagramDeliverer<Inner, Handoff> + 'a>`, obtained by
/// coercing an `Arc` of the concrete deliverer. It adds no requirement to the
/// deliverer: local `Rc` state and borrowed deliverers erase as well. The
/// trait object is neither `Send` nor `Sync`, and nothing can make it so
/// afterwards; a route table shared between threads uses
/// [`SendDatagramDeliverer`] instead.
///
/// ```
/// # use std::cell::RefCell;
/// # use std::rc::Rc;
/// # use std::sync::Arc;
/// # use sakuya_datagram_routing::claim::deliverer::DatagramDeliverer;
/// # use sakuya_datagram_routing::claim::delivery::DatagramDelivery;
/// # use sakuya_datagram_routing::claim::erased::ErasedDatagramDeliverer;
/// # use sakuya_datagram_routing::claim::finish::ReleaseUnclaimed;
/// // A deliverer that keeps its deliveries in local storage.
/// struct Local(Rc<RefCell<Vec<DatagramDelivery<Vec<u8>, ReleaseUnclaimed>>>>);
///
/// impl DatagramDeliverer<Vec<u8>> for Local {
///     fn deliver(&self, delivery: DatagramDelivery<Vec<u8>, ReleaseUnclaimed>) {
///         self.0.borrow_mut().push(delivery);
///     }
/// }
///
/// let local: Arc<dyn ErasedDatagramDeliverer<Vec<u8>>> =
///     Arc::new(Local(Rc::default()));
/// ```
pub trait ErasedDatagramDeliverer<Inner, Handoff: UnclaimedHandoff<Inner> = ReleaseUnclaimed>:
    sealed::DispatchDelivery<Inner, Handoff>
{
}

impl<Inner, Deliverer: DatagramDeliverer<Inner>> ErasedDatagramDeliverer<Inner, Deliverer::Handoff>
    for Deliverer
{
}

/// A deliverer of any type, for a route table shared between threads.
///
/// Use it only as a trait object, `Arc<dyn SendDatagramDeliverer<Inner,
/// Handoff> + 'a>`, which is `Send + Sync`. The coercion from `Arc<Deliverer>`
/// succeeds only where the concrete type shows that the deliverer is
/// `Send + Sync`, so that routing may call `deliver` from any thread:
///
/// ```compile_fail,E0277
/// # use std::cell::RefCell;
/// # use std::rc::Rc;
/// # use std::sync::Arc;
/// # use sakuya_datagram_routing::claim::deliverer::DatagramDeliverer;
/// # use sakuya_datagram_routing::claim::delivery::DatagramDelivery;
/// # use sakuya_datagram_routing::claim::erased::SendDatagramDeliverer;
/// # use sakuya_datagram_routing::claim::finish::ReleaseUnclaimed;
/// struct Local(Rc<RefCell<Vec<DatagramDelivery<Vec<u8>, ReleaseUnclaimed>>>>);
///
/// impl DatagramDeliverer<Vec<u8>> for Local {
///     fn deliver(&self, delivery: DatagramDelivery<Vec<u8>, ReleaseUnclaimed>) {
///         self.0.borrow_mut().push(delivery);
///     }
/// }
///
/// let shared: Arc<dyn SendDatagramDeliverer<Vec<u8>>> = Arc::new(Local(Rc::default()));
/// ```
///
/// Deliveries do not carry the deliverer, so nothing about them is checked
/// here: routing builds each delivery on the thread that routes the datagram
/// and passes it to `deliver` on that thread. Whether a candidate, an
/// exclusive delivery or an attempt future can move to another thread follows
/// from its own contents, the datagram, the handoff and, for a future, the
/// judgment; a deliverer that sends deliveries elsewhere, for example through
/// a [queue](super::queue), is `Send + Sync` only if they are `Send`. A
/// shared deliverer of local datagrams therefore erases, and its deliveries
/// stay on their thread:
///
/// ```
/// # use std::rc::Rc;
/// # use std::sync::Arc;
/// # use sakuya_datagram_routing::claim::candidate::DatagramClaimCandidate;
/// # use sakuya_datagram_routing::claim::deliverer::DatagramDeliverer;
/// # use sakuya_datagram_routing::claim::delivery::DatagramDelivery;
/// # use sakuya_datagram_routing::claim::erased::SendDatagramDeliverer;
/// # use sakuya_datagram_routing::claim::finish::ReleaseUnclaimed;
/// /// Processes every delivery on the routing thread.
/// struct Direct;
///
/// impl DatagramDeliverer<Rc<[u8]>> for Direct {
///     fn deliver(&self, _: DatagramDelivery<Rc<[u8]>, ReleaseUnclaimed>) {}
/// }
///
/// fn assert_send<T: Send>() {}
///
/// let shared: Arc<dyn SendDatagramDeliverer<Rc<[u8]>>> = Arc::new(Direct);
/// assert_send::<Arc<dyn SendDatagramDeliverer<Rc<[u8]>>>>();
/// assert_send::<DatagramClaimCandidate<Vec<u8>, ReleaseUnclaimed>>();
/// assert_send::<DatagramDelivery<Vec<u8>, ReleaseUnclaimed>>();
/// ```
///
/// A deliverer erased into the local trait object has lost the evidence, even
/// when its concrete type had it:
///
/// ```compile_fail,E0277
/// # use std::sync::Arc;
/// # use sakuya_datagram_routing::claim::deliverer::DatagramDeliverer;
/// # use sakuya_datagram_routing::claim::delivery::DatagramDelivery;
/// # use sakuya_datagram_routing::claim::erased::ErasedDatagramDeliverer;
/// # use sakuya_datagram_routing::claim::finish::ReleaseUnclaimed;
/// struct Plain;
///
/// impl DatagramDeliverer<Vec<u8>> for Plain {
///     fn deliver(&self, _: DatagramDelivery<Vec<u8>, ReleaseUnclaimed>) {}
/// }
///
/// let local: Arc<dyn ErasedDatagramDeliverer<Vec<u8>>> = Arc::new(Plain);
/// std::thread::spawn(move || drop(local));
/// ```
pub trait SendDatagramDeliverer<Inner, Handoff: UnclaimedHandoff<Inner> = ReleaseUnclaimed>:
    ErasedDatagramDeliverer<Inner, Handoff> + Send + Sync
{
}

impl<Inner, Deliverer> SendDatagramDeliverer<Inner, Deliverer::Handoff> for Deliverer where
    Deliverer: DatagramDeliverer<Inner> + Send + Sync
{
}
