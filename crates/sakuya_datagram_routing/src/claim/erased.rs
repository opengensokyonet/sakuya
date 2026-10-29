//! Erased deliverers for route tables that hold different deliverer types
//!
//! A route table stores deliverers of different Rust types side by side. The
//! erasure happens at registration: the concrete deliverer, its state factory,
//! its judgment and its strongly typed `deliver` are erased together, by
//! coercing `Arc<Deliverer>` into one of the trait objects below. When routing
//! dispatches a datagram, the erased object builds the strongly typed
//! candidate or exclusive delivery inside code that still knows the concrete
//! type and passes it to the original deliverer. Private state is never erased
//! on its own, and no route key is used to recover a type.
//!
//! Erasure keeps instance identity: each `Arc` is its own target, so two
//! deliverers of the same Rust type stay two targets.

use std::sync::Arc;

use super::shared::Participation;
use super::{
    DatagramClaimCandidate, DatagramDeliverer, DatagramDelivery, DatagramRouteMatchInfo,
    ExclusiveDatagram, ExclusiveDatagramDelivery,
};

pub(super) mod sealed {
    use std::sync::Arc;

    use super::super::DatagramRouteMatchInfo;
    use super::super::ExclusiveDatagram;
    use super::super::shared::Participation;

    /// Dispatch into the concrete deliverer behind an erased one.
    pub trait DispatchDelivery<Inner> {
        /// Builds a competing candidate and delivers it.
        fn deliver_competing(
            self: Arc<Self>,
            participation: Participation<Inner>,
            route: DatagramRouteMatchInfo,
        );

        /// Builds an exclusive delivery with uninitialized state and delivers
        /// it.
        fn deliver_exclusive(
            self: Arc<Self>,
            datagram: ExclusiveDatagram<Inner>,
            route: DatagramRouteMatchInfo,
        );
    }
}

impl<Inner, Deliverer: DatagramDeliverer<Inner>> sealed::DispatchDelivery<Inner> for Deliverer {
    fn deliver_competing(
        self: Arc<Self>,
        participation: Participation<Inner>,
        route: DatagramRouteMatchInfo,
    ) {
        let candidate = DatagramClaimCandidate::new(participation, route, Arc::clone(&self));
        self.deliver(DatagramDelivery::Competing(candidate));
    }

    fn deliver_exclusive(
        self: Arc<Self>,
        datagram: ExclusiveDatagram<Inner>,
        route: DatagramRouteMatchInfo,
    ) {
        let delivery = ExclusiveDatagramDelivery::new(datagram, route, None, Arc::clone(&self));
        self.deliver(DatagramDelivery::Exclusive(delivery));
    }
}

/// A deliverer of any type, for a route table used on one thread.
///
/// Every [`DatagramDeliverer`] implements it; use it only as a trait object,
/// `Arc<dyn ErasedDatagramDeliverer<Inner> + 'a>`, obtained by coercing an
/// `Arc` of the concrete deliverer. It adds no requirement to the deliverer:
/// local `Rc` state and borrowed deliverers erase as well. The trait object is
/// neither `Send` nor `Sync`, and nothing can make it so afterwards; a route
/// table shared between threads uses [`SendDatagramDeliverer`] instead.
///
/// ```
/// # use std::rc::Rc;
/// # use std::sync::Arc;
/// # use sakuya_datagram_routing::claim::*;
/// // A deliverer without fields is `Send + Sync`, yet its state is local.
/// struct Fieldless;
///
/// impl DatagramDeliverer<Vec<u8>> for Fieldless {
///     type DelivererDatagramState = Rc<Vec<u8>>;
/// #   fn new_datagram_state(
/// #       &self, _: DatagramView<'_>, _: &DatagramRouteMatchInfo,
/// #   ) -> Rc<Vec<u8>> {
/// #       Rc::new(Vec::new())
/// #   }
/// #   fn try_claim<'access>(
/// #       &self,
/// #       access: DatagramClaimAccess<'access, Vec<u8>>,
/// #       _: &DatagramRouteMatchInfo,
/// #       state: Rc<Vec<u8>>,
/// #   ) -> DatagramClaimOutcome<'access, Vec<u8>, Rc<Vec<u8>>> {
/// #       DatagramClaimOutcome::Unclaimed { access, state }
/// #   }
/// #   fn deliver(&self, _: DatagramDelivery<Vec<u8>, Self>) {}
///     // ...
/// }
///
/// let local: Arc<dyn ErasedDatagramDeliverer<Vec<u8>>> = Arc::new(Fieldless);
/// ```
pub trait ErasedDatagramDeliverer<Inner>: sealed::DispatchDelivery<Inner> {}

impl<Inner, Deliverer: DatagramDeliverer<Inner>> ErasedDatagramDeliverer<Inner> for Deliverer {}

/// A deliverer of any type, for a route table shared between threads.
///
/// Use it only as a trait object, `Arc<dyn SendDatagramDeliverer<Inner> +
/// 'a>`, which is `Send + Sync`. The coercion from `Arc<Deliverer>` succeeds
/// only where the concrete type shows that everything a dispatch produces can
/// cross threads: the deliverer is `Send + Sync`, and its private state and the
/// datagram are `Send`. Candidates, exclusive deliveries and attempt futures of
/// such a deliverer are therefore `Send`. The private state never needs `Sync`.
///
/// `Deliverer: Send + Sync` alone is not enough, because it says nothing about
/// the state its factory returns:
///
/// ```compile_fail,E0277
/// # use std::rc::Rc;
/// # use std::sync::Arc;
/// # use sakuya_datagram_routing::claim::*;
/// struct Fieldless;
///
/// impl DatagramDeliverer<Vec<u8>> for Fieldless {
///     type DelivererDatagramState = Rc<Vec<u8>>;
/// #   fn new_datagram_state(
/// #       &self, _: DatagramView<'_>, _: &DatagramRouteMatchInfo,
/// #   ) -> Rc<Vec<u8>> {
/// #       Rc::new(Vec::new())
/// #   }
/// #   fn try_claim<'access>(
/// #       &self,
/// #       access: DatagramClaimAccess<'access, Vec<u8>>,
/// #       _: &DatagramRouteMatchInfo,
/// #       state: Rc<Vec<u8>>,
/// #   ) -> DatagramClaimOutcome<'access, Vec<u8>, Rc<Vec<u8>>> {
/// #       DatagramClaimOutcome::Unclaimed { access, state }
/// #   }
/// #   fn deliver(&self, _: DatagramDelivery<Vec<u8>, Self>) {}
///     // ...
/// }
///
/// let shared: Arc<dyn SendDatagramDeliverer<Vec<u8>>> = Arc::new(Fieldless);
/// ```
///
/// State that is `Send` but not `Sync`, such as a [`Cell`](std::cell::Cell),
/// is accepted, and the candidates move between threads:
///
/// ```
/// # use std::cell::Cell;
/// # use std::sync::Arc;
/// # use sakuya_datagram_routing::claim::*;
/// struct Counting;
///
/// impl DatagramDeliverer<Vec<u8>> for Counting {
///     type DelivererDatagramState = Cell<u32>;
/// #   fn new_datagram_state(
/// #       &self, _: DatagramView<'_>, _: &DatagramRouteMatchInfo,
/// #   ) -> Cell<u32> {
/// #       Cell::new(0)
/// #   }
/// #   fn try_claim<'access>(
/// #       &self,
/// #       access: DatagramClaimAccess<'access, Vec<u8>>,
/// #       _: &DatagramRouteMatchInfo,
/// #       state: Cell<u32>,
/// #   ) -> DatagramClaimOutcome<'access, Vec<u8>, Cell<u32>> {
/// #       state.set(state.get() + 1);
/// #       DatagramClaimOutcome::Unclaimed { access, state }
/// #   }
/// #   fn deliver(&self, _: DatagramDelivery<Vec<u8>, Self>) {}
///     // ...
/// }
///
/// fn assert_send<T: Send>() {}
///
/// let shared: Arc<dyn SendDatagramDeliverer<Vec<u8>>> = Arc::new(Counting);
/// assert_send::<DatagramClaimCandidate<Vec<u8>, Counting>>();
/// assert_send::<DatagramClaimFuture<Vec<u8>, Counting>>();
/// assert_send::<DatagramDelivery<Vec<u8>, Counting>>();
/// ```
///
/// A deliverer erased into the local trait object has lost the evidence, even
/// when its concrete type had it:
///
/// ```compile_fail,E0277
/// # use std::sync::Arc;
/// # use sakuya_datagram_routing::claim::*;
/// struct Plain;
///
/// impl DatagramDeliverer<Vec<u8>> for Plain {
///     type DelivererDatagramState = ();
/// #   fn new_datagram_state(&self, _: DatagramView<'_>, _: &DatagramRouteMatchInfo) {}
/// #   fn try_claim<'access>(
/// #       &self,
/// #       access: DatagramClaimAccess<'access, Vec<u8>>,
/// #       _: &DatagramRouteMatchInfo,
/// #       state: (),
/// #   ) -> DatagramClaimOutcome<'access, Vec<u8>, ()> {
/// #       DatagramClaimOutcome::Unclaimed { access, state }
/// #   }
/// #   fn deliver(&self, _: DatagramDelivery<Vec<u8>, Self>) {}
///     // ...
/// }
///
/// let local: Arc<dyn ErasedDatagramDeliverer<Vec<u8>>> = Arc::new(Plain);
/// std::thread::spawn(move || drop(local));
/// ```
pub trait SendDatagramDeliverer<Inner>: ErasedDatagramDeliverer<Inner> + Send + Sync {}

impl<Inner, Deliverer> SendDatagramDeliverer<Inner> for Deliverer
where
    Inner: Send,
    Deliverer: DatagramDeliverer<Inner> + Send + Sync,
    Deliverer::DelivererDatagramState: Send,
{
}
