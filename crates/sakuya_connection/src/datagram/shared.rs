//! The capability of the queues of an established layer through the shared
//! connection, written once for every queues: sending and receiving on the
//! handle of the layer ([`Datagrams`]), what a writer sends through
//! ([`SharedDatagramSend`]), and the ticket of a datagram sent
//! ([`SharedDatagramTicket`]).
//!
//! Such a capability holds the connection in its wrapper and the identity
//! of its layer; a ticket also holds its datagram's key and the pointer to
//! its credential ([`CredentialPointer`]). Each operation borrows the
//! connection once, is lent the established layer while it is the
//! capability's own, and has the layer's queues do it
//! ([`DatagramQueues::send_held`] and the others), lent the send
//! strategy's publisher, whose changes it hands on at the connection
//! afterwards; a ticket names its datagram to the queues by its key with
//! its credential borrowed ([`HeldDatagram`]). The last holder of a
//! ticket's credential hands it back to the queues when it drops its
//! ticket, which withdraws the datagram, or when it releases it, which
//! does not.
//!
//! Once the layer ended, a capability reads what its queues left
//! ([`DatagramLayerRemains`]): in the connection node while the connection
//! runs, in what the parts keep after its end; a receive reads what was not
//! read until nothing is left, then reports the end.

use core::{
    borrow::Borrow,
    fmt,
    future::{Future, poll_fn},
    marker::PhantomData,
    task::Poll,
};

use bytes::Bytes;
use frunk_core::{HList, hlist_pat};
use sakuya_stream::{
    connection::{LayerEnd, LayerEndedError},
    send_options::{NoSendOptions, destination::AnyActiveLinkPath, urgency::Urgency},
};
use sakuya_wire::parts::Selector;

use super::{
    DatagramChoices, DatagramLayerRemains, DatagramLayerRemainsOf, DatagramQueues,
    DatagramQueuesFamilyOf, DatagramQueuesOf, DatagramQueuesRemainsOf, DatagramSide,
    application::{
        DatagramFrameLimits, DatagramSend, DatagramWriter, Datagrams, DroppedDatagrams,
        SendDatagramError,
    },
    send::{
        DatagramIntent, DatagramKey, DatagramSettlement, DatagramState, DatagramWithdrawCause,
        HeldDatagram, WithdrawReport,
    },
};
use crate::{
    driver::LendNode,
    error::ConnectionErrorsOf,
    share::{LineageLists, LineagePartList, RemainsOf},
    shared::SharedConnection,
    take::{GetAt, Take, TakeEach},
    v1::{
        Choices, CloseCauseOf, MakerChoices,
        application_handles::{
            connection::{ConnectionHandleRemainsOf, ConnectionHandleStateOf, LayerId},
            credential::{CredentialPointer, HandleCredential},
            established_layer::{EstablishedLayerHandle, LayerGone, LayerReach, lend_layer_or},
        },
        send::SendTypes,
        send_planning::{
            ComponentPublishing, PublisherOf, SendStrategyPublisher, StrategyPublisherFor,
        },
    },
};

/// What a datagram received is on the side of the choices `T`.
type ReceivedOf<T> = <<T as MakerChoices>::Side as DatagramSide>::Received;

/// What a lend of the layer takes: the queues, and the send strategy's
/// publisher they are lent.
type QueuesTakes<T, L> = HList![DatagramQueuesOf<T, L>, SendStrategyPublisher<PublisherOf<T, L>>];

/// What an operation through the shared connection reaches of the queues
/// of a layer: the queues and the publisher they are lent, while the layer
/// is there; otherwise how it ended and what its queues left, which is
/// there unless the layer had no queues.
enum QueuesReach<'a, T: Choices<Side: DatagramSide, Host: DatagramChoices>, L: ConnectionErrorsOf>
where
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
{
    Queues(&'a mut DatagramQueuesOf<T, L>, &'a mut PublisherOf<T, L>),
    Gone(
        Option<&'a mut DatagramLayerRemainsOf<T>>,
        LayerEnd<CloseCauseOf<T, L>>,
    ),
}

/// Lend what `op` reaches of the queues of the layer `layer` of
/// `connection` once: see [`QueuesReach`]. What the queues did through the
/// publisher is handed on at the connection afterwards.
///
/// `Ie`, `Ic` and `Ir` are where the connection handle's state is in the
/// layer's lineage and in the connection node's, and where version 1's part
/// is in what the parts keep after the end; `Iq` and `In` where the queues
/// and the send strategy's publisher are in the layer's lineage; `Ik` and
/// `Irq` where what the queues of the layers that ended left is in the
/// connection node and in what the parts keep after the end.
fn reach_queues<T, L, S, R, Ie, Ic, Ir, Iq, In, Ik, Irq>(
    connection: &S,
    layer: LayerId,
    op: impl FnOnce(QueuesReach<'_, T, L>) -> R,
) -> R
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
    RemainsOf<T, L>:
        Selector<ConnectionHandleRemainsOf<T, L>, Ir> + Selector<DatagramQueuesRemainsOf<T>, Irq>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + TakeEach<'v, QueuesTakes<T, L>, HList![Iq, In]>,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<ConnectionHandleStateOf<T, L>, Ic> + GetAt<DatagramQueuesRemainsOf<T>, Ik>,
{
    let mut op = Some(op);
    let reached = lend_layer_or::<T, L, S, _, Ie, Ic, Ir>(connection, layer, |reach| {
        let op = op.take().expect("called once");
        match reach {
            LayerReach::Layer(lineage, _) => {
                let (hlist_pat![mut queues, mut publisher], mut rest) =
                    Take::<QueuesTakes<T, L>, HList![Iq, In]>::take(lineage);
                let result = op(QueuesReach::Queues(&mut queues, publisher.publisher_mut()));
                if let Some(changed) = publisher.take_changed() {
                    rest.publish(changed);
                }
                result
            }
            LayerReach::Gone(LayerGone::Connection(mut lineage), end) => {
                let mut kept = lineage.get_mut::<DatagramQueuesRemainsOf<T>, Ik>();
                op(QueuesReach::Gone(kept.layer_mut(layer), end))
            }
            LayerReach::Gone(LayerGone::Ended(remains), end) => {
                let kept = Selector::<DatagramQueuesRemainsOf<T>, Irq>::get_mut(remains);
                op(QueuesReach::Gone(kept.layer_mut(layer), end))
            }
        }
    });
    match reached {
        Ok(done) => done,
        Err(end) => {
            let op = op.take().expect("not called");
            op(QueuesReach::Gone(None, end))
        }
    }
}

/// Reading how many datagrams were dropped on the handle of the
/// established layer `T`, `L`, `S`, `A`, whatever its queues.
///
/// `Ie`, `Ic` and `Ir` are where the connection handle's state is in the
/// layer's lineage and in the connection node's, and where version 1's part
/// is in what the parts keep after the end; `Iq` and `In` where the queues
/// and the send strategy's publisher are in the layer's lineage; `Ik` and
/// `Irq` where what the queues of the layers that ended left is in the
/// connection node and in what the parts keep after the end. The compiler
/// infers them.
impl<T, L, S, A, Ie, Ic, Ir, Iq, In, Ik, Irq> DroppedDatagrams<(Ie, Ic, Ir, Iq, In, Ik, Irq)>
    for EstablishedLayerHandle<T, L, S, A>
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
    DatagramQueuesOf<T, L>: DatagramQueues<CloseCauseOf<T, L>, SendTypes<T, L>>,
    DatagramLayerRemainsOf<T>: DatagramLayerRemains,
    RemainsOf<T, L>:
        Selector<ConnectionHandleRemainsOf<T, L>, Ir> + Selector<DatagramQueuesRemainsOf<T>, Irq>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + TakeEach<'v, QueuesTakes<T, L>, HList![Iq, In]>,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<ConnectionHandleStateOf<T, L>, Ic> + GetAt<DatagramQueuesRemainsOf<T>, Ik>,
{
    fn dropped_datagrams(&self) -> u64 {
        let (connection, layer) = self.reach();
        reach_queues::<T, L, S, _, Ie, Ic, Ir, Iq, In, Ik, Irq>(connection, layer, |reach| {
            match reach {
                QueuesReach::Queues(queues, _) => queues.dropped_datagrams(),
                QueuesReach::Gone(kept, _) => kept.map_or(0, |kept| kept.dropped()),
            }
        })
    }
}

/// The capability of the queues through the shared connection, on the
/// handle of an established layer, whatever its queues: each call, and
/// each poll of a receive, lends the layer once. The writer holds the
/// connection and the layer's identity; a ticket also holds its datagram's
/// key and its credential. Once the layer ended, a receive reads what the
/// queues left until nothing is left, then reports the end. The places are
/// as for [`DroppedDatagrams`], and `Ij` is the place of the datagram intents in the composition's sum
/// of intents.
impl<T, L, S, A, Ie, Ic, Ir, Iq, In, Ik, Irq, Ij> Datagrams<(Ie, Ic, Ir, Iq, In, Ik, Irq, Ij)>
    for EstablishedLayerHandle<T, L, S, A>
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
    DatagramQueuesOf<T, L>:
        DatagramQueues<CloseCauseOf<T, L>, SendTypes<T, L>, Received = ReceivedOf<T>>,
    DatagramLayerRemainsOf<T>: DatagramLayerRemains<Received = ReceivedOf<T>>,
    PublisherOf<T, L>: StrategyPublisherFor<DatagramIntent<Urgency>, Ij>,
    RemainsOf<T, L>:
        Selector<ConnectionHandleRemainsOf<T, L>, Ir> + Selector<DatagramQueuesRemainsOf<T>, Irq>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + TakeEach<'v, QueuesTakes<T, L>, HList![Iq, In]>,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<ConnectionHandleStateOf<T, L>, Ic> + GetAt<DatagramQueuesRemainsOf<T>, Ik>,
{
    type Received = ReceivedOf<T>;
    type SendCapability = SharedDatagramSend<T, L, S, (Ie, Ic, Ir, Iq, In, Ik, Irq, Ij)>;
    type CloseCause = CloseCauseOf<T, L>;

    fn datagram_writer(&self) -> DatagramWriter<Self::SendCapability, NoSendOptions> {
        let (connection, layer) = self.reach();
        DatagramWriter::new(SharedDatagramSend {
            connection: connection.clone(),
            layer,
            places: PhantomData,
        })
    }

    fn recv_datagram(
        &self,
    ) -> impl Future<Output = Result<ReceivedOf<T>, LayerEndedError<CloseCauseOf<T, L>>>> {
        poll_fn(move |cx| {
            let (connection, layer) = self.reach();
            reach_queues::<T, L, S, _, Ie, Ic, Ir, Iq, In, Ik, Irq>(connection, layer, |reach| {
                match reach {
                    QueuesReach::Queues(queues, _) => queues.poll_receive(cx),
                    QueuesReach::Gone(kept, end) => Poll::Ready(
                        kept.and_then(|kept| kept.pop_received())
                            .ok_or_else(|| LayerEndedError::new(end)),
                    ),
                }
            })
        })
    }
}

/// The capability of the send queue through the shared connection
/// (`SharedDatagramSend`), which a [`DatagramWriter`] holds: the connection
/// in its wrapper and the layer's identity. `I` is where the components it
/// is lent are and the place of the datagram intents, as [`Datagrams`]
/// names them. It holds no credential: dropping it means nothing to the
/// protocol. A clone sends to the same queue.
pub struct SharedDatagramSend<T, L, S, I> {
    connection: S,
    layer: LayerId,
    #[allow(clippy::type_complexity)] // a marker of three type parameters
    places: PhantomData<fn() -> (T, L, I)>,
}

impl<T, L, S: Clone, I> Clone for SharedDatagramSend<T, L, S, I> {
    fn clone(&self) -> Self {
        Self {
            connection: self.connection.clone(),
            layer: self.layer,
            places: PhantomData,
        }
    }
}

impl<T, L, S, I> fmt::Debug for SharedDatagramSend<T, L, S, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedDatagramSend").finish_non_exhaustive()
    }
}

/// Datagrams are sent with an urgency, to any active link path; each send
/// lends the layer once, and the queues keep the datagram for its ticket.
impl<T, L, S, Ie, Ic, Ir, Iq, In, Ik, Irq, Ij> DatagramSend
    for SharedDatagramSend<T, L, S, (Ie, Ic, Ir, Iq, In, Ik, Irq, Ij)>
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
    DatagramQueuesOf<T, L>: DatagramQueues<CloseCauseOf<T, L>, SendTypes<T, L>>,
    DatagramLayerRemainsOf<T>: DatagramLayerRemains,
    PublisherOf<T, L>: StrategyPublisherFor<DatagramIntent<Urgency>, Ij>,
    RemainsOf<T, L>:
        Selector<ConnectionHandleRemainsOf<T, L>, Ir> + Selector<DatagramQueuesRemainsOf<T>, Irq>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + TakeEach<'v, QueuesTakes<T, L>, HList![Iq, In]>,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<ConnectionHandleStateOf<T, L>, Ic> + GetAt<DatagramQueuesRemainsOf<T>, Ik>,
{
    type Parameters = Urgency;
    type Destination = AnyActiveLinkPath;
    type CloseCause = CloseCauseOf<T, L>;
    type Ticket =
        SharedDatagramTicket<T, L, S, (Ie, Ic, Ir, Iq, In, Ik, Irq, Ij), HandleCredential>;

    fn send_with(
        &self,
        payload: Bytes,
        parameters: &Urgency,
        destination: &AnyActiveLinkPath,
    ) -> Result<Self::Ticket, SendDatagramError<CloseCauseOf<T, L>>> {
        let key = reach_queues::<T, L, S, _, Ie, Ic, Ir, Iq, In, Ik, Irq>(
            &self.connection,
            self.layer,
            |reach| match reach {
                QueuesReach::Queues(queues, publish) => {
                    queues.send_held::<Ij, _>(publish, payload, parameters, destination)
                }
                QueuesReach::Gone(_, end) => Err(LayerEndedError::new(end).into()),
            },
        )?;
        Ok(SharedDatagramTicket {
            connection: self.connection.clone(),
            layer: self.layer,
            key,
            credential: Some(HandleCredential::new()),
            give_back: SharedDatagramTicket::<
                T,
                L,
                S,
                (Ie, Ic, Ir, Iq, In, Ik, Irq, Ij),
                HandleCredential,
            >::give_back,
            places: PhantomData,
        })
    }

    /// Nothing fits once the layer ended.
    fn datagram_limits(&self) -> DatagramFrameLimits {
        reach_queues::<T, L, S, _, Ie, Ic, Ir, Iq, In, Ik, Irq>(
            &self.connection,
            self.layer,
            |reach| match reach {
                QueuesReach::Queues(queues, _) => queues.limits(),
                QueuesReach::Gone(..) => DatagramFrameLimits {
                    guaranteed: 0,
                    peer: 0,
                },
            },
        )
    }
}

/// What hands a ticket's credential back to the queues: the connection,
/// the layer, the datagram's key and the credential; the datagram is
/// withdrawn.
type GiveBack<S> = fn(&S, LayerId, DatagramKey, HandleCredential);

/// The ticket of one datagram sent through the shared connection
/// (`SharedDatagramTicket`): the connection in its wrapper, the layer's
/// identity, the datagram's key in the queues and the pointer `C` to the
/// ticket's credential. It tells where the datagram stands and waits for
/// it to be settled, as a [`DatagramTicket`](super::send::DatagramTicket)
/// does; each call, and each poll of a wait, lends the layer once, and once
/// the layer ended reads what the queues left.
///
/// It can be cloned where `C` can: sent with the credential itself, it is
/// turned into one with a shared credential by
/// [`into_shared`](Self::into_shared). Once the last holder of the
/// credential drops its ticket, the datagram is withdrawn, if it was not
/// written into a packet yet; [`release`](Self::release) lets it go
/// without withdrawing it.
#[must_use = "dropping the ticket withdraws the datagram; `release` lets it go without that"]
pub struct SharedDatagramTicket<T, L, S, I, C: CredentialPointer> {
    connection: S,
    layer: LayerId,
    key: DatagramKey,
    /// `None` once it was handed back, by a release, a withdrawal or a
    /// move to a shared pointer.
    credential: Option<C>,
    give_back: GiveBack<S>,
    #[allow(clippy::type_complexity)] // a marker of three type parameters
    places: PhantomData<fn() -> (T, L, I)>,
}

impl<T, L, S: Clone, I, C: CredentialPointer + Clone> Clone
    for SharedDatagramTicket<T, L, S, I, C>
{
    fn clone(&self) -> Self {
        Self {
            connection: self.connection.clone(),
            layer: self.layer,
            key: self.key,
            credential: self.credential.clone(),
            give_back: self.give_back,
            places: PhantomData,
        }
    }
}

impl<T, L, S, I, C: CredentialPointer> fmt::Debug for SharedDatagramTicket<T, L, S, I, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedDatagramTicket")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// The last holder of the credential hands it back when it drops its
/// ticket, and the datagram is withdrawn.
impl<T, L, S, I, C: CredentialPointer> Drop for SharedDatagramTicket<T, L, S, I, C> {
    fn drop(&mut self) {
        if let Some(credential) = self.credential.take().and_then(C::into_credential) {
            (self.give_back)(&self.connection, self.layer, self.key, credential);
        }
    }
}

impl<T, L, S: Clone, I> SharedDatagramTicket<T, L, S, I, HandleCredential> {
    /// The same ticket with the credential behind the shared pointer `Q`
    /// ([`Arc`](alloc::sync::Arc) or [`Rc`](alloc::rc::Rc)), so that it can
    /// be cloned.
    pub fn into_shared<Q>(mut self) -> SharedDatagramTicket<T, L, S, I, Q>
    where
        Q: CredentialPointer + From<HandleCredential>,
    {
        SharedDatagramTicket {
            connection: self.connection.clone(),
            layer: self.layer,
            key: self.key,
            credential: self.credential.take().map(Q::from),
            give_back: self.give_back,
            places: PhantomData,
        }
    }
}

/// What a ticket of a datagram the layer's queues left nothing of reads:
/// withdrawn as the layer ended.
const GONE: DatagramWithdrawCause = DatagramWithdrawCause::LayerEnded;

/// The ticket's operations, whatever the queues; the places are as for
/// [`Datagrams`]. `C` lends the credential it points to ([`Borrow`]), as
/// the credential itself, [`Arc`](alloc::sync::Arc) and
/// [`Rc`](alloc::rc::Rc) do.
impl<T, L, S, C, Ie, Ic, Ir, Iq, In, Ik, Irq, Ij>
    SharedDatagramTicket<T, L, S, (Ie, Ic, Ir, Iq, In, Ik, Irq, Ij), C>
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
    DatagramQueuesOf<T, L>: DatagramQueues<CloseCauseOf<T, L>, SendTypes<T, L>>,
    DatagramLayerRemainsOf<T>: DatagramLayerRemains,
    PublisherOf<T, L>: StrategyPublisherFor<DatagramIntent<Urgency>, Ij>,
    RemainsOf<T, L>:
        Selector<ConnectionHandleRemainsOf<T, L>, Ir> + Selector<DatagramQueuesRemainsOf<T>, Irq>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + TakeEach<'v, QueuesTakes<T, L>, HList![Iq, In]>,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<ConnectionHandleStateOf<T, L>, Ic> + GetAt<DatagramQueuesRemainsOf<T>, Ik>,
    C: CredentialPointer,
{
    /// Hand the credential of `key` back: the queues forget the datagram
    /// for its holder and withdraw it, if it was not written into a packet
    /// yet; once the layer ended, what its queues left of it is forgotten.
    fn give_back(connection: &S, layer: LayerId, key: DatagramKey, credential: HandleCredential) {
        let _ = Self::withdraw_now(connection, layer, key, &credential);
    }

    /// Withdraw the datagram of `key` for the holder of `credential`, who
    /// hands it back.
    fn withdraw_now(
        connection: &S,
        layer: LayerId,
        key: DatagramKey,
        credential: &HandleCredential,
    ) -> WithdrawReport {
        let held = HeldDatagram::new(key, credential);
        reach_queues::<T, L, S, _, Ie, Ic, Ir, Iq, In, Ik, Irq>(connection, layer, |reach| {
            match reach {
                QueuesReach::Queues(queues, publish) => {
                    queues.withdraw_held::<Ij, _>(publish, held)
                }
                QueuesReach::Gone(Some(kept), _) => {
                    kept.take_ticket(key).unwrap_or(WithdrawReport::Withdrawn)
                }
                QueuesReach::Gone(None, _) => WithdrawReport::Withdrawn,
            }
        })
    }

    /// Let the datagram go without withdrawing it, if this holder is the
    /// last of its credential: it is still sent, and nothing hears whether
    /// it is acknowledged or lost. Otherwise only this holder lets go.
    pub fn release(mut self) {
        let Some(credential) = self.credential.take().and_then(C::into_credential) else {
            return;
        };
        let key = self.key;
        let held = HeldDatagram::new(key, &credential);
        reach_queues::<T, L, S, _, Ie, Ic, Ir, Iq, In, Ik, Irq>(
            &self.connection,
            self.layer,
            |reach| match reach {
                QueuesReach::Queues(queues, _) => queues.release_held(held),
                QueuesReach::Gone(Some(kept), _) => {
                    let _ = kept.take_ticket(key);
                }
                QueuesReach::Gone(None, _) => {}
            },
        );
    }
}

/// What the ticket reads and waits for borrows its credential.
impl<T, L, S, C, Ie, Ic, Ir, Iq, In, Ik, Irq, Ij>
    SharedDatagramTicket<T, L, S, (Ie, Ic, Ir, Iq, In, Ik, Irq, Ij), C>
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
    DatagramQueuesOf<T, L>: DatagramQueues<CloseCauseOf<T, L>, SendTypes<T, L>>,
    DatagramLayerRemainsOf<T>: DatagramLayerRemains,
    PublisherOf<T, L>: StrategyPublisherFor<DatagramIntent<Urgency>, Ij>,
    RemainsOf<T, L>:
        Selector<ConnectionHandleRemainsOf<T, L>, Ir> + Selector<DatagramQueuesRemainsOf<T>, Irq>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + TakeEach<'v, QueuesTakes<T, L>, HList![Iq, In]>,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<ConnectionHandleStateOf<T, L>, Ic> + GetAt<DatagramQueuesRemainsOf<T>, Ik>,
    C: CredentialPointer + Borrow<HandleCredential>,
{
    /// The datagram as this holder names it to the queues.
    fn held(&self) -> Option<HeldDatagram<'_>> {
        // invariant: the credential leaves the ticket only when it is
        // dropped, released, withdrawn or turned into another
        let credential = self.credential.as_ref()?;
        Some(HeldDatagram::new(self.key, credential.borrow()))
    }

    /// Where the datagram stands now: a datagram that waits may wait as too
    /// large for now ([`DatagramState::WaitingTooLarge`]); once the layer
    /// ended, as its queues left it, or withdrawn as the layer ended if they
    /// left nothing of it.
    pub fn state(&self) -> DatagramState {
        let Some(held) = self.held() else {
            return DatagramState::Withdrawn(GONE);
        };
        reach_queues::<T, L, S, _, Ie, Ic, Ir, Iq, In, Ik, Irq>(
            &self.connection,
            self.layer,
            |reach| match reach {
                QueuesReach::Queues(queues, publish) => queues.ticket_state::<_>(publish, held),
                QueuesReach::Gone(Some(kept), _) => kept
                    .ticket_state(self.key)
                    .unwrap_or(DatagramState::Withdrawn(GONE)),
                QueuesReach::Gone(None, _) => DatagramState::Withdrawn(GONE),
            },
        )
    }

    /// Done once the datagram was acknowledged, declared lost, or withdrawn
    /// without its holder asking, as
    /// [`DatagramTicket::settled`](super::send::DatagramTicket::settled)
    /// is; a datagram that waits as too large for now goes on waiting. Once
    /// the layer ended, as its queues left it.
    pub fn settled(&mut self) -> impl Future<Output = DatagramSettlement> + '_ {
        poll_fn(move |cx| {
            let Some(held) = self.held() else {
                return Poll::Ready(DatagramSettlement::Withdrawn(GONE));
            };
            reach_queues::<T, L, S, _, Ie, Ic, Ir, Iq, In, Ik, Irq>(
                &self.connection,
                self.layer,
                |reach| match reach {
                    QueuesReach::Queues(queues, _) => queues.poll_ticket_settled(held, cx),
                    QueuesReach::Gone(Some(kept), _) => Poll::Ready(
                        kept.ticket_settlement(self.key)
                            .unwrap_or(DatagramSettlement::Withdrawn(GONE)),
                    ),
                    QueuesReach::Gone(None, _) => Poll::Ready(DatagramSettlement::Withdrawn(GONE)),
                },
            )
        })
    }
}

impl<T, L, S, Ie, Ic, Ir, Iq, In, Ik, Irq, Ij>
    SharedDatagramTicket<T, L, S, (Ie, Ic, Ir, Iq, In, Ik, Irq, Ij), HandleCredential>
where
    T: Choices<Side: DatagramSide, Host: DatagramChoices>,
    L: LineagePartList<T> + ConnectionErrorsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    SendTypes<T, L>: ComponentPublishing<DatagramQueuesFamilyOf<T>, DatagramIntent<Urgency>>,
    DatagramQueuesOf<T, L>: DatagramQueues<CloseCauseOf<T, L>, SendTypes<T, L>>,
    DatagramLayerRemainsOf<T>: DatagramLayerRemains,
    PublisherOf<T, L>: StrategyPublisherFor<DatagramIntent<Urgency>, Ij>,
    RemainsOf<T, L>:
        Selector<ConnectionHandleRemainsOf<T, L>, Ir> + Selector<DatagramQueuesRemainsOf<T>, Irq>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + TakeEach<'v, QueuesTakes<T, L>, HList![Iq, In]>,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<ConnectionHandleStateOf<T, L>, Ic> + GetAt<DatagramQueuesRemainsOf<T>, Ik>,
{
    /// Withdraw the datagram, as
    /// [`DatagramTicket::withdraw`](super::send::DatagramTicket::withdraw)
    /// does, handing the credential back; once the layer ended, what
    /// withdrawing would have reported then. Only the one holder of the
    /// credential itself withdraws.
    pub fn withdraw(mut self) -> WithdrawReport {
        let Some(credential) = self.credential.take() else {
            // invariant: as for the reads
            return WithdrawReport::Withdrawn;
        };
        Self::withdraw_now(&self.connection, self.layer, self.key, &credential)
    }
}
