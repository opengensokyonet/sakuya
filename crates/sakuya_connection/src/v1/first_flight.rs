//! What a connection is given from its first flight (RFC 9368 §2), and
//! where what it was given waits until the parts of the tree that take it
//! are built.
//!
//! A connection is made with [`FirstFlight`] in two forms. An endpoint that
//! answers at once gives the first datagrams themselves: the first logical
//! path receives them before anything its receiver delivers, through the
//! same code as every later datagram, and the components are built as for
//! any connection. An endpoint that decides before answering has read the
//! first flight outside the connection already; it gives what that reading
//! left, [`FirstFlightReadState`], and each component it concerns takes its
//! own piece of it, once, instead of starting empty: the CRYPTO receiver,
//! the Initial keys, the receive journals and the ACK obligation of the
//! Initial space of the first logical path, the bytes received for the
//! anti-amplification limit of the first logical link, and the inputs held
//! for the first logical path. The first ClientHello read with it waits for
//! the advancing call.
//!
//! The pieces the connection node does not take itself wait in
//! [`FirstFlightStart`] until the first logical path and the first entry
//! are built.

use core::{fmt, mem};

use sakuya_link::{Link, ReceivedDatagram};
use sakuya_packet_protection::initial::{INITIAL_AEAD, InitialSecrets};
use sakuya_recovery::{ack_obligation::AckObligation, receive_journals::ReceiveJournals};
use sakuya_tls::server::engine::FirstClientHello;
use sakuya_wire::connection_id::{ConnectionId, ConnectionIdLength};

use super::{
    Choices, Server, Side,
    crypto::{CryptoReceiveCapacities, CryptoReceiver},
    input::{HeldInput, LogicalPathDatagramReceiver},
    keys::{DirectionKeys, InitialKeys, LevelKeys},
};
use crate::clock::{ConnectionChoices, InstantOf};

/// A datagram as it arrived over the link `Lk`.
type DatagramOf<Lk> = ReceivedDatagram<<Lk as Link>::Payload, Lk>;

/// The handoff of the routing domain of the choices `T`.
type HandoffOf<T> = <<T as Choices>::Receiver as LogicalPathDatagramReceiver<
    <T as ConnectionChoices>::Link,
>>::Handoff;

/// An input held for a logical path of the choices `T`.
type HeldInputOf<T> = HeldInput<<T as ConnectionChoices>::Link, HandoffOf<T>>;

/// The first flight a connection of the choices `T` is given when it is
/// made.
// given once, by value, when the connection is made: boxing what was read
// would allocate for nothing
#[allow(clippy::large_enum_variant)]
pub enum FirstFlight<T: Choices> {
    /// The first datagrams, not read yet: the first logical path receives
    /// them first, in this order. A client, which has no first flight to
    /// receive, gives none.
    Datagrams(Vec<DatagramOf<T::Link>>),
    /// What reading the first datagrams before deciding left.
    Read(FirstFlightReadState<T>),
}

impl<T: Choices> FirstFlight<T> {
    /// The CRYPTO receiver the first flight was read into, the first time
    /// it is asked for; `None` afterwards, and when it was not read.
    pub(super) fn take_crypto_receiver(
        &mut self,
    ) -> Option<CryptoReceiver<T::CryptoReceiveBuffer>> {
        match self {
            Self::Datagrams(_) => None,
            Self::Read(state) => state.crypto.take(),
        }
    }

    /// The Initial keys the first flight was read with, the first time they
    /// are asked for; `None` afterwards, and when it was not read.
    pub(super) fn take_initial_keys(&mut self) -> Option<InitialKeys<T::Crypto>> {
        match self {
            Self::Datagrams(_) => None,
            Self::Read(state) => state.keys.take(),
        }
    }

    /// What is left for the first logical path, the first entry and the
    /// advancing call, the first time it is asked for; nothing afterwards.
    /// The datagrams not read yet are cut with `dcid_len` as the length of
    /// a short header's Destination Connection ID.
    pub(super) fn take_start(&mut self, dcid_len: ConnectionIdLength) -> FirstFlightStart<T> {
        match self {
            Self::Datagrams(datagrams) => FirstFlightStart {
                datagrams: mem::take(datagrams),
                ..FirstFlightStart::empty(dcid_len)
            },
            Self::Read(state) => mem::replace(&mut state.start, FirstFlightStart::empty(dcid_len)),
        }
    }
}

impl<T: Choices> fmt::Debug for FirstFlight<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Datagrams(datagrams) => f
                .debug_struct("Datagrams")
                .field("len", &datagrams.len())
                .finish(),
            Self::Read(state) => f.debug_tuple("Read").field(state).finish(),
        }
    }
}

/// What a server read from the first datagrams of a connection before
/// deciding whether to accept it, made as [`FirstFlight::Read`] when it
/// accepts.
///
/// It is read at Initial: the CRYPTO data received at Initial, the Initial
/// keys, the receive journals and the ACK obligation of the Initial space,
/// the bytes the first datagrams held in all, the 0-RTT packets held until
/// the handshake decides on them, and the first ClientHello once it was
/// read.
pub struct FirstFlightReadState<T: Choices> {
    // each is taken once while the connection node is built; until then
    // all are there
    crypto: Option<CryptoReceiver<T::CryptoReceiveBuffer>>,
    keys: Option<InitialKeys<T::Crypto>>,
    start: FirstFlightStart<T>,
}

impl<T: Choices<Side = Server>> FirstFlightReadState<T> {
    /// Nothing read yet from a first flight sent to `client_dcid`, the
    /// Destination Connection ID of the client's first Initial packet: the
    /// Initial keys derived from it with `crypto` (RFC 9001 §5.2), each
    /// level of `capacities` with an empty CRYPTO buffer, nothing received
    /// and nothing held.
    pub fn new(
        crypto: &T::Crypto,
        client_dcid: &ConnectionId,
        capacities: &CryptoReceiveCapacities,
    ) -> Self {
        let (send, receive) =
            Server::split_initial_secrets(InitialSecrets::derive(crypto, client_dcid));
        Self {
            crypto: Some(CryptoReceiver::new(capacities)),
            keys: Some(InitialKeys::Live(LevelKeys {
                send: DirectionKeys::derive(crypto, INITIAL_AEAD, &send),
                receive: DirectionKeys::derive(crypto, INITIAL_AEAD, &receive),
            })),
            start: FirstFlightStart {
                journals: Some(ReceiveJournals::new()),
                // the Initial space acknowledges at once (RFC 9000 §13.2.1)
                ack: Some(T::AckObligation::new(None)),
                ..FirstFlightStart::empty(client_dcid.length())
            },
        }
    }
}

impl<T: Choices> fmt::Debug for FirstFlightReadState<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FirstFlightReadState")
            .field("received_bytes", &self.start.received_bytes)
            .field("held", &self.start.held.len())
            .field("first_client_hello", &self.start.first.is_some())
            .finish_non_exhaustive()
    }
}

/// What a connection of the choices `T` was given from its first flight
/// for the parts of the tree built after the connection node, kept in the
/// connection node until they take it.
///
/// The first logical path takes the datagrams not read yet, the inputs
/// held, and the receive journals and the ACK obligation of its Initial
/// space; the first entry takes the bytes received; the advancing call
/// takes the first ClientHello. Each is there once, and only when the
/// first flight was read where the piece says so.
pub struct FirstFlightStart<T: Choices> {
    datagrams: Vec<DatagramOf<T::Link>>,
    dcid_len: ConnectionIdLength,
    held: Vec<HeldInputOf<T>>,
    journals: Option<ReceiveJournals<InstantOf<T>>>,
    ack: Option<T::AckObligation>,
    received_bytes: usize,
    first: Option<FirstClientHello>,
}

impl<T: Choices> FirstFlightStart<T> {
    /// Nothing given; datagrams would be cut with `dcid_len`.
    fn empty(dcid_len: ConnectionIdLength) -> Self {
        Self {
            datagrams: Vec::new(),
            dcid_len,
            held: Vec::new(),
            journals: None,
            ack: None,
            received_bytes: 0,
            first: None,
        }
    }

    /// The first datagrams not read yet, in the order they arrived, the
    /// first time they are asked for; empty afterwards, and when the first
    /// flight was read.
    pub fn take_datagrams(&mut self) -> Vec<DatagramOf<T::Link>> {
        mem::take(&mut self.datagrams)
    }

    /// The length of a short header's Destination Connection ID the first
    /// datagrams are cut with: that of the client's first Destination
    /// Connection ID, under which routing delivers them.
    pub fn dcid_len(&self) -> ConnectionIdLength {
        self.dcid_len
    }

    /// The inputs held for the first logical path while the first flight
    /// was read, in the order of arrival, the first time they are asked
    /// for; empty afterwards, and when it was not read.
    pub fn take_held(&mut self) -> Vec<HeldInputOf<T>> {
        mem::take(&mut self.held)
    }

    /// The receive journals of the Initial space as read, the first time
    /// they are asked for; `None` afterwards, and when the first flight was
    /// not read.
    pub fn take_initial_journals(&mut self) -> Option<ReceiveJournals<InstantOf<T>>> {
        self.journals.take()
    }

    /// The ACK obligation of the Initial space as read, the first time it
    /// is asked for; `None` afterwards, and when the first flight was not
    /// read.
    pub fn take_initial_ack_obligation(&mut self) -> Option<T::AckObligation> {
        self.ack.take()
    }

    /// The bytes received in the first datagrams read, the first time they
    /// are asked for; zero afterwards, and when the first flight was not
    /// read: datagrams not read yet are counted as they are received.
    pub fn take_received_bytes(&mut self) -> usize {
        mem::take(&mut self.received_bytes)
    }

    /// The first ClientHello read with the first flight, the first time it
    /// is asked for; `None` afterwards, and when it was not read.
    pub fn take_first_client_hello(&mut self) -> Option<FirstClientHello> {
        self.first.take()
    }
}

impl<T: Choices> fmt::Debug for FirstFlightStart<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FirstFlightStart")
            .field("datagrams", &self.datagrams.len())
            .field("held", &self.held.len())
            .field("journals", &self.journals.is_some())
            .field("ack", &self.ack.is_some())
            .field("received_bytes", &self.received_bytes)
            .field("first_client_hello", &self.first.is_some())
            .finish_non_exhaustive()
    }
}
