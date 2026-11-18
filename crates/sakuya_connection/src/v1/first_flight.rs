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
//!
//! [`read_first_flight`] is the reading outside the connection. It takes
//! the datagrams of the half connection's receiver one by one and receives
//! what a first flight carries with the same functions as the receiving
//! call of a logical path: an Initial packet is opened, checked, read frame
//! by frame and recorded; a 0-RTT packet is held until the handshake
//! decides on it. Between datagrams the handshake engine reads the first
//! ClientHello from the CRYPTO receiver, which is all it is lent.
//!
//! A server that may hand the connection off for passthrough forwarding
//! instead of accepting it asks the reading to keep a [`FirstFlightLayout`]
//! as well: the Initial packets are opened in place, so what was read is
//! what it takes to build them again, not the datagrams as they arrived.

use core::{
    convert::Infallible,
    fmt,
    future::poll_fn,
    mem,
    ops::Range,
    pin::{Pin, pin},
    task::Poll,
};

use bytes::Bytes;
use frunk_core::coproduct::CoproductTaker;
use nitori_call::{LentCall, Receiver};
use nitori_io::SplitTo;
use sakuya_datagram_routing::claim::delivery::DatagramDelivery;
use sakuya_link::{Link, MIN_DATAGRAM_SIZE, ReceivedDatagram};
use sakuya_packet_protection::initial::{INITIAL_AEAD, InitialSecrets};
use sakuya_recovery::{
    ack_obligation::AckObligation,
    receive_journals::{MaxAckRanges, ReceiveJournals},
};
use sakuya_stream::connection::ImmediateClose;
use sakuya_tls::{
    engine::{CryptoLevel, HandshakeError},
    message::MessageLimits,
    server::engine::{FirstClientHello, ReadFirstClientHello, ReadFirstClientHelloError},
};
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength},
    parts::CoprodInjector,
    v1::{
        encryption_level::EncryptionLevel,
        frame::{FrameRun, set::FrameSet},
        header::TypeFields,
        packet_number::{PacketNumber, PacketNumberLength},
        protected_packet::{IntoPacketsError, Packet, ProtectedPacket, into_packets},
    },
};
use snafu::Snafu;

use super::{
    Choices, Server, Side,
    crypto::{CryptoReceiveCapacities, CryptoReceiver},
    dispatch::immediate_close,
    error::{ConnectionError, V1ConnectionErrorOf},
    input::{HeldInput, LogicalPathDatagramReceiver, short_dcid_len},
    keys::{DirectionKeys, InitialKeys, LevelKeys},
    receive::{
        ReceivedPacket, open, owe_ack, packet_number_offset, read_frames, record_received,
        reserved_bits_set, v1_error,
    },
    streams::resets::StreamResetsOf,
};
use crate::v1::{AckObligationOf, CryptoReceiveBufferOf};
use crate::{
    clock::{ConnectionChoices, InstantOf},
    dispatch::FrameSetDispatch,
    error::{ConnectionErrorOf, ConnectionErrorsOf},
    share::LineagePartList,
};

/// A datagram as it arrived over the link `Lk`.
type DatagramOf<Lk> = ReceivedDatagram<<Lk as Link>::Payload, Lk>;

/// The handoff of the routing domain of the choices `T`.
type HandoffOf<T> = <<T as crate::v1::MakerChoices>::Receiver as LogicalPathDatagramReceiver<
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
    ) -> Option<CryptoReceiver<CryptoReceiveBufferOf<T>>> {
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

    /// What is left for the first logical path and the first entry, the
    /// first time it is asked for; nothing afterwards. The datagrams not
    /// read yet are cut with `dcid_len` as the length of a short header's
    /// Destination Connection ID. The first ClientHello stays, for the
    /// advancing call.
    pub(super) fn take_start(&mut self, dcid_len: ConnectionIdLength) -> FirstFlightStart<T> {
        match self {
            Self::Datagrams(datagrams) => FirstFlightStart {
                datagrams: mem::take(datagrams),
                ..FirstFlightStart::empty(dcid_len)
            },
            Self::Read(state) => {
                let mut start = mem::replace(&mut state.start, FirstFlightStart::empty(dcid_len));
                state.start.first = start.first.take();
                start
            }
        }
    }

    /// The first ClientHello read with the first flight, the first time it
    /// is asked for; `None` afterwards, and when it was not read.
    pub(super) fn take_first_client_hello(&mut self) -> Option<FirstClientHello> {
        match self {
            Self::Datagrams(_) => None,
            Self::Read(state) => state.start.first.take(),
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
    crypto: Option<CryptoReceiver<CryptoReceiveBufferOf<T>>>,
    keys: Option<InitialKeys<T::Crypto>>,
    start: FirstFlightStart<T>,
    max_ack_ranges: MaxAckRanges,
    max_held_inputs: usize,
    layout: Option<FirstFlightLayout>,
}

impl<T, Tls> FirstFlightReadState<T>
where
    T: Choices<Side = Server<Tls>>,
    Server<Tls>: Side,
{
    /// Nothing read yet from a first flight sent to `client_dcid`, the
    /// Destination Connection ID of the client's first Initial packet: the
    /// Initial keys derived from it with `crypto` (RFC 9001 §5.2), each
    /// level of `capacities` with an empty CRYPTO buffer, nothing received
    /// and nothing held. The receive journals keep at most
    /// `max_ack_ranges`; at most `max_held_inputs` 0-RTT packets are held,
    /// and later ones are dropped.
    pub fn new(
        crypto: &T::Crypto,
        client_dcid: &ConnectionId,
        capacities: &CryptoReceiveCapacities,
        max_ack_ranges: MaxAckRanges,
        max_held_inputs: usize,
    ) -> Self {
        let (send, receive) =
            <T::Side as Side>::split_initial_secrets(InitialSecrets::derive(crypto, client_dcid));
        Self {
            crypto: Some(CryptoReceiver::new(capacities)),
            keys: Some(InitialKeys::Live(Box::new(LevelKeys {
                send: DirectionKeys::derive(crypto, INITIAL_AEAD, &send),
                receive: DirectionKeys::derive(crypto, INITIAL_AEAD, &receive),
            }))),
            start: FirstFlightStart {
                journals: Some(ReceiveJournals::new()),
                // the Initial space acknowledges at once (RFC 9000 §13.2.1)
                ack: Some(<AckObligationOf<T>>::new(None)),
                ..FirstFlightStart::empty(client_dcid.length())
            },
            max_ack_ranges,
            max_held_inputs,
            layout: None,
        }
    }

    /// Makes the reading keep a layout of the first flight from now on,
    /// which [`layout`](Self::layout) gives.
    pub fn keep_layout(&mut self) {
        self.layout.get_or_insert_with(FirstFlightLayout::default);
    }
}

impl<T: Choices> FirstFlightReadState<T> {
    /// The first ClientHello, once it was read.
    pub fn first_client_hello(&self) -> Option<&FirstClientHello> {
        self.start.first.as_ref()
    }

    /// The bytes the datagrams read so far held in all.
    pub fn received_bytes(&self) -> usize {
        self.start.received_bytes
    }

    /// The layout of the first flight read so far; `None` when the reading
    /// was not asked to [keep one](Self::keep_layout).
    pub fn layout(&self) -> Option<&FirstFlightLayout> {
        self.layout.as_ref()
    }

    /// Ends the reading without making a connection of it, as a server that
    /// hands the connection off does: gives the first ClientHello once it
    /// was read, the 0-RTT packets held, in the order they arrived, and the
    /// layout when one was kept. The rest is dropped.
    ///
    /// It takes the state by value: a connection made from what is left
    /// would read the first ClientHello again from CRYPTO data already
    /// read.
    pub fn into_parts(
        self,
    ) -> (
        Option<FirstClientHello>,
        Vec<HeldInputOf<T>>,
        Option<FirstFlightLayout>,
    ) {
        (self.start.first, self.start.held, self.layout)
    }
}

impl<T: Choices> fmt::Debug for FirstFlightReadState<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FirstFlightReadState")
            .field("received_bytes", &self.start.received_bytes)
            .field("held", &self.start.held.len())
            .field("first_client_hello", &self.start.first.is_some())
            .field("layout", &self.layout.is_some())
            .finish_non_exhaustive()
    }
}

/// What reading a first flight kept of it, to build its packets again:
/// each datagram's size and, in order, the packets of it that were read.
///
/// An Initial packet that opened and was not a duplicate is kept as an
/// [`InitialPacketLayout`]; a 0-RTT packet that was held is kept as its
/// place among the held packets ([`FirstFlightReadState::into_parts`]).
/// Packets that did not open, were dropped or were not held are not kept.
/// The CRYPTO data the Initial packets carried is not kept either: it is
/// the first ClientHello, which the reading keeps.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FirstFlightLayout {
    token: Option<Bytes>,
    datagrams: Vec<DatagramLayout>,
}

impl FirstFlightLayout {
    /// The Token field of the first Initial packet that opened, which the
    /// client repeats in every Initial packet of the attempt (RFC 9000
    /// §17.2.2); `None` when none opened.
    pub fn token(&self) -> Option<&Bytes> {
        self.token.as_ref()
    }

    /// The datagrams read, in the order they arrived.
    pub fn datagrams(&self) -> &[DatagramLayout] {
        &self.datagrams
    }
}

/// One datagram of a [`FirstFlightLayout`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatagramLayout {
    size: usize,
    packets: Vec<PacketLayout>,
}

impl DatagramLayout {
    /// The size of the datagram as it arrived.
    pub fn size(&self) -> usize {
        self.size
    }

    /// The packets kept of it, in the order they were in it.
    pub fn packets(&self) -> &[PacketLayout] {
        &self.packets
    }
}

/// A packet of a [`DatagramLayout`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PacketLayout {
    /// An Initial packet.
    Initial(InitialPacketLayout),
    /// A 0-RTT packet: the one at this index among the packets held.
    ZeroRtt(usize),
}

/// An Initial packet of a [`DatagramLayout`]: what it takes, with the
/// connection IDs of the attempt, the token and the first ClientHello, to
/// build it again with the same packet number, the same size and the same
/// CRYPTO data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialPacketLayout {
    packet_number: PacketNumber,
    packet_number_length: PacketNumberLength,
    length: usize,
    crypto: Vec<Range<u64>>,
    ping: bool,
}

impl InitialPacketLayout {
    /// The packet number.
    pub fn packet_number(&self) -> PacketNumber {
        self.packet_number
    }

    /// The length of its Packet Number field.
    pub fn packet_number_length(&self) -> PacketNumberLength {
        self.packet_number_length
    }

    /// The length of the whole packet, from its first byte to the end of
    /// its AEAD tag.
    pub fn length(&self) -> usize {
        self.length
    }

    /// The ranges of the Initial CRYPTO stream its CRYPTO frames carried,
    /// in the order of the frames.
    pub fn crypto(&self) -> &[Range<u64>] {
        &self.crypto
    }

    /// Whether it carried a PING frame.
    pub fn ping(&self) -> bool {
        self.ping
    }
}

/// What a connection of the choices `T` was given from its first flight
/// for the parts of the tree built after the connection node, kept in the
/// connection node until they take it.
///
/// The first logical path takes the datagrams not read yet, the inputs
/// held, the receive journals and the ACK obligation of its Initial space,
/// and the handshake connection ID; the first entry takes the bytes
/// received. Each is there once, and only when the first flight was read
/// where the piece says so. The first ClientHello is not here: the
/// advancing call takes it from what the connection was made with when it
/// starts.
pub struct FirstFlightStart<T: Choices> {
    datagrams: Vec<DatagramOf<T::Link>>,
    dcid_len: ConnectionIdLength,
    held: Vec<HeldInputOf<T>>,
    journals: Option<ReceiveJournals<InstantOf<T>>>,
    ack: Option<AckObligationOf<T>>,
    received_bytes: usize,
    first: Option<FirstClientHello>,
    handshake_connection_id: Option<ConnectionId>,
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
            handshake_connection_id: None,
        }
    }

    /// The Source Connection ID of the first Initial packet read that
    /// opened, the client's handshake connection ID, the first time it is
    /// asked for; `None` afterwards, and when the first flight was not read
    /// or no Initial packet in it opened.
    pub fn take_handshake_connection_id(&mut self) -> Option<ConnectionId> {
        self.handshake_connection_id.take()
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
    pub fn take_initial_ack_obligation(&mut self) -> Option<AckObligationOf<T>> {
        self.ack.take()
    }

    /// The bytes received in the first datagrams read, the first time they
    /// are asked for; zero afterwards, and when the first flight was not
    /// read: datagrams not read yet are counted as they are received.
    pub fn take_received_bytes(&mut self) -> usize {
        mem::take(&mut self.received_bytes)
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

/// Read the datagrams `taken` from the half connection's receiver already,
/// then the datagrams that `receiver` delivers, into `state` until the
/// handshake engine has read the first ClientHello within `limits`; it goes
/// into `state` too. Nothing is sent. The datagrams of `taken` are cut as
/// routing delivered them, under the client's first Destination Connection
/// ID.
///
/// Each datagram counts toward the anti-amplification limit as a whole and
/// is cut into packets. An Initial packet is received as the receiving
/// call of a logical path receives it: dropped when it does not open, is a
/// duplicate or is in a datagram shorter than [`MIN_DATAGRAM_SIZE`] (RFC
/// 9000 §14.1); otherwise its frames are read and checked against the
/// packet type, its CRYPTO data goes into the CRYPTO receiver at Initial,
/// and it is recorded in the receive journals and the ACK obligation of the
/// Initial space. A 0-RTT packet is held. A Handshake or 1-RTT packet is
/// dropped: no keys for it can come before the connection is made. A
/// competing delivery is left to the other candidates: its first packet is
/// a long header, which takes the client's Source Connection ID to judge,
/// or a 1-RTT packet. Failures to open do not count toward the integrity
/// limit here. When `state` [keeps a layout](FirstFlightReadState::keep_layout),
/// each datagram read and the packets kept of it go into the layout.
///
/// The positions are found from the composition `L` as for
/// [`receive_packet`](super::receive::receive_packet): `Ie` of version 1's
/// error in the connection's error, `Hd` of what each part's dispatch
/// takes, and `Iv` of version 1's run among the runs of the frame set.
///
/// # Errors
///
/// [`ReadFirstFlightError`], as its variants document. The rest of the
/// datagram is not read; `state` holds what was read before.
pub async fn read_first_flight<T, L, Ie, Hd, Iv, Tls>(
    state: &mut FirstFlightReadState<T>,
    taken: impl IntoIterator<Item = DatagramOf<T::Link>>,
    receiver: &mut T::Receiver,
    limits: MessageLimits,
) -> Result<(), ReadFirstFlightError<ConnectionErrorOf<L>>>
where
    T: Choices<Side = Server<Tls>>,
    CryptoReceiveBufferOf<T>: Unpin,
    <T::Link as Link>::Payload: SplitTo + AsRef<[u8]> + AsMut<[u8]> + Into<Bytes>,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd> + StreamResetsOf,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Ie>,
    <L as FrameSet>::Run<Bytes>: CoproductTaker<FrameRun<Bytes>, Iv>,
{
    for datagram in taken {
        let dcid_len = state.start.dcid_len;
        receive_datagram::<T, L, Ie, Hd, Iv, Tls>(state, datagram, dcid_len)?;
    }
    let mut reading = pin!(
        LentCall::<CryptoReceiver<CryptoReceiveBufferOf<T>>, _>::new(ReadFirstClientHello::new(
            limits
        ))
    );
    poll_fn(|cx| {
        loop {
            // invariant: the CRYPTO receiver is taken only when the
            // connection is made from the state, which ends the reading
            let crypto = state
                .crypto
                .as_mut()
                .expect("the CRYPTO receiver is there until the connection is made");
            let mut view = pin!(Pin::new(crypto).view());
            if let Poll::Ready(read) = reading.as_mut().poll_return_with_views(view.as_mut(), cx) {
                return Poll::Ready(match read {
                    Ok(first) => {
                        state.start.first = Some(first);
                        Ok(())
                    }
                    Err(source) => Err(ReadFirstFlightError::ClientHello { source }),
                });
            }
            let Poll::Ready(delivery) = receiver.poll_next(cx) else {
                return Poll::Pending;
            };
            let (datagram, dcid_len) = match delivery {
                DatagramDelivery::Exclusive(delivery) => {
                    let (datagram, route) = delivery.consume();
                    (datagram.into_inner(), short_dcid_len(&route))
                }
                // dropping the candidate leaves the datagram to the others
                DatagramDelivery::Competing(_) => continue,
            };
            if let Err(error) = receive_datagram::<T, L, Ie, Hd, Iv, Tls>(state, datagram, dcid_len)
            {
                return Poll::Ready(Err(error));
            }
        }
    })
    .await
}

/// Receive `datagram` into `state`, as [`read_first_flight`] says, cutting
/// it with `dcid_len` as the length of a short header's Destination
/// Connection ID.
fn receive_datagram<T, L, Ie, Hd, Iv, Tls>(
    state: &mut FirstFlightReadState<T>,
    datagram: ReceivedDatagram<<T::Link as Link>::Payload, T::Link>,
    dcid_len: ConnectionIdLength,
) -> Result<(), ReadFirstFlightError<ConnectionErrorOf<L>>>
where
    T: Choices<Side = Server<Tls>>,
    <T::Link as Link>::Payload: SplitTo + AsRef<[u8]> + AsMut<[u8]> + Into<Bytes>,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd> + StreamResetsOf,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Ie>,
    <L as FrameSet>::Run<Bytes>: CoproductTaker<FrameRun<Bytes>, Iv>,
{
    let size = datagram.payload().as_ref().len();
    state.start.received_bytes = state.start.received_bytes.saturating_add(size);
    if let Some(layout) = state.layout.as_mut() {
        layout.datagrams.push(DatagramLayout {
            size,
            packets: Vec::new(),
        });
    }
    // a server takes no Initial packet from a datagram too short to have
    // carried a client's first flight (RFC 9000 §14.1)
    let initial_allowed = size >= MIN_DATAGRAM_SIZE;
    let (payload, arrival) = datagram.into_parts();
    for packet in into_packets(payload, dcid_len) {
        let packet = match packet {
            Ok(Packet::Protected(packet)) => packet,
            Ok(Packet::Retry(..) | Packet::VersionNegotiation(..)) => continue,
            Err(IntoPacketsError::DcidDiffersFromFirst) => continue,
            Err(IntoPacketsError::UnreadableBoundary { .. }) => break,
        };
        match packet.level() {
            EncryptionLevel::Initial if initial_allowed => {
                receive_initial::<T, L, Ie, Hd, Iv, _, Tls>(
                    state,
                    packet,
                    arrival.at(),
                    arrival.ecn(),
                )?;
            }
            EncryptionLevel::ZeroRtt => {
                if state.start.held.len() < state.max_held_inputs {
                    if let Some(datagram) = state
                        .layout
                        .as_mut()
                        .and_then(|layout| layout.datagrams.last_mut())
                    {
                        datagram
                            .packets
                            .push(PacketLayout::ZeroRtt(state.start.held.len()));
                    }
                    state.start.held.push(HeldInput::Packet(ReceivedPacket::new(
                        packet,
                        arrival.clone(),
                    )));
                }
            }
            EncryptionLevel::Initial | EncryptionLevel::Handshake | EncryptionLevel::OneRtt => {}
        }
    }
    Ok(())
}

/// Receive the Initial packet `packet`, arrived at `at` with `ecn`, into
/// `state`, as [`read_first_flight`] says.
fn receive_initial<T, L, Ie, Hd, Iv, P, Tls>(
    state: &mut FirstFlightReadState<T>,
    packet: ProtectedPacket<P>,
    at: InstantOf<T>,
    ecn: Option<sakuya_link::EcnCodepoint>,
) -> Result<(), ReadFirstFlightError<ConnectionErrorOf<L>>>
where
    T: Choices<Side = Server<Tls>>,
    P: AsMut<[u8]> + Into<Bytes>,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd> + StreamResetsOf,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Ie>,
    <L as FrameSet>::Run<Bytes>: CoproductTaker<FrameRun<Bytes>, Iv>,
{
    let level = EncryptionLevel::Initial;
    // invariant: the keys and the space's journals and obligation are
    // taken only when the connection is made from the state
    let Some(InitialKeys::Live(keys)) = state.keys.as_ref() else {
        unreachable!("the Initial keys are live until the connection is made")
    };
    let journals = state
        .start
        .journals
        .as_mut()
        .expect("the journals are there until the connection is made");
    let largest = journals.largest().map(|(number, _)| number);
    let Some(pn_offset) = packet_number_offset(&packet) else {
        return Ok(());
    };
    let ProtectedPacket::Initial(long, _) = &packet else {
        unreachable!("only Initial packets are received here")
    };
    let scid = *long.scid();
    let token = match long.fields() {
        TypeFields::Initial { token, .. } => token.clone(),
        TypeFields::ZeroRtt { .. } | TypeFields::Handshake { .. } | TypeFields::Retry { .. } => {
            unreachable!("an Initial packet's fields are an Initial's")
        }
    };
    let mut bytes = packet.into_bytes();
    let length = bytes.as_mut().len();
    // kept once, for the layout; the token is not protected, so it reads
    // the same before and after opening
    let token = state
        .layout
        .as_ref()
        .is_some_and(|layout| layout.token.is_none())
        .then(|| Bytes::copy_from_slice(&bytes.as_mut()[token]));
    let Ok(opened) = open(&keys.receive, bytes.as_mut(), pn_offset, largest) else {
        return Ok(());
    };
    // the first Initial packet that opens sets the connection ID the
    // server sends with (RFC 9000 §7.2)
    state.start.handshake_connection_id.get_or_insert(scid);
    if reserved_bits_set(level, opened.first_byte) {
        return Err(connection::<L, Ie>(ConnectionError::ReservedBitsSet {
            level,
        }));
    }
    let Some(admission) = journals.admit(opened.number) else {
        return Ok(());
    };
    let payload = bytes.into().slice(opened.payload);
    let crypto = state
        .crypto
        .as_mut()
        .expect("the CRYPTO receiver is there until the connection is made");
    let mut closed = None;
    let mut crypto_ranges = Vec::new();
    let mut ping = false;
    let packet_facts = read_frames::<T, L, Ie, Hd, _>(
        payload,
        level,
        |source| ReadFirstFlightError::Connection { source },
        |_, run| {
            let Some(run) = run.take() else {
                return Err(ReadFirstFlightError::ExtensionFrame);
            };
            match run {
                FrameRun::Padding(_) => Ok(()),
                FrameRun::Ping(_) => {
                    ping = true;
                    Ok(())
                }
                FrameRun::Crypto(frame) => {
                    let offset = frame.offset().into_inner();
                    let start = u64::from(offset);
                    // the frame read, its end is within the stream's
                    // limit of 2^62 (RFC 9000 §19.6)
                    crypto_ranges.push(start..start + frame.data().len() as u64);
                    crypto
                        .receive_frame(CryptoLevel::Initial, offset, frame.into_data())
                        .map_err(|source| connection::<L, Ie>(ConnectionError::Crypto { source }))
                }
                FrameRun::ConnectionClose(frame) => {
                    closed.get_or_insert(immediate_close(frame));
                    Ok(())
                }
                other => Err(connection::<L, Ie>(ConnectionError::UnhandledFrame {
                    kind: other.frame_type(),
                })),
            }
        },
    )?;
    if let Some(close) = closed {
        return Err(ReadFirstFlightError::PeerClosed { close });
    }
    if let Some(layout) = state.layout.as_mut() {
        if let Some(token) = token {
            layout.token.get_or_insert(token);
        }
        if let Some(datagram) = layout.datagrams.last_mut() {
            datagram
                .packets
                .push(PacketLayout::Initial(InitialPacketLayout {
                    packet_number: opened.number,
                    packet_number_length: PacketNumberLength::from_first_byte(opened.first_byte),
                    length,
                    crypto: crypto_ranges,
                    ping,
                }));
        }
    }
    let number = admission.number();
    // invariant: as the journals
    let journals = state
        .start
        .journals
        .as_mut()
        .expect("the journals are there until the connection is made");
    let (_, run_below) = record_received(journals, admission, at, ecn, state.max_ack_ranges);
    let obligation = state
        .start
        .ack
        .as_mut()
        .expect("the ACK obligation is there until the connection is made");
    owe_ack(obligation, number, at, ecn, &packet_facts, run_below);
    Ok(())
}

/// Version 1's `error` as a failure of reading the first flight of the
/// composition `L`.
fn connection<L, Ie>(error: V1ConnectionErrorOf<L>) -> ReadFirstFlightError<ConnectionErrorOf<L>>
where
    L: ConnectionErrorsOf,
    L::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Ie>,
{
    ReadFirstFlightError::Connection {
        source: v1_error::<L, Ie>(error),
    }
}

/// A failure of reading the first flight before deciding; `E` is the
/// connection's error.
///
/// None of them is sent: the half connection the reading belongs to
/// answers or stays silent as its owner decides.
#[derive(Debug, Snafu)]
pub enum ReadFirstFlightError<E> {
    /// A packet causes a connection error, as it would in the connection:
    /// reserved bits set, a frame that does not read or is not permitted in
    /// an Initial packet (RFC 9000 §12.4), no frames, CRYPTO data beyond the
    /// buffer (§7.5), or a frame whose handling is not here yet.
    #[snafu(display("a packet of the first flight causes a connection error"))]
    Connection {
        /// The connection error.
        source: E,
    },
    /// The client closed the connection with a CONNECTION_CLOSE frame in an
    /// Initial packet.
    #[snafu(display("the client closed the connection"))]
    PeerClosed {
        /// The client's close.
        close: ImmediateClose,
    },
    /// An Initial packet carries a frame of an extension, which the first
    /// flight is read without; it is permitted there only if the extension
    /// says so, as none of this crate's do.
    #[snafu(display("an Initial packet carries a frame of an extension"))]
    ExtensionFrame,
    /// The first ClientHello could not be read, or its legacy_session_id is
    /// not empty (RFC 9001 §8.4).
    #[snafu(display("the first ClientHello could not be read"))]
    ClientHello {
        /// The failure.
        source: HandshakeError<ReadFirstClientHelloError, Infallible>,
    },
}
