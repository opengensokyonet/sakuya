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

use core::{
    convert::Infallible,
    fmt,
    future::poll_fn,
    mem,
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
        protected_packet::{IntoPacketsError, Packet, ProtectedPacket, into_packets},
    },
};
use snafu::Snafu;

use super::{
    Choices, Server, Side,
    crypto::{CryptoReceiveCapacities, CryptoReceiver},
    dispatch::immediate_close,
    error::ConnectionError,
    input::{HeldInput, LogicalPathDatagramReceiver, short_dcid_len},
    keys::{DirectionKeys, InitialKeys, LevelKeys},
    receive::{
        ReceivedPacket, open, owe_ack, packet_number_offset, read_frames, record_received,
        reserved_bits_set, v1_error,
    },
};
use crate::{
    clock::{ConnectionChoices, InstantOf},
    dispatch::FrameSetDispatch,
    error::{ConnectionErrorOf, ConnectionErrorsOf},
    share::LineagePartList,
};

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
    max_ack_ranges: MaxAckRanges,
    max_held_inputs: usize,
}

impl<T: Choices<Side = Server>> FirstFlightReadState<T> {
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
            max_ack_ranges,
            max_held_inputs,
        }
    }

    /// The first ClientHello, once it was read.
    pub fn first_client_hello(&self) -> Option<&FirstClientHello> {
        self.start.first.as_ref()
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

/// Read the first datagrams that `receiver` delivers into `state` until the
/// handshake engine has read the first ClientHello within `limits`; it goes
/// into `state` too. Nothing is sent.
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
/// limit here.
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
pub async fn read_first_flight<T, L, Ie, Hd, Iv>(
    state: &mut FirstFlightReadState<T>,
    receiver: &mut T::Receiver,
    limits: MessageLimits,
) -> Result<(), ReadFirstFlightError<ConnectionErrorOf<L>>>
where
    T: Choices<Side = Server>,
    T::CryptoReceiveBuffer: Unpin,
    <T::Link as Link>::Payload: SplitTo + AsRef<[u8]> + AsMut<[u8]> + Into<Bytes>,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd>,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Ie>,
    <L as FrameSet>::Run<Bytes>: CoproductTaker<FrameRun<Bytes>, Iv>,
{
    let mut reading = pin!(LentCall::<CryptoReceiver<T::CryptoReceiveBuffer>, _>::new(
        ReadFirstClientHello::new(limits)
    ));
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
            if let Err(error) = receive_datagram::<T, L, Ie, Hd, Iv>(state, datagram, dcid_len) {
                return Poll::Ready(Err(error));
            }
        }
    })
    .await
}

/// Receive `datagram` into `state`, as [`read_first_flight`] says, cutting
/// it with `dcid_len` as the length of a short header's Destination
/// Connection ID.
fn receive_datagram<T, L, Ie, Hd, Iv>(
    state: &mut FirstFlightReadState<T>,
    datagram: ReceivedDatagram<<T::Link as Link>::Payload, T::Link>,
    dcid_len: ConnectionIdLength,
) -> Result<(), ReadFirstFlightError<ConnectionErrorOf<L>>>
where
    T: Choices<Side = Server>,
    <T::Link as Link>::Payload: SplitTo + AsRef<[u8]> + AsMut<[u8]> + Into<Bytes>,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd>,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Ie>,
    <L as FrameSet>::Run<Bytes>: CoproductTaker<FrameRun<Bytes>, Iv>,
{
    let size = datagram.payload().as_ref().len();
    state.start.received_bytes = state.start.received_bytes.saturating_add(size);
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
                receive_initial::<T, L, Ie, Hd, Iv, _>(state, packet, arrival.at(), arrival.ecn())?;
            }
            EncryptionLevel::ZeroRtt => {
                if state.start.held.len() < state.max_held_inputs {
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
fn receive_initial<T, L, Ie, Hd, Iv, P>(
    state: &mut FirstFlightReadState<T>,
    packet: ProtectedPacket<P>,
    at: InstantOf<T>,
    ecn: Option<sakuya_link::EcnCodepoint>,
) -> Result<(), ReadFirstFlightError<ConnectionErrorOf<L>>>
where
    T: Choices<Side = Server>,
    P: AsMut<[u8]> + Into<Bytes>,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd>,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Ie>,
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
    let mut bytes = packet.into_bytes();
    let Ok(opened) = open(&keys.receive, bytes.as_mut(), pn_offset, largest) else {
        return Ok(());
    };
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
    let packet_facts = read_frames::<T, L, Ie, Hd, _>(
        payload,
        level,
        |source| ReadFirstFlightError::Connection { source },
        |_, run| {
            let Some(run) = run.take() else {
                return Err(ReadFirstFlightError::ExtensionFrame);
            };
            match run {
                FrameRun::Padding(_) | FrameRun::Ping(_) => Ok(()),
                FrameRun::Crypto(frame) => {
                    let offset = frame.offset().into_inner();
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
fn connection<L, Ie>(error: ConnectionError) -> ReadFirstFlightError<ConnectionErrorOf<L>>
where
    L: ConnectionErrorsOf,
    L::ConnectionErrors: CoprodInjector<ConnectionError, Ie>,
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
