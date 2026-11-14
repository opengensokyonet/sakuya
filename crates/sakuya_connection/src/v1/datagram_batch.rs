//! The datagrams a link path's sending call has sealed and not yet handed
//! to the link, and the writer of the one being filled.
//!
//! A [`DatagramBatch`] keeps every sealed datagram twice over, in two lists
//! of the same order: the [`OutgoingDatagram`]s the link is handed, whose
//! payload is the datagram's bytes, and one entry ([`BatchedDatagram`])
//! with its size and the sealed packet of each packet number space it
//! carries ([`BatchedPacket`]). Each entry is settled once: taken out when
//! the link accepts it, when it is given up, or when it carries a level
//! whose keys were discarded before it was handed over.
//!
//! A [`DatagramWriter`] writes one datagram into the batch's buffer, one
//! packet after the other ([`PacketWriter`]). It knows the datagram's
//! floor, which follows from what it carries (RFC 9000 §14.1, §8.2.1,
//! §8.2.2), and the last packet is padded to it. Dropped with a packet
//! sealed, it charges the end of the datagram once: each packet that counts
//! in flight to the link path's congestion controller, which gives what it
//! keeps for the packet; the bytes in flight, the probe permit and pacing
//! to the link path's congestion state; the whole datagram to the
//! anti-amplification limit; the use of its connection ID. Then its bytes
//! leave the buffer as the payload of an outgoing datagram, marked Not-ECT,
//! and the datagram joins the batch. Dropped empty, nothing happened.
//! Dropped while a panic unwinds, it does nothing at all.

use core::{fmt, num::NonZeroUsize};

use bytes::{Bytes, BytesMut};
use sakuya_link::{EcnMarking, OutgoingDatagram};
use sakuya_packet_protection::{backend::CryptoBackend, packet_number::EncodePacketNumberError};
use sakuya_recovery::{
    congestion::CongestionController, loss_detection::InFlightCharge, pacing::Pacer,
    packet_number_space::PacketNumberSpaceKind, send_journals::PacketSendAttempt,
};
use sakuya_wire::{
    connection_id::ConnectionId,
    v1::{packet_number::PacketNumber, role::Role},
};

use super::{
    aead_usage::AeadUsage,
    amplification::AntiAmplification,
    keys::{DirectionKeys, OneRttSendKeys},
    packet_writer::{PacketStart, PacketWriter},
    recovery::LinkPathCongestionState,
};
use crate::write::PaddingSummary;

/// The destination connection ID one datagram is written with: every
/// packet of the datagram carries it (RFC 9000 §12.2). It is told how many
/// bytes it was used for once the datagram is sealed; a datagram that
/// stays empty never uses it.
///
/// The connection's implementation is
/// [`DatagramConnectionId`](crate::connection_id::datagram::DatagramConnectionId),
/// which tells the destination connection ID strategy that chose it.
pub trait ConnectionIdUse {
    /// The connection ID.
    fn connection_id(&self) -> ConnectionId;

    /// A datagram of `datagram_len` bytes was sealed with it.
    fn used(self, datagram_len: usize);
}

/// One sealed packet waiting in a [`DatagramBatch`]: the send journals'
/// sealed packet `S` and, for a packet that counts in flight, what it was
/// charged with when it was sealed, with what the congestion controller
/// gave for it (`C`). The link's acceptance hands both on together.
#[derive(Debug, PartialEq, Eq)]
pub struct BatchedPacket<S, C> {
    /// The sealed packet, to hand back to its send journals.
    pub sealed: S,
    /// What the packet counts in flight; `None` for a packet with only ACK
    /// frames.
    pub in_flight: Option<InFlightCharge<C>>,
}

/// One sealed datagram waiting in a [`DatagramBatch`]: its size and the
/// sealed packet of each packet number space it carries.
///
/// `Si`, `Sh` and `Sa` are the sealed packets of the send journals of the
/// Initial, Handshake and application data spaces; `C` is what the
/// congestion controller keeps for each packet in flight.
#[derive(Debug, PartialEq, Eq)]
pub struct BatchedDatagram<Si, Sh, Sa, C> {
    len: usize,
    initial_goes_out: bool,
    /// The sealed Initial packet.
    pub initial: Option<BatchedPacket<Si, C>>,
    /// The sealed Handshake packet.
    pub handshake: Option<BatchedPacket<Sh, C>>,
    /// The sealed 0-RTT or 1-RTT packet.
    pub application_data: Option<BatchedPacket<Sa, C>>,
}

impl<Si, Sh, Sa, C> BatchedDatagram<Si, Sh, Sa, C> {
    /// The size of the datagram in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the datagram is empty; a batched datagram never is.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether its Initial packet goes out although the Initial keys are
    /// discarded: this side discarded them when it sealed its first
    /// Handshake packet, in this datagram or in a later one (RFC 9001
    /// §4.9.1).
    pub fn initial_goes_out(&self) -> bool {
        self.initial_goes_out
    }
}

/// The datagrams a link path has sealed, waiting to be handed to its
/// link, at most a given number of them.
///
/// The datagram being written lies in one buffer; once it is sealed, its
/// bytes leave the buffer as the payload of its outgoing datagram.
#[derive(Debug)]
pub struct DatagramBatch<Si, Sh, Sa, C> {
    buffer: BytesMut,
    outgoing: Vec<OutgoingDatagram>,
    datagrams: Vec<BatchedDatagram<Si, Sh, Sa, C>>,
    max_datagrams: NonZeroUsize,
}

impl<Si, Sh, Sa, C> DatagramBatch<Si, Sh, Sa, C> {
    /// An empty batch of at most `max_datagrams` datagrams.
    pub fn new(max_datagrams: NonZeroUsize) -> Self {
        Self {
            buffer: BytesMut::new(),
            outgoing: Vec::with_capacity(max_datagrams.get()),
            datagrams: Vec::with_capacity(max_datagrams.get()),
            max_datagrams,
        }
    }

    /// How many datagrams the batch holds at most.
    pub fn max_datagrams(&self) -> NonZeroUsize {
        self.max_datagrams
    }

    /// How many datagrams wait in the batch.
    pub fn len(&self) -> usize {
        self.datagrams.len()
    }

    /// Whether no datagram waits.
    pub fn is_empty(&self) -> bool {
        self.datagrams.is_empty()
    }

    /// Whether the batch holds as many datagrams as it may: the filling
    /// stops.
    pub fn is_full(&self) -> bool {
        self.datagrams.len() >= self.max_datagrams.get()
    }

    /// The waiting datagrams as the link is handed them, in order.
    pub fn outgoing(&self) -> &[OutgoingDatagram] {
        &self.outgoing
    }

    /// The bytes of each waiting datagram, in order.
    pub fn datagrams(&self) -> impl Iterator<Item = &[u8]> {
        self.outgoing.iter().map(|datagram| &datagram.payload[..])
    }

    /// The entries of the waiting datagrams, in order.
    pub fn entries(&self) -> impl Iterator<Item = &BatchedDatagram<Si, Sh, Sa, C>> {
        self.datagrams.iter()
    }

    /// Take out the first `count` datagrams, or all if fewer wait: the
    /// link accepted them.
    pub fn take_accepted(
        &mut self,
        count: usize,
    ) -> impl Iterator<Item = BatchedDatagram<Si, Sh, Sa, C>> + '_ {
        let count = count.min(self.datagrams.len());
        self.outgoing.drain(..count);
        self.datagrams.drain(..count)
    }

    /// Take out the first datagram, if any: the link gave it up.
    pub fn take_first(&mut self) -> Option<BatchedDatagram<Si, Sh, Sa, C>> {
        if self.datagrams.is_empty() {
            return None;
        }
        self.outgoing.remove(0);
        Some(self.datagrams.remove(0))
    }

    /// Take out the datagrams `discarded` picks, keeping the others in
    /// order: those carrying a packet of a level whose keys were discarded
    /// before the batch was handed to the link.
    pub fn take_discarded(
        &mut self,
        mut discarded: impl FnMut(&BatchedDatagram<Si, Sh, Sa, C>) -> bool,
    ) -> std::vec::IntoIter<BatchedDatagram<Si, Sh, Sa, C>> {
        let mut taken = Vec::new();
        let mut index = 0;
        while index < self.datagrams.len() {
            if discarded(&self.datagrams[index]) {
                self.outgoing.remove(index);
                taken.push(self.datagrams.remove(index));
            } else {
                index += 1;
            }
        }
        taken.into_iter()
    }

    /// Start writing a datagram at `now` with `cid`, sent by a side of
    /// `role`, of at most `max_len` bytes, of which packets that count in
    /// flight take at most `in_flight_room`; `probe` when it may go past
    /// the congestion window on a permit of `congestion`, which it uses if
    /// it carries anything that counts in flight. When it is sealed it is
    /// charged to `congestion`, `controller` and `anti_amplification`.
    #[allow(clippy::too_many_arguments)]
    pub fn start_datagram<'b, U, K, I>(
        &'b mut self,
        now: I,
        cid: U,
        role: Role,
        max_len: usize,
        in_flight_room: usize,
        probe: bool,
        congestion: &'b mut LinkPathCongestionState<I>,
        controller: &'b mut K,
        anti_amplification: &'b mut AntiAmplification,
    ) -> DatagramWriter<'b, Si, Sh, Sa, U, K, I>
    where
        U: ConnectionIdUse,
        K: CongestionController<I, SentState = C> + Pacer<I>,
        I: Copy,
    {
        // the buffer holds the datagram being written only: a sealed one
        // leaves it, and an empty one took its bytes back
        self.buffer.clear();
        let state = DatagramState {
            dcid: cid.connection_id(),
            role,
            start: self.buffer.len(),
            max_len,
            in_flight_room,
            in_flight: 0,
            floor: 0,
            packets: 0,
            ends_with_short_header: false,
        };
        DatagramWriter {
            buffer: &mut self.buffer,
            outgoing: &mut self.outgoing,
            datagrams: &mut self.datagrams,
            state,
            initial: None,
            handshake: None,
            application_data: None,
            initial_goes_out: false,
            cid: Some(cid),
            now,
            probe,
            congestion,
            controller,
            anti_amplification,
        }
    }
}

/// A packet sealed in the datagram being written: the send journals'
/// sealed packet, and its size if it counts in flight.
#[derive(Debug)]
pub(super) struct SealedInDatagram<S> {
    pub(super) sealed: S,
    pub(super) in_flight: Option<usize>,
}

/// What a datagram being written knows of itself; its packet writers read
/// and change it.
#[derive(Debug)]
pub(super) struct DatagramState {
    /// The destination connection ID of every packet.
    pub(super) dcid: ConnectionId,
    /// The side that sends it.
    pub(super) role: Role,
    /// Where it starts in the buffer.
    pub(super) start: usize,
    /// Its largest size.
    pub(super) max_len: usize,
    /// The most its packets that count in flight may take.
    pub(super) in_flight_room: usize,
    /// The bytes of its sealed packets that count in flight.
    pub(super) in_flight: usize,
    /// The size its last packet pads it to.
    pub(super) floor: usize,
    /// How many packets are sealed in it.
    pub(super) packets: usize,
    /// Whether a packet with a short header is sealed in it: it is the
    /// last (RFC 9000 §12.2).
    pub(super) ends_with_short_header: bool,
}

impl DatagramState {
    /// The floor rises to `floor`, as far as the datagram can grow.
    pub(super) fn raise_floor(&mut self, floor: usize) {
        self.floor = self.floor.max(floor.min(self.max_len));
    }
}

/// One datagram being written into a [`DatagramBatch`].
///
/// `U` is its connection ID, `C` the congestion controller and pacer of
/// the link path, `I` the type of instants.
pub struct DatagramWriter<'b, Si, Sh, Sa, U, C, I>
where
    U: ConnectionIdUse,
    C: CongestionController<I> + Pacer<I>,
    I: Copy,
{
    buffer: &'b mut BytesMut,
    outgoing: &'b mut Vec<OutgoingDatagram>,
    datagrams: &'b mut Vec<BatchedDatagram<Si, Sh, Sa, C::SentState>>,
    state: DatagramState,
    initial: Option<SealedInDatagram<Si>>,
    handshake: Option<SealedInDatagram<Sh>>,
    application_data: Option<SealedInDatagram<Sa>>,
    initial_goes_out: bool,
    /// Kept until the datagram is sealed.
    cid: Option<U>,
    now: I,
    probe: bool,
    congestion: &'b mut LinkPathCongestionState<I>,
    controller: &'b mut C,
    anti_amplification: &'b mut AntiAmplification,
}

impl<Si, Sh, Sa, U, C, I> fmt::Debug for DatagramWriter<'_, Si, Sh, Sa, U, C, I>
where
    U: ConnectionIdUse,
    C: CongestionController<I> + Pacer<I>,
    I: Copy,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramWriter")
            .field("state", &self.state)
            .field("probe", &self.probe)
            .finish_non_exhaustive()
    }
}

impl<Si, Sh, Sa, U, C, I> DatagramWriter<'_, Si, Sh, Sa, U, C, I>
where
    U: ConnectionIdUse,
    C: CongestionController<I> + Pacer<I>,
    I: Copy,
{
    /// The bytes written so far.
    pub fn len(&self) -> usize {
        self.buffer.len() - self.state.start
    }

    /// Whether no packet is sealed in the datagram.
    pub fn is_empty(&self) -> bool {
        self.state.packets == 0
    }

    /// The size the last packet pads the datagram to, so far.
    pub fn floor(&self) -> usize {
        self.state.floor
    }

    /// Whether a packet of `space` is sealed in the datagram.
    pub fn carries(&self, space: PacketNumberSpaceKind) -> bool {
        match space {
            PacketNumberSpaceKind::Initial => self.initial.is_some(),
            PacketNumberSpaceKind::Handshake => self.handshake.is_some(),
            PacketNumberSpaceKind::ApplicationData => self.application_data.is_some(),
        }
    }

    /// This side discarded its Initial keys as it sealed its first
    /// Handshake packet, in this datagram (RFC 9001 §4.9.1): the Initial
    /// packets sealed before, in this datagram and in those already in the
    /// batch, still go out.
    pub fn keep_initial_packets(&mut self) {
        self.initial_goes_out = true;
        for datagram in self.datagrams.iter_mut() {
            datagram.initial_goes_out = true;
        }
    }

    /// Start an Initial packet with `attempt`, protected with `keys`, its
    /// packet number encoded against `largest_acked`, with the source
    /// connection ID `scid` and `token`.
    ///
    /// # Errors
    ///
    /// The packet number cannot be encoded against `largest_acked`.
    ///
    /// # Panics
    ///
    /// The datagram already has an Initial packet, or a packet with a short
    /// header: the filling writes one packet of each space, the short one
    /// last.
    pub fn start_initial_packet<'d, A, B>(
        &'d mut self,
        attempt: A,
        keys: &'d DirectionKeys<B>,
        largest_acked: Option<PacketNumber>,
        scid: ConnectionId,
        token: Bytes,
    ) -> Result<PacketWriter<'d, A, B>, EncodePacketNumberError>
    where
        A: PacketSendAttempt<Sealed = Si>,
        A::Summary: From<PaddingSummary>,
        B: CryptoBackend,
    {
        open_slot(&self.state, &self.initial);
        PacketWriter::start(
            &mut *self.buffer,
            &mut self.state,
            &mut self.initial,
            attempt,
            PacketStart::Initial { keys, scid, token },
            largest_acked,
        )
    }

    /// Start a Handshake packet, as
    /// [`start_initial_packet`](Self::start_initial_packet) does.
    ///
    /// # Errors
    ///
    /// The packet number cannot be encoded against `largest_acked`.
    ///
    /// # Panics
    ///
    /// The datagram already has a Handshake packet, or a packet with a
    /// short header.
    pub fn start_handshake_packet<'d, A, B>(
        &'d mut self,
        attempt: A,
        keys: &'d DirectionKeys<B>,
        largest_acked: Option<PacketNumber>,
        scid: ConnectionId,
    ) -> Result<PacketWriter<'d, A, B>, EncodePacketNumberError>
    where
        A: PacketSendAttempt<Sealed = Sh>,
        A::Summary: From<PaddingSummary>,
        B: CryptoBackend,
    {
        open_slot(&self.state, &self.handshake);
        PacketWriter::start(
            &mut *self.buffer,
            &mut self.state,
            &mut self.handshake,
            attempt,
            PacketStart::Handshake { keys, scid },
            largest_acked,
        )
    }

    /// Start a 0-RTT packet, as
    /// [`start_initial_packet`](Self::start_initial_packet) does.
    ///
    /// # Errors
    ///
    /// The packet number cannot be encoded against `largest_acked`.
    ///
    /// # Panics
    ///
    /// The datagram already has a 0-RTT or 1-RTT packet.
    pub fn start_zero_rtt_packet<'d, A, B>(
        &'d mut self,
        attempt: A,
        keys: &'d DirectionKeys<B>,
        largest_acked: Option<PacketNumber>,
        scid: ConnectionId,
    ) -> Result<PacketWriter<'d, A, B>, EncodePacketNumberError>
    where
        A: PacketSendAttempt<Sealed = Sa>,
        A::Summary: From<PaddingSummary>,
        B: CryptoBackend,
    {
        open_slot(&self.state, &self.application_data);
        PacketWriter::start(
            &mut *self.buffer,
            &mut self.state,
            &mut self.application_data,
            attempt,
            PacketStart::ZeroRtt { keys, scid },
            largest_acked,
        )
    }

    /// Start a 1-RTT packet with `attempt`, protected with the current
    /// sending generation of `keys`, whose use is counted in `usage`, its
    /// packet number encoded against `largest_acked`. It has a short header:
    /// no packet follows it in the datagram.
    ///
    /// # Errors
    ///
    /// The packet number cannot be encoded against `largest_acked`.
    ///
    /// # Panics
    ///
    /// The datagram already has a 0-RTT or 1-RTT packet.
    pub fn start_one_rtt_packet<'d, A, B>(
        &'d mut self,
        attempt: A,
        keys: &'d OneRttSendKeys<B>,
        usage: &'d mut AeadUsage,
        largest_acked: Option<PacketNumber>,
    ) -> Result<PacketWriter<'d, A, B>, EncodePacketNumberError>
    where
        A: PacketSendAttempt<Sealed = Sa>,
        A::Summary: From<PaddingSummary>,
        B: CryptoBackend,
    {
        open_slot(&self.state, &self.application_data);
        PacketWriter::start(
            &mut *self.buffer,
            &mut self.state,
            &mut self.application_data,
            attempt,
            PacketStart::OneRtt { keys, usage },
            largest_acked,
        )
    }
}

/// Check that a packet can start in `slot` of the datagram of `state`.
fn open_slot<S>(state: &DatagramState, slot: &Option<S>) {
    assert!(
        slot.is_none(),
        "a datagram carries at most one packet of each packet number space"
    );
    assert!(
        !state.ends_with_short_header,
        "a packet with a short header is the last of its datagram"
    );
}

impl<Si, Sh, Sa, U, C, I> Drop for DatagramWriter<'_, Si, Sh, Sa, U, C, I>
where
    U: ConnectionIdUse,
    C: CongestionController<I> + Pacer<I>,
    I: Copy,
{
    fn drop(&mut self) {
        // a panic ends the whole connection: nothing is charged or batched
        if std::thread::panicking() || self.state.packets == 0 {
            return;
        }
        let len = self.len();
        let app_limited = self.congestion.app_limited();
        let (controller, now) = (&mut *self.controller, self.now);
        let mut charge = |bytes: usize| InFlightCharge {
            bytes,
            app_limited,
            sent_state: controller.on_packet_sealed(bytes, app_limited, now),
        };
        let initial = self.initial.take().map(|packet| BatchedPacket {
            sealed: packet.sealed,
            in_flight: packet.in_flight.map(&mut charge),
        });
        let handshake = self.handshake.take().map(|packet| BatchedPacket {
            sealed: packet.sealed,
            in_flight: packet.in_flight.map(&mut charge),
        });
        let application_data = self.application_data.take().map(|packet| BatchedPacket {
            sealed: packet.sealed,
            in_flight: packet.in_flight.map(&mut charge),
        });
        // a permit is used only by a datagram that needed it to go past the
        // window
        let probe = self.probe && self.state.in_flight > 0;
        self.congestion
            .on_datagram_sealed(self.controller, self.state.in_flight, probe);
        self.anti_amplification.sent(len);
        if let Some(cid) = self.cid.take() {
            cid.used(len);
        }
        self.outgoing.push(OutgoingDatagram {
            payload: self.buffer.split_to(len).freeze(),
            ecn: EcnMarking::NotEct,
        });
        self.datagrams.push(BatchedDatagram {
            len,
            initial_goes_out: self.initial_goes_out,
            initial,
            handshake,
            application_data,
        });
    }
}

#[cfg(test)]
mod tests;
