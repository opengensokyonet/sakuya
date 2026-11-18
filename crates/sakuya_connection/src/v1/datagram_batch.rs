//! The datagrams a link path's sending call has sealed and not yet handed
//! to the link, and the writer of the one being filled.
//!
//! A [`DatagramBatch`] keeps every sealed datagram twice over, in two lists
//! of the same order: the [`OutgoingDatagram`]s the link is handed, whose
//! payload is the datagram's bytes, and one entry ([`BatchedDatagram`])
//! with its size and the sealed packet of each packet number space it
//! carries ([`BatchedPacket`]). Each entry is settled once: taken out when
//! the link accepts it, when it is given up, or when it carries a level
//! whose keys were discarded before it was handed over. A close packet
//! sent again is an entry without packets: settling it touches nothing.
//!
//! A [`DatagramWriter`] writes one datagram into the batch's buffer, one
//! packet after the other ([`PacketWriter`]), every packet with the one
//! destination connection ID it was started with (RFC 9000 §12.2). It
//! knows the datagram's floor, which follows from what it carries (RFC 9000
//! §14.1, §8.2.1, §8.2.2), and the last packet is padded to it. Finished
//! ([`DatagramWriter::finish`]) or dropped with a packet sealed, it charges
//! the end of the datagram once: each packet that counts in flight to the
//! link path's congestion controller, which gives what it keeps for the
//! packet; the bytes in flight, the probe permit and pacing to the link
//! path's congestion state; the whole datagram to the anti-amplification
//! limit. Then its bytes leave the buffer as the payload of an outgoing
//! datagram, marked Not-ECT, and the datagram joins the batch; finishing
//! gives the datagram's size, for the use of its connection ID. Finished or
//! dropped empty, nothing happened. Dropped while a panic unwinds, it does
//! nothing at all.
//!
//! A candidate without a recovery layer writes uncharged datagrams
//! ([`DatagramBatch::start_uncharged_datagram`]): their packets count in no
//! congestion control and nothing in flight (RFC 9000 §9.4), and only the
//! anti-amplification limit is charged; [`UnchargedCongestion`] stands in
//! for the controller they are charged to none of.

use core::{fmt, marker::PhantomData, num::NonZeroUsize};

use bytes::{Bytes, BytesMut};
use sakuya_link::{EcnMarking, OutgoingDatagram};
use sakuya_packet_protection::{backend::CryptoBackend, packet_number::EncodePacketNumberError};
use sakuya_recovery::{
    congestion::{
        CongestionContext, CongestionController, InFlightPacket, RemovedPacket, SealedPacket,
        SpuriouslyLostPacket,
    },
    loss_detection::InFlightCharge,
    pacing::{Pacer, PacingInput},
    packet_number_space::PacketNumberSpaceKind,
    send_journals::PacketSendAttempt,
};
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength},
    v1::{packet_number::PacketNumber, role::Role},
};

use super::{
    aead_usage::AeadUsage,
    amplification::AntiAmplification,
    events::SealObserver,
    keys::{DirectionKeys, OneRttSendKeys},
    packet_writer::{PacketStart, PacketWriter},
    recovery::LinkPathCongestionState,
};
use crate::{feedback::InjectSummary, write::PaddingSummary};

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
///
/// A batch holds no memory until its first datagram starts. The first
/// datagram of a round asks for room for itself, in the buffer and in both
/// lists; the second asks at once for room for every datagram the round may
/// still take. Once the link
/// accepts the whole batch, the round ends and the batch lets its memory
/// go: an idle link path keeps none.
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
            outgoing: Vec::new(),
            datagrams: Vec::new(),
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

    /// Add `payload`, the datagram of a sealed close packet sent again, at
    /// the end: it carries no packet of the send journals and counts
    /// nothing in flight, and what it was charged with is the caller's.
    ///
    /// The batch must not be full.
    pub fn push_close_packet(&mut self, payload: Bytes) {
        debug_assert!(!self.is_full(), "a full batch takes no more datagrams");
        self.datagrams.push(BatchedDatagram {
            len: payload.len(),
            initial_goes_out: false,
            initial: None,
            handshake: None,
            application_data: None,
        });
        self.outgoing.push(OutgoingDatagram {
            payload,
            ecn: EcnMarking::NotEct,
        });
    }

    /// Take out the first `count` datagrams, or all if fewer wait: the
    /// link accepted them. Taking them all ends the round, and the batch
    /// lets its memory go.
    pub fn take_accepted(
        &mut self,
        count: usize,
    ) -> impl Iterator<Item = BatchedDatagram<Si, Sh, Sa, C>> + '_ {
        if count >= self.datagrams.len() {
            self.buffer = BytesMut::new();
            self.outgoing = Vec::new();
            return core::mem::take(&mut self.datagrams).into_iter();
        }
        // the link took a part: the rest stays for the next hand-over
        self.outgoing.drain(..count);
        let rest = self.datagrams.split_off(count);
        core::mem::replace(&mut self.datagrams, rest).into_iter()
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

    /// Start writing a datagram at `now` with the destination connection ID
    /// `dcid`, sent by a side of `role` that asks the peer to send with
    /// connection IDs of `local_id_length`, of at most `max_len` bytes, of
    /// which packets that count in flight take at most `in_flight_room`; `probe` when it may go past
    /// the congestion window on a permit of `congestion`, which it uses if
    /// it carries anything that counts in flight. When it is sealed it is
    /// charged to `congestion`, `controller` and `anti_amplification`.
    #[allow(clippy::too_many_arguments)]
    pub fn start_datagram<'b, K, I>(
        &'b mut self,
        now: I,
        dcid: ConnectionId,
        role: Role,
        local_id_length: ConnectionIdLength,
        max_len: usize,
        in_flight_room: usize,
        probe: bool,
        congestion: &'b mut LinkPathCongestionState<I>,
        controller: &'b mut K,
        anti_amplification: &'b mut AntiAmplification,
    ) -> DatagramWriter<'b, Si, Sh, Sa, K, I>
    where
        K: CongestionController<I, SentState = C> + Pacer<I>,
        I: Copy,
    {
        self.start_observed_datagram(
            now,
            dcid,
            role,
            local_id_length,
            max_len,
            in_flight_room,
            probe,
            congestion,
            controller,
            anti_amplification,
            (),
        )
    }

    /// Start a datagram as [`start_datagram`](Self::start_datagram) does,
    /// whose packets `observer` sees in plaintext just before each is
    /// sealed.
    #[allow(clippy::too_many_arguments)]
    pub fn start_observed_datagram<'b, K, I, O>(
        &'b mut self,
        now: I,
        dcid: ConnectionId,
        role: Role,
        local_id_length: ConnectionIdLength,
        max_len: usize,
        in_flight_room: usize,
        probe: bool,
        congestion: &'b mut LinkPathCongestionState<I>,
        controller: &'b mut K,
        anti_amplification: &'b mut AntiAmplification,
        observer: O,
    ) -> DatagramWriter<'b, Si, Sh, Sa, K, I, O>
    where
        K: CongestionController<I, SentState = C> + Pacer<I>,
        I: Copy,
    {
        self.start_charged(
            now,
            dcid,
            role,
            local_id_length,
            max_len,
            in_flight_room,
            probe,
            congestion,
            controller,
            anti_amplification,
            observer,
            true,
        )
    }

    /// Start an uncharged datagram, of a candidate without a recovery
    /// layer, as [`start_observed_datagram`](Self::start_observed_datagram)
    /// does: when it is sealed its packets count nothing in flight, and
    /// `congestion` and `controller` hear of nothing; only
    /// `anti_amplification` is charged. It may go past nothing: it uses no
    /// probe permit.
    #[allow(clippy::too_many_arguments)]
    pub fn start_uncharged_datagram<'b, K, I, O>(
        &'b mut self,
        now: I,
        dcid: ConnectionId,
        role: Role,
        local_id_length: ConnectionIdLength,
        max_len: usize,
        congestion: &'b mut LinkPathCongestionState<I>,
        controller: &'b mut K,
        anti_amplification: &'b mut AntiAmplification,
        observer: O,
    ) -> DatagramWriter<'b, Si, Sh, Sa, K, I, O>
    where
        K: CongestionController<I, SentState = C> + Pacer<I>,
        I: Copy,
    {
        self.start_charged(
            now,
            dcid,
            role,
            local_id_length,
            max_len,
            max_len,
            false,
            congestion,
            controller,
            anti_amplification,
            observer,
            false,
        )
    }

    /// Start a datagram, `charged` to congestion control or not.
    #[allow(clippy::too_many_arguments)]
    fn start_charged<'b, K, I, O>(
        &'b mut self,
        now: I,
        dcid: ConnectionId,
        role: Role,
        local_id_length: ConnectionIdLength,
        max_len: usize,
        in_flight_room: usize,
        probe: bool,
        congestion: &'b mut LinkPathCongestionState<I>,
        controller: &'b mut K,
        anti_amplification: &'b mut AntiAmplification,
        observer: O,
        charged: bool,
    ) -> DatagramWriter<'b, Si, Sh, Sa, K, I, O>
    where
        K: CongestionController<I, SentState = C> + Pacer<I>,
        I: Copy,
    {
        // the buffer holds the datagram being written only: a sealed one
        // leaves it, and an empty one took its bytes back
        self.buffer.clear();
        // the first datagram of a round asks for itself; a second asks for
        // the rest of the round at once
        let datagrams = if self.datagrams.is_empty() {
            1
        } else {
            self.max_datagrams
                .get()
                .saturating_sub(self.datagrams.len())
                .max(1)
        };
        if self.buffer.capacity() < max_len {
            self.buffer = BytesMut::with_capacity(max_len.saturating_mul(datagrams));
        }
        if self.datagrams.len() == self.datagrams.capacity() {
            self.datagrams.reserve_exact(datagrams);
        }
        if self.outgoing.len() == self.outgoing.capacity() {
            self.outgoing.reserve_exact(datagrams);
        }
        let state = DatagramState {
            dcid,
            role,
            local_id_length,
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
            now,
            probe,
            charged,
            congestion,
            controller,
            anti_amplification,
            observer,
        }
    }
}

/// A packet sealed in the datagram being written: the send journals'
/// sealed packet, its size if it counts in flight, and whether it is
/// ack-eliciting.
#[derive(Debug)]
pub(super) struct SealedInDatagram<S> {
    pub(super) sealed: S,
    pub(super) in_flight: Option<usize>,
    pub(super) ack_eliciting: bool,
}

/// What a datagram being written knows of itself; its packet writers read
/// and change it.
#[derive(Debug)]
pub(super) struct DatagramState {
    /// The destination connection ID of every packet.
    pub(super) dcid: ConnectionId,
    /// The side that sends it.
    pub(super) role: Role,
    /// The length of the connection IDs the side asks the peer to send
    /// with.
    pub(super) local_id_length: ConnectionIdLength,
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
/// `C` is the congestion controller and pacer of the link path, `I` the
/// type of instants.
pub struct DatagramWriter<'b, Si, Sh, Sa, C, I, O = ()>
where
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
    now: I,
    probe: bool,
    /// Whether its packets are charged to congestion control: those of an
    /// uncharged datagram count nothing in flight.
    charged: bool,
    congestion: &'b mut LinkPathCongestionState<I>,
    controller: &'b mut C,
    anti_amplification: &'b mut AntiAmplification,
    /// Sees each packet just before it is sealed.
    observer: O,
}

impl<Si, Sh, Sa, C, I, O> fmt::Debug for DatagramWriter<'_, Si, Sh, Sa, C, I, O>
where
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

impl<Si, Sh, Sa, C, I, O> DatagramWriter<'_, Si, Sh, Sa, C, I, O>
where
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

    /// The last packet pads the datagram to at least `floor` bytes, as far
    /// as the datagram can grow: as a datagram size probe is padded to its
    /// size.
    pub fn raise_floor(&mut self, floor: usize) {
        self.state.raise_floor(floor);
    }

    /// Whether a packet of `space` is sealed in the datagram.
    pub fn carries(&self, space: PacketNumberSpaceKind) -> bool {
        match space {
            PacketNumberSpaceKind::Initial => self.initial.is_some(),
            PacketNumberSpaceKind::Handshake => self.handshake.is_some(),
            PacketNumberSpaceKind::ApplicationData => self.application_data.is_some(),
        }
    }

    /// Whether an ack-eliciting packet of `space` is sealed in the
    /// datagram.
    pub(crate) fn carries_ack_eliciting(&self, space: PacketNumberSpaceKind) -> bool {
        fn ack_eliciting<S>(packet: &Option<SealedInDatagram<S>>) -> bool {
            packet.as_ref().is_some_and(|packet| packet.ack_eliciting)
        }
        match space {
            PacketNumberSpaceKind::Initial => ack_eliciting(&self.initial),
            PacketNumberSpaceKind::Handshake => ack_eliciting(&self.handshake),
            PacketNumberSpaceKind::ApplicationData => ack_eliciting(&self.application_data),
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
    pub fn start_initial_packet<'d, A, B, Ipd>(
        &'d mut self,
        attempt: A,
        keys: &'d DirectionKeys<B>,
        largest_acked: Option<PacketNumber>,
        scid: ConnectionId,
        token: Bytes,
    ) -> Result<PacketWriter<'d, A, B, O>, EncodePacketNumberError>
    where
        O: SealObserver,
        A: PacketSendAttempt<Sealed = Si>,
        A::Summary: InjectSummary<PaddingSummary, Ipd>,
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
            || <A::Summary as InjectSummary<PaddingSummary, Ipd>>::inject_summary(PaddingSummary),
            &mut self.observer,
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
    pub fn start_handshake_packet<'d, A, B, Ipd>(
        &'d mut self,
        attempt: A,
        keys: &'d DirectionKeys<B>,
        largest_acked: Option<PacketNumber>,
        scid: ConnectionId,
    ) -> Result<PacketWriter<'d, A, B, O>, EncodePacketNumberError>
    where
        O: SealObserver,
        A: PacketSendAttempt<Sealed = Sh>,
        A::Summary: InjectSummary<PaddingSummary, Ipd>,
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
            || <A::Summary as InjectSummary<PaddingSummary, Ipd>>::inject_summary(PaddingSummary),
            &mut self.observer,
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
    pub fn start_zero_rtt_packet<'d, A, B, Ipd>(
        &'d mut self,
        attempt: A,
        keys: &'d DirectionKeys<B>,
        largest_acked: Option<PacketNumber>,
        scid: ConnectionId,
    ) -> Result<PacketWriter<'d, A, B, O>, EncodePacketNumberError>
    where
        O: SealObserver,
        A: PacketSendAttempt<Sealed = Sa>,
        A::Summary: InjectSummary<PaddingSummary, Ipd>,
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
            || <A::Summary as InjectSummary<PaddingSummary, Ipd>>::inject_summary(PaddingSummary),
            &mut self.observer,
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
    pub fn start_one_rtt_packet<'d, A, B, Ipd>(
        &'d mut self,
        attempt: A,
        keys: &'d OneRttSendKeys<B>,
        usage: &'d mut AeadUsage,
        largest_acked: Option<PacketNumber>,
    ) -> Result<PacketWriter<'d, A, B, O>, EncodePacketNumberError>
    where
        O: SealObserver,
        A: PacketSendAttempt<Sealed = Sa>,
        A::Summary: InjectSummary<PaddingSummary, Ipd>,
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
            || <A::Summary as InjectSummary<PaddingSummary, Ipd>>::inject_summary(PaddingSummary),
            &mut self.observer,
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

impl<Si, Sh, Sa, C, I, O> DatagramWriter<'_, Si, Sh, Sa, C, I, O>
where
    C: CongestionController<I> + Pacer<I>,
    I: Copy,
{
    /// Seal the datagram into the batch: its size once it carries a
    /// packet, for the use of its connection ID; `None` when it is empty,
    /// and nothing happened. Dropping the writer seals it the same way,
    /// without the size.
    #[must_use = "a datagram sealed with content reports the use of its connection ID"]
    pub fn finish(mut self) -> Option<usize> {
        self.seal()
    }

    /// Charge the end of the datagram and move it into the batch, once: the
    /// writer is empty afterwards.
    fn seal(&mut self) -> Option<usize> {
        if self.state.packets == 0 {
            return None;
        }
        let len = self.len();
        if !self.charged {
            return Some(self.batch_uncharged(len));
        }
        let app_limited = self.congestion.app_limited();
        let (controller, now) = (&mut *self.controller, self.now);
        // the datagram's bytes come in flight when it is charged below;
        // each packet is told of those sealed before it and of itself
        let mut bytes_in_flight = self.congestion.bytes_in_flight();
        let mut charge = |bytes: usize| {
            bytes_in_flight = bytes_in_flight.saturating_add(bytes);
            InFlightCharge {
                bytes,
                app_limited,
                sent_state: controller.on_packet_sealed(&SealedPacket {
                    bytes,
                    app_limited,
                    bytes_in_flight,
                    now,
                }),
            }
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
        self.state.packets = 0;
        Some(len)
    }
}

impl<Si, Sh, Sa, C, I, O> DatagramWriter<'_, Si, Sh, Sa, C, I, O>
where
    C: CongestionController<I> + Pacer<I>,
    I: Copy,
{
    /// Move the uncharged datagram of `len` bytes into the batch, charged
    /// to the anti-amplification limit only.
    fn batch_uncharged(&mut self, len: usize) -> usize {
        let initial = self.initial.take().map(uncharged);
        let handshake = self.handshake.take().map(uncharged);
        let application_data = self.application_data.take().map(uncharged);
        self.anti_amplification.sent(len);
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
        self.state.packets = 0;
        len
    }
}

/// The packet of an uncharged datagram, which counts nothing in flight.
fn uncharged<S, C>(packet: SealedInDatagram<S>) -> BatchedPacket<S, C> {
    BatchedPacket {
        sealed: packet.sealed,
        in_flight: None,
    }
}

/// What an uncharged datagram is written with in place of a link path's
/// congestion controller and pacer: a window and an allowance without
/// bounds, and nothing to hear. `S` is what the link path's controller
/// would keep for a packet in flight, which an uncharged datagram has none
/// of.
pub struct UnchargedCongestion<S>(PhantomData<fn() -> S>);

impl<S> UnchargedCongestion<S> {
    /// The stand-in.
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<S> Default for UnchargedCongestion<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> fmt::Debug for UnchargedCongestion<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnchargedCongestion")
    }
}

impl<I, S> CongestionController<I> for UnchargedCongestion<S> {
    type SentState = S;
    type LossState = ();

    fn window(&self) -> usize {
        usize::MAX
    }

    fn on_packet_sealed(&mut self, _: &SealedPacket<I>) -> S {
        // invariant: only an uncharged datagram is written with it, and its
        // packets are sealed without a charge
        unreachable!("an uncharged datagram charges no packet")
    }

    fn on_spurious_loss(
        &mut self,
        (): (),
        _: impl Iterator<Item = SpuriouslyLostPacket<I>>,
        _: &CongestionContext<I>,
    ) {
    }

    fn on_ce(&mut self, _: u64, _: I, _: &CongestionContext<I>) {}

    fn on_lost(&mut self, _: impl Iterator<Item = InFlightPacket<I, S>>, _: &CongestionContext<I>) {
    }

    fn on_persistent_congestion(&mut self, _: &CongestionContext<I>) {}

    fn wants_recovery_send(&mut self) -> bool {
        false
    }

    fn on_acked(
        &mut self,
        _: impl Iterator<Item = InFlightPacket<I, S>>,
        _: &CongestionContext<I>,
    ) {
    }

    fn on_removed(&mut self, _: impl Iterator<Item = RemovedPacket<S>>, _: &CongestionContext<I>) {}

    fn on_max_datagram_size_changed(&mut self, _: usize, _: bool, _: &CongestionContext<I>) {}
}

impl<I, S> Pacer<I> for UnchargedCongestion<S> {
    fn next_release(&self) -> Option<I> {
        None
    }

    fn allowance(&self) -> usize {
        usize::MAX
    }

    fn refill(&mut self, _: I, _: PacingInput) -> bool {
        false
    }

    fn on_charged(&mut self, _: usize) {}
}

impl<Si, Sh, Sa, C, I, O> Drop for DatagramWriter<'_, Si, Sh, Sa, C, I, O>
where
    C: CongestionController<I> + Pacer<I>,
    I: Copy,
{
    fn drop(&mut self) {
        // a panic ends the whole connection: nothing is charged or batched
        if std::thread::panicking() {
            return;
        }
        let _ = self.seal();
    }
}

#[cfg(test)]
pub(super) mod tests;
