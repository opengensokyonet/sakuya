//! The datagrams a link path's sending call has sealed and not yet handed
//! to the link, and the writer of the one being filled.
//!
//! A [`DatagramBatch`] keeps every sealed datagram as one entry
//! ([`BatchedDatagram`]): where its bytes lie in the batch's buffer, and the
//! sealed packet of each packet number space it carries. Each entry is
//! settled once: taken out when the link accepts it, when it is given up,
//! or when it carries a level whose keys were discarded before it was
//! handed over.
//!
//! A [`DatagramWriter`] writes one datagram at the end of the batch's
//! buffer, one packet after the other ([`PacketWriter`]). It knows the
//! datagram's floor, which follows from what it carries (RFC 9000 §14.1,
//! §8.2.1, §8.2.2), and the last packet is padded to it. Dropped with a
//! packet sealed, it charges the end of the datagram once: the bytes in
//! flight, the probe permit and pacing to the link path's congestion state,
//! the whole datagram to the anti-amplification limit, the use of its
//! connection ID; then it adds the datagram to the batch. Dropped empty,
//! nothing happened. Dropped while a panic unwinds, it does nothing at
//! all.

use core::{fmt, num::NonZeroUsize, ops::Range};

use bytes::{Bytes, BytesMut};
use sakuya_packet_protection::{backend::CryptoBackend, packet_number::EncodePacketNumberError};
use sakuya_recovery::{pacing::Pacer, send_journals::PacketSendAttempt};
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

/// One sealed datagram waiting in a [`DatagramBatch`]: where its bytes lie
/// and the sealed packet of each packet number space it carries.
///
/// `Si`, `Sh` and `Sa` are the sealed packets of the send journals of the
/// Initial, Handshake and application data spaces.
#[derive(Debug, PartialEq, Eq)]
pub struct BatchedDatagram<Si, Sh, Sa> {
    range: Range<usize>,
    /// The sealed Initial packet.
    pub initial: Option<Si>,
    /// The sealed Handshake packet.
    pub handshake: Option<Sh>,
    /// The sealed 0-RTT or 1-RTT packet.
    pub application_data: Option<Sa>,
}

impl<Si, Sh, Sa> BatchedDatagram<Si, Sh, Sa> {
    /// The size of the datagram in bytes.
    pub fn len(&self) -> usize {
        self.range.len()
    }

    /// Whether the datagram is empty; a batched datagram never is.
    pub fn is_empty(&self) -> bool {
        self.range.is_empty()
    }
}

/// The datagrams a link path has sealed, waiting to be handed to its
/// link, at most a given number of them.
///
/// The bytes of all of them lie one after the other in one buffer, which
/// is emptied once no datagram is left.
#[derive(Debug)]
pub struct DatagramBatch<Si, Sh, Sa> {
    buffer: BytesMut,
    datagrams: Vec<BatchedDatagram<Si, Sh, Sa>>,
    max_datagrams: NonZeroUsize,
}

impl<Si, Sh, Sa> DatagramBatch<Si, Sh, Sa> {
    /// An empty batch of at most `max_datagrams` datagrams.
    pub fn new(max_datagrams: NonZeroUsize) -> Self {
        Self {
            buffer: BytesMut::new(),
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

    /// The bytes of each waiting datagram, in order.
    pub fn datagrams(&self) -> impl Iterator<Item = &[u8]> {
        self.datagrams
            .iter()
            .map(|datagram| &self.buffer[datagram.range.clone()])
    }

    /// Take out the first `count` datagrams, or all if fewer wait: the
    /// link accepted them.
    pub fn take_accepted(
        &mut self,
        count: usize,
    ) -> impl Iterator<Item = BatchedDatagram<Si, Sh, Sa>> + '_ {
        let count = count.min(self.datagrams.len());
        self.datagrams.drain(..count)
    }

    /// Take out the first datagram, if any: the link gave it up.
    pub fn take_first(&mut self) -> Option<BatchedDatagram<Si, Sh, Sa>> {
        (!self.datagrams.is_empty()).then(|| self.datagrams.remove(0))
    }

    /// Take out the datagrams `discarded` picks, keeping the others in
    /// order: those carrying a packet of a level whose keys were discarded
    /// before the batch was handed to the link.
    pub fn take_discarded<'a, F>(
        &'a mut self,
        mut discarded: F,
    ) -> impl Iterator<Item = BatchedDatagram<Si, Sh, Sa>> + 'a
    where
        F: FnMut(&BatchedDatagram<Si, Sh, Sa>) -> bool + 'a,
    {
        self.datagrams
            .extract_if(.., move |datagram| discarded(datagram))
    }

    /// Start writing a datagram at the end of the batch with `cid`, sent by
    /// a side of `role`, of at most `max_len` bytes, of which packets that
    /// count in flight take at most `in_flight_room`; `probe` when it goes
    /// past the congestion window on a permit of `congestion`. When it is
    /// sealed it is charged to `congestion`, `controller` and
    /// `anti_amplification`.
    #[allow(clippy::too_many_arguments)]
    pub fn start_datagram<'b, U, C, I>(
        &'b mut self,
        cid: U,
        role: Role,
        max_len: usize,
        in_flight_room: usize,
        probe: bool,
        congestion: &'b mut LinkPathCongestionState<I>,
        controller: &'b mut C,
        anti_amplification: &'b mut AntiAmplification,
    ) -> DatagramWriter<'b, Si, Sh, Sa, U, C, I>
    where
        U: ConnectionIdUse,
        C: Pacer<I>,
        I: Copy,
    {
        if self.datagrams.is_empty() {
            self.buffer.clear();
        }
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
            datagrams: &mut self.datagrams,
            state,
            initial: None,
            handshake: None,
            application_data: None,
            cid: Some(cid),
            probe,
            congestion,
            controller,
            anti_amplification,
        }
    }
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

/// One datagram being written at the end of a [`DatagramBatch`].
///
/// `U` is its connection ID, `C` the congestion controller and pacer of
/// the link path, `I` the type of instants.
pub struct DatagramWriter<'b, Si, Sh, Sa, U, C, I>
where
    U: ConnectionIdUse,
    C: Pacer<I>,
    I: Copy,
{
    buffer: &'b mut BytesMut,
    datagrams: &'b mut Vec<BatchedDatagram<Si, Sh, Sa>>,
    state: DatagramState,
    initial: Option<Si>,
    handshake: Option<Sh>,
    application_data: Option<Sa>,
    /// Kept until the datagram is sealed.
    cid: Option<U>,
    probe: bool,
    congestion: &'b mut LinkPathCongestionState<I>,
    controller: &'b mut C,
    anti_amplification: &'b mut AntiAmplification,
}

impl<Si, Sh, Sa, U, C, I> fmt::Debug for DatagramWriter<'_, Si, Sh, Sa, U, C, I>
where
    U: ConnectionIdUse,
    C: Pacer<I>,
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
    C: Pacer<I>,
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
    C: Pacer<I>,
    I: Copy,
{
    fn drop(&mut self) {
        // a panic ends the whole connection: nothing is charged or batched
        if std::thread::panicking() || self.state.packets == 0 {
            return;
        }
        let len = self.len();
        self.congestion
            .on_datagram_sealed(self.controller, self.state.in_flight, self.probe);
        self.anti_amplification.sent(len);
        if let Some(cid) = self.cid.take() {
            cid.used(len);
        }
        self.datagrams.push(BatchedDatagram {
            range: self.state.start..self.state.start + len,
            initial: self.initial.take(),
            handshake: self.handshake.take(),
            application_data: self.application_data.take(),
        });
    }
}

#[cfg(test)]
mod tests;
