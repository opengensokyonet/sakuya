//! Writing frames into a packet: what every part's frame sources write
//! with.
//!
//! A frame source gets an open packet ([`OpenPacket`]) by value and hands
//! back what it holds afterwards ([`Supplied`]): the open packet, or the
//! closed packet ([`ClosedPacket`]) that writing a frame extending to the end
//! of the packet turns it into. It writes nothing but frames: a frame with
//! its own boundary ([`DelimitedFrame`]) leaves the packet open; a frame that
//! extends to the end of the packet ([`ToPacketEndFrame`]) closes it, and only
//! an open packet in the last position ([`Last`]) can write one. Each frame
//! is written with the summary of what it carries, which goes into the
//! packet's send attempt with the frame's properties.
//!
//! An open packet carries the flight class of the source it is given to
//! ([`FlightClass`], as a type: [`FlightClassType`]): how many bytes are
//! left for the source depends on it, and the source writes only frames of
//! that class.
//!
//! What writes the bytes, keeps the packet's room and seals the packet is
//! the packet writer of the version the packet belongs to
//! ([`PacketWriting`]); an open packet holds it by value, and dropping what
//! the source hands back drops it.

use core::{fmt, marker::PhantomData};

use bytes::BytesMut;
use sakuya_recovery::send_journals::PacketSendAttempt;
use snafu::{Snafu, ensure};

/// The summary of the PADDING a packet writer writes: it has nothing to
/// hand back when the packet is acknowledged or declared lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PaddingSummary;

// ---- flight classes ----

/// Whether content counts in the bytes in flight (RFC 9002 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlightClass {
    /// ACK only: it does not count, and neither the congestion window nor
    /// pacing limits it.
    AckOnly,
    /// Anything else: it counts, and the room for it is limited by what
    /// may still go in flight.
    InFlight,
}

/// A flight class as a type: what a frame source and its frames give, and
/// what an open packet carries.
pub trait FlightClassType {
    /// The class.
    const FLIGHT_CLASS: FlightClass;
}

/// [`FlightClass::AckOnly`] as a type.
#[derive(Debug)]
pub enum AckOnlyClass {}

/// [`FlightClass::InFlight`] as a type.
#[derive(Debug)]
pub enum InFlightClass {}

/// The class of an open packet on its way to a frame source: the filling
/// hands a packet to a part with this class, and the part's dispatch gives
/// it the class of the frame source it reaches
/// ([`OpenPacket::into_source_class`]). Nothing can be written with it.
#[derive(Debug)]
pub enum ClassOfSource {}

impl FlightClassType for AckOnlyClass {
    const FLIGHT_CLASS: FlightClass = FlightClass::AckOnly;
}

impl FlightClassType for InFlightClass {
    const FLIGHT_CLASS: FlightClass = FlightClass::InFlight;
}

// ---- frames ----

/// A frame with its own boundary: it may be followed by more frames in the
/// same packet.
///
/// Its properties are those of its type. Writing it calls the frame's
/// synchronous write operation; the frame's value fixes every detail of its
/// encoding.
pub trait DelimitedFrame {
    /// Whether the frame counts in the bytes in flight.
    type Class: FlightClassType;
    /// Whether the frame elicits an acknowledgment (RFC 9002 §2).
    const ACK_ELICITING: bool;
    /// Whether a datagram carrying the frame is expanded to 1200 bytes, as
    /// far as the anti-amplification limit allows (RFC 9000 §8.2.1,
    /// §8.2.2).
    const EXPANDS_DATAGRAM: bool = false;

    /// The bytes [`write_to`](Self::write_to) writes.
    fn encoded_len(&self) -> usize;

    /// Write the frame at the end of `buffer`.
    fn write_to(self, buffer: &mut BytesMut);
}

/// A frame that extends to the end of the packet: nothing can follow it.
pub trait ToPacketEndFrame {
    /// Whether the frame counts in the bytes in flight.
    type Class: FlightClassType;
    /// Whether the frame elicits an acknowledgment (RFC 9002 §2).
    const ACK_ELICITING: bool;

    /// The bytes [`write_to`](Self::write_to) writes.
    fn encoded_len(&self) -> usize;

    /// Write the frame at the end of `buffer`.
    fn write_to(self, buffer: &mut BytesMut);
}

// ---- the packet writer an open packet holds ----

pub(crate) mod sealed {
    /// Only the packet writers of this crate write packets.
    pub trait Writing {}
    /// Only [`Last`](super::Last) and [`NotLast`](super::NotLast) are
    /// positions.
    pub trait Position {}
}

/// What an open packet writes through: the packet writer of the version
/// the packet belongs to. Only this crate's packet writers are one.
pub trait PacketWriting: sealed::Writing {
    /// The send attempt of the packet.
    type Attempt: PacketSendAttempt;

    /// The bytes a frame of `class` may take now: what is left of the
    /// datagram after the packet's AEAD tag and the PADDING header
    /// protection needs; for [`FlightClass::InFlight`], no more than may
    /// still go in flight, counting the whole packet.
    fn room(&self, class: FlightClass) -> usize;

    /// The buffer the packet is written into; frames go at its end.
    fn buffer(&mut self) -> &mut BytesMut;

    /// The bytes in the buffer so far: what a frame source wrote is the
    /// difference before and after it.
    fn buffer_len(&self) -> usize;

    /// A frame was written: its summary and properties.
    fn frame_written(
        &mut self,
        summary: SummaryOf<Self>,
        ack_eliciting: bool,
        in_flight: bool,
        expands_datagram: bool,
    );

    /// A frame extending to the end of the packet was written: PADDING
    /// added when the packet is sealed goes before the frames.
    fn close(&mut self);

    /// Whether more packets follow in the datagram: the last one is padded
    /// to the datagram's floor when it is sealed. Without this, the packet
    /// is taken to be the last.
    fn conclude(&mut self, more: bool);
}

/// The summary of a frame of the packet `W` writes.
pub type SummaryOf<W> = <<W as PacketWriting>::Attempt as PacketSendAttempt>::Summary;

// ---- positions ----

/// The position of a frame source that may close the packet: the last
/// content planned for the packet, or content whose shortest frame with a
/// Length field no longer fits while its shortest frame extending to the
/// end of the packet does.
#[derive(Debug)]
pub enum Last {}

/// The position of any other frame source: it cannot close the packet.
#[derive(Debug)]
pub enum NotLast {}

/// Where a frame source is in its packet: [`Last`] or [`NotLast`], and no
/// other.
pub trait PacketPosition: sealed::Position {
    /// Whether the position is [`Last`].
    const LAST: bool;
}

impl sealed::Position for Last {}
impl sealed::Position for NotLast {}

impl PacketPosition for Last {
    const LAST: bool = true;
}

impl PacketPosition for NotLast {
    const LAST: bool = false;
}

// ---- failures ----

/// A frame is longer than the bytes left for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(display("a frame of {frame_len} bytes does not fit in the {remaining} bytes left"))]
pub struct FrameDoesNotFitError {
    frame_len: usize,
    remaining: usize,
}

impl FrameDoesNotFitError {
    /// The length of the frame.
    pub fn frame_len(&self) -> usize {
        self.frame_len
    }

    /// The bytes that were left, fewer than the frame's length.
    pub fn remaining(&self) -> usize {
        self.remaining
    }
}

/// Whether a frame of `frame_len` bytes fits in `remaining`.
fn fits(frame_len: usize, remaining: usize) -> Result<(), FrameDoesNotFitError> {
    ensure!(
        frame_len <= remaining,
        FrameDoesNotFitSnafu {
            frame_len,
            remaining
        }
    );
    Ok(())
}

/// [`OpenPacket::write_frame`] did not write `F`: it does not fit. Nothing
/// was written; the frame comes back.
#[derive(Debug)]
pub struct FrameRejected<F> {
    frame: F,
    source: FrameDoesNotFitError,
}

impl<F> FrameRejected<F> {
    /// Why the frame was not written.
    pub fn error(&self) -> &FrameDoesNotFitError {
        &self.source
    }

    /// The frame, unwritten.
    pub fn into_frame(self) -> F {
        self.frame
    }
}

/// [`OpenPacket::write_last`] did not write `F`: it does not fit. Nothing
/// was written; the open packet, still [`Last`], and the frame come back.
pub struct LastFrameRejected<W, C, F> {
    packet: OpenPacket<W, C, Last>,
    frame: F,
    source: FrameDoesNotFitError,
}

impl<W, C, F> LastFrameRejected<W, C, F> {
    /// Why the frame was not written.
    pub fn error(&self) -> &FrameDoesNotFitError {
        &self.source
    }

    /// The open packet and the frame, unwritten.
    pub fn into_parts(self) -> (OpenPacket<W, C, Last>, F) {
        (self.packet, self.frame)
    }
}

impl<W: fmt::Debug, C, F: fmt::Debug> fmt::Debug for LastFrameRejected<W, C, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LastFrameRejected")
            .field("packet", &self.packet)
            .field("frame", &self.frame)
            .field("source", &self.source)
            .finish()
    }
}

// ---- open and closed packets ----

/// A packet frames can still be written into, given to a frame source of
/// class `C` at position `P`.
///
/// It holds the packet writer `W` by value: dropping it, or what it turns
/// into, seals the packet if a frame was written.
pub struct OpenPacket<W, C, P> {
    writer: W,
    class_and_position: PhantomData<fn() -> (C, P)>,
}

impl<W: fmt::Debug, C, P> fmt::Debug for OpenPacket<W, C, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenPacket")
            .field("writer", &self.writer)
            .finish()
    }
}

impl<W, C, P> OpenPacket<W, C, P> {
    /// The open packet of `writer`.
    pub(crate) fn new(writer: W) -> Self {
        Self {
            writer,
            class_and_position: PhantomData,
        }
    }

    /// The same packet in the last position: what the filling gives the
    /// last content of the packet, and content that fits only as the last
    /// frame.
    pub(crate) fn make_last(self) -> OpenPacket<W, C, Last> {
        OpenPacket::new(self.writer)
    }

    /// The same packet for a frame source of class `D`: the filling sets
    /// it before each supply.
    #[cfg_attr(not(test), expect(dead_code, reason = "the filling loop uses it"))]
    pub(crate) fn into_class<D>(self) -> OpenPacket<W, D, P> {
        OpenPacket::new(self.writer)
    }
}

impl<W, P> OpenPacket<W, ClassOfSource, P> {
    /// The same packet for a frame source of class `C`: what a part's
    /// dispatch does before it gives the packet to the frame source the
    /// planned item belongs to, with that source's class.
    pub fn into_source_class<C: FlightClassType>(self) -> OpenPacket<W, C, P> {
        OpenPacket::new(self.writer)
    }
}

impl<W: PacketWriting, C, P> OpenPacket<W, C, P> {
    /// The bytes in the packet's buffer so far.
    pub(crate) fn buffer_len(&self) -> usize {
        self.writer.buffer_len()
    }

    /// The bytes a frame of `class` may take now: what the filling compares
    /// an item's least room with before it hands the packet on.
    pub(crate) fn room(&self, class: FlightClass) -> usize {
        self.writer.room(class)
    }

    /// Whether more packets follow in the datagram; the packet is sealed
    /// now.
    pub(crate) fn conclude(mut self, more: bool) {
        self.writer.conclude(more);
    }
}

impl<W: PacketWriting, C: FlightClassType, P> OpenPacket<W, C, P> {
    /// The bytes a frame may take now: what is left of the packet after
    /// its header and AEAD tag, and, for content that counts in the bytes
    /// in flight, no more than may still go in flight.
    pub fn remaining(&self) -> usize {
        self.writer.room(C::FLIGHT_CLASS)
    }

    /// Write `frame`, which has its own boundary, with `summary`, what to
    /// hand back when it is acknowledged or declared lost; the packet stays
    /// open.
    ///
    /// # Errors
    ///
    /// The frame is longer than [`remaining`](Self::remaining): nothing is
    /// written, and the frame comes back.
    pub fn write_frame<F: DelimitedFrame<Class = C>>(
        &mut self,
        frame: F,
        summary: impl Into<SummaryOf<W>>,
    ) -> Result<(), FrameRejected<F>> {
        let frame_len = frame.encoded_len();
        if let Err(source) = fits(frame_len, self.remaining()) {
            return Err(FrameRejected { frame, source });
        }
        write_counted(self.writer.buffer(), frame_len, |buffer| {
            frame.write_to(buffer);
        });
        self.writer.frame_written(
            summary.into(),
            F::ACK_ELICITING,
            C::FLIGHT_CLASS == FlightClass::InFlight,
            F::EXPANDS_DATAGRAM,
        );
        Ok(())
    }
}

impl<W, C, P: PacketPosition> OpenPacket<W, C, P> {
    /// The same packet in the last position, if this is it; otherwise this
    /// packet back.
    ///
    /// # Errors
    ///
    /// The position is [`NotLast`]: the packet comes back unchanged.
    pub fn into_last(self) -> Result<OpenPacket<W, C, Last>, Self> {
        if P::LAST {
            Ok(OpenPacket::new(self.writer))
        } else {
            Err(self)
        }
    }
}

impl<W, C> OpenPacket<W, C, Last> {
    /// The same packet in position `P`: a source that took the last
    /// position and did not close the packet hands it back in the position
    /// it was given. Only the ability to close is lost.
    pub fn into_position<P: PacketPosition>(self) -> OpenPacket<W, C, P> {
        OpenPacket::new(self.writer)
    }
}

impl<W: PacketWriting, C: FlightClassType> OpenPacket<W, C, Last> {
    /// Write `frame`, which extends to the end of the packet, with
    /// `summary`; the packet closes.
    ///
    /// Only an open packet in the last position has it:
    ///
    /// ```
    /// use sakuya_connection::write::{
    ///     Last, OpenPacket, PacketWriting, Supplied, SummaryOf, ToPacketEndFrame,
    /// };
    ///
    /// fn close<W, F, S>(
    ///     packet: OpenPacket<W, F::Class, Last>,
    ///     frame: F,
    ///     summary: S,
    /// ) -> Supplied<W, F::Class, Last>
    /// where
    ///     W: PacketWriting,
    ///     F: ToPacketEndFrame,
    ///     S: Into<SummaryOf<W>>,
    /// {
    ///     match packet.write_last(frame, summary) {
    ///         Ok(closed) => Supplied::Closed(closed),
    ///         Err(rejected) => Supplied::Open(rejected.into_parts().0),
    ///     }
    /// }
    /// ```
    ///
    /// ```compile_fail,E0599
    /// use sakuya_connection::write::{
    ///     NotLast, OpenPacket, PacketWriting, Supplied, SummaryOf, ToPacketEndFrame,
    /// };
    ///
    /// fn close<W, F, S>(
    ///     packet: OpenPacket<W, F::Class, NotLast>,
    ///     frame: F,
    ///     summary: S,
    /// ) -> Supplied<W, F::Class, NotLast>
    /// where
    ///     W: PacketWriting,
    ///     F: ToPacketEndFrame,
    ///     S: Into<SummaryOf<W>>,
    /// {
    ///     match packet.write_last(frame, summary) {
    ///         Ok(closed) => Supplied::Closed(closed),
    ///         Err(rejected) => Supplied::Open(rejected.into_parts().0.into_position()),
    ///     }
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// The frame is longer than [`remaining`](Self::remaining): nothing is
    /// written, and the open packet and the frame come back.
    pub fn write_last<F: ToPacketEndFrame<Class = C>>(
        mut self,
        frame: F,
        summary: impl Into<SummaryOf<W>>,
    ) -> Result<ClosedPacket<W, C>, LastFrameRejected<W, C, F>> {
        let frame_len = frame.encoded_len();
        if let Err(source) = fits(frame_len, self.remaining()) {
            return Err(LastFrameRejected {
                packet: self,
                frame,
                source,
            });
        }
        write_counted(self.writer.buffer(), frame_len, |buffer| {
            frame.write_to(buffer);
        });
        self.writer.frame_written(
            summary.into(),
            F::ACK_ELICITING,
            C::FLIGHT_CLASS == FlightClass::InFlight,
            false,
        );
        self.writer.close();
        Ok(ClosedPacket {
            writer: self.writer,
            class: PhantomData,
        })
    }
}

/// Write with `write`, which writes `frame_len` bytes by the frame's own
/// count.
fn write_counted(buffer: &mut BytesMut, frame_len: usize, write: impl FnOnce(&mut BytesMut)) {
    let before = buffer.len();
    write(buffer);
    debug_assert_eq!(
        buffer.len() - before,
        frame_len,
        "a frame writes as many bytes as its encoded length"
    );
}

/// A packet a frame extending to its end was written into: nothing more
/// can be written. Dropping it seals the packet.
pub struct ClosedPacket<W, C> {
    writer: W,
    class: PhantomData<fn() -> C>,
}

impl<W: fmt::Debug, C> fmt::Debug for ClosedPacket<W, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClosedPacket")
            .field("writer", &self.writer)
            .finish()
    }
}

impl<W: PacketWriting, C> ClosedPacket<W, C> {
    /// The bytes in the packet's buffer so far.
    pub(crate) fn buffer_len(&self) -> usize {
        self.writer.buffer_len()
    }

    /// The bytes a frame of `class` would have after this packet: what a
    /// packet after it in the datagram is measured against.
    pub(crate) fn room(&self, class: FlightClass) -> usize {
        self.writer.room(class)
    }

    /// Whether more packets follow in the datagram; the packet is sealed
    /// now.
    pub(crate) fn conclude(mut self, more: bool) {
        self.writer.conclude(more);
    }
}

/// What a frame source hands back: the open packet, in the position it was
/// given, or the closed packet, which only an open packet in the last
/// position turns into.
#[derive(Debug)]
pub enum Supplied<W, C, P> {
    /// The packet is still open.
    Open(OpenPacket<W, C, P>),
    /// A frame extending to the end of the packet closed it.
    Closed(ClosedPacket<W, C>),
}

impl<W, C, P> Supplied<W, C, P> {
    /// The same packet back with [`ClassOfSource`]: what a part's dispatch
    /// does with what the frame source handed back.
    pub fn into_class_of_source(self) -> Supplied<W, ClassOfSource, P> {
        match self {
            Self::Open(packet) => Supplied::Open(OpenPacket::new(packet.writer)),
            Self::Closed(packet) => Supplied::Closed(ClosedPacket {
                writer: packet.writer,
                class: PhantomData,
            }),
        }
    }
}

impl<W: PacketWriting, C, P> Supplied<W, C, P> {
    /// The bytes in the packet's buffer so far.
    pub(crate) fn buffer_len(&self) -> usize {
        match self {
            Self::Open(packet) => packet.buffer_len(),
            Self::Closed(packet) => packet.buffer_len(),
        }
    }

    /// The bytes a frame of `class` may take now in the packet, or, once
    /// it is closed, would have after it.
    pub(crate) fn room(&self, class: FlightClass) -> usize {
        match self {
            Self::Open(packet) => packet.room(class),
            Self::Closed(packet) => packet.room(class),
        }
    }

    /// Whether more packets follow in the datagram; the packet is sealed
    /// now.
    pub(crate) fn conclude(self, more: bool) {
        match self {
            Self::Open(packet) => packet.conclude(more),
            Self::Closed(packet) => packet.conclude(more),
        }
    }
}
