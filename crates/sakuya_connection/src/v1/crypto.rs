//! Receiving CRYPTO data: the bytes of the TLS handshake, kept for each
//! encryption level until the handshake engine reads them.
//!
//! The CRYPTO frames of each encryption level form a byte stream of their
//! own, with offsets counted from 0 (RFC 9000 §19.6). They arrive in any
//! order and more than once, and nothing limits how much of them the peer can
//! send (RFC 9000 §7.5): the component keeps the bytes of the level being
//! read in a [`CryptoReceiveBuffer`] of bounded size and hands them out in
//! order, each byte once.
//!
//! [`CryptoReceiver`] spans the three levels, Initial, Handshake and 1-RTT,
//! because a level is left in a step of its own, after the keys of the
//! level may already be gone. Each level is in one of three states:
//!
//! - open: the handshake engine has not left the level. Frames are stored in
//!   the level's buffer, as long as they end within its capacity past the
//!   read position, and are read in order.
//! - left: the engine moved on. Only the end of the data received is kept. A
//!   frame that ends within it is a retransmission and is ignored; one that
//!   passes it is a violation (RFC 9001 §4.1.3).
//! - refused: this endpoint's role receives no handshake messages at the
//!   level. A server receives none at 1-RTT, since a client has nothing to
//!   send there (RFC 9001 §6, §4.4). A frame with data is an error; an empty
//!   one is ignored.
//!
//! Moving to a later level fails if the level being left still holds bytes
//! the engine has not read, also bytes stored ahead of a gap (RFC 9001
//! §4.1.3). Frames of the level after the one being read are stored and wait
//! until the engine moves there.
//!
//! The capacity of each open level is checked when its
//! [`CryptoReceiveCapacities`] are made, so that making the component cannot
//! fail: it is at least 4096 bytes, which RFC 9000 §7.5 requires an endpoint
//! to buffer, and at least the largest single handshake message the endpoint
//! can receive at the level, so that a message that arrives in order can
//! always be stored whole. A frame that does not fit is an error, as RFC 9000
//! §7.5 requires during the handshake.
//!
//! The component keeps no packet protection state and does not decide when
//! the engine moves to a level.

use core::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll, Waker},
};

use bytes::{BufMut, Bytes};
use nitori_call::{BorrowedReceiver, family_receiver};
use nitori_io::Read;
use sakuya_stream::receive_buffer::{
    StreamDataInput, StreamReceiveBuffer, fragmented::FragmentedStreamReceiveBuffer,
};
use sakuya_tls::{
    engine::{CryptoInput, CryptoLevel},
    message::{MessageLimits, ReceivedMessageType},
};
use sakuya_wire::var_int::VarInt;
use snafu::{Snafu, ensure};

family_receiver!(impl [B: CryptoReceiveBuffer + Unpin + 'static] for CryptoReceiver<B>);

/// The handshake engine reads the level being read. Nothing is ready when no
/// contiguous bytes are: the reader is woken when the next frame at that
/// level is received.
impl<B: CryptoReceiveBuffer + Unpin + 'static> Read for CryptoReceiver<B> {
    type Error = Infallible;

    fn poll_read<'v, Output: BufMut + ?Sized>(
        host: Pin<&mut BorrowedReceiver<'v, Self>>,
        cx: &mut Context<'_>,
        destination: &mut Output,
    ) -> Poll<Result<usize, Infallible>>
    where
        Self: 'v,
    {
        let this = host.get_pin_mut().get_mut();
        if !destination.has_remaining_mut() {
            return Poll::Ready(Ok(0));
        }
        match this.read_into(destination) {
            0 => {
                this.reader = Some(cx.waker().clone());
                Poll::Pending
            }
            read => Poll::Ready(Ok(read)),
        }
    }
}

/// The handshake engine moves the level it reads as
/// [`CryptoReceiver::move_input_to`] does.
impl<B: CryptoReceiveBuffer + Unpin + 'static> CryptoInput for CryptoReceiver<B> {
    type LevelError = CryptoLevelMoveError;

    fn move_input_to<'v>(
        view: Pin<&mut BorrowedReceiver<'v, Self>>,
        level: CryptoLevel,
    ) -> Result<(), CryptoLevelMoveError>
    where
        Self: 'v,
    {
        view.get_pin_mut().get_mut().move_input_to(level)
    }
}

#[cfg(test)]
mod tests;

/// The least capacity of an open level, in bytes: the out-of-order CRYPTO
/// data an endpoint has to buffer (RFC 9000 §7.5).
const MIN_CAPACITY: usize = 4096;

/// The size of the header of a handshake message, in bytes: a one-byte type
/// and a three-byte length (RFC 9846 §4).
const MESSAGE_HEADER_LEN: usize = 4;

/// The body length of a Finished message when the hash of the cipher suite is
/// not known yet: that of SHA-384, the longest hash a TLS 1.3 cipher suite
/// uses for QUIC.
const UNKNOWN_HASH_FINISHED_LEN: u32 = 48;

/// The reassembly store of the CRYPTO data of one encryption level.
///
/// It takes the data of CRYPTO frames at their offsets, in any order and
/// repeated, and hands it out in order. It stores whatever it is given; the
/// bound on how much that may be is kept by [`CryptoReceiver`].
///
/// # Contract
///
/// - Data at offsets already read, or already held, is ignored; shorter
///   data never replaces longer held data.
/// - [`received_end`](Self::received_end) is the largest end offset of any
///   data received, whether or not it was kept. It never decreases.
/// - [`read_chunk`](Self::read_chunk) and [`read_into`](Self::read_into)
///   hand out the contiguous data starting at
///   [`read_end`](Self::read_end), never data at or beyond the offset
///   `limit` they are given, and each byte at most once. Both move the same
///   read position: it advances by exactly the number of bytes handed out.
///   A chunk handed out is never empty.
/// - The offset of the end of data passed to [`receive`](Self::receive) is
///   at most [`VarInt::MAX`], which the reader of CRYPTO frames guarantees.
///   An implementation does not panic if it is not.
pub trait CryptoReceiveBuffer {
    /// The block type handed out by [`read_chunk`](Self::read_chunk).
    type Chunk;

    /// Takes the data of one CRYPTO frame at `offset`.
    fn receive(&mut self, offset: VarInt, data: Bytes);

    /// The largest end offset of any data received.
    fn received_end(&self) -> VarInt;

    /// How far data has been handed out: every byte below this offset has
    /// been, none at or above it.
    fn read_end(&self) -> VarInt;

    /// Hands out the next contiguous block below the offset `limit`, if one
    /// is held at [`read_end`](Self::read_end).
    fn read_chunk(&mut self, limit: VarInt) -> Option<Self::Chunk>;

    /// Copies contiguous data below the offset `limit` into `target`, as much
    /// as fits, and returns the number of bytes copied.
    fn read_into<T: BufMut + ?Sized>(&mut self, limit: VarInt, target: &mut T) -> usize;
}

/// A [`CryptoReceiveBuffer`] that holds the data as fragments keyed by
/// offset, in a [`FragmentedStreamReceiveBuffer`].
#[derive(Debug, Default)]
pub struct FragmentedCryptoReceiveBuffer {
    buffer: FragmentedStreamReceiveBuffer,
}

impl FragmentedCryptoReceiveBuffer {
    /// Creates an empty buffer.
    pub fn new() -> Self {
        Self::default()
    }
}

impl CryptoReceiveBuffer for FragmentedCryptoReceiveBuffer {
    type Chunk = Bytes;

    fn receive(&mut self, offset: VarInt, data: Bytes) {
        let end = VarInt::try_from(data.len())
            .ok()
            .and_then(|len| offset.checked_add(len));
        // A frame that ends beyond the largest offset is rejected when the
        // frame is read, so it does not get here; ignoring it keeps the
        // buffer from panicking if it does.
        let Some(end) = end else {
            return;
        };
        // invariant: `end` is not below `offset`, and the payload ends at
        // `end`, so the input is consistent.
        let input = StreamDataInput::new(offset, end, false, data)
            .expect("the payload spans exactly [offset, end)");
        self.buffer.receive_data(input);
    }

    fn received_end(&self) -> VarInt {
        self.buffer.accounted_end()
    }

    fn read_end(&self) -> VarInt {
        self.buffer.delivered_end()
    }

    fn read_chunk(&mut self, limit: VarInt) -> Option<Bytes> {
        self.buffer.read_chunk(limit)
    }

    fn read_into<T: BufMut + ?Sized>(&mut self, limit: VarInt, target: &mut T) -> usize {
        self.buffer.read_into(limit, target)
    }
}

/// A level whose capacity is below what the level needs.
///
/// The capacity must be at least 4096 bytes (RFC 9000 §7.5) and at least the
/// largest single handshake message, with its four-byte header, that the
/// endpoint can receive at the level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "capacity of {capacity} bytes at the {level:?} level is below the {minimum} bytes it needs"
))]
pub struct CryptoCapacityError {
    /// The level.
    pub level: CryptoLevel,
    /// The capacity given.
    pub capacity: usize,
    /// The least capacity the level needs.
    pub minimum: usize,
}

/// How much each encryption level of an endpoint accepts past its read
/// position, checked against the handshake messages the endpoint receives
/// there; none at a level where its role receives no handshake messages.
///
/// A [`CryptoReceiver`] is made from it and cannot fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoReceiveCapacities {
    initial: LevelCapacity,
    handshake: LevelCapacity,
    one_rtt: LevelCapacity,
}

impl CryptoReceiveCapacities {
    /// The capacities of a server: Initial receives the ClientHello and
    /// Handshake the client's Finished, preceded by its Certificate and
    /// CertificateVerify if `requires_client_certificate`; 1-RTT receives
    /// none.
    ///
    /// # Errors
    ///
    /// [`CryptoCapacityError`] if the capacity of a level is below what the
    /// level needs for messages within `limits`.
    pub fn server(
        limits: MessageLimits,
        requires_client_certificate: bool,
        initial: usize,
        handshake: usize,
    ) -> Result<Self, CryptoCapacityError> {
        use ReceivedMessageType::*;
        let handshake_messages: &[ReceivedMessageType] = if requires_client_certificate {
            &[Certificate, CertificateVerify, Finished]
        } else {
            &[Finished]
        };
        Ok(Self {
            initial: open(CryptoLevel::Initial, initial, &limits, &[ClientHello])?,
            handshake: open(
                CryptoLevel::Handshake,
                handshake,
                &limits,
                handshake_messages,
            )?,
            one_rtt: LevelCapacity::Refused,
        })
    }

    /// The capacities of a client: Initial receives the ServerHello (or
    /// HelloRetryRequest), Handshake the EncryptedExtensions,
    /// CertificateRequest, Certificate, CertificateVerify and Finished, and
    /// 1-RTT the NewSessionTicket.
    ///
    /// # Errors
    ///
    /// [`CryptoCapacityError`] if the capacity of a level is below what the
    /// level needs for messages within `limits`.
    pub fn client(
        limits: MessageLimits,
        initial: usize,
        handshake: usize,
        one_rtt: usize,
    ) -> Result<Self, CryptoCapacityError> {
        use ReceivedMessageType::*;
        Ok(Self {
            initial: open(CryptoLevel::Initial, initial, &limits, &[ServerHello])?,
            handshake: open(
                CryptoLevel::Handshake,
                handshake,
                &limits,
                &[
                    EncryptedExtensions,
                    CertificateRequest,
                    Certificate,
                    CertificateVerify,
                    Finished,
                ],
            )?,
            one_rtt: open(CryptoLevel::OneRtt, one_rtt, &limits, &[NewSessionTicket])?,
        })
    }

    /// How many bytes past its read position `level` accepts; `None` if
    /// the endpoint's role receives no handshake messages there.
    pub fn capacity(&self, level: CryptoLevel) -> Option<usize> {
        let capacity = match level {
            CryptoLevel::Initial => self.initial,
            CryptoLevel::Handshake => self.handshake,
            CryptoLevel::OneRtt => self.one_rtt,
        };
        match capacity {
            LevelCapacity::Open(capacity) => Some(capacity),
            LevelCapacity::Refused => None,
        }
    }
}

/// What one level of [`CryptoReceiveCapacities`] accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LevelCapacity {
    /// The level stores frames up to this many bytes past its read
    /// position.
    Open(usize),
    /// The endpoint's role receives no handshake messages at the level.
    Refused,
}

impl LevelCapacity {
    /// The input of the level as the receiver starts with it.
    fn input<B: Default>(self) -> LevelInput<B> {
        match self {
            LevelCapacity::Open(capacity) => LevelInput::Open {
                buffer: B::default(),
                capacity,
            },
            LevelCapacity::Refused => LevelInput::Refused,
        }
    }
}

/// A CRYPTO frame that cannot be taken.
///
/// Each variant says which transport error code ends the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum CryptoFrameError {
    /// The frame ends beyond what the level can hold past its read
    /// position: CRYPTO_BUFFER_EXCEEDED (0x0d), RFC 9000 §7.5.
    #[snafu(display("CRYPTO data at the {level:?} level exceeds the buffer"))]
    BufferExceeded {
        /// The level of the frame.
        level: CryptoLevel,
    },
    /// The frame is for a level the engine has left and passes the end of
    /// the data received there: PROTOCOL_VIOLATION (0x0a), RFC 9001 §4.1.3.
    #[snafu(display("CRYPTO data at the {level:?} level passes the end of the data received"))]
    BeyondReceivedEnd {
        /// The level of the frame.
        level: CryptoLevel,
    },
    /// The frame has data at a level where this endpoint receives none:
    /// crypto error unexpected_message (0x010a), RFC 9001 §6.
    #[snafu(display("CRYPTO data at a level that receives none"))]
    Refused,
}

/// A move to a level that cannot be made.
///
/// Each variant says which transport error code ends the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum CryptoLevelMoveError {
    /// The level being left has bytes the engine has not read, also bytes
    /// stored ahead of a gap: PROTOCOL_VIOLATION (0x0a), RFC 9001 §4.1.3.
    #[snafu(display("the {level:?} level has CRYPTO bytes that were not read"))]
    UnreadBytes {
        /// The level being left.
        level: CryptoLevel,
    },
    /// The level to move to is not after the one being read: the engine broke
    /// its contract, INTERNAL_ERROR (0x01).
    #[snafu(display("cannot move CRYPTO input from {from:?} to {to:?}"))]
    NotForward {
        /// The level being read.
        from: CryptoLevel,
        /// The level asked for.
        to: CryptoLevel,
    },
}

/// The state of the input at one encryption level.
#[derive(Debug)]
enum LevelInput<B> {
    /// The engine has not left the level: frames are stored in `buffer`, up
    /// to `capacity` bytes past its read position.
    Open { buffer: B, capacity: usize },
    /// The engine left the level: only the end of the data received stays.
    Left { received_end: VarInt },
    /// This endpoint's role receives no handshake messages at the level.
    Refused,
}

/// The CRYPTO input of a connection at all three encryption levels.
///
/// See the [module documentation](self) for the states of a level.
#[derive(Debug)]
pub struct CryptoReceiver<B> {
    reading: CryptoLevel,
    initial: LevelInput<B>,
    handshake: LevelInput<B>,
    one_rtt: LevelInput<B>,
    /// What waits to read, woken when a frame comes at the level read.
    reader: Option<Waker>,
}

impl<B: CryptoReceiveBuffer> CryptoReceiver<B> {
    /// The input with the levels of `capacities`, each open level with an
    /// empty buffer, reading Initial.
    pub fn new(capacities: &CryptoReceiveCapacities) -> Self
    where
        B: Default,
    {
        Self {
            reading: CryptoLevel::Initial,
            initial: capacities.initial.input(),
            handshake: capacities.handshake.input(),
            one_rtt: capacities.one_rtt.input(),
            reader: None,
        }
    }

    /// The level the engine reads.
    pub fn reading(&self) -> CryptoLevel {
        self.reading
    }

    /// Takes the data of a CRYPTO frame at `level`.
    ///
    /// # Errors
    ///
    /// [`CryptoFrameError`], as its variants document, if the frame must end
    /// the connection.
    pub fn receive_frame(
        &mut self,
        level: CryptoLevel,
        offset: VarInt,
        data: Bytes,
    ) -> Result<(), CryptoFrameError> {
        let input = self.input_mut(level);
        // A length that is not a `VarInt`, or an end beyond `VarInt::MAX`,
        // is beyond any capacity.
        let end = VarInt::try_from(data.len())
            .ok()
            .and_then(|len| offset.checked_add(len));
        match input {
            LevelInput::Open { buffer, capacity } => {
                let window_end = VarInt::try_from(*capacity).map_or(VarInt::MAX, |capacity| {
                    buffer.read_end().saturating_add(capacity)
                });
                ensure!(
                    end.is_some_and(|end| end <= window_end),
                    BufferExceededSnafu { level }
                );
                buffer.receive(offset, data);
                if level == self.reading
                    && let Some(reader) = self.reader.take()
                {
                    reader.wake();
                }
                Ok(())
            }
            LevelInput::Left { received_end } => {
                ensure!(
                    end.is_some_and(|end| end <= *received_end),
                    BeyondReceivedEndSnafu { level }
                );
                Ok(())
            }
            LevelInput::Refused => {
                ensure!(data.is_empty(), RefusedSnafu);
                Ok(())
            }
        }
    }

    /// Copies the next contiguous bytes of the level being read into
    /// `target`, as much as fits, and returns how many; zero if none are
    /// ready or the level takes no input.
    pub fn read_into<T: BufMut + ?Sized>(&mut self, target: &mut T) -> usize {
        match self.input_mut(self.reading) {
            LevelInput::Open { buffer, .. } => buffer.read_into(VarInt::MAX, target),
            LevelInput::Left { .. } | LevelInput::Refused => 0,
        }
    }

    /// Moves the engine's reading to `level`, leaving the level being read.
    ///
    /// Only the level being left is checked and changed. A level skipped
    /// over keeps its state: the engine never read it, and frames for it
    /// are still stored or checked as before.
    ///
    /// # Errors
    ///
    /// [`CryptoLevelMoveError`], as its variants document. The component is
    /// unchanged.
    pub fn move_input_to(&mut self, level: CryptoLevel) -> Result<(), CryptoLevelMoveError> {
        let from = self.reading;
        ensure!(level > from, NotForwardSnafu { from, to: level });
        let input = self.input_mut(from);
        if let LevelInput::Open { buffer, .. } = input {
            let received_end = buffer.received_end();
            ensure!(
                received_end <= buffer.read_end(),
                UnreadBytesSnafu { level: from }
            );
            *input = LevelInput::Left { received_end };
        }
        self.reading = level;
        Ok(())
    }

    fn input_mut(&mut self, level: CryptoLevel) -> &mut LevelInput<B> {
        match level {
            CryptoLevel::Initial => &mut self.initial,
            CryptoLevel::Handshake => &mut self.handshake,
            CryptoLevel::OneRtt => &mut self.one_rtt,
        }
    }
}

/// The least capacity of a level that receives `messages`: 4096 bytes or the
/// largest single message with its header.
fn minimum_capacity(limits: &MessageLimits, messages: &[ReceivedMessageType]) -> usize {
    messages
        .iter()
        .map(|&message| {
            // Finished is as long as the hash of the cipher suite, unknown
            // before the suite is chosen: use the longest hash.
            let body = limits
                .limit(message, None)
                .unwrap_or(UNKNOWN_HASH_FINISHED_LEN);
            body as usize + MESSAGE_HEADER_LEN
        })
        .fold(MIN_CAPACITY, usize::max)
}

/// An open level of `capacity`, if it suffices for `messages`.
fn open(
    level: CryptoLevel,
    capacity: usize,
    limits: &MessageLimits,
    messages: &[ReceivedMessageType],
) -> Result<LevelCapacity, CryptoCapacityError> {
    let minimum = minimum_capacity(limits, messages);
    ensure!(
        capacity >= minimum,
        CryptoCapacitySnafu {
            level,
            capacity,
            minimum
        }
    );
    Ok(LevelCapacity::Open(capacity))
}
