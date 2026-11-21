//! How a frame is written into a packet: whether it has its own boundary
//! ([`DelimitedFrame`]) or extends to the end of the packet
//! ([`ToPacketEndFrame`]), and the properties its type fixes: whether it
//! counts in the bytes in flight ([`FlightClass`], as a type:
//! [`FlightClassType`]), whether it elicits an acknowledgment, and whether
//! a datagram carrying it is expanded.
//!
//! The frames of version 1 implement them here. ACK and CONNECTION_CLOSE
//! are [`AckOnlyClass`]: they do not count in the bytes in flight, and do
//! not elicit an acknowledgment; every other frame here is
//! [`InFlightClass`] and elicits one (RFC 9002 §2). PATH_CHALLENGE and
//! PATH_RESPONSE expand their datagram (RFC 9000 §8.2.1, §8.2.2). STREAM is
//! delimited with a Length field and extends to the end of the packet
//! without one. PADDING is not here: only a packet writer writes it.

use bytes::{Buf, BytesMut};

use crate::frame::{
    ack::{AckFrame, codec::write_ack_frame},
    connection_close::{ConnectionCloseFrame, codec::write_connection_close_frame},
    crypto::{CryptoFrame, codec::write_crypto_frame},
    data_blocked::{DataBlockedFrame, codec::write_data_blocked_frame},
    handshake_done::{HandshakeDoneFrame, codec::write_handshake_done_frame},
    max_data::{MaxDataFrame, codec::write_max_data_frame},
    max_stream_data::{MaxStreamDataFrame, codec::write_max_stream_data_frame},
    max_streams::{MaxStreamsFrame, codec::write_max_streams_frame},
    new_connection_id::{NewConnectionIdFrame, codec::write_new_connection_id_frame},
    new_token::{NewTokenFrame, codec::write_new_token_frame},
    path_challenge::{PathChallengeFrame, codec::write_path_challenge_frame},
    path_response::{PathResponseFrame, codec::write_path_response_frame},
    ping::{PingFrame, codec::write_ping_frame},
    reset_stream::{ResetStreamFrame, codec::write_reset_stream_frame},
    retire_connection_id::{RetireConnectionIdFrame, codec::write_retire_connection_id_frame},
    stop_sending::{StopSendingFrame, codec::write_stop_sending_frame},
    stream::{
        StreamFrame,
        codec::{write_stream_frame_with_length, write_stream_frame_without_length},
    },
    stream_data_blocked::{StreamDataBlockedFrame, codec::write_stream_data_blocked_frame},
    streams_blocked::{StreamsBlockedFrame, codec::write_streams_blocked_frame},
};
use crate::{frame::NoLength, var_int::VarIntWidth};

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

impl FlightClassType for AckOnlyClass {
    const FLIGHT_CLASS: FlightClass = FlightClass::AckOnly;
}

impl FlightClassType for InFlightClass {
    const FLIGHT_CLASS: FlightClass = FlightClass::InFlight;
}

// ---- the two kinds of frames ----

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

// ---- the frames of version 1 ----

/// Implement [`DelimitedFrame`] for frames without a payload type.
macro_rules! delimited {
    ($($frame:ty => $write:ident, $class:ty, ack_eliciting = $ack:expr $(, expands = $expands:expr)?;)*) => {$(
        impl DelimitedFrame for $frame {
            type Class = $class;
            const ACK_ELICITING: bool = $ack;
            $(const EXPANDS_DATAGRAM: bool = $expands;)?

            fn encoded_len(&self) -> usize {
                <$frame>::encoded_len(self)
            }

            fn write_to(self, buffer: &mut BytesMut) {
                $write(buffer, self);
            }
        }
    )*};
}

delimited! {
    AckFrame => write_ack_frame, AckOnlyClass, ack_eliciting = false;
    PingFrame => write_ping_frame, InFlightClass, ack_eliciting = true;
    HandshakeDoneFrame => write_handshake_done_frame, InFlightClass, ack_eliciting = true;
    ResetStreamFrame => write_reset_stream_frame, InFlightClass, ack_eliciting = true;
    StopSendingFrame => write_stop_sending_frame, InFlightClass, ack_eliciting = true;
    MaxDataFrame => write_max_data_frame, InFlightClass, ack_eliciting = true;
    MaxStreamDataFrame => write_max_stream_data_frame, InFlightClass, ack_eliciting = true;
    MaxStreamsFrame => write_max_streams_frame, InFlightClass, ack_eliciting = true;
    DataBlockedFrame => write_data_blocked_frame, InFlightClass, ack_eliciting = true;
    StreamDataBlockedFrame => write_stream_data_blocked_frame, InFlightClass, ack_eliciting = true;
    StreamsBlockedFrame => write_streams_blocked_frame, InFlightClass, ack_eliciting = true;
    NewConnectionIdFrame => write_new_connection_id_frame, InFlightClass, ack_eliciting = true;
    RetireConnectionIdFrame => write_retire_connection_id_frame, InFlightClass, ack_eliciting = true;
    PathChallengeFrame => write_path_challenge_frame, InFlightClass, ack_eliciting = true, expands = true;
    PathResponseFrame => write_path_response_frame, InFlightClass, ack_eliciting = true, expands = true;
}

impl<D: Buf> DelimitedFrame for CryptoFrame<D> {
    type Class = InFlightClass;
    const ACK_ELICITING: bool = true;

    fn encoded_len(&self) -> usize {
        CryptoFrame::encoded_len(self)
    }

    fn write_to(self, buffer: &mut BytesMut) {
        write_crypto_frame(buffer, self);
    }
}

impl<D: Buf> DelimitedFrame for ConnectionCloseFrame<D> {
    type Class = AckOnlyClass;
    const ACK_ELICITING: bool = false;

    fn encoded_len(&self) -> usize {
        ConnectionCloseFrame::encoded_len(self)
    }

    fn write_to(self, buffer: &mut BytesMut) {
        write_connection_close_frame(buffer, self);
    }
}

impl<D: Buf> DelimitedFrame for NewTokenFrame<D> {
    type Class = InFlightClass;
    const ACK_ELICITING: bool = true;

    fn encoded_len(&self) -> usize {
        NewTokenFrame::encoded_len(self)
    }

    fn write_to(self, buffer: &mut BytesMut) {
        write_new_token_frame(buffer, self);
    }
}

impl<D: Buf> DelimitedFrame for StreamFrame<D, VarIntWidth> {
    type Class = InFlightClass;
    const ACK_ELICITING: bool = true;

    fn encoded_len(&self) -> usize {
        StreamFrame::encoded_len(self)
    }

    fn write_to(self, buffer: &mut BytesMut) {
        write_stream_frame_with_length(buffer, self);
    }
}

impl<D: Buf> ToPacketEndFrame for StreamFrame<D, NoLength> {
    type Class = InFlightClass;
    const ACK_ELICITING: bool = true;

    fn encoded_len(&self) -> usize {
        StreamFrame::encoded_len(self)
    }

    fn write_to(self, buffer: &mut BytesMut) {
        write_stream_frame_without_length(buffer, self);
    }
}

#[cfg(test)]
mod tests {
    use crate::frame::{FrameType, set::FrameKind as _};
    use crate::var_int::{VarInt, VarIntField};
    use bytes::Bytes;

    use super::*;

    fn class<F: DelimitedFrame>() -> FlightClass {
        F::Class::FLIGHT_CLASS
    }

    /// The static properties agree with the ones `sakuya_wire` gives each
    /// kind of frame.
    #[test]
    fn the_properties_agree_with_the_frame_kinds() {
        fn agree<F: DelimitedFrame>(kind: FrameType) {
            assert_eq!(F::ACK_ELICITING, kind.is_ack_eliciting(), "{kind:?}");
            assert_eq!(
                class::<F>() == FlightClass::InFlight,
                kind.counts_in_flight(),
                "{kind:?}"
            );
        }
        agree::<AckFrame>(FrameType::Ack);
        agree::<PingFrame>(FrameType::Ping);
        agree::<CryptoFrame<Bytes>>(FrameType::Crypto);
        agree::<HandshakeDoneFrame>(FrameType::HandshakeDone);
        agree::<NewTokenFrame<Bytes>>(FrameType::NewToken);
        agree::<MaxDataFrame>(FrameType::MaxData);
        agree::<PathChallengeFrame>(FrameType::PathChallenge);
        agree::<PathResponseFrame>(FrameType::PathResponse);
        agree::<NewConnectionIdFrame>(FrameType::NewConnectionId);
        agree::<ConnectionCloseFrame<Bytes>>(FrameType::ConnectionCloseTransport);
        agree::<ConnectionCloseFrame<Bytes>>(FrameType::ConnectionCloseApplication);
        const {
            assert!(PathChallengeFrame::EXPANDS_DATAGRAM && PathResponseFrame::EXPANDS_DATAGRAM);
            assert!(!PingFrame::EXPANDS_DATAGRAM && !AckFrame::EXPANDS_DATAGRAM);
        }
    }

    #[test]
    fn a_frame_writes_its_encoded_length() {
        let frame = MaxDataFrame::new(VarIntField::shortest(VarInt::from(70_000u32)));
        let len = DelimitedFrame::encoded_len(&frame);
        let mut buffer = BytesMut::new();
        DelimitedFrame::write_to(frame, &mut buffer);
        assert_eq!(buffer.len(), len);
        assert_eq!(buffer[0], 0x10);
    }
}
