//! The frames of version 1 that frame sources write: which kind each is,
//! [`DelimitedFrame`] or [`ToPacketEndFrame`], and its properties.
//!
//! ACK and CONNECTION_CLOSE are [`AckOnlyClass`]: they do not count in the
//! bytes in flight, and do not elicit an acknowledgment; every other frame
//! here is [`InFlightClass`] and elicits one (RFC 9002 §2). PATH_CHALLENGE
//! and PATH_RESPONSE expand their datagram (RFC 9000 §8.2.1, §8.2.2).
//! STREAM is delimited with a Length field and extends to the end of the
//! packet without one. No frame source writes CONNECTION_CLOSE: only the
//! close packet of a link path carries it.
//!
//! PADDING is not here: only the packet writer writes it. The frames of
//! extensions, behind features of `sakuya_wire` this crate does not enable,
//! are not here either.

use bytes::{Buf, BytesMut};
use sakuya_wire::{
    frame::NoLength,
    v1::frame::{
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
    },
    var_int::VarIntWidth,
};

use crate::write::{AckOnlyClass, DelimitedFrame, InFlightClass, ToPacketEndFrame};

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
    use bytes::Bytes;
    use sakuya_wire::{
        v1::frame::{FrameType, set::FrameKind as _},
        var_int::{VarInt, VarIntField},
    };

    use super::*;
    use crate::write::{FlightClass, FlightClassType};

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
