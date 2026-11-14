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
        ack::{AckFrame, codec::WriteAckFrameHostExt as _},
        connection_close::{ConnectionCloseFrame, codec::WriteConnectionCloseFrameHostExt as _},
        crypto::{CryptoFrame, codec::WriteCryptoFrameHostExt as _},
        data_blocked::{DataBlockedFrame, codec::WriteDataBlockedFrameHostExt as _},
        handshake_done::{HandshakeDoneFrame, codec::WriteHandshakeDoneFrameHostExt as _},
        max_data::{MaxDataFrame, codec::WriteMaxDataFrameHostExt as _},
        max_stream_data::{MaxStreamDataFrame, codec::WriteMaxStreamDataFrameHostExt as _},
        max_streams::{MaxStreamsFrame, codec::WriteMaxStreamsFrameHostExt as _},
        new_connection_id::{NewConnectionIdFrame, codec::WriteNewConnectionIdFrameHostExt as _},
        new_token::{NewTokenFrame, codec::WriteNewTokenFrameHostExt as _},
        path_challenge::{PathChallengeFrame, codec::WritePathChallengeFrameHostExt as _},
        path_response::{PathResponseFrame, codec::WritePathResponseFrameHostExt as _},
        ping::{PingFrame, codec::WritePingFrameHostExt as _},
        reset_stream::{ResetStreamFrame, codec::WriteResetStreamFrameHostExt as _},
        retire_connection_id::{
            RetireConnectionIdFrame, codec::WriteRetireConnectionIdFrameHostExt as _,
        },
        stop_sending::{StopSendingFrame, codec::WriteStopSendingFrameHostExt as _},
        stream::{
            StreamFrame,
            codec::{
                WriteStreamFrameWithLengthHostExt as _, WriteStreamFrameWithoutLengthHostExt as _,
            },
        },
        stream_data_blocked::{
            StreamDataBlockedFrame, codec::WriteStreamDataBlockedFrameHostExt as _,
        },
        streams_blocked::{StreamsBlockedFrame, codec::WriteStreamsBlockedFrameHostExt as _},
    },
    var_int::VarIntWidth,
};

use crate::write::{AckOnlyClass, DelimitedFrame, InFlightClass, ToPacketEndFrame};

/// The invariant of every write here: a `BytesMut` takes every byte, so
/// writing into one does not fail.
const TAKES_EVERY_BYTE: &str = "a BytesMut takes every byte";

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
                buffer.$write(self).expect(TAKES_EVERY_BYTE);
            }
        }
    )*};
}

delimited! {
    AckFrame => sync_write_ack_frame_unpin, AckOnlyClass, ack_eliciting = false;
    PingFrame => sync_write_ping_frame_unpin, InFlightClass, ack_eliciting = true;
    HandshakeDoneFrame => sync_write_handshake_done_frame_unpin, InFlightClass, ack_eliciting = true;
    ResetStreamFrame => sync_write_reset_stream_frame_unpin, InFlightClass, ack_eliciting = true;
    StopSendingFrame => sync_write_stop_sending_frame_unpin, InFlightClass, ack_eliciting = true;
    MaxDataFrame => sync_write_max_data_frame_unpin, InFlightClass, ack_eliciting = true;
    MaxStreamDataFrame => sync_write_max_stream_data_frame_unpin, InFlightClass, ack_eliciting = true;
    MaxStreamsFrame => sync_write_max_streams_frame_unpin, InFlightClass, ack_eliciting = true;
    DataBlockedFrame => sync_write_data_blocked_frame_unpin, InFlightClass, ack_eliciting = true;
    StreamDataBlockedFrame => sync_write_stream_data_blocked_frame_unpin, InFlightClass, ack_eliciting = true;
    StreamsBlockedFrame => sync_write_streams_blocked_frame_unpin, InFlightClass, ack_eliciting = true;
    NewConnectionIdFrame => sync_write_new_connection_id_frame_unpin, InFlightClass, ack_eliciting = true;
    RetireConnectionIdFrame => sync_write_retire_connection_id_frame_unpin, InFlightClass, ack_eliciting = true;
    PathChallengeFrame => sync_write_path_challenge_frame_unpin, InFlightClass, ack_eliciting = true, expands = true;
    PathResponseFrame => sync_write_path_response_frame_unpin, InFlightClass, ack_eliciting = true, expands = true;
}

impl<D: Buf> DelimitedFrame for CryptoFrame<D> {
    type Class = InFlightClass;
    const ACK_ELICITING: bool = true;

    fn encoded_len(&self) -> usize {
        CryptoFrame::encoded_len(self)
    }

    fn write_to(self, buffer: &mut BytesMut) {
        buffer
            .sync_write_crypto_frame_unpin(self)
            .expect(TAKES_EVERY_BYTE);
    }
}

impl<D: Buf> DelimitedFrame for ConnectionCloseFrame<D> {
    type Class = AckOnlyClass;
    const ACK_ELICITING: bool = false;

    fn encoded_len(&self) -> usize {
        ConnectionCloseFrame::encoded_len(self)
    }

    fn write_to(self, buffer: &mut BytesMut) {
        buffer
            .sync_write_connection_close_frame_unpin(self)
            .expect(TAKES_EVERY_BYTE);
    }
}

impl<D: Buf> DelimitedFrame for NewTokenFrame<D> {
    type Class = InFlightClass;
    const ACK_ELICITING: bool = true;

    fn encoded_len(&self) -> usize {
        NewTokenFrame::encoded_len(self)
    }

    fn write_to(self, buffer: &mut BytesMut) {
        buffer
            .sync_write_new_token_frame_unpin(self)
            .expect(TAKES_EVERY_BYTE);
    }
}

impl<D: Buf> DelimitedFrame for StreamFrame<D, VarIntWidth> {
    type Class = InFlightClass;
    const ACK_ELICITING: bool = true;

    fn encoded_len(&self) -> usize {
        StreamFrame::encoded_len(self)
    }

    fn write_to(self, buffer: &mut BytesMut) {
        buffer
            .sync_write_stream_frame_with_length_unpin(self)
            .expect(TAKES_EVERY_BYTE);
    }
}

impl<D: Buf> ToPacketEndFrame for StreamFrame<D, NoLength> {
    type Class = InFlightClass;
    const ACK_ELICITING: bool = true;

    fn encoded_len(&self) -> usize {
        StreamFrame::encoded_len(self)
    }

    fn write_to(self, buffer: &mut BytesMut) {
        buffer
            .sync_write_stream_frame_without_length_unpin(self)
            .expect(TAKES_EVERY_BYTE);
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
