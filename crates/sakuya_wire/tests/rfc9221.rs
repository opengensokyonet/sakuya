//! The error code of a DATAGRAM frame that was not negotiated.
use sakuya_wire::{
    frame::{Extensions, codec::ReadFrameHostExt as _},
    v1::transport_error::TransportErrorCode,
    var_int::VarInt,
};

/// RFC 9221 §3: "An endpoint that receives a DATAGRAM frame when it has not
/// indicated support via the transport parameter MUST terminate the
/// connection with an error of type PROTOCOL_VIOLATION."
#[test]
fn undeclared_datagram_is_a_protocol_violation() {
    for (bytes, frame_type) in [(&[0x30][..], 0x30u8), (&[0x31, 0x00], 0x31)] {
        let mut input = bytes;
        let error = input.sync_read_frame_unpin(Extensions::NONE).unwrap_err();
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::PROTOCOL_VIOLATION,
            "{bytes:02x?}"
        );
        assert_eq!(error.frame_type(), Some(VarInt::from(frame_type)));
    }
}

/// RFC 9000 §12.4 keeps applying to every other type that is not understood,
/// including RESET_STREAM_AT, whose draft names no code for this case.
#[test]
fn other_unknown_types_stay_frame_encoding_errors() {
    for bytes in [&[0x1f][..], &[0x24], &[0x2f], &[0x32], &[0x3f]] {
        let mut input = bytes;
        let error = input.sync_read_frame_unpin(Extensions::NONE).unwrap_err();
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FRAME_ENCODING_ERROR,
            "{bytes:02x?}"
        );
    }
}
