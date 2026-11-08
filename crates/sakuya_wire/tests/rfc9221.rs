//! DATAGRAM frames (RFC 9221) in a frame set, through the public interface.
#![cfg(feature = "datagram")]
use core::marker::PhantomData;
use sakuya_wire::{
    assert_frame_types_disjoint, datagram,
    frame::{PartSum, codec::ReadFrameHostExt as _},
    v1::{self, frame::Frame, transport_error::TransportErrorCode},
    var_int::VarInt,
};

type Set = PartSum<v1::Part, datagram::Part>;
assert_frame_types_disjoint!(Set);

/// RFC 9221 §4: type 0x30 extends to the end of the packet, type 0x31 has a
/// Length field.
#[test]
fn a_set_with_datagram_reads_both_types() {
    let mut input = &[0x31, 0x02, b'h', b'i', 0x30, b'e', b'n', b'd'][..];
    let Ok(PartSum::Rest(with)) = input.sync_read_frame_unpin(PhantomData::<Set>) else {
        panic!()
    };
    assert_eq!(*with.data(), b"hi");
    let Ok(PartSum::Rest(without)) = input.sync_read_frame_unpin(PhantomData::<Set>) else {
        panic!()
    };
    assert_eq!(*without.data(), b"end");
    assert!(input.is_empty());
    // RFC 9221 §3 limits the frame, type and Length included, to the
    // max_datagram_frame_size the receiver sent; reading leaves the check to
    // the receiver, which compares the size of the frame.
    assert_eq!((with.encoded_len(), without.encoded_len()), (4, 4));
}

/// The frames of version 1 stay in the part of version 1.
#[test]
fn a_set_with_datagram_reads_the_frames_of_version_1() {
    let mut input = &[0x01][..];
    assert!(matches!(
        input.sync_read_frame_unpin(PhantomData::<Set>),
        Ok(PartSum::First(Frame::Ping(_)))
    ));
}

/// Without the DATAGRAM part, 0x30 and 0x31 are unknown types: RFC 9000
/// §12.4, FRAME_ENCODING_ERROR.
#[test]
fn a_set_without_datagram_does_not_know_its_types() {
    for (bytes, frame_type) in [(&[0x30][..], 0x30u8), (&[0x31, 0x00], 0x31)] {
        let mut input = bytes;
        let error = input
            .sync_read_frame_unpin(PhantomData::<v1::Part>)
            .unwrap_err();
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FRAME_ENCODING_ERROR,
            "{bytes:02x?}"
        );
        assert_eq!(error.frame_type(), Some(VarInt::from(frame_type)));
    }
}
