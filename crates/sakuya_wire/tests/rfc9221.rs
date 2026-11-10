//! DATAGRAM frames (RFC 9221) in a frame set, through the public interface.
#![cfg(feature = "datagram")]
use core::marker::PhantomData;
use sakuya_wire::{
    assert_frame_types_disjoint, datagram,
    parts::HList,
    v1::{
        self,
        frame::{FrameRun, set::Frames},
        transport_error::TransportErrorCode,
    },
    var_int::VarInt,
};

type Set = HList![v1::Part, datagram::Part];
assert_frame_types_disjoint!(Set);

/// RFC 9221 §4: type 0x30 extends to the end of the packet, type 0x31 has a
/// Length field.
#[test]
fn a_set_with_datagram_reads_both_types() {
    let payload = [0x31, 0x02, b'h', b'i', 0x30, b'e', b'n', b'd'];
    let mut frames = Frames::new(&payload[..], PhantomData::<Set>);
    let Some(Ok(with)) = frames.next() else {
        panic!()
    };
    let with: datagram::DatagramFrame<&[u8]> = with.uninject().ok().unwrap();
    assert_eq!(*with.data(), b"hi");
    let Some(Ok(without)) = frames.next() else {
        panic!()
    };
    let without: datagram::DatagramFrame<&[u8]> = without.uninject().ok().unwrap();
    assert_eq!(*without.data(), b"end");
    assert!(frames.next().is_none());
    // RFC 9221 §3 limits the frame, type and Length included, to the
    // max_datagram_frame_size the receiver sent; reading leaves the check to
    // the receiver, which compares the size of the frame.
    assert_eq!((with.encoded_len(), without.encoded_len()), (4, 4));
}

/// The frames of version 1 stay in the part of version 1.
#[test]
fn a_set_with_datagram_reads_the_frames_of_version_1() {
    let mut frames = Frames::new(&[0x01][..], PhantomData::<Set>);
    let run = frames.next().unwrap().unwrap();
    assert!(matches!(
        run.get::<FrameRun<&[u8]>, _>(),
        Some(FrameRun::Ping(_))
    ));
}

/// Without the DATAGRAM part, 0x30 and 0x31 are unknown types: RFC 9000
/// §12.4, FRAME_ENCODING_ERROR.
#[test]
fn a_set_without_datagram_does_not_know_its_types() {
    for (bytes, frame_type) in [(&[0x30][..], 0x30u8), (&[0x31, 0x00], 0x31)] {
        let error = Frames::new(bytes, PhantomData::<HList![v1::Part]>)
            .next()
            .unwrap()
            .unwrap_err();
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FRAME_ENCODING_ERROR,
            "{bytes:02x?}"
        );
        assert_eq!(error.frame_type(), Some(VarInt::from(frame_type)));
    }
}
