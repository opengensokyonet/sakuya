//! Tests of frame sets: the lists of parts, the Frame Type values parts
//! claim, and reading frames of a set.
use super::{
    FrameSet, FrameTypeValues, Frames,
    codec::{ReadFrameError, read_frame_type},
};
use crate as v1;
use crate::var_int::VarInt;
use crate::{
    frame::{
        Frame, FrameRun, FrameType,
        codec::read_fields,
        padding::{PaddingFrame, PaddingRun},
        ping::PingFrame,
    },
    transport_error::TransportErrorCode,
};
use core::{marker::PhantomData, num::NonZeroUsize, ops::RangeInclusive};
use sakuya_wire::parts::HList;

fn vi(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

const fn range(start: u32, end: u32) -> RangeInclusive<VarInt> {
    RangeInclusive::new(VarInt::from_u32(start), VarInt::from_u32(end))
}

#[test]
fn ranges_are_disjoint_unless_they_share_a_value() {
    static LOW: FrameTypeValues = FrameTypeValues::new(&[range(0x00, 0x1e)]);
    static EDGE: FrameTypeValues = FrameTypeValues::new(&[range(0x1e, 0x1e)]);
    static ABOVE: FrameTypeValues = FrameTypeValues::new(&[range(0x1f, 0x23), range(0x30, 0x31)]);
    static EMPTY: FrameTypeValues = FrameTypeValues::new(&[range(0x10, 0x01)]);
    static NONE: FrameTypeValues = FrameTypeValues::new(&[]);
    assert!(!LOW.is_disjoint(&EDGE));
    assert!(!EDGE.is_disjoint(&LOW));
    assert!(LOW.is_disjoint(&ABOVE));
    assert!(ABOVE.is_disjoint(&LOW));
    // An empty range claims nothing, not even the values between its ends.
    assert!(LOW.is_disjoint(&EMPTY));
    assert!(LOW.is_disjoint(&NONE));
    assert!(!LOW.is_disjoint(&LOW));
    assert!(LOW.contains(vi(0x1e)) && !LOW.contains(vi(0x1f)));
    assert!(ABOVE.contains(vi(0x31)) && !ABOVE.contains(vi(0x24)));
}

#[test]
fn a_part_overlapping_itself_is_not_disjoint() {
    const { assert!(<HList![v1::Part] as FrameSet>::PARTS_DISJOINT) };
    const { assert!(!<HList![v1::Part, v1::Part] as FrameSet>::PARTS_DISJOINT) };
    // The values of a list are those of all its parts.
    let values = <HList![v1::Part, v1::Part] as FrameSet>::FRAME_TYPE_VALUES;
    assert!(values.contains(vi(0x00)) && values.contains(vi(0x1e)));
    assert!(!values.contains(vi(0x1f)));
}

/// RFC 9000 §12.4: a set of version 1 alone does not know the types of the
/// extensions, and reports them as it reports any unknown type.
#[test]
fn version_1_alone_reports_extension_types_as_unknown() {
    for encoding in [&[0x24, 0, 0, 0, 0][..], &[0x30, 1], &[0x31, 0]] {
        let mut frames = Frames::new(encoding, PhantomData::<HList![v1::Part]>);
        let error = frames.next().unwrap().unwrap_err();
        assert!(
            matches!(error, ReadFrameError::UnknownType { frame_type } if frame_type == vi(u32::from(encoding[0]))),
            "{error:?}"
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FRAME_ENCODING_ERROR
        );
        assert_eq!(
            error.to_string(),
            format!("unknown frame type {:#x}", encoding[0])
        );
        assert!(frames.next().is_none());
        assert_eq!(frames.offset(), 0);
    }
}

#[test]
fn a_set_of_version_1_alone_reads_its_frame_by_type() {
    let mut frames = Frames::new(&[0x10, 0x05, 0x01][..], PhantomData::<HList![v1::Part]>);
    let run = frames.next().unwrap().unwrap().extract();
    assert!(matches!(run, FrameRun::MaxData(max_data) if max_data.maximum_data().get() == vi(5)));
    let run = frames.next().unwrap().unwrap().extract();
    assert!(matches!(run, FrameRun::Ping(_)));
    assert!(frames.next().is_none());
}

/// The items of [`Frames`] are runs: consecutive PADDING frames are one, and
/// every other frame is one of its own.
#[test]
fn consecutive_padding_is_one_run() {
    type Set = HList![v1::Part];
    // Three PADDING, PING, two PADDING.
    let payload = [0, 0, 0, 0x01, 0, 0];
    let runs: Vec<FrameRun<&[u8]>> = Frames::new(&payload[..], PhantomData::<Set>)
        .map(|run| run.unwrap().extract())
        .collect();
    let padding = |len| FrameRun::Padding(PaddingRun::new(NonZeroUsize::new(len).unwrap()));
    assert_eq!(runs, [padding(3), FrameRun::Ping(PingFrame), padding(2)]);
}

/// The Frame Type is read apart from the fields; `read_fields` of version 1
/// reads frames, not runs: one PADDING frame, whatever follows it.
#[test]
fn read_fields_reads_one_padding_frame() {
    let mut input = &[0, 0, 0, 0x01][..];
    let type_value = read_frame_type(&mut input, PhantomData::<HList![v1::Part]>)
        .unwrap()
        .extract();
    assert_eq!(type_value.kind(), FrameType::Padding);
    let frame: Frame<&[u8]> = read_fields(&mut input, type_value).unwrap();
    assert_eq!(frame, Frame::Padding(PaddingFrame));
    assert_eq!(input, [0, 0, 0x01]);
}
