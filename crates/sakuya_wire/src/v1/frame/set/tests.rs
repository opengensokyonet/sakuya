//! Tests of frame sets: the lists of parts, the Frame Type values parts
//! claim, and reading frames of a set.
use super::{
    FrameSet, FrameTypeValues, Frames,
    codec::{ReadFrameError, ReadFrameTypeHostExt as _},
};
use crate::{
    parts::HList,
    v1::{
        self,
        frame::{
            Frame, FrameRun, FrameType,
            codec::ReadFieldsHostExt as _,
            padding::{PaddingFrame, PaddingRun},
            ping::PingFrame,
        },
        transport_error::TransportErrorCode,
    },
    var_int::VarInt,
};
use core::{marker::PhantomData, num::NonZeroUsize, ops::RangeInclusive};

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
    let (kind, value) = input
        .sync_read_frame_type_unpin(PhantomData::<HList![v1::Part]>)
        .unwrap();
    assert_eq!(kind.extract(), FrameType::Padding);
    let frame: Frame<&[u8]> = input
        .sync_read_fields_unpin(FrameType::Padding, value)
        .unwrap();
    assert_eq!(frame, Frame::Padding(PaddingFrame));
    assert_eq!(input, [0, 0, 0x01]);
}

#[cfg(all(feature = "reset_stream_at", feature = "datagram"))]
mod three_parts {
    use super::vi;
    use crate::{
        assert_frame_types_disjoint, datagram,
        parts::{HList, PartsError},
        reset_stream_at,
        v1::{
            self,
            encryption_level::EncryptionLevel,
            frame::{
                FrameRun, FrameType,
                codec::ReadFieldsError,
                set::{FrameFieldsError, FrameKind, FrameSet, Frames, codec::ReadFrameError},
            },
            role::Role,
            transport_error::TransportErrorCode,
        },
    };
    use core::marker::PhantomData;

    type Set = HList![v1::Part, reset_stream_at::Part, datagram::Part];
    // The same parts, with version 1 not first.
    type Reordered = HList![datagram::Part, v1::Part, reset_stream_at::Part];
    assert_frame_types_disjoint!(Set);
    assert_frame_types_disjoint!(Reordered);

    const SET: PhantomData<Set> = PhantomData;

    #[test]
    fn each_frame_goes_to_its_part() {
        // MAX_DATA 7; RESET_STREAM_AT on stream 4 with final size 9 and
        // reliable size 5; DATAGRAM of two bytes; three PADDING; PING.
        let payload = [
            0x10, 0x07, 0x24, 0x04, 0x00, 0x09, 0x05, 0x31, 0x02, b'h', b'i', 0, 0, 0, 0x01,
        ];

        // The iterator gives the run of each part, taken out by its type:
        // the frame of an extension, and for version 1 a frame or a run of
        // PADDING.
        let runs: Vec<_> = Frames::new(&payload[..], SET)
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(runs.len(), 5);
        assert!(matches!(
            runs[0].get::<FrameRun<&[u8]>, _>(),
            Some(FrameRun::MaxData(frame)) if frame.maximum_data().get() == vi(7)
        ));
        let frame = runs[1]
            .get::<reset_stream_at::ResetStreamAtFrame, _>()
            .unwrap();
        assert_eq!(frame.final_size().get(), vi(9));
        assert_eq!(frame.reliable_size().get(), vi(5));
        let frame = runs[2].get::<datagram::DatagramFrame<&[u8]>, _>().unwrap();
        assert_eq!(*frame.data(), b"hi");
        assert!(matches!(
            runs[3].get::<FrameRun<&[u8]>, _>(),
            Some(FrameRun::Padding(padding)) if padding.len().get() == 3
        ));
        assert!(matches!(
            runs[4].get::<FrameRun<&[u8]>, _>(),
            Some(FrameRun::Ping(_))
        ));
    }

    /// The same code takes a run out of a set whatever the order of its
    /// parts; the sum keeps the order of the list.
    #[test]
    fn a_frame_is_taken_out_by_type_whatever_the_order() {
        let payload = [0x10, 0x07, 0, 0, 0x31, 0x01, b'x'];
        let mut frames = Frames::new(&payload[..], PhantomData::<Reordered>);
        let frame = frames.next().unwrap().unwrap();
        assert!(matches!(
            frame.get::<FrameRun<&[u8]>, _>(),
            Some(FrameRun::MaxData(_))
        ));
        let frame = frames.next().unwrap().unwrap();
        assert!(matches!(
            frame.get::<FrameRun<&[u8]>, _>(),
            Some(FrameRun::Padding(padding)) if padding.len().get() == 2
        ));
        let frame = frames.next().unwrap().unwrap();
        assert!(frame.get::<datagram::DatagramFrame<&[u8]>, _>().is_some());
        assert!(frames.next().is_none());
    }

    #[test]
    fn field_failures_come_from_their_part() {
        let read =
            |encoding: &'static [u8]| Frames::new(encoding, SET).next().unwrap().unwrap_err();
        // DATAGRAM announces five bytes and holds one.
        let error = read(&[0x31, 0x05, b'x']);
        let ReadFrameError::Fields {
            source: PartsError(sum),
        } = &error
        else {
            panic!("{error:?}")
        };
        assert!(matches!(
            sum.get::<datagram::codec::ReadDatagramFrameError<_>, _>(),
            Some(datagram::codec::ReadDatagramFrameError::Data { .. })
        ));
        assert!(error.is_incomplete());
        assert_eq!(error.frame_type(), Some(vi(0x31)));
        assert_eq!(error.to_string(), "DATAGRAM data read failed");
        // RESET_STREAM_AT with a reliable size beyond its final size.
        let error = read(&[0x24, 0x00, 0x00, 0x05, 0x06]);
        let ReadFrameError::Fields {
            source: PartsError(sum),
        } = &error
        else {
            panic!("{error:?}")
        };
        let source = sum
            .get::<reset_stream_at::codec::ReadResetStreamAtFrameError<_>, _>()
            .unwrap();
        assert!(matches!(
            source,
            reset_stream_at::codec::ReadResetStreamAtFrameError::ReliableSizeAboveFinalSize { .. }
        ));
        assert_eq!(source.frame_type(), vi(0x24));
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FRAME_ENCODING_ERROR
        );
        // A version 1 frame cut short.
        let error = read(&[0x06, 0x00, 0x04, 0xaa]);
        let ReadFrameError::Fields {
            source: PartsError(sum),
        } = &error
        else {
            panic!("{error:?}")
        };
        assert!(matches!(
            sum.get::<ReadFieldsError<_>, _>(),
            Some(ReadFieldsError::Crypto { .. })
        ));
        assert_eq!(error.frame_type(), Some(vi(0x06)));
        // The failures of the Frame Type are those of every set.
        assert!(matches!(read(&[0x32]), ReadFrameError::UnknownType { .. }));
        let error = read(&[0x40, 0x30]);
        assert!(matches!(error, ReadFrameError::LongerTypeEncoding { .. }));
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::PROTOCOL_VIOLATION
        );
    }

    #[test]
    fn the_kind_of_the_set_answers_for_its_part() {
        let kind = |value: u32| <Set as FrameSet>::kind_of(vi(value)).unwrap();
        assert_eq!(kind(0x07).get::<FrameType, _>(), Some(&FrameType::NewToken));
        assert_eq!(
            kind(0x24).get::<reset_stream_at::FrameType, _>(),
            Some(&reset_stream_at::FrameType::ResetStreamAt)
        );
        assert_eq!(
            kind(0x30).get::<datagram::FrameType, _>(),
            Some(&datagram::FrameType::Datagram)
        );
        assert_eq!(<Set as FrameSet>::kind_of(vi(0x1f)), None);
        // NEW_TOKEN: only a client receives it, only in 1-RTT packets.
        assert!(kind(0x07).receivable_by(Role::Client));
        assert!(!kind(0x07).receivable_by(Role::Server));
        assert!(!kind(0x07).can_appear_in(EncryptionLevel::ZeroRtt));
        // PATH_CHALLENGE is probing; the extension frames are not.
        assert!(kind(0x1a).is_probing());
        assert!(!kind(0x24).is_probing() && !kind(0x31).is_probing());
        assert!(kind(0x31).receivable_by(Role::Server));
        assert!(kind(0x24).can_appear_in(EncryptionLevel::ZeroRtt));
        assert!(!kind(0x31).can_appear_in(EncryptionLevel::Handshake));
        assert!(kind(0x24).is_ack_eliciting() && kind(0x30).counts_in_flight());
        assert!(!kind(0x02).is_ack_eliciting() && !kind(0x02).counts_in_flight());
    }

    #[test]
    fn overlapping_parts_anywhere_in_the_set_are_found() {
        const { assert!(<Set as FrameSet>::PARTS_DISJOINT) };
        const { assert!(<Reordered as FrameSet>::PARTS_DISJOINT) };
        // Two parts that overlap within the rest of the set.
        const {
            assert!(!<HList![v1::Part, datagram::Part, datagram::Part] as FrameSet>::PARTS_DISJOINT)
        };
        // Two parts that overlap, the first and the last.
        const {
            assert!(!<HList![datagram::Part, v1::Part, datagram::Part] as FrameSet>::PARTS_DISJOINT)
        };
    }
}
