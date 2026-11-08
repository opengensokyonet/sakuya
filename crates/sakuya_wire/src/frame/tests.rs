//! Tests of frame sets: the sum of parts, the Frame Type values parts claim,
//! and reading frames of a set.
use super::{
    FrameSetPart, FrameTypeValues, Frames, PartSum,
    codec::{ReadFrameError, ReadFrameHostExt as _},
};
use crate::{
    v1::{self, frame::Frame, transport_error::TransportErrorCode},
    var_int::VarInt,
};
use core::{marker::PhantomData, ops::RangeInclusive};

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
    const { assert!(<v1::Part as FrameSetPart>::PARTS_DISJOINT) };
    const { assert!(!<PartSum<v1::Part, v1::Part> as FrameSetPart>::PARTS_DISJOINT) };
    // The values of a sum are those of both sides.
    let values = <PartSum<v1::Part, v1::Part> as FrameSetPart>::FRAME_TYPE_VALUES;
    assert!(values.contains(vi(0x00)) && values.contains(vi(0x1e)));
    assert!(!values.contains(vi(0x1f)));
}

/// RFC 9000 §12.4: a set of version 1 alone does not know the types of the
/// extensions, and reports them as it reports any unknown type.
#[test]
fn version_1_alone_reports_extension_types_as_unknown() {
    for encoding in [&[0x24, 0, 0, 0, 0][..], &[0x30, 1], &[0x31, 0]] {
        let mut frames = Frames::new(encoding, PhantomData::<v1::Part>);
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
fn a_set_of_version_1_reads_without_a_sum() {
    let mut input = &[0x10, 0x05, 0x01][..];
    let frame = input
        .sync_read_frame_unpin(PhantomData::<v1::Part>)
        .unwrap();
    assert!(matches!(frame, Frame::MaxData(max_data) if max_data.maximum_data().get() == vi(5)));
}

#[cfg(all(feature = "reset_stream_at", feature = "datagram"))]
mod three_parts {
    use super::vi;
    use crate::{
        assert_frame_types_disjoint, datagram,
        frame::{
            FrameFieldsError, FrameKind, FrameSetPart, Frames, PartSum,
            codec::{ReadFrameError, ReadFrameHostExt as _},
        },
        reset_stream_at,
        v1::{
            self,
            encryption_level::EncryptionLevel,
            frame::{Frame, FrameType, codec::ReadFieldsError},
            role::Role,
            transport_error::TransportErrorCode,
        },
    };
    use core::marker::PhantomData;

    type Set = PartSum<v1::Part, PartSum<reset_stream_at::Part, datagram::Part>>;
    assert_frame_types_disjoint!(Set);

    const SET: PhantomData<Set> = PhantomData;

    #[test]
    fn each_frame_goes_to_its_part() {
        // MAX_DATA 7; RESET_STREAM_AT on stream 4 with final size 9 and
        // reliable size 5; DATAGRAM of two bytes; three PADDING; PING.
        let payload = [
            0x10, 0x07, 0x24, 0x04, 0x00, 0x09, 0x05, 0x31, 0x02, b'h', b'i', 0, 0, 0, 0x01,
        ];
        let mut input = &payload[..];
        assert!(matches!(
            input.sync_read_frame_unpin(SET).unwrap(),
            PartSum::First(Frame::MaxData(frame)) if frame.maximum_data().get() == vi(7)
        ));
        match input.sync_read_frame_unpin(SET).unwrap() {
            PartSum::Rest(PartSum::First(frame)) => {
                assert_eq!(frame.final_size().get(), vi(9));
                assert_eq!(frame.reliable_size().get(), vi(5));
            }
            other => panic!("{other:?}"),
        }
        match input.sync_read_frame_unpin(SET).unwrap() {
            PartSum::Rest(PartSum::Rest(frame)) => assert_eq!(*frame.data(), b"hi"),
            other => panic!("{other:?}"),
        }

        // The iterator does the same, and merges the run of PADDING.
        let frames: Vec<_> = Frames::new(&payload[..], SET)
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(frames.len(), 5);
        assert!(matches!(frames[1], PartSum::Rest(PartSum::First(_))));
        assert!(matches!(frames[2], PartSum::Rest(PartSum::Rest(_))));
        assert!(matches!(
            frames[3],
            PartSum::First(Frame::Padding(padding)) if padding.len().get() == 3
        ));
        assert!(matches!(frames[4], PartSum::First(Frame::Ping(_))));
    }

    #[test]
    fn field_failures_come_from_their_part() {
        let read = |encoding: &'static [u8]| {
            let mut input = encoding;
            input.sync_read_frame_unpin(SET).unwrap_err()
        };
        // DATAGRAM announces five bytes and holds one.
        let error = read(&[0x31, 0x05, b'x']);
        assert!(matches!(
            error,
            ReadFrameError::Fields {
                source: PartSum::Rest(PartSum::Rest(
                    datagram::codec::ReadDatagramFrameError::Data { .. }
                )),
            }
        ));
        assert!(error.is_incomplete());
        assert_eq!(error.frame_type(), Some(vi(0x31)));
        assert_eq!(error.to_string(), "DATAGRAM data read failed");
        // RESET_STREAM_AT with a reliable size beyond its final size.
        let error = read(&[0x24, 0x00, 0x00, 0x05, 0x06]);
        let ReadFrameError::Fields {
            source: PartSum::Rest(PartSum::First(source)),
        } = &error
        else {
            panic!("{error:?}")
        };
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
        assert!(matches!(
            error,
            ReadFrameError::Fields {
                source: PartSum::First(ReadFieldsError::Crypto { .. })
            }
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
        let kind = |value: u32| <Set as FrameSetPart>::kind_of(vi(value)).unwrap();
        assert_eq!(kind(0x07), PartSum::First(FrameType::NewToken));
        assert_eq!(
            kind(0x24),
            PartSum::Rest(PartSum::First(reset_stream_at::FrameType::ResetStreamAt))
        );
        assert_eq!(
            kind(0x30),
            PartSum::Rest(PartSum::Rest(datagram::FrameType::Datagram))
        );
        assert_eq!(<Set as FrameSetPart>::kind_of(vi(0x1f)), None);
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
        const { assert!(<Set as FrameSetPart>::PARTS_DISJOINT) };
        // Two parts that overlap within the rest of the set.
        const {
            assert!(!<PartSum<v1::Part, PartSum<datagram::Part, datagram::Part>> as FrameSetPart>::PARTS_DISJOINT)
        };
        // A sum as the first part.
        const {
            assert!(<PartSum<PartSum<v1::Part, datagram::Part>, reset_stream_at::Part> as FrameSetPart>::PARTS_DISJOINT)
        };
        const {
            assert!(!<PartSum<PartSum<v1::Part, datagram::Part>, datagram::Part> as FrameSetPart>::PARTS_DISJOINT)
        };
    }
}
