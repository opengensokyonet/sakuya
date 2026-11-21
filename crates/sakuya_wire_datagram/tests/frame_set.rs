//! Frame sets of version 1 with both extensions, through the public
//! interface: reading frames of each part and the kinds of the set.
use sakuya_wire_v1::var_int::VarInt;

fn vi(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

mod three_parts {
    use super::vi;
    use core::marker::PhantomData;
    use sakuya_wire::parts::{HList, PartsError};
    use sakuya_wire_datagram as datagram;
    use sakuya_wire_reset_stream_at as reset_stream_at;
    use sakuya_wire_v1 as v1;
    use sakuya_wire_v1::assert_frame_types_disjoint;
    use sakuya_wire_v1::{
        encryption_level::EncryptionLevel,
        frame::{
            FrameRun, FrameType,
            codec::ReadFieldsError,
            set::{FrameFieldsError, FrameKind, FrameSet, Frames, codec::ReadFrameError},
        },
        role::Role,
        transport_error::TransportErrorCode,
    };

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
            sum.get::<datagram::codec::ReadDatagramFrameError, _>(),
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
            .get::<reset_stream_at::codec::ReadResetStreamAtFrameError, _>()
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
            sum.get::<ReadFieldsError, _>(),
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
        let kind = |value: u32| {
            <Set as FrameSet>::kind_of(<Set as FrameSet>::type_value_of(vi(value)).unwrap())
        };
        assert_eq!(kind(0x07).get::<FrameType, _>(), Some(&FrameType::NewToken));
        assert_eq!(
            kind(0x24).get::<reset_stream_at::FrameType, _>(),
            Some(&reset_stream_at::FrameType::ResetStreamAt)
        );
        assert_eq!(
            kind(0x30).get::<datagram::FrameType, _>(),
            Some(&datagram::FrameType::Datagram)
        );
        assert_eq!(<Set as FrameSet>::type_value_of(vi(0x1f)), None);
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
