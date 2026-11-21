use sakuya_stream_v1::send_options::urgency::Urgency;
use sakuya_wire_v1::frame::NoLength;
use sakuya_wire_v1::frame::{max_streams::MaxStreamsFrame, stream::StreamFrame};

use super::*;

fn id(value: u32) -> StreamId {
    StreamId::from(VarInt::from_u32(value))
}

fn urgency(value: u8) -> Urgency {
    Urgency::new(value).expect("an urgency of RFC 9218")
}

/// The least room of STREAM data is a frame with one byte of it: without
/// a Length field as the last frame, with one otherwise; the Offset field
/// is left out at 0, and the FIN alone carries no byte.
#[test]
fn the_least_room_of_stream_data_is_one_byte_of_it() {
    let at_start = shortest_stream_frame(id(4), VarInt::ZERO, true);
    let frame = StreamFrame::<_, NoLength>::without_length(
        VarIntField::shortest(id(4)),
        None,
        &[0u8][..],
        false,
    )
    .unwrap();
    assert_eq!(at_start.as_last, frame.encoded_len());
    assert_eq!(at_start.as_last, 3);
    assert_eq!(at_start.with_length, 4);

    let later = shortest_stream_frame(id(4), VarInt::from_u32(1000), true);
    assert_eq!(later.as_last, 5);
    assert_eq!(later.with_length, 6);

    let fin = shortest_stream_frame(id(4), VarInt::from_u32(1000), false);
    assert_eq!(fin.as_last, 4);
    assert_eq!(fin.with_length, 5);
}

#[test]
fn each_intent_names_its_frame_source_and_room() {
    let min = shortest_stream_frame(id(1), VarInt::ZERO, true);
    let stream = StreamIntent::Stream {
        stream_id: id(1),
        parameters: urgency(1),
        min,
    };
    assert_eq!(stream.frame_source(), FrameSourceId::Stream);
    assert_eq!(stream.min_lengths(), min);
    assert_eq!(stream.key(), StreamIntentKey::Stream(id(1)));

    let len = MaxStreamsFrame::new(
        Directionality::Unidirectional,
        VarIntField::shortest(StreamCount::new(7).unwrap()),
    )
    .encoded_len();
    let max_streams = StreamIntent::<Urgency>::MaxStreams {
        directionality: Directionality::Unidirectional,
        len,
    };
    assert_eq!(max_streams.frame_source(), FrameSourceId::MaxStreams);
    assert_eq!(
        max_streams.min_lengths(),
        MinimumLengths {
            with_length: len,
            as_last: len,
        }
    );
    let sources = [
        (
            StreamIntent::<Urgency>::ResetStream {
                stream_id: id(1),
                len: 4,
            },
            FrameSourceId::ResetStream,
        ),
        (
            StreamIntent::StopSending {
                stream_id: id(1),
                len: 3,
            },
            FrameSourceId::StopSending,
        ),
        (StreamIntent::MaxData { len: 2 }, FrameSourceId::MaxData),
        (
            StreamIntent::MaxStreamData {
                stream_id: id(1),
                len: 3,
            },
            FrameSourceId::MaxStreamData,
        ),
        (
            StreamIntent::DataBlocked { len: 2 },
            FrameSourceId::DataBlocked,
        ),
        (
            StreamIntent::StreamDataBlocked {
                stream_id: id(1),
                len: 3,
            },
            FrameSourceId::StreamDataBlocked,
        ),
        (
            StreamIntent::StreamsBlocked {
                directionality: Directionality::Bidirectional,
                len: 2,
            },
            FrameSourceId::StreamsBlocked,
        ),
    ];
    for (intent, source) in sources {
        assert_eq!(intent.frame_source(), source);
        assert_eq!(intent.key().frame_source(), source);
    }
}

/// STREAM ranks as application data by its urgency, holds no place and
/// stays after writing; the others are control frames consumed as they
/// are written.
#[test]
fn stream_data_ranks_by_urgency_and_stays_after_writing() {
    let stream = StreamIntent::Stream {
        stream_id: id(1),
        parameters: urgency(1),
        min: shortest_stream_frame(id(1), VarInt::ZERO, true),
    };
    assert_eq!(
        stream.rank(),
        SendRank {
            priority: SendPriority::ApplicationData,
            holds_place: false,
        }
    );
    assert_eq!(stream.urgency(), urgency(1));
    assert!(stream.stays_after_writing());

    let max_data = StreamIntent::<Urgency>::MaxData { len: 2 };
    assert_eq!(
        max_data.rank(),
        SendRank {
            priority: SendPriority::Control,
            holds_place: true,
        }
    );
    assert!(!max_data.stays_after_writing());
}
