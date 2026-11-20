//! The DATAGRAM extension ([RFC 9221]) as qlog writes it: its frame
//! (quic-events §8.13.23), its transport parameter (§5.3), and the events
//! of its datagrams (§5.17, §5.18).
//!
//! [RFC 9221]: https://www.rfc-editor.org/rfc/rfc9221.html
#![warn(missing_docs)]

use sakuya_connection_datagram::{DatagramDropped, DatagramEvent};
use sakuya_wire_datagram::{DatagramFrame, MaxDatagramFrameSize};

use sakuya_qlog::{
    CarriedData, QlogParameter, QlogPart, data_location,
    json::{ArrayWriter, ObjectWriter},
};

/// The part of qlog's writer for the DATAGRAM extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Part;

impl QlogPart for Part {
    type Connection = sakuya_connection_datagram::Part;

    fn write_run(run: &DatagramFrame<&[u8]>, frames: &mut ArrayWriter<'_>) {
        // The draft's DatagramFrame has `raw` only: the length of the data
        // is `raw.length`, whether or not the frame has a Length field.
        frames.object(|frame| {
            frame.str("frame_type", "datagram").object("raw", |raw| {
                raw.u64("length", run.data().len() as u64);
            });
        });
    }

    fn carried_data(run: &DatagramFrame<&[u8]>) -> Option<CarriedData> {
        Some(CarriedData::Datagram {
            length: run.data().len() as u64,
        })
    }

    fn shared_event_name(event: &DatagramEvent) -> &'static str {
        match event {
            DatagramEvent::DataMoved { .. } => "quic:datagram_data_moved",
            DatagramEvent::Dropped { .. } => "quic:datagram_dropped",
        }
    }

    fn write_shared_event(event: &DatagramEvent, data: &mut ObjectWriter<'_>) {
        match *event {
            DatagramEvent::DataMoved { length, from, to } => {
                data.str("from", data_location(from))
                    .str("to", data_location(to))
                    .object("raw", |raw| {
                        raw.u64("length", length as u64);
                    });
            }
            DatagramEvent::Dropped { length, dropped } => {
                let direction = match dropped {
                    DatagramDropped::SendQueueFull => "sending",
                    DatagramDropped::ReceiveQueueFull => "receiving",
                };
                data.str("direction", direction)
                    .object("raw", |raw| {
                        raw.u64("length", length as u64);
                    })
                    .str("trigger", "buffer_full");
            }
        }
    }
}

impl QlogParameter<MaxDatagramFrameSize> for Part {
    fn write(parameter: &MaxDatagramFrameSize, data: &mut ObjectWriter<'_>) {
        data.u64("max_datagram_frame_size", parameter.get().get());
    }
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use sakuya_qlog::{QlogParts, json::object};
    use sakuya_wire::parts::HList;
    use sakuya_wire::var_int::VarInt;
    use sakuya_wire_v1::frame::set::Frames;

    use super::*;

    /// The frames in `bytes`, written as a `frames` array.
    fn frames_of<P: QlogPart>(bytes: &[u8]) -> String {
        let mut buf = Vec::new();
        object(&mut buf, |o| {
            o.array("frames", |a| {
                for run in Frames::new(bytes, PhantomData::<HList![P::Connection]>) {
                    let Ok(run) = run else {
                        panic!("the test bytes do not read");
                    };
                    <HList![P] as QlogParts>::write_run(&run, a);
                }
            });
        });
        String::from_utf8(buf).unwrap()
    }

    fn parameter_of(write: impl FnOnce(&mut ObjectWriter<'_>)) -> String {
        let mut buf = Vec::new();
        object(&mut buf, write);
        String::from_utf8(buf).unwrap()
    }

    type ConnectionPart = sakuya_connection_datagram::Part;

    #[test]
    fn datagram_with_and_without_length() {
        assert_eq!(
            frames_of::<Part>(&[0x31, 2, 0xaa, 0xbb]),
            r#"{"frames":[{"frame_type":"datagram","raw":{"length":2}}]}"#
        );
        assert_eq!(
            frames_of::<Part>(&[0x30, 0xaa, 0xbb, 0xcc]),
            r#"{"frames":[{"frame_type":"datagram","raw":{"length":3}}]}"#
        );
    }

    #[test]
    fn carried_length() {
        use core::marker::PhantomData;
        use sakuya_wire::parts::{Coproduct, HList};
        use sakuya_wire_v1::frame::set::Frames;
        let bytes = [0x31, 2, 0xaa, 0xbb];
        let run = Frames::new(&bytes[..], PhantomData::<HList![ConnectionPart]>)
            .next()
            .unwrap();
        let Ok(Coproduct::Inl(run)) = run else {
            panic!("the test bytes do not read");
        };
        assert_eq!(
            <Part as QlogPart>::carried_data(&run),
            Some(CarriedData::Datagram { length: 2 })
        );
    }

    /// A move of a datagram's payload is written with its two places and
    /// its length; a drop with the queue it was dropped from, as the
    /// direction, and the trigger of a full buffer.
    #[test]
    fn events() {
        use sakuya_connection::v1::events::DataLocation;

        let moved = DatagramEvent::DataMoved {
            length: 3,
            from: DataLocation::Application,
            to: DataLocation::Transport,
        };
        assert_eq!(
            <Part as QlogPart>::shared_event_name(&moved),
            "quic:datagram_data_moved"
        );
        assert_eq!(
            parameter_of(|o| <Part as QlogPart>::write_shared_event(&moved, o)),
            r#"{"from":"application","to":"transport","raw":{"length":3}}"#
        );
        let dropped = DatagramEvent::Dropped {
            length: 5,
            dropped: DatagramDropped::ReceiveQueueFull,
        };
        assert_eq!(
            <Part as QlogPart>::shared_event_name(&dropped),
            "quic:datagram_dropped"
        );
        assert_eq!(
            parameter_of(|o| <Part as QlogPart>::write_shared_event(&dropped, o)),
            r#"{"direction":"receiving","raw":{"length":5},"trigger":"buffer_full"}"#
        );
    }

    #[test]
    fn parameter() {
        let text =
            parameter_of(|o| Part::write(&MaxDatagramFrameSize::new(VarInt::from_u32(1200)), o));
        assert_eq!(text, r#"{"max_datagram_frame_size":1200}"#);
    }

    /// The slots of the parameters of a list of parts are written by the
    /// part of qlog's writer of each part, in the order of the list.
    #[test]
    fn each_part_writes_the_slots_of_its_parameters() {
        use sakuya_wire::parts::HList;
        use sakuya_wire_v1::transport_parameters::{TransportParameters, integer::MaxIdleTimeout};

        use sakuya_qlog::QlogParameterSlots;

        type V1 = sakuya_connection::v1::Part;
        macro_rules! written {
            ($qlog:ty, $connection:ty) => {{
                let mut parameters = TransportParameters::<Vec<u8>, $connection>::new();
                parameters.set(MaxIdleTimeout::new(VarInt::from_u32(30_000)));
                parameters.set(MaxDatagramFrameSize::new(VarInt::from_u32(1200)));
                parameter_of(|o| <$qlog>::write_parameters(&parameters.known, o))
            }};
        }
        assert_eq!(
            written!(HList![V1, Part], HList![V1, ConnectionPart]),
            r#"{"max_idle_timeout":30000,"max_datagram_frame_size":1200}"#
        );
        assert_eq!(
            written!(HList![Part, V1], HList![ConnectionPart, V1]),
            r#"{"max_datagram_frame_size":1200,"max_idle_timeout":30000}"#
        );
    }
}
