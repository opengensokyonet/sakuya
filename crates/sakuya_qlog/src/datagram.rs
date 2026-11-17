//! The DATAGRAM extension ([RFC 9221]) as qlog writes it: its frame
//! (quic-events §8.13.23) and its transport parameter (§5.3).
//!
//! [RFC 9221]: https://www.rfc-editor.org/rfc/rfc9221.html

use sakuya_wire::datagram::{DatagramFrame, MaxDatagramFrameSize};

use crate::{
    json::{ArrayWriter, ObjectWriter},
    parameters::QlogParameter,
    part::{CarriedData, QlogPart},
};

impl QlogPart for sakuya_connection::datagram::Part {
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
}

impl QlogParameter for MaxDatagramFrameSize {
    fn write(&self, parameters: &mut ObjectWriter<'_>) {
        parameters.u64("max_datagram_frame_size", self.get().get());
    }
}

#[cfg(test)]
mod tests {
    use sakuya_wire::var_int::VarInt;

    use super::*;
    use crate::v1::tests::{frames_of, parameter_of};

    type Part = sakuya_connection::datagram::Part;

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
        use sakuya_wire::{
            parts::{Coproduct, HList},
            v1::frame::set::Frames,
        };
        let bytes = [0x31, 2, 0xaa, 0xbb];
        let run = Frames::new(&bytes[..], PhantomData::<HList![Part]>)
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

    #[test]
    fn parameter() {
        let text = parameter_of(|o| MaxDatagramFrameSize::new(VarInt::from_u32(1200)).write(o));
        assert_eq!(text, r#"{"max_datagram_frame_size":1200}"#);
    }
}
