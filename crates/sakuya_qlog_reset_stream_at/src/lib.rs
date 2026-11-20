//! The reliable stream reset extension (RESET_STREAM_AT) as qlog writes it:
//! its frame (quic-events §8.13.5) and its transport parameter (§5.3).
#![warn(missing_docs)]

use core::convert::Infallible;

use sakuya_wire_reset_stream_at::{ResetStreamAt, ResetStreamAtFrame};

use sakuya_qlog::{
    QlogParameter, QlogPart,
    json::{ArrayWriter, ObjectWriter},
};

/// The part of qlog's writer for the reliable stream reset extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Part;

impl QlogPart for Part {
    type Connection = sakuya_connection_reset_stream_at::Part;

    fn write_run(run: &ResetStreamAtFrame, frames: &mut ArrayWriter<'_>) {
        frames.object(|frame| {
            frame
                .str("frame_type", "reset_stream_at")
                .u64("stream_id", run.stream_id().get().get().get())
                // `$ApplicationError` has no names of its own: the number
                // is given beside "unknown".
                .str("error", "unknown")
                .u64("error_code", run.application_error_code().get().get().get())
                .u64("final_size", run.final_size().get().get())
                .u64("reliable_size", run.reliable_size().get().get());
        });
    }

    fn shared_event_name(event: &Infallible) -> &'static str {
        match *event {}
    }

    fn write_shared_event(event: &Infallible, _: &mut ObjectWriter<'_>) {
        match *event {}
    }
}

impl QlogParameter<ResetStreamAt> for Part {
    fn write(_: &ResetStreamAt, data: &mut ObjectWriter<'_>) {
        data.bool("reset_stream_at", true);
    }
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use super::*;
    use sakuya_qlog::{QlogParts, json::object};
    use sakuya_wire::parts::HList;
    use sakuya_wire_v1::frame::set::Frames;

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

    #[test]
    fn frame() {
        // stream 4, error 7, final size 100, reliable size 10
        assert_eq!(
            frames_of::<Part>(&[0x24, 4, 7, 0x40, 0x64, 10]),
            r#"{"frames":[{"frame_type":"reset_stream_at","stream_id":4,"error":"unknown","error_code":7,"final_size":100,"reliable_size":10}]}"#
        );
    }

    #[test]
    fn parameter() {
        let text = parameter_of(|o| Part::write(&ResetStreamAt, o));
        assert_eq!(text, r#"{"reset_stream_at":true}"#);
    }
}
