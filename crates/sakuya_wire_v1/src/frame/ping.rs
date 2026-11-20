//! PING frames ([RFC 9000 §19.2]).
//!
//! [RFC 9000 §19.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.2
use super::{FrameType, type_value};
use sakuya_wire::frame::type_var_int;
use sakuya_wire::var_int::VarInt;

/// A PING frame ([RFC 9000 §19.2]): the Frame Type alone.
///
/// [RFC 9000 §19.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.2
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PingFrame;

impl PingFrame {
    /// The kind of the frame, [`FrameType::Ping`].
    pub const fn frame_type(&self) -> FrameType {
        FrameType::Ping
    }

    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::PING)
    }

    /// The number of bytes [`codec::write_ping_frame`] writes: one.
    pub const fn encoded_len(&self) -> usize {
        1
    }
}

pub mod codec {
    //! Writing PING.

    use super::PingFrame;
    use bytes::BufMut;

    /// Writes the frame.
    ///
    /// # Panics
    ///
    /// If `dst` has no room for the frame, as [`BufMut`] does.
    pub fn write_ping_frame(dst: &mut impl BufMut, frame: PingFrame) {
        let (encoding, _) = frame.type_value().to_encoding();
        dst.put_slice(&encoding[..1]);
    }
}
