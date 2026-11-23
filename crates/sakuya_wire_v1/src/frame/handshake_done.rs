//! HANDSHAKE_DONE frames ([RFC 9000 §19.20]).
//!
//! [RFC 9000 §19.20]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.20
use super::{FrameType, type_value};
use crate::frame::type_var_int;
use sakuya_var_int::VarInt;

/// A HANDSHAKE_DONE frame ([RFC 9000 §19.20]): the Frame Type alone.
///
/// [RFC 9000 §19.20]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.20
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct HandshakeDoneFrame;

impl HandshakeDoneFrame {
    /// The kind of the frame, [`FrameType::HandshakeDone`].
    pub const fn frame_type(&self) -> FrameType {
        FrameType::HandshakeDone
    }

    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::HANDSHAKE_DONE)
    }

    /// The number of bytes [`codec::write_handshake_done_frame`] writes: one.
    pub const fn encoded_len(&self) -> usize {
        1
    }
}

pub mod codec {
    //! Writing HANDSHAKE_DONE.

    use super::HandshakeDoneFrame;
    use bytes::BufMut;
    use sakuya_var_int::codec::write_var_int;

    /// Writes the frame.
    ///
    /// # Panics
    ///
    /// If `dst` has no room for the frame, as [`BufMut`] does.
    pub fn write_handshake_done_frame(dst: &mut impl BufMut, frame: HandshakeDoneFrame) {
        write_var_int(dst, frame.type_value());
    }
}
