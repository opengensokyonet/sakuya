//! PING frames ([RFC 9000 §19.2]).
//!
//! [RFC 9000 §19.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.2
use super::{FrameType, type_value};
use crate::frame::type_var_int;
use crate::var_int::VarInt;

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
    //! Writing PING as a `nitori_call` operation.
    //!
    //! [`write_ping_frame`] is also the operation struct [`WritePingFrame`], with
    //! `WritePingFrameExt` on receiver accesses and `WritePingFrameHostExt` on
    //! call executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::PingFrame;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};

    /// Writes the frame.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails.
    #[call(sync)]
    pub async fn write_ping_frame<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: PingFrame,
    ) -> Result<(), WriteAllError<F::Error>> {
        let (encoding, _) = frame.type_value().to_encoding();
        io.write_all(&encoding[..1]).await
    }
}
