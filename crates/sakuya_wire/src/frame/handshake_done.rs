//! HANDSHAKE_DONE frames ([RFC 9000 §19.20]).
//!
//! [RFC 9000 §19.20]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.20
use super::{type_value, type_var_int};
use crate::var_int::VarInt;

/// A HANDSHAKE_DONE frame ([RFC 9000 §19.20]): the Frame Type alone.
///
/// [RFC 9000 §19.20]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.20
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct HandshakeDoneFrame;

impl HandshakeDoneFrame {
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
    //! Writing HANDSHAKE_DONE as a `nitori_call` operation.
    //!
    //! [`write_handshake_done_frame`] is also the operation struct [`WriteHandshakeDoneFrame`], with
    //! `WriteHandshakeDoneFrameExt` on receiver accesses and `WriteHandshakeDoneFrameHostExt` on
    //! call executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::HandshakeDoneFrame;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};

    /// Writes the frame.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails.
    #[call(sync)]
    pub async fn write_handshake_done_frame<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: HandshakeDoneFrame,
    ) -> Result<(), WriteAllError<F::Error>> {
        let (encoding, _) = frame.type_value().to_encoding();
        io.write_all(&encoding[..1]).await
    }
}
