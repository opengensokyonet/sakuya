//! PADDING frames ([RFC 9000 §19.1]).
//!
//! [RFC 9000 §19.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.1
use super::{type_value, type_var_int};
use crate::var_int::VarInt;
use core::num::NonZeroUsize;

/// One or more PADDING frames ([RFC 9000 §19.1]).
///
/// A PADDING frame is its Frame Type alone, the single byte `0x00`: like
/// every Frame Type, it must use its shortest encoding. Reading with
/// [`Frames`](super::Frames) reports a run of consecutive PADDING frames as
/// one value. Writing writes [`len`](Self::len) zero bytes, that many
/// PADDING frames.
///
/// [RFC 9000 §19.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.1
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PaddingFrame {
    len: NonZeroUsize,
}

impl PaddingFrame {
    /// The run of `len` PADDING frames.
    pub const fn new(len: NonZeroUsize) -> Self {
        Self { len }
    }

    /// The number of bytes.
    pub const fn len(&self) -> NonZeroUsize {
        self.len
    }

    /// The Frame Type value, zero.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::PADDING)
    }

    /// The number of bytes [`codec::write_padding_frame`] writes.
    pub const fn encoded_len(&self) -> usize {
        self.len.get()
    }

    /// The run extended by `count` more one-byte PADDING frames.
    pub(crate) fn extend(self, count: usize) -> Self {
        Self {
            len: self.len.saturating_add(count),
        }
    }
}

pub mod codec {
    //! Writing PADDING as a `nitori_call` operation.
    //!
    //! [`write_padding_frame`] is also the operation struct [`WritePaddingFrame`], with
    //! `WritePaddingFrameExt` on receiver accesses and `WritePaddingFrameHostExt` on
    //! call executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::PaddingFrame;
    use bytes::Buf;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};

    /// Writes [`PaddingFrame::len`] zero bytes.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_padding_frame<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: PaddingFrame,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(Zeros(frame.len().get())).await
    }

    /// A run of zero bytes as a buffer.
    struct Zeros(usize);

    const ZEROS: [u8; 64] = [0; 64];

    impl Buf for Zeros {
        fn remaining(&self) -> usize {
            self.0
        }

        fn chunk(&self) -> &[u8] {
            &ZEROS[..self.0.min(ZEROS.len())]
        }

        fn advance(&mut self, count: usize) {
            self.0 = self.0.saturating_sub(count);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PaddingFrame, codec::WritePaddingFrameHostExt as _};
    use core::num::NonZeroUsize;

    #[test]
    fn writes_zero_bytes() {
        let padding = PaddingFrame::new(NonZeroUsize::new(200).unwrap());
        let mut written = Vec::new();
        written.sync_write_padding_frame_unpin(padding).unwrap();
        assert_eq!(written, [0; 200]);
        assert_eq!(padding.encoded_len(), 200);
        assert_eq!(padding.len().get(), 200);
    }
}
