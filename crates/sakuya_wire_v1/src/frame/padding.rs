//! PADDING frames ([RFC 9000 §19.1]).
//!
//! A PADDING frame is its Frame Type alone, the single byte `0x00`: like
//! every Frame Type, it must use its shortest encoding. [`PaddingFrame`] is
//! one PADDING frame, the PADDING variant of [`Frame`](super::Frame), and
//! [`PaddingRun`] is a number of consecutive ones, the PADDING variant of
//! [`FrameRun`](super::FrameRun). Reading a packet payload with
//! [`Frames`](super::set::Frames) gives the consecutive PADDING frames as one
//! run, while reading a single frame, with
//! [`read_fields`](super::codec::read_fields), takes one PADDING frame at a
//! time.
//!
//! [RFC 9000 §19.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.1
use super::{FrameType, type_value};
use crate::frame::type_var_int;
use core::num::NonZeroUsize;
use sakuya_var_int::VarInt;

/// A PADDING frame ([RFC 9000 §19.1]): the Frame Type alone, one byte.
///
/// [RFC 9000 §19.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.1
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PaddingFrame;

impl PaddingFrame {
    /// The kind of the frame, [`FrameType::Padding`].
    pub const fn frame_type(&self) -> FrameType {
        FrameType::Padding
    }

    /// The Frame Type value, zero.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::PADDING)
    }

    /// The number of bytes [`codec::write_padding_frame`] writes: one.
    pub const fn encoded_len(&self) -> usize {
        1
    }
}

/// A run of consecutive PADDING frames ([RFC 9000 §19.1]), one or more.
///
/// Reading with [`Frames`](crate::frame::set::Frames) gives the
/// consecutive PADDING frames of a packet payload as one run. Writing writes
/// [`len`](Self::len) zero bytes, that many PADDING frames.
///
/// [RFC 9000 §19.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.1
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PaddingRun {
    len: NonZeroUsize,
}

impl PaddingRun {
    /// The run of `len` PADDING frames.
    pub const fn new(len: NonZeroUsize) -> Self {
        Self { len }
    }

    /// The number of PADDING frames, each one byte.
    pub const fn len(&self) -> NonZeroUsize {
        self.len
    }

    /// The kind of the frames of the run, [`FrameType::Padding`].
    pub const fn frame_type(&self) -> FrameType {
        FrameType::Padding
    }

    /// The Frame Type value of each frame of the run, zero.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::PADDING)
    }

    /// The number of bytes [`codec::write_padding_run`] writes.
    pub const fn encoded_len(&self) -> usize {
        self.len.get()
    }
}

/// One PADDING frame is a run of one.
impl From<PaddingFrame> for PaddingRun {
    fn from(PaddingFrame: PaddingFrame) -> Self {
        Self::new(NonZeroUsize::MIN)
    }
}

pub mod codec {
    //! Writing PADDING.
    //!
    //! [`write_padding_frame`] writes one PADDING frame and
    //! [`write_padding_run`] a run of them.

    use super::{PaddingFrame, PaddingRun};
    use bytes::BufMut;

    /// Writes one PADDING frame: a zero byte.
    ///
    /// # Panics
    ///
    /// If `dst` has no room for the frame, as [`BufMut`] does.
    pub fn write_padding_frame(dst: &mut impl BufMut, padding: PaddingFrame) {
        dst.put_bytes(0, padding.encoded_len());
    }

    /// Writes the PADDING frames of `padding`: a zero byte for each.
    ///
    /// # Panics
    ///
    /// If `dst` has no room for the frames, as [`BufMut`] does.
    pub fn write_padding_run(dst: &mut impl BufMut, padding: PaddingRun) {
        dst.put_bytes(0, padding.encoded_len());
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PaddingFrame, PaddingRun,
        codec::{write_padding_frame, write_padding_run},
    };
    use core::num::NonZeroUsize;

    #[test]
    fn a_frame_writes_one_zero_byte() {
        let mut written = Vec::new();
        write_padding_frame(&mut written, PaddingFrame);
        assert_eq!(written, [0]);
        assert_eq!(PaddingFrame.encoded_len(), 1);
    }

    #[test]
    fn a_run_writes_its_zero_bytes() {
        let padding = PaddingRun::new(NonZeroUsize::new(200).unwrap());
        let mut written = Vec::new();
        write_padding_run(&mut written, padding);
        assert_eq!(written, [0; 200]);
        assert_eq!(padding.encoded_len(), 200);
        assert_eq!(padding.len().get(), 200);
    }

    #[test]
    fn a_frame_is_a_run_of_one() {
        assert_eq!(PaddingRun::from(PaddingFrame).len(), NonZeroUsize::MIN);
        let padding = PaddingRun::new(NonZeroUsize::new(3).unwrap());
        assert_eq!(padding.type_value(), PaddingFrame.type_value());
        assert_eq!(padding.frame_type(), PaddingFrame.frame_type());
    }
}
