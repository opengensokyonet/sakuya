//! Reading the Frame Type of an item of a frame set as a `nitori_call`
//! operation.
//!
//! [`read_frame_type`] reads the Frame Type of the next item of the frame set
//! `S`, checks that it uses its shortest encoding, and gives the kind the
//! set has for it. [`Frames`](super::Frames) reads the Frame Type with it,
//! and then lets the part that claims the Frame Type read the rest
//! ([`FrameSetPart::read_run`](super::FrameSetPart::read_run)). Writing is
//! per frame type, in the `codec` module of each frame.
//!
//! [`read_frame_type`] is also the operation struct [`ReadFrameType`], with
//! `ReadFrameTypeExt` on receiver accesses inside other operations and
//! `ReadFrameTypeHostExt` on call executors, including the `sync_` methods
//! for receivers that never wait. Constructing an operation performs no IO.
//!
//! ```
//! use core::marker::PhantomData;
//! use sakuya_wire::{
//!     parts::HList,
//!     v1::{
//!         self,
//!         frame::{
//!             FrameType,
//!             set::codec::{ReadFrameError, ReadFrameTypeHostExt as _},
//!         },
//!         transport_error::TransportErrorCode,
//!     },
//!     var_int::VarInt,
//! };
//!
//! let set = PhantomData::<HList![v1::Part]>;
//! // MAX_DATA, then PING.
//! let mut input = &[0x10, 0x05, 0x01][..];
//! let (kind, value) = input.sync_read_frame_type_unpin(set).unwrap();
//! assert_eq!(kind.extract(), FrameType::MaxData);
//! assert_eq!(value, VarInt::from(0x10u8));
//! assert_eq!(input, [0x05, 0x01]);
//!
//! // RESET_STREAM_AT is not a frame of version 1.
//! let mut input = &[0x24, 0, 0, 0, 0][..];
//! let error = input.sync_read_frame_type_unpin(set).unwrap_err();
//! assert!(matches!(error, ReadFrameError::UnknownType { .. }));
//! assert_eq!(error.transport_error_code(), TransportErrorCode::FRAME_ENCODING_ERROR);
//!
//! // A Frame Type cut short is an incomplete failure.
//! let mut input = &[0x40][..];
//! assert!(input.sync_read_frame_type_unpin(set).unwrap_err().is_incomplete());
//! ```
// `#[call]` generates constructors, fields and extension traits without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use super::{FrameFieldsError, FrameSet};
use crate::{
    parts::PartsError,
    v1::transport_error::TransportErrorCode,
    var_int::{
        VarInt, VarIntWidth,
        codec::{ReadVarIntError, read_var_int_with_width},
    },
};
use core::marker::PhantomData;
use nitori_call::{ReceiverAccess, call};
use nitori_io::prelude::*;
use snafu::{ResultExt, Snafu};

/// Reads the Frame Type of an item of the frame set `S`, and gives the kind
/// it announces with its value; `set` names the set.
///
/// The Frame Type must use its shortest encoding ([RFC 9000 §12.4]); a
/// longer one is rejected before the type is looked up.
///
/// # Errors
///
/// [`ReadFrameError::FrameType`] if the Frame Type cannot be read,
/// [`ReadFrameError::LongerTypeEncoding`] if it uses a longer encoding than
/// necessary, and [`ReadFrameError::UnknownType`] for a value that no part
/// of `S` claims; never [`ReadFrameError::Fields`]. Bytes read before a
/// failure stay consumed.
///
/// [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
#[call(sync)]
pub async fn read_frame_type<S, F, A>(
    io: &mut A,
    set: PhantomData<S>,
) -> Result<(S::Kind, VarInt), ReadFrameError<F::Error, S::FieldsError<F::Error>>>
where
    S: FrameSet,
    F: Read,
    A: ReceiverAccess<Family = F>,
{
    use read_frame_error::*;
    let PhantomData = set;
    let (frame_type, width) = read_var_int_with_width(io).await.context(FrameTypeSnafu)?;
    LongerTypeEncodingError::check(frame_type, width).context(LongerTypeEncodingSnafu)?;
    let Some(kind) = S::kind_of(frame_type) else {
        return UnknownTypeSnafu { frame_type }.fail();
    };
    Ok((kind, frame_type))
}

/// A Frame Type uses a longer encoding than necessary ([RFC 9000 §12.4]).
///
/// It is constructed only when the check fails, so its width is always
/// longer than the shortest encoding of its Frame Type.
///
/// [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "frame type {:#x} uses a {}-byte encoding, longer than necessary",
    frame_type.get(),
    width.encoded_len()
))]
pub struct LongerTypeEncodingError {
    frame_type: VarInt,
    width: VarIntWidth,
}

impl LongerTypeEncodingError {
    /// Checks that the Frame Type `frame_type` was read in an encoding of
    /// `width`, its shortest.
    pub(crate) fn check(frame_type: VarInt, width: VarIntWidth) -> Result<(), Self> {
        if width != VarIntWidth::shortest(frame_type) {
            return Err(Self { frame_type, width });
        }
        Ok(())
    }

    /// The Frame Type.
    pub const fn frame_type(self) -> VarInt {
        self.frame_type
    }

    /// The width of its encoding, longer than the shortest.
    pub const fn width(self) -> VarIntWidth {
        self.width
    }
}

/// Failures of reading one item of a frame set whose parts report the
/// failures of reading fields as the sum `C`: the Frame Type
/// ([`read_frame_type`]) and what the part that claims it reads after it,
/// which [`Frames`](super::Frames) yields.
///
/// The failures of the Frame Type are the same for every frame set; the
/// failures of the other fields come from the part that claims the Frame
/// Type, through [`Fields`](Self::Fields).
#[derive(Debug, Snafu)]
#[snafu(module(read_frame_error), visibility(pub(crate)))]
pub enum ReadFrameError<E, C> {
    /// The Frame Type could not be read.
    #[snafu(display("frame type read failed"))]
    FrameType {
        /// The failure of reading the variable-length integer.
        source: ReadVarIntError<E>,
    },
    /// The Frame Type uses a longer encoding than necessary.
    ///
    /// RFC 9000 §12.4 requires the shortest encoding of the Frame Type; a
    /// longer one is a PROTOCOL_VIOLATION, whether or not the type is known.
    #[snafu(display("frame type encoding check failed"))]
    LongerTypeEncoding {
        /// The broken rule.
        source: LongerTypeEncodingError,
    },
    /// No part of the frame set claims the Frame Type value.
    #[snafu(display("unknown frame type {:#x}", frame_type.get()))]
    UnknownType {
        /// The Frame Type value.
        frame_type: VarInt,
    },
    /// The fields after the Frame Type could not be read, or break a limit
    /// of the encoding.
    #[snafu(transparent)]
    Fields {
        /// The failure, of the part that claims the Frame Type.
        source: PartsError<C>,
    },
}

impl<E, C: FrameFieldsError> ReadFrameError<E, C> {
    /// The Frame Type of the frame, if it could be read.
    ///
    /// This is the value for the Frame Type field of the CONNECTION_CLOSE
    /// frame that reports the error.
    pub fn frame_type(&self) -> Option<VarInt> {
        match self {
            Self::FrameType { .. } => None,
            Self::LongerTypeEncoding { source } => Some(source.frame_type()),
            Self::UnknownType { frame_type } => Some(*frame_type),
            Self::Fields { source } => Some(source.frame_type()),
        }
    }

    /// Whether the source ended within the frame.
    pub fn is_incomplete(&self) -> bool {
        match self {
            Self::FrameType { source } => source.is_incomplete(),
            Self::LongerTypeEncoding { .. } | Self::UnknownType { .. } => false,
            Self::Fields { source } => source.is_incomplete(),
        }
    }

    /// The transport error the failure corresponds to ([RFC 9000 §12.4]):
    /// PROTOCOL_VIOLATION for a Frame Type encoded longer than necessary,
    /// FRAME_ENCODING_ERROR for one that cannot be read or that no part of
    /// the set claims, and for the other fields the code the part that
    /// claims the Frame Type gives.
    ///
    /// [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
    pub fn transport_error_code(&self) -> TransportErrorCode {
        match self {
            Self::LongerTypeEncoding { .. } => TransportErrorCode::PROTOCOL_VIOLATION,
            Self::FrameType { .. } | Self::UnknownType { .. } => {
                TransportErrorCode::FRAME_ENCODING_ERROR
            }
            Self::Fields { source } => source.transport_error_code(),
        }
    }
}
