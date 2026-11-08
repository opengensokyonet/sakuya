//! Reading a frame of a frame set as a `nitori_call` operation.
//!
//! [`read_frame`] reads one frame of the frame set `P`: its Frame Type, the
//! part of `P` that claims it, and the fields that part reads. Writing is
//! per frame type, in the `codec` module of each frame.
//!
//! [`read_frame`] is also the operation struct [`ReadFrame`], with
//! `ReadFrameExt` on receiver accesses inside other operations and
//! `ReadFrameHostExt` on call executors, including the `sync_` methods for
//! receivers that never wait. Constructing an operation performs no IO.
//!
//! ```
//! use core::marker::PhantomData;
//! use sakuya_wire::{
//!     frame::codec::{ReadFrameError, ReadFrameHostExt as _},
//!     v1::{self, frame::Frame, transport_error::TransportErrorCode},
//! };
//!
//! let set = PhantomData::<v1::Part>;
//! // MAX_DATA with a four-byte Maximum Data, then PING.
//! let mut input = &[0x10, 0x80, 0x00, 0x00, 0x05, 0x01][..];
//! let Frame::MaxData(max_data) = input.sync_read_frame_unpin(set).unwrap() else { panic!() };
//! assert_eq!(max_data.maximum_data().get().get(), 5);
//! assert!(matches!(input.sync_read_frame_unpin(set).unwrap(), Frame::Ping(_)));
//!
//! // A frame cut short is an incomplete failure.
//! let mut input = &[0x10, 0x80][..];
//! assert!(input.sync_read_frame_unpin(set).unwrap_err().is_incomplete());
//!
//! // RESET_STREAM_AT is not a frame of version 1.
//! let mut input = &[0x24, 0, 0, 0, 0][..];
//! let error = input.sync_read_frame_unpin(set).unwrap_err();
//! assert!(matches!(error, ReadFrameError::UnknownType { .. }));
//! assert_eq!(error.transport_error_code(), TransportErrorCode::FRAME_ENCODING_ERROR);
//! ```
// `#[call]` generates constructors, fields and extension traits without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use super::{FrameFieldsError, FrameSetPart};
use crate::{
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

/// Reads one frame of the frame set `P`; `set` names the set.
///
/// The source is the rest of a packet payload: a STREAM or DATAGRAM frame
/// without a Length field takes all of it. Payload fields are chunks of the
/// source. A PADDING frame reads only its one-byte Frame Type.
///
/// The Frame Type must use its shortest encoding ([RFC 9000 §12.4]); a
/// longer one is rejected before the type is looked up.
///
/// # Errors
///
/// [`ReadFrameError::FrameType`] if the Frame Type cannot be read,
/// [`ReadFrameError::LongerTypeEncoding`] if it uses a longer encoding than
/// necessary, [`ReadFrameError::UnknownType`] for a value that no part of
/// `P` claims, and [`ReadFrameError::Fields`] with the failure of the part
/// that claims it if the other fields cannot be read or break a limit of
/// the encoding. Bytes read before a failure stay consumed.
///
/// # Panics
///
/// If the receiver returns a chunk longer than requested, which breaks the
/// `ReadChunk` contract of `nitori_io`; see [`payload`](crate::payload).
///
/// [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
#[call(sync)]
pub async fn read_frame<P, F, A>(
    io: &mut A,
    set: PhantomData<P>,
) -> Result<P::Frame<F::Chunk>, ReadFrameError<F::Error, P::FieldsError<F::Error>>>
where
    P: FrameSetPart,
    F: ReadChunk<Chunk: Default>,
    A: ReceiverAccess<Family = F>,
{
    use read_frame_error::*;
    let PhantomData = set;
    let (frame_type, width) = read_var_int_with_width(io).await.context(FrameTypeSnafu)?;
    LongerTypeEncodingError::check(frame_type, width).context(LongerTypeEncodingSnafu)?;
    let Some(kind) = P::kind_of(frame_type) else {
        return UnknownTypeSnafu { frame_type }.fail();
    };
    let frame = P::read_fields(io, kind, frame_type).await?;
    Ok(frame)
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

/// Failures that [`read_frame`] can produce for a frame set whose parts
/// report the failures of reading fields as `F`.
///
/// The failures of the Frame Type are the same for every frame set; the
/// failures of the other fields come from the part that claims the Frame
/// Type, through [`Fields`](Self::Fields).
#[derive(Debug, Snafu)]
#[snafu(module(read_frame_error), visibility(pub(crate)))]
pub enum ReadFrameError<E, F> {
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
        source: F,
    },
}

impl<E, F: FrameFieldsError> ReadFrameError<E, F> {
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
