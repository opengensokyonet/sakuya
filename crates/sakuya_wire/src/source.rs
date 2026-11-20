//! Reading from a source that holds a whole format in memory.
//!
//! Every reader of this crate reads from a [`Buf`]. A variable-length
//! payload field, such as the data of a STREAM frame or a token, is read
//! with [`SplitTo`] as a piece of the source itself: a byte slice yields a
//! subslice, and `Bytes` or `BytesMut` a piece that shares its storage, so
//! reading copies no payload. A source that ends before a field is complete
//! is an [`IncompleteError`]; the bytes that were there stay consumed.
use bytes::Buf;
use nitori_io::{SplitTo, error::IncompleteError};

/// The failure of a field of `expected` bytes of which `offset` have been
/// read, when `src` holds fewer than the rest; consumes what is left.
pub fn incomplete(src: &mut impl Buf, expected: usize, offset: usize) -> IncompleteError {
    let completed = offset + src.remaining();
    src.advance(src.remaining());
    // invariant: every caller has found fewer than `expected - offset` bytes
    // left, so `completed` is below `expected`.
    IncompleteError::new(expected, completed).expect("fewer bytes are left than the field needs")
}

/// Reads `N` bytes.
pub fn read_array<const N: usize>(src: &mut impl Buf) -> Result<[u8; N], IncompleteError> {
    if src.remaining() < N {
        return Err(incomplete(src, N, 0));
    }
    let mut array = [0; N];
    src.copy_to_slice(&mut array);
    Ok(array)
}

/// Reads a payload field of `length` bytes as a piece of the source.
pub fn read_payload<S: Buf + SplitTo>(src: &mut S, length: usize) -> Result<S, IncompleteError> {
    if src.remaining() < length {
        return Err(incomplete(src, length, 0));
    }
    // invariant: `length` is at most what remains, the length of the source.
    Ok(src.split_to(length).expect("the source holds the field"))
}

/// Reads the rest of the source as a payload field.
pub fn read_payload_to_end<S: Buf + SplitTo>(src: &mut S) -> S {
    let length = src.remaining();
    // invariant: the remaining bytes are the length of the source.
    src.split_to(length)
        .expect("the source holds its remaining bytes")
}
