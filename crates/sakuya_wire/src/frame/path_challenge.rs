//! PATH_CHALLENGE frames ([RFC 9000 §19.17]).
//!
//! [RFC 9000 §19.17]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.17
use super::{Head, PATH_DATA_LEN, type_value, type_var_int};
use crate::var_int::VarInt;

/// A PATH_CHALLENGE frame ([RFC 9000 §19.17]).
///
/// [`PathChallenge::new`] accepts any data, which is read through
/// [`PathChallenge::data`].
///
/// [RFC 9000 §19.17]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.17
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PathChallenge {
    data: [u8; PATH_DATA_LEN],
}

impl PathChallenge {
    /// The PATH_CHALLENGE frame with this data.
    pub const fn new(data: [u8; PATH_DATA_LEN]) -> Self {
        Self { data }
    }

    /// The data the peer echoes in PATH_RESPONSE.
    pub const fn data(&self) -> [u8; PATH_DATA_LEN] {
        self.data
    }

    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::PATH_CHALLENGE)
    }

    /// The number of bytes [`codec::write_path_challenge`] writes.
    pub const fn encoded_len(&self) -> usize {
        1 + PATH_DATA_LEN
    }

    /// The encoded frame.
    pub(crate) fn head(&self) -> Head<{ 1 + PATH_DATA_LEN }> {
        Head::new(self.type_value()).bytes(&self.data)
    }
}

pub mod codec {
    //! Writing PATH_CHALLENGE as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_path_challenge`] is also the operation struct [`WritePathChallenge`], with
    //! `WritePathChallengeExt` on receiver accesses and `WritePathChallengeHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::PathChallenge;
    use crate::frame::PATH_DATA_LEN;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{
        calls::{ReadArrayError, WriteAllError},
        prelude::*,
    };

    /// Reads the data that follows the Frame Type.
    pub(crate) async fn read_path_challenge<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<PathChallenge, ReadArrayError<F::Error>> {
        Ok(PathChallenge::new(io.read_array::<PATH_DATA_LEN>().await?))
    }

    /// Writes the frame.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_path_challenge<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: PathChallenge,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::PathChallenge;
    use crate::frame::{
        Frame,
        tests::{assert_bytes_round_trip, assert_round_trip},
    };

    #[test]
    fn round_trips() {
        let encoding = assert_round_trip(Frame::PathChallenge(PathChallenge::new(*b"challeng")));
        assert_eq!(encoding[1..], *b"challeng");
        let Frame::PathChallenge(read) = assert_bytes_round_trip(&encoding) else {
            panic!("{encoding:02x?}")
        };
        assert_eq!(read.data(), *b"challeng");
    }
}
