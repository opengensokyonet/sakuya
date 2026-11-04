//! The `cookie` extension (RFC 9846 §4.3.2).

use crate::{vector::LengthOutOfRangeError, width::Width};

/// The data of a `cookie` extension: an opaque value of 1 to 65533 bytes, so
/// that the extension data fits its two-byte length.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Cookie<C> {
    cookie: C,
}

impl<C: AsRef<[u8]>> Cookie<C> {
    /// The cookie `cookie`.
    ///
    /// # Errors
    ///
    /// [`LengthOutOfRangeError`] if `cookie` is empty or longer than 65533 bytes.
    pub fn new(cookie: C) -> Result<Self, LengthOutOfRangeError> {
        LengthOutOfRangeError::check(cookie.as_ref().len(), 1..=Width::U16.max() - 2)?;
        Ok(Self { cookie })
    }

    /// The number of bytes [`codec::write_cookie`] writes.
    pub fn encoded_len(&self) -> usize {
        2 + self.cookie.as_ref().len()
    }
}

impl<C> Cookie<C> {
    /// The cookie.
    pub fn cookie(&self) -> &C {
        &self.cookie
    }
}

pub mod codec {
    //! Reading and writing cookies as `nitori_call` operations.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::Cookie;
    use crate::{
        message::MessageSource,
        vector::{Out, ReadBoundedVectorError, read_bounded_vector},
        width::Width,
    };
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{Write, calls::WriteAllError};

    /// Reads the data of a `cookie` extension.
    ///
    /// # Errors
    ///
    /// [`ReadBoundedVectorError`], for a cookie that is empty or not all
    /// there.
    #[call(sync)]
    pub async fn read_cookie<F: MessageSource, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<Cookie<F::Bytes>, ReadBoundedVectorError> {
        let cookie = read_bounded_vector(io, Width::U16, 1..=Width::U16.max()).await?;
        Ok(Cookie { cookie })
    }

    /// Writes the data of a `cookie` extension.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails.
    #[call(sync)]
    pub async fn write_cookie<F: Write, A: ReceiverAccess<Family = F>, C: AsRef<[u8]>>(
        io: &mut A,
        cookie: &Cookie<C>,
    ) -> Result<(), WriteAllError<F::Error>> {
        cookie.encode(&mut Out::new(io)).await
    }

    impl<C: AsRef<[u8]>> Cookie<C> {
        pub(crate) async fn encode<F: Write, A: ReceiverAccess<Family = F>>(
            &self,
            out: &mut Out<'_, A>,
        ) -> Result<(), WriteAllError<F::Error>> {
            out.vector(Width::U16, self.cookie.as_ref()).await
        }
    }
}
