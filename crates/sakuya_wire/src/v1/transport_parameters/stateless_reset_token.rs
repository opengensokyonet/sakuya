//! The `stateless_reset_token` transport parameter ([RFC 9000 §18.2]).
//!
//! [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
use self::codec::{ReadStatelessResetTokenValueHostExt as _, write_stateless_reset_token_value};
use super::{SentBy, TransportParameterSpace};
use crate::{
    connection_id,
    parameters::{KeyedParameter, ReadValueError, ValueSource, read_value_error::ContentSnafu},
    var_int::VarInt,
};
use bytes::Buf;
use core::convert::Infallible;
use nitori_call::ReceiverAccess;
use nitori_io::{
    Write,
    calls::{ReadArrayError, WriteAllError},
};
use snafu::ResultExt;

/// `stateless_reset_token`, `0x02`: the Stateless Reset Token of the
/// connection ID the server chose during the handshake; sent only by a
/// server.
///
/// It holds the token, a
/// [`connection_id::StatelessResetToken`],
/// which is the whole value of the parameter: 16 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StatelessResetToken(connection_id::StatelessResetToken);

impl StatelessResetToken {
    /// The parameter with `token`.
    pub const fn new(token: connection_id::StatelessResetToken) -> Self {
        Self(token)
    }

    /// The token.
    pub const fn get(self) -> connection_id::StatelessResetToken {
        self.0
    }
}

impl From<connection_id::StatelessResetToken> for StatelessResetToken {
    fn from(token: connection_id::StatelessResetToken) -> Self {
        Self(token)
    }
}

impl From<StatelessResetToken> for connection_id::StatelessResetToken {
    fn from(parameter: StatelessResetToken) -> Self {
        parameter.0
    }
}

impl KeyedParameter for StatelessResetToken {
    type Space = TransportParameterSpace;
    type ValueError = ReadValueError<ReadArrayError<Infallible>>;

    const ID: VarInt = VarInt::from_u32(0x02);
    const ATTRIBUTES: SentBy = SentBy::ServerOnly;

    fn read_value<D: Buf + Unpin>(value: &mut ValueSource<D>) -> Result<Self, Self::ValueError> {
        value
            .sync_read_stateless_reset_token_value_unpin()
            .map(Self)
            .context(ContentSnafu)
    }

    fn value_len(&self) -> usize {
        connection_id::StatelessResetToken::LEN
    }

    async fn write_value<F, A>(&self, io: &mut A) -> Result<(), WriteAllError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
    {
        write_stateless_reset_token_value(io, self.0).await
    }
}

pub mod codec {
    //! Reading and writing the value of the `stateless_reset_token`
    //! parameter as `nitori_call` operations.
    //!
    //! [`read_stateless_reset_token_value`] and
    //! [`write_stateless_reset_token_value`] are also the operation structs
    //! [`ReadStatelessResetTokenValue`] and [`WriteStatelessResetTokenValue`],
    //! with `{Name}Ext` on receiver accesses and `{Name}HostExt` on call
    //! executors. Reading the parameters reads this value from the bytes of
    //! its parameter, which must hold nothing else.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use crate::connection_id::StatelessResetToken;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{
        calls::{ReadArrayError, WriteAllError},
        prelude::*,
    };

    /// Reads the 16 bytes of a Stateless Reset Token, and nothing after
    /// them.
    ///
    /// # Errors
    ///
    /// [`ReadArrayError`] if the bytes cannot be read; a source that ends
    /// before the sixteenth byte is incomplete.
    #[call(sync)]
    pub async fn read_stateless_reset_token_value<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<StatelessResetToken, ReadArrayError<F::Error>> {
        io.read_array::<{ StatelessResetToken::LEN }>()
            .await
            .map(StatelessResetToken::new)
    }

    /// Writes the 16 bytes of `token`.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_stateless_reset_token_value<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        token: StatelessResetToken,
    ) -> Result<(), WriteAllError<F::Error>> {
        let bytes = *token.as_bytes();
        io.write_all(&bytes[..]).await
    }
}
