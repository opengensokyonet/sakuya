//! The `stateless_reset_token` transport parameter ([RFC 9000 §18.2]).
//!
//! [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
use self::codec::{read_stateless_reset_token_value, write_stateless_reset_token_value};
use super::{RememberedForZeroRtt, SentBy, TransportParameterAttributes, TransportParameterSpace};
use crate::connection_id;
use crate::parameters::{KeyedParameter, ReadValueError, ValueSource};
use bytes::{Buf, BufMut};
use nitori_io::error::IncompleteError;
use sakuya_var_int::VarInt;

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
    type ValueError = ReadValueError<IncompleteError>;

    const ID: VarInt = VarInt::from_u32(0x02);
    const ATTRIBUTES: TransportParameterAttributes = TransportParameterAttributes {
        sent_by: SentBy::ServerOnly,
        remembered_for_zero_rtt: RememberedForZeroRtt::Prohibited,
    };

    fn read_value<D: Buf>(value: &mut ValueSource<D>) -> Result<Self, Self::ValueError> {
        read_stateless_reset_token_value(value)
            .map(Self)
            .map_err(|source| ReadValueError::Content { source })
    }

    fn value_len(&self) -> usize {
        connection_id::StatelessResetToken::LEN
    }

    fn write_value<B: BufMut>(&self, dst: &mut B) {
        write_stateless_reset_token_value(dst, self.0);
    }
}

pub mod codec {
    //! Reading and writing the value of the `stateless_reset_token`
    //! parameter.
    //!
    //! Reading the parameters reads this value from the bytes of its
    //! parameter, which must hold nothing else.

    use crate::connection_id::StatelessResetToken;
    use bytes::{Buf, BufMut};
    use nitori_io::error::IncompleteError;
    use sakuya_wire::source::read_array;

    /// Reads the 16 bytes of a Stateless Reset Token, and nothing after
    /// them.
    ///
    /// # Errors
    ///
    /// [`IncompleteError`] if the source ends before the sixteenth byte.
    pub fn read_stateless_reset_token_value(
        src: &mut impl Buf,
    ) -> Result<StatelessResetToken, IncompleteError> {
        read_array::<{ StatelessResetToken::LEN }>(src).map(StatelessResetToken::new)
    }

    /// Writes the 16 bytes of `token`.
    ///
    /// # Panics
    ///
    /// If `dst` has no room for the token, as [`BufMut`] does.
    pub fn write_stateless_reset_token_value(dst: &mut impl BufMut, token: StatelessResetToken) {
        dst.put_slice(token.as_bytes());
    }
}
