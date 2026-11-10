//! The `disable_active_migration` transport parameter
//! ([RFC 9000 §18.2]).
//!
//! [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
use super::{SentBy, TransportParameterSpace};
use crate::{
    parameters::{KeyedParameter, TrailingBytesError, ValueSource},
    var_int::VarInt,
};
use bytes::Buf;
use nitori_call::ReceiverAccess;
use nitori_io::{Write, calls::WriteAllError};

/// `disable_active_migration`, `0x0c`: the endpoint does not support active
/// connection migration on the address used during the handshake.
///
/// The parameter states this by being present, and its value is empty: a
/// value with bytes is a [`TrailingBytesError`]. Nothing is read from or
/// written to the value, so the type has no read or write operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct DisableActiveMigration;

impl KeyedParameter for DisableActiveMigration {
    type Space = TransportParameterSpace;
    type ValueError = TrailingBytesError;

    const ID: VarInt = VarInt::from_u32(0x0c);
    const ATTRIBUTES: SentBy = SentBy::Either;

    fn read_value<D: Buf + Unpin>(_value: &mut ValueSource<D>) -> Result<Self, Self::ValueError> {
        Ok(Self)
    }

    fn value_len(&self) -> usize {
        0
    }

    async fn write_value<F, A>(&self, _io: &mut A) -> Result<(), WriteAllError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
    {
        Ok(())
    }
}
