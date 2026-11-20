//! The transport parameters of version 1 whose value is a connection ID
//! ([RFC 9000 §18.2]): the three that authenticate the connection IDs of
//! the handshake ([RFC 9000 §7.3]).
//!
//! Each is a type of its own that holds the [`ConnectionId`], which is the
//! whole value of the parameter: its length is the length of the value.
//! Whether a parameter matches the connection ID that the packets used, and
//! whether the ones that must be present are, is for the handshake to
//! check. None of them is remembered for 0-RTT ([RFC 9000 §7.4.1]): they
//! belong to the connection that sends them.
//!
//! [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
//! [RFC 9000 §7.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-7.3
//! [RFC 9000 §7.4.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-7.4.1
use self::codec::{
    ReadConnectionIdValueError, read_connection_id_value, write_connection_id_value,
};
use super::{RememberedForZeroRtt, SentBy, TransportParameterAttributes, TransportParameterSpace};
use bytes::{Buf, BufMut};
use sakuya_wire::{
    connection_id::ConnectionId,
    parameters::{KeyedParameter, ReadValueError, ValueSource},
    var_int::VarInt,
};

/// Defines a transport parameter that holds a connection ID.
macro_rules! connection_id {
    ($(#[$doc:meta])* $name:ident, $id:literal, $sent_by:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name(ConnectionId);

        impl $name {
            /// The parameter with `connection_id`.
            pub const fn new(connection_id: ConnectionId) -> Self {
                Self(connection_id)
            }

            /// The connection ID.
            pub const fn get(self) -> ConnectionId {
                self.0
            }
        }

        impl From<ConnectionId> for $name {
            fn from(connection_id: ConnectionId) -> Self {
                Self(connection_id)
            }
        }

        impl From<$name> for ConnectionId {
            fn from(parameter: $name) -> Self {
                parameter.0
            }
        }

        impl KeyedParameter for $name {
            type Space = TransportParameterSpace;
            type ValueError = ReadValueError<ReadConnectionIdValueError>;

            const ID: VarInt = VarInt::from_u32($id);
            const ATTRIBUTES: TransportParameterAttributes = TransportParameterAttributes {
                sent_by: $sent_by,
                remembered_for_zero_rtt: RememberedForZeroRtt::Prohibited,
            };

            fn read_value<D: Buf>(value: &mut ValueSource<D>) -> Result<Self, Self::ValueError> {
                let length = value.remaining();
                read_connection_id_value(value, length)
                    .map(Self)
                    .map_err(|source| ReadValueError::Content { source })
            }

            fn value_len(&self) -> usize {
                self.0.len()
            }

            fn write_value<B: BufMut>(&self, dst: &mut B) {
                write_connection_id_value(dst, self.0);
            }
        }
    };
}

connection_id! {
    /// `original_destination_connection_id`, `0x00`: the Destination
    /// Connection ID of the client's first Initial packet; sent only by a
    /// server.
    OriginalDestinationConnectionId, 0x00, SentBy::ServerOnly
}

connection_id! {
    /// `initial_source_connection_id`, `0x0f`: the Source Connection ID of
    /// the first Initial packet the endpoint sent.
    InitialSourceConnectionId, 0x0f, SentBy::Either
}

connection_id! {
    /// `retry_source_connection_id`, `0x10`: the Source Connection ID of the
    /// server's Retry packet; sent only by a server.
    RetrySourceConnectionId, 0x10, SentBy::ServerOnly
}

pub mod codec {
    //! Reading and writing the value of a parameter that is a connection ID.
    //!
    //! The value holds the bytes of the connection ID and nothing else, so
    //! the length of the connection ID is the length of the value, which
    //! [`read_connection_id_value`] takes.

    use bytes::{Buf, BufMut};
    use nitori_io::error::IncompleteError;
    use sakuya_wire::{
        connection_id::{ConnectionId, ConnectionIdLength, ConnectionIdLengthError},
        source::incomplete,
    };
    use snafu::Snafu;

    /// Reads a connection ID of `length` bytes, the length of the value of
    /// its parameter, and nothing after it.
    ///
    /// # Errors
    ///
    /// [`ReadConnectionIdValueError::Length`] for a length above 20, before
    /// reading anything, and [`ReadConnectionIdValueError::Bytes`] if the
    /// source ends within the bytes.
    pub fn read_connection_id_value(
        src: &mut impl Buf,
        length: usize,
    ) -> Result<ConnectionId, ReadConnectionIdValueError> {
        let length = ConnectionIdLength::new(length)?;
        if src.remaining() < length.get() {
            let source = incomplete(src, length.get(), 0);
            return Err(ReadConnectionIdValueError::Bytes { source });
        }
        let mut bytes = [0; ConnectionId::MAX_LEN];
        src.copy_to_slice(&mut bytes[..length.get()]);
        Ok(ConnectionId::new(&bytes[..length.get()])?)
    }

    /// Failures that [`read_connection_id_value`] can produce.
    #[derive(Debug, Snafu)]
    pub enum ReadConnectionIdValueError {
        /// The value is longer than 20 bytes, the longest connection ID of
        /// QUIC version 1.
        #[snafu(transparent)]
        Length {
            /// The rejected length.
            source: ConnectionIdLengthError,
        },
        /// The bytes of the connection ID could not be read.
        #[snafu(display("connection ID read failed"))]
        Bytes {
            /// The shortfall, counted over the bytes of the connection ID.
            source: IncompleteError,
        },
    }

    /// Writes the bytes of `id`, without a length.
    ///
    /// # Panics
    ///
    /// If `dst` has no room for the connection ID, as [`BufMut`] does.
    pub fn write_connection_id_value(dst: &mut impl BufMut, id: ConnectionId) {
        dst.put_slice(id.as_bytes());
    }
}
