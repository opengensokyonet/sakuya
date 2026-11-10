//! The transport parameters of version 1 whose value is a connection ID
//! ([RFC 9000 §18.2]): the three that authenticate the connection IDs of
//! the handshake ([RFC 9000 §7.3]).
//!
//! Each is a type of its own that holds the [`ConnectionId`], which is the
//! whole value of the parameter: its length is the length of the value.
//! Whether a parameter matches the connection ID that the packets used, and
//! whether the ones that must be present are, is for the handshake to
//! check.
//!
//! [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
//! [RFC 9000 §7.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-7.3
use self::codec::{
    ReadConnectionIdValueError, ReadConnectionIdValueHostExt as _, write_connection_id_value,
};
use super::{SentBy, TransportParameterSpace};
use crate::{
    connection_id::ConnectionId,
    parameters::{KeyedParameter, ReadValueError, ValueSource, read_value_error::ContentSnafu},
    var_int::VarInt,
};
use bytes::Buf;
use core::convert::Infallible;
use nitori_call::ReceiverAccess;
use nitori_io::{Write, calls::WriteAllError};
use snafu::ResultExt;

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
            type ValueError = ReadValueError<ReadConnectionIdValueError<Infallible>>;

            const ID: VarInt = VarInt::from_u32($id);
            const ATTRIBUTES: SentBy = $sent_by;

            fn read_value<D: Buf + Unpin>(
                value: &mut ValueSource<D>,
            ) -> Result<Self, Self::ValueError> {
                let length = value.remaining();
                value
                    .sync_read_connection_id_value_unpin(length)
                    .map(Self)
                    .context(ContentSnafu)
            }

            fn value_len(&self) -> usize {
                self.0.len()
            }

            async fn write_value<F, A>(&self, io: &mut A) -> Result<(), WriteAllError<F::Error>>
            where
                F: Write,
                A: ReceiverAccess<Family = F>,
            {
                write_connection_id_value(io, self.0).await
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
    //! Reading and writing the value of a parameter that is a connection ID
    //! as `nitori_call` operations.
    //!
    //! The value holds the bytes of the connection ID and nothing else, so
    //! the length of the connection ID is the length of the value, which
    //! [`read_connection_id_value`] takes. [`read_connection_id_value`] and
    //! [`write_connection_id_value`] are also the operation structs
    //! [`ReadConnectionIdValue`] and [`WriteConnectionIdValue`], with
    //! `{Name}Ext` on receiver accesses and `{Name}HostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use crate::connection_id::{ConnectionId, ConnectionIdLength, ConnectionIdLengthError};
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{
        calls::{ReadExactError, WriteAllError},
        prelude::*,
    };
    use snafu::{ResultExt, Snafu};

    /// Reads a connection ID of `length` bytes, the length of the value of
    /// its parameter, and nothing after it.
    ///
    /// # Errors
    ///
    /// [`ReadConnectionIdValueError::Length`] for a length above 20, before
    /// reading anything, and [`ReadConnectionIdValueError::Bytes`] if the
    /// bytes cannot be read.
    #[call(sync)]
    pub async fn read_connection_id_value<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        length: usize,
    ) -> Result<ConnectionId, ReadConnectionIdValueError<F::Error>> {
        let length = ConnectionIdLength::new(length)?;
        let mut id = ConnectionId::EMPTY;
        let mut destination = &mut id.bytes[..length.get()];
        io.read_exact(&mut destination, length.get())
            .await
            .context(read_connection_id_value_error::BytesSnafu)?;
        id.len = u8::from(length);
        Ok(id)
    }

    /// Failures that [`read_connection_id_value`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_connection_id_value_error), visibility(pub(crate)))]
    pub enum ReadConnectionIdValueError<E> {
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
            /// The failure of reading the bytes.
            source: ReadExactError<E>,
        },
    }

    /// Writes the bytes of `id`, without a length.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_connection_id_value<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        id: ConnectionId,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(id.as_bytes()).await
    }
}
