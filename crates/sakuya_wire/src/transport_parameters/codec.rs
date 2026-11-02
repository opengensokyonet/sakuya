//! Reading and writing transport parameters as `nitori_call` operations.
//!
//! [`read_transport_parameters`] reads the whole value of the
//! `quic_transport_parameters` TLS extension, to the end of the source;
//! [`write_transport_parameters`] writes it. Each function is also an
//! operation struct with `{Name}Ext` on receiver accesses inside other
//! operations and `{Name}HostExt` on call executors, including the `sync_`
//! methods for receivers that never wait.
// `#[call]` generates constructors, fields and extension traits without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use super::{
    InvalidParameterError, TransportParameters, UnknownParameter, Value, id,
    preferred_address::{
        PreferredAddress,
        codec::{ReadPreferredAddressError, ReadPreferredAddressHostExt as _},
    },
    server_only,
};
use crate::{
    connection_id::{ConnectionId, ConnectionIdLengthError, StatelessResetToken},
    frame::{Head, LengthError},
    payload::{ReadPayloadError, read_payload},
    role::Role,
    transport_error::TransportErrorCode,
    var_int::{
        VarInt,
        codec::{ReadVarIntError, ReadVarIntExt as _, ReadVarIntHostExt as _},
    },
};
use bytes::{Buf, BufMut};
use core::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{calls::WriteAllError, error::WriteZero, prelude::*};
use snafu::{IntoError, ResultExt, Snafu};

/// Reads the transport parameters that an endpoint in role `sender` sent:
/// the whole source.
///
/// Values of unknown parameters are chunks of the source.
///
/// # Errors
///
/// [`ReadTransportParametersError::Field`] or
/// [`ReadTransportParametersError::Value`] if the source ends within a
/// parameter; a variant named after the layout of a known parameter for a
/// value that does not fit it; and [`ReadTransportParametersError::Invalid`]
/// for a parameter that appears twice, that a client sent but only a server
/// may send, or whose value is out of range.
#[call(sync)]
pub async fn read_transport_parameters<F, A>(
    io: &mut A,
    sender: Role,
) -> Result<TransportParameters<F::Chunk>, ReadTransportParametersError<F::Error>>
where
    F: ReadChunk<Chunk: Default + Unpin>,
    A: ReceiverAccess<Family = F>,
{
    use read_transport_parameters_error::*;
    let mut parameters = TransportParameters::default();
    let mut seen = 0u32;
    loop {
        let id = match io.read_var_int().await {
            Ok(id) => id,
            // The source ended between parameters.
            Err(error) if error.is_incomplete() && error.completed() == 0 => break,
            Err(error) => return Err(FieldSnafu.into_error(error)),
        };
        let length = io.read_var_int().await.context(FieldSnafu)?;
        let length = usize::try_from(length.get()).unwrap_or(usize::MAX);
        let value = read_payload(io, length).await.context(ValueSnafu { id })?;
        if id.get() <= id::LAST {
            let bit = 1 << id.get();
            if seen & bit != 0 {
                return Err(InvalidParameterError::Duplicate { id }.into());
            }
            seen |= bit;
            if sender == Role::Client && server_only(id) {
                return Err(InvalidParameterError::ServerOnly { id }.into());
            }
            set(&mut parameters, id, value)?;
        } else {
            if parameters
                .unknown
                .iter()
                .any(|parameter| parameter.id == id)
            {
                return Err(InvalidParameterError::Duplicate { id }.into());
            }
            parameters.unknown.push(UnknownParameter { id, value });
        }
    }
    parameters.check_ranges()?;
    Ok(parameters)
}

/// Sets the known parameter `id` from its value.
fn set<D: Buf + Unpin, E>(
    parameters: &mut TransportParameters<D>,
    id: VarInt,
    value: D,
) -> Result<(), ReadTransportParametersError<E>> {
    use read_transport_parameters_error::*;
    let length = value.remaining();
    let mut value = ValueSource(value);
    match id {
        id::ORIGINAL_DESTINATION_CONNECTION_ID => {
            parameters.original_destination_connection_id = Some(connection_id(id, value.0)?);
        }
        id::INITIAL_SOURCE_CONNECTION_ID => {
            parameters.initial_source_connection_id = Some(connection_id(id, value.0)?);
        }
        id::RETRY_SOURCE_CONNECTION_ID => {
            parameters.retry_source_connection_id = Some(connection_id(id, value.0)?);
        }
        id::STATELESS_RESET_TOKEN => {
            if length != StatelessResetToken::LEN {
                return StatelessResetTokenSnafu { length }.fail();
            }
            let mut token = [0; StatelessResetToken::LEN];
            // invariant: the value was checked to hold exactly the token.
            value.0.copy_to_slice(&mut token);
            parameters.stateless_reset_token = Some(StatelessResetToken::new(token));
        }
        id::DISABLE_ACTIVE_MIGRATION => {
            if length != 0 {
                return DisableActiveMigrationSnafu { length }.fail();
            }
            parameters.disable_active_migration = true;
        }
        id::PREFERRED_ADDRESS => {
            let address = value
                .sync_read_preferred_address_unpin()
                .context(PreferredAddressSnafu)?;
            if value.0.has_remaining() {
                return PreferredAddressLengthSnafu { length }.fail();
            }
            parameters.preferred_address = Some(address);
        }
        _ => {
            let integer = match value.sync_read_var_int_unpin() {
                Ok(integer) if !value.0.has_remaining() => integer,
                _ => return IntegerSnafu { id, length }.fail(),
            };
            let field = match id {
                id::MAX_IDLE_TIMEOUT => &mut parameters.max_idle_timeout,
                id::MAX_UDP_PAYLOAD_SIZE => &mut parameters.max_udp_payload_size,
                id::INITIAL_MAX_DATA => &mut parameters.initial_max_data,
                id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    &mut parameters.initial_max_stream_data_bidi_local
                }
                id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    &mut parameters.initial_max_stream_data_bidi_remote
                }
                id::INITIAL_MAX_STREAM_DATA_UNI => &mut parameters.initial_max_stream_data_uni,
                id::INITIAL_MAX_STREAMS_BIDI => &mut parameters.initial_max_streams_bidi,
                id::INITIAL_MAX_STREAMS_UNI => &mut parameters.initial_max_streams_uni,
                id::ACK_DELAY_EXPONENT => &mut parameters.ack_delay_exponent,
                id::MAX_ACK_DELAY => &mut parameters.max_ack_delay,
                // Every other ID up to `id::LAST` is an integer parameter.
                _ => &mut parameters.active_connection_id_limit,
            };
            *field = integer;
        }
    }
    Ok(())
}

/// The connection ID that the value of the parameter `id` holds.
fn connection_id<D: Buf, E>(
    id: VarInt,
    mut value: D,
) -> Result<ConnectionId, ReadTransportParametersError<E>> {
    let length = value.remaining();
    if length > ConnectionId::MAX_LEN {
        return Err(read_transport_parameters_error::ConnectionIdSnafu { id }
            .into_error(ConnectionIdLengthError { length }));
    }
    let mut bytes = [0; ConnectionId::MAX_LEN];
    // invariant: the value holds `length` bytes, at most 20.
    value.copy_to_slice(&mut bytes[..length]);
    ConnectionId::new(&bytes[..length])
        .context(read_transport_parameters_error::ConnectionIdSnafu { id })
}

/// The value of a known parameter as a source of its own, so that the value
/// is read with the same operations as the parameters, within its length.
struct ValueSource<D>(D);

nitori_call::family_receiver!(impl [D: Buf + Unpin] for ValueSource<D>);

impl<D: Buf + Unpin> Read for ValueSource<D> {
    type Error = Infallible;

    fn poll_read<'visit, Output: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        _: &mut Context<'_>,
        mut destination: &mut Output,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'visit,
    {
        let source = &mut host.get_pin_mut().get_mut().0;
        let count = source.remaining().min(destination.remaining_mut());
        BufMut::put(&mut destination, source.take(count));
        Poll::Ready(Ok(count))
    }
}

/// Failures that [`read_transport_parameters`] can produce.
///
/// Every failure corresponds to the transport error
/// TRANSPORT_PARAMETER_ERROR
/// ([`ReadTransportParametersError::transport_error_code`]).
#[derive(Debug, Snafu)]
#[snafu(module(read_transport_parameters_error), visibility(pub(crate)))]
pub enum ReadTransportParametersError<E> {
    /// The ID or length of a parameter could not be read.
    #[snafu(display("transport parameter field read failed"))]
    Field {
        /// The failure of reading the field.
        source: ReadVarIntError<E>,
    },
    /// The value of a parameter could not be read.
    #[snafu(display("transport parameter {:#x} value read failed", id.get()))]
    Value {
        /// The parameter ID.
        id: VarInt,
        /// The failure of reading the value.
        source: ReadPayloadError<E>,
    },
    /// The value of an integer parameter is not exactly one variable-length
    /// integer.
    #[snafu(display(
        "transport parameter {:#x} has a value of {length} bytes that is not one variable-length integer",
        id.get()
    ))]
    Integer {
        /// The parameter ID.
        id: VarInt,
        /// The length of the value.
        length: usize,
    },
    /// A connection ID parameter is longer than 20 bytes.
    #[snafu(display("transport parameter {:#x} holds an invalid connection ID", id.get()))]
    ConnectionId {
        /// The parameter ID.
        id: VarInt,
        /// The rejected length.
        source: ConnectionIdLengthError,
    },
    /// The value of `stateless_reset_token` is not 16 bytes long.
    #[snafu(display("stateless_reset_token value of {length} bytes is not 16 bytes"))]
    StatelessResetToken {
        /// The length of the value.
        length: usize,
    },
    /// `disable_active_migration` has a value.
    #[snafu(display("disable_active_migration has a value of {length} bytes"))]
    DisableActiveMigration {
        /// The length of the value.
        length: usize,
    },
    /// The value of `preferred_address` is shorter than its fields, holds no
    /// address of either family or holds an invalid connection ID.
    #[snafu(display("preferred_address value read failed"))]
    PreferredAddress {
        /// The failure of reading the fields from the value.
        source: ReadPreferredAddressError<Infallible>,
    },
    /// The value of `preferred_address` is longer than its fields.
    #[snafu(display("preferred_address value of {length} bytes is longer than its fields"))]
    PreferredAddressLength {
        /// The length of the value.
        length: usize,
    },
    /// A parameter is forbidden.
    #[snafu(transparent)]
    Invalid {
        /// Why the parameter is forbidden.
        source: InvalidParameterError,
    },
}

impl<E> ReadTransportParametersError<E> {
    /// Whether the source ended within a parameter.
    pub fn is_incomplete(&self) -> bool {
        match self {
            Self::Field { source } => source.is_incomplete(),
            Self::Value { source, .. } => source.is_incomplete(),
            _ => false,
        }
    }

    /// The transport error the failure corresponds to: always
    /// TRANSPORT_PARAMETER_ERROR ([RFC 9000 §7.4]).
    ///
    /// [RFC 9000 §7.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-7.4
    pub fn transport_error_code(&self) -> TransportErrorCode {
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR
    }
}

/// Writes `parameters` as an endpoint in role `sender` sends them, after
/// checking them with [`TransportParameters::validate`].
///
/// Parameters with their default values are omitted; the others are written
/// in the order of their IDs, followed by the unknown parameters in their
/// order. Acceptance by the receiver does not imply flushing or delivery.
///
/// # Errors
///
/// [`WriteTransportParametersError::Invalid`] before writing anything, and
/// [`WriteTransportParametersError::Write`] if the receiver stops accepting
/// bytes or fails; bytes accepted before stay written, and the error counts
/// them over the whole encoding.
#[call(sync)]
pub async fn write_transport_parameters<F, A, D>(
    io: &mut A,
    parameters: TransportParameters<D>,
    sender: Role,
) -> Result<(), WriteTransportParametersError<F::Error>>
where
    F: Write,
    A: ReceiverAccess<Family = F>,
    D: Buf,
{
    use write_transport_parameters_error::*;
    parameters.validate(sender)?;
    let mut known = Vec::new();
    parameters.for_each(|id, value| {
        if let Some(head) = known_parameter(id, value) {
            known.push(head);
        }
    });
    let mut written = 0;
    for head in known {
        put(io, head.as_slice(), &mut written)
            .await
            .context(WriteSnafu)?;
    }
    for parameter in parameters.unknown {
        // Validation bounds the length of each value by 2^62 - 1.
        let length = LengthError::length_field(parameter.value.remaining()).unwrap_or(VarInt::MAX);
        let head = Head::<16>::new(parameter.id).var_int(length);
        put(io, head.as_slice().chain(parameter.value), &mut written)
            .await
            .context(WriteSnafu)?;
    }
    Ok(())
}

/// The longest encoding of a known parameter: ID, length and a preferred
/// address.
const KNOWN_MAX: usize = 8 + 8 + PreferredAddress::MAX_LEN;

/// The encoding of a known parameter, or `None` for an unknown one.
fn known_parameter<D>(id: VarInt, value: Value<'_, D>) -> Option<Head<KNOWN_MAX>> {
    let head = Head::<KNOWN_MAX>::new(id);
    Some(match value {
        Value::Integer(integer) => head
            .var_int(VarInt::from_u32(integer.encoded_len() as u32))
            .var_int(integer),
        Value::Bytes(bytes) => head
            .var_int(VarInt::from_u32(bytes.len() as u32))
            .bytes(bytes),
        Value::PreferredAddress(address) => {
            let (encoding, length) = address.to_encoding();
            head.var_int(VarInt::from_u32(length as u32))
                .bytes(&encoding[..length])
        }
        Value::Unknown(_) => return None,
    })
}

/// Writes `bytes` completely, counting the progress of the whole encoding in
/// `written`.
async fn put<F: Write, A: ReceiverAccess<Family = F>, B: Buf>(
    io: &mut A,
    bytes: B,
    written: &mut usize,
) -> Result<(), WriteAllError<F::Error>> {
    let length = bytes.remaining();
    let before = *written;
    match io.write_all(bytes).await {
        Ok(()) => {
            *written += length;
            Ok(())
        }
        Err(WriteAllError::WriteZero { source }) => Err(WriteAllError::WriteZero {
            source: WriteZero {
                completed: before + source.completed,
            },
        }),
        Err(WriteAllError::Receiver { source, completed }) => Err(WriteAllError::Receiver {
            source,
            completed: before + completed,
        }),
    }
}

/// Failures that [`write_transport_parameters`] can produce.
#[derive(Debug, Snafu)]
#[snafu(module(write_transport_parameters_error), visibility(pub(crate)))]
pub enum WriteTransportParametersError<E> {
    /// A parameter is forbidden; nothing was written.
    #[snafu(transparent)]
    Invalid {
        /// Why the parameter is forbidden.
        source: InvalidParameterError,
    },
    /// The receiver stopped accepting bytes or failed.
    #[snafu(display("transport parameters write failed"))]
    Write {
        /// The failure of writing; it counts the bytes accepted before over
        /// the whole encoding.
        source: WriteAllError<E>,
    },
}
