//! QUIC transport parameters ([RFC 9000 §18]).
//!
//! Each endpoint states its transport parameters once, in the TLS handshake:
//! a sequence of parameters, each an ID and a length, both variable-length
//! integers, followed by that many bytes of value. [`TransportParameters`]
//! holds every parameter QUIC version 1 defines, with the defaults of
//! [RFC 9000 §18.2] for those that are absent, and keeps the parameters it
//! does not know as [`UnknownParameter`]s, so that extensions can interpret
//! them. Their values are chunks of the source the parameters were read
//! from: subslices of a byte slice, or `Bytes` that share the storage of a
//! `Bytes` source.
//!
//! [`codec::read_transport_parameters`] and
//! [`codec::write_transport_parameters`] take the [`Role`] of the endpoint
//! that sends the parameters, since a client must not send the parameters
//! that only a server may send. Both check the values RFC 9000 §18.2
//! constrains and reject a parameter that appears twice. Whether the
//! connection ID parameters match the connection IDs that the packets used
//! ([RFC 9000 §7.3]), and whether the ones that must be present are, is for
//! the handshake to check. Every [`codec::ReadTransportParametersError`]
//! corresponds to TRANSPORT_PARAMETER_ERROR.
//!
//! ```
//! use sakuya_wire::{
//!     role::Role,
//!     stream_count::StreamCount,
//!     transport_parameters::{
//!         TransportParameters,
//!         codec::{ReadTransportParametersHostExt as _, WriteTransportParametersHostExt as _},
//!     },
//!     var_int::VarInt,
//! };
//!
//! let mut parameters = TransportParameters::<&[u8]>::default();
//! parameters.initial_max_data = VarInt::from(1_048_576u32);
//! parameters.initial_max_streams_bidi = StreamCount::new(100).unwrap();
//!
//! let mut encoding = Vec::new();
//! encoding
//!     .sync_write_transport_parameters_unpin(parameters.clone(), Role::Client)
//!     .unwrap();
//! assert_eq!(encoding.len(), parameters.encoded_len());
//!
//! let decoded = encoding
//!     .as_slice()
//!     .sync_read_transport_parameters_unpin(Role::Client)
//!     .unwrap();
//! assert_eq!(decoded, parameters);
//! assert_eq!(decoded.max_udp_payload_size, VarInt::from(65527u16)); // The default.
//! ```
//!
//! [RFC 9000 §18]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18
//! [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
//! [RFC 9000 §7.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-7.3
use crate::{
    connection_id::{ConnectionId, StatelessResetToken},
    role::Role,
    stream_count::{StreamCount, StreamCountError},
    var_int::VarInt,
};
use bytes::Buf;
use preferred_address::PreferredAddress;
use snafu::Snafu;

pub mod codec;
pub mod preferred_address;

/// The transport parameter IDs of QUIC version 1 ([RFC 9000 §18.2]).
///
/// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
pub mod id {
    use crate::var_int::VarInt;

    /// `original_destination_connection_id`, `0x00`.
    pub const ORIGINAL_DESTINATION_CONNECTION_ID: VarInt = VarInt::from_u32(0x00);
    /// `max_idle_timeout`, `0x01`.
    pub const MAX_IDLE_TIMEOUT: VarInt = VarInt::from_u32(0x01);
    /// `stateless_reset_token`, `0x02`.
    pub const STATELESS_RESET_TOKEN: VarInt = VarInt::from_u32(0x02);
    /// `max_udp_payload_size`, `0x03`.
    pub const MAX_UDP_PAYLOAD_SIZE: VarInt = VarInt::from_u32(0x03);
    /// `initial_max_data`, `0x04`.
    pub const INITIAL_MAX_DATA: VarInt = VarInt::from_u32(0x04);
    /// `initial_max_stream_data_bidi_local`, `0x05`.
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: VarInt = VarInt::from_u32(0x05);
    /// `initial_max_stream_data_bidi_remote`, `0x06`.
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: VarInt = VarInt::from_u32(0x06);
    /// `initial_max_stream_data_uni`, `0x07`.
    pub const INITIAL_MAX_STREAM_DATA_UNI: VarInt = VarInt::from_u32(0x07);
    /// `initial_max_streams_bidi`, `0x08`.
    pub const INITIAL_MAX_STREAMS_BIDI: VarInt = VarInt::from_u32(0x08);
    /// `initial_max_streams_uni`, `0x09`.
    pub const INITIAL_MAX_STREAMS_UNI: VarInt = VarInt::from_u32(0x09);
    /// `ack_delay_exponent`, `0x0a`.
    pub const ACK_DELAY_EXPONENT: VarInt = VarInt::from_u32(0x0a);
    /// `max_ack_delay`, `0x0b`.
    pub const MAX_ACK_DELAY: VarInt = VarInt::from_u32(0x0b);
    /// `disable_active_migration`, `0x0c`.
    pub const DISABLE_ACTIVE_MIGRATION: VarInt = VarInt::from_u32(0x0c);
    /// `preferred_address`, `0x0d`.
    pub const PREFERRED_ADDRESS: VarInt = VarInt::from_u32(0x0d);
    /// `active_connection_id_limit`, `0x0e`.
    pub const ACTIVE_CONNECTION_ID_LIMIT: VarInt = VarInt::from_u32(0x0e);
    /// `initial_source_connection_id`, `0x0f`.
    pub const INITIAL_SOURCE_CONNECTION_ID: VarInt = VarInt::from_u32(0x0f);
    /// `retry_source_connection_id`, `0x10`.
    pub const RETRY_SOURCE_CONNECTION_ID: VarInt = VarInt::from_u32(0x10);

    /// The largest ID QUIC version 1 defines; every smaller one is defined.
    pub(super) const LAST: u64 = 0x10;
}

/// The smallest `max_udp_payload_size` RFC 9000 permits.
const MIN_MAX_UDP_PAYLOAD_SIZE: u64 = 1200;
/// The largest `ack_delay_exponent` RFC 9000 permits.
const MAX_ACK_DELAY_EXPONENT: u64 = 20;
/// `max_ack_delay` must be below this.
const MAX_ACK_DELAY_BOUND: u64 = 1 << 14;
/// The smallest `active_connection_id_limit` RFC 9000 permits.
const MIN_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;

/// The transport parameters of one endpoint ([RFC 9000 §18.2]).
///
/// Absent parameters take their defaults: absent connection IDs, token and
/// preferred address are `None`; `max_udp_payload_size` is 65527,
/// `ack_delay_exponent` 3, `max_ack_delay` 25 and
/// `active_connection_id_limit` 2; the other integers are 0 and
/// `disable_active_migration` is false. [`Default`] gives these values, and
/// encoding omits a parameter that has its default value. `D` holds the
/// values of unknown parameters: the source's chunk type for parameters that
/// were read, any [`Buf`] for parameters to write.
///
/// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportParameters<D> {
    /// The Destination Connection ID of the client's first Initial packet;
    /// sent only by a server.
    pub original_destination_connection_id: Option<ConnectionId>,
    /// The idle timeout in milliseconds; 0 disables it.
    pub max_idle_timeout: VarInt,
    /// The Stateless Reset Token of the connection ID the server chose
    /// during the handshake; sent only by a server.
    pub stateless_reset_token: Option<StatelessResetToken>,
    /// The largest UDP payload the endpoint is willing to receive; at least
    /// 1200.
    pub max_udp_payload_size: VarInt,
    /// The initial connection-level flow control limit, in bytes.
    pub initial_max_data: VarInt,
    /// The initial flow control limit for bidirectional streams the sender
    /// of these parameters opens, in bytes.
    pub initial_max_stream_data_bidi_local: VarInt,
    /// The initial flow control limit for bidirectional streams the peer
    /// opens, in bytes.
    pub initial_max_stream_data_bidi_remote: VarInt,
    /// The initial flow control limit for unidirectional streams the peer
    /// opens, in bytes.
    pub initial_max_stream_data_uni: VarInt,
    /// The initial number of bidirectional streams the peer may open.
    pub initial_max_streams_bidi: StreamCount,
    /// The initial number of unidirectional streams the peer may open.
    pub initial_max_streams_uni: StreamCount,
    /// The exponent of the ACK Delay field of ACK frames; at most 20.
    pub ack_delay_exponent: VarInt,
    /// The longest time, in milliseconds, the endpoint delays sending
    /// acknowledgments; below 2<sup>14</sup>.
    pub max_ack_delay: VarInt,
    /// Whether the endpoint refuses active connection migration to the
    /// address used during the handshake.
    pub disable_active_migration: bool,
    /// The server's preferred address; sent only by a server.
    pub preferred_address: Option<PreferredAddress>,
    /// The number of connection IDs from the peer the endpoint is willing to
    /// store; at least 2.
    pub active_connection_id_limit: VarInt,
    /// The Source Connection ID of the first Initial packet the endpoint
    /// sent.
    pub initial_source_connection_id: Option<ConnectionId>,
    /// The Source Connection ID of the server's Retry packet; sent only by a
    /// server.
    pub retry_source_connection_id: Option<ConnectionId>,
    /// The parameters this type does not represent, in the order they
    /// appear. Their IDs are distinct and none is an ID of [`id`].
    pub unknown: Vec<UnknownParameter<D>>,
}

impl<D> Default for TransportParameters<D> {
    fn default() -> Self {
        Self {
            original_destination_connection_id: None,
            max_idle_timeout: VarInt::ZERO,
            stateless_reset_token: None,
            max_udp_payload_size: VarInt::from_u32(65527),
            initial_max_data: VarInt::ZERO,
            initial_max_stream_data_bidi_local: VarInt::ZERO,
            initial_max_stream_data_bidi_remote: VarInt::ZERO,
            initial_max_stream_data_uni: VarInt::ZERO,
            initial_max_streams_bidi: StreamCount::ZERO,
            initial_max_streams_uni: StreamCount::ZERO,
            ack_delay_exponent: VarInt::from_u32(3),
            max_ack_delay: VarInt::from_u32(25),
            disable_active_migration: false,
            preferred_address: None,
            active_connection_id_limit: VarInt::from_u32(2),
            initial_source_connection_id: None,
            retry_source_connection_id: None,
            unknown: Vec::new(),
        }
    }
}

/// A transport parameter that [`TransportParameters`] does not represent,
/// such as one defined by an extension or a reserved one sent for greasing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnknownParameter<D> {
    /// The parameter ID.
    pub id: VarInt,
    /// The value.
    pub value: D,
}

/// The value of a parameter to write.
pub(crate) enum Value<'v, D> {
    Integer(VarInt),
    Bytes(&'v [u8]),
    PreferredAddress(&'v PreferredAddress),
    Unknown(&'v D),
}

impl<D: Buf> Value<'_, D> {
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Integer(value) => value.encoded_len(),
            Self::Bytes(bytes) => bytes.len(),
            Self::PreferredAddress(address) => address.encoded_len(),
            Self::Unknown(value) => value.remaining(),
        }
    }
}

impl<D> TransportParameters<D> {
    /// Checks the values RFC 9000 §18.2 constrains.
    fn check_ranges(&self) -> Result<(), InvalidParameterError> {
        MaxUdpPayloadSizeError::check(self.max_udp_payload_size)?;
        AckDelayExponentError::check(self.ack_delay_exponent)?;
        MaxAckDelayError::check(self.max_ack_delay)?;
        ActiveConnectionIdLimitError::check(self.active_connection_id_limit)?;
        Ok(())
    }

    /// Calls `visit` with each parameter to write, in order: the known ones
    /// that differ from their defaults by ID, then the unknown ones.
    pub(crate) fn for_each<'s>(&'s self, mut visit: impl FnMut(VarInt, Value<'s, D>)) {
        fn integer<'s, D: 's>(
            visit: &mut impl FnMut(VarInt, Value<'s, D>),
            id: VarInt,
            value: VarInt,
            default: VarInt,
        ) {
            if value != default {
                visit(id, Value::Integer(value));
            }
        }
        let defaults = Self::default();
        if let Some(connection_id) = &self.original_destination_connection_id {
            visit(
                id::ORIGINAL_DESTINATION_CONNECTION_ID,
                Value::Bytes(connection_id.as_bytes()),
            );
        }
        integer(
            &mut visit,
            id::MAX_IDLE_TIMEOUT,
            self.max_idle_timeout,
            defaults.max_idle_timeout,
        );
        if let Some(token) = &self.stateless_reset_token {
            visit(id::STATELESS_RESET_TOKEN, Value::Bytes(token.as_bytes()));
        }
        let integers = [
            (
                id::MAX_UDP_PAYLOAD_SIZE,
                self.max_udp_payload_size,
                defaults.max_udp_payload_size,
            ),
            (
                id::INITIAL_MAX_DATA,
                self.initial_max_data,
                defaults.initial_max_data,
            ),
            (
                id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                self.initial_max_stream_data_bidi_local,
                defaults.initial_max_stream_data_bidi_local,
            ),
            (
                id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                self.initial_max_stream_data_bidi_remote,
                defaults.initial_max_stream_data_bidi_remote,
            ),
            (
                id::INITIAL_MAX_STREAM_DATA_UNI,
                self.initial_max_stream_data_uni,
                defaults.initial_max_stream_data_uni,
            ),
            (
                id::INITIAL_MAX_STREAMS_BIDI,
                self.initial_max_streams_bidi.to_var_int(),
                defaults.initial_max_streams_bidi.to_var_int(),
            ),
            (
                id::INITIAL_MAX_STREAMS_UNI,
                self.initial_max_streams_uni.to_var_int(),
                defaults.initial_max_streams_uni.to_var_int(),
            ),
            (
                id::ACK_DELAY_EXPONENT,
                self.ack_delay_exponent,
                defaults.ack_delay_exponent,
            ),
            (
                id::MAX_ACK_DELAY,
                self.max_ack_delay,
                defaults.max_ack_delay,
            ),
        ];
        for (id, value, default) in integers {
            integer(&mut visit, id, value, default);
        }
        if self.disable_active_migration {
            visit(id::DISABLE_ACTIVE_MIGRATION, Value::Bytes(&[]));
        }
        if let Some(address) = &self.preferred_address {
            visit(id::PREFERRED_ADDRESS, Value::PreferredAddress(address));
        }
        integer(
            &mut visit,
            id::ACTIVE_CONNECTION_ID_LIMIT,
            self.active_connection_id_limit,
            defaults.active_connection_id_limit,
        );
        if let Some(connection_id) = &self.initial_source_connection_id {
            visit(
                id::INITIAL_SOURCE_CONNECTION_ID,
                Value::Bytes(connection_id.as_bytes()),
            );
        }
        if let Some(connection_id) = &self.retry_source_connection_id {
            visit(
                id::RETRY_SOURCE_CONNECTION_ID,
                Value::Bytes(connection_id.as_bytes()),
            );
        }
        for parameter in &self.unknown {
            visit(parameter.id, Value::Unknown(&parameter.value));
        }
    }
}

impl<D: Buf> TransportParameters<D> {
    /// Checks what [`codec::write_transport_parameters`] checks before
    /// writing.
    ///
    /// # Errors
    ///
    /// [`InvalidParameterError::ServerOnly`] if `sender` is a client and a
    /// parameter only a server may send is present; the variant named after
    /// a parameter, such as [`InvalidParameterError::MaxUdpPayloadSize`], for
    /// a value out of range; [`InvalidParameterError::Duplicate`] if two
    /// unknown parameters share an ID or one has an ID of [`id`]; and
    /// [`InvalidParameterError::ValueLength`] for an unknown parameter whose
    /// value is longer than its length field can state.
    pub fn validate(&self, sender: Role) -> Result<(), InvalidParameterError> {
        if sender == Role::Client {
            // Each ID is one of the four that only a server may send.
            let server_only = [
                (
                    ServerOnlyParameterId(id::ORIGINAL_DESTINATION_CONNECTION_ID),
                    self.original_destination_connection_id.is_some(),
                ),
                (
                    ServerOnlyParameterId(id::STATELESS_RESET_TOKEN),
                    self.stateless_reset_token.is_some(),
                ),
                (
                    ServerOnlyParameterId(id::PREFERRED_ADDRESS),
                    self.preferred_address.is_some(),
                ),
                (
                    ServerOnlyParameterId(id::RETRY_SOURCE_CONNECTION_ID),
                    self.retry_source_connection_id.is_some(),
                ),
            ];
            if let Some((id, _)) = server_only.into_iter().find(|&(_, present)| present) {
                return Err(InvalidParameterError::ServerOnly { id });
            }
        }
        self.check_ranges()?;
        for (index, parameter) in self.unknown.iter().enumerate() {
            let id = parameter.id;
            let repeated = self.unknown[..index].iter().any(|other| other.id == id);
            let Some(unknown_id) = UnknownParameterId::new(id).filter(|_| !repeated) else {
                return Err(InvalidParameterError::Duplicate { id });
            };
            ValueLengthError::check(unknown_id, parameter.value.remaining())?;
        }
        Ok(())
    }

    /// The number of bytes [`codec::write_transport_parameters`] writes.
    pub fn encoded_len(&self) -> usize {
        let mut length = 0usize;
        self.for_each(|id, value| {
            let value_len = value.len();
            length = length
                .saturating_add(id.encoded_len() + crate::frame::length_field_len(value_len))
                .saturating_add(value_len);
        });
        length
    }
}

/// A transport parameter that RFC 9000 §18 forbids, whether decoded or about
/// to be encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(invalid_parameter_error), visibility(pub(crate)))]
pub enum InvalidParameterError {
    /// The parameter appears more than once.
    #[snafu(display("transport parameter {:#x} appears more than once", id.get()))]
    Duplicate {
        /// The parameter ID.
        id: VarInt,
    },
    /// A client sends a parameter that only a server may send.
    #[snafu(display(
        "transport parameter {:#x} may only be sent by a server",
        id.get().get()
    ))]
    ServerOnly {
        /// The parameter ID.
        id: ServerOnlyParameterId,
    },
    /// `max_udp_payload_size` is below 1200.
    #[snafu(transparent)]
    MaxUdpPayloadSize {
        /// The broken limit.
        source: MaxUdpPayloadSizeError,
    },
    /// `ack_delay_exponent` exceeds 20.
    #[snafu(transparent)]
    AckDelayExponent {
        /// The broken limit.
        source: AckDelayExponentError,
    },
    /// `max_ack_delay` is not below 2<sup>14</sup>.
    #[snafu(transparent)]
    MaxAckDelay {
        /// The broken limit.
        source: MaxAckDelayError,
    },
    /// `active_connection_id_limit` is below 2.
    #[snafu(transparent)]
    ActiveConnectionIdLimit {
        /// The broken limit.
        source: ActiveConnectionIdLimitError,
    },
    /// `initial_max_streams_bidi` exceeds 2<sup>60</sup>.
    #[snafu(display("initial_max_streams_bidi out of range"))]
    InitialMaxStreamsBidi {
        /// The rejected count.
        source: StreamCountError,
    },
    /// `initial_max_streams_uni` exceeds 2<sup>60</sup>.
    #[snafu(display("initial_max_streams_uni out of range"))]
    InitialMaxStreamsUni {
        /// The rejected count.
        source: StreamCountError,
    },
    /// The value of an unknown parameter to write is longer than
    /// 2<sup>62</sup> − 1 bytes, more than its Transport Parameter Length
    /// field can state.
    #[snafu(transparent)]
    ValueLength {
        /// The broken limit.
        source: ValueLengthError,
    },
}

/// `max_udp_payload_size` is below 1200 ([RFC 9000 §18.2]).
///
/// It is constructed only when the check fails, so the value it holds is
/// always below 1200.
///
/// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("max_udp_payload_size {value} is below 1200"))]
pub struct MaxUdpPayloadSizeError {
    value: VarInt,
}

impl MaxUdpPayloadSizeError {
    /// The value, below 1200.
    pub const fn value(self) -> VarInt {
        self.value
    }

    /// Checks that `value` is at least 1200.
    fn check(value: VarInt) -> Result<(), Self> {
        if value.get() < MIN_MAX_UDP_PAYLOAD_SIZE {
            return Err(Self { value });
        }
        Ok(())
    }
}

/// `ack_delay_exponent` exceeds 20 ([RFC 9000 §18.2]).
///
/// It is constructed only when the check fails, so the value it holds
/// always exceeds 20.
///
/// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("ack_delay_exponent {value} exceeds 20"))]
pub struct AckDelayExponentError {
    value: VarInt,
}

impl AckDelayExponentError {
    /// The value, above 20.
    pub const fn value(self) -> VarInt {
        self.value
    }

    /// Checks that `value` is at most 20.
    fn check(value: VarInt) -> Result<(), Self> {
        if value.get() > MAX_ACK_DELAY_EXPONENT {
            return Err(Self { value });
        }
        Ok(())
    }
}

/// `max_ack_delay` is not below 2<sup>14</sup> ([RFC 9000 §18.2]).
///
/// It is constructed only when the check fails, so the value it holds is
/// always at least 2<sup>14</sup>.
///
/// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("max_ack_delay {value} is not below 2^14"))]
pub struct MaxAckDelayError {
    value: VarInt,
}

impl MaxAckDelayError {
    /// The value, at least 2<sup>14</sup>.
    pub const fn value(self) -> VarInt {
        self.value
    }

    /// Checks that `value` is below 2<sup>14</sup>.
    fn check(value: VarInt) -> Result<(), Self> {
        if value.get() >= MAX_ACK_DELAY_BOUND {
            return Err(Self { value });
        }
        Ok(())
    }
}

/// `active_connection_id_limit` is below 2 ([RFC 9000 §18.2]).
///
/// It is constructed only when the check fails, so the value it holds is
/// always 0 or 1.
///
/// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("active_connection_id_limit {value} is below 2"))]
pub struct ActiveConnectionIdLimitError {
    value: VarInt,
}

impl ActiveConnectionIdLimitError {
    /// The value, 0 or 1.
    pub const fn value(self) -> VarInt {
        self.value
    }

    /// Checks that `value` is at least 2.
    fn check(value: VarInt) -> Result<(), Self> {
        if value.get() < MIN_ACTIVE_CONNECTION_ID_LIMIT {
            return Err(Self { value });
        }
        Ok(())
    }
}

/// The value of an unknown parameter to write is longer than
/// 2<sup>62</sup> − 1 bytes, more than its Transport Parameter Length field
/// can state.
///
/// It is constructed only when the check fails, so the length it holds
/// always exceeds 2<sup>62</sup> − 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "transport parameter {:#x} has a value of {length} bytes, longer than 2^62 - 1",
    id.get().get()
))]
pub struct ValueLengthError {
    id: UnknownParameterId,
    length: usize,
}

impl ValueLengthError {
    /// The parameter ID.
    pub const fn id(self) -> UnknownParameterId {
        self.id
    }

    /// The length of the value, above 2<sup>62</sup> − 1.
    pub const fn length(self) -> usize {
        self.length
    }

    /// Checks that a value of `length` bytes for the parameter `id` fits a
    /// Transport Parameter Length field.
    fn check(id: UnknownParameterId, length: usize) -> Result<(), Self> {
        if VarInt::try_from(length).is_err() {
            return Err(Self { id, length });
        }
        Ok(())
    }
}

/// The ID of a parameter that only a server may send:
/// `original_destination_connection_id`, `stateless_reset_token`,
/// `preferred_address` or `retry_source_connection_id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ServerOnlyParameterId(VarInt);

impl ServerOnlyParameterId {
    /// The ID `id` if only a server may send its parameter, and `None` if a
    /// client may send it too.
    pub(crate) const fn new(id: VarInt) -> Option<Self> {
        match id {
            id::ORIGINAL_DESTINATION_CONNECTION_ID
            | id::STATELESS_RESET_TOKEN
            | id::PREFERRED_ADDRESS
            | id::RETRY_SOURCE_CONNECTION_ID => Some(Self(id)),
            _ => None,
        }
    }

    /// The parameter ID.
    pub const fn get(self) -> VarInt {
        self.0
    }
}

impl From<ServerOnlyParameterId> for VarInt {
    fn from(id: ServerOnlyParameterId) -> Self {
        id.0
    }
}

/// The ID of a parameter that QUIC version 1 does not define: any ID above
/// `0x10`, the last ID of [`id`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnknownParameterId(VarInt);

impl UnknownParameterId {
    /// The ID `id` if QUIC version 1 does not define it, and `None` if it is
    /// an ID of [`id`].
    pub(crate) const fn new(id: VarInt) -> Option<Self> {
        if id.get() > id::LAST {
            Some(Self(id))
        } else {
            None
        }
    }

    /// The parameter ID.
    pub const fn get(self) -> VarInt {
        self.0
    }
}

impl From<UnknownParameterId> for VarInt {
    fn from(id: UnknownParameterId) -> Self {
        id.0
    }
}

#[cfg(test)]
mod tests;
