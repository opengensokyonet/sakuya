//! QUIC transport parameters ([RFC 9000 §18]).
//!
//! Each endpoint states its transport parameters once, in the TLS handshake:
//! a sequence of parameters, each an ID and a length, both variable-length
//! integers, followed by that many bytes of value. [`TransportParameters`]
//! holds every parameter QUIC version 1 defines, with the defaults of
//! [RFC 9000 §18.2] for those that are absent, and keeps the parameters it
//! does not know as [`UnknownParameter`]s, so that extensions can interpret
//! them.
//!
//! Decoding and encoding take the [`Role`] of the endpoint that sends the
//! parameters, since a client must not send the parameters that only a server
//! may send. Both check the values RFC 9000 §18.2 constrains and reject a
//! parameter that appears twice. Whether the connection ID parameters match
//! the connection IDs that the packets used ([RFC 9000 §7.3]), and whether
//! the ones that must be present are, is for the handshake to check. Every
//! [`DecodeError`] corresponds to TRANSPORT_PARAMETER_ERROR.
//!
//! ```
//! use sakuya_wire::{role::Role, transport_parameters::TransportParameters, var_int::VarInt};
//!
//! let mut parameters = TransportParameters::default();
//! parameters.initial_max_data = VarInt::from(1_048_576u32);
//! parameters.initial_max_streams_bidi = VarInt::from(100u8);
//!
//! let mut encoding = Vec::new();
//! parameters.encode(Role::Client, &mut encoding).unwrap();
//! assert_eq!(encoding.len(), parameters.encoded_len());
//!
//! let decoded = TransportParameters::decode(&encoding, Role::Client).unwrap();
//! assert_eq!(decoded, parameters);
//! assert_eq!(decoded.max_udp_payload_size, VarInt::from(65527u16)); // The default.
//! ```
//!
//! [RFC 9000 §18]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18
//! [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
//! [RFC 9000 §7.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-7.3
use crate::{
    connection_id::{ConnectionId, NonEmptyCid},
    frame::{MAX_STREAM_COUNT, STATELESS_RESET_TOKEN_LEN},
    role::Role,
    transport_error::TransportErrorCode,
    var_int::VarInt,
};
use bytes::BufMut;
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use snafu::Snafu;

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
/// encoding omits a parameter that has its default value.
///
/// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportParameters<'a> {
    /// The Destination Connection ID of the client's first Initial packet;
    /// sent only by a server.
    pub original_destination_connection_id: Option<ConnectionId>,
    /// The idle timeout in milliseconds; 0 disables it.
    pub max_idle_timeout: VarInt,
    /// The Stateless Reset Token of the connection ID the server chose
    /// during the handshake; sent only by a server.
    pub stateless_reset_token: Option<[u8; STATELESS_RESET_TOKEN_LEN]>,
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
    /// The initial number of bidirectional streams the peer may open; at
    /// most 2<sup>60</sup>.
    pub initial_max_streams_bidi: VarInt,
    /// The initial number of unidirectional streams the peer may open; at
    /// most 2<sup>60</sup>.
    pub initial_max_streams_uni: VarInt,
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
    pub unknown: Vec<UnknownParameter<'a>>,
}

impl Default for TransportParameters<'_> {
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
            initial_max_streams_bidi: VarInt::ZERO,
            initial_max_streams_uni: VarInt::ZERO,
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

/// The `preferred_address` parameter ([RFC 9000 §18.2]): an address the
/// server would like the client to migrate to, with the connection ID to use
/// there.
///
/// An address and port of all zeros means the server has no preferred
/// address of that family. The connection ID has sequence number 1.
///
/// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PreferredAddress {
    /// The IPv4 address and port.
    pub ipv4: SocketAddrV4,
    /// The IPv6 address and port. Only the address and port are encoded;
    /// decoding sets the flow information and scope ID to zero.
    pub ipv6: SocketAddrV6,
    /// The connection ID to use at the preferred address.
    pub connection_id: NonEmptyCid,
    /// The Stateless Reset Token of that connection ID.
    pub stateless_reset_token: [u8; STATELESS_RESET_TOKEN_LEN],
}

impl PreferredAddress {
    /// The length of the fields other than the connection ID.
    const FIXED_LEN: usize = 4 + 2 + 16 + 2 + 1 + STATELESS_RESET_TOKEN_LEN;

    fn encoded_len(&self) -> usize {
        Self::FIXED_LEN + self.connection_id.as_bytes().len()
    }

    fn put<B: BufMut + ?Sized>(&self, buffer: &mut B) {
        buffer.put_slice(&self.ipv4.ip().octets());
        buffer.put_u16(self.ipv4.port());
        buffer.put_slice(&self.ipv6.ip().octets());
        buffer.put_u16(self.ipv6.port());
        let connection_id = self.connection_id.as_bytes();
        // A connection ID has at most 20 bytes.
        buffer.put_u8(connection_id.len() as u8);
        buffer.put_slice(connection_id);
        buffer.put_slice(&self.stateless_reset_token);
    }

    /// Decodes the value of the parameter, or returns `None` if its layout is
    /// wrong.
    fn decode(value: &[u8]) -> Option<Self> {
        let (ipv4, rest) = value.split_first_chunk::<4>()?;
        let (ipv4_port, rest) = rest.split_first_chunk::<2>()?;
        let (ipv6, rest) = rest.split_first_chunk::<16>()?;
        let (ipv6_port, rest) = rest.split_first_chunk::<2>()?;
        let (&length, rest) = rest.split_first()?;
        let (connection_id, rest) = rest.split_at_checked(usize::from(length))?;
        let stateless_reset_token = *<&[u8; STATELESS_RESET_TOKEN_LEN]>::try_from(rest).ok()?;
        Some(Self {
            ipv4: SocketAddrV4::new(Ipv4Addr::from(*ipv4), u16::from_be_bytes(*ipv4_port)),
            ipv6: SocketAddrV6::new(Ipv6Addr::from(*ipv6), u16::from_be_bytes(*ipv6_port), 0, 0),
            connection_id: NonEmptyCid::try_from(connection_id).ok()?,
            stateless_reset_token,
        })
    }
}

/// A transport parameter that [`TransportParameters`] does not represent,
/// such as one defined by an extension or a reserved one sent for greasing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnknownParameter<'a> {
    /// The parameter ID.
    pub id: VarInt,
    /// The value, borrowed from the decoded input.
    pub value: &'a [u8],
}

/// The value of a parameter to encode.
enum Value<'v> {
    Integer(VarInt),
    Bytes(&'v [u8]),
    PreferredAddress(&'v PreferredAddress),
}

impl Value<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Integer(value) => value.encoded_len(),
            Self::Bytes(bytes) => bytes.len(),
            Self::PreferredAddress(address) => address.encoded_len(),
        }
    }

    fn put<B: BufMut + ?Sized>(&self, buffer: &mut B) {
        match self {
            Self::Integer(value) => put_var_int(buffer, *value),
            Self::Bytes(bytes) => buffer.put_slice(bytes),
            Self::PreferredAddress(address) => address.put(buffer),
        }
    }
}

/// Writes a value into a buffer whose room has been checked.
fn put_var_int<B: BufMut + ?Sized>(buffer: &mut B, value: VarInt) {
    let result = value.encode(buffer);
    debug_assert!(result.is_ok(), "room is checked before writing");
}

/// The length of a length field for `length` bytes.
fn len_len(length: usize) -> usize {
    VarInt::try_from(length).map_or(VarInt::MAX_ENCODED_LEN, VarInt::encoded_len)
}

/// Whether a client must not send the parameter `id`.
fn server_only(id: VarInt) -> bool {
    [
        id::ORIGINAL_DESTINATION_CONNECTION_ID,
        id::STATELESS_RESET_TOKEN,
        id::PREFERRED_ADDRESS,
        id::RETRY_SOURCE_CONNECTION_ID,
    ]
    .contains(&id)
}

impl<'a> TransportParameters<'a> {
    /// Decodes the transport parameters that an endpoint in role `sender`
    /// sent.
    ///
    /// `input` is the whole value of the `quic_transport_parameters` TLS
    /// extension. Values of unknown parameters borrow from it.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Truncated`] if `input` ends within a parameter,
    /// [`DecodeError::Malformed`] for a value whose length does not fit its
    /// parameter, and [`DecodeError::Invalid`] for a parameter that appears
    /// twice, that a client sent but only a server may send, or whose value
    /// is out of range.
    pub fn decode(input: &'a [u8], sender: Role) -> Result<Self, DecodeError> {
        let mut parameters = Self::default();
        let mut seen = 0u32;
        let mut reader = Reader { input, offset: 0 };
        while reader.offset < input.len() {
            let id = reader.var_int()?;
            let length = reader.var_int()?;
            let value = reader.take(length.get())?;
            if id.get() <= id::LAST {
                let bit = 1 << id.get();
                if seen & bit != 0 {
                    return Err(InvalidParameterError::Duplicate { id }.into());
                }
                seen |= bit;
                if sender == Role::Client && server_only(id) {
                    return Err(InvalidParameterError::ServerOnly { id }.into());
                }
                parameters.set(id, value)?;
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

    /// Sets the known parameter `id` from its encoded value.
    fn set(&mut self, id: VarInt, value: &[u8]) -> Result<(), DecodeError> {
        let malformed = || DecodeError::Malformed {
            id,
            length: value.len(),
        };
        let integer = || match VarInt::decode(value) {
            Ok((integer, length)) if length == value.len() => Ok(integer),
            _ => Err(malformed()),
        };
        let connection_id = || ConnectionId::new(value).map_err(|_| malformed());
        match id {
            id::ORIGINAL_DESTINATION_CONNECTION_ID => {
                self.original_destination_connection_id = Some(connection_id()?);
            }
            id::MAX_IDLE_TIMEOUT => self.max_idle_timeout = integer()?,
            id::STATELESS_RESET_TOKEN => {
                self.stateless_reset_token = Some(value.try_into().map_err(|_| malformed())?);
            }
            id::MAX_UDP_PAYLOAD_SIZE => self.max_udp_payload_size = integer()?,
            id::INITIAL_MAX_DATA => self.initial_max_data = integer()?,
            id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                self.initial_max_stream_data_bidi_local = integer()?;
            }
            id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                self.initial_max_stream_data_bidi_remote = integer()?;
            }
            id::INITIAL_MAX_STREAM_DATA_UNI => self.initial_max_stream_data_uni = integer()?,
            id::INITIAL_MAX_STREAMS_BIDI => self.initial_max_streams_bidi = integer()?,
            id::INITIAL_MAX_STREAMS_UNI => self.initial_max_streams_uni = integer()?,
            id::ACK_DELAY_EXPONENT => self.ack_delay_exponent = integer()?,
            id::MAX_ACK_DELAY => self.max_ack_delay = integer()?,
            id::DISABLE_ACTIVE_MIGRATION => {
                if !value.is_empty() {
                    return Err(malformed());
                }
                self.disable_active_migration = true;
            }
            id::PREFERRED_ADDRESS => {
                self.preferred_address =
                    Some(PreferredAddress::decode(value).ok_or_else(malformed)?);
            }
            id::ACTIVE_CONNECTION_ID_LIMIT => self.active_connection_id_limit = integer()?,
            id::INITIAL_SOURCE_CONNECTION_ID => {
                self.initial_source_connection_id = Some(connection_id()?);
            }
            _ => self.retry_source_connection_id = Some(connection_id()?),
        }
        Ok(())
    }

    /// Checks the values RFC 9000 §18.2 constrains.
    fn check_ranges(&self) -> Result<(), InvalidParameterError> {
        let checks = [
            (
                id::MAX_UDP_PAYLOAD_SIZE,
                self.max_udp_payload_size,
                self.max_udp_payload_size.get() >= MIN_MAX_UDP_PAYLOAD_SIZE,
            ),
            (
                id::INITIAL_MAX_STREAMS_BIDI,
                self.initial_max_streams_bidi,
                self.initial_max_streams_bidi.get() <= MAX_STREAM_COUNT,
            ),
            (
                id::INITIAL_MAX_STREAMS_UNI,
                self.initial_max_streams_uni,
                self.initial_max_streams_uni.get() <= MAX_STREAM_COUNT,
            ),
            (
                id::ACK_DELAY_EXPONENT,
                self.ack_delay_exponent,
                self.ack_delay_exponent.get() <= MAX_ACK_DELAY_EXPONENT,
            ),
            (
                id::MAX_ACK_DELAY,
                self.max_ack_delay,
                self.max_ack_delay.get() < MAX_ACK_DELAY_BOUND,
            ),
            (
                id::ACTIVE_CONNECTION_ID_LIMIT,
                self.active_connection_id_limit,
                self.active_connection_id_limit.get() >= MIN_ACTIVE_CONNECTION_ID_LIMIT,
            ),
        ];
        match checks.into_iter().find(|&(_, _, valid)| !valid) {
            Some((id, value, _)) => Err(InvalidParameterError::OutOfRange { id, value }),
            None => Ok(()),
        }
    }

    /// Checks what [`TransportParameters::encode`] checks before writing.
    ///
    /// # Errors
    ///
    /// [`InvalidParameterError::ServerOnly`] if `sender` is a client and a
    /// parameter only a server may send is present,
    /// [`InvalidParameterError::OutOfRange`] for a value out of range, and
    /// [`InvalidParameterError::Duplicate`] if two unknown parameters share
    /// an ID or one has an ID of [`id`].
    pub fn validate(&self, sender: Role) -> Result<(), InvalidParameterError> {
        if sender == Role::Client {
            let server_only = [
                (
                    id::ORIGINAL_DESTINATION_CONNECTION_ID,
                    self.original_destination_connection_id.is_some(),
                ),
                (
                    id::STATELESS_RESET_TOKEN,
                    self.stateless_reset_token.is_some(),
                ),
                (id::PREFERRED_ADDRESS, self.preferred_address.is_some()),
                (
                    id::RETRY_SOURCE_CONNECTION_ID,
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
            if id.get() <= id::LAST || self.unknown[..index].iter().any(|other| other.id == id) {
                return Err(InvalidParameterError::Duplicate { id });
            }
            if VarInt::try_from(parameter.value.len()).is_err() {
                return Err(InvalidParameterError::OutOfRange {
                    id,
                    value: VarInt::MAX,
                });
            }
        }
        Ok(())
    }

    /// The number of bytes [`TransportParameters::encode`] writes.
    pub fn encoded_len(&self) -> usize {
        let mut length = 0usize;
        self.for_each(|id, value| {
            let value_len = value.len();
            length = length.saturating_add(id.encoded_len() + len_len(value_len) + value_len);
        });
        length
    }

    /// Appends the encoding of the parameters, as an endpoint in role
    /// `sender` sends them, to `buffer`.
    ///
    /// Parameters with their default values are omitted; the others are
    /// written in the order of their IDs, followed by the unknown parameters
    /// in their order. Nothing is written unless the parameters are valid and
    /// fit.
    ///
    /// # Errors
    ///
    /// [`EncodeError::Invalid`] if [`TransportParameters::validate`] fails,
    /// and [`EncodeError::Capacity`] if `buffer.remaining_mut()` is below
    /// [`TransportParameters::encoded_len`].
    pub fn encode<B: BufMut + ?Sized>(
        &self,
        sender: Role,
        buffer: &mut B,
    ) -> Result<(), EncodeError> {
        self.validate(sender)?;
        let required = self.encoded_len();
        let available = buffer.remaining_mut();
        if available < required {
            return Err(EncodeError::Capacity {
                required,
                available,
            });
        }
        self.for_each(|id, value| {
            put_var_int(buffer, id);
            put_var_int(buffer, VarInt::try_from(value.len()).unwrap_or(VarInt::MAX));
            value.put(buffer);
        });
        Ok(())
    }

    /// Calls `visit` with each parameter to encode, in order: the known ones
    /// that differ from their defaults by ID, then the unknown ones.
    fn for_each<'s>(&'s self, mut visit: impl FnMut(VarInt, Value<'s>)) {
        fn integer<'s>(
            visit: &mut impl FnMut(VarInt, Value<'s>),
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
            visit(id::STATELESS_RESET_TOKEN, Value::Bytes(token));
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
                self.initial_max_streams_bidi,
                defaults.initial_max_streams_bidi,
            ),
            (
                id::INITIAL_MAX_STREAMS_UNI,
                self.initial_max_streams_uni,
                defaults.initial_max_streams_uni,
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
            visit(parameter.id, Value::Bytes(parameter.value));
        }
    }
}

/// Reads consecutive fields of the encoded parameters.
struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn truncated(&self, required: usize) -> DecodeError {
        DecodeError::Truncated {
            required,
            available: self.input.len(),
        }
    }

    fn var_int(&mut self) -> Result<VarInt, DecodeError> {
        let rest = &self.input[self.offset..];
        match VarInt::decode(rest) {
            Ok((value, length)) => {
                self.offset += length;
                Ok(value)
            }
            Err(_) => {
                let length = rest
                    .first()
                    .map_or(1, |&first| VarInt::encoded_len_of(first));
                Err(self.truncated(self.offset + length))
            }
        }
    }

    fn take(&mut self, length: u64) -> Result<&'a [u8], DecodeError> {
        let end = usize::try_from(length)
            .ok()
            .and_then(|length| self.offset.checked_add(length));
        match end {
            Some(end) if end <= self.input.len() => {
                let field = &self.input[self.offset..end];
                self.offset = end;
                Ok(field)
            }
            _ => Err(self.truncated(end.unwrap_or(usize::MAX))),
        }
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
    #[snafu(display("transport parameter {:#x} may only be sent by a server", id.get()))]
    ServerOnly {
        /// The parameter ID.
        id: VarInt,
    },
    /// The value is outside the range RFC 9000 §18.2 permits.
    #[snafu(display("transport parameter {:#x} has out-of-range value {value}", id.get()))]
    OutOfRange {
        /// The parameter ID.
        id: VarInt,
        /// The value.
        value: VarInt,
    },
}

/// Failures of [`TransportParameters::decode`].
///
/// Every failure corresponds to the transport error
/// TRANSPORT_PARAMETER_ERROR ([`DecodeError::transport_error_code`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(decode_error), visibility(pub(crate)))]
pub enum DecodeError {
    /// The input ends within a parameter.
    #[snafu(display("transport parameters need {required} bytes, but the input has {available}"))]
    Truncated {
        /// The input length the next field requires.
        required: usize,
        /// The input length.
        available: usize,
    },
    /// The length of a value does not fit the layout of its parameter.
    #[snafu(display(
        "transport parameter {:#x} has a malformed value of {length} bytes",
        id.get()
    ))]
    Malformed {
        /// The parameter ID.
        id: VarInt,
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

impl DecodeError {
    /// The transport error the failure corresponds to: always
    /// TRANSPORT_PARAMETER_ERROR ([RFC 9000 §7.4]).
    ///
    /// [RFC 9000 §7.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-7.4
    pub fn transport_error_code(&self) -> TransportErrorCode {
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR
    }
}

/// Failures of [`TransportParameters::encode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(encode_error), visibility(pub(crate)))]
pub enum EncodeError {
    /// The buffer cannot take the whole encoding.
    #[snafu(display(
        "transport parameters need {required} bytes, but the buffer has room for {available}"
    ))]
    Capacity {
        /// The length of the encoding.
        required: usize,
        /// The room the buffer reported.
        available: usize,
    },
    /// A parameter is forbidden.
    #[snafu(transparent)]
    Invalid {
        /// Why the parameter is forbidden.
        source: InvalidParameterError,
    },
}

#[cfg(test)]
mod tests;
