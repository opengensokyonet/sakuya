use super::{
    AckDelayExponentError, ActiveConnectionIdLimitError, InvalidParameterError, MaxAckDelayError,
    MaxUdpPayloadSizeError, ServerOnlyParameterId, TransportParameters, UnknownParameter,
    UnknownParameterId, ValueLengthError,
    codec::{
        ConnectionIdParameterId, IntegerParameterId, ReadTransportParametersError,
        ReadTransportParametersHostExt as _, WriteTransportParametersError,
        WriteTransportParametersHostExt as _,
    },
    id,
    preferred_address::{
        PreferredAddress, PreferredAddressFamilies,
        codec::{
            ReadPreferredAddressError, ReadPreferredAddressHostExt as _,
            WritePreferredAddressHostExt as _,
        },
    },
};
use crate::{
    connection_id::{ConnectionId, NonEmptyCid, StatelessResetToken},
    role::Role,
    stream_count::StreamCount,
    transport_error::TransportErrorCode,
    var_int::{VarInt, codec::WriteVarIntHostExt as _},
};
use bytes::Bytes;
use core::{
    convert::Infallible,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
};

fn vi(value: u64) -> VarInt {
    VarInt::try_from(value).unwrap()
}

/// Encodes one parameter.
fn tlv(id: u64, value: &[u8]) -> Vec<u8> {
    let mut encoding = Vec::new();
    encoding.sync_write_var_int_unpin(vi(id)).unwrap();
    encoding
        .sync_write_var_int_unpin(VarInt::try_from(value.len()).unwrap())
        .unwrap();
    encoding.extend_from_slice(value);
    encoding
}

fn integer(value: u64) -> Vec<u8> {
    let mut encoding = Vec::new();
    encoding.sync_write_var_int_unpin(vi(value)).unwrap();
    encoding
}

fn ipv4() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 443)
}

fn ipv6() -> SocketAddrV6 {
    SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 4433, 0, 0)
}

fn preferred_address() -> PreferredAddress {
    PreferredAddress {
        addresses: PreferredAddressFamilies::Both(ipv4(), ipv6()),
        connection_id: NonEmptyCid::try_from(&[0x5a; 8][..]).unwrap(),
        stateless_reset_token: StatelessResetToken::new([0x11; 16]),
    }
}

fn preferred_address_value() -> Vec<u8> {
    let mut value = Vec::new();
    value
        .sync_write_preferred_address_unpin(preferred_address())
        .unwrap();
    value
}

fn read(
    encoding: &[u8],
    sender: Role,
) -> Result<TransportParameters<&[u8]>, ReadTransportParametersError<Infallible>> {
    let mut input = encoding;
    let result = input.sync_read_transport_parameters_unpin(sender);
    if result.is_ok() {
        assert!(input.is_empty());
    }
    result
}

fn write(parameters: TransportParameters<&[u8]>, sender: Role) -> Vec<u8> {
    let mut encoding = Vec::new();
    encoding
        .sync_write_transport_parameters_unpin(parameters, sender)
        .unwrap();
    encoding
}

fn invalid(error: ReadTransportParametersError<Infallible>) -> InvalidParameterError {
    match error {
        ReadTransportParametersError::Invalid { source } => source,
        other => panic!("{other:?}"),
    }
}

fn write_invalid(parameters: TransportParameters<&[u8]>, sender: Role) -> InvalidParameterError {
    let mut buffer = Vec::new();
    match buffer.sync_write_transport_parameters_unpin(parameters, sender) {
        Err(WriteTransportParametersError::Invalid { source }) => {
            assert!(buffer.is_empty());
            source
        }
        other => panic!("{other:?}"),
    }
}

fn server_parameters() -> TransportParameters<&'static [u8]> {
    TransportParameters {
        original_destination_connection_id: Some(
            ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap(),
        ),
        max_idle_timeout: vi(30_000),
        stateless_reset_token: Some(StatelessResetToken::new([0x22; 16])),
        max_udp_payload_size: vi(1472),
        initial_max_data: vi(1 << 24),
        initial_max_stream_data_bidi_local: vi(1 << 20),
        initial_max_stream_data_bidi_remote: vi(1 << 19),
        initial_max_stream_data_uni: vi(1 << 18),
        initial_max_streams_bidi: StreamCount::MAX,
        initial_max_streams_uni: StreamCount::new(3).unwrap(),
        ack_delay_exponent: vi(20),
        max_ack_delay: vi((1 << 14) - 1),
        disable_active_migration: true,
        preferred_address: Some(preferred_address()),
        active_connection_id_limit: vi(8),
        initial_source_connection_id: Some(ConnectionId::EMPTY),
        retry_source_connection_id: Some(ConnectionId::new(&[0x77; 20]).unwrap()),
        unknown: vec![
            UnknownParameter {
                id: vi(31 * 5 + 27),
                value: b"grease",
            },
            UnknownParameter {
                id: vi(0x20),
                value: &[0x80, 0x00, 0xff, 0xff],
            },
            UnknownParameter {
                id: vi(0x1d),
                value: &[],
            },
        ],
    }
}

#[test]
fn all_parameters_round_trip() {
    let parameters = server_parameters();
    let encoding = write(parameters.clone(), Role::Server);
    assert_eq!(encoding.len(), parameters.encoded_len());
    assert_eq!(read(&encoding, Role::Server).unwrap(), parameters);

    // A `Bytes` source keeps unknown values in its own storage.
    let shared = Bytes::from(encoding.clone());
    let from_bytes = shared
        .clone()
        .sync_read_transport_parameters_unpin(Role::Server)
        .unwrap();
    let grease = &from_bytes.unknown[0].value;
    assert_eq!(grease, &b"grease"[..]);
    let offset = grease.as_ptr() as usize - shared.as_ptr() as usize;
    assert_eq!(shared.slice(offset..offset + 6), *grease);

    // An exact slice takes it; a shorter one keeps the accepted prefix.
    let mut exact = vec![0; encoding.len()];
    let mut sink = exact.as_mut_slice();
    sink.sync_write_transport_parameters_unpin(parameters.clone(), Role::Server)
        .unwrap();
    assert_eq!(exact, encoding);
    let mut short = vec![0xee; encoding.len() - 1];
    let mut sink = short.as_mut_slice();
    let error = sink
        .sync_write_transport_parameters_unpin(parameters, Role::Server)
        .unwrap_err();
    let WriteTransportParametersError::Write { source } = &error else {
        panic!("{error:?}")
    };
    assert_eq!(source.completed(), encoding.len() - 1);
    assert_eq!(short, encoding[..encoding.len() - 1]);
}

#[test]
fn defaults_fill_absent_parameters_and_are_omitted() {
    let parameters = read(&[], Role::Client).unwrap();
    assert_eq!(parameters, TransportParameters::default());
    assert_eq!(parameters.max_udp_payload_size, vi(65527));
    assert_eq!(parameters.ack_delay_exponent, vi(3));
    assert_eq!(parameters.max_ack_delay, vi(25));
    assert_eq!(parameters.active_connection_id_limit, vi(2));
    assert_eq!(parameters.max_idle_timeout, VarInt::ZERO);
    assert!(!parameters.disable_active_migration);
    assert_eq!(parameters.encoded_len(), 0);

    // An explicit default value reads the same as an absent one.
    let explicit = tlv(0x03, &integer(65527));
    assert_eq!(
        read(&explicit, Role::Client).unwrap(),
        TransportParameters::default()
    );

    let client = TransportParameters::<&[u8]> {
        initial_source_connection_id: Some(ConnectionId::new(&[9; 4]).unwrap()),
        initial_max_data: vi(100),
        ..TransportParameters::default()
    };
    let mut expected = tlv(0x04, &integer(100));
    expected.extend(tlv(0x0f, &[9; 4]));
    assert_eq!(write(client, Role::Client), expected);
}

#[test]
fn duplicates_are_rejected() {
    let mut known = tlv(0x04, &integer(1));
    known.extend(tlv(0x04, &integer(1)));
    let mut unknown = tlv(0x40, b"a");
    unknown.extend(tlv(0x41, b""));
    unknown.extend(tlv(0x40, b"b"));
    for (encoding, duplicate) in [(known, 0x04), (unknown, 0x40)] {
        let error = read(&encoding, Role::Server).unwrap_err();
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::TRANSPORT_PARAMETER_ERROR
        );
        assert_eq!(
            invalid(error),
            InvalidParameterError::Duplicate { id: vi(duplicate) }
        );
    }

    let mut parameters = TransportParameters::<&[u8]>::default();
    parameters.unknown.push(UnknownParameter {
        id: id::MAX_IDLE_TIMEOUT,
        value: &[0x01],
    });
    assert_eq!(
        parameters.validate(Role::Client),
        Err(InvalidParameterError::Duplicate {
            id: id::MAX_IDLE_TIMEOUT
        })
    );
    parameters.unknown = vec![
        UnknownParameter {
            id: vi(0x40),
            value: b"",
        },
        UnknownParameter {
            id: vi(0x40),
            value: b"",
        },
    ];
    assert_eq!(
        write_invalid(parameters, Role::Client),
        InvalidParameterError::Duplicate { id: vi(0x40) }
    );
}

#[test]
fn server_only_parameters_from_a_client_are_rejected() {
    let cases = [
        (0x00, vec![1, 2, 3, 4]),
        (0x02, vec![0x33; 16]),
        (0x0d, preferred_address_value()),
        (0x10, vec![5; 8]),
    ];
    for (parameter, value) in cases {
        let encoding = tlv(parameter, &value);
        let id = ServerOnlyParameterId::new(vi(parameter)).unwrap();
        let error = invalid(read(&encoding, Role::Client).unwrap_err());
        assert_eq!(error, InvalidParameterError::ServerOnly { id });
        assert_eq!(id.get(), vi(parameter));
        let parameters = read(&encoding, Role::Server).unwrap();
        assert_eq!(
            write_invalid(parameters.clone(), Role::Client),
            InvalidParameterError::ServerOnly { id }
        );
        assert_eq!(write(parameters, Role::Server), encoding);
    }
}

#[test]
fn range_errors_hold_only_values_out_of_range() {
    for value in [0, 1199] {
        let error = MaxUdpPayloadSizeError::check(vi(value)).unwrap_err();
        assert_eq!(error.value(), vi(value));
    }
    assert_eq!(MaxUdpPayloadSizeError::check(vi(1200)), Ok(()));
    for value in [21, VarInt::MAX.get()] {
        let error = AckDelayExponentError::check(vi(value)).unwrap_err();
        assert_eq!(error.value(), vi(value));
    }
    assert_eq!(AckDelayExponentError::check(vi(20)), Ok(()));
    for value in [1 << 14, VarInt::MAX.get()] {
        let error = MaxAckDelayError::check(vi(value)).unwrap_err();
        assert_eq!(error.value(), vi(value));
    }
    assert_eq!(MaxAckDelayError::check(vi((1 << 14) - 1)), Ok(()));
    for value in [0, 1] {
        let error = ActiveConnectionIdLimitError::check(vi(value)).unwrap_err();
        assert_eq!(error.value(), vi(value));
    }
    assert_eq!(ActiveConnectionIdLimitError::check(vi(2)), Ok(()));
    let id = UnknownParameterId::new(vi(0x40)).unwrap();
    assert_eq!(ValueLengthError::check(id, 1 << 20), Ok(()));
    assert_eq!(
        MaxUdpPayloadSizeError::check(vi(1199))
            .unwrap_err()
            .to_string(),
        "max_udp_payload_size 1199 is below 1200"
    );
}

#[test]
fn values_out_of_range_are_rejected_by_parameter() {
    use InvalidParameterError as E;
    let count = |value| StreamCount::new(value).unwrap_err();
    let cases = [
        (
            0x03,
            1199,
            1200,
            E::MaxUdpPayloadSize {
                source: MaxUdpPayloadSizeError::check(vi(1199)).unwrap_err(),
            },
        ),
        (
            0x08,
            (1 << 60) + 1,
            1 << 60,
            E::InitialMaxStreamsBidi {
                source: count((1 << 60) + 1),
            },
        ),
        (
            0x09,
            (1 << 60) + 1,
            1 << 60,
            E::InitialMaxStreamsUni {
                source: count((1 << 60) + 1),
            },
        ),
        (
            0x0a,
            21,
            20,
            E::AckDelayExponent {
                source: AckDelayExponentError::check(vi(21)).unwrap_err(),
            },
        ),
        (
            0x0b,
            1 << 14,
            (1 << 14) - 1,
            E::MaxAckDelay {
                source: MaxAckDelayError::check(vi(1 << 14)).unwrap_err(),
            },
        ),
        (
            0x0e,
            1,
            2,
            E::ActiveConnectionIdLimit {
                source: ActiveConnectionIdLimitError::check(vi(1)).unwrap_err(),
            },
        ),
    ];
    for (parameter, invalid_value, valid, error) in cases {
        let read_error = read(&tlv(parameter, &integer(invalid_value)), Role::Client).unwrap_err();
        assert_eq!(
            read_error.transport_error_code(),
            TransportErrorCode::TRANSPORT_PARAMETER_ERROR
        );
        assert_eq!(invalid(read_error), error, "{parameter:#x}");
        let valid_encoding = tlv(parameter, &integer(valid));
        let parameters = read(&valid_encoding, Role::Client).unwrap();
        let mut invalid_parameters = parameters.clone();
        match parameter {
            0x03 => invalid_parameters.max_udp_payload_size = vi(invalid_value),
            // A stream count above 2^60 cannot be constructed.
            0x08 | 0x09 => {
                assert!(StreamCount::new(invalid_value).is_err());
                continue;
            }
            0x0a => invalid_parameters.ack_delay_exponent = vi(invalid_value),
            0x0b => invalid_parameters.max_ack_delay = vi(invalid_value),
            _ => invalid_parameters.active_connection_id_limit = vi(invalid_value),
        }
        assert_eq!(write_invalid(invalid_parameters, Role::Client), error);
    }
}

/// A value that claims more bytes than a Transport Parameter Length field
/// can state.
#[cfg(target_pointer_width = "64")]
struct Huge;

#[cfg(target_pointer_width = "64")]
impl bytes::Buf for Huge {
    fn remaining(&self) -> usize {
        usize::MAX
    }

    fn chunk(&self) -> &[u8] {
        &[]
    }

    fn advance(&mut self, _: usize) {}
}

#[cfg(target_pointer_width = "64")]
#[test]
fn unknown_values_longer_than_a_length_field_states_are_rejected() {
    let parameters = TransportParameters {
        unknown: vec![UnknownParameter {
            id: vi(0x40),
            value: Huge,
        }],
        ..TransportParameters::default()
    };
    let Err(InvalidParameterError::ValueLength { source }) = parameters.validate(Role::Client)
    else {
        panic!()
    };
    assert_eq!(source.id(), UnknownParameterId::new(vi(0x40)).unwrap());
    assert_eq!(source.length(), usize::MAX);
    assert_eq!(
        ValueLengthError::check(source.id(), usize::MAX),
        Err(source)
    );
}

#[test]
fn parameter_id_sets() {
    let integers = [
        0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e,
    ];
    for value in (0..=0x41).chain([31 * 5 + 27, VarInt::MAX.get()]) {
        let id = vi(value);
        let server_only = matches!(value, 0x00 | 0x02 | 0x0d | 0x10);
        let integer = integers.contains(&value);
        let connection_id = matches!(value, 0x00 | 0x0f | 0x10);
        let unknown = value > 0x10;
        let some = |present: bool| present.then_some(id);
        assert_eq!(
            ServerOnlyParameterId::new(id).map(ServerOnlyParameterId::get),
            some(server_only),
            "{value:#x}"
        );
        assert_eq!(
            IntegerParameterId::new(id).map(VarInt::from),
            some(integer),
            "{value:#x}"
        );
        assert_eq!(
            ConnectionIdParameterId::new(id).map(ConnectionIdParameterId::get),
            some(connection_id),
            "{value:#x}"
        );
        assert_eq!(
            UnknownParameterId::new(id).map(VarInt::from),
            some(unknown),
            "{value:#x}"
        );
        // The other known parameters are `stateless_reset_token`,
        // `disable_active_migration` and `preferred_address`; the sets
        // partition every ID.
        let other = matches!(value, 0x02 | 0x0c | 0x0d);
        let sets = [unknown, integer, connection_id, other];
        assert_eq!(
            sets.iter().filter(|&&member| member).count(),
            1,
            "{value:#x}"
        );
    }
}

/// Each integer parameter with a value that is not one integer, and each
/// connection ID parameter with a value that is too long, names its ID.
#[test]
fn malformed_values_name_their_parameter() {
    for parameter in [
        0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e,
    ] {
        let error = read(&tlv(parameter, &[0x05, 0x00]), Role::Server).unwrap_err();
        assert!(
            matches!(
                error,
                ReadTransportParametersError::Integer { id, length: 2 } if id.get() == vi(parameter)
            ),
            "{parameter:#x}: {error:?}"
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::TRANSPORT_PARAMETER_ERROR
        );
    }
    for parameter in [0x00, 0x0f, 0x10] {
        let error = read(&tlv(parameter, &[0; 21]), Role::Server).unwrap_err();
        assert!(
            matches!(
                error,
                ReadTransportParametersError::ConnectionId {
                    id,
                    source,
                } if id.get() == vi(parameter) && source.length() == 21
            ),
            "{parameter:#x}: {error:?}"
        );
        assert!(!error.is_incomplete());
        // Twenty bytes are a connection ID.
        let encoding = tlv(parameter, &[7; 20]);
        let parameters = read(&encoding, Role::Server).unwrap();
        let expected = Some(ConnectionId::new(&[7; 20]).unwrap());
        let connection_id = match parameter {
            0x00 => parameters.original_destination_connection_id,
            0x0f => parameters.initial_source_connection_id,
            _ => parameters.retry_source_connection_id,
        };
        assert_eq!(connection_id, expected, "{parameter:#x}");
    }
}

#[test]
fn malformed_values_are_rejected_by_parameter() {
    use ReadTransportParametersError as E;
    let mut zero_cid_address = preferred_address_value();
    zero_cid_address[24] = 0;
    zero_cid_address.drain(25..33);
    let mut long_address = preferred_address_value();
    long_address.push(0);
    let check = |parameter: u64, value: &[u8], expected: fn(&E<Infallible>) -> bool| {
        let error = read(&tlv(parameter, value), Role::Server).unwrap_err();
        assert!(expected(&error), "{parameter:#x} {value:02x?}: {error:?}");
        assert!(!error.is_incomplete());
    };
    check(
        0x01,
        &[],
        |error| matches!(error, E::Integer { id, length: 0 } if id.get() == vi(0x01)),
    );
    check(0x01, &[0x05, 0x00], |error| {
        matches!(error, E::Integer { length: 2, .. })
    });
    check(0x01, &[0x40], |error| {
        matches!(error, E::Integer { length: 1, .. })
    });
    check(
        0x02,
        &[0; 15],
        |error| matches!(error, E::StatelessResetToken { source } if source.length() == 15),
    );
    check(
        0x02,
        &[0; 17],
        |error| matches!(error, E::StatelessResetToken { source } if source.length() == 17),
    );
    check(
        0x0c,
        &[0],
        |error| matches!(error, E::DisableActiveMigration { length } if length.get() == 1),
    );

    check(0x0d, &[0; 24], |error| {
        matches!(error, E::PreferredAddress { .. })
    });
    check(0x0d, &zero_cid_address, |error| {
        matches!(error, E::PreferredAddress { .. })
    });
    check(
        0x0d,
        &long_address,
        |error| matches!(error, E::PreferredAddressLength { source } if source.length() == 50),
    );
}

/// RFC 9000 §18.2: an all-zero address and port stands for a family without
/// a preferred address. With both families all zeros there is no address.
#[test]
fn preferred_address_needs_an_address_of_some_family() {
    let mut value = preferred_address_value();
    // The IPv4 address and port, then the IPv6 address and port.
    value[..4 + 2 + 16 + 2].fill(0);
    let error = read(&tlv(0x0d, &value), Role::Server).unwrap_err();
    assert!(
        matches!(
            error,
            ReadTransportParametersError::PreferredAddress {
                source: ReadPreferredAddressError::NoAddress
            }
        ),
        "{error:?}"
    );
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR
    );
    assert!(!error.is_incomplete());
}

/// Each family alone, and both, are written with the all-zero marker in
/// place of a missing family and read back.
#[test]
fn preferred_address_families_round_trip() {
    let unspecified_v4 = [0u8; 4 + 2];
    let unspecified_v6 = [0u8; 16 + 2];
    let cases = [
        (PreferredAddressFamilies::Both(ipv4(), ipv6()), true, true),
        (PreferredAddressFamilies::Ipv4(ipv4()), true, false),
        (PreferredAddressFamilies::Ipv6(ipv6()), false, true),
    ];
    for (addresses, has_v4, has_v6) in cases {
        let address = PreferredAddress {
            addresses,
            ..preferred_address()
        };
        let mut value = Vec::new();
        value.sync_write_preferred_address_unpin(address).unwrap();
        assert_eq!(value.len(), address.encoded_len());
        assert_eq!(value[..6] == unspecified_v4, !has_v4, "{addresses:?}");
        assert_eq!(value[6..24] == unspecified_v6, !has_v6, "{addresses:?}");
        let mut input = value.as_slice();
        assert_eq!(input.sync_read_preferred_address_unpin().unwrap(), address);
        assert!(input.is_empty());
        let read_back = read(&tlv(0x0d, &value), Role::Server)
            .unwrap()
            .preferred_address
            .unwrap();
        assert_eq!(read_back, address);
    }
}

/// An all-zero address with a nonzero port is an address of its family.
#[test]
fn preferred_address_with_a_zero_address_and_a_port_has_that_family() {
    let zero_v4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 443);
    let zero_v6 = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 4433, 0, 0);
    for addresses in [
        PreferredAddressFamilies::Ipv4(zero_v4),
        PreferredAddressFamilies::Ipv6(zero_v6),
        PreferredAddressFamilies::Both(zero_v4, zero_v6),
    ] {
        let address = PreferredAddress {
            addresses,
            ..preferred_address()
        };
        let mut value = Vec::new();
        value.sync_write_preferred_address_unpin(address).unwrap();
        let mut input = value.as_slice();
        assert_eq!(input.sync_read_preferred_address_unpin().unwrap(), address);
    }
}

#[test]
fn truncated_input_is_rejected() {
    let cases: [&[u8]; 4] = [
        &[0x40],
        &[0x04],
        &[0x04, 0x02, 0x01],
        &[0x04, 0x01, 0x01, 0x40, 0x00, 0x80],
    ];
    for encoding in cases {
        let error = read(encoding, Role::Client).unwrap_err();
        assert!(error.is_incomplete(), "{encoding:02x?}: {error:?}");
    }
    // Each field of a parameter has a variant of its own.
    assert!(matches!(
        read(&[0x40], Role::Client),
        Err(ReadTransportParametersError::Id { .. })
    ));
    assert!(matches!(
        // The second ID is 0 in a two-byte encoding.
        read(&[0x04, 0x01, 0x01, 0x40, 0x00, 0x80], Role::Client),
        Err(ReadTransportParametersError::Length { id, .. }) if id == VarInt::ZERO
    ));
    assert!(matches!(
        read(&[0x04], Role::Client),
        Err(ReadTransportParametersError::Length { id, .. }) if id == vi(0x04)
    ));
    assert!(matches!(
        read(&[0x04, 0x02, 0x01], Role::Client),
        Err(ReadTransportParametersError::Value { id, .. }) if id == vi(0x04)
    ));
}

#[test]
fn preferred_address_fields_cut_short_are_named() {
    use ReadPreferredAddressError as E;
    let value = preferred_address_value();
    type Check = fn(&ReadPreferredAddressError<Infallible>) -> bool;
    // The value is cut within each fixed-length field.
    let cases: [(usize, Check); 6] = [
        (0, |error| matches!(error, E::Ipv4Address { .. })),
        (5, |error| matches!(error, E::Ipv4Port { .. })),
        (21, |error| matches!(error, E::Ipv6Address { .. })),
        (23, |error| matches!(error, E::Ipv6Port { .. })),
        (24, |error| matches!(error, E::ConnectionId { .. })),
        (value.len() - 1, |error| {
            matches!(error, E::StatelessResetToken { .. })
        }),
    ];
    for (cut, expected) in cases {
        let mut input = &value[..cut];
        let error = input.sync_read_preferred_address_unpin().unwrap_err();
        assert!(expected(&error), "{cut}: {error:?}");
        // Inside the parameter, the same failure is reported.
        let error = read(&tlv(0x0d, &value[..cut]), Role::Server).unwrap_err();
        assert!(
            matches!(&error, ReadTransportParametersError::PreferredAddress { source } if expected(source)),
            "{cut}: {error:?}"
        );
    }
}

#[test]
fn unknown_parameters_are_kept_in_order() {
    let mut encoding = tlv(0x1d, &[]);
    encoding.extend(tlv(0x04, &integer(7)));
    encoding.extend(tlv(31 * 1000 + 27, b"reserved"));
    let parameters = read(&encoding, Role::Client).unwrap();
    assert_eq!(parameters.initial_max_data, vi(7));
    assert_eq!(
        parameters.unknown,
        [
            UnknownParameter {
                id: vi(0x1d),
                value: &[][..]
            },
            UnknownParameter {
                id: vi(31 * 1000 + 27),
                value: &b"reserved"[..]
            },
        ]
    );
    // Known parameters are written first, then the unknown ones in order.
    let mut expected = tlv(0x04, &integer(7));
    expected.extend(tlv(0x1d, &[]));
    expected.extend(tlv(31 * 1000 + 27, b"reserved"));
    assert_eq!(write(parameters, Role::Client), expected);
}

#[test]
fn preferred_address_layout() {
    let value = preferred_address_value();
    let mut expected = vec![192, 0, 2, 1, 0x01, 0xbb];
    expected.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
    expected.extend_from_slice(&[0x11, 0x51, 8]);
    expected.extend_from_slice(&[0x5a; 8]);
    expected.extend_from_slice(&[0x11; 16]);
    assert_eq!(value, expected);
    assert_eq!(preferred_address().encoded_len(), value.len());
    let mut input = value.as_slice();
    assert_eq!(
        input.sync_read_preferred_address_unpin().unwrap(),
        preferred_address()
    );
    assert!(input.is_empty());
}
