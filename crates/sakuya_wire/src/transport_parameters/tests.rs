use super::{
    InvalidParameterError, TransportParameters, UnknownParameter,
    codec::{
        ReadTransportParametersError, ReadTransportParametersHostExt as _,
        WriteTransportParametersError, WriteTransportParametersHostExt as _,
    },
    id,
    preferred_address::{
        PreferredAddress,
        codec::{ReadPreferredAddressHostExt as _, WritePreferredAddressHostExt as _},
    },
};
use crate::{
    connection_id::{ConnectionId, ConnectionIdLengthError, NonEmptyCid, StatelessResetToken},
    role::Role,
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

fn preferred_address() -> PreferredAddress {
    PreferredAddress {
        ipv4: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 443),
        ipv6: SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 4433, 0, 0),
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
        initial_max_streams_bidi: vi(1 << 60),
        initial_max_streams_uni: vi(3),
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
        assert_eq!(
            invalid(read(&encoding, Role::Client).unwrap_err()),
            InvalidParameterError::ServerOnly { id: vi(parameter) }
        );
        let parameters = read(&encoding, Role::Server).unwrap();
        assert_eq!(
            write_invalid(parameters.clone(), Role::Client),
            InvalidParameterError::ServerOnly { id: vi(parameter) }
        );
        assert_eq!(write(parameters, Role::Server), encoding);
    }
}

#[test]
fn values_out_of_range_are_rejected() {
    let cases = [
        (0x03, 1199, 1200),
        (0x08, (1 << 60) + 1, 1 << 60),
        (0x09, (1 << 60) + 1, 1 << 60),
        (0x0a, 21, 20),
        (0x0b, 1 << 14, (1 << 14) - 1),
        (0x0e, 1, 2),
    ];
    for (parameter, invalid_value, valid) in cases {
        let error = InvalidParameterError::OutOfRange {
            id: vi(parameter),
            value: vi(invalid_value),
        };
        assert_eq!(
            invalid(read(&tlv(parameter, &integer(invalid_value)), Role::Client).unwrap_err()),
            error,
            "{parameter:#x}"
        );
        let valid_encoding = tlv(parameter, &integer(valid));
        let parameters = read(&valid_encoding, Role::Client).unwrap();
        let mut invalid_parameters = parameters.clone();
        match parameter {
            0x03 => invalid_parameters.max_udp_payload_size = vi(invalid_value),
            0x08 => invalid_parameters.initial_max_streams_bidi = vi(invalid_value),
            0x09 => invalid_parameters.initial_max_streams_uni = vi(invalid_value),
            0x0a => invalid_parameters.ack_delay_exponent = vi(invalid_value),
            0x0b => invalid_parameters.max_ack_delay = vi(invalid_value),
            _ => invalid_parameters.active_connection_id_limit = vi(invalid_value),
        }
        assert_eq!(write_invalid(invalid_parameters, Role::Client), error);
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
    check(0x01, &[], |error| {
        matches!(error, E::Integer { length: 0, .. })
    });
    check(0x01, &[0x05, 0x00], |error| {
        matches!(error, E::Integer { length: 2, .. })
    });
    check(0x01, &[0x40], |error| {
        matches!(error, E::Integer { length: 1, .. })
    });
    check(0x02, &[0; 15], |error| {
        matches!(error, E::StatelessResetToken { length: 15 })
    });
    check(0x02, &[0; 17], |error| {
        matches!(error, E::StatelessResetToken { length: 17 })
    });
    check(0x0c, &[0], |error| {
        matches!(error, E::DisableActiveMigration { length: 1 })
    });
    check(0x0f, &[0; 21], |error| {
        matches!(
            error,
            E::ConnectionId {
                source: ConnectionIdLengthError { length: 21 },
                ..
            }
        )
    });
    check(0x0d, &[0; 24], |error| {
        matches!(error, E::PreferredAddress { .. })
    });
    check(0x0d, &zero_cid_address, |error| {
        matches!(error, E::PreferredAddress { .. })
    });
    check(0x0d, &long_address, |error| {
        matches!(error, E::PreferredAddressLength { length: 50 })
    });
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
    assert!(matches!(
        read(&[0x04, 0x02, 0x01], Role::Client),
        Err(ReadTransportParametersError::Value { id, .. }) if id == vi(0x04)
    ));
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
