use super::{
    DecodeError, EncodeError, InvalidParameterError, PreferredAddress, TransportParameters,
    UnknownParameter, id,
};
use crate::{
    connection_id::{ConnectionId, NonEmptyCid},
    role::Role,
    transport_error::TransportErrorCode,
    var_int::VarInt,
};
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

fn vi(value: u64) -> VarInt {
    VarInt::try_from(value).unwrap()
}

/// Encodes one parameter.
fn tlv(id: u64, value: &[u8]) -> Vec<u8> {
    let mut encoding = Vec::new();
    vi(id).encode(&mut encoding).unwrap();
    VarInt::try_from(value.len())
        .unwrap()
        .encode(&mut encoding)
        .unwrap();
    encoding.extend_from_slice(value);
    encoding
}

fn integer(value: u64) -> Vec<u8> {
    let mut encoding = Vec::new();
    vi(value).encode(&mut encoding).unwrap();
    encoding
}

fn preferred_address() -> PreferredAddress {
    PreferredAddress {
        ipv4: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 443),
        ipv6: SocketAddrV6::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 4433, 0, 0),
        connection_id: NonEmptyCid::try_from(&[0x5a; 8][..]).unwrap(),
        stateless_reset_token: [0x11; 16],
    }
}

fn server_parameters() -> TransportParameters<'static> {
    TransportParameters {
        original_destination_connection_id: Some(
            ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap(),
        ),
        max_idle_timeout: vi(30_000),
        stateless_reset_token: Some([0x22; 16]),
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
    let mut encoding = Vec::new();
    parameters.encode(Role::Server, &mut encoding).unwrap();
    assert_eq!(encoding.len(), parameters.encoded_len());
    assert_eq!(
        TransportParameters::decode(&encoding, Role::Server),
        Ok(parameters.clone())
    );

    // An exact slice takes it; a shorter one is left untouched.
    let mut exact = vec![0; encoding.len()];
    parameters
        .encode(Role::Server, &mut exact.as_mut_slice())
        .unwrap();
    assert_eq!(exact, encoding);
    let mut short = vec![0xee; encoding.len() - 1];
    assert_eq!(
        parameters.encode(Role::Server, &mut short.as_mut_slice()),
        Err(EncodeError::Capacity {
            required: encoding.len(),
            available: encoding.len() - 1,
        })
    );
    assert!(short.iter().all(|&byte| byte == 0xee));
}

#[test]
fn defaults_fill_absent_parameters_and_are_omitted() {
    let parameters = TransportParameters::decode(&[], Role::Client).unwrap();
    assert_eq!(parameters, TransportParameters::default());
    assert_eq!(parameters.max_udp_payload_size, vi(65527));
    assert_eq!(parameters.ack_delay_exponent, vi(3));
    assert_eq!(parameters.max_ack_delay, vi(25));
    assert_eq!(parameters.active_connection_id_limit, vi(2));
    assert_eq!(parameters.max_idle_timeout, VarInt::ZERO);
    assert!(!parameters.disable_active_migration);
    assert_eq!(parameters.encoded_len(), 0);

    // An explicit default value decodes the same as an absent one.
    let explicit = tlv(0x03, &integer(65527));
    assert_eq!(
        TransportParameters::decode(&explicit, Role::Client),
        Ok(TransportParameters::default())
    );

    let client = TransportParameters {
        initial_source_connection_id: Some(ConnectionId::new(&[9; 4]).unwrap()),
        initial_max_data: vi(100),
        ..TransportParameters::default()
    };
    let mut encoding = Vec::new();
    client.encode(Role::Client, &mut encoding).unwrap();
    let mut expected = tlv(0x04, &integer(100));
    expected.extend(tlv(0x0f, &[9; 4]));
    assert_eq!(encoding, expected);
}

#[test]
fn duplicates_are_rejected() {
    let mut known = tlv(0x04, &integer(1));
    known.extend(tlv(0x04, &integer(1)));
    let mut unknown = tlv(0x40, b"a");
    unknown.extend(tlv(0x41, b""));
    unknown.extend(tlv(0x40, b"b"));
    for (encoding, duplicate) in [(known, 0x04), (unknown, 0x40)] {
        let error = TransportParameters::decode(&encoding, Role::Server).unwrap_err();
        assert_eq!(
            error,
            DecodeError::Invalid {
                source: InvalidParameterError::Duplicate { id: vi(duplicate) }
            }
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::TRANSPORT_PARAMETER_ERROR
        );
    }

    let mut parameters = TransportParameters::default();
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
        parameters.encode(Role::Client, &mut Vec::new()),
        Err(EncodeError::Invalid {
            source: InvalidParameterError::Duplicate { id: vi(0x40) }
        })
    );
}

#[test]
fn server_only_parameters_from_a_client_are_rejected() {
    let cases = [
        (0x00, vec![1, 2, 3, 4]),
        (0x02, vec![0x33; 16]),
        (0x0d, {
            let mut value = Vec::new();
            super::PreferredAddress::put(&preferred_address(), &mut value);
            value
        }),
        (0x10, vec![5; 8]),
    ];
    for (parameter, value) in cases {
        let encoding = tlv(parameter, &value);
        assert_eq!(
            TransportParameters::decode(&encoding, Role::Client),
            Err(DecodeError::Invalid {
                source: InvalidParameterError::ServerOnly { id: vi(parameter) }
            })
        );
        let parameters = TransportParameters::decode(&encoding, Role::Server).unwrap();
        assert_eq!(
            parameters.encode(Role::Client, &mut Vec::new()),
            Err(EncodeError::Invalid {
                source: InvalidParameterError::ServerOnly { id: vi(parameter) }
            })
        );
        let mut encoded = Vec::new();
        parameters.encode(Role::Server, &mut encoded).unwrap();
        assert_eq!(encoded, encoding);
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
    for (parameter, invalid, valid) in cases {
        let error = InvalidParameterError::OutOfRange {
            id: vi(parameter),
            value: vi(invalid),
        };
        assert_eq!(
            TransportParameters::decode(&tlv(parameter, &integer(invalid)), Role::Client),
            Err(DecodeError::Invalid { source: error }),
            "{parameter:#x}"
        );
        let valid_encoding = tlv(parameter, &integer(valid));
        let parameters = TransportParameters::decode(&valid_encoding, Role::Client).unwrap();
        let mut invalid_parameters = parameters.clone();
        match parameter {
            0x03 => invalid_parameters.max_udp_payload_size = vi(invalid),
            0x08 => invalid_parameters.initial_max_streams_bidi = vi(invalid),
            0x09 => invalid_parameters.initial_max_streams_uni = vi(invalid),
            0x0a => invalid_parameters.ack_delay_exponent = vi(invalid),
            0x0b => invalid_parameters.max_ack_delay = vi(invalid),
            _ => invalid_parameters.active_connection_id_limit = vi(invalid),
        }
        let mut buffer = Vec::new();
        assert_eq!(
            invalid_parameters.encode(Role::Client, &mut buffer),
            Err(EncodeError::Invalid { source: error })
        );
        assert!(buffer.is_empty());
    }
}

#[test]
fn malformed_values_are_rejected() {
    let mut zero_cid_address = Vec::new();
    PreferredAddress::put(&preferred_address(), &mut zero_cid_address);
    zero_cid_address[24] = 0;
    zero_cid_address.drain(25..33);
    let mut long_address = Vec::new();
    PreferredAddress::put(&preferred_address(), &mut long_address);
    long_address.push(0);
    let cases: [(u64, Vec<u8>); 10] = [
        (0x01, vec![]),
        (0x01, vec![0x05, 0x00]),
        (0x01, vec![0x40]),
        (0x02, vec![0; 15]),
        (0x02, vec![0; 17]),
        (0x0c, vec![0]),
        (0x0f, vec![0; 21]),
        (0x0d, vec![0; 24]),
        (0x0d, zero_cid_address),
        (0x0d, long_address),
    ];
    for (parameter, value) in cases {
        assert_eq!(
            TransportParameters::decode(&tlv(parameter, &value), Role::Server),
            Err(DecodeError::Malformed {
                id: vi(parameter),
                length: value.len()
            }),
            "{parameter:#x} {value:02x?}"
        );
    }
}

#[test]
fn truncated_input_is_rejected() {
    let cases: [(&[u8], usize); 4] = [
        (&[0x40], 2),
        (&[0x04], 2),
        (&[0x04, 0x02, 0x01], 4),
        (&[0x04, 0x01, 0x01, 0x40, 0x00, 0x80], 9),
    ];
    for (encoding, required) in cases {
        assert_eq!(
            TransportParameters::decode(encoding, Role::Client),
            Err(DecodeError::Truncated {
                required,
                available: encoding.len()
            }),
            "{encoding:02x?}"
        );
    }
}

#[test]
fn unknown_parameters_are_kept_in_order() {
    let mut encoding = tlv(0x1d, &[]);
    encoding.extend(tlv(0x04, &integer(7)));
    encoding.extend(tlv(31 * 1000 + 27, b"reserved"));
    let parameters = TransportParameters::decode(&encoding, Role::Client).unwrap();
    assert_eq!(parameters.initial_max_data, vi(7));
    assert_eq!(
        parameters.unknown,
        [
            UnknownParameter {
                id: vi(0x1d),
                value: &[]
            },
            UnknownParameter {
                id: vi(31 * 1000 + 27),
                value: b"reserved"
            },
        ]
    );
    // Known parameters are written first, then the unknown ones in order.
    let mut encoded = Vec::new();
    parameters.encode(Role::Client, &mut encoded).unwrap();
    let mut expected = tlv(0x04, &integer(7));
    expected.extend(tlv(0x1d, &[]));
    expected.extend(tlv(31 * 1000 + 27, b"reserved"));
    assert_eq!(encoded, expected);
}

#[test]
fn preferred_address_layout() {
    let mut value = Vec::new();
    PreferredAddress::put(&preferred_address(), &mut value);
    let mut expected = vec![192, 0, 2, 1, 0x01, 0xbb];
    expected.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
    expected.extend_from_slice(&[0x11, 0x51, 8]);
    expected.extend_from_slice(&[0x5a; 8]);
    expected.extend_from_slice(&[0x11; 16]);
    assert_eq!(value, expected);
    assert_eq!(PreferredAddress::decode(&value), Some(preferred_address()));
}
