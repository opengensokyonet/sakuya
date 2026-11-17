use core::marker::PhantomData;

use sakuya_wire::{
    frame::NoLength,
    parameters::codec::ReadParametersError,
    v1::{role::Role, transport_parameters::codec::read_transport_parameters},
};

use super::*;
use crate::{error::TransportParameterValueErrorsOf, v1};

type WithExtension = HList![v1::Part, Part];

fn size(value: u32) -> MaxDatagramFrameSize {
    MaxDatagramFrameSize::new(VarInt::from_u32(value))
}

fn with_length(data: &'static [u8]) -> DatagramFrame<Bytes> {
    DatagramFrame::with_length(VarIntWidth::One, Bytes::from_static(data))
        .expect("a short payload")
        .into()
}

fn without_length(data: &'static [u8]) -> DatagramFrame<Bytes> {
    DatagramFrame::<_, NoLength>::without_length(Bytes::from_static(data)).into()
}

/// The largest payload is counted with the Length field, at each width.
#[test]
fn the_payload_limit_is_counted_with_the_length_field() {
    assert_eq!(payload_limit(size(0)), None);
    assert_eq!(payload_limit(size(1)), None);
    assert_eq!(payload_limit(size(2)), Some(0));
    // 1 + 1 + 63
    assert_eq!(payload_limit(size(65)), Some(63));
    // 64 bytes need a Length of two bytes: 1 + 2 + 63 still fits 66
    assert_eq!(payload_limit(size(66)), Some(63));
    assert_eq!(payload_limit(size(67)), Some(64));
    // 65532 bytes would need a Length of four bytes
    assert_eq!(payload_limit(size(65535)), Some(65535 - 5));
    for limit in [2, 65, 66, 67, 1200, 16_386, 65535] {
        let largest = payload_limit(size(limit)).expect("some payload fits");
        assert!(frame_len_with_length(largest) <= limit as usize, "{limit}");
        assert!(
            frame_len_with_length(largest + 1) > limit as usize,
            "{limit}"
        );
    }
}

/// A DATAGRAM frame without a `max_datagram_frame_size` other than 0
/// among the parameters this side sent is a PROTOCOL_VIOLATION, for the
/// frame's type (RFC 9221 §3).
#[test]
fn a_datagram_without_the_parameter_announced_is_a_protocol_violation() {
    let not_sent = LocalTransportParameters::Configured(frunk_core::hlist![Some(size(1200))]);
    let left_out = LocalTransportParameters::Sent(frunk_core::hlist![None]);
    let zero = LocalTransportParameters::Sent(frunk_core::hlist![Some(size(0))]);
    for local in [not_sent, left_out, zero] {
        for (frame, frame_type) in [(with_length(b"hi"), 0x31u32), (without_length(b"hi"), 0x30)] {
            let error = check_announced(&local, &frame).expect_err("not announced");
            assert!(matches!(error, ConnectionError::NotAnnounced { .. }));
            assert_eq!(error.code(), TransportErrorCode::PROTOCOL_VIOLATION);
            assert_eq!(error.frame_type(), Some(VarInt::from_u32(frame_type)));
        }
    }
}

/// A frame larger than what this side announced is a PROTOCOL_VIOLATION;
/// one as large is taken (RFC 9221 §3: "strictly larger").
#[test]
fn a_datagram_larger_than_announced_is_a_protocol_violation() {
    // 1 + 1 + 4 bytes with a Length field, 1 + 4 without
    let six = LocalTransportParameters::Sent(frunk_core::hlist![Some(size(6))]);
    assert!(check_announced(&six, &with_length(b"four")).is_ok());
    assert!(check_announced(&six, &without_length(b"four")).is_ok());
    let error = check_announced(&six, &with_length(b"fives")).expect_err("larger");
    assert!(matches!(
        error,
        ConnectionError::FrameTooLarge {
            frame_len: 7,
            has_length: true,
            ..
        }
    ));
    assert_eq!(error.code(), TransportErrorCode::PROTOCOL_VIOLATION);
    assert_eq!(error.frame_type(), Some(VarInt::from_u32(0x31)));
    let error = check_announced(&six, &without_length(b"sixsix")).expect_err("larger");
    assert_eq!(error.code(), TransportErrorCode::PROTOCOL_VIOLATION);
    assert_eq!(error.frame_type(), Some(VarInt::from_u32(0x30)));
}

/// A `max_datagram_frame_size` of the peer's that cannot be read is the
/// extension's error, which closes with TRANSPORT_PARAMETER_ERROR.
#[test]
fn a_peer_parameter_that_cannot_be_read_is_a_transport_parameter_error() {
    // a value of one byte that starts an integer of two, and one with a
    // byte after the integer
    for encoding in [&[0x20, 0x01, 0x40][..], &[0x20, 0x02, 0x01, 0x00][..]] {
        let mut encoding = encoding;
        let error =
            read_transport_parameters(&mut encoding, Role::Server, PhantomData::<WithExtension>)
                .expect_err("a value that cannot be read");
        let ReadParametersError::InvalidValue {
            id,
            source: PartsError(source),
        } = error
        else {
            panic!("not a failure of the value: {error:?}");
        };
        let error =
            PartsError(<WithExtension as TransportParameterValueErrorsOf>::value_error(id, source));
        assert_eq!(error.code(), TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
        assert!(matches!(
            error,
            PartsError(Coproduct::Inr(Coproduct::Inl(
                ConnectionError::ParameterValue { .. }
            )))
        ));
    }
}

/// The part announces 65535 unless it is configured otherwise.
#[test]
fn the_part_announces_the_recommended_size_by_default() {
    let args = DatagramConnectionArgs::<()>::default();
    assert_eq!(
        args.transport_parameters,
        frunk_core::hlist![Some(size(65535))]
    );
}

/// A server's datagram tells whether it came in a 0-RTT packet, and reads
/// as its bytes.
#[test]
fn a_server_datagram_tells_whether_it_came_in_0_rtt() {
    let data = Bytes::from_static(b"frame");
    let early = ServerReceivedDatagram {
        data: data.clone(),
        zero_rtt: true,
    };
    assert!(early.received_zero_rtt());
    let mut late = ServerReceivedDatagram {
        data: data.clone(),
        zero_rtt: false,
    };
    assert!(!late.received_zero_rtt());
    assert_eq!(late.remaining(), 5);
    late.advance(2);
    assert_eq!(late.chunk(), b"ame");
    assert_eq!(late.into_bytes(), Bytes::from_static(b"ame"));
}
