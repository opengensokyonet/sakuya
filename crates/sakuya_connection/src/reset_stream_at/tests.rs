use core::marker::PhantomData;

use sakuya_wire::{
    parameters::codec::ReadParametersError,
    parts::HList,
    v1::{role::Role, stream_id::StreamId, transport_parameters::codec::read_transport_parameters},
    var_int::VarIntField,
};

use super::*;
use crate::{error::TransportParameterValueErrorsOf, v1};

/// Compiles only when `A` and `B` are the same type.
fn same_type<A, B>()
where
    A: SameAs<B>,
{
}

trait SameAs<B> {}

impl<A> SameAs<A> for A {}

type WithExtension = HList![v1::Part, Part];

#[test]
fn a_composition_with_the_extension_resets_reliably() {
    same_type::<StreamResetsOfParts<WithExtension>, ReliableStreamResets>();
    same_type::<StreamResetsOfParts<HList![Part, v1::Part]>, ReliableStreamResets>();
}

/// Without `reset_stream_at` among the parameters this side sent, a
/// RESET_STREAM_AT frame is one of a type the connection does not know:
/// FRAME_ENCODING_ERROR, for the frame's type.
#[test]
fn a_reset_stream_at_without_the_parameter_announced_is_a_frame_encoding_error() {
    let not_sent = LocalTransportParameters::Configured(frunk_core::hlist![Some(ResetStreamAt)]);
    let left_out = LocalTransportParameters::Sent(frunk_core::hlist![None]);
    for local in [not_sent, left_out] {
        let error = check_announced::<OnResetStreamError>(&local).expect_err("not announced");
        assert!(matches!(error, ConnectionError::NotAnnounced));
        assert_eq!(error.code(), TransportErrorCode::FRAME_ENCODING_ERROR);
        assert_eq!(error.frame_type(), Some(VarInt::from_u32(0x24)));
    }
    let announced = LocalTransportParameters::Sent(frunk_core::hlist![Some(ResetStreamAt)]);
    assert!(check_announced::<OnResetStreamError>(&announced).is_ok());
}

/// A `reset_stream_at` of the peer's with a value is the extension's error,
/// which closes with TRANSPORT_PARAMETER_ERROR (§3).
#[test]
fn a_peer_parameter_with_a_value_is_a_transport_parameter_error() {
    let mut encoding = &[0x1d, 0x01, 0x00][..];
    let error =
        read_transport_parameters(&mut encoding, Role::Server, PhantomData::<WithExtension>)
            .expect_err("a value with bytes");
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

/// The peer's `reset_stream_at` is what lets the sending parts send
/// RESET_STREAM_AT.
#[test]
fn the_peer_allows_reset_stream_at_with_its_parameter() {
    let announced = frunk_core::hlist![Some(ResetStreamAt)];
    assert!(
        PeerResetSupportSlots::<ReliableStreamResets, _>::peer_reset_support(&announced).is_some()
    );
    let left_out: HList![Option<ResetStreamAt>] = frunk_core::hlist![None];
    assert!(
        PeerResetSupportSlots::<ReliableStreamResets, _>::peer_reset_support(&left_out).is_none()
    );
}

/// The reset frame of a [`LocalResetAt`] writes as its frame, in the length
/// it states.
#[test]
fn a_reset_frame_of_either_kind_writes_its_encoded_length() {
    let at = ResetStreamAtFrame::new(
        VarIntField::shortest(StreamId::from(VarInt::from_u32(4))),
        VarIntField::shortest(ApplicationErrorCode::new(VarInt::from_u32(1))),
        VarIntField::shortest(VarInt::from_u32(9)),
        VarIntField::shortest(VarInt::from_u32(5)),
    )
    .expect("the reliable size is within the final size");
    let frame = LocalResetAtFrame::ResetStreamAt(at);
    let mut buffer = BytesMut::new();
    let len = DelimitedFrame::encoded_len(&frame);
    DelimitedFrame::write_to(frame, &mut buffer);
    assert_eq!(&buffer[..], [0x24, 0x04, 0x01, 0x09, 0x05]);
    assert_eq!(len, buffer.len());

    let plain = LocalResetAtFrame::ResetStream(ResetStreamFrame::new(
        VarIntField::shortest(StreamId::from(VarInt::from_u32(4))),
        VarIntField::shortest(ApplicationErrorCode::new(VarInt::from_u32(1))),
        VarIntField::shortest(VarInt::from_u32(9)),
    ));
    let mut buffer = BytesMut::new();
    let len = DelimitedFrame::encoded_len(&plain);
    DelimitedFrame::write_to(plain, &mut buffer);
    assert_eq!(&buffer[..], [0x04, 0x04, 0x01, 0x09]);
    assert_eq!(len, buffer.len());
}

/// A server that resumes does not leave out `reset_stream_at` when it was
/// remembered and it sends the configured parameters (§3).
#[test]
fn a_resumed_reset_stream_at_is_not_left_out() {
    use crate::v1::parameters::{ResumedParametersDecision, resume_tests::*};

    let announced = frunk_core::hlist![Some(ResetStreamAt)];
    let left_out = frunk_core::hlist![None];
    let cases = [
        (announced, announced, true),
        (announced, left_out, false),
        (left_out, left_out, true),
        (left_out, announced, true),
    ];
    for (remembered, configured, accepted) in cases {
        let (outcome, settled, _) = resume::<Part, _>(
            configured,
            ResumedParametersDecision::UseConfigured,
            &encoded::<Part>(remembered),
        );
        assert_eq!((outcome, settled), (accepted, configured));
    }
    let (accepted, settled, _) = resume::<Part, _>(
        left_out,
        ResumedParametersDecision::UseRemembered,
        &encoded::<Part>(announced),
    );
    assert!(accepted);
    assert_eq!(settled, announced);
}

/// A client whose 0-RTT the server accepted checks that the server kept a
/// remembered `reset_stream_at` (§3): one left out closes the connection
/// with PROTOCOL_VIOLATION; one announced only in this handshake, or absent
/// from both, is no failure.
#[test]
fn a_remembered_reset_stream_at_left_out_fails_the_check_of_accepted_0_rtt() {
    use sakuya_wire::v1::transport_parameters::TransportParameters;

    use crate::v1::parameters::AcceptedZeroRttParameters;

    let parameters = |announced: bool| {
        let mut parameters = TransportParameters::<Bytes, WithExtension>::new();
        if announced {
            parameters.set(ResetStreamAt);
        }
        parameters.known
    };
    let check = |remembered, received| {
        <WithExtension as AcceptedZeroRttParameters<_>>::check_accepted(&remembered, &received)
    };
    for (remembered, received) in [(true, true), (false, true), (false, false)] {
        assert!(check(parameters(remembered), parameters(received)).is_ok());
    }
    let error = check(parameters(true), parameters(false)).expect_err("left out");
    let PartsError(Coproduct::Inr(Coproduct::Inl(error))) = error else {
        panic!("not the extension's error");
    };
    assert!(matches!(error, ConnectionError::ZeroRttExtensionDisabled));
    assert_eq!(error.code(), TransportErrorCode::PROTOCOL_VIOLATION);
    assert_eq!(error.frame_type(), None);
}
