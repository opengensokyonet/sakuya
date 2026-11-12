use super::{
    InvalidTransportParametersError, RememberedForZeroRtt, ReservedParameterId, SentBy,
    ServerOnlyError, TransportParameterList, TransportParameterSlots, TransportParameterSpace,
    TransportParameters,
    codec::{
        ReadRememberedTransportParametersHostExt as _, ReadTransportParametersError,
        ReadTransportParametersHostExt as _, WriteTransportParametersHostExt as _,
    },
    connection_id::{
        InitialSourceConnectionId, OriginalDestinationConnectionId, RetrySourceConnectionId,
        codec::ReadConnectionIdValueError,
    },
    disable_active_migration::DisableActiveMigration,
    integer::{
        AckDelayExponent, ActiveConnectionIdLimit, InitialMaxData, InitialMaxStreamDataBidiLocal,
        InitialMaxStreamDataBidiRemote, InitialMaxStreamDataUni, InitialMaxStreamsBidi,
        InitialMaxStreamsUni, MaxAckDelay, MaxIdleTimeout, MaxUdpPayloadSize,
        codec::{ReadIntegerValueHostExt as _, WriteIntegerValueHostExt as _},
    },
    preferred_address::{
        PreferredAddress, PreferredAddressFamilies,
        codec::{
            ReadPreferredAddressError, ReadPreferredAddressHostExt as _,
            WritePreferredAddressHostExt as _,
        },
    },
    stateless_reset_token,
};
use crate::{
    connection_id::{ConnectionId, NonEmptyCid, StatelessResetToken},
    parameters::{
        InvalidParametersError, KeyedParameter, ParameterList, ParameterSpace, ReadValueError,
        UnknownParameter,
        codec::{ReadParametersError, WriteParametersError},
    },
    parts::HList,
    v1::{self, role::Role, stream_count::StreamCount, transport_error::TransportErrorCode},
    var_int::{
        VarInt,
        codec::{ReadVarIntFieldError, WriteVarIntHostExt as _},
    },
};
use bytes::Bytes;
use core::{
    convert::Infallible,
    error::Error,
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
};
use nitori_io::calls::ReadArrayError;

type V1 = HList![v1::Part];
type V1List = TransportParameterList<V1>;
type ReadError = ReadTransportParametersError<Infallible>;

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

fn read(encoding: &[u8], sender: Role) -> Result<TransportParameters<&[u8]>, ReadError> {
    let mut input = encoding;
    let result = input.sync_read_transport_parameters_unpin(sender, PhantomData::<V1>);
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

fn write_invalid(
    parameters: TransportParameters<&[u8]>,
    sender: Role,
) -> InvalidTransportParametersError {
    assert!(parameters.validate(sender).is_err());
    let mut buffer = Vec::new();
    match buffer.sync_write_transport_parameters_unpin(parameters, sender) {
        Err(WriteParametersError::Invalid { source }) => {
            assert!(buffer.is_empty());
            source
        }
        other => panic!("{other:?}"),
    }
}

/// The failure of reading the value of the parameter type `P`, which
/// `error` must be.
fn value_error<P: KeyedParameter>(error: &ReadError) -> &P::ValueError {
    assert_eq!(error.id(), Some(P::ID), "{error:?}");
    assert!(!error.is_incomplete());
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR
    );
    match error.value_error::<P>() {
        Some(error) => error,
        None => panic!("{error:?}"),
    }
}

fn connection_id(bytes: &[u8]) -> ConnectionId {
    ConnectionId::new(bytes).unwrap()
}

fn server_parameters() -> TransportParameters<&'static [u8]> {
    let mut parameters = TransportParameters::<&'static [u8]>::new();
    parameters.set(OriginalDestinationConnectionId::new(connection_id(&[
        1, 2, 3, 4, 5, 6, 7, 8,
    ])));
    parameters.set(MaxIdleTimeout::new(vi(30_000)));
    parameters.set(stateless_reset_token::StatelessResetToken::new(
        StatelessResetToken::new([0x22; 16]),
    ));
    parameters.set(MaxUdpPayloadSize::new(vi(1472)).unwrap());
    parameters.set(InitialMaxData::new(vi(1 << 24)));
    parameters.set(InitialMaxStreamDataBidiLocal::new(vi(1 << 20)));
    parameters.set(InitialMaxStreamDataBidiRemote::new(vi(1 << 19)));
    parameters.set(InitialMaxStreamDataUni::new(vi(1 << 18)));
    parameters.set(InitialMaxStreamsBidi::new(StreamCount::MAX));
    parameters.set(InitialMaxStreamsUni::new(StreamCount::new(3).unwrap()));
    parameters.set(AckDelayExponent::new(vi(20)).unwrap());
    parameters.set(MaxAckDelay::new(vi((1 << 14) - 1)).unwrap());
    parameters.set(DisableActiveMigration);
    parameters.set(preferred_address());
    parameters.set(ActiveConnectionIdLimit::new(vi(8)).unwrap());
    parameters.set(InitialSourceConnectionId::new(ConnectionId::EMPTY));
    parameters.set(RetrySourceConnectionId::new(connection_id(&[0x77; 20])));
    parameters.unknown = vec![
        UnknownParameter::new(
            ReservedParameterId::new(vi(31 * 5 + 27)).unwrap(),
            &b"grease"[..],
        ),
        UnknownParameter::new(vi(0x20), &[0x80, 0x00, 0xff, 0xff][..]),
        UnknownParameter::new(vi(0x1d), &[][..]),
    ];
    parameters
}

#[test]
fn all_parameters_round_trip() {
    let parameters = server_parameters();
    let encoding = write(parameters.clone(), Role::Server);
    assert_eq!(encoding.len(), parameters.encoded_len());
    let decoded = read(&encoding, Role::Server).unwrap();
    assert_eq!(decoded, parameters);
    // Every slot holds its parameter, each taken by its type.
    assert_eq!(
        decoded
            .get::<OriginalDestinationConnectionId, _>()
            .unwrap()
            .get(),
        connection_id(&[1, 2, 3, 4, 5, 6, 7, 8])
    );
    assert_eq!(
        decoded.get::<MaxIdleTimeout, _>().unwrap().get(),
        vi(30_000)
    );
    assert_eq!(
        decoded
            .get::<stateless_reset_token::StatelessResetToken, _>()
            .unwrap()
            .get(),
        StatelessResetToken::new([0x22; 16])
    );
    assert_eq!(
        decoded.get::<MaxUdpPayloadSize, _>().unwrap().get(),
        vi(1472)
    );
    assert_eq!(
        decoded.get::<InitialMaxData, _>().unwrap().get(),
        vi(1 << 24)
    );
    assert_eq!(
        decoded
            .get::<InitialMaxStreamDataBidiLocal, _>()
            .unwrap()
            .get(),
        vi(1 << 20)
    );
    assert_eq!(
        decoded
            .get::<InitialMaxStreamDataBidiRemote, _>()
            .unwrap()
            .get(),
        vi(1 << 19)
    );
    assert_eq!(
        decoded.get::<InitialMaxStreamDataUni, _>().unwrap().get(),
        vi(1 << 18)
    );
    assert_eq!(
        decoded.get::<InitialMaxStreamsBidi, _>().unwrap().get(),
        StreamCount::MAX
    );
    assert_eq!(
        decoded.get::<InitialMaxStreamsUni, _>().unwrap().get(),
        StreamCount::new(3).unwrap()
    );
    assert_eq!(decoded.get::<AckDelayExponent, _>().unwrap().get(), vi(20));
    assert_eq!(
        decoded.get::<MaxAckDelay, _>().unwrap().get(),
        vi((1 << 14) - 1)
    );
    assert_eq!(
        decoded.get::<DisableActiveMigration, _>(),
        Some(&DisableActiveMigration)
    );
    assert_eq!(
        decoded.get::<PreferredAddress, _>(),
        Some(&preferred_address())
    );
    assert_eq!(
        decoded.get::<ActiveConnectionIdLimit, _>().unwrap().get(),
        vi(8)
    );
    assert_eq!(
        decoded.get::<InitialSourceConnectionId, _>().unwrap().get(),
        ConnectionId::EMPTY
    );
    assert_eq!(
        decoded.get::<RetrySourceConnectionId, _>().unwrap().get(),
        connection_id(&[0x77; 20])
    );

    // A `Bytes` source keeps unknown values in its own storage.
    let shared = Bytes::from(encoding.clone());
    let from_bytes = shared
        .clone()
        .sync_read_transport_parameters_unpin(Role::Server, PhantomData::<V1>)
        .unwrap();
    let grease = &from_bytes.unknown[0].value;
    assert_eq!(grease, &b"grease"[..]);
    let offset = grease.as_ptr() as usize - shared.as_ptr() as usize;
    assert_eq!(shared.slice(offset..offset + 6), *grease);
    assert_eq!(from_bytes.known, parameters.known);

    // An exact slice takes it; a shorter one keeps the accepted prefix.
    let mut exact = vec![0; encoding.len()];
    let mut sink = exact.as_mut_slice();
    sink.sync_write_transport_parameters_unpin(parameters.clone(), Role::Server)
        .unwrap();
    assert_eq!(exact, encoding);
    // The cut falls in each part of the encoding in turn: within the head or
    // the value of a parameter with a type, and within an unknown one.
    for cut in [1, 5, 12, encoding.len() - 20, encoding.len() - 1] {
        let mut short = vec![0xee; cut];
        let mut sink = short.as_mut_slice();
        let error = sink
            .sync_write_transport_parameters_unpin(parameters.clone(), Role::Server)
            .unwrap_err();
        let WriteParametersError::Write { source } = &error else {
            panic!("{error:?}")
        };
        assert_eq!(source.completed(), cut);
        assert_eq!(short, encoding[..cut]);
    }
}

/// Each parameter alone is written as its ID, the length of its value and
/// its value, and read back.
#[test]
fn each_parameter_round_trips_alone() {
    fn check<P, I>(parameter: P, value: &[u8])
    where
        P: KeyedParameter<Space = TransportParameterSpace> + Clone + PartialEq + core::fmt::Debug,
        TransportParameterSlots: crate::parts::Selector<Option<P>, I>,
    {
        let mut parameters = TransportParameters::<&[u8]>::new();
        assert_eq!(parameters.set(parameter.clone()), None);
        assert_eq!(parameter.value_len(), value.len());
        let encoding = write(parameters.clone(), Role::Server);
        assert_eq!(encoding, tlv(P::ID.get(), value), "{:#x}", P::ID.get());
        assert_eq!(encoding.len(), parameters.encoded_len());
        let decoded = read(&encoding, Role::Server).unwrap();
        assert_eq!(decoded.get::<P, I>(), Some(&parameter));
        assert_eq!(decoded, parameters);
    }
    let token = StatelessResetToken::new([0x22; 16]);
    check(
        OriginalDestinationConnectionId::new(connection_id(&[1, 2])),
        &[1, 2],
    );
    check(MaxIdleTimeout::new(vi(30_000)), &integer(30_000));
    check(
        stateless_reset_token::StatelessResetToken::new(token),
        &[0x22; 16],
    );
    check(MaxUdpPayloadSize::new(vi(1200)).unwrap(), &integer(1200));
    check(
        InitialMaxData::new(VarInt::MAX),
        &integer(VarInt::MAX.get()),
    );
    check(InitialMaxStreamDataBidiLocal::new(vi(1)), &[1]);
    check(InitialMaxStreamDataBidiRemote::new(vi(2)), &[2]);
    check(InitialMaxStreamDataUni::new(vi(3)), &[3]);
    check(
        InitialMaxStreamsBidi::new(StreamCount::MAX),
        &integer(1 << 60),
    );
    check(InitialMaxStreamsUni::new(StreamCount::ZERO), &[0]);
    check(AckDelayExponent::new(vi(0)).unwrap(), &[0]);
    check(MaxAckDelay::new(vi(100)).unwrap(), &integer(100));
    check(DisableActiveMigration, &[]);
    check(preferred_address(), &preferred_address_value());
    check(ActiveConnectionIdLimit::new(vi(2)).unwrap(), &[2]);
    check(InitialSourceConnectionId::new(ConnectionId::EMPTY), &[]);
    check(
        RetrySourceConnectionId::new(connection_id(&[9; 20])),
        &[9; 20],
    );
}

#[test]
fn absent_parameters_are_none_and_have_defaults() {
    let parameters = read(&[], Role::Client).unwrap();
    assert_eq!(parameters, TransportParameters::<&[u8]>::new());
    assert_eq!(parameters, TransportParameters::<&[u8]>::default());
    assert_eq!(parameters.encoded_len(), 0);
    assert!(parameters.get::<MaxUdpPayloadSize, _>().is_none());
    assert!(parameters.get::<MaxIdleTimeout, _>().is_none());
    assert!(parameters.get::<DisableActiveMigration, _>().is_none());
    assert!(parameters.get::<InitialSourceConnectionId, _>().is_none());
    assert!(parameters.unknown.is_empty());

    // The defaults of RFC 9000 §18.2.
    assert_eq!(
        parameters.get_or_default::<MaxUdpPayloadSize, _>().get(),
        vi(65527)
    );
    assert_eq!(
        parameters.get_or_default::<AckDelayExponent, _>().get(),
        vi(3)
    );
    assert_eq!(parameters.get_or_default::<MaxAckDelay, _>().get(), vi(25));
    assert_eq!(
        parameters
            .get_or_default::<ActiveConnectionIdLimit, _>()
            .get(),
        vi(2)
    );
    assert_eq!(MaxIdleTimeout::default().get(), VarInt::ZERO);
    assert_eq!(InitialMaxData::default().get(), VarInt::ZERO);
    assert_eq!(InitialMaxStreamDataBidiLocal::default().get(), VarInt::ZERO);
    assert_eq!(
        InitialMaxStreamDataBidiRemote::default().get(),
        VarInt::ZERO
    );
    assert_eq!(InitialMaxStreamDataUni::default().get(), VarInt::ZERO);
    assert_eq!(InitialMaxStreamsBidi::default().get(), StreamCount::ZERO);
    assert_eq!(InitialMaxStreamsUni::default().get(), StreamCount::ZERO);
    // The defaults are values their types accept.
    assert_eq!(
        MaxUdpPayloadSize::new(vi(65527)),
        Ok(MaxUdpPayloadSize::default())
    );
    assert_eq!(
        AckDelayExponent::new(vi(3)),
        Ok(AckDelayExponent::default())
    );
    assert_eq!(MaxAckDelay::new(vi(25)), Ok(MaxAckDelay::default()));
    assert_eq!(
        ActiveConnectionIdLimit::new(vi(2)),
        Ok(ActiveConnectionIdLimit::default())
    );

    // Only the slots that hold a parameter are written, in the order of the
    // list.
    let mut client = TransportParameters::<&[u8]>::new();
    client.set(InitialSourceConnectionId::new(connection_id(&[9; 4])));
    client.set(InitialMaxData::new(vi(100)));
    let mut expected = tlv(0x04, &integer(100));
    expected.extend(tlv(0x0f, &[9; 4]));
    assert_eq!(write(client, Role::Client), expected);
}

/// A parameter that states the default value of its type is not an absent
/// one: it is read as `Some`, written, and read back as `Some`.
#[test]
fn a_parameter_with_its_default_value_is_present() {
    let mut encoding = tlv(0x03, &integer(65527));
    encoding.extend(tlv(0x04, &integer(0)));
    encoding.extend(tlv(0x0e, &integer(2)));
    let parameters = read(&encoding, Role::Client).unwrap();
    assert_ne!(parameters, TransportParameters::<&[u8]>::new());
    assert_eq!(
        parameters.get::<MaxUdpPayloadSize, _>(),
        Some(&MaxUdpPayloadSize::default())
    );
    assert_eq!(
        parameters.get::<InitialMaxData, _>(),
        Some(&InitialMaxData::default())
    );
    assert_eq!(
        parameters.get::<ActiveConnectionIdLimit, _>(),
        Some(&ActiveConnectionIdLimit::default())
    );
    assert_eq!(write(parameters.clone(), Role::Client), encoding);
    assert_eq!(read(&encoding, Role::Client).unwrap(), parameters);

    let mut built = TransportParameters::<&[u8]>::new();
    built.set(MaxAckDelay::default());
    let written = write(built.clone(), Role::Client);
    assert_eq!(written, tlv(0x0b, &integer(25)));
    let decoded = read(&written, Role::Client).unwrap();
    assert_eq!(
        decoded.get::<MaxAckDelay, _>(),
        Some(&MaxAckDelay::default())
    );
    assert_eq!(decoded, built);
}

#[test]
fn slots_are_set_and_taken_by_type() {
    let mut parameters = TransportParameters::<&[u8]>::new();
    assert_eq!(parameters.set(InitialMaxData::new(vi(1))), None);
    assert_eq!(
        parameters.set(InitialMaxData::new(vi(2))),
        Some(InitialMaxData::new(vi(1)))
    );
    *parameters.slot_mut::<MaxIdleTimeout, _>() = Some(MaxIdleTimeout::new(vi(7)));
    assert_eq!(
        parameters
            .slot_mut::<InitialMaxData, _>()
            .take()
            .unwrap()
            .get(),
        vi(2)
    );
    assert!(parameters.get::<InitialMaxData, _>().is_none());
    parameters.set(MaxAckDelay::new(vi(9)).unwrap());

    // Several slots at once, in any order, without their positions.
    type Taken<'a> = HList![&'a Option<MaxAckDelay>, &'a Option<MaxIdleTimeout>];
    let (taken, _rest): (Taken<'_>, _) = parameters.known.to_ref().sculpt();
    assert_eq!(taken.head.unwrap().get(), vi(9));
    assert_eq!(taken.tail.head.unwrap().get(), vi(7));
    // All the slots of a part: here the only one.
    let (all, rest): (TransportParameterSlots<V1>, _) = parameters.known.sculpt();
    assert_eq!(rest, crate::parts::HNil);
    assert_eq!(all.get::<Option<MaxIdleTimeout>, _>().unwrap().get(), vi(7));
}

#[test]
fn duplicates_are_rejected() {
    let mut known = tlv(0x04, &integer(1));
    known.extend(tlv(0x04, &integer(1)));
    let mut unknown = tlv(0x40, b"a");
    unknown.extend(tlv(0x41, b""));
    unknown.extend(tlv(0x40, b"b"));
    // A reserved ID is an unknown parameter, and may not repeat either.
    let mut reserved = tlv(31 * 2 + 27, b"a");
    reserved.extend(tlv(0x04, &integer(1)));
    reserved.extend(tlv(31 * 2 + 27, b""));
    for (encoding, duplicate) in [(known, 0x04), (unknown, 0x40), (reserved, 31 * 2 + 27)] {
        let error = read(&encoding, Role::Server).unwrap_err();
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::TRANSPORT_PARAMETER_ERROR
        );
        assert!(!error.is_incomplete());
        assert_eq!(error.id(), Some(vi(duplicate)));
        let ReadParametersError::Duplicate { source } = error else {
            panic!("{error:?}")
        };
        assert_eq!(source.id(), vi(duplicate));
    }

    // An unknown parameter to write may not have the ID of a type.
    let mut parameters = TransportParameters::<&[u8]>::new();
    parameters
        .unknown
        .push(UnknownParameter::new(MaxIdleTimeout::ID, &[0x01][..]));
    assert_eq!(
        parameters.validate(Role::Client),
        Err(InvalidParametersError::ClaimedId {
            id: MaxIdleTimeout::ID
        })
    );
    assert_eq!(
        write_invalid(parameters.clone(), Role::Client),
        InvalidParametersError::ClaimedId {
            id: MaxIdleTimeout::ID
        }
    );
    parameters.unknown = vec![
        UnknownParameter::new(vi(0x40), &b""[..]),
        UnknownParameter::new(vi(0x40), &b""[..]),
    ];
    let InvalidParametersError::Duplicate { source } = write_invalid(parameters, Role::Client)
    else {
        panic!()
    };
    assert_eq!(source.id(), vi(0x40));
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
        let error = read(&encoding, Role::Client).unwrap_err();
        assert_eq!(error.id(), Some(vi(parameter)));
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::TRANSPORT_PARAMETER_ERROR
        );
        let ReadParametersError::NotAdmitted { source } = error else {
            panic!("{error:?}")
        };
        assert_eq!(source.id(), vi(parameter));
        assert_eq!(*source.reason(), ServerOnlyError);
        let parameters = read(&encoding, Role::Server).unwrap();
        let InvalidParametersError::NotAdmitted { source: invalid } =
            write_invalid(parameters.clone(), Role::Client)
        else {
            panic!()
        };
        assert_eq!(invalid, source);
        assert_eq!(parameters.validate(Role::Server), Ok(()));
        assert_eq!(write(parameters, Role::Server), encoding);
    }
    // The space rejects before the value is read: a value that is not a
    // value of the type is not looked at.
    let error = read(&tlv(0x02, &[0; 3]), Role::Client).unwrap_err();
    assert!(matches!(error, ReadParametersError::NotAdmitted { .. }));
    let error = read(&tlv(0x02, &[0; 3]), Role::Server).unwrap_err();
    assert!(matches!(error, ReadParametersError::InvalidValue { .. }));
}

/// The four parameters of RFC 9000 §18.2 that only a server may send state
/// so, the seven that a client must not use remembered values for are not
/// remembered for 0-RTT while every other one must be (RFC 9000 §7.4.1),
/// and the IDs of the list are `0x00` to `0x10` in order.
#[test]
fn parameter_ids_senders_and_zero_rtt() {
    fn attributes<P: KeyedParameter<Space = TransportParameterSpace>>()
    -> (u64, SentBy, RememberedForZeroRtt) {
        (
            P::ID.get(),
            P::ATTRIBUTES.sent_by,
            P::ATTRIBUTES.remembered_for_zero_rtt,
        )
    }
    use RememberedForZeroRtt::{Mandatory, Prohibited};
    use SentBy::{Either, ServerOnly};
    let parameters = [
        (
            attributes::<OriginalDestinationConnectionId>(),
            (ServerOnly, Prohibited),
        ),
        (attributes::<MaxIdleTimeout>(), (Either, Mandatory)),
        (
            attributes::<stateless_reset_token::StatelessResetToken>(),
            (ServerOnly, Prohibited),
        ),
        (attributes::<MaxUdpPayloadSize>(), (Either, Mandatory)),
        (attributes::<InitialMaxData>(), (Either, Mandatory)),
        (
            attributes::<InitialMaxStreamDataBidiLocal>(),
            (Either, Mandatory),
        ),
        (
            attributes::<InitialMaxStreamDataBidiRemote>(),
            (Either, Mandatory),
        ),
        (attributes::<InitialMaxStreamDataUni>(), (Either, Mandatory)),
        (attributes::<InitialMaxStreamsBidi>(), (Either, Mandatory)),
        (attributes::<InitialMaxStreamsUni>(), (Either, Mandatory)),
        (attributes::<AckDelayExponent>(), (Either, Prohibited)),
        (attributes::<MaxAckDelay>(), (Either, Prohibited)),
        (attributes::<DisableActiveMigration>(), (Either, Mandatory)),
        (attributes::<PreferredAddress>(), (ServerOnly, Prohibited)),
        (attributes::<ActiveConnectionIdLimit>(), (Either, Mandatory)),
        (
            attributes::<InitialSourceConnectionId>(),
            (Either, Prohibited),
        ),
        (
            attributes::<RetrySourceConnectionId>(),
            (ServerOnly, Prohibited),
        ),
    ];
    for (index, ((id, sent_by, remembered), expected)) in parameters.into_iter().enumerate() {
        assert_eq!(id, index as u64);
        assert_eq!((sent_by, remembered), expected, "{id:#x}");
    }
    let ids = <V1List as ParameterList<TransportParameterSpace>>::IDS;
    for value in (0..=0x41).chain([31 * 5 + 27, VarInt::MAX.get()]) {
        assert_eq!(ids.contains(vi(value)), value <= 0x10, "{value:#x}");
    }
    const { assert!(<V1List as ParameterList<TransportParameterSpace>>::DISTINCT_AND_UNRESERVED) };
}

/// Reading the stored parameters of a server keeps the slots of the types
/// remembered for 0-RTT, empties the others and leaves out the unknown
/// parameters.
#[test]
fn remembered_parameters_keep_only_the_remembered_slots() {
    let parameters = server_parameters();
    let encoding = write(parameters.clone(), Role::Server);
    let remembered: TransportParameterSlots = encoding
        .as_slice()
        .sync_read_remembered_transport_parameters_unpin(PhantomData::<V1>)
        .unwrap();
    let mut expected = parameters.clone();
    expected.unknown.clear();
    *expected.slot_mut::<OriginalDestinationConnectionId, _>() = None;
    *expected.slot_mut::<stateless_reset_token::StatelessResetToken, _>() = None;
    *expected.slot_mut::<AckDelayExponent, _>() = None;
    *expected.slot_mut::<MaxAckDelay, _>() = None;
    *expected.slot_mut::<PreferredAddress, _>() = None;
    *expected.slot_mut::<InitialSourceConnectionId, _>() = None;
    *expected.slot_mut::<RetrySourceConnectionId, _>() = None;
    assert_eq!(remembered, expected.known);
    // What is kept is what the server sent.
    assert_eq!(
        remembered.get::<Option<InitialMaxData>, _>(),
        &Some(InitialMaxData::new(vi(1 << 24)))
    );
    assert_eq!(
        remembered.get::<Option<DisableActiveMigration>, _>(),
        &Some(DisableActiveMigration)
    );
}

/// The stored parameters are the server's: parameters only a server may
/// send are admitted, and a malformed one is rejected even if it is not
/// remembered.
#[test]
fn remembered_parameters_are_read_as_a_server_sent_them() {
    let encoding = tlv(0x02, &[0x22; 16]);
    let remembered: TransportParameterSlots = encoding
        .as_slice()
        .sync_read_remembered_transport_parameters_unpin(PhantomData::<V1>)
        .unwrap();
    assert_eq!(remembered, TransportParameters::<&[u8]>::new().known);
    let error = tlv(0x02, &[0x22; 3])
        .as_slice()
        .sync_read_remembered_transport_parameters_unpin(PhantomData::<V1>)
        .unwrap_err();
    assert!(matches!(error, ReadParametersError::InvalidValue { .. }));
}

#[test]
fn reserved_ids_have_the_form_31_n_plus_27() {
    let reserved = TransportParameterSpace::RESERVED;
    for value in 0..=1000 {
        let id = vi(value);
        let is_reserved = value >= 27 && (value - 27) % 31 == 0;
        assert_eq!(reserved.contains(id), is_reserved, "{value}");
        match ReservedParameterId::new(id) {
            Ok(reserved_id) => {
                assert!(is_reserved);
                assert_eq!(reserved_id.get(), id);
                assert_eq!(VarInt::from(reserved_id), id);
            }
            Err(error) => {
                assert!(!is_reserved);
                assert_eq!(error.id(), id);
                assert_eq!(ReservedParameterId::try_from(id), Err(error));
            }
        }
    }
    assert!(reserved.contains(vi(27)));
    assert!(!reserved.contains(vi(26)));
}

/// A reserved ID has no type: it is kept as an unknown parameter and
/// written back.
#[test]
fn reserved_parameters_are_unknown() {
    let mut encoding = tlv(31 * 1000 + 27, b"reserved");
    encoding.extend(tlv(27, b""));
    let parameters = read(&encoding, Role::Client).unwrap();
    assert_eq!(
        parameters.unknown,
        [
            UnknownParameter::new(vi(31 * 1000 + 27), &b"reserved"[..]),
            UnknownParameter::new(vi(27), &b""[..]),
        ]
    );
    assert_eq!(parameters.known, TransportParameters::<&[u8]>::new().known);
    assert_eq!(parameters.validate(Role::Client), Ok(()));
    assert_eq!(write(parameters, Role::Client), encoding);
}

#[test]
fn range_errors_hold_only_values_out_of_range() {
    for value in [0, 1199] {
        let error = MaxUdpPayloadSize::new(vi(value)).unwrap_err();
        assert_eq!(error.value(), vi(value));
    }
    assert_eq!(MaxUdpPayloadSize::new(vi(1200)).unwrap().get(), vi(1200));
    for value in [21, VarInt::MAX.get()] {
        let error = AckDelayExponent::new(vi(value)).unwrap_err();
        assert_eq!(error.value(), vi(value));
    }
    assert_eq!(AckDelayExponent::new(vi(20)).unwrap().get(), vi(20));
    for value in [1 << 14, VarInt::MAX.get()] {
        let error = MaxAckDelay::new(vi(value)).unwrap_err();
        assert_eq!(error.value(), vi(value));
    }
    assert_eq!(
        MaxAckDelay::new(vi((1 << 14) - 1)).unwrap().get(),
        vi((1 << 14) - 1)
    );
    for value in [0, 1] {
        let error = ActiveConnectionIdLimit::new(vi(value)).unwrap_err();
        assert_eq!(error.value(), vi(value));
        assert_eq!(ActiveConnectionIdLimit::try_from(vi(value)), Err(error));
    }
    assert_eq!(ActiveConnectionIdLimit::new(vi(2)).unwrap().get(), vi(2));
    assert_eq!(
        MaxUdpPayloadSize::new(vi(1199)).unwrap_err().to_string(),
        "max_udp_payload_size 1199 is below 1200"
    );
    assert!(InitialMaxStreamsBidi::try_from(vi((1 << 60) + 1)).is_err());
    assert_eq!(
        InitialMaxStreamsUni::try_from(vi(1 << 60)).unwrap().get(),
        StreamCount::MAX
    );
}

/// Reading a constrained parameter checks its range as constructing it
/// does: the failure is that of the type, with the rejected value.
#[test]
fn values_out_of_range_are_rejected_by_parameter() {
    fn check<P, V>(invalid: u64, valid: u64, expected: V)
    where
        P: KeyedParameter<
                Space = TransportParameterSpace,
                ValueError = ReadValueError<ReadVarIntFieldError<Infallible, V>>,
            > + TryFrom<VarInt, Error = V>,
        V: Error + PartialEq + 'static,
    {
        let error = read(&tlv(P::ID.get(), &integer(invalid)), Role::Client).unwrap_err();
        let ReadValueError::Content {
            source: ReadVarIntFieldError::Value { value, source },
        } = value_error::<P>(&error)
        else {
            panic!("{error:?}")
        };
        assert_eq!(*value, vi(invalid));
        assert_eq!(*source, expected);
        assert_eq!(P::try_from(vi(invalid)).err(), Some(expected));
        // The source chain reaches the broken rule.
        let chain: &dyn Error = &error;
        let rule = chain.source().unwrap().source().unwrap().source().unwrap();
        assert!(rule.downcast_ref::<V>().is_some());
        assert!(read(&tlv(P::ID.get(), &integer(valid)), Role::Client).is_ok());
        assert!(P::try_from(vi(valid)).is_ok());
    }
    check::<MaxUdpPayloadSize, _>(1199, 1200, MaxUdpPayloadSize::new(vi(1199)).unwrap_err());
    let count = |value| StreamCount::new(value).unwrap_err();
    check::<InitialMaxStreamsBidi, _>((1 << 60) + 1, 1 << 60, count((1 << 60) + 1));
    check::<InitialMaxStreamsUni, _>((1 << 60) + 1, 1 << 60, count((1 << 60) + 1));
    check::<AckDelayExponent, _>(21, 20, AckDelayExponent::new(vi(21)).unwrap_err());
    check::<MaxAckDelay, _>(
        1 << 14,
        (1 << 14) - 1,
        MaxAckDelay::new(vi(1 << 14)).unwrap_err(),
    );
    check::<ActiveConnectionIdLimit, _>(1, 2, ActiveConnectionIdLimit::new(vi(1)).unwrap_err());
}

/// A value that claims more bytes than a Transport Parameter Length field
/// can state.
#[cfg(target_pointer_width = "64")]
#[derive(Clone)]
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
    let mut parameters = TransportParameters::<Huge>::new();
    parameters
        .unknown
        .push(UnknownParameter::new(vi(0x40), Huge));
    let Err(InvalidParametersError::ValueLength { source }) = parameters.validate(Role::Client)
    else {
        panic!()
    };
    assert_eq!(source.id(), vi(0x40));
    assert_eq!(source.length(), usize::MAX);
    let mut buffer = Vec::new();
    let error = buffer
        .sync_write_transport_parameters_unpin(parameters, Role::Client)
        .unwrap_err();
    assert!(matches!(error, WriteParametersError::Invalid { .. }));
    assert!(buffer.is_empty());
}

/// Each integer parameter with a value that is not one integer, and each
/// connection ID parameter with a value that is too long, names its ID.
#[test]
fn malformed_values_name_their_parameter() {
    fn integer_parameter<P, V>(valid: u64)
    where
        P: KeyedParameter<
                Space = TransportParameterSpace,
                ValueError = ReadValueError<ReadVarIntFieldError<Infallible, V>>,
            >,
        V: Error + 'static,
    {
        // An integer and a byte after it.
        let mut value = integer(valid);
        value.push(0x00);
        let error = read(&tlv(P::ID.get(), &value), Role::Server).unwrap_err();
        let ReadValueError::Trailing { source } = value_error::<P>(&error) else {
            panic!("{error:?}")
        };
        assert_eq!((source.length(), source.unread().get()), (value.len(), 1));
        // No integer, and one cut short.
        for value in [&[][..], &[0x40]] {
            let error = read(&tlv(P::ID.get(), value), Role::Server).unwrap_err();
            let ReadValueError::Content {
                source: ReadVarIntFieldError::VarInt { source },
            } = value_error::<P>(&error)
            else {
                panic!("{error:?}")
            };
            assert!(source.is_incomplete());
            assert_eq!(source.completed(), value.len());
        }
    }
    integer_parameter::<MaxIdleTimeout, _>(5);
    integer_parameter::<MaxUdpPayloadSize, _>(1200);
    integer_parameter::<InitialMaxData, _>(5);
    integer_parameter::<InitialMaxStreamDataBidiLocal, _>(5);
    integer_parameter::<InitialMaxStreamDataBidiRemote, _>(5);
    integer_parameter::<InitialMaxStreamDataUni, _>(5);
    integer_parameter::<InitialMaxStreamsBidi, _>(5);
    integer_parameter::<InitialMaxStreamsUni, _>(5);
    integer_parameter::<AckDelayExponent, _>(5);
    integer_parameter::<MaxAckDelay, _>(5);
    integer_parameter::<ActiveConnectionIdLimit, _>(5);

    fn connection_id_parameter<P>()
    where
        P: KeyedParameter<
                Space = TransportParameterSpace,
                ValueError = ReadValueError<ReadConnectionIdValueError<Infallible>>,
            > + Into<ConnectionId>,
    {
        let error = read(&tlv(P::ID.get(), &[0; 21]), Role::Server).unwrap_err();
        let ReadValueError::Content {
            source: ReadConnectionIdValueError::Length { source },
        } = value_error::<P>(&error)
        else {
            panic!("{error:?}")
        };
        assert_eq!(source.length(), 21);
        // Twenty bytes are a connection ID, and so are none.
        for bytes in [&[7; 20][..], &[]] {
            let mut value = ValueSource::new(bytes);
            let parameter = P::read_value(&mut value).unwrap();
            assert_eq!(value.finish(), Ok(()));
            assert_eq!(parameter.into(), connection_id(bytes));
        }
    }
    use crate::parameters::ValueSource;
    connection_id_parameter::<OriginalDestinationConnectionId>();
    connection_id_parameter::<InitialSourceConnectionId>();
    connection_id_parameter::<RetrySourceConnectionId>();
}

#[test]
fn malformed_values_are_rejected_by_parameter() {
    type Token = stateless_reset_token::StatelessResetToken;
    // A token cut short, and one with a byte after it.
    let error = read(&tlv(0x02, &[0; 15]), Role::Server).unwrap_err();
    let ReadValueError::Content { source } = value_error::<Token>(&error) else {
        panic!("{error:?}")
    };
    assert!(matches!(source, ReadArrayError::Incomplete { .. }));
    let error = read(&tlv(0x02, &[0; 17]), Role::Server).unwrap_err();
    let ReadValueError::Trailing { source } = value_error::<Token>(&error) else {
        panic!("{error:?}")
    };
    assert_eq!((source.length(), source.unread().get()), (17, 1));

    // `disable_active_migration` with a value.
    let error = read(&tlv(0x0c, &[0]), Role::Server).unwrap_err();
    let source = value_error::<DisableActiveMigration>(&error);
    assert_eq!((source.length(), source.unread().get()), (1, 1));
    assert_eq!(
        source.to_string(),
        "parameter value of 1 bytes has 1 bytes after its content"
    );

    // A preferred address cut short, with an empty connection ID, and with
    // a byte after it.
    let mut zero_cid_address = preferred_address_value();
    zero_cid_address[24] = 0;
    zero_cid_address.drain(25..33);
    let mut long_address = preferred_address_value();
    long_address.push(0);
    let error = read(&tlv(0x0d, &[0; 24]), Role::Server).unwrap_err();
    assert!(matches!(
        value_error::<PreferredAddress>(&error),
        ReadValueError::Content {
            source: ReadPreferredAddressError::NoAddress
        }
    ));
    let error = read(&tlv(0x0d, &zero_cid_address), Role::Server).unwrap_err();
    assert!(matches!(
        value_error::<PreferredAddress>(&error),
        ReadValueError::Content {
            source: ReadPreferredAddressError::EmptyConnectionId { .. }
        }
    ));
    let error = read(&tlv(0x0d, &long_address), Role::Server).unwrap_err();
    let ReadValueError::Trailing { source } = value_error::<PreferredAddress>(&error) else {
        panic!("{error:?}")
    };
    assert_eq!((source.length(), source.unread().get()), (50, 1));
    // The failure of another type is not the failure of this one.
    assert!(error.value_error::<DisableActiveMigration>().is_none());
}

/// The value operations of the integer parameters read one integer of any
/// width into the type and write its shortest encoding.
#[test]
fn integer_values_are_read_and_written_by_their_operations() {
    let mut input = &[0x40, 0x19, 0xff][..];
    let delay: MaxAckDelay = input.sync_read_integer_value_unpin().unwrap();
    assert_eq!(delay.get(), vi(25));
    assert_eq!(input, [0xff]);
    let mut output = Vec::new();
    output.sync_write_integer_value_unpin(delay).unwrap();
    assert_eq!(output, [0x19]);
    let mut input = &[0x01][..];
    assert!(matches!(
        input.sync_read_integer_value_unpin::<ActiveConnectionIdLimit>(),
        Err(ReadVarIntFieldError::Value { .. })
    ));
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
            value_error::<PreferredAddress>(&error),
            ReadValueError::Content {
                source: ReadPreferredAddressError::NoAddress
            }
        ),
        "{error:?}"
    );
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
        let encoding = tlv(0x0d, &value);
        let parameters = read(&encoding, Role::Server).unwrap();
        assert_eq!(parameters.get::<PreferredAddress, _>(), Some(&address));
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
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::TRANSPORT_PARAMETER_ERROR
        );
    }
    // Each field of a parameter has a variant of its own.
    let error = read(&[0x40], Role::Client).unwrap_err();
    assert!(matches!(error, ReadParametersError::Id { .. }));
    assert_eq!(error.id(), None);
    assert!(matches!(
        // The second ID is 0 in a two-byte encoding.
        read(&[0x04, 0x01, 0x01, 0x40, 0x00, 0x80], Role::Client),
        Err(ReadParametersError::Length { id, .. }) if id == VarInt::ZERO
    ));
    assert!(matches!(
        read(&[0x04], Role::Client),
        Err(ReadParametersError::Length { id, .. }) if id == vi(0x04)
    ));
    assert!(matches!(
        read(&[0x04, 0x02, 0x01], Role::Client),
        Err(ReadParametersError::Value { id, .. }) if id == vi(0x04)
    ));
    // An unknown parameter cut short is incomplete too.
    let error = read(&[0x40, 0x40, 0x03, 0x01], Role::Client).unwrap_err();
    assert!(error.is_incomplete());
    assert!(matches!(error, ReadParametersError::Value { id, .. } if id == vi(0x40)));
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
            matches!(
                value_error::<PreferredAddress>(&error),
                ReadValueError::Content { source } if expected(source)
            ),
            "{cut}: {error:?}"
        );
    }
}

/// The parameters of extensions that are not in the list are unknown
/// parameters, kept in order after the ones with a type.
#[test]
fn unknown_parameters_are_kept_in_order() {
    let mut encoding = tlv(0x1d, &[]);
    encoding.extend(tlv(0x04, &integer(7)));
    encoding.extend(tlv(0x20, &integer(65535)));
    encoding.extend(tlv(31 * 1000 + 27, b"reserved"));
    let parameters = read(&encoding, Role::Client).unwrap();
    assert_eq!(parameters.get::<InitialMaxData, _>().unwrap().get(), vi(7));
    assert_eq!(
        parameters.unknown,
        [
            UnknownParameter::new(vi(0x1d), &[][..]),
            UnknownParameter::new(vi(0x20), &[0x80, 0x00, 0xff, 0xff][..]),
            UnknownParameter::new(vi(31 * 1000 + 27), &b"reserved"[..]),
        ]
    );
    // The slots are written first, then the unknown parameters in order.
    let mut expected = tlv(0x04, &integer(7));
    expected.extend(tlv(0x1d, &[]));
    expected.extend(tlv(0x20, &integer(65535)));
    expected.extend(tlv(31 * 1000 + 27, b"reserved"));
    assert_eq!(write(parameters, Role::Client), expected);
}

#[test]
fn read_failures_show_their_parameter() {
    let error = read(&tlv(0x03, &integer(1199)), Role::Client).unwrap_err();
    assert_eq!(error.to_string(), "parameter 0x3 has an invalid value");
    let source = Error::source(&error).unwrap();
    assert_eq!(source.to_string(), "parameter value content read failed");
    let error = read(&tlv(0x02, &[0; 16]), Role::Client).unwrap_err();
    assert_eq!(error.to_string(), "parameter 0x2 is not admitted");
    assert_eq!(
        Error::source(&error).unwrap().to_string(),
        "only a server may send this transport parameter"
    );
    let mut twice = tlv(0x0c, &[]);
    twice.extend(tlv(0x0c, &[]));
    let error = read(&twice, Role::Client).unwrap_err();
    assert_eq!(error.to_string(), "parameter 0xc appears more than once");
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

/// The parameters of extensions are remembered as their definitions say:
/// `reset_stream_at` must be, `max_datagram_frame_size` may be, and both are
/// kept; the order of the parts does not matter.
#[cfg(all(feature = "datagram", feature = "reset_stream_at"))]
#[test]
fn remembered_parameters_of_extensions() {
    use crate::{
        datagram::{self, MaxDatagramFrameSize},
        reset_stream_at::{self, ResetStreamAt},
    };
    assert_eq!(
        ResetStreamAt::ATTRIBUTES.remembered_for_zero_rtt,
        RememberedForZeroRtt::Mandatory
    );
    assert_eq!(
        MaxDatagramFrameSize::ATTRIBUTES.remembered_for_zero_rtt,
        RememberedForZeroRtt::Optional
    );
    let mut encoding = tlv(0x1d, &[]);
    encoding.extend(tlv(0x04, &integer(7)));
    encoding.extend(tlv(0x0b, &integer(30)));
    encoding.extend(tlv(0x20, &integer(1200)));
    encoding.extend(tlv(31 * 1000 + 27, b"reserved"));

    macro_rules! check {
        ($parts:ty) => {{
            let remembered = encoding
                .as_slice()
                .sync_read_remembered_transport_parameters_unpin(PhantomData::<$parts>)
                .unwrap();
            assert_eq!(
                remembered.get::<Option<ResetStreamAt>, _>(),
                &Some(ResetStreamAt)
            );
            assert_eq!(
                remembered.get::<Option<MaxDatagramFrameSize>, _>(),
                &Some(MaxDatagramFrameSize::new(vi(1200)))
            );
            assert_eq!(
                remembered.get::<Option<InitialMaxData>, _>(),
                &Some(InitialMaxData::new(vi(7)))
            );
            assert_eq!(remembered.get::<Option<MaxAckDelay>, _>(), &None);
        }};
    }
    check!(HList![v1::Part, reset_stream_at::Part, datagram::Part]);
    check!(HList![datagram::Part, v1::Part, reset_stream_at::Part]);
}
