use std::{net::SocketAddr, num::NonZeroUsize};

use bytes::Bytes;
use nitori_crypto_aws_lc::AwsLcBackend;
use sakuya_datagram_routing::route::recognizer::ConnectionIdGenerator;
use sakuya_packet_protection::{backend::ring::RingBackend, retry::verify_retry_integrity_tag};
use sakuya_wire::{
    connection_id::{ConnectionId, StatelessResetToken},
    header::codec::ReadLongHeaderHostExt as _,
    v1::{
        header::{
            LongPacketHeader, TypeFields,
            codec::{ReadLongPacketHostExt as _, WriteLongPacketHeaderHostExt as _},
        },
        packet_number::PacketNumberLength,
    },
    var_int::{VarInt, VarIntField, VarIntWidth},
};
use time::UtcDateTime;

use super::{
    FirstDatagramOutcome, IncomingLoad, LateInitialOutcome, ReleaseReason, ReturnedToken,
    StatelessCheck,
};
use crate::{
    address_token::{
        AddressTokenKey, AddressTokenLifetimes, AddressTokens, AeadAddressTokens,
        ExactTokenAddressPolicy, NewTokenAddress, NewTokenIssuer,
    },
    quota::ServerQuotas,
    retry::LoadStatelessRetryPolicy,
};

/// Generates the connection ID in its configuration.
struct FixedGenerator(ConnectionId);

impl ConnectionIdGenerator for FixedGenerator {
    type Config = ConnectionId;

    fn new(config: &ConnectionId) -> Self {
        Self(*config)
    }

    fn generate(&mut self) -> (ConnectionId, StatelessResetToken) {
        (self.0, StatelessResetToken::from([0; 16]))
    }

    fn stateless_reset_token(_: &ConnectionId, _: &ConnectionId) -> Option<StatelessResetToken> {
        None
    }
}

type Check = StatelessCheck<
    AeadAddressTokens<AwsLcBackend>,
    LoadStatelessRetryPolicy,
    RingBackend,
    FixedGenerator,
>;

fn cid(bytes: &[u8]) -> ConnectionId {
    ConnectionId::new(bytes).unwrap()
}

fn server_cid() -> ConnectionId {
    cid(&[0x5e; 8])
}

fn check() -> Check {
    let tokens = AeadAddressTokens::new(
        AwsLcBackend,
        AddressTokenKey::from_bytes(&[3; AddressTokenKey::LEN]),
        AddressTokenLifetimes::default(),
        ExactTokenAddressPolicy,
    )
    .unwrap();
    StatelessCheck::new(
        tokens,
        LoadStatelessRetryPolicy::default(),
        RingBackend,
        server_cid(),
        &ServerQuotas {
            incoming_queue_capacity: NonZeroUsize::new(8).unwrap(),
            zero_rtt_incoming_limit: 2,
            ..ServerQuotas::default()
        },
    )
}

fn now() -> UtcDateTime {
    UtcDateTime::from_unix_timestamp(1_800_000_000).unwrap()
}

fn peer() -> SocketAddr {
    "192.0.2.1:4433".parse().unwrap()
}

const IDLE: IncomingLoad = IncomingLoad {
    waiting: 0,
    waiting_born_from_zero_rtt: 0,
};

const LOADED: IncomingLoad = IncomingLoad {
    waiting: 5,
    waiting_born_from_zero_rtt: 0,
};

/// A datagram of `len` bytes holding one long packet with `header`, whose
/// Length covers the rest of the datagram.
fn datagram(header: impl Fn(VarIntField<VarInt>) -> LongPacketHeader, len: usize) -> Vec<u8> {
    let probe = header(VarIntField::new(VarInt::ZERO, VarIntWidth::Two).unwrap());
    let mut written = Vec::new();
    written.sync_write_long_packet_header_unpin(probe).unwrap();
    let length = VarInt::try_from(len - written.len()).unwrap();
    let mut packet = Vec::new();
    packet
        .sync_write_long_packet_header_unpin(header(
            VarIntField::new(length, VarIntWidth::Two).unwrap(),
        ))
        .unwrap();
    packet.resize(len, 0);
    packet
}

fn initial(dcid: ConnectionId, token: &[u8], len: usize) -> Vec<u8> {
    let token = Bytes::copy_from_slice(token);
    datagram(
        |length| {
            LongPacketHeader::initial(
                dcid,
                cid(&[0xc1; 4]),
                VarIntWidth::Two,
                token.clone(),
                PacketNumberLength::One,
                length,
            )
            .unwrap()
        },
        len,
    )
}

fn zero_rtt(dcid: ConnectionId, len: usize) -> Vec<u8> {
    datagram(
        |length| LongPacketHeader::zero_rtt(dcid, cid(&[0xc1; 4]), PacketNumberLength::One, length),
        len,
    )
}

fn client_dcid() -> ConnectionId {
    cid(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08])
}

#[test]
fn a_small_initial_is_released() {
    let outcome = check().first_datagram(
        &initial(client_dcid(), &[], 1199),
        Some(&peer()),
        IDLE,
        now(),
    );
    assert_eq!(
        outcome,
        FirstDatagramOutcome::Release(ReleaseReason::TooSmall)
    );
}

#[test]
fn an_initial_without_a_token_is_admitted_when_idle() {
    let outcome = check().first_datagram(
        &initial(client_dcid(), &[], 1200),
        Some(&peer()),
        IDLE,
        now(),
    );
    let FirstDatagramOutcome::Admit(admitted) = outcome else {
        panic!("not admitted: {outcome:?}");
    };
    assert!(!admitted.born_from_zero_rtt);
    assert_eq!(admitted.token, ReturnedToken::Absent);
}

/// The token of a Retry packet.
fn retry_token(retry: &[u8]) -> Bytes {
    let mut input = retry;
    let header = input.sync_read_long_header_unpin().unwrap();
    let packet = input.sync_read_long_packet_unpin(header).unwrap();
    assert_eq!(*packet.scid(), server_cid());
    let TypeFields::Retry { token, .. } = packet.into_fields() else {
        panic!("not a Retry packet");
    };
    token
}

#[test]
fn a_loaded_endpoint_retries_and_admits_the_returned_token() {
    let mut check = check();
    let outcome = check.first_datagram(
        &initial(client_dcid(), &[], 1200),
        Some(&peer()),
        LOADED,
        now(),
    );
    let FirstDatagramOutcome::SendRetry(retry) = outcome else {
        panic!("no Retry: {outcome:?}");
    };
    verify_retry_integrity_tag(&RingBackend, &client_dcid(), &retry).unwrap();
    let token = retry_token(&retry);

    let outcome = check.first_datagram(
        &initial(server_cid(), &token, 1200),
        Some(&peer()),
        LOADED,
        now(),
    );
    let FirstDatagramOutcome::Admit(admitted) = outcome else {
        panic!("not admitted: {outcome:?}");
    };
    assert_eq!(
        admitted.token,
        ReturnedToken::Retry {
            original_dcid: client_dcid(),
            retry_scid: server_cid(),
        }
    );
}

#[test]
fn an_invalid_retry_token_closes_the_attempt() {
    let mut check = check();
    let retry = check
        .tokens()
        .issue_retry(&peer(), &client_dcid(), now())
        .unwrap();
    let mut token = retry.to_vec();
    let last = token.len() - 1;
    token[last] ^= 1;
    let outcome = check.first_datagram(
        &initial(server_cid(), &token, 1200),
        Some(&peer()),
        IDLE,
        now(),
    );
    assert!(matches!(
        outcome,
        FirstDatagramOutcome::SendInvalidTokenClose(_)
    ));
}

#[test]
fn a_new_token_is_accepted_once() {
    let mut check = check();
    let token = check
        .tokens()
        .new_token_issuer()
        .issue(&peer(), now())
        .unwrap();
    let datagram = initial(client_dcid(), &token, 1200);
    let first = check.first_datagram(&datagram, Some(&peer()), LOADED, now());
    let FirstDatagramOutcome::Admit(admitted) = first else {
        panic!("not admitted: {first:?}");
    };
    assert_eq!(
        admitted.token,
        ReturnedToken::NewToken(NewTokenAddress::Validated)
    );

    // Accepted before, so the address counts as not validated, and the
    // loaded endpoint retries.
    let again = check.first_datagram(&datagram, Some(&peer()), LOADED, now());
    assert!(matches!(again, FirstDatagramOutcome::SendRetry(_)));
    let idle = check.first_datagram(&datagram, Some(&peer()), IDLE, now());
    let FirstDatagramOutcome::Admit(admitted) = idle else {
        panic!("not admitted: {idle:?}");
    };
    assert_eq!(admitted.token, ReturnedToken::InvalidNewToken);
}

#[test]
fn a_peer_that_is_not_a_socket_address_gets_no_retry() {
    let mut check = check();
    let token = check
        .tokens()
        .new_token_issuer()
        .issue(&peer(), now())
        .unwrap();
    let outcome = check.first_datagram(&initial(client_dcid(), &token, 1200), None, LOADED, now());
    let FirstDatagramOutcome::Admit(admitted) = outcome else {
        panic!("not admitted: {outcome:?}");
    };
    assert_eq!(admitted.token, ReturnedToken::InvalidNewToken);
}

#[test]
fn a_zero_rtt_first_packet_is_admitted_within_its_bounds() {
    let mut check = check();
    let small = zero_rtt(client_dcid(), 60);
    let outcome = check.first_datagram(&small, Some(&peer()), LOADED, now());
    let FirstDatagramOutcome::Admit(admitted) = outcome else {
        panic!("not admitted: {outcome:?}");
    };
    assert!(admitted.born_from_zero_rtt);
    assert_eq!(admitted.token, ReturnedToken::Absent);

    let short_dcid = zero_rtt(cid(&[1, 2, 3, 4]), 60);
    assert_eq!(
        check.first_datagram(&short_dcid, Some(&peer()), IDLE, now()),
        FirstDatagramOutcome::Release(ReleaseReason::ZeroRttDcidTooShort)
    );

    let full = IncomingLoad {
        waiting: 2,
        waiting_born_from_zero_rtt: 2,
    };
    assert_eq!(
        check.first_datagram(&small, Some(&peer()), full, now()),
        FirstDatagramOutcome::Release(ReleaseReason::ZeroRttIncomingLimitReached)
    );
}

#[test]
fn a_late_initial_is_checked_without_a_retry() {
    let mut check = check();
    let outcome = check.late_initial(&initial(client_dcid(), &[], 1200), Some(&peer()), now());
    assert_eq!(outcome, LateInitialOutcome::Admit(ReturnedToken::Absent));

    let mut token = check
        .tokens()
        .issue_retry(&peer(), &client_dcid(), now())
        .unwrap()
        .to_vec();
    token[5] ^= 1;
    let outcome = check.late_initial(&initial(server_cid(), &token, 1200), Some(&peer()), now());
    assert!(matches!(
        outcome,
        LateInitialOutcome::SendInvalidTokenClose(_)
    ));

    assert_eq!(
        check.late_initial(&zero_rtt(client_dcid(), 1200), Some(&peer()), now()),
        LateInitialOutcome::Release(ReleaseReason::Unreadable)
    );
    assert_eq!(
        check.late_initial(&initial(client_dcid(), &[], 1100), Some(&peer()), now()),
        LateInitialOutcome::Release(ReleaseReason::TooSmall)
    );
}
