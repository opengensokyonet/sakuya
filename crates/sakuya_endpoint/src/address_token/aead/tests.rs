use std::{net::SocketAddr, time::Duration};

use bytes::{Buf, BufMut};
use frunk_core::coproduct::{CNil, Coproduct};
use nitori_crypto_aws_lc::AwsLcBackend;
use nitori_io::SplitTo;
use sakuya_link::{PeerAddress, PeerAddressCodec, PeerAddressReadError};
use sakuya_wire::connection_id::ConnectionId;
use time::UtcDateTime;

use super::{
    AddressTokenKey, AddressTokenLifetimes, AeadAddressTokens, AeadNewTokenIssuer, PREFIX_LEN,
};
use crate::address_token::{
    AddressTokens, ExactTokenAddressPolicy, NewTokenAddress, NewTokenIssuer, TokenAddressPolicy,
    TokenKind, TokenOutcome,
};

fn start() -> UtcDateTime {
    UtcDateTime::from_unix_timestamp(1_800_000_000).unwrap()
}

fn tokens() -> AeadAddressTokens<AwsLcBackend> {
    tokens_with(ExactTokenAddressPolicy)
}

fn tokens_with<P: TokenAddressPolicy<SocketAddr>>(policy: P) -> AeadAddressTokens<AwsLcBackend, P> {
    AeadAddressTokens::new(
        AwsLcBackend,
        AddressTokenKey::from_bytes(&[7; AddressTokenKey::LEN]),
        AddressTokenLifetimes::default(),
        policy,
    )
    .unwrap()
}

fn issuer(
    tokens: &AeadAddressTokens<AwsLcBackend, impl TokenAddressPolicy<SocketAddr>>,
) -> AeadNewTokenIssuer<AwsLcBackend> {
    AddressTokens::<SocketAddr>::new_token_issuer(tokens)
}

fn peer() -> SocketAddr {
    "192.0.2.1:4433".parse().unwrap()
}

fn odcid() -> ConnectionId {
    ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]).unwrap()
}

#[test]
fn a_retry_token_returns_the_original_dcid() {
    let tokens = tokens();
    let token = tokens.issue_retry(&peer(), &odcid(), start()).unwrap();
    let later = start() + Duration::from_secs(14);
    assert_eq!(
        tokens.validate(&token, &peer(), later),
        TokenOutcome::Retry {
            original_dcid: odcid()
        }
    );
}

#[test]
fn a_retry_token_expires() {
    let tokens = tokens();
    let token = tokens.issue_retry(&peer(), &odcid(), start()).unwrap();
    let later = start() + Duration::from_secs(15);
    assert_eq!(
        tokens.validate(&token, &peer(), later),
        TokenOutcome::InvalidRetry
    );
}

#[test]
fn a_retry_token_checks_ip_and_port() {
    let tokens = tokens();
    let token = tokens.issue_retry(&peer(), &odcid(), start()).unwrap();
    let other_port: SocketAddr = "192.0.2.1:4434".parse().unwrap();
    assert_eq!(
        tokens.validate(&token, &other_port, start()),
        TokenOutcome::InvalidRetry
    );
}

#[test]
fn a_changed_retry_token_is_invalid() {
    let tokens = tokens();
    let token = tokens.issue_retry(&peer(), &odcid(), start()).unwrap();
    for index in 1..token.len() {
        let mut changed = token.to_vec();
        changed[index] ^= 1;
        assert_eq!(
            tokens.validate(&changed, &peer(), start()),
            TokenOutcome::InvalidRetry,
            "byte {index}"
        );
    }
    assert_eq!(
        tokens.validate(&token[..PREFIX_LEN + 3], &peer(), start()),
        TokenOutcome::InvalidRetry
    );
}

#[test]
fn another_key_does_not_open_a_token() {
    let token = tokens().issue_retry(&peer(), &odcid(), start()).unwrap();
    let other: AeadAddressTokens<_> = AeadAddressTokens::new(
        AwsLcBackend,
        AddressTokenKey::from_bytes(&[8; AddressTokenKey::LEN]),
        AddressTokenLifetimes::default(),
        ExactTokenAddressPolicy,
    )
    .unwrap();
    assert_eq!(
        other.validate(&token, &peer(), start()),
        TokenOutcome::InvalidRetry
    );
}

#[test]
fn a_new_token_from_the_same_ip_validates_the_address() {
    let tokens = tokens();
    let token = issuer(&tokens).issue(&peer(), start()).unwrap();
    let new_port: SocketAddr = "192.0.2.1:5000".parse().unwrap();
    let later = start() + Duration::from_secs(13 * 24 * 60 * 60);
    let TokenOutcome::NewToken(valid) = tokens.validate(&token, &new_port, later) else {
        panic!("not a valid NEW_TOKEN token");
    };
    assert_eq!(valid.address, NewTokenAddress::Validated);
    assert_eq!(
        valid.expires_at,
        start() + Duration::from_secs(14 * 24 * 60 * 60)
    );
    assert_eq!(valid.id.0, token[1..PREFIX_LEN]);
}

#[test]
fn a_new_token_from_another_ip_is_invalid_by_default() {
    let tokens = tokens();
    let token = issuer(&tokens).issue(&peer(), start()).unwrap();
    let other: SocketAddr = "192.0.2.2:4433".parse().unwrap();
    assert_eq!(
        tokens.validate(&token, &other, start()),
        TokenOutcome::InvalidNewToken
    );
}

/// Accepts any address of the same /24.
struct SameSubnet;

impl TokenAddressPolicy<SocketAddr> for SameSubnet {
    fn matches(&self, _: TokenKind, issued: &SocketAddr, current: &SocketAddr) -> bool {
        match (issued, current) {
            (SocketAddr::V4(issued), SocketAddr::V4(current)) => {
                issued.ip().octets()[..3] == current.ip().octets()[..3]
            }
            _ => false,
        }
    }
}

#[test]
fn a_looser_policy_never_validates_another_ip() {
    let tokens = tokens_with(SameSubnet);
    let token = issuer(&tokens).issue(&peer(), start()).unwrap();
    let other: SocketAddr = "192.0.2.2:4433".parse().unwrap();
    let TokenOutcome::NewToken(valid) = tokens.validate(&token, &other, start()) else {
        panic!("not a valid NEW_TOKEN token");
    };
    assert_eq!(valid.address, NewTokenAddress::LooselyMatched);
}

#[test]
fn tokens_differ_and_are_told_apart_by_their_first_byte() {
    let tokens = tokens();
    let issuer = issuer(&tokens);
    let first = issuer.issue(&peer(), start()).unwrap();
    let second = issuer.issue(&peer(), start()).unwrap();
    assert_ne!(first, second);
    let retry = tokens.issue_retry(&peer(), &odcid(), start()).unwrap();
    assert_ne!(first[0], retry[0]);
    let mut changed = first.to_vec();
    changed[3] ^= 1;
    assert_eq!(
        tokens.validate(&changed, &peer(), start()),
        TokenOutcome::InvalidNewToken
    );
}

#[test]
fn an_unknown_first_byte_is_an_invalid_new_token() {
    let tokens = tokens();
    assert_eq!(
        tokens.validate(&[0; 40], &peer(), start()),
        TokenOutcome::InvalidNewToken
    );
    assert_eq!(
        tokens.validate(&[1], &peer(), start()),
        TokenOutcome::InvalidRetry
    );
}

#[test]
fn an_ipv6_address_round_trips() {
    let tokens = tokens();
    let peer: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    let token = tokens.issue_retry(&peer, &odcid(), start()).unwrap();
    assert!(matches!(
        tokens.validate(&token, &peer, start()),
        TokenOutcome::Retry { .. }
    ));
}

/// A peer address sum of two socket-address transports.
type Two = Coproduct<SocketAddr, Coproduct<SocketAddr, CNil>>;

fn first(text: &str) -> Two {
    Coproduct::Inl(text.parse().unwrap())
}

fn second(text: &str) -> Two {
    Coproduct::Inr(Coproduct::Inl(text.parse().unwrap()))
}

#[test]
fn a_retry_token_for_a_member_of_a_sum_checks_the_whole_peer() {
    let tokens = tokens();
    let token = tokens
        .issue_retry(&second("192.0.2.1:4433"), &odcid(), start())
        .unwrap();
    assert!(matches!(
        tokens.validate(&token, &second("192.0.2.1:4433"), start()),
        TokenOutcome::Retry { .. }
    ));
    // Another port, and another member with the same socket address.
    assert_eq!(
        tokens.validate(&token, &second("192.0.2.1:4434"), start()),
        TokenOutcome::InvalidRetry
    );
    assert_eq!(
        tokens.validate(&token, &first("192.0.2.1:4433"), start()),
        TokenOutcome::InvalidRetry
    );
}

#[test]
fn a_new_token_for_a_member_of_a_sum_validates_only_its_own_network_address() {
    let tokens = tokens();
    let token = issuer(&tokens)
        .issue(&first("192.0.2.1:4433"), start())
        .unwrap();
    let TokenOutcome::NewToken(valid) = tokens.validate(&token, &first("192.0.2.1:5000"), start())
    else {
        panic!("not a valid NEW_TOKEN token");
    };
    assert_eq!(valid.address, NewTokenAddress::Validated);
    for other in [first("192.0.2.2:4433"), second("192.0.2.1:4433")] {
        assert_eq!(
            tokens.validate(&token, &other, start()),
            TokenOutcome::InvalidNewToken
        );
    }
}

/// A peer reached through a relay: it has no network address, and its bytes
/// are never written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Relayed(u64);

impl PeerAddress for Relayed {
    type NetworkAddress = std::convert::Infallible;

    fn network_address(&self) -> Option<Self::NetworkAddress> {
        None
    }
}

impl PeerAddressCodec for Relayed {
    fn write_peer(&self, _: &mut impl BufMut) {}

    fn read_peer<S: Buf + SplitTo>(_: &mut S) -> Result<Self, PeerAddressReadError> {
        Err(PeerAddressReadError::UnknownMember)
    }
}

#[test]
fn a_mixed_endpoint_binds_its_udp_member_and_not_its_relayed_one() {
    type Mixed = Coproduct<SocketAddr, Coproduct<Relayed, CNil>>;
    let tokens = tokens();
    let udp: Mixed = Coproduct::Inl(peer());
    let relayed: Mixed = Coproduct::Inr(Coproduct::Inl(Relayed(7)));
    assert!(AddressTokens::<Mixed>::binds(&tokens, &udp));
    assert!(!AddressTokens::<Mixed>::binds(&tokens, &relayed));
    let token = tokens.issue_retry(&udp, &odcid(), start()).unwrap();
    assert!(matches!(
        tokens.validate(&token, &udp, start()),
        TokenOutcome::Retry { .. }
    ));
    assert_eq!(
        tokens.validate(&token, &relayed, start()),
        TokenOutcome::InvalidRetry
    );
}
