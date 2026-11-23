//! What the reflow driver decides about a datagram that may start a new
//! connection, before any state for the connection exists.
//!
//! A datagram that no connection claims and that may start one arrives at
//! the reflow driver. Before an incoming connection exists for it, the
//! driver does only what needs no state and no waiting
//! ([`StatelessCheck::first_datagram`]):
//!
//! - It drops an Initial in a datagram smaller than 1200 bytes
//!   ([RFC 9000 §14.1]).
//! - It validates the address validation token the Initial carries. A Retry
//!   token that does not validate closes the attempt with INVALID_TOKEN
//!   ([RFC 9000 §8.1.2]); a NEW_TOKEN token is accepted once.
//! - It asks the [`StatelessRetryPolicy`] whether to answer with a stateless
//!   Retry, unless the Initial carries a valid Retry token or no token can be
//!   bound to the peer.
//! - For a datagram whose first packet is 0-RTT, it checks the destination
//!   connection ID length and the bound on incoming connections born from
//!   0-RTT, and never sends a Retry.
//!
//! An Initial that arrives later for an incoming connection born from 0-RTT
//! comes back here too ([`StatelessCheck::late_initial`]), so the token is
//! validated in one place.
//!
//! [RFC 9000 §8.1.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.2
//! [RFC 9000 §14.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-14.1

use std::{fmt, marker::PhantomData, num::NonZeroUsize};

use bytes::Bytes;
use sakuya_datagram_routing_v1::route::recognizer::ConnectionIdGenerator;
use sakuya_link::MIN_DATAGRAM_SIZE;
use sakuya_packet_protection_v1::backend::CryptoBackend;
use sakuya_wire::header::codec::read_long_header;
use sakuya_wire_v1::connection_id::ConnectionId;
use sakuya_wire_v1::header::{TypeFields, codec::read_long_packet};
use time::UtcDateTime;

use crate::{
    address_token::{AddressTokens, NewTokenAddress, TokenOutcome, UsedNewTokens, ValidNewToken},
    invalid_token::encode_invalid_token_close,
    quota::ServerQuotas,
    retry::{
        PresentedToken, StatelessRetryDecision, StatelessRetryInput, StatelessRetryPolicy,
        encode_stateless_retry, generate_stateless_scid,
    },
};

/// The shortest destination connection ID a client chooses for its first
/// Initial and 0-RTT packets in QUIC version 1 ([RFC 9000 §7.2]).
///
/// [RFC 9000 §7.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-7.2
const MIN_CLIENT_DCID_LEN: usize = 8;

/// The stateless steps the reflow driver takes for datagrams that may start
/// a connection.
///
/// It holds the server's token component `T`, its stateless Retry policy
/// `P`, the packet protection backend `B` for Retry and Initial packets, the
/// configuration of the connection ID generator `G` for their source
/// connection IDs, and the record of accepted NEW_TOKEN tokens, which only
/// the reflow driver touches.
pub struct StatelessCheck<T, P, B, G: ConnectionIdGenerator> {
    tokens: T,
    retry_policy: P,
    backend: B,
    generator: G::Config,
    used_new_tokens: UsedNewTokens,
    incoming_capacity: NonZeroUsize,
    zero_rtt_incoming_limit: usize,
    generator_type: PhantomData<fn() -> G>,
}

impl<T, P, B, G> StatelessCheck<T, P, B, G>
where
    B: CryptoBackend,
    G: ConnectionIdGenerator,
{
    /// The steps with the given components, bounded by `quotas`.
    #[must_use]
    pub fn new(
        tokens: T,
        retry_policy: P,
        backend: B,
        generator: G::Config,
        quotas: &ServerQuotas,
    ) -> Self {
        Self {
            tokens,
            retry_policy,
            backend,
            generator,
            used_new_tokens: UsedNewTokens::new(quotas.used_new_tokens_capacity),
            incoming_capacity: quotas.incoming_queue_capacity,
            zero_rtt_incoming_limit: quotas.zero_rtt_incoming_limit,
            generator_type: PhantomData,
        }
    }

    /// The token component, whose NEW_TOKEN issuer each connection takes.
    pub fn tokens(&self) -> &T {
        &self.tokens
    }

    /// What to do with `datagram`, which no connection claims and which may
    /// start one, arriving from `peer` while `load` describes the incoming
    /// connections waiting for the application.
    ///
    /// `peer` is `None` when the token component cannot bind a token to the
    /// link's peer ([`AddressTokens::binds`]): a token cannot be checked
    /// against it, so tokens count as invalid NEW_TOKEN
    /// tokens and no Retry is sent.
    pub fn first_datagram<Peer>(
        &mut self,
        datagram: &[u8],
        peer: Option<&Peer>,
        load: IncomingLoad,
        now: UtcDateTime,
    ) -> FirstDatagramOutcome
    where
        T: AddressTokens<Peer>,
        P: StatelessRetryPolicy<Peer>,
    {
        let (outcome, new_token) = self.first_datagram_unrecorded(datagram, peer, load, now);
        if let Some(new_token) = new_token {
            self.record_new_token(new_token, now);
        }
        outcome
    }

    /// What [`first_datagram`](Self::first_datagram) decides, without
    /// recording the NEW_TOKEN token it accepts for the first time; that
    /// token comes back with the outcome, for
    /// [`record_new_token`](Self::record_new_token) once the datagram is
    /// admitted for good.
    pub(crate) fn first_datagram_unrecorded<Peer>(
        &mut self,
        datagram: &[u8],
        peer: Option<&Peer>,
        load: IncomingLoad,
        now: UtcDateTime,
    ) -> (FirstDatagramOutcome, Option<UnrecordedNewToken>)
    where
        T: AddressTokens<Peer>,
        P: StatelessRetryPolicy<Peer>,
    {
        let mut new_token = None;
        let outcome = self.decide_first_datagram(datagram, peer, load, now, &mut new_token);
        (outcome, new_token)
    }

    /// Records `token` as accepted at `now`, so that it is not accepted
    /// again.
    pub(crate) fn record_new_token(&mut self, token: UnrecordedNewToken, now: UtcDateTime) {
        let recorded = self.used_new_tokens.accept_once(&token.0, now);
        debug_assert!(recorded, "nothing recorded the token since it was checked");
    }

    fn decide_first_datagram<Peer>(
        &mut self,
        datagram: &[u8],
        peer: Option<&Peer>,
        load: IncomingLoad,
        now: UtcDateTime,
        new_token: &mut Option<UnrecordedNewToken>,
    ) -> FirstDatagramOutcome
    where
        T: AddressTokens<Peer>,
        P: StatelessRetryPolicy<Peer>,
    {
        let Some(packet) = FirstPacket::read(datagram) else {
            return FirstDatagramOutcome::Release(ReleaseReason::Unreadable);
        };
        let initial = match packet {
            FirstPacket::ZeroRtt { dcid } => return self.zero_rtt(&dcid, load),
            FirstPacket::Initial(initial) => initial,
        };
        if datagram.len() < MIN_DATAGRAM_SIZE {
            return FirstDatagramOutcome::Release(ReleaseReason::TooSmall);
        }
        let token = match self.unrecorded_returned_token(&initial, peer, now, new_token) {
            Ok(token) => token,
            Err(close) => return FirstDatagramOutcome::SendInvalidTokenClose(close),
        };
        let presented = match token {
            ReturnedToken::Retry { .. } => return FirstDatagramOutcome::Admit(admitted(token)),
            ReturnedToken::Absent => PresentedToken::Absent,
            ReturnedToken::NewToken(address) => PresentedToken::NewToken(address),
            ReturnedToken::InvalidNewToken => PresentedToken::InvalidNewToken,
        };
        let Some(peer) = peer else {
            return FirstDatagramOutcome::Admit(admitted(token));
        };
        let decision = self.retry_policy.decide(&StatelessRetryInput {
            token: presented,
            peer,
            waiting_incoming: load.waiting,
            incoming_capacity: self.incoming_capacity,
        });
        if decision == StatelessRetryDecision::SendRetry
            && let Some(retry) = self.retry(&initial, peer, now)
        {
            return FirstDatagramOutcome::SendRetry(retry);
        }
        FirstDatagramOutcome::Admit(admitted(token))
    }

    /// What to do with `datagram`, a datagram whose first packet is an
    /// Initial, arriving from `peer` for an incoming connection born from
    /// 0-RTT.
    ///
    /// The incoming connection already exists, so no stateless Retry is
    /// sent; the application can still send a Retry from the incoming
    /// connection.
    pub fn late_initial<Peer>(
        &mut self,
        datagram: &[u8],
        peer: Option<&Peer>,
        now: UtcDateTime,
    ) -> LateInitialOutcome
    where
        T: AddressTokens<Peer>,
    {
        let Some(FirstPacket::Initial(initial)) = FirstPacket::read(datagram) else {
            return LateInitialOutcome::Release(ReleaseReason::Unreadable);
        };
        if datagram.len() < MIN_DATAGRAM_SIZE {
            return LateInitialOutcome::Release(ReleaseReason::TooSmall);
        }
        let mut new_token = None;
        let outcome = match self.unrecorded_returned_token(&initial, peer, now, &mut new_token) {
            Ok(token) => LateInitialOutcome::Admit(token),
            Err(close) => LateInitialOutcome::SendInvalidTokenClose(close),
        };
        if let Some(new_token) = new_token {
            self.record_new_token(new_token, now);
        }
        outcome
    }

    fn zero_rtt(&self, dcid: &ConnectionId, load: IncomingLoad) -> FirstDatagramOutcome {
        // A 0-RTT packet of the first flight carries the destination
        // connection ID of the client's first Initial ([RFC 9000 §7.2]).
        if dcid.as_bytes().len() < MIN_CLIENT_DCID_LEN {
            return FirstDatagramOutcome::Release(ReleaseReason::ZeroRttDcidTooShort);
        }
        if load.waiting_born_from_zero_rtt >= self.zero_rtt_incoming_limit {
            return FirstDatagramOutcome::Release(ReleaseReason::ZeroRttIncomingLimitReached);
        }
        FirstDatagramOutcome::Admit(AdmittedDatagram {
            born_from_zero_rtt: true,
            token: ReturnedToken::Absent,
        })
    }

    /// The token the Initial returned, or the INVALID_TOKEN close to send
    /// when it is a Retry token that does not validate. A NEW_TOKEN token
    /// not accepted before is left in `new_token`, not yet recorded.
    fn unrecorded_returned_token<Peer>(
        &mut self,
        initial: &FirstInitial,
        peer: Option<&Peer>,
        now: UtcDateTime,
        new_token: &mut Option<UnrecordedNewToken>,
    ) -> Result<ReturnedToken, Bytes>
    where
        T: AddressTokens<Peer>,
    {
        if initial.token.is_empty() {
            return Ok(ReturnedToken::Absent);
        }
        let Some(peer) = peer else {
            return Ok(ReturnedToken::InvalidNewToken);
        };
        match self.tokens.validate(&initial.token, peer, now) {
            TokenOutcome::Retry { original_dcid } => Ok(ReturnedToken::Retry {
                original_dcid,
                retry_scid: initial.dcid,
            }),
            TokenOutcome::NewToken(valid) => {
                if self.used_new_tokens.was_accepted(&valid, now) {
                    return Ok(ReturnedToken::InvalidNewToken);
                }
                let address = valid.address;
                *new_token = Some(UnrecordedNewToken(valid));
                Ok(ReturnedToken::NewToken(address))
            }
            TokenOutcome::InvalidNewToken => Ok(ReturnedToken::InvalidNewToken),
            TokenOutcome::InvalidRetry => {
                let scid = generate_stateless_scid::<G>(&self.generator);
                Err(encode_invalid_token_close(
                    &self.backend,
                    &initial.dcid,
                    &initial.scid,
                    &scid,
                ))
            }
        }
    }

    /// The stateless Retry for `initial`, or `None` when none can be made:
    /// the random source failed, or the generated source connection ID
    /// equals the Initial's destination connection ID.
    fn retry<Peer>(&self, initial: &FirstInitial, peer: &Peer, now: UtcDateTime) -> Option<Bytes>
    where
        T: AddressTokens<Peer>,
    {
        let token = self.tokens.issue_retry(peer, &initial.dcid, now).ok()?;
        let scid = generate_stateless_scid::<G>(&self.generator);
        encode_stateless_retry(&self.backend, &initial.dcid, &initial.scid, &scid, &token).ok()
    }
}

impl<T, P, B, G: ConnectionIdGenerator> fmt::Debug for StatelessCheck<T, P, B, G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StatelessCheck")
            .field("used_new_tokens", &self.used_new_tokens.len())
            .field("incoming_capacity", &self.incoming_capacity)
            .field("zero_rtt_incoming_limit", &self.zero_rtt_incoming_limit)
            .finish_non_exhaustive()
    }
}

/// A NEW_TOKEN token accepted for the first time and not yet recorded.
#[derive(Debug)]
pub(crate) struct UnrecordedNewToken(ValidNewToken);

fn admitted(token: ReturnedToken) -> AdmittedDatagram {
    AdmittedDatagram {
        born_from_zero_rtt: false,
        token,
    }
}

/// The incoming connections waiting for the application when a datagram
/// arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IncomingLoad {
    /// How many incoming connections wait for the application.
    pub waiting: usize,
    /// How many of those were born from a datagram whose first packet is
    /// 0-RTT.
    pub waiting_born_from_zero_rtt: usize,
}

/// What to do with the first datagram of a possible new connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FirstDatagramOutcome {
    /// Make an incoming connection from the datagram.
    Admit(AdmittedDatagram),
    /// Send this stateless Retry packet and keep nothing.
    SendRetry(Bytes),
    /// Send this Initial packet, which closes the attempt with
    /// INVALID_TOKEN, and keep nothing.
    SendInvalidTokenClose(Bytes),
    /// Release the datagram.
    Release(ReleaseReason),
}

/// What an incoming connection learns from the datagram it is made from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedDatagram {
    /// Whether the first packet of the datagram is 0-RTT rather than
    /// Initial.
    pub born_from_zero_rtt: bool,
    /// The token the Initial returned.
    pub token: ReturnedToken,
}

/// What to do with an Initial that arrived late for an incoming connection
/// born from 0-RTT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LateInitialOutcome {
    /// Give the datagram to the incoming connection, with the token the
    /// Initial returned.
    Admit(ReturnedToken),
    /// Send this Initial packet, which closes the attempt with
    /// INVALID_TOKEN.
    SendInvalidTokenClose(Bytes),
    /// Release the datagram.
    Release(ReleaseReason),
}

/// The token a client returned in its Initial, as the endpoint found it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReturnedToken {
    /// The Initial carries no token.
    Absent,
    /// A valid Retry token: the client's address is validated. The server
    /// states both connection IDs in its transport parameters
    /// ([RFC 9000 §7.3]).
    ///
    /// [RFC 9000 §7.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-7.3
    Retry {
        /// The destination connection ID of the Initial the Retry answered,
        /// for `original_destination_connection_id`.
        original_dcid: ConnectionId,
        /// The destination connection ID of this Initial, which the Retry
        /// gave as its source connection ID, for
        /// `retry_source_connection_id`.
        retry_scid: ConnectionId,
    },
    /// A NEW_TOKEN token accepted for the first time.
    NewToken(NewTokenAddress),
    /// A token that is not a valid Retry token, nor a valid NEW_TOKEN token
    /// accepted for the first time, and that the endpoint treats as absent
    /// ([RFC 9000 §8.1.3]).
    ///
    /// [RFC 9000 §8.1.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.3
    InvalidNewToken,
}

/// Why a datagram is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReleaseReason {
    /// The first packet is not a readable version 1 Initial or 0-RTT
    /// packet.
    Unreadable,
    /// The datagram carries an Initial and is smaller than 1200 bytes
    /// ([RFC 9000 §14.1]).
    ///
    /// [RFC 9000 §14.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-14.1
    TooSmall,
    /// The first packet is 0-RTT with a destination connection ID shorter
    /// than a client's first one can be ([RFC 9000 §7.2]).
    ///
    /// [RFC 9000 §7.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-7.2
    ZeroRttDcidTooShort,
    /// The first packet is 0-RTT and as many incoming connections born from
    /// 0-RTT wait as [`ServerQuotas::zero_rtt_incoming_limit`] allows. The
    /// endpoint counts this drop.
    ZeroRttIncomingLimitReached,
}

/// The first packet of a datagram, as far as the stateless steps read it.
enum FirstPacket {
    Initial(FirstInitial),
    ZeroRtt { dcid: ConnectionId },
}

struct FirstInitial {
    dcid: ConnectionId,
    scid: ConnectionId,
    token: Bytes,
}

impl FirstPacket {
    fn read(datagram: &[u8]) -> Option<Self> {
        let mut input = datagram;
        let header = read_long_header(&mut input).ok()?;
        let packet = read_long_packet(&mut input, header).ok()?;
        let (dcid, scid) = (*packet.dcid(), *packet.scid());
        match packet.into_fields() {
            TypeFields::Initial { token, .. } => Some(Self::Initial(FirstInitial {
                dcid,
                scid,
                token: Bytes::copy_from_slice(token),
            })),
            TypeFields::ZeroRtt { .. } => Some(Self::ZeroRtt { dcid }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
