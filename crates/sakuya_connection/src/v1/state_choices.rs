//! What the state of a connection of version 1 reads of a composition's
//! choices: the keys, recovery, the connection IDs and the paths.
//!
//! The maker fixes some of it ([`StateMakerChoices`]), the host picks the
//! rest ([`StateHostChoices`]), and the side differs in some
//! ([`StateSide`]); [`StateChoices`] has all three, with the slots of
//! [`V1Choices`].

use core::fmt::Debug;
use std::sync::Arc;

use kasen_handshake::schedule::TrafficSecret;
use sakuya_packet_protection_v1::{backend::CryptoBackend, initial::InitialSecrets};
use sakuya_recovery_v1::{
    ack_obligation::AckObligation, factory::RecoveryFactory, send_journals::SendJournals,
};

use super::{
    amplification::AddressValidation,
    common_choices::{Client, Server, V1Choices},
    component_events,
    connection_ids::{LocalConnectionIdRegistrationOf, PeerOf, ResetTokenRegistrarOf},
    crypto::{self, CryptoReceiveBuffer, send::CryptoSendBuffer},
    keys::{DirectionKeys, ZeroRttReceiveKeys, ZeroRttReceiving, ZeroRttSending},
    migration,
    new_token::{NewTokenIntent, NewTokenSource, NewTokenSummary, NoNewTokens},
    send,
    stateless_reset::StatelessResetSignal,
};
use crate::{
    clock::{ConnectionChoices, InstantOf, LinkIdOf},
    component_event::Happened,
    connection_id::{
        DestinationConnectionIdStrategy,
        local::{LocalConnectionIdStrategy, NewConnectionIdSummary},
        reset_token::ResetTokenRegistry,
    },
    frame_source::FrameSource,
};

/// What the maker of a connection of version 1 fixes of the connection's
/// state: the endpoint, or a test.
pub trait StateMakerChoices: ConnectionChoices {
    /// The cryptographic backend that derives the packet protection keys;
    /// the connection keeps a clone for the levels after Initial.
    type Crypto: CryptoBackend + Clone + 'static;
    /// What the connection holds to register the reset tokens of the
    /// peer's connection IDs for detection: it makes the registrar of each
    /// link path, for its link's peer and its logical path's
    /// [`StatelessResetSignal`].
    type ResetTokenRegistry: ResetTokenRegistry<PeerOf<Self>, Arc<StatelessResetSignal>, Registrar: 'static>
        + Clone
        + 'static;
    /// What issues this side's connection IDs after the first, one for each
    /// connection: it generates each with its stateless reset token and
    /// registers it with routing before it is disclosed.
    type ConnectionIdIssuer: crate::connection_id::local::ConnectionIdIssuer<Registration: 'static>
        + 'static;
}

/// What the state of a connection of version 1 reads of the choices: what
/// its maker fixes, the host's choices for it ([`StateHostChoices`]) and
/// the side's ([`StateSide`]).
///
/// The host's choices take only [`StateMakerChoices`]: were they to take
/// `StateChoices`, a maker's type would be choices once the host's type is
/// its host's choices, and the host's type that once the maker's type is
/// choices.
pub trait StateChoices:
    StateMakerChoices + V1Choices<Host: StateHostChoices<Self>, Side: StateSide>
{
}

impl<T> StateChoices for T
where
    T: StateMakerChoices + V1Choices<Side: StateSide>,
    T::Host: StateHostChoices<T>,
{
}

/// What the host picks for the state of the connections of version 1 that
/// the maker `T` makes. What has one implementation in sakuya has it as its
/// default.
pub trait StateHostChoices<T: StateMakerChoices + ?Sized>: 'static {
    /// What stores the CRYPTO data of one encryption level until the
    /// handshake engine reads it.
    // defaults: 5b
    type CryptoReceiveBuffer: CryptoReceiveBuffer + Default + 'static =
        crypto::FragmentedCryptoReceiveBuffer;
    /// What keeps the CRYPTO data of one encryption level that this side
    /// sends, until the peer acknowledges it.
    // defaults: 5b
    type CryptoSendBuffer: CryptoSendBuffer + Default + Unpin + 'static =
        crypto::send::OffsetMapCryptoSendBuffer;
    /// What makes the RTT estimate, the stored part of congestion control
    /// and the datagram size probing policy of each link path, one for each
    /// connection. `V` identifies a link path, as found from the list of
    /// parts: the logical link when the connection supports version 1
    /// alone. The default's congestion controller is CUBIC; a host that
    /// wants NewReno picks
    /// [`NewRenoRecoveryFactory`](sakuya_recovery_v1::factory::NewRenoRecoveryFactory).
    // defaults: 5b
    type Recovery<V: Clone + Eq + Debug + 'static>: RecoveryFactory<T::Link, Via = V> + 'static =
        sakuya_recovery_v1::factory::CubicRecoveryFactory<V>;
    /// What decides when an ACK frame is due, one for each packet number
    /// space of a logical path.
    // defaults: 5b
    type AckObligation: AckObligation<InstantOf<T>> + 'static =
        sakuya_recovery_v1::ack_obligation::Rfc9000AckObligation<InstantOf<T>>;
    /// What records the packets sent in one packet number space of a
    /// logical path, one for each space; it starts empty. `S` is the
    /// summary of a frame, as found from the list of parts, and `P`
    /// identifies a link path, as the recovery factory's `V`.
    // defaults: 5b
    type SendJournals<S: 'static, P: Clone + Eq + Debug + 'static>: SendJournals<S, InstantOf<T>, P>
        + Default
        + 'static = sakuya_recovery_v1::send_journals::DequeSendJournals<InstantOf<T>, S, P>;
    /// What decides which of the peer's connection IDs this side sends
    /// with, one for each logical path; it registers reset tokens through
    /// the registrars of the maker's
    /// [`ResetTokenRegistry`](StateMakerChoices::ResetTokenRegistry), and
    /// writes the RETIRE_CONNECTION_ID frames that retire the peer's
    /// connection IDs.
    // defaults: 5b
    type DestinationConnectionIds: DestinationConnectionIdStrategy<LinkIdOf<T>, InstantOf<T>, ResetTokenRegistrarOf<T>>
        + for<'a> FrameSource<Item<'a> = u64, Summary = send::RetireConnectionIdSummary>
        + 'static = crate::connection_id::sequence_map::SequenceMapDestinationConnectionIdStrategy<
        LinkIdOf<T>,
        ResetTokenRegistrarOf<T>,
    >;
    /// What decides how many of this side's connection IDs the peer holds
    /// and when they are issued and dropped, one for each logical path; it
    /// issues them with the maker's
    /// [`ConnectionIdIssuer`](StateMakerChoices::ConnectionIdIssuer), keeps
    /// their registrations, and writes the NEW_CONNECTION_ID frames that
    /// disclose them.
    // defaults: 5b
    type LocalConnectionIds: LocalConnectionIdStrategy<LinkIdOf<T>, InstantOf<T>, LocalConnectionIdRegistrationOf<T>>
        + for<'a> FrameSource<Item<'a> = u64, Summary = NewConnectionIdSummary>
        + 'static = crate::connection_id::local::SequenceMapLocalConnectionIdStrategy<
        LocalConnectionIdRegistrationOf<T>,
        InstantOf<T>,
    >;
    /// What decides the choices of connection migration that RFC 9000
    /// leaves to the endpoint, one for each logical path: which packets from
    /// a new logical link build a link path, when the active link path
    /// switches and with which recovery layer, the timing of path
    /// validation and how long a link path settles
    /// ([`MigrationPolicy`](migration::MigrationPolicy), asked where version
    /// 1 uses it). The default needs the peer's ends to state their network
    /// address ([`PeerAddress`](sakuya_link::PeerAddress)).
    // defaults: 5b
    type MigrationPolicy: Default + 'static = migration::Rfc9000MigrationPolicy;
}

/// The host's choices of the choices `T`, as the state reads them.
type StateHostOf<T> = <T as V1Choices>::Host;
/// The CRYPTO receive buffer of the choices `T`.
pub type CryptoReceiveBufferOf<T> = <StateHostOf<T> as StateHostChoices<T>>::CryptoReceiveBuffer;
/// The CRYPTO send buffer of the choices `T`.
pub type CryptoSendBufferOf<T> = <StateHostOf<T> as StateHostChoices<T>>::CryptoSendBuffer;
/// The ACK obligation of the choices `T`.
pub type AckObligationOf<T> = <StateHostOf<T> as StateHostChoices<T>>::AckObligation;
/// The destination connection ID strategy of the choices `T`.
pub type DestinationConnectionIdsOf<T> =
    <StateHostOf<T> as StateHostChoices<T>>::DestinationConnectionIds;
/// The local connection ID strategy of the choices `T`.
pub type LocalConnectionIdsOf<T> = <StateHostOf<T> as StateHostChoices<T>>::LocalConnectionIds;
/// The migration policy of the choices `T`.
pub type MigrationPolicyOf<T> = <StateHostOf<T> as StateHostChoices<T>>::MigrationPolicy;

/// The 0-RTT keys of the side of the choices `T`
/// ([`StateSide::OwnZeroRttKeys`]).
pub(crate) type OwnZeroRttKeysOf<T> = <<T as V1Choices>::Side as StateSide>::OwnZeroRttKeys<
    <T as StateMakerChoices>::Crypto,
    InstantOf<T>,
>;

/// What differs between the two sides in the state of a connection: the
/// 0-RTT keys, the NEW_TOKEN frames and the validation of addresses.
pub trait StateSide: 'static {
    /// The data component in the connection node where the NEW_TOKEN
    /// frames of version 1 are found ([`new_token`](super::new_token)): a
    /// server's issues and sends them ([`NewTokenSource`]); a client's
    /// never has one waiting and writes nothing ([`NoNewTokens`]), as a
    /// client must not send the frame (RFC 9000 §19.7).
    type NewTokens: for<'a> FrameSource<Item<'a> = (), Summary = NewTokenSummary> + 'static;

    /// The 0-RTT keys only this side has, a data component of the
    /// connection node: a server's to read 0-RTT packets
    /// ([`ZeroRttReceiving`]), a client's to send them ([`ZeroRttSending`]).
    type OwnZeroRttKeys<B: CryptoBackend + 'static, I: Copy + Ord + 'static>: 'static;

    /// The keys to read a 0-RTT packet with, as `keys` keeps them.
    ///
    /// A server's are not decided before its ServerHello is written, then
    /// are there while it reads 0-RTT. A client never has any: it drops
    /// every 0-RTT packet (RFC 9001 §5.6).
    fn zero_rtt_receive_keys<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        keys: &Self::OwnZeroRttKeys<B, I>,
    ) -> ZeroRttReceiveKeys<'_, B>;

    /// The keys to send a 0-RTT packet with, as `keys` keeps them.
    ///
    /// A server never has any: only a client sends 0-RTT (RFC 9001 §4.6.1).
    fn zero_rtt_send_keys<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        keys: &Self::OwnZeroRttKeys<B, I>,
    ) -> Option<&DirectionKeys<B>>;

    /// Whether `keys` start to retire with the next 1-RTT packet this side
    /// processes: a server's while it reads 0-RTT and they do not retire
    /// yet (RFC 9001 §4.9.3); never a client's.
    fn zero_rtt_awaits_retirement<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        keys: &Self::OwnZeroRttKeys<B, I>,
    ) -> bool;

    /// A 1-RTT packet was processed: a server's open `keys` retire, to be
    /// dropped a while later (RFC 9001 §4.9.3); a client's stay as they
    /// are. What happened, when the keys started to retire.
    #[must_use = "what happened is to be published in the lend"]
    fn retire_zero_rtt<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        keys: &mut Self::OwnZeroRttKeys<B, I>,
    ) -> Option<Happened<component_events::KeysRetiring<component_events::level::ZeroRtt>>>;

    /// The intent of the NEW_TOKEN frames that wait to be sent now, as
    /// `tokens` keeps them: a server's from the issue of a token until it is
    /// written, and again while a frame of it is lost and none is
    /// acknowledged; never a client's.
    fn new_token_waiting(tokens: &Self::NewTokens) -> Option<NewTokenIntent>;

    /// The Initial secrets split into this side's sending and receiving
    /// secret, in that order (RFC 9001 §5.2).
    fn split_initial_secrets(secrets: InitialSecrets) -> (TrafficSecret, TrafficSecret);

    /// Whether the address of a logical link that comes after the first is
    /// validated when its entry is made.
    ///
    /// A server's is not: it is an address the peer moved to (RFC 9000 §8,
    /// §9.3). A client's is: the limit applies only to answering packets
    /// from an address not yet validated, not to a client starting a
    /// connection or a migration (§21.1.1.1).
    fn later_link_validation() -> AddressValidation;

    /// Whether this side takes its address as validated by the peer from
    /// the start (RFC 9002 Appendix A.8).
    ///
    /// A server does: a client validates the server's address implicitly. A
    /// client does not until the server acknowledges one of its Handshake
    /// packets or the handshake is confirmed; until then it keeps a probe
    /// timeout even with nothing in flight (§6.2.2.1), so that a lost
    /// server flight cannot leave both sides waiting.
    fn peer_validates_address_implicitly() -> bool;
}

impl<Tls: 'static, Ti: 'static> StateSide for Server<Tls, Ti> {
    type NewTokens = NewTokenSource<Ti>;
    type OwnZeroRttKeys<B: CryptoBackend + 'static, I: Copy + Ord + 'static> =
        ZeroRttReceiving<B, I>;
    fn zero_rtt_receive_keys<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        keys: &ZeroRttReceiving<B, I>,
    ) -> ZeroRttReceiveKeys<'_, B> {
        keys.receive_keys()
    }
    fn zero_rtt_send_keys<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        _: &ZeroRttReceiving<B, I>,
    ) -> Option<&DirectionKeys<B>> {
        None
    }
    fn zero_rtt_awaits_retirement<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        keys: &ZeroRttReceiving<B, I>,
    ) -> bool {
        matches!(keys, ZeroRttReceiving::Open(_))
    }
    fn retire_zero_rtt<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        keys: &mut ZeroRttReceiving<B, I>,
    ) -> Option<Happened<component_events::KeysRetiring<component_events::level::ZeroRtt>>> {
        keys.retire()
    }
    fn new_token_waiting(tokens: &NewTokenSource<Ti>) -> Option<NewTokenIntent> {
        tokens.intent()
    }
    fn split_initial_secrets(secrets: InitialSecrets) -> (TrafficSecret, TrafficSecret) {
        (secrets.server, secrets.client)
    }
    fn later_link_validation() -> AddressValidation {
        AddressValidation::NotValidated
    }
    fn peer_validates_address_implicitly() -> bool {
        true
    }
}

impl<Tls: 'static, Tk: 'static, Rp: 'static, Lc: 'static> StateSide for Client<Tls, Tk, Rp, Lc> {
    type NewTokens = NoNewTokens;
    type OwnZeroRttKeys<B: CryptoBackend + 'static, I: Copy + Ord + 'static> = ZeroRttSending<B>;
    fn zero_rtt_receive_keys<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        _: &ZeroRttSending<B>,
    ) -> ZeroRttReceiveKeys<'_, B> {
        ZeroRttReceiveKeys::Gone
    }
    fn zero_rtt_send_keys<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        keys: &ZeroRttSending<B>,
    ) -> Option<&DirectionKeys<B>> {
        keys.send()
    }
    fn zero_rtt_awaits_retirement<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        _: &ZeroRttSending<B>,
    ) -> bool {
        false
    }
    fn retire_zero_rtt<B: CryptoBackend + 'static, I: Copy + Ord + 'static>(
        _: &mut ZeroRttSending<B>,
    ) -> Option<Happened<component_events::KeysRetiring<component_events::level::ZeroRtt>>> {
        None
    }
    fn new_token_waiting(_: &NoNewTokens) -> Option<NewTokenIntent> {
        None
    }
    fn split_initial_secrets(secrets: InitialSecrets) -> (TrafficSecret, TrafficSecret) {
        (secrets.client, secrets.server)
    }
    fn later_link_validation() -> AddressValidation {
        AddressValidation::Validated
    }
    fn peer_validates_address_implicitly() -> bool {
        false
    }
}
