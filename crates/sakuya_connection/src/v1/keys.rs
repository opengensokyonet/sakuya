//! The packet protection keys of each encryption level.
//!
//! Each level is one component with a state of its own: a level comes,
//! loses its sending half when the connection closes, and is discarded, by
//! the rules RFC 9001 §4.9 gives for that level alone. Which levels exist at
//! a moment is the states of these components; there is no phase value.
//! The states do not exclude every combination that the rules never reach,
//! such as Initial discarded while Handshake has not come: the conditions of
//! the transitions do (Initial is discarded when a Handshake packet is
//! processed or sent, and its keys are there by then).
//!
//! The 1-RTT level moves through generations with the key updates (RFC 9001
//! §6): [`KeyGeneration`] is one generation of one direction. The counts
//! that change with every packet are not here but in
//! [`AeadUsage`](super::aead_usage::AeadUsage) and
//! [`KeyPhaseNumbers`](super::key_phase::KeyPhaseNumbers): whoever reads
//! the keys is looked at again only when they change.

use core::fmt;

use sakuya_packet_protection::{
    backend::{AeadAlgorithm, CryptoBackend},
    header_protection::HeaderProtectionKey,
    packet_key::PacketKey,
    secret::TrafficSecret,
};
use sakuya_wire::v1::header::KeyPhase;

/// The backend the packet protection keys of the levels after Initial are
/// derived with, kept in the connection node: a clone of the one the
/// connection was made with.
#[derive(Debug, Clone)]
pub struct PacketProtectionBackend<B>(pub B);

/// The keys that protect the packets of one direction at one encryption
/// level: the packet key and the header protection key, derived from one
/// traffic secret, and the AEAD they are for.
pub struct DirectionKeys<B: CryptoBackend> {
    /// Encrypts or decrypts the payload.
    pub packet: PacketKey<B>,
    /// Applies or removes header protection.
    pub header: HeaderProtectionKey<B>,
    aead: AeadAlgorithm,
}

impl<B: CryptoBackend> DirectionKeys<B> {
    /// Derives both keys from `secret` (RFC 9001 §5.1), for the AEAD of the
    /// cipher suite that produced it.
    pub fn derive(backend: &B, aead: AeadAlgorithm, secret: &TrafficSecret) -> Self {
        Self {
            packet: PacketKey::derive(backend, aead, secret),
            header: HeaderProtectionKey::derive(backend, aead, secret),
            aead,
        }
    }

    /// The AEAD the keys are for, whose limits their use counts toward
    /// (RFC 9001 §6.6).
    pub fn aead(&self) -> AeadAlgorithm {
        self.aead
    }
}

impl<B: CryptoBackend> fmt::Debug for DirectionKeys<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectionKeys").finish_non_exhaustive()
    }
}

/// The keys of both directions at one encryption level.
pub struct LevelKeys<B: CryptoBackend> {
    /// Protects the packets this side sends.
    pub send: DirectionKeys<B>,
    /// Removes the protection of the packets this side receives.
    pub receive: DirectionKeys<B>,
}

impl<B: CryptoBackend> fmt::Debug for LevelKeys<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LevelKeys").finish_non_exhaustive()
    }
}

macro_rules! state_debug {
    ($ty:ident<$($p:ident),*> { $($variant:ident $(($($field:tt),*))?),* $(,)? }) => {
        impl<$($p),*> fmt::Debug for $ty<$($p),*>
        where
            B: CryptoBackend,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(match self {
                    $(Self::$variant $(($($field),*))? => stringify!($variant),)*
                })
            }
        }
    };
}

/// The keys of the Initial level.
///
/// They exist from the start: they are derived from the version and the
/// Destination Connection ID of the client's first Initial packet.
pub enum InitialKeys<B: CryptoBackend> {
    /// Both directions.
    Live(LevelKeys<B>),
    /// The connection is closing: only packets from the peer are read, to
    /// see whether it closes too.
    ReceiveOnly(DirectionKeys<B>),
    /// Gone: a server has processed a Handshake packet, a client has sent
    /// one (RFC 9001 §4.9.1), or the connection is draining.
    Discarded,
}
state_debug!(InitialKeys<B> { Live(_), ReceiveOnly(_), Discarded });

impl<B: CryptoBackend> InitialKeys<B> {
    /// The keys to send with, while there are any.
    pub fn send(&self) -> Option<&DirectionKeys<B>> {
        match self {
            Self::Live(keys) => Some(&keys.send),
            Self::ReceiveOnly(_) | Self::Discarded => None,
        }
    }

    /// The keys to receive with, while there are any.
    pub fn receive(&self) -> Option<&DirectionKeys<B>> {
        match self {
            Self::Live(keys) => Some(&keys.receive),
            Self::ReceiveOnly(keys) => Some(keys),
            Self::Discarded => None,
        }
    }

    /// Replace both directions, as a client does with keys derived from
    /// the Source Connection ID of a Retry (RFC 9000 §17.2.5.2).
    ///
    /// The level must still be live.
    pub fn replace(&mut self, keys: LevelKeys<B>) {
        debug_assert!(
            matches!(self, Self::Live(_)),
            "replacing Initial keys that are {self:?}"
        );
        *self = Self::Live(keys);
    }

    /// Drop the sending half; keys that are already gone stay gone.
    pub fn keep_receive_only(&mut self) {
        if let Self::Live(_) = self {
            let Self::Live(keys) = core::mem::replace(self, Self::Discarded) else {
                unreachable!()
            };
            *self = Self::ReceiveOnly(keys.receive);
        }
    }

    /// Discard the level.
    pub fn discard(&mut self) {
        *self = Self::Discarded;
    }
}

/// The keys of the Handshake level.
pub enum HandshakeKeys<B: CryptoBackend> {
    /// The handshake has not produced them yet.
    NotYet,
    /// Both directions.
    Live(LevelKeys<B>),
    /// The connection is closing: only packets from the peer are read.
    ReceiveOnly(DirectionKeys<B>),
    /// Gone: the handshake is confirmed (RFC 9001 §4.9.2), or the
    /// connection is draining or closed before they came.
    Discarded,
}
state_debug!(HandshakeKeys<B> { NotYet, Live(_), ReceiveOnly(_), Discarded });

impl<B: CryptoBackend> HandshakeKeys<B> {
    /// The keys to send with, while there are any.
    pub fn send(&self) -> Option<&DirectionKeys<B>> {
        match self {
            Self::Live(keys) => Some(&keys.send),
            Self::NotYet | Self::ReceiveOnly(_) | Self::Discarded => None,
        }
    }

    /// The keys to receive with, while there are any.
    pub fn receive(&self) -> Option<&DirectionKeys<B>> {
        match self {
            Self::Live(keys) => Some(&keys.receive),
            Self::ReceiveOnly(keys) => Some(keys),
            Self::NotYet | Self::Discarded => None,
        }
    }

    /// Install both directions, as the handshake produced them.
    ///
    /// They must not have come before.
    pub fn install(&mut self, keys: LevelKeys<B>) {
        debug_assert!(
            matches!(self, Self::NotYet),
            "installing Handshake keys that are {self:?}"
        );
        *self = Self::Live(keys);
    }

    /// Drop the sending half; keys that have not come are discarded, and
    /// keys that are already gone stay gone.
    pub fn keep_receive_only(&mut self) {
        match core::mem::replace(self, Self::Discarded) {
            Self::Live(keys) => *self = Self::ReceiveOnly(keys.receive),
            Self::ReceiveOnly(keys) => *self = Self::ReceiveOnly(keys),
            Self::NotYet | Self::Discarded => {}
        }
    }

    /// Discard the level.
    pub fn discard(&mut self) {
        *self = Self::Discarded;
    }
}

/// One generation of the 1-RTT packet keys of one direction: the traffic
/// secret of the generation, the AEAD of the cipher suite and the packet key
/// derived from them.
///
/// Generation 0 is derived from the secret the handshake produced; each
/// key update derives the next one from the secret with the "quic ku" label
/// (RFC 9001 §6.1). The header protection key is not part of a generation:
/// a key update does not change it.
pub struct KeyGeneration<B: CryptoBackend> {
    generation: u64,
    aead: AeadAlgorithm,
    secret: TrafficSecret,
    packet: PacketKey<B>,
}

impl<B: CryptoBackend> KeyGeneration<B> {
    /// Generation 0, from `secret`, which the handshake produced with the
    /// cipher suite of `aead`.
    pub fn first(backend: &B, aead: AeadAlgorithm, secret: TrafficSecret) -> Self {
        Self {
            generation: 0,
            aead,
            packet: PacketKey::derive(backend, aead, &secret),
            secret,
        }
    }

    /// The generation after this one: its secret is derived from this one's
    /// with the "quic ku" label, and its packet key from that secret.
    pub fn next(&self, backend: &B) -> Self {
        let secret = self.secret.next(backend);
        Self {
            // invariant: each generation is derived from one a packet was
            // protected with, give or take one, and packet numbers end at
            // 2^62
            generation: self.generation + 1,
            aead: self.aead,
            packet: PacketKey::derive(backend, self.aead, &secret),
            secret,
        }
    }

    /// How many key updates lie between generation 0 and this one.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The Key Phase of the packets protected with this generation: 0 for
    /// an even generation, 1 for an odd one (RFC 9001 §6).
    pub fn key_phase(&self) -> KeyPhase {
        if self.generation % 2 == 0 {
            KeyPhase::Zero
        } else {
            KeyPhase::One
        }
    }

    /// The AEAD the keys are for.
    pub fn aead(&self) -> AeadAlgorithm {
        self.aead
    }

    /// The packet key of the generation.
    pub fn packet(&self) -> &PacketKey<B> {
        &self.packet
    }

    /// The packet key alone; the secret is dropped, and with it the means
    /// to derive later generations.
    fn into_packet(self) -> PacketKey<B> {
        self.packet
    }
}

impl<B: CryptoBackend> fmt::Debug for KeyGeneration<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyGeneration")
            .field("generation", &self.generation)
            .field("aead", &self.aead)
            .finish_non_exhaustive()
    }
}

/// The keys this side protects its 1-RTT packets with: the current
/// generation of the sending direction and the header protection key.
pub struct OneRttSendKeys<B: CryptoBackend> {
    generation: KeyGeneration<B>,
    header: HeaderProtectionKey<B>,
}

impl<B: CryptoBackend> OneRttSendKeys<B> {
    /// Generation 0 and the header protection key, from the sending
    /// `secret` the handshake produced with the cipher suite of `aead`.
    fn derive(backend: &B, aead: AeadAlgorithm, secret: TrafficSecret) -> Self {
        Self {
            header: HeaderProtectionKey::derive(backend, aead, &secret),
            generation: KeyGeneration::first(backend, aead, secret),
        }
    }

    /// The generation packets are sealed with.
    pub fn generation(&self) -> &KeyGeneration<B> {
        &self.generation
    }

    /// The packet key of the generation packets are sealed with.
    pub fn packet(&self) -> &PacketKey<B> {
        self.generation.packet()
    }

    /// The header protection key.
    pub fn header(&self) -> &HeaderProtectionKey<B> {
        &self.header
    }

    /// The Key Phase the packets carry.
    pub fn key_phase(&self) -> KeyPhase {
        self.generation.key_phase()
    }

    /// Seal with the next generation from now on.
    fn update(&mut self, backend: &B) {
        self.generation = self.generation.next(backend);
    }
}

impl<B: CryptoBackend> fmt::Debug for OneRttSendKeys<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OneRttSendKeys")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

/// The keys this side removes the protection of 1-RTT packets with: the
/// current generation of the receiving direction, the next one, the
/// previous one for a while after a key update, and the header protection
/// key.
///
/// A packet whose Key Phase is that of the current generation is opened
/// with it. One with the other Key Phase is opened with the previous
/// generation when its packet number is lower than every one received with
/// the current generation, and with the next generation otherwise (RFC 9001
/// §6.5). The next generation is derived as soon as the one before it
/// becomes current, so that it is ready before the peer uses it (§6.3,
/// §9.5).
///
/// `I` is the instant of the connection's clock.
pub struct OneRttReceiveKeys<B: CryptoBackend, I> {
    /// The previous generation's packet key and the instant it is dropped,
    /// which is set after it became previous (RFC 9001 §6.5).
    previous: Option<(PacketKey<B>, Option<I>)>,
    current: KeyGeneration<B>,
    next: KeyGeneration<B>,
    header: HeaderProtectionKey<B>,
}

impl<B: CryptoBackend, I: Copy> OneRttReceiveKeys<B, I> {
    /// Generation 0, generation 1 and the header protection key, from the
    /// receiving `secret` the handshake produced with the cipher suite of
    /// `aead`.
    fn derive(backend: &B, aead: AeadAlgorithm, secret: TrafficSecret) -> Self {
        let header = HeaderProtectionKey::derive(backend, aead, &secret);
        let current = KeyGeneration::first(backend, aead, secret);
        Self {
            previous: None,
            next: current.next(backend),
            current,
            header,
        }
    }

    /// The generation the peer protects its packets with, as far as this
    /// side has seen.
    pub fn current(&self) -> &KeyGeneration<B> {
        &self.current
    }

    /// The generation after the current one, which the peer's next key
    /// update moves to.
    pub fn next(&self) -> &KeyGeneration<B> {
        &self.next
    }

    /// The packet key of the generation before the current one, while it is
    /// kept.
    pub fn previous(&self) -> Option<&PacketKey<B>> {
        self.previous.as_ref().map(|(packet, _)| packet)
    }

    /// The instant the previous generation is dropped, once it is set.
    pub fn previous_deadline(&self) -> Option<I> {
        self.previous.as_ref().and_then(|(_, deadline)| *deadline)
    }

    /// The header protection key.
    pub fn header(&self) -> &HeaderProtectionKey<B> {
        &self.header
    }

    /// The next generation becomes current, the current one previous, until
    /// an instant still to be set, and the generation after the new current
    /// one is derived.
    fn promote(&mut self, backend: &B) {
        let following = self.next.next(backend);
        let next = core::mem::replace(&mut self.next, following);
        let current = core::mem::replace(&mut self.current, next);
        self.previous = Some((current.into_packet(), None));
    }

    /// Whether the previous generation is kept without an instant to drop
    /// it.
    fn previous_awaits_deadline(&self) -> bool {
        matches!(self.previous, Some((_, None)))
    }

    /// Drop the previous generation at `at`; one that has an instant keeps
    /// it.
    fn set_previous_deadline(&mut self, at: I) {
        if let Some((_, deadline @ None)) = &mut self.previous {
            *deadline = Some(at);
        }
    }

    /// Drop the previous generation.
    fn discard_previous(&mut self) {
        self.previous = None;
    }
}

impl<B: CryptoBackend, I: fmt::Debug> fmt::Debug for OneRttReceiveKeys<B, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OneRttReceiveKeys")
            .field(
                "previous_deadline",
                &self.previous.as_ref().map(|(_, deadline)| deadline),
            )
            .field("current", &self.current)
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

/// The 1-RTT keys of both directions, with the backend later generations
/// are derived with.
///
/// The sending generation is the receiving one, or one ahead of it after
/// this side initiated a key update the peer has not answered yet.
///
/// `I` is the instant of the connection's clock.
pub struct OneRttKeyGenerations<B: CryptoBackend, I> {
    backend: B,
    send: OneRttSendKeys<B>,
    receive: OneRttReceiveKeys<B, I>,
    send_confirmed_at: Option<I>,
}

impl<B: CryptoBackend, I: Copy> OneRttKeyGenerations<B, I> {
    /// The keys packets are sealed with.
    pub fn send(&self) -> &OneRttSendKeys<B> {
        &self.send
    }

    /// The keys packets are opened with.
    pub fn receive(&self) -> &OneRttReceiveKeys<B, I> {
        &self.receive
    }

    /// When the peer acknowledged a packet sealed with the current sending
    /// generation, once it has.
    pub fn send_confirmed_at(&self) -> Option<I> {
        self.send_confirmed_at
    }

    /// The peer acknowledged a packet sealed with the current sending
    /// generation at `at`; an instant already set stays.
    pub fn send_confirmed(&mut self, at: I) {
        self.send_confirmed_at.get_or_insert(at);
    }

    /// Seal with the next sending generation from now on.
    fn update_send(&mut self) {
        self.send.update(&self.backend);
        self.send_confirmed_at = None;
    }
}

impl<B: CryptoBackend, I: fmt::Debug> fmt::Debug for OneRttKeyGenerations<B, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OneRttKeyGenerations")
            .field("send", &self.send)
            .field("receive", &self.receive)
            .field("send_confirmed_at", &self.send_confirmed_at)
            .finish_non_exhaustive()
    }
}

/// What a promotion of the next receiving generation changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Promotion {
    /// The receiving generation that is now current.
    pub(crate) generation: u64,
    /// Whether the sending generation moved with it: the peer updated first
    /// (RFC 9001 §6.2).
    pub(crate) send_updated: bool,
}

/// The keys of the 1-RTT level.
///
/// A server gets the sending half first, when it has written its Finished,
/// and the receiving half when it has verified the client's; a client gets
/// both at once. Each direction then moves through generations with the
/// key updates (RFC 9001 §6).
///
/// `I` is the instant of the connection's clock.
pub enum OneRttKeys<B: CryptoBackend, I> {
    /// The handshake has not produced them yet.
    NotYet,
    /// A server that has written its Finished and not yet verified the
    /// client's, with the backend the receiving half will be derived with.
    SendOnly(OneRttSendKeys<B>, B),
    /// Both directions.
    Live(OneRttKeyGenerations<B, I>),
    /// The connection is closing: only packets from the peer are read.
    ReceiveOnly(OneRttReceiveKeys<B, I>),
    /// Gone: the connection is draining, or closed before they came.
    Discarded,
}

impl<B: CryptoBackend, I> fmt::Debug for OneRttKeys<B, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotYet => "NotYet",
            Self::SendOnly(..) => "SendOnly",
            Self::Live(_) => "Live",
            Self::ReceiveOnly(_) => "ReceiveOnly",
            Self::Discarded => "Discarded",
        })
    }
}

impl<B: CryptoBackend, I: Copy> OneRttKeys<B, I> {
    /// The keys to send with, while there are any.
    pub fn send(&self) -> Option<&OneRttSendKeys<B>> {
        match self {
            Self::SendOnly(keys, _) => Some(keys),
            Self::Live(keys) => Some(&keys.send),
            Self::NotYet | Self::ReceiveOnly(_) | Self::Discarded => None,
        }
    }

    /// The keys to receive with, while there are any.
    pub fn receive(&self) -> Option<&OneRttReceiveKeys<B, I>> {
        match self {
            Self::Live(keys) => Some(&keys.receive),
            Self::ReceiveOnly(keys) => Some(keys),
            Self::NotYet | Self::SendOnly(..) | Self::Discarded => None,
        }
    }

    /// Install the sending half, derived with `backend` from `secret`, which
    /// the handshake produced with the cipher suite of `aead`, as a server
    /// does when it has written its Finished. The backend is kept to derive
    /// the receiving half and later generations.
    ///
    /// No key of the level may have come before.
    pub fn install_send(&mut self, backend: B, aead: AeadAlgorithm, secret: TrafficSecret) {
        debug_assert!(
            matches!(self, Self::NotYet),
            "installing 1-RTT send keys that are {self:?}"
        );
        let send = OneRttSendKeys::derive(&backend, aead, secret);
        *self = Self::SendOnly(send, backend);
    }

    /// Install the receiving half next to the sending half, derived from
    /// `secret` with the backend and for the AEAD the sending half was
    /// installed with, as a server does when it has verified the client's
    /// Finished.
    ///
    /// The sending half must be there alone.
    pub fn install_receive(&mut self, secret: TrafficSecret) {
        match core::mem::replace(self, Self::Discarded) {
            Self::SendOnly(send, backend) => {
                let receive = OneRttReceiveKeys::derive(&backend, send.generation.aead(), secret);
                *self = Self::Live(OneRttKeyGenerations {
                    backend,
                    send,
                    receive,
                    send_confirmed_at: None,
                });
            }
            other => {
                debug_assert!(false, "installing 1-RTT receive keys that are {other:?}");
                *self = other;
            }
        }
    }

    /// Install both directions, derived with `backend` from the sending and
    /// the receiving secret, which the handshake produced with the cipher
    /// suite of `aead`, as a client does when it has verified the server's
    /// Finished. The backend is kept to derive later generations.
    ///
    /// No key of the level may have come before.
    pub fn install(
        &mut self,
        backend: B,
        aead: AeadAlgorithm,
        send: TrafficSecret,
        receive: TrafficSecret,
    ) {
        debug_assert!(
            matches!(self, Self::NotYet),
            "installing 1-RTT keys that are {self:?}"
        );
        *self = Self::Live(OneRttKeyGenerations {
            send: OneRttSendKeys::derive(&backend, aead, send),
            receive: OneRttReceiveKeys::derive(&backend, aead, receive),
            backend,
            send_confirmed_at: None,
        });
    }

    /// Drop the sending half; a level that has no receiving half is
    /// discarded, and keys that are already gone stay gone.
    pub fn keep_receive_only(&mut self) {
        match core::mem::replace(self, Self::Discarded) {
            Self::Live(keys) => *self = Self::ReceiveOnly(keys.receive),
            Self::ReceiveOnly(keys) => *self = Self::ReceiveOnly(keys),
            Self::NotYet | Self::SendOnly(..) | Self::Discarded => {}
        }
    }

    /// Discard the level.
    pub fn discard(&mut self) {
        *self = Self::Discarded;
    }

    /// The instant the previous receiving generation is dropped, once it is
    /// set.
    pub fn previous_deadline(&self) -> Option<I> {
        self.receive()
            .and_then(OneRttReceiveKeys::previous_deadline)
    }

    /// Whether a previous receiving generation is kept without an instant to
    /// drop it.
    pub(crate) fn previous_awaits_deadline(&self) -> bool {
        self.receive()
            .is_some_and(OneRttReceiveKeys::previous_awaits_deadline)
    }

    /// Drop the previous receiving generation at `at`; one that has an
    /// instant keeps it.
    pub(crate) fn set_previous_deadline(&mut self, at: I) {
        match self {
            Self::Live(keys) => keys.receive.set_previous_deadline(at),
            Self::ReceiveOnly(keys) => keys.set_previous_deadline(at),
            Self::NotYet | Self::SendOnly(..) | Self::Discarded => {}
        }
    }

    /// Drop the previous receiving generation.
    pub(crate) fn discard_previous(&mut self) {
        match self {
            Self::Live(keys) => keys.receive.discard_previous(),
            Self::ReceiveOnly(keys) => keys.discard_previous(),
            Self::NotYet | Self::SendOnly(..) | Self::Discarded => {}
        }
    }

    /// A packet opened with the next receiving generation: it becomes
    /// current and the one after it is derived (RFC 9001 §6.3). When the
    /// sending generation is behind it, the peer updated first, and the
    /// sending generation moves to it too (§6.2). `None` when the level
    /// has no backend to derive with: it only receives, or has no receiving
    /// half.
    pub(crate) fn promote_next(&mut self) -> Option<Promotion> {
        let Self::Live(keys) = self else {
            return None;
        };
        keys.receive.promote(&keys.backend);
        let generation = keys.receive.current.generation;
        let send_updated = keys.send.generation.generation < generation;
        if send_updated {
            keys.update_send();
        }
        Some(Promotion {
            generation,
            send_updated,
        })
    }

    /// Initiate a key update: seal with the next sending generation from
    /// now on (RFC 9001 §6.1). The caller counts the packets sealed with it
    /// from zero in [`AeadUsage`](super::aead_usage::AeadUsage) (§6.6).
    ///
    /// Whoever calls it checks first that a key update may be initiated
    /// (§6.1); both directions must be there.
    pub(crate) fn initiate_update(&mut self) {
        let Self::Live(keys) = self else {
            debug_assert!(
                false,
                "initiating a key update of 1-RTT keys that are {self:?}"
            );
            return;
        };
        keys.update_send();
    }
}

/// A server's keys to read 0-RTT packets.
///
/// `I` is the instant of the connection's clock.
pub enum ZeroRttReceiving<B: CryptoBackend, I> {
    /// No 0-RTT packets are read: the client offered none, the server
    /// rejected it, or the keys are gone.
    None,
    /// 0-RTT was accepted and its packets are read.
    Open(DirectionKeys<B>),
    /// A 1-RTT packet has arrived: 0-RTT packets that were reordered are
    /// still read until the instant, then the keys are dropped (RFC 9001
    /// §4.9.3).
    Retiring(DirectionKeys<B>, I),
}

impl<B: CryptoBackend, I> fmt::Debug for ZeroRttReceiving<B, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "None",
            Self::Open(_) => "Open",
            Self::Retiring(..) => "Retiring",
        })
    }
}

impl<B: CryptoBackend, I: Copy + Ord> ZeroRttReceiving<B, I> {
    /// The keys to read a 0-RTT packet with, while there are any.
    pub fn receive(&self) -> Option<&DirectionKeys<B>> {
        match self {
            Self::Open(keys) | Self::Retiring(keys, _) => Some(keys),
            Self::None => None,
        }
    }

    /// Open the level with the keys of an accepted 0-RTT.
    ///
    /// It must not have been open before.
    pub fn open(&mut self, keys: DirectionKeys<B>) {
        debug_assert!(
            matches!(self, Self::None),
            "opening 0-RTT keys that are {self:?}"
        );
        *self = Self::Open(keys);
    }

    /// A 1-RTT packet has arrived: keep the keys until `until`, three
    /// probe timeouts from now by RFC 9001 §4.9.3. Keys that already retire
    /// keep their instant.
    pub fn retire_at(&mut self, until: I) {
        if let Self::Open(_) = self {
            let Self::Open(keys) = core::mem::replace(self, Self::None) else {
                unreachable!()
            };
            *self = Self::Retiring(keys, until);
        }
    }

    /// The instant the keys are dropped, while they retire.
    pub fn deadline(&self) -> Option<I> {
        match self {
            Self::Retiring(_, until) => Some(*until),
            Self::None | Self::Open(_) => None,
        }
    }

    /// Drop the keys.
    pub fn discard(&mut self) {
        *self = Self::None;
    }
}

/// A client's keys to send 0-RTT packets.
pub enum ZeroRttSending<B: CryptoBackend> {
    /// The client offered no 0-RTT.
    None,
    /// 0-RTT is offered and its packets are sent.
    Open(DirectionKeys<B>),
    /// No more 0-RTT packets are sent: the handshake has completed (RFC
    /// 9001 §4.9.3), the server rejected 0-RTT, or the connection closes.
    Closed,
}
state_debug!(ZeroRttSending<B> { None, Open(_), Closed });

impl<B: CryptoBackend> ZeroRttSending<B> {
    /// The keys to send a 0-RTT packet with, while there are any.
    pub fn send(&self) -> Option<&DirectionKeys<B>> {
        match self {
            Self::Open(keys) => Some(keys),
            Self::None | Self::Closed => None,
        }
    }

    /// Open the level with the keys of the offered 0-RTT.
    ///
    /// It must not have been open before.
    pub fn open(&mut self, keys: DirectionKeys<B>) {
        debug_assert!(
            matches!(self, Self::None),
            "opening 0-RTT keys that are {self:?}"
        );
        *self = Self::Open(keys);
    }

    /// Stop sending 0-RTT packets.
    pub fn close(&mut self) {
        if !matches!(self, Self::None) {
            *self = Self::Closed;
        }
    }
}
