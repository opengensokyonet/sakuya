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

use core::fmt;

use sakuya_packet_protection::{
    backend::{AeadAlgorithm, CryptoBackend},
    header_protection::HeaderProtectionKey,
    packet_key::PacketKey,
    secret::TrafficSecret,
};

/// The keys that protect the packets of one direction at one encryption
/// level: the packet key and the header protection key, derived from one
/// traffic secret.
pub struct DirectionKeys<B: CryptoBackend> {
    /// Encrypts or decrypts the payload.
    pub packet: PacketKey<B>,
    /// Applies or removes header protection.
    pub header: HeaderProtectionKey<B>,
}

impl<B: CryptoBackend> DirectionKeys<B> {
    /// Derives both keys from `secret` (RFC 9001 §5.1), for the AEAD of the
    /// cipher suite that produced it.
    pub fn derive(backend: &B, aead: AeadAlgorithm, secret: &TrafficSecret) -> Self {
        Self {
            packet: PacketKey::derive(backend, aead, secret),
            header: HeaderProtectionKey::derive(backend, aead, secret),
        }
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

/// The keys of the 1-RTT level.
///
/// A server gets the sending half first, when it has written its Finished,
/// and the receiving half when it has verified the client's; a client gets
/// both at once.
pub enum OneRttKeys<B: CryptoBackend> {
    /// The handshake has not produced them yet.
    NotYet,
    /// A server that has written its Finished and not yet verified the
    /// client's.
    SendOnly(DirectionKeys<B>),
    /// Both directions.
    Live(LevelKeys<B>),
    /// The connection is closing: only packets from the peer are read.
    ReceiveOnly(DirectionKeys<B>),
    /// Gone: the connection is draining, or closed before they came.
    Discarded,
}
state_debug!(OneRttKeys<B> { NotYet, SendOnly(_), Live(_), ReceiveOnly(_), Discarded });

impl<B: CryptoBackend> OneRttKeys<B> {
    /// The keys to send with, while there are any.
    pub fn send(&self) -> Option<&DirectionKeys<B>> {
        match self {
            Self::SendOnly(keys) => Some(keys),
            Self::Live(keys) => Some(&keys.send),
            Self::NotYet | Self::ReceiveOnly(_) | Self::Discarded => None,
        }
    }

    /// The keys to receive with, while there are any.
    pub fn receive(&self) -> Option<&DirectionKeys<B>> {
        match self {
            Self::Live(keys) => Some(&keys.receive),
            Self::ReceiveOnly(keys) => Some(keys),
            Self::NotYet | Self::SendOnly(_) | Self::Discarded => None,
        }
    }

    /// Install the sending half, as a server does when it has written its
    /// Finished.
    ///
    /// No key of the level may have come before.
    pub fn install_send(&mut self, keys: DirectionKeys<B>) {
        debug_assert!(
            matches!(self, Self::NotYet),
            "installing 1-RTT send keys that are {self:?}"
        );
        *self = Self::SendOnly(keys);
    }

    /// Install the receiving half next to the sending half, as a server
    /// does when it has verified the client's Finished.
    ///
    /// The sending half must be there alone.
    pub fn install_receive(&mut self, receive: DirectionKeys<B>) {
        match core::mem::replace(self, Self::Discarded) {
            Self::SendOnly(send) => *self = Self::Live(LevelKeys { send, receive }),
            other => {
                debug_assert!(false, "installing 1-RTT receive keys that are {other:?}");
                *self = other;
            }
        }
    }

    /// Install both directions, as a client does when it has verified the
    /// server's Finished.
    ///
    /// No key of the level may have come before.
    pub fn install(&mut self, keys: LevelKeys<B>) {
        debug_assert!(
            matches!(self, Self::NotYet),
            "installing 1-RTT keys that are {self:?}"
        );
        *self = Self::Live(keys);
    }

    /// Drop the sending half; a level that has no receiving half is
    /// discarded, and keys that are already gone stay gone.
    pub fn keep_receive_only(&mut self) {
        match core::mem::replace(self, Self::Discarded) {
            Self::Live(keys) => *self = Self::ReceiveOnly(keys.receive),
            Self::ReceiveOnly(keys) => *self = Self::ReceiveOnly(keys),
            Self::NotYet | Self::SendOnly(_) | Self::Discarded => {}
        }
    }

    /// Discard the level.
    pub fn discard(&mut self) {
        *self = Self::Discarded;
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
