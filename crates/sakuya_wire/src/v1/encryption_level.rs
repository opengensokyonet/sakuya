//! The encryption levels of a connection ([RFC 9001 §2.1]).
//!
//! A packet that carries frames is protected at one of four levels, which
//! its packet type announces: Initial, 0-RTT, Handshake and 1-RTT. The level
//! decides which frames the packet may carry ([RFC 9000 §12.4]); see
//! [`FrameKind::can_appear_in`](crate::v1::frame::set::FrameKind::can_appear_in).
//!
//! [RFC 9001 §2.1]: https://www.rfc-editor.org/rfc/rfc9001.html#section-2.1
//! [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4

/// The level a packet is protected at, in the order [RFC 9000 §12.2] lists
/// the packets of a datagram.
///
/// Version Negotiation and Retry packets are not protected at any level, and
/// have no value here.
///
/// [RFC 9000 §12.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EncryptionLevel {
    /// Initial packets.
    Initial,
    /// 0-RTT packets.
    ZeroRtt,
    /// Handshake packets.
    Handshake,
    /// 1-RTT packets, which have a short header.
    OneRtt,
}

impl EncryptionLevel {
    /// Every level, in order.
    pub const ALL: [Self; 4] = [Self::Initial, Self::ZeroRtt, Self::Handshake, Self::OneRtt];
}
