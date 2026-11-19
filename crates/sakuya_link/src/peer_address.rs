//! What a peer's address says about its network, and its bytes.

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::{Buf, BufMut};
use frunk_core::coproduct::{CNil, Coproduct};
use nitori_io::SplitTo;

/// The address of a link's peer, as a transport that tells its network layer
/// apart from its own routing.
///
/// A peer's address is [`Link::Peer`](crate::Link::Peer): the type a link
/// chooses for the far end. The part of it that names the network is its
/// network address; what is left over, such as the port of a UDP address, is
/// the transport's own routing. Two addresses with the same network address
/// differ only in that routing. Whether a change of peer address is a
/// change of network path, and whether an address validation token still
/// matches, depend on this and nothing else.
pub trait PeerAddress {
    /// The network address of a peer address: the IP address for UDP. For a
    /// sum of peer address types, the sum of their network addresses.
    type NetworkAddress: Eq;

    /// The network address of this peer address.
    ///
    /// `None` when the transport cannot say, as for a target reached through
    /// a relay: the address then counts as a different network address from
    /// every other address, which is always safe.
    fn network_address(&self) -> Option<Self::NetworkAddress>;
}

/// Whether `a` and `b` have the same network address, which both must be
/// able to state.
#[must_use]
pub fn same_network_address<P: PeerAddress>(a: &P, b: &P) -> bool {
    matches!(
        (a.network_address(), b.network_address()),
        (Some(a), Some(b)) if a == b
    )
}

impl PeerAddress for SocketAddr {
    type NetworkAddress = IpAddr;

    fn network_address(&self) -> Option<IpAddr> {
        Some(self.ip())
    }
}

impl<H: PeerAddress, T: PeerAddress> PeerAddress for Coproduct<H, T> {
    type NetworkAddress = Coproduct<H::NetworkAddress, T::NetworkAddress>;

    fn network_address(&self) -> Option<Self::NetworkAddress> {
        match self {
            Self::Inl(head) => head.network_address().map(Coproduct::Inl),
            Self::Inr(tail) => tail.network_address().map(Coproduct::Inr),
        }
    }
}

impl PeerAddress for CNil {
    type NetworkAddress = CNil;

    fn network_address(&self) -> Option<CNil> {
        match *self {}
    }
}

/// A peer address's stable byte form, for state kept outside the connection
/// that must be read back: the address in an address validation token.
///
/// The contract: a value whose [`network_address`](PeerAddress::network_address)
/// is `Some` reads back equal from what it wrote; a value whose network
/// address is `None` is never written. Reading what was not written by this
/// implementation fails or gives another value, which the user of the bytes
/// must survive; it must never be taken for proof.
///
/// Reading takes the source by [`Buf`] and [`SplitTo`], and writing takes a
/// [`BufMut`], as every format that is read and written whole in memory does.
pub trait PeerAddressCodec: PeerAddress + Sized {
    /// Writes this address.
    fn write_peer(&self, dst: &mut impl BufMut);

    /// Reads an address from the start of `src`, leaving what follows it.
    ///
    /// # Errors
    ///
    /// [`PeerAddressReadError`] when `src` holds no address of this type.
    fn read_peer<S: Buf + SplitTo>(src: &mut S) -> Result<Self, PeerAddressReadError>;
}

/// The bytes of a sum of peer address types: one byte, the position of the
/// member in the sum, then the member's own bytes.
///
/// A sum is its first member `H` and the sum `T` of the rest, so the
/// position is counted down the sum, and `T` is a sum or [`CNil`] itself.
/// This is the tail of such a sum.
pub trait PeerAddressTailCodec: PeerAddressCodec {
    /// Writes the position of the member this value is, counted from
    /// `index` for the first member of this tail, then the member.
    fn write_member(&self, index: u8, dst: &mut impl BufMut);

    /// Reads the member at position `index` of this tail, counting down: the
    /// first member of the tail when `index` is zero.
    ///
    /// # Errors
    ///
    /// [`PeerAddressReadError`] when `index` names no member, or the bytes
    /// are not that member's.
    fn read_member<S: Buf + SplitTo>(index: u8, src: &mut S) -> Result<Self, PeerAddressReadError>;
}

impl<H: PeerAddressCodec, T: PeerAddressTailCodec> PeerAddressCodec for Coproduct<H, T> {
    fn write_peer(&self, dst: &mut impl BufMut) {
        self.write_member(0, dst);
    }

    fn read_peer<S: Buf + SplitTo>(src: &mut S) -> Result<Self, PeerAddressReadError> {
        if !src.has_remaining() {
            return Err(PeerAddressReadError::Incomplete);
        }
        let index = src.get_u8();
        Self::read_member(index, src)
    }
}

impl<H: PeerAddressCodec, T: PeerAddressTailCodec> PeerAddressTailCodec for Coproduct<H, T> {
    fn write_member(&self, index: u8, dst: &mut impl BufMut) {
        match self {
            Self::Inl(head) => {
                dst.put_u8(index);
                head.write_peer(dst);
            }
            // invariant: a sum has far fewer than 256 members.
            Self::Inr(tail) => tail.write_member(index + 1, dst),
        }
    }

    fn read_member<S: Buf + SplitTo>(index: u8, src: &mut S) -> Result<Self, PeerAddressReadError> {
        match index.checked_sub(1) {
            None => H::read_peer(src).map(Coproduct::Inl),
            Some(index) => T::read_member(index, src).map(Coproduct::Inr),
        }
    }
}

impl PeerAddressCodec for CNil {
    fn write_peer(&self, _: &mut impl BufMut) {
        match *self {}
    }

    fn read_peer<S: Buf + SplitTo>(_: &mut S) -> Result<Self, PeerAddressReadError> {
        Err(PeerAddressReadError::UnknownMember)
    }
}

impl PeerAddressTailCodec for CNil {
    fn write_member(&self, _: u8, _: &mut impl BufMut) {
        match *self {}
    }

    fn read_member<S: Buf + SplitTo>(_: u8, _: &mut S) -> Result<Self, PeerAddressReadError> {
        Err(PeerAddressReadError::UnknownMember)
    }
}

/// The family byte of an IPv4 address.
const IPV4: u8 = 4;

/// The family byte of an IPv6 address.
const IPV6: u8 = 6;

/// The bytes of a socket address: a family byte, the IP address, the port,
/// and for IPv6 the flow information and the scope ID, all in network order.
///
/// The IPv6 scope ID is kept because a UDP link keeps it: link-local
/// addresses on different interfaces are different peers, and an address
/// must read back equal.
impl PeerAddressCodec for SocketAddr {
    fn write_peer(&self, dst: &mut impl BufMut) {
        match self {
            SocketAddr::V4(address) => {
                dst.put_u8(IPV4);
                dst.put_slice(&address.ip().octets());
                dst.put_u16(address.port());
            }
            SocketAddr::V6(address) => {
                dst.put_u8(IPV6);
                dst.put_slice(&address.ip().octets());
                dst.put_u16(address.port());
                dst.put_u32(address.flowinfo());
                dst.put_u32(address.scope_id());
            }
        }
    }

    fn read_peer<S: Buf + SplitTo>(src: &mut S) -> Result<Self, PeerAddressReadError> {
        if !src.has_remaining() {
            return Err(PeerAddressReadError::Incomplete);
        }
        match src.get_u8() {
            IPV4 => {
                if src.remaining() < 4 + 2 {
                    return Err(PeerAddressReadError::Incomplete);
                }
                let mut octets = [0; 4];
                src.copy_to_slice(&mut octets);
                let port = src.get_u16();
                Ok(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(octets),
                    port,
                )))
            }
            IPV6 => {
                if src.remaining() < 16 + 2 + 4 + 4 {
                    return Err(PeerAddressReadError::Incomplete);
                }
                let mut octets = [0; 16];
                src.copy_to_slice(&mut octets);
                let port = src.get_u16();
                let flowinfo = src.get_u32();
                let scope_id = src.get_u32();
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(octets),
                    port,
                    flowinfo,
                    scope_id,
                )))
            }
            _ => Err(PeerAddressReadError::UnknownFamily),
        }
    }
}

/// [`PeerAddressCodec::read_peer`] found no address in its source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PeerAddressReadError {
    /// The source ended before the address did.
    Incomplete,
    /// The family byte of a socket address is neither IPv4's nor IPv6's.
    UnknownFamily,
    /// The position of a member names no member of the sum, or the type has
    /// no bytes to read.
    UnknownMember,
}

impl fmt::Display for PeerAddressReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Incomplete => "the bytes end before the peer address does",
            Self::UnknownFamily => "the peer address has an unknown address family",
            Self::UnknownMember => "the peer address names no member of its sum",
        })
    }
}

impl core::error::Error for PeerAddressReadError {}

#[cfg(test)]
mod tests {
    use super::*;
    use frunk_core::coproduct::Coproduct::{Inl, Inr};

    type Sum = Coproduct<SocketAddr, Coproduct<SocketAddr, CNil>>;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_port_change_keeps_the_network_address_and_an_ip_change_does_not() {
        let a = addr("198.51.100.7:50000");
        assert!(same_network_address(&a, &addr("198.51.100.7:50001")));
        assert!(!same_network_address(&a, &addr("203.0.113.9:50000")));
        assert!(same_network_address(
            &addr("[2001:db8::1]:1"),
            &addr("[2001:db8::1]:2")
        ));
    }

    #[test]
    fn different_members_of_a_sum_differ_in_network_address() {
        let a: Sum = Inl(addr("198.51.100.7:50000"));
        let b: Sum = Inr(Inl(addr("198.51.100.7:50000")));
        assert!(same_network_address(&a, &a.clone()));
        assert!(!same_network_address(&a, &b));
    }

    #[test]
    fn socket_addresses_and_sums_read_back_what_they_wrote() {
        for text in ["198.51.100.7:50000", "[2001:db8::1]:443", "[fe80::1%3]:443"] {
            let mut bytes = Vec::new();
            addr(text).write_peer(&mut bytes);
            let mut src = &bytes[..];
            assert_eq!(SocketAddr::read_peer(&mut src), Ok(addr(text)));
            assert!(src.is_empty());
        }
        let second: Sum = Inr(Inl(addr("198.51.100.7:50000")));
        let mut bytes = Vec::new();
        second.write_peer(&mut bytes);
        assert_eq!(bytes[0], 1);
        let mut src = &bytes[..];
        let read = Sum::read_peer(&mut src).unwrap();
        assert!(matches!(read, Inr(Inl(a)) if a == addr("198.51.100.7:50000")));
        assert!(src.is_empty());
    }

    #[test]
    fn reading_bad_bytes_fails() {
        let mut bytes = Vec::new();
        addr("198.51.100.7:50000").write_peer(&mut bytes);
        let mut short = &bytes[..bytes.len() - 1];
        assert_eq!(
            SocketAddr::read_peer(&mut short),
            Err(PeerAddressReadError::Incomplete)
        );
        let mut family = &[9u8, 0, 0][..];
        assert_eq!(
            SocketAddr::read_peer(&mut family),
            Err(PeerAddressReadError::UnknownFamily)
        );
        let mut member = &[2u8][..];
        assert_eq!(
            Sum::read_peer(&mut member).map(|_| ()),
            Err(PeerAddressReadError::UnknownMember)
        );
        let mut empty = &[][..];
        assert_eq!(
            Sum::read_peer(&mut empty).map(|_| ()),
            Err(PeerAddressReadError::Incomplete)
        );
    }
}
