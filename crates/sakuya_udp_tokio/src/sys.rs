//! The socket calls of Linux: opening a socket with its options, and
//! receiving and sending a datagram or a GSO batch with control messages.

use std::{
    io::{self, IoSlice, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsRawFd, BorrowedFd, OwnedFd},
};

use nix::{
    errno::Errno,
    libc,
    sys::socket::{
        AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockProtocol,
        SockType, SockaddrStorage, bind, getsockname, recvmsg, sendmsg, setsockopt, socket,
        sockopt,
    },
};
use rustix::net::sockopt::{
    Ipv4PathMtuDiscovery, Ipv6PathMtuDiscovery, set_ip_mtu_discover, set_ipv6_mtu_discover,
};
use sakuya_link::EcnCodepoint;
use snafu::{ResultExt, Snafu};

/// The most bytes one receive takes: a GRO batch is at most 64 KiB.
pub(crate) const RECEIVE_SIZE: usize = 1 << 16;

/// The most datagrams one GSO send carries (`UDP_MAX_SEGMENTS`).
pub(crate) const MAX_GSO_SEGMENTS: usize = 64;

/// The most bytes one GSO send carries: one UDP payload over IPv4.
pub(crate) const MAX_GSO_BYTES: usize = 65_507;

/// A socket that could not be opened.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
pub enum BindError {
    /// The socket could not be created.
    #[snafu(display("could not create the socket"))]
    Create {
        /// The error of `socket`.
        source: io::Error,
    },
    /// An IPv6 socket on the unspecified address could not be made to take
    /// IPv4 too (`IPV6_V6ONLY`).
    #[snafu(display("could not let the IPv6 socket take IPv4"))]
    DualStack {
        /// The error of `setsockopt`.
        source: io::Error,
    },
    /// The socket could not be made to report the local IPv4 address each
    /// datagram arrived at (`IP_PKTINFO`), which a socket on the unspecified
    /// address needs.
    #[snafu(display("could not ask for the local IPv4 address of arrivals"))]
    Ipv4PacketInfo {
        /// The error of `setsockopt`.
        source: io::Error,
    },
    /// The socket could not be made to report the local IPv6 address each
    /// datagram arrived at (`IPV6_RECVPKTINFO`), which a socket on the
    /// unspecified address needs.
    #[snafu(display("could not ask for the local IPv6 address of arrivals"))]
    Ipv6PacketInfo {
        /// The error of `setsockopt`.
        source: io::Error,
    },
    /// The socket could not be bound to the address.
    #[snafu(display("could not bind to {address}"))]
    Bind {
        /// The address.
        address: SocketAddr,
        /// The error of `bind`.
        source: io::Error,
    },
    /// The address the socket was bound to could not be read.
    #[snafu(display("could not read the bound address"))]
    LocalAddress {
        /// The error of `getsockname`.
        source: io::Error,
    },
    /// The socket could not be registered with the tokio runtime.
    #[snafu(display("could not register the socket with the runtime"))]
    Register {
        /// The error of tokio.
        source: std::io::Error,
    },
}

/// A socket just opened, with what its options turned out to allow.
pub(crate) struct Opened {
    pub(crate) socket: std::net::UdpSocket,
    pub(crate) local: SocketAddr,
    /// IPv4 datagrams leave with DF set and the kernel's PMTU ignored.
    pub(crate) no_fragment_v4: bool,
    /// IPv6 datagrams are never fragmented locally and the kernel's PMTU is
    /// ignored.
    pub(crate) no_fragment_v6: bool,
}

/// Opens a non-blocking UDP socket bound to `address`.
///
/// An IPv6 socket on the unspecified address takes IPv4 too. Options that
/// only improve what the socket reports or how it batches are set when the
/// kernel allows them and left otherwise: DF, reading ECN, GRO.
pub(crate) fn open(address: SocketAddr) -> Result<Opened, BindError> {
    let family = match address {
        SocketAddr::V4(_) => AddressFamily::Inet,
        SocketAddr::V6(_) => AddressFamily::Inet6,
    };
    let fd: OwnedFd = socket(
        family,
        SockType::Datagram,
        SockFlag::SOCK_NONBLOCK | SockFlag::SOCK_CLOEXEC,
        SockProtocol::Udp,
    )
    .map_err(io::Error::from)
    .context(CreateSnafu)?;
    let unspecified = address.ip().is_unspecified();
    let takes_v4 = match address {
        SocketAddr::V4(_) => true,
        SocketAddr::V6(_) if unspecified => {
            setsockopt(&fd, sockopt::Ipv6V6Only, &false)
                .map_err(io::Error::from)
                .context(DualStackSnafu)?;
            true
        }
        SocketAddr::V6(_) => false,
    };
    let takes_v6 = address.is_ipv6();

    let no_fragment_v4 = takes_v4 && set_ip_mtu_discover(&fd, Ipv4PathMtuDiscovery::PROBE).is_ok();
    let no_fragment_v6 =
        takes_v6 && set_ipv6_mtu_discover(&fd, Ipv6PathMtuDiscovery::PROBE).is_ok();
    if takes_v4 {
        let _ = setsockopt(&fd, sockopt::IpRecvTos, &true);
    }
    if takes_v6 {
        let _ = setsockopt(&fd, sockopt::Ipv6RecvTClass, &true);
    }
    if unspecified {
        if takes_v4 {
            setsockopt(&fd, sockopt::Ipv4PacketInfo, &true)
                .map_err(io::Error::from)
                .context(Ipv4PacketInfoSnafu)?;
        }
        if takes_v6 {
            setsockopt(&fd, sockopt::Ipv6RecvPacketInfo, &true)
                .map_err(io::Error::from)
                .context(Ipv6PacketInfoSnafu)?;
        }
    }
    let _ = setsockopt(&fd, sockopt::UdpGroSegment, &true);

    bind(fd.as_raw_fd(), &SockaddrStorage::from(address))
        .map_err(io::Error::from)
        .context(BindSnafu { address })?;
    let local = getsockname::<SockaddrStorage>(fd.as_raw_fd())
        .map_err(io::Error::from)
        .context(LocalAddressSnafu)
        .map(|storage| socket_address(&storage).unwrap_or(address))?;
    Ok(Opened {
        socket: std::net::UdpSocket::from(fd),
        local,
        no_fragment_v4,
        no_fragment_v6,
    })
}

/// What one receive gave: `len` bytes from `peer`, in segments of `stride`
/// bytes (the last may be shorter) when GRO joined several datagrams.
pub(crate) struct Received {
    pub(crate) len: usize,
    pub(crate) stride: usize,
    pub(crate) peer: SocketAddr,
    /// The local address the datagrams arrived at, when the socket reports
    /// it.
    pub(crate) local_ip: Option<IpAddr>,
    /// The ECN codepoint of the datagrams' IP header, when the kernel
    /// reported it: GRO joins only datagrams with the same one.
    pub(crate) ecn: Option<EcnCodepoint>,
    /// The datagrams were sent to a broadcast or multicast address, not to
    /// the local address alone.
    pub(crate) to_group: bool,
}

impl Received {
    /// Whether a reply can go back: the datagrams came from a unicast
    /// address and port and were sent to this side alone.
    ///
    /// The kernel refuses to send to port 0, or from a broadcast or
    /// multicast address, with the same `EINVAL` that a socket gives when
    /// it cannot segment or mark ECN, so such datagrams get no link.
    pub(crate) fn replyable(&self) -> bool {
        !self.to_group && unicast(self.peer)
    }
}

/// Whether `address` is a unicast address and port a datagram can be sent
/// to.
fn unicast(address: SocketAddr) -> bool {
    let ip = address.ip();
    let group = match ip {
        IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast(),
        IpAddr::V6(v6) => v6.is_multicast(),
    };
    address.port() != 0 && !ip.is_unspecified() && !group
}

/// The control message space one receive needs: the local address, the
/// traffic class or TOS, and the GRO segment size, with room to spare.
pub(crate) fn control_space() -> Vec<u8> {
    nix::cmsg_space!(
        libc::in6_pktinfo,
        libc::in_pktinfo,
        libc::c_int,
        libc::c_int,
        libc::c_int
    )
}

/// Receives once into `buffer`; `control` is the space for control
/// messages.
///
/// A receive whose control messages did not fit, which the space of
/// [`control_space`] does not allow, reports neither the local address nor
/// ECN.
pub(crate) fn receive(
    fd: BorrowedFd<'_>,
    buffer: &mut [u8],
    control: &mut [u8],
) -> Result<Received, Errno> {
    let mut slices = [IoSliceMut::new(buffer)];
    let message = recvmsg::<SockaddrStorage>(
        fd.as_raw_fd(),
        &mut slices,
        Some(control),
        MsgFlags::empty(),
    )?;
    let peer = message
        .address
        .as_ref()
        .and_then(socket_address)
        .ok_or(Errno::EAFNOSUPPORT)?;
    let mut received = Received {
        len: message.bytes,
        stride: message.bytes,
        peer: canonical(peer),
        local_ip: None,
        ecn: None,
        to_group: false,
    };
    let messages = message.cmsgs();
    // The space of `control_space` holds every control message the socket
    // asks for, so they are never truncated.
    debug_assert!(messages.is_ok(), "the control messages were truncated");
    if let Ok(messages) = messages {
        for control in messages {
            match control {
                ControlMessageOwned::Ipv4PacketInfo(info) => {
                    // The header's destination differs from the local
                    // address of the arrival for a broadcast or multicast.
                    let to = Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes());
                    let local = Ipv4Addr::from(info.ipi_spec_dst.s_addr.to_ne_bytes());
                    received.to_group |= to != local;
                    received.local_ip = Some(IpAddr::V4(to));
                }
                ControlMessageOwned::Ipv6PacketInfo(info) => {
                    let to = canonical_ip(IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)));
                    received.to_group |= to.is_multicast();
                    received.local_ip = Some(to);
                }
                ControlMessageOwned::Ipv4Tos(tos) => received.ecn = Some(ecn_codepoint(tos)),
                ControlMessageOwned::Ipv6TClass(class) => {
                    received.ecn = Some(ecn_codepoint(class.to_le_bytes()[0]));
                }
                ControlMessageOwned::UdpGroSegments(size) => {
                    if let Ok(size @ 1..) = usize::try_from(size) {
                        received.stride = size;
                    }
                }
                _ => {}
            }
        }
    }
    Ok(received)
}

/// One send: `payloads` in order to `peer`, as one datagram or, with
/// `segment`, as a GSO batch of datagrams of that size.
pub(crate) struct Send<'a> {
    pub(crate) payloads: &'a [IoSlice<'a>],
    pub(crate) peer: SocketAddr,
    /// The ECN bits to set; `None` leaves the TOS or traffic class alone.
    pub(crate) ecn: Option<u8>,
    /// The local address to send from, for a socket on the unspecified
    /// address.
    pub(crate) local_ip: Option<IpAddr>,
    pub(crate) segment: Option<u16>,
    /// The socket is IPv6, so IPv4 peers are reached at their mapped
    /// address.
    pub(crate) ipv6_socket: bool,
}

/// Sends once.
pub(crate) fn send(fd: BorrowedFd<'_>, send: &Send<'_>) -> Result<(), Errno> {
    let v4_peer = send.peer.is_ipv4();
    let destination = match (send.peer, send.ipv6_socket) {
        (SocketAddr::V4(peer), true) => SocketAddr::V6(SocketAddrV6::new(
            peer.ip().to_ipv6_mapped(),
            peer.port(),
            0,
            0,
        )),
        (peer, _) => peer,
    };
    let tos = send.ecn.unwrap_or(0);
    let class = libc::c_int::from(tos);
    let segment = send.segment.unwrap_or(0);
    let v4_info = match send.local_ip {
        Some(IpAddr::V4(ip)) => Some(libc::in_pktinfo {
            ipi_ifindex: 0,
            ipi_spec_dst: libc::in_addr {
                s_addr: u32::from_ne_bytes(ip.octets()),
            },
            ipi_addr: libc::in_addr { s_addr: 0 },
        }),
        _ => None,
    };
    let v6_info = match send.local_ip {
        Some(IpAddr::V6(ip)) => Some(libc::in6_pktinfo {
            ipi6_addr: libc::in6_addr {
                s6_addr: ip.octets(),
            },
            ipi6_ifindex: 0,
        }),
        _ => None,
    };
    let mut controls = Vec::with_capacity(3);
    if send.ecn.is_some() {
        controls.push(if v4_peer {
            ControlMessage::Ipv4Tos(&tos)
        } else {
            ControlMessage::Ipv6TClass(&class)
        });
    }
    if let Some(info) = &v4_info {
        controls.push(ControlMessage::Ipv4PacketInfo(info));
    }
    if let Some(info) = &v6_info {
        controls.push(ControlMessage::Ipv6PacketInfo(info));
    }
    if send.segment.is_some() {
        controls.push(ControlMessage::UdpGsoSegments(&segment));
    }
    sendmsg(
        fd.as_raw_fd(),
        send.payloads,
        &controls,
        MsgFlags::empty(),
        Some(&SockaddrStorage::from(destination)),
    )
    .map(drop)
}

/// Whether an error of a socket call means the socket can do nothing more.
///
/// The rest are transient or concern one datagram: a full buffer, a
/// datagram too large, an ICMP error reported on the socket.
pub(crate) fn is_fatal(errno: Errno) -> bool {
    matches!(
        errno,
        Errno::EBADF | Errno::ENOTSOCK | Errno::EFAULT | Errno::EOPNOTSUPP
    )
}

fn socket_address(storage: &SockaddrStorage) -> Option<SocketAddr> {
    if let Some(v4) = storage.as_sockaddr_in() {
        Some(SocketAddr::V4(SocketAddrV4::from(*v4)))
    } else {
        storage
            .as_sockaddr_in6()
            .map(|v6| SocketAddr::V6(SocketAddrV6::from(*v6)))
    }
}

/// An IPv4 address mapped into IPv6 as the IPv4 address it is. An IPv6
/// address keeps its scope, which tells apart link-local addresses on
/// different interfaces, and drops its flow label, which does not name the
/// peer.
pub(crate) fn canonical(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::V4(SocketAddrV4::new(v4, v6.port())),
            None => SocketAddr::V6(SocketAddrV6::new(*v6.ip(), v6.port(), 0, v6.scope_id())),
        },
        SocketAddr::V4(_) => address,
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

fn ecn_codepoint(tos: u8) -> EcnCodepoint {
    match tos & 0b11 {
        0b00 => EcnCodepoint::NotEct,
        0b01 => EcnCodepoint::Ect1,
        0b10 => EcnCodepoint::Ect0,
        _ => EcnCodepoint::Ce,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mapped_address_is_the_ipv4_address_and_ipv6_keeps_its_scope() {
        let mapped = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped(),
            443,
            7,
            0,
        ));
        assert_eq!(canonical(mapped), SocketAddr::from(([192, 0, 2, 1], 443)));
        let link_local = SocketAddrV6::new("fe80::1".parse().unwrap(), 443, 7, 3);
        assert_eq!(
            canonical(SocketAddr::V6(link_local)),
            SocketAddr::V6(SocketAddrV6::new(*link_local.ip(), 443, 0, 3))
        );
    }

    fn received(peer: SocketAddr, to_group: bool) -> Received {
        Received {
            len: 0,
            stride: 0,
            peer,
            local_ip: None,
            ecn: None,
            to_group,
        }
    }

    #[test]
    fn only_datagrams_from_a_unicast_peer_to_this_side_alone_can_be_replied_to() {
        let peer = SocketAddr::from(([192, 0, 2, 1], 4433));
        assert!(received(peer, false).replyable());
        assert!(!received(peer, true).replyable());
        for unreplyable in [
            SocketAddr::from(([192, 0, 2, 1], 0)),
            SocketAddr::from(([0, 0, 0, 0], 4433)),
            SocketAddr::from(([255, 255, 255, 255], 4433)),
            SocketAddr::from(([224, 0, 0, 1], 4433)),
            "[ff02::1]:4433".parse().unwrap(),
            "[::]:4433".parse().unwrap(),
        ] {
            assert!(!received(unreplyable, false).replyable(), "{unreplyable}");
        }
    }
}
