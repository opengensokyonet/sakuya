//! The socket calls of Linux: opening a socket with its options, and
//! receiving and sending a datagram or a GSO batch with control messages.

use std::{
    io::{IoSlice, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::{AsRawFd, BorrowedFd, OwnedFd},
};

use nix::{
    errno::Errno,
    libc, setsockopt_impl, sockopt_impl,
    sys::socket::{
        AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockProtocol,
        SockType, SockaddrStorage, bind, getsockname, recvmsg, sendmsg, setsockopt, socket,
        sockopt,
    },
};
use sakuya_link::EcnCodepoint;
use snafu::{ResultExt, Snafu};

sockopt_impl!(
    /// `IP_MTU_DISCOVER`: how the kernel discovers the path MTU of IPv4.
    IpMtuDiscover,
    SetOnly,
    libc::IPPROTO_IP,
    libc::IP_MTU_DISCOVER,
    libc::c_int
);
sockopt_impl!(
    /// `IPV6_MTU_DISCOVER`: how the kernel discovers the path MTU of IPv6.
    Ipv6MtuDiscover,
    SetOnly,
    libc::IPPROTO_IPV6,
    libc::IPV6_MTU_DISCOVER,
    libc::c_int
);

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
        source: Errno,
    },
    /// An IPv6 socket on the unspecified address could not be made to take
    /// IPv4 too (`IPV6_V6ONLY`).
    #[snafu(display("could not let the IPv6 socket take IPv4"))]
    DualStack {
        /// The error of `setsockopt`.
        source: Errno,
    },
    /// The socket could not be made to report the local IPv4 address each
    /// datagram arrived at (`IP_PKTINFO`), which a socket on the unspecified
    /// address needs.
    #[snafu(display("could not ask for the local IPv4 address of arrivals"))]
    Ipv4PacketInfo {
        /// The error of `setsockopt`.
        source: Errno,
    },
    /// The socket could not be made to report the local IPv6 address each
    /// datagram arrived at (`IPV6_RECVPKTINFO`), which a socket on the
    /// unspecified address needs.
    #[snafu(display("could not ask for the local IPv6 address of arrivals"))]
    Ipv6PacketInfo {
        /// The error of `setsockopt`.
        source: Errno,
    },
    /// The socket could not be bound to the address.
    #[snafu(display("could not bind to {address}"))]
    Bind {
        /// The address.
        address: SocketAddr,
        /// The error of `bind`.
        source: Errno,
    },
    /// The address the socket was bound to could not be read.
    #[snafu(display("could not read the bound address"))]
    LocalAddress {
        /// The error of `getsockname`.
        source: Errno,
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
    .context(CreateSnafu)?;
    let unspecified = address.ip().is_unspecified();
    let takes_v4 = match address {
        SocketAddr::V4(_) => true,
        SocketAddr::V6(_) if unspecified => {
            setsockopt(&fd, sockopt::Ipv6V6Only, &false).context(DualStackSnafu)?;
            true
        }
        SocketAddr::V6(_) => false,
    };
    let takes_v6 = address.is_ipv6();

    let no_fragment_v4 =
        takes_v4 && setsockopt(&fd, IpMtuDiscover, &libc::IP_PMTUDISC_PROBE).is_ok();
    let no_fragment_v6 =
        takes_v6 && setsockopt(&fd, Ipv6MtuDiscover, &libc::IPV6_PMTUDISC_PROBE).is_ok();
    if takes_v4 {
        let _ = setsockopt(&fd, sockopt::IpRecvTos, &true);
    }
    if takes_v6 {
        let _ = setsockopt(&fd, sockopt::Ipv6RecvTClass, &true);
    }
    if unspecified {
        if takes_v4 {
            setsockopt(&fd, sockopt::Ipv4PacketInfo, &true).context(Ipv4PacketInfoSnafu)?;
        }
        if takes_v6 {
            setsockopt(&fd, sockopt::Ipv6RecvPacketInfo, &true).context(Ipv6PacketInfoSnafu)?;
        }
    }
    let _ = setsockopt(&fd, sockopt::UdpGroSegment, &true);

    bind(fd.as_raw_fd(), &SockaddrStorage::from(address)).context(BindSnafu { address })?;
    let local = getsockname::<SockaddrStorage>(fd.as_raw_fd())
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
    };
    if let Ok(messages) = message.cmsgs() {
        for control in messages {
            match control {
                ControlMessageOwned::Ipv4PacketInfo(info) => {
                    received.local_ip = Some(IpAddr::V4(Ipv4Addr::from(
                        info.ipi_addr.s_addr.to_ne_bytes(),
                    )));
                }
                ControlMessageOwned::Ipv6PacketInfo(info) => {
                    received.local_ip = Some(canonical_ip(IpAddr::V6(Ipv6Addr::from(
                        info.ipi6_addr.s6_addr,
                    ))));
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

/// An IPv4 address mapped into IPv6 as the IPv4 address it is.
pub(crate) fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(canonical_ip(address.ip()), address.port())
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
