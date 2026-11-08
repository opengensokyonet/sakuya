//! The `preferred_address` transport parameter ([RFC 9000 §18.2]).
//!
//! [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
use crate::connection_id::{ConnectionId, NonEmptyCid, StatelessResetToken};
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

/// The `preferred_address` parameter ([RFC 9000 §18.2]): an address the
/// server would like the client to migrate to, with the connection ID to use
/// there.
///
/// The connection ID has sequence number 1.
///
/// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PreferredAddress {
    /// The addresses, of one family or of both.
    pub addresses: PreferredAddressFamilies,
    /// The connection ID to use at the preferred address.
    pub connection_id: NonEmptyCid,
    /// The Stateless Reset Token of that connection ID.
    pub stateless_reset_token: StatelessResetToken,
}

/// The address families a preferred address has an address of
/// ([RFC 9000 §18.2]), with the address and port of each.
///
/// The encoding marks a missing family with an address and port of all
/// zeros (`0.0.0.0:0` or `[::]:0`); that marker appears only in the
/// encoding. Writing puts it in the place of a missing family. Reading
/// takes a family whose address and port are all zeros as missing, and
/// rejects a value in which both are; an all-zero address with a nonzero
/// port is an address of its family. An address given here that is itself
/// all zeros with port zero is written as the marker.
///
/// For IPv6 only the address and port are encoded; reading sets the flow
/// information and scope ID to zero.
///
/// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PreferredAddressFamilies {
    /// An IPv4 address only.
    Ipv4(SocketAddrV4),
    /// An IPv6 address only.
    Ipv6(SocketAddrV6),
    /// An address of each family.
    Both(SocketAddrV4, SocketAddrV6),
}

/// The IPv4 address and port that mark a missing IPv4 address.
const NO_IPV4: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
/// The IPv6 address and port that mark a missing IPv6 address.
const NO_IPV6: SocketAddrV6 = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0);

impl PreferredAddressFamilies {
    /// The families from the two encoded addresses, `None` if both are the
    /// marker of a missing family.
    fn from_encoded(ipv4: SocketAddrV4, ipv6: SocketAddrV6) -> Option<Self> {
        match (ipv4 == NO_IPV4, ipv6 == NO_IPV6) {
            (true, true) => None,
            (false, true) => Some(Self::Ipv4(ipv4)),
            (true, false) => Some(Self::Ipv6(ipv6)),
            (false, false) => Some(Self::Both(ipv4, ipv6)),
        }
    }

    /// The two encoded addresses, with the marker for a missing family.
    fn to_encoded(self) -> (SocketAddrV4, SocketAddrV6) {
        match self {
            Self::Ipv4(ipv4) => (ipv4, NO_IPV6),
            Self::Ipv6(ipv6) => (NO_IPV4, ipv6),
            Self::Both(ipv4, ipv6) => (ipv4, ipv6),
        }
    }
}

/// The length of the fields other than the connection ID.
const FIXED_LEN: usize = 4 + 2 + 16 + 2 + 1 + StatelessResetToken::LEN;

impl PreferredAddress {
    /// The longest encoding: with a 20-byte connection ID.
    pub(in crate::v1) const MAX_LEN: usize = FIXED_LEN + ConnectionId::MAX_LEN;

    /// The number of bytes [`codec::write_preferred_address`] writes.
    pub fn encoded_len(&self) -> usize {
        FIXED_LEN + self.connection_id.as_bytes().len()
    }

    /// The encoding, left-aligned in an array, and its length.
    pub(in crate::v1) fn to_encoding(self) -> ([u8; Self::MAX_LEN], usize) {
        let mut bytes = [0; Self::MAX_LEN];
        let connection_id = self.connection_id.as_bytes();
        let (ipv4, ipv6) = self.addresses.to_encoded();
        let parts: [&[u8]; 7] = [
            &ipv4.ip().octets(),
            &ipv4.port().to_be_bytes(),
            &ipv6.ip().octets(),
            &ipv6.port().to_be_bytes(),
            // A connection ID has at most 20 bytes, so its length fits a byte.
            &[connection_id.len() as u8],
            connection_id,
            self.stateless_reset_token.as_bytes(),
        ];
        let mut length = 0;
        // invariant: `MAX_LEN` counts every part with a 20-byte connection
        // ID, the longest a `NonEmptyCid` holds.
        for part in parts {
            bytes[length..length + part.len()].copy_from_slice(part);
            length += part.len();
        }
        (bytes, length)
    }
}

pub mod codec {
    //! Reading and writing the value of the `preferred_address` parameter as
    //! `nitori_call` operations.
    //!
    //! [`read_preferred_address`] and [`write_preferred_address`] are also
    //! the operation structs [`ReadPreferredAddress`] and
    //! [`WritePreferredAddress`], with `{Name}Ext` on receiver accesses and
    //! `{Name}HostExt` on call executors. Reading the parameters reads this
    //! value from the bytes of its parameter, which must hold nothing else.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::{PreferredAddress, PreferredAddressFamilies};
    use crate::connection_id::{
        EmptyCidError, NonEmptyCid, StatelessResetToken,
        codec::{ReadConnectionIdError, ReadConnectionIdExt as _},
    };
    use core::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{
        calls::{ReadArrayError, WriteAllError},
        prelude::*,
    };
    use snafu::{OptionExt, ResultExt, Snafu};

    /// Reads the fields of a preferred address, and nothing after them.
    ///
    /// # Errors
    ///
    /// [`ReadPreferredAddressError::Ipv4Address`],
    /// [`ReadPreferredAddressError::Ipv4Port`],
    /// [`ReadPreferredAddressError::Ipv6Address`],
    /// [`ReadPreferredAddressError::Ipv6Port`] or
    /// [`ReadPreferredAddressError::StatelessResetToken`] if that
    /// fixed-length field cannot be read,
    /// [`ReadPreferredAddressError::NoAddress`] if the
    /// addresses and ports of both families are all zeros,
    /// [`ReadPreferredAddressError::ConnectionId`] if the connection ID
    /// cannot be read or is longer than 20 bytes, and
    /// [`ReadPreferredAddressError::EmptyConnectionId`] if it is empty.
    #[call(sync)]
    pub async fn read_preferred_address<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<PreferredAddress, ReadPreferredAddressError<F::Error>> {
        use read_preferred_address_error::*;
        let ipv4_address = io.read_array::<4>().await.context(Ipv4AddressSnafu)?;
        let ipv4_port = io.read_array::<2>().await.context(Ipv4PortSnafu)?;
        let ipv6_address = io.read_array::<16>().await.context(Ipv6AddressSnafu)?;
        let ipv6_port = io.read_array::<2>().await.context(Ipv6PortSnafu)?;
        let ipv4 = SocketAddrV4::new(Ipv4Addr::from(ipv4_address), u16::from_be_bytes(ipv4_port));
        let ipv6 = SocketAddrV6::new(
            Ipv6Addr::from(ipv6_address),
            u16::from_be_bytes(ipv6_port),
            0,
            0,
        );
        let addresses =
            PreferredAddressFamilies::from_encoded(ipv4, ipv6).context(NoAddressSnafu)?;
        let connection_id = io.read_connection_id().await.context(ConnectionIdSnafu)?;
        let connection_id = NonEmptyCid::new(connection_id).context(EmptyConnectionIdSnafu)?;
        let stateless_reset_token = io
            .read_array::<{ StatelessResetToken::LEN }>()
            .await
            .context(StatelessResetTokenSnafu)?;
        Ok(PreferredAddress {
            addresses,
            connection_id,
            stateless_reset_token: StatelessResetToken::new(stateless_reset_token),
        })
    }

    /// Failures that [`read_preferred_address`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_preferred_address_error), visibility(pub(in crate::v1)))]
    pub enum ReadPreferredAddressError<E> {
        /// The IPv4 Address field could not be read.
        #[snafu(display("preferred address IPv4 Address read failed"))]
        Ipv4Address {
            /// The failure of reading the field.
            source: ReadArrayError<E>,
        },
        /// The IPv4 Port field could not be read.
        #[snafu(display("preferred address IPv4 Port read failed"))]
        Ipv4Port {
            /// The failure of reading the field.
            source: ReadArrayError<E>,
        },
        /// The IPv6 Address field could not be read.
        #[snafu(display("preferred address IPv6 Address read failed"))]
        Ipv6Address {
            /// The failure of reading the field.
            source: ReadArrayError<E>,
        },
        /// The IPv6 Port field could not be read.
        #[snafu(display("preferred address IPv6 Port read failed"))]
        Ipv6Port {
            /// The failure of reading the field.
            source: ReadArrayError<E>,
        },
        /// The addresses and ports of both families are all zeros
        /// ([RFC 9000 §18.2]): there is no address of either family.
        ///
        /// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
        #[snafu(display("preferred address has no address of either family"))]
        NoAddress,
        /// The connection ID could not be read, or it is longer than 20 bytes.
        #[snafu(display("preferred address connection ID read failed"))]
        ConnectionId {
            /// The failure of reading the connection ID.
            source: ReadConnectionIdError<E>,
        },
        /// The connection ID is empty.
        #[snafu(display("preferred address has an empty connection ID"))]
        EmptyConnectionId {
            /// The rejected connection ID.
            source: EmptyCidError,
        },
        /// The Stateless Reset Token could not be read.
        #[snafu(display("preferred address Stateless Reset Token read failed"))]
        StatelessResetToken {
            /// The failure of reading the token.
            source: ReadArrayError<E>,
        },
    }

    /// Writes the fields of `address`.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_preferred_address<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        address: PreferredAddress,
    ) -> Result<(), WriteAllError<F::Error>> {
        let (encoding, length) = address.to_encoding();
        io.write_all(&encoding[..length]).await
    }
}
