//! The `preferred_address` transport parameter ([RFC 9000 §18.2]).
//!
//! [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
use crate::connection_id::{ConnectionId, NonEmptyCid, StatelessResetToken};
use core::net::{SocketAddrV4, SocketAddrV6};

/// The `preferred_address` parameter ([RFC 9000 §18.2]): an address the
/// server would like the client to migrate to, with the connection ID to use
/// there.
///
/// An address and port of all zeros means the server has no preferred
/// address of that family; reading rejects a value in which both families
/// are all zeros, since it leaves no address to migrate to. The connection
/// ID has sequence number 1.
///
/// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PreferredAddress {
    /// The IPv4 address and port.
    pub ipv4: SocketAddrV4,
    /// The IPv6 address and port. Only the address and port are encoded;
    /// reading sets the flow information and scope ID to zero.
    pub ipv6: SocketAddrV6,
    /// The connection ID to use at the preferred address.
    pub connection_id: NonEmptyCid,
    /// The Stateless Reset Token of that connection ID.
    pub stateless_reset_token: StatelessResetToken,
}

/// The length of the fields other than the connection ID.
const FIXED_LEN: usize = 4 + 2 + 16 + 2 + 1 + StatelessResetToken::LEN;

impl PreferredAddress {
    /// The longest encoding: with a 20-byte connection ID.
    pub(crate) const MAX_LEN: usize = FIXED_LEN + ConnectionId::MAX_LEN;

    /// The number of bytes [`codec::write_preferred_address`] writes.
    pub fn encoded_len(&self) -> usize {
        FIXED_LEN + self.connection_id.as_bytes().len()
    }

    /// The encoding, left-aligned in an array, and its length.
    pub(crate) fn to_encoding(self) -> ([u8; Self::MAX_LEN], usize) {
        let mut bytes = [0; Self::MAX_LEN];
        let connection_id = self.connection_id.as_bytes();
        let parts: [&[u8]; 7] = [
            &self.ipv4.ip().octets(),
            &self.ipv4.port().to_be_bytes(),
            &self.ipv6.ip().octets(),
            &self.ipv6.port().to_be_bytes(),
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

    use super::PreferredAddress;
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
    use snafu::{ResultExt, Snafu};

    /// Reads the fields of a preferred address, and nothing after them.
    ///
    /// # Errors
    ///
    /// [`ReadPreferredAddressError::Address`] or
    /// [`ReadPreferredAddressError::StatelessResetToken`] if a fixed-length
    /// field cannot be read, [`ReadPreferredAddressError::NoAddress`] if the
    /// addresses and ports of both families are all zeros,
    /// [`ReadPreferredAddressError::ConnectionId`] if the connection ID
    /// cannot be read or is longer than 20 bytes, and
    /// [`ReadPreferredAddressError::EmptyConnectionId`] if it is empty.
    #[call(sync)]
    pub async fn read_preferred_address<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<PreferredAddress, ReadPreferredAddressError<F::Error>> {
        let [a, b, c, d, p0, p1, ipv6 @ .., q0, q1] =
            io.read_array::<{ 4 + 2 + 16 + 2 }>()
                .await
                .context(read_preferred_address_error::AddressSnafu)?;
        let ipv4 = SocketAddrV4::new(Ipv4Addr::from([a, b, c, d]), u16::from_be_bytes([p0, p1]));
        let ipv6 = SocketAddrV6::new(Ipv6Addr::from(ipv6), u16::from_be_bytes([q0, q1]), 0, 0);
        let unspecified_v4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        let unspecified_v6 = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0);
        if ipv4 == unspecified_v4 && ipv6 == unspecified_v6 {
            return read_preferred_address_error::NoAddressSnafu.fail();
        }
        let connection_id = io
            .read_connection_id()
            .await
            .context(read_preferred_address_error::ConnectionIdSnafu)?;
        let connection_id = NonEmptyCid::new(connection_id)
            .context(read_preferred_address_error::EmptyConnectionIdSnafu)?;
        let stateless_reset_token = io
            .read_array::<{ StatelessResetToken::LEN }>()
            .await
            .context(read_preferred_address_error::StatelessResetTokenSnafu)?;
        Ok(PreferredAddress {
            ipv4,
            ipv6,
            connection_id,
            stateless_reset_token: StatelessResetToken::new(stateless_reset_token),
        })
    }

    /// Failures that [`read_preferred_address`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_preferred_address_error), visibility(pub(crate)))]
    pub enum ReadPreferredAddressError<E> {
        /// The addresses and ports could not be read.
        #[snafu(display("preferred address read failed"))]
        Address {
            /// The failure of reading the fields.
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
