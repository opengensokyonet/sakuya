//! The `server_name` extension (RFC 6066 §3).
//!
//! In a ClientHello its data is a list of names; host_name is the only name
//! type, and a list may hold at most one name of each type, so the data is
//! one [`ServerName`]. In EncryptedExtensions the data is empty.

use crate::{vector::LengthOutOfRange, width::Width};
use snafu::Snafu;

/// The data of a `server_name` extension in a ClientHello: one host_name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ServerName<C> {
    host_name: C,
}

/// The name type of host_name.
const HOST_NAME: u8 = 0;

impl<C: AsRef<[u8]>> ServerName<C> {
    /// The list that holds `host_name`, the bytes of a DNS host name.
    ///
    /// # Errors
    ///
    /// [`LengthOutOfRange`] if `host_name` is empty or longer than 65530
    /// bytes, so that the list fits the extension.
    pub fn new(host_name: C) -> Result<Self, LengthOutOfRange> {
        LengthOutOfRange::check(host_name.as_ref().len(), 1..=Width::U16.max() - 5)?;
        Ok(Self { host_name })
    }

    /// The number of bytes [`codec::write_server_name`] writes.
    pub fn encoded_len(&self) -> usize {
        5 + self.host_name.as_ref().len()
    }
}

impl<C> ServerName<C> {
    /// The host name.
    pub fn host_name(&self) -> &C {
        &self.host_name
    }
}

/// A name of a type other than host_name, whose layout is not known, so the
/// list cannot be read further.
///
/// It is constructed only for another type, so the type is never 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("server name of unknown type {name_type}"))]
pub struct UnknownNameType {
    name_type: u8,
}

impl UnknownNameType {
    /// The name type.
    pub const fn name_type(self) -> u8 {
        self.name_type
    }
}

pub mod codec {
    //! Reading and writing `server_name` data as `nitori_call` operations.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::{HOST_NAME, ServerName, UnknownNameType};
    use crate::{
        alert::AlertDescription,
        message::MessageSource,
        vector::{Out, ReadBoundedVectorError, read_bounded_vector, read_u8},
        width::Width,
    };
    use bytes::Buf;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{Write, calls::WriteAllError, error::Incomplete};
    use snafu::{ResultExt, Snafu};

    /// Reads the data of a `server_name` extension in a ClientHello.
    ///
    /// # Errors
    ///
    /// [`ReadServerNameError`].
    #[call(sync)]
    pub async fn read_server_name<F: MessageSource, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<ServerName<F::Bytes>, ReadServerNameError> {
        use read_server_name_error::*;
        let range = 1..=Width::U16.max();
        let mut list = read_bounded_vector(io, Width::U16, range.clone())
            .await
            .context(ListSnafu)?;
        let mut host_name = None;
        while list.has_remaining() {
            let name = list.sync_read_server_name_entry_unpin()?;
            if host_name.replace(name).is_some() {
                return DuplicateHostNameSnafu.fail();
            }
        }
        // invariant: the list is not empty, and every name in it is a
        // host_name.
        let host_name = host_name.expect("a nonempty list holds a host name");
        Ok(ServerName { host_name })
    }

    /// Reads one name of a server name list, which must be a host_name.
    #[call(sync)]
    async fn read_server_name_entry<F: MessageSource, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<F::Bytes, ReadServerNameError> {
        use read_server_name_error::*;
        let name_type = read_u8(io).await.context(NameTypeSnafu)?;
        if name_type != HOST_NAME {
            return Err(UnknownNameType { name_type }.into());
        }
        read_bounded_vector(io, Width::U16, 1..=Width::U16.max())
            .await
            .context(HostNameSnafu)
    }

    /// Failures that [`read_server_name`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_server_name_error), visibility(pub(crate)))]
    pub enum ReadServerNameError {
        /// The list could not be read.
        #[snafu(display("server name list read failed"))]
        List {
            /// The failure of reading the list.
            source: ReadBoundedVectorError,
        },
        /// The name type of an entry could not be read.
        #[snafu(display("server name type read failed"))]
        NameType {
            /// The shortfall.
            source: Incomplete,
        },
        /// An entry has a name type other than host_name.
        #[snafu(transparent)]
        UnknownNameType {
            /// The type.
            source: UnknownNameType,
        },
        /// A host name could not be read.
        #[snafu(display("host name read failed"))]
        HostName {
            /// The failure of reading the name.
            source: ReadBoundedVectorError,
        },
        /// The list holds more than one host_name (RFC 6066 §3).
        #[snafu(display("server name list holds more than one host name"))]
        DuplicateHostName,
    }

    impl ReadServerNameError {
        /// The alert the failure calls for: illegal_parameter for a second
        /// host name, decode_error otherwise.
        pub fn alert(&self) -> AlertDescription {
            match self {
                Self::DuplicateHostName => AlertDescription::ILLEGAL_PARAMETER,
                _ => AlertDescription::DECODE_ERROR,
            }
        }
    }

    /// Writes the data of a `server_name` extension in a ClientHello.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails.
    #[call(sync)]
    pub async fn write_server_name<F: Write, A: ReceiverAccess<Family = F>, C: AsRef<[u8]>>(
        io: &mut A,
        name: &ServerName<C>,
    ) -> Result<(), WriteAllError<F::Error>> {
        name.encode(&mut Out::new(io)).await
    }

    impl<C: AsRef<[u8]>> ServerName<C> {
        pub(crate) async fn encode<F: Write, A: ReceiverAccess<Family = F>>(
            &self,
            out: &mut Out<'_, A>,
        ) -> Result<(), WriteAllError<F::Error>> {
            let host_name = self.host_name.as_ref();
            out.length(Width::U16, 3 + host_name.len()).await?;
            out.u8(HOST_NAME).await?;
            out.vector(Width::U16, host_name).await
        }
    }
}
