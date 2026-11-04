//! The `application_layer_protocol_negotiation` extension (RFC 7301 §3.1).
//!
//! In a ClientHello its data is the [`ProtocolNameList`] the client offers;
//! in EncryptedExtensions it is a list of exactly one name, the
//! [`ProtocolName`] the server selected.

use crate::{vector::LengthOutOfRangeError, width::Width};
use snafu::Snafu;

/// An application protocol name: 1 to 255 bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProtocolName<C> {
    name: C,
}

impl<C: AsRef<[u8]>> ProtocolName<C> {
    /// The protocol name `name`.
    ///
    /// # Errors
    ///
    /// [`LengthOutOfRangeError`] if `name` is empty or longer than 255 bytes.
    pub fn new(name: C) -> Result<Self, LengthOutOfRangeError> {
        LengthOutOfRangeError::check(name.as_ref().len(), 1..=Width::U8.max())?;
        Ok(Self { name })
    }

    /// The number of bytes the name takes in a list.
    fn entry_len(&self) -> usize {
        1 + self.name.as_ref().len()
    }

    /// The number of bytes [`codec::write_selected_protocol`] writes.
    pub fn encoded_len(&self) -> usize {
        2 + self.entry_len()
    }
}

impl<C> ProtocolName<C> {
    /// The name.
    pub fn name(&self) -> &C {
        &self.name
    }
}

/// A nonempty list of protocol names, in preference order.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProtocolNameList<C> {
    names: Vec<ProtocolName<C>>,
}

impl<C: AsRef<[u8]>> ProtocolNameList<C> {
    /// The list of `names`.
    ///
    /// # Errors
    ///
    /// [`LengthOutOfRangeError`] if `names` is empty or its encoding is longer
    /// than 65533 bytes, so that the list fits the extension.
    pub fn new(names: Vec<ProtocolName<C>>) -> Result<Self, LengthOutOfRangeError> {
        let len = names.iter().map(ProtocolName::entry_len).sum();
        LengthOutOfRangeError::check(len, 2..=Width::U16.max() - 2)?;
        Ok(Self { names })
    }

    /// The number of bytes [`codec::write_protocol_name_list`] writes.
    pub fn encoded_len(&self) -> usize {
        2 + self
            .names
            .iter()
            .map(ProtocolName::entry_len)
            .sum::<usize>()
    }
}

impl<C> ProtocolNameList<C> {
    /// The names.
    pub fn names(&self) -> &[ProtocolName<C>] {
        &self.names
    }
}

/// A list that should hold the one selected protocol holds more.
///
/// It is constructed only when the check fails, so the count is at least 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("selected protocol list holds {count} names instead of one"))]
pub struct ProtocolsNotSingleError {
    count: usize,
}

impl ProtocolsNotSingleError {
    /// The number of names in the list.
    pub const fn count(self) -> usize {
        self.count
    }
}

pub mod codec {
    //! Reading and writing protocol name lists as `nitori_call` operations.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::{ProtocolName, ProtocolNameList, ProtocolsNotSingleError};
    use crate::{
        alert::AlertDescription,
        message::MessageSource,
        vector::{Out, ReadBoundedVectorError, read_bounded_vector},
        width::Width,
    };
    use bytes::Buf;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{Write, calls::WriteAllError};
    use snafu::{ResultExt, Snafu};

    /// Reads a protocol name list.
    ///
    /// # Errors
    ///
    /// [`ReadProtocolNameListError`].
    #[call(sync)]
    pub async fn read_protocol_name_list<F: MessageSource, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<ProtocolNameList<F::Bytes>, ReadProtocolNameListError> {
        use read_protocol_name_list_error::*;
        let mut list = read_bounded_vector(io, Width::U16, 2..=Width::U16.max())
            .await
            .context(ListSnafu)?;
        let mut names = Vec::new();
        while list.has_remaining() {
            names.push(list.sync_read_protocol_name_unpin()?);
        }
        Ok(ProtocolNameList { names })
    }

    #[call(sync)]
    async fn read_protocol_name<F: MessageSource, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<ProtocolName<F::Bytes>, ReadProtocolNameListError> {
        let name = read_bounded_vector(io, Width::U8, 1..=Width::U8.max())
            .await
            .context(read_protocol_name_list_error::NameSnafu)?;
        Ok(ProtocolName { name })
    }

    /// Failures that [`read_protocol_name_list`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_protocol_name_list_error), visibility(pub(crate)))]
    pub enum ReadProtocolNameListError {
        /// The list could not be read.
        #[snafu(display("protocol name list read failed"))]
        List {
            /// The failure of reading the list.
            source: ReadBoundedVectorError,
        },
        /// A name could not be read.
        #[snafu(display("protocol name read failed"))]
        Name {
            /// The failure of reading the name.
            source: ReadBoundedVectorError,
        },
    }

    impl ReadProtocolNameListError {
        /// The alert the failure calls for: always decode_error.
        pub fn alert(&self) -> AlertDescription {
            AlertDescription::DECODE_ERROR
        }
    }

    /// Writes a protocol name list.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails.
    #[call(sync)]
    pub async fn write_protocol_name_list<
        F: Write,
        A: ReceiverAccess<Family = F>,
        C: AsRef<[u8]>,
    >(
        io: &mut A,
        list: &ProtocolNameList<C>,
    ) -> Result<(), WriteAllError<F::Error>> {
        list.encode(&mut Out::new(io)).await
    }

    /// Reads a protocol name list of exactly one name, as EncryptedExtensions
    /// carries the selected protocol.
    ///
    /// # Errors
    ///
    /// [`ReadSelectedProtocolError`].
    #[call(sync)]
    pub async fn read_selected_protocol<F: MessageSource, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<ProtocolName<F::Bytes>, ReadSelectedProtocolError> {
        let mut list = read_protocol_name_list(io).await?;
        if list.names.len() != 1 {
            let count = list.names.len();
            return Err(ProtocolsNotSingleError { count }.into());
        }
        // invariant: the list holds exactly one name.
        Ok(list.names.pop().expect("one name"))
    }

    /// Failures that [`read_selected_protocol`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_selected_protocol_error), visibility(pub(crate)))]
    pub enum ReadSelectedProtocolError {
        /// The list could not be read.
        #[snafu(transparent)]
        List {
            /// The failure of reading the list.
            source: ReadProtocolNameListError,
        },
        /// The list holds more than one name (RFC 7301 §3.1).
        #[snafu(transparent)]
        NotSingle {
            /// The number of names.
            source: ProtocolsNotSingleError,
        },
    }

    impl ReadSelectedProtocolError {
        /// The alert the failure calls for: illegal_parameter for more than
        /// one name, decode_error otherwise.
        pub fn alert(&self) -> AlertDescription {
            match self {
                Self::List { source } => source.alert(),
                Self::NotSingle { .. } => AlertDescription::ILLEGAL_PARAMETER,
            }
        }
    }

    /// Writes a protocol name list of the one name `protocol`.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails.
    #[call(sync)]
    pub async fn write_selected_protocol<
        F: Write,
        A: ReceiverAccess<Family = F>,
        C: AsRef<[u8]>,
    >(
        io: &mut A,
        protocol: &ProtocolName<C>,
    ) -> Result<(), WriteAllError<F::Error>> {
        protocol.encode_selected(&mut Out::new(io)).await
    }

    impl<C: AsRef<[u8]>> ProtocolName<C> {
        pub(crate) async fn encode_selected<F: Write, A: ReceiverAccess<Family = F>>(
            &self,
            out: &mut Out<'_, A>,
        ) -> Result<(), WriteAllError<F::Error>> {
            out.length(Width::U16, self.entry_len()).await?;
            out.vector(Width::U8, self.name.as_ref()).await
        }
    }

    impl<C: AsRef<[u8]>> ProtocolNameList<C> {
        pub(crate) async fn encode<F: Write, A: ReceiverAccess<Family = F>>(
            &self,
            out: &mut Out<'_, A>,
        ) -> Result<(), WriteAllError<F::Error>> {
            out.length(Width::U16, self.encoded_len() - 2).await?;
            for name in &self.names {
                out.vector(Width::U8, name.name.as_ref()).await?;
            }
            Ok(())
        }
    }
}
