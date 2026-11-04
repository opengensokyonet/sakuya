//! The `pre_shared_key` extension (RFC 8446 §4.2.11).
//!
//! In a ClientHello its data is [`OfferedPsks`]: the identities the client
//! offers and a binder for each. In a ServerHello it is the [`PskIndex`] of
//! the identity the server selected.
//!
//! A binder covers the ClientHello up to the binders, with its lengths as
//! if the binders were there (RFC 8446 §4.2.11.2), so a client writes the
//! ClientHello with binders of the right lengths, computes the binders over
//! the bytes before [`OfferedPsks::binders_len`] and writes them in place.

use crate::{vector::LengthOutOfRangeError, width::Width};
use snafu::{ResultExt, Snafu};

/// One offered identity: an opaque label, such as a ticket, and the
/// obfuscated age of the ticket.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PskIdentity<C> {
    identity: C,
    obfuscated_ticket_age: u32,
}

impl<C: AsRef<[u8]>> PskIdentity<C> {
    /// The identity `identity`, with `obfuscated_ticket_age`.
    ///
    /// # Errors
    ///
    /// [`LengthOutOfRangeError`] if `identity` is empty or longer than 65535
    /// bytes.
    pub fn new(identity: C, obfuscated_ticket_age: u32) -> Result<Self, LengthOutOfRangeError> {
        LengthOutOfRangeError::check(identity.as_ref().len(), 1..=Width::U16.max())?;
        Ok(Self {
            identity,
            obfuscated_ticket_age,
        })
    }

    fn entry_len(&self) -> usize {
        2 + self.identity.as_ref().len() + 4
    }
}

impl<C> PskIdentity<C> {
    /// The identity.
    pub fn identity(&self) -> &C {
        &self.identity
    }

    /// The obfuscated ticket age.
    pub fn obfuscated_ticket_age(&self) -> u32 {
        self.obfuscated_ticket_age
    }
}

/// One binder: an HMAC of 32 to 255 bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PskBinder<C> {
    binder: C,
}

impl<C: AsRef<[u8]>> PskBinder<C> {
    /// The binder `binder`.
    ///
    /// # Errors
    ///
    /// [`LengthOutOfRangeError`] if `binder` is shorter than 32 or longer than
    /// 255 bytes.
    pub fn new(binder: C) -> Result<Self, LengthOutOfRangeError> {
        LengthOutOfRangeError::check(binder.as_ref().len(), 32..=Width::U8.max())?;
        Ok(Self { binder })
    }

    fn entry_len(&self) -> usize {
        1 + self.binder.as_ref().len()
    }
}

impl<C> PskBinder<C> {
    /// The binder.
    pub fn binder(&self) -> &C {
        &self.binder
    }
}

/// The index of the identity a server selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PskIndex(u16);

impl PskIndex {
    /// The index `index`.
    pub const fn new(index: u16) -> Self {
        Self(index)
    }

    /// The index.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// The identities a client offers, with one binder for each, in the same
/// order.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OfferedPsks<C> {
    identities: Vec<PskIdentity<C>>,
    binders: Vec<PskBinder<C>>,
}

impl<C: AsRef<[u8]>> OfferedPsks<C> {
    /// The offer of `identities` with `binders`.
    ///
    /// # Errors
    ///
    /// [`InvalidOfferedPsksError::CountMismatch`] if the counts differ, and
    /// [`InvalidOfferedPsksError::Length`] if there is no identity or the
    /// encoding is longer than the 65535 bytes of the extension.
    pub fn new(
        identities: Vec<PskIdentity<C>>,
        binders: Vec<PskBinder<C>>,
    ) -> Result<Self, InvalidOfferedPsksError> {
        PskCountMismatchError::check(identities.len(), binders.len())?;
        let offered = Self {
            identities,
            binders,
        };
        LengthOutOfRangeError::check(offered.encoded_len(), 44..=Width::U16.max())
            .context(invalid_offered_psks::LengthSnafu)?;
        Ok(offered)
    }

    /// The number of bytes [`codec::write_offered_psks`] writes.
    pub fn encoded_len(&self) -> usize {
        let identities: usize = self.identities.iter().map(PskIdentity::entry_len).sum();
        2 + identities + self.binders_len()
    }

    /// The number of bytes the binders take at the end of the encoding,
    /// their length field included: what a binder does not cover of a
    /// ClientHello whose last extension this is.
    pub fn binders_len(&self) -> usize {
        2 + self.binders.iter().map(PskBinder::entry_len).sum::<usize>()
    }
}

impl<C> OfferedPsks<C> {
    /// The identities, in the order offered.
    pub fn identities(&self) -> &[PskIdentity<C>] {
        &self.identities
    }

    /// The binders, one for each identity.
    pub fn binders(&self) -> &[PskBinder<C>] {
        &self.binders
    }
}

/// The counts of identities and binders differ.
///
/// It is constructed only when they differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("{identities} PSK identities with {binders} binders"))]
pub struct PskCountMismatchError {
    identities: usize,
    binders: usize,
}

impl PskCountMismatchError {
    /// The number of identities.
    pub const fn identities(self) -> usize {
        self.identities
    }

    /// The number of binders, never [`identities`](Self::identities).
    pub const fn binders(self) -> usize {
        self.binders
    }

    fn check(identities: usize, binders: usize) -> Result<(), Self> {
        if identities != binders {
            return Err(Self {
                identities,
                binders,
            });
        }
        Ok(())
    }
}

/// Failures of [`OfferedPsks::new`].
#[derive(Debug, Snafu)]
#[snafu(module(invalid_offered_psks), visibility(pub(crate)))]
pub enum InvalidOfferedPsksError {
    /// The counts differ.
    #[snafu(transparent)]
    CountMismatch {
        /// The counts.
        source: PskCountMismatchError,
    },
    /// There is no identity, or the encoding is too long.
    #[snafu(display("offered PSKs length out of range"))]
    Length {
        /// The broken range.
        source: LengthOutOfRangeError,
    },
}

pub mod codec {
    //! Reading and writing offered PSKs as `nitori_call` operations.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::{OfferedPsks, PskBinder, PskCountMismatchError, PskIdentity};
    use crate::{
        alert::AlertDescription,
        message::MessageSource,
        vector::{Out, ReadBoundedVectorError, read_bounded_vector, read_u32},
        width::Width,
    };
    use bytes::Buf;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{Write, calls::WriteAllError, error::Incomplete};
    use snafu::{ResultExt, Snafu};

    /// Reads the data of a `pre_shared_key` extension in a ClientHello.
    ///
    /// # Errors
    ///
    /// [`ReadOfferedPsksError`].
    #[call(sync)]
    pub async fn read_offered_psks<F: MessageSource, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<OfferedPsks<F::Bytes>, ReadOfferedPsksError> {
        use read_offered_psks_error::*;
        let mut list = read_bounded_vector(io, Width::U16, 7..=Width::U16.max())
            .await
            .context(IdentitiesSnafu)?;
        let mut identities = Vec::new();
        while list.has_remaining() {
            identities.push(list.sync_read_psk_identity_unpin()?);
        }
        let mut list = read_bounded_vector(io, Width::U16, 33..=Width::U16.max())
            .await
            .context(BindersSnafu)?;
        let mut binders = Vec::new();
        while list.has_remaining() {
            binders.push(list.sync_read_psk_binder_unpin()?);
        }
        PskCountMismatchError::check(identities.len(), binders.len())?;
        Ok(OfferedPsks {
            identities,
            binders,
        })
    }

    #[call(sync)]
    async fn read_psk_identity<F: MessageSource, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<PskIdentity<F::Bytes>, ReadOfferedPsksError> {
        use read_offered_psks_error::*;
        let identity = read_bounded_vector(io, Width::U16, 1..=Width::U16.max())
            .await
            .context(IdentitySnafu)?;
        let obfuscated_ticket_age = read_u32(io).await.context(TicketAgeSnafu)?;
        Ok(PskIdentity {
            identity,
            obfuscated_ticket_age,
        })
    }

    #[call(sync)]
    async fn read_psk_binder<F: MessageSource, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<PskBinder<F::Bytes>, ReadOfferedPsksError> {
        let binder = read_bounded_vector(io, Width::U8, 32..=Width::U8.max())
            .await
            .context(read_offered_psks_error::BinderSnafu)?;
        Ok(PskBinder { binder })
    }

    /// Failures that [`read_offered_psks`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_offered_psks_error), visibility(pub(crate)))]
    pub enum ReadOfferedPsksError {
        /// The list of identities could not be read.
        #[snafu(display("PSK identity list read failed"))]
        Identities {
            /// The failure of reading the list.
            source: ReadBoundedVectorError,
        },
        /// An identity could not be read.
        #[snafu(display("PSK identity read failed"))]
        Identity {
            /// The failure of reading the identity.
            source: ReadBoundedVectorError,
        },
        /// The obfuscated age of an identity could not be read.
        #[snafu(display("PSK ticket age read failed"))]
        TicketAge {
            /// The shortfall.
            source: Incomplete,
        },
        /// The list of binders could not be read.
        #[snafu(display("PSK binder list read failed"))]
        Binders {
            /// The failure of reading the list.
            source: ReadBoundedVectorError,
        },
        /// A binder could not be read.
        #[snafu(display("PSK binder read failed"))]
        Binder {
            /// The failure of reading the binder.
            source: ReadBoundedVectorError,
        },
        /// The counts of identities and binders differ.
        #[snafu(transparent)]
        CountMismatch {
            /// The counts.
            source: PskCountMismatchError,
        },
    }

    impl ReadOfferedPsksError {
        /// The alert the failure calls for: illegal_parameter for counts
        /// that differ, decode_error otherwise.
        pub fn alert(&self) -> AlertDescription {
            match self {
                Self::CountMismatch { .. } => AlertDescription::ILLEGAL_PARAMETER,
                _ => AlertDescription::DECODE_ERROR,
            }
        }
    }

    /// Writes the data of a `pre_shared_key` extension in a ClientHello.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails.
    #[call(sync)]
    pub async fn write_offered_psks<F: Write, A: ReceiverAccess<Family = F>, C: AsRef<[u8]>>(
        io: &mut A,
        offered: &OfferedPsks<C>,
    ) -> Result<(), WriteAllError<F::Error>> {
        offered.encode(&mut Out::new(io)).await
    }

    impl<C: AsRef<[u8]>> OfferedPsks<C> {
        pub(crate) async fn encode<F: Write, A: ReceiverAccess<Family = F>>(
            &self,
            out: &mut Out<'_, A>,
        ) -> Result<(), WriteAllError<F::Error>> {
            let identities: usize = self.identities.iter().map(PskIdentity::entry_len).sum();
            out.length(Width::U16, identities).await?;
            for identity in &self.identities {
                out.vector(Width::U16, identity.identity.as_ref()).await?;
                out.u32(identity.obfuscated_ticket_age).await?;
            }
            out.length(Width::U16, self.binders_len() - 2).await?;
            for binder in &self.binders {
                out.vector(Width::U8, binder.binder.as_ref()).await?;
            }
            Ok(())
        }
    }
}
