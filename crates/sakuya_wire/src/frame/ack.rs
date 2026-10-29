//! ACK frames ([RFC 9000 §19.3]).
//!
//! An ACK frame states the acknowledged packet numbers as inclusive ranges,
//! from the largest packet number down: each range lies below the previous
//! one and is separated from it by at least one unacknowledged packet number.
//! A frame that was read holds the ranges as [`AckRanges`]; a frame to write
//! takes any [`Clone`] iterator of ranges, so that its length can be computed
//! before it is written.
//!
//! [RFC 9000 §19.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3
use super::{type_value, type_var_int};
use crate::{packet_number::PacketNumber, var_int::VarInt};
use core::{iter::Cloned, ops::RangeInclusive, slice};
use snafu::Snafu;

/// An ACK frame ([RFC 9000 §19.3]).
///
/// `ranges` yields the acknowledged packet numbers as inclusive ranges,
/// largest first. A frame that was read holds [`AckRanges`]; to write, any
/// [`Clone`] iterator of such ranges can be used, for example
/// `ranges.iter().cloned()` over a slice of ranges.
///
/// [RFC 9000 §19.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack<R> {
    /// The ACK Delay field: the acknowledgment delay in microseconds, divided
    /// by 2 to the power of the sender's `ack_delay_exponent`.
    pub ack_delay: VarInt,
    /// The acknowledged ranges, largest first.
    pub ranges: R,
    /// The ECN counts; present in type `0x03`.
    pub ecn_counts: Option<EcnCounts>,
}

/// The ECN counts of an ACK frame of type `0x03` ([RFC 9000 §19.3.2]).
///
/// [RFC 9000 §19.3.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3.2
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct EcnCounts {
    /// ECT0 Count: packets received with the ECT(0) codepoint.
    pub ect0: VarInt,
    /// ECT1 Count: packets received with the ECT(1) codepoint.
    pub ect1: VarInt,
    /// ECN-CE Count: packets received with the ECN-CE codepoint.
    pub ce: VarInt,
}

/// The iterator over the ranges of [`AckRanges`].
pub type AckRangeIter<'a> = Cloned<slice::Iter<'a, RangeInclusive<PacketNumber>>>;

impl<R: Iterator<Item = RangeInclusive<PacketNumber>> + Clone> Ack<R> {
    /// The largest acknowledged packet number: the end of the first range.
    pub fn largest_acknowledged(&self) -> Option<PacketNumber> {
        self.ranges.clone().next().map(|range| *range.end())
    }

    /// The Frame Type value [`codec::write_ack`] writes: `0x03` with ECN
    /// counts, `0x02` without.
    pub fn type_value(&self) -> VarInt {
        type_var_int(if self.ecn_counts.is_some() {
            type_value::ACK_ECN
        } else {
            type_value::ACK
        })
    }

    /// The number of bytes [`codec::write_ack`] writes.
    ///
    /// Iterates over a clone of the ranges. For ranges that
    /// [`Ack::validate`] rejects, the value has no meaning.
    pub fn encoded_len(&self) -> usize {
        self.values().map(VarInt::encoded_len).sum()
    }

    /// Checks that there is at least one range and that the ranges are
    /// ordered as the encoding requires.
    ///
    /// # Errors
    ///
    /// [`InvalidAckError::NoRange`] without ranges, and
    /// [`InvalidAckError::Range`] for the first range that is empty or does
    /// not lie below the previous range with at least one packet number
    /// between them.
    pub fn validate(&self) -> Result<(), InvalidAckError> {
        let mut ranges = self.ranges.clone();
        let Some(first) = ranges.next() else {
            return Err(InvalidAckError::NoRange);
        };
        if first.start() > first.end() {
            return Err(InvalidAckError::Range { index: 0 });
        }
        let mut smallest = *first.start();
        for (index, range) in (1..).zip(ranges) {
            let below = range
                .end()
                .checked_add(2)
                .is_some_and(|limit| limit <= smallest);
            if range.start() > range.end() || !below {
                return Err(InvalidAckError::Range { index });
            }
            smallest = *range.start();
        }
        Ok(())
    }

    /// The values of the encoding, in order, each a variable-length integer:
    /// Frame Type, Largest Acknowledged, ACK Delay, ACK Range Count, First
    /// ACK Range, the Gap and ACK Range Length pairs, and the ECN counts.
    pub(crate) fn values(&self) -> impl Iterator<Item = VarInt> + Clone + use<R> {
        let mut ranges = self.ranges.clone();
        let first = ranges.next();
        let count = ranges.clone().count();
        let (largest, first_len, first_start) = first.map_or((0, 0, 0), |range| {
            let (start, end) = range.into_inner();
            (
                end.get(),
                end.get().saturating_sub(start.get()),
                start.get(),
            )
        });
        let prefix = [
            self.type_value().get(),
            largest,
            self.ack_delay.get(),
            count as u64,
            first_len,
        ];
        let pairs = ranges
            .scan(first_start, |smallest, range| {
                let (start, end) = range.into_inner();
                let gap = smallest.saturating_sub(end.get()).saturating_sub(2);
                *smallest = start.get();
                Some([gap, end.get().saturating_sub(start.get())])
            })
            .flatten();
        let ecn = self
            .ecn_counts
            .map(|counts| [counts.ect0.get(), counts.ect1.get(), counts.ce.get()])
            .into_iter()
            .flatten();
        // Every value is a packet number, a difference of packet numbers, a
        // count of at most `usize::MAX` ranges, or a variable-length integer.
        prefix
            .into_iter()
            .chain(pairs)
            .chain(ecn)
            .map(|value| VarInt::new(value).unwrap_or(VarInt::MAX))
    }
}

impl Ack<AckRanges> {
    /// The largest acknowledged packet number: the end of the first range.
    pub fn largest_acknowledged(&self) -> PacketNumber {
        self.ranges.largest()
    }

    /// The Frame Type value [`codec::write_frame`](super::codec::write_frame)
    /// writes: `0x03` with ECN counts, `0x02` without.
    pub fn type_value(&self) -> VarInt {
        self.as_iter().type_value()
    }

    /// The number of bytes [`codec::write_frame`](super::codec::write_frame)
    /// writes.
    pub fn encoded_len(&self) -> usize {
        self.as_iter().encoded_len()
    }

    /// Checks the ranges as [`Ack::validate`] does for an iterator; ranges
    /// that were read always pass.
    ///
    /// # Errors
    ///
    /// [`InvalidAckError`] for ranges that break the order of the encoding.
    pub fn validate(&self) -> Result<(), InvalidAckError> {
        self.as_iter().validate()
    }

    /// The same frame with its ranges as an iterator, as
    /// [`codec::write_ack`] takes it.
    pub fn as_iter(&self) -> Ack<AckRangeIter<'_>> {
        Ack {
            ack_delay: self.ack_delay,
            ranges: self.ranges.iter(),
            ecn_counts: self.ecn_counts,
        }
    }
}

/// The ranges of an ACK frame that was read, largest first.
///
/// Each item is the inclusive range of packet numbers that one ACK Range
/// acknowledges, restored from the Largest Acknowledged, First ACK Range and
/// Gap fields. There is at least one range, and each lies below the previous
/// one with at least one packet number between them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AckRanges {
    ranges: Vec<RangeInclusive<PacketNumber>>,
}

impl AckRanges {
    /// The ranges, largest first.
    pub fn iter(&self) -> AckRangeIter<'_> {
        self.ranges.iter().cloned()
    }

    /// The ranges, largest first, as a slice.
    pub fn as_slice(&self) -> &[RangeInclusive<PacketNumber>] {
        &self.ranges
    }

    /// The number of ranges, at least one.
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// Whether there are no ranges; never true for ranges that were read.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The largest acknowledged packet number.
    pub fn largest(&self) -> PacketNumber {
        self.ranges
            .first()
            .map_or(PacketNumber::ZERO, |range| *range.end())
    }
}

impl<'a> IntoIterator for &'a AckRanges {
    type Item = RangeInclusive<PacketNumber>;
    type IntoIter = AckRangeIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// An ACK frame to write breaks a limit of the encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum InvalidAckError {
    /// The frame has no range.
    #[snafu(display("ACK frame has no range"))]
    NoRange,
    /// A range is empty, or does not lie below the previous range with at
    /// least one packet number between them.
    #[snafu(display("ACK range {index} is empty or out of order"))]
    Range {
        /// The position of the range: 0 for the first.
        index: usize,
    },
}

pub mod codec {
    //! Writing ACK frames as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_ack`] is also the operation struct [`WriteAck`], with
    //! `WriteAckExt` on receiver accesses and `WriteAckHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::{Ack, AckRanges, EcnCounts, InvalidAckError};
    use crate::{
        packet_number::PacketNumber,
        var_int::{
            VarInt,
            codec::{ReadVarIntError, ReadVarIntExt as _},
        },
    };
    use bytes::Buf;
    use core::ops::RangeInclusive;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type of an ACK frame, with ECN
    /// counts if `ecn_counts` is set.
    pub(crate) async fn read_ack<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        ecn_counts: bool,
    ) -> Result<Ack<AckRanges>, ReadAckError<F::Error>> {
        let largest = PacketNumber::from_var_int(field(io).await?);
        let ack_delay = field(io).await?;
        let count = field(io).await?.get();
        let below_zero = |index| read_ack_error::RangeSnafu { index }.build();
        let mut smallest = largest
            .checked_sub(field(io).await?.get())
            .ok_or_else(|| below_zero(0))?;
        // The count is not trusted for the allocation; each range is read
        // before it is stored.
        let mut ranges = Vec::with_capacity(1 + count.min(16) as usize);
        ranges.push(smallest..=largest);
        for index in 1..=count {
            let gap = field(io).await?.get();
            let length = field(io).await?.get();
            let range_largest = smallest
                .checked_sub(gap)
                .and_then(|value| value.checked_sub(2))
                .ok_or_else(|| below_zero(index))?;
            smallest = range_largest
                .checked_sub(length)
                .ok_or_else(|| below_zero(index))?;
            ranges.push(smallest..=range_largest);
        }
        let ecn_counts = if ecn_counts {
            Some(EcnCounts {
                ect0: field(io).await?,
                ect1: field(io).await?,
                ce: field(io).await?,
            })
        } else {
            None
        };
        Ok(Ack {
            ack_delay,
            ranges: AckRanges { ranges },
            ecn_counts,
        })
    }

    async fn field<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<VarInt, ReadAckError<F::Error>> {
        io.read_var_int().await.context(read_ack_error::FieldSnafu)
    }

    /// Failures of reading an ACK frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_ack_error), visibility(pub(crate)))]
    pub enum ReadAckError<E> {
        /// A field could not be read.
        #[snafu(display("ACK field read failed"))]
        Field {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// An ACK range extends below packet number 0.
        #[snafu(display("ACK range {index} extends below packet number 0"))]
        Range {
            /// The position of the range: 0 for the First ACK Range.
            index: u64,
        },
    }

    /// Writes `frame`, after checking it with [`Ack::validate`].
    ///
    /// Iterates over clones of the ranges.
    ///
    /// # Errors
    ///
    /// [`WriteAckError::Invalid`] before writing anything, and
    /// [`WriteAckError::Write`] if the receiver stops accepting bytes or
    /// fails; bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_ack<F, A, R>(
        io: &mut A,
        frame: Ack<R>,
    ) -> Result<(), WriteAckError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
        R: Iterator<Item = RangeInclusive<PacketNumber>> + Clone,
    {
        frame.validate()?;
        write_body(io, &frame)
            .await
            .context(write_ack_error::WriteSnafu)
    }

    /// Writes a frame that has been checked.
    pub(crate) async fn write_body<F, A, R>(
        io: &mut A,
        frame: &Ack<R>,
    ) -> Result<(), WriteAllError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
        R: Iterator<Item = RangeInclusive<PacketNumber>> + Clone,
    {
        io.write_all(VarInts::new(frame.values())).await
    }

    /// Failures that [`write_ack`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(write_ack_error), visibility(pub(crate)))]
    pub enum WriteAckError<E> {
        /// The frame breaks a limit of the encoding; nothing was written.
        #[snafu(transparent)]
        Invalid {
            /// The broken limit.
            source: InvalidAckError,
        },
        /// The receiver stopped accepting bytes or failed.
        #[snafu(display("ACK write failed"))]
        Write {
            /// The failure of writing.
            source: WriteAllError<E>,
        },
    }

    /// The encodings of a sequence of variable-length integers as one
    /// buffer.
    struct VarInts<I> {
        current: [u8; VarInt::MAX_ENCODED_LEN],
        position: usize,
        current_len: usize,
        values: I,
        remaining: usize,
    }

    impl<I: Iterator<Item = VarInt> + Clone> VarInts<I> {
        fn new(values: I) -> Self {
            let remaining = values.clone().map(VarInt::encoded_len).sum();
            let mut buffer = Self {
                current: [0; VarInt::MAX_ENCODED_LEN],
                position: 0,
                current_len: 0,
                values,
                remaining,
            };
            buffer.load();
            buffer
        }

        /// Moves to the next value once the current one is consumed.
        fn load(&mut self) {
            while self.position == self.current_len {
                let Some(value) = self.values.next() else {
                    return;
                };
                (self.current, self.current_len) = value.to_encoding();
                self.position = 0;
            }
        }
    }

    impl<I: Iterator<Item = VarInt> + Clone> Buf for VarInts<I> {
        fn remaining(&self) -> usize {
            self.remaining
        }

        fn chunk(&self) -> &[u8] {
            &self.current[self.position..self.current_len]
        }

        fn advance(&mut self, mut count: usize) {
            count = count.min(self.remaining);
            self.remaining -= count;
            while count > 0 {
                let step = count.min(self.current_len - self.position);
                if step == 0 {
                    // `remaining` counts every byte of every value, so the
                    // values do not run out before `count` does.
                    break;
                }
                self.position += step;
                count -= step;
                self.load();
            }
        }
    }
}

#[cfg(test)]
mod tests;
