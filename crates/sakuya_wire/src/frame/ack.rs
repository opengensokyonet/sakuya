//! ACK frames ([RFC 9000 §19.3]).
//!
//! An ACK frame acknowledges packet numbers as inclusive ranges, from the
//! largest packet number down. Its fields state them relative to one
//! another: Largest Acknowledged and First ACK Range give the first range,
//! and each following ACK Range gives a Gap of unacknowledged packet numbers
//! below the previous range and the length of the next one.
//!
//! [`Ack`] holds these fields as they are encoded, each variable-length
//! integer with its width, so that a frame reads back as it was written and
//! writes back the bytes it was read from. [`Ack::packet_ranges`] computes
//! the packet number ranges from them, as an iterator.
//! [`Ack::from_packet_ranges`] goes the other way for a sender: it states
//! any [`Clone`] iterator of packet number ranges in the shortest encodings,
//! without collecting them.
//!
//! [RFC 9000 §19.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3
use super::{type_value, type_var_int};
use crate::{
    packet_number::PacketNumber,
    var_int::{VarInt, VarIntField, VarIntWidth},
};
use core::{
    iter::{Copied, FusedIterator},
    ops::RangeInclusive,
    slice,
};
use snafu::Snafu;

/// An ACK frame ([RFC 9000 §19.3]): type `0x02`, or `0x03` with ECN counts.
///
/// The fields are those of the encoding, each variable-length integer with
/// its width. `ranges` yields the [`AckRange`]s that follow First ACK Range,
/// in order; the ACK Range Count field holds their number, so only its width
/// is stored. A frame that was read holds [`AckRanges`]; to write, any
/// [`Clone`] iterator of ACK Ranges can be used, such as the one
/// [`Ack::from_packet_ranges`] builds.
///
/// [RFC 9000 §19.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack<R> {
    /// The Largest Acknowledged field: the largest packet number the frame
    /// acknowledges.
    pub largest_acknowledged: VarIntField<PacketNumber>,
    /// The ACK Delay field: the acknowledgment delay in microseconds, divided
    /// by 2 to the power of the sender's `ack_delay_exponent`.
    pub ack_delay: VarIntField<VarInt>,
    /// The width of the ACK Range Count field, which holds the number of
    /// items of `ranges`.
    pub ack_range_count_width: VarIntWidth,
    /// The First ACK Range field: how many packet numbers below Largest
    /// Acknowledged the first range also acknowledges.
    pub first_ack_range: VarIntField<VarInt>,
    /// The ACK Ranges after the first range, in order.
    pub ranges: R,
    /// The ECN counts; present in type `0x03`.
    pub ecn_counts: Option<EcnCounts>,
}

/// One ACK Range of an ACK frame ([RFC 9000 §19.3.1]): a gap of
/// unacknowledged packet numbers, then a range of acknowledged ones, below
/// the previous range.
///
/// [RFC 9000 §19.3.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3.1
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AckRange {
    /// The Gap field: the number of unacknowledged packet numbers between
    /// the previous range and this one, minus one.
    pub gap: VarIntField<VarInt>,
    /// The ACK Range Length field: how many packet numbers below the largest
    /// one of this range the range also acknowledges.
    pub ack_range_length: VarIntField<VarInt>,
}

/// The ECN counts of an ACK frame of type `0x03` ([RFC 9000 §19.3.2]).
///
/// [RFC 9000 §19.3.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EcnCounts {
    /// ECT0 Count: packets received with the ECT(0) codepoint.
    pub ect0: VarIntField<VarInt>,
    /// ECT1 Count: packets received with the ECT(1) codepoint.
    pub ect1: VarIntField<VarInt>,
    /// ECN-CE Count: packets received with the ECN-CE codepoint.
    pub ce: VarIntField<VarInt>,
}

/// The iterator over the ACK Ranges of [`AckRanges`].
pub type AckRangeIter<'a> = Copied<slice::Iter<'a, AckRange>>;

impl<R> Ack<R> {
    /// The Frame Type value: `0x03` with ECN counts, `0x02` without.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(if self.ecn_counts.is_some() {
            type_value::ACK_ECN
        } else {
            type_value::ACK
        })
    }
}

impl<R: Iterator<Item = AckRange> + Clone> Ack<R> {
    /// The acknowledged packet numbers as inclusive ranges, largest first,
    /// computed from the fields.
    ///
    /// Iterates over a clone of the ACK Ranges. For a frame that
    /// [`Ack::validate`] rejects because a range extends below packet number
    /// 0, the iteration ends before that range.
    pub fn packet_ranges(&self) -> PacketRanges<R> {
        PacketRanges::new(
            self.largest_acknowledged.get(),
            self.first_ack_range.get(),
            self.ranges.clone(),
        )
    }

    /// The number of bytes [`codec::write_ack`] writes.
    ///
    /// Iterates over a clone of the ACK Ranges.
    pub fn encoded_len(&self) -> usize {
        self.fields().map(|(_, width)| width.encoded_len()).sum()
    }

    /// Checks that no range extends below packet number 0 and that the ACK
    /// Range Count field can hold the number of ACK Ranges.
    ///
    /// # Errors
    ///
    /// [`InvalidAckError::BelowZero`] for the first range that extends below
    /// packet number 0, and [`InvalidAckError::RangeCount`] if the number of
    /// ACK Ranges does not fit the width of the ACK Range Count field.
    pub fn validate(&self) -> Result<(), InvalidAckError> {
        let count = self.ranges.clone().count();
        let width = self.ack_range_count_width;
        if !VarInt::try_from(count).is_ok_and(|count| width.fits(count)) {
            return Err(InvalidAckError::RangeCount { count, width });
        }
        // The packet ranges end early at the first range below zero.
        let reached = self.packet_ranges().count();
        if reached != count + 1 {
            return Err(InvalidAckError::BelowZero { index: reached });
        }
        Ok(())
    }

    /// The fields of the encoding, in order, each a variable-length integer
    /// with its width: Frame Type, Largest Acknowledged, ACK Delay, ACK Range
    /// Count, First ACK Range, the Gap and ACK Range Length of each ACK
    /// Range, and the ECN counts.
    pub(crate) fn fields(&self) -> impl Iterator<Item = (VarInt, VarIntWidth)> + Clone + use<R> {
        fn pair<T: Copy + Into<VarInt> + TryFrom<VarInt>>(
            field: VarIntField<T>,
        ) -> (VarInt, VarIntWidth) {
            (field.to_var_int(), field.width())
        }
        let type_value = self.type_value();
        // A count that validation rejects is never encoded.
        let count = VarInt::try_from(self.ranges.clone().count()).unwrap_or(VarInt::MAX);
        let prefix = [
            (type_value, VarIntWidth::shortest(type_value)),
            pair(self.largest_acknowledged),
            pair(self.ack_delay),
            (count, self.ack_range_count_width),
            pair(self.first_ack_range),
        ];
        let ranges = self
            .ranges
            .clone()
            .flat_map(|range| [pair(range.gap), pair(range.ack_range_length)]);
        let ecn = self
            .ecn_counts
            .into_iter()
            .flat_map(|counts| [pair(counts.ect0), pair(counts.ect1), pair(counts.ce)]);
        prefix.into_iter().chain(ranges).chain(ecn)
    }
}

impl Ack<AckRanges> {
    /// The acknowledged packet numbers as inclusive ranges, largest first, as
    /// [`Ack::packet_ranges`] computes them for an iterator.
    pub fn packet_ranges(&self) -> PacketRanges<AckRangeIter<'_>> {
        self.as_iter().packet_ranges()
    }

    /// The number of bytes [`codec::write_frame`](super::codec::write_frame)
    /// writes.
    pub fn encoded_len(&self) -> usize {
        self.as_iter().encoded_len()
    }

    /// Checks the frame as [`Ack::validate`] does for an iterator; a frame
    /// that was read always passes.
    ///
    /// # Errors
    ///
    /// [`InvalidAckError`] for the broken rule.
    pub fn validate(&self) -> Result<(), InvalidAckError> {
        self.as_iter().validate()
    }

    /// The same frame with its ACK Ranges as an iterator, as
    /// [`codec::write_ack`] takes it.
    pub fn as_iter(&self) -> Ack<AckRangeIter<'_>> {
        Ack {
            largest_acknowledged: self.largest_acknowledged,
            ack_delay: self.ack_delay,
            ack_range_count_width: self.ack_range_count_width,
            first_ack_range: self.first_ack_range,
            ranges: self.ranges.iter(),
            ecn_counts: self.ecn_counts,
        }
    }
}

impl<I: Iterator<Item = RangeInclusive<PacketNumber>> + Clone> Ack<FromPacketRanges<I>> {
    /// The ACK frame that acknowledges `ranges`, with `ack_delay` and
    /// `ecn_counts` as given and every field derived from the ranges in its
    /// shortest encoding.
    ///
    /// `ranges` yields inclusive ranges of packet numbers, largest first:
    /// each range lies below the previous one with at least one packet
    /// number between them. It is iterated over once here to check this and
    /// count the ranges, and again, through clones, whenever the frame is
    /// measured or written; nothing is collected.
    ///
    /// # Errors
    ///
    /// [`PacketRangesError::NoRange`] without ranges, and
    /// [`PacketRangesError::Range`] for the first range that is empty or does
    /// not lie below the previous one with at least one packet number between
    /// them.
    pub fn from_packet_ranges(
        mut ranges: I,
        ack_delay: VarIntField<VarInt>,
        ecn_counts: Option<EcnCounts>,
    ) -> Result<Self, PacketRangesError> {
        let Some(first) = ranges.next() else {
            return Err(PacketRangesError::NoRange);
        };
        let (smallest, largest) = first.into_inner();
        if smallest > largest {
            return Err(PacketRangesError::Range { index: 0 });
        }
        let mut previous = smallest;
        let mut count = 0usize;
        for (index, range) in (1..).zip(ranges.clone()) {
            let below = range
                .end()
                .checked_add(2)
                .is_some_and(|limit| limit <= previous);
            if range.start() > range.end() || !below {
                return Err(PacketRangesError::Range { index });
            }
            previous = *range.start();
            count += 1;
        }
        // `count` is at most `usize::MAX`; a count above 2^62 - 1 could not
        // be iterated over.
        let count = VarInt::try_from(count).unwrap_or(VarInt::MAX);
        // The first range was checked to be ordered.
        let first_ack_range = largest
            .to_var_int()
            .checked_sub(smallest.to_var_int())
            .unwrap_or(VarInt::ZERO);
        Ok(Self {
            largest_acknowledged: VarIntField::shortest(largest),
            ack_delay,
            ack_range_count_width: VarIntWidth::shortest(count),
            first_ack_range: VarIntField::shortest(first_ack_range),
            ranges: FromPacketRanges { ranges, smallest },
            ecn_counts,
        })
    }
}

/// The ACK Ranges of an ACK frame that was read: the ranges after the first
/// one, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct AckRanges {
    ranges: Vec<AckRange>,
}

impl AckRanges {
    /// The ACK Ranges, in order.
    pub fn iter(&self) -> AckRangeIter<'_> {
        self.ranges.iter().copied()
    }

    /// The ACK Ranges, in order, as a slice.
    pub fn as_slice(&self) -> &[AckRange] {
        &self.ranges
    }

    /// The number of ACK Ranges: the value of the ACK Range Count field.
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// Whether there is no ACK Range after the first range.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

impl From<Vec<AckRange>> for AckRanges {
    fn from(ranges: Vec<AckRange>) -> Self {
        Self { ranges }
    }
}

impl FromIterator<AckRange> for AckRanges {
    fn from_iter<T: IntoIterator<Item = AckRange>>(ranges: T) -> Self {
        Self {
            ranges: ranges.into_iter().collect(),
        }
    }
}

impl<'a> IntoIterator for &'a AckRanges {
    type Item = AckRange;
    type IntoIter = AckRangeIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// The packet number ranges that the fields of an ACK frame acknowledge,
/// largest first; see [`Ack::packet_ranges`].
#[derive(Clone, Debug)]
pub struct PacketRanges<R> {
    ranges: R,
    state: PacketRangesState,
}

/// Where [`PacketRanges`] stands.
#[derive(Clone, Debug)]
enum PacketRangesState {
    /// The first range is next.
    First(RangeInclusive<PacketNumber>),
    /// The next ACK Range lies below this smallest packet number of the
    /// previous range.
    Below(PacketNumber),
    /// The ranges ended, or the next one would extend below packet number 0.
    Done,
}

impl<R> PacketRanges<R> {
    fn new(largest: PacketNumber, first_ack_range: VarInt, ranges: R) -> Self {
        let state = match largest.checked_sub(first_ack_range.get()) {
            Some(smallest) => PacketRangesState::First(smallest..=largest),
            None => PacketRangesState::Done,
        };
        Self { ranges, state }
    }
}

impl<R: Iterator<Item = AckRange>> Iterator for PacketRanges<R> {
    type Item = RangeInclusive<PacketNumber>;

    fn next(&mut self) -> Option<Self::Item> {
        match core::mem::replace(&mut self.state, PacketRangesState::Done) {
            PacketRangesState::First(range) => {
                self.state = PacketRangesState::Below(*range.start());
                Some(range)
            }
            PacketRangesState::Below(previous) => {
                let range = self.ranges.next()?;
                let largest = previous
                    .checked_sub(range.gap.get().get())?
                    .checked_sub(2)?;
                let smallest = largest.checked_sub(range.ack_range_length.get().get())?;
                self.state = PacketRangesState::Below(smallest);
                Some(smallest..=largest)
            }
            PacketRangesState::Done => None,
        }
    }
}

impl<R: Iterator<Item = AckRange>> FusedIterator for PacketRanges<R> {}

/// The ACK Ranges of [`Ack::from_packet_ranges`]: each packet number range
/// after the first, stated as a Gap and an ACK Range Length in their
/// shortest encodings.
#[derive(Clone, Debug)]
pub struct FromPacketRanges<I> {
    ranges: I,
    /// The smallest packet number of the previous range.
    smallest: PacketNumber,
}

impl<I: Iterator<Item = RangeInclusive<PacketNumber>>> Iterator for FromPacketRanges<I> {
    type Item = AckRange;

    fn next(&mut self) -> Option<Self::Item> {
        let (start, end) = self.ranges.next()?.into_inner();
        // The construction checked that each range is ordered and lies at
        // least two below the smallest packet number of the previous one.
        let gap = self
            .smallest
            .to_var_int()
            .saturating_sub(end.to_var_int())
            .saturating_sub(VarInt::from(2u8));
        let ack_range_length = end.to_var_int().saturating_sub(start.to_var_int());
        self.smallest = start;
        Some(AckRange {
            gap: VarIntField::shortest(gap),
            ack_range_length: VarIntField::shortest(ack_range_length),
        })
    }
}

/// An ACK frame to write breaks a rule of the encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum InvalidAckError {
    /// A range extends below packet number 0.
    #[snafu(display("ACK range {index} extends below packet number 0"))]
    BelowZero {
        /// The position of the range: 0 for the range of First ACK Range,
        /// `n` for the `n`-th ACK Range.
        index: usize,
    },
    /// The ACK Range Count field cannot hold the number of ACK Ranges.
    #[snafu(display(
        "{count} ACK ranges do not fit a {}-byte ACK Range Count field",
        width.encoded_len()
    ))]
    RangeCount {
        /// The number of ACK Ranges.
        count: usize,
        /// The width of the ACK Range Count field.
        width: VarIntWidth,
    },
}

/// The packet number ranges given to [`Ack::from_packet_ranges`] cannot be
/// acknowledged by one ACK frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum PacketRangesError {
    /// There is no range.
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

    use super::{Ack, AckRange, AckRanges, EcnCounts, InvalidAckError};
    use crate::{
        frame::read_field,
        packet_number::PacketNumber,
        var_int::{VarInt, VarIntField, VarIntWidth, codec::ReadVarIntError},
    };
    use bytes::Buf;
    use core::convert::Infallible;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type of an ACK frame, with ECN
    /// counts if `ecn_counts` is set.
    pub(crate) async fn read_ack<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        ecn_counts: bool,
    ) -> Result<Ack<AckRanges>, ReadAckError<F::Error>> {
        let largest_acknowledged: VarIntField<PacketNumber> = field(io).await?;
        let ack_delay = field(io).await?;
        let count: VarIntField<VarInt> = field(io).await?;
        let first_ack_range: VarIntField<VarInt> = field(io).await?;
        let below_zero = |index| read_ack_error::RangeSnafu { index }.build();
        let mut smallest = largest_acknowledged
            .get()
            .checked_sub(first_ack_range.get().get())
            .ok_or_else(|| below_zero(0))?;
        // The count is not trusted for the allocation; each range is read
        // before it is stored.
        let count_value = count.get().get();
        let mut ranges = Vec::with_capacity(count_value.min(16) as usize);
        for index in 1..=count_value {
            let gap: VarIntField<VarInt> = field(io).await?;
            let ack_range_length: VarIntField<VarInt> = field(io).await?;
            let range_largest = smallest
                .checked_sub(gap.get().get())
                .and_then(|value| value.checked_sub(2))
                .ok_or_else(|| below_zero(index))?;
            smallest = range_largest
                .checked_sub(ack_range_length.get().get())
                .ok_or_else(|| below_zero(index))?;
            ranges.push(AckRange {
                gap,
                ack_range_length,
            });
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
            largest_acknowledged,
            ack_delay,
            ack_range_count_width: count.width(),
            first_ack_range,
            ranges: AckRanges { ranges },
            ecn_counts,
        })
    }

    async fn field<T, F, A>(io: &mut A) -> Result<VarIntField<T>, ReadAckError<F::Error>>
    where
        T: Copy + Into<VarInt> + TryFrom<VarInt, Error = Infallible>,
        F: Read,
        A: ReceiverAccess<Family = F>,
    {
        read_field(io).await.context(read_ack_error::FieldSnafu)
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
    /// Iterates over clones of the ACK Ranges.
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
        R: Iterator<Item = AckRange> + Clone,
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
        R: Iterator<Item = AckRange> + Clone,
    {
        io.write_all(VarInts::new(frame.fields())).await
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

    /// The encodings of a sequence of variable-length integers, each of its
    /// width, as one buffer.
    struct VarInts<I> {
        current: [u8; VarInt::MAX_ENCODED_LEN],
        position: usize,
        current_len: usize,
        values: I,
        remaining: usize,
    }

    impl<I: Iterator<Item = (VarInt, VarIntWidth)> + Clone> VarInts<I> {
        fn new(values: I) -> Self {
            let remaining = values.clone().map(|(_, width)| width.encoded_len()).sum();
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
                let Some((value, width)) = self.values.next() else {
                    return;
                };
                (self.current, self.current_len) = value.to_encoding_of(width);
                self.position = 0;
            }
        }
    }

    impl<I: Iterator<Item = (VarInt, VarIntWidth)> + Clone> Buf for VarInts<I> {
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
