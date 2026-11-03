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
//! writes back the bytes it was read from; the ACK Ranges are collected in
//! [`AckRanges`]. [`Ack::new`] checks that no range extends below packet
//! number 0 and that the ACK Range Count field can state the number of ACK
//! Ranges. [`Ack::packet_ranges`] computes the packet number ranges from the
//! fields, as an iterator. [`Ack::from_packet_ranges`] goes the other way
//! for a sender: it states packet number ranges in the shortest encodings.
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
/// its width. [`ranges`](Self::ranges) holds the [`AckRange`]s that follow
/// First ACK Range, in order; the ACK Range Count field holds their number,
/// so only its width is stored.
///
/// No range extends below packet number 0, and the ACK Range Count field can
/// state the number of ACK Ranges. [`Ack::new`] checks both, so every value
/// writes an encoding that reads back to the same value; the fields are read
/// through methods of the same names.
///
/// [RFC 9000 §19.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.3
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ack {
    largest_acknowledged: VarIntField<PacketNumber>,
    ack_delay: VarIntField<VarInt>,
    ack_range_count_width: VarIntWidth,
    first_ack_range: VarIntField<VarInt>,
    ranges: AckRanges,
    ecn_counts: Option<EcnCounts>,
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

impl Ack {
    /// The ACK frame with these fields.
    ///
    /// # Errors
    ///
    /// [`InvalidAckError::RangeCount`] if the number of ACK Ranges does not
    /// fit the width of the ACK Range Count field, and
    /// [`InvalidAckError::BelowZero`] for the first range that extends below
    /// packet number 0.
    pub fn new(
        largest_acknowledged: VarIntField<PacketNumber>,
        ack_delay: VarIntField<VarInt>,
        ack_range_count_width: VarIntWidth,
        first_ack_range: VarIntField<VarInt>,
        ranges: AckRanges,
        ecn_counts: Option<EcnCounts>,
    ) -> Result<Self, InvalidAckError> {
        let count = ranges.len();
        if !VarInt::try_from(count).is_ok_and(|value| ack_range_count_width.fits(value)) {
            return Err(InvalidAckError::RangeCount {
                count,
                width: ack_range_count_width,
            });
        }
        let mut smallest =
            AckBelowZeroError::check_first(largest_acknowledged.get(), first_ack_range.get())?;
        for (index, range) in (1..).zip(ranges.iter()) {
            smallest = AckBelowZeroError::check_next(smallest, range, index)?;
        }
        Ok(Self {
            largest_acknowledged,
            ack_delay,
            ack_range_count_width,
            first_ack_range,
            ranges,
            ecn_counts,
        })
    }

    /// The ACK frame that acknowledges `ranges`, with `ack_delay` and
    /// `ecn_counts` as given and every field derived from the ranges in its
    /// shortest encoding.
    ///
    /// `ranges` yields inclusive ranges of packet numbers, largest first:
    /// each range lies below the previous one with at least one packet
    /// number between them. It is iterated over once, to check this and to
    /// collect the Gap and ACK Range Length of each range after the first
    /// into [`AckRanges`].
    ///
    /// # Errors
    ///
    /// [`PacketRangesError::NoRanges`] without ranges,
    /// [`PacketRangesError::EmptyRange`] for the first range that is empty,
    /// and [`PacketRangesError::NotBelowPrevious`] for the first range that
    /// does not lie below the previous one with at least one packet number
    /// between them.
    pub fn from_packet_ranges<I>(
        ranges: I,
        ack_delay: VarIntField<VarInt>,
        ecn_counts: Option<EcnCounts>,
    ) -> Result<Self, PacketRangesError>
    where
        I: IntoIterator<Item = RangeInclusive<PacketNumber>>,
    {
        let mut ranges = ranges.into_iter();
        let Some(first) = ranges.next() else {
            return Err(PacketRangesError::NoRanges);
        };
        let (smallest, largest) = first.into_inner();
        if smallest > largest {
            return Err(PacketRangesError::EmptyRange { index: 0 });
        }
        let mut previous = smallest;
        let mut ack_ranges = Vec::new();
        for (index, range) in (1..).zip(ranges) {
            let (start, end) = range.into_inner();
            if start > end {
                return Err(PacketRangesError::EmptyRange { index });
            }
            if !end.checked_add(2).is_some_and(|limit| limit <= previous) {
                return Err(PacketRangesError::NotBelowPrevious { index });
            }
            // The range is ordered and lies at least two below the smallest
            // packet number of the previous one, so nothing saturates.
            let gap = previous
                .to_var_int()
                .saturating_sub(end.to_var_int())
                .saturating_sub(VarInt::from(2u8));
            let ack_range_length = end.to_var_int().saturating_sub(start.to_var_int());
            ack_ranges.push(AckRange {
                gap: VarIntField::shortest(gap),
                ack_range_length: VarIntField::shortest(ack_range_length),
            });
            previous = start;
        }
        // The first range was checked to be ordered.
        let first_ack_range = largest.to_var_int().saturating_sub(smallest.to_var_int());
        // A count above 2^62 - 1 could not be held in memory.
        let count = VarInt::try_from(ack_ranges.len()).unwrap_or(VarInt::MAX);
        let frame = Self::new(
            VarIntField::shortest(largest),
            ack_delay,
            VarIntWidth::shortest(count),
            VarIntField::shortest(first_ack_range),
            AckRanges { ranges: ack_ranges },
            ecn_counts,
        );
        // invariant: the ranges were checked to be ordered and separated, so
        // none extends below packet number 0, and the ACK Range Count field
        // has the shortest width for the count.
        Ok(frame.unwrap_or_else(|error| unreachable!("{error}")))
    }

    /// The Largest Acknowledged field: the largest packet number the frame
    /// acknowledges.
    pub const fn largest_acknowledged(&self) -> VarIntField<PacketNumber> {
        self.largest_acknowledged
    }

    /// The ACK Delay field: the acknowledgment delay in microseconds, divided
    /// by 2 to the power of the sender's `ack_delay_exponent`.
    pub const fn ack_delay(&self) -> VarIntField<VarInt> {
        self.ack_delay
    }

    /// The width of the ACK Range Count field, which holds the number of
    /// [`ranges`](Self::ranges).
    pub const fn ack_range_count_width(&self) -> VarIntWidth {
        self.ack_range_count_width
    }

    /// The First ACK Range field: how many packet numbers below Largest
    /// Acknowledged the first range also acknowledges.
    pub const fn first_ack_range(&self) -> VarIntField<VarInt> {
        self.first_ack_range
    }

    /// The ACK Ranges after the first range, in order.
    pub const fn ranges(&self) -> &AckRanges {
        &self.ranges
    }

    /// The ECN counts; present in type `0x03`.
    pub const fn ecn_counts(&self) -> Option<EcnCounts> {
        self.ecn_counts
    }

    /// The Frame Type value: `0x03` with ECN counts, `0x02` without.
    pub const fn type_value(&self) -> VarInt {
        type_value_of(self.ecn_counts.is_some())
    }

    /// The acknowledged packet numbers as inclusive ranges, largest first,
    /// computed from the fields: one for First ACK Range and one for each
    /// ACK Range.
    pub fn packet_ranges(&self) -> PacketRanges<'_> {
        let range = first_range(self.largest_acknowledged.get(), self.first_ack_range.get());
        // invariant: construction checked that no range extends below
        // packet number 0.
        let range = range.unwrap_or_else(|| unreachable!("ACK range 0 below packet number 0"));
        PacketRanges {
            ranges: self.ranges.ranges.iter().copied(),
            state: PacketRangesState::First(range),
        }
    }

    /// The number of bytes [`codec::write_ack`] writes.
    pub fn encoded_len(&self) -> usize {
        self.fields().map(|(_, width)| width.encoded_len()).sum()
    }

    /// The fields of the encoding, in order, each a variable-length integer
    /// with its width: Frame Type, Largest Acknowledged, ACK Delay, ACK Range
    /// Count, First ACK Range, the Gap and ACK Range Length of each ACK
    /// Range, and the ECN counts.
    pub(crate) fn fields(&self) -> impl Iterator<Item = (VarInt, VarIntWidth)> + Clone {
        fn pair<T: Copy + Into<VarInt> + TryFrom<VarInt>>(
            field: VarIntField<T>,
        ) -> (VarInt, VarIntWidth) {
            (field.to_var_int(), field.width())
        }
        let type_value = self.type_value();
        // Construction checked that the count fits its width.
        let count = VarInt::try_from(self.ranges.len()).unwrap_or(VarInt::MAX);
        let prefix = [
            (type_value, VarIntWidth::shortest(type_value)),
            pair(self.largest_acknowledged),
            pair(self.ack_delay),
            (count, self.ack_range_count_width),
            pair(self.first_ack_range),
        ];
        let ranges = self
            .ranges
            .iter()
            .flat_map(|range| [pair(range.gap), pair(range.ack_range_length)]);
        let ecn = self
            .ecn_counts
            .into_iter()
            .flat_map(|counts| [pair(counts.ect0), pair(counts.ect1), pair(counts.ce)]);
        prefix.into_iter().chain(ranges).chain(ecn)
    }
}

/// The ACK Ranges of an ACK frame: the ranges after the first one, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct AckRanges {
    ranges: Vec<AckRange>,
}

impl AckRanges {
    /// The ACK Ranges, in order.
    pub fn iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = AckRange> + ExactSizeIterator + FusedIterator + Clone + '_
    {
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
    type IntoIter = Copied<slice::Iter<'a, AckRange>>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.iter().copied()
    }
}

/// The packet number ranges that the fields of an ACK frame acknowledge,
/// largest first; see [`Ack::packet_ranges`].
///
/// It yields one range for First ACK Range and one for each ACK Range:
/// construction of the frame checked that none extends below packet number
/// 0, so the iteration does not end early.
#[derive(Clone, Debug)]
pub struct PacketRanges<'a> {
    ranges: Copied<slice::Iter<'a, AckRange>>,
    state: PacketRangesState,
}

/// Where [`PacketRanges`] stands.
#[derive(Clone, Debug)]
enum PacketRangesState {
    /// The range of First ACK Range is next.
    First(RangeInclusive<PacketNumber>),
    /// The next ACK Range lies below this smallest packet number of the
    /// previous range.
    Below(PacketNumber),
}

impl Iterator for PacketRanges<'_> {
    type Item = RangeInclusive<PacketNumber>;

    fn next(&mut self) -> Option<Self::Item> {
        let previous = match &self.state {
            PacketRangesState::First(range) => {
                let range = range.clone();
                self.state = PacketRangesState::Below(*range.start());
                return Some(range);
            }
            PacketRangesState::Below(previous) => *previous,
        };
        let range = next_range(previous, self.ranges.next()?);
        // invariant: construction checked that no range extends below
        // packet number 0.
        let range = range.unwrap_or_else(|| unreachable!("ACK range below packet number 0"));
        self.state = PacketRangesState::Below(*range.start());
        Some(range)
    }
}

impl FusedIterator for PacketRanges<'_> {}

/// The packet numbers of the range of First ACK Range below Largest
/// Acknowledged `largest`, or `None` if it would extend below packet number
/// 0.
fn first_range(
    largest: PacketNumber,
    first_ack_range: VarInt,
) -> Option<RangeInclusive<PacketNumber>> {
    let smallest = largest.checked_sub(first_ack_range.get())?;
    Some(smallest..=largest)
}

/// The packet numbers of the ACK Range `range` below a range whose smallest
/// packet number is `previous`, or `None` if it would extend below packet
/// number 0.
fn next_range(previous: PacketNumber, range: AckRange) -> Option<RangeInclusive<PacketNumber>> {
    let largest = previous
        .checked_sub(range.gap.get().get())?
        .checked_sub(2)?;
    let smallest = largest.checked_sub(range.ack_range_length.get().get())?;
    Some(smallest..=largest)
}

/// The Frame Type value of an ACK frame with ECN counts if `ecn_counts` is
/// set: `0x03`, or `0x02` without.
pub(crate) const fn type_value_of(ecn_counts: bool) -> VarInt {
    type_var_int(if ecn_counts {
        type_value::ACK_ECN
    } else {
        type_value::ACK
    })
}

/// A range of an ACK frame extends below packet number 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("ACK range {index} extends below packet number 0"))]
pub struct AckBelowZeroError {
    /// The position of the range: 0 for the range of First ACK Range, `n`
    /// for the `n`-th ACK Range.
    pub index: usize,
}

impl AckBelowZeroError {
    /// Checks the range of First ACK Range below Largest Acknowledged
    /// `largest`, and returns its smallest packet number.
    fn check_first(largest: PacketNumber, first_ack_range: VarInt) -> Result<PacketNumber, Self> {
        match first_range(largest, first_ack_range) {
            Some(range) => Ok(*range.start()),
            None => Err(Self { index: 0 }),
        }
    }

    /// Checks the `index`-th ACK Range `range` below a range whose smallest
    /// packet number is `previous`, and returns its smallest packet number.
    fn check_next(
        previous: PacketNumber,
        range: AckRange,
        index: usize,
    ) -> Result<PacketNumber, Self> {
        match next_range(previous, range) {
            Some(range) => Ok(*range.start()),
            None => Err(Self { index }),
        }
    }
}

/// The fields of an ACK frame break a rule of the encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum InvalidAckError {
    /// A range extends below packet number 0.
    #[snafu(transparent)]
    BelowZero {
        /// The broken rule.
        source: AckBelowZeroError,
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
    #[snafu(display("ACK frame has no ranges"))]
    NoRanges,
    /// A range is empty: its start is above its end.
    #[snafu(display("packet number range {index} is empty"))]
    EmptyRange {
        /// The position of the range: 0 for the first.
        index: usize,
    },
    /// A range does not lie below the previous range with at least one
    /// packet number between them.
    #[snafu(display("packet number range {index} does not lie below the previous one with a gap"))]
    NotBelowPrevious {
        /// The position of the range, from 1.
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

    use super::{Ack, AckBelowZeroError, AckRange, AckRanges, EcnCounts};
    use crate::{
        frame::read_field,
        packet_number::PacketNumber,
        var_int::{VarInt, VarIntField, VarIntWidth, codec::ReadVarIntError},
    };
    use bytes::Buf;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type of an ACK frame of type
    /// `0x02`, without ECN counts.
    ///
    /// Each range is checked as soon as its fields are read, so a range that
    /// extends below packet number 0 is reported before the rest is read.
    pub(crate) async fn read_ack<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<Ack, ReadAckError<F::Error>> {
        Ok(read_ack_fields(io).await?.into_ack(None))
    }

    /// Reads the fields that follow the Frame Type of an ACK frame of type
    /// `0x03`, with ECN counts; ranges are checked as [`read_ack`] does.
    pub(crate) async fn read_ack_ecn<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<Ack, ReadAckEcnError<F::Error>> {
        use read_ack_ecn_error::*;
        let fields = read_ack_fields(io).await?;
        let ecn_counts = EcnCounts {
            ect0: read_field(io).await.context(Ect0CountSnafu)?,
            ect1: read_field(io).await.context(Ect1CountSnafu)?,
            ce: read_field(io).await.context(EcnCeCountSnafu)?,
        };
        Ok(fields.into_ack(Some(ecn_counts)))
    }

    /// The fields that both ACK frame types have, as they were read.
    struct AckFields {
        largest_acknowledged: VarIntField<PacketNumber>,
        ack_delay: VarIntField<VarInt>,
        ack_range_count_width: VarIntWidth,
        first_ack_range: VarIntField<VarInt>,
        ranges: Vec<AckRange>,
    }

    impl AckFields {
        /// The ACK frame with these fields and `ecn_counts`.
        fn into_ack(self, ecn_counts: Option<EcnCounts>) -> Ack {
            let frame = Ack::new(
                self.largest_acknowledged,
                self.ack_delay,
                self.ack_range_count_width,
                self.first_ack_range,
                AckRanges {
                    ranges: self.ranges,
                },
                ecn_counts,
            );
            // invariant: each range was checked as it was read, and the ACK
            // Range Count field was read at this width and states the number
            // of ranges.
            frame.unwrap_or_else(|error| unreachable!("{error}"))
        }
    }

    /// Reads the fields from Largest Acknowledged to the last ACK Range,
    /// checking each range as soon as its fields are read.
    async fn read_ack_fields<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<AckFields, ReadAckError<F::Error>> {
        use read_ack_error::*;
        let largest_acknowledged: VarIntField<PacketNumber> =
            read_field(io).await.context(LargestAcknowledgedSnafu)?;
        let ack_delay = read_field(io).await.context(AckDelaySnafu)?;
        let count: VarIntField<VarInt> = read_field(io).await.context(AckRangeCountSnafu)?;
        let first_ack_range: VarIntField<VarInt> =
            read_field(io).await.context(FirstAckRangeSnafu)?;
        let mut smallest =
            AckBelowZeroError::check_first(largest_acknowledged.get(), first_ack_range.get())?;
        // The count is not trusted for the allocation; each range is read
        // before it is stored.
        let count_value = count.get().get();
        let mut ranges = Vec::with_capacity(count_value.min(16) as usize);
        while (ranges.len() as u64) < count_value {
            let index = ranges.len() + 1;
            let gap = read_field(io).await.context(GapSnafu { index })?;
            let ack_range_length = read_field(io)
                .await
                .context(AckRangeLengthSnafu { index })?;
            let range = AckRange {
                gap,
                ack_range_length,
            };
            smallest = AckBelowZeroError::check_next(smallest, range, index)?;
            ranges.push(range);
        }
        Ok(AckFields {
            largest_acknowledged,
            ack_delay,
            ack_range_count_width: count.width(),
            first_ack_range,
            ranges,
        })
    }

    /// Failures of reading an ACK frame of type `0x02`, and of reading the
    /// fields before the ECN counts of type `0x03`.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_ack_error), visibility(pub(crate)))]
    pub enum ReadAckError<E> {
        /// The Largest Acknowledged field could not be read.
        #[snafu(display("ACK Largest Acknowledged read failed"))]
        LargestAcknowledged {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The ACK Delay field could not be read.
        #[snafu(display("ACK Delay read failed"))]
        AckDelay {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The ACK Range Count field could not be read.
        #[snafu(display("ACK Range Count read failed"))]
        AckRangeCount {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The First ACK Range field could not be read.
        #[snafu(display("First ACK Range read failed"))]
        FirstAckRange {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Gap field of an ACK Range could not be read.
        #[snafu(display("Gap of ACK Range {index} read failed"))]
        Gap {
            /// The position of the ACK Range, from 1.
            index: usize,
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The ACK Range Length field of an ACK Range could not be read.
        #[snafu(display("ACK Range Length of ACK Range {index} read failed"))]
        AckRangeLength {
            /// The position of the ACK Range, from 1.
            index: usize,
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// A range extends below packet number 0.
        #[snafu(transparent)]
        BelowZero {
            /// The broken rule.
            source: AckBelowZeroError,
        },
    }

    impl<E> ReadAckError<E> {
        /// Whether the source ended within the frame.
        pub(crate) fn is_incomplete(&self) -> bool {
            match self {
                Self::LargestAcknowledged { source }
                | Self::AckDelay { source }
                | Self::AckRangeCount { source }
                | Self::FirstAckRange { source }
                | Self::Gap { source, .. }
                | Self::AckRangeLength { source, .. } => source.is_incomplete(),
                Self::BelowZero { .. } => false,
            }
        }
    }

    /// Failures of reading an ACK frame of type `0x03`, with ECN counts.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_ack_ecn_error), visibility(pub(crate)))]
    pub enum ReadAckEcnError<E> {
        /// A field before the ECN counts could not be read, or a range
        /// extends below packet number 0.
        #[snafu(transparent)]
        Ack {
            /// The failure.
            source: ReadAckError<E>,
        },
        /// The ECT0 Count field could not be read.
        #[snafu(display("ECT0 Count read failed"))]
        Ect0Count {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The ECT1 Count field could not be read.
        #[snafu(display("ECT1 Count read failed"))]
        Ect1Count {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The ECN-CE Count field could not be read.
        #[snafu(display("ECN-CE Count read failed"))]
        EcnCeCount {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
    }

    impl<E> ReadAckEcnError<E> {
        /// Whether the source ended within the frame.
        pub(crate) fn is_incomplete(&self) -> bool {
            match self {
                Self::Ack { source } => source.is_incomplete(),
                Self::Ect0Count { source }
                | Self::Ect1Count { source }
                | Self::EcnCeCount { source } => source.is_incomplete(),
            }
        }
    }

    /// Writes `frame`; [`Ack::new`] checked its rules.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_ack<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: Ack,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(VarInts::new(frame.fields())).await
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
