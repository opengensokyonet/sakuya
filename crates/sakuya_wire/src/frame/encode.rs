//! Encoding of frames, shared by the slice entry points and the operations.
use super::{
    Ack, ConnectionClose, Crypto, DataBlocked, Datagram, EncodeError, HandshakeDone,
    InvalidFrameError, MAX_CID_LEN, MAX_STREAM_COUNT, MaxData, MaxStreamData, MaxStreams,
    NewConnectionId, NewToken, PATH_DATA_LEN, Padding, PathChallenge, PathResponse, Ping,
    ResetStream, ResetStreamAt, RetireConnectionId, STATELESS_RESET_TOKEN_LEN, StopSending, Stream,
    StreamDataBlocked, StreamsBlocked, stream_bits, type_value,
};
use crate::{stream_id::Directionality, var_int::VarInt};
use bytes::BufMut;
use core::ops::RangeInclusive;

/// The most bytes the fields before the payload of a frame take, except for
/// PADDING and ACK: NEW_CONNECTION_ID with a 20-byte connection ID.
pub(super) const HEAD_MAX: usize = 1 + 8 + 8 + 1 + MAX_CID_LEN + STATELESS_RESET_TOKEN_LEN;

/// The largest data length permitted after `offset` by the 2<sup>62</sup> − 1
/// bound, capped to `usize`.
pub(super) fn data_limit(offset: VarInt) -> usize {
    usize::try_from(VarInt::MAX.get() - offset.get()).unwrap_or(usize::MAX)
}

/// Whether data of `length` bytes at `offset` ends within 2<sup>62</sup> − 1.
fn data_end_valid(offset: VarInt, length: usize) -> bool {
    u64::try_from(length).is_ok_and(|length| length <= VarInt::MAX.get() - offset.get())
}

/// The shortest encoded length of `value`, or 8 for a value beyond
/// [`VarInt::MAX`], which validation rejects.
fn var_len(value: u64) -> usize {
    VarInt::new(value).map_or(VarInt::MAX_ENCODED_LEN, VarInt::encoded_len)
}

fn len_len(length: usize) -> usize {
    var_len(length as u64)
}

/// Writes a value into a buffer whose room has been checked.
pub(super) fn put_var_int<B: BufMut + ?Sized>(buffer: &mut B, value: VarInt) {
    let result = value.encode(buffer);
    debug_assert!(result.is_ok(), "room is checked before writing");
}

/// Writes a length that validation has checked.
fn put_len<B: BufMut + ?Sized>(buffer: &mut B, length: usize) {
    put_var_int(buffer, VarInt::try_from(length).unwrap_or(VarInt::MAX));
}

/// The largest `n` with `fixed + len(n) + n <= room` and `n <= limit`, where
/// `len(n)` is the length of the Length field.
pub(super) fn max_len_with_length_field(fixed: usize, limit: usize, room: usize) -> Option<usize> {
    const CLASSES: [(usize, u64); 4] = [
        (1, (1 << 6) - 1),
        (2, (1 << 14) - 1),
        (4, (1 << 30) - 1),
        (8, (1 << 62) - 1),
    ];
    CLASSES
        .iter()
        .filter_map(|&(field_len, class_max)| {
            let left = room.checked_sub(fixed + field_len)?;
            let class_max = usize::try_from(class_max).unwrap_or(usize::MAX);
            Some(left.min(class_max).min(limit))
        })
        .max()
}

/// The encoding of one frame type, split into the fields before the payload
/// and the payload.
pub(super) trait Body {
    /// The Frame Type value.
    fn type_value(&self) -> VarInt;
    /// Checks the limits of the encoding.
    fn validate(&self) -> Result<(), InvalidFrameError>;
    /// The length of the fields before the payload, including the type.
    fn head_len(&self) -> usize;
    /// Writes the fields before the payload, including the type.
    fn put_head<B: BufMut + ?Sized>(&self, buffer: &mut B);
    /// The payload that follows the head.
    fn payload(&self) -> &[u8] {
        &[]
    }
}

pub(super) fn body_len<T: Body + ?Sized>(body: &T) -> usize {
    body.head_len().saturating_add(body.payload().len())
}

pub(super) fn encode_body<T: Body + ?Sized, B: BufMut + ?Sized>(
    body: &T,
    buffer: &mut B,
) -> Result<(), EncodeError> {
    body.validate()?;
    let required = body_len(body);
    let available = buffer.remaining_mut();
    if available < required {
        return Err(EncodeError::Capacity {
            required,
            available,
        });
    }
    body.put_head(buffer);
    buffer.put_slice(body.payload());
    Ok(())
}

/// Generates the public encoding methods of frame structs that implement
/// [`Body`].
macro_rules! encoding_methods {
    ($($name:ident $(<$lifetime:lifetime>)?),* $(,)?) => {$(
        impl $(<$lifetime>)? $name $(<$lifetime>)? {
            /// The Frame Type value `encode` writes.
            pub fn type_value(&self) -> VarInt {
                Body::type_value(self)
            }

            /// The number of bytes `encode` writes.
            pub fn encoded_len(&self) -> usize {
                body_len(self)
            }

            /// Checks the limits that `encode` checks before writing; see
            /// the type documentation.
            ///
            /// # Errors
            ///
            /// [`InvalidFrameError`] for a field that breaks a limit.
            pub fn validate(&self) -> Result<(), InvalidFrameError> {
                Body::validate(self)
            }

            /// Appends the encoding of the frame to `buffer`.
            ///
            /// Nothing is written unless the frame is valid and fits.
            ///
            /// # Errors
            ///
            /// [`EncodeError::Invalid`] if `validate` fails, and
            /// [`EncodeError::Capacity`] if `buffer.remaining_mut()` is below
            /// `encoded_len`.
            pub fn encode<B: BufMut + ?Sized>(&self, buffer: &mut B) -> Result<(), EncodeError> {
                encode_body(self, buffer)
            }
        }
    )*};
}

encoding_methods!(
    Padding,
    Ping,
    ResetStream,
    StopSending,
    Crypto<'a>,
    NewToken<'a>,
    Stream<'a>,
    MaxData,
    MaxStreamData,
    MaxStreams,
    DataBlocked,
    StreamDataBlocked,
    StreamsBlocked,
    NewConnectionId<'a>,
    RetireConnectionId,
    PathChallenge,
    PathResponse,
    ConnectionClose<'a>,
    HandshakeDone,
    ResetStreamAt,
    Datagram<'a>,
);

const fn type_var_int(value: u64) -> VarInt {
    VarInt::from_u32(value as u32)
}

/// Implements [`Body`] for a frame whose fields after the type are all
/// variable-length integers.
macro_rules! var_int_body {
    ($name:ident, |$frame:ident| $type_value:expr, [$($field:expr),*]) => {
        impl Body for $name {
            fn type_value(&self) -> VarInt {
                type_var_int($type_value)
            }

            fn validate(&self) -> Result<(), InvalidFrameError> {
                Ok(())
            }

            fn head_len(&self) -> usize {
                let $frame = self;
                1 $(+ VarInt::from($field).encoded_len())*
            }

            fn put_head<B: BufMut + ?Sized>(&self, buffer: &mut B) {
                let $frame = self;
                put_var_int(buffer, Body::type_value($frame));
                $(put_var_int(buffer, VarInt::from($field));)*
            }
        }
    };
}

var_int_body!(Ping, |_frame| type_value::PING, []);
var_int_body!(HandshakeDone, |_frame| type_value::HANDSHAKE_DONE, []);
var_int_body!(
    ResetStream,
    |frame| type_value::RESET_STREAM,
    [
        frame.stream_id,
        frame.application_error_code,
        frame.final_size
    ]
);
var_int_body!(
    StopSending,
    |frame| type_value::STOP_SENDING,
    [frame.stream_id, frame.application_error_code]
);
var_int_body!(MaxData, |frame| type_value::MAX_DATA, [frame.maximum_data]);
var_int_body!(
    MaxStreamData,
    |frame| type_value::MAX_STREAM_DATA,
    [frame.stream_id, frame.maximum_stream_data]
);
var_int_body!(
    DataBlocked,
    |frame| type_value::DATA_BLOCKED,
    [frame.maximum_data]
);
var_int_body!(
    StreamDataBlocked,
    |frame| type_value::STREAM_DATA_BLOCKED,
    [frame.stream_id, frame.maximum_stream_data]
);
var_int_body!(
    RetireConnectionId,
    |frame| type_value::RETIRE_CONNECTION_ID,
    [frame.sequence_number]
);

impl Body for Padding {
    fn type_value(&self) -> VarInt {
        VarInt::ZERO
    }

    fn validate(&self) -> Result<(), InvalidFrameError> {
        Ok(())
    }

    fn head_len(&self) -> usize {
        self.len.get()
    }

    fn put_head<B: BufMut + ?Sized>(&self, buffer: &mut B) {
        buffer.put_bytes(0, self.len.get());
    }
}

fn validate_stream_count(
    frame_type: VarInt,
    maximum_streams: VarInt,
) -> Result<(), InvalidFrameError> {
    if maximum_streams.get() > MAX_STREAM_COUNT {
        return Err(InvalidFrameError::StreamCount {
            frame_type,
            maximum_streams,
        });
    }
    Ok(())
}

macro_rules! stream_count_body {
    ($name:ident, $bidi:expr, $uni:expr) => {
        impl Body for $name {
            fn type_value(&self) -> VarInt {
                type_var_int(match self.directionality {
                    Directionality::Bidirectional => $bidi,
                    Directionality::Unidirectional => $uni,
                })
            }

            fn validate(&self) -> Result<(), InvalidFrameError> {
                validate_stream_count(Body::type_value(self), self.maximum_streams)
            }

            fn head_len(&self) -> usize {
                1 + self.maximum_streams.encoded_len()
            }

            fn put_head<B: BufMut + ?Sized>(&self, buffer: &mut B) {
                put_var_int(buffer, Body::type_value(self));
                put_var_int(buffer, self.maximum_streams);
            }
        }
    };
}

stream_count_body!(
    MaxStreams,
    type_value::MAX_STREAMS_BIDI,
    type_value::MAX_STREAMS_UNI
);
stream_count_body!(
    StreamsBlocked,
    type_value::STREAMS_BLOCKED_BIDI,
    type_value::STREAMS_BLOCKED_UNI
);

impl Body for Crypto<'_> {
    fn type_value(&self) -> VarInt {
        type_var_int(type_value::CRYPTO)
    }

    fn validate(&self) -> Result<(), InvalidFrameError> {
        if !data_end_valid(self.offset, self.data.len()) {
            return Err(InvalidFrameError::DataEnd {
                frame_type: Body::type_value(self),
                offset: self.offset,
                length: self.data.len(),
            });
        }
        Ok(())
    }

    fn head_len(&self) -> usize {
        1 + self.offset.encoded_len() + len_len(self.data.len())
    }

    fn put_head<B: BufMut + ?Sized>(&self, buffer: &mut B) {
        put_var_int(buffer, Body::type_value(self));
        put_var_int(buffer, self.offset);
        put_len(buffer, self.data.len());
    }

    fn payload(&self) -> &[u8] {
        self.data
    }
}

impl Body for NewToken<'_> {
    fn type_value(&self) -> VarInt {
        type_var_int(type_value::NEW_TOKEN)
    }

    fn validate(&self) -> Result<(), InvalidFrameError> {
        if self.token.is_empty() {
            return Err(InvalidFrameError::EmptyToken);
        }
        validate_len(Body::type_value(self), self.token.len())
    }

    fn head_len(&self) -> usize {
        1 + len_len(self.token.len())
    }

    fn put_head<B: BufMut + ?Sized>(&self, buffer: &mut B) {
        put_var_int(buffer, Body::type_value(self));
        put_len(buffer, self.token.len());
    }

    fn payload(&self) -> &[u8] {
        self.token
    }
}

fn validate_len(frame_type: VarInt, length: usize) -> Result<(), InvalidFrameError> {
    if VarInt::try_from(length).is_err() {
        return Err(InvalidFrameError::Length { frame_type, length });
    }
    Ok(())
}

impl Body for Stream<'_> {
    fn type_value(&self) -> VarInt {
        let mut value = type_value::STREAM;
        if self.offset != VarInt::ZERO {
            value |= stream_bits::OFF;
        }
        if self.has_length {
            value |= stream_bits::LEN;
        }
        if self.fin {
            value |= stream_bits::FIN;
        }
        type_var_int(value)
    }

    fn validate(&self) -> Result<(), InvalidFrameError> {
        if !data_end_valid(self.offset, self.data.len()) {
            return Err(InvalidFrameError::DataEnd {
                frame_type: Body::type_value(self),
                offset: self.offset,
                length: self.data.len(),
            });
        }
        Ok(())
    }

    fn head_len(&self) -> usize {
        let offset_len = if self.offset == VarInt::ZERO {
            0
        } else {
            self.offset.encoded_len()
        };
        let length_len = if self.has_length {
            len_len(self.data.len())
        } else {
            0
        };
        1 + self.stream_id.get().encoded_len() + offset_len + length_len
    }

    fn put_head<B: BufMut + ?Sized>(&self, buffer: &mut B) {
        put_var_int(buffer, Body::type_value(self));
        put_var_int(buffer, self.stream_id.get());
        if self.offset != VarInt::ZERO {
            put_var_int(buffer, self.offset);
        }
        if self.has_length {
            put_len(buffer, self.data.len());
        }
    }

    fn payload(&self) -> &[u8] {
        self.data
    }
}

impl Body for NewConnectionId<'_> {
    fn type_value(&self) -> VarInt {
        type_var_int(type_value::NEW_CONNECTION_ID)
    }

    fn validate(&self) -> Result<(), InvalidFrameError> {
        let length = self.connection_id.len();
        if length == 0 || length > MAX_CID_LEN {
            return Err(InvalidFrameError::ConnectionIdLength { length });
        }
        if self.retire_prior_to > self.sequence_number {
            return Err(InvalidFrameError::RetirePriorTo {
                sequence_number: self.sequence_number,
                retire_prior_to: self.retire_prior_to,
            });
        }
        Ok(())
    }

    fn head_len(&self) -> usize {
        1 + self.sequence_number.encoded_len()
            + self.retire_prior_to.encoded_len()
            + 1
            + self.connection_id.len()
            + STATELESS_RESET_TOKEN_LEN
    }

    fn put_head<B: BufMut + ?Sized>(&self, buffer: &mut B) {
        put_var_int(buffer, Body::type_value(self));
        put_var_int(buffer, self.sequence_number);
        put_var_int(buffer, self.retire_prior_to);
        // Validation bounds the length by 20.
        buffer.put_u8(self.connection_id.len() as u8);
        buffer.put_slice(self.connection_id);
        buffer.put_slice(self.stateless_reset_token);
    }
}

macro_rules! path_data_body {
    ($name:ident, $type_value:expr) => {
        impl Body for $name {
            fn type_value(&self) -> VarInt {
                type_var_int($type_value)
            }

            fn validate(&self) -> Result<(), InvalidFrameError> {
                Ok(())
            }

            fn head_len(&self) -> usize {
                1 + PATH_DATA_LEN
            }

            fn put_head<B: BufMut + ?Sized>(&self, buffer: &mut B) {
                put_var_int(buffer, Body::type_value(self));
                buffer.put_slice(&self.data);
            }
        }
    };
}

path_data_body!(PathChallenge, type_value::PATH_CHALLENGE);
path_data_body!(PathResponse, type_value::PATH_RESPONSE);

impl Body for ConnectionClose<'_> {
    fn type_value(&self) -> VarInt {
        type_var_int(match self.frame_type {
            Some(_) => type_value::CONNECTION_CLOSE,
            None => type_value::CONNECTION_CLOSE_APPLICATION,
        })
    }

    fn validate(&self) -> Result<(), InvalidFrameError> {
        validate_len(Body::type_value(self), self.reason_phrase.len())
    }

    fn head_len(&self) -> usize {
        1 + self.error_code.encoded_len()
            + self.frame_type.map_or(0, VarInt::encoded_len)
            + len_len(self.reason_phrase.len())
    }

    fn put_head<B: BufMut + ?Sized>(&self, buffer: &mut B) {
        put_var_int(buffer, Body::type_value(self));
        put_var_int(buffer, self.error_code);
        if let Some(frame_type) = self.frame_type {
            put_var_int(buffer, frame_type);
        }
        put_len(buffer, self.reason_phrase.len());
    }

    fn payload(&self) -> &[u8] {
        self.reason_phrase
    }
}

impl Body for ResetStreamAt {
    fn type_value(&self) -> VarInt {
        type_var_int(type_value::RESET_STREAM_AT)
    }

    fn validate(&self) -> Result<(), InvalidFrameError> {
        if self.reliable_size > self.final_size {
            return Err(InvalidFrameError::ReliableSize {
                final_size: self.final_size,
                reliable_size: self.reliable_size,
            });
        }
        Ok(())
    }

    fn head_len(&self) -> usize {
        1 + self.stream_id.get().encoded_len()
            + self.application_error_code.encoded_len()
            + self.final_size.encoded_len()
            + self.reliable_size.encoded_len()
    }

    fn put_head<B: BufMut + ?Sized>(&self, buffer: &mut B) {
        put_var_int(buffer, Body::type_value(self));
        put_var_int(buffer, self.stream_id.get());
        put_var_int(buffer, self.application_error_code);
        put_var_int(buffer, self.final_size);
        put_var_int(buffer, self.reliable_size);
    }
}

impl Body for Datagram<'_> {
    fn type_value(&self) -> VarInt {
        type_var_int(if self.has_length {
            type_value::DATAGRAM_WITH_LENGTH
        } else {
            type_value::DATAGRAM
        })
    }

    fn validate(&self) -> Result<(), InvalidFrameError> {
        validate_len(Body::type_value(self), self.data.len())
    }

    fn head_len(&self) -> usize {
        1 + if self.has_length {
            len_len(self.data.len())
        } else {
            0
        }
    }

    fn put_head<B: BufMut + ?Sized>(&self, buffer: &mut B) {
        put_var_int(buffer, Body::type_value(self));
        if self.has_length {
            put_len(buffer, self.data.len());
        }
    }

    fn payload(&self) -> &[u8] {
        self.data
    }
}

/// The ACK Range Count, First ACK Range and the Gap and ACK Range Length
/// pairs of a sequence of ranges, as [`AckFields::of`] computes them.
pub(super) struct AckFields {
    largest: u64,
    first: u64,
    count: u64,
    /// The encoded length of the First ACK Range and the pairs.
    ranges_len: usize,
    /// The result of checking the ranges.
    valid: Result<(), InvalidFrameError>,
}

impl AckFields {
    pub(super) fn of<R: Iterator<Item = RangeInclusive<u64>>>(mut ranges: R) -> Self {
        let Some(first) = ranges.next() else {
            return Self {
                largest: 0,
                first: 0,
                count: 0,
                ranges_len: 1,
                valid: Err(InvalidFrameError::EmptyAck),
            };
        };
        let (start, end) = first.into_inner();
        let mut valid = if start <= end && end <= VarInt::MAX.get() {
            Ok(())
        } else {
            Err(InvalidFrameError::AckRange { index: 0 })
        };
        let first = end.saturating_sub(start);
        let mut fields = Self {
            largest: end,
            first,
            count: 0,
            ranges_len: var_len(first),
            valid: Ok(()),
        };
        let mut smallest = start;
        for (index, range) in (1..).zip(ranges) {
            let (start, end) = range.into_inner();
            if valid.is_ok()
                && !(start <= end && end.checked_add(2).is_some_and(|end| end <= smallest))
            {
                valid = Err(InvalidFrameError::AckRange { index });
            }
            let (gap, length) = ack_pair(smallest, start, end);
            fields.ranges_len += var_len(gap) + var_len(length);
            fields.count += 1;
            smallest = start;
        }
        fields.valid = valid;
        fields
    }
}

/// The Gap and ACK Range Length of the range `start..=end` that follows a
/// range whose smallest packet number is `smallest`.
fn ack_pair(smallest: u64, start: u64, end: u64) -> (u64, u64) {
    (
        smallest.saturating_sub(end).saturating_sub(2),
        end.saturating_sub(start),
    )
}

impl<R: Iterator<Item = RangeInclusive<u64>> + Clone> Ack<R> {
    fn ack_type_value(&self) -> u64 {
        if self.ecn_counts.is_some() {
            type_value::ACK_ECN
        } else {
            type_value::ACK
        }
    }

    /// The length of the Type, Largest Acknowledged, ACK Delay and ACK Range
    /// Count fields.
    fn prefix_len(&self, fields: &AckFields) -> usize {
        1 + var_len(fields.largest) + self.ack_delay.encoded_len() + var_len(fields.count)
    }

    fn ecn_len(&self) -> usize {
        self.ecn_counts.map_or(0, |counts| {
            counts.ect0.encoded_len() + counts.ect1.encoded_len() + counts.ce.encoded_len()
        })
    }

    /// The values of the encoding, in order, each a variable-length integer.
    pub(super) fn values(&self, fields: &AckFields) -> impl Iterator<Item = u64> + use<R> {
        let prefix = [
            self.ack_type_value(),
            fields.largest,
            self.ack_delay.get(),
            fields.count,
            fields.first,
        ];
        let mut ranges = self.ranges.clone();
        let first_start = ranges.next().map_or(0, |range| *range.start());
        let pairs = ranges
            .scan(first_start, |smallest, range| {
                let (start, end) = range.into_inner();
                let (gap, length) = ack_pair(*smallest, start, end);
                *smallest = start;
                Some([gap, length])
            })
            .flatten();
        let ecn = self
            .ecn_counts
            .map(|counts| [counts.ect0.get(), counts.ect1.get(), counts.ce.get()])
            .into_iter()
            .flatten();
        prefix.into_iter().chain(pairs).chain(ecn)
    }
}

impl<R: Iterator<Item = RangeInclusive<u64>> + Clone> Body for Ack<R> {
    fn type_value(&self) -> VarInt {
        type_var_int(self.ack_type_value())
    }

    fn validate(&self) -> Result<(), InvalidFrameError> {
        AckFields::of(self.ranges.clone()).valid
    }

    fn head_len(&self) -> usize {
        let fields = AckFields::of(self.ranges.clone());
        self.prefix_len(&fields) + fields.ranges_len + self.ecn_len()
    }

    fn put_head<B: BufMut + ?Sized>(&self, buffer: &mut B) {
        let fields = AckFields::of(self.ranges.clone());
        for value in self.values(&fields) {
            put_var_int(buffer, VarInt::new(value).unwrap_or(VarInt::MAX));
        }
    }
}
