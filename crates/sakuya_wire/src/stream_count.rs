//! Stream counts ([RFC 9000 §4.6]).
//!
//! A [`StreamCount`] is a cumulative number of streams of one type: the
//! Maximum Streams field of MAX_STREAMS and STREAMS_BLOCKED frames, and the
//! `initial_max_streams_bidi` and `initial_max_streams_uni` transport
//! parameters. It is at most 2<sup>60</sup>, since no stream ID of a type
//! past that count can be encoded ([RFC 9000 §19.11], §19.14, §18.2).
//!
//! Converting a [`VarInt`] into a `StreamCount` fails above that bound with
//! [`StreamCountError`]; the reader of the value decides which error it
//! means: FRAME_ENCODING_ERROR in a frame, TRANSPORT_PARAMETER_ERROR in a
//! transport parameter.
//!
//! [RFC 9000 §4.6]: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.6
//! [RFC 9000 §19.11]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.11
use crate::var_int::VarInt;
use core::fmt;
use snafu::Snafu;

/// A cumulative number of streams of one type: 0 to 2<sup>60</sup>.
///
/// Equality, ordering and hashing are those of the numeric value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamCount(VarInt);

impl StreamCount {
    /// No stream.
    pub const ZERO: Self = Self(VarInt::ZERO);

    /// The largest stream count, 2<sup>60</sup>.
    pub const MAX: Self = match VarInt::new(1 << 60) {
        Ok(value) => Self(value),
        // invariant: 2^60 is below 2^62, and a constant is evaluated at
        // compile time.
        Err(_) => panic!("2^60 is a variable-length integer"),
    };

    /// Returns the stream count `value`.
    ///
    /// This is the `const` form of `StreamCount::try_from(value)`.
    ///
    /// # Errors
    ///
    /// [`StreamCountError`] if `value` exceeds [`StreamCount::MAX`].
    pub const fn new(value: u64) -> Result<Self, StreamCountError> {
        match VarInt::new(value) {
            Ok(count) if value <= Self::MAX.get() => Ok(Self(count)),
            _ => Err(StreamCountError { value }),
        }
    }

    /// The numeric value.
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// The count as a variable-length integer.
    pub const fn to_var_int(self) -> VarInt {
        self.0
    }
}

impl From<StreamCount> for VarInt {
    fn from(count: StreamCount) -> Self {
        count.0
    }
}

impl TryFrom<VarInt> for StreamCount {
    type Error = StreamCountError;

    /// Accepts values up to [`StreamCount::MAX`].
    fn try_from(value: VarInt) -> Result<Self, Self::Error> {
        Self::new(value.get())
    }
}

impl TryFrom<u64> for StreamCount {
    type Error = StreamCountError;

    /// Accepts values up to [`StreamCount::MAX`].
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<StreamCount> for u64 {
    fn from(count: StreamCount) -> Self {
        count.get()
    }
}

/// Formats the numeric value.
impl fmt::Display for StreamCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A value exceeds [`StreamCount::MAX`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("stream count {value} exceeds 2^60"))]
pub struct StreamCountError {
    /// The rejected value.
    pub value: u64,
}

#[cfg(test)]
mod tests {
    use super::{StreamCount, StreamCountError};
    use crate::var_int::VarInt;

    #[test]
    fn counts_stop_at_2_60() {
        assert_eq!(StreamCount::MAX.get(), 1 << 60);
        assert_eq!(StreamCount::ZERO.get(), 0);
        assert_eq!(StreamCount::default(), StreamCount::ZERO);
        for value in [0, 63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30, 1 << 60] {
            let count = StreamCount::new(value).unwrap();
            assert_eq!(count.get(), value);
            assert_eq!(u64::from(count), value);
            let var_int = VarInt::try_from(value).unwrap();
            assert_eq!(VarInt::from(count), var_int);
            assert_eq!(count.to_var_int(), var_int);
            // The conversions agree in both directions.
            assert_eq!(StreamCount::try_from(var_int), Ok(count));
            assert_eq!(StreamCount::try_from(value), Ok(count));
        }
        for value in [(1 << 60) + 1, (1 << 62) - 1] {
            let error = StreamCountError { value };
            assert_eq!(StreamCount::new(value), Err(error));
            assert_eq!(
                StreamCount::try_from(VarInt::try_from(value).unwrap()),
                Err(error)
            );
        }
        assert_eq!(
            StreamCount::new(u64::MAX),
            Err(StreamCountError { value: u64::MAX })
        );
        assert_eq!(
            StreamCountError {
                value: (1 << 60) + 1
            }
            .to_string(),
            "stream count 1152921504606846977 exceeds 2^60"
        );
        assert_eq!(StreamCount::new(100).unwrap().to_string(), "100");
        assert!(StreamCount::new(5).unwrap() < StreamCount::MAX);
    }
}
