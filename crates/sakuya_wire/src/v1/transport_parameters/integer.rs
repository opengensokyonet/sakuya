//! The transport parameters of version 1 whose value is one variable-length
//! integer ([RFC 9000 §18.2]).
//!
//! Each is a type of its own that holds the integer. A type whose values
//! RFC 9000 constrains checks the range when it is constructed and when it
//! is read: [`MaxUdpPayloadSize`], [`AckDelayExponent`], [`MaxAckDelay`] and
//! [`ActiveConnectionIdLimit`] with an error of their own, and the two
//! stream limits, [`InitialMaxStreamsBidi`] and [`InitialMaxStreamsUni`], by
//! holding a [`StreamCount`]. Every type implements [`Default`] with the
//! value [RFC 9000 §18.2] gives an absent parameter.
//!
//! The values are read and written by the two operations of [`codec`],
//! which any parameter type whose value is one variable-length integer can
//! use, in this space or another.
//!
//! [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
use crate::{
    v1::stream_count::{StreamCount, StreamCountError},
    var_int::VarInt,
};
use snafu::Snafu;

/// Implements `KeyedParameter` in the space of the transport parameters for
/// a type whose value is one variable-length integer: `$name` has the ID
/// `$id`, is sent by `$sent_by`, and converts from a `VarInt` with `TryFrom`
/// and into one with `Into`.
macro_rules! integer_transport_parameter {
    ($name:ty, $id:literal, $sent_by:expr) => {
        impl $crate::parameters::KeyedParameter for $name {
            type Space = $crate::v1::transport_parameters::TransportParameterSpace;
            type ValueError = $crate::parameters::ReadValueError<
                $crate::var_int::codec::ReadVarIntFieldError<
                    ::core::convert::Infallible,
                    <$name as ::core::convert::TryFrom<$crate::var_int::VarInt>>::Error,
                >,
            >;

            const ID: $crate::var_int::VarInt = $crate::var_int::VarInt::from_u32($id);
            const ATTRIBUTES: $crate::v1::transport_parameters::SentBy = $sent_by;

            fn read_value<D: ::bytes::Buf + ::core::marker::Unpin>(
                value: &mut $crate::parameters::ValueSource<D>,
            ) -> ::core::result::Result<Self, Self::ValueError> {
                use $crate::v1::transport_parameters::integer::codec::ReadIntegerValueHostExt as _;
                ::snafu::ResultExt::context(
                    value.sync_read_integer_value_unpin(),
                    $crate::parameters::read_value_error::ContentSnafu,
                )
            }

            fn value_len(&self) -> usize {
                $crate::var_int::VarInt::from(*self).encoded_len()
            }

            async fn write_value<F, A>(
                &self,
                io: &mut A,
            ) -> ::core::result::Result<(), ::nitori_io::calls::WriteAllError<F::Error>>
            where
                F: ::nitori_io::Write,
                A: ::nitori_call::ReceiverAccess<Family = F>,
            {
                $crate::v1::transport_parameters::integer::codec::write_integer_value(io, *self)
                    .await
            }
        }
    };
}
// The modules of extensions use it too, and each is compiled only with its
// feature.
#[allow(unused_imports)]
pub(crate) use integer_transport_parameter;

/// Defines a transport parameter that holds any variable-length integer and
/// is 0 when absent.
macro_rules! unconstrained {
    ($(#[$doc:meta])* $name:ident, $id:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(VarInt);

        impl $name {
            /// The parameter with `value`.
            pub const fn new(value: VarInt) -> Self {
                Self(value)
            }

            /// The value.
            pub const fn get(self) -> VarInt {
                self.0
            }
        }

        impl From<VarInt> for $name {
            fn from(value: VarInt) -> Self {
                Self(value)
            }
        }

        impl From<$name> for VarInt {
            fn from(parameter: $name) -> Self {
                parameter.0
            }
        }

        integer_transport_parameter!($name, $id, crate::v1::transport_parameters::SentBy::Either);
    };
}

/// Defines a transport parameter whose values RFC 9000 constrains: `$name`
/// holds a `VarInt` that `$error::check` accepts, and is `$default` when
/// absent.
macro_rules! constrained {
    ($(#[$doc:meta])* $name:ident, $id:literal, $error:ident, $default:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(VarInt);

        impl $name {
            /// The parameter with `value`.
            ///
            /// This is the `const` form of `TryFrom<VarInt>`.
            ///
            /// # Errors
            ///
            #[doc = concat!("[`", stringify!($error), "`] if `value` is out of range.")]
            pub const fn new(value: VarInt) -> Result<Self, $error> {
                match $error::check(value) {
                    Ok(()) => Ok(Self(value)),
                    Err(error) => Err(error),
                }
            }

            /// The value.
            pub const fn get(self) -> VarInt {
                self.0
            }
        }

        #[doc = concat!("The value of an absent parameter, ", stringify!($default), ".")]
        impl Default for $name {
            fn default() -> Self {
                Self(VarInt::from_u32($default))
            }
        }

        impl TryFrom<VarInt> for $name {
            type Error = $error;

            fn try_from(value: VarInt) -> Result<Self, $error> {
                Self::new(value)
            }
        }

        impl From<$name> for VarInt {
            fn from(parameter: $name) -> Self {
                parameter.0
            }
        }

        integer_transport_parameter!($name, $id, crate::v1::transport_parameters::SentBy::Either);
    };
}

/// Defines a transport parameter that holds a `StreamCount` and is 0 when
/// absent.
macro_rules! stream_count {
    ($(#[$doc:meta])* $name:ident, $id:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(StreamCount);

        impl $name {
            /// The parameter with `count`.
            pub const fn new(count: StreamCount) -> Self {
                Self(count)
            }

            /// The number of streams.
            pub const fn get(self) -> StreamCount {
                self.0
            }
        }

        impl From<StreamCount> for $name {
            fn from(count: StreamCount) -> Self {
                Self(count)
            }
        }

        impl From<$name> for StreamCount {
            fn from(parameter: $name) -> Self {
                parameter.0
            }
        }

        impl TryFrom<VarInt> for $name {
            type Error = StreamCountError;

            fn try_from(value: VarInt) -> Result<Self, StreamCountError> {
                StreamCount::try_from(value).map(Self)
            }
        }

        impl From<$name> for VarInt {
            fn from(parameter: $name) -> Self {
                parameter.0.to_var_int()
            }
        }

        integer_transport_parameter!($name, $id, crate::v1::transport_parameters::SentBy::Either);
    };
}

unconstrained! {
    /// `max_idle_timeout`, `0x01`: the idle timeout in milliseconds; 0, also
    /// the value of an absent parameter, disables it.
    MaxIdleTimeout, 0x01
}

constrained! {
    /// `max_udp_payload_size`, `0x03`: the largest UDP payload the endpoint
    /// is willing to receive, at least 1200; 65527 when absent.
    MaxUdpPayloadSize, 0x03, MaxUdpPayloadSizeError, 65527
}

unconstrained! {
    /// `initial_max_data`, `0x04`: the initial connection-level flow control
    /// limit, in bytes; 0 when absent.
    InitialMaxData, 0x04
}

unconstrained! {
    /// `initial_max_stream_data_bidi_local`, `0x05`: the initial flow
    /// control limit for bidirectional streams the sender of the parameters
    /// opens, in bytes; 0 when absent.
    InitialMaxStreamDataBidiLocal, 0x05
}

unconstrained! {
    /// `initial_max_stream_data_bidi_remote`, `0x06`: the initial flow
    /// control limit for bidirectional streams the peer opens, in bytes; 0
    /// when absent.
    InitialMaxStreamDataBidiRemote, 0x06
}

unconstrained! {
    /// `initial_max_stream_data_uni`, `0x07`: the initial flow control limit
    /// for unidirectional streams the peer opens, in bytes; 0 when absent.
    InitialMaxStreamDataUni, 0x07
}

stream_count! {
    /// `initial_max_streams_bidi`, `0x08`: the initial number of
    /// bidirectional streams the peer may open, at most 2<sup>60</sup>; 0
    /// when absent.
    InitialMaxStreamsBidi, 0x08
}

stream_count! {
    /// `initial_max_streams_uni`, `0x09`: the initial number of
    /// unidirectional streams the peer may open, at most 2<sup>60</sup>; 0
    /// when absent.
    InitialMaxStreamsUni, 0x09
}

constrained! {
    /// `ack_delay_exponent`, `0x0a`: the exponent of the ACK Delay field of
    /// ACK frames, at most 20; 3 when absent.
    AckDelayExponent, 0x0a, AckDelayExponentError, 3
}

constrained! {
    /// `max_ack_delay`, `0x0b`: the longest time, in milliseconds, the
    /// endpoint delays sending acknowledgments, below 2<sup>14</sup>; 25
    /// when absent.
    MaxAckDelay, 0x0b, MaxAckDelayError, 25
}

constrained! {
    /// `active_connection_id_limit`, `0x0e`: the number of connection IDs
    /// from the peer the endpoint is willing to store, at least 2; 2 when
    /// absent.
    ActiveConnectionIdLimit, 0x0e, ActiveConnectionIdLimitError, 2
}

/// The smallest `max_udp_payload_size` RFC 9000 permits.
const MIN_MAX_UDP_PAYLOAD_SIZE: u64 = 1200;
/// The largest `ack_delay_exponent` RFC 9000 permits.
const MAX_ACK_DELAY_EXPONENT: u64 = 20;
/// `max_ack_delay` must be below this.
const MAX_ACK_DELAY_BOUND: u64 = 1 << 14;
/// The smallest `active_connection_id_limit` RFC 9000 permits.
const MIN_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;

/// `max_udp_payload_size` is below 1200 ([RFC 9000 §18.2]).
///
/// It is constructed only when the check fails, so the value it holds is
/// always below 1200.
///
/// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("max_udp_payload_size {value} is below 1200"))]
pub struct MaxUdpPayloadSizeError {
    value: VarInt,
}

impl MaxUdpPayloadSizeError {
    /// The value, below 1200.
    pub const fn value(self) -> VarInt {
        self.value
    }

    /// Checks that `value` is at least 1200.
    const fn check(value: VarInt) -> Result<(), Self> {
        if value.get() < MIN_MAX_UDP_PAYLOAD_SIZE {
            return Err(Self { value });
        }
        Ok(())
    }
}

/// `ack_delay_exponent` exceeds 20 ([RFC 9000 §18.2]).
///
/// It is constructed only when the check fails, so the value it holds
/// always exceeds 20.
///
/// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("ack_delay_exponent {value} exceeds 20"))]
pub struct AckDelayExponentError {
    value: VarInt,
}

impl AckDelayExponentError {
    /// The value, above 20.
    pub const fn value(self) -> VarInt {
        self.value
    }

    /// Checks that `value` is at most 20.
    const fn check(value: VarInt) -> Result<(), Self> {
        if value.get() > MAX_ACK_DELAY_EXPONENT {
            return Err(Self { value });
        }
        Ok(())
    }
}

/// `max_ack_delay` is not below 2<sup>14</sup> ([RFC 9000 §18.2]).
///
/// It is constructed only when the check fails, so the value it holds is
/// always at least 2<sup>14</sup>.
///
/// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("max_ack_delay {value} is not below 2^14"))]
pub struct MaxAckDelayError {
    value: VarInt,
}

impl MaxAckDelayError {
    /// The value, at least 2<sup>14</sup>.
    pub const fn value(self) -> VarInt {
        self.value
    }

    /// Checks that `value` is below 2<sup>14</sup>.
    const fn check(value: VarInt) -> Result<(), Self> {
        if value.get() >= MAX_ACK_DELAY_BOUND {
            return Err(Self { value });
        }
        Ok(())
    }
}

/// `active_connection_id_limit` is below 2 ([RFC 9000 §18.2]).
///
/// It is constructed only when the check fails, so the value it holds is
/// always 0 or 1.
///
/// [RFC 9000 §18.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("active_connection_id_limit {value} is below 2"))]
pub struct ActiveConnectionIdLimitError {
    value: VarInt,
}

impl ActiveConnectionIdLimitError {
    /// The value, 0 or 1.
    pub const fn value(self) -> VarInt {
        self.value
    }

    /// Checks that `value` is at least 2.
    const fn check(value: VarInt) -> Result<(), Self> {
        if value.get() < MIN_ACTIVE_CONNECTION_ID_LIMIT {
            return Err(Self { value });
        }
        Ok(())
    }
}

pub mod codec {
    //! Reading and writing the value of a parameter that is one
    //! variable-length integer as `nitori_call` operations.
    //!
    //! [`read_integer_value`] and [`write_integer_value`] are generic over
    //! the parameter type, which converts from and into a
    //! [`VarInt`]. They are also the operation
    //! structs [`ReadIntegerValue`] and [`WriteIntegerValue`], with
    //! `{Name}Ext` on receiver accesses and `{Name}HostExt` on call
    //! executors. Reading the parameters reads this value from the bytes of
    //! its parameter, which must hold nothing else.
    //!
    //! ```
    //! use sakuya_wire::{
    //!     v1::transport_parameters::integer::{
    //!         MaxAckDelay,
    //!         codec::{ReadIntegerValueHostExt as _, WriteIntegerValueHostExt as _},
    //!     },
    //!     var_int::VarInt,
    //! };
    //!
    //! let delay = MaxAckDelay::new(VarInt::from(100u8)).unwrap();
    //! let mut value = Vec::new();
    //! value.sync_write_integer_value_unpin(delay).unwrap();
    //! assert_eq!(value, [0x40, 0x64]);
    //! let read: MaxAckDelay = value.as_slice().sync_read_integer_value_unpin().unwrap();
    //! assert_eq!(read, delay);
    //!
    //! // 2^14 is out of range.
    //! let mut value = &[0x80, 0x00, 0x40, 0x00][..];
    //! assert!(value.sync_read_integer_value_unpin::<MaxAckDelay>().is_err());
    //! ```
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use crate::var_int::{
        VarInt, VarIntField,
        codec::{ReadVarIntFieldError, read_var_int_field},
    };
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};

    /// Reads one variable-length integer, of any width, as a parameter of
    /// the type `T`, and nothing after it.
    ///
    /// # Errors
    ///
    /// [`ReadVarIntFieldError::VarInt`] if the integer cannot be read, and
    /// [`ReadVarIntFieldError::Value`] if `T` rejects it.
    #[call(sync)]
    pub async fn read_integer_value<T, F, A>(
        io: &mut A,
    ) -> Result<T, ReadVarIntFieldError<F::Error, <T as TryFrom<VarInt>>::Error>>
    where
        T: Copy + Into<VarInt> + TryFrom<VarInt>,
        F: Read,
        A: ReceiverAccess<Family = F>,
    {
        read_var_int_field(io).await.map(VarIntField::into_inner)
    }

    /// Writes the shortest encoding of the integer of `parameter`
    /// completely.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_integer_value<T, F, A>(
        io: &mut A,
        parameter: T,
    ) -> Result<(), WriteAllError<F::Error>>
    where
        T: Into<VarInt>,
        F: Write,
        A: ReceiverAccess<Family = F>,
    {
        let (encoding, encoded_len) = parameter.into().to_encoding();
        io.write_all(&encoding[..encoded_len]).await
    }
}
