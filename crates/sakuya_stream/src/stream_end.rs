//! Rules about the end of a stream that both directions apply.
//!
//! The send direction checks them for local calls, the receive direction for
//! the peer's frames ([RFC 9000 §4.5], [RFC 9000 §13.3]; with the reliable
//! stream reset extension also draft-ietf-quic-reliable-stream-reset-11 §5);
//! each failure is defined once here and wrapped by the errors of both.
//!
//! - [`FinalSizeChangeError`]: a final size, once known, does not change.
//! - [`BeyondFinalSizeError`]: stream data does not pass the final size.
//! - [`ResetCodeChangeError`]: the error code of a reset does not change.
//!
//! Each error has private fields and is constructed only by its `check` when
//! the check fails, so it holds only values for which the rule fails.
//!
//! [RFC 9000 §4.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.5
//! [RFC 9000 §13.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-13.3
use sakuya_wire::v1::application_error::ApplicationErrorCode;
use sakuya_wire::var_int::VarInt;
use snafu::{Snafu, ensure};

/// A final size differs from the one already known for the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("final size {stated} differs from the known final size {known}"))]
pub struct FinalSizeChangeError {
    known: VarInt,
    stated: VarInt,
}

impl FinalSizeChangeError {
    /// Checks that `stated` equals the `known` final size.
    ///
    /// # Errors
    ///
    /// [`FinalSizeChangeError`] if they differ.
    pub fn check(known: VarInt, stated: VarInt) -> Result<(), Self> {
        ensure!(known == stated, FinalSizeChangeSnafu { known, stated });
        Ok(())
    }

    /// The final size known before.
    pub const fn known(self) -> VarInt {
        self.known
    }

    /// The final size stated now, which differs from [`known`](Self::known).
    pub const fn stated(self) -> VarInt {
        self.stated
    }
}

/// Stream data ends beyond the final size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("stream data ends at {end}, beyond the final size {final_size}"))]
pub struct BeyondFinalSizeError {
    final_size: VarInt,
    end: VarInt,
}

impl BeyondFinalSizeError {
    /// Checks that data ending at `end` does not pass `final_size`.
    ///
    /// # Errors
    ///
    /// [`BeyondFinalSizeError`] if `end` exceeds `final_size`.
    pub fn check(final_size: VarInt, end: VarInt) -> Result<(), Self> {
        ensure!(end <= final_size, BeyondFinalSizeSnafu { final_size, end });
        Ok(())
    }

    /// The final size.
    pub const fn final_size(self) -> VarInt {
        self.final_size
    }

    /// The end of the data, which exceeds [`final_size`](Self::final_size).
    pub const fn end(self) -> VarInt {
        self.end
    }
}

/// A reset states an error code different from the one already known for
/// the stream's reset.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("reset error code {stated} differs from the known code {known}"))]
pub struct ResetCodeChangeError {
    known: ApplicationErrorCode,
    stated: ApplicationErrorCode,
}

impl ResetCodeChangeError {
    /// Checks that `stated` equals the `known` error code of the reset.
    ///
    /// # Errors
    ///
    /// [`ResetCodeChangeError`] if they differ.
    pub fn check(known: ApplicationErrorCode, stated: ApplicationErrorCode) -> Result<(), Self> {
        ensure!(known == stated, ResetCodeChangeSnafu { known, stated });
        Ok(())
    }

    /// The error code known before.
    pub const fn known(self) -> ApplicationErrorCode {
        self.known
    }

    /// The error code stated now, which differs from [`known`](Self::known).
    pub const fn stated(self) -> ApplicationErrorCode {
        self.stated
    }
}
