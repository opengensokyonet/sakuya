//! The protocol violations a NEW_CONNECTION_ID frame can commit.
//!
//! [`NewConnectionIdViolationError`] lists every violation a destination
//! connection ID strategy can report for the frame; each is a connection
//! error, closed with the code of
//! [`transport_error_code`](NewConnectionIdViolationError::transport_error_code).
//! Which of the optional ones a strategy checks is its own choice.
//!
//! Each violation is an error struct with private fields, constructed only
//! by its `check` (or `new`, when every value violates the rule), so it
//! holds only values for which its rule fails. Strategies other than
//! sakuya's construct them the same way.
//!
//! A Retire Prior To above the Sequence Number and a connection ID length
//! outside 1 to 20 are rejected when the frame is read
//! (FRAME_ENCODING_ERROR) and are not among them.

use sakuya_wire::{
    connection_id::{ConnectionId, StatelessResetToken},
    v1::{
        transport_error::TransportErrorCode, transport_parameters::integer::ActiveConnectionIdLimit,
    },
};
use snafu::{Snafu, ensure};

/// After a NEW_CONNECTION_ID frame, more connection IDs are active than
/// this side's `active_connection_id_limit` (CONNECTION_ID_LIMIT_ERROR,
/// [RFC 9000 §5.1.1], MUST).
///
/// [RFC 9000 §5.1.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.1
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "{active} active connection IDs exceed the active_connection_id_limit {}",
    limit.get()
))]
pub struct ActiveConnectionIdLimitExceededError {
    active: usize,
    limit: ActiveConnectionIdLimit,
}

impl ActiveConnectionIdLimitExceededError {
    /// Checks that `active` connection IDs are within `limit`.
    ///
    /// # Errors
    ///
    /// [`ActiveConnectionIdLimitExceededError`] if there are more.
    pub fn check(active: usize, limit: ActiveConnectionIdLimit) -> Result<(), Self> {
        let within = u64::try_from(active).is_ok_and(|active| active <= limit.get().get());
        ensure!(
            within,
            ActiveConnectionIdLimitExceededSnafu { active, limit }
        );
        Ok(())
    }

    /// The number of active connection IDs, above [`limit`](Self::limit).
    pub const fn active(self) -> usize {
        self.active
    }

    /// This side's `active_connection_id_limit`.
    pub const fn limit(self) -> ActiveConnectionIdLimit {
        self.limit
    }
}

/// Retire Prior To leaves more connection IDs retired and not yet
/// acknowledged as retired than this side tracks
/// (CONNECTION_ID_LIMIT_ERROR, [RFC 9000 §5.1.2], MAY).
///
/// [RFC 9000 §5.1.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "{unacknowledged} unacknowledged retirements exceed the {limit} this side tracks"
))]
pub struct RetirementLimitExceededError {
    unacknowledged: usize,
    limit: usize,
}

impl RetirementLimitExceededError {
    /// Checks that `unacknowledged` retirements are within `limit`.
    ///
    /// # Errors
    ///
    /// [`RetirementLimitExceededError`] if there are more.
    pub fn check(unacknowledged: usize, limit: usize) -> Result<(), Self> {
        ensure!(
            unacknowledged <= limit,
            RetirementLimitExceededSnafu {
                unacknowledged,
                limit
            }
        );
        Ok(())
    }

    /// The number of retirements not yet acknowledged, above
    /// [`limit`](Self::limit).
    pub const fn unacknowledged(self) -> usize {
        self.unacknowledged
    }

    /// How many unacknowledged retirements this side tracks.
    pub const fn limit(self) -> usize {
        self.limit
    }
}

/// A NEW_CONNECTION_ID frame arrived while this side sends with the
/// zero-length connection ID (PROTOCOL_VIOLATION, [RFC 9000 §19.15], MUST).
///
/// [RFC 9000 §19.15]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "NEW_CONNECTION_ID with sequence number {sequence} while the peer's connection ID is zero-length"
))]
pub struct ZeroLengthConnectionIdInUseError {
    sequence: u64,
}

impl ZeroLengthConnectionIdInUseError {
    /// The violation of a frame with the sequence number `sequence`; any
    /// such frame commits it.
    pub const fn new(sequence: u64) -> Self {
        Self { sequence }
    }

    /// The frame's sequence number.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

/// A sequence number already given to one connection ID comes with another
/// (PROTOCOL_VIOLATION, [RFC 9000 §19.15], MAY).
///
/// [RFC 9000 §19.15]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "sequence number {sequence} given to connection ID {known} comes with {received}"
))]
pub struct SequenceNumberReusedError {
    sequence: u64,
    known: ConnectionId,
    received: ConnectionId,
}

impl SequenceNumberReusedError {
    /// Checks that `received`, with the sequence number `sequence`, is the
    /// connection ID `known` that number was given to.
    ///
    /// # Errors
    ///
    /// [`SequenceNumberReusedError`] if they differ.
    pub fn check(sequence: u64, known: ConnectionId, received: ConnectionId) -> Result<(), Self> {
        ensure!(
            known == received,
            SequenceNumberReusedSnafu {
                sequence,
                known,
                received
            }
        );
        Ok(())
    }

    /// The sequence number.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// The connection ID the sequence number was given to first.
    pub const fn known(self) -> ConnectionId {
        self.known
    }

    /// The other connection ID it came with now.
    pub const fn received(self) -> ConnectionId {
        self.received
    }
}

/// A connection ID already issued with one sequence number comes with
/// another (PROTOCOL_VIOLATION, [RFC 9000 §19.15], MAY).
///
/// [RFC 9000 §19.15]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "connection ID {id} issued with sequence number {known_sequence} comes with {received_sequence}"
))]
pub struct ConnectionIdResequencedError {
    id: ConnectionId,
    known_sequence: u64,
    received_sequence: u64,
}

impl ConnectionIdResequencedError {
    /// Checks that the connection ID `id`, issued with `known_sequence`,
    /// comes again with the same sequence number, `received_sequence`.
    ///
    /// # Errors
    ///
    /// [`ConnectionIdResequencedError`] if the numbers differ.
    pub fn check(
        id: ConnectionId,
        known_sequence: u64,
        received_sequence: u64,
    ) -> Result<(), Self> {
        ensure!(
            known_sequence == received_sequence,
            ConnectionIdResequencedSnafu {
                id,
                known_sequence,
                received_sequence
            }
        );
        Ok(())
    }

    /// The connection ID.
    pub const fn id(self) -> ConnectionId {
        self.id
    }

    /// The sequence number it was issued with first.
    pub const fn known_sequence(self) -> u64 {
        self.known_sequence
    }

    /// The other sequence number it came with now.
    pub const fn received_sequence(self) -> u64 {
        self.received_sequence
    }
}

/// A connection ID comes again with another stateless reset token
/// (PROTOCOL_VIOLATION, [RFC 9000 §19.15], MAY).
///
/// The tokens are not kept in the error, so that reporting it does not
/// reveal them.
///
/// [RFC 9000 §19.15]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "connection ID {id} with sequence number {sequence} comes with another stateless reset token"
))]
pub struct ResetTokenChangedError {
    sequence: u64,
    id: ConnectionId,
}

impl ResetTokenChangedError {
    /// Checks that the connection ID `id` with the sequence number
    /// `sequence` comes with the token it was issued with, `known` (none for
    /// a handshake connection ID the peer gave no token for).
    ///
    /// # Errors
    ///
    /// [`ResetTokenChangedError`] if `received` is another token.
    pub fn check(
        sequence: u64,
        id: ConnectionId,
        known: Option<StatelessResetToken>,
        received: StatelessResetToken,
    ) -> Result<(), Self> {
        ensure!(
            known == Some(received),
            ResetTokenChangedSnafu { sequence, id }
        );
        Ok(())
    }

    /// The sequence number.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// The connection ID.
    pub const fn id(self) -> ConnectionId {
        self.id
    }
}

/// One stateless reset token comes for two connection IDs
/// (PROTOCOL_VIOLATION, [RFC 9000 §10.3.2], MAY).
///
/// The token is not kept in the error, so that reporting it does not
/// reveal it.
///
/// [RFC 9000 §10.3.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "the stateless reset token of sequence number {sequence} is that of sequence number {other_sequence}"
))]
pub struct ResetTokenReusedError {
    sequence: u64,
    other_sequence: u64,
}

impl ResetTokenReusedError {
    /// Checks that `token`, received with the sequence number `sequence`,
    /// is not `other_token`, the token of the connection ID with
    /// `other_sequence`.
    ///
    /// # Errors
    ///
    /// [`ResetTokenReusedError`] if the tokens are equal and the sequence
    /// numbers differ.
    pub fn check(
        sequence: u64,
        token: StatelessResetToken,
        other_sequence: u64,
        other_token: StatelessResetToken,
    ) -> Result<(), Self> {
        ensure!(
            sequence == other_sequence || token != other_token,
            ResetTokenReusedSnafu {
                sequence,
                other_sequence
            }
        );
        Ok(())
    }

    /// The sequence number of the frame that repeats the token.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// The sequence number of the connection ID the token was issued with
    /// before, not [`sequence`](Self::sequence).
    pub const fn other_sequence(self) -> u64 {
        self.other_sequence
    }
}

/// The violations a NEW_CONNECTION_ID frame can commit.
///
/// The error code to close the connection with is
/// [`transport_error_code`](Self::transport_error_code).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum NewConnectionIdViolationError {
    /// More connection IDs are active than this side's
    /// `active_connection_id_limit` (CONNECTION_ID_LIMIT_ERROR).
    #[snafu(
        context(false),
        display("NEW_CONNECTION_ID exceeds the active connection ID limit")
    )]
    ActiveLimitExceeded {
        /// The number of active connection IDs and the limit.
        source: ActiveConnectionIdLimitExceededError,
    },
    /// More connection IDs wait for their retirement to be acknowledged
    /// than this side tracks (CONNECTION_ID_LIMIT_ERROR).
    #[snafu(
        context(false),
        display("NEW_CONNECTION_ID retires more connection IDs than this side tracks")
    )]
    RetirementLimitExceeded {
        /// The number of unacknowledged retirements and the limit.
        source: RetirementLimitExceededError,
    },
    /// The frame arrived while this side sends with the zero-length
    /// connection ID (PROTOCOL_VIOLATION).
    #[snafu(
        context(false),
        display("NEW_CONNECTION_ID received for a zero-length connection ID")
    )]
    ZeroLengthInUse {
        /// The frame's sequence number.
        source: ZeroLengthConnectionIdInUseError,
    },
    /// A sequence number comes with another connection ID
    /// (PROTOCOL_VIOLATION).
    #[snafu(context(false), display("NEW_CONNECTION_ID reuses a sequence number"))]
    SequenceNumberReused {
        /// The sequence number and both connection IDs.
        source: SequenceNumberReusedError,
    },
    /// A connection ID comes with another sequence number
    /// (PROTOCOL_VIOLATION).
    #[snafu(
        context(false),
        display("NEW_CONNECTION_ID gives a connection ID another sequence number")
    )]
    ConnectionIdResequenced {
        /// The connection ID and both sequence numbers.
        source: ConnectionIdResequencedError,
    },
    /// A connection ID comes with another stateless reset token
    /// (PROTOCOL_VIOLATION).
    #[snafu(
        context(false),
        display("NEW_CONNECTION_ID changes a stateless reset token")
    )]
    ResetTokenChanged {
        /// The sequence number and the connection ID.
        source: ResetTokenChangedError,
    },
    /// One stateless reset token comes for two connection IDs
    /// (PROTOCOL_VIOLATION).
    #[snafu(
        context(false),
        display("NEW_CONNECTION_ID repeats a stateless reset token")
    )]
    ResetTokenReused {
        /// The sequence numbers of both connection IDs.
        source: ResetTokenReusedError,
    },
}

impl NewConnectionIdViolationError {
    /// The QUIC transport error code to close the connection with.
    pub fn transport_error_code(&self) -> TransportErrorCode {
        match self {
            Self::ActiveLimitExceeded { .. } | Self::RetirementLimitExceeded { .. } => {
                TransportErrorCode::CONNECTION_ID_LIMIT_ERROR
            }
            Self::ZeroLengthInUse { .. }
            | Self::SequenceNumberReused { .. }
            | Self::ConnectionIdResequenced { .. }
            | Self::ResetTokenChanged { .. }
            | Self::ResetTokenReused { .. } => TransportErrorCode::PROTOCOL_VIOLATION,
        }
    }
}
