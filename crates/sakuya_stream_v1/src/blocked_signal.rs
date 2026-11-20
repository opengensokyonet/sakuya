//! The intent to send a BLOCKED frame (`DATA_BLOCKED`, `STREAMS_BLOCKED`)
//! once for each limit, shared by the connection-level signals.
//!
//! It follows the stream-level
//! [`FullCeilingAdmission`](crate::send::flow_control::FullCeilingAdmission):
//! the intent arises only when the sender is actually blocked at a limit; a
//! frame carrying a limit is wanted once, so a sent frame ends the intent for
//! that limit; a higher limit clears the intent left from a lower one.

/// The intent to signal being blocked at a limit `L`:
///
/// ```text
///          blocked at L               sent L
///   Quiet ─────────────▶ Wanted(L) ◀────────▶ Signalled(L)
///     ▲                     │        lost L       │
///     └───── limit raised above L ────────────────┘
/// ```
///
/// Being blocked at a higher limit than the one recorded moves to
/// `Wanted` of the higher limit; at a lower one it changes nothing, since
/// limits only grow and the lower one is stale.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum BlockedSignal<L> {
    /// No frame is wanted, and none was sent for a limit still in effect.
    #[default]
    Quiet,
    /// A frame carrying `L` is wanted.
    Wanted(L),
    /// A frame carrying `L` was sent; no other is wanted for `L`.
    Signalled(L),
}

impl<L: Copy + Ord> BlockedSignal<L> {
    /// Records that the sender was actually blocked at `limit`.
    pub(crate) fn on_blocked(&mut self, limit: L) {
        match *self {
            Self::Wanted(recorded) | Self::Signalled(recorded) if recorded >= limit => {}
            Self::Quiet | Self::Wanted(_) | Self::Signalled(_) => *self = Self::Wanted(limit),
        }
    }

    /// Records that a frame carrying `limit` was sent.
    ///
    /// A frame for a limit that is no longer wanted changes nothing.
    pub(crate) fn on_sent(&mut self, limit: L) {
        if *self == Self::Wanted(limit) {
            *self = Self::Signalled(limit);
        }
    }

    /// Records that a frame carrying `limit` was lost: while it is still
    /// the limit recorded as signalled, a frame carrying it is wanted again
    /// ([RFC 9000 §13.3]). A frame for another limit changes nothing.
    ///
    /// [RFC 9000 §13.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-13.3
    pub(crate) fn on_lost(&mut self, limit: L) {
        if *self == Self::Signalled(limit) {
            *self = Self::Wanted(limit);
        }
    }

    /// Records that the limit grew to `limit`: an intent for a lower limit
    /// is cleared.
    pub(crate) fn on_limit_raised(&mut self, limit: L) {
        match *self {
            Self::Wanted(recorded) | Self::Signalled(recorded) if recorded < limit => {
                *self = Self::Quiet;
            }
            Self::Quiet | Self::Wanted(_) | Self::Signalled(_) => {}
        }
    }

    /// The limit a frame is wanted for, if any.
    pub(crate) fn wanted(self) -> Option<L> {
        match self {
            Self::Wanted(limit) => Some(limit),
            Self::Quiet | Self::Signalled(_) => None,
        }
    }
}

#[cfg(test)]
mod tests;
