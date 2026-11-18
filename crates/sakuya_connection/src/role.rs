//! What a link path does: the role of a link path.

use crate::{
    component_event::Happened, send_strategy::LinkPathRoleKind,
    v1::component_events::LinkPathRoleChanged,
};

/// What a link path does, and when it ends.
///
/// The role holds only its mark and its end time; the recovery state of the
/// link path is the recovery layer below it, which exists while the role is
/// `Active` or `Settling`. `I` is the instant of the connection's clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkPathRole<I> {
    /// Being validated: only probing is sent, and no recovery layer exists.
    Candidate,
    /// The link path that application data is sent over (RFC 9000's active
    /// path).
    Active,
    /// A link path that is no longer active: only PATH_RESPONSE is sent,
    /// late acknowledgements are still settled, and at the instant the link
    /// path ends with what is unsettled handed back.
    Settling(I),
    /// The connection is closing: when packets arrive, the close packet is
    /// sent back; the link path ends at the instant.
    Closing(I),
    /// The connection is draining: nothing is sent; the link path ends at
    /// the instant.
    Draining(I),
}

impl<I: Copy> LinkPathRole<I> {
    /// The instant the link path ends, if it has one.
    pub fn end_time(&self) -> Option<I> {
        match self {
            Self::Candidate | Self::Active => None,
            Self::Settling(at) | Self::Closing(at) | Self::Draining(at) => Some(*at),
        }
    }

    /// The role as the send strategy sees it.
    pub fn kind(&self) -> LinkPathRoleKind {
        match self {
            Self::Candidate => LinkPathRoleKind::Candidate,
            Self::Active => LinkPathRoleKind::Active,
            Self::Settling(_) => LinkPathRoleKind::Settling,
            Self::Closing(_) => LinkPathRoleKind::Closing,
            Self::Draining(_) => LinkPathRoleKind::Draining,
        }
    }

    /// Whether the link path has a recovery layer in this role.
    pub fn has_recovery(&self) -> bool {
        matches!(self, Self::Active | Self::Settling(_))
    }

    /// Enter `Closing`, ending at `at`: a link path already closing or
    /// draining keeps its role. What happened, when the role changed.
    #[must_use = "what happened is to be published in the lend"]
    pub fn close(&mut self, at: I) -> Option<Happened<LinkPathRoleChanged>> {
        if matches!(self, Self::Closing(_) | Self::Draining(_)) {
            return None;
        }
        *self = Self::Closing(at);
        Some(Happened::new())
    }

    /// Enter `Draining`. A closing link path keeps its end time (RFC 9000
    /// §10.2.2); any other ends at `at`. What happened, when the role
    /// changed.
    #[must_use = "what happened is to be published in the lend"]
    pub fn drain(&mut self, at: I) -> Option<Happened<LinkPathRoleChanged>> {
        let draining = matches!(self, Self::Draining(_));
        *self = match *self {
            Self::Closing(end) | Self::Draining(end) => Self::Draining(end),
            Self::Candidate | Self::Active | Self::Settling(_) => Self::Draining(at),
        };
        (!draining).then(Happened::new)
    }
}
