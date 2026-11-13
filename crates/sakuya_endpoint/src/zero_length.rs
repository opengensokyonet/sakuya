//! Connections that choose zero-length local connection IDs.
//!
//! A connection whose local connection ID is zero-length is found by the
//! local end of the link its packets arrive on ([RFC 9000 §5.2]). Each
//! connection chooses this for itself, so connections with zero-length and
//! with other connection IDs share a binding. The endpoint keeps the rules
//! that follow:
//!
//! - At most one connection uses zero-length connection IDs on one local end
//!   ([RFC 9000 §5.1]): [`ZeroLengthLocals::occupy`] fails for a second one
//!   with [`ZeroLengthLocalCidInUseError`]. A connection holds its
//!   [`ZeroLengthLocalOccupancy`] together with its route entry in a
//!   [`ZeroLengthRegistration`], so the local end is free again only once
//!   the entry is gone, after the connection's closing or draining period.
//! - Short headers that arrive on an occupied local end are also read with a
//!   zero-length destination connection ID: [`ZeroLengthLocalRecognizer`]
//!   adds that reading to the lengths the host's recognizer gives.
//!
//! [RFC 9000 §5.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1
//! [RFC 9000 §5.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.2

use std::{
    fmt,
    hash::Hash,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use dashmap::DashSet;
use sakuya_datagram_routing::route::recognizer::ConnectionIdRecognizer;
use sakuya_link::LinkId;
use sakuya_wire::connection_id::ConnectionIdLength;
use snafu::Snafu;

/// The local ends on which a connection uses zero-length local connection
/// IDs.
pub struct ZeroLengthLocals<Local: Eq + Hash> {
    occupied: DashSet<Local>,
    /// How many local ends are occupied, so that the common case of none
    /// reads no set.
    count: AtomicUsize,
}

impl<Local: Eq + Hash> ZeroLengthLocals<Local> {
    /// No local end occupied.
    #[must_use]
    pub fn new() -> Self {
        Self {
            occupied: DashSet::new(),
            count: AtomicUsize::new(0),
        }
    }

    /// Whether a connection uses zero-length local connection IDs on
    /// `local`.
    #[must_use]
    pub fn is_occupied(&self, local: &Local) -> bool {
        self.count.load(Ordering::Acquire) != 0 && self.occupied.contains(local)
    }
}

impl<Local: Clone + Eq + Hash> ZeroLengthLocals<Local> {
    /// Occupies `local` for one connection until the returned occupancy is
    /// dropped.
    ///
    /// # Errors
    ///
    /// [`ZeroLengthLocalCidInUseError`] when another connection already
    /// occupies `local`.
    pub fn occupy(
        self: &Arc<Self>,
        local: Local,
    ) -> Result<ZeroLengthLocalOccupancy<Local>, ZeroLengthLocalCidInUseError> {
        if !self.occupied.insert(local.clone()) {
            return Err(ZeroLengthLocalCidInUseError);
        }
        self.count.fetch_add(1, Ordering::AcqRel);
        Ok(ZeroLengthLocalOccupancy {
            locals: Arc::clone(self),
            local,
        })
    }
}

impl<Local: Eq + Hash> Default for ZeroLengthLocals<Local> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Local: Eq + Hash> fmt::Debug for ZeroLengthLocals<Local> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZeroLengthLocals")
            .field("occupied", &self.count.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// The local end of the arriving link already has a connection that uses
/// zero-length local connection IDs ([RFC 9000 §5.1]).
///
/// [RFC 9000 §5.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1
#[derive(Debug, Snafu)]
#[snafu(display("a connection already uses zero-length connection IDs on this local end"))]
pub struct ZeroLengthLocalCidInUseError;

/// One connection's hold on a local end for zero-length local connection
/// IDs; dropping it frees the local end.
pub struct ZeroLengthLocalOccupancy<Local: Eq + Hash> {
    locals: Arc<ZeroLengthLocals<Local>>,
    local: Local,
}

impl<Local: Eq + Hash> ZeroLengthLocalOccupancy<Local> {
    /// The occupied local end.
    #[must_use]
    pub fn local(&self) -> &Local {
        &self.local
    }
}

impl<Local: Eq + Hash> Drop for ZeroLengthLocalOccupancy<Local> {
    fn drop(&mut self) {
        // invariant: only `occupy` makes an occupancy, after inserting its
        // local end, and only this drop removes it.
        if self.locals.occupied.remove(&self.local).is_some() {
            self.locals.count.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl<Local: Eq + Hash + fmt::Debug> fmt::Debug for ZeroLengthLocalOccupancy<Local> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZeroLengthLocalOccupancy")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

/// A connection's zero-length route entry `R` together with its occupancy of
/// the local end.
///
/// Dropping it revokes the entry first and then frees the local end, so no
/// moment has two connections taking zero-length packets on one local end.
#[derive(Debug)]
pub struct ZeroLengthRegistration<R, Local: Eq + Hash> {
    // Fields drop in this order.
    registration: R,
    occupancy: ZeroLengthLocalOccupancy<Local>,
}

impl<R, Local: Eq + Hash> ZeroLengthRegistration<R, Local> {
    /// Holds `registration`, the route entry registered for zero-length
    /// connection IDs on the local end of `occupancy`.
    #[must_use]
    pub fn new(registration: R, occupancy: ZeroLengthLocalOccupancy<Local>) -> Self {
        Self {
            registration,
            occupancy,
        }
    }

    /// The route entry.
    #[must_use]
    pub fn registration(&self) -> &R {
        &self.registration
    }

    /// The occupied local end.
    #[must_use]
    pub fn local(&self) -> &Local {
        self.occupancy.local()
    }
}

/// The host's connection ID recognizer `R`, which also reads a short header
/// with a zero-length destination connection ID when it arrives on a local
/// end a connection occupies.
///
/// The host's recognizer need not know which connections chose zero-length
/// connection IDs. The extra reading is one more candidate, which claim
/// resolution tells apart from the others by packet protection.
#[derive(Debug)]
pub struct ZeroLengthLocalRecognizer<R, Local: Eq + Hash> {
    inner: R,
    locals: Arc<ZeroLengthLocals<Local>>,
}

impl<R, Local: Eq + Hash> ZeroLengthLocalRecognizer<R, Local> {
    /// Wraps `inner`, adding the zero-length reading on the local ends
    /// occupied in `locals`.
    #[must_use]
    pub fn new(inner: R, locals: Arc<ZeroLengthLocals<Local>>) -> Self {
        Self { inner, locals }
    }
}

impl<R, Local, Peer> ConnectionIdRecognizer<Local, Peer> for ZeroLengthLocalRecognizer<R, Local>
where
    R: ConnectionIdRecognizer<Local, Peer>,
    Local: Eq + Hash,
{
    fn short_dcid_lengths<'a>(
        &'a self,
        datagram: &'a [u8],
        link: &'a LinkId<Local, Peer>,
    ) -> impl Iterator<Item = ConnectionIdLength> + 'a {
        let add_zero = self.locals.is_occupied(&link.local);
        self.inner
            .short_dcid_lengths(datagram, link)
            // The zero-length reading is yielded once, after the host's.
            .filter(move |&length| !(add_zero && length == ConnectionIdLength::ZERO))
            .chain(add_zero.then_some(ConnectionIdLength::ZERO))
    }
}

#[cfg(test)]
mod tests;
