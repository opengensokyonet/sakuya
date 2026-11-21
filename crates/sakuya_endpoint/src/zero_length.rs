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
//!   [occupancy](ZeroLengthLocals::Occupancy) together with its route entry
//!   in a [`ZeroLengthRegistration`], so the local end is free again only
//!   once the entry is gone, after the connection's closing or draining
//!   period.
//! - Short headers that arrive on an occupied local end are also read with a
//!   zero-length destination connection ID: [`ZeroLengthLocalRecognizer`]
//!   adds that reading to the lengths the host's recognizer gives.
//!
//! The occupied local ends are a table every short header is looked up in,
//! so they are a trait whose handles reach their own structure, as the route
//! index is ([`synchronization`](crate::synchronization)):
//! [`HashSetZeroLengthLocals`] is the one of an endpoint on one thread.
//!
//! [RFC 9000 §5.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1
//! [RFC 9000 §5.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.2

use alloc::rc::Rc;
use core::{
    cell::RefCell,
    fmt,
    hash::{BuildHasher, Hash},
};

use hashbrown::HashSet;
use sakuya_datagram_routing::route::recognizer::ConnectionIdRecognizer;
use sakuya_link::LinkId;
use sakuya_wire_v1::connection_id::ConnectionIdLength;
use snafu::Snafu;

/// The local ends on which a connection uses zero-length local connection
/// IDs (`ZeroLengthLocals`): a handle, whose clones are the same table.
///
/// Occupying a local end and finding whether one is occupied each happen
/// within one access of the table, so that two connections never both
/// occupy one local end. The table is `Send` and `Sync` exactly as its
/// implementation makes it.
pub trait ZeroLengthLocals<Local>: Clone {
    /// One connection's hold on a local end; dropping it frees the local end
    /// (`ZeroLengthLocalOccupancy`). How it finds the table again is the
    /// implementation's.
    type Occupancy;

    /// No local end occupied.
    fn new() -> Self;

    /// Whether a connection uses zero-length local connection IDs on
    /// `local`.
    fn is_occupied(&self, local: &Local) -> bool;

    /// Occupies `local` for one connection, until the occupancy is dropped.
    ///
    /// # Errors
    ///
    /// [`ZeroLengthLocalCidInUseError`] when another connection occupies
    /// `local`.
    fn occupy(&self, local: Local) -> Result<Self::Occupancy, ZeroLengthLocalCidInUseError>;
}

/// The occupied local ends of an endpoint on one thread
/// (`HashSetZeroLengthLocals`): a hash set in a cell, which the table's
/// clones share through an `Rc`.
///
/// It is neither `Send` nor `Sync`. `S` builds the hashers of the set, and
/// the host chooses it; the local ends are this side's, not values the peer
/// chooses.
pub struct HashSetZeroLengthLocals<Local, S> {
    occupied: Rc<RefCell<HashSet<Local, S>>>,
}

impl<Local, S> Clone for HashSetZeroLengthLocals<Local, S> {
    fn clone(&self) -> Self {
        Self {
            occupied: Rc::clone(&self.occupied),
        }
    }
}

impl<Local, S> ZeroLengthLocals<Local> for HashSetZeroLengthLocals<Local, S>
where
    Local: Clone + Eq + Hash,
    S: BuildHasher + Default,
{
    type Occupancy = HashSetZeroLengthLocalOccupancy<Local, S>;

    fn new() -> Self {
        Self {
            occupied: Rc::new(RefCell::new(HashSet::with_hasher(S::default()))),
        }
    }

    fn is_occupied(&self, local: &Local) -> bool {
        let occupied = self.occupied.borrow();
        !occupied.is_empty() && occupied.contains(local)
    }

    fn occupy(
        &self,
        local: Local,
    ) -> Result<HashSetZeroLengthLocalOccupancy<Local, S>, ZeroLengthLocalCidInUseError> {
        if !self.occupied.borrow_mut().insert(local.clone()) {
            return Err(ZeroLengthLocalCidInUseError);
        }
        Ok(HashSetZeroLengthLocalOccupancy {
            occupied: Rc::clone(&self.occupied),
            local,
        })
    }
}

impl<Local, S> fmt::Debug for HashSetZeroLengthLocals<Local, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashSetZeroLengthLocals")
            .field("occupied", &self.occupied.borrow().len())
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

/// One connection's hold on a local end of a [`HashSetZeroLengthLocals`]; it
/// keeps the table, and dropping it frees the local end.
pub struct HashSetZeroLengthLocalOccupancy<Local: Eq + Hash, S: BuildHasher> {
    occupied: Rc<RefCell<HashSet<Local, S>>>,
    local: Local,
}

impl<Local: Eq + Hash, S: BuildHasher> HashSetZeroLengthLocalOccupancy<Local, S> {
    /// The occupied local end.
    #[must_use]
    pub fn local(&self) -> &Local {
        &self.local
    }
}

impl<Local: Eq + Hash, S: BuildHasher> Drop for HashSetZeroLengthLocalOccupancy<Local, S> {
    fn drop(&mut self) {
        self.occupied.borrow_mut().remove(&self.local);
    }
}

impl<Local: Eq + Hash + fmt::Debug, S: BuildHasher> fmt::Debug
    for HashSetZeroLengthLocalOccupancy<Local, S>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashSetZeroLengthLocalOccupancy")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

/// A connection's zero-length route entry `R` together with its occupancy
/// `O` of the local end.
///
/// Dropping it revokes the entry first and then frees the local end, so no
/// moment has two connections taking zero-length packets on one local end.
#[derive(Debug)]
pub struct ZeroLengthRegistration<R, O> {
    // Fields drop in this order.
    registration: R,
    occupancy: O,
}

impl<R, O> ZeroLengthRegistration<R, O> {
    /// Holds `registration`, the route entry registered for zero-length
    /// connection IDs on the local end of `occupancy`.
    #[must_use]
    pub fn new(registration: R, occupancy: O) -> Self {
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

    /// The occupancy of the local end.
    #[must_use]
    pub fn occupancy(&self) -> &O {
        &self.occupancy
    }
}

/// The host's connection ID recognizer `R`, which also reads a short header
/// with a zero-length destination connection ID when it arrives on a local
/// end a connection occupies in the table `Z`.
///
/// The host's recognizer need not know which connections chose zero-length
/// connection IDs. The extra reading is one more candidate, which claim
/// resolution tells apart from the others by packet protection.
#[derive(Debug)]
pub struct ZeroLengthLocalRecognizer<R, Z> {
    inner: R,
    locals: Z,
}

impl<R, Z> ZeroLengthLocalRecognizer<R, Z> {
    /// Wraps `inner`, adding the zero-length reading on the local ends
    /// occupied in `locals`.
    #[must_use]
    pub fn new(inner: R, locals: Z) -> Self {
        Self { inner, locals }
    }
}

impl<R, Z, Local, Peer> ConnectionIdRecognizer<Local, Peer> for ZeroLengthLocalRecognizer<R, Z>
where
    R: ConnectionIdRecognizer<Local, Peer>,
    Z: ZeroLengthLocals<Local>,
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
