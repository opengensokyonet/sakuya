//! Recognizing and generating connection IDs
//!
//! A short header does not state the length of its destination connection ID;
//! only the side that issued the connection ID knows how to read it. Routing
//! therefore asks a [`ConnectionIdRecognizer`] for every
//! [`ConnectionIdLength`] under which a short header can be read, and reads
//! each with
//! [`read_short_header`](sakuya_wire::header::codec::read_short_header). Generation
//! and recognition must agree, which is the implementation's responsibility:
//! routing keeps no format numbers, length registry or pairing credentials.
//!
//! [`ConnectionIdLengths`] and [`LeastOccupiedConnectionIds`] are one simple
//! pair: a fixed set of accepted lengths, and generation of one of them that
//! prefers values few entries use. Neither is a required framework.

use std::fmt;
use std::num::NonZeroUsize;

use sakuya_link::LinkId;
use sakuya_wire::connection_id::{ConnectionId, ConnectionIdLength, NonEmptyCid};
use smallvec::SmallVec;

/// Reads the destination connection IDs a short header may carry.
///
/// `Local` and `Peer` are the ends of the links the datagrams arrive on
/// ([`sakuya_link::Link::Local`], [`sakuya_link::Link::Peer`]); an
/// implementation that cares about one kind of end implements the trait for
/// that type only.
pub trait ConnectionIdRecognizer<Local, Peer> {
    /// Yields every destination connection ID length under which the short
    /// header at the start of `datagram`, arriving on `link`, can be read.
    ///
    /// Each length is a separate interpretation; [`ConnectionIdLength::ZERO`]
    /// is the explicit zero-length interpretation, and it is offered only when
    /// the recognizer yields it. A length longer than the datagram yields no
    /// interpretation.
    fn short_dcid_lengths<'a>(
        &'a self,
        datagram: &'a [u8],
        link: &'a LinkId<Local, Peer>,
    ) -> impl Iterator<Item = ConnectionIdLength> + 'a;
}

/// A recognizer that accepts a fixed set of connection ID lengths.
///
/// A set may hold several lengths, for example while older connection IDs of
/// another length are still alive, and it may hold zero to accept zero-length
/// connection IDs on every link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionIdLengths {
    lengths: SmallVec<[ConnectionIdLength; 4]>,
}

impl ConnectionIdLengths {
    /// Accepts the given lengths, in order, ignoring repetitions.
    pub fn new(lengths: impl IntoIterator<Item = ConnectionIdLength>) -> Self {
        let mut accepted = SmallVec::new();
        for length in lengths {
            if !accepted.contains(&length) {
                accepted.push(length);
            }
        }
        Self { lengths: accepted }
    }

    /// The accepted lengths.
    pub fn lengths(&self) -> impl Iterator<Item = ConnectionIdLength> + '_ {
        self.lengths.iter().copied()
    }
}

impl<Local, Peer> ConnectionIdRecognizer<Local, Peer> for ConnectionIdLengths {
    fn short_dcid_lengths<'a>(
        &'a self,
        _datagram: &'a [u8],
        _link: &'a LinkId<Local, Peer>,
    ) -> impl Iterator<Item = ConnectionIdLength> + 'a {
        self.lengths()
    }
}

/// How many route entries currently use a connection ID.
///
/// Generation may consult it to avoid values in use. It is an observation,
/// not a reservation: the value can be taken right after it is read, and a
/// collision is legal.
pub trait ConnectionIdOccupancy {
    /// The number of local and Initial entries registered under `cid`.
    fn occupancy(&self, cid: &NonEmptyCid) -> usize;
}

/// Produces connection IDs for this side to issue.
pub trait ConnectionIdGenerator {
    /// Generates a connection ID according to the generator's own policy,
    /// possibly consulting `occupancy`.
    ///
    /// The result is not promised to be unique; the connection ID manager
    /// registers it and discloses it only after the registration took effect.
    fn generate(&self, occupancy: &impl ConnectionIdOccupancy) -> ConnectionId;
}

/// Generates connection IDs of one length, preferring the least used of a few
/// random samples.
///
/// The random bytes come from `fill`, which the owner supplies. A length of
/// zero always generates the zero-length connection ID.
pub struct LeastOccupiedConnectionIds<Fill> {
    length: ConnectionIdLength,
    samples: NonZeroUsize,
    fill: Fill,
}

impl<Fill: Fn(&mut [u8])> LeastOccupiedConnectionIds<Fill> {
    /// Generates connection IDs of `length` bytes from `samples` candidates
    /// each, filled by `fill`.
    pub fn new(length: ConnectionIdLength, samples: NonZeroUsize, fill: Fill) -> Self {
        Self {
            length,
            samples,
            fill,
        }
    }

    fn sample(&self) -> ConnectionId {
        let mut bytes = [0; ConnectionId::MAX_LEN];
        let active = &mut bytes[..self.length.get()];
        (self.fill)(active);
        // invariant: a `ConnectionIdLength` never exceeds
        // `ConnectionId::MAX_LEN`, so `active` is a valid connection ID.
        ConnectionId::new(active).expect("a connection ID length is at most the maximum")
    }
}

impl<Fill: Fn(&mut [u8])> ConnectionIdGenerator for LeastOccupiedConnectionIds<Fill> {
    fn generate(&self, occupancy: &impl ConnectionIdOccupancy) -> ConnectionId {
        if self.length.is_zero() {
            return ConnectionId::EMPTY;
        }
        let occupied =
            |cid: &ConnectionId| NonEmptyCid::new(*cid).map_or(0, |cid| occupancy.occupancy(&cid));
        let first = self.sample();
        let first_occupied = occupied(&first);
        let (least, _) = (1..self.samples.get()).fold((first, first_occupied), |least, _| {
            let sample = self.sample();
            let sample_occupied = occupied(&sample);
            if sample_occupied < least.1 {
                (sample, sample_occupied)
            } else {
                least
            }
        });
        least
    }
}

impl<Fill> fmt::Debug for LeastOccupiedConnectionIds<Fill> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeastOccupiedConnectionIds")
            .field("length", &self.length)
            .field("samples", &self.samples)
            .finish_non_exhaustive()
    }
}
