//! Recognizing and generating connection IDs
//!
//! A short header does not state the length of its destination connection ID;
//! only the side that issued the connection ID knows how to read it. Routing
//! therefore asks a [`ConnectionIdRecognizer`] for every length under which a
//! short header can be read, and reads each with
//! [`read_short_header`](sakuya_wire::header::codec::read_short_header). Generation
//! and recognition must agree, which is the implementation's responsibility:
//! routing keeps no format numbers, length registry or pairing credentials.
//!
//! [`ConnectionIdLengths`] and [`LeastOccupiedConnectionIds`] are one simple
//! pair: a fixed set of accepted lengths, and generation of one of them that
//! prefers values few entries use. Neither is a required framework.

use std::num::NonZeroUsize;

use sakuya_link::LinkId;
use sakuya_wire::connection_id::{ConnectionId, ConnectionIdLengthError, NonEmptyCid};
use smallvec::SmallVec;

/// Reads the destination connection IDs a short header may carry.
pub trait ConnectionIdRecognizer {
    /// Yields every destination connection ID length under which the short
    /// header at the start of `datagram`, arriving on `link`, can be read.
    ///
    /// Each length is a separate interpretation; a length of zero is the
    /// explicit zero-length interpretation, and it is offered only when the
    /// recognizer yields it. Yielding a length longer than the datagram, or
    /// than [`ConnectionId::MAX_LEN`], yields no interpretation for it.
    fn short_dcid_lengths<'a>(
        &'a self,
        datagram: &'a [u8],
        link: &'a LinkId,
    ) -> impl Iterator<Item = usize> + 'a;
}

/// A recognizer that accepts a fixed set of connection ID lengths.
///
/// A set may hold several lengths, for example while older connection IDs of
/// another length are still alive, and it may hold zero to accept zero-length
/// connection IDs on every link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionIdLengths {
    lengths: SmallVec<[u8; 4]>,
}

impl ConnectionIdLengths {
    /// Accepts the given lengths, in order, ignoring repetitions.
    ///
    /// # Errors
    ///
    /// [`ConnectionIdLengthError`] if a length exceeds
    /// [`ConnectionId::MAX_LEN`].
    pub fn new(lengths: &[usize]) -> Result<Self, ConnectionIdLengthError> {
        let mut accepted = SmallVec::new();
        for &length in lengths {
            let byte = valid_length(length)?;
            if !accepted.contains(&byte) {
                accepted.push(byte);
            }
        }
        Ok(Self { lengths: accepted })
    }

    /// The accepted lengths.
    pub fn lengths(&self) -> impl Iterator<Item = usize> + '_ {
        self.lengths.iter().map(|&length| usize::from(length))
    }
}

impl ConnectionIdRecognizer for ConnectionIdLengths {
    fn short_dcid_lengths<'a>(
        &'a self,
        _datagram: &'a [u8],
        _link: &'a LinkId,
    ) -> impl Iterator<Item = usize> + 'a {
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
    fn generate(&self, occupancy: &dyn ConnectionIdOccupancy) -> ConnectionId;
}

/// Generates connection IDs of one length, preferring the least used of a few
/// random samples.
///
/// The random bytes come from `fill`, which the owner supplies. A length of
/// zero always generates the zero-length connection ID.
pub struct LeastOccupiedConnectionIds<Fill> {
    length: u8,
    samples: NonZeroUsize,
    fill: Fill,
}

impl<Fill: Fn(&mut [u8])> LeastOccupiedConnectionIds<Fill> {
    /// Generates connection IDs of `length` bytes from `samples` candidates
    /// each, filled by `fill`.
    ///
    /// # Errors
    ///
    /// [`ConnectionIdLengthError`] if `length` exceeds
    /// [`ConnectionId::MAX_LEN`].
    pub fn new(
        length: usize,
        samples: NonZeroUsize,
        fill: Fill,
    ) -> Result<Self, ConnectionIdLengthError> {
        Ok(Self {
            length: valid_length(length)?,
            samples,
            fill,
        })
    }

    fn sample(&self) -> ConnectionId {
        let mut bytes = [0; ConnectionId::MAX_LEN];
        let active = &mut bytes[..usize::from(self.length)];
        (self.fill)(active);
        ConnectionId::new(active).expect("the length was validated")
    }
}

impl<Fill: Fn(&mut [u8])> ConnectionIdGenerator for LeastOccupiedConnectionIds<Fill> {
    fn generate(&self, occupancy: &dyn ConnectionIdOccupancy) -> ConnectionId {
        if self.length == 0 {
            return ConnectionId::EMPTY;
        }
        (0..self.samples.get())
            .map(|_| self.sample())
            .min_by_key(|cid| NonEmptyCid::new(*cid).map_or(0, |cid| occupancy.occupancy(&cid)))
            .expect("at least one sample is taken")
    }
}

impl<Fill> std::fmt::Debug for LeastOccupiedConnectionIds<Fill> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeastOccupiedConnectionIds")
            .field("length", &self.length)
            .field("samples", &self.samples)
            .finish_non_exhaustive()
    }
}

fn valid_length(length: usize) -> Result<u8, ConnectionIdLengthError> {
    if length > ConnectionId::MAX_LEN {
        return Err(ConnectionIdLengthError { length });
    }
    Ok(u8::try_from(length).expect("connection ID lengths fit in a byte"))
}
