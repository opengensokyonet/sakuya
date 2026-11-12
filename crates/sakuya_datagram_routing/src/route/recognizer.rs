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
//! A [`ConnectionIdGenerator`] issues the connection IDs of one connection,
//! with their stateless reset tokens, and may compute a token again later for
//! a connection whose state is gone.
//!
//! [`ConnectionIdLengths`] and [`LeastOccupiedConnectionIds`] are one simple
//! pair: a fixed set of accepted lengths, and generation of one of them that
//! prefers values few entries use. Neither is a required framework.

use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;

use sakuya_link::LinkId;
use sakuya_wire::connection_id::{
    ConnectionId, ConnectionIdLength, NonEmptyCid, StatelessResetToken,
};
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

impl<Occupancy: ConnectionIdOccupancy + ?Sized> ConnectionIdOccupancy for &Occupancy {
    fn occupancy(&self, cid: &NonEmptyCid) -> usize {
        (**self).occupancy(cid)
    }
}

impl<Occupancy: ConnectionIdOccupancy + ?Sized> ConnectionIdOccupancy for Arc<Occupancy> {
    fn occupancy(&self, cid: &NonEmptyCid) -> usize {
        (**self).occupancy(cid)
    }
}

/// Produces the connection IDs one connection issues, with their stateless
/// reset tokens.
///
/// Every connection holds its own generator value, made from the endpoint's
/// [`Config`](Self::Config) when the connection is created. Whether
/// connections share state is up to the implementation, for example a shared
/// counter or key held inside the value.
pub trait ConnectionIdGenerator {
    /// What the endpoint keeps to make a generator for each connection.
    type Config: Clone;

    /// Makes the generator of one connection.
    fn new(config: &Self::Config) -> Self;

    /// Generates a connection ID according to the generator's own policy,
    /// with the stateless reset token issued with it.
    ///
    /// The connection ID is not promised to be unique; the connection ID
    /// manager registers it and discloses it only after the registration took
    /// effect. The token must be hard to guess ([RFC 9000 §10.3]).
    ///
    /// [RFC 9000 §10.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3
    fn generate(&mut self) -> (ConnectionId, StatelessResetToken);

    /// Computes again the stateless reset token that a generator made from
    /// `config` issued with `cid`, without any state of the connection.
    ///
    /// A generator that derives tokens from the connection ID and a static
    /// key ([RFC 9000 §10.3.2]) returns it; one that draws tokens at random
    /// returns `None`, and then no stateless reset is sent for `cid`.
    ///
    /// [RFC 9000 §10.3.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3.2
    fn stateless_reset_token(
        config: &Self::Config,
        cid: &ConnectionId,
    ) -> Option<StatelessResetToken>;
}

/// Generates connection IDs of one length, preferring the least used of a few
/// random samples, with random stateless reset tokens.
///
/// The random bytes of connection IDs and tokens come from `fill`, which the
/// owner supplies and which must be unpredictable. The route entries in use
/// are read from `occupancy`. A length of zero always generates the
/// zero-length connection ID. Tokens are not derived, so
/// [`stateless_reset_token`](ConnectionIdGenerator::stateless_reset_token)
/// is always `None`. The value is its own configuration: every connection
/// gets a clone.
#[derive(Clone)]
pub struct LeastOccupiedConnectionIds<Occupancy, Fill> {
    length: ConnectionIdLength,
    samples: NonZeroUsize,
    occupancy: Occupancy,
    fill: Fill,
}

impl<Occupancy, Fill> LeastOccupiedConnectionIds<Occupancy, Fill>
where
    Occupancy: ConnectionIdOccupancy,
    Fill: Fn(&mut [u8]),
{
    /// Generates connection IDs of `length` bytes from `samples` candidates
    /// each, filled by `fill` and compared by `occupancy`.
    pub fn new(
        length: ConnectionIdLength,
        samples: NonZeroUsize,
        occupancy: Occupancy,
        fill: Fill,
    ) -> Self {
        Self {
            length,
            samples,
            occupancy,
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

    fn least_occupied(&self) -> ConnectionId {
        if self.length.is_zero() {
            return ConnectionId::EMPTY;
        }
        let occupied = |cid: &ConnectionId| {
            NonEmptyCid::new(*cid).map_or(0, |cid| self.occupancy.occupancy(&cid))
        };
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

impl<Occupancy, Fill> ConnectionIdGenerator for LeastOccupiedConnectionIds<Occupancy, Fill>
where
    Occupancy: ConnectionIdOccupancy + Clone,
    Fill: Fn(&mut [u8]) + Clone,
{
    type Config = Self;

    fn new(config: &Self) -> Self {
        config.clone()
    }

    fn generate(&mut self) -> (ConnectionId, StatelessResetToken) {
        let cid = self.least_occupied();
        let mut token = [0; StatelessResetToken::LEN];
        (self.fill)(&mut token);
        (cid, StatelessResetToken::new(token))
    }

    fn stateless_reset_token(_config: &Self, _cid: &ConnectionId) -> Option<StatelessResetToken> {
        None
    }
}

impl<Occupancy, Fill> fmt::Debug for LeastOccupiedConnectionIds<Occupancy, Fill> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeastOccupiedConnectionIds")
            .field("length", &self.length)
            .field("samples", &self.samples)
            .finish_non_exhaustive()
    }
}
