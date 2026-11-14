//! Time: the clock a connection reads and sleeps on.
//!
//! Only the driver reads the clock: once at the start of each poll. That
//! instant is the "now" of everything the poll does; components keep
//! deadlines in their state and are handed the instant as an argument.
pub use sakuya_clock::{CheckedAdd, MonotonicClock};
use sakuya_link::{Link, LinkId};

/// The choices of a composition that belong to no part: the types every
/// part uses.
pub trait ConnectionChoices: 'static {
    /// The clock.
    type Clock: MonotonicClock;
    /// The links the connection sends over: the instants they report are
    /// those of the clock.
    type Link: Link<Instant = InstantOf<Self>>;
}

/// A point in time of the choices `T`.
pub type InstantOf<T> = <<T as ConnectionChoices>::Clock as MonotonicClock>::Instant;

/// The identity of a link of the choices `T`, with the types of its two
/// ends.
pub type LinkIdOf<T> = LinkId<
    <<T as ConnectionChoices>::Link as Link>::Local,
    <<T as ConnectionChoices>::Link as Link>::Peer,
>;
