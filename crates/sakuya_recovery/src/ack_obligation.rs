//! When to acknowledge what one packet number space received (RFC 9000
//! §13.2.1, §13.2.2).
//!
//! The receive journals keep what was received; the
//! [`AckObligation`] decides whether an ACK frame is due now, by an
//! instant, or not at all. It sees the same packets as the journals, at the
//! same moment, and is replaceable: an extension such as ACK_FREQUENCY
//! changes its thresholds and delays, not the storage of ranges.
//! [`Rfc9000AckObligation`] follows RFC 9000.
use core::{ops::Add, time::Duration};

use sakuya_wire::v1::packet_number::PacketNumber;

/// Whether an ACK frame is due. `I` is the type of instants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AckDue<I> {
    /// Nothing is due.
    NotDue,
    /// Send an ACK frame now.
    Now,
    /// Send an ACK frame by this instant.
    By(I),
}

impl<I: Ord + Copy> AckDue<I> {
    /// The tighter of the two: `Now` before any instant, an earlier instant
    /// before a later one, any of them before `NotDue`.
    #[must_use]
    pub fn tighter(self, other: Self) -> Self {
        match (self, other) {
            (Self::Now, _) | (_, Self::Now) => Self::Now,
            (Self::By(a), Self::By(b)) => Self::By(a.min(b)),
            (Self::By(at), Self::NotDue) | (Self::NotDue, Self::By(at)) => Self::By(at),
            (Self::NotDue, Self::NotDue) => Self::NotDue,
        }
    }

    /// The instant when an ACK frame is due by, if any.
    pub fn deadline(self) -> Option<I> {
        match self {
            Self::By(at) => Some(at),
            Self::NotDue | Self::Now => None,
        }
    }
}

/// Whether and when one packet number space must acknowledge what it
/// received. `I` is the type of instants.
///
/// Every method is one event. The fixed code calls
/// [`record`](Self::record) right after the receive journals record the
/// same packet, [`ack_written`](Self::ack_written) when an ACK frame of this
/// space goes into a packet, [`ack_lost`](Self::ack_lost) when that packet
/// is declared lost or its send result is unknown, and
/// [`on_deadline`](Self::on_deadline) when the instant of
/// [`due`](Self::due) came.
pub trait AckObligation<I> {
    /// The obligation of a space whose ack-eliciting packets are
    /// acknowledged at the latest `max_delay` after they arrive; `None` for
    /// a space whose ack-eliciting packets are acknowledged at once (the
    /// Initial and Handshake spaces, RFC 9000 §13.2.1).
    fn new(max_delay: Option<Duration>) -> Self
    where
        Self: Sized;

    /// A packet was processed: its number, when it arrived, whether it was
    /// ack-eliciting, whether it arrived with CE, and where the run of
    /// processed packet numbers just below it starts
    /// ([`received_run_below`](crate::receive_journals::ReceiveJournals::received_run_below)).
    fn record(
        &mut self,
        number: PacketNumber,
        at: I,
        ack_eliciting: bool,
        ecn_ce: bool,
        run_below: Option<PacketNumber>,
    );

    /// What is due now.
    fn due(&self) -> AckDue<I>;

    /// Whether a packet of this space that is sent anyway should carry an
    /// ACK frame.
    fn wants_piggyback(&self) -> bool;

    /// An ACK frame whose Largest Acknowledged is `largest` was written into
    /// a packet: nothing is due any more. Returns what was due before, to
    /// be kept with the packet for [`ack_lost`](Self::ack_lost).
    fn ack_written(&mut self, largest: PacketNumber) -> AckDue<I>;

    /// The packet that carried an ACK frame was declared lost, or its send
    /// result is unknown; `before` is what [`ack_written`](Self::ack_written)
    /// returned for it. What is due becomes the tighter of the two.
    fn ack_lost(&mut self, before: AckDue<I>);

    /// The instant of [`due`](Self::due) came at `now`: an ACK frame is due
    /// now. Afterwards `due` has no instant at or before `now`.
    fn on_deadline(&mut self, now: I);
}

/// The acknowledgment rules of RFC 9000 §13.2.
///
/// An ack-eliciting packet is acknowledged at once when its space has no
/// delay (Initial, Handshake), when it is the second ack-eliciting packet
/// since the last ACK frame (§13.2.2), when it arrived with CE, when it is
/// below the largest ack-eliciting packet number received, or when packets
/// are missing between that one and it; otherwise by the delay after it
/// arrived, keeping an earlier instant already set. A packet that is not
/// ack-eliciting creates no obligation, but a packet sent anyway carries an
/// ACK frame once the ranges changed since the last one (§13.2: the peer
/// learns its ACK-only packets arrived and can trim its ranges).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rfc9000AckObligation<I> {
    max_delay: Option<Duration>,
    due: AckDue<I>,
    eliciting_since_written: u32,
    largest_eliciting: Option<PacketNumber>,
    changed_since_written: bool,
}

impl<I: Ord + Copy + Add<Duration, Output = I>> AckObligation<I> for Rfc9000AckObligation<I> {
    fn new(max_delay: Option<Duration>) -> Self {
        Self {
            max_delay,
            due: AckDue::NotDue,
            eliciting_since_written: 0,
            largest_eliciting: None,
            changed_since_written: false,
        }
    }

    fn record(
        &mut self,
        number: PacketNumber,
        at: I,
        ack_eliciting: bool,
        ecn_ce: bool,
        run_below: Option<PacketNumber>,
    ) {
        self.changed_since_written = true;
        if !ack_eliciting {
            return;
        }
        self.eliciting_since_written = self.eliciting_since_written.saturating_add(1);
        let out_of_order = self.largest_eliciting.is_some_and(|largest| {
            let next = largest.checked_add(1).unwrap_or(PacketNumber::MAX);
            number < largest || (number > next && run_below.is_none_or(|start| start > next))
        });
        if self
            .largest_eliciting
            .is_none_or(|largest| number > largest)
        {
            self.largest_eliciting = Some(number);
        }
        let now = match self.max_delay {
            None => true,
            Some(_) => ecn_ce || out_of_order || self.eliciting_since_written >= 2,
        };
        self.due = match (now, self.max_delay) {
            (true, _) | (false, None) => AckDue::Now,
            (false, Some(delay)) => self.due.tighter(AckDue::By(at + delay)),
        };
    }

    fn due(&self) -> AckDue<I> {
        self.due
    }

    fn wants_piggyback(&self) -> bool {
        self.due != AckDue::NotDue || self.changed_since_written
    }

    fn ack_written(&mut self, _largest: PacketNumber) -> AckDue<I> {
        self.eliciting_since_written = 0;
        self.changed_since_written = false;
        core::mem::replace(&mut self.due, AckDue::NotDue)
    }

    fn ack_lost(&mut self, before: AckDue<I>) {
        self.due = self.due.tighter(before);
    }

    fn on_deadline(&mut self, now: I) {
        if let AckDue::By(at) = self.due
            && at <= now
        {
            self.due = AckDue::Now;
        }
    }
}

#[cfg(test)]
mod tests;
