//! How the streams of a composition are reset: the reset kind
//! ([`StreamResets`]), which the list of parts folds from RFC 9000's
//! ([`StreamResetsOf`]).
//!
//! The fold starts from [`Rfc9000StreamResets`] at the end of the list and
//! lets each part, from the last to the first, replace the kind it is given
//! ([`StreamResetsPart`]); a part that changes nothing passes it on. Every
//! stream set of the composition sends and receives resets of the kind the
//! fold gives, and the failures of a RESET_STREAM frame are of that kind
//! too.

use core::{convert::Infallible, fmt};
use sakuya_wire::v1::frame::write::{DelimitedFrame, InFlightClass};

use sakuya_stream::{
    connection_receive_flow::ConnectionReceiveFlowController,
    connection_send_credit::ConnectionSendFlowController,
    receive::{
        StreamReceiver,
        flow_control::ReceiveFlowControlPolicy,
        remote_reset::{RemoteReset, RemoteResetFacts},
        termination::ReceiveTerminationPolicy,
        violation::{OnResetStreamError, ResetStreamViolation},
    },
    receive_buffer::StreamReceiveBuffer,
    send::{
        StreamSender,
        finish::ResetError,
        flow_control::SendFlowControlPolicy,
        local_reset::{LocalReset, LocalResetTarget},
        termination::{ResetOnAbandonTermination, SendTerminationPolicy},
    },
    send_buffer::{SendMarker, StreamSendBuffer},
};
use sakuya_wire::{
    parts::{HCons, HNil},
    v1::{application_error::ApplicationErrorCode, frame::reset_stream::ResetStreamFrame},
};

/// How the streams of a composition are reset: what a sending part's reset
/// targets, what a receiving part keeps of the peer's resets, and the rules
/// of a RESET_STREAM frame.
pub trait StreamResets: 'static {
    /// The target of a reset this side sends; its frame is written into
    /// the packets that count in flight.
    type Local: LocalResetTarget<Frame: DelimitedFrame<Class = InFlightClass>>;

    /// What a receiving part keeps of the peer's resets.
    type Remote: RemoteResetFacts;

    /// Why a RESET_STREAM frame is rejected.
    type OnResetStreamError: ResetStreamViolation;

    /// The termination policy of the sending parts of
    /// [`LockedStreamSet`](super::locked::LockedStreamSet): it resets a
    /// stream whose writer is abandoned, whose data has no destination
    /// left, or whose peer sent STOP_SENDING.
    type SendTermination: SendTerminationPolicy<Self::Local, WriteLimitReason = Infallible>;

    /// What the peer's transport parameters allow the sending parts beyond
    /// RFC 9000's resets, taken when the stream set is made
    /// ([`PeerResetSupportSlots`]); its default is what a peer whose
    /// parameters are not known allows.
    type PeerSupport: Copy + Default + fmt::Debug + Send + Sync + 'static;

    /// The termination policy that resets with `abandon_code` when the
    /// writer is abandoned and with `destination_exhausted_code` when data
    /// has no destination left.
    fn send_termination(
        abandon_code: ApplicationErrorCode,
        destination_exhausted_code: ApplicationErrorCode,
    ) -> Self::SendTermination;

    /// `receiver` takes a RESET_STREAM frame, with `connection`, the
    /// connection's receive flow controller.
    ///
    /// # Errors
    ///
    /// [`OnResetStreamError`](Self::OnResetStreamError) if the frame breaks
    /// a rule; the connection closes.
    fn on_reset_stream<C, Lc>(
        receiver: &mut StreamReceiver<C, Lc, Self::Remote>,
        frame: ResetStreamFrame,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), Self::OnResetStreamError>
    where
        C: StreamReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy<Self::Remote>;

    /// `sender` resets its stream with `error_code`, ending it with
    /// RESET_STREAM.
    ///
    /// # Errors
    ///
    /// [`ResetError`] as the sender's own reset returns it.
    fn reset<C, K, Lc, B, M>(
        sender: &mut StreamSender<C, K, Lc, Self::Local, B, M>,
        error_code: ApplicationErrorCode,
    ) -> Result<(), ResetError<Lc>>
    where
        K: ConnectionSendFlowController,
        M: SendMarker,
        C: StreamSendBuffer<B, K::Reservation, M>
            + SendFlowControlPolicy<Self::Local>
            + SendTerminationPolicy<Self::Local>;
}

/// The resets of RFC 9000 (§3.1, §3.2, §19.4): RESET_STREAM abandons all
/// the data of a stream, and a later one changes nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rfc9000StreamResets;

impl StreamResets for Rfc9000StreamResets {
    type Local = LocalReset;
    type Remote = RemoteReset;
    type OnResetStreamError = OnResetStreamError;
    type SendTermination = ResetOnAbandonTermination;
    type PeerSupport = ();

    fn send_termination(
        abandon_code: ApplicationErrorCode,
        destination_exhausted_code: ApplicationErrorCode,
    ) -> ResetOnAbandonTermination {
        ResetOnAbandonTermination::new(abandon_code, destination_exhausted_code)
    }

    fn on_reset_stream<C, Lc>(
        receiver: &mut StreamReceiver<C, Lc, RemoteReset>,
        frame: ResetStreamFrame,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), OnResetStreamError>
    where
        C: StreamReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy<RemoteReset>,
    {
        receiver.on_reset_stream(frame, connection)
    }

    fn reset<C, K, Lc, B, M>(
        sender: &mut StreamSender<C, K, Lc, LocalReset, B, M>,
        error_code: ApplicationErrorCode,
    ) -> Result<(), ResetError<Lc>>
    where
        K: ConnectionSendFlowController,
        M: SendMarker,
        C: StreamSendBuffer<B, K::Reservation, M>
            + SendFlowControlPolicy<LocalReset>
            + SendTerminationPolicy<LocalReset>,
    {
        sender.reset(error_code)
    }
}

/// The peer's transport parameter slots `Self`, from which the reset kind
/// `X` takes what the peer allows its sending parts
/// ([`StreamResets::PeerSupport`]); `I` is where the parameters it reads
/// are, which the compiler infers.
pub trait PeerResetSupportSlots<X: StreamResets, I> {
    /// What the peer allows, as its parameters in these slots state.
    fn peer_reset_support(&self) -> X::PeerSupport;
}

/// RFC 9000's resets need nothing of the peer's parameters.
impl<S> PeerResetSupportSlots<Rfc9000StreamResets, ()> for S {
    fn peer_reset_support(&self) {}
}

/// How a part changes the reset kind of the parts after it.
///
/// It is implemented by the marker type of each part; a part that changes
/// nothing passes `Prev` on.
pub trait StreamResetsPart {
    /// The reset kind with this part, from `Prev`, that of the parts after
    /// it.
    type Fold<Prev: StreamResets>: StreamResets;
}

/// The reset kind of a list of parts: RFC 9000's, as each part of the list
/// changes it, the last part first ([`StreamResetsPart`]).
///
/// It is implemented for `HNil` and for `HCons<P, Ps>` of a part `P` and a
/// list of parts `Ps`.
pub trait StreamResetsOf {
    /// The reset kind.
    type StreamResets: StreamResets;
}

impl StreamResetsOf for HNil {
    type StreamResets = Rfc9000StreamResets;
}

impl<P: StreamResetsPart, Ps: StreamResetsOf> StreamResetsOf for HCons<P, Ps> {
    type StreamResets = P::Fold<Ps::StreamResets>;
}

/// The reset kind of the list of parts `L`.
pub type StreamResetsOfParts<L> = <L as StreamResetsOf>::StreamResets;

/// The failure of a RESET_STREAM frame of the list of parts `L`.
pub type OnResetStreamErrorOf<L> = <StreamResetsOfParts<L> as StreamResets>::OnResetStreamError;

#[cfg(test)]
mod tests {
    use frunk_core::HList;

    use super::*;
    use crate::v1;

    /// Compiles only when `A` and `B` are the same type.
    fn same_type<A, B>()
    where
        A: SameAs<B>,
    {
    }

    trait SameAs<B> {}

    impl<A> SameAs<A> for A {}

    #[test]
    fn version_1_alone_resets_as_rfc_9000() {
        same_type::<StreamResetsOfParts<HList![v1::Part]>, Rfc9000StreamResets>();
    }
}
