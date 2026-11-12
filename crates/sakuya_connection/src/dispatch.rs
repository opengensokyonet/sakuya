//! Frame dispatch: how the frames of a packet reach the components that
//! handle them.
//!
//! Each part of a composition reads its own frames, as the part of the
//! frame set it is ([`FrameSetPart`]), and dispatches them: the marker type
//! of the part implements [`FrameDispatch`], which hands a run of its frames
//! to the components it concerns, its own and other parts', taken from the
//! lent logical path. A part handles only its own frames. The list of parts
//! dispatches a run to the part that read it ([`FrameSetDispatch`]), written
//! once for every list; a failure is the part's own connection error, at the
//! part's position in the composition's connection error.
//!
//! Frames are dispatched in the order of the packet, each exactly once and
//! synchronously; once one fails, the rest of the packet is not dispatched.
//! What a packet comes to as a whole, such as whether it is ack-eliciting,
//! is summed from the kinds of its frames alone ([`PacketFacts`]), and is
//! used after every frame of the packet was handled.
use core::convert::Infallible;

use bytes::Bytes;
use sakuya_wire::{
    parts::{CNil, Coproduct, HCons, HNil},
    v1::{
        encryption_level::EncryptionLevel,
        frame::set::{FrameKind, FrameSet, FrameSetPart},
    },
};

use crate::{
    call::CallBundle,
    clock::{ConnectionChoices, InstantOf},
    component::LineageOf,
    error::{ConnectionErrorPart, ConnectionErrorsOf},
    layer::LogicalPath,
    others::OtherNodes,
    share::LineageLists,
};

/// What dispatching a frame knows about the packet it came in.
///
/// It is read only; each branch of a dispatch hands on just what the
/// component it calls needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchFacts<I> {
    level: EncryptionLevel,
    at: I,
}

impl<I: Copy> DispatchFacts<I> {
    /// A packet protected at `level` that arrived at `at`.
    pub fn new(level: EncryptionLevel, at: I) -> Self {
        Self { level, at }
    }

    /// The encryption level the packet was protected at.
    pub fn level(&self) -> EncryptionLevel {
        self.level
    }

    /// When the datagram of the packet arrived.
    pub fn at(&self) -> I {
        self.at
    }
}

/// How the frames of one part reach the state of a connection: implemented
/// by the marker type of the part.
///
/// `L` is the composition's list of parts and `H` what the impl infers the
/// positions of the components it takes by.
pub trait FrameDispatch<T: ConnectionChoices, L, H>: FrameSetPart + ConnectionErrorPart
where
    for<'v> L: LineageLists<'v, T>,
{
    /// Hand `run`, read from a packet the logical path received, to the
    /// components it concerns: the logical path's lineage and the other
    /// nodes are those a call of the logical path is lent.
    ///
    /// # Errors
    ///
    /// The frames break a rule the part enforces; the connection closes.
    fn dispatch<'v, B: CallBundle>(
        lineage: &mut LineageOf<'v, T, L, LogicalPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        run: Self::Run<Bytes>,
        packet: &DispatchFacts<InstantOf<T>>,
    ) -> Result<(), Self::ConnectionError>;

    /// The connection error that a failure of reading the fields of one of
    /// this part's frames is.
    fn fields_error(error: Self::FieldsError<Infallible>) -> Self::ConnectionError;
}

/// Dispatching a run to the part of a list that read it.
///
/// It is implemented for every list whose parts implement
/// [`FrameDispatch`]; `L` is the whole composition and `Hs` the positions of
/// each part's impl.
pub trait FrameSetDispatch<T: ConnectionChoices, L, Hs>: FrameSet + ConnectionErrorsOf
where
    for<'v> L: LineageLists<'v, T>,
{
    /// Hand `run` to the part that read it.
    ///
    /// # Errors
    ///
    /// The part's failure, at the part's position.
    fn dispatch<'v, B: CallBundle>(
        lineage: &mut LineageOf<'v, T, L, LogicalPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        run: Self::Run<Bytes>,
        packet: &DispatchFacts<InstantOf<T>>,
    ) -> Result<(), Self::ConnectionErrors>;

    /// The connection error that a failure of reading the fields of a frame
    /// is, as the part that claims the frame gives it.
    fn fields_error(error: Self::FieldsError<Infallible>) -> Self::ConnectionErrors;
}

impl<T: ConnectionChoices, L> FrameSetDispatch<T, L, HNil> for HNil
where
    for<'v> L: LineageLists<'v, T>,
{
    fn dispatch<'v, B: CallBundle>(
        _: &mut LineageOf<'v, T, L, LogicalPath>,
        _: &mut OtherNodes<'v, T, L, B>,
        run: CNil,
        _: &DispatchFacts<InstantOf<T>>,
    ) -> Result<(), CNil> {
        match run {}
    }

    fn fields_error(error: CNil) -> CNil {
        match error {}
    }
}

impl<T: ConnectionChoices, L, P, Ps, H, Hs> FrameSetDispatch<T, L, HCons<H, Hs>> for HCons<P, Ps>
where
    for<'v> L: LineageLists<'v, T>,
    P: FrameDispatch<T, L, H>,
    Ps: FrameSetDispatch<T, L, Hs>,
{
    fn dispatch<'v, B: CallBundle>(
        lineage: &mut LineageOf<'v, T, L, LogicalPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        run: Self::Run<Bytes>,
        packet: &DispatchFacts<InstantOf<T>>,
    ) -> Result<(), Self::ConnectionErrors> {
        match run {
            Coproduct::Inl(run) => {
                P::dispatch(lineage, others, run, packet).map_err(Coproduct::Inl)
            }
            Coproduct::Inr(run) => {
                Ps::dispatch(lineage, others, run, packet).map_err(Coproduct::Inr)
            }
        }
    }

    fn fields_error(error: Self::FieldsError<Infallible>) -> Self::ConnectionErrors {
        match error {
            Coproduct::Inl(error) => Coproduct::Inl(P::fields_error(error)),
            Coproduct::Inr(error) => Coproduct::Inr(Ps::fields_error(error)),
        }
    }
}

/// What the frames of one packet come to, from their kinds alone, once every
/// frame was handled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PacketFacts {
    frames: usize,
    ack_eliciting: bool,
    non_probing: bool,
}

impl PacketFacts {
    /// Count a run of frames of `kind`.
    pub fn note<K: FrameKind>(&mut self, kind: K) {
        self.frames += 1;
        self.ack_eliciting |= kind.is_ack_eliciting();
        self.non_probing |= !kind.is_probing();
    }

    /// Whether the packet has no frames, which RFC 9000 §12.4 forbids.
    pub fn is_empty(&self) -> bool {
        self.frames == 0
    }

    /// Whether the packet is ack-eliciting (RFC 9002 §2).
    pub fn is_ack_eliciting(&self) -> bool {
        self.ack_eliciting
    }

    /// Whether the packet has a frame that is not a probing frame: it is a
    /// non-probing packet (RFC 9000 §9.1).
    pub fn is_non_probing(&self) -> bool {
        self.non_probing
    }
}

#[cfg(test)]
mod tests {
    use sakuya_wire::v1::frame::FrameType;

    use super::*;

    #[test]
    fn padding_and_path_challenge_make_a_probing_packet() {
        let mut facts = PacketFacts::default();
        assert!(facts.is_empty());
        facts.note(FrameType::PathChallenge);
        facts.note(FrameType::Padding);
        assert!(!facts.is_empty());
        assert!(facts.is_ack_eliciting());
        assert!(!facts.is_non_probing());
    }

    #[test]
    fn an_ack_alone_is_neither_ack_eliciting_nor_probing() {
        let mut facts = PacketFacts::default();
        facts.note(FrameType::Ack);
        assert!(!facts.is_ack_eliciting());
        assert!(facts.is_non_probing());
    }
}
