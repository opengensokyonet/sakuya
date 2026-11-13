//! Frame sets composed of parts.
//!
//! The payload of a QUIC packet, once packet protection is removed, is a
//! sequence of frames, each starting with a Frame Type field. A frame never
//! extends past the end of its packet ([RFC 9000 §12.4]), so frames are read
//! from a source that holds the complete payload of one packet: a frame that
//! the payload cuts short is a terminal incomplete failure, not a reason to
//! wait for more bytes.
//!
//! # Frame sets
//!
//! QUIC version 1 and each extension define their own frames, and nothing
//! else: a *part* of a frame set. A part is a marker type that implements
//! [`FrameSetPart`]: [`v1::Part`](crate::v1::Part) for the frames of
//! [RFC 9000], and one in the module of each extension that this crate
//! implements behind a feature of the same name, `reset_stream_at` and
//! `datagram`. A part states its frames, the kinds of its frames
//! ([`FrameKind`]), the failures of reading their fields, and the Frame Type
//! values it claims ([`FrameTypeValues`]).
//!
//! The frame set of a connection is the list of the parts it uses, such as
//! `HList![v1::Part, datagram::Part]` (see [`parts`](crate::parts)), and the
//! list implements [`FrameSet`]. What the set reads is a `Coproduct` of what
//! the parts read, with one variant per part in the order of the list, ending
//! in `CNil`; the kinds and the failures of reading fields are sums in the
//! same way. A set of version 1 alone is the list `HList![v1::Part]`. A
//! caller takes the item of a part out of the sum by its type, with `get`,
//! `uninject` or `extract`, and does not depend on the position of the part
//! in the list. Reading an item reads its Frame Type
//! ([`codec::read_frame_type`]), checks that it uses its shortest encoding,
//! asks the set which part claims it, and lets that part read the rest
//! ([`FrameSetPart::read_run`]) from the Frame Type value as the part
//! claims it ([`FrameSetPart::TypeValue`]). A Frame Type value that no part of the set
//! claims is unknown, including the values of an extension that is not in the
//! set: a FRAME_ENCODING_ERROR ([RFC 9000 §12.4]).
//!
//! The parts of a set must claim disjoint Frame Type values, or the frames of
//! one would be read as those of another. Two checks reject a set that breaks
//! this at compile time: [`assert_frame_types_disjoint!`](crate::assert_frame_types_disjoint),
//! which whoever composes a set writes for it and which `cargo check` already
//! evaluates, and an assertion in [`FrameSet::type_value_of`], which fails when the
//! code that reads with the set is built.
//!
//! ```compile_fail
//! use sakuya_wire::{assert_frame_types_disjoint, parts::HList, v1};
//!
//! // Version 1 twice claims every value twice.
//! assert_frame_types_disjoint!(HList![v1::Part, v1::Part]);
//! ```
//!
//! ```compile_fail
//! use core::marker::PhantomData;
//! use sakuya_wire::{
//!     parts::HList,
//!     v1::{self, frame::set::Frames},
//! };
//!
//! let mut frames = Frames::new(&[0x01][..], PhantomData::<HList![v1::Part, v1::Part]>);
//! let _ = frames.next();
//! ```
//!
//! # Reading
//!
//! [`Frames`] walks a packet payload held by a byte slice or `Bytes`, item
//! by item, without collecting the items first. Its items are of the *runs*
//! of the set ([`FrameSet::Run`]): once the Frame Type is read and the part
//! that claims it is known, that part reads the item from the source
//! ([`FrameSetPart::read_run`]) and decides what it holds. For most parts a
//! run is one frame; a part whose consecutive frames are better taken
//! together may read them as one run. Payload fields are chunks of the
//! source, of the type parameter `D` of the frames: subslices of a byte slice
//! and `Bytes` that share the storage of a `Bytes` source, so reading copies
//! no payload.
//!
//! ```
//! use core::marker::PhantomData;
//! use sakuya_wire::{
//!     parts::HList,
//!     v1::{
//!         self,
//!         frame::{FrameRun, set::Frames},
//!     },
//! };
//!
//! type Set = HList![v1::Part];
//!
//! // PING, then three PADDING frames.
//! let payload = [0x01, 0x00, 0x00, 0x00];
//! let mut frames = Frames::new(&payload[..], PhantomData::<Set>);
//! let Some(Ok(run)) = frames.next() else { panic!() };
//! assert!(matches!(run.extract(), FrameRun::Ping(_)));
//! let Some(Ok(run)) = frames.next() else { panic!() };
//! let FrameRun::Padding(padding) = run.extract() else { panic!() };
//! assert_eq!(padding.len().get(), 3);
//! assert!(frames.next().is_none());
//!
//! // DATAGRAM is not a frame of version 1.
//! let mut frames = Frames::new(&[0x30, 0x01][..], PhantomData::<Set>);
//! assert!(frames.next().unwrap().is_err());
//! ```
//!
//! [RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000.html
//! [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
use crate::{
    parts::{CNil, Coproduct, HCons, HNil, PartsError},
    v1::{encryption_level::EncryptionLevel, role::Role, transport_error::TransportErrorCode},
    var_int::VarInt,
};
use bytes::Buf;
use core::{iter::FusedIterator, marker::PhantomData, ops::RangeInclusive};
use nitori_call::{Direct, Receiver};
use nitori_io::{Read, ReadChunk};

pub mod codec;

#[cfg(test)]
mod tests;

/// The kind of a frame, as its Frame Type field announces it, and what the
/// kind alone determines.
///
/// The kinds of each part implement it, and so do the sums of kinds of a
/// list of parts, which answer for the part they belong to.
pub trait FrameKind: Copy + Eq {
    /// Whether a frame of this kind can appear in a packet protected at
    /// `level` ([RFC 9000 §12.4], Table 3).
    ///
    /// [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
    fn can_appear_in(self, level: EncryptionLevel) -> bool;

    /// Whether a packet containing a frame of this kind is ack-eliciting
    /// ([RFC 9002 §2]).
    ///
    /// [RFC 9002 §2]: https://www.rfc-editor.org/rfc/rfc9002.html#section-2
    fn is_ack_eliciting(self) -> bool;

    /// Whether a packet containing a frame of this kind counts as in flight
    /// ([RFC 9002 §2]).
    ///
    /// [RFC 9002 §2]: https://www.rfc-editor.org/rfc/rfc9002.html#section-2
    fn counts_in_flight(self) -> bool;

    /// Whether this is a probing frame ([RFC 9000 §9.1]): a packet that
    /// contains only probing frames is a probing packet.
    ///
    /// [RFC 9000 §9.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-9.1
    fn is_probing(self) -> bool;

    /// Whether an endpoint of `role` can receive a frame of this kind.
    fn receivable_by(self, role: Role) -> bool;
}

/// A part of a frame set: the frames that version 1 or one extension
/// defines.
///
/// It is implemented by the marker type of each part. A list of parts
/// implements [`FrameSet`], which [`Frames`] reads with.
pub trait FrameSetPart {
    /// What this part gives as one item when a packet payload in memory is
    /// read item by item ([`Frames`]): a frame, or consecutive frames that
    /// the part reads as one value. `D` is the type of its payload fields.
    type Run<D>;

    /// The kinds of the frames of this part.
    type Kind: FrameKind;

    /// A Frame Type value this part claims, with what the part reads from
    /// it: obtained only from [`type_value_of`](Self::type_value_of), so it
    /// is always a value of this part.
    type TypeValue: Copy;

    /// The failures of reading the fields after the Frame Type; each states
    /// the transport error it corresponds to ([`FrameFieldsError`]).
    type FieldsError<E>;

    /// The Frame Type values this part claims.
    const FRAME_TYPE_VALUES: &'static FrameTypeValues;

    /// The Frame Type value `value` in the form of this part, or `None` for
    /// a value this part does not claim.
    fn type_value_of(value: VarInt) -> Option<Self::TypeValue>;

    /// The kind that the Frame Type value `type_value` announces.
    fn kind_of(type_value: Self::TypeValue) -> Self::Kind;

    /// The kind of the frames of `run`: the kind of the Frame Type it was
    /// read from ([`kind_of`](Self::kind_of)).
    fn run_kind<D>(run: &Self::Run<D>) -> Self::Kind;

    /// Reads a run from `source`, a packet payload in memory from which the
    /// Frame Type `type_value` has just been read.
    ///
    /// The source is the rest of a packet payload; payload fields are chunks
    /// of it. A part may read several consecutive frames as one run. A part
    /// whose run is one frame reads the fields of the frame with the
    /// synchronous host method of its own read operation.
    // The type spells out the chunks and the failure of the source `H`.
    #[allow(clippy::type_complexity)]
    fn read_run<H>(
        source: &mut H,
        type_value: Self::TypeValue,
    ) -> Result<
        Self::Run<<Direct<H> as ReadChunk>::Chunk>,
        Self::FieldsError<<Direct<H> as Read>::Error>,
    >
    where
        H: Buf + Receiver<Family = Direct<H>> + Unpin,
        Direct<H>: ReadChunk<Chunk: Default>;
}

/// A frame set: a list of parts, `HNil` or `HCons<P, Ps>` of parts `P` and
/// the set `Ps`, such as `HList![v1::Part, datagram::Part]`.
///
/// [`Frames`] reads a set: it looks the Frame Type up with
/// [`type_value_of`](Self::type_value_of) and reads the rest with
/// [`read_run`](Self::read_run). A run, a kind, a claimed Frame Type value
/// or a failure of the set is a
/// `Coproduct` of those of the parts, one variant per part in the order of
/// the list, ending in `CNil`; the empty set has none of them.
pub trait FrameSet {
    /// A run of this set, the item of [`Frames`]: what the part that claims
    /// a Frame Type reads as one item ([`FrameSetPart::Run`]). `D` is the
    /// type of its payload fields.
    type Run<D>;

    /// The kinds of the frames of this set.
    type Kind: FrameKind;

    /// A Frame Type value a part of this set claims, in the form of that part
    /// ([`FrameSetPart::TypeValue`]).
    type TypeValue: Copy;

    /// The failures of reading the fields after the Frame Type; each states
    /// the transport error it corresponds to ([`FrameFieldsError`]).
    type FieldsError<E>;

    /// The Frame Type values the parts of this set claim.
    const FRAME_TYPE_VALUES: &'static FrameTypeValues;

    /// Whether the parts of this set claim disjoint Frame Type values.
    const PARTS_DISJOINT: bool;

    /// The Frame Type value `value` in the form of the part of this set that
    /// claims it, or `None` for a value no part of this set claims.
    fn type_value_of(value: VarInt) -> Option<Self::TypeValue>;

    /// The kind that the Frame Type value `type_value` announces, as its
    /// part gives it ([`FrameSetPart::kind_of`]).
    fn kind_of(type_value: Self::TypeValue) -> Self::Kind;

    /// The kind of the frames of `run`, as the part of the run gives it
    /// ([`FrameSetPart::run_kind`]).
    fn run_kind<D>(run: &Self::Run<D>) -> Self::Kind;

    /// Reads a run from `source`, a packet payload in memory from which the
    /// Frame Type `type_value` has just been read, as the part that claims it
    /// does ([`FrameSetPart::read_run`]).
    // The type spells out the chunks and the failure of the source `H`.
    #[allow(clippy::type_complexity)]
    fn read_run<H>(
        source: &mut H,
        type_value: Self::TypeValue,
    ) -> Result<
        Self::Run<<Direct<H> as ReadChunk>::Chunk>,
        Self::FieldsError<<Direct<H> as Read>::Error>,
    >
    where
        H: Buf + Receiver<Family = Direct<H>> + Unpin,
        Direct<H>: ReadChunk<Chunk: Default>;
}

impl FrameSet for HNil {
    type Run<D> = CNil;
    type Kind = CNil;
    type TypeValue = CNil;
    type FieldsError<E> = CNil;

    const FRAME_TYPE_VALUES: &'static FrameTypeValues = &FrameTypeValues::new(&[]);

    const PARTS_DISJOINT: bool = true;

    fn type_value_of(_value: VarInt) -> Option<CNil> {
        None
    }

    fn kind_of(type_value: CNil) -> CNil {
        match type_value {}
    }

    fn run_kind<D>(run: &CNil) -> CNil {
        match *run {}
    }

    fn read_run<H>(_source: &mut H, type_value: CNil) -> Result<CNil, CNil>
    where
        H: Buf + Receiver<Family = Direct<H>> + Unpin,
        Direct<H>: ReadChunk<Chunk: Default>,
    {
        match type_value {}
    }
}

impl<P: FrameSetPart, Ps: FrameSet> FrameSet for HCons<P, Ps> {
    type Run<D> = Coproduct<P::Run<D>, Ps::Run<D>>;
    type Kind = Coproduct<P::Kind, Ps::Kind>;
    type TypeValue = Coproduct<P::TypeValue, Ps::TypeValue>;
    type FieldsError<E> = Coproduct<P::FieldsError<E>, Ps::FieldsError<E>>;

    const FRAME_TYPE_VALUES: &'static FrameTypeValues =
        &FrameTypeValues::join(P::FRAME_TYPE_VALUES, Ps::FRAME_TYPE_VALUES);

    const PARTS_DISJOINT: bool =
        Ps::PARTS_DISJOINT && P::FRAME_TYPE_VALUES.is_disjoint(Ps::FRAME_TYPE_VALUES);

    fn type_value_of(value: VarInt) -> Option<Self::TypeValue> {
        // Evaluated when the function is generated for a concrete set, so a
        // set whose parts overlap does not build. Each cell of the list
        // checks its part against the rest.
        const {
            assert!(
                P::FRAME_TYPE_VALUES.is_disjoint(Ps::FRAME_TYPE_VALUES),
                "two parts of the frame set claim the same Frame Type value"
            );
        }
        P::type_value_of(value)
            .map(Coproduct::Inl)
            .or_else(|| Ps::type_value_of(value).map(Coproduct::Inr))
    }

    fn kind_of(type_value: Self::TypeValue) -> Self::Kind {
        match type_value {
            Coproduct::Inl(type_value) => Coproduct::Inl(P::kind_of(type_value)),
            Coproduct::Inr(type_value) => Coproduct::Inr(Ps::kind_of(type_value)),
        }
    }

    fn run_kind<D>(run: &Self::Run<D>) -> Self::Kind {
        match run {
            Coproduct::Inl(run) => Coproduct::Inl(P::run_kind(run)),
            Coproduct::Inr(run) => Coproduct::Inr(Ps::run_kind(run)),
        }
    }

    fn read_run<H>(
        source: &mut H,
        type_value: Self::TypeValue,
    ) -> Result<
        Self::Run<<Direct<H> as ReadChunk>::Chunk>,
        Self::FieldsError<<Direct<H> as Read>::Error>,
    >
    where
        H: Buf + Receiver<Family = Direct<H>> + Unpin,
        Direct<H>: ReadChunk<Chunk: Default>,
    {
        match type_value {
            Coproduct::Inl(type_value) => P::read_run(source, type_value)
                .map(Coproduct::Inl)
                .map_err(Coproduct::Inl),
            Coproduct::Inr(type_value) => Ps::read_run(source, type_value)
                .map(Coproduct::Inr)
                .map_err(Coproduct::Inr),
        }
    }
}

/// A failure of reading the fields of a frame after its Frame Type, as a
/// [`FrameSetPart::FieldsError`] reports it.
///
/// The sums of the failures of a list of parts implement it too, and so does
/// [`PartsError`] around such a sum.
pub trait FrameFieldsError {
    /// The Frame Type of the frame.
    fn frame_type(&self) -> VarInt;

    /// Whether the source ended within the frame.
    fn is_incomplete(&self) -> bool;

    /// The transport error the failure corresponds to.
    fn transport_error_code(&self) -> TransportErrorCode;
}

impl FrameKind for CNil {
    fn can_appear_in(self, _level: EncryptionLevel) -> bool {
        match self {}
    }

    fn is_ack_eliciting(self) -> bool {
        match self {}
    }

    fn counts_in_flight(self) -> bool {
        match self {}
    }

    fn is_probing(self) -> bool {
        match self {}
    }

    fn receivable_by(self, _role: Role) -> bool {
        match self {}
    }
}

impl<H: FrameKind, T: FrameKind> FrameKind for Coproduct<H, T> {
    fn can_appear_in(self, level: EncryptionLevel) -> bool {
        match self {
            Self::Inl(kind) => kind.can_appear_in(level),
            Self::Inr(kind) => kind.can_appear_in(level),
        }
    }

    fn is_ack_eliciting(self) -> bool {
        match self {
            Self::Inl(kind) => kind.is_ack_eliciting(),
            Self::Inr(kind) => kind.is_ack_eliciting(),
        }
    }

    fn counts_in_flight(self) -> bool {
        match self {
            Self::Inl(kind) => kind.counts_in_flight(),
            Self::Inr(kind) => kind.counts_in_flight(),
        }
    }

    fn is_probing(self) -> bool {
        match self {
            Self::Inl(kind) => kind.is_probing(),
            Self::Inr(kind) => kind.is_probing(),
        }
    }

    fn receivable_by(self, role: Role) -> bool {
        match self {
            Self::Inl(kind) => kind.receivable_by(role),
            Self::Inr(kind) => kind.receivable_by(role),
        }
    }
}

impl FrameFieldsError for CNil {
    fn frame_type(&self) -> VarInt {
        match *self {}
    }

    fn is_incomplete(&self) -> bool {
        match *self {}
    }

    fn transport_error_code(&self) -> TransportErrorCode {
        match *self {}
    }
}

impl<H: FrameFieldsError, T: FrameFieldsError> FrameFieldsError for Coproduct<H, T> {
    fn frame_type(&self) -> VarInt {
        match self {
            Self::Inl(error) => error.frame_type(),
            Self::Inr(error) => error.frame_type(),
        }
    }

    fn is_incomplete(&self) -> bool {
        match self {
            Self::Inl(error) => error.is_incomplete(),
            Self::Inr(error) => error.is_incomplete(),
        }
    }

    fn transport_error_code(&self) -> TransportErrorCode {
        match self {
            Self::Inl(error) => error.transport_error_code(),
            Self::Inr(error) => error.transport_error_code(),
        }
    }
}

impl<C: FrameFieldsError> FrameFieldsError for PartsError<C> {
    fn frame_type(&self) -> VarInt {
        self.0.frame_type()
    }

    fn is_incomplete(&self) -> bool {
        self.0.is_incomplete()
    }

    fn transport_error_code(&self) -> TransportErrorCode {
        self.0.transport_error_code()
    }
}

/// Takes the run of the only part out of what reading with a frame set of
/// one part gives, for tests of a part that read through [`Frames`]. The
/// failure keeps its sum of one failure.
#[cfg(test)]
pub(crate) trait OnlyPart {
    /// What this is with the run of the part in place of the sum of one
    /// run.
    type Narrowed;

    /// Takes the run of the part out of the sum.
    fn only_part(self) -> Self::Narrowed;
}

#[cfg(test)]
impl<F, Er> OnlyPart for Result<Coproduct<F, CNil>, Er> {
    type Narrowed = Result<F, Er>;

    fn only_part(self) -> Result<F, Er> {
        self.map(Coproduct::extract)
    }
}

/// The item of [`Frames`].
#[cfg(test)]
impl<F, Er> OnlyPart for Option<Result<Coproduct<F, CNil>, Er>> {
    type Narrowed = Option<Result<F, Er>>;

    fn only_part(self) -> Option<Result<F, Er>> {
        self.map(OnlyPart::only_part)
    }
}

/// The Frame Type values a part claims: ranges of values, or for a
/// list of parts those of the parts it holds.
#[derive(Debug)]
pub struct FrameTypeValues(Values);

#[derive(Debug)]
enum Values {
    Ranges(&'static [RangeInclusive<VarInt>]),
    Join(&'static FrameTypeValues, &'static FrameTypeValues),
}

impl FrameTypeValues {
    /// The values in `ranges`; an empty range claims no value.
    pub const fn new(ranges: &'static [RangeInclusive<VarInt>]) -> Self {
        Self(Values::Ranges(ranges))
    }

    /// The values of `first` and those of `rest`.
    const fn join(first: &'static Self, rest: &'static Self) -> Self {
        Self(Values::Join(first, rest))
    }

    /// Whether no value is in both `self` and `other`.
    pub const fn is_disjoint(&self, other: &Self) -> bool {
        match self.0 {
            Values::Ranges(ranges) => {
                let mut index = 0;
                while index < ranges.len() {
                    if !other.excludes(&ranges[index]) {
                        return false;
                    }
                    index += 1;
                }
                true
            }
            Values::Join(first, rest) => first.is_disjoint(other) && rest.is_disjoint(other),
        }
    }

    /// Whether no value of `range` is in `self`.
    const fn excludes(&self, range: &RangeInclusive<VarInt>) -> bool {
        match self.0 {
            Values::Ranges(ranges) => {
                let (start, end) = (range.start().get(), range.end().get());
                let mut index = 0;
                while index < ranges.len() {
                    let (other_start, other_end) =
                        (ranges[index].start().get(), ranges[index].end().get());
                    if start <= end
                        && other_start <= other_end
                        && start <= other_end
                        && other_start <= end
                    {
                        return false;
                    }
                    index += 1;
                }
                true
            }
            Values::Join(first, rest) => first.excludes(range) && rest.excludes(range),
        }
    }

    /// Whether `value` is in `self`.
    #[cfg(test)]
    pub(crate) const fn contains(&self, value: VarInt) -> bool {
        !self.excludes(&RangeInclusive::new(value, value))
    }
}

/// Asserts at compile time that the parts of a frame set claim disjoint
/// Frame Type values ([`FrameSet::PARTS_DISJOINT`]).
///
/// Whoever composes a frame set writes it for the set's type; `cargo check`
/// reports a set whose parts overlap.
///
/// ```
/// use sakuya_wire::{assert_frame_types_disjoint, parts::HList, v1};
///
/// assert_frame_types_disjoint!(HList![v1::Part]);
/// ```
#[macro_export]
macro_rules! assert_frame_types_disjoint {
    ($set:ty) => {
        const _: () = ::core::assert!(
            <$set as $crate::v1::frame::set::FrameSet>::PARTS_DISJOINT,
            "two parts of the frame set claim the same Frame Type value"
        );
    };
}

/// Iterates over the runs of the frame set `S` in a packet payload held by
/// a memory source such as a byte slice or `Bytes`, reading each when it is
/// reached.
///
/// Each item is a run ([`FrameSet::Run`]) or the error that ends the
/// iteration; after an error the iterator yields `None`. For each item, the
/// iterator reads the Frame Type ([`codec::read_frame_type`]), and the part
/// that claims it reads the run ([`FrameSet::read_run`]): one frame, or
/// consecutive frames as one value. Payload fields are chunks of the source;
/// see the [module documentation](self).
#[derive(Clone, Debug)]
pub struct Frames<H, S> {
    source: H,
    consumed: usize,
    start: usize,
    failed: bool,
    part: PhantomData<S>,
}

impl<H: Buf, S> Frames<H, S> {
    /// Iterates over the runs of `payload`, of the frame set `S`.
    pub fn new(payload: H, part: PhantomData<S>) -> Self {
        Self {
            source: payload,
            consumed: 0,
            start: 0,
            failed: false,
            part,
        }
    }

    /// The offset in the payload of the next run, or after a failure of
    /// the frame that failed.
    pub fn offset(&self) -> usize {
        self.start
    }

    /// The payload from the next run on; after a failure, what the failed
    /// frame left unread.
    pub fn remainder(&self) -> &H {
        &self.source
    }

    /// Takes the payload from the next run on.
    pub fn into_remainder(self) -> H {
        self.source
    }
}

impl<H, S> Iterator for Frames<H, S>
where
    H: Buf + Receiver<Family = Direct<H>> + Unpin,
    Direct<H>: ReadChunk<Chunk: Default>,
    S: FrameSet,
{
    type Item = Result<
        S::Run<<Direct<H> as ReadChunk>::Chunk>,
        codec::ReadFrameError<
            <Direct<H> as Read>::Error,
            S::FieldsError<<Direct<H> as Read>::Error>,
        >,
    >;

    fn next(&mut self) -> Option<Self::Item> {
        use codec::{ReadFrameError, ReadFrameTypeHostExt as _};
        if self.failed || !self.source.has_remaining() {
            return None;
        }
        self.start = self.consumed;
        let before = self.source.remaining();
        let frame_type = self.source.sync_read_frame_type_unpin(self.part);
        let result = frame_type.and_then(|type_value| {
            S::read_run(&mut self.source, type_value).map_err(|error| ReadFrameError::Fields {
                source: PartsError(error),
            })
        });
        self.consumed += before - self.source.remaining();
        if result.is_err() {
            self.failed = true;
        } else {
            self.start = self.consumed;
        }
        Some(result)
    }
}

impl<H, S> FusedIterator for Frames<H, S>
where
    H: Buf + Receiver<Family = Direct<H>> + Unpin,
    Direct<H>: ReadChunk<Chunk: Default>,
    S: FrameSet,
{
}
