//! Sets of parameters keyed by ID, composed of parts.
//!
//! An endpoint states parameters as a sequence of items, each an ID, a
//! Length and that many bytes of value, the ID and the Length being
//! variable-length integers. Which IDs exist, which are reserved, what else
//! decides whether a parameter may appear and which error a bad set
//! corresponds to are the rules of a *parameter space*
//! ([`ParameterSpace`]), such as the transport parameters of QUIC version 1
//! (`sakuya_wire_v1::transport_parameters`). This
//! module holds what the spaces share and knows no particular space.
//!
//! # Parameter types
//!
//! Each parameter is a type of its own, which is the value of one ID of one
//! space ([`KeyedParameter`]): the type states its ID, the attributes its
//! space attaches to it, how its value is read and written, and the failure
//! of reading it. A type has the same ID wherever it is used.
//!
//! QUIC version 1 and each extension define their own parameter types, and
//! nothing else: a *part* states them as a list of types, such as
//! `HList![InitialMaxData, MaxAckDelay]`, used as a type only
//! ([`ParametersPart`]). The parameters of a connection are those of the
//! parts it uses: for a list of parts, such as
//! `HList![v1::Part, datagram::Part]` (see [`parts`](crate::parts)),
//! [`ParametersOf`] gives the lists of the parts joined in the order of the
//! parts, one flat list of parameter types ([`ParameterList`]).
//!
//! # Slots
//!
//! [`Parameters`] holds one slot per parameter type of a list, an `Option`
//! of the type, in a flat list such as
//! `HList![Option<InitialMaxData>, Option<MaxAckDelay>]`, and the parameters
//! that no type of the list claims as [`UnknownParameter`]s. A slot is
//! `None` for a parameter that was not received, or is not to be sent, which
//! is distinct from a parameter that states its default value. A caller
//! takes a slot by its type, with [`Parameters::get`] and
//! [`Parameters::set`], or several at once with `sculpt` on
//! [`Parameters::known`], and does not depend on the position of the type
//! or of its part in the list.
//!
//! # Reading and writing
//!
//! [`codec::read_parameters`] reads a sequence to the end of its source. For
//! each item it reads the ID and the Length and takes the value as one piece
//! of the source. If a type of the list claims the ID, the slot of the type
//! must be empty, or the parameter appears twice; the space is asked whether
//! the parameter may appear ([`ParameterSpace::admit`]); and the type reads
//! its value from the piece ([`KeyedParameter::read_value`]), all of it. An
//! ID that no type claims goes to [`Parameters::unknown`] with its value,
//! unless it is there already. That includes the reserved IDs of the space,
//! which no type can claim. [`codec::write_parameters`] writes the slots
//! that hold a parameter in the order of the list, then the unknown
//! parameters in their order.
//!
//! A space can keep part of a set that was read by the attributes of the
//! types: [`ParameterList::retain`] empties the slots whose attributes a
//! condition rejects, such as the transport parameters that are not
//! remembered for 0-RTT.
//!
//! Two types of a list must not claim the same ID, and none may claim a
//! reserved ID of the space. Two checks reject a list that breaks this at
//! compile time: [`assert_parameters_distinct!`](crate::assert_parameters_distinct),
//! which whoever composes a list writes for it and which `cargo check`
//! already evaluates, and an assertion in [`Parameters::new`],
//! [`codec::read_parameters`] and [`codec::write_parameters`], which fails
//! when the code that uses the list is built.
//! Examples of lists that fail the checks are in
//! `sakuya_wire_v1::transport_parameters`.
//!
//! A type that claims a reserved ID is rejected in the same way; here `0x1b`,
//! which is 31 × 0 + 27, in the space of the QUIC transport parameters:
//!
use crate::{
    frame::{Head, length_field_len},
    parts::{CNil, Coproduct, ErrorCoproduct, HCons, HNil, PartsError, Selector},
    var_int::VarInt,
};
use alloc::collections::BTreeSet;
use bytes::{Buf, BufMut};
use codec::ReadParametersError;
use core::{
    error::Error,
    fmt::{self, Debug},
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    ops::Add,
};
use snafu::{IntoError, ResultExt, Snafu};

pub mod codec;

#[cfg(test)]
mod tests;

/// The reserved IDs of a parameter space: the IDs of the form
/// `step` × N + `offset`, for every integer N from 0.
///
/// No parameter type may claim a reserved ID, and a reserved ID that is read
/// is an unknown parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReservedIds {
    step: NonZeroU64,
    offset: u64,
}

impl ReservedIds {
    /// The IDs `step` × N + `offset`.
    pub const fn new(step: NonZeroU64, offset: u64) -> Self {
        Self { step, offset }
    }

    /// The distance between two consecutive reserved IDs.
    pub const fn step(&self) -> NonZeroU64 {
        self.step
    }

    /// The smallest reserved ID.
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Whether `id` is reserved.
    pub const fn contains(&self, id: VarInt) -> bool {
        let id = id.get();
        id >= self.offset && (id - self.offset).is_multiple_of(self.step.get())
    }
}

/// A parameter space: the rules that the parameters of one kind share, such
/// as the QUIC transport parameters.
///
/// It is implemented by a marker type. The parameter types of the space name
/// it ([`KeyedParameter::Space`]), so a type of one space cannot enter a list
/// of another.
pub trait ParameterSpace {
    /// What the space attaches to each parameter type
    /// ([`KeyedParameter::ATTRIBUTES`]), for [`admit`](Self::admit) to
    /// decide with.
    type Attributes;

    /// What is known about a set of parameters as a whole when it is read
    /// or checked, for [`admit`](Self::admit) to decide with.
    type Context: Copy;

    /// Why a parameter may not appear.
    type AdmitError: Error + 'static;

    /// The error codes of the protocol that the space belongs to.
    type ErrorCode;

    /// The error that every failure of reading a set of parameters of this
    /// space corresponds to.
    const ERROR_CODE: Self::ErrorCode;

    /// The reserved IDs of the space.
    const RESERVED: ReservedIds;

    /// Checks whether the parameter `id`, whose type has `attributes`, may
    /// appear in a set of parameters with `context`.
    ///
    /// Reading calls it for each parameter that a type of the list claims,
    /// before the value is read, and [`Parameters::validate`] for each slot
    /// that holds a parameter.
    ///
    /// # Errors
    ///
    /// [`Self::AdmitError`] if the parameter may not appear.
    fn admit(
        id: VarInt,
        attributes: &Self::Attributes,
        context: Self::Context,
    ) -> Result<(), Self::AdmitError>;
}

/// A parameter type: the value of one ID of a parameter space.
///
/// The type checks the rules of its own value when it is constructed, and
/// reading constructs it in the same way, so a slot never holds a value its
/// type forbids.
pub trait KeyedParameter: Sized {
    /// The space of the parameter.
    type Space: ParameterSpace;

    /// Why a value is not a value of this type: its content cannot be read
    /// or breaks a rule of the type, or bytes follow the content
    /// ([`TrailingBytesError`]). [`ReadValueError`] combines the two around
    /// the failure of a read function.
    type ValueError: Error + From<TrailingBytesError> + 'static;

    /// The ID of the parameter.
    const ID: VarInt;

    /// What the space attaches to this type.
    const ATTRIBUTES: <Self::Space as ParameterSpace>::Attributes;

    /// Reads the parameter from `value`, the value of one item: the bytes
    /// that its Length counts.
    ///
    /// An implementation reads with its own read function, as from any
    /// [`Buf`]. It need not check that the value ends where the
    /// parameter does: whoever calls this checks it afterwards
    /// ([`ValueSource::finish`]) and reports bytes that are left as
    /// [`Self::ValueError`].
    ///
    /// # Errors
    ///
    /// [`Self::ValueError`] if the content cannot be read or breaks a rule
    /// of the type.
    fn read_value<D: Buf>(value: &mut ValueSource<D>) -> Result<Self, Self::ValueError>;

    /// The number of bytes [`write_value`](Self::write_value) writes.
    fn value_len(&self) -> usize;

    /// Writes the value of the parameter, without its ID and Length, with
    /// the write function of the type: exactly
    /// [`value_len`](Self::value_len) bytes.
    ///
    /// # Panics
    ///
    /// If `dst` has no room for the value, as [`BufMut`] does.
    fn write_value<B: BufMut>(&self, dst: &mut B);
}

/// The value of one parameter as a source of its own, so that a parameter
/// type reads its value with the same functions as any other source, within
/// the length of the value.
///
/// It is a [`Buf`] over the bytes of the value that have not been read: a
/// value that is shorter than what is read from it is an incomplete failure
/// of the read function.
#[derive(Clone, Debug)]
pub struct ValueSource<D> {
    value: D,
    length: usize,
}

impl<D: Buf> ValueSource<D> {
    /// The source of the bytes of `value`.
    pub fn new(value: D) -> Self {
        let length = value.remaining();
        Self { value, length }
    }

    /// The length of the whole value.
    pub fn length(&self) -> usize {
        self.length
    }

    /// The number of bytes that have not been read.
    pub fn remaining(&self) -> usize {
        self.value.remaining()
    }

    /// Checks that the whole value has been read.
    ///
    /// # Errors
    ///
    /// [`TrailingBytesError`] if bytes are left.
    pub fn finish(&self) -> Result<(), TrailingBytesError> {
        match NonZeroUsize::new(self.value.remaining()) {
            None => Ok(()),
            Some(unread) => Err(TrailingBytesError {
                length: self.length,
                unread,
            }),
        }
    }
}

/// The bytes of the value that have not been read.
impl<D: Buf> Buf for ValueSource<D> {
    fn remaining(&self) -> usize {
        self.value.remaining()
    }

    fn chunk(&self) -> &[u8] {
        self.value.chunk()
    }

    fn advance(&mut self, count: usize) {
        self.value.advance(count);
    }
}

/// The value of a parameter holds bytes after the content of its type.
///
/// It is constructed only when bytes are left once the content has been
/// read, so the number of bytes left is never zero and never exceeds the
/// length of the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("parameter value of {length} bytes has {unread} bytes after its content"))]
pub struct TrailingBytesError {
    length: usize,
    unread: NonZeroUsize,
}

impl TrailingBytesError {
    /// The length of the whole value.
    pub const fn length(self) -> usize {
        self.length
    }

    /// The number of bytes after the content, at most
    /// [`length`](Self::length).
    pub const fn unread(self) -> NonZeroUsize {
        self.unread
    }
}

/// Failures of reading the value of a parameter with a read function that
/// fails with `R`: the [`KeyedParameter::ValueError`] of a type whose
/// content is read by such a function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(read_value_error), visibility(pub(crate)))]
pub enum ReadValueError<R> {
    /// The content could not be read from the value, or breaks a rule of
    /// its type.
    #[snafu(display("parameter value content read failed"))]
    Content {
        /// The failure of the read function of the type.
        source: R,
    },
    /// Bytes follow the content.
    #[snafu(transparent)]
    Trailing {
        /// The broken rule.
        source: TrailingBytesError,
    },
}

/// The IDs that the types of a [`ParameterList`] claim, in the order of the
/// list.
#[derive(Debug)]
pub struct ParameterIds(Option<(VarInt, &'static ParameterIds)>);

impl ParameterIds {
    /// No ID.
    const EMPTY: Self = Self(None);

    /// `first`, then the IDs of `rest`.
    const fn with(first: VarInt, rest: &'static Self) -> Self {
        Self(Some((first, rest)))
    }

    /// Whether `id` is one of the IDs.
    pub const fn contains(&self, id: VarInt) -> bool {
        let mut ids = self;
        while let Some((first, rest)) = ids.0 {
            if first.get() == id.get() {
                return true;
            }
            ids = rest;
        }
        false
    }
}

/// A list of parameter types of the space `S`: `HNil`, or `HCons<H, T>` of a
/// parameter type `H` and a list `T`, such as
/// `HList![InitialMaxData, MaxAckDelay]`. The list is used as a type only;
/// the values are in [`Self::Slots`].
///
/// [`Parameters`] and the functions of [`codec`] work on a list through
/// this trait; each of its functions handles the first type of the list and
/// leaves the rest to the rest of the list.
pub trait ParameterList<S: ParameterSpace> {
    /// One slot per type, in the order of the list: `HNil`, or
    /// `HCons<Option<H>, T::Slots>`.
    type Slots;

    /// The sum of the [`KeyedParameter::ValueError`]s of the types: `CNil`,
    /// or `Coproduct<H::ValueError, T::ValueErrors>`.
    type ValueErrors: ErrorCoproduct;

    /// The IDs the types claim.
    const IDS: &'static ParameterIds;

    /// Whether no two types claim the same ID, and none claims a reserved
    /// ID of the space.
    const DISTINCT_AND_UNRESERVED: bool;

    /// The slots with every slot empty.
    fn empty() -> Self::Slots;

    /// Gives the value of the parameter `id` that was just read to the type
    /// that claims it, which reads it into its slot; `context` is that of
    /// the set of parameters. Gives the value back if no type of the list
    /// claims `id`.
    ///
    /// The slot must be empty; then the space must admit the parameter
    /// ([`ParameterSpace::admit`]); then the type reads the value, all of
    /// it.
    ///
    /// # Errors
    ///
    /// [`ReadParametersError::Duplicate`] if the slot holds a parameter
    /// already, [`ReadParametersError::NotAdmitted`] if the space does not
    /// admit the parameter, and [`ReadParametersError::InvalidValue`] if the
    /// type cannot read the value or does not read all of it; never the
    /// other variants.
    // The type spells out the failures of the space and of the list.
    #[allow(clippy::type_complexity)]
    fn read_into<D: Buf>(
        slots: &mut Self::Slots,
        id: VarInt,
        value: D,
        context: S::Context,
    ) -> Result<Option<D>, ReadParametersError<S::AdmitError, Self::ValueErrors>>;

    /// Checks each slot that holds a parameter as
    /// [`Parameters::validate`] describes.
    ///
    /// # Errors
    ///
    /// [`InvalidParametersError::NotAdmitted`] and
    /// [`InvalidParametersError::ValueLength`]; never the other variants.
    fn validate(
        slots: &Self::Slots,
        context: S::Context,
    ) -> Result<(), InvalidParametersError<S::AdmitError>>;

    /// Empties each slot whose type has attributes that `keep` rejects, and
    /// leaves the others as they are.
    fn retain<K: FnMut(&S::Attributes) -> bool>(slots: &mut Self::Slots, keep: &mut K);

    /// The number of bytes [`write`](Self::write) writes.
    fn encoded_len(slots: &Self::Slots) -> usize;

    /// Writes each slot that holds a parameter, in the order of the list:
    /// the ID, the Length and the value.
    ///
    /// # Panics
    ///
    /// If `dst` has no room for the parameters, as [`BufMut`] does.
    fn write<B: BufMut>(slots: &Self::Slots, dst: &mut B);
}

impl<S: ParameterSpace> ParameterList<S> for HNil {
    type Slots = HNil;
    type ValueErrors = CNil;

    const IDS: &'static ParameterIds = &ParameterIds::EMPTY;

    const DISTINCT_AND_UNRESERVED: bool = true;

    fn empty() -> HNil {
        HNil
    }

    fn read_into<D: Buf>(
        _slots: &mut HNil,
        _id: VarInt,
        value: D,
        _context: S::Context,
    ) -> Result<Option<D>, ReadParametersError<S::AdmitError, CNil>> {
        Ok(Some(value))
    }

    fn validate(
        _slots: &HNil,
        _context: S::Context,
    ) -> Result<(), InvalidParametersError<S::AdmitError>> {
        Ok(())
    }

    fn retain<K: FnMut(&S::Attributes) -> bool>(_slots: &mut HNil, _keep: &mut K) {}

    fn encoded_len(_slots: &HNil) -> usize {
        0
    }

    fn write<B: BufMut>(_slots: &HNil, _dst: &mut B) {}
}

impl<S, H, T> ParameterList<S> for HCons<H, T>
where
    S: ParameterSpace,
    H: KeyedParameter<Space = S>,
    T: ParameterList<S>,
{
    type Slots = HCons<Option<H>, T::Slots>;
    type ValueErrors = Coproduct<H::ValueError, T::ValueErrors>;

    const IDS: &'static ParameterIds = &ParameterIds::with(H::ID, T::IDS);

    const DISTINCT_AND_UNRESERVED: bool =
        T::DISTINCT_AND_UNRESERVED && !T::IDS.contains(H::ID) && !S::RESERVED.contains(H::ID);

    fn empty() -> Self::Slots {
        HCons {
            head: None,
            tail: T::empty(),
        }
    }

    fn read_into<D: Buf>(
        slots: &mut Self::Slots,
        id: VarInt,
        value: D,
        context: S::Context,
    ) -> Result<Option<D>, ReadParametersError<S::AdmitError, Self::ValueErrors>> {
        if id != H::ID {
            return T::read_into(&mut slots.tail, id, value, context)
                .map_err(ReadParametersError::after);
        }
        if slots.head.is_some() {
            return Err(DuplicateError { id }.into());
        }
        S::admit(id, &H::ATTRIBUTES, context).context(NotAdmittedSnafu { id })?;
        let mut source = ValueSource::new(value);
        let parameter = H::read_value(&mut source)
            .and_then(|parameter| {
                source.finish()?;
                Ok(parameter)
            })
            .map_err(|error| {
                codec::read_parameters_error::InvalidValueSnafu { id }
                    .into_error(PartsError(Coproduct::Inl(error)))
            })?;
        slots.head = Some(parameter);
        Ok(None)
    }

    fn validate(
        slots: &Self::Slots,
        context: S::Context,
    ) -> Result<(), InvalidParametersError<S::AdmitError>> {
        if let Some(parameter) = &slots.head {
            S::admit(H::ID, &H::ATTRIBUTES, context).context(NotAdmittedSnafu { id: H::ID })?;
            ValueLengthError::check(H::ID, parameter.value_len())?;
        }
        T::validate(&slots.tail, context)
    }

    fn retain<K: FnMut(&S::Attributes) -> bool>(slots: &mut Self::Slots, keep: &mut K) {
        if !keep(&H::ATTRIBUTES) {
            slots.head = None;
        }
        T::retain(&mut slots.tail, keep);
    }

    fn encoded_len(slots: &Self::Slots) -> usize {
        let first = slots
            .head
            .as_ref()
            .map_or(0, |parameter| item_len(H::ID, parameter.value_len()));
        first.saturating_add(T::encoded_len(&slots.tail))
    }

    fn write<B: BufMut>(slots: &Self::Slots, dst: &mut B) {
        if let Some(parameter) = &slots.head {
            dst.put_slice(item_head(H::ID, parameter.value_len()).as_slice());
            parameter.write_value(dst);
        }
        T::write(&slots.tail, dst);
    }
}

/// The number of bytes of an item with the ID `id` and a value of
/// `value_len` bytes.
fn item_len(id: VarInt, value_len: usize) -> usize {
    (id.encoded_len() + length_field_len(value_len)).saturating_add(value_len)
}

/// The ID and the Length of an item with a value of `value_len` bytes.
fn item_head(id: VarInt, value_len: usize) -> Head<16> {
    // Validation bounds the length of each value by 2^62 - 1.
    let length = VarInt::try_from(value_len).unwrap_or(VarInt::MAX);
    // invariant: 16 bytes hold two variable-length integers of the longest
    // encoding.
    Head::<16>::new(id)
        .and_then(|head| head.var_int(length))
        .expect("the head holds the fields")
}

/// The parameter types of a part in the space `S`: what version 1 or one
/// extension defines there.
///
/// It is implemented by the marker type of each part that defines
/// parameters of the space.
pub trait ParametersPart<S: ParameterSpace> {
    /// The parameter types of the part, as a list used as a type only, such
    /// as `HList![InitialMaxData, MaxAckDelay]`.
    type Parameters: ParameterList<S>;
}

/// The parameter types of a list of parts in the space `S`: the lists of the
/// parts ([`ParametersPart::Parameters`]) joined in the order of the parts.
///
/// It is implemented for `HNil` and for `HCons<P, Ps>` of a part `P` and a
/// list of parts `Ps`, such as `HList![v1::Part, datagram::Part]`.
pub trait ParametersOf<S: ParameterSpace> {
    /// The joined list: one flat list of parameter types.
    type Parameters: ParameterList<S>;
}

impl<S: ParameterSpace> ParametersOf<S> for HNil {
    type Parameters = HNil;
}

impl<S, P, Ps> ParametersOf<S> for HCons<P, Ps>
where
    S: ParameterSpace,
    P: ParametersPart<S>,
    Ps: ParametersOf<S>,
    P::Parameters: Add<Ps::Parameters>,
    <P::Parameters as Add<Ps::Parameters>>::Output: ParameterList<S>,
{
    type Parameters = <P::Parameters as Add<Ps::Parameters>>::Output;
}

/// Asserts at compile time that no two types of a list of parameter types
/// claim the same ID and that none claims a reserved ID of its space
/// ([`ParameterList::DISTINCT_AND_UNRESERVED`]).
///
/// Whoever composes a list writes it for the space and the list; `cargo
/// check` reports a list that breaks the rule.
#[macro_export]
macro_rules! assert_parameters_distinct {
    ($space:ty, $list:ty $(,)?) => {
        const _: () = ::core::assert!(
            <$list as $crate::parameters::ParameterList<$space>>::DISTINCT_AND_UNRESERVED,
            "two parameter types of the list claim the same ID, or one claims a reserved ID"
        );
    };
}

/// A parameter that no type of a list claims, such as one defined by an
/// extension that is not in the list, or a reserved one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnknownParameter<D> {
    /// The parameter ID.
    pub id: VarInt,
    /// The value.
    pub value: D,
}

impl<D> UnknownParameter<D> {
    /// The parameter `id` with `value`.
    pub fn new(id: impl Into<VarInt>, value: D) -> Self {
        Self {
            id: id.into(),
            value,
        }
    }
}

/// The parameters of one endpoint in the space `S`: a slot for each type of
/// the list `L`, and the parameters that no type of `L` claims.
///
/// `D` holds the values of unknown parameters: the type of the source
/// for parameters that were read, any [`Buf`] for parameters to write.
pub struct Parameters<S: ParameterSpace, L: ParameterList<S>, D> {
    /// One slot per type of the list, in the order of the list; `None` for a
    /// parameter that is absent.
    pub known: L::Slots,
    /// The parameters that no type of the list claims, in the order they
    /// appear. To be written, their IDs must be distinct and none may be
    /// the ID of a type of the list ([`validate`](Self::validate)).
    pub unknown: Vec<UnknownParameter<D>>,
    space: PhantomData<S>,
}

impl<S: ParameterSpace, L: ParameterList<S>, D> Parameters<S, L, D> {
    /// No parameter: every slot empty.
    pub fn new() -> Self {
        const {
            assert!(
                L::DISTINCT_AND_UNRESERVED,
                "two parameter types of the list claim the same ID, or one claims a reserved ID"
            );
        }
        Self {
            known: L::empty(),
            unknown: Vec::new(),
            space: PhantomData,
        }
    }

    /// The parameter of the type `T`, or `None` if it is absent.
    ///
    /// `I` is the position of the type in the list, which the compiler
    /// infers: `parameters.get::<InitialMaxData, _>()`.
    pub fn get<T, I>(&self) -> Option<&T>
    where
        L::Slots: Selector<Option<T>, I>,
    {
        self.known.get().as_ref()
    }

    /// The parameter of the type `T`, or the default value of the type if
    /// it is absent.
    pub fn get_or_default<T, I>(&self) -> T
    where
        T: Clone + Default,
        L::Slots: Selector<Option<T>, I>,
    {
        self.get::<T, I>().cloned().unwrap_or_default()
    }

    /// The slot of the type `T`.
    pub fn slot_mut<T, I>(&mut self) -> &mut Option<T>
    where
        L::Slots: Selector<Option<T>, I>,
    {
        self.known.get_mut()
    }

    /// Puts `parameter` into the slot of its type, and gives what the slot
    /// held.
    pub fn set<T, I>(&mut self, parameter: T) -> Option<T>
    where
        L::Slots: Selector<Option<T>, I>,
    {
        self.slot_mut::<T, I>().replace(parameter)
    }
}

impl<S: ParameterSpace, L: ParameterList<S>, D: Buf> Parameters<S, L, D> {
    /// Checks what [`codec::write_parameters`] checks before writing, for a
    /// set of parameters with `context`.
    ///
    /// # Errors
    ///
    /// [`InvalidParametersError::NotAdmitted`] if the space does not admit a
    /// parameter that a slot holds; [`InvalidParametersError::ClaimedId`] if
    /// an unknown parameter has the ID of a type of the list;
    /// [`InvalidParametersError::Duplicate`] if two unknown parameters share
    /// an ID; and [`InvalidParametersError::ValueLength`] for a value that
    /// is longer than its Length can state.
    pub fn validate(
        &self,
        context: S::Context,
    ) -> Result<(), InvalidParametersError<S::AdmitError>> {
        L::validate(&self.known, context)?;
        let mut seen = UnknownIds::new();
        for (index, parameter) in self.unknown.iter().enumerate() {
            let id = parameter.id;
            if L::IDS.contains(id) {
                return ClaimedIdSnafu { id }.fail();
            }
            seen.check(&self.unknown[..index], id)?;
            ValueLengthError::check(id, parameter.value.remaining())?;
        }
        Ok(())
    }

    /// The number of bytes [`codec::write_parameters`] writes.
    pub fn encoded_len(&self) -> usize {
        self.unknown
            .iter()
            .fold(L::encoded_len(&self.known), |length, parameter| {
                length.saturating_add(item_len(parameter.id, parameter.value.remaining()))
            })
    }
}

impl<S: ParameterSpace, L: ParameterList<S>, D> Default for Parameters<S, L, D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: ParameterSpace, L: ParameterList<S>, D: Clone> Clone for Parameters<S, L, D>
where
    L::Slots: Clone,
{
    fn clone(&self) -> Self {
        Self {
            known: self.known.clone(),
            unknown: self.unknown.clone(),
            space: PhantomData,
        }
    }
}

impl<S: ParameterSpace, L: ParameterList<S>, D: Debug> Debug for Parameters<S, L, D>
where
    L::Slots: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parameters")
            .field("known", &self.known)
            .field("unknown", &self.unknown)
            .finish()
    }
}

impl<S: ParameterSpace, L: ParameterList<S>, D: PartialEq> PartialEq for Parameters<S, L, D>
where
    L::Slots: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.known == other.known && self.unknown == other.unknown
    }
}

impl<S: ParameterSpace, L: ParameterList<S>, D: Eq> Eq for Parameters<S, L, D> where L::Slots: Eq {}

/// The IDs of the unknown parameters of a set seen so far, to find one that
/// appears twice without comparing each ID with every ID before it.
///
/// A set has few unknown parameters as a rule, so the first
/// [`SCAN_LIMIT`](Self::SCAN_LIMIT) are compared one by one and nothing is
/// allocated; from there on the IDs are kept in an ordered set, so a set of
/// n unknown parameters takes time in O(n log n).
struct UnknownIds {
    /// Empty until there are [`SCAN_LIMIT`](Self::SCAN_LIMIT) earlier
    /// parameters; from then on, the ID of every one of them.
    seen: BTreeSet<VarInt>,
}

impl UnknownIds {
    /// The number of earlier parameters up to which an ID is compared with
    /// each of them.
    const SCAN_LIMIT: usize = 16;

    fn new() -> Self {
        Self {
            seen: BTreeSet::new(),
        }
    }

    /// Checks that `id` is not the ID of a parameter of `earlier`, the
    /// unknown parameters before it, which hold distinct IDs; every call
    /// gives the parameters of the previous call and the one it checked.
    fn check<D>(
        &mut self,
        earlier: &[UnknownParameter<D>],
        id: VarInt,
    ) -> Result<(), DuplicateError> {
        if earlier.len() < Self::SCAN_LIMIT {
            if earlier.iter().any(|parameter| parameter.id == id) {
                return Err(DuplicateError { id });
            }
            return Ok(());
        }
        if self.seen.is_empty() {
            self.seen
                .extend(earlier.iter().map(|parameter| parameter.id));
        }
        if self.seen.insert(id) {
            Ok(())
        } else {
            Err(DuplicateError { id })
        }
    }
}

/// A parameter appears more than once in a set of parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("parameter {:#x} appears more than once", id.get()))]
pub struct DuplicateError {
    id: VarInt,
}

impl DuplicateError {
    /// The parameter ID.
    pub const fn id(self) -> VarInt {
        self.id
    }
}

/// The space does not admit a parameter in a set of parameters
/// ([`ParameterSpace::admit`]); `A` is the reason the space gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("parameter {:#x} is not admitted", id.get()))]
pub struct NotAdmittedError<A> {
    id: VarInt,
    source: A,
}

impl<A> NotAdmittedError<A> {
    /// The parameter ID.
    pub const fn id(&self) -> VarInt {
        self.id
    }

    /// The reason the space gives.
    pub const fn reason(&self) -> &A {
        &self.source
    }
}

/// The value of a parameter to write is longer than 2<sup>62</sup> − 1
/// bytes, more than its Length can state.
///
/// It is constructed only when the check fails, so the length it holds
/// always exceeds 2<sup>62</sup> − 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "parameter {:#x} has a value of {length} bytes, longer than 2^62 - 1",
    id.get()
))]
pub struct ValueLengthError {
    id: VarInt,
    length: usize,
}

impl ValueLengthError {
    /// The parameter ID.
    pub const fn id(self) -> VarInt {
        self.id
    }

    /// The length of the value, above 2<sup>62</sup> − 1.
    pub const fn length(self) -> usize {
        self.length
    }

    /// Checks that a value of `length` bytes for the parameter `id` fits a
    /// Length.
    fn check(id: VarInt, length: usize) -> Result<(), Self> {
        if VarInt::try_from(length).is_err() {
            return Err(Self { id, length });
        }
        Ok(())
    }
}

/// A set of parameters that must not be written
/// ([`Parameters::validate`]); `A` is the reason the space gives for a
/// parameter it does not admit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum InvalidParametersError<A> {
    /// The space does not admit a parameter that a slot holds.
    #[snafu(transparent)]
    NotAdmitted {
        /// The parameter and the reason.
        source: NotAdmittedError<A>,
    },
    /// An unknown parameter has the ID of a type of the list, whose slot is
    /// the place of that parameter.
    #[snafu(display(
        "unknown parameter {:#x} has the ID of a parameter type of the list",
        id.get()
    ))]
    ClaimedId {
        /// The parameter ID.
        id: VarInt,
    },
    /// Two unknown parameters share an ID.
    #[snafu(transparent)]
    Duplicate {
        /// The repeated parameter.
        source: DuplicateError,
    },
    /// A value is longer than its Length can state.
    #[snafu(transparent)]
    ValueLength {
        /// The broken limit.
        source: ValueLengthError,
    },
}
