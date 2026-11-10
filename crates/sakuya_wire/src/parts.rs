//! Compositions of parts, and the sums of what each part gives.
//!
//! A composition is a list of parts, such as
//! `HList![v1::Part, datagram::Part]`. What the parts give one each, such as
//! the frame, the kind or the failure of reading a frame, is a value of the
//! sum of those types: a `Coproduct` that ends in `CNil`, with one variant
//! per part in the order of the list. The list and the sum are types of
//! `frunk_core`, re-exported here: [`HList!`] and [`Coprod!`] write their
//! types, [`HCons`] and [`HNil`] are the cells of a list, and
//! [`Coproduct`], [`CNil`], [`CoprodInjector`] and [`CoprodUninjector`] build
//! and take apart a sum. A caller picks a part's value out of a sum by its
//! type, with `get`, `uninject` or `extract`, and does not name its position.
//! A list of values, such as the slots of a set of parameters
//! ([`parameters`](crate::parameters)), is taken apart by type in the same
//! way: `get` and `get_mut` take one element ([`Selector`]) and `sculpt`
//! takes several at once ([`Sculptor`]).
//!
//! [`PartsError`] wraps the sum of the failures of the parts, so that it is
//! one error that shows and chains as the failure of the part it holds.
use core::{
    error::Error,
    fmt::{self, Debug, Display},
};

pub use frunk_core::{
    Coprod, HList,
    coproduct::{CNil, CoprodInjector, CoprodUninjector, Coproduct},
    hlist::{HCons, HNil, Sculptor, Selector},
};

/// A sum of the failures of the parts of a composition, wrapped to be one
/// error.
///
/// It shows as the failure it holds, and its source is that failure's
/// source. `C` is a `Coproduct` of errors that ends in `CNil`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PartsError<C>(pub C);

/// A sum of errors: a `Coproduct` of errors that ends in `CNil`.
///
/// It lets [`PartsError`] reach the error the sum holds.
pub trait ErrorCoproduct {
    /// The error this sum holds.
    fn as_error(&self) -> &(dyn Error + 'static);
}

impl ErrorCoproduct for CNil {
    fn as_error(&self) -> &(dyn Error + 'static) {
        match *self {}
    }
}

impl<H: Error + 'static, T: ErrorCoproduct> ErrorCoproduct for Coproduct<H, T> {
    fn as_error(&self) -> &(dyn Error + 'static) {
        match self {
            Self::Inl(error) => error,
            Self::Inr(rest) => rest.as_error(),
        }
    }
}

impl<C: ErrorCoproduct> Display for PartsError<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(self.0.as_error(), f)
    }
}

impl<C: ErrorCoproduct + Debug> Error for PartsError<C> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.as_error().source()
    }
}
