//! Taking components out of a view by type.
//!
//! A view is a flat list of mutable borrows, one for each component of the
//! nodes it covers. Taking components moves their borrows out and leaves a
//! [`TakenOut`] marker in their place, so the rest is a view again and keeps
//! the position of every component: what a lend took is recorded by
//! position, without looking at types at run time. Taking a component twice,
//! or one the view does not have, does not compile.
//!
//! The positions a take goes by (`I`, `Is`, `Hs`) are inferred where the
//! list of parts is concrete; generic code passes them on as type
//! parameters.

pub use frunk_core::indices::{Here, There};
use sakuya_wire::parts::{HCons, HNil};

use crate::component::ComponentTypeList;

/// What is left in a view where a component was taken out.
#[derive(Debug)]
pub struct TakenOut;

/// The value of a position in a list: [`Here`] is 0, [`There`] one more.
pub trait Position {
    /// The position.
    const VALUE: usize;
}
impl Position for Here {
    const VALUE: usize = 0;
}
impl<I: Position> Position for There<I> {
    const VALUE: usize = 1 + I::VALUE;
}

/// The positions taken in one lend, in the order they were taken.
///
/// It is filled by the takes of a [`Lineage`] and read by the driver after
/// the lend.
#[derive(Debug, Default)]
pub struct TakenPositions(Vec<usize>);

impl TakenPositions {
    pub(crate) fn push(&mut self, position: usize) {
        self.0.push(position);
    }
    pub(crate) fn drain(&mut self) -> std::vec::Drain<'_, usize> {
        self.0.drain(..)
    }
    pub(crate) fn clear(&mut self) {
        self.0.clear();
    }
}

/// The mutable borrows, for `'a`, of a list of component types.
pub trait RefsOf<'a> {
    /// One `&'a mut` for each component, in order.
    type Out;
}
impl<'a> RefsOf<'a> for HNil {
    type Out = HNil;
}
impl<'a, X: 'a, Xs: RefsOf<'a>> RefsOf<'a> for HCons<X, Xs> {
    type Out = HCons<&'a mut X, Xs::Out>;
}

/// A list from which the component `X` can be taken for `'a`, at position
/// `I`.
#[diagnostic::on_unimplemented(
    message = "the component `{X}` cannot be taken from this view",
    label = "`{X}` is not in this view, or it is taken already",
    note = "a view holds each component of the lent node and the nodes above it once; another take or another participant of the same capability may have it"
)]
pub trait TakeAt<'a, X: 'a, I> {
    /// The list with [`TakenOut`] in the place of `X`.
    type Rest;
    /// Where `X` is in the list.
    const AT: usize;
    /// Move the borrow of `X` out.
    fn take_at(self) -> (&'a mut X, Self::Rest);
}
impl<'a, X: 'a, T> TakeAt<'a, X, Here> for HCons<&'a mut X, T> {
    type Rest = HCons<TakenOut, T>;
    const AT: usize = 0;
    #[inline]
    fn take_at(self) -> (&'a mut X, HCons<TakenOut, T>) {
        (
            self.head,
            HCons {
                head: TakenOut,
                tail: self.tail,
            },
        )
    }
}
impl<'a, X: 'a, H, T: TakeAt<'a, X, I>, I> TakeAt<'a, X, There<I>> for HCons<H, T> {
    type Rest = HCons<H, T::Rest>;
    const AT: usize = 1 + T::AT;
    #[inline]
    fn take_at(self) -> (&'a mut X, Self::Rest) {
        let (item, tail) = self.tail.take_at();
        (
            item,
            HCons {
                head: self.head,
                tail,
            },
        )
    }
}

/// A list from which the components `U` (a list of component types) can be
/// taken for `'a`, at the positions `Is`.
pub trait TakeEach<'a, U: RefsOf<'a>, Is> {
    /// The list with [`TakenOut`] in their places.
    type Rest;
    /// Move the borrows out, in the order of `U`; `at` is told the position
    /// of each.
    fn take_each(self, at: &mut impl FnMut(usize)) -> (U::Out, Self::Rest);
}
impl<'a, V> TakeEach<'a, HNil, HNil> for V {
    type Rest = V;
    #[inline]
    fn take_each(self, _: &mut impl FnMut(usize)) -> (HNil, V) {
        (HNil, self)
    }
}
impl<'a, V, X: 'a, Us: RefsOf<'a>, I, Is> TakeEach<'a, HCons<X, Us>, HCons<I, Is>> for V
where
    V: TakeAt<'a, X, I>,
    V::Rest: TakeEach<'a, Us, Is>,
{
    type Rest = <V::Rest as TakeEach<'a, Us, Is>>::Rest;
    #[inline]
    fn take_each(self, at: &mut impl FnMut(usize)) -> (HCons<&'a mut X, Us::Out>, Self::Rest) {
        let (head, rest) = self.take_at();
        at(V::AT);
        let (tail, rest) = rest.take_each(at);
        (HCons { head, tail }, rest)
    }
}

/// A list from which the components `U` (a list of component types) can be
/// read together, at the positions `Is`.
///
/// It is to [`GetAt`] what [`TakeEach`] is to [`TakeAt`]: generic code
/// names the list once and passes on one type parameter for all of its
/// positions. The borrows' type depends on `U` alone, so generic code can
/// take them apart.
pub trait ReadEach<U: ComponentTypeList, Is> {
    /// Read the components, in the order of `U`.
    fn read_each(&self) -> U::Refs<'_>;
}
impl<V> ReadEach<HNil, HNil> for V {
    #[inline]
    fn read_each(&self) -> HNil {
        HNil
    }
}
impl<V, X: 'static, Xs: ComponentTypeList, I, Is> ReadEach<HCons<X, Xs>, HCons<I, Is>> for V
where
    V: GetAt<X, I> + ReadEach<Xs, Is>,
{
    #[inline]
    fn read_each(&self) -> HCons<&X, Xs::Refs<'_>> {
        HCons {
            head: self.get_at(),
            tail: <V as ReadEach<Xs, Is>>::read_each(self),
        }
    }
}

/// A list that holds a borrow of the component `X`, at position `I`.
#[diagnostic::on_unimplemented(
    message = "the component `{X}` is not in this view",
    label = "`{X}` is not in this view, or it is taken already"
)]
pub trait GetAt<X, I> {
    /// Where `X` is in the list.
    const AT: usize;
    /// Read `X`.
    fn get_at(&self) -> &X;
    /// Change `X`, through a list that already holds it mutably.
    fn get_at_mut(&mut self) -> &mut X;
}
impl<X, T> GetAt<X, Here> for HCons<&mut X, T> {
    const AT: usize = 0;
    #[inline]
    fn get_at(&self) -> &X {
        self.head
    }
    #[inline]
    fn get_at_mut(&mut self) -> &mut X {
        self.head
    }
}
impl<X, H, T: GetAt<X, I>, I> GetAt<X, There<I>> for HCons<H, T> {
    const AT: usize = 1 + T::AT;
    #[inline]
    fn get_at(&self) -> &X {
        self.tail.get_at()
    }
    #[inline]
    fn get_at_mut(&mut self) -> &mut X {
        self.tail.get_at_mut()
    }
}

/// A list of borrows borrowed again for a shorter time, positions kept.
///
/// It is implemented for every `'s`, not only one the borrows outlive:
/// [`reborrow`](Self::reborrow) takes the list for `'s`, so it can only be
/// called for one they do, and a bound that holds for every pair of
/// lifetimes, such as `for<'v, 's> <L as LineageLists<'v, T>>::LinkPath:
/// Reborrow<'s>`, can be met.
pub trait Reborrow<'s> {
    /// The list with every borrow shortened to `'s`.
    type Out;
    /// Borrow every element again.
    fn reborrow(&'s mut self) -> Self::Out;
}
impl<'s> Reborrow<'s> for HNil {
    type Out = HNil;
    #[inline]
    fn reborrow(&'s mut self) -> HNil {
        HNil
    }
}
impl<'s, X: 's, T: Reborrow<'s>> Reborrow<'s> for HCons<&mut X, T> {
    type Out = HCons<&'s mut X, T::Out>;
    #[inline]
    fn reborrow(&'s mut self) -> Self::Out {
        HCons {
            head: &mut *self.head,
            tail: self.tail.reborrow(),
        }
    }
}
impl<'s, T: Reborrow<'s>> Reborrow<'s> for HCons<TakenOut, T> {
    type Out = HCons<TakenOut, T::Out>;
    #[inline]
    fn reborrow(&'s mut self) -> Self::Out {
        HCons {
            head: TakenOut,
            tail: self.tail.reborrow(),
        }
    }
}

/// A node's data and the data of the nodes above it, flat: what a call, an
/// expiry or a reread is lent first.
///
/// For a link path it is the data of the connection, of the link path's
/// logical link entry, of its logical path and of the link path itself.
/// Components are taken out by type with [`Take`]; what is left is a
/// lineage again. Every mutable take is recorded, and the
/// driver rereads what reads the components taken.
pub struct Lineage<'r, V> {
    list: V,
    taken: &'r mut TakenPositions,
}

impl<'r, V> Lineage<'r, V> {
    pub(crate) fn new(list: V, taken: &'r mut TakenPositions) -> Self {
        Self { list, taken }
    }

    /// Read the component `X`, without taking it.
    #[inline]
    pub fn get<X, I>(&self) -> &X
    where
        V: GetAt<X, I>,
    {
        self.list.get_at()
    }

    /// Read the components `U` (a list of component types) together, as
    /// shared borrows in the order of `U`, without taking them.
    #[inline]
    pub fn read_each<U: ComponentTypeList, Is>(&self) -> U::Refs<'_>
    where
        V: ReadEach<U, Is>,
    {
        self.list.read_each()
    }

    /// Change the component `X` in place, without taking it out; the change
    /// is recorded like a take.
    #[inline]
    pub fn get_mut<X, I>(&mut self) -> &mut X
    where
        V: GetAt<X, I>,
    {
        self.taken.push(V::AT);
        self.list.get_at_mut()
    }

    /// This lineage again for a shorter time, with nothing taken, so that it
    /// can be taken from and still be there afterwards.
    #[inline]
    pub fn reborrow<'s>(&'s mut self) -> Lineage<'s, <V as Reborrow<'s>>::Out>
    where
        V: Reborrow<'s>,
    {
        Lineage {
            list: self.list.reborrow(),
            taken: &mut *self.taken,
        }
    }
}

/// A list of mutable borrows made shared: what a take to read only gives.
pub(crate) trait ShareEach {
    /// One shared borrow for each, in order.
    type Out;
    /// Make every borrow shared.
    fn share_each(self) -> Self::Out;
}
impl ShareEach for HNil {
    type Out = HNil;
    #[inline]
    fn share_each(self) -> HNil {
        HNil
    }
}
impl<'a, X, T: ShareEach> ShareEach for HCons<&'a mut X, T> {
    type Out = HCons<&'a X, T::Out>;
    #[inline]
    fn share_each(self) -> Self::Out {
        HCons {
            head: &*self.head,
            tail: self.tail.share_each(),
        }
    }
}

impl<'r, V> Lineage<'r, V> {
    /// Take the components `U` out to read them only, as shared borrows in
    /// the order of `U`, with the rest of the view, which can then be taken
    /// from or lent mutably while they are read.
    ///
    /// Nothing can change them through the borrows given, so the take is
    /// not recorded: what reads them is not reread for it.
    #[inline]
    pub(crate) fn take_read<'a, U, Is>(self) -> (<U::Out as ShareEach>::Out, Lineage<'r, V::Rest>)
    where
        V: TakeEach<'a, U, Is>,
        U: RefsOf<'a>,
        U::Out: ShareEach,
    {
        let Lineage { list, taken } = self;
        let (items, rest) = list.take_each(&mut |_| {});
        (items.share_each(), Lineage { list: rest, taken })
    }
}

/// Take named components out of a view.
///
/// `U` is the list of component types, as in
/// `Take::<HList![Pto, Rtt], _>::take(lineage)`; the components come back as
/// mutable borrows in that order, with the rest of the view.
pub trait Take<'a, U: RefsOf<'a>, Is>: Sized {
    /// What is left of the view.
    type Rest;
    /// Take the components.
    fn take(self) -> (U::Out, Self::Rest);
}
impl<'r, 'a, V: TakeEach<'a, U, Is>, U: RefsOf<'a>, Is> Take<'a, U, Is> for Lineage<'r, V> {
    type Rest = Lineage<'r, V::Rest>;
    #[inline]
    fn take(self) -> (U::Out, Lineage<'r, V::Rest>) {
        let Lineage { list, taken } = self;
        let (items, rest) = list.take_each(&mut |at| taken.push(at));
        (items, Lineage { list: rest, taken })
    }
}

#[cfg(test)]
mod tests {
    use frunk_core::{hlist, hlist_pat};
    use sakuya_wire::parts::HList;

    use super::*;

    #[test]
    fn a_reborrowed_lineage_is_there_again_after_a_take() {
        let (mut a, mut b) = (1u8, 2u16);
        let mut taken = TakenPositions::default();
        let mut lineage = Lineage::new(hlist![&mut a, &mut b], &mut taken);
        {
            let (hlist_pat![b], _) = Take::<HList![u16], _>::take(lineage.reborrow());
            *b += 1;
        }
        *lineage.get_mut::<u8, _>() += 1;
        assert_eq!(*lineage.get::<u16, _>(), 3);
        assert_eq!(taken.drain().collect::<Vec<_>>(), [1, 0]);
    }
}
