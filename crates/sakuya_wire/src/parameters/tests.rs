//! The mechanism with a space of its own, which is not that of the QUIC
//! transport parameters: no attributes, no context, and other reserved IDs.
use super::{
    KeyedParameter, ParameterList, ParameterSpace, Parameters, ParametersOf, ParametersPart,
    ReadValueError, ReservedIds, TrailingBytesError, UnknownParameter, ValueSource,
    codec::{ReadParametersError, ReadParametersHostExt as _, WriteParametersHostExt as _},
    read_value_error::ContentSnafu,
};
use crate::{
    parts::{HList, HNil},
    var_int::{
        VarInt,
        codec::{ReadVarIntError, ReadVarIntHostExt as _},
    },
};
use bytes::Buf;
use core::{convert::Infallible, marker::PhantomData, num::NonZeroU64};
use nitori_call::ReceiverAccess;
use nitori_io::{calls::WriteAllError, prelude::*};
use snafu::ResultExt;

struct Space;

impl ParameterSpace for Space {
    type Attributes = ();
    type Context = ();
    type AdmitError = Infallible;
    type ErrorCode = u16;

    const ERROR_CODE: u16 = 0x0109;

    const RESERVED: ReservedIds = ReservedIds::new(NonZeroU64::new(0x1f).unwrap(), 0x21);

    fn admit(_id: VarInt, _attributes: &(), _context: ()) -> Result<(), Infallible> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Size(VarInt);

impl KeyedParameter for Size {
    type Space = Space;
    type ValueError = ReadValueError<ReadVarIntError<Infallible>>;

    const ID: VarInt = VarInt::from_u32(0x06);
    const ATTRIBUTES: () = ();

    fn read_value<D: Buf + Unpin>(value: &mut ValueSource<D>) -> Result<Self, Self::ValueError> {
        value
            .sync_read_var_int_unpin()
            .map(Self)
            .context(ContentSnafu)
    }

    fn value_len(&self) -> usize {
        self.0.encoded_len()
    }

    async fn write_value<F, A>(&self, io: &mut A) -> Result<(), WriteAllError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
    {
        let (encoding, encoded_len) = self.0.to_encoding();
        io.write_all(&encoding[..encoded_len]).await
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Flag;

impl KeyedParameter for Flag {
    type Space = Space;
    type ValueError = TrailingBytesError;

    const ID: VarInt = VarInt::from_u32(0x08);
    const ATTRIBUTES: () = ();

    fn read_value<D: Buf + Unpin>(_: &mut ValueSource<D>) -> Result<Self, TrailingBytesError> {
        Ok(Self)
    }

    fn value_len(&self) -> usize {
        0
    }

    async fn write_value<F, A>(&self, _: &mut A) -> Result<(), WriteAllError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
    {
        Ok(())
    }
}

struct First;
struct Second;

impl ParametersPart<Space> for First {
    type Parameters = HList![Size];
}

impl ParametersPart<Space> for Second {
    type Parameters = HList![Flag];
}

type Both = <HList![Second, First] as ParametersOf<Space>>::Parameters;

crate::assert_parameters_distinct!(Space, Both);
crate::assert_parameters_distinct!(Space, HNil);

#[test]
fn a_space_of_its_own_reads_and_writes() {
    // Size 300, a reserved ID (0x1f * 1 + 0x21), then the flag.
    let encoding = [0x06, 0x02, 0x41, 0x2c, 0x40, 0x40, 0x01, 0xee, 0x08, 0x00];
    let mut input = &encoding[..];
    let parameters = input
        .sync_read_parameters_unpin((), PhantomData::<(Space, Both)>)
        .unwrap();
    assert_eq!(
        parameters.get::<Size, _>(),
        Some(&Size(VarInt::from(300u16)))
    );
    assert_eq!(parameters.get::<Flag, _>(), Some(&Flag));
    assert_eq!(
        parameters.unknown,
        [UnknownParameter::new(VarInt::from(0x40u8), &[0xee][..])]
    );
    assert_eq!(parameters.validate(()), Ok(()));
    let mut written = Vec::new();
    written
        .sync_write_parameters_unpin(parameters.clone(), ())
        .unwrap();
    // The slots in the order of the list, the flag first, then the unknown.
    assert_eq!(
        written,
        [0x08, 0x00, 0x06, 0x02, 0x41, 0x2c, 0x40, 0x40, 0x01, 0xee]
    );
    assert_eq!(written.len(), parameters.encoded_len());
    assert_eq!(<Space as ParameterSpace>::ERROR_CODE, 0x0109);
}

#[test]
fn the_empty_list_keeps_every_parameter_as_unknown() {
    let mut input = &[0x06, 0x01, 0x05, 0x08, 0x00][..];
    let parameters = input
        .sync_read_parameters_unpin((), PhantomData::<(Space, HNil)>)
        .unwrap();
    assert_eq!(parameters.known, HNil);
    assert_eq!(parameters.unknown.len(), 2);
    let mut input = &[0x06, 0x00, 0x06, 0x00][..];
    let error = input
        .sync_read_parameters_unpin((), PhantomData::<(Space, HNil)>)
        .unwrap_err();
    assert!(matches!(error, ReadParametersError::Duplicate { .. }));
}

#[test]
fn ids_of_a_list_and_reserved_ids() {
    let ids = <Both as ParameterList<Space>>::IDS;
    for value in 0u8..=0x40 {
        assert_eq!(
            ids.contains(VarInt::from(value)),
            matches!(value, 0x06 | 0x08)
        );
    }
    let reserved = Space::RESERVED;
    assert_eq!((reserved.step().get(), reserved.offset()), (0x1f, 0x21));
    for value in 0u16..=1000 {
        let expected = value >= 0x21 && (value - 0x21) % 0x1f == 0;
        assert_eq!(reserved.contains(VarInt::from(value)), expected, "{value}");
    }
    let parameters = Parameters::<Space, Both, &[u8]>::new();
    assert!(parameters.get::<Size, _>().is_none());
}

#[test]
fn a_value_source_reports_what_is_left() {
    let mut value = ValueSource::new(&[0x05, 0xaa, 0xbb][..]);
    assert_eq!((value.length(), value.remaining()), (3, 3));
    assert_eq!(
        Size::read_value(&mut value).unwrap(),
        Size(VarInt::from(5u8))
    );
    let error = value.finish().unwrap_err();
    assert_eq!((error.length(), error.unread().get()), (3, 2));
    assert_eq!(ValueSource::new(&[][..]).finish(), Ok(()));
}
