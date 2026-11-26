//! Decoding a variable-length integer from a borrowed source, and encoding
//! one into a borrowed sink, are `Send` when the source or sink is.
use nitori_call::{ConstructedAccess, ReceiverAccess};
use nitori_codec::prelude::*;
use nitori_io::{Read, Write};
use sakuya_var_int::{VarInt, VarIntField};

/// Checks that `future` is `Send`, then runs it.
fn send<T: Future + Send>(future: T) -> T::Output {
    nitori_call::__private::run_sync(future)
}

async fn through<I: ReceiverAccess<Family: Read<Metadata = ()>>>(io: &mut I) -> Option<u64> {
    let field = io.decode::<VarIntField<VarInt>>().await.ok()?;
    Some(field.get().get())
}

async fn into<I: ReceiverAccess<Family: Write<(), Report = ()>>>(
    io: &mut I,
    value: VarInt,
) -> bool {
    io.encode(value).await.is_ok()
}

#[test]
fn decoding_from_a_borrowed_source_is_send() {
    let mut io = ConstructedAccess::new(&[0x25, 0x7b, 0xbd, 0x00][..]);
    assert_eq!(send(io.decode::<VarInt>()).unwrap().get(), 37);
    assert_eq!(send(through(&mut io)), Some(15_293));
    assert_eq!(send(through(&mut &mut io)), Some(0));
}

#[test]
fn encoding_into_a_borrowed_sink_is_send() {
    let mut io = ConstructedAccess::new(Vec::new());
    let value = VarInt::from_u32(37);
    send(io.encode(value)).unwrap();
    assert!(send(into(&mut io, value)));
    assert!(send(into(&mut &mut io, value)));
    assert_eq!(io.into_inner(), [0x25; 3]);
}
