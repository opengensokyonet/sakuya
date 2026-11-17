//! Variable-length integers in the three implementations.
use quinn_proto::{VarInt as QVarInt, coding::Codec as _};
use s2n_codec::{DecoderBuffer, EncoderValue as _};
use s2n_quic_core::varint::VarInt as SVarInt;
use sakuya_wire::var_int::{
    VarInt, VarIntField, VarIntWidth,
    codec::{read_var_int, read_var_int_field, write_var_int, write_var_int_field},
};

/// The value and the bytes consumed, or `None` if the input is too short.
pub type Read = Option<(u64, usize)>;

pub fn read_sakuya(bytes: &[u8]) -> Read {
    let mut source = bytes;
    let value = read_var_int(&mut source).ok()?;
    Some((value.get(), bytes.len() - source.len()))
}

/// Reads with sakuya's field reader, which keeps the width of the encoding.
pub fn read_sakuya_field(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut source = bytes;
    let field: VarIntField<VarInt> = read_var_int_field(&mut source).ok()?;
    let consumed = bytes.len() - source.len();
    assert_eq!(field.width().encoded_len(), consumed);
    Some((field.get().get(), consumed))
}

pub fn read_quinn(bytes: &[u8]) -> Read {
    let mut source = bytes;
    let value = QVarInt::decode(&mut source).ok()?;
    Some((value.into_inner(), bytes.len() - source.len()))
}

pub fn read_s2n(bytes: &[u8]) -> Read {
    let (value, rest) = DecoderBuffer::new(bytes).decode::<SVarInt>().ok()?;
    Some((value.as_u64(), bytes.len() - rest.len()))
}

/// The shortest encoding of `value`, below 2^62, with sakuya.
pub fn write_sakuya(value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    write_var_int(&mut output, VarInt::new(value).unwrap());
    output
}

/// The encoding of `value` in `width`, which must be able to hold it, with
/// sakuya's field writer.
pub fn write_sakuya_as(value: u64, width: VarIntWidth) -> Vec<u8> {
    let field = VarIntField::new(VarInt::new(value).unwrap(), width).unwrap();
    let mut output = Vec::new();
    write_var_int_field(&mut output, field);
    output
}

pub fn write_quinn(value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    QVarInt::from_u64(value).unwrap().encode(&mut output);
    output
}

pub fn write_s2n(value: u64) -> Vec<u8> {
    SVarInt::new(value).unwrap().encode_to_vec()
}
