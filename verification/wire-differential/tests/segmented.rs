//! sakuya reads from a source whose bytes come in short chunks what it reads
//! from a contiguous slice.
//!
//! The readers take any `Buf + SplitTo`. A `Buf` may hand out its bytes in
//! several chunks, so a reader that looked only at the first chunk, or
//! assumed a field lies within one, would read differently here.
use bytes::{Buf, Bytes};
use core::{marker::PhantomData, num::NonZeroUsize, ops::Range};
use nitori_io::{SplitTo, SplitToError};
use proptest::prelude::*;
use sakuya_var_int::{
    VarInt, VarIntField,
    codec::{read_var_int, read_var_int_field},
};
use sakuya_wire_v1::{
    role::Role,
    transport_parameters::codec::{read_transport_parameters, write_transport_parameters},
};
use wire_differential::{
    cases,
    frames::{
        generate::payload,
        sakuya::{self, Full, V1Only},
    },
    headers::{
        generate::{coalesced, datagram},
        read_sakuya, read_sakuya_from,
    },
    parameters::{generate::parameters, sakuya::Parts},
};

/// Bytes whose `chunk` is at most `segment` long.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Segmented {
    bytes: Bytes,
    segment: NonZeroUsize,
}

impl Segmented {
    fn new(bytes: &[u8], segment: NonZeroUsize) -> Self {
        Self {
            bytes: Bytes::copy_from_slice(bytes),
            segment,
        }
    }
}

impl Buf for Segmented {
    fn remaining(&self) -> usize {
        self.bytes.len()
    }

    fn chunk(&self) -> &[u8] {
        &self.bytes[..self.bytes.len().min(self.segment.get())]
    }

    fn advance(&mut self, count: usize) {
        self.bytes.advance(count);
    }
}

impl SplitTo for Segmented {
    fn split_to(&mut self, at: usize) -> Result<Self, SplitToError> {
        Ok(Self {
            bytes: SplitTo::split_to(&mut self.bytes, at)?,
            segment: self.segment,
        })
    }
}

/// All the bytes not yet read, for the models that compare what was read.
impl AsRef<[u8]> for Segmented {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// The bytes of the payload each item was read from.
fn ranges<D>(read: &sakuya::Read<D>) -> Vec<Range<usize>> {
    read.runs.iter().map(|(range, _)| range.clone()).collect()
}

fn segment() -> impl Strategy<Value = NonZeroUsize> {
    (1usize..=8).prop_map(|length| NonZeroUsize::new(length).unwrap())
}

fn role() -> impl Strategy<Value = Role> {
    prop_oneof![Just(Role::Client), Just(Role::Server)]
}

proptest! {
    #![proptest_config(cases::config(20_000))]

    #[test]
    fn var_ints_read_the_same(bytes in prop::collection::vec(any::<u8>(), 0..10), segment in segment()) {
        let mut slice = &bytes[..];
        let mut segmented = Segmented::new(&bytes, segment);
        let from_slice = read_var_int(&mut slice).map(VarInt::get);
        let from_segmented = read_var_int(&mut segmented).map(VarInt::get);
        prop_assert_eq!(format!("{from_slice:?}"), format!("{from_segmented:?}"));
        prop_assert_eq!(slice.len(), segmented.remaining());

        let mut slice = &bytes[..];
        let mut segmented = Segmented::new(&bytes, segment);
        let from_slice: Result<VarIntField<VarInt>, _> = read_var_int_field(&mut slice);
        let from_segmented: Result<VarIntField<VarInt>, _> = read_var_int_field(&mut segmented);
        prop_assert_eq!(format!("{from_slice:?}"), format!("{from_segmented:?}"));
        prop_assert_eq!(slice.len(), segmented.remaining());
    }

    #[test]
    fn frames_read_the_same(payload in payload(), segment in segment()) {
        let from_slice = sakuya::read(&payload);
        let from_segmented = sakuya::read_with::<Full, _>(Segmented::new(&payload, segment));
        prop_assert_eq!(ranges(&from_slice), ranges(&from_segmented));
        prop_assert_eq!(from_slice.decoded(), from_segmented.decoded());
        prop_assert_eq!(from_slice.failure, from_segmented.failure);

        let from_slice = sakuya::read_v1(&payload);
        let from_segmented = sakuya::read_with::<V1Only, _>(Segmented::new(&payload, segment));
        prop_assert_eq!(ranges(&from_slice), ranges(&from_segmented));
        prop_assert_eq!(from_slice.decoded(), from_segmented.decoded());
        prop_assert_eq!(from_slice.failure, from_segmented.failure);
    }

    /// Parameters read from either source write the same bytes, and a
    /// failure is the same failure.
    #[test]
    fn transport_parameters_read_the_same(
        bytes in parameters(),
        sender in role(),
        segment in segment(),
    ) {
        let mut slice = &bytes[..];
        let mut segmented = Segmented::new(&bytes, segment);
        let from_slice = read_transport_parameters(&mut slice, sender, PhantomData::<Parts>);
        let from_segmented =
            read_transport_parameters(&mut segmented, sender, PhantomData::<Parts>);
        match (from_slice, from_segmented) {
            (Ok(from_slice), Ok(from_segmented)) => {
                let mut written_from_slice = Vec::new();
                let mut written_from_segmented = Vec::new();
                let slice_result =
                    write_transport_parameters(&mut written_from_slice, from_slice, sender);
                let segmented_result =
                    write_transport_parameters(&mut written_from_segmented, from_segmented, sender);
                prop_assert_eq!(format!("{slice_result:?}"), format!("{segmented_result:?}"));
                prop_assert_eq!(written_from_slice, written_from_segmented);
            }
            (from_slice, from_segmented) => prop_assert_eq!(
                format!("{:?}", from_slice.err()),
                format!("{:?}", from_segmented.err())
            ),
        }
    }

    #[test]
    fn packet_headers_read_the_same(
        (bytes, short_len) in prop_oneof![coalesced(), datagram()],
        segment in segment(),
    ) {
        let mut segmented = Segmented::new(&bytes, segment);
        prop_assert_eq!(
            read_sakuya(&bytes, short_len),
            read_sakuya_from(&mut segmented, short_len)
        );
    }
}
