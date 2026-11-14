//! The fuzzer drives both the bytes of a packet and, through the first
//! twelve bytes, what gets protected: the packet number, the connection ID
//! and token lengths, the sender and the reserved bits. sakuya and the
//! rustls keys through quinn-proto protect it identically and each opens
//! it; the raw input as a datagram is opened by both or by neither; and the
//! Retry Integrity Tag of the input is the same in both.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rustls::Side;
use wire_differential::protection::{
    Initial, open_quinn, open_sakuya,
    retry::{QuinnRetry, is_valid_sakuya, tag_sakuya},
};

thread_local! {
    static QUINN_RETRY: QuinnRetry = QuinnRetry::new();
}

fuzz_target!(|input: &[u8]| {
    if input.len() < 12 {
        return;
    }
    let (head, rest) = input.split_at(12);
    // A packet number below 2^40.
    let number = u64::from_be_bytes(head[..8].try_into().unwrap()) >> 24;
    let dcid_len = usize::from(head[8] % 21).min(rest.len());
    let scid_len = usize::from(head[9] % 21).min(rest.len() - dcid_len);
    let token_len = usize::from(head[10] % 32).min(rest.len() - dcid_len - scid_len);
    let (dcid, rest) = rest.split_at(dcid_len);
    let (scid, rest) = rest.split_at(scid_len);
    let (token, payload) = rest.split_at(token_len);
    let side = if head[11] & 1 == 0 {
        Side::Client
    } else {
        Side::Server
    };
    if payload.len() >= 4 {
        let packet = Initial {
            dcid: dcid.to_vec(),
            scid: scid.to_vec(),
            token: token.to_vec(),
            packet_number: number,
            largest_acked: number.checked_sub(1 + u64::from(head[11] >> 1)),
            payload: payload.to_vec(),
            reserved_bits: head[11],
        };
        let ours = packet.protect_sakuya(side);
        assert_eq!(ours, packet.protect_quinn(side));
        if let Some(protected) = ours {
            let opened = open_sakuya(&protected, dcid, side, packet.largest_acked);
            assert_eq!(
                opened,
                open_quinn(&protected, dcid, side, packet.largest_acked)
            );
            assert_eq!(opened.unwrap().payload, payload);
        }
    }
    // The raw input as a datagram: both refuse it or both open it alike.
    let ours = open_sakuya(input, dcid, side, None);
    let theirs = open_quinn(input, dcid, side, None);
    if ours.is_ok() || theirs.is_ok() {
        assert_eq!(ours, theirs);
    }
    // The input as a Retry packet, the integrity tag for the connection ID.
    let without_tag = &input[..input.len() - 16.min(input.len())];
    QUINN_RETRY.with(|quinn| {
        assert_eq!(tag_sakuya(dcid, without_tag), quinn.tag(dcid, without_tag));
        let header_len = usize::from(head[0]).min(without_tag.len());
        assert_eq!(
            is_valid_sakuya(dcid, input),
            quinn.is_valid(dcid, input, header_len)
        );
    });
});
