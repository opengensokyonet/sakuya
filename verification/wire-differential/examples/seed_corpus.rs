//! Writes seed corpora for the fuzz targets into the directory given as the
//! first argument, one subdirectory per target.
//!
//! The frames, parameters, headers and protection seeds come from the
//! proptest strategies. The handshake_messages seeds are the handshake
//! messages of RFC 8448 that the tests of `sakuya_tls` hold, read from
//! `crates/sakuya_tls/tests/common/rfc8448.rs` of this repository, each
//! message alone and each section's messages in a row, and a Finished and a
//! message_hash of each hash length.
use proptest::{
    strategy::{Strategy, ValueTree},
    test_runner::TestRunner,
};
use std::{
    env, fs,
    path::{Path, PathBuf},
};
use wire_differential::{frames, headers, parameters, protection};

/// The number of seeds of each target the strategies give.
const SEEDS: usize = 3000;

/// The handshake types `sakuya_tls` collects from a CRYPTO stream, and
/// end_of_early_data, which RFC 8448 holds and QUIC does not carry.
const HANDSHAKE_TYPES: [u8; 9] = [1, 2, 4, 5, 8, 11, 13, 15, 20];

fn write(directory: &Path, name: &str, bytes: &[u8]) {
    fs::create_dir_all(directory).unwrap();
    fs::write(directory.join(name), bytes).unwrap();
}

fn sample<S: Strategy>(strategy: &S, runner: &mut TestRunner) -> S::Value {
    strategy.new_tree(runner).unwrap().current()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// The hexadecimal constants of `rfc8448.rs` that hold one whole handshake
/// message, with the name of the module and of the constant.
fn handshake_messages(source: &str) -> Vec<(String, Vec<u8>)> {
    let mut section = String::new();
    let mut messages = Vec::new();
    let mut rest = source;
    while let Some(at) = rest.find("pub ") {
        rest = &rest[at + 4..];
        if let Some(module) = rest.strip_prefix("mod ") {
            section = module
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .next()
                .unwrap_or_default()
                .to_owned();
        } else if let Some(constant) = rest.strip_prefix("const ") {
            let name = constant.split(':').next().unwrap_or_default().trim();
            let Some(start) = constant.find('"') else {
                continue;
            };
            let value = &constant[start + 1..];
            let Some(end) = value.find('"') else { continue };
            let Some(bytes) = unhex(&value[..end]) else {
                continue;
            };
            let whole = bytes.len() >= 4
                && HANDSHAKE_TYPES.contains(&bytes[0])
                && 4 + u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]) as usize
                    == bytes.len();
            if whole {
                messages.push((format!("{section}_{}", name.to_lowercase()), bytes));
            }
        }
    }
    messages
}

fn main() {
    let root = PathBuf::from(env::args().nth(1).expect("the corpus directory"));
    let mut runner = TestRunner::deterministic();
    let payload = frames::generate::payload();
    let list = parameters::generate::parameters();
    let (single, coalesced) = (
        headers::generate::datagram(),
        headers::generate::coalesced(),
    );
    let initial = protection::generate::initial();
    for index in 0..SEEDS {
        let name = format!("seed-{index:05}");
        write(&root.join("frames"), &name, &sample(&payload, &mut runner));
        write(&root.join("parameters"), &name, &sample(&list, &mut runner));
        let (datagram, short_len) = if index % 2 == 0 {
            sample(&single, &mut runner)
        } else {
            sample(&coalesced, &mut runner)
        };
        let mut input = vec![short_len.get() as u8];
        input.extend(datagram);
        write(&root.join("headers"), &name, &input);
        // The layout the protection target cuts its input into.
        let packet = sample(&initial, &mut runner);
        let mut input = (packet.packet_number << 24).to_be_bytes().to_vec();
        input.extend([
            packet.dcid.len() as u8,
            packet.scid.len() as u8,
            packet.token.len() as u8,
            packet.reserved_bits,
        ]);
        for part in [&packet.dcid, &packet.scid, &packet.token, &packet.payload] {
            input.extend(part);
        }
        write(&root.join("protection"), &name, &input);
    }

    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/sakuya_tls/tests/common/rfc8448.rs");
    let messages = handshake_messages(&fs::read_to_string(source).unwrap());
    let directory = root.join("handshake_messages");
    let mut sections: Vec<&str> = Vec::new();
    for (name, bytes) in &messages {
        write(&directory, name, bytes);
        let section = name.split('_').next().unwrap_or_default();
        if !sections.contains(&section) {
            sections.push(section);
        }
    }
    for section in sections {
        let flight: Vec<u8> = messages
            .iter()
            .filter(|(name, _)| name.split('_').next() == Some(section))
            .flat_map(|(_, bytes)| bytes.iter().copied())
            .collect();
        write(&directory, &format!("{section}_all"), &flight);
    }
    for body_len in [32u8, 48] {
        for message_type in [20u8, 254] {
            let mut bytes = vec![message_type, 0, 0, body_len];
            bytes.extend(0..body_len);
            write(
                &directory,
                &format!("synthetic_{message_type}_{body_len}"),
                &bytes,
            );
        }
    }
    println!(
        "{SEEDS} seeds for each of frames, parameters, headers and protection; {} handshake messages",
        messages.len()
    );
}
