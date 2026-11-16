//! Ed25519 test certificates, built in memory: a self-signed root, and a
//! leaf for a DNS name issued by it, valid from 2025 to 2049.
//!
//! The keys come from a one-byte seed, so a test can make the same key
//! twice, or a root that is not the one a verifier trusts.

use nitori_crypto::{SignatureScheme, SigningKey as _};
use nitori_crypto_aws_lc::Ed25519SigningKey;

/// The Ed25519 key with the 32-byte seed `[seed; 32]`.
pub fn key(seed: u8) -> Ed25519SigningKey {
    let mut pkcs8 = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    pkcs8.extend([seed; 32]);
    // invariant: the document above is a PKCS#8 Ed25519 private key for
    // any seed
    Ed25519SigningKey::from_pkcs8(&pkcs8).expect("an ed25519 pkcs#8 document")
}

/// A root named "Test Root", self-signed by `key(seed)`, as DER.
pub fn root(seed: u8) -> Vec<u8> {
    let root = key(seed);
    let basic_constraints = extension(&[0x55, 0x1d, 0x13], true, &seq(&[&tlv(0x01, &[0xff])]));
    certificate(
        seed,
        "Test Root",
        "Test Root",
        root.public_key(),
        &[basic_constraints],
        &root,
    )
}

/// The serverAuth certificate of `key(seed)` for `dns_name`, issued by
/// `root(root_seed)`, as DER.
pub fn leaf(seed: u8, root_seed: u8, dns_name: &str) -> Vec<u8> {
    let alternative_names = extension(
        &[0x55, 0x1d, 0x11],
        false,
        &seq(&[&tlv(0x82, dns_name.as_bytes())]),
    );
    let server_auth = extension(
        &[0x55, 0x1d, 0x25],
        false,
        &seq(&[&tlv(
            0x06,
            &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01],
        )]),
    );
    certificate(
        seed,
        "Test Root",
        dns_name,
        key(seed).public_key(),
        &[alternative_names, server_auth],
        &key(root_seed),
    )
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.extend([0x81, len as u8]);
    } else {
        // invariant: the certificates here are far below 64 KiB
        let len = u16::try_from(len).expect("a test certificate under 64 KiB");
        out.push(0x82);
        out.extend(len.to_be_bytes());
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn name(common_name: &str) -> Vec<u8> {
    let attribute = seq(&[
        &tlv(0x06, &[0x55, 0x04, 0x03]),
        &tlv(0x0c, common_name.as_bytes()),
    ]);
    seq(&[&tlv(0x31, &attribute)])
}

fn ed25519() -> Vec<u8> {
    seq(&[&tlv(0x06, &[0x2b, 0x65, 0x70])])
}

fn bits(bytes: &[u8]) -> Vec<u8> {
    tlv(0x03, &[&[0], bytes].concat())
}

fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let critical = if critical {
        tlv(0x01, &[0xff])
    } else {
        Vec::new()
    };
    seq(&[&tlv(0x06, oid), &critical, &tlv(0x04, value)])
}

fn certificate(
    serial: u8,
    issuer: &str,
    subject: &str,
    public_key: &[u8],
    extensions: &[Vec<u8>],
    signer: &Ed25519SigningKey,
) -> Vec<u8> {
    let extensions: Vec<&[u8]> = extensions.iter().map(Vec::as_slice).collect();
    let validity = seq(&[&tlv(0x17, b"250101000000Z"), &tlv(0x17, b"491231235959Z")]);
    let tbs = seq(&[
        &tlv(0xa0, &tlv(0x02, &[2])),
        &tlv(0x02, &[serial]),
        &ed25519(),
        &name(issuer),
        &validity,
        &name(subject),
        &seq(&[&ed25519(), &bits(public_key)]),
        &tlv(0xa3, &seq(&extensions)),
    ]);
    // invariant: an Ed25519 key signs with ED25519, and completes at once
    let signature = signer
        .sign(SignatureScheme::ED25519, &tbs)
        .into_inner()
        .expect("an ed25519 key signs with ed25519");
    seq(&[&tbs, &ed25519(), &bits(signature.as_bytes())])
}
