//! The packet protection examples of RFC 9001 Appendix A, run through the
//! `ring` backend.

#![cfg(feature = "ring")]

use std::cell::RefCell;
use std::rc::Rc;

use sakuya_packet_protection::backend::ring::{
    RingAeadKey, RingBackend, RingHeaderProtectionCipher,
};
use sakuya_packet_protection::backend::{
    AEAD_NONCE_LEN, AEAD_TAG_LEN, AeadAlgorithm, AeadInputTooLong, AeadKey, AuthenticationFailed,
    CryptoBackend, ExpandLabelError, ExpandOutputTooLong, HeaderProtectionCipher, KdfAlgorithm,
    KeyLengthMismatch, MAX_HASH_LEN,
};
use sakuya_packet_protection::header_protection::{HeaderProtectionError, HeaderProtectionKey};
use sakuya_packet_protection::initial::{INITIAL_AEAD, INITIAL_SALT, InitialSecrets};
use sakuya_packet_protection::packet_key::{OpenPacketError, PacketKey, SealPacketError};
use sakuya_packet_protection::packet_number::{PacketNumberLength, TruncatedPacketNumber};
use sakuya_packet_protection::retry::{
    VerifyRetryIntegrityError, compute_retry_integrity_tag, verify_retry_integrity_tag,
};
use sakuya_packet_protection::secret::TrafficSecret;
use sakuya_wire::connection_id::ConnectionId;
use sakuya_wire::packet_number::PacketNumber;

fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    assert!(digits.len().is_multiple_of(2), "odd number of hex digits");
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn cid(text: &str) -> ConnectionId {
    ConnectionId::new(&hex(text)).unwrap()
}

fn pn(value: u64) -> PacketNumber {
    PacketNumber::new(value).unwrap()
}

/// What a [`Recording`] backend saw.
#[derive(Default)]
struct Log {
    expand_infos: Vec<Vec<u8>>,
    aead_keys: Vec<Vec<u8>>,
    header_protection_keys: Vec<Vec<u8>>,
    nonces: Vec<[u8; AEAD_NONCE_LEN]>,
}

/// The `ring` backend, recording the inputs that derivation produces.
#[derive(Default)]
struct Recording {
    log: Rc<RefCell<Log>>,
}

struct RecordingAeadKey {
    inner: RingAeadKey,
    log: Rc<RefCell<Log>>,
}

impl CryptoBackend for Recording {
    type AeadKey = RecordingAeadKey;
    type HeaderProtectionCipher = RingHeaderProtectionCipher;

    fn hkdf_extract(
        &self,
        kdf: KdfAlgorithm,
        salt: &[u8],
        ikm: &[u8],
        prk: &mut [u8; MAX_HASH_LEN],
    ) {
        RingBackend.hkdf_extract(kdf, salt, ikm, prk);
    }

    fn hkdf_expand(
        &self,
        kdf: KdfAlgorithm,
        prk: &[u8],
        info: &[&[u8]],
        output: &mut [u8],
    ) -> Result<(), ExpandOutputTooLong> {
        self.log.borrow_mut().expand_infos.push(info.concat());
        RingBackend.hkdf_expand(kdf, prk, info, output)
    }

    fn aead_key(
        &self,
        aead: AeadAlgorithm,
        key: &[u8],
    ) -> Result<RecordingAeadKey, KeyLengthMismatch> {
        self.log.borrow_mut().aead_keys.push(key.to_vec());
        Ok(RecordingAeadKey {
            inner: RingBackend.aead_key(aead, key)?,
            log: Rc::clone(&self.log),
        })
    }

    fn header_protection_cipher(
        &self,
        aead: AeadAlgorithm,
        key: &[u8],
    ) -> Result<RingHeaderProtectionCipher, KeyLengthMismatch> {
        self.log
            .borrow_mut()
            .header_protection_keys
            .push(key.to_vec());
        RingBackend.header_protection_cipher(aead, key)
    }
}

impl AeadKey for RecordingAeadKey {
    fn seal_in_place(
        &self,
        nonce: &[u8; AEAD_NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8; AEAD_TAG_LEN],
    ) -> Result<(), AeadInputTooLong> {
        self.log.borrow_mut().nonces.push(*nonce);
        self.inner.seal_in_place(nonce, aad, in_out, tag)
    }

    fn open_in_place(
        &self,
        nonce: &[u8; AEAD_NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> Result<(), AuthenticationFailed> {
        self.log.borrow_mut().nonces.push(*nonce);
        self.inner.open_in_place(nonce, aad, in_out, tag)
    }
}

/// The key, IV and header protection key derived from `secret`, as the
/// backend received them.
fn derived_material(aead: AeadAlgorithm, secret: &TrafficSecret) -> (Vec<u8>, [u8; 12], Vec<u8>) {
    let backend = Recording::default();
    let key = PacketKey::derive(&backend, aead, secret);
    HeaderProtectionKey::derive(&backend, aead, secret);
    // Packet number zero leaves the IV as the nonce.
    let mut packet = [0u8; 1 + AEAD_TAG_LEN];
    key.seal(PacketNumber::ZERO, &mut packet, 1).unwrap();
    let log = backend.log.borrow();
    (
        log.aead_keys[0].clone(),
        log.nonces[0],
        log.header_protection_keys[0].clone(),
    )
}

const CLIENT_DCID: &str = "8394c8f03e515708";

// RFC 9001 Appendix A.1.

#[test]
fn a1_initial_secret() {
    let mut initial_secret = [0; MAX_HASH_LEN];
    RingBackend.hkdf_extract(
        KdfAlgorithm::HkdfSha256,
        &INITIAL_SALT,
        &hex(CLIENT_DCID),
        &mut initial_secret,
    );
    assert_eq!(initial_secret[32..], [0; 16]);
    assert_eq!(
        initial_secret[..32],
        hex("7db5df06e7a69e432496adedb0085192 3595221596ae2ae9fb8115c1e9ed0a44")
    );
}

#[test]
fn a1_client_and_server_initial_secrets() {
    let backend = Recording::default();
    let secrets = InitialSecrets::derive(&backend, &cid(CLIENT_DCID));
    assert_eq!(secrets.client.kdf(), KdfAlgorithm::HkdfSha256);
    assert_eq!(
        secrets.client.as_bytes(),
        hex("c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea")
    );
    assert_eq!(
        secrets.server.as_bytes(),
        hex("3c199828fd139efd216c155ad844cc81 fb82fa8d7446fa7d78be803acdda951b")
    );
    let log = backend.log.borrow();
    assert_eq!(
        log.expand_infos,
        [
            hex("00200f746c73313320636c69656e7420696e00"),
            hex("00200f746c7331332073657276657220696e00"),
        ]
    );
}

#[test]
fn a1_packet_protection_labels() {
    let backend = Recording::default();
    let secrets = InitialSecrets::derive(&RingBackend, &cid(CLIENT_DCID));
    PacketKey::derive(&backend, INITIAL_AEAD, &secrets.client);
    HeaderProtectionKey::derive(&backend, INITIAL_AEAD, &secrets.client);
    let log = backend.log.borrow();
    assert_eq!(
        log.expand_infos,
        [
            hex("00100e746c7331332071756963206b657900"),
            hex("000c0d746c733133207175696320697600"),
            hex("00100d746c733133207175696320687000"),
        ]
    );
}

#[test]
fn a1_client_keys() {
    let secrets = InitialSecrets::derive(&RingBackend, &cid(CLIENT_DCID));
    let (key, iv, hp) = derived_material(INITIAL_AEAD, &secrets.client);
    assert_eq!(key, hex("1f369613dd76d5467730efcbe3b1a22d"));
    assert_eq!(iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
    assert_eq!(hp, hex("9f50449e04a0e810283a1e9933adedd2"));
}

#[test]
fn a1_server_keys() {
    let secrets = InitialSecrets::derive(&RingBackend, &cid(CLIENT_DCID));
    let (key, iv, hp) = derived_material(INITIAL_AEAD, &secrets.server);
    assert_eq!(key, hex("cf3a5331653c364c88f0f379b6067e37"));
    assert_eq!(iv.to_vec(), hex("0ac1493ca1905853b0bba03e"));
    assert_eq!(hp, hex("c206b8d9b9f0f37644430b490eeaa314"));
}

// RFC 9001 Appendix A.2.

const CLIENT_CRYPTO_FRAME: &str = "
    060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
    04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
    616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
    04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
    baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
    0d0010000e0403050306030203080408 050806002d00020101001c0002400100
    3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
    75300901100f088394c8f03e51570806 048000ffff";

const CLIENT_HEADER: &str = "c300000001088394c8f03e5157080000449e00000002";

const CLIENT_PACKET: &str = "
    c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
    d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
    1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
    8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
    30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
    457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
    4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
    4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
    485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
    059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
    7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
    9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
    be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
    68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
    c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
    f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
    291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
    25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
    14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
    ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
    e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
    c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
    203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
    cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
    fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
    a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
    90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
    162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
    40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
    6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
    8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
    be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
    54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
    760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
    f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
    056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
    7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
    e221af44860018ab0856972e194cd934";

/// Offset of the Packet Number field in both Initial examples.
const INITIAL_PN_OFFSET: usize = 18;

fn client_payload() -> Vec<u8> {
    let mut payload = hex(CLIENT_CRYPTO_FRAME);
    payload.resize(1162, 0);
    payload
}

fn client_keys() -> (PacketKey<RingBackend>, HeaderProtectionKey<RingBackend>) {
    let secrets = InitialSecrets::derive(&RingBackend, &cid(CLIENT_DCID));
    (
        PacketKey::derive(&RingBackend, INITIAL_AEAD, &secrets.client),
        HeaderProtectionKey::derive(&RingBackend, INITIAL_AEAD, &secrets.client),
    )
}

#[test]
fn a2_client_initial_mask() {
    let cipher = RingBackend
        .header_protection_cipher(INITIAL_AEAD, &hex("9f50449e04a0e810283a1e9933adedd2"))
        .unwrap();
    let sample: [u8; 16] = hex("d1b1c98dd7689fb8ec11d242b123dc9b").try_into().unwrap();
    assert_eq!(cipher.mask(&sample).to_vec(), hex("437b9aec36"));
}

#[test]
fn a2_client_initial_protect() {
    let (key, hp) = client_keys();
    let header = hex(CLIENT_HEADER);
    let mut packet = header.clone();
    packet.extend(client_payload());
    packet.extend([0; AEAD_TAG_LEN]);
    assert_eq!(packet.len(), 1200);

    key.seal(pn(2), &mut packet, header.len()).unwrap();
    hp.apply(&mut packet, INITIAL_PN_OFFSET).unwrap();
    assert_eq!(packet, hex(CLIENT_PACKET));
}

#[test]
fn a2_client_initial_unprotect() {
    let (key, hp) = client_keys();
    let mut packet = hex(CLIENT_PACKET);

    let truncated = hp.remove(&mut packet, INITIAL_PN_OFFSET).unwrap();
    assert_eq!(truncated.encoded_len(), PacketNumberLength::Four);
    assert_eq!(truncated.as_bytes(), [0, 0, 0, 2]);
    let header_len = INITIAL_PN_OFFSET + truncated.encoded_len().get();
    assert_eq!(packet[..header_len], hex(CLIENT_HEADER));

    let packet_number = truncated.decode(None);
    assert_eq!(packet_number, pn(2));
    let payload = key.open(packet_number, &mut packet, header_len).unwrap();
    assert_eq!(payload, client_payload());
}

// RFC 9001 Appendix A.3.

const SERVER_PAYLOAD: &str = "
    02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739
    88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94
    0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00
    020304";

const SERVER_HEADER: &str = "c1000000010008f067a5502a4262b50040750001";

const SERVER_PACKET: &str = "
    cf000000010008f067a5502a4262b500 4075c0d95a482cd0991cd25b0aac406a
    5816b6394100f37a1c69797554780bb3 8cc5a99f5ede4cf73c3ec2493a1839b3
    dbcba3f6ea46c5b7684df3548e7ddeb9 c3bf9c73cc3f3bded74b562bfb19fb84
    022f8ef4cdd93795d77d06edbb7aaf2f 58891850abbdca3d20398c276456cbc4
    2158407dd074ee";

fn server_keys() -> (PacketKey<RingBackend>, HeaderProtectionKey<RingBackend>) {
    let secrets = InitialSecrets::derive(&RingBackend, &cid(CLIENT_DCID));
    (
        PacketKey::derive(&RingBackend, INITIAL_AEAD, &secrets.server),
        HeaderProtectionKey::derive(&RingBackend, INITIAL_AEAD, &secrets.server),
    )
}

#[test]
fn a3_server_initial_mask() {
    let cipher = RingBackend
        .header_protection_cipher(INITIAL_AEAD, &hex("c206b8d9b9f0f37644430b490eeaa314"))
        .unwrap();
    let sample: [u8; 16] = hex("2cd0991cd25b0aac406a5816b6394100").try_into().unwrap();
    assert_eq!(cipher.mask(&sample).to_vec(), hex("2ec0d8356a"));
}

#[test]
fn a3_server_initial_protect() {
    let (key, hp) = server_keys();
    let header = hex(SERVER_HEADER);
    let mut packet = header.clone();
    packet.extend(hex(SERVER_PAYLOAD));
    packet.extend([0; AEAD_TAG_LEN]);

    key.seal(pn(1), &mut packet, header.len()).unwrap();
    hp.apply(&mut packet, INITIAL_PN_OFFSET).unwrap();
    assert_eq!(packet, hex(SERVER_PACKET));
}

#[test]
fn a3_server_initial_unprotect() {
    let (key, hp) = server_keys();
    let mut packet = hex(SERVER_PACKET);

    let truncated = hp.remove(&mut packet, INITIAL_PN_OFFSET).unwrap();
    assert_eq!(truncated.encoded_len(), PacketNumberLength::Two);
    assert_eq!(truncated.value(), 1);
    let header_len = INITIAL_PN_OFFSET + truncated.encoded_len().get();
    assert_eq!(packet[..header_len], hex(SERVER_HEADER));

    let packet_number = truncated.decode(None);
    assert_eq!(packet_number, pn(1));
    let payload = key.open(packet_number, &mut packet, header_len).unwrap();
    assert_eq!(payload, hex(SERVER_PAYLOAD));
}

// RFC 9001 Appendix A.4.

const RETRY_PACKET: &str = "
    ff000000010008f067a5502a4262b574 6f6b656e04a265ba2eff4d829058fb3f
    0f2496ba";

#[test]
fn a4_retry_tag_compute() {
    let packet = hex(RETRY_PACKET);
    let (retry_without_tag, tag) = packet.split_at(packet.len() - AEAD_TAG_LEN);
    let computed = compute_retry_integrity_tag(&RingBackend, &cid(CLIENT_DCID), retry_without_tag);
    assert_eq!(computed, tag);
}

#[test]
fn a4_retry_tag_verify() {
    let packet = hex(RETRY_PACKET);
    verify_retry_integrity_tag(&RingBackend, &cid(CLIENT_DCID), &packet).unwrap();

    let mut corrupted = packet.clone();
    corrupted[10] ^= 0x01;
    assert!(matches!(
        verify_retry_integrity_tag(&RingBackend, &cid(CLIENT_DCID), &corrupted),
        Err(VerifyRetryIntegrityError::Authentication { .. })
    ));

    let other_odcid = cid("8394c8f03e515709");
    assert!(matches!(
        verify_retry_integrity_tag(&RingBackend, &other_odcid, &packet),
        Err(VerifyRetryIntegrityError::Authentication { .. })
    ));
}

#[test]
fn retry_rejects_malformed_inputs() {
    let packet = hex(RETRY_PACKET);
    assert!(matches!(
        verify_retry_integrity_tag(&RingBackend, &cid(CLIENT_DCID), &packet[..15]),
        Err(VerifyRetryIntegrityError::PacketTooShort { packet_len: 15 })
    ));
    assert!(matches!(
        verify_retry_integrity_tag(&RingBackend, &cid(CLIENT_DCID), &[]),
        Err(VerifyRetryIntegrityError::PacketTooShort { packet_len: 0 })
    ));
    // The shortest packet holds only a tag; it does not authenticate.
    assert!(matches!(
        verify_retry_integrity_tag(&RingBackend, &cid(CLIENT_DCID), &packet[..16]),
        Err(VerifyRetryIntegrityError::Authentication { .. })
    ));
}

// RFC 9001 Appendix A.5.

const CHACHA_SECRET: &str = "9ac312a7f877468ebe69422748ad00a1 5443f18203a07d6060f688f30f21632b";
const CHACHA_PN: u64 = 654_360_564;
const CHACHA_HEADER: &str = "4200bff4";
const CHACHA_PACKET: &str = "4cfe4189655e5cd55c41f69080575d7999c25a5bfb";

fn chacha_secret() -> TrafficSecret {
    TrafficSecret::new(KdfAlgorithm::HkdfSha256, &hex(CHACHA_SECRET)).unwrap()
}

#[test]
fn a5_chacha20_keys() {
    let (key, iv, hp) = derived_material(AeadAlgorithm::ChaCha20Poly1305, &chacha_secret());
    assert_eq!(
        key,
        hex("c6d98ff3441c3fe1b2182094f69caa2e d4b716b65488960a7a984979fb23e1c8")
    );
    assert_eq!(iv.to_vec(), hex("e0459b3474bdd0e44a41c144"));
    assert_eq!(
        hp,
        hex("25a282b9e82f06f21f488917a4fc8f1b 73573685608597d0efcb076b0ab7a7a4")
    );
}

#[test]
fn a5_key_update_secret() {
    let backend = Recording::default();
    let next = chacha_secret().next(&backend);
    assert_eq!(next.kdf(), KdfAlgorithm::HkdfSha256);
    assert_eq!(
        next.as_bytes(),
        hex("1223504755036d556342ee9361d25342 1a826c9ecdf3c7148684b36b714881f9")
    );
    // HkdfLabel for "quic ku" with a 32-byte output.
    assert_eq!(
        backend.log.borrow().expand_infos,
        [[&[0x00, 0x20, 0x0d][..], b"tls13 quic ku", &[0x00]].concat()]
    );
}

#[test]
fn a5_chacha20_short_header_protect() {
    let secret = chacha_secret();
    let backend = Recording::default();
    let key = PacketKey::derive(&backend, AeadAlgorithm::ChaCha20Poly1305, &secret);
    let hp = HeaderProtectionKey::derive(&backend, AeadAlgorithm::ChaCha20Poly1305, &secret);
    let truncated = TruncatedPacketNumber::new(0x00bff4, PacketNumberLength::Three).unwrap();
    assert_eq!(truncated.as_bytes(), [0x00, 0xbf, 0xf4]);

    let header = hex(CHACHA_HEADER);
    let mut packet = header.clone();
    packet.push(0x01);
    packet.extend([0; AEAD_TAG_LEN]);
    key.seal(pn(CHACHA_PN), &mut packet, header.len()).unwrap();
    assert_eq!(
        backend.log.borrow().nonces,
        [<[u8; 12]>::try_from(hex("e0459b3474bdd0e46d417eb0")).unwrap()]
    );
    assert_eq!(
        packet[header.len()..],
        hex("655e5cd55c41f69080575d7999c25a5bfb")
    );

    hp.apply(&mut packet, 1).unwrap();
    assert_eq!(packet, hex(CHACHA_PACKET));
}

#[test]
fn a5_chacha20_short_header_unprotect() {
    let secret = chacha_secret();
    let key = PacketKey::derive(&RingBackend, AeadAlgorithm::ChaCha20Poly1305, &secret);
    let hp = HeaderProtectionKey::derive(&RingBackend, AeadAlgorithm::ChaCha20Poly1305, &secret);
    let mut packet = hex(CHACHA_PACKET);

    let truncated = hp.remove(&mut packet, 1).unwrap();
    assert_eq!(truncated.encoded_len(), PacketNumberLength::Three);
    assert_eq!(truncated.value(), 0x00bff4);
    assert_eq!(packet[..4], hex(CHACHA_HEADER));

    let packet_number = truncated.decode(Some(pn(CHACHA_PN - 1)));
    assert_eq!(packet_number, pn(CHACHA_PN));
    let payload = key.open(packet_number, &mut packet, 4).unwrap();
    assert_eq!(payload, [0x01]);
}

#[test]
fn key_update_keeps_header_protection_key() {
    let secret = chacha_secret();
    let aead = AeadAlgorithm::ChaCha20Poly1305;
    let next = secret.next(&RingBackend);
    let old_key = PacketKey::derive(&RingBackend, aead, &secret);
    let new_key = PacketKey::derive(&RingBackend, aead, &next);
    let hp = HeaderProtectionKey::derive(&RingBackend, aead, &secret);

    // The next generation's key and IV come from the next secret.
    let (key_bytes, iv, _) = derived_material(aead, &next);
    let mut expected_key = [0; 32];
    RingBackend
        .hkdf_expand_label(
            KdfAlgorithm::HkdfSha256,
            next.as_bytes(),
            b"quic key",
            &[],
            &mut expected_key,
        )
        .unwrap();
    let mut expected_iv = [0; 12];
    RingBackend
        .hkdf_expand_label(
            KdfAlgorithm::HkdfSha256,
            next.as_bytes(),
            b"quic iv",
            &[],
            &mut expected_iv,
        )
        .unwrap();
    assert_eq!(key_bytes, expected_key);
    assert_eq!(iv, expected_iv);

    // A packet sealed with the new key is unmasked with the unchanged header
    // protection key and opens only with the new key.
    let header = hex("4600bff5");
    let mut sealed = header.clone();
    sealed.extend([0x01, 0x00, 0x00]);
    sealed.extend([0; AEAD_TAG_LEN]);
    new_key
        .seal(pn(CHACHA_PN + 1), &mut sealed, header.len())
        .unwrap();
    hp.apply(&mut sealed, 1).unwrap();

    let mut packet = sealed.clone();
    let truncated = hp.remove(&mut packet, 1).unwrap();
    assert_eq!(packet[..4], header);
    let packet_number = truncated.decode(Some(pn(CHACHA_PN)));
    assert_eq!(packet_number, pn(CHACHA_PN + 1));
    assert!(matches!(
        old_key.open(packet_number, &mut packet, 4),
        Err(OpenPacketError::Authentication { .. })
    ));

    let mut packet = sealed.clone();
    hp.remove(&mut packet, 1).unwrap();
    assert_eq!(
        new_key.open(packet_number, &mut packet, 4).unwrap(),
        [0x01, 0x00, 0x00]
    );
}

// Behaviour on failure.

#[test]
fn failed_open_overwrites_payload() {
    let (key, hp) = client_keys();
    let received = hex(CLIENT_PACKET);
    let other_secrets = InitialSecrets::derive(&RingBackend, &cid("0001020304050607"));
    let wrong_key = PacketKey::derive(&RingBackend, INITIAL_AEAD, &other_secrets.client);

    let mut packet = received.clone();
    let truncated = hp.remove(&mut packet, INITIAL_PN_OFFSET).unwrap();
    let header_len = INITIAL_PN_OFFSET + truncated.encoded_len().get();
    let ciphertext_end = packet.len() - AEAD_TAG_LEN;
    assert!(matches!(
        wrong_key.open(pn(2), &mut packet, header_len),
        Err(OpenPacketError::Authentication { .. })
    ));
    // The ciphertext is gone: `ring` zeroed the region it decrypted. The
    // header and the tag are untouched.
    assert_ne!(
        packet[header_len..ciphertext_end],
        received[header_len..ciphertext_end]
    );
    assert!(
        packet[header_len..ciphertext_end]
            .iter()
            .all(|&byte| byte == 0)
    );
    assert_eq!(packet[..header_len], hex(CLIENT_HEADER));
    assert_eq!(packet[ciphertext_end..], received[ciphertext_end..]);
    // Opening the same buffer with the right key now fails too.
    assert!(key.open(pn(2), &mut packet, header_len).is_err());

    // Rebuilt from the received datagram, the packet opens with the right key.
    let mut packet = received.clone();
    hp.remove(&mut packet, INITIAL_PN_OFFSET).unwrap();
    assert_eq!(
        key.open(pn(2), &mut packet, header_len).unwrap(),
        client_payload()
    );
}

#[test]
fn failed_length_checks_leave_buffer_unchanged() {
    let (key, hp) = client_keys();
    let received = hex(CLIENT_PACKET);

    let mut short = received[..INITIAL_PN_OFFSET + 4 + 15].to_vec();
    assert!(matches!(
        hp.remove(&mut short, INITIAL_PN_OFFSET),
        Err(HeaderProtectionError::SampleOutOfBounds {
            pn_offset: INITIAL_PN_OFFSET,
            packet_len: 37
        })
    ));
    assert!(matches!(
        hp.apply(&mut short, INITIAL_PN_OFFSET),
        Err(HeaderProtectionError::SampleOutOfBounds { .. })
    ));
    assert_eq!(short, received[..37]);

    let mut packet = received.clone();
    assert!(matches!(
        hp.remove(&mut packet, 0),
        Err(HeaderProtectionError::PacketNumberOffsetZero)
    ));
    assert!(matches!(
        hp.remove(&mut packet, usize::MAX),
        Err(HeaderProtectionError::SampleOutOfBounds { .. })
    ));

    let mut tiny = received[..30].to_vec();
    assert!(matches!(
        key.open(pn(2), &mut tiny, 22),
        Err(OpenPacketError::PacketTooShort { .. })
    ));
    assert!(matches!(
        key.seal(pn(2), &mut tiny, 22),
        Err(SealPacketError::PacketTooShort { source })
            if (source.packet_len, source.header_len) == (30, 22)
    ));
    let mut tag_only = received[..16].to_vec();
    assert!(matches!(
        key.seal(pn(2), &mut tag_only, 1),
        Err(SealPacketError::PacketTooShort { .. })
    ));
    assert!(key.seal(pn(2), &mut tag_only, 0).is_ok());
    assert_eq!(tiny, received[..30]);
    assert_eq!(packet, received);
}

// Derivation lengths.

#[test]
fn derivation_lengths_follow_the_cipher_suite() {
    let suites = [
        (AeadAlgorithm::Aes128Gcm, KdfAlgorithm::HkdfSha256, 16, 32),
        (AeadAlgorithm::Aes256Gcm, KdfAlgorithm::HkdfSha384, 32, 48),
        (
            AeadAlgorithm::ChaCha20Poly1305,
            KdfAlgorithm::HkdfSha256,
            32,
            32,
        ),
    ];
    for (aead, kdf, key_len, secret_len) in suites {
        assert_eq!(aead.key_len(), key_len);
        assert_eq!(kdf.hash_len(), secret_len);
        let secret = TrafficSecret::new(kdf, &vec![0x5a; secret_len]).unwrap();
        assert_eq!(secret.as_bytes().len(), secret_len);
        assert_eq!(secret.next(&RingBackend).as_bytes().len(), secret_len);

        let (key, iv, hp) = derived_material(aead, &secret);
        assert_eq!(key.len(), key_len, "{aead:?} key");
        assert_eq!(iv.len(), AEAD_NONCE_LEN, "{aead:?} iv");
        assert_eq!(hp.len(), key_len, "{aead:?} header protection key");

        // The derived keys protect a packet end to end.
        let packet_key = PacketKey::derive(&RingBackend, aead, &secret);
        let hp_key = HeaderProtectionKey::derive(&RingBackend, aead, &secret);
        let mut packet = vec![0x40, 0xaa, 0x07, 0x01, 0x00, 0x00, 0x00];
        packet.extend([0; AEAD_TAG_LEN]);
        let original = packet.clone();
        packet_key.seal(pn(7), &mut packet, 3).unwrap();
        hp_key.apply(&mut packet, 2).unwrap();
        let truncated = hp_key.remove(&mut packet, 2).unwrap();
        assert_eq!(truncated.decode(Some(pn(6))), pn(7));
        assert_eq!(
            packet_key.open(pn(7), &mut packet, 3).unwrap(),
            &original[3..7]
        );
    }
}

#[test]
fn traffic_secret_rejects_wrong_length() {
    let error = TrafficSecret::new(KdfAlgorithm::HkdfSha384, &[0; 32]).unwrap_err();
    assert_eq!((error.expected, error.actual), (48, 32));
}

#[test]
fn expand_label_rejects_oversized_inputs() {
    let secret = [0; 32];
    let kdf = KdfAlgorithm::HkdfSha256;
    let mut output = [0; 16];
    assert!(matches!(
        RingBackend.hkdf_expand_label(kdf, &secret, &[b'x'; 250], &[], &mut output),
        Err(ExpandLabelError::LabelTooLong { label_len: 256 })
    ));
    assert!(matches!(
        RingBackend.hkdf_expand_label(kdf, &secret, b"quic key", &[0; 256], &mut output),
        Err(ExpandLabelError::ContextTooLong { context_len: 256 })
    ));
    let mut long_output = vec![0; 255 * 32 + 1];
    assert!(matches!(
        RingBackend.hkdf_expand_label(kdf, &secret, b"quic key", &[], &mut long_output),
        Err(ExpandLabelError::OutputTooLong {
            source: ExpandOutputTooLong {
                output_len: 8161,
                max_output_len: 8160
            }
        })
    ));
    assert!(long_output.iter().all(|&byte| byte == 0));
    RingBackend
        .hkdf_expand_label(
            kdf,
            &secret,
            &[b'x'; 249],
            &[0; 255],
            &mut long_output[..8160],
        )
        .unwrap();
}

#[test]
fn backend_rejects_wrong_lengths() {
    let error = RingBackend
        .aead_key(AeadAlgorithm::Aes128Gcm, &[0; 32])
        .unwrap_err();
    assert_eq!((error.expected, error.actual), (16, 32));
    let error = RingBackend
        .aead_key(AeadAlgorithm::ChaCha20Poly1305, &[0; 16])
        .unwrap_err();
    assert_eq!((error.expected, error.actual), (32, 16));
    let error = RingBackend
        .header_protection_cipher(AeadAlgorithm::Aes256Gcm, &[0; 16])
        .unwrap_err();
    assert_eq!((error.expected, error.actual), (32, 16));

    let mut output = vec![0; 255 * 48 + 1];
    let error = RingBackend
        .hkdf_expand(KdfAlgorithm::HkdfSha384, &[0; 48], &[b"info"], &mut output)
        .unwrap_err();
    assert_eq!((error.output_len, error.max_output_len), (12241, 12240));
    assert!(output.iter().all(|&byte| byte == 0));
    RingBackend
        .hkdf_expand(
            KdfAlgorithm::HkdfSha384,
            &[0; 48],
            &[b"info"],
            &mut output[..12240],
        )
        .unwrap();
}
