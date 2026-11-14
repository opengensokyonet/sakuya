#!/usr/bin/env python3
"""Writes packet protection vectors for every AEAD from an independent
implementation (OpenSSL through the cryptography package).

RFC 9001 Appendix A has no vector for AES-256-GCM with SHA-384. Each line holds
aead, kdf, secret, next secret, packet number, Packet Number field offset,
unprotected header, payload and the protected packet.
"""
import hashlib
import hmac
import random
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


def expand(hash_name, secret, info, length):
    output, block, counter = b"", b"", 1
    while len(output) < length:
        block = hmac.new(secret, block + info + bytes([counter]), hash_name).digest()
        output += block
        counter += 1
    return output[:length]


def expand_label(hash_name, secret, label, length):
    full = b"tls13 " + label
    info = struct.pack(">H", length) + bytes([len(full)]) + full + bytes([0])
    return expand(hash_name, secret, info, length)


def mask(aead, hp, sample):
    if aead == "chacha20":
        cipher = Cipher(algorithms.ChaCha20(hp, sample), mode=None).encryptor()
        return cipher.update(bytes(5))
    cipher = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    return cipher.update(sample)[:5]


def seal(aead, key, nonce, payload, header):
    if aead == "chacha20":
        return ChaCha20Poly1305(key).encrypt(nonce, payload, header)
    return AESGCM(key).encrypt(nonce, payload, header)


SUITES = [
    ("aes128", "sha256", 16, 32),
    ("aes256", "sha384", 32, 48),
    ("chacha20", "sha256", 32, 32),
]


def line(rng, aead, kdf, key_len, secret_len):
    secret = rng.randbytes(secret_len)
    next_secret = expand_label(kdf, secret, b"quic ku", secret_len)
    key = expand_label(kdf, secret, b"quic key", key_len)
    iv = expand_label(kdf, secret, b"quic iv", 12)
    hp = expand_label(kdf, secret, b"quic hp", key_len)

    number = rng.getrandbits(rng.choice([8, 16, 24, 32, 48, 62]))
    field_len = rng.randint(1, 4)
    field = (number & ((1 << (8 * field_len)) - 1)).to_bytes(field_len, "big")
    payload = rng.randbytes(rng.randint(4 - field_len + 16, 64))
    if rng.random() < 0.5:
        first = 0x40 | rng.getrandbits(5) & 0x1c | (field_len - 1)
        dcid = rng.randbytes(rng.randint(0, 20))
        prefix = bytes([first]) + dcid
    else:
        first = 0xe0 | rng.getrandbits(2) << 2 | (field_len - 1)
        dcid = rng.randbytes(rng.randint(0, 20))
        scid = rng.randbytes(rng.randint(0, 20))
        length = field_len + len(payload) + 16
        prefix = (
            bytes([first])
            + (1).to_bytes(4, "big")
            + bytes([len(dcid)])
            + dcid
            + bytes([len(scid)])
            + scid
            + (0x4000 | length).to_bytes(2, "big")
        )
    header = prefix + field
    pn_offset = len(prefix)
    nonce = iv[:4] + (int.from_bytes(iv[4:], "big") ^ number).to_bytes(8, "big")
    sealed = seal(aead, key, nonce, payload, header)
    protected = bytearray(header + sealed)
    sample = bytes(protected[pn_offset + 4 : pn_offset + 20])
    bits = mask(aead, hp, sample)
    protected[0] ^= bits[0] & (0x0f if first & 0x80 else 0x1f)
    for index in range(field_len):
        protected[pn_offset + index] ^= bits[index + 1]
    return " ".join(
        [aead, kdf, secret.hex(), next_secret.hex(), str(number), str(pn_offset),
         header.hex(), payload.hex(), bytes(protected).hex()]
    )


def main():
    rng = random.Random(0x5a6b)
    with open(sys.argv[1], "w") as out:
        for suite in SUITES:
            for _ in range(int(sys.argv[2])):
                out.write(line(rng, *suite) + "\n")


if __name__ == "__main__":
    main()
