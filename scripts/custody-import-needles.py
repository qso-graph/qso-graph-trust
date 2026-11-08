# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

"""Independent, test-only PKCS#12 KDF/PBKDF2 oracle. No production crypto is imported.

Reads the failed-open password over stdin, corpus paths as arguments. Emits labelled hex needles
only over its pipe to the parent test, never the test log. This parser handles these fixed corpus
files, not operator input. Production's bounded reader is deliberately not reused.
"""

import base64
import hashlib
import hmac
import re
import pathlib
import sys


def fields(data):
    out = []
    while data:
        tag, length = data[:2]
        start = 2
        if length >= 128:
            count = length & 127
            length = int.from_bytes(data[2:2 + count], "big")
            start += count
        end = start + length
        assert end <= len(data)
        out.append((tag, data[start:end], data[:end]))
        data = data[end:]
    return out


def seq(data):
    tag, value, _ = fields(data)[0]
    assert tag == 0x30
    return fields(value)


def emit(label, value):
    print(label + "\t" + value.hex())


def key_needles(label, key):
    emit(label, key)
    # Partial and recoverable representations: internal hash words and HMAC pad buffers.
    emit(label + " fragment", key[:16])
    emit(label + " LE words", b"".join(key[i:i + 4][::-1] for i in range(0, len(key), 4)))
    for pad, name in [(0x36, " ipad"), (0x5c, " opad")]:
        emit(label + name, bytes(b ^ pad for b in key[:16]))


def kdf(name, password, salt, count, purpose, length):
    def expand(value):
        n = 64 * ((len(value) + 63) // 64)
        return (value * ((n + len(value) - 1) // len(value)))[:n] if n else b""

    state = expand(salt) + expand(password)
    out = b""
    while len(out) < length:
        digest = bytes([purpose]) * 64 + state
        for _ in range(count):
            digest = hashlib.new(name, digest).digest()
        out += digest
        b = int.from_bytes((digest * 64)[:64], "big") + 1
        state = b"".join(
            ((int.from_bytes(state[i:i + 64], "big") + b) % (1 << 512)).to_bytes(64, "big")
            for i in range(0, len(state), 64)
        )
    return out[:length]


def cipher(label, algorithm, password=b"qgt-test"):
    oid, params = seq(algorithm)
    assert oid[1].hex() == "2a864886f70d01050d"  # PBES2
    kdf_params, scheme = seq(params[2])
    kdf_oid, kdf_params = seq(kdf_params[2])
    assert kdf_oid[1].hex() == "2a864886f70d01050c"
    salt, count, *rest = seq(kdf_params[2])
    name = "sha1"
    if rest and rest[0][0] == 2:
        rest = rest[1:]
    if rest:
        prf = seq(rest[0][2])[0][1].hex()
        name = {"2a864886f70d0209": "sha256", "2a864886f70d0207": "sha1"}[prf]
    scheme_oid = seq(scheme[2])[0][1].hex()
    length = {"60864801650304012a": 32, "608648016503040102": 16, "2a864886f70d0307": 24}[scheme_oid]
    key_needles(label, hashlib.pbkdf2_hmac(name, password, salt[1], int.from_bytes(count[1], "big"), length))


pfx = seq(pathlib.Path(sys.argv[1]).read_bytes())
failed_password = sys.stdin.buffer.read()
for label, password in [("PKCS#12", b"qgt-test"), ("failed PKCS#12", failed_password)]:
    bmp = password.decode("utf-8").encode("utf-16be") + b"\0\0"
    emit(label + " BMP password", bmp)
    info, salt, *count = seq(pfx[2][2])
    digest_info = seq(info[2])
    oid = seq(digest_info[0][2])[0][1].hex()
    name = {"2b0e03021a": "sha1", "608648016503040201": "sha256"}[oid]
    count = int.from_bytes(count[0][1], "big") if count else 1
    key = kdf(name, bmp, salt[1], count, 3, hashlib.new(name).digest_size)
    # Prove the independently derived MAC key against the corpus MAC itself, not its own control.
    auth = fields(seq(pfx[1][2])[1][1])[0][1]
    matches = hmac.compare_digest(hmac.digest(key, auth, name), digest_info[1][1])
    assert matches == (label == "PKCS#12")
    key_needles(label + " MAC key", key)

safe = seq(pfx[1][2])
auth = fields(safe[1][1])[0][1]
for content in seq(auth):
    oid, explicit = seq(content[2])
    if oid[1].hex() == "2a864886f70d010706":  # encryptedData certificates
        encrypted = seq(explicit[1])
        encrypted_info = seq(encrypted[1][2])
        cipher("PKCS#12 certificate AES key", encrypted_info[1][2])
    else:
        assert oid[1].hex() == "2a864886f70d010701"
        for bag in seq(fields(explicit[1])[0][1]):
            bag = seq(bag[2])
            assert bag[0][1].hex() == "2a864886f70d010c0a0102"  # shroudedKeyBag
            envelope = bag[1][1]
            cipher("PKCS#12 private AES key", seq(envelope)[0][2])
            # The Rust test uses its independent RustCrypto decoder for exact plaintext bytes.
            emit("envelope", envelope)

# Also search the original protected TQSL key-unlock derivation, independently of the PFX.
key_file = pathlib.Path(sys.argv[2]).read_bytes()
pem = re.search(b"-----BEGIN ENCRYPTED PRIVATE KEY-----.*?-----END ENCRYPTED PRIVATE KEY-----", key_file, re.S)
if pem:
    envelope = base64.b64decode(b"".join(pem[0].splitlines()[1:-1]))
    cipher("TQSL unlock key", seq(envelope)[0][2], pathlib.Path(sys.argv[3]).read_bytes())
