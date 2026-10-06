#!/usr/bin/env python3
"""Independent reference for the host side of the ECDH key transport (Pkcs11KeyTransport).

Z       = ECDH(d, Q): the 32-octet x-coordinate on P-256
KEK     = SHA-256(Z || 00000001 || SharedInfo)        (ANSI X9.63 KDF with SHA-256, one block)
wrapped = RFC 3394 AES key wrap under KEK (default IV A6A6A6A6A6A6A6A6)

SharedInfo:
  samTransport  "OPSAMKT1" || samTransportPub(65) || hostEphPub(65) || ASCII(IIII)
  handoff       "OPSAMHO1" || samId || stationSki
  backup        "OPFPEBK1" || backupPub(65) || ASCII(IIII)

The ECDH primitive is computed with a small affine P-256 implementation written here and checked
against the `cryptography` package; the KDF with hashlib and with X963KDF; the wrap with a direct
RFC 3394 implementation and with `cryptography`'s aes_key_wrap, also checked against the RFC 3394
section 4.6 vector. Case samTransport[0] uses the inputs of transport.json endToEnd[0] (the SAM
KAT) and must reproduce its output; that is asserted when transport.json is present.

Writes host-keytransport.json next to this script.
Usage: python3 host_keytransport_vectors.py
"""

import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.keywrap import aes_key_wrap
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] + A) * pow(2 * p1[1], P - 2, P) % P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], P - 2, P) % P
    x = (lam * lam - p1[0] - p2[0]) % P
    return (x, (lam * (p1[0] - x) - p1[1]) % P)


def mul(k, point):
    result = None
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def encode(point):
    return b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def decode(data):
    assert len(data) == 65 and data[0] == 4
    x, y = int.from_bytes(data[1:33], "big"), int.from_bytes(data[33:], "big")
    assert (y * y - (x * x * x + A * x + 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B)) % P == 0
    return (x, y)


def ecdh(d, peer):
    z = mul(d, decode(peer))[0].to_bytes(32, "big")
    library = ec.derive_private_key(d, ec.SECP256R1()).exchange(
        ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer)
    )
    assert z == library
    return z


def public(d):
    point = encode(mul(d, G))
    library = (
        ec.derive_private_key(d, ec.SECP256R1())
        .public_key()
        .public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    )
    assert point == library
    return point


def x963(z, shared_info):
    direct = hashlib.sha256(z + b"\x00\x00\x00\x01" + shared_info).digest()
    library = X963KDF(algorithm=hashes.SHA256(), length=32, sharedinfo=shared_info).derive(z)
    assert direct == library
    return direct


def kw(kek, key):
    """RFC 3394 section 2.2.1, index-based."""
    n = len(key) // 8
    a = bytes.fromhex("A6A6A6A6A6A6A6A6")
    r = [key[8 * i : 8 * i + 8] for i in range(n)]
    encryptor = Cipher(algorithms.AES(kek), modes.ECB()).encryptor()
    for j in range(6):
        for i in range(n):
            b = encryptor.update(a + r[i])
            t = (n * j) + i + 1
            a = (int.from_bytes(b[:8], "big") ^ t).to_bytes(8, "big")
            r[i] = b[8:]
    out = a + b"".join(r)
    assert out == aes_key_wrap(kek, key)
    return out


def iin_ascii(iin):
    return ("%04d" % iin).encode("ascii")


def case(name, recipient_d, ephemeral_d, key, shared_info_of, extra):
    recipient_pub = public(recipient_d)
    ephemeral_pub = public(ephemeral_d)
    z = ecdh(ephemeral_d, recipient_pub)
    assert z == ecdh(recipient_d, ephemeral_pub)
    shared_info = shared_info_of(recipient_pub, ephemeral_pub)
    kek = x963(z, shared_info)
    entry = {
        "name": name,
        "recipientPrivHex": "%064X" % recipient_d,
        "recipientPubHex": recipient_pub.hex().upper(),
        "ephemeralPrivHex": "%064X" % ephemeral_d,
        "ephemeralPubHex": ephemeral_pub.hex().upper(),
    }
    entry.update(extra)
    entry.update(
        {
            "sharedInfoHex": shared_info.hex().upper(),
            "zHex": z.hex().upper(),
            "kekHex": kek.hex().upper(),
            "keyHex": key.hex().upper(),
            "wrappedHex": kw(kek, key).hex().upper(),
        }
    )
    return entry


def main():
    rfc_kek = bytes(range(32))
    rfc_key = bytes.fromhex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
    rfc_wrapped = kw(rfc_kek, rfc_key)
    assert rfc_wrapped.hex().upper() == (
        "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
    )

    fpe_key = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94")
    sam = [
        case(
            "sam-1234",
            0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721,
            0x7D7DC5F71EB29DDAF80D6214632EEAE03D9058AF1FB6D22ED80BADB62BC1A534,
            fpe_key,
            lambda r, e: b"OPSAMKT1" + r + e + iin_ascii(1234),
            {"iin": 1234},
        ),
        case(
            "sam-0042",
            0x3B1D2C4E5F60718293A4B5C6D7E8F90112233445566778899AABBCCDDEEFF00,
            0x0A1B2C3D4E5F60718293A4B5C6D7E8F9FEDCBA98765432100123456789ABCDEF,
            bytes(range(32, 64)),
            lambda r, e: b"OPSAMKT1" + r + e + iin_ascii(42),
            {"iin": 42},
        ),
    ]
    sam_id = bytes.fromhex("0102030405060708")
    station_ski = bytes.fromhex("A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4")
    handoff = [
        case(
            "handoff",
            0x5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A,
            0x1234567812345678123456781234567812345678123456781234567812345678,
            bytes(range(0x40, 0x40 + 56)),
            lambda r, e: b"OPSAMHO1" + sam_id + station_ski,
            {"samIdHex": sam_id.hex().upper(), "stationSkiHex": station_ski.hex().upper()},
        )
    ]
    backup = [
        case(
            "backup-1234",
            0x7777777777777777777777777777777777777777777777777777777777777777,
            0x2222222222222222222222222222222222222222222222222222222222222222,
            fpe_key,
            lambda r, e: b"OPFPEBK1" + r + iin_ascii(1234),
            {"iin": 1234},
        )
    ]

    here = os.path.dirname(os.path.abspath(__file__))
    sam_kat = os.path.join(here, "transport.json")
    if os.path.exists(sam_kat):
        with open(sam_kat) as handle:
            first = json.load(handle)["endToEnd"][0]
        assert first["wrappedHex"] == sam[0]["wrappedHex"], "host and SAM vectors disagree"
        assert first["kekHex"] == sam[0]["kekHex"]

    out = {
        "schema": "openphysical.host-keytransport-vectors/1",
        "rfc3394": {
            "kekHex": rfc_kek.hex().upper(),
            "keyHex": rfc_key.hex().upper(),
            "wrappedHex": rfc_wrapped.hex().upper(),
        },
        "samTransport": sam,
        "handoff": handoff,
        "backup": backup,
    }
    with open(os.path.join(here, "host-keytransport.json"), "w") as handle:
        json.dump(out, handle, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    main()
