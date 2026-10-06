#!/usr/bin/env python3
"""Independent reference for the Issuer SAM FF1-key transport (PUT PARAMETERS v5).

Z      = ECDH(transportPriv, hostEphPub), the 32-octet x-coordinate (P-256)
KEK    = SHA-256(Z || 00000001 || SharedInfo)                    (ANSI X9.63 KDF, one block)
         SharedInfo = "OPSAMKT1" || transportPub(65) || hostEphPub(65) || ASCII(IIN)(4)
wrapped = RFC 3394 AES key wrap of the 32-octet FF1 key under KEK (default IV A6..A6)

The KDF is computed twice, with hashlib and with the `cryptography` X963KDF, and the wrap is
checked against the RFC 3394 Section 4.6 vector. Writes transport.json next to this script.
Usage: python3 sam_transport_vectors.py
"""

import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PREFIX = b"OPSAMKT1"


def point(public_key):
    return public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def kdf(z, transport_pub, host_pub, iin_ascii):
    shared_info = PREFIX + transport_pub + host_pub + iin_ascii
    direct = hashlib.sha256(z + b"\x00\x00\x00\x01" + shared_info).digest()
    library = X963KDF(algorithm=hashes.SHA256(), length=32, sharedinfo=shared_info).derive(z)
    assert direct == library
    return direct


def end_to_end(transport_scalar, host_scalar, iin, fpe_key):
    transport = ec.derive_private_key(transport_scalar, ec.SECP256R1())
    host = ec.derive_private_key(host_scalar, ec.SECP256R1())
    transport_pub = point(transport.public_key())
    host_pub = point(host.public_key())
    z = host.exchange(ec.ECDH(), transport.public_key())
    assert z == transport.exchange(ec.ECDH(), host.public_key())
    iin_ascii = ("%04d" % iin).encode("ascii")
    kek = kdf(z, transport_pub, host_pub, iin_ascii)
    wrapped = aes_key_wrap(kek, fpe_key)
    assert aes_key_unwrap(kek, wrapped) == fpe_key
    return {
        "transportPrivHex": "%064X" % transport_scalar,
        "transportPubHex": transport_pub.hex().upper(),
        "hostEphPrivHex": "%064X" % host_scalar,
        "hostEphPubHex": host_pub.hex().upper(),
        "iin": iin,
        "zHex": z.hex().upper(),
        "kekHex": kek.hex().upper(),
        "fpeKeyHex": fpe_key.hex().upper(),
        "wrappedHex": wrapped.hex().upper(),
    }


def main():
    # RFC 3394 Section 4.6: wrap 256 bits of key data with a 256-bit KEK.
    rfc_kek = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    rfc_key = bytes.fromhex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
    rfc_wrapped = bytes.fromhex(
        "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
    )
    assert aes_key_wrap(rfc_kek, rfc_key) == rfc_wrapped

    fpe_key = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94")
    cases = [
        end_to_end(
            0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721,
            0x7D7DC5F71EB29DDAF80D6214632EEAE03D9058AF1FB6D22ED80BADB62BC1A534,
            1234,
            fpe_key,
        ),
        end_to_end(
            0x0000000000000000000000000000000000000000000000000000000000000002,
            0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632550,
            0,
            bytes(range(32)),
        ),
        end_to_end(
            0x1F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100,
            0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF,
            9999,
            bytes(32),
        ),
    ]
    out = {
        "schema": "openphysical.sam-transport-vectors/1",
        "rfc3394": {
            "kekHex": rfc_kek.hex().upper(),
            "keyHex": rfc_key.hex().upper(),
            "wrappedHex": rfc_wrapped.hex().upper(),
        },
        "x963": [
            {
                "zHex": c["zHex"],
                "transportPubHex": c["transportPubHex"],
                "hostEphPubHex": c["hostEphPubHex"],
                "iin": c["iin"],
                "kekHex": c["kekHex"],
            }
            for c in cases
        ],
        "endToEnd": cases,
    }
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "transport.json")
    with open(path, "w") as handle:
        json.dump(out, handle, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    main()
