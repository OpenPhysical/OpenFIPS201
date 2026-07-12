# VCI Trust Anchor Test Vectors

This folder contains VCI captures from NIST test cards and generated VCI trust anchor records used by the proposal examples and validation scripts.

These byte-complete files are committed public test fixtures from public test
cards. Source captures may include plaintext PINs, pairing codes, OPACITY
ephemeral private keys, shared secrets, and derived session keys for replay and
validation. Do not use any value in these files as operational secret material.

The CVC and `5FC122` bytes are captured test-card data. GSA FICAM card-builder material is not used to synthesize these CVCs; it is used separately for reusable keys and certificates in the PIV Auto demonstration fixtures.

## Layout

Each card folder contains:

- `source-vector.json`: original NIST test-card VCI capture JSON.
- `content-signing-certificate.der`: X.509 content-signing certificate extracted from `5FC122`.
- `secure-messaging-cvc-7f21.bin`: secure messaging CVC object.
- `smcs-5fc122.bin`: Secure Messaging Certificate Signer object, including the content-signing certificate and, when present, an Intermediate CVC.
- `vci-trust-anchor-record.bin`: generated binary `7F50` VCI trust anchor record.

## Included Cases

| Folder | Source Vector | Flow | Content Signer | Anchor IIN | CVC IIN | Anchor Length |
| --- | --- | --- | --- | --- | --- | --- |
| `card-2-direct` | `nist_special_database_33_card_2.json` | Direct EC P-384 | `CN=Test PIV Content Signer 4` | `B6103792270FBD08` | `B6103792270FBD08` | 140 |
| `card-3-intermediate` | `nist_special_database_33_card_3.json` | RSA-2048 anchor with Intermediate CVC | `CN=Test PIV Content Signer 1` | `9BC5E7735F14EC7F` | `3DA648B01A85BBDD` | 317 |
| `card-4-direct` | `nist_special_database_33_card_4.json` | Direct EC P-256 | `CN=Test PIV Content Signer 3` | `1905976BDDCA823D` | `1905976BDDCA823D` | 110 |
| `card-5-direct` | `nist_special_database_33_card_5.json` | Direct EC P-384 | `CN=Test PIV Content Signer 4` | `B6103792270FBD08` | `B6103792270FBD08` | 140 |
| `card-16-intermediate` | `nist_special_database_33_card_16.json` | RSA-2048 anchor with Intermediate CVC | `CN=Test PIV-I Content Signer 1` | `4CC9C7B3A4F1C83E` | `6F8FF48F42B3E22E` | 317 |

## Reproduce Trust Anchor Records

```bash
scripts/import_vci_vector_fixtures.py --skip-sm-vci-corpus

scripts/make_vci_trust_anchor.py \
  test-vectors/vci-trust-anchors/card-4-direct/content-signing-certificate.der \
  /tmp/card4.anchor

scripts/make_vci_trust_anchor.py \
  test-vectors/vci-trust-anchors/card-16-intermediate/content-signing-certificate.der \
  /tmp/card16.anchor
```

## Validate Chains

```bash
scripts/validate_vci_chain.py \
  --anchor test-vectors/vci-trust-anchors/card-3-intermediate/vci-trust-anchor-record.bin \
  --cvc test-vectors/vci-trust-anchors/card-3-intermediate/secure-messaging-cvc-7f21.bin \
  --smcs test-vectors/vci-trust-anchors/card-3-intermediate/smcs-5fc122.bin

scripts/validate_vci_chain.py \
  --anchor test-vectors/vci-trust-anchors/card-4-direct/vci-trust-anchor-record.bin \
  --cvc test-vectors/vci-trust-anchors/card-4-direct/secure-messaging-cvc-7f21.bin

scripts/validate_vci_chain.py \
  --anchor test-vectors/vci-trust-anchors/card-16-intermediate/vci-trust-anchor-record.bin \
  --cvc test-vectors/vci-trust-anchors/card-16-intermediate/secure-messaging-cvc-7f21.bin \
  --smcs test-vectors/vci-trust-anchors/card-16-intermediate/smcs-5fc122.bin
```

Direct cases do not require `5FC122` for PD validation. Intermediate cases require `5FC122` because the secure messaging CVC is signed by an Intermediate CVC rather than directly by the loaded trust anchor.
