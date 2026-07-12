# PIV VCI / Secure Messaging Test Vectors

Known-answer fixtures captured from NIST Special Database 33 cards. Used by
`OpenFIPS201VciVectorTest` (host-side OPACITY + SM replay against `VciSupport`).

## Layout

| Pattern | Interface | Cipher suites |
| ------- | --------- | ------------- |
| `vci_vectors_sd33-*.json` | Contact | CS2 (0x27), CS7 (0x2E) |
| `vci_contactless_sd33-*.json` | Contactless | CS2, CS7 |
| `v2/nist_special_database_33_card_*.json` | Contactless enrolment + VCI | CS2 (3,4) + CS7 (2,5,16) long sessions |
| `cvc-corpus/*/secure-messaging-cvc-7f21.bin` | CVC structure KATs | CS2 + CS7 |
| `trust-anchors/card-*` | PD trust-anchor chain validation | direct EC + intermediate RSA |

## Sources

- Primary: `OpenPhysical.Net/vectors` (same schema as the `sm_vci_vectors` captures)
- v2 long-session APDU fixtures align with public NIST SD33 capture sets
- CVC corpus / trust anchors are trimmed copies of the SD33-derived fixtures
  (`source-vector.json` omitted to keep the tree small)

## Notes

These files may include plaintext PINs, pairing codes, OPACITY ephemeral private keys,
shared secrets, and derived session keys. Do **not** use any value as operational secret
material. SD33 Card 8 (`vci_vectors_sd33-08.json`) supports SM but not VCI.

The applet currently implements CS2 only; CS7 vectors exercise host-side OPACITY/SM
parity so a future CS7 applet change can land against known-good wire format.
