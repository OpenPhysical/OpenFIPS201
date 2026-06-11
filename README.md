# OpenFIPS201 OpenPhysical Fork

This repository contains the OpenPhysical fork of
[OpenFIPS201](https://github.com/Mistial-Dev/OpenFIPS201/tree/master), an open
source Java Card implementation of the NIST Personal Identity Verification
(PIV) card application.

OpenFIPS201 was commissioned and funded by the Australian Department of Defence
to provide an open implementation of the card application specified by
[FIPS 201](https://csrc.nist.gov/publications/detail/fips/201/3/final) and the
NIST SP 800-73 PIV interface specifications. This fork preserves that upstream
work and carries OpenPhysical changes for validation, conformance testing, and
ongoing maintenance.

The original upstream README is preserved at
[docs/README-upstream.md](docs/README-upstream.md).

## Relationship to Upstream

The upstream project is maintained at
[makinako/OpenFIPS201](https://github.com/makinako/OpenFIPS201/tree/master).
This repository is a downstream fork used by OpenPhysical to integrate and test
changes before they are proposed upstream or carried as OpenPhysical-specific
maintenance.

The fork keeps the original project structure where possible. Documentation and
test fixtures that were previously under `doc/` have been moved to `docs/` so
GitHub renders the documentation directory consistently.

## OpenPhysical Changes

This fork includes the following notable changes beyond the upstream
baseline:

- Expanded APDU conformance tests using JCardEngine.
- Additional negative-path coverage for PIV management operations.
- Test coverage for secure channel and extended APDU handling.
- Enforcement of SP 800-73-5 retry counter and PIN length requirements.
- PIV-style `CHANGE REFERENCE DATA` support for the management key.
- Symmetric cipher selection by management key type for `GENERAL AUTHENTICATE`.
- Full one-to-three byte PIV data object identifiers for GET DATA, PUT DATA,
  create, and delete operations.
- PIV-style attestation authority support with host provisioning tooling for
  SCP03/SCP02-protected F9 import and issuer certificate publication.
- PIV Virtual Contact Interface (VCI) secure messaging (OPACITY key
  establishment, cipher suite CS2) with host provisioning and probe tooling and
  a ZeroMQ emulator bridge.
- Vector-based VCI conformance tests that replay real-card OPACITY key
  establishment and secure-messaging captures as known-answer checks.
- Java Card 3.0.5 build targeting with a JDK 11-compatible Ant toolchain.
- Ivy-based test dependency resolution and removal of stale checked-in test
  dependency jars.
- Updated test and tooling dependencies, including JCardEngine, GlobalPlatformPro,
  APDU4J, JUnit, Mockito, Bouncy Castle, ASM, SLF4J, and JaCoCo.

## VCI / Secure Messaging Conformance

This fork implements PIV secure messaging and the Virtual Contact Interface
(VCI) per NIST SP 800-73-5 Part 2.

- **Cipher suite:** CS2 only — ECC Curve P-256, AES-128, SHA-256 (algorithm
  identifier `0x27`). CS7 (`0x2E`) is not implemented. SP 800-73-5 Part 2
  §4.1.4 permits a card to support a single suite; CS7 is required only when a
  digital-signature (`9C`), key-management (`9D`), or retired key-management
  (`82`–`95`) key is an ECC Curve P-384 key, which this configuration does not
  use. The Application Property Template advertises `0x27` only after the
  secure-messaging key (`0x04`) and its card-verifiable certificate are present.
- **Key establishment:** OPACITY Zero Key Management via `GENERAL AUTHENTICATE`
  (`P1=0x27`, `P2=0x04`), deriving the `SK_CFRM`/`SK_MAC`/`SK_ENC`/`SK_RMAC`
  session keys and a key-confirmation cryptogram.
- **Message protection:** secure messaging on class byte `0x0C`, with the
  `0x87` (encrypted data), `0x97` (Le), `0x8E` (MAC), and `0x99` (status) data
  objects, AES-CBC encryption and AES-CMAC authentication, MAC chaining, and the
  encryption counter.
- **VCI policy:** pairing-code or no-pairing operation selected by the Discovery
  Object PIN usage policy, with pairing-code verification on key reference
  `0x98`.

The CS2 establishment, session-key derivation, secure-messaging wrap/unwrap, and
MAC/counter chaining are verified byte-for-byte against known-answer test
vectors captured from real PIV cards, in addition to a live end-to-end
establishment against the in-process emulator.

### Contactless access to PIN-protected objects

VCI does not bypass the PIN. Per SP 800-73-5 Part 2 Table 2, the biometric
containers — Cardholder Fingerprints (`0x6010`) and Cardholder Facial Image
(`0x6030`) — have a contactless read rule of "VCI and PIN", and Printed
Information (`0x3001`) is "VCI and (PIN or OCC)". These objects *can* be
retrieved over VCI, but only after the PIN is verified in addition to
establishing VCI. (This concerns the readable biometric *containers*; the
on-card reference templates used for on-card comparison are never released by
either interface.)

In the reference contactless vectors these objects return status word `0x6982`
(security status not satisfied) when read before the PIN has been verified over
the secure channel, and the corresponding contact vectors — which verify the
PIN early — read the same objects successfully. The status reflects the access
rule, not a VCI restriction: once the PIN is verified over VCI, the read is
permitted.

In OpenFIPS201 these access rules are not special-cased in the secure-messaging
code; they are the per-object contact and contactless access modes (`0x8C` /
`0x8D`) assigned when each data object is defined at pre-personalization. A
PIV-conformant configuration sets the biometric containers to require PIN (and
VCI on the contactless interface). Secure messaging itself still succeeds for a
denied read — the transport status word remains `0x9000` and the access-control
status word is carried inside the secure-messaging–protected response.

## Repository Layout

- `src/com/makina/security/openfips201/` contains the Java Card applet source.
- `src/dev/mistial/tests/openfips201/` contains the JCardEngine-based conformance
  and behavior tests.
- `src/dev/mistial/tools/openfips201/` contains host-side utilities, including
  attestation provisioning tooling.
- `build/` contains the Ant build, Ivy dependency metadata, and generated build
  output.
- `tools/` contains checked-in build tools and Java Card test harness jars that
  are not resolved through Ivy.
- `docs/` contains project documentation, ASN.1 fixtures, and the preserved
  upstream README.

## Building and Testing

Run the standard test target from the repository root:

```sh
ant -f build/build.xml test
```

The test target resolves Maven dependencies through Ivy into `build/lib` and
runs the JCardEngine-backed JUnit suite.

## License

OpenFIPS201 is distributed under the MIT License. See [LICENSE.md](LICENSE.md)
for the license text.
