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
- ISO 7816-4 proprietary-class administration for PIN, PUK, key, object, and configuration updates.
- Symmetric cipher selection by management key type for `GENERAL AUTHENTICATE`.
- Full one-to-three byte PIV data object identifiers for GET DATA, PUT DATA,
  create, and delete operations.
- PIV-style attestation authority support with host provisioning tooling for
  SCP03/SCP02-protected F9 import and issuer certificate publication.
- Single-key PIV slots: a key reference can hold one key definition. Changing a
  slot's mechanism is a delete/recreate operation, not a second definition.
- PIV Virtual Contact Interface (VCI) secure messaging (OPACITY key
  establishment, cipher suites CS2 and CS7 as build-time alternatives) with
  host provisioning and probe tooling and a ZeroMQ emulator bridge.
- Vector-based VCI conformance tests that replay real-card OPACITY key
  establishment and secure-messaging captures as known-answer checks.
- Java Card 3.0.5 build targeting with a JDK 11-compatible Ant toolchain.
- Ivy-based test dependency resolution and removal of stale checked-in test
  dependency jars.
- Updated test and tooling dependencies, including JCardEngine, GlobalPlatformPro,
  APDU4J, JUnit, Mockito, Bouncy Castle, ASM, SLF4J, and JaCoCo.

Administrative updates intentionally support two parallel authorization paths: an SCP session with
command encryption, or prior authentication of the applicable administrative key (normally `9B`).
PIN and PUK replacement uses proprietary `CHANGE REFERENCE DATA` (`80 24 01 <reference>`). Key
material uses proprietary `UPDATE KEY` (`80 25 01 <reference>`) with the algorithm in tag `80`.
Under SCP the class is `84`. Structure and configuration changes use administrative `PUT DATA`
(`80/84 DB FF FF`) and remain SCP-only. The authenticated-`9B` path does not encrypt APDU contents.

Administrative status/version queries use proprietary `GET DATA` (`80/84 CB FF FF`). In FIPS mode,
the interindustry PIV command surface accepts only the standard P1/P2 forms; the relaxed build also
retains the earlier protected administrative encodings for compatibility.

Administrative PUT DATA accepts one operation per command. Legacy bulk containers are rejected
because Java Card allocation and deletion cannot be rolled back reliably as one transaction; an
issuance system must submit and verify each operation separately.

Configuration fields for OCC, PUK update restriction, enumeration restriction, and RSA-CRT
selection are rejected with `6A81` because those behaviors are not implemented. VCI configuration
is supported. Unsupported settings are not accepted as inert values, and supported configuration
updates are applied transactionally.

Incoming TLV lengths must use their shortest valid encoding, and trailing bytes after the declared
top-level value are rejected. This deliberate strictness catches malformed issuance data, but tools
that emit non-minimal BER lengths must canonicalize their encoding before sending it to the applet.

ECDH public points are validated on-card before key agreement. Because validation uses software
multi-precision arithmetic, each target card model must be qualified on real hardware for P-256 and
P-384 GENERAL AUTHENTICATE latency and reader timeout behavior before deployment.

## VCI / Secure Messaging Conformance

This fork implements the SP 800-73-5 Part 2 secure-messaging path used by VCI:
OPACITY key establishment, SM APDU unwrap/wrap, MAC chaining, RMAC, pairing
code verification, and APT advertisement.

The applet is built for one OPACITY suite at a time:

| Suite | Build property | Curve | Keys / hash | Algorithm ID |
| ----- | -------------- | ----- | ----------- | ------------ |
| CS2 | `-Dvci.suite=CS2` | P-256 | AES-128 / SHA-256 | `0x27` |
| CS7 | `-Dvci.suite=CS7` | P-384 | AES-256 / SHA-384 | `0x2E` |

CS2 is the default. The selected suite is advertised in the Application
Property Template only after the SM key (`0x04`) and its CVC are loaded. The
admin provisioning path supports the larger CS7 CVCs when the CS7 build is
enabled.

OPACITY runs through `GENERAL AUTHENTICATE` with `P1` set to the selected suite
and `P2=0x04`. Before ECDH, the applet validates the host ephemeral public key
as required by SP 800-73-5 Part 2 C4; invalid points fail with `6A80`.

Secure messaging uses class byte `0x0C` and the standard `87`, `97`, `8E`, and
`99` data objects. Bad SM object structure, ordering, duplication, unknown
objects, and MAC failures return `6988`. Pairing-code mismatch returns `6300`;
commands that require a satisfied protected VCI session return `6982` when that
condition is not met.

The VCI tests cover both host-side vectors and live emulator flows. The vector
tests replay CS2 and CS7 captures from real cards for OPACITY, KDF, SM
wrap/unwrap, MAC/RMAC, and counter chaining. The end-to-end tests provision the
emulator, establish OPACITY, verify pairing, run wrapped commands, and reject
off-curve host public keys for both suites.

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
- `tools/piv_test_runner/` contains OpenPhysical-fork configuration for the
  external NIST SP 800-73-4 PIV Test Runner and the repo-owned headless harness.

## Conformance and NPIVP

Formal listing and data-model expectations are documented separately from the
JUnit suite. Unless a document explicitly says otherwise, these claims apply to
the OpenFIPS201 OpenPhysical fork in this repository, not to the upstream
`makinako/OpenFIPS201` project.

- [docs/CONFORMANCE_AND_NPIVP.md](docs/CONFORMANCE_AND_NPIVP.md) — specification
  map, product posture (including OCC out of scope, SM suite builds, algorithm
  listing caveats), repository test coverage, remaining SP 800-85A/85B coverage,
  and NPIVP evidence priorities.
- [docs/NPIVP_VENDOR_EVIDENCE.md](docs/NPIVP_VENDOR_EVIDENCE.md) — vendor
  evidence (VE) checklist aligned with the NPIVP Test Summary form.
- [tools/piv_test_runner/README.md](tools/piv_test_runner/README.md) — how to
  obtain and run the NIST PIV Test Runner with the configs in this repository.

In-repo tests exercise command behaviour, VCI/secure messaging, and selected
crypto paths. Formal interface and personalised-data testing is described in
[docs/CONFORMANCE_AND_NPIVP.md](docs/CONFORMANCE_AND_NPIVP.md).

The enforced 80% JaCoCo applet line floor records the simulator regression baseline.

Release candidates must pass `ant -f build/build.xml test-all`. This runs slow SM/VCI coverage for
the full standard/FIPS × CS2/CS7 × attestation on/off matrix.

## Building and Testing

Run the standard test target from the repository root:

```sh
ant -f build/build.xml test
```

The test target resolves Maven dependencies through Ivy into `build/lib` and
runs the JCardEngine-backed JUnit suite.

Persistent object and key metadata is an internal CAP layout, not an upgrade-stable storage
format. Installing a build that changes that layout requires deleting the previous applet instance,
installing the new CAP, and personalising the card again from the issuer's authoritative profile.
Do not upgrade an existing instance in place.

The NIST SP 800-73-4 PIV Test Runner is supported as an external local tool.
The encrypted NIST archive, extracted tool, archive password, generated logs,
and runner output are not tracked. A headless harness can run selected NIST APDU
vectors against the in-process emulator through a SmartcardIO adapter. See
[tools/piv_test_runner/README.md](tools/piv_test_runner/README.md).

VCI suite selection is controlled by `vci.suite`; CS2 is the default:

```sh
ant -f build/build.xml -Dvci.suite=CS2 test-suite
ant -f build/build.xml -Dvci.suite=CS7 test-suite
```

The combined matrix targets run CS2 and CS7, with and without attestation:

```sh
ant -f build/build.xml test-all
```

## Issuer Tooling

Host-side tooling is exposed through one entrypoint:

```sh
ant -f build/build.xml openfips201-tool -Dargs="--help"
```

The tool covers PC/SC cards and the ZeroMQ emulator, CAP load/install, F9
attestation authority import, proof attestation, SCP03 key derivation/rotation,
profile-aware forward/backward keyroll, PKCS#11-backed signing and SCP03 KDF3
derivation, and cardstock batch preparation. The issuer-facing path is:

```sh
ant -f build/build.xml openfips201-tool -Dargs='producer setup --name bigcorp_01'
ant -f build/build.xml openfips201-tool -Dargs='batch create --producer bigcorp_01 --name 2026-07'
ant -f build/build.xml openfips201-tool -Dargs='card produce --producer bigcorp_01 --batch 2026-07 --target pcsc:JCOP --stock-scp-key <printed-batch-key> --yes'
```

Producer state and batch receipts live under `~/.openfips201`. Subject names
for the root CA and F9 attestation authority are configurable; the tool does
not force a particular common name. The PKCS#11 path uses the tool's own
Cryptoki binding rather than SunPKCS11. A finished cardstock receipt records
CPLC, KDD, proof-key deletion, and post-rotation SCP verification. See
[docs/OPENFIPS201_TOOL.md](docs/OPENFIPS201_TOOL.md).

The ZeroMQ client performs a bounded readiness handshake, never retries stateful APDUs, and reuses
one thread-confined transport across each multi-step cardstock workflow.

## License

This OpenFIPS201 OpenPhysical fork is distributed under the MIT License. See
[LICENSE.md](LICENSE.md) for the license text.
