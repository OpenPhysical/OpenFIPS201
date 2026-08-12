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
[Mistial-Dev/OpenFIPS201](https://github.com/Mistial-Dev/OpenFIPS201/tree/master).
This repository is a downstream fork used by OpenPhysical to integrate and test
changes before they are proposed upstream or carried as OpenPhysical-specific
maintenance.

The fork keeps the original project structure where possible. Documentation and
test fixtures that were previously under `doc/` have been moved to `docs/` so
GitHub renders the documentation directory consistently.

## OpenPhysical Changes

This fork currently includes the following notable changes beyond the upstream
baseline:

- Expanded APDU conformance tests using JCardEngine.
- Additional unhappy-path coverage for PIV management operations.
- Regression coverage for secure channel and extended APDU handling.
- Enforcement of SP 800-73-5 retry counter and PIN length requirements.
- PIV-style `CHANGE REFERENCE DATA` support for the management key.
- Symmetric cipher selection by management key type for `GENERAL AUTHENTICATE`.
- Java Card 3.0.5 build targeting with a JDK 11-compatible Ant toolchain.
- Ivy-based test dependency resolution and removal of stale checked-in test
  dependency jars.
- Updated test and tooling dependencies, including JCardEngine, GlobalPlatformPro,
  APDU4J, JUnit, Mockito, Bouncy Castle, ASM, SLF4J, and JaCoCo.

Administrative `CHANGE REFERENCE DATA` operations intentionally support two parallel authorization
paths: an SCP session with command encryption, or prior authentication of the applicable
administrative key (normally `9B`). This applies to management keys, PINs, and PUKs, allowing card
administration when GlobalPlatform secure-channel credentials are unavailable. Deployments that
require transport confidentiality must use SCP; the authenticated-`9B` path does not encrypt APDU
contents.

Administrative PUT DATA accepts one operation per command. Legacy bulk containers are rejected
because Java Card allocation and deletion cannot be rolled back reliably as one transaction; an
issuance system must submit and verify each operation separately.

Configuration fields for VCI, OCC, PUK update restriction, enumeration restriction, and RSA-CRT
selection are rejected with `6A81` because those behaviors are not implemented. They are not
accepted as inert settings. Configuration updates that are supported are applied transactionally.

Incoming TLV lengths must use their shortest valid encoding, and trailing bytes after the declared
top-level value are rejected. This deliberate strictness catches malformed issuance data, but tools
that emit non-minimal BER lengths must canonicalize their encoding before sending it to the applet.

ECDH public points are validated on-card before key agreement. Because validation uses software
multi-precision arithmetic, each target card model must be qualified on real hardware for P-256 and
P-384 GENERAL AUTHENTICATE latency and reader timeout behavior before deployment.

## Repository Layout

- `src/com/makina/security/openfips201/` contains the Java Card applet source.
- `src/dev/mistial/tests/openfips201/` contains the JCardEngine-based regression
  and conformance tests.
- `build/` contains the Ant build, Ivy dependency metadata, and generated build
  output.
- `tools/` contains checked-in build tools and Java Card test harness jars that
  are not resolved through Ivy.
- `docs/` contains project documentation, ASN.1 fixtures, and the preserved
  upstream README.
- `tools/piv_test_runner/` contains OpenPhysical-fork configuration for the
  external NIST SP 800-73-4 PIV Test Runner and the repo-owned headless harness.

## Building and Testing

Run the standard test target from the repository root:

```sh
ant -f build/build.xml test
```

The test target resolves Maven dependencies through Ivy into `build/lib` and
runs the JCardEngine-backed JUnit suite.

The NIST SP 800-73-4 PIV Test Runner is supported as an external local tool.
The encrypted NIST archive, extracted tool, archive password, generated logs,
and runner output are not tracked. A headless harness can run selected NIST APDU
vectors against the in-process emulator through a SmartcardIO adapter. See
[tools/piv_test_runner/README.md](tools/piv_test_runner/README.md).

## License

OpenFIPS201 is distributed under the MIT License. See [LICENSE.md](LICENSE.md)
for the license text.
