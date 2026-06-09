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
