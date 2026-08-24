# OpenFIPS201 for OpenPhysical

This repository is the OpenPhysical fork of
[OpenFIPS201](https://github.com/Mistial-Dev/OpenFIPS201/tree/master), an open-source Java Card
implementation of the NIST Personal Identity Verification (PIV) card application.

## Fork Relationship and Acknowledgements

OpenFIPS201 was commissioned and funded by the Australian Department of Defence to provide an open
implementation of the card application specified by FIPS 201 and the NIST SP 800-73 PIV interface
specifications. Its repository history includes
[Mistial-Dev/OpenFIPS201](https://github.com/Mistial-Dev/OpenFIPS201/tree/master), and the upstream
project is maintained at [makinako/OpenFIPS201](https://github.com/makinako/OpenFIPS201).

OpenPhysical maintains this downstream fork for conformance validation, security hardening,
attestation, VCI secure messaging, issuer tooling, and continued maintenance. The fork preserves
the original project's license, copyright notices, source history, and attribution. The original
project documentation is retained at [docs/README-upstream.md](docs/README-upstream.md).

The OpenPhysical additions build on the original applet and the work of its authors, contributors,
and funders. Nothing in this repository's additional functionality changes that provenance.

## OpenPhysical Fork Differences

The OpenPhysical fork adds and changes the following applet behavior, tooling, and validation:

- NIST SP 800-73-5 command behavior, retry-counter rules, PIN limits, and negative-path tests
- ISO/IEC 7816-4 proprietary-class commands for PIN, PUK, key, object, and configuration
  administration
- management-key cipher selection based on the provisioned PIV algorithm
- complete one-to-three-byte PIV data-object identifiers for read, write, create, and delete
  operations
- single-definition key slots, with an explicit delete-and-create operation when the mechanism
  changes
- PIV-style F9 attestation with SCP-protected authority provisioning, staged authority updates,
  generated-key provenance, certificate construction, host verification, and issuer tooling
- VCI secure messaging with OPACITY CS2 or CS7 selected when the CAP is built
- VCI host provisioning, CVC handling, pairing policy, secure-messaging probes, and a ZeroMQ
  emulator bridge
- CS2 and CS7 known-answer vectors for OPACITY, key derivation, command and response MACs,
  encryption, counters, and response chaining
- stricter APDU, BER-TLV, DER, CVC, object-lifecycle, transaction, and state-transition validation
- an eight-variant release matrix covering standard and FIPS profiles, CS2 and CS7, and
  attestation enabled and disabled
- a unified issuer tool for card discovery, CAP installation, SCP key management, attestation,
  producer profiles, batches, and production receipts
- Java Card 3.0.5 targeting with maintained build, test, coverage, and dependency tooling

Detailed requirement mappings and residual limits are in
[Conformance and NPIVP](docs/CONFORMANCE_AND_NPIVP.md) and
[Validation Status and Deployment Gaps](docs/FIPS_AND_TEST_GAPS.md).

## Quick Start

### Requirements

- JDK 17
- Apache Ant
- Internet access for the first test run, so Apache Ivy can resolve test dependencies

The repository contains the Java Card SDK and build tools required to produce the CAP.

### Test and Build

Run the default test suite:

```sh
ant -f build/build.xml test
```

Build the default CAP:

```sh
ant -f build/build.xml compile
```

The default build uses the standard profile, VCI cipher suite CS2, and attestation. The CAP and a
matching `.properties` file are written to `build/bin/`. Keep these two files together. The
properties file records the profile, VCI suite, attestation setting, and target platform.

### Find a Card and Install the CAP

List PC/SC readers:

```sh
ant -f build/build.xml openfips201-tool -Dargs='cards list'
```

Review the installation options:

```sh
ant -f build/build.xml openfips201-tool -Dargs='applet install --help'
```

The issuer tool does not build, clean, or replace CAP artifacts. Pass the intended CAP explicitly
with `--cap` when you install it.

## Choose a Build Profile

Each CAP contains one profile, one VCI suite, and one attestation setting.

| Choice      | Values                    | Default  |
| ----------- | ------------------------- | -------- |
| Profile     | `compile`, `compile-fips` | Standard |
| VCI suite   | `CS2`, `CS7`              | `CS2`    |
| Attestation | `true`, `false`           | `true`   |

Examples:

```sh
# Standard profile, CS7, attestation enabled
ant -f build/build.xml compile -Dvci.suite=CS7

# FIPS profile, CS2, attestation disabled
ant -f build/build.xml compile-fips -Dvci.suite=CS2 -Dattestation.enabled=false
```

The FIPS profile controls applet configuration, required PIV objects, and permitted algorithms.
Shared APDU syntax, TLV validation, and error handling are the same in both profiles. A FIPS-profile
CAP does not by itself establish certification of the Java Card platform or the complete card
system.

## Recommended Issuance Order

1. Build and retain the selected CAP and its `.properties` file.
2. Install the CAP through an authenticated GlobalPlatform secure channel.
3. Provision the F9 attestation authority first, if the build and issuer profile use attestation.
4. Create the required objects and key definitions.
5. Load cardholder data and import or generate cardholder keys.
6. Apply the one-way personalization transition.
7. Verify the card identity, expected objects, attestation chain, and active SCP keys.

For repeatable production, use the guided producer, batch, and card workflow:

```sh
ant -f build/build.xml openfips201-tool \
  -Dargs='producer setup --name example_issuer'

ant -f build/build.xml openfips201-tool \
  -Dargs='batch create --producer example_issuer --name 2026-08'

ant -f build/build.xml openfips201-tool \
  -Dargs='card produce --producer example_issuer --batch 2026-08 --target pcsc:READER --stock-scp-key HEX_KEY --yes'
```

The tool stores issuer state and batch receipts under `~/.openfips201`. Treat this directory as
sensitive operational data. Protect its access and include it in the issuer's backup plan. See
[Issuer Tool](docs/OPENFIPS201_TOOL.md) for PKCS#11 support, key rotation, receipts, and recovery
guidance.

## Administrative Commands

Administrative operations require either:

- a GlobalPlatform secure channel with command encryption, or
- prior authentication of the applicable administrative key, normally key reference `9B`.

The authenticated-`9B` path authorizes an operation but does not encrypt APDU contents. Use a secure
channel when the command contains sensitive values.

OpenFIPS201 separates issuer commands from the interindustry PIV command syntax:

- PIN and PUK replacement: `80 24 01 <reference>`
- Key replacement: `80 25 01 <reference>`
- Object and configuration administration: `80/84 DB FF FF`
- Administrative status queries: `80/84 CB FF FF`

Under GlobalPlatform secure messaging, the secure-channel layer sets the protected class byte.
Administrative `PUT DATA` accepts one operation per command. Submit and verify each operation before
continuing. This avoids relying on rollback for Java Card allocation or deletion.

Give each created data object an explicit capacity. If the platform cannot delete persistent
objects, the first successful write to a dynamically sized object sets the largest reusable buffer.
Later values cannot exceed that size.

## Attestation

Attestation-enabled CAPs can provision an ECC P-256 F9 authority and attest keys that were generated
on the card. Supported target algorithms are RSA-1024 in the standard profile, RSA-2048, RSA-3072,
ECC P-256, and ECC P-384.

Provision F9 before cardholder keys. The applet validates the imported F9 key pair before it commits
the authority, and an authority update is staged so an interrupted operation does not leave mixed
key and certificate state. Attestation-disabled CAPs do not contain the attestation command path.

See [Attestation](docs/ATTESTATION.md) for the certificate profile, provisioning APDUs, host
verification, and status words.

## VCI Secure Messaging

OpenFIPS201 implements the OPACITY secure-messaging path in NIST SP 800-73-5 Part 2. The selected
suite is advertised only after secure-messaging key reference `04` and its Card Verifiable
Certificate are provisioned.

| Suite | Build property    | Curve | Session protection  | Algorithm ID |
| ----- | ----------------- | ----- | ------------------- | ------------ |
| CS2   | `-Dvci.suite=CS2` | P-256 | AES-128 and SHA-256 | `0x27`       |
| CS7   | `-Dvci.suite=CS7` | P-384 | AES-256 and SHA-384 | `0x2E`       |

Secure messaging uses class byte `0C` and data objects `87`, `97`, `8E`, and `99`. The applet
rejects invalid secure-messaging structure or MACs with `6988`, a pairing-code mismatch with
`6300`, and an unsatisfied protected-VCI requirement with `6982`.

On-card ECDH point validation uses software multi-precision arithmetic. Qualify P-256 and P-384
GENERAL AUTHENTICATE latency, reader timeouts, reset behavior, and interrupted transactions on each
target card platform before deployment.

See [VCI Conformance](tools/piv_test_runner/VCI_CONFORMANCE.md) for the clause map and vector runner.

## Validation

Run all eight build variants before a release:

```sh
ant -f build/build.xml test-all
```

This target covers standard and FIPS profiles, CS2 and CS7, and attestation enabled and disabled.
The test suite enforces an 80% JaCoCo applet line-coverage floor and includes targeted negative-path
tests. Formal card-interface and data-model validation still requires the applicable NIST suites and
the intended card platform.

Useful references:

- [Conformance and NPIVP](docs/CONFORMANCE_AND_NPIVP.md)
- [NPIVP Vendor Evidence](docs/NPIVP_VENDOR_EVIDENCE.md)
- [Validation Status and Gaps](docs/FIPS_AND_TEST_GAPS.md)
- [PIV Test Runner](tools/piv_test_runner/README.md)

## Deployment Limits

Persistent object and key metadata are internal to a CAP build. Do not install a CAP with a changed
persistent layout over an existing applet instance. Delete the instance, install the intended CAP,
and personalize the card from the issuer's authoritative profile.

Configuration fields for OCC, PUK update restriction, enumeration restriction, and RSA-CRT
selection return `6A81` because these behaviors are not implemented. Unsupported fields are not
accepted as inactive settings.

Incoming TLV lengths must use the shortest valid encoding. The applet also rejects bytes after the
declared top-level value. Issuer software must send canonical BER-TLV encodings.

## Repository Layout

- `src/com/makina/security/openfips201/`: production applet source
- `src/dev/mistial/tools/openfips201/`: issuer and provisioning tools
- `src/dev/mistial/tests/`: simulator, conformance, and host-tool tests
- `build/`: Ant build definition and generated output
- `docs/`: public operational and conformance documentation
- `tools/piv_test_runner/`: external validation harness and VCI vector runner

## Project and License

This repository is maintained by OpenPhysical and derives from the open-source
[OpenFIPS201](https://github.com/makinako/OpenFIPS201) project commissioned by the Australian
Department of Defence. It is distributed under the MIT License. See [LICENSE.md](LICENSE.md).
