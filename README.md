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
- PIV-style F9 attestation with an on-card generated, immutable F9 authority, a PKIX chain from the
  producer root through a per-batch Issuer SAM to each card, generated-key provenance, and host
  verification
- an Issuer SAM Java Card applet that allocates 17-digit OPIDs (decimal LCG enciphered with FF1),
  meters issuance against a root-signed quota, signs the F9 certificate, and keeps a hash-chained
  audit ledger
- VCI secure messaging with OPACITY CS2 or CS7 selected when the CAP is built
- VCI host provisioning, CVC handling, pairing policy, secure-messaging probes, and a ZeroMQ
  emulator bridge
- CS2 and CS7 known-answer vectors for OPACITY, key derivation, command and response MACs,
  encryption, counters, and response chaining
- stricter APDU, BER-TLV, DER, CVC, object-lifecycle, transaction, and state-transition validation
- an eight-variant release matrix covering standard and FIPS profiles, CS2 and CS7, and
  attestation enabled and disabled
- a unified issuer tool for card discovery, CAP installation, SCP key management, PKCS#11 custody,
  a two-station issuance model (a root station that allocates batches and personalizes SAMs, and a
  production station that produces cards through the SAM), top-up, receipts, ledger audit, trust
  export and attestation verification
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

Build and test the Issuer SAM applet, and run the SoftHSM custody and issuance end-to-end tests
(SoftHSM2 required):

```sh
ant -f build/build.xml compile-sam   # build/bin/OpenPhysicalIssuerSam-0.1.cap
ant -f build/build.xml test-sam
ant -f build/build.xml test-host
```

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

Issuance uses two stations, each with its own PKCS#11 token and OpenFIPS201 home, set up under the
same producer name (handoff bundles and top-up files name the producer). The root
station holds the root CA key and the per-IIN FF1 keys and handles only SAMs. The production station
holds the card master key and the public `root.pem`, and handles SAMs and cards. The root key, FF1
keys and LCG parameters never reach the production station.

1. Build and retain the selected CAP and its `.properties` file (attestation enabled), and the
   Issuer SAM CAP.
2. Set up both stations (`producer setup --station root|production`), create the production
   station's handoff key (`station init`) and import it at the root (`station import`).
3. At the root: create the allocation registry once (`root init`), allocate an (IIN, batch) with its
   quota (`root allocate`), and personalize the batch SAM (`sam personalize`), which writes a
   root-signed handoff bundle for the production station.
4. At the production station: take over the SAM (`sam receive`), which rotates its keys and sets the
   operator PIN, and creates the batch with a new stock SCP03 key for its cards.
5. Produce each card with `card produce`: it installs the CAP, has the card generate F9, has the SAM
   allocate the OPID and certify F9, verifies the chain and the SAM's DECIPHER of the OPID, loads the
   certificate (which activates F9 and wipes every other key and data object), checks a proof
   attestation, and rotates the card's SCP keys. The card leaves with an unrecorded random local PIN.
6. Then provision the cardholder PIN, PUK, `9B`, key `04`, cardholder keys and data objects over
   the secure channel. In FIPS builds `9A` and `9C` must be generated on the card.
7. Apply the one-way personalization transition.
8. Verify the card identity, expected objects, attestation chain (`attestation verify --from-card`),
   and active SCP keys.
9. At the end of a batch, `batch close` and then `sam terminate`; give relying parties the output of
   `producer export-trust`. The root station can replay every OPID of an exported ledger with
   `root audit-ledger`.

```sh
# Root station
ant -f build/build.xml openfips201-tool -Dargs='producer setup --name example_issuer --station root \
  --pkcs11-module /path/to/pkcs11.so --pkcs11-pin-env HSM_PIN \
  --root-subject "CN=Example OpenFIPS201 Root" --f9-subject "CN=Example OpenFIPS201 F9"'
ant -f build/build.xml openfips201-tool -Dargs='root init --producer example_issuer'
ant -f build/build.xml openfips201-tool -Dargs='root allocate --producer example_issuer \
  --iin 1234 --batch 1 --quota 1000'

# Production station
ant -f build/build.xml openfips201-tool -Dargs='producer setup --name example_issuer --station production \
  --root-pem /transfer/root.pem --pkcs11-module /path/to/pkcs11.so --pkcs11-pin-env HSM_PIN'
ant -f build/build.xml openfips201-tool -Dargs='station init --producer example_issuer --out /transfer/station.pem'

# Root station
ant -f build/build.xml openfips201-tool -Dargs='station import --producer example_issuer \
  --name line1 --pub /transfer/station.pem'
ant -f build/build.xml openfips201-tool -Dargs='sam personalize --producer example_issuer \
  --iin 1234 --batch 1 --sam pcsc:SAM_READER --station line1 --bundle-out /transfer/sam-handoff.json \
  --install --sam-cap build/bin/OpenPhysicalIssuerSam-0.1.cap --sam-stock-key-file /secure/sam-stock.key --yes'

# Production station
ant -f build/build.xml openfips201-tool -Dargs='sam receive --producer example_issuer \
  --bundle /transfer/sam-handoff.json --sam pcsc:SAM_READER \
  --operator-pin-file /secure/operator.pin --stock-key-out /secure/stock.key --yes'
ant -f build/build.xml openfips201-tool -Dargs='card produce --producer example_issuer \
  --batch 1234-0001 --target pcsc:CARD_READER --sam pcsc:SAM_READER \
  --stock-scp-key-file /secure/stock.key --operator-pin-file /secure/operator.pin --yes'
```

`producer setup --dev-softhsm` creates a development SoftHSM producer that can issue only to
emulator targets unless `card produce --allow-dev-custody` is given. Each station keeps its state
under `~/.openfips201`, owner-only: the root station its registry and the batch LCG records, the
production station batches, receipts and ledgers. Treat both homes as sensitive and include them in
the issuer's backup plan. See [Issuer Tool](docs/OPENFIPS201_TOOL.md) for custody, secrets, top-up,
ledger audit, batch close, trust export and recovery.

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

Status words follow ISO/IEC 7816-4 §5.6. The applet returns no proprietary `6Exx` or `6Fxx` codes
other than `6F00`, and SP 800-73-5 codes take precedence where that specification mandates one.

| SW     | Administrative and configuration meaning                                                      |
| ------ | --------------------------------------------------------------------------------------------- |
| `6A80` | Malformed or invalid command data: a missing, wrong-length or invalid element in admin `PUT DATA`; an unknown operation; a configuration value that is empty, out of range, inconsistent, FIPS-forbidden or non-canonically encoded; a retired configuration tag; an imported key that fails its pairwise consistency test. |
| `6A81` | Function not supported: an unimplemented configuration field (OCC policy, PUK restrict-update, restrict-enumeration, RSA CRT) or a mechanism the key object does not support. |
| `6A88` | Referenced data object or key not found, including delete of an object that does not exist. |
| `6A89` | The key or data object being created already exists.                                          |
| `6982` | Security status not satisfied: no secure channel with C-ENC and no authenticated admin key.    |
| `6985` | Conditions of use not satisfied: wrong lifecycle state, e.g. structural changes after PERSONALIZE. |
| `6F00` | Internal fault, including an on-card generated key that fails its pairwise consistency test.   |

PIN and PUK commands follow SP 800-73-5 Part 2. For example, a new PIN that appears in the PIN
history returns `6A80`.

Give each created data object an explicit capacity. If the platform cannot delete persistent
objects, the first successful write to a dynamically sized object sets the largest reusable buffer.
Later values cannot exceed that size.

## Attestation

Attestation-enabled CAPs generate an ECC P-256 F9 authority on the card and attest keys that were
generated on the card. Supported target algorithms are RSA-1024 in the standard profile, RSA-2048,
RSA-3072, ECC P-256, and ECC P-384. F9 is never importable.

The chain is root CA → Issuer SAM → card F9 → leaf. The card proves possession of F9 to the SAM,
which allocates the card's OPID and signs the F9 certificate; the host validates the chain before
the card loads it. Loading the certificate activates F9, wipes every other key and data object, and
makes F9, its certificate and the OPID immutable. Provision F9 before cardholder keys.
Attestation-disabled CAPs do not contain the attestation command path.

See [Attestation](docs/ATTESTATION.md) for the certificate profiles, APDUs, OPID layout and status
words, and [Issuer SAM](docs/ISSUER_SAM.md) for the SAM applet.

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

This target covers standard and FIPS profiles, CS2 and CS7, and attestation enabled and disabled,
then runs the ZeroMQ bridge test, `test-sam` with slow tests, and `test-host`.

`ant -f build/build.xml coverage` (a separate CI job) measures JaCoCo coverage for three profiles
that together compile every preprocessor branch (standard CS2 with attestation, standard CS7
without, FIPS CS2 with attestation) and the host tool, and enforces line and branch ratchets per
profile, with separate per-class floors for the security-critical applet classes. The floors are
defined in `build/build.xml`. Formal card-interface and data-model validation still requires the
applicable NIST suites and the intended card platform.

Useful references:

- [Attestation](docs/ATTESTATION.md) and [Issuer SAM](docs/ISSUER_SAM.md)
- [Issuer Tool](docs/OPENFIPS201_TOOL.md) and [Production Qualification](docs/PRODUCTION_QUALIFICATION.md)
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

Incoming TLV lengths use BER definite form with at most two subsequent length bytes and must use the
shortest valid encoding; indefinite and non-minimal lengths (for example `81 05` or `82 00 80`) are
rejected with `6A80` (`6988` for the data objects of a secure-messaging command). The applet also rejects bytes after the declared top-level value. Issuer
software must send canonical BER-TLV encodings.

## Repository Layout

- `src/com/makina/security/openfips201/`: production applet source
- `src/dev/mistial/openphysical/sam/`: Issuer SAM applet source
- `src/dev/mistial/tools/openfips201/`: issuer and provisioning tools
- `src/dev/mistial/tests/`, `src/dev/mistial/tool-tests/`, `src/dev/mistial/sam-tests/`: applet,
  host-tool and SAM tests
- `test-vectors/opid/`: OPID, LCG, FF1 and FASC-N vectors shared with OpenPhysical.Net
- `build/`: Ant build definition and generated output
- `docs/`: public operational and conformance documentation
- `tools/piv_test_runner/`: external validation harness and VCI vector runner

## Project and License

This repository is maintained by OpenPhysical and derives from the open-source
[OpenFIPS201](https://github.com/makinako/OpenFIPS201) project commissioned by the Australian
Department of Defence. It is distributed under the MIT License. See [LICENSE.md](LICENSE.md).
