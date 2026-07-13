# PIV Test Runner

Configuration and test inputs for the **NIST PIV Test Runner**, the
NIST-distributed tool used for SP 800-73 / SP 800-85A-style **card application
interface** interoperability testing (NPIVP-oriented).

These files are for the OpenFIPS201 OpenPhysical fork in this repository. They
are not upstream `makinako/OpenFIPS201` product claims or upstream test
configuration.

This directory does **not** implement SP 800-85B data-model tests. For the
broader conformance picture (repository coverage, VE checklist, 85A vs 85B), see:

- [docs/CONFORMANCE_AND_NPIVP.md](../../docs/CONFORMANCE_AND_NPIVP.md)
- [docs/NPIVP_VENDOR_EVIDENCE.md](../../docs/NPIVP_VENDOR_EVIDENCE.md)

## Obtaining the tool

1. Download the PIV Test Runner distribution from  
   [NIST CSRC PIV downloads](https://csrc.nist.gov/Projects/PIV/download).
2. Request the archive password by email to **piv-dmtester@nist.gov**.
3. Install and run the tool per NIST’s instructions (PC/SC readers, middleware
   DLLs as required by the package version you received).

The Test Runner is **external** to this repository and is **not** invoked by
`ant test`.

## Repository contents

| Path | Purpose |
| ---- | ------- |
| `config/OpenFIPS201.xml` | Baseline Test Runner configuration (narrow optional filter) |
| `config/OpenFIPS201-ECC256.xml` | ECC P-256–oriented algorithm selections |
| `config/OpenFIPS201-ECC384.xml` | ECC P-384–oriented algorithm selections |
| `config/OpenFIPS201-RSA2048.xml` | RSA-2048–oriented algorithm selections |
| `test_keys/` | Sample keys/certificates used with the configs |

Configs are based on the SP 800-73-4 Test Runner configuration format
(`ConfigFormat_PIV_SP800_73_4.xml`). Revisit field names if your NIST package
targets a newer schema.

## Setup steps

1. Install and launch the PIV Test Runner.
2. Open one of the configuration files under `config/`.
3. Set **CONTACT_READER_NAME** and **CONTACTLESS_READER_NAME** to your PC/SC
   readers (the checked-in names are placeholders for virtual readers).
4. Load the OpenFIPS201 OpenPhysical fork CAP onto the target card or emulator.
5. **Pre-personalise** and **personalise** the applet so that the objects and
   keys expected by the Test Runner exist with the correct ACRs and algorithms.
   Dynamic definition means a blank install will fail most data-object and
   crypto tests.
6. Align PIN/PUK/pairing values in the config with the personalised card
   (`PIN_VALID`, `PUK_VALID`, `PAIRING_CODE`, block attempt counts, etc.).
7. Run the selected test suites and archive logs for the NPIVP package.

Upstream personalisation references (Makina wiki; may move):

- [Pre-Personalisation](https://github.com/makinako/OpenFIPS201/wiki/Pre-Personalisation)
- [Security Personalisation](https://github.com/makinako/OpenFIPS201/wiki/Security-Personalisation)

Host tooling in the OpenPhysical fork may also provision cards/emulators; see
[docs/OPENFIPS201_TOOL.md](../../docs/OPENFIPS201_TOOL.md).

## What these configs intentionally limit

The checked-in defaults are **development-oriented**, not a full listing run:

| Setting (typical) | Effect |
| ----------------- | ------ |
| `OPTIONAL_TEST_FILTER` | Restricts optional suites (e.g. digital signature, discovery, key management only in the baseline file) |
| `RUN_BLOCKING_TESTS*` | Most configs keep blocking exhaustion tests off; the RSA-2048 config enables PIN/PUK blocking coverage |
| `SYMMETRIC_CARD_AUTHENTICATION_KEY_SUPPORTED` = `false` | Symmetric CAK not exercised (aligned with deprecated status in SP 800-78-5) |
| Empty pairing fields | Pairing-driven paths are not fully driven unless you fill them |

Before NPIVP or formal regression:

1. Enable optional filters for **every feature you claim** on the Test Summary
   (Discovery, Key History, Secure Messaging / crypto suites, VCI with/without
   pairing, Global PIN, Printed Information, etc.).
2. Turn on blocking tests only on disposable personalisation or with known
   unblock procedures.
3. Use a CAP built for the SM suite you claim (`vci.suite=CS2` or `CS7`); one
   CAP advertises one suite.
4. Do not list OCC. The OpenPhysical fork does not implement OCC, does not claim
   OCC, and treats OCC as out of scope.
5. Prefer AES management keys and RSA-2048 / ECC P-256/P-384 over RSA-1024 or
   3TDEA for new listing matrices.

## Relationship to in-repo JUnit tests

| Harness | Strengths | Limitations |
| ------- | --------- | ----------- |
| `ant test` (JCardEngine) | Fast; VCI/SM vectors; PIN/admin edge cases; no physical reader | Not a NIST-certified 85A run; limited SP 800-85B content checks |
| PIV Test Runner (this dir) | Closer to NPIVP interface procedures | Requires personalised card; configs must be widened for listing; not in CI |
| SP 800-85B Data Model Tester | CHUID/CMS/biometrics/cert profiles | Separate NIST tool; not configured in this directory |

## Algorithm and feature matrix

When preparing NPIVP **Listing Summary** cells, use only algorithms and optional
features that are both **implemented in the CAP under test** and **exercised**
by the Test Runner config + personalisation. Authoritative product posture,
repository test coverage, and remaining SP 800-85A/85B coverage are summarised in
[docs/CONFORMANCE_AND_NPIVP.md](../../docs/CONFORMANCE_AND_NPIVP.md).

Vendor documentation statements required alongside Test Runner logs are
catalogued in [docs/NPIVP_VENDOR_EVIDENCE.md](../../docs/NPIVP_VENDOR_EVIDENCE.md).
