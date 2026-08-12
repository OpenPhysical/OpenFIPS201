# PIV Test Runner

Configuration and test inputs for the **NIST PIV Test Runner** used with the
OpenFIPS201 OpenPhysical fork in this repository. These files are not upstream
`makinako/OpenFIPS201` product claims or upstream test configuration.

The NIST Test Runner package is external to this repository. The encrypted
archive, extracted installer/tool, password, generated logs, and local result
directories must stay out of git.

## Local setup

The SP 800-73-4 Test Runner package is published by NIST:

```text
https://csrc.nist.gov/CSRC/media/Projects/NIST-Personal-Identity-Verification-Program/documents/install_SP800_73_4_tester_5.0.1_20200212-0308_enc.zip
```

The archive is password-protected. Obtain the password from the NIST PIV Test
Runner distribution process and enter it only when `unzip` prompts for it. Do
not commit the password, put it in `.envrc`, or pass it on the command line.

From the repository root:

```sh
tools/piv_test_runner/setup-nist-tester.sh
```

The setup script downloads the archive to `tools/piv_test_runner/local/downloads/`,
extracts the installer under `tools/piv_test_runner/local/runner/`, and installs
the Test Runner under `tools/piv_test_runner/local/install/`. These paths are
ignored by git.

The installed SP 800-73-4 Test Runner package also contains NIST's official
SP 800-85B `CHECK_*` data-model groups. The headless adapter can execute those
groups against the same personalised emulator image. For the broader
conformance picture, FIPS product gaps, and the macOS emulator plan, see:

- [docs/CONFORMANCE_AND_NPIVP.md](../../docs/CONFORMANCE_AND_NPIVP.md)
- [docs/FIPS_AND_TEST_GAPS.md](../../docs/FIPS_AND_TEST_GAPS.md)
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
| `config/OpenFIPS201.xml` | Baseline Test Runner configuration with optional tests narrowed for development |
| `config/OpenFIPS201-ECC256.xml` | ECC P-256-oriented algorithm selections |
| `config/OpenFIPS201-ECC384.xml` | ECC P-384-oriented algorithm selections |
| `config/OpenFIPS201-RSA2048.xml` | RSA-2048-oriented algorithm selections |
| `test_keys/` | Sample keys/certificates used with the configs |
| `setup-nist-tester.sh` | Local-only download/extract/install helper for the NIST package |
| `run-nist-harness.sh` | Headless harness wrapper for repo-owned adapter code |
| `run-nist-data-model.sh` | Complete positive-golden-image data-model matrix and TSV summary |

The checked-in configs use the SP 800-73-4 Test Runner configuration format
(`ConfigFormat_PIV_SP800_73_4.xml`).

## Running the GUI runner

1. Run `tools/piv_test_runner/setup-nist-tester.sh`.
2. Launch the NIST PIV Test Runner from the local install directory.
3. Open one of the configuration files under `tools/piv_test_runner/config/`.
4. Set the contact and contactless reader names to your PC/SC readers.
5. Load the OpenFIPS201 OpenPhysical fork CAP onto the target card or emulator.
6. Pre-personalise and personalise the applet so the objects, keys, access
   control rules, and algorithms expected by the selected config exist.
7. Align PIN, PUK, and pairing values in the config with the personalised card.
8. Run the selected suites and archive local logs outside git.

The installed SP 800-73-4 runner is a GUI tool. The NIST package also includes
middleware and data-model tooling. This repository only provides
OpenFIPS201-specific configuration and key material.

## Running the headless harness

The repo includes a small Java harness under
`src/dev/mistial/tools/openfips201/nist/`. It uses NIST's installed test-vector
classes directly and supplies the card through an adapter. It supports the
in-process OpenFIPS201 jCard emulator (`tools/jcard-v26.08.10.jar`) and physical
cards through PC/SC. The emulator is exposed as a SmartcardIO terminal so
NIST's PC/SC wrapper can use it unchanged.

Install the NIST runner first, then list the vectors visible through a config:

```sh
tools/piv_test_runner/run-nist-harness.sh \
  --config tools/piv_test_runner/config/OpenFIPS201.xml \
  --list-tests
```

Run one smoke vector against the emulator:

```sh
tools/piv_test_runner/run-nist-harness.sh \
  --target emulator \
  --config tools/piv_test_runner/config/OpenFIPS201.xml \
  --test SelectCommand:1 \
  --out tools/piv_test_runner/piv_tests/smoke
```

Provision a GSA ICAM folder into a FIPS_MODE image, then run a vector against
that same image:

```sh
tools/piv_test_runner/run-nist-harness.sh \
  --fips --target emulator \
  --icam test-vectors/gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV \
  --provision \
  --config tools/piv_test_runner/config/OpenFIPS201-RSA2048.xml \
  --test GetDataCommand:1
```

Build a signed SP 800-73-5 VCI profile from that identity material and issue an
on-card CS2 or CS7 secure-messaging credential before running the vector:

```sh
tools/piv_test_runner/run-nist-harness.sh \
  --fips --target emulator \
  --icam test-vectors/gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV \
  --provision \
  --vci cs2 --pairing-code 12345678 \
  --test SelectCommand:1
```

Use `--vci cs7` for P-384/AES-256. The output directory contains an ephemeral
content-signer key and certificate. They are test-card issuer artifacts and must
not be reused for production credentials.

Run the reviewed CS2/CS7 secure-messaging and virtual-contact matrix together:

```sh
tools/piv_test_runner/run-nist-vci-matrix.sh --out /tmp/openfips201-nist-vci
```

The matrix gate expects the currently classified claim-inapplicable runner failures and fails on
any change to that boundary. Review an unexpected pass as carefully as an unexpected failure, then
update the classification and `docs/FIPS_AND_TEST_GAPS.md` together.

Run all four official SP 800-85B data-model groups against every compatible
positive GSA image:

```sh
tools/piv_test_runner/run-nist-data-model.sh \
  --out tools/piv_test_runner/piv_tests/data-model
```

The default matrix covers seven positive images on the standard build and
cards 37, 46, and 47 on the FIPS build. It writes `summary.tsv`, one JUnit XML
file per build/image/group, and the complete runner logs. A nonzero exit means
an official assertion failed or a result file was not produced; the script
still runs every matrix cell before exiting.

Run a selected suite:

```sh
tools/piv_test_runner/run-nist-harness.sh \
  --target emulator \
  --config tools/piv_test_runner/config/OpenFIPS201.xml \
  --suite contact \
  --out tools/piv_test_runner/piv_tests/contact
```

Useful selectors:

| Option | Meaning |
| ------ | ------- |
| `--list-tests` | Print `Subsystem:Id` entries from the NIST configuration |
| `--fips` | Compile and install the FIPS_MODE applet |
| `--target emulator\|pcsc` | Select the in-process emulator or a physical PC/SC card |
| `--reader NAME` | Select the physical reader used with `--target pcsc` |
| `--icam DIR` | Load expected GSA ICAM personalization metadata |
| `--provision` | Apply the selected profile before running vectors |
| `--yes` | Confirm destructive physical-card provisioning |
| `--reinstall-cap FILE` | Reinstall a fresh physical applet before each isolated vector |
| `--scp 02\|03` | Select the GlobalPlatform secure-channel protocol for provisioning |
| `--scp-key-version N` | Select the card's SCP key version |
| `--scp-key HEX` | Use one shared SCP ENC/MAC/DEK key |
| `--scp-enc-key HEX` | Set the first of three distinct SCP keys |
| `--scp-mac-key HEX` | Set the second of three distinct SCP keys |
| `--scp-dek-key HEX` | Set the third of three distinct SCP keys |
| `--vci cs2\|cs7` | Re-sign and provision a native Part 1 VCI profile |
| `--pairing-code 12345678` | Set the eight-digit test-card pairing code |
| `--test SelectCommand:1` | Run one vector |
| `--suite contact` | Run vectors whose NIST `TestInterface` is `CONTACT` |
| `--suite contactless` | Run vectors whose NIST `TestInterface` is `CONTACTLESS` |
| `--suite card-contact` | Run contact card-application/CHECK vectors, excluding middleware `piv*` |
| `--suite all` | Run all vectors loaded from the configuration |
| `--shared-card` | Keep one provisioned image across vectors instead of the safe fresh-image default |
| `--limit N` | Stop after N selected vectors |

The emulator starts with a freshly installed applet. Without `--provision`, use
`SelectCommand:1` as the bare-card smoke test. With `--icam --provision`, provisioning and
both interface transports share one persistent emulator image. On a physical card, `--icam`
is metadata-only by default: the harness verifies public objects and the declared management-key
capability without consuming PIN retries. Physical mutation requires both `--provision` and
`--yes`; use `--reinstall-cap` when isolated destructive vectors need a fresh applet instance.
Multi-vector runs use a fresh image by default. Use `--shared-card` only for an intentional
stateful sequence.

At launch, the harness creates a local class-only compatibility overlay for four
NIST 5.0.1 classes that call BouncyCastle 1.56 APIs removed from the emulator's
current dependency. It does not modify or redistribute the installed NIST jars.

Generated runner output such as `piv_tests/`, logs, buffers, and result
directories is local-only and ignored by git. Every completed harness run writes
CI-readable JUnit XML to `<out>/nist-results.xml`, including failed vectors.

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

## Formal evidence run

For a listing evidence run:

1. Record the source commit, exact CAP SHA-256, profile sidecar, card platform, reader, runner
   version, and the SHA-256 of the final runner configuration.
2. Use disposable, fully personalised physical cards and enable every test applicable to the
   claimed features. Run every claimed contact and contactless interface without treating filtered,
   disabled, or aborted applicable tests as passes.
3. On the real multi-application card, capture initial and repeated PIV SELECT, selection of another
   installed application, PIV re-selection, and selection of a nonexistent AID. Verify the required
   security-state preservation and clearing after each transition.
4. Execute every claimed key-reference × algorithm × legal-role × operation cell, including each
   claimed retired key-management slot. Cover generation/import and interface/SM policy wherever
   supported.
5. Archive the immutable runner configuration, complete logs, results, card personalisation record,
   and matrix. Store the evidence outside git and review it before preparing vendor statements.

Run the package's `CHECK_*` groups on the same final personalised profile and retain its actual card
captures and report as the separate SP 800-85B evidence gate.

## Relationship to in-repo JUnit tests

| Harness | Strengths | Limitations |
| ------- | --------- | ----------- |
| `ant test` (JCardEngine) | Fast; VCI/SM vectors; PIN/admin edge cases; no physical reader | Not a NIST-certified 85A run; limited SP 800-85B content checks |
| PIV Test Runner (this dir) | Closer to NPIVP interface procedures | Requires personalised card; configs must be widened for listing; not in CI |
| SP 800-85B `CHECK_*` groups | CHUID/CMS/biometrics/cert profiles | Available through the installed runner; emulator evidence is not a physical-card lab report |

## Algorithm and feature matrix

When preparing NPIVP **Listing Summary** cells, use only algorithms and optional
features that are both **implemented in the CAP under test** and **exercised**
by the Test Runner config + personalisation. Authoritative product posture,
repository test coverage, and remaining SP 800-85A/85B coverage are summarised in
[docs/CONFORMANCE_AND_NPIVP.md](../../docs/CONFORMANCE_AND_NPIVP.md).

Vendor documentation statements required alongside Test Runner logs are
catalogued in [docs/NPIVP_VENDOR_EVIDENCE.md](../../docs/NPIVP_VENDOR_EVIDENCE.md).
