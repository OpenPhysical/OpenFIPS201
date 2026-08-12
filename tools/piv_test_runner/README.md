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
classes directly and supplies the card through an adapter. The current adapter
target is the in-process OpenFIPS201 JCardEngine emulator, exposed as a
SmartcardIO terminal so NIST's PC/SC wrapper can use it unchanged.

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
| `--test SelectCommand:1` | Run one vector |
| `--suite contact` | Run vectors whose NIST `TestInterface` is `CONTACT` |
| `--suite contactless` | Run vectors whose NIST `TestInterface` is `CONTACTLESS` |
| `--suite all` | Run all vectors loaded from the configuration |
| `--limit N` | Stop after N selected vectors |

The emulator starts with a freshly installed applet. Most NIST suites require a
pre-personalised and personalised card state matching the selected config. Use
`SelectCommand:1` as the basic harness smoke test; broader suites are expected
to fail until the adapter target provisions the emulator for that profile.

Generated runner output such as `piv_tests/`, logs, buffers, and result
directories is local-only and ignored by git.
