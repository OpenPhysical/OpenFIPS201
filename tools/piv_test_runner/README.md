# PIV Test Runner

This directory contains OpenFIPS201 configurations, test material, and wrappers
for NIST PIV Test Runner 5.0.1.

The NIST runner is downloaded locally and is not part of this repository.

## Contents

| Path | Purpose |
| ---- | ------- |
| `config/OpenFIPS201.xml` | Default development configuration |
| `config/OpenFIPS201-ECC256.xml` | P-256 algorithm configuration |
| `config/OpenFIPS201-ECC384.xml` | P-384 algorithm configuration |
| `config/OpenFIPS201-RSA2048.xml` | RSA-2048 algorithm configuration |
| `test_keys/` | Keys and certificates referenced by the configurations |
| `setup-nist-tester.sh` | Downloads and installs the NIST runner locally |
| `run-nist-harness.sh` | Runs NIST vectors against the emulator or a PC/SC card |
| `run-nist-data-model.sh` | Runs the SP 800-85B data-model matrix |
| `run-nist-vci-matrix.sh` | Runs the CS2 and CS7 VCI matrix |

The XML files use the SP 800-73-4 configuration format shipped with Test
Runner 5.0.1.

## Install the NIST runner

From the repository root:

```sh
tools/piv_test_runner/setup-nist-tester.sh
```

The script downloads the encrypted NIST archive and prompts for its password.
It installs the package under `tools/piv_test_runner/local/`. That directory is
ignored by git.

The installed package can also be used directly through its GUI. Load one of
the XML files under `config/`, select the PC/SC readers, and use a card whose
personalization matches the configuration.

## Headless harness

`run-nist-harness.sh` compiles the selected applet profile, loads the NIST
runner classes, and runs selected vectors. Its default target is the in-process
jCard emulator.

List the vectors loaded by the default configuration:

```sh
tools/piv_test_runner/run-nist-harness.sh --list-tests
```

Run a bare-card SELECT smoke test:

```sh
tools/piv_test_runner/run-nist-harness.sh \
  --test SelectCommand:1 \
  --out tools/piv_test_runner/piv_tests/smoke
```

Provision a GSA ICAM image into a FIPS applet and run a vector:

```sh
tools/piv_test_runner/run-nist-harness.sh \
  --fips \
  --icam test-vectors/gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV \
  --provision \
  --config tools/piv_test_runner/config/OpenFIPS201-RSA2048.xml \
  --test GetDataCommand:1
```

Provision a CS2 VCI profile before running the vector:

```sh
tools/piv_test_runner/run-nist-harness.sh \
  --fips \
  --icam test-vectors/gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV \
  --provision \
  --vci cs2 \
  --pairing-code 12345678 \
  --test SelectCommand:1
```

Use `--vci cs7` for the P-384/AES-256 build. VCI provisioning writes generated
content-signer material under the selected output directory.

Run against a physical card by selecting its PC/SC reader:

```sh
tools/piv_test_runner/run-nist-harness.sh \
  --target pcsc \
  --reader "READER NAME" \
  --test SelectCommand:1
```

Physical provisioning requires `--provision --yes` and an ICAM image. Supply
the card's GlobalPlatform credentials with either `--scp-key` or all three of
`--scp-enc-key`, `--scp-mac-key`, and `--scp-dek-key`. `--scp` selects SCP02 or
SCP03, or automatic protocol selection; `--scp-key-version` selects the key
version.

Multiple physical-card vectors require either `--shared-card` or
`--reinstall-cap FILE`. Emulator runs isolate vectors by default;
`--shared-card` makes a selected sequence use one applet instance.

Run `tools/piv_test_runner/run-nist-harness.sh --help` for the complete option
list.

## Matrix wrappers

Run the four `CHECK_*` data-model groups across the configured positive GSA
images:

```sh
tools/piv_test_runner/run-nist-data-model.sh \
  --out tools/piv_test_runner/piv_tests/data-model
```

The default matrix runs seven images with the standard build and images 37, 46,
and 47 with the FIPS build. Use `--mode standard`, `--mode fips`, or `--icam
DIR` to narrow the run. The script writes `summary.tsv`, per-cell logs, and
JUnit XML, then exits nonzero if an assertion fails or a result file is missing.

Run the FIPS CS2/CS7 secure-messaging and virtual-contact matrix:

```sh
tools/piv_test_runner/run-nist-vci-matrix.sh \
  --out tools/piv_test_runner/piv_tests/vci-matrix
```

This wrapper checks the failure classification encoded in
`run-nist-vci-matrix.sh` and exits nonzero if it changes.

## Configuration limits

The checked-in XML files are development configurations:

- `OPTIONAL_TEST_FILTER` selects digital-signature, Discovery Object, and
  key-management tests.
- Symmetric card authentication is disabled.
- Pairing-code fields are empty until patched by the headless VCI flow or set
  for a matching card.
- PIN and PUK blocking tests are disabled except in the RSA-2048 configuration,
  where PIN and PUK blocking are enabled.

Adjust the selected configuration to match the applet build and personalized
card under test.

## Output

Harness runs write logs, generated material, and `nist-results.xml` beneath the
selected `--out` directory. The default output trees under
`tools/piv_test_runner/piv_tests/` and the local NIST installation are ignored
by git.

The harness builds a local compatibility overlay for NIST 5.0.1 classes that
use Bouncy Castle 1.56 APIs. It does not modify the installed NIST jars.

Repository conformance coverage and remaining gaps are tracked in
[`docs/CONFORMANCE_AND_NPIVP.md`](../../docs/CONFORMANCE_AND_NPIVP.md) and
[`docs/FIPS_AND_TEST_GAPS.md`](../../docs/FIPS_AND_TEST_GAPS.md).
