# Conformance, NPIVP, and Data-Model Testing

This document records how OpenFIPS201 (OpenPhysical fork) maps to NIST PIV
specifications, what automated tests cover today, and what remains for formal
NPIVP listing and SP 800-85B data-model validation.

The scope is the OpenFIPS201 OpenPhysical fork in this repository.

Card-platform release gates are recorded in
[Production qualification](PRODUCTION_QUALIFICATION.md).

## Reference specifications

| Layer                                | Specification                                           | Primary concern for this applet                                                                                                                |
| ------------------------------------ | ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Credential policy                    | FIPS 201-3                                              | What a PIV identity is                                                                                                                         |
| Card application namespace / objects | SP 800-73-5 Part 1                                      | Mandatory/optional objects, Discovery, ACRs, VCI policy bits                                                                                   |
| Card command interface               | SP 800-73-5 Part 2                                      | SELECT, GET/PUT DATA, VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER, GENERAL AUTHENTICATE, GENERATE ASYMMETRIC KEY PAIR, secure messaging |
| Algorithms and key sizes             | SP 800-78-5                                             | Algorithm identifiers, phase-outs (e.g. 3TDEA, RSA-1024)                                                                                       |
| Biometrics                           | SP 800-76-2                                             | Fingerprint / face / iris encodings (content, not applet parsing)                                                                              |
| Card / middleware interface tests    | SP 800-85A-4                                            | NPIVP command-interface and related assertions                                                                                                 |
| PIV data model tests                 | SP 800-85B (and draft SP 800-85B-4)                     | BER-TLV structure, CMS signatures, biometrics, certificate profiles                                                                            |
| Listing form                         | NIST NPIVP Test Summary (e.g. `Test-SummaryNPIVP.xlsx`) | Algorithm matrix, optional features, vendor evidence (VE) rows                                                                                 |

Authoritative text lives in the project reference library and NIST CSRC
publications. Clause numbers below are orientation aids; always confirm against
the current normative PDF.

## Architecture note (why 85A and 85B split)

OpenFIPS201 (OpenPhysical fork) is a **dynamically defined** object and key store:

- The CAP does **not** ship pre-created CCC, CHUID, certificates, biometrics, or
  Security Object containers.
- Objects and keys are created and populated at pre-personalisation /
  personalisation (administrative PUT DATA / key load under SCP, plus normal
  PUT DATA when authorised).
- Data object payloads are stored and returned largely as **opaque** BER-TLV
  values. The applet enforces access control, command framing, and cryptographic
  use of keys; it does **not** implement a full SP 800-85B semantic validator
  for CHUID CMS, CBEFF biometric bodies, or X.509 certificate profiles.

Therefore:

| System under test                        | Primary standards                             | Typical tooling                                                                               |
| ---------------------------------------- | --------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Applet CAP + command logic               | SP 800-73-5, SP 800-78-5, parts of SP 800-85A | JUnit / JCardEngine (`ant test`), NIST PIV Test Runner configs under `tools/piv_test_runner/` |
| Fully personalised card + issuer content | SP 800-85B / 85B-4 data model                 | Official runner `CHECK_*` groups on emulator; physical-card report remains external           |
| NPIVP product listing                    | 85A + 85B evidence + vendor docs              | Test Summary spreadsheet + VE package ([NPIVP_VENDOR_EVIDENCE.md](NPIVP_VENDOR_EVIDENCE.md))  |

## Product posture (listing-oriented claims)

Use this table when filling an NPIVP Test Summary or answering “does the
product implement X?”. Claims must match the build and personalisation profile
actually submitted.

| Capability                                            | Posture                                                          | Notes                                                                                       |
| ----------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| PIV AID `A000000308000010000100`                      | Implemented                                                      | SELECT returns the APT; tag `AC` lists the SM suite (`27` or `2E`) whenever key `04` and its CVC are present, independent of VCI mode (SP 800-73-5 Part 2 §3.1.1) |
| Local PIN (`0x80`) / PUK (`0x81`)                     | Implemented                                                      | SP 800-73-5 length and retry caps enforced in config; the PUK is exactly 8 bytes; a disabled PUK returns `6A88` for CHANGE REFERENCE DATA and RESET RETRY COUNTER |
| Global PIN (`0x00`)                                   | Supported; every defined Discovery policy combination is covered | Document explicitly if listed                                                               |
| OCC (on-card comparison)                              | Out of scope                                                     | Not implemented and not claimed                                                             |
| VCI with pairing code                                 | Implemented                                                      | Discovery PIN Usage Policy bits; VERIFY key ref `0x98` over SM                              |
| VCI without pairing code                              | Implemented                                                      | Configurable VCI mode                                                                       |
| Secure messaging (OPACITY)                            | Implemented                                                      | Build-time **one** suite: CS2 (`0x27`) or CS7 (`0x2E`)                                      |
| Intermediate CVC                                      | Not a focused product claim                                      | Do not mark Tested without a defined multi-hop path and evidence                            |
| Key History object / retired KMKs (`0x82`–`0x95`)     | Slot model supported                                             | History **content** and full operational matrix require personalisation and test evidence   |
| Symmetric Card Authentication key                     | Not supported                                                    | Reference `9E` permits asymmetric signing only                                              |
| RSA-1024 (`0x06`)                                     | Still in code                                                    | **Not** appropriate for current SP 800-78-5 listing cells                                   |
| RSA-2048 (`0x07`), ECC P-256 (`0x11`), P-384 (`0x14`) | Implemented                                                      | Preferred asymmetric set for present-day listing                                            |
| RSA-3072 (`0x05`)                                     | **Implemented**                                                  | Advertised in the application property template and supported by the RSA key implementation |
| 3TDEA admin / default                                 | Still present                                                    | Deprecated through 2030; prefer AES for new listings                                        |
| AES-128/192/256 admin                                 | Implemented                                                      | Preferred for management key                                                                |
| OpenPhysical attestation (`INS F9`, key `F9`)         | Extension                                                        | Outside base NPIVP PIV data model; document separately ([ATTESTATION.md](ATTESTATION.md))   |

## Automated test coverage (repository CI)

### Coverage evidence boundary

`ant -f build/build.xml coverage` measures three profiles that together compile every
preprocessor branch (`standard-CS2-attestation`, `standard-CS7-no-attestation`,
`fips-CS2-attestation`) and enforces JaCoCo line and branch floors per profile, per-class floors for
the security-critical handlers, and a separate host-tool floor. The floors are ratchets set just
below the measured values; the current values are the `coverage.rules.*` properties in
`build/build.xml` (see [FIPS_AND_TEST_GAPS.md](FIPS_AND_TEST_GAPS.md#automated-release-gates)).
Coverage counts executed lines and branches only. Security boundaries,
failure paths, cryptographic state transitions, transaction behavior, and platform primitives are
tracked through the requirement-specific tests and external gates below.

### Secure-messaging release gate

A releasable source revision must pass `ant -f build/build.xml test-all`. That target builds and
executes the complete isolated matrix, with slow secure-messaging and VCI tests enabled:

- standard and FIPS candidate profiles;
- OPACITY cipher suites CS2 and CS7; and
- attestation enabled and disabled.

All eight profiles must finish successfully. A passing default CS2 run, a unit-vector-only run, or
an aborted simulator test does not substitute for this gate. Release evidence must retain each
profile's CAP, build log, and JUnit XML directory from `build/matrix/`.

Primary suites live under `src/dev/mistial/tests/` and
`src/dev/mistial/tool-tests/`. Run with:

```sh
ant -f build/build.xml test
ant -f build/build.xml test-all   # includes slow tests / suite matrix
```

### Repository Test Coverage

- Command dispatch, P1/P2 rejection, unprovisioned GET DATA (`6A82`)
- Local PIN VERIFY / CHANGE REFERENCE DATA / RESET RETRY COUNTER status-word
  behaviour (including several SP 800-73-5 “either 6A80 or 63Cx” cases), the disabled-PUK `6A88`
  response, and retry-counter restoration after a PIN-history or platform rejection; a
  table-driven matrix across malformed, wrong, blocked, contactless, VCI and intermediate-reserve
  conditions; an unprovisioned (install-time) PUK that matches fails as a mismatch (`63CX`,
  counter decremented)
- Administrative entry points over contactless keep their status words: `6982` for the GP secure
  channel and proprietary `80 24`/`80 25`, `6A81` for PUT DATA and GENERATE ASYMMETRIC KEY PAIR
  (SP 800-73-5 Part 2 Section 3)
- GET RESPONSE bound to the class family of the initiating command: a GP SCP GET RESPONSE
  continues only a response started under GP SCP (otherwise `6985`) and never releases a pending
  PIV secure-messaging response
- Rejection of non-minimal BER-TLV length encodings on every incoming TLV path, including the
  streamed secure-messaging `87` object (`6988`); shortest-form lengths in every `TLVWriter` output
- Seeded property tests of SM unwrap, command chaining and GET/PUT DATA against reference models
- Imported EC public points validated on the curve (`6A80`, partial import cleared)
- Config rejection of non-conformant PIN/PUK retry (>10) and PIN length bounds
- Management key (9B) GENERAL AUTHENTICATE and CHANGE REFERENCE DATA
- Selected GENERAL AUTHENTICATE paths (RSA key transport, ECC signature shapes,
  symmetric admin)
- VCI / OPACITY / secure messaging (CS2 default and CS7 matrix), Discovery VCI
  bits, contactless VCI access modes
- Single-key slot invariants and retired-slot range handling
- Host-side SP 800-85A **checklist fragments** for pairing length/charset and SM
  constants (`OpenFIPS201Sp80085aSmVciChecklistTest`) — not a certified 85A harness

### Remaining Coverage

Repository tests cover the applet policy and negative paths listed below. These areas still require
physical-card or listing-quality evidence for an NPIVP or SP 800-85A/B campaign.

The emulator tests are implementation evidence for the named paths. They do not cover every
SP 800-85A assertion or every claimed key-reference, algorithm, and role combination. The table
keeps those untested or externally tested areas explicit.

#### SP 800-85A — card command interface

| Theme                               | Gap                                                                                                              |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| SELECT                              | Actual multi-application ICC selection, re-selection, nonexistent AID behavior, and security-state transitions   |
| GET DATA + ACRs                     | Final personalized-card captures across contact, contactless, and VCI for every claimed object policy            |
| Global PIN                          | Actual platform Global PIN behavior and cross-application persistence                                            |
| Contactless intermediate retry      | Physical dual-interface exhaustion with preservation of the issuer's final contact retry                         |
| RESET RETRY COUNTER                 | Physical-card retry, blocked-PUK, and tear behavior across the claimed policy                                    |
| GENERAL AUTHENTICATE                | Every claimed keyRef × algorithm × role on the target platform, including latency and interrupted-chain behavior |
| GENERATE ASYMMETRIC KEY PAIR        | Physical provider encodings, replacement, tear behavior, and every claimed algorithm                             |
| Optional Discovery PIN Usage Policy | Physical VCI profiles and middleware interoperability for each claimed policy combination                        |

#### SP 800-85B — data model

The installed NIST SP 800-73-4 Test Runner includes four official SP 800-85B
`CHECK_*` groups. `run-nist-data-model.sh` executes them headlessly against the
positive GSA images and preserves JUnit XML, full logs, and a TSV matrix summary:

| Official group               | Assertions exercised                                                                     |
| ---------------------------- | ---------------------------------------------------------------------------------------- |
| `CHECK_BER_TLV_conformance`  | CCC, CHUID, Printed Information, certificate containers, Security Object, Key History    |
| `CHECK_signed_data_elements` | CHUID, biometric, and Security Object CMS structures, signatures, attributes, and hashes |
| `CHECK_biometric_data`       | CBEFF and fingerprint/facial data constraints                                            |
| `CHECK_certificate_profile`  | key usage, EKU, policy, AIA/SAN, expiry, and on-card private-key correspondence          |

Attestation tests validate the **OpenPhysical attestation certificate profile**,
not FIPS 201 PIV Authentication / Digital Signature / Key Management / Card
Authentication certificate profiles.

#### NPIVP algorithm × key listing matrix

The emulator suite exercises the implemented policy and representative operations. A listing still
needs each claimed cell reproduced on the target card platform:

| Key                   | Listing expectation                     | CI posture                                                                            |
| --------------------- | --------------------------------------- | ------------------------------------------------------------------------------------- |
| `04` SM               | CS2 and/or CS7                          | Covered in one suite per CAP; physical platform evidence pending                      |
| `9A`                  | Claimed algs only                       | Emulator algorithm/role paths covered; physical matrix pending                        |
| `9B`                  | AES preferred; 3TDEA compatibility only | Emulator admin paths covered; physical matrix pending                                 |
| `9C` / `9D` / `9E`    | Claimed algs only                       | Emulator signature/key-establishment/card-auth paths covered; physical matrix pending |
| Retired KMK `82`–`95` | Max retired count + ops                 | Emulator slot and key-establishment paths covered; physical matrix pending            |

## External tools (not wired into `ant test`)

### NIST PIV Test Runner (interface-oriented)

Configuration and notes: [tools/piv_test_runner/README.md](../tools/piv_test_runner/README.md).

- Obtained from NIST CSRC PIV downloads (password via `piv-dmtester@nist.gov`).
- Repository configs intentionally **narrow** optional filters and disable many
  blocking tests for routine development runs.
- A listing-quality run requires a fully pre-personalised and personalised card,
  reader selection, and re-enabling of tests that match the claimed feature set.

### NIST PIV Data Model testing (SP 800-85B)

- Validates content of personalised containers (CHUID, biometrics, certs,
  Security Object, etc.).
- Integrated into the headless emulator harness through `run-nist-data-model.sh`,
  but not invoked by the routine `ant test` target.
- Requires issuer golden data (or NIST test personalisation material) that
  matches SP 800-78 and FIPS 201 certificate/biometric profiles.

## External release and validation gates

### Gate 1: SP 800-85A and NPIVP interface evidence

Freeze the source commit, exact CAP and SHA-256 digest, profile sidecar, platform descriptor,
personalisation inputs, reader model, card platform, and Test Runner version/configuration. Run the
official NIST PIV Test Runner against disposable, fully personalised physical cards over every
claimed interface. Every applicable vector must pass; an applicable test may not be filtered,
disabled, aborted, or replaced with an emulator assertion.

The submission configuration must also exercise application selection on the actual multi-app card:
initial PIV SELECT, repeated PIV SELECT, selection of another installed application, PIV re-selection,
and selection of a nonexistent AID. Retain status words and evidence that PIV application security
state is preserved or cleared as SP 800-73 requires.

### Gate 2: Claimed key and algorithm matrix

Exercise every claimed combination of key reference, algorithm, legal role, and operation. This
includes key `04`, keys `9A` through `9E`, every claimed retired key-management slot `82` through
`95`, and extension key `F9` in a separate non-NPIVP matrix. Cover generation and import where each
is supported (`F9` is generation-only in every profile; `9A` and `9C` are generation-only in the FIPS
profile), plus contact, contactless, and secure-messaging access policy. Sampled algorithms or
one representative slot do not establish the other listing cells.

### Gate 3: SP 800-85B personalised-card evidence

Run the official NIST runner's data-model groups against the final personalised physical-card profile.
The checked-in corpus under `test-vectors/sp800-85b-personalization/` freezes issuer inputs only; it
does not contain synthetic card objects and is not runner evidence by itself. Retain the runner
version and configuration, complete results, actual GET DATA captures, CMS verification evidence,
CBEFF and certificate-profile results, and input-to-card consistency checks. Keep secrets outside
the evidence archive.

### Gate 4: FIPS 140 / CMVP evidence

Bind the exact FIPS-profile CAP to the claimed Java Card platform and module boundary, approved
algorithm implementations, entropy evidence, integrity mechanism, startup and conditional
self-tests, and the laboratory/CMVP evidence required for the target validation.

## Evidence Priorities

Priority items for formal listing evidence:

1. **Golden personalisation profile** for the seven mandatory interoperable
   objects plus claimed optionals, with ACRs per SP 800-73-5 Part 1.
2. **SP 800-85B host assertions** (structure + CMS verify + key-to-cert binding)
   over GET DATA of that profile.
3. **Full ACR GET DATA matrix** (contact / contactless / VCI).
4. **Contactless intermediate retry and blocked PIN/PUK** status-word evidence.
5. **GENERAL AUTHENTICATE chain-interrupt rollback** evidence.
6. **Vendor evidence package** for every VE row claimed Pass
   ([NPIVP_VENDOR_EVIDENCE.md](NPIVP_VENDOR_EVIDENCE.md)).
7. Parameterized **keyRef × algorithm** operational evidence for every NPIVP
   matrix cell claimed.
8. Explicit listing of **Global PIN**, **Key History**, and **Intermediate CVC**
   as Yes/No with matching evidence — never silent defaults.
9. Prefer **AES** management keys and **RSA-2048 / RSA-3072 / ECC** in listing
   materials; do not claim RSA-1024. OCC is out of scope.

## Related documents

- [FIPS_AND_TEST_GAPS.md](FIPS_AND_TEST_GAPS.md) — FIPS-profile product gaps, test
  gaps, and the macOS emulator plan for GSA ICAM + NIST headless suites
- [NPIVP_VENDOR_EVIDENCE.md](NPIVP_VENDOR_EVIDENCE.md) — VE checklist text for
  vendor documentation submissions
- [CONFORMANCE_PROVISIONING.md](CONFORMANCE_PROVISIONING.md) — GSA ICAM
  provisioning onto the emulator
- [ATTESTATION.md](ATTESTATION.md) — OpenPhysical attestation extension
- [OPENFIPS201_TOOL.md](OPENFIPS201_TOOL.md) — host tooling
- [tools/piv_test_runner/README.md](../tools/piv_test_runner/README.md) — NIST
  Test Runner setup
- Repository root [README.md](../README.md) — build, VCI suite selection, layout
