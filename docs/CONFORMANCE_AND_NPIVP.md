# Conformance, NPIVP, and Data-Model Testing

This document records how OpenFIPS201 (OpenPhysical fork) maps to NIST PIV
specifications, what automated tests cover today, and what remains for formal
NPIVP listing and SP 800-85B data-model validation.

The scope is the OpenFIPS201 OpenPhysical fork in this repository.

## Reference specifications

| Layer | Specification | Primary concern for this applet |
| ----- | ------------- | ------------------------------- |
| Credential policy | FIPS 201-3 | What a PIV identity is |
| Card application namespace / objects | SP 800-73-5 Part 1 | Mandatory/optional objects, Discovery, ACRs, VCI policy bits |
| Card command interface | SP 800-73-5 Part 2 | SELECT, GET/PUT DATA, VERIFY, CHANGE REFERENCE DATA, RESET RETRY COUNTER, GENERAL AUTHENTICATE, GENERATE ASYMMETRIC KEY PAIR, secure messaging |
| Algorithms and key sizes | SP 800-78-5 | Algorithm identifiers, phase-outs (e.g. 3TDEA, RSA-1024) |
| Biometrics | SP 800-76-2 | Fingerprint / face / iris encodings (content, not applet parsing) |
| Card / middleware interface tests | SP 800-85A-4 | NPIVP command-interface and related assertions |
| PIV data model tests | SP 800-85B (and draft SP 800-85B-4) | BER-TLV structure, CMS signatures, biometrics, certificate profiles |
| Listing form | NIST NPIVP Test Summary (e.g. `Test-SummaryNPIVP.xlsx`) | Algorithm matrix, optional features, vendor evidence (VE) rows |

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

| System under test | Primary standards | Typical tooling |
| ----------------- | ----------------- | --------------- |
| Applet CAP + command logic | SP 800-73-5, SP 800-78-5, parts of SP 800-85A | JUnit / JCardEngine (`ant test`), NIST PIV Test Runner configs under `tools/piv_test_runner/` |
| Fully personalised card + issuer content | SP 800-85B / 85B-4 data model | Official runner `CHECK_*` groups on emulator; physical-card report remains external |
| NPIVP product listing | 85A + 85B evidence + vendor docs | Test Summary spreadsheet + VE package ([NPIVP_VENDOR_EVIDENCE.md](NPIVP_VENDOR_EVIDENCE.md)) |

## Product posture (listing-oriented claims)

Use this table when filling an NPIVP Test Summary or answering “does the
product implement X?”. Claims must match the build and personalisation profile
actually submitted.

| Capability | Posture | Notes |
| ---------- | ------- | ----- |
| PIV AID `A000000308000010000100` | Implemented | SELECT returns Application Property Template (APT) |
| Local PIN (`0x80`) / PUK (`0x81`) | Implemented | SP 800-73-5 length and retry caps enforced in config |
| Global PIN (`0x00`) | Supported; every defined Discovery policy combination is covered | Document explicitly if listed |
| OCC (on-card comparison) | Out of scope | Not implemented and not claimed |
| VCI with pairing code | Implemented | Discovery PIN Usage Policy bits; VERIFY key ref `0x98` over SM |
| VCI without pairing code | Implemented | Configurable VCI mode |
| Secure messaging (OPACITY) | Implemented | Build-time **one** suite: CS2 (`0x27`) or CS7 (`0x2E`) |
| Intermediate CVC | Not a focused product claim | Do not mark Tested without a defined multi-hop path and evidence |
| Key History object / retired KMKs (`0x82`–`0x95`) | Slot model supported | History **content** and full operational matrix require personalisation and test evidence |
| Symmetric Card Authentication key | Possible | Deprecated in SP 800-78-5; Test Runner default config often disables it |
| RSA-1024 (`0x06`) | Still in code | **Not** appropriate for current SP 800-78-5 listing cells |
| RSA-2048 (`0x07`), ECC P-256 (`0x11`), P-384 (`0x14`) | Implemented | Preferred asymmetric set for present-day listing |
| RSA-3072 (`0x05`) | **Implemented** | Advertised in the application property template and supported by the RSA key implementation |
| 3TDEA admin / default | Still present | Deprecated through 2030; prefer AES for new listings |
| AES-128/192/256 admin | Implemented | Preferred for management key |
| OpenPhysical attestation (`INS F9`, key `F9`) | Extension | Outside base NPIVP PIV data model; document separately ([ATTESTATION.md](ATTESTATION.md)) |

## Automated test coverage (repository CI)

### Coverage evidence boundary

`ant -f build/build.xml coverage` enforces an **80% applet line-coverage floor**, based on the
measured simulator baseline. The metric records executed source lines. Security boundaries,
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
  behaviour (including several SP 800-73-5 “either 6A80 or 63Cx” cases)
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

These areas require additional evidence for an NPIVP or SP 800-85A/B campaign.

#### SP 800-85A — card command interface

| Theme | Gap |
| ----- | --- |
| SELECT | Full APT BER-TLV validation; re-SELECT preserves or clears security status per AS05.09–11; invalid AID behaviour on multi-app ICC |
| GET DATA + ACRs | Matrix over mandatory OIDs with Always / PIN / PIN Always / VCI / Never on contact vs contactless |
| Global PIN | VERIFY / CHANGE / Discovery policy combinations |
| Contactless intermediate retry | Dedicated exhaustion test proves VERIFY returns `6983` and preserves the issuer's final contact retry |
| RESET RETRY COUNTER | Full blocked-PUK, optional PUK-counter-reset policy, success-state matrix |
| GENERAL AUTHENTICATE | Full keyRef × alg × role matrix; **interrupted chain rollback** (AS05.36C) |
| GENERATE ASYMMETRIC KEY PAIR | Public-key encoding, replace-existing, admin gating, alg matrix |
| Optional Discovery PIN Usage Policy | Complete local/global/VCI bit combinations beyond VCI pairing bits |

#### SP 800-85B — data model

The installed NIST SP 800-73-4 Test Runner includes four official SP 800-85B
`CHECK_*` groups. `run-nist-data-model.sh` executes them headlessly against the
positive GSA images and preserves JUnit XML, full logs, and a TSV matrix summary:

| Official group | Assertions exercised |
| -------------- | -------------------- |
| `CHECK_BER_TLV_conformance` | CCC, CHUID, Printed Information, certificate containers, Security Object, Key History |
| `CHECK_signed_data_elements` | CHUID, biometric, and Security Object CMS structures, signatures, attributes, and hashes |
| `CHECK_biometric_data` | CBEFF and fingerprint/facial data constraints |
| `CHECK_certificate_profile` | key usage, EKU, policy, AIA/SAN, expiry, and on-card private-key correspondence |

Attestation tests validate the **OpenPhysical attestation certificate profile**,
not FIPS 201 PIV Authentication / Digital Signature / Key Management / Card
Authentication certificate profiles.

#### NPIVP algorithm × key listing matrix

CI exercises **samples** of algorithms, not a complete NPIVP grid:

| Key | Listing expectation | CI posture |
| --- | ------------------- | ---------- |
| `04` SM | CS2 and/or CS7 | Covered per build; not both suites in one CAP |
| `9A` | Claimed algs only | Limited operational tests |
| `9B` | AES preferred; 3TDEA legacy | Admin-path coverage present |
| `9C` / `9D` / `9E` | Claimed algs only | Limited |
| Retired KMK `82`–`95` | Max retired count + ops | Slot create/delete; not full crypto matrix |

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
is supported, plus contact, contactless, and secure-messaging access policy. Sampled algorithms or
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

- [FIPS_AND_TEST_GAPS.md](FIPS_AND_TEST_GAPS.md) — FIPS_MODE product gaps, test
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
