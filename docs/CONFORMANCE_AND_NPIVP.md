# Conformance, NPIVP, and Data-Model Testing

This document records how OpenFIPS201 (OpenPhysical fork) maps to NIST PIV
specifications, what automated tests cover today, and what remains for formal
NPIVP listing and SP 800-85B data-model validation.

It is documentation only: it does not change applet behaviour. Unless explicitly
stated otherwise, claims in this document apply only to the OpenFIPS201
OpenPhysical fork in this repository and should not be read as claims about the
upstream `makinako/OpenFIPS201` project.

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
| Fully personalised card + issuer content | SP 800-85B / 85B-4 data model | NIST PIV Data Model Tester / personalisation golden fixtures (not yet in CI) |
| NPIVP product listing | 85A + 85B evidence + vendor docs | Test Summary spreadsheet + VE package ([NPIVP_VENDOR_EVIDENCE.md](NPIVP_VENDOR_EVIDENCE.md)) |

## Product posture (listing-oriented claims)

Use this table when filling an NPIVP Test Summary or answering “does the
product implement X?”. Claims must match the build and personalisation profile
actually submitted.

| Capability | Posture | Notes |
| ---------- | ------- | ----- |
| PIV AID `A000000308000010000100` | Implemented | SELECT returns Application Property Template (APT) |
| Local PIN (`0x80`) / PUK (`0x81`) | Implemented | SP 800-73-5 length and retry caps enforced in config |
| Global PIN (`0x00`) | Supported in code | Prefer documenting explicitly if listed; CI coverage is limited |
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

`ant -f build/build.xml coverage` enforces a **55% applet line-coverage floor**. This is a
regression guard against broad test loss, chosen from the measured simulator baseline. It is not a
security target and must not be raised or lowered to imply assurance that the percentage cannot
provide.

The JaCoCo result does **not** prove that security boundaries, failure paths, cryptographic state
transitions, Java Card transaction behavior, or every supported platform primitive were exercised.
It is also not NPIVP, SP 800-85A, SP 800-85B, CMVP, or FIPS 140 validation evidence. Those claims
require the named external suites, complete requirement matrices, platform evidence, and retained
test artifacts described below.

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
| Contactless intermediate retry | Issuer intermediate retry → `6983` on VERIFY/CHANGE (logic exists; dedicated test coverage is limited) |
| RESET RETRY COUNTER | Full blocked-PUK, optional PUK-counter-reset policy, success-state matrix |
| GENERAL AUTHENTICATE | Full keyRef × alg × role matrix; **interrupted chain rollback** (AS05.36C) |
| GENERATE ASYMMETRIC KEY PAIR | Public-key encoding, replace-existing, admin gating, alg matrix |
| Optional Discovery PIN Usage Policy | Complete local/global/VCI bit combinations beyond VCI pairing bits |

#### SP 800-85B — data model

Personalised content validation is **not** automated in this repository:

| Area | Examples of missing assertions |
| ---- | ------------------------------ |
| BER-TLV objects | CCC data model number; CHUID FASC-N / GUID-UUID / expiry / signature field; Printed Information; cert container size/tags; Security Object; Key History |
| CMS / signatures | SignedData structure for CHUID, biometrics, Security Object; pivSigner-DN / pivFASC-N or Card UUID attributes; algorithm tables from SP 800-78 |
| Biometrics | CBEFF patron format; INCITS 378 fingerprint constraints; facial JPEG 2000 profile; iris (if claimed) |
| Certificate profiles | keyUsage / EKU / policy OIDs / AIA; SAN FASC-N or UUID; public key matches on-card key; expiry vs CHUID |

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
- **Not** integrated into this repository’s CI.
- Requires issuer golden data (or NIST test personalisation material) that
  matches SP 800-78 and FIPS 201 certificate/biometric profiles.

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

- [NPIVP_VENDOR_EVIDENCE.md](NPIVP_VENDOR_EVIDENCE.md) — VE checklist text for
  vendor documentation submissions
- [ATTESTATION.md](ATTESTATION.md) — OpenPhysical attestation extension
- [OPENFIPS201_TOOL.md](OPENFIPS201_TOOL.md) — host tooling
- [tools/piv_test_runner/README.md](../tools/piv_test_runner/README.md) — NIST
  Test Runner setup
- Repository root [README.md](../README.md) — build, VCI suite selection, layout
