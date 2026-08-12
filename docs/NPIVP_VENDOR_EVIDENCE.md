# NPIVP Vendor Evidence (VE) Checklist

NIST NPIVP listings require **vendor documentation** that states how the card
application implements specific SP 800-73 / SP 800-85A assertions. The NPIVP
Test Summary workbook (e.g. `Test-SummaryNPIVP.xlsx`, sheet **VE Requirements**)
lists these as `VExx.yy…` identifiers.

This file is a **documentation template** for the OpenFIPS201 OpenPhysical fork
in this repository. It is not an upstream `makinako/OpenFIPS201` vendor evidence
package. Fill the **Vendor statement** column (or a linked product manual
section) before submission. Status values:

| Status | Meaning |
| ------ | ------- |
| Draft | Text below is a starting point for the OpenFIPS201 OpenPhysical fork; refine for the exact CAP, config, and personalisation profile under test |
| N/A | Feature not claimed (document why) |
| Pass | Statement reviewed and matches product + tests |
| Fail | Known gap; do not claim Pass on the listing form |

References use SP 800-73-4 / 85A-4 numbering as on common NPIVP forms; map to
SP 800-73-5 clause text when preparing a 73-5-based submission.

Related: [CONFORMANCE_AND_NPIVP.md](CONFORMANCE_AND_NPIVP.md).

---

## Platform and security status

| ID | Requirement (summary) | Status | Vendor statement (draft) |
| -- | --------------------- | ------ | ------------------------ |
| VE01.08.01 | Default selected card application | Draft | Document whether the ICC selects the OpenFIPS201 OpenPhysical fork by default after ATR/reset, or requires SELECT. The OpenPhysical fork is a loadable applet; default selection is a **card platform** configuration, not fixed by the CAP alone. |
| VE01.16.01 | Application security status indicators set FALSE when currently selected application changes | Draft | When another application becomes selected, PIV application security status indicators are cleared per deselect behaviour in the PIV Card Application (see SP 800-73 Part 2 SELECT security-status rules). Document platform multi-app behaviour. |
| VE01.16A-R4.01 | Which indicators are application vs global | Draft | **Application security status:** PIV Card Application PIN (`0x80`), PUK (`0x81`), pairing code (`0x98`), PIV Card Application Administration Key (`0x9B`). **Global security status:** Global PIN (`0x00`) when used. OCC is out of scope for this fork. |

## Data objects and algorithms

| ID | Requirement (summary) | Status | Vendor statement (draft) |
| -- | --------------------- | ------ | ------------------------ |
| VE02.03.01 | List all data objects present and BER-TLV tags | Draft | Objects are **not** fixed at install. After personalisation, list every created object with its card-command tag (e.g. CCC `5FC107`, CHUID `5FC102`, Discovery `7E`, cert containers per SP 800-73 Part 1). Attach the pre-personalisation profile used for the NPIVP card. |
| VE03.01.01 | List algorithm identifiers supported | Draft | Supported mechanism IDs in the applet include: `00`/`03` 3TDEA-ECB (deprecated), `05` RSA-3072, `06` RSA-1024 (legacy; not for current 78-5 listing), `07` RSA-2048, `08`/`0A`/`0C` AES-128/192/256-ECB, `11` ECC P-256, `14` ECC P-384, `27` CS2 SM, `2E` CS7 SM. A given CAP is built for **one** SM suite (CS2 or CS7). Publish only algorithms claimed on the Test Summary matrix. |
| VE03.09-R4.01 | Export of biometric reference data not allowed | N/A | OCC is out of scope. This fork does not implement or claim OCC and does not enroll biometric reference templates for on-card comparison. |

## SELECT and application identity

| ID | Requirement (summary) | Status | Vendor statement (draft) |
| -- | --------------------- | ------ | ------------------------ |
| VE05.05.01 | PIV Card Application Identifier | Draft | AID: `A0 00 00 03 08 00 00 10 00 01 00` (RID NIST + PIX PIV Card Application + version). |
| VE05.06.01 | Only one PIV Card Application on the ICC | Draft | Issuance policy: only one instance of the PIV Card Application AID is loaded/selected on the ICC under test. Platform load procedures must enforce this. |
| VE05.07.01 | Valid AIDs and SELECT mechanisms | Draft | Full AID SELECT by DF name; document whether partial/right-truncated AID SELECT is supported by the platform and applet. Provide the list of AIDs used in the NPIVP configuration. |
| VE05.09.01 | Re-SELECT of PIV AID leaves security status unchanged | Draft | State compliance with SP 800-73: if PIV is already selected and SELECT names the PIV AID (or supported right-truncated form), the application remains selected and PIV security status indicators are **unchanged**. |
| VE05.10.01 | SELECT with unsupported AID leaves PIV selected and status unchanged | Draft | State that an invalid/unsupported AID does not deselect PIV or clear PIV security status when PIV was already selected (platform + applet behaviour as tested). |
| VE05.11.01 | SELECT of another valid application deselects PIV and clears PIV security status | Draft | State that selecting a different application clears PIV application security status indicators as required. |

## Discovery, PIN policy, contactless

| ID | Requirement (summary) | Status | Vendor statement (draft) |
| -- | --------------------- | ------ | ------------------------ |
| VE05.12A.01 | GET DATA returns object only if ACR satisfied | Draft | GET DATA evaluates contact vs contactless access modes (including VCI). Unsatisfied security condition returns `6982`. Unprovisioned object returns `6A82`. |
| VE05.13.01 | Discovery Object when Global PIN and App PIN both used | Draft | If both Global PIN and PIV Application PIN are used, Discovery Object and PIN Usage Policy bits shall be present and documented (see SP 800-73 Part 1 Table for PIN Usage Policy). |
| VE05.13A-R4.01 | OCC and BIT Group Template | N/A | OCC is out of scope; BIT Group Template is not used for OCC authentication. |
| VE05.13B-R4.01 | VCI requires Discovery Object with policy bits | Draft | When VCI is enabled, Discovery Object (`7E`) is created/maintained with PIN Usage Policy bit 4 set for VCI; bit 3 encodes pairing required vs not required per SP 800-73-5. |
| VE05.14.01 | Local PIN key reference `80` | Draft | Key reference `80` is the PIV Card Application PIN, verifiable with VERIFY. |
| VE05.16.01 | Discovery / pairing interactions as implemented | Draft | Document pairing code length (8 ASCII digits), VERIFY with P2=`98` only over secure messaging/VCI path as implemented, and status words (`6300` for wrong pairing code where applicable). |
| VE05.17.01 | Retry counter zero → operation blocked | Draft | When retries remaining is zero for PIN/PUK, further VERIFY/CHANGE that would use that reference fail with `6983` (blocked). |
| VE05.18.01 / VE05.18A-R4.01 | Contactless restrictions for PIN / OCC | Draft | Document that PIN over contactless requires SM/VCI as configured; intermediate retry threshold yields `6983` without further decrement as specified. OCC is out of scope. |
| VE05.19.01 | Wrong PIN decrements retry / sets status FALSE | Draft | Well-formed incorrect PIN returns `63CX` and decrements retries; security status for that reference is FALSE. |

## VERIFY / CHANGE REFERENCE DATA / RESET RETRY COUNTER

| ID | Requirement (summary) | Status | Vendor statement (draft) |
| -- | --------------------- | ------ | ------------------------ |
| VE05.22A.01 | PIN padding and charset | Draft | PIV Application PIN: 8-byte field, significant digits ASCII `0`–`9`, padded with `FF`; minimum significant length configurable but not below 6 and not above 8 per SP 800-73-5 enforcement. Pairing code: exactly 8 ASCII digits, no `FF` padding. |
| VE05.22B.01 | Unsupported key reference → `6A88` | Draft | VERIFY/CHANGE with unsupported P2 key reference returns `6A88`. |
| VE05.22C-R4.01 | VERIFY reset security status (P1=`FF`) | Draft | VERIFY with P1=`FF` resets security status for the key reference without changing the reference data or retry counter (document exact P1 encoding supported). |
| VE05.22D-R4.01 | Malformed vs wrong PIN status words | Draft | Malformed PIN encoding: `6A80` without retry decrement. Wrong value with valid encoding: `63CX` with decrement. |
| VE05.23.01 | CHANGE REFERENCE DATA key refs | Draft | Document allowed P2 values (Application PIN, PUK, admin key change path as implemented). |
| VE05.24A-R4.01 | Contactless CHANGE restrictions | Draft | CHANGE REFERENCE DATA for PIN over contactless requires VCI/SM per product policy; plaintext contactless PIN change is rejected (`6982`) even if contactless PIN change config flags are considered — document exact behaviour under test. |
| VE05.25.01 | Retry zero / intermediate contactless → `6983` | Draft | Document issuer intermediate retry values for contactless and blocked behaviour. |
| VE05.25A-R4.01 | Combined invalid CHANGE cases | Draft | Document mapping to `6A80` vs `63CX` when old and/or new reference data are wrong or malformed (SP 800-73-5 allows specified combinations). |
| VE05.26.01 | Successful CHANGE sets status TRUE and resets retries | Draft | On success, security status TRUE and retry counter restored to reset value. |
| VE05.27.01 | `63CX` on CHANGE sets status FALSE and decrements | Draft | As specified. |
| VE05.28A.01 | Unsupported CHANGE key ref → `6A88` | Draft | As specified. |
| VE05.29.01 | RESET RETRY COUNTER P2 = Application PIN | Draft | P2 identifies the PIN being unblocked (Application PIN). Unsupported P2 → `6A88`. |
| VE05.30.02 | PUK retries zero → `6983`, PIN not reset | Draft | Document blocked PUK behaviour. |
| VE05.31.02 | Successful reset restores PIN retries; optional PUK retry restore | Draft | State whether PUK retry counter is restored on success. |
| VE05.32.01 | Wrong PUK → `63CX`, PIN status FALSE, PUK retries decrement | Draft | As specified. |
| VE05.33.01 | Combined invalid PUK/new PIN | Draft | Either `6A80` or `63CX` when both wrong; if `6A80`, PUK retries and PIN status unchanged. |

## Cryptographic commands and secure messaging

| ID | Requirement (summary) | Status | Vendor statement (draft) |
| -- | --------------------- | ------ | ------------------------ |
| VE05.34.01 | Cryptographic operations supported | Draft | List roles actually offered: authentication (challenge/response), signatures, RSA key transport / ECDH key establishment, OPACITY secure messaging establishment. Attestation (`F9`) is an OpenPhysical extension — list only if in scope for the product claim, not as NPIVP mandatory PIV crypto. |
| VE05.36.01 | Invalid alg/key ref → `6A86` (or product’s specified SW where 73-5 distinguishes `6A88`) | Draft | Document exact status words for invalid P1/P2 combinations (the OpenPhysical fork uses `6A88` for unknown key reference and `6A86` for incorrect P1/P2 in several paths — align statements with measured SW). |
| VE05.36A.01 | Invalid command data → `6A80` | Draft | Malformed Dynamic Authentication Template / TLV → `6A80`. |
| VE05.36B.01 | PIN-protected key without prior PIN → `6982` | Draft | GENERAL AUTHENTICATE on PIN-gated keys without satisfied PIN returns `6982`. |
| VE05.36C.01 | Interrupted GENERAL AUTHENTICATE chain rolls back | Draft | Document that a non-chaining command interrupting a GENERAL AUTHENTICATE chain restores pre-chain state. **Provide test evidence;** treat as a known CI gap until demonstrated. |
| VE05.37.01 | PUT DATA format and parameters | Draft | Normal PUT DATA: P1=`3F`, P2=`FF`, tag list `5C` + data `53` (and Discovery/biometric addressing as implemented). Administrative create/delete/config: P2=`00` under GlobalPlatform secure channel. See `docs/asn1/` and pre-personalisation guide. |
| VE05.38.01 | Implemented algorithm identifiers | Draft | Same list as VE03.01.01, filtered to the listing matrix. |
| VE05.41-R4.01 | Whether secure messaging is implemented | Draft | **Yes** — OPACITY VCI secure messaging; one of CS2 or CS7 per CAP build (`vci.suite`). |
| VE05.42-R4.01 | SM only via PIV SM key `04` and Part 2 protocol | Draft | Non-card-management SM is established only with key reference `0x04` using the SP 800-73 Part 2 OPACITY protocol and cipher suite advertised in the APT after SM key + CVC load. |

---

## How to use this checklist in a listing package

1. Freeze the **CAP build** (JC version, `vci.suite`, attestation on/off).
2. Freeze the **personalisation profile** (object list, ACRs, keys, algorithms).
3. For each VE row you will mark Pass on the Test Summary, copy a final
   statement into the formal vendor document and attach the test log that
   demonstrates it.
4. Mark OCC N/A. Mark Intermediate CVC, Key History, Global PIN, etc. as N/A
   unless that feature is truly in the claimed configuration.
5. Keep SP 800-85B data-model evidence in a separate annex (personalisation
   golden values + Data Model Tester results); VE rows above are primarily
   interface and documentation evidence.

## Document control

| Field | Value |
| ----- | ----- |
| Applies to | OpenFIPS201 OpenPhysical fork only |
| Companion | [CONFORMANCE_AND_NPIVP.md](CONFORMANCE_AND_NPIVP.md) |
| Code changes | None required by this document |
