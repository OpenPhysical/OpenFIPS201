# FIPS Compliance Gaps and Test Gaps

This document is the working map for **FIPS candidate (listing-oriented) readiness**
and for **running everything we can on macOS** against the OpenFIPS201 applet in the
in-process / ZeroMQ **jCard emulator**.

It complements:

- [CONFORMANCE_AND_NPIVP.md](CONFORMANCE_AND_NPIVP.md) — standards map, CI posture, external gates  
- [CONFORMANCE_PROVISIONING.md](CONFORMANCE_PROVISIONING.md) — GSA ICAM → emulator provision path  
- [NPIVP_VENDOR_EVIDENCE.md](NPIVP_VENDOR_EVIDENCE.md) — VE statement draft  
- [tools/piv_test_runner/README.md](../tools/piv_test_runner/README.md) — NIST Test Runner / headless harness  

**Product under discussion for certification claims:** the **`FIPS_MODE` CAP** (AES
admin, no RSA-1024/3TDEA in APT, Part 1 Table 5 key ACRs, contactless admin/RRC/PUK
hard-fail `6A81`, personalisation gate). The **standard** CAP remains an interop /
legacy build and is **not** the listing product.

**Goal of this plan:** maximize **GSA (ICAM / host CCT)** and **NIST (85A-style
card-command vectors)** coverage on **macOS**, using the **emulator + applet**, for
every assertion that does not require a physical multi-app ICC or a CMVP lab.

---

## 1. What “FIPS” means here

Three different “FIPS” labels are easy to conflate:

| Label | Meaning | Who owns it |
| ----- | ------- | ----------- |
| **FIPS 201-3** | Federal PIV identity policy (what a PIV credential is) | Issuer + host ecosystem |
| **FIPS_MODE CAP** | This fork’s compile-time **strict PIV candidate profile** (`FipsPolicy`) | Applet build + personalisation |
| **FIPS 140 / CMVP** | Cryptographic module validation of the JC platform + module boundary | Platform vendor + lab |

This document focuses on **FIPS_MODE CAP** gaps relative to SP 800-73-5 / SP 800-78-5
and on **test gaps** relative to SP 800-85A-4 card-application testing and GSA ICAM
interoperability. It does **not** claim a CMVP certificate path.

SP 800-85A-4 validates **PIV Card Application** command interface and object
accessibility (test toolkit → reader → card). Middleware API listing (`piv*`) is a
different product class. This applet is a **card application**, not middleware.

---

## 2. Target architecture on macOS

```text
┌─────────────────────────────────────────────────────────────────┐
│ macOS host                                                       │
│                                                                  │
│  ┌──────────────┐   APDU    ┌─────────────────────────────────┐ │
│  │ NIST headless│──────────▶│ jCardEngine emulator            │ │
│  │ harness      │ SmartcardIO│  (in-process or ZMQ serve)      │ │
│  │ (Java 8)     │           │  OpenFIPS201 applet class       │ │
│  └──────────────┘           └─────────────────────────────────┘ │
│                                                                  │
│  ┌──────────────┐   SCP03   ┌─────────────────────────────────┐ │
│  │ OpenFips201  │──────────▶│ same emulator endpoint          │ │
│  │ Tool / ICAM  │ provision │  (tcp://127.0.0.1:5555 optional)│ │
│  │ provisioner  │           └─────────────────────────────────┘ │
│  └──────────────┘                                                │
│                                                                  │
│  ┌──────────────┐   reader  ┌─────────────────────────────────┐ │
│  │ piv-conform. │──name────▶│ "OpenFIPS201 Emulator" (if CCT   │ │
│  │ / GSA CCT    │  PC/SC    │  can attach via ZMQ/PCSC bridge) │ │
│  └──────────────┘           └─────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

| Component | Mac status today |
| --------- | ---------------- |
| JDK 8 + Ant build / `ant test` / `ant test-all` | Works |
| jCardEngine (`tools/jcard-v*.jar`) | Works in-process and via `emulator serve` |
| `tools/provision-icam.sh` + `OpenFips201Tool` | Works on Mac for standard and **FIPS_MODE** CAPs + ICAM folders |
| NIST headless harness (`run-nist-harness.sh`) | Works on Mac; `--fips --icam DIR` provisions and tests one persistent image |
| NIST GUI Test Runner | Windows-oriented installer; **not required** if headless vectors cover card-app AS |
| Official NIST Data Model Tester / GSA CCT GUI | Often Windows-centric; host-side corpus + custom CCT against emulator is the Mac path |
| Physical dual-interface + multi-app SELECT | **Not** emulator-substitutable for final VE05.09–11 |

---

## 3. FIPS compliance gaps

These are gaps relative to a **claimable FIPS_MODE listing product**, not a list of
unfixed command-interface oracles. Recent work closed SM CLA `6982`, chain soft-abort,
key-`04` Case-6 ECDH rejection, Global PIN deselect, intermediate VERIFY status,
pairing Discovery binding, mutual-auth case priority, and RRC PIN-status preservation.

### 3.1 Closed in applet code (do not re-open as “FIPS gaps”)

| Topic | Status |
| ----- | ------ |
| SM CLA without session keys → `6982` | Implemented |
| Interrupted command chain soft-abort (plaintext + SM) | Implemented |
| Key `04` raw ECDH (tag `85`) rejected | Implemented |
| Plaintext re-establish only OPACITY Case 1A while SM live | Implemented |
| Global PIN survives PIV deselect; app PIN/PUK clear | Implemented |
| Empty VERIFY status uses contactless intermediate floor | Implemented |
| Pairing `98`: Discovery bits + contact Always / contactless SM | Implemented |
| FIPS contactless PUT / GENERATE / RRC / PUK CHANGE → `6A81` | Implemented |
| FIPS keyRef × role × alg gate (`FipsPolicy.allowsKeyDefinition`) | Implemented |
| FIPS interoperable object ACRs at create (`allowsObjectDefinition`) | Implemented |
| FIPS CS2 build rejects P-384 on 9C/9D/retired KM | Implemented |
| FIPS personalisation readiness gate before lifecycle lock | Implemented (structural) |
| ICAM Part 1 object/key access modes, including CCC VCI | Implemented and validated with GSA card 46 |
| FIPS ICAM provisioning in NIST harness | Implemented (`--fips --icam DIR`) |

### 3.2 Open FIPS / product gaps

#### F-1 — Closed: ICAM personalisation ACRs

`IcamCardFolder` now applies the Part 1 contact/contactless modes for CCC, SO,
biometrics, certificates, and keys. The real GSA card-46 folder provisions all 11
objects and four RSA-2048 keys into a FIPS_MODE emulator without a create failure.

#### F-2 — Personalisation readiness is structural, not SP 800-85B-deep

`isFipsPersonalizationReady()` requires mandatory objects, usable 9A/9E, CVMs, and
(when VCI) SM key+CVC+Discovery (+ pairing container if pairing mode). Cert containers
and Security Object have some structure checks; CCC/CHUID/biometrics can still be
well-formed TLV without content validity.

**Impact:** Lifecycle can lock without an 85B-credible golden profile.  
**Mitigation for Mac testing:** host `CertificationProfileValidator` + SO hash binding
already exist for preflight; wire them into every FIPS provision path and document that
full 85B remains external.

#### F-3 — SP 800-78-5 Table 10 is a hardened **subset**, not a full claim

| Table 10 item | FIPS CAP |
| ------------- | -------- |
| AES admin 9B | Yes |
| RSA-2048 / 3072 / P-256 / P-384 cardholder | Yes (no post-2030 drop of RSA-2048) |
| RSA-1024 retired KMK | **Blocked** (stricter) |
| 3TDEA admin / default | **Blocked** |
| Symmetric Card Auth on 9E | **Not definable** |
| SM 27 **and** 2E in one CAP | **No** — one suite per CAP |

**Claim language:** “FIPS-hardened subset of SP 800-78-5 Table 10 (through-2030 AES
admin + asymmetric cardholder; one OPACITY suite),” not “implements full Table 10.”

#### F-4 — Discovery content vs Security Object / dynamic policy

When Discovery is **stored** (issuer PUT), GET returns stored bytes and Global PIN /
pairing gates parse those bytes. When Discovery is **empty/uninitialised**, GET may
synthesise policy (without Global PIN). FIPS personalisation requires stored Discovery
when VCI is on.

**Gap for GSA path:** ICAM Discovery bytes must match FIPS-advertised VCI/pairing
policy and must match Security Object digests after any host rewrite.

#### F-5 — Standard CAP residual (listing footgun)

Non-FIPS builds still allow:

- GET DATA `P2=00` extended objects  
- CRD admin via interindustry `P1=FF`  
- Contactless RRC/PUK when config flags permit  
- APT advertising RSA-1024 / 3TDEA  

**Rule:** never submit standard CAP as the NPIVP product; Mac automation should build
and provision **FIPS_MODE** for “certification profile” runs.

#### F-6 — Attestation extension (out of NPIVP; FIPS matrix cell)

F9 attestation is OpenPhysical-only. RSA-3072 + ATTEST buffer sizing is a residual
extension issue. Keep attestation **off** for NPIVP card-app claims; matrix still
builds att on/off for product completeness.

#### F-7 — FIPS 140 / CMVP

Power-up self-tests and pairwise consistency checks support a module story; they are
**not** a CMVP certificate. Track under a separate Gate 4 (see CONFORMANCE_AND_NPIVP).

#### F-8 — Documentation drift

| Doc claim | Code reality |
| --------- | ------------ |
| Coverage floor 55% | `build/build.xml` enforces **80%** line |
| Some CONFORMANCE gap rows (chain interrupt, etc.) | Code fixed; docs lag |
| VE05.16 “pairing only over SM” | Contact Always + contactless SM implemented |

---

## 4. Test gaps

### 4.1 Inventory of what exists

| Layer | Mechanism | Mac? | Coverage |
| ----- | --------- | ---- | -------- |
| Applet unit / APDU JUnit | `ant test` (excludes `@Tag("slow")`) | Yes | Command SW samples, PIN, admin PUT, selected GA, VCI |
| Full matrix | `ant test-all` — 8 profiles (standard\|fips × CS2\|CS7 × att on\|off), includes slow SM | Yes | Release gate |
| Host VCI / OPACITY vectors | tool-tests (`OpenFIPS201Vci*`, SM checklist) | Yes | Strong for SM crypto KATs |
| ICAM provision | provisioner + NIST `--icam` | Yes | GSA card 46 on standard and FIPS_MODE |
| 85B issuer-input corpus | `test-sp80085b-corpus` / `test-vectors/sp800-85b-personalization/` | Yes | Inputs only, not card GET DATA |
| NIST headless harness | `tools/piv_test_runner/run-nist-harness.sh` | Yes | Personalised FIPS card-command vectors on one image |
| NIST GUI runner | External Windows install | Partial | Prefer headless on Mac |
| GSA piv-conformance / CCT | External host stack | Conditional | Needs provisioned emulator + trust material |
| Physical multi-app SELECT | Hardware | No on emulator | VE05.09–11 residual |
| Official 85B Data Model Tester | External | Often Windows | Emulator GET DATA captures can feed custom checks first |

### 4.2 NIST (SP 800-85A-style) gaps

Measured FIPS_MODE + GSA card-46 results on the in-process emulator:

- contact SELECT **2/2**, GET DATA **14/14**, VERIFY **15/15**, CRD **22/22**, RRC **17/17**, PUT DATA **11/11**;
- contactless SELECT **3/3**, GET DATA **11/11**, VERIFY **1/1**, CRD **6/6**, GENERATE **4/4**.

Remaining root causes are now isolated rather than a bare-card failure cascade:

1. **Direct administrative authentication** — legacy GENERATE contact vectors use 9B mutual authentication, while FIPS_MODE requires SCP03 for administrative commands.  
2. **RSA runner defect** — the official runner can feed a modulus-sized random integer outside the valid raw-RSA domain and throws `DataLengthException` before a useful product verdict.  
3. **SM profile material** — GSA card 46 does not advertise/provision VCI, so SM/virtual-contact suites are not applicable to that frozen profile.  
4. **Middleware vectors (`piv*`)** — require a middleware IUT and remain out of scope for this card application.  
5. **Some CHECK_\* TRUE are optional skips** — treat only requirement counts from applicable vectors as evidence.

| 85A / 73 theme | JUnit | Emulator NIST harness today | Target for Mac automation |
| -------------- | ----- | --------------------------- | ------------------------- |
| SELECT / APT | Partial | Contact and contactless pass | Physical multi-app residual |
| GET DATA + ACR | Partial | Contact and contactless pass for card 46 | Add VCI-enabled frozen profile |
| VERIFY / CRD / RRC | Strong samples | Applicable contact/contactless vectors pass | Preserve fresh image per destructive vector |
| GENERAL AUTHENTICATE | Samples | Official RSA runner blocked | Correct runner input domain or use independent vectors |
| GA chain interrupt | Code fixed; limited AS05.36C evidence | Not asserted | Dedicated harness/JUnit vector |
| GENERATE KEY PAIR | Partial | Fail / auth | Admin path under SCP on emulator |
| Secure messaging / VCI | Strong JUnit | Mostly fail | After SM key+CVC+Discovery provision |
| Multi-app SELECT | Gap | Gap | **Physical residual** |
| Full alg matrix | Gap | Gap | Parameterize configs per claimed cell |
| Middleware `piv*` | N/A | Fail | **Exclude** from card-app gate |

### 4.3 GSA ICAM / host gaps

| Item | Status |
| ---- | ------ |
| Load ICAM card-46 objects/keys onto **standard** CAP emulator | MVP documented green path |
| Load same onto **FIPS** CAP | Green: 11 objects + 4 RSA-2048 keys |
| Discovery/SO hash consistency after host rewrite | Tooling moving toward bind/validate; must be mandatory in FIPS path |
| VCI/SM materials from ICAM folder | **Not loaded** — need `VciProvisioning` (or profile sidecar) |
| Attestation F9 from ICAM | Out of scope for ICAM path |
| piv-conformance / CCT against “OpenFIPS201 Emulator” | Documented intent; depends on PC/SC or process bridge on Mac |
| Negative ICAM cards (tampered CHUID, etc.) | Loadable as-is for host negative tests once positive path green |

### 4.4 JUnit / CI residual gaps (even when NIST is green)

- Full ACR × OID × contact/contactless/VCI matrix  
- Full claimed keyRef × algorithm × role operational matrix  
- Global PIN full Discovery combinations (if claimed)  
- Contactless intermediate retry exhaustion on disposable scenarios  
- Multi-app deselect (cannot fully simulate platform multi-app)  
- Docs still listing some fixed items as “remaining”  

### 4.5 Explicitly not Mac-emulator complete

| Requirement | Why emulator is insufficient |
| ----------- | ---------------------------- |
| VE01 default selection after ATR | Platform policy |
| VE05.09–11 multi-app SELECT / invalid AID | Needs second real application on ICC |
| Contact vs contactless radio behaviour | Emulator media flags ≠ RF stack |
| Official NPIVP listing submission | Lab + physical card + unfiltered runner |
| FIPS 140 CMVP | Lab + platform boundary |
| Full SP 800-85B lab report | Official DMT + personalised content |

---

## 5. What we *can* make green on Mac (scope of work)

Prioritised so GSA and NIST exercise the **same personalised emulator image**.

### Phase A — FIPS golden personalisation on emulator (blocker for everything else)

1. **Done:** FIPS ACR map for ICAM and capacity preflight.  
2. **Build FIPS CAP** for the suite under test, e.g.  
   `ant -f build/build.xml compile` with FIPS + CS2 (or CS7) and **attestation off** for NPIVP-shaped runs.  
3. **Provision pipeline** (ZMQ or in-process):  
   - install applet  
   - create objects/keys with FIPS ACRs  
   - import/generate keys, PUT DATA bodies  
   - set PIN/PUK/9B to values used by NIST config  
   - load SM key `04` + CVC (+ pairing container if pairing claimed)  
   - run `CertificationProfileValidator`  
   - optional: personalise lifecycle tag when testing post-personalise behaviour  
4. **Smoke:** SELECT, VERIFY PIN, GET DATA CHUID/CCC/certs, GA Card Auth (`9E`).

**Exit criterion:** FIPS CAP + ICAM-46 (or frozen profile) fully provisioned on emulator without `6A80` create failures.

### Phase B — NIST headless card-app suite on Mac

1. New listing-oriented config, e.g. `tools/piv_test_runner/config/OpenFIPS201-FIPS-CS2.xml`:  
   - PIN/PUK/pairing match provisioned secrets  
   - `KEY_ALGORITHMS_*` match personalised keys  
   - `KEY_ALGORITHMS_SECURE_MESSAGING` = `27` (or `2E` for CS7)  
   - `KEY_ALGORITHMS_CARD_MANAGEMENT` = AES (`08`/`0A`/`0C`)  
   - align `GENERAL_AUTH_*` with actual algs (no RSA-vs-ECC mismatch)  
   - `OPTIONAL_TEST_FILTER` = claimed optionals only (or empty for full claim)  
   - enable blocking only on disposable runs  
2. **Done:** `--fips --icam DIR` installs and provisions the same emulator image used by both transports.  
3. Run:  
   ```sh
   tools/piv_test_runner/setup-nist-tester.sh   # once; needs NIST password
   tools/piv_test_runner/run-nist-harness.sh \
     --target emulator \
     --config tools/piv_test_runner/config/OpenFIPS201-FIPS-CS2.xml \
     --suite contact \
     --out tools/piv_test_runner/piv_tests/fips-contact
   ```  
4. **Done:** use `--suite card-contact` / `card-contactless` to exclude middleware-only `piv*` suites.
5. **Done:** every harness run writes `<out>/nist-results.xml`; archive it with the console log outside git.

**Exit criterion:** All **card-application** contact vectors applicable to the claim pass on emulator; contactless suite pass under emulator media flags; failures triaged as real product bugs vs config/claim mismatches.

### Phase C — GSA / host path on Mac

1. ZMQ emulator + FIPS provision (Phase A).  
2. piv-conformance / CCT against reader name **OpenFIPS201 Emulator** (or documented bridge).  
3. Host trust material: real file copies of ICAM root/intermediate (no symlinks).  
4. Positive checks: SELECT, VERIFY, GET DATA, Card Auth verify against cert.  
5. Optional negative ICAM cards after positive is green.

**Exit criterion:** Documented one-command (or short script) path on Mac from clean tree → provisioned FIPS emulator → CCT smoke green.

### Phase D — Expand automated evidence (still Mac)

1. JUnit: full ACR matrix; claimed keyRef×alg GA matrix; AS05.36C interrupt cases.  
2. Host-side 85B structural checks over GET DATA of golden profile (CMS parse, key↔cert bind) — **not** a substitute for official DMT, but closes a Mac-testable gap.  
3. Promote VE Draft rows to Pass **only** with Phase B/C logs for the frozen CAP SHA.  
4. Fix docs: coverage 80%, closed code gaps, VE05.16 pairing wording.

### Phase E — Residual (not fully Mac-emulator)

1. Physical dual-interface card with same CAP + profile.  
2. Multi-app SELECT / security-status pack.  
3. Unfiltered lab NIST runner + formal 85B DMT if listing.  
4. CMVP if required.

---

## 6. Recommended frozen Mac test profiles

| Profile ID | CAP flags | Personalisation | NIST config | Purpose |
| ---------- | --------- | --------------- | ----------- | ------- |
| `mac-fips-cs2-icam46` | FIPS, CS2, att off | ICAM-46 + FIPS ACRs + AES 9B + SM materials if VCI claimed | FIPS-CS2 listing XML | Primary GSA+NIST dry run |
| `mac-fips-cs7-ecc` | FIPS, CS7, att off | ECC P-384 cardholder + CS7 SM | FIPS-CS7 XML | CS7 / P-384 claim cell |
| `mac-std-cs2-icam46` | standard, CS2 | Current ICAM path | Dev XML (existing) | Interop only; not listing |
| `mac-fips-cs2-att` | FIPS, CS2, att on | + F9 authority | Non-NPIVP extension suite | Product matrix only |

Secrets for automated runs (test-only, not production):

| Secret | Value used by StandardCardProfile / ICAM docs |
| ------ | ----------------------------------------------- |
| Local PIN | `123456` (padded `FF`) |
| PUK | `12345678` |
| Management 9B | AES-128 test key from StandardCardProfile |
| SCP03 | Emulator default test master key |

NIST configs must match these after provision.

---

## 7. Concrete engineering backlog (ordered)

| # | Work item | Unblocks |
| - | --------- | -------- |
| 1 | **Done:** FIPS ACR (+ capacity) map for ICAM / certification provisioner | F-1, Phase A |
| 2 | **Done:** harness selects and compiles **FIPS_MODE** explicitly | Phase A/B |
| 3 | **Done:** harness provisions PIN, PUK, objects, and keys before vectors | NIST FAIL cascade |
| 4 | Finish dedicated FIPS NIST XMLs for CS2/CS7 SM profiles | Phase B |
| 5 | **Done:** `card-<interface>` suite selector excludes middleware `piv*` | Honest pass rate |
| 6 | **Done:** harness builds FIPS, installs/provisions in-process, runs vectors, and writes JUnit XML | Developer UX |
| 7 | GSA CCT / piv-conformance smoke doc + trust material checklist | Phase C |
| 8 | JUnit ACR + keyRef×alg matrix expansion | CI evidence |
| 9 | Host-side 85B structure over GET DATA of golden profile | Partial 85B on Mac |
| 10 | Doc sync (coverage 80%, VE drafts, closed code gaps) | Process hygiene |
| 11 | Physical multi-app + lab 85A/85B (when ready for listing) | Phase E |

---

## 8. Success metrics

| Metric | Current (approx.) | Mac target (pre-lab) |
| ------ | ----------------- | -------------------- |
| FIPS CAP ICAM provision | **Passes** with GSA card 46 | Preserve as regression gate |
| NIST harness card-app contact (claimed) | Core applicable vectors pass; GA/admin incompatibilities classified | All applicable vectors pass |
| NIST middleware `piv*` | Fail | Explicitly out of scope / N/A |
| GSA ICAM CCT smoke | Manual / partial | Documented green on emulator |
| `ant test-all` 8-profile matrix | Release gate | Still green |
| VE claimable rows | Draft | Pass with attached Mac logs for frozen CAP |
| Official NPIVP listing | Not started | Physical + unfiltered (Phase E) |

---

## 9. Related commands (cheat sheet)

```sh
# Full JUnit matrix (includes FIPS × CS2/CS7 × attestation)
ant -f build/build.xml test-all

# Line coverage floor (80% in build.xml)
ant -f build/build.xml coverage

# Emulator + ICAM through the headless NIST harness
tools/piv_test_runner/run-nist-harness.sh \
  --fips --target emulator \
  --icam /path/to/46_Golden_FIPS_201-2_PIV \
  --config tools/piv_test_runner/config/OpenFIPS201-RSA2048.xml \
  --test SelectCommand:1 \
  --out tools/piv_test_runner/piv_tests/smoke
```

---

## 10. Document control

| Field | Value |
| ----- | ----- |
| Applies to | OpenFIPS201 OpenPhysical fork |
| Audience | Engineering working FIPS listing prep and Mac CI |
| Not a substitute for | Formal NPIVP Test Summary, lab reports, CMVP certificate |
| Companion | [CONFORMANCE_AND_NPIVP.md](CONFORMANCE_AND_NPIVP.md), [CONFORMANCE_PROVISIONING.md](CONFORMANCE_PROVISIONING.md), [NPIVP_VENDOR_EVIDENCE.md](NPIVP_VENDOR_EVIDENCE.md) |
