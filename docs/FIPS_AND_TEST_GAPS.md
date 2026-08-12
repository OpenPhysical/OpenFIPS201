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

### Status snapshot (re-checked)

| Area | State |
| ---- | ----- |
| FIPS_MODE command-interface hygiene (SM CLA, chains, key `04`, CVM edges) | **Closed in applet** |
| FIPS ICAM ACR provision (GSA 37/46/47) | **Green** on emulator |
| Repo-owned GSA card-access smoke (`test-gsa-icam-smoke`) | **Green** (7 standard + 3 FIPS profiles) |
| NIST headless card-app contact/contactless (ICAM-46 + FIPS) | **Mostly green**; residuals classified (admin auth, RSA domain, dated cert, claim-inapplicable) |
| NIST VCI matrix CS2/CS7 (`run-nist-vci-matrix.sh`) | **SM 6/7, virtual-contact 3/7** per suite; classification gated |
| Official GSA CCT / piv-conformance headless | **Blocked in host stack** (JDK/Gradle/JPMS/resources) — not a card defect |
| Official 85B `CHECK_*` groups (`run-nist-data-model.sh`) | **Executed headlessly**; 530 vectors, 484 pass, 46 fixture/profile residuals |
| Physical multi-app SELECT, lab NPIVP, CMVP, physical-card 85B report | **Still external** |

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
| NIST data-model `CHECK_*` groups | Run headlessly on Mac through the installed official SP 800-73-4 package |
| GSA CCT GUI | Host-side corpus + custom CCT against emulator is the current Mac path |
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
(when VCI) SM key+CVC+Discovery (+ pairing container if pairing mode). Applet-side
readiness is structural; the host certification preflight supplies the deeper issuer-input checks.

**Impact:** Lifecycle can lock without an 85B-credible golden profile.
**Mitigation for Mac testing:** host `CertificationProfileValidator` now verifies the
detached CHUID CMS signature, uses its content-signing certificate to verify the
Security Object CMS signature, validates BA/LDS hashes, and exact-compares card GET DATA
readback. It also verifies certificate SKIDs and private-key/certificate bindings. Full 85B
policy semantics and certification remain external.

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

#### F-4 — Closed: Discovery content vs Security Object / dynamic policy

When Discovery is **stored** (issuer PUT), GET returns stored bytes and Global PIN /
pairing gates parse those bytes. When Discovery is **empty/uninitialised**, GET may
synthesise policy (without Global PIN). FIPS personalisation requires stored Discovery
when VCI is on.

`NativeVciProfile` replaces the legacy Discovery object, removes deprecated CHUID tag
0x32, creates the Part 1 pairing and SM signer containers, and re-signs both CHUID and
Security Object with one fresh content-signing key. Strict validation checks the CMS
signatures, LDS hashes, unsigned-object coverage, schemas, capacities, and Tables 2/5
ACRs before card mutation.

#### F-5 — Standard CAP residual (listing footgun)

Non-FIPS builds still allow:

- GET DATA `P2=00` extended objects  
- CRD admin via interindustry `P1=FF`  
- Contactless RRC/PUK when config flags permit  
- APT advertising RSA-1024 / 3TDEA  

**Rule:** never submit standard CAP as the NPIVP product; Mac automation should build
and provision **FIPS_MODE** for “certification profile” runs.

#### F-6 — Attestation extension (out of NPIVP; FIPS matrix cell)

F9 attestation is OpenPhysical-only. The response-buffer boundary is covered with the maximum
accepted issuer profile and RSA-3072, the largest supported subject public key. Keep attestation
**off** for NPIVP card-app claims; matrix still builds att on/off for product completeness.

#### F-7 — FIPS 140 / CMVP

Power-up self-tests and pairwise consistency checks support a module story; they are
**not** a CMVP certificate. Track under a separate Gate 4 (see CONFORMANCE_AND_NPIVP).

#### F-8 — Closed: documentation drift

The coverage floor, chain-interruption evidence, and pairing contact/contactless behavior are now
aligned across the conformance and vendor-evidence documents. Draft vendor rows remain Draft until
logs are attached to a frozen physical-card CAP; that status reflects missing external evidence,
not documentation disagreement with current code.

---

## 4. Test gaps

### 4.1 Inventory of what exists

| Layer | Mechanism | Mac? | Coverage |
| ----- | --------- | ---- | -------- |
| Applet unit / APDU JUnit | `ant test` (excludes `@Tag("slow")`) | Yes | Command SW samples, PIN, admin PUT, selected GA, VCI |
| Full matrix | `ant test-all` — 8 profiles (standard\|fips × CS2\|CS7 × att on\|off), includes slow SM | Yes | Release gate |
| Host VCI / OPACITY vectors | tool-tests (`OpenFIPS201Vci*`, SM checklist) | Yes | Strong for SM crypto KATs |
| ICAM provision | seven vendored positive GSA profiles + NIST `--icam` | Yes | All provision on standard; GSA FIPS PIV cards 37/46/47 provision on FIPS_MODE |
| 85B issuer-input corpus | `test-sp80085b-corpus` / `test-vectors/sp800-85b-personalization/` | Yes | Inputs only, not card GET DATA |
| Official GSA negative folders | `test-sp80085b-corpus` / vendored ICAM objects | Yes | Eight intrinsic negatives rejected; card 05 source assets require runtime certificate mutation |
| NIST headless harness | `run-nist-harness.sh` + `run-nist-vci-matrix.sh` | Yes | Legacy GSA or native signed CS2/CS7 VCI profiles; reviewed VCI classification gate |
| NIST GUI runner | External Windows install | Partial | Prefer headless on Mac |
| GSA positive card-access smoke | Repo-owned `test-gsa-icam-smoke` | Yes | Provisions seven positive profiles on standard and cards 37/46/47 on FIPS; card 46 also performs independent 9E verification |
| GSA piv-conformance / CCT | External host stack | Conditional | Upstream-derived runner is broken before card execution |
| Physical multi-app SELECT | Hardware | No on emulator | VE05.09–11 residual |
| Official 85B `CHECK_*` groups | `run-nist-data-model.sh` | Yes | 7 standard + 3 FIPS positive-image runs; XML, logs, and TSV summary |

### 4.2 NIST (SP 800-85A-style) gaps

Measured FIPS_MODE + GSA card-46 results on the in-process emulator:

- contact SELECT **2/2**, GET DATA **14/14**, VERIFY **15/15**, CRD **22/22**, RRC **17/17**, PUT DATA **11/11**;
- contactless SELECT **3/3**, GET DATA **11/11**, VERIFY **1/1**, CRD **6/6**, GENERATE **4/4**.
- 85B-style CHECKs: BER-TLV **17/18** (only rolling six-year expiry), certificate
  profiles **12/15** (three legacy-vs-CITE policy OID expectations); all exercised
  certificate key-pair operations pass.
- signed-data CHECKs **6/6**; biometric CHECKs **14/14**, including the
  455-requirement facial-image validation.

Full positive-image matrix re-run on 2026-08-11: **530/530 vectors executed**, with
**484 pass and 46 fail**, and **zero missing result files**. The 46 runner-level failures are:

1. BER-TLV `:2` in all 10 runs: the immutable CHUID date of 2032-12-02 is now more than
   the runner's rolling six-year limit from the execution date.
2. Certificate-profile vectors: 34 failures, dominated by legacy GSA/CITE certificate-policy
   OIDs; the PIV-I/NFI images additionally expose historical interim-status and SAN/FASC-N
   expectations. All exercised on-card private-key correspondence operations pass.
3. Card 54 only: signed-data `:2` and biometric `:2` each report the fingerprint FASC-N differs
   from its CHUID FASC-N. The applet returns the provisioned bytes unchanged.

These are personalised golden-image findings, not command-path mutations by the applet. The raw
runner result remains non-green and must not be presented as an unqualified conformance pass.

Remaining root causes are now isolated rather than a bare-card failure cascade:

1. **Direct administrative authentication** — legacy GENERATE contact vectors use 9B mutual authentication, while FIPS_MODE requires SCP03 for administrative commands.  
2. **Runner compatibility** — modern BouncyCastle linkage is handled by a generated
   four-class overlay; the remaining RSA vector can feed a modulus-sized integer outside
   the valid raw-RSA domain and throws `DataLengthException` before a useful product verdict.
3. **SM/VCI runner coverage** — `--vci cs2|cs7` builds and provisions a signed native
   Part 1 profile, issues the on-card SM key/CVC, and enables PIN use only after pairing.
   For both CS2 and CS7, the official card secure-messaging suite passes **6/7** vectors
   and the virtual-contact suite passes **3/7**. OPACITY, pairing, protected GET/PUT,
   VERIFY, CRD, RRC, GENERATE, C-MAC, and R-MAC are exercised. The secure-messaging GA
   vector intentionally omits pairing but expects VCI-gated keys to succeed. The remaining
   virtual-contact CRD/PUT/RRC expectations include contactless administrative or PUK
   operations forbidden by the strict FIPS profile. The harness now injects the provisioned
   key algorithms and certificates into the runner configuration; the remaining GA requirements
   assume a symmetric 9E, contactless 9B use, or a different unknown-key status than this profile.  
   `run-nist-vci-matrix.sh` reruns all 28 vector/profile cells and rejects any unreviewed change to
   that classification.
4. **Middleware vectors (`piv*`)** — require a middleware IUT and remain out of scope for this card application.  
5. **Some CHECK_\* TRUE are optional skips** — treat only requirement counts from applicable vectors as evidence.

| 85A / 73 theme | JUnit | Emulator NIST harness today | Target for Mac automation |
| -------------- | ----- | --------------------------- | ------------------------- |
| SELECT / APT | Partial | Contact and contactless pass | Physical multi-app residual |
| GET DATA + ACR | Partial | Contact, contactless, CS2 VCI, and CS7 VCI pass | Freeze native signed profile outputs |
| VERIFY / CRD / RRC | Strong samples | Applicable contact/contactless vectors pass | Preserve fresh image per destructive vector |
| GENERAL AUTHENTICATE | Samples | Official RSA runner blocked | Correct runner input domain or use independent vectors |
| GA chain interrupt | Dedicated AS05.36C regression passes | Unrelated-command abort asserted | Preserve in all profile suites |
| GENERATE KEY PAIR | Partial | Fail / auth | Admin path under SCP on emulator |
| Secure messaging / VCI | Strong JUnit | CS2/CS7 SM 6/7; virtual contact 3/7 | Resolve claim-inapplicable vectors and algorithm fixtures |
| Multi-app SELECT | Gap | Gap | **Physical residual** |
| Full alg matrix | Claimed asymmetric mechanism/role paths verified: RSA-2048/3072 raw signing and key transport, P-256/P-384 signing and ECDH | Distinct signing references 9A/9C/9E and key-establishment classes 9D/retired are exercised | Preserve with the exhaustive retired-slot policy gate |
| Middleware `piv*` | N/A | Fail | **Exclude** from card-app gate |

### 4.3 GSA ICAM / host gaps

| Item | Status |
| ---- | ------ |
| Load positive GSA profiles onto **standard** CAP emulator | Green for cards 01, 02, 37, 39, 46, 47, and 54 |
| Load GSA FIPS PIV profiles onto **FIPS** CAP | Green for cards 37, 46, and 47, including card 37 Key History and retired keys |
| Discovery/SO hash consistency after host rewrite | Closed: native builder re-signs CHUID/SO and strict preflight verifies both |
| VCI/SM materials from ICAM folder | Closed for emulator: `--vci cs2|cs7` derives a native signed profile and issues on-card CVC |
| Attestation F9 from ICAM | Out of scope for ICAM path |
| Repo-owned headless GSA smoke | Green across seven standard profiles and three FIPS profiles; SELECT, PIN, CCC/CHUID/9E certificate, plus independent card-46 9E verification |
| piv-conformance / CCT against “OpenFIPS201 Emulator” | Host bridge exists in the OpenPhysical fork, but the upstream-derived headless stack is not yet an executable gate; see the audited blockers below |
| Negative ICAM semantics | Eight official intrinsic-negative folders are vendored and rejected (03, 04, 06, 07, 08, 23, 38, 55), including SKID validation; card 05 is vendored and its byte-identical valid source certificates are covered by the runtime certificate-mutation test |

### 4.4 JUnit / CI residual gaps (even when NIST is green)

- **Closed:** the immutable FIPS policy exhaustively checks every Part 1 object and key against all
  supported access-mode pairs. Representative runtime tests exercise the shared access-control
  path for contact, contactless, ALWAYS, NEVER, PIN, VCI, and VCI+PIN; per-OID repetition would not
  traverse distinct enforcement code.
- **Closed:** the claimed keyRef × algorithm × role operational classes are covered. RSA-2048 and
  RSA-3072 raw signing are
  independently verified with each generated public key. P-256/SHA-256 and P-384/SHA-384 signing
  are exercised, including the FIPS CS2 exclusion and CS7 success path. P-256 and P-384 ECDH are
  independently compared with the host-derived shared secret under their applicable profiles.
  RSA-2048 and RSA-3072 key transport encrypt with the generated public key and verify the card's
  recovered representative. Runtime RSA-2048 operations cover signing references 9A, 9C, and 9E,
  plus key-establishment references 9D and retired 82. The immutable-policy test separately covers
  every interchangeable retired reference 82 through 95.
- **Closed:** every defined local/global PIN, preference, and VCI/pairing Discovery policy
  combination is parsed and checked, with invalid preference combinations rejected.
- **Closed:** contactless VERIFY exhaustion is driven through the handler until `6983`, proving the
  issuer's final contact retry is preserved without another comparison or decrement.
- Multi-app deselect (cannot fully simulate platform multi-app)  

### 4.5 Audited GSA host-runner blockers

The OpenPhysical `piv-conformance` fork was built from a disposable copy on macOS. This separates
host-runner failures from card responses:

- Gradle 6.6.1 requires **JDK 11** here; the active JDK 26 fails inside Gradle's compiler scanner.
- `cardlib` production sources compile on JDK 11, but its emulator smoke test is placed in a
  conflicting JPMS package and does not compile.
- `conformancelib` production and test sources compile on JDK 11, but the test task looks for
  `pdval.properties` and `x509-certs/` in the working directory instead of its packaged resources;
  discovery consequently reports zero runnable tests and fails during validator setup.
- The dormant CLI is not part of the fork's normal build and contains uncompilable source
  (`or(Method ...`) plus stale package names. Its Shadow 4.0.4 build is incompatible with current
  Gradle, while the repository wrapper does not include the CLI project.
- The current host bridge smoke accepts any two-byte status word after SELECT, so it proves only
  transport liveness, not successful PIV selection or conformance.

Until those host defects are repaired in the fork or a maintained runner is vendored here, do not
describe the official GSA CCT as green. The repo-owned `test-gsa-icam-smoke` is substantive positive
card-access evidence: exact ICAM readback/key-certificate validation plus SELECT, PIN, core GET DATA,
and independently verified Card Authentication. It is intentionally not labeled as the official CCT.

### 4.6 Explicitly not Mac-emulator complete

| Requirement | Why emulator is insufficient |
| ----------- | ---------------------------- |
| VE01 default selection after ATR | Platform policy |
| VE05.09–11 multi-app SELECT / invalid AID | Needs second real application on ICC |
| Contact vs contactless radio behaviour | Emulator media flags ≠ RF stack |
| Official NPIVP listing submission | Lab + physical card + unfiltered runner |
| FIPS 140 CMVP | Lab + platform boundary |
| Full SP 800-85B physical-card lab report | Physical personalised card + retained official-runner evidence |

---

## 5. Mac work plan — phase status

Phases A–D below are the original Mac automation plan. **A is met; B and D are largely
met with classified residuals; C is met via repo-owned smoke (not official CCT); E remains
external.**

### Phase A — FIPS golden personalisation on emulator — **MET**

Done: FIPS ACR map, capacity preflight, ICAM provision on FIPS CAP, PIN/PUK/9B, exact
readback, and optional native VCI (`--vci cs2|cs7`) with SM key/CVC/pairing.

**Exit criterion (met):** FIPS CAP + GSA cards 37/46/47 provision on emulator without create
failures; card 46 smoke includes independent 9E verification.

### Phase B — NIST headless card-app suite on Mac — **MOSTLY MET**

Done: `--fips --icam`, shared emulator session, `card-contact` / `card-contactless` suite
filters, JUnit XML output, dynamic config patch for provisioned secrets/algs, and
`run-nist-vci-matrix.sh` classification gate for CS2/CS7 SM + virtual-contact cells.

Checked-in base XMLs (`OpenFIPS201.xml`, `OpenFIPS201-RSA2048.xml`, ECC variants) remain the
config hosts; the harness patches connectivity, pairing, and key material at run time. A
static `OpenFIPS201-FIPS-CS2.xml` file is optional polish, not a blocker.

**Remaining residuals (classified, not bare-card cascade):**

1. Contact GENERATE paths that assume 9B mutual auth (FIPS admin prefers SCP03).  
2. Some official GA vectors with invalid RSA domain or claim-inapplicable key assumptions.  
3. VCI matrix: SM **6/7**, virtual-contact **3/7** (inapplicable FIPS contactless admin/PUK
   and pairing-vs-VCI-key expectations).  
4. Dated-card / policy OID CHECK expectations (content calendar, not applet SW).

**Exit criterion (partial):** Applicable card-app contact/contactless vectors pass; residuals
documented and gated so unreviewed regressions fail CI.

### Phase C — GSA / host path on Mac — **PARTIAL (repo smoke green)**

Done: `ant -f build/build.xml test-gsa-icam-smoke` provisions and exercises positive
profiles headlessly on the emulator.

Not done: official piv-conformance / CCT headless stack (see §4.5 host blockers).

**Exit criterion for listing-adjacent Mac work (met via smoke):** clean tree → FIPS/standard
provision → SELECT/PIN/GET DATA/9E path without an external CCT GUI.  
**Exit criterion for “official CCT green” (open):** repair or vendor a runnable CCT.

### Phase D — Expand automated evidence (still Mac) — **MOSTLY MET**

1. **Done:** ACR policy matrix, claimed keyRef×alg×role classes, Discovery policy matrix,
   contactless intermediate exhaustion, AS05.36C-style interrupt coverage.  
2. **Done on emulator:** host CMS/LDS/SKID/key↔cert proofs, intrinsic-negative GSA folders, and
   all four official data-model `CHECK_*` groups across the compatible positive-image matrix.  
3. **Open:** promote VE Draft → Pass only with frozen CAP SHA + archived Mac logs.  
4. **Done:** coverage floor and key VE wording aligned with code.

### Phase E — Residual (not fully Mac-emulator) — **OPEN**

1. Physical dual-interface card with same CAP + profile.  
2. Multi-app SELECT / security-status pack.  
3. Unfiltered physical-card NIST runner + formal retained 85B report if listing.  
4. CMVP if required.

---

## 6. Recommended frozen Mac test profiles

| Profile ID | CAP flags | Personalisation | NIST config host | Purpose |
| ---------- | --------- | --------------- | ---------------- | ------- |
| `mac-fips-cs2-icam46` | FIPS, CS2, att off | ICAM-46 + FIPS ACRs + AES 9B | `OpenFIPS201-RSA2048.xml` (harness patches secrets/algs) | Primary GSA+NIST dry run |
| `mac-fips-cs2-vci` / `mac-fips-cs7-vci` | FIPS, CS2 or CS7, att off | `--vci cs2\|cs7` native signed profile + SM CVC | Same hosts + `run-nist-vci-matrix.sh` | VCI/SM gate |
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
| 4 | **Done:** dynamic FIPS CS2/CS7 provisioning/config alignment plus reviewed VCI matrix gate | Phase B |
| 5 | **Done:** `card-<interface>` suite selector excludes middleware `piv*` | Honest pass rate |
| 6 | **Done:** harness builds FIPS, installs/provisions in-process, runs vectors, and writes JUnit XML | Developer UX |
| 7 | **Partial:** seven positive GSA images are vendored and provisioned headlessly, with cards 37/46/47 green on FIPS; official host runner remains broken before card execution | Phase C |
| 8 | **Done:** exhaustive Part 1 object/key policy ACR matrix plus distinct runtime signing and key-establishment reference classes | CI evidence |
| 9 | **Partial:** exact readback, CHUID/SO CMS, LDS hashes, SKID/key↔cert proofs, eight official intrinsic-negative folders, and the card-05 runtime mutation are enforced; remaining policy semantics require the official DMT | Partial 85B on Mac |
| 10 | **Done:** coverage, VE wording, NIST residuals, and closed code gaps synchronized | Process hygiene |
| 11 | Physical multi-app + lab 85A/85B (when ready for listing) | Phase E |

---

## 8. Success metrics

| Metric | Current (approx.) | Mac target (pre-lab) |
| ------ | ----------------- | -------------------- |
| FIPS CAP ICAM provision | **Passes** with GSA cards 37, 46, and 47 | Preserve as regression gate |
| NIST harness card-app contact (claimed) | Core commands plus signed-data/biometric CHECK suites pass; GA/admin and dated-card incompatibilities classified | All applicable vectors pass |
| NIST middleware `piv*` | Fail | Explicitly out of scope / N/A |
| Repo-owned GSA ICAM card-access smoke | **Passes** for seven standard and three FIPS golden profiles | Preserve as regression gate |
| Official GSA CCT | Blocked in host runner before card execution | Repair/vendor the official runner, then attach its positive log |
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

# Repo-owned GSA ICAM positive smoke (standard + FIPS golden profiles)
ant -f build/build.xml test-gsa-icam-smoke

# Emulator + ICAM through the headless NIST harness (card-app suite)
tools/piv_test_runner/setup-nist-tester.sh   # once; needs NIST archive password
tools/piv_test_runner/run-nist-harness.sh \
  --fips --target emulator \
  --icam /path/to/46_Golden_FIPS_201-2_PIV \
  --config tools/piv_test_runner/config/OpenFIPS201-RSA2048.xml \
  --suite card-contact \
  --out tools/piv_test_runner/piv_tests/fips-card-contact

# Native signed VCI matrix (CS2/CS7 × SM + virtual-contact); classification gated
tools/piv_test_runner/run-nist-vci-matrix.sh \
  --icam /path/to/46_Golden_FIPS_201-2_PIV \
  --out tools/piv_test_runner/piv_tests/vci-matrix

# Official data-model groups: 7 standard + 3 FIPS positive GSA images
tools/piv_test_runner/run-nist-data-model.sh \
  --out tools/piv_test_runner/piv_tests/data-model
```

---

## 10. Document control

| Field | Value |
| ----- | ----- |
| Applies to | OpenFIPS201 OpenPhysical fork |
| Audience | Engineering working FIPS listing prep and Mac CI |
| Last re-check | 2026-08-11 — code + harness artifacts vs this ledger |
| Not a substitute for | Formal NPIVP Test Summary, lab reports, CMVP certificate |
| Companion | [CONFORMANCE_AND_NPIVP.md](CONFORMANCE_AND_NPIVP.md), [CONFORMANCE_PROVISIONING.md](CONFORMANCE_PROVISIONING.md), [NPIVP_VENDOR_EVIDENCE.md](NPIVP_VENDOR_EVIDENCE.md) |
