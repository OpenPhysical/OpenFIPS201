# Validation Status and Deployment Gaps

This document states what the repository can verify automatically and what still requires the
target card platform, official test packages, or a laboratory. It is a deployment-planning aid, not
a certification statement.

## Product Scope

OpenFIPS201 provides two applet configurations:

- The **standard profile** supports the full documented OpenPhysical feature set.
- The **FIPS profile** applies the applet's FIPS-oriented object, lifecycle, and algorithm policy.

Code used by only one profile or attestation setting is compiled only into those CAPs: the FIPS
power-up self-tests (`FipsPowerUpSelfTests`, excluded as a whole file), the FIPS personalization
readiness check, the OPACITY key-derivation known-answer test and the FIPS access-mode checks only
into FIPS CAPs; `PIVAttestation`, `DERWriter` and `DERValidator` (the latter two excluded as whole
files) and the activation wipe helpers only into attestation-enabled CAPs. A standard CAP therefore
contains no FIPS self-test code, and an attestation-disabled CAP omits the attestation
implementation.

The profile choice does not change shared APDU syntax, TLV parsing, or input validation. A
FIPS-profile CAP is one part of a PIV card system. It does not establish FIPS 140 validation,
NPIVP listing, or approval of the Java Card platform.

The applet is a PIV card application. Middleware API testing applies to a different product
boundary.

## Automated Release Gates

| Gate                 | Command                                        | Scope                                                                                          |
| -------------------- | ---------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Default applet tests | `ant -f build/build.xml test`                  | Standard profile, CS2/CS7 × attestation on/off; excludes `@Tag("slow")`                        |
| Release matrix       | `ant -f build/build.xml test-all`              | Standard/FIPS × CS2/CS7 × attestation on/off with slow tests, then ZMQ transport, `test-sam` (full-period) and `test-host` |
| Coverage             | `ant -f build/build.xml coverage`              | JaCoCo line and branch ratchets over three profiles, per-class floors, host-tool floor        |
| GSA profile smoke    | `ant -f build/build.xml test-gsa-icam-smoke`   | Profile provisioning and selected card-access checks                                           |

The coverage target measures `standard-CS2-attestation`, `standard-CS7-no-attestation` and
`fips-CS2-attestation`, which together compile every preprocessor branch. Only applet classes are
instrumented; a coverage-only source copy rewrites `ISOException.throwIt` calls into explicit throws
so those lines are counted. `CoverageGate` applies `[Class:]COUNTER=minimum` rules; each floor sits
just below the measured value and is raised as coverage improves:

| Profile                       | Bundle floor             | Per-class floors (line / branch)                                                                                                                                                  |
| ----------------------------- | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `standard-CS2-attestation`    | line 0.88, branch 0.75   | `PIVPinCommandHandler` 0.83/0.76, `PIVSecureMessaging` 0.94/0.85, `ChainBuffer` 0.91/0.87, `PIVSecurityProvider` 0.78/0.67, `PIVAuthenticationCommandHandler` 0.86/0.80, `PIVAttestation` 0.95/0.78 |
| `standard-CS7-no-attestation` | line 0.84, branch 0.73   | —                                                                                                                                                                                 |
| `fips-CS2-attestation`        | line 0.88, branch 0.76   | —                                                                                                                                                                                 |
| host tool                     | line 0.66, branch 0.54   | —                                                                                                                                                                                 |

The authoritative values are the `coverage.rules.*` properties in `build/build.xml`. The host-tool
floor assumes no SoftHSM2 module; the `softhsm`-tagged tests add to it.

CI runs `test-all` (which includes the GSA profile smoke test in each matrix variant) and the
coverage ratchets, both with SoftHSM2 installed, so the `softhsm`-tagged custody and issuance tests
in `test-host` execute rather than skip by assumption.

## Manual NIST Release Gates

| Gate              | Command                                        | Scope                                                    |
| ----------------- | ---------------------------------------------- | -------------------------------------------------------- |
| VCI matrix        | `tools/piv_test_runner/run-nist-vci-matrix.sh` | CS2 and CS7 secure messaging and virtual-contact vectors |
| Data-model groups | `tools/piv_test_runner/run-nist-data-model.sh` | Applicable SP 800-85B data-model checks                  |

These gates are run by hand: `setup-nist-tester.sh` needs the NIST archive password interactively,
so CI cannot install the runner. A release must also retain the CAP, matching build-properties
file, test logs including the manual NIST runs, and hashes.

## Verified in the Emulator

Repository tests cover:

- ISO/IEC 7816-4 command and response chaining, including interruption and malformed sequences;
  GET RESPONSE is bound to the class family of the initiating command (a GP SCP GET RESPONSE
  continues only a GP SCP response and never releases a pending PIV SM response)
- standard and proprietary command separation
- PIN, PUK, retry-counter, and security-status transitions, including retry-counter restoration
  after a PIN-history or platform rejection and `6A88` for a disabled PUK
- rejection of non-minimal BER-TLV length encodings on every incoming TLV path, including the
  streaming parser for the encrypted `87` object of a secure-messaging command (`6988` and session
  destroyed, SP 800-73-5 Part 2 Section 4.2.7); `TLVWriter` always emits the shortest length form
  (ISO/IEC 7816-4 Section 6.3), with OPACITY `7C` headers pinned across the `7F`/`80`/`FF`
  boundaries
- seeded property tests against independent reference models: mutated secure-messaging commands
  (non-minimal lengths, bad padding, misordered or missing objects, MAC and byte corruption) unwrap
  exactly or fail with `6987`/`6988` and a destroyed session; random command-chaining sequences
  reassemble byte-exactly or fail with the documented status words and recover; mutated GET/PUT
  DATA commands return only ISO or SP 800-73-5 status words and leave the card usable
- secure-messaging INS `24`, `25` and `47` commands whose plaintext exceeds the APDU buffer, sent as
  SM chains; plaintext commands during a real OPACITY session over contact and contactless
- a PIN/PUK command matrix for VERIFY, CHANGE REFERENCE DATA and RESET RETRY COUNTER across
  malformed, wrong, blocked, contactless, VCI and intermediate-reserve conditions; an install-time
  PUK that was never set by the issuer fails as a mismatch (`63CX`, counter decremented)
- the FIPS personalization readiness gate at APDU level: PERSONALIZE succeeds on a ready card and
  returns `6985` with the lifecycle unchanged for an advertised but absent VCI, a usable retired key
  without Key History, or a malformed `5FC123` with pairing-code VCI
- injected crypto faults: a `CryptoException` during RSA import or ECDH returns `6A80` and clears
  the key or abandons the authentication context; GENERAL AUTHENTICATE Cases 4 and 5 faults return
  `6A80`; a forced pairwise-consistency failure on ECC and RSA generation (FIPS builds) and F9
  generation (attestation builds) returns `6F00` and leaves no usable key
- validation of imported EC public points (encoding, coordinate range, curve equation), `6A80` with
  the partial import cleared
- FIPS-profile power-up self-tests (AES, AES-CMAC, SHA-256, SHA-384 in CS7, ECDSA P-256, ECC CDH
  P-256, RSA-2048 and the OPACITY KDA through its production entry point) and the fail-closed latch
  through the installed applet
- administrative authorization through GlobalPlatform SCP and key reference `9B`
- key and object creation, replacement, deletion, and lifecycle restrictions
- RSA-2048, RSA-3072, P-256, and P-384 operations in their permitted profiles
- on-card F9 generation, proof of possession, F9 certificate load and activation, proof attestation,
  and independent certificate parsing; Issuer SAM issuance through `test-sam`
- OPACITY CS2 and CS7 key establishment
- secure-messaging encryption, MACs, counters, replay checks, pairing, and session teardown
- malformed APDU, TLV, DER, CVC, and secure-messaging inputs
- applet deletion: services are owned per instance and allocated at install, `uninstall()` clears
  nothing, a refused deletion leaves the PIV or Issuer SAM instance usable without allocation, and
  two PIV instances share no service object (`OpenFIPS201UninstallTest`, `IssuerSamUninstallTest`)

The GSA profile smoke provisions seven positive standard profiles and three positive FIPS profiles.
In FIPS builds it first confirms that importing the profiles' `9A`/`9C` keys is refused, then
generates `9A` and `9C` on the card and imports the remaining keys. It checks exact data readback and
selected certificate-to-key operations. This evidence is useful for
regression testing but is not a substitute for an official GSA or NIST result.

## Recorded External-Suite Results

The headless card-command harness has exercised contact and contactless PIV command groups against
the emulator. Residual results are classified by applicability, profile assumptions, and test-data
content. An unexplained failure is not accepted as a pass.

The recorded SP 800-85B positive-image run executed 530 vectors: 484 passed and 46 reported
failures. The reported failures are associated with fixed test-image dates, certificate-policy
expectations, and one fingerprint/CHUID identifier mismatch in the supplied data. The applet returns
the provisioned object bytes unchanged. Retain the complete result files when using these figures as
evidence.

For VCI, the repository runner evaluates the secure-messaging and virtual-contact groups for both
CS2 and CS7. Secure messaging reports seven tests and zero failures per suite. Virtual contact
reports seven tests and three runner failures per suite for command cases that expect contactless
rejection. The clause assessment accepts all seven results only after it verifies the exact test
names and protected statuses. The runner rejects any additional or unclassified failure.

## Product Constraints

### Algorithm and Profile Limits

The FIPS profile permits a deliberate subset of the SP 800-78-5 algorithm combinations:

- AES card-management keys
- RSA-2048, RSA-3072, P-256, and P-384 cardholder keys where the selected key reference permits them
- one OPACITY suite in each CAP

RSA-1024 and 3TDEA are not permitted in the FIPS profile. A CAP advertises only its selected OPACITY
suite. Product claims must name the exact CAP profile and suite.

In the FIPS profile, keys `9A` and `9C` cannot be defined as importable and must be generated on the
card (FIPS 201-3 Sections 4.2.2.1 and 4.2.2.4). The standard profile allows imported `9A` and `9C`.
Key `F9` is generated on the card in both profiles.

### Personalization Readiness

The applet checks the required object and key structure before the one-way personalization
transition. In the FIPS profile this includes generated origin for `9A` and, when present, `9C`,
and an active F9 authority in attestation-enabled CAPs. Issuer software remains responsible for
semantic checks of certificates, signed objects, data hashes, access-control rules, and private-key
bindings.

The repository issuer path verifies CHUID and Security Object signatures, LDS hashes, subject-key
identifiers, object readback, and selected key-to-certificate bindings. Formal issuer-policy
validation remains an external gate.

### Attestation

F9 attestation is an OpenPhysical extension and is outside the NPIVP card-application claim. Use an
attestation-disabled CAP, which omits the attestation implementation, for an NPIVP submission
unless the test authority directs otherwise. The
release matrix still tests attestation-enabled and attestation-disabled CAPs.

### Platform Behavior

The emulator cannot establish:

- default application selection after reset
- multi-application selection and security-status behavior, including preservation of the security
  status and secure-messaging session on a PIV re-SELECT (jCardEngine cannot model
  `reSelectingApplet()`)
- the card reset that clears PIN validation when the host tool disconnects
- contactless radio timing and field-loss behavior
- EEPROM tear resistance and transaction behavior on the target chip, including a tear during PIN
  or PUK retry-counter restoration (`OwnerPIN` counter updates do not participate in transactions,
  so the restore is not atomic)
- Java Card platform cryptographic validation
- physical-card response timing and reader compatibility

## Required Hardware Follow-Up

Before deployment, repeat the applicable tests on every target card and reader combination (the
gates are detailed in [Production Qualification](PRODUCTION_QUALIFICATION.md#card-platform-gates)):

1. Install the exact retained CAP and verify its hash and build properties, including
   `build.sha256`.
2. Run contact and contactless command-interface suites.
3. Run CS2 or CS7 VCI tests for the suite in the CAP.
4. Verify F9 provisioning and every supported attestation target algorithm if attestation is enabled.
5. Exercise reset, deselect, field loss, interrupted writes, interrupted PIN/PUK update with PIN
   history, interrupted secure-messaging CVC replacement, interrupted F9 certificate load and
   activation, and, for the Issuer SAM, interrupted ISSUE, TOP UP, VOID, CLOSE and personalization.
6. Measure CS2 and CS7 secure-messaging establishment latency, P-256 and P-384 ECDH and EC
   point-validation latency, and reader timeout margins.
7. Run multi-application selection and security-status tests, including PIV re-SELECT
   (security status and secure-messaging session preserved) and PIN validation cleared by the card
   reset when the host tool disconnects.
8. Retain official tool output, card identifiers, platform details, and test configuration.

## Certification Boundaries

| Claim                          | Required evidence                                                  |
| ------------------------------ | ------------------------------------------------------------------ |
| Repository regression status   | Retained eight-variant test and coverage results                   |
| PIV card-interface conformance | Applicable official NIST suite results on the target card          |
| PIV data-model conformance     | Applicable SP 800-85B results for the personalized card            |
| NPIVP listing                  | Laboratory and program evidence for the complete submitted product |
| FIPS 140 validation            | CMVP evidence for the defined cryptographic module boundary        |

Do not describe a configuration as certified, listed, compliant, or validated unless the named
authority has issued evidence for that exact product boundary.

## Related Documents

- [Conformance and NPIVP](CONFORMANCE_AND_NPIVP.md)
- [Conformance Provisioning](CONFORMANCE_PROVISIONING.md)
- [NPIVP Vendor Evidence](NPIVP_VENDOR_EVIDENCE.md)
- [PIV Test Runner](../tools/piv_test_runner/README.md)
- [VCI Conformance](../tools/piv_test_runner/VCI_CONFORMANCE.md)
