# Validation Status and Deployment Gaps

This document states what the repository can verify automatically and what still requires the
target card platform, official test packages, or a laboratory. It is a deployment-planning aid, not
a certification statement.

## Product Scope

OpenFIPS201 provides two applet configurations:

- The **standard profile** supports the full documented OpenPhysical feature set.
- The **FIPS profile** applies the applet's FIPS-oriented object, lifecycle, and algorithm policy.

The profile choice does not change shared APDU syntax, TLV parsing, or input validation. A
FIPS-profile CAP is one part of a PIV card system. It does not establish FIPS 140 validation,
NPIVP listing, or approval of the Java Card platform.

The applet is a PIV card application. Middleware API testing applies to a different product
boundary.

## Automated Release Gates

| Gate                 | Command                                        | Scope                                                           |
| -------------------- | ---------------------------------------------- | --------------------------------------------------------------- |
| Default applet tests | `ant -f build/build.xml test`                  | APDU behavior, access control, crypto paths, and negative cases |
| Eight-variant matrix | `ant -f build/build.xml test-all`              | Standard/FIPS × CS2/CS7 × attestation on/off                    |
| Coverage             | `ant -f build/build.xml coverage`              | JaCoCo applet line floor of 80%                                 |
| GSA profile smoke    | `ant -f build/build.xml test-gsa-icam-smoke`   | Profile provisioning and selected card-access checks            |
| VCI matrix           | `tools/piv_test_runner/run-nist-vci-matrix.sh` | CS2 and CS7 secure messaging and virtual-contact vectors        |
| Data-model groups    | `tools/piv_test_runner/run-nist-data-model.sh` | Applicable SP 800-85B data-model checks                         |

The eight-variant matrix is the repository release gate. A release must also retain the CAP,
matching build-properties file, test logs, and hashes.

## Verified in the Emulator

Repository tests cover:

- ISO/IEC 7816-4 command and response chaining, including interruption and malformed sequences
- standard and proprietary command separation
- PIN, PUK, retry-counter, and security-status transitions
- administrative authorization through GlobalPlatform SCP and key reference `9B`
- key and object creation, replacement, deletion, and lifecycle restrictions
- RSA-2048, RSA-3072, P-256, and P-384 operations in their permitted profiles
- F9 provisioning, staged authority updates, proof attestation, and independent certificate parsing
- OPACITY CS2 and CS7 key establishment
- secure-messaging encryption, MACs, counters, replay checks, pairing, and session teardown
- malformed APDU, TLV, DER, CVC, and secure-messaging inputs

The GSA profile smoke provisions seven positive standard profiles and three positive FIPS profiles.
It checks exact data readback and selected certificate-to-key operations. This evidence is useful for
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

### Personalization Readiness

The applet checks the required object and key structure before the one-way personalization
transition. Issuer software remains responsible for semantic checks of certificates, signed
objects, data hashes, access-control rules, and private-key bindings.

The repository issuer path verifies CHUID and Security Object signatures, LDS hashes, subject-key
identifiers, object readback, and selected key-to-certificate bindings. Formal issuer-policy
validation remains an external gate.

### Attestation

F9 attestation is an OpenPhysical extension and is outside the NPIVP card-application claim. Use an
attestation-disabled CAP for an NPIVP submission unless the test authority directs otherwise. The
release matrix still tests attestation-enabled and attestation-disabled CAPs.

### Platform Behavior

The emulator cannot establish:

- default application selection after reset
- multi-application selection and security-status behavior
- contactless radio timing and field-loss behavior
- EEPROM tear resistance and transaction behavior on the target chip
- Java Card platform cryptographic validation
- physical-card response timing and reader compatibility

## Required Hardware Follow-Up

Before deployment, repeat the applicable tests on every target card and reader combination:

1. Install the exact retained CAP and verify its hash and build properties.
2. Run contact and contactless command-interface suites.
3. Run CS2 or CS7 VCI tests for the suite in the CAP.
4. Verify F9 provisioning and every supported attestation target algorithm if attestation is enabled.
5. Exercise reset, deselect, field loss, interrupted writes, and interrupted authority rotation.
6. Measure P-256 and P-384 ECDH latency and reader timeout margins.
7. Run multi-application selection and security-status tests.
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
