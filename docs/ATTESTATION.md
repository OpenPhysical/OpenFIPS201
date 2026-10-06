# Attestation

This fork implements a PIV attestation command (`INS F9`). A relying party that holds only the
OpenPhysical root certificate can verify, with ordinary RFC 5280 path validation, that an attested
key was generated inside a genuine card, and can identify that card by its OPID.

## Chain of Trust

```text
Root CA (offline HSM)
  └── Issuer SAM        CA:TRUE pathLen 1, key generated on the SAM, one per batch
        └── Card F9     CA:TRUE pathLen 0, key generated on the card, subject serialNumber = OPID
              └── Leaf  CA:FALSE, attests one on-card generated PIV key
```

- The **root** certifies one Issuer SAM per batch. The SAM certificate carries the root-signed
  batch extension (v3) that fixes the IIN, batch number, initial quota and, through a digest, the LCG
  parameters and the FF1 key check value, and records the entry of the root's allocation registry
  that allocated the batch (`allocationSeq`, `registryHead`). See [ISSUER_SAM.md](ISSUER_SAM.md).
- The **Issuer SAM** allocates the card's OPID, checks the card's proof of possession of its F9
  key, and signs the F9 certificate.
- The card's **F9** key is generated on the card and never leaves it. The F9 certificate is loaded
  once; after that F9, its certificate and the OPID are immutable for the life of the applet
  instance.
- Each **leaf** is built and signed by the card for one target key generated on the card.

The card does not verify the SAM's signature on the F9 certificate. It checks the profile, the
OPID syntax and that the certificate certifies its own F9 key. The issuance host must run PKIX
validation of root → SAM → F9 before it loads the certificate, because loading cannot be undone.

## Authority State Machine

| State        | Value | Meaning                                                                                       |
| ------------ | ----- | --------------------------------------------------------------------------------------------- |
| `NONE`       | `00`  | No usable authority. Initial state, and the state while F9 is being generated.                |
| `GENERATED`  | `01`  | F9 was generated on the card and passed its pairwise test. PROVE and certificate load allowed. |
| `ACTIVATING` | `02`  | A validated certificate is stored; the destructive activation wipe may be incomplete.         |
| `ACTIVE`     | `03`  | The authority issues attestation certificates. F9, its certificate and the OPID are fixed.    |

Transitions:

- `GENERATE F9` resets the authority to `NONE` in one transaction, generates the pair, runs the
  pairwise consistency test, and only then enters `GENERATED`. A tear at any point leaves `NONE` or
  a complete generated pair. Generating again from `GENERATED` replaces the pair.
- A successful certificate load commits the certificate offsets and `ACTIVATING` in one
  transaction, clears every other key and data object, and then commits `ACTIVE`.
- `ACTIVATING` is persistent. SELECT, and every F9 command, completes an interrupted wipe before
  doing anything else, so `ACTIVATING` is rarely observable.
- There is no transition out of `ACTIVE`. Re-rooting a card requires deleting the applet instance.

F9 may be generated, proven or certified only while the state is `NONE` or `GENERATED` and the
applet's GlobalPlatform lifecycle is `SELECTABLE`. Otherwise the command returns `6985`.

## Provisioning Order

F9 must be the first provisioning step after installation. Activation clears:

- the key material of every key object except F9, including `9B` and `04`;
- the contents of every data object.

Object and key definitions, configuration, PIN/PUK state and the current GlobalPlatform secure
channel are preserved. Anything provisioned before activation is lost, so provision `9B`, PIN, PUK,
key `04`, cardholder keys and data objects after the F9 certificate is loaded.

In FIPS builds with attestation, the transition to `PERSONALIZED` also requires the authority to be
`ACTIVE`.

## Commands

All F9 provisioning commands require an authenticated GlobalPlatform secure channel with command
encryption and command MAC (CLA `84`). A prior `9B` authentication is not sufficient.

### 1. Define F9

F9 is created through the administrative key-definition path with a fixed shape: P-256 (`11`),
role SIGN (`04`), attributes `ATTR_NONE` (`00`, never importable), and access mode NEVER (`00`) on
both interfaces. Any other shape returns `6A80`.

```text
84 DB FF FF  66 12  8B 01 F9  8C 01 00  8D 01 00  8E 01 11  8F 01 04  90 01 00
```

F9 cannot be deleted (`6A80`). In builds without attestation, defining F9 returns `6A80`.

### 2. Generate F9

```text
84 47 00 F9  05  AC 03 80 01 11  00
→ 7F 49 43 86 41 04 <X> <Y>   9000
```

The pairwise consistency test runs for F9 in every build; a failure returns `6F00` and leaves the
state `NONE`.

### 3. PROVE (proof of possession)

```text
84 F9 F9 01  Lc  N  00
→ <DER ECDSA-Sig-Value>   9000
```

`N` is the issuer nonce, 16 to 64 octets (the Issuer SAM sends 32). The card signs, with ECDSA
P-256 / SHA-256:

```text
M = "OPF9POP" (4F 50 46 39 50 4F 50) || N || F9pub (65-octet uncompressed point)
```

PROVE is accepted only under the secure channel and only in state `GENERATED`. It is permanently
unavailable once a certificate has been accepted.

| SW     | Condition                                                                 |
| ------ | ------------------------------------------------------------------------- |
| `6982` | No encrypted and MACed secure channel                                     |
| `6700` | Nonce shorter than 16 or longer than 64 octets                            |
| `6A88` | F9 is not defined                                                         |
| `6985` | State is not `GENERATED`, F9 has no generated pair, or applet not SELECTABLE |

### 4. Load the F9 certificate (element 70)

The certificate is sent through administrative `CHANGE REFERENCE DATA` with `P1=11` (P-256) and
`P2=F9`, as a `SEQUENCE` holding exactly one element `70`. It is normally command-chained (CLA `94`
on non-final frames).

```text
84 24 11 F9  Lc  30 82 LL LL  70 82 LL LL  <certificate DER>
```

The card validates the certificate (see [F9 Certificate Profile](#f9-certificate-profile)),
requires its SubjectPublicKeyInfo to equal the card's own F9 key and its subjectKeyIdentifier to
equal the RFC 7093 method 1 value of that key, and runs a sign/verify self-test with F9. It then
stores the certificate in the container `53 82 LL LL 70 82 LL LL <cert> 71 01 00 FE 00`, enters
`ACTIVATING`, runs the activation wipe, and enters `ACTIVE`.

| SW     | Condition                                                                   |
| ------ | --------------------------------------------------------------------------- |
| `6982` | No encrypted and MACed secure channel, or element `86` / `87` (F9 import)   |
| `6A88` | F9 is not defined, or P1 is not `11`                                        |
| `6985` | State is not `GENERATED`, F9 has no generated pair, or applet not SELECTABLE |
| `6A84` | Certificate longer than `0x2E0` (736) octets, or subject longer than 128    |
| `6A80` | Any other element tag, certificate shorter than 256 octets, any profile or binding failure |

Element `86` and `87` (F9 public point and private scalar) are never accepted: F9 key material is
generated on the card in every build.

### 5. Read back

The F9 certificate is public. Once the authority is `ACTIVE` it is served without authentication
on every interface, in two forms:

```text
00 F9 F9 00 [Le]                       → <certificate DER>
00 CB 3F FF 05 5C 03 5F FF 01 [Le]     → 53 82 LL LL 70 82 LL LL <cert> 71 01 00 FE 00
```

`00 F9 F9 00` returns `6985` before activation; GET DATA `5FFF01` returns `6A82`. `5FFF01` is a
virtual, read-only object: CREATE OBJECT for `5FFF01` returns `6A80` and PUT DATA cannot write it.
The issuance host should require the read-back certificate to be byte-identical to the one it
loaded.

### 6. Attest a key

```text
00 F9 <slot> 00 [Le]
→ <leaf certificate DER>   9000
```

The response is a raw DER X.509 certificate, not wrapped in a PIV data-object tag. The command
carries no data; command data after any secure-channel unwrap returns `6700`. `P2` other than `00`
(except the PROVE form) returns `6A86`.

Supported target slots are `9A`, `9C`, `9D`, `9E` and the retired key-management slots `82` through
`95`. Supported target algorithms are RSA-1024 (standard profile only), RSA-2048, RSA-3072, ECC
P-256 and ECC P-384. F9 is always P-256 and leaves are signed with ecdsa-with-SHA256.

The target key's normal access rules apply. A slot configured for PIN access requires a verified
PIN. A slot whose contactless access mode requires the Virtual Contact Interface is attestable over
contactless only after VCI is established. A slot blocked on the current interface is not
attestable on that interface.

Only keys generated on the card are attestable. Imported keys return `6985`. Because activation
clears every non-F9 key, every attestable key was generated after the F9 certificate was loaded.

| SW     | Condition                                                                         |
| ------ | --------------------------------------------------------------------------------- |
| `6A86` | Slot not attestable, or invalid P2                                                |
| `6985` | Authority not `ACTIVE`, target has no key material, target imported, or target role has no defined keyUsage |
| `6A88` | Target slot has no key object                                                     |
| `6982` | Target access mode not satisfied (including VCI-gated keys over contactless before VCI) |
| `6A84` | Generated certificate exceeds the 1024-octet response buffer                      |

## Status Words (summary)

- `9000`: success.
- `6982`: F9 command outside the required secure channel, F9 key import attempted, or attestation
  target access mode not satisfied.
- `6985`: authority in the wrong state, applet not `SELECTABLE` for F9 provisioning, target key
  missing, imported or without a defined keyUsage.
- `6F00`: F9 pairwise consistency test failed during generation.
- `6A80`: malformed element, malformed or non-canonical DER, profile violation, or key binding
  mismatch; F9 definition with the wrong shape; F9 delete; CREATE OBJECT `5FFF01`.
- `6A82`: GET DATA `5FFF01` before activation.
- `6A84`: certificate or subject above the supported limits.
- `6A86`: invalid attestation slot or parameters.
- `6A88`: F9 or target key reference not found.
- `6700`: PROVE nonce length, or command data on a certificate request.

## GET STATUS

In attestation builds GET STATUS (`80 CB FF FF 05 5C 03 2F 47 53`) adds:

| Tag  | Value                                                            |
| ---- | ---------------------------------------------------------------- |
| `89` | Authority state (`00` to `03`, see above)                        |
| `8A` | OPID (ASCII digits, F9 subject serialNumber); only when `ACTIVE` |
| `8B` | F9 subject key identifier (20 octets); only when `ACTIVE`        |

## F9 Certificate Profile

The Issuer SAM produces this profile (see [ISSUER_SAM.md](ISSUER_SAM.md#f9-certificate-profile)).
The card enforces the following when the certificate is loaded:

- One strict DER `Certificate` with no trailing octets; RFC 5280 Section 4.1 requires DER.
- Version v3. Serial number positive, minimal, at most 20 octets.
- `signatureAlgorithm` is exactly ecdsa-with-SHA256 without parameters
  (`30 0A 06 08 2A 86 48 CE 3D 04 03 02`), and the TBSCertificate `signature` AlgorithmIdentifier
  is byte-equal to it.
- Issuer and subject are valid DER Names; the subject is at most 128 octets and differs from the
  issuer.
- The subject contains exactly one `serialNumber` (2.5.4.5) attribute, alone in its RDN, encoded
  as PrintableString, whose value is a canonical OPID (see [Card Identity (OPID)](#card-identity-opid)).
- Validity is DER with canonical `UTCTime` through 2049 and `GeneralizedTime` from 2050, both with
  seconds and `Z`; `notAfter` is not earlier than `notBefore`.
- SubjectPublicKeyInfo equals the card's own F9 P-256 key.
- No issuerUniqueID or subjectUniqueID; extensions are present and contain exactly one each of:

  | Extension                         | Criticality  | Required value                                            |
  | --------------------------------- | ------------ | --------------------------------------------------------- |
  | basicConstraints (2.5.29.19)      | critical     | `30 06 01 01 FF 02 01 00` (cA TRUE, pathLenConstraint 0)  |
  | keyUsage (2.5.29.15)              | critical     | `03 02 02 04` (keyCertSign only)                          |
  | subjectKeyIdentifier (2.5.29.14)  | non-critical | 20 octets, RFC 7093 method 1 of the card's F9 key         |
  | authorityKeyIdentifier (2.5.29.35)| non-critical | keyIdentifier present and non-empty                       |

- An explicit `critical FALSE` is rejected (X.690 Section 11.5). Any other critical extension is
  rejected. Other non-critical extensions, such as the SAM issuance extension, are accepted.
- Size 256 to 736 octets.

The card does not check the signature value, the AKI value, or the validity dates against a clock.
It does not decipher the OPID. Those checks belong to the issuance host and to
relying parties.

The subject key identifier is the leftmost 160 bits of SHA-256 over the subjectPublicKey BIT STRING
value (`04 || X || Y`), RFC 7093 Section 2 method 1.

## Leaf Certificate Profile

| Field                 | Value                                                                       |
| --------------------- | --------------------------------------------------------------------------- |
| version               | v3                                                                          |
| serialNumber          | 16 random octets, positive and non-zero                                     |
| signature             | ecdsa-with-SHA256 (1.2.840.10045.4.3.2), parameters absent                  |
| issuer                | F9 certificate subject, byte-for-byte (carries the OPID)                    |
| validity              | F9 certificate validity, byte-for-byte                                      |
| subject               | `CN=PIV Attestation <slot>` (UTF8String, slot as two uppercase hex digits)  |
| subjectPublicKeyInfo  | the target key                                                              |
| extensions            | see below, in this order                                                    |

| Extension                            | Criticality  | Value                                               |
| ------------------------------------ | ------------ | --------------------------------------------------- |
| basicConstraints                     | non-critical | `30 00` (cA FALSE)                                  |
| keyUsage                             | critical     | by target role, see below                           |
| authorityKeyIdentifier               | non-critical | keyIdentifier = F9 subject key identifier           |
| OpenPhysical attestation extension   | non-critical | `1.3.6.1.4.1.57923.20.10.20.1`, see below           |

keyUsage follows the target role in GENERAL AUTHENTICATE dispatch order (RFC 5280 Section 4.2.1.3):

| Target role                    | keyUsage           | DER           |
| ------------------------------ | ------------------ | ------------- |
| SIGN                           | digitalSignature   | `03 02 07 80` |
| key establishment, ECC         | keyAgreement       | `03 02 03 08` |
| key establishment, RSA         | keyEncipherment    | `03 02 05 20` |
| any other                      | refused with `6985`|               |

### OpenPhysical Attestation Extension

```asn1
OpenPhysicalAttestation ::= SEQUENCE {
  version          INTEGER (1),
  appletVersion    OCTET STRING (SIZE 4),  -- major, minor, revision, debug
  buildFlags       OCTET STRING (SIZE 1),  -- bit 0 FIPS profile, bit 1 attestation support
  vciSuite         OCTET STRING (SIZE 1),  -- 27 (CS2) or 2E (CS7)
  platformId       OCTET STRING,           -- build platform identifier, at most 32 octets
  keyReference     OCTET STRING (SIZE 1),  -- attested slot
  mechanism        OCTET STRING (SIZE 1),  -- PIV algorithm identifier
  role             OCTET STRING (SIZE 1),  -- key role bits
  attributes       OCTET STRING (SIZE 1),  -- key attribute bits
  origin           ENUMERATED { generated(2) },
  contactMode      OCTET STRING (SIZE 1),  -- access mode, contact
  contactlessMode  OCTET STRING (SIZE 1)   -- access mode, contactless
}
```

`appletVersion`, `buildFlags`, `vciSuite` and `platformId` match the CAP's `.cap.properties`. The
build fails if the platform identifier is longer than 32 characters, which keeps the worst-case leaf
(maximum issuer subject and an RSA-3072 key) inside the 1024-octet response buffer.

The leaf is built directly into a `CLEAR_ON_DESELECT` transient buffer, with a persistent fallback
that is wiped after the response chain completes or is abandoned. Overflow fails closed with `6A84`.

## Verification by a Relying Party

A verifier holding the root certificate should:

1. Require strict DER for every certificate.
2. Validate the path root → SAM → F9 → leaf with PKIX at the time of interest.
3. Require byte-equal issuer and subject Names at each link and AKI/SKI linkage.
4. Require the SAM certificate to have pathLen 1 and the batch extension, and the F9 certificate to
   have pathLen 0, keyUsage keyCertSign, and a serialNumber that is a canonical 17-digit OPID whose
   IIN equals the `issuerId` of the SAM batch extension. The batch and issuance index are enciphered
   and cannot be checked without the IIN's FF1 key (or the SAM's DECIPHER command).
5. Require the leaf to have cA FALSE, the AKI, and a well-formed OpenPhysical extension, and, where
   applicable, compare the leaf SubjectPublicKeyInfo with the slot certificate and the CHUID GUID and
   FASC-N with the values derived from the OPID.
6. Where the issuer publishes them, check the SAM against the root-signed allocation registry
   (`allocationSeq` names this SAM's allocation, a `bind` line binds it to this SAM, and its head
   equals `registryHead`) and require the OPID not to appear in any SAM-signed VOID entry.

`openfips201 attestation verify` implements these checks; `--registry` and `--voids` enable step 6,
`--expect-opid` pins the OPID, and `--producer`/`--batch` take the anchor and SAM certificate from a
producer profile.

## Card Identity (OPID)

The OPID is the card's identity. It is allocated by the Issuer SAM, appears as the F9 subject
`serialNumber`, and therefore appears in the issuer Name of every leaf the card signs.

### Layout

There is one OPID layout (v2): 17 ASCII decimal digits, canonical form without separators.

```text
OPID = IIII ‖ E ‖ L

IIII  IIN, 4 digits, plaintext
E     FF1_K(B ‖ X, ASCII(IIII)), 12 digits
        B = batch number, 4 digits
        X = x_n, 8 digits: the batch LCG state after the n-th issuance
        K = AES-256 FF1 key, one per IIN, shared by every batch and SAM of that IIN
L     Luhn mod-10 check digit over the 16 typed digits IIII ‖ E
```

- E is NIST SP 800-38G FF1 with AES-256, radix 10, 12 digits (u = v = 6), tweak `ASCII(IIII)`.
  The domain is exactly `[0, 10^12)`, so no cycle-walking is needed.
- The IIN is never enciphered; it enters FF1 only as the tweak.
- L is computed over the digits a person types, `IIII ‖ E`, never over the plaintext batch or LCG
  state. Doubling starts at the rightmost payload digit (ISO/IEC 7812-1 Annex B).
- Display grouping is `IIII EEEE EEEE EEEEL` (4-4-4-5), for display only. The middle groups are
  ciphertext, not a readable batch or serial.

The card accepts exactly 17 ASCII digits whose Luhn sum, including L, is a multiple of ten. It does
not decipher E. 18-digit and other v1 (format-coded) OPIDs are rejected.

### Uniqueness and Unpredictability

- Batch numbers are unique per IIN. The root station's root-signed allocation registry refuses a
  duplicate (IIN, batch) allocation and a second SAM binding; neither the SAM nor the card can
  enforce this across batches.
- Each batch LCG has full period modulo 10^8, so `X` is unique within a batch, and therefore
  `(B, X)` is unique per IIN.
- FF1 under one key and tweak is a permutation of `[0, 10^12)`, so E, and hence the OPID, is unique
  per IIN.
- The LCG provides uniqueness and full period. The FF1 key provides unpredictability: without K,
  neither the batch nor the issuance order can be read from an OPID, and the next OPID cannot be
  predicted from earlier ones.

### Derived Identifiers

D denotes the 17 digits; E the 12 enciphered digits (see `test-vectors/opid/README.md` for the
shared vectors).

| Identifier              | Derivation                                                                                  |
| ----------------------- | ------------------------------------------------------------------------------------------- |
| GUID (CHUID tag `34`)   | RFC 9562 UUIDv8, big-endian bytes: hex `D[0..8] ‖ D[8..12] ‖ "8" ‖ D[12..15] ‖ "80" ‖ D[15..17] ‖ "4F504E504859"`, string `DDDDDDDD-DDDD-8DDD-80DD-4F504E504859` |
| UUID OID                | `2.25.` + the GUID as an unsigned 128-bit integer                                           |
| CCC card identifier     | `F0 15 ‖ 00 00 00 00 ‖ ASCII(D)` (23 octets)                                                 |
| FASC-N (CHUID tag `30`) | see below                                                                                   |

The GUID carries version nibble 8 and variant nibble 8; the node field is ASCII "OPNPHY".

FASC-N fields:

| Field                         | Value                          |
| ----------------------------- | ------------------------------ |
| Agency / System / Credential  | `9999` / `9999` / `999999` (PIV-I) |
| Credential Series (CS)        | E[2]                           |
| Individual Credential Issue   | E[3]                           |
| Person Identifier (PI)        | E[0] E[1] E[4..12] (10 digits) |
| Organizational Category (OC)  | 3 (commercial enterprise)      |
| Organizational Identifier (OI)| IIN                            |
| Person/Organization Association (POA) | 6 (organizational affiliate), always |

Every digit of E appears exactly once, so the FASC-N is unique per OPID. A CHUID whose FASC-N carries
any other POA does not match the OPID.

## OIDs

| OID                              | Name                                       | Where                         |
| -------------------------------- | ------------------------------------------ | ----------------------------- |
| `1.3.6.1.4.1.57923.20.10.10.1`   | SAM parameters packet (version 5)          | SAM PUT PARAMETERS            |
| `1.3.6.1.4.1.57923.20.10.10.2`   | F9 issuance extension (version 1)          | F9 certificate, non-critical  |
| `1.3.6.1.4.1.57923.20.10.10.3`   | SAM batch extension (version 3)            | SAM certificate, non-critical |
| `1.3.6.1.4.1.57923.20.10.20.1`   | OpenPhysical attestation extension         | leaf certificate, non-critical |
| `2.5.4.5`                        | serialNumber (carries the OPID)            | F9 subject, leaf issuer       |
| `1.2.840.10045.4.3.2`            | ecdsa-with-SHA256                          | all three signatures          |

The OpenPhysical OIDs are to be registered in the OpenPhysical.Net OID catalog.

## FIPS Profile and Key Origin

- F9 is generated on the card in every build; FipsPolicy rejects an importable F9 definition in
  every profile.
- In FIPS builds, `9A` and `9C` cannot be defined as importable. FIPS 201-3 Section 4.2.2.1: the
  PIV authentication key "SHALL be generated on the PIV Card"; Section 4.2.2.4: "The PIV digital
  signature key SHALL be generated on the PIV Card." The FIPS personalization check also requires
  `9A`, and `9C` when present, to have generated origin.
- Standard builds allow importable `9A` and `9C` for usability, as YubiKey PIV does.
- Independently of the profile, only keys generated on the card are attestable.

## Issuing Credentials

The host workflow that drives this sequence is split across two stations: the root station
allocates batches in its registry and personalizes SAMs; the production station receives a SAM and
produces cards, holding neither the root key, the FF1 keys nor the LCG parameters. Both are
documented in [OPENFIPS201_TOOL.md](OPENFIPS201_TOOL.md).

## Relationship To Other Attestation Systems

This command follows the PIV attestation shape exposed by YubiKeys: slot `F9` is the attestation
issuer, and `INS F9` returns a generated certificate for a target key. This fork differs in three
ways: F9 is generated on the card and certified through the Issuer SAM rather than imported, the F9
certificate is served by the applet itself, and `INS F9` enforces the target slot's access rules.
The implementation is independent of PivApplet.
