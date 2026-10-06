# Issuer SAM

The Issuer SAM is a Java Card applet in this repository (package `dev.mistial.openphysical.sam`,
applet class `IssuerSam`). It is the per-batch issuing CA in the attestation chain:

```text
Root CA (offline HSM) → Issuer SAM (CA:TRUE pathLen 1) → card F9 (CA:TRUE pathLen 0) → leaf
```

See [ATTESTATION.md](ATTESTATION.md) for the card side and the OPID layout.

## Trust Role

- The SAM key pair is generated on the SAM. The root certifies its public key in a certificate
  that carries the root-signed **batch extension**, binding the SAM to one IIN, one batch number, an
  initial quota, the exact LCG parameters and the FF1 key check value (through `paramsDigest`), and
  the root's allocation registry entry (`allocationSeq`, `registryHead`).
- The FF1 key reaches the SAM only wrapped to a one-time SAM transport key (PUT PARAMETERS v5).
- The SAM **allocates** each card's OPID: it advances the batch LCG and enciphers the batch number
  and LCG value with FF1 under the IIN's key. It **meters** issuance against a quota. Allocation,
  metering and the audit hash chain advance together in one transaction per issuance.
- The SAM verifies the card's proof of possession of its F9 key, then builds and signs the F9
  certificate. The host never supplies an OPID, a serial number or a quota value.
- Every event is recorded in a hash-chained ledger entry signed by the SAM key.
- Quota increases require a root signature.
- The SAM never returns `a`, `c`, `x0`, the current LCG value, the jump maps or the FF1 key.

## Identifiers

| Item         | Value                                                                    |
| ------------ | ------------------------------------------------------------------------ |
| Package AID  | `F04F50454E50485953414D` (`F0` ‖ "OPENPHY" ‖ "SAM", ISO/IEC 7816-5 category F) |
| Applet AID   | `F04F50454E50485953414D0001000000` (package ‖ `00` ‖ `01` ‖ `000000`)    |
| Version      | 0.1 (SELECT FCI tag `80`, STATUS tag `8E`)                               |
| CAP          | `build/bin/OpenPhysicalIssuerSam-0.1.cap` and `.cap.properties`          |

Category F AIDs are unregistered, so these AIDs are unique by convention only.

The SAM is contact-only: `select()` declines a contactless interface. SELECT returns the FCI
`6F 07 80 02 00 01 81 01 <lifecycle>`.

## Lifecycle

| State           | Value | Entered by                                   |
| --------------- | ----- | -------------------------------------------- |
| `INSTALLED`     | `5A`  | installation                                 |
| `PARAMS_SET`    | `69`  | PUT PARAMETERS                               |
| `KEY_GENERATED` | `96`  | GENERATE SAM KEY                             |
| `CERT_LOADED`   | `A5`  | LOAD SAM CERTIFICATE                         |
| `OPERATIONAL`   | `C3`  | LOCK                                         |
| `CLOSED`        | `E1`  | CLOSE                                        |
| `TERMINATED`    | `3C`  | TERMINATE                                    |

The values have pairwise Hamming distance of at least four and are compared only with equality, so
a single fault cannot turn one valid state into another, and an unknown value satisfies no state.

Before LOCK each personalization handler first demotes the lifecycle (one atomic write), then writes
its data, then promotes the lifecycle in one transaction. A tear leaves the SAM in an earlier state
whose data is re-provisioned by repeating the command.

- GENERATE TRANSPORT KEY may repeat in `INSTALLED` and `PARAMS_SET`; each call replaces the
  transport key.
- PUT PARAMETERS may repeat in `INSTALLED` and `PARAMS_SET`. It requires a transport key (`6985`
  otherwise) and destroys it on success.
- GENERATE SAM KEY may repeat from `PARAMS_SET`, `KEY_GENERATED` or `CERT_LOADED`; from
  `CERT_LOADED` it drops the certificate and returns to `KEY_GENERATED`.
- LOAD SAM CERTIFICATE may repeat in `KEY_GENERATED` and `CERT_LOADED`.
- After LOCK (`OPERATIONAL`, `CLOSED`, `TERMINATED`) every personalization command returns `6985`.
- CLOSE moves `OPERATIONAL` to `CLOSED`: BEGIN ISSUANCE, ISSUE and TOP UP are refused (`6985`);
  STATUS, LAST ENTRY, VERIFY PIN, CHANGE OPERATOR PIN, DECIPHER, VOID and TERMINATE remain. CLOSE in
  `CLOSED` is idempotent.
- TERMINATE (from `OPERATIONAL` or `CLOSED`) clears the SAM private key, the transport key, the FF1
  key, the LCG parameters and state, and the jump maps; the SAM can sign, issue and decipher nothing
  afterwards.

## Access Control

- CLA `80` is plaintext and `84` is secure-channel protected. A command counts as protected only if
  a GlobalPlatform secure channel with AUTHENTICATED, C_DECRYPTION and C_MAC exists and unwrapped
  that APDU. An `84` command without such a session returns `6982`.
- Personalization (GENERATE TRANSPORT KEY, PUT PARAMETERS, SET OPERATOR PIN, GENERATE SAM KEY,
  LOAD SAM CERTIFICATE, LOCK), VERIFY PIN, CHANGE OPERATOR PIN and GET DATA PARAMS / LAST RESULT
  require the secure channel. The FF1 key in PUT PARAMETERS is additionally wrapped, on the root
  token, to the SAM transport key (see [PUT PARAMETERS v5](#put-parameters-v5)).
- BEGIN ISSUANCE and ISSUE require the secure channel, a verified operator PIN and the `OPERATIONAL`
  state. DECIPHER, VOID, CLOSE and TERMINATE require the secure channel, a verified operator PIN and
  `OPERATIONAL` or `CLOSED`. A missing channel or PIN is `6982`; a wrong state is `6985`.
- TOP UP authenticates itself with a root ECDSA signature; the secure channel is optional. It is
  accepted only in `OPERATIONAL`.
- GET DATA STATUS, SAM CERTIFICATE and LAST ENTRY are plaintext.
- Responses are not secure-channel wrapped. Authenticity of SAM output comes from the SAM
  signatures (ledger entries, signed STATUS), not from the channel. No SAM response carries secret
  material.
- The operator PIN is 6 to 16 octets with 5 tries. INITIALIZE UPDATE and deselection reset its
  verified state. CHANGE OPERATOR PIN checks the old PIN against the same retry counter. There is no
  unblock: a blocked PIN permanently disables every PIN-gated command.
- The chaining bit (CLA `90` / `94`) is accepted only on PUT PARAMETERS, LOAD SAM CERTIFICATE and
  ISSUE. Every ISSUE frame requires the lifecycle, secure channel and operator PIN; only the last
  frame uses the nonce, and a rejected frame abandons the chain. A
  chain is bound to its INS, P1-P2 and the protection of its first frame; a frame with different
  protection abandons the chain with `6982`. A rejected PUT PARAMETERS frame zeroizes the staged
  packet.
- Responses longer than Ne are returned with `61xx` and continued with GET RESPONSE
  (`00`/`80`/`84 C0 00 00`). Any other command abandons a pending response.

## Commands

| Command              | CLA     | INS | P1 P2   | Data                                   | Response                       | State                           | Status words |
| -------------------- | ------- | --- | ------- | -------------------------------------- | ------------------------------ | ------------------------------- | ------------ |
| SELECT               | `00`    | A4  | `04 00` | applet AID                             | FCI                            | any                             | — |
| INITIALIZE UPDATE    | `80`    | 50  | per GP  | host challenge                         | per GP                         | any                             | per GP |
| EXTERNAL AUTHENTICATE| `84`    | 82  | per GP  | host cryptogram                        | —                              | any                             | per GP |
| GENERATE TRANSPORT KEY | `84`  | 4A  | `00 00` | —                                      | `86 41 04XY` (transport point) | `INSTALLED`, `PARAMS_SET`       | `6982`, `6985` |
| PUT PARAMETERS       | `84`/`94` | D0 | `00 00` | IssuerSamParameters v5 (≤ 512 octets) | —                              | `INSTALLED`, `PARAMS_SET`       | `6982`, `6985`, `6A80`, `6700` |
| SET OPERATOR PIN     | `84`    | D2  | `00 81` | PIN, 6..16 octets                      | —                              | before LOCK                     | `6982`, `6985`, `6A80` |
| GENERATE SAM KEY     | `84`    | 46  | `00 00` | —                                      | `86 41 04XY`                   | `PARAMS_SET`..`CERT_LOADED`     | `6982`, `6985` |
| LOAD SAM CERTIFICATE | `84`/`94` | D4 | `00 00` | certificate DER (≤ 1024 octets)       | `8B 14 <SAM SKI>`              | `KEY_GENERATED`, `CERT_LOADED`  | `6982`, `6985`, `6A80`, `6300`, `6700` |
| LOCK                 | `84`    | D6  | `00 00` | —                                      | `71 L genesis 72 L sig`        | `CERT_LOADED`                   | `6982`, `6985`, `6A84` |
| VERIFY PIN           | `84`    | 20  | `00 81` | PIN, or empty for status               | —                              | `OPERATIONAL`, `CLOSED`         | `6982`, `6985`, `6A80`, `63Cx`, `6983` |
| CHANGE OPERATOR PIN  | `84`    | 24  | `00 81` | `80 L oldPIN ‖ 81 L newPIN` (6..16 each) | —                            | `OPERATIONAL`, `CLOSED`         | `6982`, `6985`, `6A80`, `63Cx`, `6983` |
| BEGIN ISSUANCE       | `84`    | 84  | `00 00` | —                                      | N (32 octets)                  | `OPERATIONAL`                   | `6982`, `6985`, `6A84` |
| ISSUE                | `84`/`94` | 2A | `00 F9` | `86 41 F9pub ‖ 9E L PoP ‖ 93 L Validity ‖ 94 20 capSha256 ‖ 95 20 cplcSha256` (≤ 275 octets) | `70 L cert ‖ 71 L entry ‖ 72 L sig` | `OPERATIONAL`              | `6982`, `6985`, `6A80`, `6A84`, `6300`, `6500`, `6700` |
| DECIPHER             | `84`    | 2C  | `00 00` | `80 11 <17 ASCII digits>`              | `81 04 batch ‖ 82 01 sameBatch [‖ 83 04 n ‖ 84 01 issued]` | `OPERATIONAL`, `CLOSED` | `6982`, `6985`, `6A80`, `6A88` |
| VOID                 | `84`    | 2E  | `00 00` | `80 04 issuanceSeq ‖ 81 01 reason`     | `71 L entry ‖ 72 L sig`        | `OPERATIONAL`, `CLOSED`         | `6982`, `6985`, `6A80` |
| CLOSE                | `84`    | E8  | `00 00` | —                                      | `71 L entry ‖ 72 L sig`        | `OPERATIONAL`, `CLOSED`         | `6982`, `6985` |
| TOP UP               | `80`/`84` | 32 | `00 00` | `80 08 ts ‖ 81 04 add ‖ 9E L rootSig` | `71 L entry ‖ 72 L sig`        | `OPERATIONAL`                   | `6985`, `6300`, `6A80` |
| GET DATA STATUS      | `80`/`84` | CA | `00 01` | —                                     | STATUS TLV                     | any                             | — |
| GET DATA SIGNED STATUS | `80`/`84` | CA | `01 01` | host nonce, 16..32 octets           | STATUS TLV ‖ `9E L sig`        | SAM key present, not `TERMINATED` | `6A80`, `6985` |
| GET DATA SAM CERT    | `80`/`84` | CA | `00 02` | —                                     | SAM certificate DER            | `CERT_LOADED` or later          | `6985` |
| GET DATA LAST ENTRY  | `80`/`84` | CA | `00 03` | —                                     | `71 L entry ‖ 72 L sig` (`71` only when `TERMINATED`) | `OPERATIONAL`, `CLOSED`, `TERMINATED` | `6985` |
| GET DATA PARAMS      | `84`    | CA  | `00 04` | —                                      | PARAMS TLV                     | `PARAMS_SET` or later           | `6982`, `6985` |
| GET DATA LAST RESULT | `84`    | CA  | `00 05` | —                                      | the last ISSUE response        | `OPERATIONAL`                   | `6982`, `6985` |
| TERMINATE            | `84`    | E6  | `00 00` | —                                      | `71 L entry ‖ 72 L sig`        | `OPERATIONAL`, `CLOSED`         | `6982`, `6985` |

Common status words: `6E00` for an unsupported CLA, `6D00` for an unknown INS, `6A86` for wrong
P1-P2, `6700` for command data on a GET DATA `P1=00` form, and `6F00` for an unexpected error before
any commit.

Status words specific to the SAM:

| SW     | Meaning                                                                                |
| ------ | -------------------------------------------------------------------------------------- |
| `6300` | Signature verification failed (root signature on the SAM certificate or top-up, or the F9 proof of possession). Persistent state is unchanged. |
| `6500` | Failure after the issuance (or ledger) commit. The OPID is burned; GET DATA LAST ENTRY recovers the committed entry. |
| `6A84` | Quota or LCG period exhausted, an event counter would overflow, or insufficient commit capacity at LOCK. |
| `6A88` | DECIPHER: the OPID belongs to another IIN.                                             |
| `6985` | Conditions of use not satisfied: wrong lifecycle state, including any personalization command after LOCK. |

LOCK returns `6985` when the operator PIN is not set or the stored parameters do not re-validate,
and `6A84` when `JCSystem.getMaxCommitCapacity()` is below 512 octets.

### STATUS and PARAMS

STATUS TLV (each tag has a one-octet length):

| Tag  | Value                                                      |
| ---- | ---------------------------------------------------------- |
| `80` | lifecycle                                                  |
| `82` | IIN, 4 ASCII digits                                        |
| `83` | batch number, 4 ASCII digits                               |
| `85` | issued, u32                                                |
| `86` | quota, u32                                                 |
| `87` | m = 10^8, u32                                              |
| `88` | last accepted top-up timestamp, u64 ms                     |
| `89` | eventSeq, u32                                              |
| `8A` | chain head, 32 octets                                      |
| `8B` | SAM SKI, 20 octets                                         |
| `8C` | PIN set flag, tries remaining                              |
| `8E` | version major, minor                                       |
| `8F` | allocationSeq from the batch extension, u32                |
| `90` | registryHead from the batch extension, 32 octets           |

The signed STATUS form appends `9E L sig`, an ECDSA P-256 / SHA-256 signature by the SAM key over
`"OPSAMSTAT1" ‖ nonce ‖ STATUS TLV`.

PARAMS TLV (non-secret fields only): `82` IIN, `83` batch (ASCII digits), `85` issued, `86` quota,
`93` paramsDigest (32 octets). The issuance software that generated the parameters checks them
against `paramsDigest`.

## PUT PARAMETERS v5

GENERATE TRANSPORT KEY first creates a one-time P-256 key pair on the SAM and returns its public
point. One PUT PARAMETERS command then carries every parameter, including the FF1 key wrapped to that
transport key. The packet is DER only and every field is validated, and the key unwrapped, before
anything is written; the lifecycle moves to `PARAMS_SET` only after every field, the derived jump
maps and `paramsDigest` are stored. The transport key is destroyed after a successful command.

```asn1
IssuerSamParameters ::= SEQUENCE {
  type               OBJECT IDENTIFIER,     -- 1.3.6.1.4.1.57923.20.10.10.1
  version            INTEGER (5),
  issue              [16] IMPLICIT SEQUENCE {
    issuerId         INTEGER (0..9999),
    batchNumber      INTEGER (0..9999),
    initialQuota     INTEGER (0..100000000) },
  lcg                [17] IMPLICIT SEQUENCE {
    seed             INTEGER (0..99999999),  -- x0
    modulus          INTEGER (100000000),    -- exactly 10^8
    multiplier       INTEGER,                -- a
    increment        INTEGER },              -- c
  f9SubjectTemplate  [20] EXPLICIT Name,     -- RDN content at most 96 octets, may be empty,
                                             -- must not contain serialNumber
  samSubject         [21] EXPLICIT Name OPTIONAL,  -- at most 128 octets; if present, the SAM
                                                   -- certificate subject must equal it
  rootPublicKey      [22] IMPLICIT OCTET STRING (SIZE 65),  -- uncompressed P-256, validated on curve
  initialTimestamp   [23] IMPLICIT OCTET STRING (SIZE 8),   -- u64 ms, big-endian
  wrappedFpeKey      [24] IMPLICIT SEQUENCE {
    hostEphemeralPublicKey OCTET STRING (SIZE 65),  -- uncompressed P-256, validated on curve
    wrappedKey             OCTET STRING (SIZE 40) } -- RFC 3394 AES key wrap of the FF1 key
}
```

The FF1 key is recovered as follows:

```text
Z   = ECDH(transportPriv, hostEph)                  -- 32-octet x-coordinate
KEK = SHA-256(Z ‖ 00000001 ‖ "OPSAMKT1" ‖ transportPub(65) ‖ hostEph(65) ‖ ASCII(IIN)(4))
K   = AES-256 key unwrap (RFC 3394, default IV A6…A6) of wrappedKey under KEK
```

Binding the IIN into the KDF ties the wrapped key to the IIN in the same packet. An integrity
failure of the unwrap is `6A80` with nothing written. Without a transport key PUT PARAMETERS returns
`6985`.

All INTEGERs are non-negative and fit 32 bits. A violation returns `6A80`. The packet may be
command-chained and is staged at offset 512 of the 1056-octet I/O buffer (at most 512 octets).
The staged packet and the APDU buffer are zeroized after the command, whether it succeeds or fails.

## OPID Allocation

### LCG

The SAM never chooses its LCG parameters. The root station generates `a`, `c` and `x0` from a
CSPRNG, records them in its batch record (production stations never hold them), and provisions them
with PUT PARAMETERS. The SAM has no
parameter-generation code path: it validates, stores, binds the parameters to the root-signed batch
extension through `paramsDigest`, and advances `x` as it issues.

```text
f(x) = (a·x + c) mod 10^8
```

The SAM checks the Hull–Dobell full-period conditions for `m = 10^8`:

- `0 <= a, c, x0 < m`;
- the units digit of `c` is 1, 3, 7 or 9 (`gcd(c, 10) = 1`);
- `a ≡ 1 (mod 20)`: units digit 1 and an even tens digit;
- `a ≠ 1` (a counter is rejected).

With these conditions the sequence has full period `m`.

Values are held as little-endian arrays of 8 decimal digit values. `f` is computed with schoolbook
multiplication truncated to 8 digits: reduction modulo `10^8` is truncation, so every partial
product and carry at digit position 8 or above is discarded. All loop bounds are fixed and all
arithmetic uses `short` intermediates (`t <= 9 + 9·9 + 9`), so the result is exact.

Issuance number `n >= 1` uses

```text
x_n = f^n(x0)
```

so the first issuance uses `f(x0)`, never `x0`. LOCK sets `x = x0`; each ISSUE commits `x = f(x)`
and `issued = n`. The SAM issues only while `issued < quota` and `issued < 10^8`; the second bound
stops the sequence before it would return to `x0`.

### FF1

```text
E = FF1_K(B ‖ X, T)    B = batch (4 digits), X = x_n (8 digits), T = ASCII(IIN) (4 octets)
OPID = IIN ‖ E ‖ Luhn(IIN ‖ E)
```

- FF1 is NIST SP 800-38G Rev. 1 Algorithms 7 (encrypt) and 8 (decrypt) with AES-256 and radix 10.
  The SAM implementation supports 6 to 12 digits and is used with n = 12 (u = v = 6, b = 3, d = 8).
  The PRF is AES-256-CBC-MAC with a zero IV over the two-block input `P ‖ Q`.
- The numeral additions and subtractions modulo `10^m` are done digit-wise in `short` arithmetic;
  all intermediates are zeroized on return.
- The domain is exactly `[0, 10^12)`, so there is no cycle-walking.
- K is one key per IIN, shared by every batch and every SAM of that IIN. It is provisioned in PUT
  PARAMETERS (`wrappedFpeKey`) and committed to the SAM certificate only through its key check
  value:

```text
fpeKcv = SHA-256("OPSAMFPEKCV1" ‖ AES-256-ECB_K(0^16))[0..16)
```

`x_n` itself never leaves the SAM.

### Jump Maps

PUT PARAMETERS derives eight affine maps from `(a, c)` and stores them:

```text
M_j = f^(10^(j-1)),  j = 1..8,  as pairs (A_j, C_j) mod 10^8,  M_1 = (a, c),  M_(j+1) = M_j^10
```

For a full-period LCG modulo `10^8`, `x mod 10^j` is itself a full-period LCG modulo `10^j`, so the
low `j` digits of `x_n` depend only on `n mod 10^j`. This lets DECIPHER recover `n` from `X` one
decimal digit at a time with at most 9 map applications per digit (at most 72 in total). The jump
maps are secret and never returned.

### paramsDigest v3

```text
paramsDigest = SHA-256("OPSAMPRM3" ‖ IIN digits(4) ‖ batch digits(4)
                       ‖ a digits(8) ‖ c digits(8) ‖ x0 digits(8)
                       ‖ initialQuota(u32 BE) ‖ initialTimestamp(u64 BE) ‖ fpeKcv(16))
```

The preimage is 69 octets. Each digit is one octet with value 0..9; IIN and batch digits are most
significant first, `a`, `c` and `x0` digits least significant first. The SAM computes it once at PUT
PARAMETERS, from the initial quota and timestamp, and stores it. The FF1 key itself never enters the
digest. The host computes the same value (`test-vectors/opid/fpe.json`, `paramsDigestV3[]`).

## DECIPHER

```text
84 2C 00 00  Lc  80 11 <17 ASCII digits>
→ 81 04 <batch, 4 ASCII digits>  82 01 <sameBatch>  [83 04 <n, u32>  84 01 <issued>]
```

1. The data is exactly `80 11` and 17 ASCII digits with a valid Luhn digit (`6A80`).
2. The IIN must be this SAM's IIN (`6A88`).
3. `(B ‖ X) = FF1.Decrypt_K(E, ASCII(IIN))`.
4. The response carries B and whether B is this SAM's batch.
5. For this SAM's batch only, the SAM recovers `n` with `f^n(x0) = X` using the jump maps (start at
   `y = x0`; for digit `j = 1..8`, apply `M_j` until the low `j` digits of `y` equal those of `X`,
   recording the count as digit `j` of `n`). It returns `n` and `issued = 01` when
   `1 <= n <= issued`. `n = 0` means `X = x0`, which is never issued.

X is never returned. Because the FF1 key is per IIN, DECIPHER reveals the batch number of any
well-formed OPID of the same IIN, including OPIDs issued by other SAMs; it reveals the issuance index
only for its own batch.

## SAM Certificate (root-issued)

LOAD SAM CERTIFICATE parses the certificate strictly and returns `6A80` on any deviation:

- one DER Certificate, no trailing octets; v3; serial 1..20 octets, positive and minimal;
- `signature` and `signatureAlgorithm` are both exactly ecdsa-with-SHA256 without parameters;
- issuer and subject are valid Names; subject at most 128 octets and equal to the provisioned
  `samSubject` when one was given;
- SubjectPublicKeyInfo byte-equals the SAM's own P-256 SPKI; no unique identifiers;
- extensions, no duplicate OIDs:
  - basicConstraints critical, `cA TRUE`, pathLenConstraint exactly 1;
  - keyUsage critical, DER BIT STRING asserting keyCertSign;
  - subjectKeyIdentifier non-critical, equal to the RFC 7093 method 1 value of the SAM key;
  - the batch extension, non-critical, equal to the stored parameters;
  - any other critical extension is rejected.

If the profile holds but the signature does not verify under the provisioned root key, the SAM
returns `6300`. The validity is stored and bounds every F9 validity the SAM will sign.

### Batch Extension v3

```asn1
SamBatchExtension ::= SEQUENCE {     -- 1.3.6.1.4.1.57923.20.10.10.3, non-critical
  version           INTEGER (3),
  issuerId          INTEGER,
  batch             INTEGER,
  initialQuota      INTEGER,
  initialTimestamp  OCTET STRING (SIZE 8),
  paramsDigest      OCTET STRING (SIZE 32),
  allocationSeq     INTEGER,               -- sequence number of the root allocation registry entry
  registryHead      OCTET STRING (SIZE 32) -- registry hash-chain head after that entry
}
```

`version` must be 3 and the next five fields must equal the stored values; `paramsDigest` must equal
the digest recorded at PUT PARAMETERS. Through this extension the root authorizes the IIN, the batch number, the initial
quota, the top-up timestamp floor, the exact LCG parameters and the FF1 key (by its check value).
`allocationSeq` and `registryHead` are not checked by the SAM; it stores them and reports them in
STATUS (`8F`, `90`) so the SAM is traceable to the root's allocation registry. Only digests appear in
the certificate.

## Issuance

### Per-card sequence

```text
SAM   84 20 00 81  PIN                          VERIFY PIN
SAM   84 84 00 00                               → N (32 octets)
card  84 F9 F9 01  20  N  00                    → PoP
SAM   84 2A 00 F9  86 41 F9pub 9E L PoP 93 L Validity 94 20 capSha256 95 20 cplcSha256 (chained)
                                                → 70 L cert  71 L entry  72 L sig
card  84 24 11 F9  30 82 LL LL 70 82 LL LL cert (chained)
```

The card and the SAM are separate applets in separate readers. Selecting another applet on the SAM's
card deselects the SAM, which clears the nonce and the operator session.

The nonce is single-use. It is consumed at the start of ISSUE, and by any other command sent to the
SAM between BEGIN and ISSUE except GET RESPONSE (and by SELECT and deselection). One BEGIN therefore
permits at most one ISSUE attempt.

### ISSUE order

1. Lifecycle, secure channel and operator PIN.
2. Require an active nonce (`6985`), copy it into the PoP message, and consume it.
3. Strict parse: `86 41 F9pub`, `9E L PoP`, `93 L Validity`, `94 20 capSha256`,
   `95 20 cplcSha256`, each once, in order, nothing trailing (`6A80`). The `93` value is a DER
   Validity of at most 64 octets. Both measurements are required: the earlier three-element form,
   a missing, short, long, swapped or repeated measurement is `6A80`. The request is assembled at
   the top of the I/O buffer; a chain longer than 275 octets is refused with `6700` while it is
   assembled. `capSha256` is the host-measured SHA-256 of the PIV CAP file installed on the card and
   `cplcSha256` the SHA-256 of the card's CPLC data; the SAM cannot measure either and binds both,
   as supplied, into the F9 issuance extension and the ISSUE ledger entry.
4. The F9 point is on P-256 and differs from the SAM key and the root key (`6A80`).
5. Validity: `notBefore < notAfter`, `notBefore >= SAM notBefore`, `notAfter <= SAM notAfter`
   (`6A80`).
6. Capacity: `issued < quota` and `issued < 10^8` (`6A84`).
7. Verify the PoP `"OPF9POP" ‖ N ‖ F9pub` under the F9 point (`6300`).
8. In transient memory: `x' = f(x)`, `issued' = issued + 1`, `eventSeq' = eventSeq + 1`,
   `E = FF1_K(batch ‖ x', ASCII(IIN))` and the 17-digit OPID. The FF1 work area is zeroized.
9. A random positive non-zero 16-octet serial.
10. The TBSCertificate and `tbsHash = SHA-256(TBS)`.
11. The ISSUE ledger entry and its hash, the new chain head.
12. **One transaction** that re-checks the lifecycle and capacity, then writes `x`, `issued`,
    `eventSeq`, the chain head and the last entry. This is the only point at which an OPID is
    consumed.
13. After the commit: sign the `tbsHash` read back from the persistent last entry, finish the
    certificate, sign the entry.

Steps 2 to 11 change no persistent state; a failure there leaves the SAM unchanged except for the
consumed nonce. Any failure after step 12 returns `6500`.

### Burn semantics and recovery

Once step 12 commits, the OPID is burned: it is never issued again, whether or not the host receives
the certificate.

- **Lost response.** If the ISSUE response is lost, `84 CA 00 05` (GET DATA LAST RESULT) re-serves the
  complete response from RAM without re-signing, provided no other command has been sent since.
  GET RESPONSE, VERIFY PIN, INITIALIZE UPDATE and EXTERNAL AUTHENTICATE do not clear it; every other
  command and deselection do.
- **`6500` or no LAST RESULT.** GET DATA LAST ENTRY returns the committed ISSUE entry (OPID, F9 SKI,
  capSha256, cplcSha256, tbsHash) with a fresh SAM signature over the persistent chain head. The certificate itself is not
  recoverable. The card is issued again with a new BEGIN, PROVE and ISSUE and receives the next OPID.
- DECIPHER confirms that an OPID belongs to this batch and was issued (`n <= issued`).
- VOID records a signed VOID entry for a burned issuance, so relying parties can be told the OPID
  is not in use.

The SAM does not track F9 public keys, so a second ISSUE for the same F9 key yields a second
certificate with a different OPID. Only the certificate the card loads is ever served by the card;
duplicate `f9Ski` values in the ledger identify such re-issuance.

## F9 Certificate Profile

The SAM builds the F9 certificate inside the `70` response frame:

| Field                | Value                                                                             |
| -------------------- | --------------------------------------------------------------------------------- |
| version              | v3                                                                                |
| serialNumber         | 16 random octets, positive and non-zero                                           |
| signature            | ecdsa-with-SHA256, parameters absent                                              |
| issuer               | the SAM certificate subject, exact DER                                            |
| validity             | as supplied by the host in ISSUE, inside the SAM certificate validity             |
| subject              | template RDNs ‖ final RDN `serialNumber` (2.5.4.5, PrintableString) = 17-digit OPID |
| subjectPublicKeyInfo | id-ecPublicKey / prime256v1, the card's F9 point                                  |

Extensions, in order:

| Extension                       | Criticality  | Value                                                      |
| ------------------------------- | ------------ | ---------------------------------------------------------- |
| basicConstraints                | critical     | `30 06 01 01 FF 02 01 00` (cA TRUE, pathLenConstraint 0)   |
| keyUsage                        | critical     | `03 02 02 04` (keyCertSign)                                |
| subjectKeyIdentifier            | non-critical | RFC 7093 method 1 of the F9 point                          |
| authorityKeyIdentifier          | non-critical | keyIdentifier = SAM SKI                                    |
| F9 issuance extension           | non-critical | see below                                                  |

```asn1
F9IssuanceExtension ::= SEQUENCE {   -- 1.3.6.1.4.1.57923.20.10.10.2
  version        INTEGER (2),
  issuanceSeq    INTEGER,                 -- n: this card is the n-th issuance of the batch
  eventSeq       INTEGER,                 -- ledger event number of this ISSUE entry
  prevChainHead  OCTET STRING (SIZE 32),  -- chain head before this entry
  capSha256      OCTET STRING (SIZE 32),  -- SHA-256 of the installed PIV CAP file (host-measured)
  cplcSha256     OCTET STRING (SIZE 32)   -- SHA-256 of the card's CPLC data (host-measured)
}
```

Version 1 (without `capSha256` and `cplcSha256`) is rejected by `attestation verify`. See
[ATTESTATION.md](ATTESTATION.md#build-cap-and-cplc-identity) for what the measurements prove.

The worst case (128-octet SAM subject, 96-octet template, GeneralizedTime validity, five-octet
`eventSeq` INTEGER, 72-octet signature) is 756 octets, inside the card's 760-octet (`0x2F8`) limit;
`F9CertificateSizeTest` checks it. The template is at most 96
octets of RDN content, so the subject with the OPID stays within the card's 128-octet limit. The PIV
card checks the profile as described in [ATTESTATION.md](ATTESTATION.md#f9-certificate-profile).

## Ledger

### Entry format

```text
"OPSAMLE1"(8) ‖ type(1) ‖ samSki(20) ‖ eventSeq(4) ‖ prevHead(32) ‖ payload

GENESIS 01: sha256(samCert)(32) ‖ paramsDigest(32) ‖ quota(4) ‖ lastTs(8)
ISSUE   02: issuanceSeq(4) ‖ opidLen(1) = 17 ‖ opid(17) ‖ f9Ski(20) ‖ capSha256(32)
            ‖ cplcSha256(32) ‖ tbsHash(32)
TOPUP   03: ts(8) ‖ added(4) ‖ newQuota(4)
TERM    04: issued(4) ‖ quota(4)
VOID    05: issuanceSeq(4) ‖ opidLen(1) = 17 ‖ opid(17) ‖ reason(1)
CLOSE   06: issued(4) ‖ quota(4)
```

- VOID takes `80 04 issuanceSeq ‖ 81 01 reason` with `1 <= issuanceSeq <= issued` (`6A80`
  otherwise). The SAM recomputes the OPID of that issuance itself (jump maps, then FF1); the host
  never supplies it. Repeated voids of the same issuance are allowed. Reason `1` is used for
  reissue, `0` is unspecified.
- CLOSE commits the CLOSE entry once and enters `CLOSED`. A repeated CLOSE re-serves the stored
  CLOSE entry with a fresh signature and writes nothing.

- All integers are unsigned big-endian.
- GENESIS is event 1 with `prevHead = 0^32`. Every later entry has `eventSeq = previous + 1` and
  `prevHead = SHA-256(previous entry)`.
- `head_n = SHA-256(entry_n)`. The SAM persists the current head and the last entry (at most 203
  octets: an ISSUE entry is the 65-octet header and a 138-octet payload).
- `capSha256` and `cplcSha256` in an ISSUE entry are the values received in ISSUE, identical to
  those in the F9 issuance extension. The host refuses an entry that binds other values than it
  sent.
- The SAM signs each entry with `signPreComputedHash(SHA-256(entry))`, so a verifier uses plain
  SHA256withECDSA over the entry bytes.
- The domain prefix never starts with `0x30`, so an entry cannot be parsed as a certificate.
- `tbsHash` in an ISSUE entry is the hash the SAM signs for the F9 certificate, which binds the entry
  to exactly one certificate.
- Entries carry the enciphered OPID only; the plaintext batch and LCG value are not in the ledger.

Every event follows one order: validate without state changes, compute in transient memory, commit
in one transaction, then sign.

Responses carry `71 L entry ‖ 72 L sig`. The SAM keeps only the last entry; the full chain is the
issuance software's ledger, which it verifies from GENESIS and compares with the SAM's current head.

## Quota Top-Up

The root authorizes additional quota with a signed message:

```text
M = "OPSAMTOPUP1" ‖ samSki(20) ‖ ts(u64 ms BE) ‖ add(u32 BE)
TOP UP data = 80 08 ts ‖ 81 04 add ‖ 9E L ECDSA-P256-SHA256_root(M)
```

TOP UP is accepted only in `OPERATIONAL` (`6985`).

1. Verify the root signature over `M` (`6300`). Binding to `samSki` prevents reuse on another SAM.
2. Require `ts` strictly greater than the last accepted timestamp, unsigned (`6985`). The first
   top-up must exceed `initialTimestamp` from the batch extension. This rejects replays and older
   authorizations.
3. Require `add > 0`, no overflow, and `quota + add <= 10^8` (`6A80`).
4. Commit quota, timestamp, eventSeq, chain head and the TOPUP entry in one transaction.

Because acceptance is strictly monotonic in `ts`, applying a newer authorization makes every
unapplied older one permanently invalid.

## Memory

- **Transient (`CLEAR_ON_DESELECT`), allocated at install:** 1056-octet I/O buffer (also the EC
  point validator workspace and the staging area for chained commands), 320-octet scratch (also the
  FF1 work area), 33-octet nonce and state, plus small chaining, DER writer and TLV reader contexts.
  About 1.45 KB. There is no persistent fallback. The I/O buffer holds the largest response, ISSUE:
  `70 82 LL LL` and a 756-octet F9 certificate, `71 81 CB` and the 203-octet entry, and `72 L` with
  a signature of at most 72 octets, 1040 octets in all.
- **Persistent:** about 1.8 KB of state (SAM certificate up to 1024 octets, last entry 203, F9
  subject template 96, expected SAM subject 128, LCG digits, 128 octets of jump maps, paramsDigest,
  counters, chain head, SKI, validity bounds, allocationSeq, registryHead, CLOSE entry), the
  operator PIN, six P-256 key objects (SAM private and public, root public, the F9 public key of the
  card being issued, transport private and public) and one AES-256 key object for FF1. Java Card
  3.0.5 has no transient EC public key, so these are persistent objects; the transport pair is
  cleared after PUT PARAMETERS.
- A transient (`CLEAR_ON_DESELECT`) AES-256 KEK for the transport unwrap.
- One `Signature` (ECDSA SHA-256), one `MessageDigest`, one `RandomData`, two `KeyPair`s (SAM,
  transport), one `KeyAgreement` (`ALG_EC_SVDP_DH_PLAIN`), an AES CBC `Cipher` (the FF1 PRF) and an
  AES ECB `Cipher` (key unwrap), each allocated at install. A platform without AES-256 fails
  installation.
- LOCK requires at least 512 octets of commit capacity for the per-event transactions.
- Platform requirements: ECDSA P-256 sign and verify, ECDH P-256 (`ALG_EC_SVDP_DH_PLAIN`),
  `Signature.signPreComputedHash`, AES-256, and the RAM above.

## Build and Test

```sh
ant -f build/build.xml compile-sam   # build/bin/OpenPhysicalIssuerSam-0.1.cap and .cap.properties
ant -f build/build.xml test-sam      # SAM unit and APDU tests (slow tests excluded)
```

- `preprocess-sam` copies the shared, profile-independent classes `TLV`, `TLVReader`, `DERWriter`,
  `DERValidator`, `ECParams`, `ECParamsP256` and `ECPointValidator` from the PIV package, rewrites
  their package, and prepends a GENERATED header. The build fails if the whitelist is incomplete or a
  shared file contains a JPP directive. The shared sources' SHA-256 values are written to
  `build/sam/shared-sources.sha256`. The SAM is not built as a library CAP.
- `test` runs `test-sam` once; `test-all` runs it with slow tests included (`-Dsam.include.slow=true`).
- `clean-sam` removes the SAM build outputs.
- Tests live in `src/dev/mistial/sam-tests/`, outside the PIV profile matrix. The LCG, FF1, jump-map,
  DECIPHER and paramsDigest vectors are shared with the host in `test-vectors/opid/`.

### Emulator limitations

- jCardEngine does not roll back persistent writes on `abortTransaction`. Tear and abort behaviour is
  covered by white-box commit-ordering tests (writes happen inside the transaction, signing after the
  commit) rather than end-to-end tears. Atomicity on power loss must be qualified on the target chip.
- jCardEngine offers no logical channels. The dual-applet test installs the PIV applet and the SAM
  together to show they coexist, but runs issuance against a second engine for the card, matching the
  production topology of separate card and SAM readers.
