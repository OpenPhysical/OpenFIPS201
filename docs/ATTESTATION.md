# Attestation

This fork implements a PIV attestation command with a different provisioning and access-control
model from YubiKey attestation. This applet does not import or parse an issuer X.509 certificate.
Instead, provisioning commits an attestation authority profile directly: the F9 issuer key, the
issuer subject `Name` DER, and the issuer certificate `Validity` DER.

This avoids issuer-certificate desynchronization inside the card. The provisioning system remains
responsible for creating, storing, and publishing the external issuer certificate that corresponds
to the committed F9 public key and subject name.

## Provisioning Order

The attestation authority operation is destructive and must be the first provisioning step.

When the operation succeeds, the applet stores the F9 attestation key and issuer profile, then
clears every other PIV key object's key material and clears every PIV data object's contents. Object
definitions, configuration, PIN/PUK state, and the current GlobalPlatform secure channel state are
preserved.

Do not run this operation after cardholder keys or certificates have been provisioned unless the
intent is to wipe them.

## Authority Operation

The authority profile is injected through administrative `CHANGE REFERENCE DATA` because it is key
and key-adjacent reference data. It must be sent over a GlobalPlatform secure channel with
authentication, command encryption, and command MAC.

Use `P1=11` and `P2=F9`, where `11` is the PIV ECC P-256 mechanism and `F9` is the attestation
authority key reference. Each command carries the applet's existing key-update shape: a `SEQUENCE`
containing exactly one element.

```text
84 24 11 F9  30 len 86 len  F9 ECC P-256 public point W, uncompressed X9.62 form
84 24 11 F9  30 len 87 len  F9 ECC P-256 private scalar S
84 24 11 F9  30 len 92 len  issuer subject, DER X.509 Name
84 24 11 F9  30 len 93 len  issuer validity, DER X.509 Validity
84 24 11 F9  30 02  E0 00   clear staged F9 key material and profile
```

The clear element tag is `E0`. A tag byte with bits B5-B1 all set (such as `FF`) starts a BER
multi-byte tag and cannot be used as a key element tag.

The elements may arrive in any order. When the fourth required element is accepted, the applet
validates the F9 key pair, commits the authority profile, and clears existing object contents.
Re-importing F9 profile metadata after a successful commit recommits the authority and runs the
same destructive clear. Re-importing F9 key material stages a key rotation; the applet waits for
both public and private key elements before validating the new keypair and running the destructive
clear, so a partial key rotation cannot activate a mixed old/new authority.

The host provisioning tool sends an F9 clear element before importing a replacement authority
profile. This makes re-provisioning deterministic: the applet commits once, on the final required
element, instead of temporarily combining new key material with an old subject or validity profile.

The subject is stored as exact DER and is not interpreted as text. Any valid X.509 `Name` shape is
allowed, including non-CN-first names, multi-RDN names, and multi-attribute RDNs. The subject is
capped at `0x80` bytes of DER and the validity at `0x40`; attestation issuer names are
intentionally small, while target keys up to RSA-2048 are supported.

The validity is stored as exact DER:

```asn1
Validity ::= SEQUENCE {
  notBefore  Time,
  notAfter   Time
}
```

Both `UTCTime` and `GeneralizedTime` are accepted.

## Attestation Command

The attestation command is:

```text
00 F9 <slot> 00 [Le]
```

The response is a raw DER X.509 certificate for the requested target slot. It is not wrapped in a
PIV data-object tag.

Supported target slots are `9A`, `9C`, `9D`, `9E`, and retired slots `82` through `95`.

Supported target key algorithms are RSA-1024, RSA-2048, ECC P-256, and ECC P-384. The attestation
issuer key is always ECC P-256 and generated certificates are signed with ECDSA-with-SHA256.

Unlike YubiKey-style public attestation, this applet applies the target key's normal access rules
before issuing an attestation certificate. A target slot configured for PIN access requires a
verified PIN. A target slot whose contactless access mode requires the Virtual Contact Interface
(VCI / secure messaging) is not attestable over the contactless interface until VCI is established.
A target slot blocked on the current contact/contactless interface is not attestable on that
interface.

## Certificate Profile

Generated target certificates are X.509 v3 certificates with:

- A positive random serial number.
- `signatureAlgorithm` and TBSCertificate signature algorithm set to ECDSA-with-SHA256.
- Issuer copied byte-for-byte from the configured issuer subject DER.
- Validity copied byte-for-byte from the configured validity DER.
- Subject `CN=PIV Attestation <slot>`.
- SubjectPublicKeyInfo copied from the target key.
- `BasicConstraints CA=false`.
- `KeyUsage digitalSignature`.

The resulting certificate validates against an external issuer certificate when that issuer
certificate has the same subject and public key as the committed F9 authority profile.

The applet builds each certificate directly into a CLEAR_ON_DESELECT response buffer supplied by
the caller. The buffer is sized for the worst supported certificate (maximum issuer subject plus
an RSA-2048 SubjectPublicKeyInfo); assembly fails closed with `6A84` on overflow. Temporaries use
the shared PIV scratch; the only persistent attestation data are the issuer subject and validity
profile. The JCRE zeroes the response buffer on deselection.

## Host Tooling

The repository includes a host provisioning tool:

```sh
ant -f build/build.xml attestation-tool -Dargs="--help"
```

The tool supports these workflows:

- `list-readers`: list available PC/SC readers.
- `prepare-csr`: generate an ECC P-256 F9 key pair and PKCS#10 CSR on the host.
- `provision`: provision an existing F9 private key and issuer certificate onto the card.
- `direct-provision`: generate a local F9 issuer certificate and provision it in one operation.

External-CA workflow:

```sh
ant -f build/build.xml attestation-tool -Dargs='prepare-csr \
  --subject "CN=Device F9,O=Example" \
  --key-out f9.key.pem \
  --csr-out f9.csr.pem'

# Have the CA sign f9.csr.pem, producing f9.issuer.pem.

ant -f build/build.xml attestation-tool -Dargs='provision \
  --reader "reader name" \
  --scp 03 \
  --scp-key 404142434445464748494A4B4C4D4E4F \
  --issuer-key f9.key.pem \
  --issuer-cert f9.issuer.pem'
```

Local test workflow:

```sh
ant -f build/build.xml attestation-tool -Dargs='direct-provision \
  --reader "reader name" \
  --scp 03 \
  --scp-key 404142434445464748494A4B4C4D4E4F \
  --subject "CN=Device F9,O=Example" \
  --not-before 2026-01-01 \
  --not-after 2030-01-01 \
  --issuer-key-out f9.key.pem \
  --issuer-cert-out f9.issuer.pem'
```

Provisioning selects the PIV applet first and opens the GlobalPlatform secure channel against the
selected applet. `--scp auto` is the default; it sends one `INITIALIZE UPDATE` and uses the SCP
version reported by the card before `EXTERNAL AUTHENTICATE`. It does not try one SCP version and
then fall back to another after authentication failure. Use `--scp 03` or `--scp 02` when the mode
is known and should be enforced. Cards may permanently block a security domain after a small number
of failed SCP authentication attempts, so provisioning must not be run with guessed keys.

`probe-scp` performs the same applet selection and SCP establishment without changing F9 or any PIV
data object. It is intended for reader/key validation before running a provisioning command.

The tool accepts either one static key with `--scp-key` or separate `--scp-enc-key`,
`--scp-mac-key`, and `--scp-dek-key` values. Private-key export requires a non-empty passphrase
unless `--no-private-key-encryption` is explicitly set.

The provisioning command sequence is:

1. Create or reuse F9 as an ECC P-256 attestation authority key definition.
2. Clear any existing F9 authority profile so replacement provisioning commits only after all new
   elements are present.
3. Import F9 public point, private scalar, issuer subject DER, and issuer validity DER using
   protected `CHANGE REFERENCE DATA` commands.
4. Create or reuse the issuer certificate PIV data object.
5. Store the external issuer certificate in that object with `PUT DATA`.

The default issuer certificate object is `5F FF 01`, matching the commonly used YubiKey-compatible
attestation issuer certificate slot.

## Validation Rules

The applet rejects authority provisioning unless:

- The command is sent through the administrative SCP-only `PUT DATA` path.
- F9 public and private key elements are valid ECC P-256 values.
- The F9 key pair can sign and verify a test digest.
- The subject is one complete definite-length DER `Name`.
- The validity is one complete definite-length DER `Validity`.

The applet rejects attestation unless:

- The authority profile has been committed.
- The target slot exists.
- The target slot's contact/contactless access mode is satisfied. On the contactless interface this
  includes the VCI access condition: a VCI-gated target key requires secure messaging (VCI) to be
  established before it is attestable.
- The target key was generated on-card after the current authority commit.
- The target algorithm is supported.

Imported target keys are not attestable.

## Status Words

- `9000`: success.
- `6985`: attestation authority missing, target key missing material, or target key not generated.
- `6982`: authority operation was attempted outside the required secure channel, or attestation
  was attempted without satisfying the target slot access mode (including a VCI-gated target key
  attested over the contactless interface before VCI is established).
- `6A80`: malformed authority data, malformed DER, unsupported authority fields, or key-pair mismatch.
- `6A84`: configured subject, validity, or generated certificate exceeds supported limits.
- `6A86`: invalid attestation slot or command parameters.
- `6A88`: target slot/key reference not found.

## Relationship To Other Attestation Systems

This command follows the PIV attestation shape commonly exposed by YubiKeys: slot `F9` is the
attestation issuer, and `INS F9` returns a generated certificate for a target key. This fork
intentionally differs by enforcing target-slot access rules for `INS F9`. The attestation
implementation is independent of PivApplet.
