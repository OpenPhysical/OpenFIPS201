# Conformance provisioning from GSA ICAM folders

OpenFIPS201 accepts **GSA ICAM card-builder card folders natively**. There is no intermediate
package conversion step for the golden-path conformance workflow: point the provisioner at a
directory such as:

```text
gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV/
```

and the host tooling creates containers, imports keys (or generates `9A` and `9C` on the card, see
[FIPS-profile CAPs](#fips-profile-caps-9a-and-9c)), and PUT DATAs object bodies over GlobalPlatform
SCP03.

## What an ICAM folder contains

| File pattern                           | PIV mapping                          |
| -------------------------------------- | ------------------------------------ |
| `1 - Discovery Object`                 | Discovery (`7E`)                     |
| `2 - Security Object`                  | Security Object (`5FC106`)           |
| `3 - ICAM_PIV_Auth*.p12` / `.crt`      | Key `9A` + cert container `5FC105`   |
| `4 - ICAM_PIV_Dig_Sig*.p12` / `.crt`   | Key `9C` + cert container `5FC10A`   |
| `5 - ICAM_PIV_Key_Mgmt*.p12` / `.crt`  | Key `9D` + cert container `5FC10B`   |
| `6 - ICAM_PIV_Card_Auth*.p12` / `.crt` | Key `9E` + cert container `5FC101`   |
| `7 - CCC`                              | Card Capability Container (`5FC107`) |
| `8 - CHUID Object`                     | CHUID (`5FC102`)                     |
| `9 - Fingerprints`                     | Fingerprints (`5FC103`, PIN)         |
| `10 - Face Object`                     | Facial image (`5FC108`, PIN)         |
| `11 - Printed Information`             | Printed Information (`5FC109`, PIN)  |

When both `ICAM_Test_Card_*` and plain `ICAM_PIV_*` assets exist, the loader prefers
`ICAM_Test_Card` (same rule as OpenPhysical VirtualPiv).

### PKCS#12 password

The published GSA ICAM corpus uses an **empty** PKCS#12 password. Override with
`--p12-password` for custom folders.

### Secrets applied by the provisioner

| Secret              | Default                                            |
| ------------------- | -------------------------------------------------- |
| Local PIN           | `123456` (StandardCardProfile, padded with `0xFF`) |
| PUK                 | `12345678`                                         |
| Management key `9B` | AES-128 fixed test key from StandardCardProfile    |
| SCP03               | GlobalPlatform test master key (emulator default)  |

## Commands

Build tooling:

```bash
ant -f build/build.xml tool-compile
```

Start the ZeroMQ emulator (registers the applet class and serves APDUs):

```bash
java -cp "build/tool-bin:tools/jcard-v26.08.10.jar:build/lib/*" \
  dev.mistial.tools.openfips201.OpenFips201Tool \
  emulator serve --endpoint tcp://127.0.0.1:5555
```

Install + provision from ICAM card 46 (the helper script runs GP install with
`--skip-load` then loads the folder):

```bash
tools/provision-icam.sh \
  /path/to/gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV

# or explicitly:
CAP=build/matrix/standard-CS2-attestation/bin/OpenFIPS201-*.cap
java -cp "build/tool-bin:tools/jcard-v26.08.10.jar:build/lib/*" \
  dev.mistial.tools.openfips201.OpenFips201Tool \
  applet install --cap "$CAP" --skip-load \
  --target zmq:tcp://127.0.0.1:5555 \
  --scp-key 404142434445464748494A4B4C4D4E4F

java -cp "build/tool-bin:tools/jcard-v26.08.10.jar:build/lib/*" \
  dev.mistial.tools.openfips201.OpenFips201Tool \
  provision \
  --icam /path/to/.../46_Golden_FIPS_201-2_PIV \
  --target zmq:tcp://127.0.0.1:5555
```

Verified end-to-end against card 46 on a standard-profile CAP: 11 objects + 4 RSA-2048 keys
(9A/9C/9D/9E) import successfully.

## FIPS-profile CAPs: 9A and 9C

FIPS 201-3 Section 4.2.2.1 requires the PIV Authentication key to be "generated on the PIV Card",
and Section 4.2.2.4 requires the same of the Digital Signature key. A FIPS-profile CAP therefore
refuses an importable definition of `9A` or `9C` with `6A80` at key creation. A standard-profile
CAP allows importable `9A` and `9C` for usability, as YubiKey PIV does.

`ConformanceProvisioner` takes a key source:

| Key source       | Behaviour                                                                                      |
| ---------------- | ---------------------------------------------------------------------------------------------- |
| `IMPORT`         | Every key is defined importable and imported from the folder's PKCS#12 files.                 |
| `GENERATE_9A_9C` | `9A` and `9C` are defined non-importable (`ATTR_NONE`) and generated on the card; `9D` and `9E` are imported. |

`KeySource.forBuild(fips)` selects `GENERATE_9A_9C` for FIPS builds and `IMPORT` otherwise. With
`GENERATE_9A_9C` the folder's `9A` and `9C` certificates do not certify the generated keys; the
objects still load and read back byte-for-byte, but certificate-to-key checks for `9A` and `9C` do
not hold. The report counts imported and generated keys separately.

The FIPS-mode repository tests (`GsaIcam46HeadlessSmokeTest`, `OpenFIPS201VciEndToEndTest`) use
`forBuild`, and the smoke test first asserts that importing the vendored `9A`/`9C` is refused.

The default `ConformanceProvisioner.provision(...)` overload detects the profile from the target
applet's GET STATUS tag `87` (FIPS mode) and applies `KeySource.forBuild` itself. If the applet does
not report tag `87`, it fails with an explicit message. The `provision` CLI command and the NIST
harness use this overload, so they generate `9A`/`9C` on the card for FIPS-profile CAPs, import them
for standard CAPs, and report how many keys were imported and how many generated.

For cards with distinct SCP03 ENC, MAC, and DEK keys, pass the complete split key set. Literal hex
keys are accepted for `zmq:` targets only; a `pcsc:` target takes each key from an environment
variable or an owner-only file:

```bash
ant -f build/build.xml openfips201-tool -Dargs='provision \
  --icam /path/to/.../46_Golden_FIPS_201-2_PIV \
  --target pcsc:Reader \
  --scp-enc-key-env SCP_ENC \
  --scp-mac-key-env SCP_MAC \
  --scp-dek-key-env SCP_DEK'
```

Use `--scp-key`, `--scp-key-env` or `--scp-key-file` when all three SCP03 keys are identical. Do not
combine the shared and split forms.

## Certification profile

`provision --certification-profile` validates the folder against the frozen SP 800-73-5 Part 1
certification profile (`CertificationProfileValidator`) before writing anything, provisions it, and
only after a successful readback performs the one-way personalization transition. `--vci`,
`--pairing-required` and `--government-email` declare the issuer claims that change which objects
are required. Without `--certification-profile` the applet is left in the administrative state.

The validator checks, among others:

- the mandatory objects (CCC, CHUID, PIV Authentication and Card Authentication certificates,
  fingerprints, facial image, Security Object);
- the CHUID signature (eContentType id-PIV-CHUIDSecurityObject, signer DN, Table 2 digest);
- the content signing certificate's extKeyUsage (`ContentSigningProfile`): critical and asserting
  only the purpose of the card type. An all-nines FASC-N (non-federally issued PIV-I) requires
  id-fpki-pivi-content-signing (`2.16.840.1.101.3.8.7`). Otherwise an FPKI PIV content signing
  policy requires id-PIV-content-signing (`2.16.840.1.101.3.6.7`), a PIV-I content signing policy
  requires the PIV-I purpose, and without either policy both purposes are accepted (SP 800-116
  permits federally issued PIV-I with a real agency code). The same rule applies to the signer of
  the secure-messaging certificate signer object `5FC122`;
- the Discovery PIN Usage Policy: only the Part 1 Table 1 first-byte values, no OCC, and a Global
  PIN bit only when the configuration enables it.

Content signers generated by the repository tooling (`VciProvisioning`, `NativeVciProfile`) assert
the purpose chosen from the card's FASC-N by the same rule.

## piv-conformance (OpenPhysical fork)

After provisioning:

```bash
export OPENFIPS201_EMULATOR_ENDPOINT=tcp://127.0.0.1:5555
# run CCT / cardlib smoke against reader name "OpenFIPS201 Emulator"
```

The provisioner uses separate card connections for issuer administration and verification. PIN,
key, and object mutations run under GP SCP03. It then closes that connection, selects PIV on a
fresh plain connection, verifies the PIN, and reassembles each object with ISO 7816-4 `00 C0` GET
RESPONSE commands before comparing the exact bytes. Certification personalization occurs only
after every readback succeeds.

Expected MVP checks after load:

1. SELECT PIV AID succeeds.
2. VERIFY local PIN `123456` succeeds.
3. GET DATA CHUID / CCC / at least one certificate returns `9000`.
4. GENERAL AUTHENTICATE with Card Authentication (`9E`) verifies against the on-card cert.

The repository provides a headless path for these checks:

```bash
ant -f build/build.xml \
  -Dfips.mode=true -Dfips.platform=test-jcard \
  -Dvci.suite=CS2 -Dattestation.enabled=false \
  test-gsa-icam-smoke
```

`GsaIcam46HeadlessSmokeTest` loads the vendored card 46, provisions all 11 objects and four keys
(in FIPS mode with `9A` and `9C` generated on the card), then requires successful SELECT, local PIN VERIFY, CCC/CHUID/Card Authentication certificate reads,
and an independently verified RSA-2048 Card Authentication operation with key `9E`.

## Implementation map

| Class                       | Role                                         |
| --------------------------- | -------------------------------------------- |
| `IcamCardFolder`            | Native ICAM directory → `ConformancePackage` |
| `ConformancePackage`        | Objects + keys + PIN/PUK/9B model            |
| `ConformanceProvisioner`    | SCP03 create/import/generate/PUT DATA        |
| `OpenFips201Tool provision` | CLI entry                                    |
| `tools/provision-icam.sh`   | Convenience wrapper                          |

## piv-conformance host trust material (no symlinks)

Certificate-container objects are written with SP 800-73 tags `70` / `71` / empty
`FE`. For PKIX atoms against **ICAM** card content, the CCT process working
directory must contain **real file copies** (not symlinks — Windows hosts do not
handle them reliably):

```text
cwd/
  cacerts.jks                 # copy of conformancelib x509-certs/cacerts.jks
  pdval.properties            # defaultAlias=icam test card piv root ca
  x509-certs/
    cacerts.jks               # same keystore copy
    certsIssuedToICAMTestCardSigningCA.p7c   # intermediate (AIA or local copy)
```

ICAM EE certs chain to **ICAM Test Card Root CA**, not production Federal Common
Policy CA G2. Set `defaultAlias=icam test card piv root ca` in `pdval.properties`
(the stock CCT keystore already contains that alias). Fetch the signing-CA
intermediate from the ICAM AIA URL or from
`gsa-icam-card-builder/.../ICAM_CA_and_Signer/` as ordinary copied files.

## Limitations (MVP)

- VCI / SM key (`04`) and pairing are **not** loaded from ICAM folders; use `VciProvisioning` when SM cases are needed.
- Attestation authority (`F9`) is not part of the ICAM load path.
- Negative ICAM profiles, such as a modified CHUID or expired certificate, are loaded without
  correction for deterministic host-side negative tests.
- Emulator reset clears personalisation; re-run `provision` after restart.
- The applet is left in the administrative (pre-personalise) lifecycle state so re-provisioning remains possible under SCP.
- Provisioning verifies the local PIN and reads every object back through GET DATA, requiring an exact byte match with the source package before reporting success.
- **FIPS-profile CAP:** the loader maps ICAM objects and keys to the Part 1 contact/contactless ACRs enforced by `FipsPolicy`. GSA card 46 provisions successfully with `9A` and `9C` generated on the card
  (`KeySource.GENERATE_9A_9C`); VCI secure messaging remains a separate profile extension.
