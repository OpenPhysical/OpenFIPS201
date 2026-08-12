# Conformance provisioning from GSA ICAM folders

OpenFIPS201 accepts **GSA ICAM card-builder card folders natively**. There is no intermediate
package conversion step for the golden-path conformance workflow: point the provisioner at a
directory such as:

```text
gsa-icam-card-builder/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV/
```

and the host tooling creates containers, imports keys, and PUT DATAs object bodies over GlobalPlatform
SCP03.

## What an ICAM folder contains

| File pattern | PIV mapping |
| ------------ | ----------- |
| `1 - Discovery Object` | Discovery (`7E`) |
| `2 - Security Object` | Security Object (`5FC106`) |
| `3 - ICAM_PIV_Auth*.p12` / `.crt` | Key `9A` + cert container `5FC105` |
| `4 - ICAM_PIV_Dig_Sig*.p12` / `.crt` | Key `9C` + cert container `5FC10A` |
| `5 - ICAM_PIV_Key_Mgmt*.p12` / `.crt` | Key `9D` + cert container `5FC10B` |
| `6 - ICAM_PIV_Card_Auth*.p12` / `.crt` | Key `9E` + cert container `5FC101` |
| `7 - CCC` | Card Capability Container (`5FC107`) |
| `8 - CHUID Object` | CHUID (`5FC102`) |
| `9 - Fingerprints` | Fingerprints (`5FC103`, PIN) |
| `10 - Face Object` | Facial image (`5FC108`, PIN) |
| `11 - Printed Information` | Printed Information (`5FC109`, PIN) |

When both `ICAM_Test_Card_*` and plain `ICAM_PIV_*` assets exist, the loader prefers
`ICAM_Test_Card` (same rule as OpenPhysical VirtualPiv).

### PKCS#12 password

The published GSA ICAM corpus uses an **empty** PKCS#12 password. Override with
`--p12-password` for custom folders.

### Secrets applied by the provisioner

| Secret | Default |
| ------ | ------- |
| Local PIN | `123456` (StandardCardProfile, padded with `0xFF`) |
| PUK | `12345678` |
| Management key `9B` | AES-128 fixed test key from StandardCardProfile |
| SCP03 | GlobalPlatform test master key (emulator default) |

## Commands

Build tooling:

```bash
ant -f build/build.xml tool-compile
```

Start the ZeroMQ emulator (registers the applet class and serves APDUs):

```bash
java -cp "build/tool-bin:tools/jcard-v26.07.13.jar:build/lib/*" \
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
java -cp "build/tool-bin:tools/jcard-v26.07.13.jar:build/lib/*" \
  dev.mistial.tools.openfips201.OpenFips201Tool \
  applet install --cap "$CAP" --skip-load \
  --target zmq:tcp://127.0.0.1:5555 \
  --scp-key 404142434445464748494A4B4C4D4E4F

java -cp "build/tool-bin:tools/jcard-v26.07.13.jar:build/lib/*" \
  dev.mistial.tools.openfips201.OpenFips201Tool \
  provision \
  --icam /path/to/.../46_Golden_FIPS_201-2_PIV \
  --target zmq:tcp://127.0.0.1:5555
```

Verified end-to-end against card 46: 11 objects + 4 RSA-2048 keys (9A/9C/9D/9E) import successfully.

## piv-conformance (OpenPhysical fork)

After provisioning:

```bash
export OPENFIPS201_EMULATOR_ENDPOINT=tcp://127.0.0.1:5555
# run CCT / cardlib smoke against reader name "OpenFIPS201 Emulator"
```

Expected MVP checks after load:

1. SELECT PIV AID succeeds.
2. VERIFY local PIN `123456` succeeds.
3. GET DATA CHUID / CCC / at least one certificate returns `9000`.
4. GENERAL AUTHENTICATE with Card Authentication (`9E`) verifies against the on-card cert.

## Implementation map

| Class | Role |
| ----- | ---- |
| `IcamCardFolder` | Native ICAM directory → `ConformancePackage` |
| `ConformancePackage` | Objects + keys + PIN/PUK/9B model |
| `ConformanceProvisioner` | SCP03 create/import/PUT DATA |
| `OpenFips201Tool provision` | CLI entry |
| `tools/provision-icam.sh` | Convenience wrapper |

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
- Negative ICAM cards (tampered CHUID, expired certs, etc.) load as-is — useful for host-side negative tests once the positive path is green.
- Emulator reset clears personalisation; re-run `provision` after restart.
- The applet is left in the administrative (pre-personalise) lifecycle state so re-provisioning remains possible under SCP.
- **FIPS_MODE CAP:** the loader maps ICAM objects and keys to the Part 1 contact/contactless ACRs enforced by `FipsPolicy`. GSA card 46 provisions successfully; VCI/SM remains a separate profile extension.
