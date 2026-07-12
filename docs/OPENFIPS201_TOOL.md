# OpenFIPS201 Issuer Tool

`openfips201-tool` is the host-side entrypoint for emulator work, applet
loading, attestation setup, GP key rotation, and cardstock preparation.

Run it through Ant:

```sh
ant -f build/build.xml openfips201-tool -Dargs="--help"
```

Card targets are explicit:

```text
pcsc:<reader name fragment>
zmq:<endpoint>
```

## Cardstock

The cardstock command is for issuer batch prep. It takes stock cards, loads the
applet, imports an F9 attestation authority, collects a proof attestation,
derives issuer-specific SCP03 keys, rotates the card to those keys, verifies the
new secure channel, and writes a receipt.

```sh
ant -f build/build.xml openfips201-tool \
  -Dargs='cardstock prepare \
    --profile profiles/bigcorp_01.json \
    --target pcsc:JCOP \
    --signer pkcs11 \
    --pkcs11-module /usr/local/lib/softhsm/libsofthsm2.so \
    --pkcs11-token-label bigcorp_issuer \
    --pkcs11-key-alias f9-ca \
    --pkcs11-pin-env BIGCORP_HSM_PIN \
    --yes'
```

For local emulator work:

```sh
ant -f build/build.xml openfips201-tool \
  -Dargs='emulator serve --endpoint tcp://127.0.0.1:5555'

ant -f build/build.xml openfips201-tool \
  -Dargs='cardstock prepare \
    --profile emulator-dev \
    --target zmq:tcp://127.0.0.1:5555 \
    --signer ephemeral'
```

The emulator starts as stock: JCardEngine has the OpenFIPS201 class registered,
but no OpenFIPS201 instance is installed or selectable. The development profile
therefore skips GP CAP LOAD and lets the GPPro client run INSTALL [for install
and make selectable]. Physical-card profiles should leave `applet.loadCap` at
the default `true`.

The development profile uses the GlobalPlatform test SCP03 key and writes
receipts under `build/cardstock-receipts`.

## Profile Shape

Profiles are JSON. They may contain paths, labels, aliases, key versions, AIDs,
and environment variable names. They must not contain raw SCP keys, HSM PINs, or
private key material.

```json
{
  "name": "bigcorp_01",
  "stockScp": {
    "mode": "scp03",
    "keyVersion": 0,
    "masterKeyEnv": "BIGCORP_STOCK_SCP03_KEY"
  },
  "applet": {
    "capPath": "build/bin/OpenFIPS201-OP-0.1.cap",
    "packageAid": "A00000030800001000",
    "appletAid": "A000000308000010000100",
    "instanceAid": "A000000308000010000100",
    "loadCap": true,
    "deleteExisting": false
  },
  "attestation": {
    "issuerSubject": "CN=BigCorp OpenFIPS201 Cardstock,O=BigCorp",
    "issuerValidityDays": 3650,
    "proofSlot": "82",
    "deleteProofKey": true,
    "issuerObjectId": "5FFF01"
  },
  "cardKeys": {
    "kdf": "hmac-sha256-counter-v1",
    "newKeyVersion": 1,
    "masterKeyEnv": "BIGCORP_CARD_MASTER_KEY",
    "export": "none"
  },
  "pkcs11": {
    "module": "/usr/local/lib/softhsm/libsofthsm2.so",
    "tokenLabel": "bigcorp_issuer",
    "keyAlias": "f9-ca",
    "pinEnv": "BIGCORP_HSM_PIN"
  },
  "receipts": {
    "directory": "receipts/bigcorp_01"
  }
}
```

## Attestation Model

Cardstock preparation assumes F9 is imported into the applet. The issuer CA key
can remain non-extractable in PKCS#11/HSM; it signs the F9 issuer certificate.
The generated F9 private scalar is imported over the administrative SCP channel
and zeroized by the host process after import.

The proof step creates a temporary generated key in the configured retired slot
(`82` by default), asks INS F9 to attest it, stores the certificate in the
receipt, and deletes the proof key unless the profile says otherwise.

## GP Key Rotation

`gp keys derive` prints per-card SCP03 KCVs without mutating the card:

```sh
ant -f build/build.xml openfips201-tool \
  -Dargs='gp keys derive \
    --master-key-env BIGCORP_CARD_MASTER_KEY \
    --context bigcorp_01-card_0001'
```

`gp keys rotate` writes the derived keyset with GlobalPlatform PUT KEY and then
opens a new secure channel with those keys:

```sh
ant -f build/build.xml openfips201-tool \
  -Dargs='gp keys rotate \
    --target pcsc:JCOP \
    --scp 03 \
    --scp-key 404142434445464748494A4B4C4D4E4F \
    --new-master-key-env BIGCORP_CARD_MASTER_KEY \
    --context bigcorp_01-card_0001 \
    --new-key-version 1'
```

Receipts record the new key version and KCVs, not raw keys.
