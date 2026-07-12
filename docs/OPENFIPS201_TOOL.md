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

## Producer Workflow

For normal issuer prep, use the producer commands. They keep issuer state under
`~/.openfips201`, default to a managed SoftHSM token, and leave card-specific
receipts in the batch directory.

Create an issuer profile and token objects:

```sh
ant -f build/build.xml openfips201-tool \
  -Dargs='producer setup \
    --name bigcorp_01 \
    --root-subject "O=BigCorp,CN=BigCorp OpenFIPS201 Root" \
    --f9-subject "O=BigCorp,OU=Cardstock,CN=BigCorp OpenFIPS201 F9"'
```

`--f9-subject` is a **template** only: do not include `serialNumber`. At produce time
the tool appends `serialNumber=<instanceId>` so each card has a unique F9 subject and
certificate serial. If a subject option is omitted in an interactive terminal, the tool
prompts with an editable default. The applet still stores the final subject as opaque
DER X.509 `Name` data; generated target attestation certificates copy that exact DER
into their issuer field.

Create a batch:

```sh
ant -f build/build.xml openfips201-tool \
  -Dargs='batch create --producer bigcorp_01 --name 2026-07'
```

`batch create` prints the stock SCP03 master key once. The batch metadata stores
the key version, KCV, and receipt paths, not the raw key. New issuer batch keys
default to key version 1. Use that printed key for cards that are initialized as
stock for the batch.

Produce one card:

```sh
ant -f build/build.xml openfips201-tool \
  -Dargs='card produce \
    --producer bigcorp_01 \
    --batch 2026-07 \
    --target pcsc:JCOP \
    --stock-scp-key 404142434445464748494A4B4C4D4E4F \
    --yes'
```

`card produce` loads and installs the applet, imports a generated F9 authority,
collects and deletes a proof key, reads CPLC and the 10-byte KDD, derives the
new SCP03 keys with the HSM-held AES card-master key, rotates the card keys, and
verifies the new secure channel.

Each batch has:

```text
~/.openfips201/producers/<producer>/producer.json
~/.openfips201/producers/<producer>/batches/<batch>/batch.json
~/.openfips201/producers/<producer>/batches/<batch>/receipts.csv
~/.openfips201/producers/<producer>/batches/<batch>/receipts/*.json
```

The CSV row includes the producer, batch, target, CPLC, KDD, new SCP key version,
ENC/MAC/DEK KCVs, root subject, **instance id**, F9 subject, F9 serial (hex), F9 SPKI
SHA-256, F9 certificate hash, proof slot, proof-key deletion result, and whether the
proof leaf issuer matched the F9 instance id.

Each produce mints a unique F9 authority. The instance id is 32 uppercase hex digits
(16 random bytes). It is both the F9 certificate serial and a `serialNumber` RDN on the
F9 subject (appended to the producer subject template). Keep the template short enough
that the composed subject DER stays within 128 bytes.

Successful `card produce` / `cardstock prepare` print a lifecycle summary, for example:

```text
Card produced.
  Instance ID:     A1B2C3D4E5F60718293A4B5C6D7E8F90
  F9 subject:      SERIALNUMBER=A1B2...,CN=...
  F9 serial:       0xA1B2...
  F9 SPKI SHA-256: ...
  F9 cert SHA-256: ...
  Proof slot:      9A
  Proof issuer OK: true
  Proof key gone:  true
  Receipt:         ~/.openfips201/producers/.../receipts/....json
```

Receipt JSON also includes `instanceId`, `f9CertificateSerialHex`, `f9SpkiSha256`,
`f9CertificateBase64`, and `f9ProofIssuerMatched`.

## Cardstock

The lower-level cardstock command is for profile-driven issuer prep. It takes stock cards, loads the
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
therefore skips GP CAP LOAD and runs INSTALL [for install and make selectable].
Physical-card profiles should leave `applet.loadCap` at the default `true`.

The development profile uses the GlobalPlatform test SCP03 key and writes
receipts under `build/cardstock-receipts`. Production profiles derive the new
card SCP03 keys from the card's KDD using SCP03 KDF3 with an AES master key held
in PKCS#11.

A clean cardstock receipt has `proofKeyDeleted: true` and the operations list
includes `SCP keys rotated and verified`. Proof-key cleanup is mandatory when
`deleteProofKey` is enabled; if the cleanup delete fails, `cardstock prepare`
aborts instead of writing a finished-stock receipt. The proof certificate can
span multiple APDUs; when GPPro requests the continuation over SCP, the applet
processes the protected `GET RESPONSE` through the platform secure-channel layer
so SCP counters remain synchronized for the cleanup and key rotation commands
that follow.

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
    "rootSubject": "O=BigCorp,CN=BigCorp OpenFIPS201 Root",
    "issuerSubject": "O=BigCorp,OU=Cardstock,CN=BigCorp OpenFIPS201 F9",
    "issuerValidityDays": 3650,
    "proofSlot": "9A",
    "deleteProofKey": true,
    "issuerObjectId": "5FFF01"
  },
  "cardKeys": {
    "deriver": "pkcs11",
    "kdf": "scp03-kdf3",
    "newKeyVersion": 2,
    "masterKeyAlias": "bigcorp-card-master",
    "export": "none"
  },
  "pkcs11": {
    "module": "/usr/local/lib/softhsm/libsofthsm2.so",
    "tokenLabel": "bigcorp_issuer",
    "keyAlias": "f9-ca",
    "pinEnv": "BIGCORP_HSM_PIN",
    "pinFile": null,
    "softhsmConfig": null
  },
  "receipts": {
    "directory": "receipts/bigcorp_01"
  }
}
```

`attestation.rootSubject` is the issuer/root CA name used on the F9 certificate.
`attestation.issuerSubject` is the F9 authority subject imported into the
applet. `pkcs11.keyAlias` selects the ECDSA root key used to sign the F9
certificate. `cardKeys.masterKeyAlias` selects the AES issuer card-master key
used for SCP03 KDF3. They may live in the same token, but they are different
objects and should have different labels. Use `keyId` / `masterKeyId` instead
of labels if your token management policy uses CKA_ID as the stable handle.

If the card-master AES key is on a different token, set `cardKeys.pkcs11` with
its own `module`, `tokenLabel` or `slot`, and `pinEnv` or `pinFile`. Omitted
fields inherit from the top-level `pkcs11` block.

## Attestation Model

Cardstock preparation assumes F9 is imported into the applet. The issuer CA key
can remain non-extractable in PKCS#11/HSM; it signs the F9 issuer certificate.
The tool talks to PKCS#11 directly through a small Cryptoki binding. It does not
use SunPKCS11 or shell out to `pkcs11-tool`.
The generated F9 private scalar is imported over the administrative SCP channel
and zeroized by the host process after import.

The PKCS#11 signing object must be an EC private key with a matching X.509
certificate object on the token. The certificate provides the public key used in
the generated F9 issuer certificate path; the private key never leaves the
token.

The proof step creates a temporary generated key in the configured slot (`9A`
by default), asks INS F9 to attest it, stores the certificate in the
receipt, and deletes the proof key unless the profile says otherwise.

OpenFIPS201 slots hold one key definition. If the configured proof slot already
contains a key, cardstock preparation fails before proof generation; choose a
free slot in the issuer profile or clean the card before producing it.

When `deleteProofKey` is enabled, failure to delete the temporary proof key is a
command failure. The card may already have been installed and attested, so the
operator should retry cleanup or quarantine the card rather than treating it as
finished issuer stock.

## GP Key Rotation

`gp card kdd` reads the 10-byte SCP key diversification data returned by
GlobalPlatform `INITIALIZE UPDATE`. This is a read-only probe; it selects the
Issuer Security Domain and does not authenticate or mutate the card.

```sh
ant -f build/build.xml openfips201-tool \
  -Dargs='gp card kdd \
    --target pcsc:JCOP'
```

Use `--raw` when debugging card profiles; it prints the complete
`INITIALIZE UPDATE` response data in addition to the first 10 KDD bytes.

`gp keys derive-card` reads KDD from the card, derives the matching SCP03 keys
through the PKCS#11 AES card-master key, and prints the KDD and KCVs. It does
not mutate the card.

```sh
ant -f build/build.xml openfips201-tool \
  -Dargs='gp keys derive-card \
    --target pcsc:JCOP \
    --pkcs11-module /usr/local/lib/softhsm/libsofthsm2.so \
    --pkcs11-token-label bigcorp_issuer \
    --pkcs11-key-alias bigcorp-card-master \
    --pkcs11-pin-env BIGCORP_HSM_PIN'
```

`gp keys derive` is the same derivation with an explicit KDD value. Use it when
you already captured the KDD or need reproducible diagnostics:

```sh
ant -f build/build.xml openfips201-tool \
  -Dargs='gp keys derive \
    --kdd 00002345496554204839 \
    --pkcs11-module /usr/local/lib/softhsm/libsofthsm2.so \
    --pkcs11-token-label bigcorp_issuer \
    --pkcs11-key-alias bigcorp-card-master \
    --pkcs11-pin-env BIGCORP_HSM_PIN'
```

The AES master key must permit `CKM_AES_CMAC` signing. The tool builds the
same SCP03 KDF3 inputs as GlobalPlatformPro's `kdf3` mode and asks the token to
CMAC those inputs. It prints only KCVs.

`gp keys rotate` writes the derived keyset with GlobalPlatform PUT KEY and then
opens a new secure channel with those keys:

```sh
ant -f build/build.xml openfips201-tool \
  -Dargs='gp keys rotate \
    --target pcsc:JCOP \
    --scp 03 \
    --scp-key 404142434445464748494A4B4C4D4E4F \
    --kdd 00002345496554204839 \
    --pkcs11-module /usr/local/lib/softhsm/libsofthsm2.so \
    --pkcs11-token-label bigcorp_issuer \
    --pkcs11-key-alias bigcorp-card-master \
    --pkcs11-pin-env BIGCORP_HSM_PIN \
    --new-key-version 1'
```

Receipts record the card KDD, KDF name, new key version, and KCVs. They do not
record raw keys.

`gp keys keyroll` is the profile-aware issuer command for moving a card between
stock/batch SCP keys and the issuer-derived card keys from the profile:

```sh
ant -f build/build.xml openfips201-tool \
  -Dargs='gp keys keyroll forward \
    --profile ~/.openfips201/producers/bigcorp_01/producer.json \
    --target pcsc:JCOP \
    --stock-scp-key <printed-batch-key> \
    --yes'
```

`forward` opens the card with the stock or batch key and replaces it with the
profile-derived SCP03 KDF3 keyset. `backward` does the reverse, opening with the
profile-derived keyset and replacing it with the stock or batch key:

```sh
ant -f build/build.xml openfips201-tool \
  -Dargs='gp keys keyroll backward \
    --profile ~/.openfips201/producers/bigcorp_01/producer.json \
    --target pcsc:JCOP \
    --stock-scp-key <printed-batch-key> \
    --yes'
```

Run `gp keys preflight` before manual keyrolls on physical cards:

```sh
ant -f build/build.xml openfips201-tool \
  -Dargs='gp keys preflight \
    --profile ~/.openfips201/producers/bigcorp_01/producer.json \
    --target pcsc:JCOP \
    --direction forward \
    --stock-scp-key <printed-batch-key>'
```

The command reads KDD from the card by default. Pass `--kdd` when you already
have the 10 diversification bytes from a receipt or diagnostic run. The
stock/batch key version defaults to 1 for keys the issuer workflow writes onto
cards; issuer-derived produced-card keys default to version 2. Physical-card
preflight rejects any rotation where the current and target key versions are the
same, before sending `PUT KEY`. Pass `--stock-scp-key-version` when the current
factory key or rollback key lives at another version. Physical PC/SC keyroll
targets require `--yes`; ZeroMQ emulator targets do not.
