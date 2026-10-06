# OpenFIPS201 Issuer Tool

`openfips201` is the host-side tool for card discovery, CAP installation, GlobalPlatform key
management, Issuer SAM operation, card production, ledger audit, attestation verification and
conformance provisioning.

Run it through Ant:

```sh
ant -f build/build.xml openfips201-tool -Dargs="--help"
ant -f build/build.xml openfips201-tool -Dargs="<command> --help"
```

Top-level commands: `cards`, `emulator`, `applet`, `crypto`, `attestation`, `gp`, `producer`,
`root`, `station`, `batch`, `sam`, `card`, `ledger`, `provision`, `interactive`, and the deprecated
`cardstock`.

Card and SAM targets are explicit:

```text
pcsc:<reader name fragment>
zmq:<endpoint>
```

A reader fragment must match exactly one reader name, or one reader name exactly; an ambiguous
fragment is refused.

Exit status: `0` success, `1` failure (any error), `2` usage error. `card produce`, `ledger verify`
and `attestation verify` define more specific codes below.

## Issuance Overview

Issuance is split between two stations. Each has its own OpenFIPS201 home and PKCS#11 token, and
both are set up under the same producer name. The root station never touches a card; the production
station never holds the root key, an FF1 key or LCG parameters. Material crosses between them only
as files: `root.pem`, `station.pem`, `sam-handoff.json`, top-up requests and authorizations, and an
exported `ledger.jsonl`.

```text
Root station (root token + SAM reader)
  producer setup --station root   root CA key on the token, root.pem
  root init                       root-signed allocation registry, head mirrored on the token
  station import                  store a production station's station.pem under a name
  root allocate                   (IIN, batch) with its initial quota
  sam personalize                 LCG drawn and kept at the root, IIN FF1 key wrapped to the SAM,
                                  SAM key and certificate, LOCK, registry bind, sam-handoff.json
  root sign-top-up                sign a production top-up request
  root audit-ledger               replay every OPID of an exported production ledger

Production station (production token + SAM reader + card reader)
  producer setup --station production --root-pem root.pem
                                  card master key on the token, public root.pem only
  station init                    handoff ECDH key on the token, station.pem
  sam receive                     verify the bundle, rotate the SAM keys, set the operator PIN,
                                  create the batch and its stock SCP03 key
  card produce                    one card: install, F9 generate/prove, SAM ISSUE, verify (with
                                  SAM DECIPHER), load, proof, read-back, SCP key rotation, receipt
  sam top-up                      request out, root-signed authorization in
  sam void / decipher / status    VOID an issued OPID, reverse an OPID, signed STATUS
  ledger verify / reconcile       audit ledger.jsonl, recover one lost SAM event
  batch close, sam terminate      end of batch
  producer export-trust           root.pem, SAM certificates, voids.json and trust.json

Relying party
  attestation verify              PKIX root -> SAM -> F9 -> leaf, from files or read from a card
```

Station-specific commands check the station recorded in `producer.json` and refuse to run at the
other station.

The trust model, APDUs and certificate profiles are in [ATTESTATION.md](ATTESTATION.md) and
[ISSUER_SAM.md](ISSUER_SAM.md).

## Custody Tiers

A producer has one of two custody tiers, recorded as `custody` in `producer.json`.

| Tier          | Setup                         | Keys                                   | Card and SAM targets |
| ------------- | ----------------------------- | -------------------------------------- | -------------------- |
| `pkcs11`      | `--pkcs11-module` (HSM)       | on a token initialized with vendor tools; PIN never stored by the tool | `pcsc:` and `zmq:` |
| `softhsm-dev` | `--dev-softhsm`               | SoftHSM2 file token under the OpenFIPS201 home, user PIN in `pkcs11.pin` | `zmq:` only, unless `card produce --allow-dev-custody` |

- With `pkcs11`, the token must already exist and have a user PIN; setup refuses to initialize it.
  The PIN comes from `--pkcs11-pin-env`, `--pkcs11-pin-file` or a no-echo prompt, and the chosen
  source (not the PIN) is recorded in the profile.
- With `--dev-softhsm`, the tool initializes the token through PKCS#11 (`C_InitToken`,
  `C_InitPIN`) with distinct random 16-byte hex SO and user PINs; no PIN appears on a command line.
  `pkcs11.pin` is created only after initialization succeeds and is never overwritten. The SO PIN is
  shown once on the console or written to `--so-pin-out` (a new file outside the OpenFIPS201 home);
  it is required by `producer destroy`. Set `OPENFIPS201_SOFTHSM_MODULE` to override the module path.
- A `softhsm-dev` root station never personalizes a `pcsc:` SAM, and a `softhsm-dev` production
  station's `card produce` refuses a `pcsc:` card without `--allow-dev-custody`.

Token contents depend on the station. Keys are generated on the token (an FF1 key may instead be
imported with `producer iin import-key`) and are non-extractable; an FF1 key leaves the root token
only wrapped, to a SAM transport key or to a backup key.

| Station      | Token objects                                                                          |
| ------------ | -------------------------------------------------------------------------------------- |
| `root`       | root CA key `<name>-root-ca` (ECDSA P-256, with its certificate); one AES-256 FF1 key per IIN, `<name>-iin-IIII-fpe`; the allocation registry head |
| `production` | AES-256 card master key `<name>-card-master` (SCP03 KDF3 derivation of card and SAM keys); P-256 handoff key `<name>-station-handoff` |

Every production command first refuses a token that holds the root key (by `root.pem` key
identifier or the `-root-ca` label) or any key labelled `*-fpe`, and a home whose batch records hold
LCG parameters. `sam personalize` refuses a reader whose card answers SELECT for the PIV applet.

## Secrets

Every secret input has at most one of three forms:

| Form           | Example                      | Notes                                                  |
| -------------- | ---------------------------- | ------------------------------------------------------ |
| literal        | `--stock-scp-key HEX`        | visible in the process table; **refused for `pcsc:` targets**, accepted for `zmq:` |
| environment    | `--stock-scp-key-env NAME`   | reads the named variable                               |
| owner-only file| `--stock-scp-key-file PATH`  | regular file, owned by the user, no group/other bits   |

With no form given, the tool prompts on the console without echo. The SAM operator PIN
(`--operator-pin-env`, `--operator-pin-file`), PKCS#11 PINs and SO PINs have no literal form. SCP
keys follow the same pattern (`--scp-key`, `--scp-key-env`, `--scp-key-file`, and the split
`--scp-enc-key*`, `--scp-mac-key*`, `--scp-dek-key*`).

Error messages replace any run of 32 or more hex digits with `<redacted>`. Set
`-Dopenfips201.debug=true` to print stack traces.

## On-Disk Layout

The home is `~/.openfips201`, overridden by `-Dopenfips201.home` or `OPENFIPS201_HOME`. Every
directory created below the home is mode 0700 and every file mode 0600, applied at creation. An
existing directory must be owned by the user and not group- or world-writable (group/other read bits
are removed with a warning); secret files are checked to be owner-only before they are read. Files
are created with `CREATE_NEW` or replaced atomically (temporary file, fsync, `ATOMIC_MOVE`);
ledger lines are appended under a file lock.

```text
~/.openfips201/
  softhsm/softhsm2.conf, softhsm/tokens/         --dev-softhsm only
  producers/<producer>/
    producer.json            openfips201.producer/3: station, custody, PKCS#11 selection, root SKI
    root.pem                 root CA certificate (trust anchor for relying parties)
    pkcs11.pin               --dev-softhsm only

    Root station only:
    registry/allocations.jsonl                   root-signed allocation registry
    station-keys/<station>.pem                   imported production station handoff keys
    root/batches/IIII-NNNN-<samId>.lcg.json      openfips201.root-lcg/1: LCG a/c/x0, quota,
                                                 initial timestamp, FF1 KCV, paramsDigest
    root/batches/IIII-NNNN.sam.json              openfips201.root-sam/1: bound SAM, certificate,
                                                 allocationSeq, registry head

    Production station only:
    batches/IIII-NNNN/
      batch.json             openfips201.batch/4: IIN, batch, paramsDigest, registry lines, quota,
                             stock key KCV, SAM binding; no LCG parameters
      batch.lock             exclusive lock held by every SAM or card operation
      sam.pem                SAM certificate
      ledger.jsonl           host hash-chained ledger
      receipts.csv           one row per card attempt
      receipts/IIII-NNNN-<seq>-<millis>.json     openfips201.receipt/2
```

The root station's `*.lcg.json` records, together with the IIN FF1 key on the root token, predict a
batch's OPID sequence: keep the root home on encrypted storage with restricted access. The
production home holds no LCG or FF1 material, but its receipts and ledgers are the issuance record.
Include both homes in the issuer's backup plan.

## Producer

### producer setup

```sh
# Root station, hardware custody
ant -f build/build.xml openfips201-tool -Dargs='producer setup \
  --name bigcorp_01 --station root \
  --pkcs11-module /usr/lib/vendor/libpkcs11.so --pkcs11-token-label bigcorp_root \
  --pkcs11-pin-env BIGCORP_HSM_PIN \
  --root-subject "O=BigCorp,CN=BigCorp OpenFIPS201 Root" \
  --f9-subject "O=BigCorp,CN=BigCorp OpenFIPS201 F9"'

# Production station, hardware custody (root.pem copied from the root station)
ant -f build/build.xml openfips201-tool -Dargs='producer setup \
  --name bigcorp_01 --station production --root-pem /transfer/root.pem \
  --pkcs11-module /usr/lib/vendor/libpkcs11.so --pkcs11-token-label bigcorp_line1 \
  --pkcs11-pin-env BIGCORP_HSM_PIN'

# Development custody
ant -f build/build.xml openfips201-tool -Dargs='producer setup --name dev_01 --station root --dev-softhsm'
```

- `--station` is `root` (default) or `production` and cannot change for an existing producer. A
  production station requires `--root-pem`; a root station refuses it.
- Setup is idempotent: re-running reuses the existing keys and re-exports `root.pem`. Custody cannot
  change for an existing producer. A `producer.json` older than schema 3 is refused with migration
  guidance: set up both stations again and re-issue the SAMs.
- Root station: creates or reuses `<name>-root-ca`. The root certificate has critical
  basicConstraints cA TRUE without pathLen, critical keyUsage keyCertSign and cRLSign, and an
  RFC 7093 method 1 subjectKeyIdentifier. `--root-validity-days` sets its validity. IIN FF1 keys are
  created on first use by `sam personalize`.
- Production station: creates or reuses `<name>-card-master` and copies the public `--root-pem`.
  It never holds the root key.
- `--f9-subject` (root station) is the F9 subject **template**, without `serialNumber`; the SAM
  appends the OPID as the final `serialNumber` RDN. Missing subjects are prompted for on a new root
  station.

### producer root reissue-certificate

```sh
ant -f build/build.xml openfips201-tool -Dargs='producer root reissue-certificate --name bigcorp_01 --yes'
```

Issues a new root certificate for the same root key with the current root profile (including the
SKI), replaces it on the token, re-exports `root.pem` and rewrites `producer.json`. Relying parties
must be given the new `root.pem`. Commands that sign with the root refuse to run when the token
certificate differs from `root.pem`.

### producer destroy

```sh
ant -f build/build.xml openfips201-tool -Dargs='producer destroy \
  --name dev_01 --confirm-token-label dev_01 --so-pin-file /secure/dev_01.so-pin'
```

Erases the token with its SO PIN (from `--so-pin-env`, `--so-pin-file` or a prompt), then deletes
`pkcs11.pin`, `root.pem` and `producer.json`. Batches, receipts and root station records are kept.

### producer export-trust

```sh
ant -f build/build.xml openfips201-tool -Dargs='producer export-trust --name bigcorp_01 --out /export/bigcorp_01-trust'
```

Runs at either station and writes the public material a relying party needs, owner-only, into
`--out`:

- `root.pem`: the trust anchor;
- `sam-IIII-NNNN.pem`: the SAM certificate of every bound SAM (root station) or received batch
  (production station);
- root station: `allocations.jsonl`, the allocation registry (input to `attestation verify
  --registry`);
- production station: `voids.json` (`openfips201.voids/1`), every SAM-signed VOID entry of its
  ledgers (input to `attestation verify --voids`);
- `trust.json` (`openfips201.trust/2`): the producer, the station, the root file, SHA-256, SKI and
  subject, and for each SAM its file, batch, IIN, SAM identifier, SHA-256, SKI and validity.

No key, PIN, LCG or FF1 material is read or written. The command refuses to run if any of these
files already exists in the output directory.

## Root Station

### station init and station import

```sh
# Production station
ant -f build/build.xml openfips201-tool -Dargs='station init --producer bigcorp_01 --out /transfer/station.pem'
# Root station
ant -f build/build.xml openfips201-tool -Dargs='station import --producer bigcorp_01 --name line1 --pub /transfer/station.pem'
```

`station init` creates (or reuses) the P-256 handoff key `<name>-station-handoff` on the production
token and writes its public key as `station.pem`. `station import` stores it at the root as
`station-keys/<name>.pem`. The station key identifier (RFC 7093 method 1) binds each handoff bundle
to one station.

### root init and root allocate

```sh
ant -f build/build.xml openfips201-tool -Dargs='root init --producer bigcorp_01'
ant -f build/build.xml openfips201-tool -Dargs='root allocate --producer bigcorp_01 --iin 1234 --batch 42 --quota 5000'
```

`root init` creates `registry/allocations.jsonl` with a root-signed genesis line and stores the
registry head on the root token. Each line is root-signed canonical JSON with `seq`, `type`
(`genesis`, `allocate`, `bind`, `topup`), `iin`, `batch`, `at` and `prev` (SHA-256 of the previous
line). Every registry command first requires the file head to equal the token head, which refuses a
stale or forked copy.

`root allocate` records an (IIN, batch) allocation with its initial quota. IIN and batch are
0..9999, the quota 1..10^8 (the LCG period), and a second allocation of the same (IIN, batch) is
refused. The batch is named `IIII-NNNN` on both stations.

### IIN FF1 keys

The FF1 key of an IIN is an AES-256 key on the root token, labelled `<name>-iin-IIII-fpe`. It is
generated by the first `sam personalize` for the IIN and reused for every later batch of that IIN.
It leaves the token only wrapped:

- to a SAM's one-time transport key, inside PUT PARAMETERS v5;
- to an operator backup key with `producer iin backup-key --name P --iin IIII --to-pub backup.pem
  --out iin-IIII.backup.json` (ECDH P-256, X9.63 SHA-256 KDF with SharedInfo
  `"OPFPEBK1" ‖ backupPub ‖ ASCII(IIII)`, RFC 3394 key wrap; schema `openfips201.iin-fpe-backup/1`).

`producer iin import-key --name P --iin IIII --yes` migrates a plaintext `iin-IIII.fpe.json`
(`openfips201.iin-fpe/1`) into the root token, verifies its KCV through the token, then overwrites
and deletes the file. No command creates such a file; FF1 keys are otherwise only generated on the
token.

One key serves every batch and SAM of the IIN. Its compromise exposes the batch and issuance value
of every OPID of the IIN; with a batch's LCG record, that batch's future OPIDs become predictable.
See [SECURITY_NOTES.md](../SECURITY_NOTES.md#opid-sequence-secrecy). The key cannot be replaced for
an IIN without breaking cross-batch uniqueness; back it up with `backup-key`.

### sam personalize

```sh
ant -f build/build.xml openfips201-tool -Dargs='sam personalize \
  --producer bigcorp_01 --iin 1234 --batch 42 --sam pcsc:SAMReader \
  --station line1 --bundle-out /transfer/sam-handoff-1234-0042.json \
  --install --sam-cap build/bin/OpenPhysicalIssuerSam-0.1.cap \
  --sam-stock-key-file /secure/sam-stock.key --yes'
```

| Option                | Meaning                                                                |
| --------------------- | ---------------------------------------------------------------------- |
| `--iin`, `--batch`    | an allocated, not yet bound (IIN, batch)                               |
| `--station`           | the imported production station that receives the SAM                  |
| `--bundle-out`        | new `sam-handoff.json` file                                            |
| `--sam-subject`       | SAM subject template; the SAM's KDD is appended as `serialNumber` (128-octet limit) |
| `--sam-validity-days` | SAM certificate validity (default 3650)                                |
| `--f9-validity-days`  | F9 certificate validity requested per card (default 3650), capped by the SAM certificate |
| `--install`, `--sam-cap` | install the SAM instance first, loading the CAP if given            |
| `--sam-stock-key-env`, `--sam-stock-key-file` | the SAM's stock SCP03 key; required for `pcsc:`, a `zmq:` SAM defaults to the GlobalPlatform test key |
| `--yes`               | required for a `pcsc:` SAM                                             |

One online step with the root token and the SAM, never a card:

1. Preflight: the (IIN, batch) is allocated and unbound; the F9 and SAM subject templates fit the
   SAM's limits; the reader does not hold a PIV card; the SAM is freshly installed (lifecycle
   INSTALLED).
2. The IIN FF1 key is created on the root token if absent. The LCG (`a`, `c`, `x0`) is drawn and
   stored only in `root/batches/IIII-NNNN-<samId>.lcg.json` with the quota, initial timestamp, FF1
   KCV and `paramsDigest`.
3. Over the SAM's stock secure channel: GENERATE TRANSPORT KEY; PUT PARAMETERS v5 with the FF1 key
   wrapped on the root token to the transport key (the SAM's reported `paramsDigest` must equal the
   root's); SET PIN with a random operator PIN; GENERATE.
4. The root issues the SAM certificate (basicConstraints critical cA pathLen 1, keyUsage critical
   keyCertSign and digitalSignature, SKI, AKI, batch extension v3 carrying `allocationSeq` and the
   registry head after the bind line) and loads it; the SAM must report the same SKI.
5. The SAM's GlobalPlatform keys are rotated to random handoff keys (key version `7E`). LOCK; the
   genesis entry must commit to the SAM certificate, `paramsDigest` and quota.
6. The registry `bind` line is appended, `root/batches/IIII-NNNN.sam.json` written, and
   `sam-handoff.json` written; the handoff secrets are then wiped.

An interrupted personalization is not resumed: reinstall the SAM (or use another) and repeat the
command. The handoff keys exist only in memory and in the bundle, so a SAM whose bundle was never
written cannot be operated.

`sam-handoff.json` (`openfips201.sam-handoff/1`) is root-signed canonical JSON. Its plaintext members
are the producer, IIN, batch, SAM identifier (KDD), quota, initial timestamp, `paramsDigest`, F9
validity, SAM and root certificates, the registry `allocate` and `bind` lines, and the signed genesis
entry. Only the handoff SCP keys and the operator PIN are secret: they are wrapped to the station's
handoff key (ECDH P-256, X9.63 SHA-256 KDF with SharedInfo `"OPSAMHO1" ‖ samId ‖ stationSki`,
RFC 3394 key wrap).

## Production Station: Issuer SAM

### sam receive

```sh
ant -f build/build.xml openfips201-tool -Dargs='sam receive \
  --producer bigcorp_01 --bundle /transfer/sam-handoff-1234-0042.json --sam pcsc:SAMReader \
  --operator-pin-file /secure/operator.pin --stock-key-out /secure/1234-0042.stock-key --yes'
```

1. The bundle's root signature, its root certificate (equal to `root.pem`), the chain root → SAM,
   the batch extension against the bundle, and the registry `allocate`/`bind` lines (root
   signatures, linkage, and SHA-256 of the `bind` line equal to the certificate's registry head)
   are verified. The bundle must name this producer, be wrapped to this station's key and name the
   SAM in the reader (KDD).
2. The handoff secrets are unwrapped through the production token.
3. Over the handoff channel: the SAM's `paramsDigest` must equal the bundle's, and its signed STATUS
   must be OPERATIONAL, issued 0, at the genesis entry, with the certificate's `allocationSeq` and
   registry head.
4. The SAM's GlobalPlatform keys are rotated to keys derived from its KDD with the card master key;
   the handoff keys no longer authenticate.
5. CHANGE OPERATOR PIN from the handoff PIN to the operator's PIN (6 to 16 printable ASCII
   characters, from `--operator-pin-env`, `--operator-pin-file` or a prompt).
6. `batches/IIII-NNNN/` is created (`batch.json` without LCG parameters, `sam.pem`, ledger `genesis`
   line; state `SAM_BOUND`). An existing batch of that name is refused.

A new stock SCP03 key for the batch's cards is generated, printed once (or written to
`--stock-key-out`) and recorded only by its GlobalPlatform Section B.6 KCV. Stock cards for the
batch must carry this key.

`batch show --producer P --name IIII-NNNN` prints the batch state, OPID identity, `paramsDigest`,
registry binding, quota and SAM.

### sam status

```sh
ant -f build/build.xml openfips201-tool -Dargs='sam status --producer bigcorp_01 --batch 1234-0042 --sam pcsc:SAMReader [--json]'
```

Reads STATUS signed over a fresh nonce and verifies it with `sam.pem`: lifecycle, issued and quota,
event sequence, chain head, SAM SKI and PIN tries.

### sam top-up

Top-up is a file exchange; the root key is never at the production station.

```sh
# Production station: write a request (reads the SAM's signed STATUS)
... -Dargs='sam top-up --producer bigcorp_01 --batch 1234-0042 --sam pcsc:SAMReader --add 1000 --request-out topup-req.json'
# Root station: check and sign it
... -Dargs='root sign-top-up --producer bigcorp_01 --request topup-req.json --out topup-auth.json'
# Production station: apply it
... -Dargs='sam top-up --producer bigcorp_01 --batch 1234-0042 --sam pcsc:SAMReader --authorization-in topup-auth.json'
```

- The request (`openfips201.topup-request/2`) names the producer, batch, SAM identifier, SAM SKI,
  timestamp and `add`, and carries the SAM's current STATUS signed over a nonce. Its timestamp is
  `max(now, last accepted + 1 s)`.
- `root sign-top-up` requires the batch to be bound to that SAM in the registry, the STATUS to verify
  under the bound SAM's certificate and be OPERATIONAL for that IIN and batch, and the timestamp to
  be later than the SAM's last top-up and every top-up already authorized for the batch. It appends
  a registry `topup` line and returns the authorization (`openfips201.topup-authorization/2`), an
  ECDSA P-256 signature over `"OPSAMTOPUP1" ‖ samSki ‖ ts(u64) ‖ add(u32)`.
- Applying checks the authorization names this producer, batch and SAM and verifies under
  `root.pem`, sends TOP UP, requires the SAM's TOPUP entry to match and extend the ledger, appends
  the `topup` line, updates `batch.json`, and confirms the new quota with a signed STATUS.
- The SAM accepts only strictly increasing timestamps. Apply authorizations in the order their
  requests were created; applying a newer one makes every unapplied older one permanently invalid.

### sam decipher

```sh
ant -f build/build.xml openfips201-tool -Dargs='sam decipher --producer bigcorp_01 --batch 1234-0042 --sam pcsc:SAMReader --opid <17-digit OPID>'
```

Sends DECIPHER over the SAM's derived secure channel after VERIFY PIN and prints the batch number,
whether it is this SAM's batch and, if so, the issuance number and whether it has been issued. The
production station holds no FF1 key, so the SAM is the only authority. An OPID of another IIN is
refused by the SAM.

### sam void

```sh
ant -f build/build.xml openfips201-tool -Dargs='sam void --producer bigcorp_01 --batch 1234-0042 --sam pcsc:SAMReader --seq 17 [--reason 1]'
```

The SAM recomputes the OPID of issuance `--seq` and signs a VOID entry (reason 0 unspecified,
1 reissue). The entry must verify, extend the ledger and name the ledger's OPID for that issuance;
it is recorded as the ledger `void` line and exported in `voids.json` by `producer export-trust`.

### sam change-pin

```sh
ant -f build/build.xml openfips201-tool -Dargs='sam change-pin --producer bigcorp_01 --batch 1234-0042 --sam pcsc:SAMReader \
  --operator-pin-file /secure/operator.pin --new-pin-file /secure/operator.new.pin'
```

Changes the SAM operator PIN with CHANGE OPERATOR PIN.

## Producing Cards

### card produce

```sh
ant -f build/build.xml openfips201-tool -Dargs='card produce \
  --producer bigcorp_01 --batch 1234-0042 \
  --target pcsc:CardReader --sam pcsc:SAMReader \
  --stock-scp-key-file /secure/1234-0042.stock-key \
  --operator-pin-file /secure/operator.pin --yes'
```

Runs at the production station. The host relays, persists and verifies what the SAM returns; it
never computes an OPID.

| Option                 | Meaning                                                                |
| ---------------------- | ---------------------------------------------------------------------- |
| `--target`             | card reader (required)                                                 |
| `--sam`                | Issuer SAM reader; must differ from `--target`                         |
| `--cap`                | PIV CAP (default `build/bin/OpenFIPS201-standard-CS2-attestation-true.cap`); `<cap>.properties` must say `attestation.enabled=true` |
| `--stock-scp-key*`     | the batch stock key; its KCV is checked before any reader is opened    |
| `--operator-pin-*`     | SAM operator PIN                                                       |
| `--yes`                | required for a `pcsc:` card                                            |
| `--allow-dev-custody`  | permit a `softhsm-dev` producer to issue to a `pcsc:` card             |
| `--reissue`            | the card is a burned card of this batch: void its OPID, delete and reinstall the applet, and produce it with the next OPID |

Before the stages, the tool checks the stock KCV, distinct readers and that the batch is
`SAM_BOUND`, applies the production token guards, reads the SAM's KDD (it must be the batch's SAM),
opens the SAM with its derived SCP keys and verifies the operator PIN. It then holds the batch lock
for the whole issuance.

Stages, recorded in the receipt as they are entered:

| Stage              | Work                                                                                   |
| ------------------ | -------------------------------------------------------------------------------------- |
| `PREFLIGHT`        | CAP carries attestation; SAM signed STATUS: OPERATIONAL, this batch's SAM, quota left, and equal to the ledger (issued count, event, head); a card that already has a PIV instance is refused unless a burned receipt of this batch names it (CPLC, KDD) and `--reissue` is given; receipt created with `CREATE_NEW` |
| `APPLET_INSTALLED` | CPLC and KDD read; for a reissue the SAM VOIDs the burned OPID (ledger `void` line), the old instance is deleted and stock keys restored if they were rotated; applet loaded (`pcsc:`) and installed over the stock channel |
| `F9_GENERATED`     | F9 defined and generated on the card                                                   |
| `SAM_NONCE`        | BEGIN ISSUANCE                                                                         |
| `F9_PROVED`        | card PROVE; the host pre-verifies the proof                                            |
| `ISSUE_REQUESTED`  | SAM ISSUE with the F9 point, proof and validity                                        |
| `ISSUED`           | raw response saved in the receipt (`burned: true`) and the ledger `issue` line appended before parsing |
| `F9_VERIFIED`      | entry signature and chain position, OPID syntax (17 digits, Luhn, batch IIN), SPKI, certificate OPID equals entry OPID, SKI, TBS hash, PKIX root → SAM → F9, and SAM DECIPHER of the OPID equals (this batch, issuance number, issued); a failure is recorded as stage `VERIFY_FAILED` and nothing is loaded |
| `F9_LOADED`        | certificate loaded; the card's read-back must be byte-identical                         |
| `PROOF_VERIFIED`   | proof key generated in `9A` under a temporary local PIN, attested, verified root → leaf, deleted; the local PIN is then set to 8 random digits that are not recorded |
| `APPLET_READBACK`  | GET VERSION; GET STATUS must report the authority ACTIVE with this OPID and F9 SKI      |
| `KEYS_ROTATED`     | CPLC and KDD re-read (a different card fails); SCP03 keys rotated to KDF3 keys derived from the KDD |
| `COMPLETED`        | identifiers (OPID, GUID, UUID OID, FASC-N, CCC) recorded; ledger `outcome`; CSV row     |

After `card produce` the card has an active F9 authority, rotated SCP keys and an unknown random
local PIN, so shipped stock never carries a known PIN. Personalization sets the cardholder PIN, PUK,
`9B`, VCI key `04`, cardholder keys and data objects afterwards over the secure channel with the
rotated keys; the activation wipe would erase anything provisioned before F9.

Exit codes and burned OPIDs:

| Exit | Meaning                                                                                       |
| ---- | --------------------------------------------------------------------------------------------- |
| `0`  | completed                                                                                     |
| `1`  | failed before the SAM committed an OPID (also any failure before the receipt exists)          |
| `3`  | failed after the SAM committed the OPID; it is burned and never reused                        |

On exit 3 the ledger gets an `outcome` line with status `FAILED` when the ISSUE response was
received. If the SAM returned `6500`, the tool recovers the entry with GET LAST ENTRY at once. If
the response was lost, the receipt says so and `ledger reconcile` must be run before the next card;
preflight refuses to continue while the ledger and the SAM disagree. A card that failed after the
OPID was burned cannot reuse it: run `card produce --reissue` on it. The SAM VOIDs the burned OPID,
the applet is deleted and reinstalled, and the card receives the next OPID; the receipts and ledger
`outcome` lines link the attempts (`reissueOf`, `supersededBy`).

Receipts (`openfips201.receipt/2`) are created owner-only and replaced atomically at every stage,
so a crash leaves the last stage on disk. They record: producer, batch, readers, custody, stage
history with times, `status` (`IN_PROGRESS`, `COMPLETED`, `FAILED`), `burned`, a redacted failure;
the CAP path, SHA-256, load-file hash, whether it was loaded and its `.properties`; CPLC and parsed
fields, initial and final KDD, GET VERSION and GET STATUS responses; the SAM SKI, nonce, issuance
and event sequence, OPID, raw ISSUE response, entry and signature; the F9 point, SKI, subject,
certificate and hash, read-back result; the proof slot, point, leaf and deletion; the verifier
reports; identifiers; and the new key version and KCVs. Receipts never contain raw keys.

`receipts.csv` columns: timestamp, producer, batch, target, status, stage, opid, issuance_seq,
cplc, kdd_initial, kdd_final, new_key_version, enc_kcv, mac_kcv, dek_kcv, f9_ski, f9_cert_sha256,
guid, fascn, receipt.

`interactive` prompts for producer, batch and readers and runs `card produce`; `--dry-run` prints
the equivalent command. `cardstock prepare` is a deprecated alias of `card produce` with the same
options.

## Ledger

`batches/IIII-NNNN/ledger.jsonl` holds one compact JSON object per line: `v` (1), `type`, `at`, and
`prev` (SHA-256 of the previous line's text; 64 zeros on the first line). Types:

| Type      | Content                                                        |
| --------- | -------------------------------------------------------------- |
| `genesis` | SAM genesis entry and signature                                |
| `topup`   | SAM TOPUP entry and signature                                  |
| `issue`   | SAM ISSUE entry and signature, seq, OPID, F9 SKI, certificate hash, receipt, `recovered` |
| `void`    | SAM VOID entry and signature for an issued OPID                |
| `close`   | SAM CLOSE entry and signature; the batch produces no further cards |
| `term`    | SAM TERM entry and signature, written by `sam terminate`       |
| `outcome` | final status and stage of an issued OPID's card, optionally linked by `reissueOf` / `supersededBy` |
| `lost`    | an issued OPID whose card will never carry it                  |

Every SAM line carries the SAM's ledger `entry`, its `sig`, `eventSeq` and `head`.

### ledger verify

```sh
ant -f build/build.xml openfips201-tool -Dargs='ledger verify --producer bigcorp_01 --batch 1234-0042 \
  [--sam pcsc:SAMReader [--operator-pin-file /secure/operator.pin] [--decipher-sample 8]]'
```

Offline checks:

- line hash chain, genesis first;
- every SAM entry verifies under the SAM key and names the SAM SKI; the entries form the SAM chain
  (event + 1, previous head);
- genesis commits to `sam.pem`, `paramsDigest` and the initial quota;
- the SAM certificate verifies under `root.pem` and its batch extension matches the batch record;
  the registry `allocate`/`bind` lines verify under the root and the `bind` line hash equals the
  certificate's registry head;
- issuance numbers 1, 2, …, each OPID a canonical 17-digit OPID of the batch IIN, no repeated OPID or
  F9 key identifier;
- every `outcome`, `lost` and `void` line names an issued (seq, OPID) pair;
- `close` records the final issued count; no `issue` or `topup` follows it; nothing follows `term`.

The production station never recomputes an OPID. With `--sam`, the live SAM's signed STATUS must be
at the ledger's last entry (event, chain head, issued count) and CLOSED exactly when the ledger is
closed, which detects a truncated or diverged ledger. With an operator PIN as well, up to
`--decipher-sample` issued OPIDs (default 8; first, last and evenly spaced; `0` disables) are
DECIPHERed and must return their issuance numbers. Exit `0` valid, `1` invalid.

### ledger reconcile

```sh
ant -f build/build.xml openfips201-tool -Dargs='ledger reconcile --producer bigcorp_01 --batch 1234-0042 --sam pcsc:SAMReader'
```

Reads the SAM's signed last entry (GET DATA LAST ENTRY). It is accepted only when it verifies, names
the batch SAM and extends the ledger's last SAM entry exactly. A missing ISSUE is recorded as `issue`
(`recovered: true`) followed by `lost`; a missing TOPUP as `topup` (and `batch.json` updated); a
missing VOID as `void`. More than one missing event cannot be recovered. Prints `IN_SYNC`,
`RECOVERED_ISSUE`, `RECOVERED_TOPUP` or `RECOVERED_VOID`.

### root audit-ledger

```sh
# Root station, with ledger.jsonl exported from the production station
ant -f build/build.xml openfips201-tool -Dargs='root audit-ledger --producer bigcorp_01 --ledger /transfer/ledger.jsonl --batch 1234-0042'
```

Verifies the ledger's hash chain and SAM entries under the bound SAM's certificate from the root's
SAM record (genesis commitment to that certificate, the recorded `paramsDigest` and quota), then
replays every issued OPID from the root's LCG record and the IIN FF1 key on the root token. Exit `0` valid, `1`
invalid.

## Closing a Batch

Close the batch first, then terminate its SAM:

```sh
ant -f build/build.xml openfips201-tool -Dargs='batch close --producer bigcorp_01 --batch 1234-0042 --sam pcsc:SAMReader \
  --operator-pin-file /secure/operator.pin --yes'
ant -f build/build.xml openfips201-tool -Dargs='sam terminate --producer bigcorp_01 --batch 1234-0042 --sam pcsc:SAMReader \
  --operator-pin-file /secure/operator.pin --yes'
```

- `batch close`: the SAM's signed STATUS must agree with the ledger (issued count, event, chain
  head; otherwise run `ledger reconcile` first). SAM CLOSE commits a signed CLOSE entry carrying the
  issued count and quota, which must verify, extend the ledger and match the ledger's issued count.
  It is appended as the `close` line and the batch becomes `CLOSED`. The SAM then refuses BEGIN,
  ISSUE and TOP UP, so `card produce` and `sam top-up` no longer succeed; DECIPHER and VOID still
  work. Repeating the command is harmless: the SAM returns its stored CLOSE entry.
- `sam terminate`: over the SAM's derived secure channel and after VERIFY PIN it sends TERMINATE;
  the TERM entry must verify and extend the ledger and is appended as the `term` line, and the batch
  becomes `TERMINATED`. Terminating a batch that is not closed is allowed with a warning. The SAM
  clears its key, FF1 key and LCG state and can sign nothing afterwards, so `sam status` and `ledger
  verify --sam` no longer work against it; keep the last verified ledger. Termination is
  irreversible.

## Attestation Verification

From files (a relying party with the exported trust material):

```sh
ant -f build/build.xml openfips201-tool -Dargs='attestation verify \
  --anchor root.pem --chain sam-1234-0042.pem --chain f9.pem --leaf leaf.pem \
  [--registry allocations.jsonl] [--voids voids.json] \
  [--slot-cert 9a.pem] [--expect-opid <17-digit OPID>] [--at 2026-10-05] [--json]'
```

From a card:

```sh
ant -f build/build.xml openfips201-tool -Dargs='attestation verify --from-card \
  --target pcsc:CardReader --slot 9A [--pin-env PIV_PIN | --pin-file /secure/pin] \
  --producer bigcorp_01 --batch 1234-0042'
```

- With `--from-card`, the tool selects PIV over a plain connection, verifies the PIN if one is
  given (6 to 8 characters, needed for PIN-protected slots), and reads the leaf (`00 F9 <slot> 00`)
  and the F9 certificate (`00 F9 F9 00`). `--leaf` is then not allowed and `--chain` takes only the
  SAM certificate.
- `--producer` supplies the anchor (the producer's `root.pem`) when `--anchor` is omitted;
  `--producer --batch` supplies the batch's SAM certificate (a production station batch) instead of
  `--chain`.
- Without `--from-card`, `--chain` takes the SAM certificate, then the F9 certificate, and `--leaf`
  is required.
- `--registry` (from the root station's `export-trust`): the registry must verify under the anchor
  line by line and as a chain; its `allocate` line at the SAM's `allocationSeq` must name the SAM's
  IIN, batch and initial quota, and a `bind` line must name the SAM and hash to the certificate's
  registry head.
- `--voids` (from the production station's `export-trust`): the F9 OPID must not appear among the
  VOID entries signed by the SAM key.

Checks: strict DER, signature algorithms, PKIX path at `--at` (default now), name chaining and
AKI/SKI linkage, the SAM batch extension and pathLen, the F9 profile and OPID, the leaf profile and
OpenPhysical extension, and optionally the registry binding, the void list, the slot certificate
SPKI and the expected OPID. Exit `0` valid, `1` invalid, `2` usage or input error.

## Emulator

```sh
ant -f build/build.xml openfips201-tool -Dargs='emulator serve --endpoint tcp://127.0.0.1:5555 --applet piv'
ant -f build/build.xml openfips201-tool -Dargs='emulator serve --endpoint tcp://127.0.0.1:5556 --applet sam'
```

`--applet` registers the PIV applet (`piv`, default) or the Issuer SAM (`sam`). The emulator starts
as stock: the class is registered but no instance is installed. `card produce` installs the PIV
applet without loading a CAP on `zmq:` targets; `sam personalize --install` installs the SAM. The
emulator uses the GlobalPlatform test SCP03 key unless `--scp03-key` is given. A full issuance needs
two emulators, one per applet.

The client checks the emulator protocol with a bounded handshake. APDUs are never retried; a timeout
closes the transport and reports the card state as indeterminate.

## Conformance Provisioning

```sh
ant -f build/build.xml openfips201-tool -Dargs='provision \
  --icam /path/to/46_Golden_FIPS_201-2_PIV --target pcsc:CardReader --scp-key-file /secure/scp.key'
```

`provision` loads a GSA ICAM card folder over SCP03 (see
[CONFORMANCE_PROVISIONING.md](CONFORMANCE_PROVISIONING.md)). It reads GET STATUS tag `87` from the
installed applet: on a FIPS build it defines `9A` and `9C` non-importable and generates them on the
card, otherwise it imports every key. It fails if the applet does not report its FIPS mode.
`--certification-profile` validates the folder against the certification claims
(`--government-email`, `--vci`, `--pairing-required`) and personalizes the applet after read-back.

## GlobalPlatform Key Management

`gp card kdd --target T [--raw]` reads the 10-byte KDD from INITIALIZE UPDATE without
authenticating.

`gp keys derive --kdd HEX` and `gp keys derive-card --target T` derive SCP03 KDF3 keys through the
PKCS#11 AES card master key (`--pkcs11-module`, `--pkcs11-token-label`, `--pkcs11-key-alias`,
`--pkcs11-pin-env`) and print KCVs only. The key must permit `CKM_AES_CMAC`.

`gp keys rotate` writes the derived keyset with PUT KEY and authenticates with it. The KDD is always
read from the card; `--kdd` is an expected value and a mismatch is refused.

```sh
ant -f build/build.xml openfips201-tool -Dargs='gp keys rotate \
  --target pcsc:CardReader --scp 03 --scp-key-env CARD_SCP_KEY \
  --pkcs11-module /usr/lib/vendor/libpkcs11.so --pkcs11-token-label bigcorp_issuer \
  --pkcs11-key-alias bigcorp_01-card-master --pkcs11-pin-env BIGCORP_HSM_PIN \
  --new-key-version 2'
```

`gp keys keyroll forward|backward --profile producers/<p>/producer.json --target T` moves a card
between the stock key (`--stock-scp-key*`) and the profile-derived keys. `gp keys preflight
--direction forward|backward` validates the same rotation without mutating the card and prints the
rollback command. Physical targets require `--yes` for keyroll. Rotation rejects equal current and
target key versions.

`--scp auto` (default) sends one INITIALIZE UPDATE and uses the reported SCP version; it never
retries with another version. Cards may block their security domain after a few failed
authentications, so never run commands with guessed keys.

## Other Commands

- `cards list`: PC/SC reader names.
- `applet install --cap C --target T`: load and install a CAP (`--skip-load`, `--delete-existing`,
  AID overrides).
- `crypto pkcs11 list`: validate a token and signing-key selection; the key must carry a matching
  certificate.
