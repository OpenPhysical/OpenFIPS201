# Production qualification

Qualify each supported card, Issuer SAM platform, provider, reader, and build profile before issuing
production credentials. Software regression results and card-platform evidence are separate release
gates.

## Custody gate

- Issuance runs on two stations with separate hosts and hardware tokens. The root station token holds
  the root CA key and the per-IIN FF1 keys; the production station token holds the AES-256 card
  master key and the handoff key. Root, SAM and card are never together: the root station refuses a
  reader holding a PIV card, and every production command refuses a token holding the root key or an
  FF1 key, or a home holding LCG records.
- Production stations use `pkcs11` custody: hardware tokens initialized with the vendor's tools,
  with non-extractable keys. `card produce` refuses a `pcsc:` card for a `softhsm-dev` producer
  unless `--allow-dev-custody` is given, and a `softhsm-dev` root never personalizes a `pcsc:` SAM.
  Do not use `--allow-dev-custody` for production cards.
- Supply PINs, the stock SCP keys and the operator PIN through environment variables, owner-only
  files or the no-echo prompt. Literal key options are refused for `pcsc:` targets.
- The batch LCG records (`root/batches/*.lcg.json`) exist only in the root station home; with the
  IIN FF1 key they predict a batch's OPIDs. Keep the root home on access-controlled, encrypted
  storage, back up each FF1 key with `producer iin backup-key` under the same controls as the HSM
  backup, and record who can read them. See
  [SECURITY_NOTES.md](../SECURITY_NOTES.md#opid-sequence-secrecy).
- Batch numbers are unique per IIN through the root's allocation registry, which refuses a second
  allocation of an (IIN, batch) and a second SAM binding. Run one root station per producer and back
  up `registry/allocations.jsonl` with the token (the token holds the registry head).

## Issuer SAM ceremonies

Run each step under dual control and retain its output:

1. Root station: `producer setup --station root` (or `producer root reissue-certificate`),
   `root init` once, and distribution of `root.pem` to the production stations.
2. Production station: `producer setup --station production --root-pem root.pem` and `station
   init`; transfer `station.pem` to the root, which runs `station import`. Verify the station key
   out of band.
3. Root station: `root allocate` (IIN, batch, quota), then `sam personalize --station <name>
   --bundle-out <file>`. Retain the root's `*.sam.json` and `*.lcg.json` records. Transfer the
   bundle and the SAM to the production station; only that station's token can unwrap the bundle.
4. Production station: `sam receive` with the operator PIN and stock key destination. Record the
   SAM's KDD, SAM SKI, operator PIN custodians and stock key delivery. The operator PIN has 5 tries
   and no unblock; a blocked PIN ends issuance on that SAM.
5. Quota top-ups: `sam top-up --request-out` (production) → `root sign-top-up` (root) → `sam top-up
   --authorization-in` (production). The SAM accepts only strictly increasing timestamps; the tool
   sets each request's timestamp to `max(now, last accepted + 1 s)`. Apply authorizations in request
   order, because a newer authorization permanently invalidates unapplied older ones. Keep host
   clocks correct: a clock far in the future raises the floor for every later top-up.
6. Before and after each production session: `sam status` and `ledger verify --sam` with the
   operator PIN, which compares the host ledger with the live SAM's signed STATUS (detecting
   truncation or divergence) and DECIPHER-checks a sample of issued OPIDs.
7. Trust distribution: run `producer export-trust --name P --out DIR` into a new directory at the
   root station (`root.pem`, SAM certificates, `allocations.jsonl`) and at each production station
   (`root.pem`, SAM certificates, `voids.json`), and publish the files and each `trust.json` to
   relying parties through an authenticated channel. Relying parties pin `root.pem` and check the
   SHA-256 and SKI values in `trust.json`. Re-export after every void and after `producer root
   reissue-certificate`.
8. End of batch: reconcile and verify the ledger against the live SAM (`ledger verify --sam`), then
   `batch close` (SAM-signed CLOSE entry; the SAM refuses further BEGIN, ISSUE and TOP UP), then `sam
   terminate` (TERM entry recorded; the SAM's signing key, FF1 key and LCG state are cleared). Run
   `ledger verify` once more offline, transfer `ledger.jsonl` to the root for `root audit-ledger`,
   archive the batch directory, and retire or destroy the terminated SAM. Only exit `0` is a clean
   pass; exit `4` (a legacy format 1 ledger whose receipts are not bound) needs a recorded
   disposition.

Every `card produce` receipt (`openfips201.receipt/2`) records the CAP SHA-256, load-file hash and
`.cap.properties` (including `build.sha256`), the CPLC SHA-256 (`card.cplcSha256`), the GET VERSION and GET STATUS read-back (authority ACTIVE, OPID, F9 SKI), the
SAM entry and signature, the verifier reports (including the SAM's DECIPHER of the OPID) and the new
SCP key KCVs. Retain receipts, the CSV and `ledger.jsonl` with the batch evidence, and reconcile
every exit-3 (burned OPID) result with `ledger reconcile` before the next card; a burned card is
reissued with `card produce --reissue`, which VOIDs its OPID. Produced cards leave the line with an
unrecorded random local PIN; personalization must set the cardholder PIN over the secure channel.

## Ledger and receipt integrity

The ledger (format 2) binds every receipt rewrite from the `issue` line on, and every failure
record, by the SHA-256 of the receipt as written. `ledger verify` requires each receipt the ledger
names to exist in the batch's `receipts/` directory and to match its last binding, so an edited
CPLC, KDD or OPID fails verification. `root audit-ledger` checks the bindings for form only; the
receipt files stay at the production station and are checked there. See
[Issuer Tool](OPENFIPS201_TOOL.md#ledger).

A receipt rewrite and its ledger line are two separate file writes. A host crash between them
leaves the receipt one rewrite ahead of its last binding, and `ledger verify` fails closed for that
receipt. The tool does not re-bind a receipt. When `ledger verify` reports a receipt that `differs
from its last ledger binding`:

1. Stop production on the batch. Do not edit the receipt or the ledger, and do not append lines by
   hand: the ledger is hash-chained and append-only.
2. Preserve the receipt, the ledger and the host logs, and record the receipt's SHA-256 and the
   last hash the ledger recorded for it.
3. Under dual control, establish the cause. A crash leaves the receipt exactly one rewrite ahead of the last bound
   version: one further stage, a failure record, or a `supersededBy` link. Treat any other
   difference as tampering. Confirm the card's state from the card (`attestation verify --from-card`) and the
   SAM's from `ledger verify --sam`.
4. Record the finding and the decision to continue or close the batch in the batch evidence. The
   batch's `ledger verify` keeps reporting that receipt; retain the record with every later
   verification result and with the archived batch.

## Issuer key lifecycle

Validate the live F9 proof before rotating management credentials. Require its signature, issuer
naming, and public point to match the configured authority and the generated proof key.

SCP rotation uses these stages:

1. Authenticate the source and inspect destination inventory.
2. Add an absent destination, or replace an existing destination only with explicit
   permission.
3. Authenticate with the destination credentials before retiring anything.
4. Inspect and delete the authenticated source version using separate SCP sessions.
5. Verify that the destination remains present and the source is absent.

These stages are separate card mutations, not one transaction. A failure stops
without automatic retries or compensating key mutations. `RotationFailure`
reports the last attempted stage and non-secret version numbers. After a failed
PUT KEY or DELETE, inspect inventory and retain both credential sets securely
until the card's state and retirement outcome are confirmed.

Destination versions are `01..7F`, per GlobalPlatform Card Specification v2.3.1
Section 11.8.2.3. Authentication selector `00` is not a destination. Restoring
reserved factory versions, including `FF`, requires a card-specific procedure.
Recovery metadata records the authenticated version and omits unsupported generic
recovery commands. Do not repeatedly try rejected SCP credentials.

## Software gates

Use JDK 17 and the pinned project dependencies:

```sh
tools/ant/bin/ant -f build/build.xml test-all
tools/ant/bin/ant -f build/build.xml coverage
tools/piv_test_runner/run-nist-vci-matrix.sh --out PRIVATE_OUTPUT_DIRECTORY
```

`test-all` runs the eight-profile matrix (Standard/FIPS × CS2/CS7 × attestation enabled/disabled),
the ZeroMQ bridge test, `test-sam` with slow tests, and `test-host` (SoftHSM custody and the
two-emulator issuance end-to-end tests; requires SoftHSM2). Assumption-aborted cases do not execute
their full assertions. Keep generated issuer material and raw tester logs in private output.

Record raw NIST tester results separately from clause assessments. The
virtual-contact runner reports policy-rejection failures for operations that
SP 800-85A-4 C.2.2.4, C.2.3.4, and C.3.1.4 require to fail. Preserve the XML,
traces, and controlling requirements; do not relabel the raw run as all-green.

## Release identity

Every attested card carries three SHA-256 values (see
[Attestation](ATTESTATION.md#build-cap-and-cplc-identity)): the leaf `buildSha256`, asserted by the
applet build, and the F9 issuance extension `capSha256` and `cplcSha256`, measured by the
production host and signed by the SAM.

For each released CAP variant, publish to relying parties through the same authenticated channel
as the trust material:

1. the SHA-256 of the CAP file (`shasum -a 256 <cap>`, equal to the receipt's `cap.sha256`);
2. `build.sha256` from its `.cap.properties`.

`card produce` refuses a CAP whose `.cap.properties` lacks `build.sha256` and a card that serves no
CPLC data, both before an OPID is burned. Produce cards only from a published CAP file.

To verify a card against a release:

```sh
ant -f build/build.xml openfips201-tool -Dargs='attestation verify --from-card \
  --target pcsc:CardReader --slot 9A --anchor root.pem --chain sam.pem \
  --expect-cap <published CAP SHA-256> --expect-build <published build.sha256>'
```

Add `--expect-cplc <SHA-256 of the card CPLC>` where the card's CPLC is recorded, or use
`--receipt <receipt.json>` at the production station. A match on `capSha256` shows that a trusted
SAM issued the card for that CAP file as reported by the production host; a match on `buildSha256`
shows that the applet signing the leaf claims that build. Neither is an on-card measurement of the
installed code.

## Issuer SAM platform gates

The emulator does not roll back persistent writes on `abortTransaction`, so SAM atomicity is tested
only with white-box ordering tests. On every SAM platform:

1. Confirm AES-256 (`KeyBuilder.LENGTH_AES_256`, `ALG_AES_BLOCK_128_CBC_NOPAD` and
   `ALG_AES_BLOCK_128_ECB_NOPAD`), ECDSA P-256 sign and verify with SHA-256,
   `Signature.signPreComputedHash`, P-256 ECDH (`ALG_EC_SVDP_DH_PLAIN`, for the transport key that
   unwraps the FF1 key), and about 1.45 KB of `CLEAR_ON_DESELECT` RAM. Installation fails without
   these algorithms.
2. Confirm `JCSystem.getMaxCommitCapacity()` of at least 512 octets; LOCK refuses less.
3. Interrupt power around ISSUE (before, during and after the commit), TOP UP, VOID, CLOSE, LOCK
   and each personalization step. After reselection the SAM must show either the old or the new event, never
   a mixture: issued count, LCG state, event sequence and chain head consistent with GET LAST
   ENTRY, and `ledger reconcile` able to recover at most one missing event.
4. Measure ISSUE and DECIPHER latency against the reader timeout.

## Card-platform gates

Before issuing production credentials on a platform:

1. Qualify its key inventory and source retirement, including interrupted add,
   destination verification, DELETE failure, reverse roll, and reserved factory
   version recovery. Inventory alone is not proof that old credentials are unusable.
2. Interrupt power around F9 generation, the F9 certificate load and the activation wipe. After
   reselection the authority must be `GENERATED` with no certificate, or complete the wipe and become
   `ACTIVE`; it must never serve a certificate while other keys or data from before activation
   remain.
3. Exercise the actual provider and transports: AES/CMAC/ECDH failure cleanup,
   CS2/CS7 establishment and replacement, command and response chaining, final
   partial receive blocks, and contact/contactless access policy. The segmented
   receive fallback supports input blocks up to 256 bytes. Measure, over contact and contactless,
   CS2 (P-256) and CS7 (P-384) secure-messaging establishment latency and the software EC
   point-validation latency (GENERAL AUTHENTICATE key agreement, OPACITY and EC public-point import)
   against the reader timeout.
4. Interrupt power around:
   - CHANGE REFERENCE DATA and RESET RETRY COUNTER (PIN or PUK update with PIN history). After
     reselection the reference data and the PIN history must both be old or both new. The retry
     counter may lie between its prior value and the maximum only after the correct value was
     presented (`OwnerPIN` counter updates are not transactional; see
     [SECURITY_NOTES.md](../SECURITY_NOTES.md#pin-and-puk-retry-counters)).
   - replacement of the secure-messaging CVC of key `04`. The card must hold the complete previous
     or the complete new CVC, and OPACITY must establish with it.
   - the Issuer SAM ISSUE, VOID and CLOSE commits (see [Issuer SAM platform
     gates](#issuer-sam-platform-gates)) and the F9 certificate load and activation (item 2).
5. Confirm that the PIV security status does not outlive the host session. The status is held in
   `CLEAR_ON_RESET` memory, so a card reset clears PIN validation; verify on the target reader and
   middleware that the card is reset (or powered down) when the issuer tool disconnects, and that a
   new session must verify the PIN again.
6. Confirm that a re-SELECT of the PIV application preserves the security status and the
   secure-messaging session (SP 800-73-5 Part
   2 Section 3.1.1, SELECT) while selecting another application and then PIV again clears it. jCardEngine
   cannot model `reSelectingApplet()`, so this is verified on hardware only.
7. Measure object write latency, EEPROM/storage use, and commit capacity with the
   largest supported face container. Check interrupted staging and publication
   using the real reader and card, not emulator transaction mocks.
8. For a certificate-free Veridt test credential, use standard/non-FIPS mode and
   a disposable identity. Qualify CCC/CHUID/UUID recognition, the actual encoded
   face file and capacity, PIN retries, and PIN-gated retrieval. Contactless VCI,
   pairing, and access policy require their own end-to-end checks.
9. Exercise a DELETE of the PIV and Issuer SAM instances that the card refuses (JCRE 3.0.5
   Section 11.3.4.2) and confirm the instance stays fully usable, and that deleting one of two
   PIV instances leaves the other usable. Each instance owns its cryptographic services and codecs,
   allocated at install, and `uninstall()` releases nothing, so a failed deletion needs no
   allocation after install. The emulator tests (`OpenFIPS201UninstallTest`,
   `IssuerSamUninstallTest`) cover this behaviour, not the platform's deletion path.

Retain card/OS/provider version, reader firmware, build profile, CAP hash,
provisioning profile, sanitized traces, and recovery outcomes with each result.
