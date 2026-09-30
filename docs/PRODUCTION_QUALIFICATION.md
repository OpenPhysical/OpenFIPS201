# Production qualification

Qualify each supported card, provider, reader, and build profile before issuing
production credentials. Software regression results and card-platform evidence
are separate release gates.

## Issuer key lifecycle

Validate the live F9 proof before rotating management credentials. Require its
signature, issuer naming, and public point to match the configured authority and
the generated proof key.

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

The eight-profile matrix is Standard/FIPS × CS2/CS7 × attestation enabled/disabled.
Assumption-aborted cases do not execute their full assertions. Keep generated
issuer material and raw tester logs in private output.

Record raw NIST tester results separately from clause assessments. The
virtual-contact runner reports policy-rejection failures for operations that
SP 800-85A-4 C.2.2.4, C.2.3.4, and C.3.1.4 require to fail. Preserve the XML,
traces, and controlling requirements; do not relabel the raw run as all-green.

## Card-platform gates

Before issuing production credentials on a platform:

1. Qualify its key inventory and source retirement, including interrupted add,
   destination verification, DELETE failure, reverse roll, and reserved factory
   version recovery. Inventory alone is not proof that old credentials are unusable.
2. Interrupt power around F9 component commit, activation intent, purge, and final
   activation. Reselection must expose either the old consistent state or an
   inactive/recoverable state, never an active mixed authority.
3. Exercise the actual provider and transports: AES/CMAC/ECDH failure cleanup,
   CS2/CS7 establishment and replacement, command and response chaining, final
   partial receive blocks, and contact/contactless access policy. The segmented
   receive fallback supports input blocks up to 256 bytes.
4. Measure object write latency, EEPROM/storage use, and commit capacity with the
   largest supported face container. Check interrupted staging and publication
   using the real reader and card, not emulator transaction mocks.
5. For a certificate-free Veridt test credential, use standard/non-FIPS mode and
   a disposable identity. Qualify CCC/CHUID/UUID recognition, the actual encoded
   face file and capacity, PIN retries, and PIN-gated retrieval. Contactless VCI,
   pairing, and access policy require their own end-to-end checks.

Retain card/OS/provider version, reader firmware, build profile, CAP hash,
provisioning profile, sanitized traces, and recovery outcomes with each result.
