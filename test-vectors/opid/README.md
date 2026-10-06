# OPID test vectors (layout v2)

Every file carries `"schema":"openphysical.opid-vectors/2"`. The vectors are shared by the host
tool (`dev.mistial.tools.openfips201.opid`), the Issuer SAM, the PIV applet and OpenPhysical.Net.
They were produced by an independent Python reference (FF1 per SP 800-38G Algorithms 7 and 8,
verified against all nine NIST FF1 samples) and are re-derived field by field by the Java tests in
`src/dev/mistial/tool-tests/dev/mistial/tools/openfips201/opid/`. Layout v2 replaces every
format-coded OPID; 18-digit and other v1 OPIDs are invalid.

## OPID

```
OPID = IIII ‖ E ‖ L                      17 decimal digits; canonical form has no separators
  IIII  IIN, 4 digits, plaintext
  E     FF1_K(B ‖ X, ASCII(IIII)), 12 digits
          B = batch number (4 digits), X = x_n (8 digits, LCG state after the n-th advance)
          K = AES-256 key, one per IIN; FF1 radix 10, n = 12 (u = v = 6), no cycle-walking
  L     Luhn digit over the 16 typed digits IIII ‖ E
Display grouping: IIII EEEE EEEE EEEEL (4-4-4-5), display only. The E digits are FF1 ciphertext, not a readable batch or CIN.
```

- FF1 applies **only** to `B ‖ X`. The IIN is always plaintext and enters FF1 only as the tweak.
- L is computed over the digits the user types, `IIII ‖ E`; never over the plaintext batch or
  LCG state.
- Uniqueness: batch numbers are unique per IIN and each batch LCG has full period, so `(B, X)` is
  unique per IIN; FF1 permutes `[0, 10^12)`, so every OPID is unique per IIN.

## Derived identifiers (D = the 17 digits)

- GUID (CHUID tag 34): RFC 9562 UUIDv8, big-endian bytes, hex
  `D[0..8] ‖ D[8..12] ‖ "8" ‖ D[12..15] ‖ "8" ‖ "0" ‖ D[15..17] ‖ "4F504E504859"`
  (string `DDDDDDDD-DDDD-8DDD-80DD-4F504E504859`).
- `uuidOid` = `2.25.` + the GUID as an unsigned 128-bit integer.
- CCC card identifier: `F0 15 ‖ 00 00 00 00 ‖ ASCII(D)` (23 bytes).
- FASC-N (CHUID tag 30): agency 9999, system 9999, credential 999999, CS = E[2], ICI = E[3],
  PI = E[0] E[1] E[4..12], OC = 3, OI = IIN, POA = 6 (organizational affiliate, fixed). A CHUID
  whose FASC-N carries any other POA does not match the OPID.

## LCG

`f(x) = (a·x + c) mod 10^8`, exact integer arithmetic. Hull–Dobell: `1 <= c < m`, `gcd(c, 10) = 1`,
`1 < a < m`, `a ≡ 1 (mod 20)`, `0 <= x0 < m`. Issuance number `n >= 1` has `x_n = f^n(x0)`.

Jump maps `M_j = f^(10^(j-1))`, j = 1..8, as affine pairs `(A_j, C_j)` mod 10^8 with
`M_1 = (a, c)` and `M_(j+1) = M_j^10`.

Index recovery (the SAM DECIPHER algorithm): `y = x0, n = 0`; for j = 1..8, for t = 0..9: if
`y mod 10^j == X mod 10^j` record `n += t·10^(j-1)` and go to the next j, else `y = M_j(y)`. The
result satisfies `f^n(x0) = X`, `0 <= n < 10^8`; n = 0 means X = x0, which is never issued.

## Digests

`fpeKcv = SHA-256("OPSAMFPEKCV1" ‖ AES-256-ECB_K(0^16))[0..16)`.

`paramsDigest = SHA-256("OPSAMPRM3" ‖ IIN digits(4) ‖ batch digits(4) ‖ a digits(8) ‖ c digits(8) ‖
x0 digits(8) ‖ initialQuota(u32 BE) ‖ initialTs(u64 BE) ‖ fpeKcv(16))`, a 69-byte preimage. Each
digit is one byte 0..9; IIN and batch digits most-significant first, a, c and x0
least-significant first. `initialQuota <= 10^8`. The FF1 key never enters the digest. This is the
only parameters digest.

## Files

| File | Contents |
|---|---|
| `luhn.json` | `vectors[]`: `{payload, check}`. |
| `opid-valid.json` | `vectors[]`: `{case, printed, display, iin, e, check, guid, guidBytesHex, uuidOid, poa, fascnHex, cccHex}`; `poa` is always 6. |
| `opid-invalid.json` | `vectors[]`: `{input, reason}` strings both parsers reject (bad Luhn, wrong length including v1 format OPIDs, non-digits). `fields[]`: `{iin, e, reason}` that `Opid.of` rejects. `chuidPoa[]`: FASC-N POA values other than 6, which the CHUID check rejects. |
| `lcg.json` | `vectors[]`: `{cinDigits, a, c, x0, first20, at1000, period, jumpMaps, indexRecovery}` with `first20[i] = x_(i+1)`, `jumpMaps[j-1] = [A_j, C_j]` and `indexRecovery[] = {n, x}`. Entries with `cinDigits < 8` exist for exhaustive tests only. `rejected[]`: `{a, c, x0, reason}` for m = 10^8. |
| `fpe.json` | `nistFf1[]`: SP 800-38G FF1 radix-10 samples 1, 2, 4, 5, 7, 8. `kcv[]`: `{keyHex, aesZeroBlockHex, kcvHex}`. `ff1[]`: 12-digit `{keyHex, iin, tweakHex, plaintext, enciphered}`. `sequences[]`: `{iin, batch, a, c, x0, keyHex, tweakHex, issuance[] = {n, x, plaintext, e, opid}}`. `decipher`: one SAM batch `{iin, batch, a, c, x0, keyHex, issued, jumpMaps, cases[] = {opid, note, batch, sameBatch, count?, issuedFlag?}, rejected[] = {opid, reason, sw}}`. `paramsDigestV3[]`: `{iin, batch, a, c, x0, initialQuota, initialTs, keyHex, fpeKcvHex, preimageHex, sha256}`. |
| `fascn-codec.json` | `vectors[]`: decoded FASC-N fields per hex value (the first five are the OpenPhysical.Net `FascNCodecTest` values). `invalid[]`: `{hex, reason}` the strict decoder rejects. |
