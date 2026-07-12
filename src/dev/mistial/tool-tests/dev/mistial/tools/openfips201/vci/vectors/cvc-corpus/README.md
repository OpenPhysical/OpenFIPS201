# VCI CVC Corpus

This folder preserves secure messaging CVC objects extracted from VCI JSON
captures from NIST test cards.

Each subdirectory contains:

- `source-vector.json`: original NIST test-card VCI vector JSON.
- `secure-messaging-cvc-7f21.bin`: the exact CVC from `opacity.cvc_raw`.
- `metadata.json`: parsed CVC fields useful for quick review.

These entries are a CVC parsing/interoperability corpus. They do not all include the `5FC122` Secure Messaging Certificate Signer object or content-signing certificate needed for full trust-anchor validation. Regenerate the corpus with:

```bash
scripts/import_vci_vector_fixtures.py
```
