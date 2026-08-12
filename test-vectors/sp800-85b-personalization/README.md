# SP 800-85B personalisation input

This corpus freezes the published, non-sensitive metadata for **NIST Test PIV Card 1** from
NISTIR 8347 Version 2, Appendix C.1. The values are inputs to an issuer personalisation run and to
the operator prompts of the external PIV Data Model Tester.

Run `sh tools/export-sp80085b-corpus.sh [output-directory]`. The export is deterministic and
contains the normalized input, the tester manifest, and SHA-256 checksums.

The corpus deliberately does not fabricate card objects. SP 800-85B Sections 2.4.2 through 2.4.4
require valid CMS, CBEFF/biometric, and certificate-profile content. Those finished objects must be
produced by the external issuer system and captured from the personalised card. OpenFIPS201 stores
and retrieves them; it does not construct CMS or CBEFF data on card.

Sources:

- NISTIR 8347 Version 2, Table 1, Table 2, and Appendix C.1.
- NIST SP 800-85B, Sections 2.2 through 2.4 and test areas 8 through 11.
- NIST SP 800-73-5 Part 1, PIV data-object identifiers and data model.
