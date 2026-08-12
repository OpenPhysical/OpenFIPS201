# GSA ICAM Card Builder Test Material

This directory contains these complete positive card folders from
the U.S. General Services Administration's `gsa-icam-card-builder` repository.

- `01_Golden_PIV`
- `02_Golden_PIV-I`
- `37_Golden_FIPS_201-2_PIV_PPS_F=512_D=64`
- `39_Golden_FIPS_201-2_Fed_PIV-I`
- `46_Golden_FIPS_201-2_PIV`
- `47_Golden_FIPS_201-2_PIV_SAN_Order`
- `54_Golden_FIPS_201-2_NFI_PIV-I`

It also contains these official negative profiles:

- `03_SKID_Mismatch`
- `04_Tampered_CHUID`
- `05_Tampered_Certificates`
- `06_Tampered_PHOTO`
- `07_Tampered_Fingerprints`
- `08_Tampered_Security_Object`
- `23_Public_Private_Key_mismatch`
- `38_Bad_Hash_in_Sec_Object`
- `55_FIPS_201-2_Missing_Security_Object`

- Source: `https://github.com/GSA/gsa-icam-card-builder`
- Source commit: `6d5a872547b96c48dff7fc7c14ae1d205438ae38`
- Retrieved: 2026-08-11
- License: CC0 / U.S. public domain, reproduced in `LICENSE.md` and `LICENSE.txt`

These are official FIPS 201 / PIV-I interoperability images and are kept byte-for-byte for GSA
compatibility testing. Their legacy fields must not be treated as a native SP 800-73-5
personalization profile.
