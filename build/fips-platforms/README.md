# FIPS platform descriptors

`compile-fips` requires a descriptor for the exact Java Card platform that will host the CAP:

```sh
tools/ant/bin/ant -f build/build.xml compile-fips -Dfips.platform=vendor-product-version
```

Each release properties file identifies the exact platform and records its module validation,
entropy, and CAP-integrity evidence. `test-jcard.properties` is the simulator descriptor used by the
CI matrix.

The descriptor also supplies `fips.platform.tag-bytes`, the ASCII platform ID encoded as
comma-separated Java byte literals. The build embeds these bytes in the CAP status response.
