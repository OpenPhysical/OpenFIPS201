# FIPS platform descriptors

`compile-fips` requires a descriptor for the exact Java Card platform that will host the CAP:

```sh
tools/ant/bin/ant -f build/build.xml compile-fips -Dfips.platform=vendor-product-version
```

Each properties file must identify the platform and cite the module validation, entropy, and CAP
integrity evidence on which the applet's FIPS boundary depends. Do not copy the test descriptor for
release artifacts. A FIPS candidate CAP is not itself a validation claim.

The descriptor also supplies `fips.platform.tag-bytes`, the ASCII platform ID encoded as
comma-separated Java byte literals. The build embeds these bytes in the CAP status response.
