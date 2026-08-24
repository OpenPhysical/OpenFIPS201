# VCI conformance assessment

`run-nist-vci-matrix.sh` assesses each VCI result against the controlling
requirement. It retains the test XML and logs as evidence and writes the
normative result to `summary.tsv`.

## Clause mapping

### Change reference data for the PUK

[SP 800-85A-4, C.2.2.4](https://doi.org/10.6028/NIST.SP.800-85A-4)
defines the virtual-contact scenario as C.2.2.1 **excluding step 3, the PUK
tests**. The controlling text says, "with the exception of ... step 3 (PUK
tests)." [SP 800-73-5 Part 2,
Section 3.2.2](https://doi.org/10.6028/NIST.SP.800-73pt2-5) requires a command
for key reference `81` to fail when it is not submitted over the contact
interface. Section 3.2.2 does not mandate a status word for this case.
OpenFIPS201 returns protected status `6A81`, and the release gate checks that
documented implementation behavior.

### Reset retry counter

SP 800-85A-4 C.2.3.4 states that RESET RETRY COUNTER cannot be issued through
VCI and that steps 2 and 5 "return an error status word." SP 800-73-5 Part 2,
Table 2 marks RESET RETRY COUNTER as contactless `No` and requires `6A81` for
commands in that category.

### Put data

SP 800-85A-4 C.3.1.4 requires each PUT DATA attempt to "return an error status
word." SP 800-73-5 Part 2, Table 2 marks PUT DATA as contactless `No` and
requires `6A81` unless qualifying contactless card management is enabled. The
FIPS profile does not enable that exception.

The applet authenticates and decrypts the complete logical command before it
returns protected status `6A81`. A bounded parser handles a secure-messaging
field that spans APDUs and retains no rejected plaintext.

## Release rule

The runner XML and clause assessment are reported separately:

- Secure messaging reports seven tests and zero failures for each suite.
- Virtual contact reports seven tests and three runner failures for each suite:
  `ChangeReferenceDataCommand:4`, `ResetRetryCounterCommand:4`, and
  `PutDataCommand:4`.
- The clause assessment accepts those three results only when the response is
  the expected protected rejection. This produces seven accepted results for
  each suite without rewriting the retained runner XML.

The release gate requires protected status `6A81` for the documented PUK
behavior and for every mapped RESET RETRY COUNTER and PUT DATA result. No test
result may be missing, changed, or added.

The gate exits nonzero if the runner counts, exact test names, protected
statuses, or clause assessment differ from this record.
