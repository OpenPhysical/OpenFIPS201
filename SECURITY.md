# Security Policy

## Supported versions

Until this fork publishes a versioned release, security fixes are made against
the current `master` branch only. Older commits, development branches, and
upstream OpenFIPS201 releases are not supported by this fork.

## Reporting a vulnerability

Email [security@mistial.dev](mailto:security@mistial.dev) with the subject:

```text
[OpenFIPS201 Security] Brief description
```

Please do not open a public issue, pull request, or discussion before we have
had a reasonable opportunity to investigate and release a fix.

Include as much of the following as is available:

- The affected commit, version, and build profile.
- The Java Card platform, reader, and host environment, when relevant.
- A concise impact assessment and the conditions required to reproduce it.
- Reproduction steps, APDU transcripts, logs, or a minimal test case.
- Any suggested remediation and whether you want public credit.

Do not send live management keys, PINs, PUKs, private keys, personal identity
data, or biometric data. Use test cards and synthetic data. If a report needs
other sensitive material, send a minimal first message and request an encrypted
channel before sharing it.

## What to expect

Our response targets are:

- Acknowledgement within five business days.
- An initial assessment or status update within ten business days.
- An update at least every fourteen days while an accepted report remains open.

These are targets, not guarantees. Hardware-specific behavior, external
validation, and coordination with upstream projects or vendors may require more
time.

We will validate the report, assess its impact, and coordinate a remediation
and disclosure timeline with the reporter. When appropriate, we will publish a
security advisory, request a CVE, and credit the reporter. This project does not
currently offer a bug bounty.

## Scope

This policy covers vulnerabilities in this repository's:

- Java Card applet and cryptographic protocol handling.
- Provisioning, administration, secure-channel, VCI, and attestation tools.
- Build, test, packaging, and release processes when they affect artifact
  security or integrity.

The following are generally outside scope:

- Defects that exist only in an upstream project or third-party dependency.
- Unsupported cards, readers, operating systems, or historical revisions.
- Previously documented certification gaps without a distinct security impact.
- Unvalidated automated scanner output.
- Social engineering, denial of service against maintainers, or testing that
  risks other people's systems or data.

Please still contact us if an upstream or dependency vulnerability is
exploitable through this project. We may need to mitigate it here while also
coordinating with its maintainer.

## Safe harbor

We consider security research conducted under this policy to be authorized when
you act in good faith, comply with applicable law, test only systems and cards
you own or are authorized to test, avoid privacy violations and unnecessary
disruption, and access only the data needed to demonstrate the issue.

We will not initiate legal action against researchers for accidental,
good-faith violations of this policy. If you are unsure whether planned testing
is covered, contact us before proceeding.

## Related documentation

[`SECURITY_NOTES.md`](SECURITY_NOTES.md) contains technical security notes for
the implementation. Conformance and validation status is documented separately
in the repository's test and certification documentation.
