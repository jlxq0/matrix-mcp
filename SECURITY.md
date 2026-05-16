# Security

## Reporting

Please don't open a public issue. Email **julian@lindner.earth** with:

- what the issue is
- a minimal reproduction
- the version you tested (`git describe --tags` or the image tag)
- which trust boundary is affected (see [THREAT_MODEL.md](THREAT_MODEL.md))

I'll reply when I can. This is a one-person project, so don't expect a
24-hour SLA – but I do read every report.

## Out of scope

- Anything that requires the homeserver, MAS, or 1Password Connect to
  already be compromised. Those are trusted by design.
- Bugs in upstream dependencies (`matrix-rust-sdk`, MAS, Synapse,
  `rmcp`). Report those upstream and CC me if matrix-mcp's behaviour
  amplifies them.
- A malicious matrix-mcp operator. Run your own – this isn't a hosted
  service.

## Cryptographic primitives

`matrix-rust-sdk` does the olm/megolm/cross-signing work. If you find
an issue in those primitives, please report to the
[matrix-rust-sdk security team](https://github.com/matrix-org/matrix-rust-sdk/security)
first.

To verify a given matrix-mcp device is properly cross-signed on your
homeserver, run
[`scripts/verify-device-signature.py`](scripts/verify-device-signature.py).
