# OMS conformance vectors

The OpenSSF Model Signing v1.0 test vectors, vendored so cross-verification is
an ordinary offline `go test` — no second toolchain in CI, no network.

| | |
|---|---|
| Source | `https://github.com/ossf/model-signing-spec/tree/main/test-vectors/v1.0` |
| Commit | `a0c91e2c930298efb8e8445bf475e4fa217d89cd` |
| Retrieved | 2026-08-26 |
| Spec | OMS v1.0 (`spec/v1.0.md`) |

- `vectors/valid/` — one bundle per signing method (`key`, `certificate`,
  `sigstore`). These are produced by the reference implementation, so parsing
  them is a genuine interop check rather than a test of our own output.
- `vectors/invalid/` — structurally broken bundles that must be rejected.
- `vectors/invalid-payload/` — a bundle whose statement carries the wrong
  predicate type.

Refresh by re-downloading from that path and updating the commit above. If a
vector stops parsing after a refresh, that is a real signal about a spec change,
not a test to relax.
