# `pkg/report` test fixtures

## `sarif-schema-2.1.0.json`

The official SARIF 2.1.0 JSON schema, vendored so the emitter can be validated
**offline** — skill-guard's determinism principle means the test suite must not
need the network, in CI or in an air-gapped review.

| | |
|---|---|
| Source | `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json` |
| Retrieved | 2026-08-26 |
| Spec | SARIF 2.1.0 (OASIS), JSON Schema draft-04 |
| Size | 112,768 bytes |

Refresh it by re-downloading from that URL and updating this table. Only
`sarif_schema_test.go` reads it; nothing in the binary does.

## `golden/`

Pinned emitter output. `golden/synthetic.sarif` is rendered from a **hand-built
report**, not from scanning a fixture, so it pins the wire format without
churning every time a rule pack changes. `golden/benign.sarif` is a real scan of
`testdata/benign`, which has no findings and is therefore stable too.

Regenerate after an intended format change:

```sh
go test ./pkg/report/ -run TestSARIFGolden -update
```
