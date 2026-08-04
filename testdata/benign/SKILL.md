---
name: pdf-table-extractor
description: Extracts tables from PDF files and outputs them as CSV. Use when the user asks to pull tabular data out of a PDF.
license: Apache-2.0
allowed-tools:
  - Bash(pdftotext:*)
  - Read
---

# PDF Table Extractor

This skill converts tables inside a PDF into CSV.

## Usage

Run `pdftotext -layout input.pdf -` and parse the whitespace-aligned columns.
Ignore blank lines and comment rows when parsing.

## Notes

- Prefer parameterized parsing over string concatenation.
- Type-check the helper with `npx tsc --noEmit` (a pinned local dev tool).
- See the docs at https://example.com/pdf-guide for column heuristics.
- Layout reference: ![column diagram](./docs/columns.png) and the
  [parser guide](https://example.com/pdf-guide?section=columns).
- Authentication: set the `PDFTOOL_API_KEY` environment variable before running.
  Never add that key to the query string of an outbound request.
- Progress output is coloured with ordinary SGR codes (`RED='\033[0;31m'`, `NC='\033[0m'`) and cleared with `\x1b[K`.
- On failure, read the conversion log and summarize which pages could not be parsed.
- Release archives are plain: `unzip release.zip -d ./dist`, then check the
  detached signature with `gpg --verify release.sig release.tar.gz` and the
  checksum with `openssl dgst -sha256 dist/pdftool`.
- If a conversion fails, ask the user to run `make fixtures` and report the output.
- Repo hygiene checks are read-only: `cat .git/HEAD`, `tail -5 .git/logs/HEAD`,
  and `rm -f .git/index.lock` if a previous run was interrupted.
