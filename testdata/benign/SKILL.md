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
- See the docs at https://example.com/pdf-guide for column heuristics.
