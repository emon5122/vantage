# Versioning & migration analysis

Module: [`vantage.kb.versions`](../../src/vantage/kb/versions.py)

The knowledge base is **multi-version**: every fact is scoped to the target
application version it was observed in. This lets the framework track how a
protocol and its managed surface evolve across releases.

## What is versioned

`commands`, `packets`, `schemas`, `classes`, `strings`, and `assets` all carry a
`version` column. Importing captures/artifacts under a new `--version` creates a
parallel view; existing versions are untouched.

## Diffing two versions

`versions.diff(db, v1, v2)` computes:

- **new / removed opcodes** (commands present in one version but not the other)
- **schema changes** per shared command: added fields, removed fields, and
  fields whose type set changed (`retyped`)
- **new / removed classes**
- **new endpoints** (host-like recovered strings)

`versions.migration_report_md(diff)` renders a human-readable migration report,
and the CLI exposes it as `vantage kb diff <v1> <v2> --out report.md`.

## Example (from the test suite)

Importing a v2 capture where the `login` command gained a field and a new command
appeared yields:

```
new_opcodes:      1   (method:newcmd)
changed_schemas:  1   (method:login: added #9)
```

This is exercised by
[`tests/test_versions_and_search.py`](../../tests/test_versions_and_search.py).

## Semantic versioning of the framework itself

Vantage follows [SemVer](https://semver.org). The public surface is the CLI, the
`vantage.*` Python API, the on-disk artifact formats, and the SQLite schema. The
KB schema carries a `schema_version` in its `meta` table to support forward
migrations. See [`CHANGELOG.md`](../../CHANGELOG.md).
