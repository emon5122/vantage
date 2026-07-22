# Knowledge base & knowledge graph

Package: [`vantage.kb`](../../src/vantage/kb/)

The knowledge base is a single-file SQLite store that turns a stream of
observations into a **versioned, deduplicated, cross-linked knowledge graph** of
a target's protocol and managed type system.

## Why SQLite

- Zero operational overhead; a database is a portable file.
- Transactional and crash-safe (WAL); indexes + a large page cache scale to
  millions of observations.
- Trivially inspectable with any SQLite client and queryable with plain SQL.

## Schema overview

Defined in [`kb/schema.sql`](../../src/vantage/kb/schema.sql). Key tables:

| Table | Purpose | Dedup key |
|---|---|---|
| `sessions` | one imported capture directory | `source_dir` + `content_hash` |
| `connections` | per-socket peer / lifetime | `session,fd,open_ts` |
| `commands` | learned opcodes/methods | `version,command_key` |
| `packets` | **deduplicated** packet knowledge | `fingerprint` = `version\|command\|dir\|mtype\|shape` |
| `schemas` / `schema_fields` | merged per-command schema | `command_id` / `schema_id,field` |
| `requests` / `responses` | sampled correlated instances (timing) | — |
| `classes` / `methods` | recovered managed types | `version,assembly,ns,name` |
| `gameplay_actions` | labelled captures | `label,session` |
| `confidence_history` | append-only provenance | — |
| `relationships` | generic graph edges | `src,dst,relation` |

## The knowledge graph

`relationships` is a typed edge table connecting any two entities:

```
action  --observed_during-->  command
command --serialized_by---->  class
command --describes-------->  schema
```

Traversing these edges answers questions like *"which classes serialize the
commands seen during a given gameplay action?"* without bespoke joins per query.

## Scaling strategy

Raw frames never bloat the store. Millions of identical heartbeats collapse into
**one** `packets` row whose `obs_count` increments; the table is bounded by the
number of distinct payload *shapes*, not the number of frames. Timing detail is
preserved via a bounded sample of `requests`/`responses` per command per session.

See [performance-and-scalability.md](../performance-and-scalability.md) for the
numbers and the sharding path beyond a single file.

## Idempotent, incremental import

Re-importing an unchanged capture directory is a **no-op** (content-hash gate),
so the incremental updater can sweep a captures tree repeatedly / on a schedule
and only new observations enrich the graph. This property is tested in
[`tests/test_kb.py`](../../tests/test_kb.py).
