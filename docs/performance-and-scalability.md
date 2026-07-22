# Performance & scalability

## Design targets

- Ingest **millions of captured frames** without unbounded database growth.
- Keep the offline pipeline dependency-free and fast enough to run in CI.
- Regenerate docs + viewer in seconds on a laptop-class machine.

## How scale is achieved

### Packet fingerprint deduplication

Raw frames are never stored one-per-row. Each frame collapses into a `packets`
row keyed by a **fingerprint** (`version | command | direction | mtype | shape`),
with an `obs_count`. The table is bounded by the number of distinct payload
*shapes*, not the number of frames — so a million identical heartbeats become one
row with `obs_count = 1_000_000`.

### Bounded samples for timing

`requests`/`responses` retain a capped sample per command per session
(`SAMPLE_CAP`), enough for RTT/heartbeat statistics without storing every
instance.

### SQLite tuning

`kb/db.py` enables:

- `PRAGMA journal_mode=WAL` — concurrent readers, durable writes.
- `PRAGMA synchronous=NORMAL` — fast, crash-safe under WAL.
- `PRAGMA cache_size=-64000` — ~64 MB page cache.
- indexes on hot columns (`commands.category/opcode/request_cmd_id`,
  `packets.command_id`, `schema_fields.field`, `classes.role/name`,
  `relationships.src/dst`).

### Streaming import

`frames.jsonl` is read line-by-line; imports run inside a single transaction and
commit once per session, amortising write cost.

## Complexity

| Operation | Cost |
|---|---|
| Import a session of *F* frames | O(F) with O(1) amortised upserts |
| Packet dedup | O(1) hash lookup per frame |
| Schema merge | O(distinct fields) per command per session |
| Version diff | O(commands + fields + classes) for the two versions |
| Search (canned) | index-backed; sub-linear on the hot paths |

## Beyond a single file

For fleets of captures or continuous ingestion:

- **Shard by version or target** into separate `.db` files; the version-diff
  engine already operates across versions and can operate across attached
  databases.
- **Batch imports** with the incremental updater (idempotent, so parallel workers
  can retry safely).
- The schema is portable to server-grade engines (PostgreSQL) with minimal
  changes should a shared, concurrent store be required — the ORM-free SQL is
  intentionally standard.

## Benchmark harness

The synthetic generator (`vantage.protocol.synthetic`) can emit arbitrarily many
sessions for load testing; the test suite runs the full offline pipeline in well
under a second.
