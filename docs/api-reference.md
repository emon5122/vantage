# API reference

The public Python API lives under `vantage.*`. Import with `src/` on the path
(`pip install -e .` or `PYTHONPATH=src`). Every function is observation-only.

Conventions: **Inputs** and **Outputs** describe the primary contract; **Fails**
lists the notable failure modes; **Extend** notes where to plug in.

---

## `vantage.protocol.msgpack`

- **Purpose** — dependency-free MessagePack decoder + type-annotator.
- `decode(buf, offset=0) -> (value, type_node, consumed)`
  - Inputs: `bytes`, start offset. Outputs: decoded value, a type tree for schema
    inference, bytes consumed.
  - Fails: `MsgpackError` on truncated/invalid input.
- `to_jsonable(obj) -> obj` — normalise int map keys to `#n` for JSON.
- **Extend** — register alternative decoders via the `serialization` plugin seam.

## `vantage.protocol.fpnn`

- **Purpose** — FPNN frame parsing + TCP-stream reassembly.
- `parse_message(buf, off=0, decode_payload=True) -> (record, consumed)`
- `iter_stream(buf, off=0) -> yields (record, start, end)` — splits a reassembled
  stream; yields `{"desync_skipped": n}` markers on resync; stops at the first
  incomplete frame (returns leftover offset to the caller).
- **Fails** — `FpnnParseError` on bad magic (caller resynchronises).

## `vantage.protocol.correlate`

- `load_frames(path) -> list` — read `frames.jsonl`.
- `correlate(frames, timeout_s=15) -> {stats, pairs, pushes, unanswered, heartbeats, retries}`.

## `vantage.protocol.schema`

- `command_key(frame) -> str` — `method:<name>` or `op:<n>` grouping key.
- `infer(frames, min_samples=3) -> {command_key: schema}` — per-command schema
  with per-field and overall confidence.

## `vantage.protocol.build`

- `build(capture_dirs, out_dir, target="unknown") -> summary` — writes
  `protocol.json`, `opcode_map.json`, `request_map.json`, `schemas/*.json`,
  `confidence_report.json`.

## `vantage.metadata.classifier`

- `score_one(assembly, ns, name) -> {role, confidence, tier, categories, reasons}`
  — classify one managed class; third-party TLS/crypto internals are bucketed to
  `TlsCryptoInternal`.
- **Extend** — add categories/keywords via the `classifier` plugin seam.

## `vantage.kb.db`

- `open_db(path) -> DB` — create/migrate a knowledge base.
- `DB.q/q1/ex` — read/execute; `DB.bump_confidence(...)` — update + journal a
  score; `DB.add_relationship(...)` — add a graph edge.

## `vantage.kb.importer`

- `import_path(db, path, version, label=None) -> (kind, result)` — auto-detect and
  ingest any supported artifact.
- `import_capture / import_classes_ranked / import_types / import_protocol /
  import_events` — type-specific importers with dedup/merge.
- **Fails** — `ValueError` on an unrecognised path.

## `vantage.kb.search`

- `packets_during_action`, `cmdid_for_category`, `packets_using_field`,
  `classes_serializing`, `command_detail`, and `run_sql` (single read-only
  `SELECT` only; anything else raises `ValueError`).

## `vantage.kb.versions`

- `diff(db, v1, v2) -> {new_opcodes, removed_opcodes, schema_changes,
  new_classes, removed_classes, new_endpoints, summary}`.
- `migration_report_md(diff) -> str`.

## `vantage.kb.docgen` / `graphs` / `viewer`

- `docgen.regenerate(db, outdir, version) -> [doc names]`.
- `graphs.write_all(db, outdir, version) -> [file names]` — Mermaid + Graphviz.
- `viewer.build(db, outdir, version=None) -> index.html` — self-contained HTML;
  `viewer.serve(dir, port)` — local static server.

## `vantage.plugins`

- `discover() -> [metadata]`, `load(registry=None) -> Registry`.
- `Registry.add_serialization/add_classifier_rule/add_kb_importer`.

## CLI (`vantage.cli`)

`main(argv) -> int`. Subcommands: `version`, `kb`, `protocol {build,synth}`,
`classify`, `instrument {process,recover,capture,analyze}`, `plugins`.
