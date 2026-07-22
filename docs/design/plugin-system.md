# Plugin system

Package: [`vantage.plugins`](../../src/vantage/plugins/__init__.py)

Vantage is extensible along three **observation-only** seams. Plugins add the
ability to *understand* more of what is observed; they never add the ability to
*act on* a target.

| Seam | Extends | Example |
|---|---|---|
| `serialization` | payload decoders | add Protobuf/FlatBuffers/custom-TLV decoding |
| `classifier` | managed-class categorisation | teach the classifier a project-specific subsystem |
| `kb_importer` | knowledge-base ingest | register a new artifact type |

## Authoring a plugin

A plugin is any importable module exposing a `PLUGIN` dict and a `register`
callable:

```python
PLUGIN = {"name": "protobuf-decoder", "description": "...", "version": "1.0.0",
          "observation_only": True}

def register(registry):
    registry.add_serialization("protobuf", decode_protobuf)   # decode_protobuf(bytes) -> dict
```

See [`plugins/example_classifier_rules.py`](../../plugins/example_classifier_rules.py)
for a complete, working example.

## Discovery

Plugins are discovered from two sources:

1. The `vantage.plugins` **entry-point group** (for pip-installed plugins).
2. Any `*.py` under **`$VANTAGE_PLUGINS_DIR`** (defaults to `./plugins`).

`vantage plugins list` enumerates discovered plugins. `vantage.plugins.load()`
registers them into a `Registry`.

## Contract

- Decoders and importers **read** bytes/artifacts; they must not emit, mutate, or
  replay traffic, and must not write target memory.
- Plugins run in the host process, not in the target — they never touch the
  device.
- CI and `CONTRIBUTING.md` reject plugins that add offensive capability.
