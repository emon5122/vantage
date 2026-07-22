# Runtime instrumentation

Packages: [`vantage.instrument`](../../src/vantage/instrument/) (Python launchers)
and [`vantage/agent`](../../src/vantage/agent/) (Frida JavaScript).

The instrumentation layer attaches to a running Unity IL2CPP process with Frida
and installs **read-only** hooks. Every hook reads arguments/return values and
lets the original call proceed unchanged. There is no `Interceptor.replace`, no
memory write, and no traffic modification anywhere in the agent.

> **Optional dependency.** Frida is an optional extra (`pip install
> 'vantage-il2cpp[instrument]'`). The rest of the framework — analysis, knowledge
> base, docs — runs without it and without a device.

## Agent structure

```
agent/
├── bootstrap.js         orchestrates enabled hook modules in dependency order
├── core/                logger (throttled JSON events) · utils · state · event bus
├── hooks/
│   ├── process.js       Unity version, loaded libs + load order, dlopen, JNI_OnLoad, RegisterNatives
│   ├── il2cpp_api.js    locate + hook the IL2CPP read-only API
│   ├── metadata.js      open/openat/fopen/AAssetManager_open/read/mmap of the metadata file
│   ├── decrypt_observer.js   detect when in-memory metadata becomes plaintext (opt-in)
│   ├── network.js       connect/send/recv/DNS/SSL — hosts, ports, sizes (no modification)
│   ├── requests.js      per-request records + heuristic classification
│   ├── assets.js        AssetBundle file/API observation
│   ├── strings.js       il2cpp_string_new keyword capture (runtime endpoint recovery)
│   ├── lua.js           Lua VM / loadbuffer / pcall observation
│   ├── metadata_recovery.js  drive the IL2CPP type-system walk
│   └── fpnn_capture.js  raw FPNN frame capture off the socket layer
└── il2cpp/              api_defs · api_locator · traverse · classify · correlate · regscan
```

## Launchers

| CLI | Module | Purpose |
|---|---|---|
| `vantage instrument process` | `instrument/process.py` | general observation session → `events.jsonl` |
| `vantage instrument recover` | `instrument/il2cpp.py` | IL2CPP metadata recovery → `metadata.json` |
| `vantage instrument capture` | `instrument/capture.py` | FPNN frame capture → `frames.jsonl` |
| `vantage instrument analyze` | `instrument/analyze.py` | reduce a session to a report |

The host builds the agent by concatenating the JS modules (each an independent
IIFE), injects the JSON config as a global, attaches/spawns the process, and
streams structured events to timestamped logs.

## Failure modes & degradation

- **Frida absent** — launchers exit with a clear message; offline tooling is
  unaffected.
- **Hardened target detects Frida** — the framework does **not** evade detection;
  a session may be terminated. This is logged (`session detached`) and is the
  correct, in-scope behaviour.
- **Stripped IL2CPP exports** — the API locator degrades to offsets/opt-in probe;
  see [metadata-recovery.md](metadata-recovery.md).

## Safety review checklist (enforced in `CONTRIBUTING.md`)

- [ ] no `Interceptor.replace` / trampolines that alter behaviour
- [ ] no `Memory.write*`, `Memory.protect(..., 'rwx')` writes, or patch bytes
- [ ] no `send()` that carries a command to alter the target
- [ ] socket hooks read only; buffers are never modified before the real call
