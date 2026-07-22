# Architecture

Vantage is a layered, observation-only framework for analysing Unity **IL2CPP**
applications on Android. Each layer produces structured artifacts that the next
layer consumes; nothing in the pipeline transmits, injects, replays, or modifies
target state.

## Design in one sentence

> Read what the runtime has already decrypted, decoded, or connected — never make
> the target do anything it would not do on its own — and turn each authorised
> observation into permanent, evidence-graded, queryable knowledge.

---

## Module architecture

```mermaid
flowchart TB
  subgraph agent["Frida agent (JavaScript, in-process, read-only)"]
    core["core/ — logger · utils · state · bus"]
    hooks["hooks/ — process · network · metadata · strings · lua · assets · requests"]
    il2cppjs["il2cpp/ — api_locator · traverse · classify · regscan"]
  end
  subgraph py["Python framework (src/vantage)"]
    instrument["instrument/ — process · il2cpp · capture · analyze"]
    protocol["protocol/ — msgpack · fpnn · correlate · schema · build"]
    metadata["metadata/ — classifier · inventory"]
    kb["kb/ — db · confidence · importer · search · versions · graphs · docgen · viewer"]
    plugins["plugins/ — serialization · classifier · kb_importer seams"]
    cli["cli — unified entry point"]
  end
  hooks -- structured JSON events --> instrument
  il2cppjs -- type records --> instrument
  instrument -- frames / metadata / logs --> protocol
  instrument -- class inventory --> metadata
  protocol -- protocol.json / schemas --> kb
  metadata -- ranked classes --> kb
  kb --> docgen["docs + HTML viewer"]
  plugins -.extends.-> protocol
  plugins -.extends.-> metadata
  plugins -.extends.-> kb
  cli --> instrument & protocol & metadata & kb
```

---

## Data flow

```mermaid
flowchart LR
  A["Target process\n(Unity IL2CPP)"] -->|Frida attach/spawn| B["Agent hooks\n(read-only)"]
  B -->|send(JSON)| C["Host logger\n→ events.jsonl"]
  C --> D["Reducers\n(analyze / build)"]
  D --> E["Artifacts\nframes.jsonl · types.json · protocol.json · schemas/"]
  E --> F["Knowledge base\n(SQLite)"]
  F --> G["Docs · Diagrams · HTML viewer · Search · Version diffs"]
```

---

## Knowledge pipeline

```mermaid
flowchart LR
  cap["Capture session\n(labelled by gameplay action)"] --> imp["Importer\n(dedup + merge)"]
  cls["Class inventory"] --> imp
  proto["Protocol artifacts"] --> imp
  imp --> learn["Opcode learning\n+ relationships"]
  learn --> conf["Confidence engine\n(never downgrade)"]
  conf --> store["SQLite tables\n(fingerprinted, versioned)"]
  store --> out["Auto docs + viewer\n+ version diffs + search"]
```

---

## Capture pipeline (protocol)

```mermaid
sequenceDiagram
  participant App as Target
  participant Agent as Agent (socket hooks)
  participant Host as Host reassembler
  participant Lib as protocol library
  App->>Agent: send()/recv() (observed, unchanged)
  Agent->>Host: raw frame chunks (base64) + metadata
  Host->>Host: reassemble per-(fd,dir) TCP stream
  Host->>Lib: byte stream
  Lib->>Lib: split frames → decode MessagePack → correlate
  Lib->>Host: frames.jsonl + protocol.json + schemas/
```

---

## Runtime instrumentation

```mermaid
flowchart TD
  boot["bootstrap.js"] --> A["process — libs, load order, JNI_OnLoad, dlopen"]
  boot --> B["il2cpp_api — locate + hook read-only API"]
  boot --> C["metadata — open/read/mmap of metadata file"]
  boot --> D["decrypt_observer — detect plaintext (opt-in)"]
  boot --> E["network — connect/send/recv/DNS (sizes+peers)"]
  boot --> F["strings — il2cpp_string_new keyword capture"]
  boot --> G["lua — VM/loadbuffer/pcall"]
  A & B & C & D & E & F & G --> log["structured JSON events"]
```

---

## Protocol decoding

```mermaid
flowchart LR
  stream["TCP byte stream"] --> frame["FPNN framer\n(magic-validated)"]
  frame --> hdr["header: magic/version/flag/mtype/ss/psize/seq/method"]
  frame --> pay["MessagePack decoder"]
  pay --> typed["typed value tree"]
  typed --> shape["normalised shape\n(→ packet fingerprint)"]
  typed --> sch["schema inference\n(Verified/Likely/Unknown)"]
```

---

## Knowledge base

```mermaid
erDiagram
  sessions ||--o{ connections : has
  sessions ||--o{ gameplay_actions : labels
  commands ||--o{ packets : fingerprints
  commands ||--|| schemas : describes
  schemas ||--o{ schema_fields : fields
  commands ||--o{ requests : sampled
  requests ||--o{ responses : paired
  classes ||--o{ methods : declares
  commands }o--o{ classes : relationships
  ANY ||--o{ confidence_history : journals
```

---

## Documentation generation

```mermaid
flowchart LR
  db["SQLite KB"] --> dg["docgen"]
  dg --> md["protocol.md · opcode_reference · schema_reference · request_lifecycle · network_diagram · CHANGELOG"]
  dg --> gg["graphs: packet_flow.mmd · opcode_relationships.dot · class_relationships.mmd · schema_evolution.mmd"]
  db --> vw["viewer → self-contained index.html"]
```

---

## Version comparison

```mermaid
flowchart LR
  v1["version A snapshot"] --> diff["versions.diff"]
  v2["version B snapshot"] --> diff
  diff --> rep["new/removed opcodes · schema changes · new/removed classes · new endpoints"]
  rep --> mig["migration report (md)"]
```

---

## Plugin system

```mermaid
flowchart TD
  disc["discover()\n(entry points + ./plugins)"] --> reg["Registry"]
  reg --> s["serialization decoders"]
  reg --> c["classifier rules"]
  reg --> k["kb importers"]
  s & c & k -.consumed by.-> core["core pipeline"]
```

---

## Confidence engine

```mermaid
flowchart LR
  obs["new observation\n(grade, count, source)"] --> merge["merge(old, new)"]
  merge -->|stronger| up["upgrade score/grade"]
  merge -->|weaker| keep["keep stronger (corroborate)"]
  up & keep --> hist["append to confidence_history\n(source, version, ts, reason)"]
```

---

## Repository layout

```
vantage/
├── src/vantage/            importable package
│   ├── agent/              Frida JS agent (core/, hooks/, il2cpp/)
│   ├── instrument/         Python launchers (frida-optional)
│   ├── protocol/           FPNN + MessagePack + correlation + schema + build
│   ├── metadata/           managed-class classifier + inventory
│   ├── kb/                 SQLite knowledge base + docgen + viewer
│   ├── plugins/            plugin registry + discovery
│   ├── configs/            default config + offsets template
│   └── cli.py              unified `vantage` entry point
├── tests/                  pytest suite (offline; no device needed)
├── sample-data/            synthetic inputs (clearly marked)
├── examples/               example outputs (synthetic)
├── plugins/                drop-in plugin directory (example included)
├── docs/                   this documentation set
├── scripts/                developer helpers
├── .github/                CI, templates, automation
└── pyproject.toml          packaging + tooling config
```

See [design/philosophy.md](design/philosophy.md) for the reasoning behind these
boundaries, and [components/](components/) for per-subsystem detail.
