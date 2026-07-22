# Vantage documentation

Start here, then dive into the area you need.

## Overview
- [Architecture](architecture.md) — modules, data flow, and every pipeline diagram
- [Design philosophy, decisions & trade-offs](design/philosophy.md)

## Design
- [Evidence model](design/evidence-model.md) — grades, three-tier confidence, provenance
- [Confidence engine](design/confidence-engine.md) — scoring + the never-downgrade invariant
- [Knowledge base & knowledge graph](design/knowledge-base.md)
- [Versioning & migration analysis](design/versioning.md)
- [Plugin system](design/plugin-system.md)

## Components
- [Runtime instrumentation](components/runtime-instrumentation.md) — the Frida agent
- [IL2CPP metadata recovery](components/metadata-recovery.md)
- [Protocol analysis](components/protocol-analysis.md) — FPNN + MessagePack

## Reference
- [API reference](api-reference.md)

## Security, ethics & scope
- [Threat model & security posture](threat-model.md)
- [Ethics & responsible research](ethics-and-responsible-research.md)
- [Limitations](limitations.md)

## Operations
- [Performance & scalability](performance-and-scalability.md)
- [Roadmap](roadmap.md)

---

Everything here is game-agnostic. Target-specific analysis belongs in isolated,
private case studies (kept out of the public repository).
