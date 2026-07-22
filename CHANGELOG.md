# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-07-22

Initial public release of **Vantage**, an observation-only runtime analysis and
protocol-intelligence framework for Unity IL2CPP applications.

### Added
- **Runtime instrumentation** (Frida, read-only): process/library discovery,
  `JNI_OnLoad`/`RegisterNatives`, network/DNS/socket observation, Lua tracing,
  runtime string recovery, and metadata/decryption *observation*.
- **IL2CPP metadata recovery**: in-memory type-system traversal via the runtime's
  read-only API, with a layered locator (named exports / offsets / behavioural
  probe / registration scan) and a managed-class classifier.
- **Protocol analysis**: dependency-free MessagePack decoder, FPNN framer with
  stream reassembly, quest/answer correlation, and confidence-graded schema
  inference.
- **Knowledge base**: versioned SQLite store with a confidence engine
  (never-downgrade), packet fingerprint deduplication, opcode learning, a
  knowledge graph, version diffing/migration reports, a read-only search engine,
  auto-generated documentation, and a self-contained HTML viewer.
- **Plugin system**: `serialization`, `classifier`, and `kb_importer` extension
  seams with entry-point + directory discovery.
- **Unified CLI** (`vantage`), synthetic sample-data generator, and 60-test
  offline suite.
- Full documentation set (architecture, design, components, API, threat model,
  ethics, limitations, performance, roadmap) and GitHub project scaffolding.

### Security / scope
- Enforced observation-only guarantee across the codebase: no traffic
  modification, injection, replay, memory modification, automation, key
  extraction, or protection bypass.

[Unreleased]: https://github.com/emon5122/vantage/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/emon5122/vantage/releases/tag/v0.1.0
