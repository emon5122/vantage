# Roadmap

Directional, not a commitment. Contributions welcome — see
[`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Near term

- [ ] Managed-level protocol hooks (read plaintext request/response *before*
      serialization) once the IL2CPP API is located — closes the TLS-visibility
      gap without touching traffic.
- [ ] First-class **Protobuf** and **FlatBuffers** decoders as bundled plugins.
- [ ] `iOS` agent parity for the IL2CPP read-only traversal.
- [ ] Richer HTML viewer: relationship graph exploration, schema-evolution
      timelines rendered client-side.

## Medium term

- [ ] Pluggable framing decoders beyond FPNN (generic length-prefixed TLV,
      gRPC-web, SignalR) via the `serialization` seam.
- [ ] Postgres backend option for shared, concurrent knowledge bases.
- [ ] Signed, reproducible release artifacts + SBOM.
- [ ] A `vantage doctor` command that checks device/frida-server ABI match.

## Longer term

- [ ] Cross-target knowledge federation (compare framing/schema conventions
      across many apps) for defensive threat-intelligence use.
- [ ] Static-analysis bridge: import Il2CppDumper output directly to bootstrap
      offsets and seed the class graph before any live session.
- [ ] Structured "case study" export format so researchers can publish
      methodology + synthetic reproductions without target-specific data.

## Explicitly out of scope (permanently)

Anything that would let the framework *act on* a target: automation, bots,
cheats, packet injection/replay, memory modification, or protection bypass. These
will never be accepted; see [threat-model.md](threat-model.md).
