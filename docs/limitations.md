# Limitations

Vantage is deliberately scoped to observation. Its limits follow directly from
that choice and from the realities of hardened targets.

## Protocol

- **Framing** is decoded for the **FPNN** family (TCP + MessagePack). Other RPC
  frameworks require a plugin decoder.
- **TLS transports**: for HTTP/2 or other TLS traffic, socket-level capture sees
  ciphertext + host/port/size only. Plaintext requires managed-level hooks (an
  extension point), which need the IL2CPP API located.
- **Opcodes and schemas are only as complete as your captures.** Unobserved
  commands/fields remain `Unknown`; the framework never fabricates them.

## Metadata recovery

- On **hardened** targets (stripped/encrypted `libil2cpp` exports), the read-only
  API cannot be resolved by name. You must supply RVAs from a static analysis of
  a decrypted dump you are authorised to make, or opt into the behavioural probe.
  Vantage does not produce that dump and does not defeat protection.
- Method **return/parameter type names** are best-effort (non-allocating
  accessors); some generic/edge types resolve as primitives only.

## Instrumentation

- **Anti-analysis is not evaded.** Hardened targets may detect Frida and
  terminate a session. This is expected and unhandled by design.
- Requires a `frida-server` matching the **target process ABI** (32- vs 64-bit).

## Knowledge base

- Single-file SQLite scales to millions of observations but is not a distributed
  store; extreme scale needs the sharding path in
  [performance-and-scalability.md](performance-and-scalability.md).
- Heuristic **classification** and request **categorisation** are transparent
  (every result carries `reasons`) but remain heuristics until corroborated by
  captured evidence.

## Platform

- Primary target is **Android** Unity IL2CPP. The offline analysis/KB is
  OS-independent; the agent's native hooks assume Linux/Android libc + Bionic
  linker semantics.

## Non-capabilities (by design, not limitation)

No cheating, automation, injection, replay, memory modification, key extraction,
or protection bypass — see [threat-model.md](threat-model.md).
