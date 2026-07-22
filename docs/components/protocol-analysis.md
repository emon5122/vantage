# Protocol analysis

Package: [`vantage.protocol`](../../src/vantage/protocol/)

Vantage decodes the **FPNN** RPC framing (an open protocol, github.com/highras/fpnn)
and its **MessagePack** payloads from captured byte streams. Framing is documented
from the public standard (evidence-graded `spec`); opcodes, schemas, and payloads
are derived purely from observed frames.

## Pipeline

```
raw TCP stream  →  fpnn.iter_stream  →  fpnn.parse_message  →  msgpack.decode
                                    →  correlate            →  schema.infer  →  build
```

| Module | Purpose | Inputs | Outputs |
|---|---|---|---|
| [`msgpack.py`](../../src/vantage/protocol/msgpack.py) | dependency-free MessagePack decoder | bytes | value + type tree |
| [`fpnn.py`](../../src/vantage/protocol/fpnn.py) | FPNN framer (header/seq/method/payload) + reassembly | byte stream | frame records |
| [`correlate.py`](../../src/vantage/protocol/correlate.py) | quest↔answer pairing, RTT, heartbeat/push/retry | frames | timing model |
| [`schema.py`](../../src/vantage/protocol/schema.py) | per-command schema inference + confidence | frames | schemas |
| [`build.py`](../../src/vantage/protocol/build.py) | assemble `protocol.json`/`opcode_map`/`schemas/` | capture dirs | artifacts |
| [`synthetic.py`](../../src/vantage/protocol/synthetic.py) | **synthetic** spec-conformant frames | — | test/sample input |

## FPNN framing (byte offsets)

```
 off sz  field     meaning                                             grade
  0   4  magic     "FPNN" (TCP) / "FUNN" (UDP)                         spec
  4   1  version   typically 0x01                                      spec
  5   1  flag       0x80 FLAG_MSGPACK · 0x40 FLAG_JSON                  spec
  6   1  mtype      0 one-way quest · 1 two-way quest · 2 answer        spec
  7   1  ss         quest: method-name length · answer: status          spec
  8   4  psize      payload size (little-endian)                        spec
 12   4  seqNum     request id (LE u32)                                 spec
 16  ss  method     quest only, UTF-8                                   spec
 ..  ps  payload    MessagePack map                                     verified(class)
```

The parser **magic-validates** every frame and resynchronises on desync — it
never guesses frame boundaries.

## MessagePack decoding

The decoder handles the full type set (nil/bool/int/float/str/bin/array/map/ext +
timestamp), **preserves integer map keys** (compact protocols use field *numbers*
as keys — surfaced as `#n`), and wraps `bin`/`ext` JSON-safely. Output is JSON.

## Correlation & timing

- pairs two-way quests with answers by `seqNum`; measures RTT (min/median/max)
- detects **heartbeats** (regularly-spaced same-method quests → interval + jitter)
- detects **server pushes** (one-way quests arriving on rx)
- detects **retries** and **timeouts**

## Schema inference & confidence

Frames are grouped by command (method name, else an in-payload opcode field); the
MessagePack type trees are merged into a field schema with per-field
`Verified/Likely/Unknown` grades that accumulate across sessions. See
[evidence-model.md](../design/evidence-model.md).

## Correctness

The decoders and analysis are validated end-to-end on **synthetic**
spec-conformant frames (never a live capture) by
[`tests/test_msgpack.py`](../../tests/test_msgpack.py),
[`tests/test_fpnn.py`](../../tests/test_fpnn.py), and
[`tests/test_protocol_analysis.py`](../../tests/test_protocol_analysis.py). Live
capture is required to populate real opcodes/schemas — the tooling never fabricates
them.
