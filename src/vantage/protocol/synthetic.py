"""
vantage.protocol.synthetic — generate SYNTHETIC, spec-conformant FPNN frames.

Used by the test suite, examples, and sample-data generator to exercise the
decoders. These frames are FABRICATED to the documented FPNN/MessagePack layout;
they are NOT captured from any application and are NOT evidence about any live
protocol. This module contains a minimal MessagePack *encoder* used ONLY to build
that synthetic input — the framework never encodes or transmits real traffic.
"""
import struct


def mp(v):
    """Minimal MessagePack encoder (synthetic input only)."""
    if v is None:
        return b"\xc0"
    if v is True:
        return b"\xc3"
    if v is False:
        return b"\xc2"
    if isinstance(v, int):
        if 0 <= v <= 0x7f:
            return bytes([v])
        if -32 <= v < 0:
            return bytes([v & 0xff])
        if 0 <= v <= 0xffffffff:
            return b"\xce" + struct.pack(">I", v)
        return b"\xd3" + struct.pack(">q", v)
    if isinstance(v, float):
        return b"\xcb" + struct.pack(">d", v)
    if isinstance(v, str):
        b = v.encode("utf-8")
        if len(b) <= 31:
            return bytes([0xa0 | len(b)]) + b
        return b"\xd9" + bytes([len(b)]) + b
    if isinstance(v, list):
        out = bytes([0x90 | len(v)]) if len(v) <= 15 else b"\xdc" + struct.pack(">H", len(v))
        return out + b"".join(mp(x) for x in v)
    if isinstance(v, dict):
        out = bytes([0x80 | len(v)]) if len(v) <= 15 else b"\xde" + struct.pack(">H", len(v))
        return out + b"".join(mp(k) + mp(val) for k, val in v.items())
    raise TypeError(type(v))


def frame(mtype, seq, payload, method=None, flag=0x80, status=0):
    """Build one synthetic FPNN message (TCP magic)."""
    pl = mp(payload)
    ss = len(method.encode()) if method is not None else status
    hdr = b"FPNN" + bytes([1, flag, mtype, ss]) + struct.pack("<I", len(pl))
    body = struct.pack("<I", seq)  # seq present for quest + answer (spec)
    if method is not None:
        body += method.encode()
    body += pl
    return hdr + body


def synthetic_session():
    """A small, self-consistent synthetic session: login + heartbeat + push.

    Returns (tx_stream, tx_timestamps, rx_stream, rx_timestamps).
    """
    tx, rx, ts_tx, ts_rx = bytearray(), bytearray(), [], []
    tx += frame(1, 1, {1: "user", 2: "token", 3: 42}, method="login"); ts_tx.append(0.0)
    rx += frame(2, 1, {1: 100001, 2: "ok"}, status=0); ts_rx.append(0.05)
    for i in range(5):
        tx += frame(1, 2 + i, {1: 1700000000 + i}, method="ping"); ts_tx.append(1.0 + i)
        rx += frame(2, 2 + i, {1: 1}, status=0); ts_rx.append(1.03 + i)
    rx += frame(0, 7, {1: 3, 2: "push"}, method="onPush"); ts_rx.append(6.0)
    return bytes(tx), ts_tx, bytes(rx), ts_rx


def write_session(out_dir, label="synthetic", peer=("198.51.100.7", 13013)):
    """Write a synthetic capture session (frames.jsonl + connections.json)."""
    import json
    import os
    from vantage.protocol.fpnn import iter_stream
    os.makedirs(out_dir, exist_ok=True)
    tx, ts_tx, rx, ts_rx = synthetic_session()
    with open(os.path.join(out_dir, "frames.jsonl"), "w", encoding="utf-8") as f:
        for buf, direction, tss in [(tx, "tx", ts_tx), (rx, "rx", ts_rx)]:
            idx = 0
            for rec, a, b in iter_stream(buf):
                if rec.get("desync_skipped"):
                    continue
                rec["_dir"] = direction
                rec["_ts"] = tss[idx] if idx < len(tss) else None
                rec["_fd"] = 91
                rec["_peer"] = {"ip": peer[0], "port": peer[1]}
                rec["_synthetic"] = True
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                idx += 1
    with open(os.path.join(out_dir, "connections.json"), "w", encoding="utf-8") as f:
        json.dump({"label": label, "synthetic": True,
                   "connections": {"91": {"peer": {"ip": peer[0], "port": peer[1]}, "lifetime_ms": 6000}}}, f, indent=2)
    return out_dir
