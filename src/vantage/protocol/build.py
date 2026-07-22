#!/usr/bin/env python3
"""
vantage.protocol.build — assemble FPNN protocol artifacts from captured frames.

Given one or more capture-session directories (each containing ``frames.jsonl``
produced by the observation-only capture agent), this emits:

    protocol.json          transport/framing/encoding spec + observed statistics
    opcode_map.json        every observed command/method: counts, directions
    request_map.json       command <-> command-id <-> schema (capture-driven slots)
    schemas/<Cmd>.json     per-command inferred schema (Verified/Likely/Unknown)
    confidence_report.json

Framing fields are drawn from the public FPNN standard (structural certainty);
opcodes and schemas are derived purely from observed frames. Analysis only:
nothing is transmitted, injected, replayed, or modified.

CLI:
    python -m vantage.protocol.build <capture_dir> [more_dirs...] [--out DIR] [--target NAME]
"""
import argparse
import json
import os
import re

from vantage.protocol.correlate import load_frames, correlate
from vantage.protocol.schema import infer

# Evidence-graded framing spec (public FPNN standard; applications that embed the
# FPNN C# SDK implement this layout). Structural fields are graded "spec"; they
# flip to "observed" once a live capture magic-matches. Application-layer notes
# (auth/encryption) are deliberately generic and observation-scoped.
FRAMING_SPEC = {
    "transport": {"type": "TCP", "value": "raw stream (com.fpnn.TCPClient/TCPConnection)", "confidence": "verified(class)"},
    "magic": {"tcp": "FPNN (0x46504E4E)", "udp": "FUNN", "confidence": "spec"},
    "header_bytes": 12,
    "header": [
        {"offset": 0, "size": 4, "field": "magic", "confidence": "spec"},
        {"offset": 4, "size": 1, "field": "version", "note": "typically 0x01", "confidence": "spec"},
        {"offset": 5, "size": 1, "field": "flag", "note": "0x80 FLAG_MSGPACK, 0x40 FLAG_JSON", "confidence": "spec"},
        {"offset": 6, "size": 1, "field": "mtype", "note": "0 oneway-quest, 1 twoway-quest, 2 answer", "confidence": "spec"},
        {"offset": 7, "size": 1, "field": "ss", "note": "quest: method-name length; answer: status", "confidence": "spec"},
        {"offset": 8, "size": 4, "field": "psize", "note": "payload size, little-endian", "confidence": "spec"},
    ],
    "after_header": [
        {"field": "seqNum", "size": 4, "note": "LE; present for two-way quest & answer (one-way: confirm by capture)", "confidence": "spec"},
        {"field": "method", "size": "ss", "note": "quest only, UTF-8", "confidence": "spec"},
        {"field": "payload", "size": "psize", "note": "MessagePack map (FLAG_MSGPACK) or JSON", "confidence": "spec"},
    ],
    "encoding": {"value": "MessagePack", "evidence": "com.fpnn.msgpack.MsgPacker/MsgUnpacker + FLAG_MSGPACK", "confidence": "verified(class)"},
    "authentication": {"value": "first two-way quest after connect typically carries a session token",
                       "confidence": "inferred", "note": "confirm method + fields by capturing the login exchange"},
    "heartbeat": {"value": "recurring same-method quest at a regular interval", "confidence": "capture-derived"},
    "reconnect": {"value": "new connect() to same peer after close()", "confidence": "capture-derived"},
    "request_ids": {"value": "seqNum (LE u32), monotonic per connection", "confidence": "spec"},
    "push_messages": {"value": "one-way quest (mtype=0) arriving on rx", "confidence": "spec+capture"},
    "compression": {"value": "FPNN supports a ZIP flag; observe the flag byte", "confidence": "spec/observe"},
    "encryption": {"value": "raw TCP (no TLS on the FPNN socket); any application-layer field encryption is observed, never removed",
                   "confidence": "observe", "note": "no protection, signing, or integrity check is bypassed"},
    "error_handling": {"value": "answer with ss(status) != 0 carries an error payload", "confidence": "spec"},
    "version_negotiation": {"value": "header.version; application version negotiated out of band over HTTP", "confidence": "spec+inferred"},
}


def sanitize(name):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


def build(capture_dirs, out_dir, target="unknown"):
    frames = []
    for d in capture_dirs:
        fs = load_frames(d)
        frames.extend(fs)
    corr = correlate(frames) if frames else {"stats": {}, "pairs": [], "pushes": [], "unanswered": [], "heartbeats": [], "retries": []}
    schemas = infer(frames) if frames else {}

    os.makedirs(os.path.join(out_dir, "schemas"), exist_ok=True)

    opcode_map = {k: {"command": k, "samples": sc["samples"], "directions": sc["directions"],
                      "message_types": sc["message_types"], "encoding": sc["encoding"],
                      "confidence": sc["overall_confidence"]} for k, sc in schemas.items()}
    request_map = {k: {"command": k, "request_cmd_id": None, "managed_class": None, "calling_method": None,
                       "schema_ref": f"schemas/{sanitize(k)}.json", "confidence": sc["overall_confidence"]}
                   for k, sc in schemas.items()}
    protocol = {
        "target": target,
        "framing": FRAMING_SPEC,
        "observed": {
            "frames": len(frames), "correlation": corr["stats"], "heartbeats": corr["heartbeats"],
            "pushes_count": len(corr["pushes"]), "retries_count": len(corr["retries"]),
            "commands_observed": len(schemas),
        },
        "note": "framing fields are FPNN-standard (spec); opcodes/schemas are capture-derived. "
                "No traffic was generated, replayed, or modified.",
    }
    conf = {
        "framing": "spec (FPNN public standard) — magic-confirmed once captured",
        "encoding": "verified(class) MessagePack",
        "commands": {k: v["overall_confidence"] for k, v in schemas.items()},
        "heartbeats": corr["heartbeats"],
        "verified_fields": sum(1 for sc in schemas.values() for f in sc["fields"] if f["confidence"] == "Verified"),
        "likely_fields": sum(1 for sc in schemas.values() for f in sc["fields"] if f["confidence"] == "Likely"),
        "unknown_fields": sum(1 for sc in schemas.values() for f in sc["fields"] if f["confidence"] == "Unknown"),
    }

    def dump(name, obj):
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)

    dump("protocol.json", protocol)
    dump("opcode_map.json", opcode_map)
    dump("request_map.json", request_map)
    dump("confidence_report.json", conf)
    for k, sc in schemas.items():
        dump(os.path.join("schemas", sanitize(k) + ".json"), sc)
    return {"frames": len(frames), "commands": len(schemas), "correlation": corr["stats"], "out": out_dir}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build FPNN protocol artifacts from captures (observation only)")
    ap.add_argument("dirs", nargs="+", help="capture session directories (each with frames.jsonl)")
    ap.add_argument("--out", default=os.path.join(os.getcwd(), "protocol"))
    ap.add_argument("--target", default="unknown")
    args = ap.parse_args(argv)
    res = build(args.dirs, args.out, args.target)
    print(f"[*] {res['frames']} frames · {res['commands']} commands -> {res['out']}")
    print(f"[*] correlation: {res['correlation']}")


if __name__ == "__main__":
    main()
