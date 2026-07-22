"""
schema_infer.py — infer per-command payload schemas from captured FPNN frames.

Groups frames by command key (quest method name; falls back to an in-payload
opcode field if the method is generic), then merges the MessagePack type trees of
all samples into a field schema with presence/optionality/type-stability and a
confidence label. Analysis only — derived purely from observed payloads.

Confidence per field:
  Verified : present in ALL samples with a single stable type  (>= min_samples)
  Likely   : present in most samples, or stable type but few samples
  Unknown  : sparse / mixed types / < min_samples
"""
import json
import os
from collections import defaultdict, Counter

from vantage.protocol.correlate import load_frames

# heuristics for finding an opcode/command field inside a generic payload
OPCODE_KEYS = ["cmd", "cmdid", "cmd_id", "op", "opcode", "c", "1", "#1", "mtype", "type", "act", "action"]


def type_of(tnode):
    if not isinstance(tnode, dict):
        return "unknown"
    t = tnode.get("t", "unknown")
    if t in ("uint8", "uint16", "uint32", "uint64", "int8", "int16", "int32", "int64", "int"):
        return "int"
    if t in ("float32", "float64"):
        return "float"
    return t


def command_key(frame):
    """Command grouping key: method name, else an opcode field value in payload."""
    m = frame.get("method")
    if m:
        return f"method:{m}"
    payload = frame.get("payload")
    if isinstance(payload, dict):
        for k in OPCODE_KEYS:
            if k in payload and isinstance(payload[k], int):
                return f"op:{payload[k]}"
    # answers grouped by seq are handled by correlation; here mark generic
    mt = frame.get("header", {}).get("mtype_name", "?")
    return f"anon:{mt}"


def merge_fields(samples_types):
    """Merge map 'fields' type-nodes across samples -> {key: {types, count}}."""
    field_types = defaultdict(Counter)
    total = 0
    for tnode in samples_types:
        if not isinstance(tnode, dict) or tnode.get("t") != "map":
            continue
        total += 1
        for key, vt in (tnode.get("fields") or {}).items():
            field_types[str(key)][type_of(vt)] += 1
    schema = {}
    for key, tc in field_types.items():
        present = sum(tc.values())
        types = list(tc.keys())
        stable = len(types) == 1
        schema[key] = {
            "field": key,
            "types": dict(tc),
            "present_in": present,
            "of_samples": total,
            "optional": present < total,
            "type_stable": stable,
        }
    return schema, total


def confidence_for(field, total, min_samples):
    if total < min_samples:
        return "Unknown"
    if not field["optional"] and field["type_stable"]:
        return "Verified"
    if field["type_stable"] or field["present_in"] >= max(2, total * 0.6):
        return "Likely"
    return "Unknown"


def infer(frames, min_samples=3):
    groups = defaultdict(list)
    for f in frames:
        if f.get("payload_types"):
            groups[command_key(f)].append(f)
    schemas = {}
    for key, gframes in groups.items():
        types = [f.get("payload_types") for f in gframes]
        fields, total = merge_fields(types)
        for fk in fields:
            fields[fk]["confidence"] = confidence_for(fields[fk], total, min_samples)
        # overall schema confidence
        if total >= min_samples and fields and all(v["confidence"] == "Verified" for v in fields.values()):
            overall = "Verified"
        elif total >= 1 and fields:
            overall = "Likely" if total >= 2 else "Unknown"
        else:
            overall = "Unknown"
        dirs = Counter(f.get("_dir") for f in gframes)
        mtypes = Counter(f["header"]["mtype_name"] for f in gframes)
        schemas[key] = {
            "command": key,
            "samples": total,
            "directions": dict(dirs),
            "message_types": dict(mtypes),
            "encoding": "messagepack" if any(f["header"].get("flag_msgpack") for f in gframes) else "unknown",
            "overall_confidence": overall,
            "fields": sorted(fields.values(), key=lambda x: str(x["field"])),
            "example_payload": next((f.get("payload") for f in gframes if f.get("payload") is not None), None),
        }
    return schemas
