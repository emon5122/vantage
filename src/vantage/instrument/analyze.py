#!/usr/bin/env python3
"""
analyze.py — offline reducer for a session's events.jsonl.

Reads the timestamped JSONL produced by launcher.py and emits:
  - report.md   : human-readable session report
  - report.json : machine summary (endpoints, libraries, JNI, lua, requests)

Usage:
    python3 analyze.py logs/session_YYYYMMDD_HHMMSS
    python3 analyze.py logs/session_.../events.jsonl
"""
import json
import os
import sys
from collections import defaultdict, Counter


def load(path):
    if os.path.isdir(path):
        path = os.path.join(path, "events.jsonl")
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    load.path = path


def main():
    if len(sys.argv) < 2:
        print("usage: analyze.py <session_dir|events.jsonl>")
        sys.exit(1)
    src = sys.argv[1]
    base = src if os.path.isdir(src) else os.path.dirname(src)

    libs = []            # (seq, name)
    jni_onload = []
    register_natives = []
    unity_version = None
    app_version = None
    metadata_events = []
    plaintext_events = []
    connects = []
    dns = []
    endpoints = set()
    strings = []
    lua_chunks = []
    requests = []
    by_phase = Counter()
    summary = None

    for rec in load(src):
        ph = rec.get("phase"); ev = rec.get("event"); d = rec.get("data", {})
        by_phase[ph] += 1
        if ev == "library_loaded":
            libs.append((d.get("seq"), d.get("name")))
        elif ev == "unity_version":
            unity_version = d.get("version")
        elif ev == "app_version":
            app_version = f'{d.get("versionName")} ({d.get("versionCode")})'
        elif ev in ("JNI_OnLoad_enter", "JNI_OnLoad_leave"):
            jni_onload.append((ev, d.get("module")))
        elif ev == "RegisterNatives":
            register_natives.append(d)
        elif ev in ("open", "fopen", "mmap", "read", "AAssetManager_open"):
            metadata_events.append((ev, d))
        elif ev == "plaintext_ready":
            plaintext_events.append(d)
        elif ev == "connect":
            connects.append(d)
        elif ev == "dns_lookup":
            dns.append(d.get("host"))
        elif ev == "string":
            v = d.get("value")
            strings.append((d.get("via"), v))
            if v and ("://" in v or v.startswith("wss") or ".com" in v or ".net" in v or ".cn" in v):
                endpoints.add(v)
        elif ev == "endpoint_string":
            endpoints.add(d.get("value"))
        elif ev == "lua_load":
            lua_chunks.append(d)
        elif ev == "request":
            requests.append(d)
        elif ev == "session_summary":
            summary = d

    dests = Counter((c.get("ip"), c.get("port"), c.get("label")) for c in connects)
    req_cats = Counter(r.get("classification", {}).get("label") for r in requests)

    out = {
        "events_total": sum(by_phase.values()),
        "by_phase": dict(by_phase),
        "unity_version": unity_version,
        "app_version": app_version,
        "library_load_order": [n for _, n in sorted(libs, key=lambda x: (x[0] or 0))],
        "jni_onload": jni_onload,
        "register_natives_count": len(register_natives),
        "register_natives": register_natives[:50],
        "metadata_event_count": len(metadata_events),
        "plaintext_ready": plaintext_events,
        "connections": [{"ip": ip, "port": port, "label": lbl, "count": n}
                        for (ip, port, lbl), n in dests.most_common()],
        "dns": Counter(dns).most_common(),
        "endpoints_recovered": sorted(endpoints),
        "interesting_strings": strings[:200],
        "lua_chunks": lua_chunks[:200],
        "request_categories": dict(req_cats),
        "agent_summary": summary,
    }

    with open(os.path.join(base, "report.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    md = []
    md.append(f"# Runtime session report\n")
    md.append(f"- Events: **{out['events_total']}**  ·  by phase: `{out['by_phase']}`")
    md.append(f"- Unity: **{unity_version}**  ·  App: **{app_version}**\n")
    md.append("## Library load order")
    for i, n in enumerate(out["library_load_order"], 1):
        md.append(f"{i}. `{n}`")
    md.append("\n## JNI_OnLoad / RegisterNatives")
    md.append(f"- JNI_OnLoad events: {len(jni_onload)}  ·  RegisterNatives calls: {len(register_natives)}")
    md.append("\n## Metadata")
    md.append(f"- metadata file/mmap/read events: {out['metadata_event_count']}")
    md.append(f"- plaintext_ready detections: {len(plaintext_events)}")
    md.append("\n## Network")
    md.append("| dest ip | port | label | connects |")
    md.append("|---|---|---|---|")
    for c in out["connections"]:
        md.append(f"| {c['ip']} | {c['port']} | {c['label']} | {c['count']} |")
    md.append("\n### DNS lookups")
    for h, n in out["dns"]:
        md.append(f"- `{h}` ×{n}")
    md.append("\n### Endpoints recovered (runtime strings)")
    for e in out["endpoints_recovered"]:
        md.append(f"- `{e}`")
    md.append("\n## Request categories (heuristic)")
    for k, v in out["request_categories"].items():
        md.append(f"- {k}: {v}")
    md.append("\n## Lua chunks loaded")
    for c in out["lua_chunks"][:80]:
        md.append(f"- `{c.get('chunk')}` ({c.get('kind')}, {c.get('size')}B)")

    with open(os.path.join(base, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")

    print(f"[*] wrote {os.path.join(base, 'report.md')} and report.json")
    print(f"[*] {out['events_total']} events · {len(out['endpoints_recovered'])} endpoints · "
          f"{len(out['library_load_order'])} libs · {len(lua_chunks)} lua chunks")


if __name__ == "__main__":
    main()
