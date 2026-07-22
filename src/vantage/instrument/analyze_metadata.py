#!/usr/bin/env python3
"""
analyze_metadata.py — reduce a Phase 4 recovery session into a managed-architecture
report.

Input: a recovery session dir (with metadata.json and/or events.jsonl containing
'recovered_class' events).

Output (in the session dir):
  types.json    Assembly -> Namespace -> Class -> Method tree (recovered)
  report.md     managed architecture report + confidence ranking + diagrams
"""
import json
import os
import sys
from collections import defaultdict, Counter


def load_recovered(path):
    if os.path.isdir(path):
        mj = os.path.join(path, "metadata.json")
        ev = os.path.join(path, "events.jsonl")
        if os.path.exists(mj):
            with open(mj, encoding="utf-8") as f:
                data = json.load(f)
            return data.get("recovered_classes", []), path
        recs = []
        if os.path.exists(ev):
            with open(ev, encoding="utf-8") as f:
                for line in f:
                    try:
                        r = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if r.get("event") == "recovered_class":
                        recs.append(r.get("data"))
        return recs, path
    # a file
    with open(path, encoding="utf-8") as f:
        if path.endswith(".jsonl"):
            recs = []
            for line in f:
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if r.get("event") == "recovered_class":
                    recs.append(r.get("data"))
            return recs, os.path.dirname(path)
        data = json.load(f)
        return data.get("recovered_classes", data), os.path.dirname(path)


def main():
    if len(sys.argv) < 2:
        print("usage: analyze_metadata.py <recovery_dir|metadata.json|events.jsonl>")
        sys.exit(1)
    recovered, base = load_recovered(sys.argv[1])
    if not recovered:
        print("[!] no recovered_class records found (recovery may have been blocked by an "
              "unlocated IL2CPP API — see the session's events.jsonl B4 'recovery_blocked').")
    # de-dup
    seen = set()
    uniq = []
    for c in recovered:
        if not c:
            continue
        key = (c.get("assembly"), c.get("ns"), c.get("name"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)

    # tree
    tree = defaultdict(lambda: defaultdict(list))
    by_role = Counter()
    by_tier = Counter()
    for c in uniq:
        tree[c.get("assembly") or "?"][c.get("ns") or ""].append(c)
        if c.get("role"):
            by_role[c["role"]] += 1
        by_tier[c.get("tier", "?")] += 1

    types = {}
    for asm, nss in tree.items():
        types[asm] = {}
        for ns, classes in nss.items():
            types[asm][ns] = [{
                "class": c.get("name"),
                "role": c.get("role"),
                "confidence": c.get("confidence"),
                "tier": c.get("tier"),
                "verified": c.get("verified"),
                "method_count": c.get("method_count"),
                "methods": c.get("methods", []),
                "correlation": c.get("correlation", []),
            } for c in sorted(classes, key=lambda x: -(x.get("confidence") or 0))]

    with open(os.path.join(base, "types.json"), "w", encoding="utf-8") as f:
        json.dump(types, f, indent=2, ensure_ascii=False)

    ranked = sorted(uniq, key=lambda x: -(x.get("confidence") or 0))

    md = ["# Managed architecture report (runtime-recovered)\n",
          f"- Recovered classified classes: **{len(uniq)}**",
          f"- By tier: `{dict(by_tier)}`",
          f"- By role: `{dict(by_role.most_common())}`\n",
          "> `verified: runtime_metadata` = read from the in-memory (already-decrypted) "
          "type system via the runtime's own read-only API. Method `rva` values are "
          "MethodInfo.methodPointer offsets. No decryption/keys/patching involved.\n",
          "## Networking / serialization / update / asset classes (ranked)\n",
          "| conf | tier | role | assembly | namespace | class | #methods |",
          "|---|---|---|---|---|---|---|"]
    for c in ranked[:120]:
        md.append(f"| {c.get('confidence')} | {c.get('tier')} | {c.get('role')} | "
                  f"`{c.get('assembly')}` | `{c.get('ns')}` | `{c.get('name')}` | {c.get('method_count','?')} |")

    # method signature sample for the top networking classes
    md.append("\n## Recovered method signatures (sample, top classes)\n")
    for c in ranked[:15]:
        md.append(f"### `{c.get('ns')}.{c.get('name')}`  ({c.get('role')}, conf {c.get('confidence')})")
        for m in (c.get("methods") or [])[:12]:
            params = ", ".join([p or "?" for p in (m.get("param_types") or [])]) if m.get("param_types") else f"{m.get('params','?')} args"
            md.append(f"- `{m.get('ret','?')} {m.get('name')}({params})`  rva={m.get('rva')}")
        md.append("")

    md.append("## Recovery diagram\n")
    md.append("```mermaid")
    md.append("flowchart TD")
    md.append("  D[il2cpp_domain_get] --> A[assemblies]")
    md.append("  A --> I[images]")
    md.append("  I --> C[classes]")
    md.append("  C --> M[methods: name/params/return/rva]")
    md.append("  M --> R[classify + correlate -> role + confidence]")
    md.append("```")

    with open(os.path.join(base, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")

    print(f"[*] {len(uniq)} classes -> {os.path.join(base,'types.json')} + report.md")
    print(f"[*] roles: {dict(by_role.most_common())}")


if __name__ == "__main__":
    main()
