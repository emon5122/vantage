#!/usr/bin/env python3
"""
build_static_inventory.py — classify the VERIFIED static class inventory
(data/managed_monoscript_classes.txt, recovered in Phase 2 from
globalgamemanagers.assets MonoScript names) into the Phase-4 target categories.

This produces REAL, evidence-backed deliverables from data already in hand — the
same classes the on-device recover.py would confirm with method-level detail:

  data/managed_inventory.summary.json     assemblies/namespaces/category counts
  data/networking_classes.ranked.json     classified classes, ranked by confidence
  data/PHASE4_static_findings.md           human-readable ranked findings

Every class here is VERIFIED to exist (MonoScript). The 'role'/'confidence' is a
lexical classification of that verified class — clearly separated from method
detail, which is only recoverable at runtime (recover.py).
"""
import json
import os
from collections import Counter, defaultdict

from vantage.metadata.classifier import score_one, CAT

HERE = os.getcwd()
SRC = os.environ.get("VANTAGE_CLASSES", os.path.join(os.getcwd(), "sample-data", "monoscript_classes.txt"))


def main():
    if not os.path.exists(SRC):
        raise SystemExit(f"missing {SRC} (copy the Phase 2 allscripts.txt here)")

    rows = []
    with open(SRC, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("|")
            asm = parts[0] if len(parts) > 0 else ""
            ns = parts[1] if len(parts) > 1 else ""
            name = parts[2] if len(parts) > 2 else ""
            rows.append((asm, ns, name))

    asm_counts = Counter(a for a, _, _ in rows)
    ns_counts = Counter(f"{a}|{n}" for a, n, _ in rows if n)

    classified = []
    lib_internal = 0
    cat_counts = Counter()
    for asm, ns, name in rows:
        sc = score_one(asm, ns, name)
        if not sc["role"]:
            continue
        if sc.get("library_internal"):
            lib_internal += 1
            continue  # third-party TLS/crypto plumbing — counted, not ranked
        cat_counts[sc["role"]] += 1
        classified.append({
            "assembly": asm, "namespace": ns, "class": name,
            "role": sc["role"], "confidence": sc["confidence"], "tier": sc["tier"],
            "categories": sc["categories"], "reasons": sc["reasons"],
            "verified": "static_monoscript",     # class existence is verified
            "method_detail": "pending_runtime",   # RVA/params require recover.py
        })

    classified.sort(key=lambda x: (-x["confidence"], x["role"], x["class"]))

    summary = {
        "source": "globalgamemanagers.assets MonoScript (Phase 2, verified)",
        "total_classes": len(rows),
        "classified_classes": len(classified),
        "tls_crypto_internal_excluded": lib_internal,
        "assemblies": asm_counts.most_common(),
        "top_namespaces": ns_counts.most_common(40),
        "by_category": cat_counts.most_common(),
        "categories_defined": list(CAT.keys()),
    }

    os.makedirs(os.path.join(HERE, "data"), exist_ok=True)
    with open(os.path.join(HERE, "data", "managed_inventory.summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    with open(os.path.join(HERE, "data", "networking_classes.ranked.json"), "w", encoding="utf-8") as f:
        json.dump(classified, f, indent=2, ensure_ascii=False)

    # markdown
    md = ["# Phase 4 — static classification findings (verified classes)\n",
          f"Source: **{summary['source']}**  ·  total classes: **{len(rows)}**  ·  classified: **{len(classified)}**\n",
          "> Class existence is VERIFIED (MonoScript). Role/confidence is a lexical classification. "
          "Method RVAs/params are `pending_runtime` (recover.py).\n",
          "## By category", ""]
    for cat, n in cat_counts.most_common():
        md.append(f"- **{cat}**: {n}")
    md.append("\n## Highest-confidence networking/serialization classes\n")
    md.append("| conf | tier | role | assembly | namespace | class |")
    md.append("|---|---|---|---|---|---|")
    for c in classified[:80]:
        md.append(f"| {c['confidence']} | {c['tier']} | {c['role']} | `{c['assembly']}` | `{c['namespace']}` | `{c['class']}` |")
    with open(os.path.join(HERE, "data", "PHASE4_static_findings.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")

    print(f"[*] classified {len(classified)}/{len(rows)} classes")
    print(f"[*] by_category: {dict(cat_counts.most_common())}")
    print(f"[*] wrote data/managed_inventory.summary.json, data/networking_classes.ranked.json, data/PHASE4_static_findings.md")


if __name__ == "__main__":
    main()
