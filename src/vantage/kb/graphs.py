"""
kb/graphs.py — generate Graphviz (.dot) and Mermaid (.mmd) diagrams from the KB:
packet flow, opcode relationships, schema evolution, class relationships.
Text output only (render externally). Observation-derived.
"""
import os


def _san(s):
    return "".join(ch if ch.isalnum() else "_" for ch in str(s))[:60]


def packet_flow_mermaid(db, version=None):
    L = ["flowchart LR"]
    rows = db.q("""SELECT a.label AS action, c.command_key AS cmd, c.direction AS dir, c.obs_count AS n
                   FROM gameplay_actions a
                   JOIN relationships r ON r.src_type='action' AND r.src_id=a.id AND r.dst_type='command'
                   JOIN commands c ON c.id=r.dst_id """ + ("WHERE c.version=?" if version else ""),
                (version,) if version else ())
    seen = set()
    for r in rows:
        a, cmd = _san(r["action"]), _san(r["cmd"])
        if a not in seen:
            L.append(f'  A_{a}["{r["action"]}"]'); seen.add(a)
        L.append(f'  A_{a} -->|{r["n"]}x| C_{cmd}["{r["cmd"]}"]')
    if len(L) == 1:
        L.append("  empty[No captured actions yet]")
    return "\n".join(L)


def opcode_relationships_dot(db, version=None):
    L = ["digraph opcodes {", '  rankdir=LR; node[shape=box,fontsize=10];']
    rows = db.q("SELECT command_key, category, request_cmd_id, obs_count, confidence_grade FROM commands "
                + ("WHERE version=?" if version else ""), (version,) if version else ())
    cats = {}
    for r in rows:
        cats.setdefault(r["category"] or "uncategorised", []).append(r)
    for cat, cmds in cats.items():
        L.append(f'  subgraph "cluster_{_san(cat)}" {{ label="{cat}"; color=grey;')
        for c in cmds:
            lbl = c["command_key"] + (f"\\n{c['request_cmd_id']}" if c["request_cmd_id"] else "")
            L.append(f'    "{c["command_key"]}" [label="{lbl}\\n({c["confidence_grade"] or "?"}, {c["obs_count"]}x)"];')
        L.append("  }")
    L.append("}")
    return "\n".join(L)


def class_relationships_mermaid(db, version=None, limit=60):
    L = ["flowchart TD"]
    rows = db.q("SELECT namespace, name, role FROM classes "
                + ("WHERE version=? " if version else "") +
                "ORDER BY confidence DESC LIMIT ?", ((version, limit) if version else (limit,)))
    by_ns = {}
    for r in rows:
        by_ns.setdefault(r["namespace"] or "(global)", []).append(r)
    for ns, cls in by_ns.items():
        nsid = _san(ns)
        L.append(f'  subgraph {nsid}["{ns}"]')
        for c in cls:
            L.append(f'    {nsid}_{_san(c["name"])}["{c["name"]}<br/>{c["role"]}"]')
        L.append("  end")
    if len(L) == 1:
        L.append("  empty[No classes imported]")
    return "\n".join(L)


def schema_evolution_mermaid(db, command_key=None):
    L = ["timeline", "  title Schema/confidence evolution"]
    sql = ("SELECT ch.ts, ch.entity_type, ch.grade, ch.reason FROM confidence_history ch "
           "ORDER BY ch.ts LIMIT 200")
    rows = db.q(sql)
    if not rows:
        return "timeline\n  title Schema evolution\n  none : no history yet"
    by_day = {}
    for r in rows:
        day = (r["ts"] or "")[:10]
        by_day.setdefault(day, []).append(f'{r["entity_type"]}:{r["grade"]}')
    for day, evs in by_day.items():
        uniq = list(dict.fromkeys(evs))[:6]
        L.append(f'  {day} : ' + " : ".join(uniq))
    return "\n".join(L)


def write_all(db, outdir, version=None):
    os.makedirs(outdir, exist_ok=True)
    files = {
        "packet_flow.mmd": packet_flow_mermaid(db, version),
        "opcode_relationships.dot": opcode_relationships_dot(db, version),
        "class_relationships.mmd": class_relationships_mermaid(db, version),
        "schema_evolution.mmd": schema_evolution_mermaid(db),
    }
    for name, content in files.items():
        with open(os.path.join(outdir, name), "w", encoding="utf-8") as f:
            f.write(content + "\n")
    return list(files.keys())
