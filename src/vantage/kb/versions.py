"""
kb/versions.py — multi-version comparison + migration reports.
Detects new/removed opcodes, changed schemas, new/removed classes, new endpoints.
"""
import json


def _commands(db, version):
    return {r["command_key"]: dict(r) for r in db.q("SELECT * FROM commands WHERE version=?", (version,))}


def _classes(db, version):
    return {f"{r['namespace']}.{r['name']}": dict(r)
            for r in db.q("SELECT * FROM classes WHERE version=?", (version,))}


def _schema_fields(db, command_id):
    return {r["field"]: dict(r) for r in db.q(
        "SELECT sf.* FROM schema_fields sf JOIN schemas s ON s.id=sf.schema_id WHERE s.command_id=?", (command_id,))}


def _endpoints(db, version):
    return {r["value"] for r in db.q(
        "SELECT value FROM strings WHERE version=? AND (value LIKE 'http%' OR value LIKE 'wss%' "
        "OR value LIKE '%.com%' OR value LIKE '%.net%' OR value LIKE '%.cn%')", (version,))}


def diff(db, v1, v2):
    c1, c2 = _commands(db, v1), _commands(db, v2)
    k1, k2 = set(c1), set(c2)
    new_ops = sorted(k2 - k1)
    removed_ops = sorted(k1 - k2)

    schema_changes = []
    for ck in sorted(k1 & k2):
        f1 = _schema_fields(db, c1[ck]["id"])
        f2 = _schema_fields(db, c2[ck]["id"])
        added = sorted(set(f2) - set(f1))
        removed = sorted(set(f1) - set(f2))
        retyped = []
        for f in set(f1) & set(f2):
            t1 = set(json.loads(f1[f]["types"] or "{}"))
            t2 = set(json.loads(f2[f]["types"] or "{}"))
            if t1 and t2 and t1 != t2:
                retyped.append({"field": f, "from": sorted(t1), "to": sorted(t2)})
        if added or removed or retyped:
            schema_changes.append({"command": ck, "added_fields": added, "removed_fields": removed, "retyped": retyped})

    cl1, cl2 = _classes(db, v1), _classes(db, v2)
    new_classes = sorted(set(cl2) - set(cl1))
    removed_classes = sorted(set(cl1) - set(cl2))

    e1, e2 = _endpoints(db, v1), _endpoints(db, v2)
    new_endpoints = sorted(e2 - e1)

    return {
        "from": v1, "to": v2,
        "new_opcodes": new_ops, "removed_opcodes": removed_ops,
        "schema_changes": schema_changes,
        "new_classes": new_classes, "removed_classes": removed_classes,
        "new_endpoints": new_endpoints,
        "summary": {
            "new_opcodes": len(new_ops), "removed_opcodes": len(removed_ops),
            "changed_schemas": len(schema_changes),
            "new_classes": len(new_classes), "removed_classes": len(removed_classes),
            "new_endpoints": len(new_endpoints),
        },
    }


def migration_report_md(d):
    L = [f"# Migration report: {d['from']} → {d['to']}\n", f"Summary: `{d['summary']}`\n"]
    L.append("## New opcodes/commands")
    L += [f"- `{x}`" for x in d["new_opcodes"]] or ["- (none)"]
    L.append("\n## Removed opcodes/commands")
    L += [f"- `{x}`" for x in d["removed_opcodes"]] or ["- (none)"]
    L.append("\n## Schema changes")
    if not d["schema_changes"]:
        L.append("- (none)")
    for sc in d["schema_changes"]:
        L.append(f"- `{sc['command']}`: +{sc['added_fields']} −{sc['removed_fields']} retyped={sc['retyped']}")
    L.append("\n## Class changes")
    L.append(f"- new: {len(d['new_classes'])} · removed: {len(d['removed_classes'])}")
    for x in d["new_classes"][:50]:
        L.append(f"  - + `{x}`")
    L.append("\n## New endpoints")
    L += [f"- `{x}`" for x in d["new_endpoints"]] or ["- (none)"]
    return "\n".join(L) + "\n"
