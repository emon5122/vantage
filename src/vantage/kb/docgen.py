"""
kb/docgen.py — regenerate documentation from the KB after every import:
protocol.md, opcode_reference.md, schema_reference.md, request_lifecycle.md,
class_diagram.mmd, network_diagram.mmd, CHANGELOG.md.
Every value is sourced from the DB; nothing is invented.
"""
import json
import os

from vantage.kb import graphs


def _framing(db, version):
    raw = db.get_meta(f"framing:{version}") or db.get_meta("framing:unknown")
    return json.loads(raw) if raw else {}


def protocol_md(db, version):
    fr = _framing(db, version)
    cmds = db.q("SELECT COUNT(*) n FROM commands WHERE version=?", (version,))[0]["n"]
    pk = db.q("SELECT COUNT(*) n, COALESCE(SUM(obs_count),0) o FROM packets WHERE version=?", (version,))[0]
    L = [f"# FPNN protocol — knowledge base view (version `{version}`)\n",
         "_Auto-generated from the observation KB. Every field is evidence-graded; "
         "nothing is guessed._\n",
         f"- commands learned: **{cmds}**  ·  distinct packets: **{pk['n']}**  ·  observations: **{pk['o']}**\n",
         "## Framing (grade shown)"]
    if fr:
        L.append(f"- transport: `{fr.get('transport',{}).get('value','?')}` ({fr.get('transport',{}).get('confidence','?')})")
        L.append(f"- encoding: `{fr.get('encoding',{}).get('value','?')}` ({fr.get('encoding',{}).get('confidence','?')})")
        L.append("- header:")
        for h in fr.get("header", []):
            L.append(f"  - +{h['offset']} [{h['size']}] `{h['field']}` — {h.get('note','')} _({h.get('confidence')})_")
    else:
        L.append("- (import protocol.json to populate framing)")
    L.append("\n## Commands (top by observation)")
    L.append("| command | cmdid | category | dir | conf | obs | rtt_med_ms | heartbeat_s |")
    L.append("|---|---|---|---|---|---|---|---|")
    for r in db.q("SELECT * FROM commands WHERE version=? ORDER BY obs_count DESC LIMIT 100", (version,)):
        L.append(f"| `{r['command_key']}` | {r['request_cmd_id'] or ''} | {r['category'] or ''} | "
                 f"{r['direction'] or ''} | {r['confidence_grade'] or '?'} | {r['obs_count']} | "
                 f"{r['rtt_med_ms'] if r['rtt_med_ms'] is not None else ''} | "
                 f"{r['heartbeat_s'] if r['heartbeat_s'] is not None else ''} |")
    return "\n".join(L) + "\n"


def opcode_reference_md(db, version):
    L = [f"# Opcode / command reference (`{version}`)\n",
         "| command_key | opcode | RequestCmdID | managed_class | category | dir | confidence | first_seen | last_seen |",
         "|---|---|---|---|---|---|---|---|---|"]
    for r in db.q("SELECT * FROM commands WHERE version=? ORDER BY category, command_key", (version,)):
        L.append(f"| `{r['command_key']}` | {r['opcode'] if r['opcode'] is not None else ''} | "
                 f"{r['request_cmd_id'] or ''} | {r['managed_class'] or ''} | {r['category'] or ''} | "
                 f"{r['direction'] or ''} | {r['confidence_grade'] or '?'} ({r['confidence']:.2f}) | "
                 f"{r['first_seen'] or ''} | {r['last_seen'] or ''} |")
    if len(L) == 3:
        L.append("| _(no commands yet — run capture.py then import)_ | | | | | | | | |")
    return "\n".join(L) + "\n"


def schema_reference_md(db, version):
    L = [f"# Schema reference (`{version}`)\n",
         "_Field confidence: **Verified** (all samples, stable type, ≥3) · **Likely** · **Unknown**._\n"]
    rows = db.q("""SELECT c.command_key AS ck, s.id AS sid, s.samples, s.overall_confidence
                   FROM schemas s JOIN commands c ON c.id=s.command_id WHERE s.version=?
                   ORDER BY s.samples DESC""", (version,))
    if not rows:
        L.append("_(no schemas yet)_")
        return "\n".join(L) + "\n"
    for r in rows:
        L.append(f"## `{r['ck']}` — {r['samples']} samples ({r['overall_confidence']})")
        L.append("| field | type(s) | present | optional | confidence |")
        L.append("|---|---|---|---|---|")
        for f in db.q("SELECT * FROM schema_fields WHERE schema_id=? ORDER BY field", (r["sid"],)):
            types = ",".join(json.loads(f["types"] or "{}").keys())
            L.append(f"| `{f['field']}` | {types} | {f['present_in']}/{f['of_samples']} | "
                     f"{'yes' if f['optional'] else 'no'} | {f['confidence']} |")
        L.append("")
    return "\n".join(L) + "\n"


def request_lifecycle_md(db, version):
    L = [f"# Request lifecycle (`{version}`)\n",
         "```mermaid", "sequenceDiagram", "  participant C as Client", "  participant S as Gateway"]
    pairs = db.q("""SELECT c.command_key ck, AVG(rp.rtt_ms) rtt, COUNT(*) n
                    FROM responses rp JOIN commands c ON c.id=rp.command_id
                    WHERE c.version=? GROUP BY c.command_key ORDER BY n DESC LIMIT 12""", (version,))
    if not pairs:
        L.append("  C->>S: (no request/response pairs captured yet)")
    for p in pairs:
        L.append(f"  C->>S: {p['ck']}  (n={p['n']})")
        L.append(f"  S-->>C: answer  (~{(p['rtt'] or 0):.1f} ms)")
    L.append("```")
    return "\n".join(L) + "\n"


def network_diagram_md(db, version):
    L = [f"# Network map (`{version}`)\n", "```mermaid", "flowchart LR", "  App[Client]"]
    for r in db.q("SELECT DISTINCT peer_ip, peer_port, transport FROM connections"):
        if r["peer_ip"]:
            L.append(f'  App -->|{r["transport"]}| N_{r["peer_port"]}["{r["peer_ip"]}:{r["peer_port"]}"]')
    L.append("```")
    return "\n".join(L) + "\n"


def changelog_md(db):
    L = ["# KB change log\n", "_Confidence upgrades over time (append-only provenance)._\n",
         "| ts | entity | grade | source | reason |", "|---|---|---|---|---|"]
    for r in db.q("SELECT * FROM confidence_history ORDER BY id DESC LIMIT 200"):
        L.append(f"| {r['ts']} | {r['entity_type']}#{r['entity_id']} | {r['grade']} | "
                 f"{r['source']} | {r['reason']} |")
    return "\n".join(L) + "\n"


def regenerate(db, outdir, version):
    os.makedirs(outdir, exist_ok=True)
    docs = {
        "protocol.md": protocol_md(db, version),
        "opcode_reference.md": opcode_reference_md(db, version),
        "schema_reference.md": schema_reference_md(db, version),
        "request_lifecycle.md": request_lifecycle_md(db, version),
        "network_diagram.md": network_diagram_md(db, version),
        "CHANGELOG.md": changelog_md(db),
    }
    for name, content in docs.items():
        with open(os.path.join(outdir, name), "w", encoding="utf-8") as f:
            f.write(content)
    graphs.write_all(db, os.path.join(outdir, "diagrams"), version)
    return list(docs.keys())
