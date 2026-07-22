"""
kb/search.py — query engine (read-only). Canned queries for the Objective-7
questions plus a guarded generic SELECT runner. Never mutates the DB.
"""
import re


def packets_during_action(db, label):
    """Which packets/commands are sent during e.g. 'building' upgrades?"""
    return [dict(r) for r in db.q("""
        SELECT DISTINCT c.command_key, c.method, c.opcode, c.direction, c.category,
               c.request_cmd_id, c.obs_count, c.confidence_grade
        FROM gameplay_actions a
        JOIN relationships r ON r.src_type='action' AND r.src_id=a.id AND r.dst_type='command'
        JOIN commands c ON c.id=r.dst_id
        WHERE a.label LIKE ? ORDER BY c.obs_count DESC""", (f"%{label}%",))]


def cmdid_for_category(db, category):
    """Which RequestCmdID / commands belong to e.g. Alliance?"""
    return [dict(r) for r in db.q("""
        SELECT command_key, method, opcode, request_cmd_id, category, obs_count, confidence_grade
        FROM commands WHERE category LIKE ? OR request_cmd_id LIKE ? ORDER BY obs_count DESC""",
        (f"%{category}%", f"%{category}%"))]


def packets_using_field(db, field):
    """Show every command/schema using field e.g. #17."""
    return [dict(r) for r in db.q("""
        SELECT c.command_key, c.method, sf.field, sf.types, sf.confidence, sf.present_in, sf.of_samples
        FROM schema_fields sf
        JOIN schemas s ON s.id=sf.schema_id
        JOIN commands c ON c.id=s.command_id
        WHERE sf.field=? ORDER BY sf.of_samples DESC""", (field,))]


def classes_serializing(db, category):
    """Which classes serialize e.g. March requests?"""
    return [dict(r) for r in db.q("""
        SELECT DISTINCT cl.assembly, cl.namespace, cl.name, cl.role, cl.confidence
        FROM classes cl
        WHERE (cl.role LIKE ? OR cl.category LIKE ?)
           OR cl.id IN (SELECT dst_id FROM relationships WHERE dst_type='class' AND relation='serialized_by')
        ORDER BY cl.confidence DESC LIMIT 200""", (f"%{category}%", f"%{category}%"))]


def schema_changed_between(db, v1, v2):
    from vantage.kb import versions
    return versions.diff(db, v1, v2)["schema_changes"]


def command_detail(db, command_key, version=None):
    args = [command_key]
    sql = "SELECT * FROM commands WHERE command_key=?"
    if version:
        sql += " AND version=?"; args.append(version)
    cmd = db.q1(sql, tuple(args))
    if not cmd:
        return None
    cmd = dict(cmd)
    s = db.q1("SELECT id, samples, overall_confidence FROM schemas WHERE command_id=?", (cmd["id"],))
    if s:
        cmd["schema"] = {"samples": s["samples"], "overall_confidence": s["overall_confidence"],
                         "fields": [dict(r) for r in db.q("SELECT field,types,present_in,of_samples,optional,confidence "
                                                          "FROM schema_fields WHERE schema_id=? ORDER BY field", (s["id"],))]}
    cmd["packets"] = [dict(r) for r in db.q("SELECT direction,payload_shape,obs_count,payload_len_min,payload_len_max "
                                            "FROM packets WHERE command_id=?", (cmd["id"],))]
    return cmd


_SELECT = re.compile(r"^\s*select\b", re.I)


def run_sql(db, sql):
    """Guarded generic query — SELECT only (read-only)."""
    if not _SELECT.match(sql) or ";" in sql.rstrip().rstrip(";"):
        raise ValueError("only a single read-only SELECT is permitted")
    return [dict(r) for r in db.q(sql)]


CANNED = {
    "packets-during": (packets_during_action, ["label"]),
    "cmdid-for": (cmdid_for_category, ["category"]),
    "field": (packets_using_field, ["field"]),
    "classes-serializing": (classes_serializing, ["category"]),
    "command": (command_detail, ["command_key"]),
}
