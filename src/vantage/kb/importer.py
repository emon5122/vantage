"""
kb/importer.py — ingest observation artifacts into the KB with dedup + merge.

Supported inputs (auto-detected):
  capture session dir : frames.jsonl (+ connections.json)   -> commands/packets/schemas/timing/actions
  networking_classes.ranked.json                            -> classes
  types.json (Phase 4)                                      -> classes + methods
  protocol dir / protocol.json                              -> framing meta
  opcode_map.json / request_map.json / schemas/*.json       -> commands/schemas + cmdid links
  events.jsonl (Phase H strings / Phase G assets)           -> strings/assets

Dedup: re-importing an UNCHANGED session dir is a no-op (content-hash gate).
Every packet collapses to a fingerprint with an observation count; schemas merge
field-by-field with cross-session accumulation; confidence only ever strengthens.
"""
import json
import os
import sys
from collections import Counter, defaultdict

from vantage.kb.db import now, sha1

from vantage.protocol.schema import command_key, type_of, merge_fields
from vantage.protocol.correlate import correlate

SAMPLE_CAP = 200


# ---------- shape normalisation (drives packet fingerprints) ----------
def shape_of(tnode):
    if not isinstance(tnode, dict):
        return "?"
    t = tnode.get("t")
    if t == "map":
        fs = tnode.get("fields") or {}
        return "{" + ",".join(f"{k}:{shape_of(v)}" for k, v in sorted(fs.items(), key=lambda x: str(x[0]))) + "}"
    if t == "array":
        items = tnode.get("items") or []
        return "[" + (shape_of(items[0]) if items else "?") + "]"
    return type_of(tnode)


def norm_field(k):
    """Canonical field name: integer msgpack keys -> "#n" (matches payload JSON
    and the 'field #17' search); string keys kept as-is."""
    if isinstance(k, int):
        return f"#{k}"
    s = str(k)
    return f"#{s}" if s.isdigit() else s


def _read_jsonl(path):
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def _load_json(path, default=None):
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------- command learning ----------
def learn_command(db, version, ckey, method=None, opcode=None, mtype=None,
                  direction=None, category=None, encoding=None, source="capture", inc=1):
    db.track_version(version)
    row = db.q1("SELECT id, direction, obs_count FROM commands WHERE version=? AND command_key=?",
                (version, ckey))
    ts = now()
    if row is None:
        db.ex("INSERT INTO commands(version,command_key,method,opcode,mtype,direction,category,encoding,"
              "obs_count,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
              (version, ckey, method, opcode, mtype, direction, category, encoding, inc, ts, ts))
        cid = db.q1("SELECT id FROM commands WHERE version=? AND command_key=?", (version, ckey))["id"]
    else:
        cid = row["id"]
        newdir = row["direction"]
        if direction and row["direction"] and row["direction"] != direction:
            newdir = "both"
        elif direction:
            newdir = direction
        db.ex("UPDATE commands SET obs_count=obs_count+?, last_seen=?, direction=COALESCE(?,direction), "
              "method=COALESCE(method,?), opcode=COALESCE(opcode,?), mtype=COALESCE(mtype,?), "
              "category=COALESCE(category,?), encoding=COALESCE(encoding,?) WHERE id=?",
              (inc, ts, newdir, method, opcode, mtype, category, encoding, cid))
    grade = "observed" if source == "capture" else ("Verified" if source == "protocol.json" else "inferred")
    db.bump_confidence("command", cid, grade, count=inc, source=source, version=version)
    return cid


def upsert_packet(db, version, cid, direction, mtype, method, status, shape, sample, plen):
    fp = sha1(version, cid, direction, mtype, shape)
    ts = now()
    row = db.q1("SELECT id, payload_len_min, payload_len_max FROM packets WHERE fingerprint=?", (fp,))
    if row is None:
        db.ex("INSERT INTO packets(version,command_id,fingerprint,direction,mtype,method,status,payload_shape,"
              "sample_payload,payload_len_min,payload_len_max,obs_count,first_seen,last_seen) "
              "VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?,?)",
              (version, cid, fp, direction, mtype, method, status, shape,
               json.dumps(sample, ensure_ascii=False)[:4000] if sample is not None else None,
               plen, plen, ts, ts))
    else:
        lo = min(row["payload_len_min"] if row["payload_len_min"] is not None else plen, plen)
        hi = max(row["payload_len_max"] if row["payload_len_max"] is not None else plen, plen)
        db.ex("UPDATE packets SET obs_count=obs_count+1, last_seen=?, payload_len_min=?, payload_len_max=? WHERE id=?",
              (ts, lo, hi, row["id"]))


def merge_schema(db, cid, version, add_samples, field_stats):
    """field_stats: {field: {"types": Counter, "present": int}}; add_samples: frames merged."""
    ts = now()
    srow = db.q1("SELECT id, samples FROM schemas WHERE command_id=?", (cid,))
    if srow is None:
        db.ex("INSERT INTO schemas(command_id,version,samples,updated_at) VALUES(?,?,?,?)",
              (cid, version, add_samples, ts))
        sid = db.q1("SELECT id FROM schemas WHERE command_id=?", (cid,))["id"]
        total = add_samples
    else:
        sid = srow["id"]
        total = (srow["samples"] or 0) + add_samples
        db.ex("UPDATE schemas SET samples=?, updated_at=?, version=? WHERE id=?", (total, ts, version, sid))

    from vantage.kb import confidence as C
    verified_overall = True
    for field, st in field_stats.items():
        frow = db.q1("SELECT id, types, present_in FROM schema_fields WHERE schema_id=? AND field=?", (sid, field))
        types_new = Counter(st["types"])
        if frow is None:
            types = dict(types_new)
            present = st["present"]
            first = ts
        else:
            types = json.loads(frow["types"] or "{}")
            for k, v in types_new.items():
                types[k] = types.get(k, 0) + v
            present = (frow["present_in"] or 0) + st["present"]
            first = None
        type_stable = len(types) == 1
        optional = present < total
        conf = C.field_confidence(present, total, type_stable=type_stable)
        if conf != "Verified":
            verified_overall = False
        if frow is None:
            db.ex("INSERT INTO schema_fields(schema_id,field,types,present_in,of_samples,optional,"
                  "type_stable,confidence,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (sid, field, json.dumps(types), present, total, int(optional), int(type_stable), conf, first, ts))
        else:
            db.ex("UPDATE schema_fields SET types=?,present_in=?,of_samples=?,optional=?,type_stable=?,"
                  "confidence=?,last_seen=? WHERE id=?",
                  (json.dumps(types), present, total, int(optional), int(type_stable), conf, ts, frow["id"]))
        # unknown-field tracking
        if conf == "Unknown":
            db.ex("INSERT INTO unknown_fields(command_id,field,reason,version,first_seen,last_seen) "
                  "VALUES(?,?,?,?,?,?) ON CONFLICT(command_id,field) DO UPDATE SET last_seen=excluded.last_seen",
                  (cid, field, f"{present}/{total} samples", version, ts, ts))
        else:
            db.ex("DELETE FROM unknown_fields WHERE command_id=? AND field=?", (cid, field))
    overall = "Verified" if (verified_overall and total >= 3 and field_stats) else ("Likely" if total >= 2 else "Unknown")
    db.ex("UPDATE schemas SET overall_confidence=? WHERE id=?", (overall, sid))


# ---------- capture session ----------
def import_capture(db, session_dir, version="unknown", label=None):
    frames_path = os.path.join(session_dir, "frames.jsonl")
    conns_path = os.path.join(session_dir, "connections.json")
    if not os.path.exists(frames_path):
        return {"skipped": session_dir, "reason": "no frames.jsonl"}

    with open(frames_path, "rb") as f:
        raw = f.read()
    chash = sha1(raw, os.path.exists(conns_path) and open(conns_path, "rb").read() or b"")
    src = os.path.abspath(session_dir)
    existing = db.q1("SELECT id, content_hash FROM sessions WHERE source_dir=?", (src,))
    if existing and existing["content_hash"] == chash:
        return {"skipped": src, "reason": "unchanged (idempotent)"}

    conns = _load_json(conns_path, {}) or {}
    label = label or conns.get("label") or os.path.basename(session_dir.rstrip("/"))
    ts = now()
    db.track_version(version)
    if existing:
        sid = existing["id"]
        db.ex("UPDATE sessions SET content_hash=?, imported_at=?, label=?, version=? WHERE id=?",
              (chash, ts, label, version, sid))
    else:
        db.ex("INSERT INTO sessions(source_dir,content_hash,label,version,imported_at) VALUES(?,?,?,?,?)",
              (src, chash, label, version, ts))
        sid = db.q1("SELECT id FROM sessions WHERE source_dir=?", (src,))["id"]

    # connections
    for fd, c in (conns.get("connections") or {}).items():
        peer = c.get("peer") or {}
        db.ex("INSERT OR IGNORE INTO connections(session_id,fd,peer_ip,peer_port,transport,tls,open_ts,close_ts,lifetime_ms) "
              "VALUES(?,?,?,?,?,?,?,?,?)",
              (sid, int(fd) if str(fd).isdigit() else None, peer.get("ip"), peer.get("port"),
               "tcp", 0, c.get("open_ts"), c.get("close_ts"), c.get("lifetime_ms")))

    # frames -> commands/packets + per-command field accumulation
    frames = [fr for fr in _read_jsonl(frames_path) if "header" in fr]
    per_cmd_fields = defaultdict(lambda: {"samples": 0, "fields": defaultdict(lambda: {"types": Counter(), "present": 0}), "cid": None})
    cmd_ids = {}
    for fr in frames:
        ckey = command_key(fr)
        direction = fr.get("_dir")
        mt = fr["header"]["mtype"]
        method = fr.get("method")
        opcode = None
        if ckey.startswith("op:"):
            try:
                opcode = int(ckey.split(":", 1)[1])
            except ValueError:
                pass
        cid = cmd_ids.get(ckey)
        if cid is None:
            cid = learn_command(db, version, ckey, method=method, opcode=opcode, mtype=fr["header"]["mtype_name"],
                                direction=direction, category=(label if label else None),
                                encoding="messagepack" if fr["header"].get("flag_msgpack") else None, source="capture")
            cmd_ids[ckey] = cid
        else:
            learn_command(db, version, ckey, direction=direction, source="capture")
        # packet fingerprint
        tnode = fr.get("payload_types")
        shape = shape_of(tnode) if tnode else "(empty)"
        upsert_packet(db, version, cid, direction, mt, method,
                      fr.get("status"), shape, fr.get("payload"), fr.get("payload_len"))
        # field accumulation
        acc = per_cmd_fields[ckey]; acc["cid"] = cid
        if isinstance(tnode, dict) and tnode.get("t") == "map":
            acc["samples"] += 1
            for k, vt in (tnode.get("fields") or {}).items():
                fld = acc["fields"][norm_field(k)]
                fld["types"][type_of(vt)] += 1
                fld["present"] += 1

    # merge accumulated schemas
    for ckey, acc in per_cmd_fields.items():
        if acc["samples"] and acc["cid"]:
            merge_schema(db, acc["cid"], version, acc["samples"], acc["fields"])

    # correlation: timing + sampled requests/responses + heartbeats
    corr = correlate(frames)
    hb = {h["method"]: h for h in corr["heartbeats"]}
    rtt_by_cmd = defaultdict(list)
    for p in corr["pairs"]:
        ckey = f"method:{p['method']}" if p.get("method") else None
        if not ckey:
            continue
        cid = cmd_ids.get(ckey)
        if cid is None:
            continue
        rtt_by_cmd[cid].append(p["rtt_ms"])
        # sampled request+response
        cnt = db.q1("SELECT COUNT(*) c FROM requests WHERE command_id=? AND session_id=?", (cid, sid))["c"]
        if cnt < SAMPLE_CAP:
            db.ex("INSERT INTO requests(session_id,command_id,seq,ts,payload_len) VALUES(?,?,?,?,?)",
                  (sid, cid, p.get("seq"), p.get("ts"), p.get("req_len")))
            rid = db.q1("SELECT last_insert_rowid() id")["id"]
            db.ex("INSERT INTO responses(request_id,command_id,seq,status,rtt_ms,payload_len,ts) VALUES(?,?,?,?,?,?,?)",
                  (rid, cid, p.get("seq"), p.get("status"), p.get("rtt_ms"), p.get("resp_len"), p.get("ts")))
    for cid, rtts in rtt_by_cmd.items():
        rtts.sort()
        med = rtts[len(rtts) // 2]
        db.ex("UPDATE commands SET rtt_min_ms=?, rtt_med_ms=?, rtt_max_ms=? WHERE id=?",
              (round(min(rtts), 2), round(med, 2), round(max(rtts), 2), cid))
    for method, h in hb.items():
        ckey = f"method:{method}"
        cid = cmd_ids.get(ckey)
        if cid:
            db.ex("UPDATE commands SET heartbeat_s=? WHERE id=?", (h["interval_s_median"], cid))
            db.bump_confidence("command", cid, "observed", count=h["count"], source="capture", version=version)

    # gameplay action
    if label:
        db.ex("INSERT INTO gameplay_actions(label,version,session_id,first_seen,last_seen,packet_count) "
              "VALUES(?,?,?,?,?,?) ON CONFLICT(label,session_id) DO UPDATE SET last_seen=excluded.last_seen, "
              "packet_count=excluded.packet_count",
              (label, version, sid, ts, ts, len(frames)))
        arow = db.q1("SELECT id FROM gameplay_actions WHERE label=? AND session_id=?", (label, sid))
        for cid in cmd_ids.values():
            db.add_relationship("action", arow["id"], "command", cid, "observed_during", evidence=label, version=version)

    db.ex("UPDATE sessions SET frames=? WHERE id=?", (len(frames), sid))
    db.commit()
    return {"session": src, "label": label, "version": version, "frames": len(frames),
            "commands": len(cmd_ids), "pairs": corr["stats"].get("pairs"), "pushes": corr["stats"].get("pushes")}


# ---------- classes / types ----------
def import_classes_ranked(db, path, version="unknown"):
    data = _load_json(path, [])
    n = 0
    db.track_version(version)
    for c in data:
        asm, ns, name = c.get("assembly"), c.get("namespace"), c.get("class")
        ts = now()
        db.ex("INSERT INTO classes(version,assembly,namespace,name,role,category,confidence,tier,verified,reasons,first_seen,last_seen) "
              "VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(version,assembly,namespace,name) DO UPDATE SET "
              "last_seen=excluded.last_seen, role=COALESCE(classes.role,excluded.role)",
              (version, asm, ns, name, c.get("role"), c.get("role"), c.get("confidence"), c.get("tier"),
               c.get("verified"), json.dumps(c.get("reasons")), ts, ts))
        n += 1
    db.commit()
    return {"classes": n, "version": version}


def import_types(db, path, version="unknown"):
    data = _load_json(path, {})
    nc = nm = 0
    db.track_version(version)
    for asm, nss in data.items():
        for ns, classes in nss.items():
            for c in classes:
                name = c.get("class")
                ts = now()
                db.ex("INSERT INTO classes(version,assembly,namespace,name,role,category,confidence,tier,verified,method_count,first_seen,last_seen) "
                      "VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(version,assembly,namespace,name) DO UPDATE SET "
                      "method_count=excluded.method_count, verified=excluded.verified, last_seen=excluded.last_seen",
                      (version, asm, ns, name, c.get("role"), c.get("role"), c.get("confidence"), c.get("tier"),
                       c.get("verified"), c.get("method_count"), ts, ts))
                cid = db.q1("SELECT id FROM classes WHERE version=? AND assembly=? AND namespace=? AND name=?",
                            (version, asm, ns, name))["id"]
                nc += 1
                for m in (c.get("methods") or []):
                    db.ex("INSERT OR IGNORE INTO methods(class_id,name,params,return_type,param_types,rva) "
                          "VALUES(?,?,?,?,?,?)",
                          (cid, m.get("name"), m.get("params"), m.get("ret"),
                           json.dumps(m.get("param_types")), m.get("rva")))
                    nm += 1
    db.commit()
    return {"classes": nc, "methods": nm, "version": version}


# ---------- protocol artifacts ----------
def import_protocol(db, path, version="unknown"):
    pdir = path if os.path.isdir(path) else os.path.dirname(path)
    out = {"opcodes": 0, "schemas": 0, "cmdid_links": 0}
    proto = _load_json(os.path.join(pdir, "protocol.json"))
    if proto:
        db.set_meta(f"framing:{version}", json.dumps(proto.get("framing", {})))
        db.track_version(version)
    for ck, om in (_load_json(os.path.join(pdir, "opcode_map.json"), {}) or {}).items():
        cid = learn_command(db, version, ck, encoding=om.get("encoding"), source="protocol.json")
        out["opcodes"] += 1
    for ck, rm in (_load_json(os.path.join(pdir, "request_map.json"), {}) or {}).items():
        cid = learn_command(db, version, ck, source="protocol.json")
        db.ex("UPDATE commands SET request_cmd_id=COALESCE(?,request_cmd_id), managed_class=COALESCE(?,managed_class), "
              "calling_method=COALESCE(?,calling_method) WHERE id=?",
              (rm.get("request_cmd_id"), rm.get("managed_class"), rm.get("calling_method"), cid))
        if rm.get("managed_class"):
            cl = db.q1("SELECT id FROM classes WHERE name=? OR (namespace||'.'||name)=?",
                       (rm["managed_class"], rm["managed_class"]))
            if cl:
                db.add_relationship("command", cid, "class", cl["id"], "serialized_by", version=version)
                out["cmdid_links"] += 1
    schdir = os.path.join(pdir, "schemas")
    if os.path.isdir(schdir):
        for fn in os.listdir(schdir):
            if not fn.endswith(".json"):
                continue
            sc = _load_json(os.path.join(schdir, fn))
            if not sc:
                continue
            ck = sc.get("command")
            cid = learn_command(db, version, ck, source="protocol.json")
            fields = {}
            for fld in sc.get("fields", []):
                fields[norm_field(fld["field"])] = {"types": Counter(fld.get("types", {})), "present": fld.get("present_in", 0)}
            if fields:
                merge_schema(db, cid, version, sc.get("samples", 0), fields)
            out["schemas"] += 1
    db.commit()
    return out


# ---------- optional strings / assets from events.jsonl ----------
def import_events(db, path, version="unknown"):
    ns = na = 0
    for ev in _read_jsonl(path):
        e, d = ev.get("event"), ev.get("data", {})
        if e == "string" and d.get("value"):
            ts = now()
            db.ex("INSERT INTO strings(version,value,via,obs_count,first_seen,last_seen) VALUES(?,?,?,1,?,?) "
                  "ON CONFLICT(version,value) DO UPDATE SET obs_count=obs_count+1, last_seen=excluded.last_seen",
                  (version, d["value"][:500], d.get("via"), ts, ts))
            ns += 1
        elif e in ("bundle_file_open",) and d.get("bundle"):
            ts = now()
            db.ex("INSERT INTO assets(version,bundle,path,kind,obs_count,first_seen,last_seen) VALUES(?,?,?,?,1,?,?) "
                  "ON CONFLICT(version,bundle) DO UPDATE SET obs_count=obs_count+1, last_seen=excluded.last_seen",
                  (version, d["bundle"], d.get("path"), "assetbundle", ts, ts))
            na += 1
    db.commit()
    return {"strings": ns, "assets": na}


# ---------- auto dispatch ----------
def import_path(db, path, version="unknown", label=None):
    if os.path.isdir(path):
        if os.path.exists(os.path.join(path, "frames.jsonl")):
            return ("capture", import_capture(db, path, version, label))
        if os.path.exists(os.path.join(path, "protocol.json")) or os.path.isdir(os.path.join(path, "schemas")):
            return ("protocol", import_protocol(db, path, version))
        raise ValueError(f"unrecognised directory: {path}")
    base = os.path.basename(path)
    if base == "networking_classes.ranked.json":
        return ("classes", import_classes_ranked(db, path, version))
    if base == "types.json":
        return ("types", import_types(db, path, version))
    if base in ("protocol.json", "opcode_map.json", "request_map.json"):
        return ("protocol", import_protocol(db, path, version))
    if base == "frames.jsonl":
        return ("capture", import_capture(db, os.path.dirname(path), version, label))
    if base.endswith(".jsonl"):
        return ("events", import_events(db, path, version))
    raise ValueError(f"unrecognised file: {path}")
