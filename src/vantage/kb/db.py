"""
kb/db.py — SQLite connection, migration, and upsert helpers for the KB.
Tuned for scale: WAL, big cache, batched writes via transactions.
"""
import os
import sqlite3
import time
import hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA = os.path.join(HERE, "schema.sql")


def now():
    # wall-clock ISO; avoids importing datetime.now inconsistencies
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha1(*parts):
    h = hashlib.sha1()
    for p in parts:
        h.update(str(p).encode("utf-8", "replace"))
    return h.hexdigest()


class DB:
    def __init__(self, path):
        self.path = path
        new = not os.path.exists(path)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self.conn.execute("PRAGMA cache_size=-64000;")
        self.conn.execute("PRAGMA foreign_keys=ON;")
        self.init_schema()
        if new:
            self.set_meta("created_at", now())
        self.set_meta("schema_version", "1")

    def init_schema(self):
        with open(SCHEMA, encoding="utf-8") as f:
            self.conn.executescript(f.read())
        self.conn.commit()

    # --- meta ---
    def set_meta(self, k, v):
        self.conn.execute("INSERT INTO meta(key,value) VALUES(?,?) "
                          "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, str(v)))

    def get_meta(self, k, default=None):
        r = self.conn.execute("SELECT value FROM meta WHERE key=?", (k,)).fetchone()
        return r["value"] if r else default

    # --- generic ---
    def q(self, sql, args=()):
        return self.conn.execute(sql, args).fetchall()

    def q1(self, sql, args=()):
        return self.conn.execute(sql, args).fetchone()

    def ex(self, sql, args=()):
        return self.conn.execute(sql, args)

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.commit()
        self.conn.close()

    def track_version(self, version):
        if not version:
            return
        self.ex("INSERT INTO versions(version,first_seen,last_seen) VALUES(?,?,?) "
                "ON CONFLICT(version) DO UPDATE SET last_seen=excluded.last_seen",
                (version, now(), now()))

    # --- confidence helper: update an entity's score + journal ---
    def bump_confidence(self, entity_type, entity_id, new_grade, count=1,
                        source="import", version=None, field=None,
                        score_col="confidence", grade_col="confidence_grade",
                        table=None):
        from vantage.kb import confidence as C
        table = table or (entity_type + "s")
        row = self.q1(f"SELECT {score_col} AS s, {grade_col} AS g FROM {table} WHERE id=?", (entity_id,))
        old_s = row["s"] if row else 0.0
        old_g = row["g"] if row else None
        m = C.merge(old_s, old_g, new_grade, count, source)
        if m["changed"]:
            self.ex(f"UPDATE {table} SET {score_col}=?, {grade_col}=? WHERE id=?",
                    (m["score"], m["grade"], entity_id))
        self.ex("INSERT INTO confidence_history(entity_type,entity_id,field,old_score,new_score,"
                "grade,source,version,ts,reason,obs_count) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (entity_type, entity_id, field, old_s, m["score"], m["grade"], source,
                 version, now(), m["reason"], count))
        return m

    def add_relationship(self, src_type, src_id, dst_type, dst_id, relation, evidence=None, version=None):
        self.ex("INSERT INTO relationships(src_type,src_id,dst_type,dst_id,relation,evidence,version,obs_count) "
                "VALUES(?,?,?,?,?,?,?,1) ON CONFLICT(src_type,src_id,dst_type,dst_id,relation) "
                "DO UPDATE SET obs_count=obs_count+1",
                (src_type, src_id, dst_type, dst_id, relation, evidence, version))


def open_db(path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    return DB(path)
