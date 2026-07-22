-- the target application Protocol Knowledge Base — SQLite schema (observation-derived only).
-- Designed to scale to millions of frames: raw frames collapse to deduplicated
-- packet fingerprints with observation counts; hot columns are indexed.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS versions (
  id         INTEGER PRIMARY KEY,
  version    TEXT UNIQUE NOT NULL,
  first_seen TEXT,
  last_seen  TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  id           INTEGER PRIMARY KEY,
  source_dir   TEXT UNIQUE NOT NULL,
  content_hash TEXT,
  label        TEXT,
  package      TEXT,
  version      TEXT,
  imported_at  TEXT,
  frames       INTEGER DEFAULT 0,
  notes        TEXT
);

CREATE TABLE IF NOT EXISTS connections (
  id          INTEGER PRIMARY KEY,
  session_id  INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
  fd          INTEGER,
  peer_ip     TEXT,
  peer_port   INTEGER,
  transport   TEXT,
  tls         INTEGER,
  open_ts     REAL,
  close_ts    REAL,
  lifetime_ms REAL,
  UNIQUE(session_id, fd, open_ts)
);

CREATE TABLE IF NOT EXISTS gameplay_actions (
  id           INTEGER PRIMARY KEY,
  label        TEXT NOT NULL,
  version      TEXT,
  session_id   INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
  first_seen   TEXT,
  last_seen    TEXT,
  packet_count INTEGER DEFAULT 0,
  UNIQUE(label, session_id)
);

CREATE TABLE IF NOT EXISTS commands (
  id              INTEGER PRIMARY KEY,
  version         TEXT NOT NULL,
  command_key     TEXT NOT NULL,          -- method:login | op:12345 | anon:answer
  method          TEXT,
  opcode          INTEGER,
  request_cmd_id  TEXT,                    -- NetEase.RequestCmdID name if linked
  category        TEXT,                    -- Login/Alliance/... (from action/classification)
  managed_class   TEXT,
  calling_method  TEXT,
  direction       TEXT,                    -- tx | rx | both
  mtype           TEXT,
  encoding        TEXT,
  obs_count       INTEGER DEFAULT 0,
  rtt_min_ms      REAL, rtt_med_ms REAL, rtt_max_ms REAL,
  heartbeat_s     REAL,
  first_seen      TEXT,
  last_seen       TEXT,
  confidence      REAL DEFAULT 0,
  confidence_grade TEXT,
  UNIQUE(version, command_key)
);
CREATE INDEX IF NOT EXISTS ix_commands_cat     ON commands(category);
CREATE INDEX IF NOT EXISTS ix_commands_cmdid   ON commands(request_cmd_id);
CREATE INDEX IF NOT EXISTS ix_commands_opcode  ON commands(opcode);

CREATE TABLE IF NOT EXISTS packets (
  id             INTEGER PRIMARY KEY,
  version        TEXT,
  command_id     INTEGER REFERENCES commands(id) ON DELETE CASCADE,
  fingerprint    TEXT UNIQUE NOT NULL,     -- version|command|dir|mtype|shape
  direction      TEXT,
  mtype          INTEGER,
  method         TEXT,
  status         INTEGER,
  payload_shape  TEXT,
  sample_payload TEXT,
  payload_len_min INTEGER,
  payload_len_max INTEGER,
  obs_count      INTEGER DEFAULT 0,
  first_seen     TEXT,
  last_seen      TEXT
);
CREATE INDEX IF NOT EXISTS ix_packets_cmd ON packets(command_id);

-- sampled request/response instances (capped per command/session) for lifecycle+timing
CREATE TABLE IF NOT EXISTS requests (
  id          INTEGER PRIMARY KEY,
  session_id  INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
  command_id  INTEGER REFERENCES commands(id) ON DELETE CASCADE,
  seq         INTEGER,
  ts          REAL,
  payload_len INTEGER
);
CREATE INDEX IF NOT EXISTS ix_requests_cmd ON requests(command_id);

CREATE TABLE IF NOT EXISTS responses (
  id          INTEGER PRIMARY KEY,
  request_id  INTEGER REFERENCES requests(id) ON DELETE CASCADE,
  command_id  INTEGER REFERENCES commands(id) ON DELETE CASCADE,
  seq         INTEGER,
  status      INTEGER,
  rtt_ms      REAL,
  payload_len INTEGER,
  ts          REAL
);
CREATE INDEX IF NOT EXISTS ix_responses_cmd ON responses(command_id);

CREATE TABLE IF NOT EXISTS schemas (
  id                 INTEGER PRIMARY KEY,
  command_id         INTEGER UNIQUE REFERENCES commands(id) ON DELETE CASCADE,
  version            TEXT,
  samples            INTEGER DEFAULT 0,
  overall_confidence TEXT,
  updated_at         TEXT
);

CREATE TABLE IF NOT EXISTS schema_fields (
  id          INTEGER PRIMARY KEY,
  schema_id   INTEGER REFERENCES schemas(id) ON DELETE CASCADE,
  field       TEXT NOT NULL,               -- "#1" for int keys, else str key
  types       TEXT,                        -- JSON {type: count}
  present_in  INTEGER DEFAULT 0,
  of_samples  INTEGER DEFAULT 0,
  optional    INTEGER DEFAULT 1,
  type_stable INTEGER DEFAULT 0,
  confidence  TEXT,                        -- Verified | Likely | Unknown
  first_seen  TEXT,
  last_seen   TEXT,
  UNIQUE(schema_id, field)
);
CREATE INDEX IF NOT EXISTS ix_fields_field ON schema_fields(field);

CREATE TABLE IF NOT EXISTS unknown_fields (
  id          INTEGER PRIMARY KEY,
  command_id  INTEGER REFERENCES commands(id) ON DELETE CASCADE,
  field       TEXT,
  reason      TEXT,
  version     TEXT,
  first_seen  TEXT,
  last_seen   TEXT,
  UNIQUE(command_id, field)
);

CREATE TABLE IF NOT EXISTS classes (
  id           INTEGER PRIMARY KEY,
  version      TEXT NOT NULL,
  assembly     TEXT,
  namespace    TEXT,
  name         TEXT NOT NULL,
  role         TEXT,
  category     TEXT,
  confidence   REAL,
  tier         TEXT,
  verified     TEXT,
  method_count INTEGER,
  reasons      TEXT,
  first_seen   TEXT,
  last_seen    TEXT,
  UNIQUE(version, assembly, namespace, name)
);
CREATE INDEX IF NOT EXISTS ix_classes_role ON classes(role);
CREATE INDEX IF NOT EXISTS ix_classes_name ON classes(name);

CREATE TABLE IF NOT EXISTS methods (
  id          INTEGER PRIMARY KEY,
  class_id    INTEGER REFERENCES classes(id) ON DELETE CASCADE,
  name        TEXT,
  params      INTEGER,
  return_type TEXT,
  param_types TEXT,
  rva         TEXT,
  flags       INTEGER,
  UNIQUE(class_id, name, params)
);

CREATE TABLE IF NOT EXISTS strings (
  id         INTEGER PRIMARY KEY,
  version    TEXT,
  value      TEXT,
  via        TEXT,
  obs_count  INTEGER DEFAULT 1,
  first_seen TEXT,
  last_seen  TEXT,
  UNIQUE(version, value)
);

CREATE TABLE IF NOT EXISTS assets (
  id         INTEGER PRIMARY KEY,
  version    TEXT,
  bundle     TEXT,
  path       TEXT,
  kind       TEXT,
  obs_count  INTEGER DEFAULT 1,
  first_seen TEXT,
  last_seen  TEXT,
  UNIQUE(version, bundle)
);

-- append-only provenance: never overwrite stronger evidence
CREATE TABLE IF NOT EXISTS confidence_history (
  id          INTEGER PRIMARY KEY,
  entity_type TEXT,      -- command | schema_field | class | string | ...
  entity_id   INTEGER,
  field       TEXT,
  old_score   REAL,
  new_score   REAL,
  grade       TEXT,
  source      TEXT,      -- capture | protocol.json | classifier | request_map | ...
  version     TEXT,
  ts          TEXT,
  reason      TEXT,
  obs_count   INTEGER
);
CREATE INDEX IF NOT EXISTS ix_conf_entity ON confidence_history(entity_type, entity_id);

CREATE TABLE IF NOT EXISTS relationships (
  id       INTEGER PRIMARY KEY,
  src_type TEXT, src_id INTEGER,
  dst_type TEXT, dst_id INTEGER,
  relation TEXT,
  evidence TEXT,
  version  TEXT,
  obs_count INTEGER DEFAULT 1,
  UNIQUE(src_type, src_id, dst_type, dst_id, relation)
);
CREATE INDEX IF NOT EXISTS ix_rel_src ON relationships(src_type, src_id);
CREATE INDEX IF NOT EXISTS ix_rel_dst ON relationships(dst_type, dst_id);
