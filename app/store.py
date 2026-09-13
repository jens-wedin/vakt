"""SQLite persistence: known devices, events, Protect device states, meta."""
import sqlite3
from datetime import datetime, timezone

import config

_conn: sqlite3.Connection | None = None


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
          mac TEXT PRIMARY KEY,
          name TEXT,
          first_seen TEXT,
          last_seen TEXT,
          last_network TEXT,
          last_ip TEXT,
          is_wired INTEGER
        );
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT,
          kind TEXT,
          severity TEXT,      -- info | warning | critical
          mac TEXT,
          message TEXT
        );
        CREATE TABLE IF NOT EXISTS protect_devices (
          id TEXT PRIMARY KEY,
          kind TEXT,
          name TEXT,
          state TEXT,
          last_change TEXT
        );
        CREATE TABLE IF NOT EXISTS config_objects (
          collection TEXT,
          obj_id TEXT,
          name TEXT,
          data TEXT,           -- normalized canonical JSON (secrets hashed)
          PRIMARY KEY (collection, obj_id)
        );
        CREATE TABLE IF NOT EXISTS meta (
          key TEXT PRIMARY KEY,
          value TEXT
        );
        """)
        _ensure_columns(_conn, "devices", {
            "ewma_up": "REAL DEFAULT 0",        # learned upload baseline, bytes/s
            "samples": "INTEGER DEFAULT 0",
            "last_rx_bytes": "INTEGER",
            "last_tx_bytes": "INTEGER",
            "last_counter_ts": "REAL",
            "high_since": "REAL",
            "last_traffic_alert": "REAL",
        })
        _ensure_columns(_conn, "events", {"acked": "INTEGER DEFAULT 0"})
        _conn.commit()
    return _conn


def _ensure_columns(conn: sqlite3.Connection, table: str, cols: dict[str, str]):
    have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    for name, decl in cols.items():
        if name not in have:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def get_meta(key: str) -> str | None:
    row = db().execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def set_meta(key: str, value: str):
    db().execute("INSERT INTO meta(key,value) VALUES(?,?) "
                 "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
    db().commit()


def get_devices() -> dict[str, sqlite3.Row]:
    return {r["mac"]: r for r in db().execute("SELECT * FROM devices")}


def upsert_device(mac, name, network, ip, is_wired, seen):
    db().execute("""
      INSERT INTO devices(mac,name,first_seen,last_seen,last_network,last_ip,is_wired)
      VALUES(?,?,?,?,?,?,?)
      ON CONFLICT(mac) DO UPDATE SET
        name=excluded.name, last_seen=excluded.last_seen,
        last_network=excluded.last_network, last_ip=excluded.last_ip,
        is_wired=excluded.is_wired
    """, (mac, name, seen, seen, network, ip, 1 if is_wired else 0))
    db().commit()


def update_device_fields(mac, **fields):
    # column names are code-controlled, never user input
    cols = ", ".join(f"{k}=?" for k in fields)
    db().execute(f"UPDATE devices SET {cols} WHERE mac=?", (*fields.values(), mac))
    db().commit()


def ack_event(event_id: int):
    db().execute("UPDATE events SET acked=1 WHERE id=?", (event_id,))
    db().commit()


def add_event(kind, severity, mac, message) -> dict:
    ts = now_iso()
    db().execute("INSERT INTO events(ts,kind,severity,mac,message) VALUES(?,?,?,?,?)",
                 (ts, kind, severity, mac, message))
    db().commit()
    return {"ts": ts, "kind": kind, "severity": severity, "mac": mac, "message": message}


def recent_events(limit=100) -> list[sqlite3.Row]:
    return list(db().execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)))


def get_protect_devices() -> dict[str, sqlite3.Row]:
    return {r["id"]: r for r in db().execute("SELECT * FROM protect_devices")}


def get_config_objects() -> dict[tuple[str, str], sqlite3.Row]:
    return {(r["collection"], r["obj_id"]): r
            for r in db().execute("SELECT * FROM config_objects")}


def upsert_config_object(collection, obj_id, name, data):
    db().execute("""
      INSERT INTO config_objects(collection,obj_id,name,data) VALUES(?,?,?,?)
      ON CONFLICT(collection,obj_id) DO UPDATE SET
        name=excluded.name, data=excluded.data
    """, (collection, obj_id, name, data))
    db().commit()


def delete_config_object(collection, obj_id):
    db().execute("DELETE FROM config_objects WHERE collection=? AND obj_id=?",
                 (collection, obj_id))
    db().commit()


def upsert_protect_device(id, kind, name, state):
    db().execute("""
      INSERT INTO protect_devices(id,kind,name,state,last_change) VALUES(?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET
        kind=excluded.kind, name=excluded.name, state=excluded.state,
        last_change=excluded.last_change
    """, (id, kind, name, state, now_iso()))
    db().commit()
