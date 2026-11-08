"""SQLite storage: scans, hosts, findings and an API cache."""
import json, os, sqlite3, time
from contextlib import closing

DB_PATH = os.environ.get("NETAUDIT_DB", os.path.join(os.path.dirname(__file__), "..", "data", "netaudit.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY, target TEXT, profile TEXT, status TEXT, progress REAL DEFAULT 0,
  message TEXT, started REAL, finished REAL, summary TEXT, log TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS hosts(
  id INTEGER PRIMARY KEY, scan_id INTEGER, ip TEXT, mac TEXT, vendor TEXT, hostname TEXT,
  os_name TEXT, os_accuracy INTEGER, device_type TEXT, ports TEXT, risk REAL DEFAULT 0);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY, scan_id INTEGER, host_id INTEGER, ip TEXT, category TEXT, severity TEXT,
  title TEXT, description TEXT, evidence TEXT, port INTEGER, proto TEXT, cve TEXT, cvss REAL,
  epss REAL, kev INTEGER DEFAULT 0, risk REAL, attack TEXT, remediation TEXT, confidence TEXT, refs TEXT);
CREATE INDEX IF NOT EXISTS f_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS h_scan ON hosts(scan_id);
CREATE TABLE IF NOT EXISTS cache(key TEXT PRIMARY KEY, value TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS assets(
  ip TEXT PRIMARY KEY, label TEXT, criticality TEXT DEFAULT 'normal', notes TEXT, approved INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS dismissals(
  id INTEGER PRIMARY KEY, ip TEXT, title TEXT, reason TEXT, note TEXT, created REAL,
  UNIQUE(ip, title));
"""

def conn():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    return c

def init():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    with closing(conn()) as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)
        # A scan can only be "running"/"queued" while this process is alive to update it, so any
        # row still in that state at startup is left over from a previous run that was killed or
        # crashed mid-scan (Ctrl+C, a restart, a power loss). Mark it failed instead of leaving it
        # looking active forever, which would otherwise grey out "Run audit" permanently.
        c.execute("UPDATE scans SET status='error', message='Interrupted (app was restarted during this scan)', "
                  "finished=? WHERE status IN ('running','queued')", (time.time(),))
        c.commit()

def q(sql, args=()):
    with closing(conn()) as c:
        return [dict(r) for r in c.execute(sql, args).fetchall()]

def x(sql, args=()):
    with closing(conn()) as c:
        cur = c.execute(sql, args)
        c.commit()
        return cur.lastrowid

def update_scan(scan_id, **kw):
    cols = ", ".join(f"{k}=?" for k in kw)
    x(f"UPDATE scans SET {cols} WHERE id=?", (*kw.values(), scan_id))

def log(scan_id, msg):
    stamp = time.strftime("%H:%M:%S")
    x("UPDATE scans SET message=?, log=log||? WHERE id=?", (msg, f"[{stamp}] {msg}\n", scan_id))

def cache_get(key, ttl):
    r = q("SELECT value, ts FROM cache WHERE key=?", (key,))
    if r and time.time() - r[0]["ts"] < ttl:
        return json.loads(r[0]["value"])
    return None

def cache_put(key, value):
    x("INSERT OR REPLACE INTO cache(key,value,ts) VALUES(?,?,?)", (key, json.dumps(value), time.time()))
