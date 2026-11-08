"""FastAPI server: REST API + dashboard."""
import base64
import csv
import hmac
import io
import ipaddress
import json
import os
import socket
import subprocess
import threading
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import auth_scan, creds, db, report, rules, scanner


@asynccontextmanager
async def lifespan(_app):
    db.init()
    yield


app = FastAPI(title="NetAudit", lifespan=lifespan)
STATIC = os.path.join(os.path.dirname(__file__), "static")
ALLOW_PUBLIC = os.environ.get("NETAUDIT_ALLOW_PUBLIC") == "1"
MAX_ADDRESSES = 65536

BASIC_USER = os.environ.get("NETAUDIT_USER")
BASIC_PASS = os.environ.get("NETAUDIT_PASSWORD")


@app.middleware("http")
async def require_auth(request: Request, call_next):
    """HTTP Basic Auth, only when NETAUDIT_USER/NETAUDIT_PASSWORD are set. With neither set
    (the default), the app is unauthenticated and should only be bound to 127.0.0.1 (see run.py)."""
    if not (BASIC_USER and BASIC_PASS):
        return await call_next(request)
    header = request.headers.get("authorization", "")
    ok = False
    if header.startswith("Basic "):
        try:
            u, p = base64.b64decode(header[6:]).decode().split(":", 1)
            ok = hmac.compare_digest(u, BASIC_USER) and hmac.compare_digest(p, BASIC_PASS)
        except Exception:
            ok = False
    if not ok:
        return PlainTextResponse("Authentication required", status_code=401,
                                 headers={"WWW-Authenticate": 'Basic realm="NetAudit"'})
    return await call_next(request)


class CredRule(BaseModel):
    cidr: str
    protocol: str  # "ssh" | "winrm"
    username: str
    password: Optional[str] = None
    key_path: Optional[str] = None
    key_passphrase: Optional[str] = None
    port: Optional[int] = None
    use_ssl: bool = False
    saved_name: Optional[str] = None  # if set, load the secret from the vault instead of using the fields above


class ScanRequest(BaseModel):
    target: str
    profile: str = "standard"
    authorized: bool = False
    nvd_api_key: Optional[str] = None
    skip_cve: bool = False
    credentials: list[CredRule] = []
    test_default_credentials: bool = False


class SaveCredRequest(BaseModel):
    name: str
    protocol: str
    username: str
    password: Optional[str] = None
    key_path: Optional[str] = None
    key_passphrase: Optional[str] = None
    port: Optional[int] = None
    use_ssl: bool = False


class AssetRequest(BaseModel):
    ip: str
    label: Optional[str] = None
    criticality: str = "normal"  # critical_asset | high | normal | low
    notes: Optional[str] = None


class DismissRequest(BaseModel):
    ip: str
    title: str
    reason: str = "accepted_risk"  # accepted_risk | false_positive
    note: Optional[str] = None


def parse_targets(text):
    nets = []
    for tok in text.replace(",", " ").split():
        try:
            net = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            raise HTTPException(400, f"'{tok}' is not a valid IP address or CIDR range (example: 192.168.1.0/24).")
        if net.num_addresses > MAX_ADDRESSES:
            raise HTTPException(400, f"{tok} is too large (limit is a /16, {MAX_ADDRESSES} addresses).")
        if not ALLOW_PUBLIC and not (net.is_private or net.is_link_local):
            raise HTTPException(400, f"{tok} is a public range. Only private ranges are allowed by default. "
                                     "Set NETAUDIT_ALLOW_PUBLIC=1 if you are authorized to scan it.")
        nets.append(str(net))
    if not nets:
        raise HTTPException(400, "Enter at least one target.")
    return nets


def local_cidr():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return str(ipaddress.ip_network(ip + "/24", strict=False))
    except Exception:
        return "192.168.1.0/24"


@app.get("/api/info")
def info():
    exe = scanner.nmap_path()
    version = None
    if exe:
        try:
            version = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=10).stdout.splitlines()[0]
        except Exception:
            pass
    return dict(nmap=bool(exe), nmap_version=version, privileged=scanner.is_privileged(), local_cidr=local_cidr(),
                profiles=scanner.PROFILES, nvd_key_env=bool(os.environ.get("NVD_API_KEY")),
                categories=rules.CATEGORIES, allow_public=ALLOW_PUBLIC,
                ssh_available=auth_scan.paramiko is not None, winrm_available=auth_scan.winrm is not None,
                saved_credentials=creds.list_saved())


@app.post("/api/scans")
def start_scan(req: ScanRequest):
    if not req.authorized:
        raise HTTPException(400, "Confirm that you are authorized to scan this network.")
    if req.profile not in scanner.PROFILES:
        raise HTTPException(400, "Unknown scan profile.")
    if not scanner.nmap_path():
        raise HTTPException(400, "Nmap is not installed or not on PATH. Install it from https://nmap.org/download.")
    if any(r["status"] in ("queued", "running") for r in db.q("SELECT status FROM scans")):
        raise HTTPException(409, "An audit is already running. Wait for it to finish or cancel it.")
    targets = parse_targets(req.target)
    cred_rules = []
    for c in req.credentials:
        try:
            ipaddress.ip_network(c.cidr, strict=False)
        except ValueError:
            raise HTTPException(400, f"'{c.cidr}' in credentials is not a valid IP or CIDR range.")
        if c.protocol not in ("ssh", "winrm"):
            raise HTTPException(400, "Credential protocol must be 'ssh' or 'winrm'.")
        rule = c.dict()
        if c.saved_name:
            saved = creds.get(c.saved_name)
            if not saved:
                raise HTTPException(400, f"No saved credential named '{c.saved_name}'.")
            rule.update(saved)
        cred_rules.append(rule)
    sid = db.x("INSERT INTO scans(target,profile,status,progress,message,started) VALUES(?,?,?,?,?,?)",
               (" ".join(targets), req.profile, "queued", 0, "Queued", time.time()))
    key = req.nvd_api_key or os.environ.get("NVD_API_KEY")
    threading.Thread(target=scanner.run_scan,
                     args=(sid, targets, req.profile, key, req.skip_cve, cred_rules, req.test_default_credentials),
                     daemon=True).start()
    return {"id": sid}


# ---------------------------------------------------------------- credential vault

@app.get("/api/credentials")
def creds_list():
    return {"names": creds.list_saved()}


@app.post("/api/credentials")
def creds_save(req: SaveCredRequest):
    if req.protocol not in ("ssh", "winrm"):
        raise HTTPException(400, "Protocol must be 'ssh' or 'winrm'.")
    creds.save(req.name, {k: v for k, v in req.dict().items() if k != "name"})
    return {"ok": True}


@app.delete("/api/credentials/{name}")
def creds_delete(name: str):
    creds.delete(name)
    return {"ok": True}


# ---------------------------------------------------------------- assets & dismissals

@app.get("/api/assets")
def assets_list():
    return db.q("SELECT * FROM assets")


@app.put("/api/assets")
def assets_set(req: AssetRequest):
    if req.criticality not in ("critical_asset", "high", "normal", "low"):
        raise HTTPException(400, "criticality must be one of: critical_asset, high, normal, low")
    db.x("INSERT INTO assets(ip,label,criticality,notes) VALUES(?,?,?,?) "
         "ON CONFLICT(ip) DO UPDATE SET label=excluded.label, criticality=excluded.criticality, notes=excluded.notes",
         (req.ip, req.label, req.criticality, req.notes))
    return {"ok": True}


@app.get("/api/dismissals")
def dismissals_list():
    return db.q("SELECT * FROM dismissals ORDER BY created DESC")


@app.post("/api/dismissals")
def dismiss(req: DismissRequest):
    db.x("INSERT INTO dismissals(ip,title,reason,note,created) VALUES(?,?,?,?,?) "
         "ON CONFLICT(ip,title) DO UPDATE SET reason=excluded.reason, note=excluded.note, created=excluded.created",
         (req.ip, req.title, req.reason, req.note, time.time()))
    return {"ok": True}


@app.delete("/api/dismissals/{dismissal_id}")
def undismiss(dismissal_id: int):
    db.x("DELETE FROM dismissals WHERE id=?", (dismissal_id,))
    return {"ok": True}


@app.get("/api/scans")
def list_scans():
    rows = db.q("SELECT id,target,profile,status,progress,message,started,finished,summary FROM scans ORDER BY id DESC LIMIT 50")
    for r in rows:
        r["summary"] = json.loads(r["summary"]) if r["summary"] else None
    return rows


def _scan(sid):
    r = db.q("SELECT * FROM scans WHERE id=?", (sid,))
    if not r:
        raise HTTPException(404, "Scan not found")
    r = r[0]
    r["summary"] = json.loads(r["summary"]) if r["summary"] else None
    return r


@app.get("/api/scans/{sid}")
def get_scan(sid: int):
    r = _scan(sid)
    r["log"] = "\n".join(r["log"].splitlines()[-12:])
    return r


@app.post("/api/scans/{sid}/cancel")
def cancel(sid: int):
    _scan(sid)
    scanner.CANCELLED.add(sid)
    p = scanner.PROCS.get(sid)
    if p:
        p.terminate()
    return {"ok": True}


@app.delete("/api/scans/{sid}")
def delete(sid: int):
    r = _scan(sid)
    if r["status"] in ("queued", "running"):
        raise HTTPException(409, "Cancel the audit before deleting it.")
    for t in ("findings", "hosts"):
        db.x(f"DELETE FROM {t} WHERE scan_id=?", (sid,))
    db.x("DELETE FROM scans WHERE id=?", (sid,))
    return {"ok": True}


def _findings(sid, include_dismissed=True):
    rows = db.q("SELECT * FROM findings WHERE scan_id=?", (sid,))
    dismissed = {(d["ip"], d["title"]): d for d in db.q("SELECT * FROM dismissals")}
    for f in rows:
        f["attack"] = [dict(id=t, name=rules.ATTACK.get(t, ("", ""))[0], tactic=rules.ATTACK.get(t, ("", ""))[1])
                       for t in json.loads(f["attack"] or "[]")]
        f["refs"] = json.loads(f["refs"] or "[]")
        f["kev"] = bool(f["kev"])
        d = dismissed.get((f["ip"], f["title"]))
        f["dismissed"] = dict(reason=d["reason"], note=d["note"]) if d else None
    if not include_dismissed:
        rows = [f for f in rows if not f["dismissed"]]
    rows.sort(key=lambda f: (-rules.SEV_ORDER[f["severity"]], -(f["risk"] or 0)))
    return rows


@app.get("/api/scans/{sid}/findings")
def findings(sid: int):
    _scan(sid)
    return _findings(sid)


@app.get("/api/scans/{sid}/hosts")
def hosts(sid: int):
    _scan(sid)
    rows = db.q("SELECT * FROM hosts WHERE scan_id=? ORDER BY risk DESC, ip", (sid,))
    counts = {}
    for f in db.q("SELECT host_id, severity FROM findings WHERE scan_id=?", (sid,)):
        counts.setdefault(f["host_id"], {}).setdefault(f["severity"], 0)
        counts[f["host_id"]][f["severity"]] += 1
    assets = {a["ip"]: a for a in db.q("SELECT * FROM assets")}
    for h in rows:
        h["ports"] = json.loads(h["ports"] or "[]")
        h["counts"] = counts.get(h["id"], {})
        h["criticality"] = assets.get(h["ip"], {}).get("criticality", "normal")
        h["label"] = assets.get(h["ip"], {}).get("label")
    return rows


@app.get("/api/trends")
def trends(limit: int = 30):
    scans = db.q("SELECT id,target,profile,started,finished FROM scans WHERE status='done' ORDER BY id DESC LIMIT ?",
                 (limit,))
    scans.reverse()
    out = []
    for s in scans:
        sev = {r["severity"]: r["n"] for r in db.q(
            "SELECT severity, COUNT(*) n FROM findings WHERE scan_id=? GROUP BY severity", (s["id"],))}
        host_count, avg_risk = db.q("SELECT COUNT(*) n, COALESCE(AVG(risk),0) r FROM hosts WHERE scan_id=?",
                                    (s["id"],))[0].values()
        out.append(dict(scan_id=s["id"], finished=s["finished"], hosts=host_count, avg_risk=round(avg_risk, 1),
                        critical=sev.get("critical", 0), high=sev.get("high", 0), medium=sev.get("medium", 0),
                        low=sev.get("low", 0)))
    return out


@app.get("/api/scans/{sid}/attack")
def attack(sid: int):
    agg = {}
    for f in _findings(sid):
        for t in f["attack"]:
            a = agg.setdefault(t["id"], dict(id=t["id"], name=t["name"], tactic=t["tactic"], count=0, severity="info",
                                             hosts=set()))
            a["count"] += 1
            a["hosts"].add(f["ip"])
            if rules.SEV_ORDER[f["severity"]] > rules.SEV_ORDER[a["severity"]]:
                a["severity"] = f["severity"]
    out = [dict(a, hosts=sorted(a["hosts"])) for a in agg.values()]
    return sorted(out, key=lambda a: (-rules.SEV_ORDER[a["severity"]], -a["count"]))


@app.get("/api/scans/{sid}/attack-layer.json")
def attack_layer(sid: int):
    techs = attack(sid)
    layer = {"name": f"NetAudit scan {sid}", "versions": {"attack": "15", "navigator": "5.1.0", "layer": "4.5"},
             "domain": "enterprise-attack", "description": "Techniques observed in NetAudit findings",
             "gradient": {"colors": ["#ffe9a8", "#d4570e", "#a61b1b"], "minValue": 1, "maxValue": 4},
             "techniques": [dict(techniqueID=t["id"], score=rules.SEV_ORDER[t["severity"]],
                                 comment=f"{t['count']} finding(s) on {len(t['hosts'])} device(s)") for t in techs]}
    return Response(json.dumps(layer, indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="netaudit-{sid}-attack-layer.json"'})


@app.get("/api/scans/{sid}/export.csv")
def export_csv(sid: int):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "category", "device", "port", "title", "cve", "cvss", "epss", "kev", "risk", "confidence",
                "attack", "remediation", "evidence"])
    for f in _findings(sid):
        w.writerow([f["severity"], rules.CATEGORIES.get(f["category"], f["category"]), f["ip"],
                    f"{f['port']}/{f['proto']}" if f["port"] else "", f["title"], f["cve"] or "", f["cvss"] or "",
                    f["epss"] if f["epss"] is not None else "", "yes" if f["kev"] else "", f["risk"], f["confidence"],
                    " ".join(t["id"] for t in f["attack"]), f["remediation"], f["evidence"]])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="netaudit-{sid}.csv"'})


@app.get("/api/scans/{sid}/export.json")
def export_json(sid: int):
    data = dict(scan=_scan(sid), hosts=hosts(sid), findings=_findings(sid))
    data["scan"].pop("log", None)
    return Response(json.dumps(data, indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="netaudit-{sid}.json"'})


@app.get("/api/scans/{sid}/report.pdf")
def export_pdf(sid: int):
    scan = _scan(sid)
    pdf = report.generate(scan, hosts(sid), _findings(sid, include_dismissed=False))
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="netaudit-{sid}-report.pdf"'})


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


app.mount("/static", StaticFiles(directory=STATIC), name="static")
