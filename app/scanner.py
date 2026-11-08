"""Scan pipeline: discover (Nmap) -> fingerprint -> match CVEs -> apply rules -> store."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import traceback
import xml.etree.ElementTree as ET
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import ipaddress

from . import auth_scan, db, default_creds, intel, notify, rules

MAX_CVES_PER_SERVICE = 15
CANCELLED = set()
PROCS = {}

TCP_SCRIPTS = "ssl-enum-ciphers,smb-security-mode,smb2-security-mode,smb-protocols,ftp-anon,http-title"

PROFILES = {
    "quick": "Top 100 ports, service versions. A few minutes.",
    "standard": "Top 1000 ports, versions, OS, SMB/TLS/FTP checks, SNMP. Recommended.",
    "deep": "Ports 1-10000, versions, OS, all checks. Slow on large ranges.",
}


class Cancelled(Exception):
    pass


def is_privileged():
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def nmap_path():
    return shutil.which("nmap")


def build_passes(profile, privileged):
    tcp = ["-sS" if privileged else "-sT", "-T4", "-sV", "--open", "--stats-every", "3s"]
    if profile == "quick":
        tcp += ["--top-ports", "100", "--version-light"]
    else:
        tcp += ["--script", TCP_SCRIPTS, "--script-timeout", "45s"]
        tcp += ["--top-ports", "1000"] if profile == "standard" else ["-p", "1-10000"]
        if privileged:
            tcp += ["-O", "--osscan-limit"]
    passes = [("TCP", tcp)]
    if profile != "quick" and privileged:
        passes.append(("UDP", ["-sU", "-T4", "-p", "69,161,1900", "--open", "--script", "snmp-info",
                               "--stats-every", "3s"]))
    return passes


def _classify(osclass_type, os_name, vendor):
    t = (osclass_type or "").lower()
    names = {"router": "Router", "switch": "Switch", "wap": "Access point", "firewall": "Firewall",
             "printer": "Printer", "storage-misc": "Storage", "webcam": "Camera", "phone": "Phone",
             "voip phone": "Phone", "general purpose": "Computer", "bridge": "Bridge", "media device": "Media device",
             "game console": "Game console", "power-device": "Power device", "specialized": "Specialized"}
    if t in names:
        return names[t]
    v = (vendor or "").lower()
    if any(k in v for k in ("ubiquiti", "ruckus", "aruba", "tp-link", "netgear", "mikrotik", "cisco", "juniper")):
        return "Network device"
    return "Unknown"


def parse_xml(path):
    hosts = []
    for h in ET.parse(path).getroot().findall("host"):
        st = h.find("status")
        if st is None or st.get("state") != "up":
            continue
        ip = mac = vendor = None
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                ip = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac, vendor = a.get("addr"), a.get("vendor")
        hn = h.find("hostnames/hostname")
        os_name, acc, otype = None, 0, None
        os_cpes = []
        matches = h.findall("os/osmatch")
        if matches:
            best = max(matches, key=lambda m: int(m.get("accuracy", 0)))
            os_name, acc = best.get("name"), int(best.get("accuracy", 0))
            oc = best.find("osclass")
            otype = oc.get("type") if oc is not None else None
            if oc is not None:
                os_cpes = [c.text for c in oc.findall("cpe") if c.text]
        ports = []
        for p in h.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            ports.append(dict(
                port=int(p.get("portid")), proto=p.get("protocol"),
                service=svc.get("name") if svc is not None else None,
                product=svc.get("product") if svc is not None else None,
                version=svc.get("version") if svc is not None else None,
                extrainfo=svc.get("extrainfo") if svc is not None else None,
                cpe=[c.text for c in svc.findall("cpe")] if svc is not None else [],
                scripts={s.get("id"): s.get("output") for s in p.findall("script")}))
        hostscripts = {s.get("id"): s.get("output") for s in h.findall("hostscript/script")}
        hosts.append(dict(ip=ip, mac=mac, vendor=vendor, hostname=hn.get("name") if hn is not None else None,
                          os_name=os_name, os_accuracy=acc, os_cpes=os_cpes,
                          device_type=_classify(otype, os_name, vendor), ports=ports, hostscripts=hostscripts))
    return hosts


def _run_pass(scan_id, label, args, targets, lo, hi):
    exe = nmap_path()
    if not exe:
        raise RuntimeError("Nmap was not found. Install it from https://nmap.org/download and make sure 'nmap' is on your PATH.")
    out = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
    out.close()
    cmd = [exe, *args, "-oX", out.name, *targets]
    db.log(scan_id, f"{label} pass: {' '.join(cmd[:1] + args[:6])} ...")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    PROCS[scan_id] = proc
    for line in proc.stdout:
        if scan_id in CANCELLED:
            proc.terminate()
            raise Cancelled()
        m = re.search(r"About (\d+(?:\.\d+)?)% done", line)
        if m:
            db.update_scan(scan_id, progress=round(lo + (hi - lo) * float(m.group(1)) / 100, 3),
                           message=f"{label} scan {float(m.group(1)):.0f}%")
        elif "QUITTING" in line or "requires root" in line.lower():
            db.log(scan_id, line.strip())
    proc.wait()
    PROCS.pop(scan_id, None)
    if scan_id in CANCELLED:
        raise Cancelled()
    if proc.returncode != 0 and (not os.path.getsize(out.name)):
        raise RuntimeError(f"Nmap exited with code {proc.returncode}. Run the app as administrator/root for full scans.")
    try:
        return parse_xml(out.name)
    finally:
        os.unlink(out.name)


def discover(scan_id, targets, profile):
    priv = is_privileged()
    if not priv:
        db.log(scan_id, "Not running as administrator/root: using TCP connect scan, no OS detection, no UDP/SNMP checks.")
    passes = build_passes(profile, priv)
    merged = {}
    span = 0.55 / len(passes)
    for i, (label, args) in enumerate(passes):
        for h in _run_pass(scan_id, label, args, targets, 0.02 + i * span, 0.02 + (i + 1) * span):
            cur = merged.setdefault(h["ip"], h)
            if cur is not h:
                seen = {(p["port"], p["proto"]) for p in cur["ports"]}
                cur["ports"] += [p for p in h["ports"] if (p["port"], p["proto"]) not in seen]
                cur["hostscripts"].update(h["hostscripts"])
                for k in ("mac", "vendor", "hostname", "os_name", "os_cpes"):
                    cur[k] = cur[k] or h[k]
    return list(merged.values())


CRIT_BONUS = {"critical_asset": 1.5, "high": 0.5, "normal": 0, "low": -0.5}


def _cred_for(ip, cred_rules):
    for rule in cred_rules or []:
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(rule["cidr"], strict=False):
                return rule
        except ValueError:
            continue
    return None


def run_authenticated(scan_id, hosts, cred_rules):
    """Runs SSH/WinRM checks for hosts that match a supplied credential rule. Mutates nothing;
    returns {ip: (findings, error_or_None, protocol)}."""
    out = {}
    if not cred_rules:
        return out
    for i, h in enumerate(hosts):
        rule = _cred_for(h["ip"], cred_rules)
        if not rule:
            continue
        db.update_scan(scan_id, message=f"Authenticated check {i + 1}: {h['ip']} over {rule['protocol'].upper()}")
        try:
            if rule["protocol"] == "ssh":
                findings, err = auth_scan.ssh_audit(h["ip"], rule.get("port"), rule["username"],
                                                    rule.get("password"), rule.get("key_path"), rule.get("key_passphrase"))
            elif rule["protocol"] == "winrm":
                findings, err = auth_scan.winrm_audit(h["ip"], rule["username"], rule.get("password"),
                                                      rule.get("use_ssl", False), rule.get("port"))
            else:
                findings, err = [], f"Unknown protocol '{rule['protocol']}'"
        except Exception as e:
            findings, err = [], f"Unexpected error during authenticated check: {e}"
        if err:
            db.log(scan_id, f"Authenticated check on {h['ip']} ({rule['protocol']}): {err}")
            findings = [rules.mk("misconfiguration", "info", "Authenticated check could not run",
                                 f"Tried to log in over {rule['protocol'].upper()} to run deeper checks: {err}",
                                 "Verify the credential, that the service is enabled, and that this host is reachable "
                                 "on the management network.", confidence="high", risk=0.0)]
        out[h["ip"]] = (findings, err, rule["protocol"])
    return out


def previous_scan_id(scan_id):
    rows = db.q("SELECT id FROM scans WHERE status='done' AND id<? ORDER BY id DESC LIMIT 1", (scan_id,))
    return rows[0]["id"] if rows else None


def diff_scans(old_id, new_id):
    """New/resolved devices and findings between two completed scans, keyed for a human-readable summary."""
    old_hosts = {h["ip"] for h in db.q("SELECT ip FROM hosts WHERE scan_id=?", (old_id,))}
    new_hosts = {h["ip"] for h in db.q("SELECT ip FROM hosts WHERE scan_id=?", (new_id,))}
    key = lambda f: (f["ip"], f["title"])
    old_f = {key(f) for f in db.q("SELECT ip,title FROM findings WHERE scan_id=?", (old_id,))}
    new_f = db.q("SELECT ip,title,severity FROM findings WHERE scan_id=?", (new_id,))
    new_f_keys = {key(f) for f in new_f}
    old_f_full = db.q("SELECT ip,title,severity FROM findings WHERE scan_id=?", (old_id,))
    return dict(
        new_devices=sorted(new_hosts - old_hosts), removed_devices=sorted(old_hosts - new_hosts),
        new_findings=[f for f in new_f if key(f) in (new_f_keys - old_f)],
        resolved_findings=[f for f in old_f_full if key(f) not in new_f_keys])


def run_default_cred_checks(scan_id, hosts):
    out = {}
    for i, h in enumerate(hosts):
        if scan_id in CANCELLED:
            raise Cancelled()
        relevant = [p for p in h["ports"] if p["port"] in default_creds.CHECKERS]
        if not relevant:
            continue
        db.update_scan(scan_id, message=f"Default-credential check {i + 1}: {h['ip']} ({len(relevant)} service(s))")
        try:
            found = default_creds.run(h)
        except Exception as e:
            db.log(scan_id, f"Default-credential check on {h['ip']} failed: {e}")
            found = []
        if found:
            out[h["ip"]] = found
            db.log(scan_id, f"Default credential found on {h['ip']}: {found[0]['title']}")
    return out


def process(scan_id, hosts, nvd_key=None, skip_cve=False, cred_rules=None, test_defaults=False):
    """Analyze discovered hosts and store hosts + findings. Returns summary dict."""
    iocs = rules.load_iocs()
    auth_results = run_authenticated(scan_id, hosts, cred_rules)
    if test_defaults:
        n_services = sum(1 for h in hosts for p in h["ports"] if p["port"] in default_creds.CHECKERS)
        db.log(scan_id, f"Testing default credentials on {n_services} service(s). This is slow by design "
                        "(rate-limited) and may take several minutes.")
        default_results = run_default_cred_checks(scan_id, hosts)
    else:
        default_results = {}
    kev, warnings = set(), []
    cpe_jobs = {}  # cpe23 -> list of (ip, port_or_None) it came from
    for h in hosts:
        for p in h["ports"]:
            for c in p.get("cpe", []):
                c23 = intel.cpe22_to_23(c)
                if c23:
                    cpe_jobs.setdefault(c23, []).append((h["ip"], p["port"]))
        for c in h.get("os_cpes") or []:
            c23 = intel.cpe22_to_23(c)
            if c23:
                cpe_jobs.setdefault(c23, []).append((h["ip"], None))
    cve_by_cpe = {}
    if cpe_jobs and not skip_cve:
        try:
            kev = intel.get_kev()
        except Exception as e:
            warnings.append(f"Could not download the CISA KEV catalog ({e}). KEV flags unavailable.")
        workers = 5 if nvd_key else 1  # NVD allows 50 req/30s with a key, 5 req/30s without
        eta = "" if nvd_key else f" (about {int(len(cpe_jobs) * 6.5)}s without an NVD API key)"
        db.log(scan_id, f"Looking up CVEs for {len(cpe_jobs)} distinct service/OS versions{eta}")
        done = [0]

        def _lookup(cpe):
            if scan_id in CANCELLED:
                raise Cancelled()
            try:
                return cpe, intel.nvd_lookup(cpe, nvd_key), None
            except Exception as e:
                return cpe, None, str(e)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for cpe, result, err in pool.map(_lookup, cpe_jobs):
                done[0] += 1
                db.update_scan(scan_id, progress=round(0.6 + 0.3 * done[0] / len(cpe_jobs), 3),
                               message=f"CVE lookup {done[0]}/{len(cpe_jobs)}: {cpe.split(':')[4]} {cpe.split(':')[5]}")
                if err:
                    warnings.append(f"NVD lookup failed for {cpe} ({err})")
                else:
                    cve_by_cpe[cpe] = result
        epss = intel.epss_scores([c["id"] for v in cve_by_cpe.values() for c in v])
    else:
        epss = {}
        if skip_cve:
            db.log(scan_id, "CVE lookup skipped (offline mode).")
    for w in warnings:
        db.log(scan_id, "Warning: " + w)

    def cve_findings(c23, banner, fix_target, port=None, proto=None):
        cves = cve_by_cpe.get(c23) or []
        if not cves:
            return []
        out = []
        ranked = sorted(cves, key=lambda v: intel.risk_score(v["cvss"], epss.get(v["id"]), v["id"] in kev), reverse=True)
        for v in ranked[:MAX_CVES_PER_SERVICE]:
            is_kev, e = v["id"] in kev, epss.get(v["id"])
            unscored = v["cvss"] is None
            desc = v["description"]
            if unscored:
                desc = desc + " — " + intel.nvd_status_note(v.get("vuln_status"))
            out.append(rules.mk(
                "patch_management", intel.severity_from_cvss(v["cvss"], is_kev),
                f"{v['id']}: {banner}" + (" (unscored by NVD)" if unscored else ""), desc,
                f"Update {fix_target} to a release that fixes {v['id']}. "
                "Distribution packages often backport fixes without changing the version number, so verify with your package manager first.",
                port, proto, f"{port}/{proto} {banner}" if port else banner, intel.attack_for_cve(v["id"], v["description"]),
                cve=v["id"], cvss=v["cvss"], epss=e, kev=is_kev, confidence="low" if unscored else "medium",
                refs=[f"https://nvd.nist.gov/vuln/detail/{v['id']}"], risk=intel.risk_score(v["cvss"], e, is_kev)))
        extra = len(ranked) - MAX_CVES_PER_SERVICE
        if extra > 0:
            out.append(rules.mk("patch_management", "info", f"{extra} more CVEs match {banner}",
                                "Only the highest-risk CVEs per service are listed individually.",
                                f"Update {fix_target}; this clears the remaining CVEs as well.",
                                port, proto, banner, [], confidence="medium"))
        return out

    db.update_scan(scan_id, progress=0.92, message="Applying rules and storing results")
    assets = {a["ip"]: a for a in db.q("SELECT * FROM assets")}
    all_findings = []
    for h in hosts:
        found = rules.analyze_host(h, iocs)
        if h["ip"] in auth_results:
            found += auth_results[h["ip"]][0]
        if h["ip"] in default_results:
            found += default_results[h["ip"]]
        for p in h["ports"]:
            for c in p.get("cpe", []):
                c23 = intel.cpe22_to_23(c)
                if c23:
                    banner = " ".join(x for x in (p.get("product"), p.get("version")) if x) or c
                    found += cve_findings(c23, banner, p.get("product") or "the software", p["port"], p["proto"])
        for c in h.get("os_cpes") or []:
            c23 = intel.cpe22_to_23(c)
            if c23:
                found += cve_findings(c23, h.get("os_name") or c, "the operating system/firmware")
        crit = assets.get(h["ip"], {}).get("criticality", "normal")
        risk = round(min(10.0, rules.host_risk(found) + CRIT_BONUS.get(crit, 0)), 1) if found else 0.0
        hid = db.x("INSERT INTO hosts(scan_id,ip,mac,vendor,hostname,os_name,os_accuracy,device_type,ports,risk) "
                   "VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (scan_id, h["ip"], h["mac"], h["vendor"], h["hostname"], h["os_name"], h["os_accuracy"],
                    h["device_type"], json.dumps([{k: v for k, v in p.items() if k != "scripts"} for p in h["ports"]]),
                    risk))
        for f in found:
            f["ip"] = h["ip"]
            db.x("INSERT INTO findings(scan_id,host_id,ip,category,severity,title,description,evidence,port,proto,cve,"
                 "cvss,epss,kev,risk,attack,remediation,confidence,refs) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 (scan_id, hid, h["ip"], f["category"], f["severity"], f["title"], f["description"], f["evidence"],
                  f["port"], f["proto"], f["cve"], f["cvss"], f["epss"], int(f["kev"]), f["risk"],
                  json.dumps(f["attack"]), f["remediation"], f["confidence"], json.dumps(f["refs"])))
        all_findings += found
    authenticated_hosts = sum(1 for v in auth_results.values() if v[1] is None)
    auth_errors = sum(1 for v in auth_results.values() if v[1] is not None)
    prev = previous_scan_id(scan_id)
    diff = diff_scans(prev, scan_id) if prev else None
    return dict(hosts=len(hosts), findings=len(all_findings),
                by_severity=dict(Counter(f["severity"] for f in all_findings)),
                by_category=dict(Counter(f["category"] for f in all_findings)),
                kev=sum(1 for f in all_findings if f["kev"]), warnings=warnings,
                authenticated_hosts=authenticated_hosts, auth_errors=auth_errors,
                compared_to_scan=prev, diff=diff)


def maybe_alert(scan_id, summary):
    """Sends a Slack/email alert if configured via environment variables and the scan is serious enough.
    Controlled by: NETAUDIT_SLACK_WEBHOOK, NETAUDIT_ALERT_MIN_SEVERITY (default 'high'),
    and for email: NETAUDIT_SMTP_HOST/PORT/USER/PASSWORD/TO."""
    min_sev = os.environ.get("NETAUDIT_ALERT_MIN_SEVERITY", "high")
    if not notify.should_alert(summary, min_sev):
        return
    scan = db.q("SELECT id,target,profile FROM scans WHERE id=?", (scan_id,))[0]
    text = notify.summarize(scan, summary)
    hook = os.environ.get("NETAUDIT_SLACK_WEBHOOK")
    if hook:
        err = notify.send_slack(hook, text)
        db.log(scan_id, "Slack alert sent" if not err else f"Slack alert failed: {err}")
    to_addr = os.environ.get("NETAUDIT_SMTP_TO")
    if to_addr:
        err = notify.send_email(os.environ.get("NETAUDIT_SMTP_HOST", ""), int(os.environ.get("NETAUDIT_SMTP_PORT", "587")),
                                os.environ.get("NETAUDIT_SMTP_USER", ""), os.environ.get("NETAUDIT_SMTP_PASSWORD", ""),
                                to_addr, f"NetAudit alert: scan #{scan_id} on {scan['target']}", text)
        db.log(scan_id, "Email alert sent" if not err else f"Email alert failed: {err}")


def run_scan(scan_id, targets, profile, nvd_key=None, skip_cve=False, cred_rules=None, test_defaults=False):
    try:
        db.update_scan(scan_id, status="running", progress=0.01, message="Starting")
        hosts = discover(scan_id, targets, profile)
        db.log(scan_id, f"Found {len(hosts)} live device(s)")
        summary = process(scan_id, hosts, nvd_key, skip_cve, cred_rules, test_defaults)
        db.update_scan(scan_id, status="done", progress=1.0, finished=time.time(), summary=json.dumps(summary),
                       message=f"Done: {summary['findings']} findings on {summary['hosts']} devices")
        maybe_alert(scan_id, summary)
    except Cancelled:
        db.update_scan(scan_id, status="cancelled", finished=time.time(), message="Cancelled")
    except Exception as e:
        db.log(scan_id, traceback.format_exc(limit=3))
        db.update_scan(scan_id, status="error", finished=time.time(), message=str(e))
    finally:
        CANCELLED.discard(scan_id)
        PROCS.pop(scan_id, None)
