"""Vulnerability intelligence: NVD (CVEs), CISA KEV (actively exploited), EPSS (exploit probability)."""
import json
import os
import re
import threading
import time

import requests

from . import db

HEADERS = {"User-Agent": "NetAudit/1.0"}
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
DAY = 86400

_nvd_lock = threading.Lock()
_last_nvd = 0.0


class IntelError(Exception):
    pass


def get_kev():
    """Set of CVE ids in the CISA Known Exploited Vulnerabilities catalog (cached 24h)."""
    cached = db.cache_get("kev", DAY)
    if cached is not None:
        return set(cached)
    r = requests.get(KEV_URL, headers=HEADERS, timeout=30)
    r.raise_for_status()
    ids = [v["cveID"] for v in r.json().get("vulnerabilities", [])]
    db.cache_put("kev", ids)
    return set(ids)


def cpe22_to_23(cpe):
    """Convert Nmap's CPE 2.2 URI to CPE 2.3, or None if there is no usable version."""
    m = re.match(r"cpe:/([aoh]):([^:]+):([^:]+):([^:]+)(?::([^:]+))?", cpe or "")
    if not m:
        return None
    part, vendor, product, version, update = m.groups()
    if not version or version in ("*", "-"):
        return None
    # NVD stores e.g. OpenSSH 7.2p2 as version 7.2, update p2
    p = re.match(r"^(\d+(?:\.\d+)*)(p\d+)$", version)
    if p:
        version, update = p.group(1), p.group(2)
    return f"cpe:2.3:{part}:{vendor}:{product}:{version}:{update or '*'}:*:*:*:*:*:*"


def _throttle(api_key):
    global _last_nvd
    gap = 0.7 if api_key else 6.5  # NVD public limit: 5 req/30s, with key 50 req/30s
    with _nvd_lock:
        wait = gap - (time.time() - _last_nvd)
        if wait > 0:
            time.sleep(wait)
        _last_nvd = time.time()


def nvd_lookup(cpe23, api_key=None):
    """CVEs affecting a CPE. Returns list of dicts (cached 7 days)."""
    key = "nvd:" + cpe23
    cached = db.cache_get(key, 7 * DAY)
    if cached is not None:
        return cached
    headers = dict(HEADERS)
    if api_key:
        headers["apiKey"] = api_key
    last = None
    for attempt in range(3):
        _throttle(api_key)
        try:
            r = requests.get(NVD_URL, params={"cpeName": cpe23, "isVulnerable": "", "resultsPerPage": 2000},
                             headers=headers, timeout=60)
            if r.status_code in (403, 429, 503):
                last = f"NVD returned {r.status_code}"
                time.sleep(10 * (attempt + 1))
                continue
            r.raise_for_status()
            break
        except requests.RequestException as e:
            last = str(e)
            time.sleep(3)
    else:
        raise IntelError(last or "NVD request failed")
    out = []
    for v in r.json().get("vulnerabilities", []):
        c = v["cve"]
        if c.get("vulnStatus") == "Rejected":
            continue
        desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
        score, vector = None, None
        for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if c.get("metrics", {}).get(k):
                d = c["metrics"][k][0]["cvssData"]
                score, vector = d.get("baseScore"), d.get("vectorString")
                break
        cwes = [w["value"] for p in c.get("weaknesses", []) for w in p.get("description", [])
                if w["value"].startswith("CWE-")]
        # Since April 2026 NVD only prioritizes enrichment (CVSS/CPE/CWE) for CVEs in CISA KEV or a
        # short "critical software" list; everything else can sit at vulnStatus "Awaiting Analysis" or
        # the newer "Not Scheduled" indefinitely, with score/vector left empty. We surface that status
        # rather than silently treating an unscored CVE as a confident medium severity.
        out.append(dict(id=c["id"], description=desc, cvss=score, vector=vector,
                        published=(c.get("published") or "")[:10], cwes=cwes,
                        vuln_status=c.get("vulnStatus")))
    db.cache_put(key, out)
    return out


def epss_scores(cve_ids):
    """EPSS probability (0-1) per CVE. Failures return what we have."""
    out, ids = {}, sorted(set(cve_ids))
    for i in range(0, len(ids), 80):
        chunk = ids[i:i + 80]
        cached = {c: db.cache_get("epss:" + c, DAY) for c in chunk}
        out.update({c: v for c, v in cached.items() if v is not None})
        todo = [c for c, v in cached.items() if v is None]
        if not todo:
            continue
        try:
            r = requests.get(EPSS_URL, params={"cve": ",".join(todo)}, headers=HEADERS, timeout=30)
            r.raise_for_status()
            for row in r.json().get("data", []):
                out[row["cve"]] = float(row["epss"])
                db.cache_put("epss:" + row["cve"], float(row["epss"]))
        except (requests.RequestException, ValueError, KeyError):
            pass
    return out


_CTID = None


def _ctid_map():
    """Optional: data/cve_attack_mapping.json {"CVE-2021-44228": ["T1190", ...]} (e.g. converted from the
    Center for Threat-Informed Defense 'Mapping ATT&CK to CVE for Impact' dataset)."""
    global _CTID
    if _CTID is None:
        path = os.path.join(os.path.dirname(__file__), "..", "data", "cve_attack_mapping.json")
        try:
            _CTID = json.load(open(path, encoding="utf-8"))
        except (OSError, ValueError):
            _CTID = {}
    return _CTID


def attack_for_cve(cve_id, description):
    """ATT&CK techniques for a CVE: CTID mapping if supplied, otherwise a keyword heuristic."""
    mapped = _ctid_map().get(cve_id)
    if mapped:
        return mapped
    d = description.lower()
    t = []
    if re.search(r"remote code execution|execute arbitrary (code|commands?)|arbitrary command", d):
        t += ["T1190", "T1210", "T1059"]
    if re.search(r"privilege", d) and re.search(r"escalat|elevat|gain", d):
        t.append("T1068")
    if re.search(r"denial of service|crash|infinite loop|resource exhaustion", d):
        t.append("T1499")
    if re.search(r"authentication bypass|bypass authentication|default credential|hard-?coded", d):
        t.append("T1078")
    if re.search(r"information disclosure|sensitive information|read arbitrary|memory disclosure", d):
        t.append("T1005")
    if re.search(r"man-in-the-middle", d):
        t.append("T1557")
    return t or ["T1190"]


def severity_from_cvss(score, kev=False):
    """kev=True means CISA lists this as actively exploited in the wild, which is independent of
    (and these days, often more current than) whether NVD has gotten around to scoring it. An
    unscored CVE that's under active exploitation is treated as seriously as a high/critical scored
    one, not watered down to "medium" just because a number is missing."""
    order = ["low", "medium", "high", "critical"]
    if score is None:
        sev = "high" if kev else "medium"
    elif score >= 9.0:
        sev = "critical"
    elif score >= 7.0:
        sev = "high"
    elif score >= 4.0:
        sev = "medium"
    else:
        sev = "low"
    if kev and sev != "critical":
        sev = order[order.index(sev) + 1]
    return sev


def risk_score(cvss, epss, kev):
    if cvss is not None:
        base = cvss
    else:
        base = 8.0 if kev else 5.0  # unscored-but-KEV should rank near the scored critical/high findings
    return round(min(10.0, base + (1.5 if kev else 0) + (1.0 if (epss or 0) >= 0.1 else 0)), 1)


UNSCORED_STATUSES = {"Awaiting Analysis", "Undergoing Analysis", "Received", "Deferred", "Not Scheduled"}


def nvd_status_note(vuln_status):
    """Human-readable line explaining why a CVE has no score, for the finding description."""
    if vuln_status == "Not Scheduled":
        return ("NVD has classified this CVE as 'Not Scheduled' under its 2026 risk-based enrichment "
                "policy, meaning it will not receive a CVSS score or CPE data unless it's later "
                "added to CISA's KEV catalog or reprioritized. Severity here is an estimate.")
    if vuln_status in ("Awaiting Analysis", "Undergoing Analysis", "Received"):
        return (f"NVD has not finished scoring this CVE yet (status: {vuln_status}); it may still "
                "be enriched later. Severity here is an estimate until then.")
    return "NVD has not published a CVSS score for this CVE. Severity here is an estimate."
