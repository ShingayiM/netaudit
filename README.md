# NetAudit

A network audit tool. Point it at your network, run it, and get one dashboard of every vulnerability it finds,
grouped into categories and mapped to MITRE ATT&CK, CVEs, CISA KEV and EPSS.

**Categories:** Patch management, End-of-life software, Exposed services (open ports), Misconfiguration, Malware indicators.

## Setup (5 minutes)

1. Install **Python 3.9+** and **Nmap** (https://nmap.org/download; on Windows also install Npcap, which the Nmap installer offers).
2. In this folder:
   ```
   pip install -r requirements.txt
   ```
3. Start it. **Run as administrator/root** for OS detection, ARP discovery (MAC and vendor) and UDP/SNMP checks:
   ```
   sudo python run.py            # Linux / macOS
   python run.py                 # Windows, from an Administrator terminal
   ```
4. Your browser opens at http://127.0.0.1:8808. Enter a range (it pre-fills your local /24), pick a depth, tick the
   authorization box, and select **Run audit**.

Optional: get a free NVD API key (https://nvd.nist.gov/developers/request-an-api-key) and paste it under *Advanced*
or set `NVD_API_KEY`. Without a key, CVE lookups take about 6.5 seconds per distinct service version.

## What it does

| Stage | How |
|---|---|
| Discovery and fingerprinting | Nmap: live hosts, open ports, service versions (`-sV`), OS (`-O`), MAC vendor, NSE checks for SMB, TLS, FTP, SNMP, HTTP |
| CVE matching | Nmap CPEs are converted to CPE 2.3 and looked up in the NVD API 2.0 (cached 7 days in SQLite) |
| Prioritization | CISA KEV (actively exploited) and EPSS flag and rank CVEs. Risk = CVSS, +1.5 if KEV, +1.0 if EPSS >= 10% |
| ATT&CK mapping | Hand-written mappings for exposed services and misconfigurations. CVEs use a keyword heuristic, or the CTID dataset if supplied |
| Categorization | `app/rules.py`: risky ports, EOL OS and software tables, SMB/TLS/FTP/SNMP checks, known-bad software, suspicious ports, IOC list |
| Reporting | Dashboard, per-finding remediation, CSV and JSON export, ATT&CK Navigator layer, scan history |

Scan depths: **Quick** (top 100 ports), **Standard** (top 1000 + OS + checks, recommended), **Deep** (ports 1-10000).

## Authenticated scanning (credentials)

For real patch levels and malware/AV status, give NetAudit a login to the device under **Advanced** on the run
panel, or save it once under the credential vault (encrypted locally in `data/credentials.enc`, keyed by
`data/.credkey`; never commit either file, and `.gitignore` already excludes them).

- **SSH** (Linux/macOS): pending package updates, reboot-required flag, SSHd hardening (root login, password auth),
  host firewall state, EOL kernel/distro, world-writable files in system paths, basic AV presence.
- **WinRM** (Windows): missing Windows updates (via the Windows Update API), Defender status and signature age,
  Windows Firewall per profile, SMBv1, RDP enabled, Guest/DefaultAccount in Administrators, OS EOL.
  Enable WinRM on the target first: `winrm quickconfig` (run as administrator on that machine), and allow it through
  its firewall if remote.
- A credential only applies to the IP/CIDR range you give it, so you can mix SSH ranges and WinRM ranges in the same
  scan. A failed login shows up as an informational finding on that device rather than silently skipping it.
- These checks need direct credentials to each device, same as any authenticated vulnerability scanner. For many
  hosts at once, consider a shared local account created for this purpose with read-only/audit rights, not a
  personal admin login.

## Tracking over time

Every completed scan is automatically compared with the previous one: the dashboard header shows new devices,
devices no longer seen, new findings and resolved findings. Mark a finding as **accepted risk** or **false positive**
from its detail panel; it's then hidden by default (toggle "show dismissed" in the Findings tab) and stays hidden
across future scans of the same device and title.

## Asset importance

On the Devices tab, set a device's importance (critical asset / high value / normal / low value). This adjusts its
risk score so a vulnerable domain controller or file server stands out above the same finding on a low-value device.

## NVD's 2026 enrichment policy (and how NetAudit handles it)

Since April 2026, NVD only prioritizes full CVSS/CPE enrichment for CVEs in CISA's KEV catalog or
on a short "critical software" list; a large backlog of older CVEs is now marked **"Not Scheduled"**
and may never get a score. NetAudit does not treat an unscored CVE as a quiet "medium":
- If it's listed in CISA KEV (actively exploited), it's shown as **critical** even with no CVSS score,
  since real-world exploitation is a stronger signal than a missing number.
- Otherwise it's tagged **"unscored by NVD"** in the findings table and drawer, with the specific
  NVD status (Not Scheduled / Awaiting Analysis / etc.) in the description, so you know the severity
  shown is an estimate rather than a published score. Click through to the NVD page for the CVE to
  judge it yourself.

## OSV.dev supplement for Linux hosts

Authenticated SSH checks on Debian/Ubuntu hosts also query [OSV.dev](https://osv.dev) for a short
watchlist of security-critical packages (OpenSSH, OpenSSL, sudo, bash, libc6, Python, curl, nginx,
Apache, systemd), matched by exact installed version. OSV indexes distro advisories directly and
isn't affected by NVD's backlog, so it can surface advisories that version-based NVD/CPE matching
misses. It's a supplement, not a full package audit — it checks ~10 packages, not your whole
system. Other distros (RHEL/Rocky/Alma/SUSE) aren't covered yet; OSV does support them, so this
could be extended (see `OSV_ECOSYSTEM` in `app/auth_scan.py`).

## Default-credential testing (opt-in)

Tick "Test common default credentials" under Advanced to try a short, well-known list of factory
logins (admin/admin, root/root, ubnt/ubnt, etc.) over SSH, FTP, Telnet and HTTP against open
services. It's rate-limited (about one attempt every 0.6s per service) and stops at the first
success, so it's slow by design rather than a general brute-force tool. Only use it on devices
you're authorized to test — it attempts real logins.

## Better ATT&CK mapping

By default, CVE-to-ATT&CK mapping uses a keyword heuristic. For real mapping data on older CVEs,
run:
```
python scripts/fetch_ctid_mapping.py
```
This downloads the Center for Threat-Informed Defense's "Mapping ATT&CK to CVE for Impact" dataset
(archived, last updated 2021, ~800 CVEs) and writes `data/cve_attack_mapping.json`. NetAudit uses it
automatically if present, and falls back to the keyword heuristic for anything not in it.

## Scheduling and headless use

Run a scan without the dashboard, e.g. from Windows Task Scheduler or cron:
```
python -m app.cli --target 192.168.1.0/24 --profile standard
python -m app.cli --target 192.168.1.0/24 --fail-on critical --json-out result.json
python -m app.cli --target 192.168.1.0/24 --cred "192.168.1.10/32:ssh:admin:p455w0rd"
```
Exit code 0 = clean, 1 = something at or above `--fail-on` severity was found (default: high),
2 = the scan itself errored. See `python -m app.cli --help`.

## Alerts

Set these environment variables (same for the web app and the CLI) to get notified when a scan
finds something at or above `NETAUDIT_ALERT_MIN_SEVERITY` (default `high`) or anything in CISA KEV:
- **Slack:** `NETAUDIT_SLACK_WEBHOOK` — an incoming webhook URL.
- **Email:** `NETAUDIT_SMTP_HOST`, `NETAUDIT_SMTP_PORT` (default 587), `NETAUDIT_SMTP_USER`,
  `NETAUDIT_SMTP_PASSWORD`, `NETAUDIT_SMTP_TO`.

## Reports and trends

- **PDF report:** download button on the dashboard, or `GET /api/scans/{id}/report.pdf` — summary,
  severity/category breakdown, devices by risk, and the top findings with remediation.
- **Trends tab:** average device risk and critical+high finding counts across your last 30 scans
  of this network, so you can see whether things are improving.

## Securing the dashboard

By default the dashboard has no login, which is fine as long as it's bound to `127.0.0.1` (the
default). If you set `NETAUDIT_HOST` to anything else, set a login too:
```
set NETAUDIT_USER=youradmin
set NETAUDIT_PASSWORD=a-strong-password
python run.py
```
(`export` instead of `set` on Linux/macOS.) Without both variables set, run.py prints a warning if
`NETAUDIT_HOST` isn't localhost. This is HTTP Basic Auth over plain HTTP — fine on a trusted LAN,
not fine over the open internet; put it behind a VPN or a reverse proxy with TLS for anything else.

## Honest limits

- **Malware detection is indicator-based only.** A network scan cannot see inside a host. NetAudit reports known backdoored
  software, listeners on ports malware commonly uses, and matches against `data/iocs.txt`. Confirm with AV/EDR.
- **CVE matches are version-based.** Linux distributions backport fixes without changing version numbers, so those findings
  are marked *medium confidence*. Network gear that hides its version produces no CVE matches.
- **OS-level patch gaps (missing Windows KBs, kernel CVEs) need authenticated scanning**, which this version does not do.
  OS support status is covered by the EOL table instead.
- EOL dates and risky-port lists are local tables in `app/rules.py`. Review them periodically.
- Switches and APs are found and assessed when they expose services (SSH, Telnet, HTTP, SNMP). Enable SNMP checks
  by running with admin/root. OS/firmware CVE matching now also uses Nmap's OS-fingerprint CPE when one is detected,
  which covers more network gear than service-banner matching alone, but still depends on Nmap recognizing the device.
- Default-credential testing covers a short, fixed list — it checks "was the default ever changed", not every
  possible weak password.

## Extending

- **Better ATT&CK for CVEs:** save a JSON of the form `{"CVE-2021-44228": ["T1190", "T1059"]}` as
  `data/cve_attack_mapping.json` (e.g. converted from the CTID "Mapping ATT&CK to CVE for Impact" dataset).
- **IOCs:** add IPs, hostnames or MACs to `data/iocs.txt`.
- **New rules:** add entries to `RISKY`, `OUTDATED_PRODUCTS` or `OS_EOL` in `app/rules.py`.
- **Public ranges:** blocked by default. `NETAUDIT_ALLOW_PUBLIC=1` lifts it, only for ranges you are authorized to scan.
- **Network access to the dashboard:** it binds to 127.0.0.1 and has no login. Do not expose it without adding authentication.

## Responsible use

Only scan networks you own or have written permission to test. Scanning can disrupt fragile devices (old printers,
industrial controllers); start with Quick and schedule Deep scans for maintenance windows.

## Layout

```
run.py                  launcher (web dashboard)
app/main.py             REST API, exports, dashboard auth
app/cli.py              headless scan runner (python -m app.cli)
app/scanner.py          Nmap runner, XML parser, analysis pipeline
app/intel.py            NVD, KEV, EPSS, CVE to ATT&CK
app/rules.py            categorization rules and ATT&CK tables
app/auth_scan.py        authenticated SSH/WinRM checks
app/default_creds.py    opt-in default-credential testing
app/creds.py            encrypted credential vault
app/notify.py           Slack/email alerting
app/report.py           PDF report generation
app/db.py               SQLite storage (data/netaudit.db)
app/static/index.html   dashboard
scripts/fetch_ctid_mapping.py   optional: real CVE->ATT&CK dataset
```
