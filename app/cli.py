"""Headless scan runner for scheduled use (Windows Task Scheduler, cron, CI).

Examples:
  python -m app.cli --target 192.168.1.0/24 --profile standard
  python -m app.cli --target 10.0.0.0/24 --profile quick --fail-on critical --json-out result.json
  python -m app.cli --target 192.168.1.0/24 --cred "192.168.1.10/32:ssh:admin:p455w0rd"

Exit codes: 0 = completed, nothing at or above --fail-on; 1 = completed, something at/above
--fail-on was found; 2 = the scan itself errored.

Scheduling:
  Windows Task Scheduler: Action = "python", Arguments = "-m app.cli --target 192.168.1.0/24",
    Start in = this project's folder. Run with highest privileges for OS detection.
  cron (Linux/macOS): sudo crontab -e, then e.g. "0 2 * * * cd /path/to/netaudit && python -m app.cli --target 192.168.1.0/24"
Alerts (Slack/email) and the NVD key are read from the same environment variables as the web app
(see README): NETAUDIT_SLACK_WEBHOOK, NETAUDIT_SMTP_*, NVD_API_KEY.
"""
import argparse
import json
import sys
import time

from . import db, main as main_mod, scanner


def parse_cred(spec):
    parts = spec.split(":")
    if len(parts) < 4:
        raise ValueError(f"--cred must be 'cidr:protocol:username:password' (or ':key:/path/to/key'): {spec}")
    cidr, protocol, username, secret = parts[0], parts[1], parts[2], ":".join(parts[3:])
    rule = {"cidr": cidr, "protocol": protocol, "username": username}
    if protocol == "ssh" and secret.startswith("key:"):
        rule["key_path"] = secret[4:]
    else:
        rule["password"] = secret
    return rule


def main(argv=None):
    p = argparse.ArgumentParser(description="Run a NetAudit scan without the web dashboard.")
    p.add_argument("--target", required=True, help="IP or CIDR range(s), space-separated")
    p.add_argument("--profile", default="standard", choices=list(scanner.PROFILES))
    p.add_argument("--skip-cve", action="store_true")
    p.add_argument("--test-default-credentials", action="store_true")
    p.add_argument("--nvd-key", default=None)
    p.add_argument("--cred", action="append", default=[], help="cidr:protocol:username:password, repeatable")
    p.add_argument("--fail-on", default="high", choices=["low", "medium", "high", "critical", "none"],
                   help="exit code 1 if a finding at/above this severity is present (default: high)")
    p.add_argument("--json-out", default=None, help="write the scan summary as JSON to this path")
    args = p.parse_args(argv)

    if not scanner.nmap_path():
        print("Nmap is not installed or not on PATH.", file=sys.stderr)
        return 2
    targets = main_mod.parse_targets(args.target)
    cred_rules = [parse_cred(c) for c in args.cred]
    db.init()
    sid = db.x("INSERT INTO scans(target,profile,status,progress,message,started) VALUES(?,?,?,?,?,?)",
               (" ".join(targets), args.profile, "queued", 0, "Queued", time.time()))
    print(f"Scan #{sid}: {' '.join(targets)} ({args.profile})")
    scanner.run_scan(sid, targets, args.profile, args.nvd_key, args.skip_cve, cred_rules,
                     args.test_default_credentials)
    row = db.q("SELECT status,summary,message FROM scans WHERE id=?", (sid,))[0]
    if row["status"] != "done":
        print(f"Scan failed: {row['message']}", file=sys.stderr)
        return 2
    summary = json.loads(row["summary"])
    print(f"Done: {summary['hosts']} device(s), {summary['findings']} finding(s). "
         f"By severity: {summary['by_severity']}")
    if args.json_out:
        json.dump(summary, open(args.json_out, "w"), indent=1)
    if args.fail_on == "none":
        return 0
    order = ["low", "medium", "high", "critical"]
    threshold = order.index(args.fail_on)
    hit = any(summary["by_severity"].get(s, 0) > 0 for s in order[threshold:])
    return 1 if hit else 0


if __name__ == "__main__":
    sys.exit(main())
