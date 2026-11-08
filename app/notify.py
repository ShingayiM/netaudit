"""Alerting: send a short message to Slack and/or email when a scan finds something serious."""
import smtplib
import ssl
from email.mime.text import MIMEText

import requests


def send_slack(webhook_url, text):
    try:
        r = requests.post(webhook_url, json={"text": text}, timeout=15)
        r.raise_for_status()
        return None
    except requests.RequestException as e:
        return str(e)


def send_email(smtp_host, smtp_port, username, password, to_addr, subject, body, use_tls=True):
    try:
        msg = MIMEText(body)
        msg["Subject"], msg["From"], msg["To"] = subject, username, to_addr
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as s:
            if use_tls:
                s.starttls(context=ssl.create_default_context())
            if username and password:
                s.login(username, password)
            s.sendmail(username, [to_addr], msg.as_string())
        return None
    except Exception as e:
        return str(e)


def summarize(scan, summary):
    kev = summary.get("kev", 0)
    sev = summary.get("by_severity", {})
    lines = [f"NetAudit scan #{scan['id']} on {scan['target']} ({scan['profile']}): "
             f"{summary.get('hosts', 0)} device(s), {summary.get('findings', 0)} finding(s)."]
    if sev.get("critical") or sev.get("high"):
        lines.append(f"Critical: {sev.get('critical', 0)}, High: {sev.get('high', 0)}, "
                     f"Medium: {sev.get('medium', 0)}, Low: {sev.get('low', 0)}")
    if kev:
        lines.append(f"{kev} finding(s) are under active exploitation (CISA KEV) — prioritize these.")
    diff = summary.get("diff")
    if diff:
        if diff.get("new_devices"):
            lines.append(f"New devices seen: {', '.join(diff['new_devices'][:10])}")
        if diff.get("new_findings"):
            lines.append(f"{len(diff['new_findings'])} new finding(s) since the previous scan.")
    return "\n".join(lines)


def should_alert(summary, min_severity="high"):
    order = ["info", "low", "medium", "high", "critical"]
    threshold = order.index(min_severity) if min_severity in order else 3
    sev = summary.get("by_severity", {})
    return any(sev.get(s, 0) > 0 for s in order[threshold:]) or summary.get("kev", 0) > 0
