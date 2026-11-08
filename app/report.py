"""Generates a one-file PDF audit report: summary, risk by category, top findings, device list."""
import datetime as dt
import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

from . import rules

SEV_COLOR = {"critical": colors.HexColor("#a61b1b"), "high": colors.HexColor("#d4570e"),
             "medium": colors.HexColor("#c28f00"), "low": colors.HexColor("#4a7c59"),
             "info": colors.HexColor("#7b8794")}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("Small", parent=ss["Normal"], fontSize=8.5, leading=11, textColor=colors.HexColor("#444")))
    ss.add(ParagraphStyle("H1b", parent=ss["Heading1"], spaceBefore=4, spaceAfter=10))
    ss.add(ParagraphStyle("H2b", parent=ss["Heading2"], spaceBefore=16, spaceAfter=8))
    return ss


def _sev_counts(findings):
    out = {s: 0 for s in rules.SEV_ORDER}
    for f in findings:
        out[f["severity"]] = out.get(f["severity"], 0) + 1
    return out


def generate(scan, hosts, findings):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.7 * inch, bottomMargin=0.7 * inch,
                            leftMargin=0.7 * inch, rightMargin=0.7 * inch, title=f"NetAudit report #{scan['id']}")
    ss = _styles()
    story = []
    when = dt.datetime.fromtimestamp(scan["finished"]).strftime("%Y-%m-%d %H:%M") if scan.get("finished") else ""
    scored = [f for f in findings if f["severity"] != "info"]
    sev = _sev_counts(findings)
    kev_n = sum(1 for f in findings if f.get("kev"))

    story.append(Paragraph("NetAudit Network Vulnerability Report", ss["H1b"]))
    story.append(Paragraph(f"Target: {scan['target']} &nbsp;&nbsp; Scan depth: {scan['profile']} &nbsp;&nbsp; "
                           f"Completed: {when}", ss["Normal"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        f"<b>{len(hosts)}</b> device(s) audited, <b>{len(scored)}</b> finding(s)"
        + (f", including <b>{kev_n}</b> under active exploitation (CISA KEV)" if kev_n else "") + ".", ss["Normal"]))

    sev_rows = [["Severity", "Count"]] + [[s.capitalize(), str(sev.get(s, 0))] for s in rules.SEV_ORDER if s != "info"]
    t = Table(sev_rows, colWidths=[2.2 * inch, 1.2 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d2935")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 10), ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ccc")),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    story += [Spacer(1, 10), t]

    story.append(Paragraph("Findings by category", ss["H2b"]))
    cat_rows = [["Category", "Count"]]
    for key, name in rules.CATEGORIES.items():
        n = sum(1 for f in findings if f["category"] == key)
        if n:
            cat_rows.append([name, str(n)])
    t2 = Table(cat_rows, colWidths=[3.2 * inch, 1.2 * inch])
    t2.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d2935")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 10), ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#ccc")),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    story.append(t2)

    story.append(Paragraph("Devices by risk", ss["H2b"]))
    dev_rows = [["Device", "OS / type", "Open ports", "Risk"]]
    for h in sorted(hosts, key=lambda x: -(x["risk"] or 0))[:40]:
        dev_rows.append([h["ip"] + (f"\n{h['hostname']}" if h.get("hostname") else ""),
                         h.get("os_name") or h.get("device_type") or "Unknown", str(len(h.get("ports") or [])),
                         f"{h['risk']:.1f}"])
    t3 = Table(dev_rows, colWidths=[1.6 * inch, 2.6 * inch, 0.9 * inch, 0.7 * inch], repeatRows=1)
    t3.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d2935")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#ccc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    story.append(t3)

    story.append(PageBreak())
    story.append(Paragraph("Top findings", ss["H1b"]))
    ranked = sorted(scored, key=lambda f: (-rules.SEV_ORDER[f["severity"]], -(f["risk"] or 0)))[:60]
    for f in ranked:
        block = [
            Paragraph(f"<font color='{SEV_COLOR.get(f['severity'], colors.black).hexval()}'><b>"
                     f"{f['severity'].upper()}</b></font> &nbsp; {f['title']}"
                     + (" <font color='#a61b1b'><b>[ACTIVELY EXPLOITED]</b></font>" if f.get("kev") else ""), ss["Normal"]),
            Paragraph(f"Device: {f['ip']}" + (f" &nbsp;&nbsp; Port: {f['port']}/{f['proto']}" if f.get("port") else "")
                     + (f" &nbsp;&nbsp; CVSS: {f['cvss']}" if f.get("cvss") is not None else ""), ss["Small"]),
            Paragraph(f["description"][:500], ss["Normal"]),
            Paragraph(f"<b>Remediation:</b> {f['remediation'][:400]}", ss["Small"]),
            Spacer(1, 8),
        ]
        story.append(KeepTogether(block))

    story.append(Paragraph(
        "Generated by NetAudit. CVE matching is version-based and may include backported-fix false positives; "
        "malware indicators are based on open ports and known-bad banners, not host inspection, unless "
        "authenticated checks were run. Verify findings before remediation.", ss["Small"]))
    doc.build(story)
    return buf.getvalue()
