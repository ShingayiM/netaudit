"""Rule engine: turns scan data for one device into categorized findings.

Tables here are local and offline. Review them from time to time (EOL dates,
risky ports) and extend them for your environment.
"""
import datetime as dt
import os
import re

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEV_BASE_RISK = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}

CATEGORIES = {
    "patch_management": "Patch management",
    "end_of_life": "End-of-life software",
    "open_port": "Exposed services",
    "misconfiguration": "Misconfiguration",
    "malware_indicator": "Malware indicators",
}

# technique id -> (name, tactic)
ATTACK = {
    "T1005": ("Data from Local System", "Collection"),
    "T1018": ("Remote System Discovery", "Discovery"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    "T1021.005": ("Remote Services: VNC", "Lateral Movement"),
    "T1021.006": ("Remote Services: Windows Remote Management", "Lateral Movement"),
    "T1040": ("Network Sniffing", "Credential Access"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1078.001": ("Valid Accounts: Default Accounts", "Initial Access"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1133": ("External Remote Services", "Initial Access"),
    "T1135": ("Network Share Discovery", "Discovery"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1210": ("Exploitation of Remote Services", "Lateral Movement"),
    "T1219": ("Remote Access Software", "Command and Control"),
    "T1498": ("Network Denial of Service", "Impact"),
    "T1499": ("Endpoint Denial of Service", "Impact"),
    "T1557": ("Adversary-in-the-Middle", "Credential Access"),
    "T1557.001": ("Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay", "Credential Access"),
    "T1562": ("Impair Defenses", "Defense Evasion"),
    "T1602": ("Data from Configuration Repository", "Collection"),
    "T1602.001": ("Data from Configuration Repository: SNMP (MIB Dump)", "Collection"),
    "T1610": ("Deploy Container", "Execution"),
}

# key -> (title, severity, description, remediation, attack techniques)
RISKY = {
    "telnet": ("Telnet service exposed", "high",
               "Telnet sends credentials and sessions in clear text and is a favorite target for brute forcing on network gear and IoT devices.",
               "Disable Telnet and use SSH. Restrict device management to a dedicated management VLAN.",
               ["T1021", "T1078", "T1040", "T1110"]),
    "ftp": ("FTP service exposed", "medium",
            "FTP transmits credentials and data in clear text.",
            "Replace with SFTP or FTPS and disable anonymous access.", ["T1078", "T1040", "T1105"]),
    "tftp": ("TFTP service exposed", "high",
             "TFTP has no authentication and is commonly used to pull router and switch configuration files.",
             "Disable TFTP, or restrict it by ACL to the specific hosts that need it.", ["T1602", "T1105"]),
    "rsh": ("Legacy r-service (rsh/rlogin/rexec) exposed", "high",
            "The r-services rely on host trust and clear-text traffic and should not be used.",
            "Disable the r-services and use SSH.", ["T1021", "T1078"]),
    "smb": ("SMB (TCP 445) reachable", "high",
            "SMB has a long history of wormable vulnerabilities and is the main path for lateral movement and ransomware spread.",
            "Limit SMB to file-server segments with firewall rules, disable SMBv1, enforce SMB signing and keep Windows patched.",
            ["T1021.002", "T1210", "T1135"]),
    "netbios": ("NetBIOS session service exposed", "medium",
                "NetBIOS enables host and share enumeration and name-poisoning attacks.",
                "Disable NetBIOS over TCP/IP where not needed and block ports 137-139 between segments.", ["T1135", "T1557.001"]),
    "msrpc": ("Windows RPC endpoint mapper exposed", "medium",
              "The RPC endpoint mapper reveals services and has been the entry point for many Windows exploits.",
              "Block TCP 135 at segment boundaries and keep hosts patched.", ["T1210", "T1046"]),
    "rdp": ("Remote Desktop (RDP) exposed", "high",
            "RDP is heavily brute forced and has had critical pre-authentication vulnerabilities.",
            "Require VPN or an RD Gateway, enable Network Level Authentication, enforce MFA and account lockout.",
            ["T1021.001", "T1110", "T1133"]),
    "vnc": ("VNC remote desktop exposed", "high",
            "VNC often uses weak or no authentication and weak encryption.",
            "Tunnel VNC over SSH or a VPN, set strong passwords, or replace it with a managed remote-access tool.",
            ["T1021.005", "T1110"]),
    "winrm": ("Windows Remote Management exposed", "medium",
              "WinRM allows remote command execution with valid credentials.",
              "Restrict WinRM to admin hosts, prefer HTTPS (5986) and enforce strong authentication.", ["T1021.006", "T1078"]),
    "snmp": ("SNMP service exposed", "medium",
             "SNMP v1/v2c uses community strings in clear text and can leak device configuration.",
             "Move to SNMPv3 with authentication and encryption, and restrict access by ACL.", ["T1602.001", "T1046"]),
    "upnp": ("UPnP/SSDP service exposed", "medium",
             "UPnP can be abused to open firewall ports and leak device details.",
             "Disable UPnP on routers and endpoints that do not need it.", ["T1046", "T1190"]),
    "mssql": ("Microsoft SQL Server exposed", "medium",
              "Database ports should not be reachable from general client networks.",
              "Restrict to application servers by firewall, disable the sa login and enforce encryption.", ["T1190", "T1078"]),
    "mysql": ("MySQL exposed", "medium",
              "Database ports should not be reachable from general client networks.",
              "Bind to localhost or restrict by firewall; remove anonymous and default accounts.", ["T1190", "T1078"]),
    "postgres": ("PostgreSQL exposed", "medium",
                 "Database ports should not be reachable from general client networks.",
                 "Restrict access in pg_hba.conf and with firewall rules.", ["T1190", "T1078"]),
    "mongodb": ("MongoDB exposed", "high",
                "MongoDB instances have historically been deployed without authentication.",
                "Enable authentication, bind to internal interfaces only and restrict by firewall.", ["T1190", "T1078"]),
    "redis": ("Redis exposed", "high",
              "Redis has no authentication by default and can be abused for remote code execution.",
              "Bind to localhost, require a password/ACLs and firewall the port.", ["T1190", "T1059"]),
    "memcached": ("Memcached exposed", "high",
                  "Open memcached leaks cached data and is abused for DDoS amplification.",
                  "Bind to localhost, disable UDP and firewall the port.", ["T1190", "T1498"]),
    "elasticsearch": ("Elasticsearch exposed", "high",
                      "Elasticsearch without security enabled exposes all indexed data.",
                      "Enable authentication and TLS and restrict network access.", ["T1190", "T1078"]),
    "docker": ("Docker remote API exposed", "critical",
               "The unauthenticated Docker API gives full control of the host.",
               "Disable the TCP socket or protect it with mutual TLS and firewall rules.", ["T1190", "T1610"]),
    "x11": ("X11 display server exposed", "medium",
            "Open X11 allows keystroke capture and screen access.",
            "Disable TCP listening for X11 and use SSH forwarding.", ["T1021", "T1040"]),
    "ldap": ("LDAP (clear text) exposed", "low",
             "Unencrypted LDAP exposes credentials and directory data on the wire.",
             "Use LDAPS or StartTLS and require LDAP signing.", ["T1040"]),
    "winbox": ("MikroTik Winbox management exposed", "medium",
               "Winbox on exposed routers has had critical credential-disclosure vulnerabilities.",
               "Restrict management services to a management network and update RouterOS.", ["T1190", "T1133"]),
    "tr069": ("TR-069 (CWMP) management exposed", "medium",
              "Exposed CWMP has been exploited at scale by botnets.",
              "Restrict TR-069 to the ISP's ACS addresses and update firmware.", ["T1190"]),
    "http-clear": ("Web interface served over HTTP only", "low",
                   "Credentials and sessions to this web interface cross the network unencrypted.",
                   "Enable HTTPS on the management interface and disable plain HTTP.", ["T1040", "T1557"]),
}

SERVICE_KEY = {
    "telnet": "telnet", "ftp": "ftp", "tftp": "tftp", "shell": "rsh", "login": "rsh", "exec": "rsh",
    "microsoft-ds": "smb", "netbios-ssn": "netbios", "msrpc": "msrpc", "ms-wbt-server": "rdp",
    "vnc": "vnc", "wsman": "winrm", "wsmans": "winrm", "snmp": "snmp", "upnp": "upnp", "ms-sql-s": "mssql",
    "mysql": "mysql", "postgresql": "postgres", "mongodb": "mongodb", "redis": "redis",
    "memcached": "memcached", "docker": "docker", "x11": "x11", "ldap": "ldap",
}
PORT_KEY = {
    (23, "tcp"): "telnet", (21, "tcp"): "ftp", (69, "udp"): "tftp", (512, "tcp"): "rsh", (513, "tcp"): "rsh",
    (514, "tcp"): "rsh", (445, "tcp"): "smb", (139, "tcp"): "netbios", (135, "tcp"): "msrpc",
    (3389, "tcp"): "rdp", (5900, "tcp"): "vnc", (5901, "tcp"): "vnc", (5985, "tcp"): "winrm",
    (5986, "tcp"): "winrm", (161, "udp"): "snmp", (1900, "udp"): "upnp", (1433, "tcp"): "mssql",
    (3306, "tcp"): "mysql", (5432, "tcp"): "postgres", (27017, "tcp"): "mongodb", (6379, "tcp"): "redis",
    (11211, "tcp"): "memcached", (9200, "tcp"): "elasticsearch", (2375, "tcp"): "docker",
    (6000, "tcp"): "x11", (389, "tcp"): "ldap", (8291, "tcp"): "winbox", (7547, "tcp"): "tr069",
}

# Ports commonly used by malware and backdoors (low confidence, needs verification)
SUSPICIOUS_PORTS = {
    31337: "Back Orifice / 'elite' backdoor port", 12345: "NetBus trojan default port",
    4444: "Metasploit / reverse-shell default port", 1337: "common backdoor port",
    6667: "IRC, historically used for botnet command and control", 5555: "Android ADB / common RAT port",
    9050: "Tor SOCKS proxy", 9001: "Tor onion-router port", 2323: "alternate Telnet used by Mirai-style botnets",
}

# Software that is out of support. (substring of product, minimum supported version tuple, category, label)
OUTDATED_PRODUCTS = [
    ("openssh", (8, 0), "patch_management", "OpenSSH older than 8.0"),
    ("apache httpd", (2, 4), "end_of_life", "Apache HTTP Server 2.2 or older (end of life)"),
    ("microsoft iis", (10, 0), "end_of_life", "IIS older than 10.0 (Windows Server 2012 R2 or older)"),
    ("mysql", (8, 0), "end_of_life", "MySQL 5.x (end of life)"),
    ("php", (8, 2), "end_of_life", "PHP older than 8.2 (end of life)"),
    ("samba", (4, 0), "end_of_life", "Samba 3.x (end of life)"),
]

# Operating systems with a fixed end-of-support date: (regex, label, date)
OS_EOL = [
    (r"windows xp", "Windows XP", "2014-04-08"),
    (r"windows vista", "Windows Vista", "2017-04-11"),
    (r"windows 7\b", "Windows 7", "2020-01-14"),
    (r"windows 8\.1", "Windows 8.1", "2023-01-10"),
    (r"windows 8\b", "Windows 8", "2016-01-12"),
    (r"server 2003", "Windows Server 2003", "2015-07-14"),
    (r"server 2008", "Windows Server 2008", "2020-01-14"),
    (r"server 2012", "Windows Server 2012", "2023-10-10"),
    (r"windows 10", "Windows 10", "2025-10-14"),
    (r"esxi 6\.", "VMware ESXi 6.x", "2022-10-15"),
    (r"esxi 7\.", "VMware ESXi 7.x", "2025-10-02"),
    (r"linux 2\.[46]", "Linux kernel 2.x", "2016-01-01"),
    (r"linux 3\.", "Linux kernel 3.x", "2017-01-01"),
]

KNOWN_BAD = [
    (r"vsftpd 2\.3\.4", "vsftpd 2.3.4 backdoor", "CVE-2011-2523",
     "This vsftpd release shipped with a backdoor that opens a root shell on port 6200."),
    (r"proftpd 1\.3\.3c", "ProFTPD 1.3.3c backdoored build", None,
     "A compromised ProFTPD 1.3.3c source distribution contained a backdoor."),
]


def vt(s):
    nums = [int(n) for n in re.findall(r"\d+", s or "")[:3]]
    return tuple(nums) if nums else (0,)


def mk(category, severity, title, description, remediation, port=None, proto=None, evidence="",
       attack=(), cve=None, cvss=None, epss=None, kev=False, confidence="high", refs=(), risk=None):
    return dict(category=category, severity=severity, title=title, description=description,
                remediation=remediation, port=port, proto=proto, evidence=evidence, attack=list(attack),
                cve=cve, cvss=cvss, epss=epss, kev=bool(kev), confidence=confidence, refs=list(refs),
                risk=risk if risk is not None else SEV_BASE_RISK[severity])


def load_iocs():
    path = os.path.join(os.path.dirname(__file__), "..", "data", "iocs.txt")
    out = set()
    try:
        for line in open(path, encoding="utf-8"):
            line = line.strip().lower()
            if line and not line.startswith("#"):
                out.add(line)
    except OSError:
        pass
    return out


def _script_findings(host, p):
    out, s = [], p.get("scripts") or {}
    ev = lambda k: (s.get(k) or "")[:500]
    port, proto = p["port"], p["proto"]
    if "snmp-info" in s:
        out.append(mk("misconfiguration", "high", "SNMP answers to the default 'public' community",
                      "The device returned data for the default read community string, exposing system details and potentially the full MIB.",
                      "Change community strings or move to SNMPv3, and restrict SNMP by ACL.",
                      port, proto, ev("snmp-info"), ["T1602.001", "T1078.001"]))
    if "Anonymous FTP login allowed" in (s.get("ftp-anon") or ""):
        out.append(mk("misconfiguration", "high", "Anonymous FTP login allowed",
                      "Anyone on the network can log in to this FTP server without credentials.",
                      "Disable anonymous access or remove the service.", port, proto, ev("ftp-anon"), ["T1078.001", "T1105"]))
    tls = s.get("ssl-enum-ciphers") or ""
    if tls:
        old = [v for v in ("SSLv3", "TLSv1.0", "TLSv1.1") if v in tls]
        weak = re.findall(r"least strength: ([A-F])", tls)
        if old:
            out.append(mk("misconfiguration", "medium", "Deprecated TLS/SSL versions enabled: " + ", ".join(old),
                          "Old protocol versions have known weaknesses (POODLE, BEAST) and are rejected by modern compliance standards.",
                          "Allow only TLS 1.2 and TLS 1.3.", port, proto, ev("ssl-enum-ciphers"), ["T1040", "T1557"]))
        elif any(w in "DEF" for w in weak):
            out.append(mk("misconfiguration", "medium", "Weak TLS cipher suites offered",
                          "The service offers cipher suites rated D or worse.",
                          "Remove weak ciphers and prefer AEAD suites with forward secrecy.", port, proto, ev("ssl-enum-ciphers"), ["T1040"]))
    if "Index of /" in (s.get("http-title") or ""):
        out.append(mk("misconfiguration", "low", "Web directory listing enabled",
                      "The web server lists directory contents, which can expose files not meant to be public.",
                      "Disable directory indexing.", port, proto, ev("http-title"), ["T1005"]))
    return out


def _host_script_findings(host):
    out, hs = [], host.get("hostscripts") or {}
    if "SMBv1" in (hs.get("smb-protocols") or "") or "NT LM 0.12" in (hs.get("smb-protocols") or ""):
        out.append(mk("misconfiguration", "high", "SMBv1 enabled",
                      "SMBv1 is obsolete and was the vector for EternalBlue (WannaCry, NotPetya).",
                      "Disable SMBv1 (Windows: Disable-WindowsOptionalFeature SMB1Protocol; Samba: min protocol = SMB2).",
                      445, "tcp", hs["smb-protocols"][:500], ["T1210", "T1021.002"]))
    sec = (hs.get("smb-security-mode") or "") + (hs.get("smb2-security-mode") or "")
    if re.search(r"message_signing: disabled|signing enabled but not required|signing is disabled", sec, re.I):
        out.append(mk("misconfiguration", "medium", "SMB signing not required",
                      "Without required signing, SMB sessions can be relayed or tampered with.",
                      "Require SMB signing via Group Policy or Samba 'server signing = mandatory'.",
                      445, "tcp", sec[:500], ["T1557.001"]))
    return out


def analyze_host(h, iocs=None):
    """Non-CVE findings for one device."""
    out = []
    ports = h.get("ports") or []
    has_tls = any(p["port"] in (443, 8443) for p in ports)
    for p in ports:
        banner = " ".join(x for x in (p.get("product"), p.get("version"), p.get("extrainfo")) if x)
        evidence = f"{p['port']}/{p['proto']} {p.get('service') or ''} {banner}".strip()
        key = SERVICE_KEY.get((p.get("service") or "").lower()) or PORT_KEY.get((p["port"], p["proto"]))
        if key is None and p["port"] == 80 and p["proto"] == "tcp" and not has_tls:
            key = "http-clear"
        if key in RISKY:
            title, sev, desc, fix, att = RISKY[key]
            out.append(mk("open_port", sev, f"{title} on {p['port']}/{p['proto']}", desc, fix,
                          p["port"], p["proto"], evidence, att))
        if p["port"] in SUSPICIOUS_PORTS and p["proto"] == "tcp":
            out.append(mk("malware_indicator", "medium", f"Listening on suspicious port {p['port']}",
                          f"{SUSPICIOUS_PORTS[p['port']]}. A listener here is not proof of infection but warrants investigation.",
                          "Identify the process owning this port (netstat/ss/lsof) and scan the host with AV/EDR.",
                          p["port"], p["proto"], evidence, ["T1071", "T1219"], confidence="low"))
        out += _script_findings(h, p)
        low = f"{p.get('product') or ''} {p.get('version') or ''}".lower().strip()
        if "ssh" in (p.get("service") or "") and re.search(r"protocol 1\.\d", (p.get("extrainfo") or "") + " " + banner):
            out.append(mk("misconfiguration", "critical", "SSH protocol version 1 supported",
                          "SSHv1 is cryptographically broken.", "Set 'Protocol 2' (or upgrade the SSH server).",
                          p["port"], p["proto"], evidence, ["T1040", "T1557"]))
        for rx, title, cve, desc in KNOWN_BAD:
            if re.search(rx, low, re.I):
                out.append(mk("malware_indicator", "critical", title, desc,
                              "Treat the host as compromised: isolate it, reinstall from a trusted source and rotate credentials.",
                              p["port"], p["proto"], evidence, ["T1190", "T1059"], cve=cve, cvss=9.8, confidence="high",
                              risk=10.0))
        if p.get("version"):
            for sub, minv, cat, label in OUTDATED_PRODUCTS:
                if sub in low and vt(p["version"]) < minv:
                    out.append(mk(cat, "high" if cat == "end_of_life" else "medium", label,
                                  f"{p.get('product')} {p['version']} is no longer maintained or is far behind current releases, "
                                  "so security fixes are missing.",
                                  "Upgrade to a supported release. If this is a distro package, confirm backported patches.",
                                  p["port"], p["proto"], evidence, ["T1190"],
                                  confidence="medium"))
    for f in _host_script_findings(h):
        out.append(f)
    name, acc = (h.get("os_name") or ""), (h.get("os_accuracy") or 0)
    if name and acc >= 85:
        for rx, label, date in OS_EOL:
            if re.search(rx, name, re.I):
                if dt.date.fromisoformat(date) <= dt.date.today():
                    out.append(mk("end_of_life", "high", f"{label} is out of support (ended {date})",
                                  f"Nmap fingerprinted the OS as '{name}' ({acc}% match). Unsupported systems no longer receive security patches.",
                                  "Upgrade or replace the system, or isolate it on a restricted segment until it can be retired.",
                                  evidence=f"OS fingerprint: {name} ({acc}%)", attack=["T1190", "T1210", "T1068"],
                                  confidence="medium", risk=8.0))
                break
    if iocs:
        keys = {str(x).lower() for x in (h.get("ip"), h.get("mac"), h.get("hostname")) if x}
        for hit in keys & iocs:
            out.append(mk("malware_indicator", "critical", f"Device matches indicator of compromise: {hit}",
                          "This device's address or hostname appears in your IOC list (data/iocs.txt).",
                          "Isolate the device and investigate with your incident response process.",
                          evidence=hit, attack=["T1071"], risk=9.8))
    return out


def host_risk(findings):
    if not findings:
        return 0.0
    risks = sorted((f["risk"] for f in findings), reverse=True)
    serious = sum(1 for r in risks if r >= 7)
    return round(min(10.0, risks[0] + 0.1 * max(0, serious - 1)), 1)
