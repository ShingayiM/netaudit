"""Authenticated (credentialed) host auditing.

Unlike the Nmap pass, this logs in to the device and reads its real state: installed patches,
package versions, security services, and local hardening settings. This is what finds a missing
Windows KB or an out-of-date apt package that a banner scan cannot see, and it is the main source
for genuine malware/AV-status findings rather than port-based guesses.

Credentials are passed in as plain dicts at call time and are never written to disk by this module;
see creds.py for the only place they're persisted (encrypted), and only if the user opts in.
"""
import datetime as dt
import re
import socket

import requests

from . import rules

try:
    import paramiko
except ImportError:
    paramiko = None
try:
    import winrm
except ImportError:
    winrm = None

SSH_TIMEOUT = 12
WINRM_TIMEOUT = 15

# OSV.dev supplements NVD for the packages most likely to matter, rather than auditing every
# installed package (which would be slow and noisy). It's queried by distro+version directly,
# so it isn't subject to NVD's 2026 enrichment backlog at all.
OSV_WATCHLIST = ["openssh-server", "openssl", "sudo", "bash", "libc6", "python3", "curl", "nginx", "apache2", "systemd"]
OSV_ECOSYSTEM = {"debian": "Debian", "ubuntu": "Ubuntu"}  # OSV also covers rocky/alma/wolfi/suse; add here if needed
OSV_TIMEOUT = 20


def mk(category, severity, title, description, remediation, evidence="", attack=(), confidence="high", risk=None):
    return rules.mk(category, severity, title, description, remediation, evidence=evidence, attack=list(attack),
                    confidence=confidence, risk=risk)


# ---------------------------------------------------------------- SSH / Linux, macOS

def _ssh_run(client, cmd):
    try:
        _, out, _ = client.exec_command(cmd, timeout=SSH_TIMEOUT)
        return out.read().decode(errors="replace").strip()
    except Exception:
        return ""


def osv_check(client, distro_id, distro_version):
    """Queries OSV.dev for a short watchlist of security-critical packages on Debian/Ubuntu hosts.
    Returns (findings, error_or_None). error is None even when the distro isn't covered; that's
    not a failure, just nothing to check."""
    base = OSV_ECOSYSTEM.get((distro_id or "").lower())
    if not base:
        return [], None
    ecosystem = f"{base}:{distro_version}" if distro_version else base
    versions = {}
    for pkg in OSV_WATCHLIST:
        out = _ssh_run(client, f"dpkg-query -W -f='${{Version}}' {pkg} 2>/dev/null")
        if out and "no packages found" not in out.lower():
            versions[pkg] = out.strip()
    if not versions:
        return [], None
    queries = [{"package": {"name": p, "ecosystem": ecosystem}, "version": v} for p, v in versions.items()]
    try:
        r = requests.post("https://api.osv.dev/v1/querybatch", json={"queries": queries}, timeout=OSV_TIMEOUT)
        r.raise_for_status()
        results = r.json().get("results", [])
    except Exception as e:
        return [], f"OSV.dev lookup failed: {e}"
    out = []
    for (pkg, ver), res in zip(versions.items(), results):
        vulns = (res or {}).get("vulns") or []
        for v in vulns[:5]:
            vid = v.get("id", "")
            out.append(rules.mk(
                "patch_management", "high", f"{vid}: {pkg} {ver} (OSV)",
                f"OSV.dev lists {vid} as affecting {pkg} version {ver} on this system. NetAudit shows "
                "the advisory ID and package only here; open the link for the full write-up and fixed version.",
                f"Update {pkg} past this advisory's fixed version.", evidence=f"{pkg} {ver}", attack=["T1190"],
                cve=vid if vid.startswith("CVE-") else None, confidence="medium", risk=7.0,
                refs=[f"https://osv.dev/vulnerability/{vid}"]))
        if len(vulns) > 5:
            out.append(rules.mk("patch_management", "info", f"{len(vulns) - 5} more OSV.dev advisories for {pkg} {ver}",
                                "Only the first 5 are listed individually for this package.",
                                f"Update {pkg}; this likely clears the remaining advisories too.", evidence=f"{pkg} {ver}"))
    return out, None


def ssh_audit(host, port, username, password=None, key_path=None, key_passphrase=None):
    """Returns (findings list, error string or None). Never raises past this function."""
    if paramiko is None:
        return [], "paramiko is not installed (pip install paramiko)"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        kwargs = dict(hostname=host, port=port or 22, username=username, timeout=SSH_TIMEOUT,
                     banner_timeout=SSH_TIMEOUT, auth_timeout=SSH_TIMEOUT, allow_agent=False, look_for_keys=False)
        if key_path:
            kwargs["pkey"] = paramiko.RSAKey.from_private_key_file(key_path, password=key_passphrase)
        else:
            kwargs["password"] = password
        client.connect(**kwargs)
    except paramiko.AuthenticationException:
        return [], "Authentication failed: check the username and password or key."
    except (paramiko.SSHException, socket.error, OSError) as e:
        return [], f"Could not connect over SSH: {e}"
    found = []
    try:
        osrel = _ssh_run(client, "cat /etc/os-release 2>/dev/null")
        distro = re.search(r'PRETTY_NAME="([^"]+)"', osrel)
        distro = distro.group(1) if distro else _ssh_run(client, "uname -a")[:80]
        distro_id_m = re.search(r'^ID=(.+)$', osrel, re.M)
        distro_id = distro_id_m.group(1).strip('"') if distro_id_m else ""
        distro_ver_m = re.search(r'^VERSION_ID="?([\d.]+)"?', osrel, re.M)
        distro_version = distro_ver_m.group(1) if distro_ver_m else ""
        kernel = _ssh_run(client, "uname -r")
        whoami = _ssh_run(client, "whoami")
        is_root = whoami == "root"
        evidence_os = f"{distro} / kernel {kernel}"

        pending = None
        if _ssh_run(client, "command -v apt-get"):
            n = _ssh_run(client, "apt-get -s upgrade 2>/dev/null | grep -c ^Inst")
            sec = _ssh_run(client, "apt-get -s upgrade 2>/dev/null | grep -c -i security")
            pending = ("apt", int(n or 0), int(sec or 0))
        elif _ssh_run(client, "command -v dnf"):
            n = _ssh_run(client, "dnf check-update --quiet 2>/dev/null | grep -c . || true")
            pending = ("dnf", int(n or 0), None)
        elif _ssh_run(client, "command -v yum"):
            n = _ssh_run(client, "yum check-update --quiet 2>/dev/null | grep -c . || true")
            pending = ("yum", int(n or 0), None)
        if pending and pending[1] > 0:
            mgr, n, sec = pending
            sev = "high" if (sec and sec > 0) else "medium"
            found.append(mk("patch_management", sev, f"{n} pending OS package update(s) ({mgr})",
                            f"{n} package(s) have updates available" + (f", {sec} tagged security-related" if sec else "")
                            + f" on {evidence_os}.",
                            f"Run the distribution's update command ({mgr} update/upgrade) during a maintenance window.",
                            evidence_os, ["T1190"], confidence="high",
                            risk=7.5 if sev == "high" else 5.0))
        reboot = _ssh_run(client, "test -f /var/run/reboot-required && echo yes")
        if reboot == "yes":
            found.append(mk("patch_management", "medium", "Reboot required to apply updates",
                            "A previously installed update needs a reboot to take effect; the fix is not fully applied until then.",
                            "Schedule a reboot.", evidence_os, ["T1190"]))

        fw_ufw = _ssh_run(client, "command -v ufw >/dev/null && ufw status 2>/dev/null")
        if fw_ufw and "inactive" in fw_ufw.lower():
            found.append(mk("misconfiguration", "medium", "Host firewall (ufw) is inactive",
                            "No local firewall is filtering inbound connections on this host.",
                            "Enable ufw or configure an equivalent host firewall.", fw_ufw[:200], ["T1190"]))

        sshd = _ssh_run(client, "cat /etc/ssh/sshd_config 2>/dev/null; cat /etc/ssh/sshd_config.d/*.conf 2>/dev/null")
        if re.search(r"^\s*PermitRootLogin\s+yes", sshd, re.M | re.I):
            found.append(mk("misconfiguration", "high", "SSH allows direct root login",
                            "PermitRootLogin yes lets an attacker brute-force the most privileged account directly.",
                            "Set 'PermitRootLogin no' or 'prohibit-password', and use sudo with a named account instead.",
                            "sshd_config: PermitRootLogin yes", ["T1078", "T1110"]))
        if re.search(r"^\s*PasswordAuthentication\s+yes", sshd, re.M | re.I) or not sshd:
            found.append(mk("misconfiguration", "medium", "SSH password authentication is enabled",
                            "Password auth over SSH is a common brute-force target compared to key-based auth.",
                            "Disable password authentication and use SSH keys once key access is confirmed working.",
                            "sshd_config: PasswordAuthentication yes" if sshd else "default (not explicitly disabled)",
                            ["T1110", "T1078"], confidence="medium" if not sshd else "high"))

        av = _ssh_run(client, "command -v clamscan || command -v freshclam || systemctl is-active clamav-daemon 2>/dev/null")
        if not av:
            found.append(mk("malware_indicator", "low", "No antivirus/AV agent detected on this host",
                            "No common Linux AV (ClamAV) was found. Many Linux hosts intentionally run none; "
                            "treat this as informational unless your policy requires an agent.",
                            "Install an AV/EDR agent if required by policy, or confirm one is centrally managed and just not visible here.",
                            confidence="low", risk=2.0))

        world_w = _ssh_run(client, "find /etc /usr/local/bin /usr/local/sbin -xdev -type f -perm -0002 2>/dev/null | head -5")
        if world_w:
            found.append(mk("misconfiguration", "medium", "World-writable files in system directories",
                            "Files any local user can modify in system paths can be used for privilege escalation.",
                            "Remove world-write permission (chmod o-w) from the listed files.", world_w, ["T1068"]))

        for rx, label, date in rules.OS_EOL:
            if re.search(rx, distro, re.I) and dt.date.fromisoformat(date) <= dt.date.today():
                found.append(mk("end_of_life", "high", f"{label} is out of support (ended {date})",
                                f"Authenticated check found this host running {distro}, which is past its support end date.",
                                "Upgrade or replace the system.", evidence_os, ["T1190"], risk=8.0))
        if re.match(r"^2\.[46]\.|^3\.", kernel):
            found.append(mk("end_of_life", "high", f"Kernel {kernel} is very old",
                            "This kernel version predates many security mitigations and is likely unsupported.",
                            "Upgrade the OS/kernel.", evidence_os, ["T1068"]))
        osv_findings, osv_err = osv_check(client, distro_id, distro_version)
        if osv_err:
            found.append(mk("misconfiguration", "info", "OSV.dev supplemental check did not run", osv_err,
                            "No action needed; the NVD-based checks above still cover this host.",
                            confidence="low", risk=0.0))
        found += osv_findings

        if not is_root:
            found.append(mk("misconfiguration", "info", "Authenticated checks ran as a non-root user",
                            "Some checks (full package audit, file permission sweep) are more complete with a privileged account.",
                            "Optionally provide a sudo-capable account for deeper checks.", f"logged in as {whoami}",
                            confidence="high", risk=0.5))
    finally:
        client.close()
    return found, None


# ---------------------------------------------------------------- WinRM / Windows

_PS_HOTFIX_MISSING = """
$ErrorActionPreference='SilentlyContinue'
try{
  $u=New-Object -ComObject Microsoft.Update.Session
  $s=$u.CreateUpdateSearcher()
  $r=$s.Search("IsInstalled=0 and IsHidden=0")
  $r.Updates | ForEach-Object { $_.Title }
}catch{ "ERR:" + $_.Exception.Message }
"""

_PS_FACTS = r"""
$ErrorActionPreference='SilentlyContinue'
$os=Get-CimInstance Win32_OperatingSystem
$cs=Get-CimInstance Win32_ComputerSystem
$fwprofiles = Get-NetFirewallProfile | Select-Object Name,Enabled
$defender = Get-MpComputerStatus
$smb1 = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State
$rdp = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
$admins = (net localgroup administrators) -join "|"
[PSCustomObject]@{
  OS=$os.Caption; Build=$os.BuildNumber; LastBoot=$os.LastBootUpTime
  Firewall=($fwprofiles | ForEach-Object {"$($_.Name)=$($_.Enabled)"}) -join ","
  DefenderEnabled=$defender.AntivirusEnabled; DefenderUpToDate=$defender.AntivirusSignatureAge
  RealtimeProtection=$defender.RealTimeProtectionEnabled
  SMB1=$smb1; RDPDisabled=$rdp; Admins=$admins
} | ConvertTo-Json -Compress
"""


def winrm_audit(host, username, password, use_ssl=False, port=None):
    if winrm is None:
        return [], "pywinrm is not installed (pip install pywinrm)"
    scheme = "https" if use_ssl else "http"
    port = port or (5986 if use_ssl else 5985)
    try:
        session = winrm.Session(f"{scheme}://{host}:{port}/wsman", auth=(username, password),
                                transport="ntlm", server_cert_validation="ignore",
                                operation_timeout_sec=WINRM_TIMEOUT, read_timeout_sec=WINRM_TIMEOUT + 5)
        r = session.run_cmd("whoami")
        if r.status_code != 0:
            return [], "Connected but authentication failed: check the username and password."
    except Exception as e:
        return [], f"Could not connect over WinRM: {e}. Ensure WinRM is enabled (winrm quickconfig) and reachable."

    found = []
    try:
        facts_raw = session.run_ps(_PS_FACTS)
        import json
        facts = json.loads(facts_raw.std_out.decode(errors="replace") or "{}")
    except Exception:
        facts = {}
    os_name = facts.get("OS", "Windows")
    build = facts.get("Build", "")
    evidence = f"{os_name} build {build}".strip()

    for rx, label, date in rules.OS_EOL:
        if re.search(rx, os_name, re.I) and dt.date.fromisoformat(date) <= dt.date.today():
            found.append(mk("end_of_life", "high", f"{label} is out of support (ended {date})",
                            f"Authenticated check found this host running {os_name} (build {build}).",
                            "Upgrade the OS or isolate and plan retirement.", evidence, ["T1190"], risk=8.0))

    fw = facts.get("Firewall", "")
    for prof in re.findall(r"(\w+)=False", fw):
        found.append(mk("misconfiguration", "high", f"Windows Firewall disabled for the {prof} profile",
                        "With this profile's firewall off, inbound connections are not filtered on that network type.",
                        "Re-enable Windows Firewall for all profiles (Set-NetFirewallProfile -All -Enabled True).",
                        fw, ["T1190"]))

    if facts.get("DefenderEnabled") is False:
        found.append(mk("malware_indicator", "critical", "Microsoft Defender antivirus is disabled",
                        "Real-time antivirus protection is off, leaving the host unprotected against common malware.",
                        "Re-enable Defender, or confirm a third-party AV/EDR is active and managing this exclusion.",
                        evidence, ["T1562"], risk=9.0))
    elif facts.get("RealtimeProtection") is False:
        found.append(mk("malware_indicator", "high", "Defender real-time protection is off",
                        "Defender is present but not actively scanning in real time.",
                        "Re-enable real-time protection.", evidence, ["T1562"], risk=7.0))
    sig_age = facts.get("DefenderUpToDate")
    if isinstance(sig_age, (int, float)) and sig_age > 7:
        found.append(mk("patch_management", "medium", f"Antivirus definitions are {int(sig_age)} days old",
                        "Outdated signatures reduce detection of recent malware.",
                        "Update Defender signatures (Update-MpSignature) or check the agent's update schedule.",
                        evidence, ["T1562"]))

    if (facts.get("SMB1") or "") == "Enabled":
        found.append(mk("misconfiguration", "high", "SMBv1 is enabled",
                        "SMBv1 is obsolete and was the vector for EternalBlue (WannaCry, NotPetya).",
                        "Disable it: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
                        evidence, ["T1210", "T1021.002"]))

    if str(facts.get("RDPDisabled")) == "0":
        found.append(mk("open_port", "medium", "Remote Desktop is enabled",
                        "RDP is allowed on this host. Confirm it is intended and restricted to admins.",
                        "Disable RDP if unused, or restrict it to a jump host / VPN with NLA and MFA enforced.",
                        evidence, ["T1021.001"], confidence="medium"))

    admins = facts.get("Admins", "")
    for bad in ("Guest", "DefaultAccount"):
        if bad in admins:
            found.append(mk("misconfiguration", "high", f"Built-in '{bad}' account is a local administrator",
                            f"The {bad} account should never hold administrative rights.",
                            f"Remove {bad} from the Administrators group.", admins[:300], ["T1078.001"]))

    try:
        hotfix_raw = session.run_ps(_PS_HOTFIX_MISSING)
        lines = [l.strip() for l in hotfix_raw.std_out.decode(errors="replace").splitlines() if l.strip()]
        titles = [l for l in lines if not l.startswith("ERR:")]
        if titles:
            kbs = ", ".join(re.findall(r"KB\d+", " ".join(titles))[:8]) or f"{len(titles)} update(s)"
            sev = "high" if any(re.search(r"security|critical", t, re.I) for t in titles) else "medium"
            found.append(mk("patch_management", sev, f"{len(titles)} Windows update(s) not installed",
                            "Windows Update reports these updates as applicable and not yet installed: "
                            + "; ".join(titles[:5]) + ("..." if len(titles) > 5 else ""),
                            "Install pending updates (Windows Update, or your patch management tool).",
                            kbs, ["T1190"], confidence="high", risk=7.5 if sev == "high" else 5.5))
    except Exception:
        pass  # Windows Update COM API can be restricted by policy; other findings above still apply
    return found, None
