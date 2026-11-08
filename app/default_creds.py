"""Default-credential checks: tries a short, well-known list of factory logins against a device,
the same check most commercial vulnerability scanners (Nessus, OpenVAS) include. This is opt-in,
only runs against hosts inside the authorized scan range, stops at the first success per
service, and is rate-limited to avoid hammering fragile devices or locking out real accounts.

This is not a general brute-force tool: the list is short and fixed, not an imported wordlist,
and there is no way to extend it from the API or UI.
"""
import ftplib
import socket
import time

import requests
import urllib3

from . import rules

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # self-signed certs are normal on device admin pages

try:
    import paramiko
except ImportError:
    paramiko = None

DELAY = 0.6  # seconds between attempts, per host
TIMEOUT = 5

# (username, password) - common factory/vendor defaults. Keep this list short and well-known;
# it is a sanity check for "was the default ever changed", not a password-cracking wordlist.
SSH_FTP_PAIRS = [
    ("admin", "admin"), ("admin", "password"), ("admin", ""), ("root", "root"),
    ("root", "toor"), ("root", ""), ("admin", "1234"), ("ubnt", "ubnt"),
    ("pi", "raspberry"), ("administrator", "administrator"),
]
HTTP_PAIRS = SSH_FTP_PAIRS + [("admin", "admin123"), ("admin", "12345")]
TELNET_PAIRS = SSH_FTP_PAIRS


def mk(ip, protocol, port, username, password):
    shown = password if password else "(blank)"
    return rules.mk(
        "misconfiguration", "critical", f"Default credential works over {protocol.upper()} ({username}/{shown})",
        f"The device accepted the well-known default login {username}/{shown} over {protocol.upper()} on port {port}. "
        "Anyone on the network can use this to log in.",
        "Change this password immediately and check vendor documentation for any other default accounts on this device.",
        port=port, proto=protocol, evidence=f"{protocol} {port}: {username}/{shown} succeeded",
        attack=["T1078.001"], confidence="high", risk=10.0)


def check_ssh(ip, port=22):
    if paramiko is None:
        return []
    for user, pw in SSH_FTP_PAIRS:
        time.sleep(DELAY)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(ip, port=port, username=user, password=pw, timeout=TIMEOUT,
                           banner_timeout=TIMEOUT, auth_timeout=TIMEOUT, allow_agent=False, look_for_keys=False)
            client.close()
            return [mk(ip, "ssh", port, user, pw)]
        except paramiko.AuthenticationException:
            continue
        except Exception:
            return []  # connection-level failure; don't keep retrying a dead service
    return []


def check_ftp(ip, port=21):
    for user, pw in SSH_FTP_PAIRS:
        time.sleep(DELAY)
        try:
            f = ftplib.FTP(timeout=TIMEOUT)
            f.connect(ip, port, timeout=TIMEOUT)
            f.login(user, pw)
            f.quit()
            return [mk(ip, "ftp", port, user, pw)]
        except ftplib.error_perm:
            continue
        except Exception:
            return []
    return []


def check_telnet(ip, port=23):
    for user, pw in TELNET_PAIRS:
        time.sleep(DELAY)
        try:
            sock = socket.create_connection((ip, port), timeout=TIMEOUT)
            sock.settimeout(TIMEOUT)
            banner = b""
            try:
                banner = sock.recv(2048)
            except socket.timeout:
                pass
            sock.sendall((user + "\r\n").encode())
            time.sleep(0.4)
            try:
                banner += sock.recv(2048)
            except socket.timeout:
                pass
            sock.sendall((pw + "\r\n").encode())
            time.sleep(0.6)
            try:
                banner += sock.recv(4096)
            except socket.timeout:
                pass
            sock.close()
            text = banner.decode(errors="ignore").lower()
            # heuristic: a shell-like prompt or "welcome" and no repeated login prompt means we're in
            if any(p in text for p in ("$", "#", ">", "welcome")) and text.count("login") < 2 and "incorrect" not in text:
                return [mk(ip, "telnet", port, user, pw)]
        except Exception:
            return []
    return []


def check_http(ip, port, use_https=False):
    scheme = "https" if use_https else "http"
    for user, pw in HTTP_PAIRS:
        time.sleep(DELAY)
        try:
            r = requests.get(f"{scheme}://{ip}:{port}/", auth=(user, pw), timeout=TIMEOUT, verify=False)
            if r.status_code in (200, 302) and r.status_code != 401:
                # Only trust this if an unauthenticated request to the same URL was rejected;
                # otherwise the page simply doesn't require auth at all.
                anon = requests.get(f"{scheme}://{ip}:{port}/", timeout=TIMEOUT, verify=False)
                if anon.status_code == 401:
                    return [mk(ip, f"http{'s' if use_https else ''}", port, user, pw)]
                return []
        except requests.RequestException:
            return []
    return []


# port -> checker. HTTP(S) admin ports are checked too since routers/cameras often serve login on them.
CHECKERS = {
    22: lambda ip: check_ssh(ip, 22), 21: lambda ip: check_ftp(ip, 21), 23: lambda ip: check_telnet(ip, 23),
    80: lambda ip: check_http(ip, 80), 8080: lambda ip: check_http(ip, 8080),
    443: lambda ip: check_http(ip, 443, True), 8443: lambda ip: check_http(ip, 8443, True),
}


def run(host):
    """host: parsed Nmap host dict. Returns a findings list; stops at the first hit per port."""
    out = []
    for p in host.get("ports") or []:
        checker = CHECKERS.get(p["port"])
        if checker and p["proto"] == "tcp":
            try:
                out += checker(host["ip"])
            except Exception:
                pass
    return out
