#!/usr/bin/env python3
"""Generate the synthetic security logs for the fictional "Harbor Lab" incident.

SYNTHETIC DATA ONLY. Every host, user, IP address and hash below is invented.
External addresses come from the RFC 5737 documentation ranges, which are
reserved for examples and are never routed on the public Internet.

The output is deterministic (fixed random seed): running the script twice
produces byte-identical files, so the datasets can be re-created and reviewed
like source code.

Outputs (written below --out-dir):
    linux/auth.log          Ubuntu-style /var/log/auth.log (traditional syslog format)
    linux/auth_ecs.jsonl    The same events as a Filebeat-like ECS JSON approximation
    linux/audit.log         auditd records (simplified, see docs/log-normalization.md)
    windows/sysmon_native.jsonl   Sysmon events with native field names (Splunk-friendly)
    windows/sysmon_ecs.jsonl      The same events with ECS field names (Elastic-friendly)
"""

import argparse
import base64
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 20260314
UTC = timezone.utc
INCIDENT_DAY = datetime(2026, 3, 14, tzinfo=UTC)

LAB_DOMAIN = "harbor.test"
LINUX_HOST = "web01"
WINDOWS_HOST = "WS01"
ATTACKER_IP = "203.0.113.45"  # RFC 5737 TEST-NET-3
JUMP_HOST_IP = "10.10.30.5"
BACKUP_SERVER_IP = "10.10.30.40"
VULN_SCANNER_IP = "10.10.30.60"
WS01_IP = "10.10.10.20"

UIDS = {"root": 0, "labadmin": 1000, "svc-backup": 1002, "support01": 1003}
VALID_SSH_USERS = {"root", "labadmin", "svc-backup", "deploy"}


def at(hour, minute, second=0, millis=0):
    """Return a UTC timestamp on the incident day."""
    return INCIDENT_DAY.replace(hour=hour, minute=minute, second=second, microsecond=millis * 1000)


def iso_z(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def syslog_time(ts):
    # Traditional syslog pads single-digit days with a space ("Mar  4"). It has no year.
    return f"{ts.strftime('%b')} {ts.day:>2} {ts.strftime('%H:%M:%S')}"


def deep_merge(base, extra):
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base


# ---------------------------------------------------------------------------
# Linux authentication log
# ---------------------------------------------------------------------------


class AuthLog:
    """Collects authentication events and renders them as syslog text and ECS JSON."""

    def __init__(self, rng):
        self.rng = rng
        self.events = []  # (timestamp, program, pid, message, ecs_fields)
        self.used_pids = set()

    def pid_for(self, ts):
        # Process IDs grow during the day, like on a real machine, and are never reused.
        pid = 900 + int((ts - INCIDENT_DAY).total_seconds()) // 15
        while pid in self.used_pids:
            pid += 1
        self.used_pids.add(pid)
        return pid

    def add(self, ts, program, message, pid=None, ecs=None):
        self.events.append((ts, program, pid, message, ecs or {}))

    # --- sshd -------------------------------------------------------------
    def ssh_failed(self, ts, user, ip):
        pid, port = self.pid_for(ts), self.rng.randint(40000, 60000)
        valid = user in VALID_SSH_USERS
        ecs = {
            "event": {"category": ["authentication"], "action": "ssh_login", "outcome": "failure"},
            "source": {"ip": ip, "port": port},
            "user": {"name": user},
            "system": {"auth": {"ssh": {"event": "Failed", "method": "password"}}},
        }
        if valid:
            self.add(ts, "sshd", f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={user}", pid)
            self.add(ts, "sshd", f"Failed password for {user} from {ip} port {port} ssh2", pid, ecs)
        else:
            self.add(ts, "sshd", f"Invalid user {user} from {ip} port {port}", pid,
                     {"event": {"category": ["authentication"], "action": "ssh_login", "outcome": "failure"},
                      "source": {"ip": ip, "port": port}, "user": {"name": user},
                      "system": {"auth": {"ssh": {"event": "Invalid"}}}})
            self.add(ts, "sshd", "pam_unix(sshd:auth): check pass; user unknown", pid)
            self.add(ts, "sshd", f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}", pid)
            self.add(ts, "sshd", f"Failed password for invalid user {user} from {ip} port {port} ssh2", pid, ecs)
            self.add(ts, "sshd", f"Connection closed by invalid user {user} {ip} port {port} [preauth]", pid)

    def ssh_accepted(self, ts, user, ip, method="password"):
        pid, port = self.pid_for(ts), self.rng.randint(40000, 60000)
        ecs = {
            "event": {"category": ["authentication"], "action": "ssh_login", "outcome": "success"},
            "source": {"ip": ip, "port": port},
            "user": {"name": user},
            "system": {"auth": {"ssh": {"event": "Accepted", "method": method}}},
        }
        self.add(ts, "sshd", f"Accepted {method} for {user} from {ip} port {port} ssh2", pid, ecs)
        self.add(ts, "sshd", f"pam_unix(sshd:session): session opened for user {user}(uid={UIDS.get(user, 1100)}) by (uid=0)", pid)
        return pid, port

    def ssh_closed(self, ts, user, ip, pid, port):
        self.add(ts, "sshd", f"Disconnected from user {user} {ip} port {port}", pid)
        self.add(ts, "sshd", f"pam_unix(sshd:session): session closed for user {user}", pid)

    # --- sudo / su / account management ----------------------------------------
    def sudo_command(self, ts, user, command, cwd=None, target="root"):
        cwd = cwd or f"/home/{user}"
        ecs = {"event": {"category": ["process"], "action": "sudo_command", "outcome": "success"},
               "user": {"name": user, "effective": {"name": target}},
               "process": {"name": "sudo", "args": command.split()}}
        self.add(ts, "sudo", f"{user} : TTY=pts/0 ; PWD={cwd} ; USER={target} ; COMMAND={command}", ecs=ecs)
        self.add(ts, "sudo", f"pam_unix(sudo:session): session opened for user {target}(uid=0) by {user}(uid={UIDS.get(user, 1100)})")

    def sudo_not_in_sudoers(self, ts, user, command):
        ecs = {"event": {"category": ["process"], "action": "sudo_command", "outcome": "failure"},
               "user": {"name": user}}
        self.add(ts, "sudo", f"{user} : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}", ecs=ecs)

    def su_failed(self, ts, from_user, to_user):
        pid = self.pid_for(ts)
        ecs = {"event": {"category": ["authentication"], "action": "su", "outcome": "failure"},
               "user": {"name": from_user, "target": {"name": to_user}}}
        self.add(ts, "su", f"FAILED SU (to {to_user}) {from_user} on pts/0", pid, ecs)

    def su_success(self, ts, from_user, to_user):
        pid = self.pid_for(ts)
        ecs = {"event": {"category": ["authentication"], "action": "su", "outcome": "success"},
               "user": {"name": from_user, "target": {"name": to_user}}}
        self.add(ts, "su", f"(to {to_user}) {from_user} on pts/0", pid, ecs)
        self.add(ts, "su", f"pam_unix(su-l:session): session opened for user {to_user}(uid={UIDS[to_user]}) by {from_user}(uid={UIDS[from_user]})", pid)

    def useradd(self, ts, user):
        pid, uid = self.pid_for(ts), UIDS[user]
        ecs = {"event": {"category": ["iam"], "type": ["creation", "user"], "action": "user_added", "outcome": "success"},
               "user": {"name": user}}
        self.add(ts, "useradd", f"new group: name={user}, GID={uid}", pid)
        self.add(ts, "useradd", f"new user: name={user}, UID={uid}, GID={uid}, home=/home/{user}, shell=/bin/bash, from=/dev/pts/0", pid, ecs)

    def usermod_add_group(self, ts, user, group):
        pid = self.pid_for(ts)
        ecs = {"event": {"category": ["iam"], "type": ["change", "group"], "action": "added-user-to-group", "outcome": "success"},
               "user": {"name": user, "group": {"name": group}}}
        self.add(ts, "usermod", f"add '{user}' to group '{group}'", pid, ecs)
        self.add(ts, "usermod", f"add '{user}' to shadow group '{group}'", pid)

    def passwd_changed(self, ts, user):
        pid = self.pid_for(ts)
        self.add(ts, "passwd", f"pam_unix(passwd:chauthtok): password changed for {user}", pid,
                 {"event": {"category": ["iam"], "action": "password_changed", "outcome": "success"}, "user": {"name": user}})

    def cron_session(self, ts):
        pid = self.pid_for(ts)
        self.add(ts, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", pid)
        self.add(ts + timedelta(seconds=1), "CRON", "pam_unix(cron:session): session closed for user root", pid)

    # --- rendering -----------------------------------------------------------
    def sorted_events(self):
        return sorted(self.events, key=lambda event: event[0])  # stable sort keeps same-second order

    def render_syslog(self):
        lines = []
        for ts, program, pid, message, _ in self.sorted_events():
            tag = f"{program}[{pid}]" if pid is not None else program
            lines.append(f"{syslog_time(ts)} {LINUX_HOST} {tag}: {message}")
        return "\n".join(lines) + "\n"

    def render_ecs(self):
        docs = []
        for ts, program, pid, message, extra in self.sorted_events():
            if not extra:
                continue  # only events with a security meaning are exported as ECS documents
            doc = {
                "@timestamp": iso_z(ts),
                "host": {"name": LINUX_HOST},
                "event": {"dataset": "system.auth", "module": "system", "kind": "event"},
                "process": {"name": program, "pid": pid} if pid is not None else {"name": program},
                "message": message,
                "labels": {"synthetic": "true"},
            }
            docs.append(deep_merge(doc, extra))
        return docs


def build_auth_log(rng):
    log = AuthLog(rng)

    # Normal background: hourly cron sessions (noise that detections must ignore).
    for hour in range(0, 13):
        log.cron_session(at(hour, 17, 1))

    # 02:00 - the legitimate nightly backup login uses a public key from the backup server.
    pid, port = log.ssh_accepted(at(2, 0, 5), "svc-backup", BACKUP_SERVER_IP, method="publickey")
    log.ssh_closed(at(2, 14, 30), "svc-backup", BACKUP_SERVER_IP, pid, port)

    # 07:00 - an authorised vulnerability scanner checks credentials: a known false positive.
    for i in range(7):
        log.ssh_failed(at(7, 0, 4 * i + 3), "nessus-probe", VULN_SCANNER_IP)

    # 08:30 - an administrator mistypes a password twice (below any sensible threshold).
    log.ssh_failed(at(8, 30, 12), "labadmin", JUMP_HOST_IP)
    log.ssh_failed(at(8, 30, 19), "labadmin", JUMP_HOST_IP)
    pid, port = log.ssh_accepted(at(8, 30, 31), "labadmin", JUMP_HOST_IP, method="publickey")
    log.sudo_command(at(8, 35, 2), "labadmin", "/usr/bin/apt update")
    # A legitimate but "sensitive" administrator action: detections must not blindly treat it as an attack.
    log.sudo_command(at(9, 5, 12), "labadmin", "/usr/sbin/visudo -c")
    log.sudo_command(at(12, 40, 17), "labadmin", "/usr/bin/systemctl restart nginx")
    log.ssh_closed(at(12, 55, 0), "labadmin", JUMP_HOST_IP, pid, port)

    # 10:02 - password guessing from the attacker, about 56 attempts in 3.5 minutes.
    guesses = ["admin", "root", "test", "ubuntu", "oracle", "postgres", "user", "guest",
               "pi", "ftpuser", "deploy", "support"]
    ts = at(10, 2, 11)
    for attempt in range(56):
        log.ssh_failed(ts, guesses[attempt % len(guesses)], ATTACKER_IP)
        ts += timedelta(seconds=rng.uniform(2.5, 4.5))  # a scripted tool tries a password every few seconds

    # 10:06 - three failures against the real service account, then a successful login.
    for second in (12, 16, 20):
        log.ssh_failed(at(10, 6, second), "svc-backup", ATTACKER_IP)
    ssh_pid, ssh_port = log.ssh_accepted(at(10, 6, 41), "svc-backup", ATTACKER_IP, method="password")

    # 10:08 - privilege escalation attempts: sudo is denied, su fails once, then succeeds.
    log.sudo_not_in_sudoers(at(10, 8, 5), "svc-backup", "/usr/bin/bash")
    log.su_failed(at(10, 8, 40), "svc-backup", "labadmin")
    log.su_success(at(10, 9, 30), "svc-backup", "labadmin")
    log.sudo_command(at(10, 10, 2), "labadmin", "/bin/bash", cwd="/home/labadmin")

    # 10:11 - persistence: a new account with sudo rights is created from the root shell.
    log.useradd(at(10, 11, 20), "support01")
    log.passwd_changed(at(10, 11, 35), "support01")
    log.usermod_add_group(at(10, 11, 50), "support01", "sudo")

    # The attacker leaves.
    log.ssh_closed(at(10, 14, 30), "svc-backup", ATTACKER_IP, ssh_pid, ssh_port)
    return log


# ---------------------------------------------------------------------------
# auditd
# ---------------------------------------------------------------------------


class AuditLog:
    """Renders simplified auditd records. 'auid' is the original login uid and survives su/sudo."""

    def __init__(self):
        self.lines = []
        self.sequence = 400

    def event(self, ts, records):
        """Add several records that belong to the same event (same timestamp and serial)."""
        self.sequence += 1
        stamp = f"audit({ts.timestamp():.3f}:{self.sequence})"
        for record_type, body in records:
            self.lines.append((ts, f"type={record_type} msg={stamp}: {body}"))

    def render(self):
        return "\n".join(line for _, line in sorted(self.lines, key=lambda item: item[0])) + "\n"


def hex_cmd(command):
    return command.encode().hex().upper()


def build_audit_log():
    audit = AuditLog()
    common = "uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0"

    # Background noise: the PAM helper reads /etc/shadow whenever someone logs in (a false-positive source).
    for second in (28, 29, 30):
        audit.event(at(8, 30, second, 211), [
            ("SYSCALL", 'arch=c000003e syscall=257 success=yes exit=4 a0=ffffff9c items=1 ppid=2011 pid=2040 '
                        f'auid=4294967295 {common} tty=(none) ses=4294967295 comm="unix_chkpwd" '
                        'exe="/usr/sbin/unix_chkpwd" key="shadow_read"'),
            ("PATH", 'item=0 name="/etc/shadow" inode=131245 dev=fd:00 mode=0100640 ouid=0 ogid=42 rdev=00:00 nametype=NORMAL'),
        ])

    # Legitimate administrator command.
    audit.event(at(8, 35, 2, 310), [
        ("USER_CMD", "pid=1580 uid=1000 auid=1000 ses=11 msg='cwd=\"/home/labadmin\" "
                     f"cmd={hex_cmd('/usr/bin/apt update')} exe=\"/usr/bin/sudo\" terminal=pts/0 res=success'"),
    ])

    # 10:10 - labadmin (auid=1002 = the svc-backup login session) starts a root shell with sudo.
    audit.event(at(10, 10, 2, 480), [
        ("USER_CMD", "pid=2231 uid=1000 auid=1002 ses=14 msg='cwd=\"/home/labadmin\" "
                     "cmd=\"/bin/bash\" exe=\"/usr/bin/sudo\" terminal=pts/0 res=success'"),
    ])

    # 10:11 - account creation from the root shell.
    audit.event(at(10, 11, 20, 120), [
        ("SYSCALL", 'arch=c000003e syscall=59 success=yes exit=0 a0=55d0c8e2 items=2 ppid=2236 pid=2301 '
                    f'auid=1002 {common} tty=pts0 ses=14 comm="useradd" exe="/usr/sbin/useradd" key="user_mgmt"'),
        ("EXECVE", 'argc=5 a0="useradd" a1="-m" a2="-s" a3="/bin/bash" a4="support01"'),
        ("ADD_USER", "pid=2301 uid=0 auid=1002 ses=14 msg='op=adding user id=1003 "
                     "exe=\"/usr/sbin/useradd\" hostname=? addr=? terminal=pts/0 res=success'"),
    ])
    audit.event(at(10, 11, 50, 640), [
        ("SYSCALL", 'arch=c000003e syscall=59 success=yes exit=0 a0=55d0c8f1 items=2 ppid=2236 pid=2310 '
                    f'auid=1002 {common} tty=pts0 ses=14 comm="usermod" exe="/usr/sbin/usermod" key="user_mgmt"'),
        ("EXECVE", 'argc=4 a0="usermod" a1="-aG" a2="sudo" a3="support01"'),
    ])

    # 10:12 - credential access: the root shell reads /etc/shadow.
    audit.event(at(10, 12, 44, 90), [
        ("SYSCALL", 'arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c items=1 ppid=2236 pid=2322 '
                    f'auid=1002 {common} tty=pts0 ses=14 comm="cat" exe="/usr/bin/cat" key="shadow_read"'),
        ("EXECVE", 'argc=2 a0="cat" a1="/etc/shadow"'),
        ("PATH", 'item=0 name="/etc/shadow" inode=131245 dev=fd:00 mode=0100640 ouid=0 ogid=42 rdev=00:00 nametype=NORMAL'),
    ])
    return audit


# ---------------------------------------------------------------------------
# Windows Sysmon
# ---------------------------------------------------------------------------

WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
EXPLORER = r"C:\Windows\explorer.exe"
CMD = r"C:\Windows\System32\cmd.exe"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
WSCRIPT = r"C:\Windows\System32\wscript.exe"
CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
NOTEPAD = r"C:\Windows\System32\notepad.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"
AGENT = r"C:\Program Files\HarborInventory\agent.exe"  # fictional inventory agent
DROPPED_SCRIPT = r"C:\Users\jdoe\AppData\Local\Temp\harbor_update.js"


def encode_powershell(script):
    """PowerShell's -EncodedCommand expects base64 of the UTF-16LE text."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


class SysmonLog:
    def __init__(self, rng):
        self.rng = rng
        self.events = []
        self.next_pid = 3000

    def new_process(self, ts, image, command_line, parent, user="HARBOR\\jdoe", integrity="Medium"):
        """Record a Sysmon event 1 and return a small handle other events can refer to."""
        self.next_pid += self.rng.randint(4, 40)
        sha = hashlib.sha256(f"synthetic-binary:{image}".encode()).hexdigest()
        guid = "{" + hashlib.md5(f"{ts.isoformat()}{image}".encode()).hexdigest()[:8] + "-0000-0000-0000-" + f"{self.next_pid:012x}" + "}"
        process = {"image": image, "pid": self.next_pid, "guid": guid, "command_line": command_line, "user": user}
        self.events.append({"ts": ts, "code": 1, "process": process, "parent": parent, "integrity": integrity, "sha256": sha})
        return process

    def network(self, ts, process, dest_ip, dest_port, user="HARBOR\\jdoe"):
        self.events.append({"ts": ts, "code": 3, "process": dict(process, user=user), "dest_ip": dest_ip,
                            "dest_port": dest_port, "src_port": self.rng.randint(49152, 65000)})

    def file_create(self, ts, process, target):
        self.events.append({"ts": ts, "code": 11, "process": process, "target": target})

    def sorted_events(self):
        return sorted(self.events, key=lambda event: event["ts"])


def sysmon_utc(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S.") + f"{ts.microsecond // 1000:03d}"


def build_sysmon(rng):
    log = SysmonLog(rng)
    explorer = {"image": EXPLORER, "pid": 2840, "guid": "{5a1c3f2e-0000-0000-0000-000000002840}",
                "command_line": EXPLORER, "user": "HARBOR\\jdoe"}
    agent_parent = {"image": AGENT, "pid": 1904, "guid": "{5a1c3f2e-0000-0000-0000-000000001904}",
                    "command_line": f'"{AGENT}" --collect', "user": "NT AUTHORITY\\SYSTEM"}

    # Normal user activity during the morning.
    chrome = log.new_process(at(8, 52, 10), CHROME, f'"{CHROME}"', explorer)
    for minute, ip in ((53, "198.51.100.80"), (58, "198.51.100.81"), (4, "198.51.100.80")):
        hour = 9 if minute == 4 else 8
        log.network(at(hour, minute, 20, 100), chrome, ip, 443)
    log.new_process(at(9, 15, 44), NOTEPAD, f'"{NOTEPAD}" C:\\Users\\jdoe\\Documents\\todo.txt', explorer)
    clean_doc = log.new_process(at(9, 40, 3), WINWORD, f'"{WINWORD}" "C:\\Users\\jdoe\\Documents\\Report.docx"', explorer)
    log.network(at(9, 40, 9), clean_doc, "198.51.100.90", 443)  # benign Word Online connection

    # Known false positive: the inventory agent runs an encoded (but benign) PowerShell command.
    benign_encoded = encode_powershell("Get-ComputerInfo | Out-Null")
    log.new_process(at(9, 0, 30), POWERSHELL,
                    f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {benign_encoded}",
                    agent_parent, user="NT AUTHORITY\\SYSTEM", integrity="System")

    # Background svchost DNS traffic.
    svchost = {"image": SVCHOST, "pid": 1120, "guid": "{5a1c3f2e-0000-0000-0000-000000001120}",
               "command_line": f"{SVCHOST} -k NetworkService -p -s Dnscache", "user": "NT AUTHORITY\\NETWORK SERVICE"}
    for minute in (5, 25, 45):
        log.network(at(10, minute, 2, 300), svchost, "10.10.10.1", 53, user="NT AUTHORITY\\NETWORK SERVICE")

    # 11:29 - the suspicious document is opened.
    word = log.new_process(at(11, 29, 48, 120), WINWORD,
                           f'"{WINWORD}" "C:\\Users\\jdoe\\Downloads\\Invoice_March.docm"', explorer)

    # 11:30 - Word starts cmd.exe, which starts an encoded PowerShell command (harmless message).
    payload = encode_powershell('Write-Output "synthetic training event - harmless"')
    ps_args = f"-NoProfile -WindowStyle Hidden -EncodedCommand {payload}"
    cmd = log.new_process(at(11, 30, 14, 512), CMD, f"cmd.exe /c powershell.exe {ps_args}", word)
    powershell = log.new_process(at(11, 30, 14, 903), POWERSHELL, f"powershell.exe {ps_args}", cmd)
    log.network(at(11, 30, 16, 205), powershell, ATTACKER_IP, 443)
    log.file_create(at(11, 30, 17, 640), powershell, DROPPED_SCRIPT)
    script = log.new_process(at(11, 30, 20, 77), WSCRIPT, f'"{WSCRIPT}" "{DROPPED_SCRIPT}"', powershell)

    # 11:31-11:38 - beaconing: one connection about every 60 seconds, with a little jitter.
    ts = at(11, 31, 20)
    for _ in range(8):
        log.network(ts, script, ATTACKER_IP, 443)
        ts += timedelta(seconds=60 + rng.uniform(-1.5, 1.5))

    # Discovery commands run by the script.
    for offset, (image, args) in enumerate(((r"C:\Windows\System32\whoami.exe", "whoami /all"),
                                            (r"C:\Windows\System32\ipconfig.exe", "ipconfig /all"),
                                            (r"C:\Windows\System32\net.exe", "net user"))):
        log.new_process(at(11, 36, 40 + 5 * offset), image, args, script)
    return log


def render_sysmon_native(log):
    docs = []
    descriptions = {1: "Process Create", 3: "Network connection detected", 11: "File created"}
    for event in log.sorted_events():
        process, code = event["process"], event["code"]
        doc = {
            "UtcTime": sysmon_utc(event["ts"]),
            "Computer": f"{WINDOWS_HOST}.{LAB_DOMAIN}",
            "EventCode": code,
            "EventDescription": descriptions[code],
            "ProcessGuid": process["guid"],
            "ProcessId": process["pid"],
            "Image": process["image"],
            "User": process["user"],
            "labels": {"synthetic": "true"},
        }
        if code == 1:
            parent = event["parent"]
            doc.update({"CommandLine": process["command_line"], "IntegrityLevel": event["integrity"],
                        "Hashes": f"SHA256={event['sha256']}", "ParentImage": parent["image"],
                        "ParentProcessId": parent["pid"], "ParentCommandLine": parent["command_line"]})
        elif code == 3:
            doc.update({"Protocol": "tcp", "Initiated": "true", "SourceIp": WS01_IP, "SourcePort": event["src_port"],
                        "DestinationIp": event["dest_ip"], "DestinationPort": event["dest_port"]})
        elif code == 11:
            doc.update({"TargetFilename": event["target"]})
        docs.append(doc)
    return docs


def windows_name(path):
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


def render_sysmon_ecs(log):
    docs = []
    for event in log.sorted_events():
        process, code = event["process"], event["code"]
        user_domain, _, user_name = process["user"].rpartition("\\")
        doc = {
            "@timestamp": iso_z(event["ts"]),
            "host": {"name": WINDOWS_HOST},
            "event": {"code": str(code), "provider": "Microsoft-Windows-Sysmon", "kind": "event"},
            "winlog": {"event_id": str(code), "channel": "Microsoft-Windows-Sysmon/Operational",
                       "computer_name": f"{WINDOWS_HOST}.{LAB_DOMAIN}"},
            "user": {"name": user_name, "domain": user_domain},
            "process": {"pid": process["pid"], "entity_id": process["guid"], "executable": process["image"],
                        "name": windows_name(process["image"])},
            "labels": {"synthetic": "true"},
        }
        if code == 1:
            parent = event["parent"]
            doc["event"].update({"category": ["process"], "type": ["start"], "action": "Process Create (rule: ProcessCreate)"})
            doc["process"].update({"command_line": process["command_line"], "hash": {"sha256": event["sha256"]},
                                   "parent": {"pid": parent["pid"], "executable": parent["image"],
                                              "name": windows_name(parent["image"]),
                                              "command_line": parent["command_line"]}})
        elif code == 3:
            doc["event"].update({"category": ["network"], "type": ["connection", "start"],
                                 "action": "Network connection detected (rule: NetworkConnect)"})
            doc["network"] = {"protocol": "tcp", "transport": "tcp", "direction": "egress"}
            doc["source"] = {"ip": WS01_IP, "port": event["src_port"]}
            doc["destination"] = {"ip": event["dest_ip"], "port": event["dest_port"]}
        elif code == 11:
            doc["event"].update({"category": ["file"], "type": ["creation"], "action": "File created (rule: FileCreate)"})
            doc["file"] = {"path": event["target"], "name": windows_name(event["target"])}
        docs.append(doc)
    return docs


# ---------------------------------------------------------------------------


def write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    # open() instead of Path.write_text(newline=...), which needs Python 3.10+.
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def write_jsonl(path, docs):
    write_text(path, "".join(json.dumps(doc, separators=(",", ":")) + "\n" for doc in docs))


def generate(out_dir):
    rng = random.Random(SEED)
    auth = build_auth_log(rng)
    write_text(out_dir / "linux" / "auth.log", auth.render_syslog())
    write_jsonl(out_dir / "linux" / "auth_ecs.jsonl", auth.render_ecs())
    write_text(out_dir / "linux" / "audit.log", build_audit_log().render())
    sysmon = build_sysmon(rng)
    write_jsonl(out_dir / "windows" / "sysmon_native.jsonl", render_sysmon_native(sysmon))
    write_jsonl(out_dir / "windows" / "sysmon_ecs.jsonl", render_sysmon_ecs(sysmon))


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic Harbor Lab security logs.")
    parser.add_argument("--out-dir", default="datasets", help="directory to write the datasets to (default: datasets)")
    args = parser.parse_args()
    out_dir = Path(args.out_dir)
    generate(out_dir)
    for path in sorted(out_dir.rglob("*")):
        if path.is_file() and path.suffix in {".log", ".jsonl"}:
            print(f"wrote {path} ({sum(1 for _ in path.open(encoding='utf-8'))} lines)")


if __name__ == "__main__":
    main()
