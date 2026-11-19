#!/usr/bin/env python3
"""Reference implementation of the lab's detections, runnable without a SIEM.

WHY THIS FILE EXISTS
    The Splunk (SPL) and Elastic (KQL / EQL / Query DSL) queries in this repository cannot be
    executed without those products. Each detection is therefore also written here in plain
    Python, using the same logic, so that the *detection idea* can be run and tested against the
    synthetic datasets on any computer. If this file finds the attack in the data, we know the
    data contains what the queries are supposed to find.

WHAT THIS FILE DOES NOT PROVE
    It does not prove that the SPL or Elastic syntax is correct. Those queries remain
    "NOT TESTED" until you run them in a real Splunk or Elastic installation.

Standard library only (Python 3.8+).

Usage:
    python3 detections/reference_detections.py --datasets datasets
"""

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

YEAR = 2026  # traditional syslog lines carry no year; the datasets describe 2026-03-14
PRIVATE_PREFIXES = ("10.", "192.168.") + tuple(f"172.{n}." for n in range(16, 32))
PRIVILEGED_GROUPS = {"sudo", "admin", "wheel", "root", "adm", "shadow", "docker", "lxd"}
OFFICE_PROCESSES = ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE")
SHELL_PROCESSES = ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe")
NETWORK_SCRIPT_HOSTS = ("powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe")

SYSLOG_LINE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<clock>\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+"
    r"(?P<process>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)
MONTHS = {name: number for number, name in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def is_private(ip):
    return ip.startswith(PRIVATE_PREFIXES) or ip.startswith("127.")


def parse_auth_log(path):
    """Yield dictionaries with time (datetime, UTC), host, process and message for every line."""
    events = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        match = SYSLOG_LINE.match(line)
        if not match:
            continue
        stamp = datetime(YEAR, MONTHS[match["month"]], int(match["day"]),
                         *map(int, match["clock"].split(":")), tzinfo=timezone.utc)
        events.append({"time": stamp, "host": match["host"], "process": match["process"], "message": match["message"]})
    return events


def iso(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


# --- Linux authentication ------------------------------------------------------------------------

FAILED = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port")
ACCEPTED = re.compile(r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port")


def ssh_bruteforce(events, threshold=10, span_seconds=300):
    """D01 - mirrors `bin _time span=5m | stats count BY _time src_ip | where count >= 10`.

    Uses fixed ("tumbling") 5-minute buckets like Splunk's `bin`, so failures that straddle a bucket
    boundary are split, which is a known limitation of this style of query.
    """
    buckets = defaultdict(lambda: {"failures": 0, "users": set()})
    for event in events:
        found = FAILED.search(event["message"])
        if not found:
            continue
        bucket = int(event["time"].timestamp() // span_seconds) * span_seconds
        entry = buckets[(bucket, found["ip"], event["host"])]
        entry["failures"] += 1
        entry["users"].add(found["user"])
    results = []
    for (bucket, ip, host), entry in sorted(buckets.items()):
        if entry["failures"] >= threshold:
            results.append({"bucket_start": iso(datetime.fromtimestamp(bucket, timezone.utc)), "src_ip": ip, "host": host,
                            "failures": entry["failures"], "distinct_users": len(entry["users"])})
    return results


def success_after_failures(events, window_seconds=600, min_failures=10):
    """D02 - mirrors `streamstats time_window=10m count(eval(result="Failed")) BY src_ip | where result="Accepted"`."""
    recent_failures = defaultdict(list)
    results = []
    for event in sorted(events, key=lambda item: item["time"]):
        now = event["time"].timestamp()
        failed = FAILED.search(event["message"])
        if failed:
            recent_failures[failed["ip"]].append(now)
            continue
        accepted = ACCEPTED.search(event["message"])
        if accepted:
            ip = accepted["ip"]
            prior = [t for t in recent_failures[ip] if now - window_seconds <= t <= now]
            if len(prior) >= min_failures:
                results.append({"time": iso(event["time"]), "user": accepted["user"], "src_ip": ip,
                                "method": accepted["method"], "prior_failures": len(prior)})
    return results


def accepted_logins(events):
    """Baseline helper - every successful SSH login. Used to ask "is this how this account normally logs in?"."""
    results = []
    for event in events:
        found = ACCEPTED.search(event["message"])
        if found:
            results.append({"time": iso(event["time"]), "user": found["user"], "method": found["method"], "src_ip": found["ip"]})
    return results



def sudo_denied(events):
    """D03 - sudo requests that were refused."""
    results = []
    for event in events:
        if event["process"] != "sudo":
            continue
        found = re.match(r"(?P<user>\S+)\s+:\s+(?P<reason>user NOT in sudoers|\d+ incorrect password attempts?)", event["message"])
        if found:
            results.append({"time": iso(event["time"]), "host": event["host"], "user": found["user"], "reason": found["reason"]})
    return results


SU_SUCCESS = re.compile(r"^\(to (?P<to_user>[^)]+)\) (?P<from_user>\S+) on (?P<tty>\S+)")
SU_FAILED = re.compile(r"^FAILED SU \(to (?P<to_user>[^)]+)\) (?P<from_user>\S+) on (?P<tty>\S+)")


def su_activity(events):
    """D04 - every `su`, successful or not."""
    results = []
    for event in events:
        if event["process"] != "su":
            continue
        for outcome, pattern in (("success", SU_SUCCESS), ("failure", SU_FAILED)):
            found = pattern.match(event["message"])
            if found:
                results.append({"time": iso(event["time"]), "from_user": found["from_user"], "to_user": found["to_user"],
                                "outcome": outcome})
    return results


def account_changes(events):
    """D05 - new accounts and additions to privileged groups."""
    results = []
    for event in events:
        created = re.match(r"new user: name=(?P<account>[^,]+)", event["message"])
        if event["process"] == "useradd" and created:
            results.append({"time": iso(event["time"]), "account": created["account"], "change": "account created"})
        added = re.match(r"add '(?P<account>[^']+)' to group '(?P<group>[^']+)'", event["message"])
        if event["process"] == "usermod" and added and added["group"] in PRIVILEGED_GROUPS:
            results.append({"time": iso(event["time"]), "account": added["account"],
                            "change": f"added to group {added['group']}"})
    return results


# --- Linux auditd -------------------------------------------------------------------------------

AUDIT_STAMP = re.compile(r"audit\((?P<epoch>\d+\.\d+):(?P<serial>\d+)\)")


def audit_records(path):
    records = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        stamp = AUDIT_STAMP.search(line)
        if not stamp:
            continue
        fields = dict(re.findall(r'\b(\w+)=("[^"]*"|\S+)', line))
        records.append({"type": re.match(r"type=(\w+)", line)[1], "epoch": float(stamp["epoch"]), "serial": stamp["serial"],
                        "fields": {key: value.strip('"') for key, value in fields.items()}})
    return records


def shadow_reads(records):
    """D06 - reads of /etc/shadow (audit key shadow_read), excluding the PAM helper, with the original login uid."""
    results = []
    for record in records:
        fields = record["fields"]
        if record["type"] == "SYSCALL" and fields.get("key") == "shadow_read" and fields.get("exe") != "/usr/sbin/unix_chkpwd":
            results.append({"time": iso(datetime.fromtimestamp(record["epoch"], timezone.utc)), "exe": fields["exe"],
                            "auid": int(fields["auid"]), "uid": int(fields["uid"])})
    return results


def session_activity(records, auid):
    """D07 - everything one login session (auid) did, even after su and sudo changed the effective user."""
    return [{"time": iso(datetime.fromtimestamp(r["epoch"], timezone.utc)), "type": r["type"], "uid": int(r["fields"]["uid"]),
             "exe": r["fields"].get("exe", "")}
            for r in records if r["fields"].get("auid") == str(auid)]


# --- Windows Sysmon -----------------------------------------------------------------------------


def load_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def image_name(path):
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def office_spawning_shell(sysmon, exclude_parents=()):
    """D08 - an Office application starting a command interpreter or script host."""
    results = []
    for event in sysmon:
        if event["EventCode"] != 1:
            continue
        parent = image_name(event["ParentImage"])
        if parent in (name.lower() for name in OFFICE_PROCESSES) and image_name(event["Image"]) in SHELL_PROCESSES:
            if parent in (name.lower() for name in exclude_parents):
                continue
            results.append({"time": event["UtcTime"], "computer": event["Computer"], "user": event["User"],
                            "parent": image_name(event["ParentImage"]), "image": image_name(event["Image"])})
    return results


def encoded_powershell(sysmon, exclude_parent_images=()):
    """D09 - PowerShell started with an encoded command. Known-good parents can be excluded (tuning)."""
    results = []
    for event in sysmon:
        if event["EventCode"] != 1 or image_name(event["Image"]) != "powershell.exe":
            continue
        if not re.search(r"\s-(?:enc|encodedcommand|ec)\s", event["CommandLine"], re.IGNORECASE):
            continue
        if any(event["ParentImage"].lower().endswith(p.lower()) for p in exclude_parent_images):
            continue
        results.append({"time": event["UtcTime"], "computer": event["Computer"], "parent": image_name(event["ParentImage"]),
                        "user": event["User"]})
    return results


def external_connections_by_script_hosts(sysmon):
    """D10 - network connections to non-private addresses made by PowerShell, script hosts or cmd."""
    grouped = defaultdict(lambda: {"count": 0, "first": None, "last": None})
    for event in sysmon:
        if event["EventCode"] != 3 or image_name(event["Image"]) not in NETWORK_SCRIPT_HOSTS:
            continue
        if is_private(event["DestinationIp"]):
            continue
        key = (event["Computer"], image_name(event["Image"]), event["DestinationIp"], event["DestinationPort"])
        entry = grouped[key]
        entry["count"] += 1
        entry["first"] = min(filter(None, [entry["first"], event["UtcTime"]]))
        entry["last"] = max(filter(None, [entry["last"], event["UtcTime"]]))
    return [{"computer": c, "image": i, "dest_ip": ip, "dest_port": port, **values} for (c, i, ip, port), values in sorted(grouped.items())]


def beaconing(sysmon, min_connections=5, max_stdev=5.0, min_interval=30, max_interval=600):
    """D11 - mirrors `streamstats ... delta ... | stats avg(delta) stdev(delta) | where stdev < 5`."""
    times = defaultdict(list)
    for event in sysmon:
        if event["EventCode"] == 3 and not is_private(event["DestinationIp"]):
            moment = datetime.strptime(event["UtcTime"], "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
            times[(event["Computer"], image_name(event["Image"]), event["DestinationIp"], event["DestinationPort"])].append(
                moment.timestamp())
    results = []
    for key, stamps in sorted(times.items()):
        stamps.sort()
        deltas = [b - a for a, b in zip(stamps, stamps[1:])]
        if len(stamps) < min_connections or not deltas:
            continue
        mean = sum(deltas) / len(deltas)
        stdev = (sum((d - mean) ** 2 for d in deltas) / (len(deltas) - 1)) ** 0.5 if len(deltas) > 1 else 0.0
        if stdev < max_stdev and min_interval <= mean <= max_interval:
            results.append({"computer": key[0], "image": key[1], "dest_ip": key[2], "dest_port": key[3],
                            "connections": len(stamps), "avg_interval_s": round(mean, 1), "stdev_s": round(stdev, 2)})
    return results


# --- Cross-source pivot ---------------------------------------------------------------------------


def ioc_pivot(ioc, auth_lines, sysmon):
    """D12 - where does one indicator (an IP address) appear? Mirrors the SPL pivot over several sourcetypes."""
    hits = {"linux_secure": sum(ioc in line for line in auth_lines),
            "sysmon": sum(1 for event in sysmon if ioc in json.dumps(event))}
    return {source: count for source, count in hits.items() if count}


# --------------------------------------------------------------------------------------------------


def run_all(datasets):
    datasets = Path(datasets)
    auth_path = datasets / "linux" / "auth.log"
    events = parse_auth_log(auth_path)
    records = audit_records(datasets / "linux" / "audit.log")
    sysmon = load_jsonl(datasets / "windows" / "sysmon_native.jsonl")
    auth_lines = auth_path.read_text(encoding="utf-8").splitlines()
    return {
        "D01_ssh_bruteforce": ssh_bruteforce(events),
        "D02_success_after_failures": success_after_failures(events),
        "baseline_accepted_logins": accepted_logins(events),
        "D03_sudo_denied": sudo_denied(events),
        "D04_su_activity": su_activity(events),
        "D05_account_changes": account_changes(events),
        "D06_shadow_reads": shadow_reads(records),
        "D07_session_activity_auid_1002": session_activity(records, 1002),
        "D08_office_spawning_shell": office_spawning_shell(sysmon),
        "D09_encoded_powershell": encoded_powershell(sysmon),
        "D09b_encoded_powershell_tuned": encoded_powershell(sysmon, exclude_parent_images=[r"\HarborInventory\agent.exe"]),
        "D10_external_connections_by_script_hosts": external_connections_by_script_hosts(sysmon),
        "D11_beaconing": beaconing(sysmon),
        "D12_ioc_pivot_203.0.113.45": ioc_pivot("203.0.113.45", auth_lines, sysmon),
    }


def main():
    parser = argparse.ArgumentParser(description="Run the reference detections on the synthetic datasets.")
    parser.add_argument("--datasets", default="datasets", help="folder that contains linux/ and windows/ (default: datasets)")
    args = parser.parse_args()
    print(json.dumps(run_all(args.datasets), indent=2))


if __name__ == "__main__":
    main()
