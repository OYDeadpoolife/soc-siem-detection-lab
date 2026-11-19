"""The synthetic datasets: reproducible, well-formed, clearly synthetic, free of real-looking data."""

import base64
import ipaddress
import re
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import DATASETS, ROOT, read_jsonl

FILES = {
    "linux/auth.log": 353,
    "linux/auth_ecs.jsonl": 135,
    "linux/audit.log": 16,
    "windows/sysmon_native.jsonl": 28,
    "windows/sysmon_ecs.jsonl": 28,
}
ALLOWED_NETWORKS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24")]


@pytest.mark.parametrize("relative, lines", FILES.items())
def test_files_exist_with_the_expected_number_of_lines(relative, lines):
    text = (DATASETS / relative).read_text(encoding="utf-8")
    assert len(text.splitlines()) == lines
    assert text.endswith("\n")


def test_datasets_are_reproducible(tmp_path):
    subprocess.run([sys.executable, str(ROOT / "tools/generate_synthetic_logs.py"), "--out-dir", str(tmp_path)],
                   check=True, capture_output=True)
    for relative in FILES:
        assert (tmp_path / relative).read_bytes() == (DATASETS / relative).read_bytes(), relative


def test_every_json_document_is_marked_synthetic():
    for relative in ("linux/auth_ecs.jsonl", "windows/sysmon_native.jsonl", "windows/sysmon_ecs.jsonl"):
        for document in read_jsonl(DATASETS / relative):
            assert document["labels"] == {"synthetic": "true"}, relative


def test_only_documentation_and_private_addresses_are_used():
    for relative in FILES:
        for address in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", (DATASETS / relative).read_text(encoding="utf-8"))):
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                continue  # not an address (for example a version number)
            assert any(ip in network for network in ALLOWED_NETWORKS), f"{address} in {relative} is not a documentation or private address"


def test_host_names_use_the_reserved_test_domain():
    for relative in ("windows/sysmon_native.jsonl", "windows/sysmon_ecs.jsonl"):
        for document in read_jsonl(DATASETS / relative):
            computer = document.get("Computer") or document["winlog"]["computer_name"]
            assert computer.endswith(".harbor.test")


def test_auth_log_is_syslog_formatted_and_chronological():
    pattern = re.compile(r"^[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d web01 [A-Za-z_-]+(\[\d+\])?: ")
    previous = ""
    for line in (DATASETS / "linux/auth.log").read_text(encoding="utf-8").splitlines():
        assert pattern.match(line), line
        stamp = line[:15]
        assert stamp >= previous, "lines are not in time order"
        previous = stamp


def test_audit_log_records_share_serial_numbers_per_event():
    lines = (DATASETS / "linux/audit.log").read_text(encoding="utf-8").splitlines()
    serials = []
    for line in lines:
        match = re.match(r"^type=[A-Z_]+ msg=audit\((\d+\.\d{3}):(\d+)\): ", line)
        assert match, line
        serials.append(int(match.group(2)))
    assert serials == sorted(serials)
    assert len(set(serials)) < len(serials)  # several records belong to one event


def test_ecs_and_native_sysmon_files_describe_the_same_events():
    native = read_jsonl(DATASETS / "windows/sysmon_native.jsonl")
    ecs = read_jsonl(DATASETS / "windows/sysmon_ecs.jsonl")
    assert len(native) == len(ecs)
    for left, right in zip(native, ecs):
        assert left["UtcTime"].replace(" ", "T") + "Z" == right["@timestamp"]
        assert str(left["EventCode"]) == right["event"]["code"]
        assert left["ProcessId"] == right["process"]["pid"]


def test_sysmon_events_are_in_time_order_and_on_the_incident_day():
    stamps = [event["UtcTime"] for event in read_jsonl(DATASETS / "windows/sysmon_native.jsonl")]
    assert stamps == sorted(stamps)
    assert all(stamp.startswith("2026-03-14 ") for stamp in stamps)


def test_encoded_powershell_commands_decode_to_harmless_text():
    decoded = set()
    for event in read_jsonl(DATASETS / "windows/sysmon_native.jsonl"):
        match = re.search(r"-EncodedCommand (\S+)", event.get("CommandLine", ""))
        if match:
            decoded.add(base64.b64decode(match.group(1)).decode("utf-16-le"))
    assert decoded == {"Get-ComputerInfo | Out-Null", 'Write-Output "synthetic training event - harmless"'}


def test_the_attacker_address_links_the_three_sources():
    needle = "203.0.113.45"
    assert needle in (DATASETS / "linux/auth.log").read_text()
    assert needle in (DATASETS / "windows/sysmon_native.jsonl").read_text()
    assert needle in (DATASETS / "windows/sysmon_ecs.jsonl").read_text()


def test_scenario_contains_the_deliberate_false_positives():
    auth = (DATASETS / "linux/auth.log").read_text()
    assert auth.count("Failed password for invalid user nessus-probe from 10.10.30.60") == 7  # the authorised scanner
    assert "visudo -c" in auth  # a legitimate sensitive command
    assert any("HarborInventory" in event.get("ParentImage", "") for event in read_jsonl(DATASETS / "windows/sysmon_native.jsonl"))


def test_generator_output_contains_no_executable_content():
    for relative in FILES:
        data = (DATASETS / relative).read_bytes()
        assert b"\x00" not in data and not data.startswith((b"MZ", b"\x7fELF", b"#!"))
