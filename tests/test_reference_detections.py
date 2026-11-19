"""The reference detections must find exactly what the scenario contains, and nothing else."""

from conftest import DATASETS


def test_d01_brute_force_is_split_by_the_fixed_bins(results):
    assert results["D01_ssh_bruteforce"] == [
        {"bucket_start": "2026-03-14T10:00:00Z", "src_ip": "203.0.113.45", "host": "web01", "failures": 49, "distinct_users": 12},
        {"bucket_start": "2026-03-14T10:05:00Z", "src_ip": "203.0.113.45", "host": "web01", "failures": 10, "distinct_users": 8},
    ]


def test_d01_lower_threshold_also_catches_the_scanner(reference):
    events = reference.parse_auth_log(DATASETS / "linux/auth.log")
    sources = {row["src_ip"] for row in reference.ssh_bruteforce(events, threshold=5)}
    assert sources == {"203.0.113.45", "10.10.30.60"}  # the authorised scanner appears: a false positive
    assert {row["src_ip"] for row in reference.ssh_bruteforce(events, threshold=10)} == {"203.0.113.45"}


def test_d02_success_after_failures(results):
    assert results["D02_success_after_failures"] == [
        {"time": "2026-03-14T10:06:41Z", "user": "svc-backup", "src_ip": "203.0.113.45", "method": "password", "prior_failures": 59}]


def test_d02_does_not_flag_normal_logins(reference):
    events = reference.parse_auth_log(DATASETS / "linux/auth.log")
    flagged_users = {row["user"] for row in reference.success_after_failures(events)}
    assert "labadmin" not in flagged_users  # two typos then a success is below the threshold
    assert reference.success_after_failures(events, min_failures=100) == []


def test_baseline_shows_the_login_method_changed(results):
    logins = [(row["user"], row["method"], row["src_ip"]) for row in results["baseline_accepted_logins"]]
    assert ("svc-backup", "publickey", "10.10.30.40") in logins
    assert ("svc-backup", "password", "203.0.113.45") in logins


def test_d03_to_d05_authentication_and_privilege(results):
    assert results["D03_sudo_denied"] == [{"time": "2026-03-14T10:08:05Z", "host": "web01", "user": "svc-backup", "reason": "user NOT in sudoers"}]
    assert [(r["time"], r["outcome"]) for r in results["D04_su_activity"]] == [
        ("2026-03-14T10:08:40Z", "failure"), ("2026-03-14T10:09:30Z", "success")]
    assert [(r["account"], r["change"]) for r in results["D05_account_changes"]] == [
        ("support01", "account created"), ("support01", "added to group sudo")]


def test_d06_excludes_the_pam_helper(results):
    assert results["D06_shadow_reads"] == [{"time": "2026-03-14T10:12:44Z", "exe": "/usr/bin/cat", "auid": 1002, "uid": 0}]


def test_d06_without_the_exclusion_would_be_noisy(reference):
    records = reference.audit_records(DATASETS / "linux/audit.log")
    pam_reads = [r for r in records if r["type"] == "SYSCALL" and r["fields"].get("exe") == "/usr/sbin/unix_chkpwd"]
    assert len(pam_reads) == 3


def test_d07_auid_survives_su_and_sudo(results):
    rows = results["D07_session_activity_auid_1002"]
    assert [r["exe"] for r in rows] == ["/usr/bin/sudo", "/usr/sbin/useradd", "/usr/sbin/useradd", "/usr/sbin/usermod", "/usr/bin/cat"]
    assert {r["uid"] for r in rows} == {0, 1000}  # effective users differ, yet it is one login session


def test_d08_office_spawning_shell(results):
    assert results["D08_office_spawning_shell"] == [
        {"time": "2026-03-14 11:30:14.512", "computer": "WS01.harbor.test", "user": "HARBOR\\jdoe", "parent": "winword.exe", "image": "cmd.exe"}]


def test_d09_tuning_removes_the_inventory_agent(results):
    assert len(results["D09_encoded_powershell"]) == 2
    tuned = results["D09b_encoded_powershell_tuned"]
    assert [row["time"] for row in tuned] == ["2026-03-14 11:30:14.903"]
    assert tuned[0]["parent"] == "cmd.exe"


def test_d10_external_connections(results):
    rows = {row["image"]: row for row in results["D10_external_connections_by_script_hosts"]}
    assert set(rows) == {"powershell.exe", "wscript.exe"}
    assert rows["powershell.exe"]["count"] == 1 and rows["wscript.exe"]["count"] == 8
    assert all(row["dest_ip"] == "203.0.113.45" and row["dest_port"] == 443 for row in rows.values())


def test_d11_beaconing_is_only_the_script_host(results):
    rows = results["D11_beaconing"]
    assert len(rows) == 1
    assert rows[0]["image"] == "wscript.exe" and rows[0]["connections"] == 8
    assert 58 <= rows[0]["avg_interval_s"] <= 61 and rows[0]["stdev_s"] < 1.5


def test_d11_ignores_private_destinations_and_irregular_traffic(reference):
    sysmon = reference.load_jsonl(DATASETS / "windows/sysmon_native.jsonl")
    destinations = {row["dest_ip"] for row in reference.beaconing(sysmon, min_connections=2, max_stdev=1000, min_interval=0, max_interval=10**6)}
    assert not any(ip.startswith("10.") for ip in destinations)  # the svchost DNS traffic goes to a private address


def test_d12_pivot(results):
    assert results["D12_ioc_pivot_203.0.113.45"] == {"linux_secure": 214, "sysmon": 9}


def test_unknown_indicator_has_no_hits(reference):
    assert reference.ioc_pivot("192.0.2.254", ["nothing here"], []) == {}


def test_reference_run_is_deterministic(reference):
    assert reference.run_all(DATASETS) == reference.run_all(DATASETS)
