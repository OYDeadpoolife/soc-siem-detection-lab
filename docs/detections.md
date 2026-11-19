# Detection catalog

Each detection has: a Splunk SPL file (`splunk/spl/`), a Python reference function (`detections/reference_detections.py`) and,
for most, an Elastic equivalent (`elastic/`).

**Status legend.** *Logic*: the idea is implemented in Python and tested against the synthetic data (**PASS**). *SPL / Elastic syntax*:
not run in a real Splunk or Elastic (**NOT TESTED**). Expected results below come from the Python reference.

| ID | Name | SPL file | Reference function | Elastic | MITRE ATT&CK | Logic | SPL / Elastic syntax |
|---|---|---|---|---|---|---|---|
| DET-01 | SSH brute force | `DET-01_ssh_bruteforce.spl` | `ssh_bruteforce` | KQL, Query DSL | T1110.001 | PASS | NOT TESTED |
| DET-02 | SSH success after failures | `DET-02_success_after_failures.spl` | `success_after_failures` | KQL, EQL | T1078.003 | PASS | NOT TESTED |
| DET-03 | sudo request denied | `DET-03_sudo_denied.spl` | `sudo_denied` | KQL | T1548.003 | PASS | NOT TESTED |
| DET-04 | su activity | `DET-04_su_activity.spl` | `su_activity` | KQL | T1078.003 | PASS | NOT TESTED |
| DET-05 | New account / privileged group | `DET-05_account_changes.spl` | `account_changes` | KQL | T1136.001, T1098 | PASS | NOT TESTED |
| DET-06 | Read of `/etc/shadow` | `DET-06_auditd_shadow_reads.spl` | `shadow_reads` | not provided | T1003.008 | PASS | NOT TESTED |
| DET-07 | Session activity by `auid` | `DET-07_auditd_session_by_auid.spl` | `session_activity` | not provided | T1078.003 | PASS | NOT TESTED |
| DET-08 | Office starts a shell | `DET-08_office_spawning_shell.spl` | `office_spawning_shell` | KQL, EQL | T1204.002, T1059 | PASS | NOT TESTED |
| DET-09a | Encoded PowerShell (untuned) | `DET-09a_encoded_powershell.spl` | `encoded_powershell` | KQL | T1059.001, T1027 | PASS | NOT TESTED |
| DET-09b | Encoded PowerShell (tuned) | `DET-09b_encoded_powershell_tuned.spl` | `encoded_powershell` (with exclusion) | KQL, Query DSL | T1059.001, T1027 | PASS | NOT TESTED |
| DET-10 | External connections by script hosts | `DET-10_external_connections_script_hosts.spl` | `external_connections_by_script_hosts` | KQL | T1071.001, T1105 | PASS | NOT TESTED |
| DET-11 | Beaconing | `DET-11_beaconing.spl` | `beaconing` | not provided | T1071.001 | PASS | NOT TESTED |
| DET-12 | Indicator pivot | `DET-12_ioc_pivot.spl` | `ioc_pivot` | Query DSL | (investigation) | PASS | NOT TESTED |

## Results on the synthetic data

| ID | Expected result | Note |
|---|---|---|
| DET-01 | `203.0.113.45`: 49 failures in the 10:00 bucket and 10 in the 10:05 bucket | One attack, split by fixed 5-minute bins — a limitation of `bin`. A sliding window (`streamstats time_window`) would report it once |
| DET-02 | `svc-backup` from `203.0.113.45` at 10:06:41, method `password`, 59 failures in the previous 10 minutes | |
| DET-03 | `svc-backup`, "user NOT in sudoers", 10:08:05 | |
| DET-04 | `svc-backup` to `labadmin`: failure 10:08:40, success 10:09:30 | |
| DET-05 | `support01` created 10:11:20; added to `sudo` 10:11:50 | |
| DET-06 | One read by `/usr/bin/cat` at 10:12:44 with `auid=1002`, `uid=0` | The three reads by `unix_chkpwd` at 08:30 are excluded |
| DET-07 | Five records for `auid=1002` (sudo, useradd x2, usermod, cat) | Shows the root actions belong to the `svc-backup` login |
| DET-08 | `WINWORD.EXE` starts `cmd.exe` at 11:30:14 | |
| DET-09a / b | 2 events / 1 event | The inventory agent at 09:00:30 is a false positive removed by the tuning |
| DET-10 | `powershell.exe` (1 connection) and `wscript.exe` (8 connections) to `203.0.113.45:443` | |
| DET-11 | `wscript.exe` to `203.0.113.45:443`: 8 connections, average 59.2 s, standard deviation 0.52 s | |
| DET-12 | `203.0.113.45` appears in `linux_secure` (214 lines) and Sysmon (9 events) | |

## False positives and tuning (summary)

| ID | False positive in the data or in real life | Tuning |
|---|---|---|
| DET-01 | The lab scanner `10.10.30.60` (7 failures: below the threshold of 10, but it would fire at a threshold of 5) | Allow-list scanners; set the threshold from your baseline |
| DET-02 | Users behind one NAT address after many mistakes | Combine with the login method and account type |
| DET-05 | Planned onboarding | Compare with change tickets |
| DET-06 | The PAM helper `unix_chkpwd` reads `/etc/shadow` at every login | Exclude it (already done) and other known tools |
| DET-09a | The inventory agent's encoded command | Exclude the known parent by full path (DET-09b) |
| DET-11 | Update checks and keep-alive connections | Allow-list destinations; tune count and deviation |

## Blind spots (what these detections will not catch)

* **Low-and-slow brute force** below the threshold, or spread over many sources (password spraying).
* **Valid credentials used without any failures** (stolen or leaked passwords): DET-02 never fires. Use baseline checks such as
  "service account logs in with a password from a new address" (see the baseline query in the walkthrough).
* **Renamed or copied binaries** (`powershell.exe` renamed) and PowerShell without `-enc` (for example downloaded cradles).
* **Beacons with random timing (jitter)** exceed the deviation limit in DET-11.
* **Attackers who clear or stop logging.** Nothing here detects missing logs; add a "host stopped sending logs" alert in a real SOC.
* **Anything outside the collected sources** (DNS, proxy, e-mail, cloud).
