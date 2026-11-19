# Incident report (example)

> **Fictional.** Written from the SOC's point of view for the synthetic incident. Organisation, people and systems are invented.
> The DFIR toolkit project contains the forensic report for the Windows evidence.

| Field | Value |
|---|---|
| Incident ID | INC-2026-0314-01 (fictional) |
| Status | Contained (fictional) |
| Severity | High |
| Detected | 2026-03-14 10:06:41 UTC by DET-02 |
| Reported by | SOC analyst (training exercise) |

## 1. Summary

An external address (`203.0.113.45`) guessed SSH passwords against the DMZ server `web01` and logged in as the service account
`svc-backup`. The attacker then switched to the administrator account `labadmin`, obtained a root shell, created a new privileged account
(`support01`) and read the password hash file. About 80 minutes later a user on the workstation `WS01` opened a Word document that started
a hidden encoded PowerShell command, which contacted the same external address and then beaconed to it about once a minute.

## 2. Timeline (UTC)

| Time | Event | Detection |
|---|---|---|
| 10:02–10:05 | About 56 failed SSH logins from `203.0.113.45` | DET-01 |
| 10:06:41 | `svc-backup` logs in with a password from the same address | DET-02 |
| 10:08:05 | `svc-backup` denied by sudo | DET-03 |
| 10:08:40 / 10:09:30 | `su` to `labadmin`: failure, then success | DET-04 |
| 10:10:02 | `labadmin` runs `sudo /bin/bash` | (auditd, DET-07) |
| 10:11:20 / 10:11:50 | `support01` created and added to `sudo` | DET-05 |
| 10:12:44 | `/etc/shadow` read by `cat`, `auid=1002` | DET-06 |
| 11:29:47 | `Invoice_March.docm` opened on WS01 | (Sysmon) |
| 11:30:14 | Word starts `cmd.exe`, then hidden PowerShell with an encoded command | DET-08, DET-09b |
| 11:30:16 | PowerShell connects to `203.0.113.45:443` | DET-10 |
| 11:31–11:38 | `wscript.exe` connects every ~60 s | DET-11 |

## 3. Detection coverage

All steps of the attack were seen by at least one detection **in the synthetic data** (Python reference). The Splunk and Elastic queries have not
been run on a real SIEM, so real-world coverage is unproven.

## 4. Impact (assessed)

Two accounts on `web01` compromised, a persistent privileged account created, password hashes exposed, and one workstation executing attacker-influenced code
with an outbound channel. No evidence of data exfiltration was found, but the data sources cannot rule it out.

## 5. Response actions recommended

1. Isolate `web01` and WS01; keep them powered on until memory is captured.
2. Block `203.0.113.45` at the firewall; search all logs for it (DET-12).
3. Disable `support01`; reset `svc-backup`, `labadmin`, `jdoe` and any account with a hash on `web01`.
4. Hand the evidence to DFIR with hashes and this timeline.

## 6. Lessons learned and tuning

* Alert when a **service account** authenticates with a password or from outside the management network.
* Replace the fixed-bin brute-force query with a sliding window.
* Exclude the inventory agent by full path; keep the exclusion list under review.
* Disable SSH password authentication on internet-facing servers.

## 7. Limitations of this report

Synthetic data; no real SIEM validation; attribution is not possible from these logs; the link between the two hosts is an inference.
