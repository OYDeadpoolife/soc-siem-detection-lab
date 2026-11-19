# Synthetic datasets

**Everything here is synthetic.** The organisation ("Harbor Lab"), hosts, users, addresses and hashes are invented. External addresses
come from the RFC 5737 documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`), which are reserved for examples and never routed on the
Internet. The files describe one fictional day, **2026-03-14 (UTC)**. No real attack was performed to create them, and they are not from a real system.

Regenerate them (the output is byte-for-byte identical every time):

```bash
python3 tools/generate_synthetic_logs.py --out-dir datasets
```

| File | Format | Lines | Meant for |
|---|---|---|---|
| `linux/auth.log` | Traditional syslog, as written by Ubuntu's rsyslog (no year; assume 2026, UTC) | 353 | Splunk sourcetype `linux_secure`; Filebeat `system.auth` |
| `linux/auth_ecs.jsonl` | One JSON object per line, ECS-style fields (an **approximation** of Filebeat output) | 135 | Elastic index `soc-lab-linux-auth` |
| `linux/audit.log` | auditd records, simplified (see `docs/auditd-rules.md`) | 16 | Splunk sourcetype `linux_audit` |
| `windows/sysmon_native.jsonl` | Sysmon events 1, 3 and 11 with the native Sysmon field names (`Image`, `CommandLine`, `DestinationIp`, ...) | 28 | Splunk sourcetype `sysmon:json` |
| `windows/sysmon_ecs.jsonl` | The same 28 events with ECS field names (`process.executable`, `destination.ip`, ...) | 28 | Elastic index `soc-lab-windows-sysmon` |

Every JSON document contains `"labels": {"synthetic": "true"}` so synthetic data can never be mistaken for real data in a SIEM.

## The story in the data (all times UTC)

| Time | Event |
|---|---|
| 02:00 | Normal nightly login of `svc-backup` from the backup server with a public key |
| 07:00 | An authorised vulnerability scanner causes 7 failed logins (a deliberate false positive) |
| 08:30 | An administrator mistypes a password twice, then logs in (below any threshold) |
| 09:00 | A legitimate management agent runs an encoded PowerShell command on WS01 (a deliberate false positive) |
| 10:02–10:05 | `203.0.113.45` guesses SSH passwords against `web01` (56 failures) |
| 10:06:41 | `svc-backup` logs in with a **password** from `203.0.113.45` |
| 10:08–10:12 | `sudo` denied, `su` to `labadmin`, root shell, new account `support01` in group `sudo`, `/etc/shadow` read |
| 11:29–11:30 | On WS01, Word opens a document and starts `cmd.exe`, then hidden encoded PowerShell, which contacts `203.0.113.45:443` and writes `harbor_update.js` |
| 11:31–11:38 | `wscript.exe` contacts `203.0.113.45:443` about once a minute (beaconing) |
| 11:36 | `whoami`, `ipconfig`, `net user` |

The encoded PowerShell commands decode to harmless text (`Get-ComputerInfo | Out-Null` and `Write-Output "synthetic training event - harmless"`).
Nothing in these files is executable or malicious.
