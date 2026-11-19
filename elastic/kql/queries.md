# Kibana (KQL) queries

> **Status: NOT TESTED in Kibana.** The field names are the ones used in `datasets/linux/auth_ecs.jsonl` and
> `datasets/windows/sysmon_ecs.jsonl`, which are *approximations* of what Filebeat's `system` module and Winlogbeat's Sysmon
> module produce. Real field names differ by version: check them in Discover before relying on a query.
> The detection logic behind each query is tested in Python (`detections/reference_detections.py`).

Load the data as two indices, `soc-lab-linux-auth` and `soc-lab-windows-sysmon` (see `docs/setup.md`), create a data view for each
(timestamp field `@timestamp`) and paste the query into the Discover search bar.

Index and data view: `soc-lab-linux-auth`

| ID | Query | What you should see in the synthetic data |
|---|---|---|
| DET-01 | `event.action : "ssh_login" and event.outcome : "failure"` then **visualise `source.ip`** (top values) | `203.0.113.45` with 59 failures; the scanner `10.10.30.60` with 7 |
| DET-02 | `event.action : "ssh_login" and event.outcome : "success" and source.ip : "203.0.113.45"` | one login: `svc-backup`, method `password`, 10:06:41 |
| DET-03 | `event.action : "sudo_command" and event.outcome : "failure"` | `svc-backup`, 10:08:05 |
| DET-04 | `event.action : "su"` | two events: failure 10:08:40 and success 10:09:30, `svc-backup` to `labadmin` |
| DET-05 | `event.action : ("user_added" or "added-user-to-group")` | `support01` created and added to group `sudo` |

Index and data view: `soc-lab-windows-sysmon`

| ID | Query | What you should see |
|---|---|---|
| DET-08 | `event.code : "1" and process.parent.name : ("WINWORD.EXE" or "EXCEL.EXE" or "POWERPNT.EXE" or "OUTLOOK.EXE") and process.name : ("cmd.exe" or "powershell.exe" or "wscript.exe" or "cscript.exe" or "mshta.exe")` | `WINWORD.EXE` starting `cmd.exe`, 11:30:14 |
| DET-09a | `event.code : "1" and process.name : "powershell.exe" and process.command_line : (*-enc* or *-EncodedCommand*)` | two events (the inventory agent at 09:00:30 and the attack at 11:30:14) |
| DET-09b | `event.code : "1" and process.name : "powershell.exe" and process.command_line : (*-enc* or *-EncodedCommand*) and not process.parent.executable : *HarborInventory*` | only the 11:30:14 event |
| DET-10 | `event.code : "3" and process.name : ("powershell.exe" or "wscript.exe" or "cscript.exe" or "mshta.exe" or "cmd.exe") and not destination.ip : ("10.0.0.0/8" or "172.16.0.0/12" or "192.168.0.0/16")` | 9 connections to `203.0.113.45:443` |

Not provided for Elastic in this repository: DET-06 and DET-07 (auditd; the field names depend on whether you use Auditbeat or
the Filebeat auditd module and on the version), DET-11 (beaconing; it needs a transform or a machine-learning job) and DET-12 as
KQL (see `elastic/queries/ioc_pivot.json`).

## Notes

* KQL wildcards (`*-enc*`) work on `keyword` fields. If `process.command_line` is mapped as `text`, use a runtime field or the
  Query DSL variant in `elastic/queries/encoded_powershell.json`.
* CIDR notation on `ip` fields (`destination.ip : "10.0.0.0/8"`) is supported by KQL.
