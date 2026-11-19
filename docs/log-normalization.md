# Log normalization notes

Raw logs from different systems describe the same ideas ("who", "from where", "did what", "did it work") with different names. A SIEM
normalizes them so one query works across sources. This page documents the mapping used in this lab. **The mappings to Splunk CIM and
Elastic ECS are best-effort and NOT TESTED in a real Splunk or Elastic**; check them against the version you run.

## 1. Linux authentication (auth.log)

| Concept | Raw text (`auth.log`) | Splunk (rex in the SPL files) | CIM Authentication | ECS (in `auth_ecs.jsonl`) |
|---|---|---|---|---|
| Failed SSH login | `Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2` | `result=Failed`, `user`, `src_ip`, `method` | `action=failure`, `user`, `src`, `app=sshd` | `event.outcome=failure`, `event.action=ssh_login`, `user.name`, `source.ip` |
| Successful SSH login | `Accepted password for svc-backup from 203.0.113.45 port 50979 ssh2` | `result=Accepted`, `method=password` | `action=success` | `event.outcome=success`, `system.auth.ssh.method=password` |
| Unknown user | `Invalid user admin from 203.0.113.45 port 51234` | (counted by DET-01 through the failed line) | `action=failure` | `system.auth.ssh.event=Invalid` |
| sudo command | `sudo:  labadmin : TTY=pts/0 ; PWD=/home/labadmin ; USER=root ; COMMAND=/bin/bash` | `user`, command | (privilege escalation; not in CIM Authentication) | `event.action=sudo_command`, `user.effective.name`, `process.args` |
| sudo denied | `sudo: svc-backup : user NOT in sudoers ; ...` | `reason` | | `event.outcome=failure` |
| su | `su[3370]: (to labadmin) svc-backup on pts/0` | `from_user`, `to_user` | | `event.action=su`, `user.name`, `user.target.name` |
| Account created | `useradd[3371]: new user: name=support01, UID=1003, ...` | `account` | (Change data model) | `event.action=user_added`, `user.name=support01` |
| Added to group | `usermod[3373]: add 'support01' to group 'sudo'` | `account`, `group` | | `event.action=added-user-to-group`, `user.group.name=sudo` |

Timestamps: traditional syslog has **no year and no time zone**. `props.conf.example` sets `TZ = UTC` for the lab; in real life set the
time zone of the server and make sure the SIEM infers the right year. Newer Ubuntu releases may write ISO-8601 timestamps instead.

## 2. Linux auditd

| Concept | Raw | Splunk fields (rex) | Notes |
|---|---|---|---|
| Record type | `type=SYSCALL`, `type=EXECVE`, `type=USER_CMD`, `type=ADD_USER`, `type=PATH` | `audit_type` | One event is several records sharing the same `msg=audit(<epoch>:<serial>)` |
| Original login user | `auid=1002` | `auid` | **Survives `su` and `sudo`**; unset sessions show `4294967295` |
| Effective user | `uid=0` | `uid` | Match with `\buid=` so that `auid=`, `euid=` and `suid=` are not matched |
| Rule key | `key="shadow_read"` | `audit_key` | Set by the rule in `docs/auditd-rules.md` |
| Program | `exe="/usr/bin/cat"` | `exe` | |
| Command (sudo) | `cmd=2F7573722F62696E2F61707420757064617465` | | Hex when the command contains spaces: decode with `ausearch -i` or `xxd -r -p` |

The auditd records in `audit.log` are **simplified** for teaching: real records contain more fields (`a0`-`a3`, `items`, `subj`, ...). Elastic
equivalents are not provided because the field names depend on Auditbeat or the Filebeat auditd module and on the version.

## 3. Windows Sysmon

| Concept | Native field (Splunk, `sysmon_native.jsonl`) | CIM Endpoint.Processes | ECS (`sysmon_ecs.jsonl`) |
|---|---|---|---|
| Event type | `EventCode` (1, 3, 11) | | `event.code` (string) |
| Computer | `Computer` | `dest` | `host.name`, `winlog.computer_name` |
| User | `User` (`HARBOR\jdoe`) | `user` | `user.domain`, `user.name` |
| Process path | `Image` | `process_path` | `process.executable`, `process.name` |
| Command line | `CommandLine` | `process` | `process.command_line` |
| Parent process | `ParentImage`, `ParentCommandLine` | `parent_process_path`, `parent_process` | `process.parent.executable`, `process.parent.command_line` |
| Process hash | `Hashes` (`SHA256=...`) | `process_hash` | `process.hash.sha256` |
| Destination | `DestinationIp`, `DestinationPort` | (Network Traffic) `dest_ip`, `dest_port` | `destination.ip`, `destination.port` |
| Source | `SourceIp`, `SourcePort` | `src_ip`, `src_port` | `source.ip`, `source.port` |
| Created file | `TargetFilename` | | `file.path`, `file.name` |
| Time | `UtcTime` (`2026-03-14 11:30:14.512`, UTC) | | `@timestamp` (ISO 8601 with `Z`) |

Windows paths contain backslashes. In SPL string comparisons a backslash is written `\\` (for example `Image="*\\powershell.exe"`).

## 4. A note on field names in the SPL files

The SPL files extract fields with `rex` so that they work on raw text without any add-on. In a real deployment, install the vendor
add-ons (Splunk Add-on for Unix and Linux, Splunk Add-on for Sysmon, or an equivalent) and use their field names and CIM tags instead.
