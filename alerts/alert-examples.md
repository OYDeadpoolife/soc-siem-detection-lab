# Alert examples and investigation notes

These are **example alert documents** of the kind a SIEM or ticketing system creates, with an analyst's notes. They describe the
synthetic incident; the JSON is illustrative, not the output of a real Splunk or Elastic.

## ALERT-001 — SSH brute force (DET-01)

```json
{
  "alert_id": "ALERT-001",
  "rule": "DET-01 SSH brute force",
  "severity": "medium",
  "time": "2026-03-14T10:05:00Z",
  "host": "web01",
  "entities": { "src_ip": "203.0.113.45", "targeted_users": 12 },
  "evidence": { "failures_in_bucket": 49, "bucket": "2026-03-14T10:00:00Z/5m" },
  "mitre": ["T1110.001"],
  "status": "triaged",
  "disposition": "true positive"
}
```

**Analyst notes:** 49 failures from one Internet address in one bucket and 10 in the next, against 12 account names (admin, root, ubuntu, ...).
Source is not a known scanner. No success at this point in the alert; checked for a later success (see ALERT-002). Block recommended.
**Tuning:** the attack is reported twice because of the fixed 5-minute bins; use a sliding window.

## ALERT-002 — SSH success after failures (DET-02)

```json
{
  "alert_id": "ALERT-002",
  "rule": "DET-02 SSH success after failures",
  "severity": "high",
  "time": "2026-03-14T10:06:41Z",
  "host": "web01",
  "entities": { "user": "svc-backup", "src_ip": "203.0.113.45", "method": "password" },
  "evidence": { "failures_last_10m": 59 },
  "mitre": ["T1078.003", "T1110.001"],
  "status": "escalated",
  "disposition": "true positive"
}
```

**Analyst notes:** `svc-backup` normally logs in with a key from `10.10.30.40`; this is a password from the Internet. Followed the account:
sudo denied (10:08:05), `su` to `labadmin` (10:09:30), new account `support01` (10:11:20). **Escalated to the incident owner as high severity;**
recommended isolating `web01` and preserving evidence.

## ALERT-003 — Office application starting a shell (DET-08)

```json
{
  "alert_id": "ALERT-003",
  "rule": "DET-08 Office application starting a shell",
  "severity": "high",
  "time": "2026-03-14T11:30:14Z",
  "host": "WS01",
  "entities": { "user": "HARBOR\\jdoe", "parent": "WINWORD.EXE", "image": "cmd.exe" },
  "evidence": { "followed_by": ["DET-09b encoded PowerShell 11:30:14", "DET-10 connection to 203.0.113.45:443 11:30:16", "DET-11 beaconing 11:31-11:38"] },
  "mitre": ["T1204.002", "T1059.001"],
  "status": "escalated",
  "disposition": "true positive"
}
```

**Analyst notes:** Word started `cmd.exe`, which started hidden PowerShell with `-EncodedCommand`. The connection destination `203.0.113.45` is the same
address that attacked `web01`. Isolate WS01 (keep it powered on), collect a triage package for DFIR.
**False-positive check:** the encoded PowerShell at 09:00:30 from the inventory agent is benign and excluded by DET-09b; this one is not.

## ALERT-004 — Benign: lab vulnerability scanner (not an alert at the production threshold)

```json
{
  "alert_id": "ALERT-004",
  "rule": "DET-01 SSH brute force (threshold 5, experiment)",
  "severity": "medium",
  "time": "2026-03-14T07:00:00Z",
  "host": "web01",
  "entities": { "src_ip": "10.10.30.60", "failures": 7 },
  "mitre": ["T1110.001"],
  "status": "closed",
  "disposition": "false positive (authorised scanner)"
}
```

**Analyst notes:** an internal authorised scanner (`scanner01`) checking credentials. At the production threshold of 10 this does not alert;
at a threshold of 5 it would. **Tuning:** allow-list the scanner's address instead of raising the threshold for everyone.
