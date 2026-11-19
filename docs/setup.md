# Setup and validation

There are three levels. Level 1 needs nothing but Python and is what the automated tests use. Levels 2 and 3 need a Splunk or Elastic
installation; **the author did not have one when this repository was built, so those levels are instructions, not verified results.**

## Level 1 — Local validation (no SIEM)  ✔ tested

Requirements: Python 3.8 or newer.

```bash
python3 tools/generate_synthetic_logs.py --out-dir datasets      # writes 5 files; the output is identical on every run
python3 detections/reference_detections.py --datasets datasets   # runs the 12 detections and prints JSON
python3 -m pytest -q                                              # needs: pip install -r requirements-dev.txt
```

What each command does and how to tell it worked:

| Command | Modifies | Success looks like | Failure looks like |
|---|---|---|---|
| `generate_synthetic_logs.py --out-dir datasets` | Writes five files into `datasets/` (overwrites the same files) | Five lines starting with `wrote datasets/...` | A Python traceback |
| `reference_detections.py --datasets datasets` | Nothing (prints only) | A JSON document with keys `D01_ssh_bruteforce` ... | `FileNotFoundError` if `datasets/` is missing |
| `pytest -q` | Nothing outside temporary folders | `N passed` | `FAILED` lines with the reason |

## Level 2 — Splunk  (NOT TESTED)

Use a lab instance (Splunk Enterprise trial or free licence on a Linux VM). Downloading Splunk requires a free account on splunk.com;
follow Splunk's installation guide for your operating system.

1. Create an index named `soc_lab` (Settings > Indexes > New Index).
2. Add the data with **Settings > Add Data > Upload**, once per file, choosing the sourcetype and index:

   | File | Source type | Index | Time settings |
   |---|---|---|---|
   | `datasets/linux/auth.log` | `linux_secure` (or *Operating System > linux_secure*) | `soc_lab` | The log has no year: set the year when asked, or use the `props.conf.example` |
   | `datasets/linux/audit.log` | `linux_audit` (create a custom one if missing) | `soc_lab` | Timestamp is `msg=audit(<epoch>...)` |
   | `datasets/windows/sysmon_native.jsonl` | `sysmon:json` (custom: JSON, timestamp field `UtcTime`) | `soc_lab` | `%Y-%m-%d %H:%M:%S.%3N`, time zone UTC |

   Alternatively place `splunk/props.conf.example` and `splunk/inputs.conf.example` (renamed without `.example`) into an app and adjust the paths.
3. Set the time range of your search to **2026-03-14** (all time also works).
4. Open a file from `splunk/spl/`, copy the lines **below the blank line** (the `#` lines are documentation) into the search bar and run it.
5. Compare with the "Expected" line in the file header and with `docs/detections.md`. Record the real result in `TEST_RESULTS.md`
   (PASS, or FAIL with the error) and fix the query if needed.

Optional: import `splunk/dashboards/soc_overview.xml`, and create alerts from `splunk/savedsearches.conf.example`.

## Level 3 — Elastic Stack  (NOT TESTED)

Use a lab Elasticsearch and Kibana (for example Elastic's own lab installation guide, or Docker). Keep the lab on an isolated network.

```bash
python3 tools/make_bulk_files.py                       # writes build/bulk/*.ndjson (tested)
ES_URL=https://localhost:9200 scripts/load_to_elasticsearch.sh --dry-run    # shows what would be sent (tested)
ES_URL=https://localhost:9200 ES_API_KEY=... scripts/load_to_elasticsearch.sh    # sends the data (NOT TESTED)
```

* Create the API key in Kibana (Stack Management > API keys) and keep it in an environment variable, never in a file or in Git.
* In Kibana create two data views, `soc-lab-linux-auth` and `soc-lab-windows-sysmon`, with the timestamp field `@timestamp`.
* Open Discover and try the queries in `elastic/kql/queries.md`; use Dev Tools for the JSON bodies in `elastic/queries/`, and
  Security > Timelines > Correlation for the EQL files.
* Check the field names in Discover first: they are approximations of Filebeat/Winlogbeat output and may differ in your version.

## Connecting the lab to a real environment

The same queries work on real logs once they are collected with the right sourcetype or ECS mapping.

| Source | Splunk | Elastic |
|---|---|---|
| Linux `auth.log`, auditd | Universal Forwarder `[monitor:///var/log/auth.log]` with `sourcetype = linux_secure`; auditd with `linux_audit` | Filebeat `system` module (`elastic/beats/filebeat.yml.example`); Auditbeat for auditd |
| Windows Sysmon | Universal Forwarder `[WinEventLog://Microsoft-Windows-Sysmon/Operational]` plus the Splunk Add-on for Sysmon (field names differ from the JSON in this lab) | Winlogbeat (`elastic/beats/winlogbeat.yml.example`) |
| pfSense firewall | Syslog input, sourcetype `pfsense:filterlog` | Filebeat syslog input or the pfSense integration |

Before pointing real logs at these queries: replace the lab's index and sourcetype names, run each query on a short time range, and
**tune the thresholds and exclusions on your own baseline**. Do not collect logs from systems you are not authorised to monitor.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Splunk shows events in 2025 or the current year | The syslog line has no year | Set the year in the upload dialog or `props.conf` |
| Sysmon fields are missing in Splunk | JSON not extracted | Use sourcetype `sysmon:json` with `INDEXED_EXTRACTIONS = json`, or add `| spath` to the query |
| `rex` returns nothing | The sourcetype breaks lines differently, or the raw text differs | Check one raw event; the `rex` patterns expect the lines in `datasets/linux/auth.log` |
| Kibana queries return nothing | Field names differ from the lab's ECS approximation | Look at one document in Discover and adjust the field names |
| `Permission denied` when running a script | The executable bit was lost by a web upload | `chmod +x scripts/load_to_elasticsearch.sh`, or run it with `bash` |
| `load_to_elasticsearch.sh` says it needs ES_URL | The environment variable is missing | Set `ES_URL`, and `ES_API_KEY` for a real send |
