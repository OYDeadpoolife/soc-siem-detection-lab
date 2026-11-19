# Screenshot guide

Images `01` and `04` are rendered from the real output of the commands below, run on a clean clone of the repository. They are not
photographs of a terminal window, and nothing in them is edited. Image `01` pipes the output through `jq 'map_values(length)'` instead of `less`, so
that it fits in one picture. Images `02` and `03` do not exist, because the queries have not been run in Splunk or Elastic. A screenshot must show a
real run: do not edit or fabricate results.

| File | Open | Do | What must be visible |
|---|---|---|---|
| `01-reference-detections.png` | A terminal in the repository folder | `python3 detections/reference_detections.py --datasets datasets \| less` (or pipe to `jq`) | The keys `D02_success_after_failures`, `D05_account_changes`, `D08_office_spawning_shell`, `D11_beaconing` with their results |
| `02-splunk-det02.png` | Splunk Web, Search & Reporting, time range 2026-03-14 | Run `splunk/spl/DET-02_success_after_failures.spl` | The result row for `svc-backup` / `203.0.113.45` and the search text. **Only take this if you really ran it in Splunk** |
| `03-kibana-discover.png` | Kibana Discover on `soc-lab-windows-sysmon` | Run the DET-08 KQL query from `elastic/kql/queries.md` | The `WINWORD.EXE` → `cmd.exe` document. **Only if you really ran it** |
| `04-test-results.png` | A terminal with the virtual environment active | `python3 -m pytest -q` | The final line with the number of passed tests |
| `05-architecture.png` (optional) | The README on GitHub | Scroll to the architecture diagram | The rendered Mermaid diagram (this also proves that GitHub renders it) |

Embed in `README.md` with: `![Splunk DET-02](screenshots/02-splunk-det02.png)`

Before uploading: crop or blur anything personal (your user name, real host names, licence keys, e-mail addresses).
If you could not run the queries in a real SIEM, leave screenshots 02 and 03 out: the README states that they are untested.
