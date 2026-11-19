# Test results — soc-siem-detection-lab

Last full local run: **2026-10-03**. Result: **121 passed, 0 failed, 0 skipped** (`python3 -m pytest`, about 1 second).
GitHub Actions: **2026-11-19**. Result: **121 passed** on Python 3.8 and on Python 3.12 (Ubuntu). The first run failed; see "FAIL" below.

> **The most important sentence on this page:** *no Splunk or Elastic installation was available, so not a single SPL, KQL, EQL or
> Query DSL query has been executed in a SIEM.* The tests below verify the datasets, the detection **logic** (in Python) and the
> **static** properties of the query files. They cannot find a syntax error in an SPL query.

## Environment of that run

| Item | Value |
|---|---|
| Operating system | macOS 15.7.4 (arm64) |
| Python / pytest | Python 3.9.6, pytest 8.4.2 |
| ShellCheck / shfmt | ShellCheck 0.11.0, shfmt 3.14.1 (for the loader script) |

## PASS — executed and successful

| Area | Tests | What was verified |
|---|---|---|
| Datasets (`test_datasets.py`) | 17 | Line counts; **regenerating gives byte-identical files**; every JSON document is labelled `synthetic`; only documentation (RFC 5737) and private addresses appear; host names use the reserved `.test` domain; syslog format and time order; auditd records and shared serial numbers; the ECS and native Sysmon files describe the same 28 events; encoded PowerShell decodes only to two harmless strings; the attacker address links all three sources; the deliberate false positives are present; no executable content |
| Reference detections (`test_reference_detections.py`) | 17 | Each of the 12 detections returns exactly the expected result on the scenario (including the **49 + 10 split of the brute force by fixed 5-minute bins**); thresholds and tuning change results as documented (the lab scanner appears at threshold 5 and not at 10; the inventory agent is removed by DET-09b; `unix_chkpwd` reads are excluded from DET-06); normal logins are not flagged; results are deterministic |
| Query files, static checks (`test_queries.py`) | 39 | All 13 SPL files are documented (10 header fields), start with the lab index, are **read-only** (no `delete`, `outputlookup`, `collect`, `sendemail`, `script`, `map`, ...), have balanced parentheses and quotes, point at an existing reference function and are marked `NOT TESTED in Splunk`; the catalog and README mention every detection and its status honestly; Elastic claims in the catalog match the KQL file; the Query DSL bodies are valid JSON with only keys Elasticsearch accepts; EQL files are sequences with a time limit; the dashboard XML is well-formed; configuration examples contain no secrets; alert examples are valid JSON; every Mermaid block has a known type and balanced brackets |
| Elasticsearch helpers (`test_bulk.py`) | 7 | `make_bulk_files.py` output alternates action and document lines with the right index; invalid JSON is rejected; the loader's `--dry-run` sends nothing; it refuses without `ES_URL` or `ES_API_KEY`; it never uses `--insecure` or a key on the command line; **ShellCheck and shfmt clean** |
| Repository (`test_static.py`) | 41 | All required files exist and are not empty; Python compiles; no secrets or personal paths; no backup files; README states that data is synthetic and queries are untested; no document claims a SIEM run that did not happen |

### GitHub Actions (2026-11-19)

Commit `8ff7e6c`, run: <https://github.com/OYDeadpoolife/soc-siem-detection-lab/actions/runs/44528425441>. **121 passed in both jobs.**

| Runner | Python | Test tools |
|---|---|---|
| `ubuntu-24.04` | 3.8 | `pytest` 8.3.5 only (the pip-installed shfmt is not used in this job, see FAIL below) |
| `ubuntu-latest` (Ubuntu 26.04) | 3.12 | `pytest` 9.2.0, `shellcheck-py`, `shfmt-py` (the shfmt format check runs here) |

### Mutation check (does the suite really catch bugs?)

Five deliberate bugs were introduced one at a time into a copy of the project, and the suite failed each time: the brute-force threshold
`>=` changed to `>`, the PAM-helper exclusion removed from DET-06, an SPL file's status changed from "NOT TESTED" to "tested", a `| delete`
command added to an SPL query, and a changed port in the Sysmon dataset (dataset drift).

### Development notes (nothing hidden)

During development the suite failed several times before the final run. The causes were all in the tests: a balance check that did not
understand escaped parentheses and character classes in regular expressions, a table-row filter that also matched another table,
a dictionary key missing in network events, and a formatting difference reported by shfmt. They were fixed in the tests (or by running
`shfmt -w`). No test was skipped or weakened to get a pass. Separately, while writing the Elastic files, a `_comment` key in the Query DSL
JSON was found to be something Elasticsearch would reject, so the documentation moved to `elastic/queries/README.md` and a test now
forbids unknown top-level keys.

## FAIL — executed and failed

None in the last local run. **The first GitHub Actions run (2026-11-19, commit `d245805`) failed in both jobs.** The causes were outside the detection logic:

1. `test_no_backup_or_cache_files` counted `.pyc` files that the test run itself writes under `__pycache__` (they are git-ignored and never
   published). This had not shown up locally, where no bytecode was written. The test now ignores `__pycache__` and `.pytest_cache`.
2. Python 3.8 is not offered on the newest Ubuntu runner image (`ubuntu-latest`), so that job could not start. It now runs on `ubuntu-24.04`.
3. On Python 3.8 `pip` can only install shfmt 3.7.0, which formats the loader script differently from the shfmt 3.14 the project is formatted with
   (`test_loader_passes_shellcheck_and_shfmt` failed). The 3.8 job now installs pytest only; the shfmt format check runs in the 3.12 job.

Fixed in commits `8cdf1fb` and `8ff7e6c`. Both jobs have been green since.

## NOT TESTED — environment not available to the author when this was written

| Item | Why |
|---|---|
| **All SPL queries** (`splunk/spl/*.spl`) in Splunk | No Splunk installation. Syntax, field extraction and results are unverified |
| **All KQL, EQL and Query DSL queries** in Elastic/Kibana | No Elastic Stack. Field names are approximations of Filebeat/Winlogbeat output |
| `props.conf`, `inputs.conf`, `savedsearches.conf`, the dashboard, Filebeat and Winlogbeat examples | No Splunk or Elastic; the examples are checked only for secrets and well-formedness |
| `scripts/load_to_elasticsearch.sh` sending data | No Elasticsearch; only `--dry-run` and the refusal cases were run |
| Mermaid diagrams in `docs/` rendering on GitHub | The diagram in the README was viewed on GitHub on 2026-11-19 (the first version had clipped text, so the labels were changed to SVG text). The four diagrams in `docs/` were checked only in a local Mermaid 11.4.1 render and by a syntax-balance test |
| auditd rules on a real Linux server | Written from documentation; not applied |

## MANUAL VERIFICATION REQUIRED — to be done on your own machine

1. **Splunk.** Follow `docs/setup.md`, Level 2. For each file in `splunk/spl/` run the query and compare with the "Expected" header line. Record
   PASS, or FAIL with the error message, here, and fix the query.
2. **Elastic.** Follow `docs/setup.md`, Level 3. Run the KQL, EQL and Query DSL examples and compare with the expected results in
   `elastic/kql/queries.md` and `elastic/queries/README.md`. Check the field names in Discover first.
3. **Auditd.** On a lab VM, apply `docs/auditd-rules.md`, run `sudo cat /etc/shadow` and confirm `ausearch -k shadow_read -i` shows it.
4. **Python versions.** Already run in GitHub Actions (see above). Optional: repeat locally with `python3 -m pytest -q`.
5. **Mermaid.** The README diagram has been checked on GitHub. Open the four diagrams in `docs/` on GitHub and confirm they render with readable text.

Until step 1 and 2 are done, describe this project as: *"SIEM detections and datasets with a tested Python reference implementation;
queries written for Splunk and Elastic but not yet validated in a live SIEM."*
