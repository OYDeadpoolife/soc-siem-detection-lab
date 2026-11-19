"""Repository hygiene: required files, no secrets or personal paths, Python compiles, claims stay honest."""

import py_compile
import re

import pytest

from conftest import ROOT

REQUIRED_FILES = [
    "README.md", "LICENSE", ".gitignore", ".editorconfig", "Makefile", "requirements-dev.txt", "TEST_RESULTS.md",
    "tools/generate_synthetic_logs.py", "tools/make_bulk_files.py", "scripts/load_to_elasticsearch.sh",
    "detections/reference_detections.py", "datasets/README.md", "datasets/linux/auth.log", "datasets/linux/audit.log",
    "datasets/linux/auth_ecs.jsonl", "datasets/windows/sysmon_native.jsonl", "datasets/windows/sysmon_ecs.jsonl",
    "splunk/props.conf.example", "splunk/inputs.conf.example", "splunk/savedsearches.conf.example", "splunk/dashboards/soc_overview.xml",
    "elastic/kql/queries.md", "elastic/queries/README.md", "elastic/beats/filebeat.yml.example", "elastic/beats/winlogbeat.yml.example",
    "alerts/alert-examples.md", "docs/architecture.md", "docs/setup.md", "docs/log-normalization.md", "docs/detections.md",
    "docs/triage-workflow.md", "docs/investigation-walkthrough.md", "docs/incident-report-example.md", "docs/auditd-rules.md",
    "screenshots/README.md", ".github/workflows/ci.yml",
]
# Written in pieces so this file does not match itself; the last marker is the account name used while developing.
LOCAL_PATH_MARKERS = ("/Use" + "rs/", "orhay" + "yosef")


@pytest.mark.parametrize("relative", REQUIRED_FILES)
def test_required_file_exists_and_is_not_empty(relative):
    path = ROOT / relative
    assert path.is_file(), f"missing {relative}"
    assert path.stat().st_size > 100, f"{relative} looks empty"


def test_python_files_compile(tmp_path):
    for path in list((ROOT / "tools").glob("*.py")) + list((ROOT / "detections").glob("*.py")):
        py_compile.compile(str(path), doraise=True, cfile=str(tmp_path / (path.name + "c")))


def test_no_secrets_or_local_paths():
    patterns = [r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"AKIA[0-9A-Z]{16}", r"ghp_[A-Za-z0-9]{36}", r"xox[baprs]-[A-Za-z0-9-]+"]
    skip = {".git", ".pytest_cache", "__pycache__", "build"}
    for path in ROOT.rglob("*"):
        if not path.is_file() or skip & set(path.relative_to(ROOT).parts):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in patterns:
            assert not re.search(pattern, text), f"possible secret in {path.relative_to(ROOT)}"
        for marker in LOCAL_PATH_MARKERS:
            assert marker not in text, f"local path or account name in {path.relative_to(ROOT)}"


def test_no_backup_or_cache_files():
    names = [p.name for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]
    # .DS_Store (created by the macOS Finder) is ignored by .gitignore and removed by the packaging step.
    assert not [n for n in names if n.endswith((".orig", ".bak", ".swp", ".pyc"))]


def test_readme_states_what_is_not_tested_and_that_data_is_synthetic():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "NOT verified" in readme and "synthetic" in readme.lower() and "NOT TESTED" in readme
    assert "have not been run in Splunk or Elastic" in readme.replace("**", "") or "not been run in Splunk or Elastic" in readme.replace("**", "")


def test_no_document_claims_a_siem_run_that_never_happened():
    """A line may only say that something was tested/verified in a SIEM if the same line also says it was NOT."""
    claim = re.compile(r"(?i)\b(verified|validated|tested|confirmed) (in|on|with|against|inside) (a real |an actual |the real )?(splunk|elastic|elasticsearch|kibana)")
    for path in list((ROOT / "docs").glob("*.md")) + [ROOT / "README.md", ROOT / "TEST_RESULTS.md"]:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if claim.search(line):
                assert re.search(r"(?i)\bnot\b|\bno\b|untested|without|until you|needs? ", line), f"{path.name}:{number}: {line}"
