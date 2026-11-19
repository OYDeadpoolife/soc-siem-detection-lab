"""The Elasticsearch bulk-file builder and the loader's dry-run mode."""

import json
import os
import shutil
import subprocess
import sys

import pytest

from conftest import DATASETS, ROOT, read_jsonl

LOADER = ROOT / "scripts" / "load_to_elasticsearch.sh"


def build(tmp_path):
    out = tmp_path / "bulk"
    subprocess.run([sys.executable, str(ROOT / "tools" / "make_bulk_files.py"), "--datasets", str(DATASETS), "--out-dir", str(out)],
                   check=True, capture_output=True)
    return out


def test_bulk_files_alternate_action_and_document_lines(tmp_path):
    out = build(tmp_path)
    for name, source, index in (("soc-lab-linux-auth.ndjson", "linux/auth_ecs.jsonl", "soc-lab-linux-auth"),
                                ("soc-lab-windows-sysmon.ndjson", "windows/sysmon_ecs.jsonl", "soc-lab-windows-sysmon")):
        lines = (out / name).read_text(encoding="utf-8").splitlines()
        documents = read_jsonl(DATASETS / source)
        assert len(lines) == 2 * len(documents)
        for position, document in enumerate(documents):
            assert json.loads(lines[2 * position]) == {"index": {"_index": index}}
            assert json.loads(lines[2 * position + 1]) == document


def test_bulk_builder_rejects_invalid_json(tmp_path):
    bad = tmp_path / "data" / "linux"
    bad.mkdir(parents=True)
    (bad / "auth_ecs.jsonl").write_text('{"ok": true}\n{not json}\n')
    (tmp_path / "data" / "windows").mkdir()
    (tmp_path / "data" / "windows" / "sysmon_ecs.jsonl").write_text("")
    completed = subprocess.run([sys.executable, str(ROOT / "tools" / "make_bulk_files.py"), "--datasets", str(tmp_path / "data"),
                                "--out-dir", str(tmp_path / "out")], capture_output=True, text=True)
    assert completed.returncode != 0 and "JSONDecodeError" in completed.stderr


def run_loader(*args, env_extra=None):
    env = dict(os.environ)
    env.pop("ES_URL", None)
    env.pop("ES_API_KEY", None)
    env.update(env_extra or {})
    return subprocess.run([str(LOADER), *map(str, args)], capture_output=True, text=True, env=env)


def test_loader_dry_run_sends_nothing_and_needs_no_credentials(tmp_path):
    out = build(tmp_path)
    result = run_loader("--bulk-dir", out, "--dry-run", env_extra={"ES_URL": "https://example.test:9200"})
    assert result.returncode == 0, result.stderr
    assert "would send" in result.stdout and "135 documents" in result.stdout and "28 documents" in result.stdout


def test_loader_refuses_without_a_target_or_a_key(tmp_path):
    out = build(tmp_path)
    assert run_loader("--bulk-dir", out, "--dry-run").returncode == 2  # no ES_URL
    without_key = run_loader("--bulk-dir", out, env_extra={"ES_URL": "https://example.test:9200"})
    assert without_key.returncode == 2 and "ES_API_KEY" in without_key.stderr


def test_loader_fails_clearly_for_a_missing_folder_and_bad_option(tmp_path):
    assert run_loader("--bulk-dir", tmp_path / "missing", env_extra={"ES_URL": "https://x.test"}).returncode == 3
    assert run_loader("--bogus", env_extra={"ES_URL": "https://x.test"}).returncode == 2


def test_loader_never_puts_the_key_on_a_command_line_or_in_the_file():
    text = LOADER.read_text(encoding="utf-8")
    assert "ES_API_KEY" in text and "--insecure" not in text and " -k " not in text
    assert "sudo" not in text


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck is not installed")
def test_loader_passes_shellcheck_and_shfmt():
    assert subprocess.run(["shellcheck", "-x", str(LOADER)], capture_output=True).returncode == 0
    if shutil.which("shfmt"):
        assert subprocess.run(["shfmt", "-d", "-i", "4", "-ci", str(LOADER)], capture_output=True).returncode == 0
