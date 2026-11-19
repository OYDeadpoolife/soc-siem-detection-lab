"""Static checks of the query and configuration files.

These tests do NOT run Splunk or Elastic. They only verify what can be verified without them: that every query file is documented,
read-only, structurally sane, cross-referenced with the reference implementation and the documentation, and that JSON and XML parse.
The result is deliberately called a static check: it cannot find SPL or KQL syntax errors.
"""

import json
import re
import xml.etree.ElementTree as ET

import pytest

from conftest import ROOT

SPL_DIR = ROOT / "splunk" / "spl"
SPL_FILES = sorted(SPL_DIR.glob("*.spl"))
REQUIRED_HEADERS = ["ID", "Name", "Purpose", "Data", "MITRE ATT&CK", "Reference implementation", "Expected on the synthetic datasets",
                    "False positives", "Tuning", "Status"]
FORBIDDEN_SPL_COMMANDS = ("delete", "outputlookup", "outputcsv", "collect", "sendemail", "script", "run", "map", "rest", "dbxquery", "tscollect")


def split_spl(path):
    headers, body = {}, []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            key, _, value = line[1:].partition(":")
            if value:
                headers[key.strip()] = value.strip()
        elif line.strip():
            body.append(line)
    return headers, "\n".join(body)


def test_there_are_thirteen_spl_files():
    assert len(SPL_FILES) == 13


@pytest.mark.parametrize("path", SPL_FILES, ids=lambda p: p.name)
def test_spl_file_is_documented_and_marked_not_tested(path):
    headers, _ = split_spl(path)
    for name in REQUIRED_HEADERS:
        assert headers.get(name), f"{path.name}: missing header '{name}'"
    assert path.name.startswith(headers["ID"] + "_")
    assert headers["Status"].startswith("NOT TESTED in Splunk")
    assert re.search(r"T\d{4}", headers["MITRE ATT&CK"]) or "investigation" in headers["MITRE ATT&CK"].lower() or "Supports" in headers["MITRE ATT&CK"]


@pytest.mark.parametrize("path", SPL_FILES, ids=lambda p: p.name)
def test_spl_query_is_read_only_and_structurally_sane(path):
    _, body = split_spl(path)
    assert body.startswith("index=soc_lab"), "every query names the lab index explicitly"
    for command in FORBIDDEN_SPL_COMMANDS:
        assert not re.search(rf"\|\s*{command}\b", body), f"{path.name} uses the command '{command}'"
    # Escaped characters (\( \" ...) and character classes ([^)]) are not structure, so remove them before counting.
    structure = re.sub(r"\[\^?[^\]]*\]", "", re.sub(r"\\.", "", body))
    assert structure.count("(") == structure.count(")"), "unbalanced parentheses"
    assert structure.count('"') % 2 == 0, "unbalanced double quotes"
    assert "||" not in body and not body.rstrip().endswith("|")
    for line in body.splitlines()[1:]:
        assert line.lstrip().startswith(("|", "(")), f"{path.name}: unexpected continuation line: {line!r}"


def test_every_spl_file_points_at_an_existing_reference_function(reference):
    for path in SPL_FILES:
        headers, _ = split_spl(path)
        function = headers["Reference implementation"].split("::")[1].split()[0]
        assert hasattr(reference, function), f"{path.name} refers to missing function {function}"


def test_every_detection_is_documented_in_the_catalog():
    catalog = (ROOT / "docs" / "detections.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for path in SPL_FILES:
        detection = split_spl(path)[0]["ID"]
        assert detection in catalog, f"{detection} missing from docs/detections.md"
        assert path.name in catalog
    for number in range(1, 13):
        assert f"DET-{number:02d}" in readme


def test_catalog_claims_about_elastic_match_the_files():
    kql = (ROOT / "elastic" / "kql" / "queries.md").read_text(encoding="utf-8")
    catalog = (ROOT / "docs" / "detections.md").read_text(encoding="utf-8")
    rows = [line for line in catalog.splitlines() if line.startswith("| DET-") and ".spl" in line]
    assert len(rows) == 13
    for row in rows:
        cells = [c.strip() for c in row.strip("|").split("|")]
        detection, elastic = cells[0], cells[4]
        if "KQL" in elastic:
            assert detection in kql, f"{detection} is claimed to have a KQL query"
        if elastic == "not provided":
            assert f"| {detection} |" not in kql


def test_every_status_in_the_catalog_is_honest():
    catalog = (ROOT / "docs" / "detections.md").read_text(encoding="utf-8")
    for row in (line for line in catalog.splitlines() if line.startswith("| DET-") and ".spl" in line):
        assert row.rstrip().endswith("| PASS | NOT TESTED |"), row


@pytest.mark.parametrize("path", sorted((ROOT / "elastic" / "queries").glob("*.json")), ids=lambda p: p.name)
def test_query_dsl_bodies_are_valid_json_with_only_search_keys(path):
    body = json.loads(path.read_text(encoding="utf-8"))
    assert set(body) <= {"size", "query", "aggs", "sort", "_source"}, "unknown top-level keys are rejected by Elasticsearch"
    assert "query" in body


def test_eql_files_are_sequences_with_a_time_limit_and_marked_not_tested():
    for path in (ROOT / "elastic" / "eql").glob("*.eql"):
        text = path.read_text(encoding="utf-8")
        assert re.search(r"^sequence by \S+ with maxspan=\d+[smh]$", text, re.MULTILINE), path.name
        assert "NOT TESTED" in text and text.count("[") >= 2


def test_dashboard_is_well_formed_and_uses_the_lab_index():
    tree = ET.parse(ROOT / "splunk" / "dashboards" / "soc_overview.xml")
    queries = [element.text for element in tree.iter("query")]
    assert len(queries) == 4 and all(q.strip().startswith("index=soc_lab") for q in queries)


def test_configuration_examples_contain_no_secrets():
    for path in list((ROOT / "elastic" / "beats").glob("*.example")) + list((ROOT / "splunk").glob("*.example")):
        text = path.read_text(encoding="utf-8")
        assert "NOT TESTED" in text, path.name
        for line in text.splitlines():
            if re.match(r"\s*(api_key|password)\s*[:=]", line):
                assert "${ES_API_KEY}" in line, f"{path.name}: literal credential? {line}"


def test_alert_examples_are_valid_json_and_reference_real_detections():
    text = (ROOT / "alerts" / "alert-examples.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```json\n(.*?)\n```", text, re.DOTALL)
    assert len(blocks) == 4
    for block in blocks:
        alert = json.loads(block)
        assert re.match(r"DET-\d{2}", alert["rule"]) and alert["alert_id"].startswith("ALERT-")


def test_mermaid_diagrams_have_a_known_type_and_balanced_brackets():
    count = 0
    for path in list((ROOT / "docs").glob("*.md")) + [ROOT / "README.md"]:
        for block in re.findall(r"```mermaid\n(.*?)\n```", path.read_text(encoding="utf-8"), re.DOTALL):
            count += 1
            assert block.split()[0] in {"flowchart", "graph", "sequenceDiagram"}, path.name
            for opening, closing in ("[]", "()", "{}"):
                assert block.count(opening) == block.count(closing), f"{path.name}: unbalanced {opening}{closing}"
            assert block.count('"') % 2 == 0, f"{path.name}: unbalanced quotes"
    assert count >= 5
