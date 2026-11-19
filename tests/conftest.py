"""Shared paths and loaders for the SOC lab tests."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DATASETS = ROOT / "datasets"


def load_module(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def reference():
    return load_module("reference_detections", "detections/reference_detections.py")


@pytest.fixture(scope="session")
def generator():
    return load_module("generate_synthetic_logs", "tools/generate_synthetic_logs.py")


@pytest.fixture(scope="session")
def results(reference):
    return reference.run_all(DATASETS)


def read_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
