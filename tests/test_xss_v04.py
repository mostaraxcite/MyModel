"""Tests for XSS-SLM v0.4 pipeline: external sources, adversarial, v4 build."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "security-models" / "xss" / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FETCH = _load("fetch_external_sources")
ADV = _load("adversarial_hard_test")
BUILD = _load("build_v3_dataset")


def test_curated_records_have_provenance_and_license():
    rows = FETCH.curated_records()
    assert rows, "curated records must not be empty"
    allowed_labels = {"SAFE", "POSSIBLE_XSS", "XSS"}
    for row in rows:
        prov = row["provenance"]
        assert prov["origin"] == "external-curated"
        assert "source_url" in prov and prov["source_url"].startswith("http")
        assert "license" in prov and prov["license"]
        assert "content_sha256_20" in prov
        assert row["label"] in allowed_labels


def test_adversarial_rows_are_locked_and_unique():
    rows = ADV.build_adversarial(seed=2028, copies_per_case=1)
    assert len(rows) > 50
    codes = [row["code"] for row in rows]
    assert len(set(codes)) == len(codes), "adversarial codes must be unique"
    for row in rows:
        assert row["provenance"]["partition"] == "hard_test_v4_locked"
        assert row["label"] in ("SAFE", "POSSIBLE_XSS", "XSS")


def test_external_shape_rows_validate_and_substitute_placeholder():
    rows = BUILD.make_external_shape_rows(count=200, seed=2027)
    assert rows
    for row in rows:
        code = row["code"]
        assert "__SRC__" not in code, f"unsubstituted placeholder in {row['id']}"
        errors = BUILD.validate_sample(row, allow_unknown_sanitizer=True)
        assert not errors, f"invalid shape row {row['id']}: {errors}"


def test_v4_manifest_promotion_threshold_and_locked_hard_test():
    """The v0.4 manifest must declare the hard test locked and threshold = 0.90."""
    manifest_path = ROOT / "security-models" / "xss" / "data" / "manifest.json"
    if not manifest_path.exists():
        return  # build not yet run in this checkout
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["version"] == "v0.4"
    assert manifest["policy"]["hard_test_v4_locked"] is True
    assert manifest["policy"]["promotion_threshold_macro_f1"] == 0.90
    assert manifest["policy"]["standard_test_unchanged"] is True


def test_external_shape_no_template_tokens():
    """External-shape rows must not contain the synthetic template markers."""
    forbidden = ("value0", "value1", "value2", "tainted_0", "tainted_1", "tainted_2")
    rows = BUILD.make_external_shape_rows(count=200, seed=2027)
    for row in rows:
        for token in forbidden:
            assert token not in row["code"], f"forbidden template token {token} in {row['id']}"


def test_adversarial_origin_marker():
    rows = ADV.build_adversarial(seed=2028, copies_per_case=1)
    for row in rows:
        assert row["provenance"]["origin"] == "adversarial"
