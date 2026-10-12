"""Reproducible manual 2026 XSS benchmark; no Kaggle/model invocation."""
import hashlib
import json

import pytest

from evaluation.fresh_static_xss_suite import (
    CASES, LABELS, DECISIONS, dataset_manifest, evaluate,
)
from evaluation.spark_xss_heldout import cases as old_frozen
from training.spark_xss_evidence_v3 import candidate_rows


def test_fresh_suite_version_and_provenance():
    manifest=dataset_manifest()
    assert len(CASES)==42
    assert manifest["label_distribution"]=={
        "unsafe":15,"safe":15,"needs_review":12
    }
    assert manifest["partitions"]=={"diagnostic":26,"audit":16}
    assert manifest["promotion"]=="DO_NOT_PROMOTE"
    assert manifest["training_use"]=="FORBIDDEN"
    assert manifest["test_only"] is True
    assert len(set(manifest["code_sha256"].values()))==42
    for c in CASES:
        assert c.rationale
        assert manifest["code_sha256"][c.id]==hashlib.sha256(c.code.encode()).hexdigest()


def test_new_cases_are_exactly_disjoint_from_prior_frozen_and_sft():
    previous={c["code"].strip() for c in old_frozen()}
    previous.update(c["code"].strip() for c in candidate_rows())
    assert previous.isdisjoint({c.code.strip() for c in CASES})


def test_diagnostic_report_is_complete_without_browser_claims():
    report=evaluate(partition="diagnostic")
    assert report["n"]==26
    assert report["browser_confirmed"]==0
    assert report["model_evaluated"] is False
    assert report["promotion"]=="DO_NOT_PROMOTE"
    assert len(report["cases"])==26
    for label in LABELS:
        assert set(report["confusion"][label])==set(DECISIONS)
    for score in report["metrics"].values():
        assert 0.0<=score<=1.0
    assert all(x["static_decision"] in DECISIONS for x in report["cases"])


def test_rejects_implicit_or_invalid_partition():
    with pytest.raises(ValueError,match="diagnostic or audit"):
        evaluate(partition="all")


def test_benchmark_has_no_model_vulnerability_authority():
    from pathlib import Path
    s=(Path(__file__).resolve().parents[1]/"evaluation/fresh_static_xss_suite.py").read_text()
    assert "grounded_review" in s
    assert "KAGGLE" not in s.upper()
    assert "browser_confirmed" in s
    assert "promotion" in s
