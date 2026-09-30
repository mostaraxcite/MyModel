"""Regression tests for the v0.5 repair set."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from training.train_peft_encoder import DEFAULT_LORA_TARGETS
from xss_specialist.adapter_registry import AdapterSpec, Registry, load_classifier
from xss_specialist.oracle import analyze


def test_lora_targets_do_not_capture_generic_dense_layers():
    assert DEFAULT_LORA_TARGETS == ["query", "key", "value"]
    assert "dense" not in DEFAULT_LORA_TARGETS


def test_static_heuristic_does_not_call_static_href_xss():
    assert analyze("a.setAttribute('href', '/home')").label == "SAFE"
    assert analyze("a.setAttribute('href', trustedPath)").label == "POSSIBLE_XSS"
    assert analyze("a.setAttribute('onclick', location.search)").label == "XSS"


def test_external_v5_has_unique_classifier_inputs():
    path = Path("security-models/xss/data/external_test_v5.jsonl")
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    hashes = [row["provenance"]["content_sha256"] for row in rows]
    assert len(rows) == 454
    assert len(hashes) == len(set(hashes))


def test_external_v5_conflicts_are_quarantined():
    path = Path("security-models/xss/data/external_test_v5_conflicts.jsonl")
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    assert len(rows) == 2
    assert len({row["label"] for row in rows}) == 2
    assert len({row["provenance"]["content_sha256"] for row in rows}) == 1


def test_missing_promoted_full_model_fails_loudly(tmp_path: Path):
    reg = Registry(
        registry_path=tmp_path / "REGISTRY.json",
        adapters={
            "v0.4-baseline": AdapterSpec(
                name="v0.4-baseline",
                kind="full",
                base_model="google/bert_uncased_L-4_H-256_A-4",
                path=str(tmp_path / "missing-model"),
                promoted=True,
            )
        },
        active="v0.4-baseline",
    )
    with pytest.raises(FileNotFoundError, match="not bundled in Git"):
        load_classifier(registry=reg)
