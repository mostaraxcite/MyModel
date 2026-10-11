"""Offline quality gates for locked Spark XSS evaluation."""
import json
from pathlib import Path

import pytest

from evaluation.spark_xss_heldout import cases, assert_no_training_overlap
from evaluation.spark_xss_benchmark import classification_metrics, score_report, spark_input

ROOT = Path(__file__).resolve().parents[1]


def test_frozen_data_is_balanced_and_nonempty():
    c = cases()
    assert len(c) == 48
    assert len({x["id"] for x in c}) == 48
    assert sum(x["label"] == "safe" for x in c) == 24
    assert sum(x["label"] == "vulnerable" for x in c) == 24
    assert len({x["family"] for x in c}) >= 10
    assert all(x["code"] in x["prompt"] for x in c)


def test_no_exact_overlap_with_training_or_prior_dev_set():
    result = assert_no_training_overlap(ROOT / "data/training/sft_v3.jsonl")
    assert result["exact_overlaps"] == 0
    assert result["cases"] == 48


def test_overlap_guard_rejects_an_inserted_heldout_case(tmp_path):
    test = cases()[0]
    mock = tmp_path / "leaked.jsonl"
    mock.write_text(json.dumps({"messages": [{"content": test["prompt"]}]}) + "\n")
    with pytest.raises(ValueError, match="overlaps"):
        assert_no_training_overlap(mock)


def test_pairwise_static_controls_are_balanced():
    pairs = {}
    for item in cases():
        stem = item["id"].removesuffix("-safe").removesuffix("-unsafe")
        pairs.setdefault(stem, set()).add(item["label"])
    assert len(pairs) == 24
    assert all(tags == {"safe", "vulnerable"} for tags in pairs.values())


def test_metrics_are_valid_and_explicit():
    out = classification_metrics(
        ["safe", "safe", "vulnerable", "vulnerable"],
        ["safe", "vulnerable", "vulnerable", "safe"],
    )
    assert out["tp"] == out["tn"] == out["fp"] == out["fn"] == 1
    assert out["accuracy"] == 0.5
    assert out["fpr"] == 0.5
    assert out["fnr"] == 0.5
    assert out["f1"] == 0.5


def test_abstentions_do_not_game_false_positive_rate():
    out = classification_metrics(["safe", "vulnerable"], ["unknown", "unknown"])
    assert out["abstained"] == 2
    assert out["fp"] == out["fn"] == 1
    assert out["accuracy"] == 0


def test_misaligned_scores_are_rejected():
    items = cases()
    b = [{"id": x["id"], "prediction": x["label"]} for x in items]
    with pytest.raises(ValueError, match="Incomplete"):
        score_report(items, b, b[:-1])
    with pytest.raises(ValueError, match="align"):
        score_report(items, b[::-1], b)


def test_perfect_score_does_not_promote_to_production():
    items = cases()
    b = [{"id": x["id"], "prediction": "vulnerable"} for x in items]
    tuned = [{"id": x["id"], "prediction": x["label"]} for x in items]
    result = score_report(items, b, tuned)
    assert result["trained"]["accuracy"] == 1
    assert result["trained"]["fpr"] == 0
    assert result["trained"]["fnr"] == 0
    assert result["paired_contrast_accuracy"] == 1
    assert result["promotion_recommendation"] == "DO_NOT_PROMOTE"


def test_spark_chat_prefix_matches_sft_logs():
    prefix = spark_input(cases()[0]["prompt"])
    assert "<|System|>" in prefix and "<|User|>" in prefix
    assert prefix.endswith("<|Bot|></think>Classification:")
    assert chr(96) * 3 + "javascript" in prefix


def test_no_training_frozen_data_dependency_or_auto_promotion():
    assert all("benchmark" not in x["code"] for x in cases())
    source = (ROOT / "evaluation/spark_xss_benchmark.py").read_text()
    assert "PeftModel.from_pretrained" in source
    assert "AutoModelForCausalLM.from_pretrained" in source
    assert "DO_NOT_PROMOTE" in source
    assert "assert_no_training_overlap" in source
