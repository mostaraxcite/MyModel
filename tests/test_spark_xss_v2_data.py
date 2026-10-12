"""Regression tests for Spark XSS v2 safe-sink and data balance repair."""
from collections import Counter
from pathlib import Path
import json

import pytest

from training.spark_xss_v2_data import BASE, PAIRS, SOURCES, build, FENCE
from training.spark_xss import convert
from evaluation.spark_xss_heldout import cases as original_heldout

ROOT = Path(__file__).resolve().parents[1]


def test_v2_balances_labels_and_removes_speculative_sanitizer_calls(tmp_path):
    out = tmp_path / "v4-balanced.jsonl"
    manifest = build(ROOT / BASE, out)
    rows = [json.loads(t) for t in out.read_text().splitlines()]
    assert manifest["excluded_speculative_or_nearmiss"] == 101
    assert manifest["new_pairs"] == len(PAIRS) * len(SOURCES) == 144
    assert manifest["new_records"] == 288
    assert manifest["total_records"] == len(rows)
    assert len(rows) > 480
    assert abs(manifest["labels"]["safe"] - manifest["labels"]["vulnerable"]) < 0.05 * len(rows)
    assert not any("tm-nmg-" in r["case_id"] for r in rows)
    assert all(r["messages"][1]["content"].startswith(
        "Classification: vulnerable" if r["vulnerable"] else "Classification: safe"
    ) for r in rows)
    assert not any("executes as script." in r["messages"][1]["content"]
                   for r in rows if r["case_id"].startswith("v2-"))
    assert FENCE + "javascript" in rows[-1]["messages"][0]["content"]
    assert manifest["promotion"] == "NOT_EVALUATED"


def test_v2_generated_pairs_hold_source_and_change_sink(tmp_path):
    out = tmp_path / "v4-balanced.jsonl"
    build(ROOT / BASE, out)
    rows = [json.loads(t) for t in out.read_text().splitlines()
            if '"case_id": "v2-' in t]
    assert len(rows) == 288
    pairs = {}
    for r in rows:
        family, postfix = r["case_id"].rsplit("-", 1)
        stem = family.rsplit("-", 1)[0]
        pairs.setdefault((stem, postfix), []).append(r)
    assert len(pairs) == 144
    for pair in pairs.values():
        assert len(pair) == 2
        assert {r["vulnerable"] for r in pair} == {True, False}
        unsafe, safe = sorted(pair, key=lambda r: not r["vulnerable"])
        unsafe_code = unsafe["messages"][0]["content"]
        safe_code = safe["messages"][0]["content"]
        assert unsafe_code != safe_code
        # first line of synthetic snippet remains identical for both labels
        def lines(r):
            return r["messages"][0]["content"].split(FENCE + "javascript\n", 1)[1].split("\n" + FENCE, 1)[0].splitlines()
        assert lines(unsafe)[0] == lines(safe)[0]


def test_no_exact_eval_case_is_used_for_training(tmp_path):
    out = tmp_path / "v4-balanced.jsonl"
    build(ROOT / BASE, out)
    rows = [json.loads(t) for t in out.read_text().splitlines()]
    # This test compares full snippets; conceptual overlap is NOT ruled out.
    benchmark_codes = {x["code"].strip() for x in original_heldout()}
    training_codes = set()
    import re
    for r in rows:
        q = r["messages"][0]["content"]
        m = re.search(re.escape(FENCE) + r"javascript\n(.*?)\n" + re.escape(FENCE), q, re.S)
        if m:
            training_codes.add(m.group(1).strip())
    assert not (benchmark_codes & training_codes)


def test_v2_converter_preserves_group_disjointness(tmp_path):
    out = tmp_path / "v4-balanced.jsonl"
    build(ROOT / BASE, out)
    prepared = tmp_path / "prepared"
    manifest = convert(out, prepared, balanced_v2=True)
    recipe = __import__("yaml").safe_load((prepared / "train.yaml").read_text())
    assert recipe["learning_rate"] == 2e-5
    assert recipe["num_train_epochs"] == 1.0
    assert recipe["lora_rank"] == 8
    assert recipe["logging_steps"] == 5
    assert manifest["train_records"] + manifest["eval_records"] > 480
    assert manifest["train_template_groups"] + manifest["eval_template_groups"] >= 20
    split_tags = {}
    for split in ("train", "eval"):
        for sample in json.loads((prepared / (split + ".json")).read_text()):
            assert "instruction" in sample
            assert "output" in sample


def test_v2_deterministic_and_refuses_changed_v3(tmp_path):
    first = build(ROOT / BASE, tmp_path / "first.jsonl")
    second = build(ROOT / BASE, tmp_path / "second.jsonl")
    assert first["dataset_sha256"] == second["dataset_sha256"]
    broken = tmp_path / "wrong.jsonl"
    broken.write_text("{}\n")
    with pytest.raises(ValueError, match="Unexpected source version"):
        build(broken, tmp_path / "bad.jsonl")
    assert not (tmp_path / "bad.jsonl").exists()
