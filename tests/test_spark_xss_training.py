"""Lightweight unit tests: do not download models, scan targets, or start training."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile

import pytest
import yaml

from training.spark_xss import convert, source_is_training_data, validate_record


PROJECT = Path(__file__).resolve().parents[1]


def row(group: str, suffix: str, vulnerable: bool, *, origin: str = "synthetic") -> dict:
    return {
        "case_id": f"{group}-{suffix}",
        "origin": origin,
        "tags": ["train", group],
        "vulnerable": vulnerable,
        "messages": [
            {"role": "user", "content": f"Analyze XSS in {group} code {suffix}"},
            {"role": "assistant", "content": f"Classification: {'vulnerable' if vulnerable else 'safe'}"},
        ],
    }


def make_source(folder: Path) -> Path:
    source = folder / "sft.jsonl"
    values = [
        row("html_template", "v-01", True),
        row("html_template", "s-01", False),
        row("script_template", "v-01", True),
        row("script_template", "s-01", False),
        row("dom_template", "v-01", True),
        row("dom_template", "s-01", False),
        row("url_template", "v-01", True),
        row("url_template", "s-01", False),
    ]
    source.write_text("".join(json.dumps(r) + "\n" for r in values), encoding="utf-8")
    return source


def test_export_is_group_disjoint_and_never_launches_training(tmp_path):
    with tempfile.TemporaryDirectory(prefix="spark-test-", dir=PROJECT / "data" / "training") as directory:
        source = make_source(Path(directory))
        out = tmp_path / "spark"
        manifest = convert(source, out, valid_fraction=0.25)
        train = json.loads((out / "train.json").read_text())
        valid = json.loads((out / "eval.json").read_text())
        assert manifest["status"] == "DATA_PREPARED_NOT_TRAINED"
        assert manifest["promotion"] == "NOT_EVALUATED"
        assert manifest["browser_confirmation_required"]
        assert len(train) + len(valid) == 8
        assert all("instruction" in r and "output" in r for r in train + valid)
        assert not ({r["instruction"].split()[3] for r in train} &
                    {r["instruction"].split()[3] for r in valid})
        assert manifest["train_template_groups"] == 3
        assert manifest["eval_template_groups"] == 1
        assert set(manifest["class_counts"]["train"]) == {"safe", "vulnerable"}
        assert set(manifest["class_counts"]["eval"]) == {"safe", "vulnerable"}
        recipe = yaml.safe_load((out / "train.yaml").read_text())
        assert recipe["model_name_or_path"] == "XHToken/Spark-X2.5-4B"
        assert recipe["do_eval"] and recipe["do_train"]
        assert recipe["finetuning_type"] == "lora"
        assert recipe["dataset"] == "spark_xss_train"
        assert recipe["eval_dataset"] == "spark_xss_eval"
        assert recipe["template"] == "spark"
        assert recipe["gradient_checkpointing"] is True
        assert not (out / "adapter").exists()


def test_export_deterministic(tmp_path):
    with tempfile.TemporaryDirectory(prefix="spark-test-", dir=PROJECT / "data" / "training") as directory:
        source = make_source(Path(directory))
        one = convert(source, tmp_path / "one")
        two = convert(source, tmp_path / "two")
        assert one["train_sha256"] == two["train_sha256"]
        assert one["eval_sha256"] == two["eval_sha256"]


def test_frozen_benchmarks_are_forbidden(tmp_path):
    assert not source_is_training_data(PROJECT / "benchmarks" / "frozen" / "test.jsonl")
    with pytest.raises(ValueError, match="data/training"):
        convert(PROJECT / "benchmarks" / "frozen" / "test.jsonl", tmp_path)


def test_unknown_or_unreviewed_origin_rejected():
    with pytest.raises(ValueError, match="origin"):
        validate_record(row("a", "v-1", True, origin="web_scrape"), 1)
    with pytest.raises(ValueError, match="reviewed"):
        validate_record(row("a", "v-1", True, origin="verified"), 1)


def test_locked_test_tag_rejected():
    record = row("a", "v-1", True)
    record["tags"].append("locked")
    with pytest.raises(ValueError, match="locked"):
        validate_record(record, 1)


def test_duplicate_prompt_across_groups_fails(tmp_path):
    with tempfile.TemporaryDirectory(prefix="spark-test-", dir=PROJECT / "data" / "training") as directory:
        source = make_source(Path(directory))
        values = [json.loads(line) for line in source.read_text().splitlines()]
        values[2]["messages"][0]["content"] = values[0]["messages"][0]["content"]
        source.write_text("".join(json.dumps(r) + "\n" for r in values))
        with pytest.raises(ValueError, match="Identical prompts"):
            convert(source, tmp_path / "out")


def test_existing_xss_sft_v3_corpus_prepares_without_gpu(tmp_path):
    manifest = convert(PROJECT / "data" / "training" / "sft_v3.jsonl", tmp_path / "prepared")
    assert manifest["train_records"] + manifest["eval_records"] == 359
    assert manifest["train_template_groups"] + manifest["eval_template_groups"] == 8
    assert manifest["status"] == "DATA_PREPARED_NOT_TRAINED"
    assert manifest["promotion"] == "NOT_EVALUATED"
