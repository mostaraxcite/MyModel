"""Guarantee v3 trains on grounded fields, not forced binary labels."""
import json
import re
from pathlib import Path

import pytest
import yaml

from evaluation.spark_xss_heldout import cases as old_evaluation_cases
from training.spark_xss_evidence_v3 import (
    GROUPS, SOURCES, VARIABLES, candidate_rows, build,
)
from xss_specialist.evidence_pipeline import review_evidence, validate_advisory


def test_v3_three_state_template_grouping_and_counts():
    rows=candidate_rows()
    assert len(rows)==len(GROUPS)*len(SOURCES)*len(VARIABLES)==340
    assert len({r["code"] for r in rows})==len(rows)
    for split in ("train","eval"):
        sample=[r for r in rows if r["split"]==split]
        assert {r["expected_static_status"] for r in sample}=={"CANDIDATE","SAFE","INCONCLUSIVE"}
    train={r["family"] for r in rows if r["split"]=="train"}
    dev={r["family"] for r in rows if r["split"]=="eval"}
    assert train.isdisjoint(dev)


def test_no_old_exposed_48_case_contamination():
    old={r["code"].strip() for r in old_evaluation_cases()}
    generated={r["code"].strip() for r in candidate_rows()}
    assert generated.isdisjoint(old)


def test_no_previous_sft_snippet_contamination():
    root=Path(__file__).resolve().parents[1]
    existing=set()
    fence=chr(96)*3
    for line in (root/"data/training/sft_v3.jsonl").read_text().splitlines():
        if not line.strip(): continue
        record=json.loads(line)
        p=record["messages"][0]["content"]
        for match in re.finditer(re.escape(fence)+r"(?:javascript|js)\n(.*?)\n"+re.escape(fence),p,re.S):
            existing.add(match.group(1).strip())
    new={r["code"].strip() for r in candidate_rows()}
    assert not (new & existing)


def test_prompts_do_not_teach_final_binary_verdict():
    for r in candidate_rows():
        q=r["messages"][0]["content"]
        a=json.loads(r["messages"][1]["content"])
        assert "Classification:" not in q
        assert "Classification:" not in r["messages"][1]["content"]
        assert "decision" not in a
        assert "confirmed" not in a
        assert set(a)=={"snippet_sha256","source","flow","sink","defense","limitations"}
        assert a["snippet_sha256"]==review_evidence(r["code"])["snippet_sha256"]
        assert "XSS_EVIDENCE_FIELDS" in q
        assert r["origin"]=="synthetic"


def test_oracle_compatibility_of_training_advisory():
    for r in candidate_rows():
        expected=review_evidence(r["code"])
        advisory=json.loads(r["messages"][1]["content"])
        result=validate_advisory(advisory,expected)
        assert result["accepted"] is True, (r["case_id"],result)


def test_v3_output_recipe_and_no_production_promotion(tmp_path):
    m=build(tmp_path/"adapter-source")
    assert m["status"]=="DATA_PREPARED_NOT_TRAINED"
    assert m["train"]==220 and m["eval"]==120
    assert m["training_target"]=="ADVISORY_EVIDENCE_FIELDS_ONLY"
    assert m["promotion"]=="DO_NOT_PROMOTE"
    recipe=yaml.safe_load((tmp_path/"adapter-source/train.yaml").read_text())
    assert recipe["model_name_or_path"]=="XHToken/Spark-X2.5-4B"
    assert recipe["learning_rate"]==1.0e-5
    assert recipe["quantization_bit"]==4
    assert recipe["lora_rank"]==8
    train=json.loads((tmp_path/"adapter-source/train.json").read_text())
    dev=json.loads((tmp_path/"adapter-source/eval.json").read_text())
    assert len(train)==220 and len(dev)==120
    assert all("instruction" in record and "output" in record for record in train+dev)
    assert not (tmp_path/"adapter-source/adapter").exists()


def test_v3_reproducibility(tmp_path):
    a=build(tmp_path/"a")
    b=build(tmp_path/"b")
    assert a["train_sha256"]==b["train_sha256"]
    assert a["eval_sha256"]==b["eval_sha256"]


def test_v3_prevent_overwriting_training_or_frozen(tmp_path):
    root=Path(__file__).resolve().parents[1]
    with pytest.raises(ValueError,match="cannot overwrite"):
        build(root/"data/training/not-allowed")
    with pytest.raises(ValueError,match="cannot overwrite"):
        build(root/"evaluation/unsafe")
