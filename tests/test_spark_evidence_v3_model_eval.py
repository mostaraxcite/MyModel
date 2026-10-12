"""Check evidence-only GPU result scoring is strict and cannot be promoted."""
import json
import pytest

from evaluation.spark_evidence_v3_model_eval import (
    FIELDS,parse_advisory,score_predictions,select_internal_dev,spark_prompt
)
from xss_specialist.evidence_pipeline import review_evidence


def test_dev_is_stratified_and_template_held_out():
    cases=select_internal_dev()
    assert len(cases)==12
    groups={item["family"] for item in cases}
    assert len(groups)==6
    assert all(sum(x["family"]==f for x in cases)==2 for f in groups)
    assert {item["expected_static_status"] for item in cases}=={
        "SAFE","CANDIDATE","INCONCLUSIVE"
    }


def test_only_exact_evidence_object_qualifies():
    sample=select_internal_dev()[0]
    proof=review_evidence(sample["code"])
    true_fields={k:proof[k] for k in FIELDS}
    assert parse_advisory(json.dumps(true_fields))==true_fields
    assert parse_advisory(json.dumps({**true_fields,"verdict":"XSS"})) is None
    assert parse_advisory("Classification: vulnerable") is None
    assert parse_advisory(json.dumps({**true_fields,"confirmed":True})) is None
    assert parse_advisory("not-json") is None


def test_perfect_advice_is_accepted_but_never_promoted():
    cases=select_internal_dev()
    preds=[]
    for item in cases:
        expected=review_evidence(item["code"])
        data={k:expected[k] for k in FIELDS}
        preds.append({"case_id":item["case_id"],"raw":json.dumps(data)})
    out=score_predictions(cases,preds)
    assert out["json_valid_rate"]==1.0
    assert out["grounded_exact_rate"]==1.0
    assert all(rate==1.0 for rate in out["field_exact_rate"].values())
    assert out["model_can_override_gate"] is False
    assert out["browser_confirmations"]==0


def test_wrong_evidence_and_partial_json_are_rejected():
    cases=select_internal_dev()
    preds=[]
    for item in cases:
        proof=review_evidence(item["code"])
        data={k:proof[k] for k in FIELDS}
        data["source"]={"status":"OBSERVED","observed":["invented.attacker"]}
        preds.append({"case_id":item["case_id"],"raw":json.dumps(data)})
    scored=score_predictions(cases,preds)
    assert scored["json_valid_rate"]==1.0
    assert scored["grounded_exact_rate"]==0.0
    assert scored["field_exact_rate"]["source"]==0.0
    with pytest.raises(ValueError,match="Missing or incomplete"):
        score_predictions(cases,preds[:-1])


def test_prompt_never_primes_binary_label():
    prompt=spark_prompt(select_internal_dev()[0]["messages"][0]["content"])
    assert prompt.endswith("<|Bot|></think>")
    assert not prompt.endswith("Classification:")


def test_kaggle_field_eval_uses_verified_training_and_fp16():
    from pathlib import Path
    root=Path(__file__).resolve().parents[1]
    src=(root/"kaggle/spark_evidence_v3_eval.py").read_text()
    workflow=(root/".github/workflows/spark-evidence-v3-field-eval.yml").read_text()
    assert 'EXPECTED_TRAINING_SHA = "131bbeb6600537a0635047bd62dca688da72a7fe"' in src
    assert 'run_state.get("model_has_final_authority") is False' in src
    assert 'training_rows") == 220' in src
    assert 'tree-sitter-javascript' in src
    assert 'evaluation.spark_evidence_v3_model_eval' in src
    assert "KernelWorkerStatus.COMPLETE" in workflow
    assert '"model_promoted"] is False' in workflow
    assert 'spark-xss-evidence-v3' in workflow
    assert 'spark-evidence-v3-field-evaluation' in workflow
    assert 'DO_NOT_PROMOTE' in workflow
