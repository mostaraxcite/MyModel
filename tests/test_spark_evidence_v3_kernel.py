"""Kaggle v3 evidence-advisor training must not overwrite prior adapters."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def test_v3_kernel_is_isolated_and_evidence_only():
    v3=(ROOT/"kaggle/spark_xss_evidence_v3_train.py").read_text()
    v2=(ROOT/"kaggle/spark_xss_train_v2.py").read_text()
    old=(ROOT/"kaggle/spark_xss_train.py").read_text()
    assert 'REPO_SHA = "__MYMODEL_SHA__"' in v3
    assert "spark-xss-evidence-v3-result" in v3
    assert "spark-xss-result-v2" in v2
    assert 'spark-xss-result"' in old
    assert "training.spark_xss_evidence_v3" in v3
    assert "ADVISORY_EVIDENCE_FIELDS_ONLY" in v3
    assert "model_has_final_authority" in v3
    assert "candidate_saved_not_evaluated" in v3
    assert '"model_promoted": False' in v3
    assert "KAGGLE_ROOT" in v3
    assert "training.spark_xss_v2_data" not in v3
    assert "data/training/sft_v3.jsonl" not in v3
    assert "data/training/sft_v4_balanced.jsonl" not in v3


def test_v3_uses_conservative_t4_fork_and_no_automatic_promotion():
    v3=(ROOT/"kaggle/spark_xss_evidence_v3_train.py").read_text()
    assert 'TRANSFORMERS_VERSION = "4.57.1"' in v3
    assert 'FORK_SHA = "f56888d47dc5681e15b83ddbea01adddf2050adf"' in v3
    assert 'SPARK_XSS_PREPARE_ONLY' in v3
    assert 'tree-sitter-javascript' in v3
    assert 'model_info(MODEL_ID)' in v3
    assert 'browser_confirmation_required' in v3
    assert 'model_promoted = True' not in v3
