"""V2 regression remains read-only and cannot bypass adapter provenance."""
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def test_v2_evaluator_pins_only_trained_candidate():
    source=(ROOT/"kaggle/spark_xss_eval_v2.py").read_text()
    assert 'EXPECTED_TRAINING_SHA = "06069340505e535573230a81eb88c45560084df3"' in source
    assert 'run_state.get("training_variant") == "balanced_v2_hard_negatives"' in source
    assert 'run_state.get("dataset_records", 0) >= 480' in source
    assert 'PeftModel' not in source or "run_evaluation(" in source
    assert 'EXPOSED_V1_REGRESSION_NOT_FRESH_INDEPENDENT' in source
    assert '(OUTPUT / "report.json").write_text' in source
    assert '"NOT_APPROVED"' in source


def test_v2_eval_workflow_requires_real_finished_training():
    s=(ROOT/".github/workflows/spark-xss-v2-regression-eval.yml").read_text()
    assert "KernelWorkerStatus.COMPLETE" in s
    assert "candidate_saved_not_evaluated" in s
    assert "refusing GPU evaluation" in s
    assert "spark-xss-balanced-v2-candidate" in s
    assert "spark-xss-v2-regression-evaluation" in s
    assert "workflow_run" in s
    assert "[launch-spark-v2]" not in s
    assert "--file-pattern 'run_status[.]json$'" in s
