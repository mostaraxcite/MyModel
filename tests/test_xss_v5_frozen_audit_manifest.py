"""Audited suite metadata only: don't score frozen cases during PR CI."""
from hashlib import sha256

from evaluation.fresh_xss_v5_flow_audit import CASES, manifest
from evaluation.fresh_static_xss_suite import CASES as previous_audit
from evaluation.spark_xss_heldout import cases as original_benchmark


def test_24_case_audit_is_frozen_and_non_promoting():
    m=manifest()
    assert m["count"]=={"unsafe":8,"safe":8,"needs_review":8}
    assert len(m["code_sha256"])==24
    assert m["browser_executions"]==0
    assert m["training_use"]=="FORBIDDEN"
    assert m["model_evaluated"] is False
    assert m["promotion"]=="DO_NOT_PROMOTE"
    for case in CASES:
        assert m["code_sha256"][case.id]==sha256(case.code.encode()).hexdigest()
        assert case.reviewer_note


def test_new_audit_has_no_exact_previous_code_reuse():
    prior={c.code.strip() for c in previous_audit}
    prior.update(c["code"].strip() for c in original_benchmark())
    assert prior.isdisjoint({c.code.strip() for c in CASES})


def test_audit_is_read_only_workflow_and_separate_from_pr_tests():
    from pathlib import Path
    root=Path(__file__).resolve().parents[1]
    script=(root/".github/workflows/xss-v5-frozen-flow-audit.yml").read_text()
    assert "[audit-xss-flow-v5]" in script
    assert "workflow_dispatch" in script
    assert "kaggle kernels push" not in script
    assert "evaluation.fresh_xss_v5_flow_audit" in script
    assert "--output" in script
    assert "actions/upload-artifact" in script
