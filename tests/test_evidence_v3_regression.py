"""Regression reports must retain abstentions and never claim confirmations."""
from evaluation.evidence_v3_regression import evaluate


def test_static_exposed_suite_reports_48_complete_three_way_results():
    r=evaluate()
    assert len(r["results"])==48
    assert set(r["confusion"])=={"safe","vulnerable"}
    assert sum(r["confusion"]["safe"].values())==24
    assert sum(r["confusion"]["vulnerable"].values())==24
    assert r["confirmed_via_browser"]==0
    assert r["promotion"]=="DO_NOT_PROMOTE"
    assert 0<=r["candidate_fpr"]<=1
    assert 0<=r["candidate_recall"]<=1
    assert all(x["confirmed"] is False for x in r["results"])
