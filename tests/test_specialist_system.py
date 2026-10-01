import pytest

from live.scope import Enforcer, Scope
from xss_specialist.system import review


def test_static_safe_is_bounded_and_never_confirmed():
    result = review("box.textContent = location.hash;")
    assert result.verdict == "SAFE"
    assert result.confirmed is False
    assert result.confirmation_status == "BOUNDED_STATIC_SAFE"
    assert result.requires_browser is False


def test_static_candidate_stays_possible_without_browser():
    result = review("box.innerHTML = location.hash;")
    assert result.static_verdict == "CANDIDATE"
    assert result.verdict == "POSSIBLE_XSS"
    assert result.confirmed is False
    assert result.requires_browser is True
    assert result.confirmation_status == "BROWSER_NOT_RUN"


def test_inconclusive_never_becomes_safe_without_browser():
    result = review("box.innerHTML = unknown();")
    assert result.static_verdict == "INCONCLUSIVE"
    assert result.verdict == "POSSIBLE_XSS"
    assert result.confirmed is False
    assert result.requires_browser is True


def test_live_candidate_requires_explicit_scope():
    with pytest.raises(ValueError, match="explicit authorized Enforcer"):
        review(
            "box.innerHTML = location.hash;",
            live_candidate={"url": "http://127.0.0.1:1/echo", "param": "q"},
        )


def test_deterministic_structural_review_is_explanatory_only():
    fields = {
        "source_expression": "req.query.q",
        "sink_expression": "res.send(req.query.q)",
        "defense_expression": "[NO_DEFENSE]",
        "relation": {
            "source_expression": "req.query.q",
            "sink_expression": "res.send",
            "flow_excerpt": "res.send(req.query.q)",
        },
    }
    result = review("res.send(req.query.q);", fields=fields)
    assert result.structural["source"]["label"] == "SERVER"
    assert result.structural["sink"]["label"] == "DANGEROUS_HTML"
    assert result.structural["flow"]["relation"] == "CONNECTED"
    assert result.confirmed is False
    assert result.verdict == "POSSIBLE_XSS"
