"""Router behaviour tests for the v0.5 hybrid pipeline."""
from __future__ import annotations

from xss_specialist.router import FastDecision, SecurityRouter


def test_high_confidence_safe_does_not_call_triage():
    called = []
    router = SecurityRouter(
        lambda _: FastDecision("SAFE", 0.97),
        lambda _: called.append(True) or "",
    )
    result = router.predict("node.textContent = input")
    assert result.route == "encoder"
    assert result.verdict == "SAFE"
    assert result.requires_oracle is False
    assert not called


def test_uncertain_xss_requires_browser_confirmation():
    router = SecurityRouter(
        lambda _: FastDecision("POSSIBLE_XSS", 0.61),
        lambda _: "Classification: XSS\nSource: input\nSink: innerHTML",
    )
    result = router.predict("helper(input)")
    assert result.route == "browser_required"
    assert result.verdict == "XSS"
    assert result.requires_oracle is True


def test_unparseable_triage_output_abstains():
    router = SecurityRouter(
        lambda _: FastDecision("XSS", 0.5),
        lambda _: "insufficient evidence",
    )
    result = router.predict("unknown()")
    assert result.verdict == "POSSIBLE_XSS"
    assert result.route == "abstain"
    assert result.requires_oracle is True


def test_high_confidence_xss_requires_browser_confirmation():
    router = SecurityRouter(
        lambda _: FastDecision("XSS", 0.99),
        lambda _: "",
    )
    result = router.predict("element.innerHTML = input")
    assert result.route == "browser_required"
    assert result.requires_oracle is True
    assert result.escalation_reason == "xss_needs_browser_confirmation"


def test_low_confidence_xss_can_abstain():
    router = SecurityRouter(
        lambda _: FastDecision("XSS", 0.70),
        lambda _: "Classification: POSSIBLE_XSS",
    )
    result = router.predict("foo()")
    assert result.route == "abstain"
    assert result.escalation_reason == "low_confidence"
    assert result.verdict == "POSSIBLE_XSS"
    assert result.requires_oracle is True


def test_safe_below_threshold_uses_static_heuristic():
    router = SecurityRouter(
        lambda _: FastDecision("SAFE", 0.50),
        lambda _: "Classification: SAFE",
    )
    result = router.predict("y = 1")
    assert result.route == "heuristic"
    assert result.verdict == "SAFE"
    assert result.requires_oracle is False
