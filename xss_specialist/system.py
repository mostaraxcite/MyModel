"""Unified XSS specialist review pipeline.

Authority boundary:
- deterministic taint may establish a bounded local SAFE or a CANDIDATE;
- structural semantic/flow layers explain and prioritize only;
- live browser execution is the only path to confirmed XSS;
- non-execution never converts a static candidate/inconclusive path to SAFE.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from xss_specialist.evidence_pipeline import review_evidence
from xss_specialist.grounded_advisor import grounded_review
from xss_specialist.flow_relations import deterministic_relation
from xss_specialist.semantic_oracle import classify_defense, classify_sink, classify_source
from xss_specialist.taint import analyze


@dataclass(frozen=True)
class SpecialistDecision:
    verdict: str
    confirmed: bool
    confidence: float
    static_verdict: str
    requires_browser: bool
    confirmation_status: str
    structural: dict | None
    browser_evidence: dict | None
    limitations: list[str]
    evidence: dict | None = None
    model_assistance: dict | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _deterministic_structure(fields: dict) -> dict:
    required = ("source_expression", "sink_expression", "defense_expression", "relation")
    missing = [name for name in required if name not in fields]
    if missing:
        raise ValueError(f"missing structural fields: {missing}")
    relation = {"task": "FLOW_RELATION", **dict(fields["relation"])}
    return {
        "engine": "deterministic-structural-taxonomy-v1",
        "source": classify_source(str(fields["source_expression"])),
        "sink": classify_sink(str(fields["sink_expression"])),
        "defense": classify_defense(str(fields["defense_expression"])),
        "flow": deterministic_relation(relation),
        "final_judge": False,
        "confirmed": False,
    }


def _structural_review(fields: dict | None, advisor: Any | None) -> dict | None:
    if fields is None:
        return None
    if advisor is None:
        return _deterministic_structure(fields)
    return advisor.review_fields(
        source_expression=fields["source_expression"],
        sink_expression=fields["sink_expression"],
        defense_expression=fields["defense_expression"],
        relation=fields["relation"],
    )


def review(
    code: str,
    *,
    fields: dict | None = None,
    structural_advisor: Any | None = None,
    live_candidate: dict | None = None,
    enforcer: Any | None = None,
    finding_id: str = "XSS-REVIEW",
    trusted_modules: tuple[str, ...] = (),
    browser_timeout_ms: int = 4000,
    model_focus: dict | None = None,
) -> SpecialistDecision:
    """Review a code path and optionally confirm it against an explicitly scoped live target."""
    if live_candidate is not None and enforcer is None:
        raise ValueError("live_candidate requires an explicit authorized Enforcer")

    static = analyze(code, trusted_modules=trusted_modules)
    static_evidence = review_evidence(code, trusted_modules=trusted_modules)
    # Model focus affects presentation ONLY. All security facts and the final
    # verdict remain independent of its suggestions.
    model_assistance = (
        grounded_review(code, model_focus=model_focus, trusted_modules=trusted_modules)
        if model_focus is not None else None
    )
    structural = _structural_review(fields, structural_advisor)

    if static_evidence["decision"]["status"] == "SAFE":
        return SpecialistDecision(
            verdict="SAFE",
            confirmed=False,
            confidence=1.0,
            static_verdict="SAFE",
            requires_browser=False,
            confirmation_status="BOUNDED_STATIC_SAFE",
            structural=structural,
            browser_evidence=None,
            limitations=list(static.get("limitations", [])),
            evidence=static_evidence,
        model_assistance=model_assistance,
            model_assistance=model_assistance,
        )

    if live_candidate is None:
        return SpecialistDecision(
            verdict="POSSIBLE_XSS",
            confirmed=False,
            confidence=0.5 if static_evidence["decision"]["status"] == "CANDIDATE" else 0.25,
            static_verdict=static["verdict"],
            requires_browser=True,
            confirmation_status="BROWSER_NOT_RUN",
            structural=structural,
            browser_evidence=None,
            limitations=list(static.get("limitations", [])),
            evidence=static_evidence,
            model_assistance=model_assistance,
        )

    from live.pipeline import assess_candidate

    live = assess_candidate(
        dict(live_candidate),
        enforcer,
        fid=finding_id,
        timeout_ms=browser_timeout_ms,
    )
    finding = live["finding"]
    evidence = {
        "finding_id": finding.finding_id,
        "status": finding.status,
        "browser_result": finding.browser_result,
        "reproduction": finding.reproduction,
        "marker_ev": {
            key: live["marker_ev"].get(key)
            for key in (
                "requested_url", "final_url", "status", "reflected_html",
                "reflected_dom", "executed", "scope_blocked", "error",
            )
            if key in live["marker_ev"]
        },
        "execution_attempts": [
            {
                key: event.get(key)
                for key in (
                    "requested_url", "final_url", "status", "executed",
                    "raw_reflected", "probe_note", "marker", "scope_blocked", "error",
                )
                if key in event
            }
            for event in live["exec_evs"]
        ],
    }

    if finding.status == "CONFIRMED" and finding.browser_result == "executed":
        return SpecialistDecision(
            verdict="XSS",
            confirmed=True,
            confidence=0.99,
            static_verdict=static["verdict"],
            requires_browser=False,
            confirmation_status="CONFIRMED_BROWSER_EXECUTION",
            structural=structural,
            browser_evidence=evidence,
            limitations=list(static.get("limitations", [])),
            evidence=static_evidence,
            model_assistance=model_assistance,
        )

    return SpecialistDecision(
        verdict="POSSIBLE_XSS",
        confirmed=False,
        confidence=0.60 if finding.status == "LIKELY" else 0.30,
        static_verdict=static["verdict"],
        requires_browser=True,
        confirmation_status=f"UNCONFIRMED_{finding.status}",
        structural=structural,
        browser_evidence=evidence,
        limitations=list(static.get("limitations", [])),
        evidence=static_evidence,
    )
