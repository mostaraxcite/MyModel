"""Evidence-first XSS review over the bounded JavaScript taint analyzer.

Never treats a language-model answer, keyword match, or unverified sanitizer
name as proof of source-to-sink flow. This module is pure local code review.
No network requests, payload delivery, or browser execution.
"""
from __future__ import annotations

import hashlib

from xss_specialist.taint import analyze as analyze_taint

SINK_KINDS = {
    "html": "HTML_PARSER",
    "javascript": "SCRIPT_EXECUTION",
    "text": "TEXT_ONLY",
}
REQUIRED_FIELDS = (
    "source", "flow", "sink", "defense", "decision", "limitations"
)


def _sink_evidence(item: dict) -> dict:
    """Make one evidence record for one AST-identified output operation."""
    sources = sorted(set(item.get("sources") or []))
    trace = list(item.get("flow") or [])
    context = item.get("context")
    kind = SINK_KINDS.get(context, "UNKNOWN")
    if item.get("verdict") == "INCONCLUSIVE":
        relation = "UNKNOWN"
    elif sources:
        relation = "CONNECTED"
    else:
        relation = "DISCONNECTED"
    if kind == "TEXT_ONLY":
        protection = "SAFE_OUTPUT_API"
    elif item.get("sanitizer_compatible") and item.get("sanitizer"):
        protection = "VERIFIED_CONTEXTUAL_SANITIZATION"
    elif relation == "CONNECTED" and kind in ("HTML_PARSER", "SCRIPT_EXECUTION"):
        protection = "NONE"
    elif relation == "UNKNOWN":
        protection = "UNKNOWN"
    else:
        protection = "NOT_REQUIRED_FOR_THIS_FLOW"
    rule = ("SAFE_TEXT_OUTPUT" if kind == "TEXT_ONLY" else
            "SANITIZED_HTML" if protection == "VERIFIED_CONTEXTUAL_SANITIZATION" else
            "UNPROTECTED_CONNECTED_SINK" if relation == "CONNECTED" and protection == "NONE" else
            "DISCONNECTED" if relation == "DISCONNECTED" else
            "UNRESOLVED")
    return {
        "source": {
            "status": "OBSERVED" if sources else
                      "UNKNOWN" if relation == "UNKNOWN" else "NONE_ON_THIS_PATH",
            "expressions": sources,
        },
        "flow": {
            "relation": relation,
            "trace": trace,
            "basis": "bounded_ast_value_propagation",
        },
        "sink": {
            "expression": item.get("sink", ""),
            "line": item.get("line"),
            "execution_context": context or "unknown",
            "kind": kind,
        },
        "defense": {
            "status": protection,
            "sanitizer_identity": item.get("sanitizer"),
            "context_compatible": bool(item.get("sanitizer_compatible")),
        },
        "decision": {
            "rule": rule,
            "status": "CANDIDATE" if rule == "UNPROTECTED_CONNECTED_SINK" else
                      "INCONCLUSIVE" if relation == "UNKNOWN" else "BOUNDED_SAFE",
            "confirmed": False,
        },
    }


def review_evidence(code: str, *, trusted_modules: tuple[str, ...] = ()) -> dict:
    """Ground all facts in the actual syntax tree and tracked values.

    CANDIDATE means a reviewable static path; NOT browser-confirmed XSS.
    SAFE means only the reviewed local paths are bounded-safe. Unknown
    control flow is never silently upgraded to safe.
    """
    if not isinstance(code, str):
        raise TypeError("JavaScript source text must be a string")
    static = analyze_taint(code, trusted_modules=trusted_modules)
    records = [_sink_evidence(s) for s in static["sinks"]]
    limitations = list(static["limitations"])
    candidate = any(r["decision"]["status"] == "CANDIDATE" for r in records)
    # The taint engine is the authoritative static gate, not the SLM's text.
    if candidate and static["verdict"] == "CANDIDATE":
        decision, rule = "CANDIDATE", "TRACKED_UNPROTECTED_SOURCE_TO_SINK"
    elif (
        static["verdict"] == "SAFE"
        and records
        and not limitations
        and all(r["decision"]["status"] == "BOUNDED_SAFE" for r in records)
    ):
        decision, rule = "SAFE", "BOUNDED_STATIC_PATH_SAFE"
    else:
        decision, rule = "INCONCLUSIVE", "MISSING_OR_UNRESOLVED_EVIDENCE"
    digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
    return {
        "engine": "xss-evidence-first-v1",
        "snippet_sha256": digest,
        "language": "javascript",
        "source": {
            "observed": list(static.get("observed_sources", [])),
            "status": "OBSERVED" if static.get("observed_sources") else
                      "UNKNOWN" if limitations else "NOT_OBSERVED",
        },
        "flow": {"per_sink": [r["flow"] for r in records]},
        "sink": {"per_sink": [r["sink"] for r in records]},
        "defense": {"per_sink": [r["defense"] for r in records]},
        "paths": records,
        "decision": {
            "status": decision,
            "rule": rule,
            "confirmed": False,
            "requires_browser_confirmation": decision != "SAFE",
            "scope": "bounded local JavaScript paths, not whole-site security",
        },
        "limitations": limitations + (
            ["No supported output sink in supplied code"]
            if not records and not limitations else []
        ),
        "source_static_verdict": static["verdict"],
        "model_has_final_authority": False,
    }


def validate_advisory(candidate: dict, evidence: dict) -> dict:
    """Reject model assertions not matched to deterministic observed evidence.

    The advisor may suggest priorities/reasoning but NEVER overrides the
    static verdict or browser confirmation. Proof is not inferred from text.
    """
    if not isinstance(candidate, dict):
        return {"accepted": False, "reason": "advisory_not_object",
                "decision": evidence["decision"]}
    if candidate.get("snippet_sha256") != evidence.get("snippet_sha256"):
        return {"accepted": False, "reason": "snippet_hash_mismatch",
                "decision": evidence["decision"]}
    if candidate.get("confirmed") is True or candidate.get("verdict") in {"XSS", "CONFIRMED"}:
        return {"accepted": False, "reason": "unverified_confirmation",
                "decision": evidence["decision"]}
    for key in ("source", "flow", "sink", "defense", "limitations"):
        if candidate.get(key) != evidence.get(key):
            return {"accepted": False, "reason": "unsupported_" + key,
                    "decision": evidence["decision"]}
    # Evidence-only LoRA does not predict a verdict. Legacy proposals with
    # a verdict are accepted only when they exactly match the deterministic gate.
    if "decision" in candidate and candidate["decision"] != evidence["decision"]:
        return {"accepted": False, "reason": "model_decision_disagrees",
                "decision": evidence["decision"]}
    return {
        "accepted": True, "reason": "evidence_match_only",
        "decision": evidence["decision"], "confirmed": False,
    }
