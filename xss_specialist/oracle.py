"""Deterministic XSS oracle.

Pure-Python, regex-based detector used as a fallback when the ML classifier is
uncertain. The oracle never mutates state and produces the same verdict for the
same input. It is intentionally conservative: it only fires XSS or SAFE when
the pattern is unambiguous, and returns None (abstain) otherwise so the caller
can defer to the ML model.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


# (sink regex, source regex) -> XSS when both match. The sink regex looks for
# dangerous DOM/JavaScript sinks; the source regex looks for tainted data that
# could be controlled by an attacker.
SINK_SOURCE_RULES: tuple[tuple[re.Pattern[str], re.Pattern[str]], ...] = (
    (
        re.compile(r"\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln)\b"),
        re.compile(r"(location\.|document\.|window\.|parent\.|top\.|self\.|frames\[|formData|querySelector|\.search|\.hash|\.params|req\.|req\.body|req\.query|req\.params|URLSearchParams|location\.search|location\.hash)",
                  re.IGNORECASE),
    ),
    (
        re.compile(r"\b(eval|Function)\s*\("),
        re.compile(r"(\+|`\$\{|location\.|document\.|window\.|req\.|req\.body|req\.query|req\.params|location\.search|location\.hash|\.value\b)",
                  re.IGNORECASE),
    ),
    (
        re.compile(r"\.(src|href|action)\s*="),
        re.compile(r"(location\.|document\.|window\.|req\.|req\.body|req\.query|req\.params|location\.search|location\.hash|URLSearchParams)",
                  re.IGNORECASE),
    ),
    (
        re.compile(r"setAttribute\s*\(\s*['\"](on[a-z]+|src|href|action|data)['\"]"),
        re.compile(r".{0,200}", re.IGNORECASE | re.DOTALL),  # any source counts for setAttribute on event handlers
    ),
    (
        re.compile(r"\breplaceWith\b|\binsertAdjacentElement\b"),
        re.compile(r"(location\.|document\.|window\.|req\.|formData|querySelector|location\.search|location\.hash)",
                  re.IGNORECASE),
    ),
)


# Hard SAFE patterns: when these alone describe the code, we treat it as SAFE
# without consulting the ML model. Conservative — only fires when the entire
# code is a benign shape we have seen many times.
SAFE_ONLY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\s*node\.textContent\s*=\s*[^;\n]+;?\s*$", re.IGNORECASE),
    re.compile(r"^\s*\w+\.textContent\s*=\s*[^;\n]+;?\s*$", re.IGNORECASE),
    re.compile(r"^\s*element\.setAttribute\s*\(\s*['\"](class|id|aria-[a-z]+)['\"]", re.IGNORECASE),
)


@dataclass(frozen=True)
class OracleVerdict:
    label: str  # "SAFE", "XSS", or "POSSIBLE_XSS" (abstain)
    rule: str | None  # which rule fired
    confidence: float  # 0.0 for abstain, 1.0 for hard rules


def analyze(code: str) -> OracleVerdict:
    if not code or not code.strip():
        return OracleVerdict("SAFE", "empty", 0.6)

    for pattern in SAFE_ONLY_PATTERNS:
        if pattern.search(code):
            return OracleVerdict("SAFE", "safe_pattern", 0.9)

    for sink, source in SINK_SOURCE_RULES:
        if sink.search(code) and source.search(code):
            return OracleVerdict("XSS", "sink_and_source", 0.95)

    return OracleVerdict("POSSIBLE_XSS", None, 0.0)


def explain(code: str) -> list[str]:
    """Return human-readable reasons for the verdict."""
    reasons: list[str] = []
    for sink, source in SINK_SOURCE_RULES:
        if sink.search(code) and source.search(code):
            reasons.append(f"matched rule: sink={sink.pattern!r} + tainted source")
    if not reasons:
        reasons.append("no rule fired; deferred to ML")
    return reasons