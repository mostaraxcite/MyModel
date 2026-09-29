"""Two-stage router: compact encoder first, oracle only when uncertain."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class FastDecision:
    verdict: str
    confidence: float


@dataclass(frozen=True)
class RoutedDecision:
    verdict: str
    confidence: float
    route: str
    requires_oracle: bool
    specialist_output: str | None = None
    escalation_reason: str | None = None


class SecurityRouter:
    """Routes a code snippet through the encoder+adapter.

    The encoder+adapter is treated as the fast path. Anything below
    `direct_threshold` is escalated. The v0.5 hybrid path escalates to a
    deterministic oracle (regex rules) instead of a generative LoRA. The
    legacy generative path remains supported by passing a different
    `specialist_predict`.

    Parameters
    ----------
    fast_predict:
        Callable returning a FastDecision for a code snippet.
    specialist_predict:
        Callable returning a string verdict for a code snippet. In v0.5 the
        default is the deterministic oracle.
    direct_threshold:
        Minimum confidence at which the fast path's SAFE verdict is accepted
        without escalation.
    xss_threshold:
        Minimum confidence at which the fast path's XSS verdict is accepted
        directly. XSS verdicts trigger oracle confirmation (but the ML verdict
        is binding for routing).
    """

    def __init__(
        self,
        fast_predict: Callable[[str], FastDecision],
        specialist_predict: Callable[[str], str],
        direct_threshold: float = 0.90,
        xss_threshold: float = 0.85,
    ):
        self.fast_predict = fast_predict
        self.specialist_predict = specialist_predict
        self.direct_threshold = direct_threshold
        self.xss_threshold = xss_threshold

    def predict(self, code: str) -> RoutedDecision:
        fast = self.fast_predict(code)
        verdict, confidence = fast.verdict, fast.confidence

        if verdict == "SAFE" and confidence >= self.direct_threshold:
            return RoutedDecision(
                verdict=verdict,
                confidence=confidence,
                route="encoder",
                requires_oracle=False,
            )

        if verdict == "XSS" and confidence >= self.xss_threshold:
            return RoutedDecision(
                verdict=verdict,
                confidence=confidence,
                route="encoder",
                requires_oracle=True,
                escalation_reason="xss_needs_oracle_confirmation",
            )

        analysis = self.specialist_predict(code)
        parsed = self._parse_verdict(analysis)
        return RoutedDecision(
            verdict=parsed,
            confidence=confidence,
            route="oracle" if parsed != "POSSIBLE_XSS" else "abstain",
            requires_oracle=parsed != "SAFE",
            specialist_output=analysis,
            escalation_reason="low_confidence",
        )

    @staticmethod
    def _parse_verdict(text: str) -> str:
        normalized = text.upper()
        for label in ("POSSIBLE_XSS", "XSS", "SAFE"):
            if f"CLASSIFICATION: {label}" in normalized or f"VERDICT: {label}" in normalized:
                return label
        return "POSSIBLE_XSS"