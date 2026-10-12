"""Oracle-locked XSS evidence and narrow, non-authoritative model assistance.

The AST/taint analyzer creates ALL security facts. A language model may only
select existing evidence-path identifiers for presentation. Neither its output
nor free-form reasoning can add sources, sinks, defenses or confirmations.
No browser, networking, JavaScript execution, or model runtime is required.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from xss_specialist.evidence_pipeline import review_evidence

SCHEMA = "xss-oracle-locked-v1"
FOCUS_SCHEMA = "xss-path-focus-v1"
MODEL_ALLOWED_KEYS = frozenset({"schema_version", "snippet_sha256", "focus_path_ids"})
MAX_MODEL_FOCUS = 10

_RULE_PRIORITY = {"CANDIDATE": 0, "INCONCLUSIVE": 1, "BOUNDED_SAFE": 2}


def _grounded_explanation(path: dict) -> str:
    """Render only the deterministic evidence; never quote model explanations."""
    source = path["source"]
    flow = path["flow"]
    sink = path["sink"]
    defense = path["defense"]
    relation = flow["relation"]
    kind = sink["kind"]
    status = path["decision"]["status"]
    name = sink["expression"]
    observed = ", ".join(source["expressions"]) if source["expressions"] else "no tracked untrusted input"
    if status == "CANDIDATE":
        return (
            "Potential XSS: a tracked untrusted source (" + observed +
            ") reaches " + name + " through a connected local data flow. "
            "The destination can interpret content (" + kind +
            "), and the analyzer found no compatible protection on this path. "
            "Browser execution has not been demonstrated."
        )
    if relation == "UNKNOWN" or status == "INCONCLUSIVE":
        return (
            "Inconclusive: the analyzer cannot establish this complete data "
            "flow or its protection status for " + name + ". "
            "It must not be treated as either proven safe or confirmed XSS."
        )
    if kind == "TEXT_ONLY" and defense["status"] == "SAFE_OUTPUT_API":
        return (
            "Bounded-safe output path: " + name +
            " treats its input as text, rather than executing it as HTML "
            "or script. This does not establish whole-application safety."
        )
    if defense["status"] == "CONTEXTUAL_HTML_ENCODING":
        return (
            "Bounded-safe output path: percent-encoding the whole untrusted "
            "value prevents it from creating HTML markup in " + name +
            ". This does not imply JavaScript execution contexts or decoded "
            "output are safe."
        )
    if defense["status"] == "VERIFIED_CONTEXTUAL_SANITIZATION":
        return (
            "Bounded-safe output path: a trusted, audited sanitizer is "
            "compatible with this local HTML sink (" + name +
            "). Other paths and runtime conditions were not assessed."
        )
    if defense["status"] in {"VERIFIED_RELATIVE_URL_PREFIX", "VERIFIED_NAVIGATION_URL_PREFIX"}:
        return (
            "Bounded-safe navigation path: a statically fixed URL prefix prevents "
            "the input from forming a script-executing scheme at " + name +
            ". This does not establish remote-script, redirect, server-side or whole-application safety."
        )
    if relation == "DISCONNECTED":
        return (
            "Bounded-safe output path: the analyzer found no tracked "
            "untrusted input connected to " + name +
            ". Other inputs and routes may require separate analysis."
        )
    # The default is never a security claim stronger than the oracle.
    return "Only the bounded local path is described; broader behavior is not established."


def build_oracle_packet(code: str, *, trusted_modules: tuple[str, ...] = ()) -> dict:
    """Return immutable-evidence-shaped fields, derived solely from AST facts."""
    evidence = review_evidence(code, trusted_modules=trusted_modules)
    paths = []
    for i, record in enumerate(evidence["paths"], 1):
        paths.append({
            "path_id": "p" + str(i),
            "source": record["source"],
            "flow": record["flow"],
            "sink": record["sink"],
            "defense": record["defense"],
            "decision": record["decision"],
            "explanation": _grounded_explanation(record),
        })
    return {
        "schema_version": SCHEMA,
        "snippet_sha256": evidence["snippet_sha256"],
        "engine": evidence["engine"],
        "source": evidence["source"],
        "flow": evidence["flow"],
        "sink": evidence["sink"],
        "defense": evidence["defense"],
        "paths": paths,
        "decision": evidence["decision"],
        "limitations": evidence["limitations"],
        "model_has_final_authority": False,
        "browser_confirmed": False,
        "explanation_provenance": "deterministic_ast_oracle",
    }


def validate_model_focus(proposal: Any, packet: dict) -> dict:
    """Accept only references to existing path IDs; reject all model facts."""
    fallback = {"accepted": False, "focus_path_ids": [], "model_authority": False}
    if not isinstance(proposal, dict) or set(proposal) != MODEL_ALLOWED_KEYS:
        return {**fallback, "reason": "unsupported_model_schema"}
    if proposal["schema_version"] != FOCUS_SCHEMA:
        return {**fallback, "reason": "unsupported_schema_version"}
    if proposal["snippet_sha256"] != packet["snippet_sha256"]:
        return {**fallback, "reason": "snippet_hash_mismatch"}
    ids = proposal["focus_path_ids"]
    if not isinstance(ids, list) or len(ids) > MAX_MODEL_FOCUS or any(
        not isinstance(pid, str) for pid in ids
    ):
        return {**fallback, "reason": "invalid_path_id_list"}
    if len(ids) != len(set(ids)):
        return {**fallback, "reason": "duplicate_path_ids"}
    allowed = {p["path_id"] for p in packet["paths"]}
    if any(pid not in allowed for pid in ids):
        return {**fallback, "reason": "unsupported_path_id"}
    return {
        "accepted": True,
        "reason": "existing_path_ids_only",
        "focus_path_ids": ids,
        "model_authority": False,
    }


def grounded_review(code: str, *, model_focus: Any = None,
                    trusted_modules: tuple[str, ...] = ()) -> dict:
    """Present immutable oracle facts; allow focus ordering only when validated.

    The model focus is not a score, finding, sanitizer policy or verdict.
    Untrusted model prose and added fields are always rejected.
    """
    packet = build_oracle_packet(code, trusted_modules=trusted_modules)
    accepted = None if model_focus is None else validate_model_focus(model_focus, packet)
    # A focus suggestion must never push a suspected or unresolved security
    # path out of the visible priority list. Those are mandatory, even if
    # the model names only a safe sink or provides an empty selection.
    mandatory = [
        item["path_id"] for item in packet["paths"]
        if item["decision"]["status"] in ("CANDIDATE", "INCONCLUSIVE")
    ]
    if accepted and accepted["accepted"]:
        desired = mandatory + accepted["focus_path_ids"]
        focus_ids = list(dict.fromkeys(desired))
        source = "validated_model_selection_with_mandatory_paths"
    else:
        focus_ids = [
            item["path_id"] for item in sorted(
                packet["paths"],
                key=lambda p: (_RULE_PRIORITY[p["decision"]["status"]], p["path_id"]),
            )
        ]
        source = "deterministic_priority"
    packet["presentation"] = {
        "focus_path_ids": focus_ids,
        "focus_source": source,
        "explanations_from_model": False,
        "mandatory_security_path_ids": mandatory,
    }
    if accepted is not None:
        packet["model_advisory"] = accepted
    return packet


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="Local JavaScript file, not a URL")
    parser.add_argument("--model-focus-json", type=Path,
                        help="Untrusted path-ID selection JSON; never executes model output")
    parser.add_argument("--trusted-module", action="append", default=[],
                        help="Explicitly audited sanitizer import name")
    args = parser.parse_args()
    candidate = None
    if args.model_focus_json is not None:
        candidate = json.loads(args.model_focus_json.read_text(encoding="utf-8"))
    report = grounded_review(
        args.file.read_text(encoding="utf-8"),
        model_focus=candidate,
        trusted_modules=tuple(args.trusted_module),
    )
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
