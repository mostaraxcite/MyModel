"""Evaluate the integrated XSS semantic+flow advisor on pinned real upstream code.

No locked Hard/External benchmark is read. Cases are built at runtime from:
- google/firing-range: intentionally vulnerable DOM source/sink fixtures.
- cure53/DOMPurify: official sanitizer demos.

The model remains advisory; this evaluator scores structural labels only.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from sklearn.metrics import accuracy_score, f1_score

from xss_specialist.dual_branch import LABEL_SPACES
from xss_specialist.dual_branch_review import IntegratedAdvisor


FIRING_SOURCES = [
    "src/tests/dom/data/sources/document/referrer.tmpl",
    "src/tests/dom/data/sources/localStorage/property.tmpl",
    "src/tests/dom/data/sources/sessionStorage/property.tmpl",
    "src/tests/dom/data/sources/window/name.tmpl",
]
FIRING_SINKS = [
    ("src/tests/dom/data/sinks/innerHtml.tmpl", "DANGEROUS_HTML", "div.innerHTML"),
    ("src/tests/dom/data/sinks/documentWrite.tmpl", "DANGEROUS_HTML", "document.write"),
    ("src/tests/dom/data/sinks/eval.tmpl", "DANGEROUS_JS", "eval"),
]
DOMPURIFY_DEMOS = [
    "demos/basic-demo.html",
    "demos/hooks-demo.html",
    "demos/config-demo.html",
    "demos/trusted-types-demo.html",
    "demos/hooks-target-blank-demo.html",
]


def script_block(html: str) -> str:
    blocks = re.findall(r"<script(?:\s[^>]*)?>(.*?)</script>", html, re.I | re.S)
    useful = [b for b in blocks if "DOMPurify.sanitize" in b and "innerHTML" in b]
    if not useful:
        raise ValueError("DOMPurify demo missing sanitize->innerHTML script block")
    return max(useful, key=len).strip()


def build_cases(firing: Path, dompurify: Path) -> list[dict]:
    cases = []
    for source_rel in FIRING_SOURCES:
        source = (firing / source_rel).read_text(encoding="utf-8", errors="replace").strip()
        for sink_rel, sink_label, sink_expression in FIRING_SINKS:
            sink = (firing / sink_rel).read_text(encoding="utf-8", errors="replace").strip()
            code = source + "\n\n" + sink
            cases.append({
                "id": f"firing:{Path(source_rel).stem}:{Path(sink_rel).stem}",
                "family": "firing-range",
                "code": code,
                "relation": {
                    "source_expression": "payload",
                    "sink_expression": sink_expression,
                    "flow_excerpt": code,
                },
                "expected": {
                    "source": "BROWSER",
                    "sink": sink_label,
                    "defense": "NONE",
                    "flow": "CONNECTED",
                },
            })

    for rel in DOMPURIFY_DEMOS:
        html = (dompurify / rel).read_text(encoding="utf-8", errors="replace")
        code = script_block(html)
        if "const dirty" not in code and "let dirty" not in code:
            continue
        cases.append({
            "id": f"dompurify:{Path(rel).name}",
            "family": "dompurify-demo",
            "code": code,
            "relation": {
                "source_expression": "dirty",
                "sink_expression": "clean",
                "flow_excerpt": code,
            },
            "expected": {
                "source": "NONE",
                "sink": "DANGEROUS_HTML",
                "defense": "SANITIZATION",
                # Under the bounded flow policy DOMPurify.sanitize is an opaque call.
                "flow": "UNKNOWN",
            },
        })
    return cases


def task_metrics(rows: list[dict], task: str) -> dict:
    labels = LABEL_SPACES[task]
    index = {label: i for i, label in enumerate(labels)}
    truth = [index[row["expected"][task]] for row in rows]
    pred = [index[row["predicted"][task]] for row in rows]
    present = sorted(set(truth))
    return {
        "macro_f1_present": float(
            f1_score(truth, pred, labels=present, average="macro", zero_division=0)
        ),
        "accuracy": float(accuracy_score(truth, pred)),
        "present_labels": [labels[i] for i in present],
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--semantic-model-dir", type=Path, required=True)
    p.add_argument("--flow-model-dir", type=Path, required=True)
    p.add_argument("--firing-range-root", type=Path, required=True)
    p.add_argument("--dompurify-root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()

    advisor = IntegratedAdvisor(args.semantic_model_dir, args.flow_model_dir)
    cases = build_cases(args.firing_range_root, args.dompurify_root)
    if len(cases) < 15:
        raise SystemExit(f"insufficient real integration cases: {len(cases)}")

    scored = []
    for case in cases:
        sem = advisor.semantic(case["code"])
        flow = advisor.flow(case["relation"])
        predicted = {
            "source": sem["source"]["label"],
            "sink": sem["sink"]["label"],
            "defense": sem["defense"]["label"],
            "flow": flow["label"],
        }
        scored.append({
            "id": case["id"],
            "family": case["family"],
            "expected": case["expected"],
            "predicted": predicted,
            "confidence": {
                "source": sem["source"]["confidence"],
                "sink": sem["sink"]["confidence"],
                "defense": sem["defense"]["confidence"],
                "flow": flow["confidence"],
            },
            "tuple_correct": predicted == case["expected"],
        })

    metrics = {
        task: task_metrics(scored, task)
        for task in ("source", "sink", "defense", "flow")
    }
    tuple_accuracy = sum(r["tuple_correct"] for r in scored) / len(scored)

    # Development-only integration gate. It intentionally does not promote.
    passed = bool(
        metrics["source"]["macro_f1_present"] >= 0.75
        and metrics["sink"]["macro_f1_present"] >= 0.80
        and metrics["defense"]["macro_f1_present"] >= 0.75
        and metrics["flow"]["macro_f1_present"] >= 0.80
        and tuple_accuracy >= 0.65
    )

    report = {
        "schema": "xss-integrated-real-v1",
        "case_count": len(scored),
        "families": sorted({r["family"] for r in scored}),
        "metrics": metrics,
        "tuple_accuracy": tuple_accuracy,
        "research_gate_passed": passed,
        "promotion_allowed": False,
        "locked_hard_or_external_used": False,
        "final_judge": False,
        "cases": scored,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
