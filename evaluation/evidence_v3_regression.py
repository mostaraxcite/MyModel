"""CPU-only bounded XSS decision regression against the *exposed* 48 cases.

This is diagnostic, not a fresh held-out generalization benchmark. The
purpose is to measure the abstention/alert split of the new static gate
without claiming browser execution or trained model quality.
"""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

from evaluation.spark_xss_heldout import cases
from xss_specialist.evidence_pipeline import review_evidence

CLASSES = ("CANDIDATE", "SAFE", "INCONCLUSIVE")


def evaluate() -> dict:
    rows = cases()
    confusion = {
        "safe": Counter({label: 0 for label in CLASSES}),
        "vulnerable": Counter({label: 0 for label in CLASSES}),
    }
    details = []
    for item in rows:
        result = review_evidence(item["code"])
        status = result["decision"]["status"]
        if status not in CLASSES:
            raise AssertionError("Unexpected static gate output")
        confusion[item["label"]][status] += 1
        details.append({
            "id": item["id"],
            "static_label": item["label"],
            "gate": status,
            "limitations": result["limitations"],
            "confirmed": result["decision"]["confirmed"],
        })
    true_positive_count = sum(confusion["vulnerable"].values())
    benign_count = sum(confusion["safe"].values())
    if true_positive_count == 0 or benign_count == 0:
        raise ValueError("Benchmark needs both classes")
    return {
        "suite": "exposed_48_synthetic_static_regression",
        "candidate_alerts_from_unsafe": confusion["vulnerable"]["CANDIDATE"],
        "candidate_alerts_from_safe": confusion["safe"]["CANDIDATE"],
        "missed_with_static_safe": confusion["vulnerable"]["SAFE"],
        "abstentions_on_unsafe": confusion["vulnerable"]["INCONCLUSIVE"],
        "abstentions_on_safe": confusion["safe"]["INCONCLUSIVE"],
        "candidate_recall": confusion["vulnerable"]["CANDIDATE"] / true_positive_count,
        "candidate_fpr": confusion["safe"]["CANDIDATE"] / benign_count,
        "decision_coverage": (
            len(rows) - confusion["safe"]["INCONCLUSIVE"] -
            confusion["vulnerable"]["INCONCLUSIVE"]
        ) / len(rows),
        "confusion": {gold: dict(counts) for gold, counts in confusion.items()},
        "results": details,
        "confirmed_via_browser": 0,
        "promotion": "DO_NOT_PROMOTE",
    }


def main() -> None:
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    report=evaluate()
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k!="results"},indent=2))


if __name__ == "__main__":
    main()
