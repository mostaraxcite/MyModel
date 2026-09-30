"""Evaluate an adapter on the locked external_test_v5 (binary only)."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from sklearn.metrics import classification_report, confusion_matrix

from xss_specialist.adapter_registry import load_classifier


LABELS = ["SAFE", "XSS"]


def validate_rows(rows: list[dict]) -> list[dict]:
    seen: set[str] = set()
    for row in rows:
        code_hash = hashlib.sha256(row["code"].encode()).hexdigest()
        recorded = row.get("provenance", {}).get("content_sha256")
        if recorded != code_hash:
            raise ValueError(f"content hash mismatch for external row {row.get('id')}")
        if code_hash in seen:
            raise ValueError(
                "external_test_v5 contains duplicate classifier inputs; regenerate with "
                "import_official_fixtures.py before evaluation"
            )
        seen.add(code_hash)
        if row["label"] not in LABELS:
            raise ValueError(f"unsupported external label: {row['label']}")
    return rows


def prediction_rows(rows: list[dict], scores: list[list[dict]]) -> list[dict]:
    output = []
    for row, items in zip(rows, scores):
        best = max(items, key=lambda item: item["score"])
        truth, predicted = row["label"], best["label"]
        provenance = row["provenance"]
        output.append({
            "id": row["id"],
            "project": row.get("project", provenance.get("repository", "")),
            "path": provenance.get("path", ""),
            "line": provenance.get("line", 0),
            "truth": truth,
            "prediction": predicted,
            "confidence": float(best["score"]),
            "error": None if truth == predicted else f"{truth}_AS_{predicted}",
            "source_url": provenance.get("source_url", ""),
            "partition": provenance.get("partition", "external_test_v5_locked"),
        })
    return output


def project_breakdown(predictions: list[dict]) -> dict:
    grouped = defaultdict(list)
    for row in predictions:
        grouped[row["project"]].append(row)
    result = {}
    for project, rows in sorted(grouped.items()):
        result[project] = {
            "count": len(rows),
            "correct": sum(row["truth"] == row["prediction"] for row in rows),
            "abstained": sum(row["prediction"] == "POSSIBLE_XSS" for row in rows),
            "errors": dict(Counter(row["error"] for row in rows if row["error"])),
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", default="v0.4-baseline")
    parser.add_argument("--data", type=Path, default=Path("security-models/xss/data/external_test_v5.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("security-models/xss/evaluation/v05_external_v5_metrics.json"))
    parser.add_argument("--predictions", type=Path, default=Path("security-models/xss/evaluation/v05_external_v5_predictions.jsonl"))
    args = parser.parse_args()

    rows = validate_rows([
        json.loads(line)
        for line in args.data.read_text(encoding="utf-8").splitlines()
        if line
    ])
    classify, spec = load_classifier(args.adapter)
    scores = classify([row["code"] for row in rows], batch_size=32, truncation=True)
    predictions = prediction_rows(rows, scores)
    raw_predictions = [row["prediction"] for row in predictions]
    decided = [(row["label"], prediction) for row, prediction in zip(rows, raw_predictions) if prediction in LABELS]
    y_true, y_pred = zip(*decided) if decided else ([], [])
    matrix = confusion_matrix(y_true, y_pred, labels=LABELS)
    report = classification_report(y_true, y_pred, labels=LABELS, output_dict=True, zero_division=0)
    safe_total = sum(row["label"] == "SAFE" for row in rows)
    xss_total = sum(row["label"] == "XSS" for row in rows)
    false_positive = sum(row["label"] == "SAFE" and pred == "XSS" for row, pred in zip(rows, raw_predictions))
    false_negative = sum(row["label"] == "XSS" and pred == "SAFE" for row, pred in zip(rows, raw_predictions))
    result = {
        "adapter": spec.name,
        "adapter_kind": spec.kind,
        "base_model": spec.base_model,
        "dataset": "external_test_v5_locked",
        "count": len(rows),
        "coverage": len(decided) / len(rows) if rows else 0.0,
        "abstention_rate": raw_predictions.count("POSSIBLE_XSS") / len(rows) if rows else 0.0,
        "decided_macro_f1": report["macro avg"]["f1-score"],
        "per_label": {label: report[label] for label in LABELS},
        "xss_false_positive_rate_all": false_positive / safe_total if safe_total else 0.0,
        "xss_false_negative_rate_all": false_negative / xss_total if xss_total else 0.0,
        "confusion_decided": {"labels": LABELS, "matrix": matrix.tolist()},
        "by_project": project_breakdown(predictions),
        "promotion": {
            "passed": (
                report["macro avg"]["f1-score"] >= 0.90
                and len(decided) / len(rows) >= 0.90
                and false_positive / safe_total <= 0.08
                and false_negative / xss_total <= 0.08
            ),
            "requirements": {"macro_f1": 0.90, "coverage": 0.90, "max_fpr": 0.08, "max_fnr": 0.08},
        },
    }
    args.predictions.parent.mkdir(parents=True, exist_ok=True)
    args.predictions.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in predictions), encoding="utf-8"
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "adapter": spec.name,
        "coverage": result["coverage"],
        "decided_macro_f1": result["decided_macro_f1"],
        "passed": result["promotion"]["passed"],
    }, indent=2))


if __name__ == "__main__":
    main()