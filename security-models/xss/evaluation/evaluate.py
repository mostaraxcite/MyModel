"""Evaluate an adapter from the registry against the locked Hard Test v4."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from sklearn.metrics import classification_report, confusion_matrix

from xss_specialist.adapter_registry import load_classifier


LABELS = ["SAFE", "POSSIBLE_XSS", "XSS"]


def error_rates(matrix: list[list[int]]) -> dict:
    total = sum(sum(row) for row in matrix)
    result = {}
    for index, label in enumerate(LABELS):
        tp = matrix[index][index]
        fp = sum(row[index] for row in matrix) - tp
        fn = sum(matrix[index]) - tp
        tn = total - tp - fp - fn
        result[label] = {
            "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
            "false_negative_rate": fn / (fn + tp) if fn + tp else 0.0,
        }
    return result


def measure_latency(classify, rows: list[dict]) -> dict:
    sample = rows[: min(64, len(rows))]
    start = time.perf_counter()
    classify([row["code"] for row in sample], truncation=True)
    elapsed = time.perf_counter() - start
    return {"avg_ms_per_snippet": round((elapsed / len(sample)) * 1000, 3)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", default="v0.4-baseline")
    parser.add_argument("--data", type=Path, default=Path("security-models/xss/data/hard_test.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("security-models/xss/evaluation/v05_hard_metrics.json"))
    parser.add_argument("--promotion-threshold", type=float, default=0.90)
    parser.add_argument("--latency", action="store_true", help="Measure inference latency on a 64-snippet sample.")
    args = parser.parse_args()

    rows = [json.loads(line) for line in args.data.read_text(encoding="utf-8").splitlines() if line]

    classify, spec = load_classifier(args.adapter)
    scores = classify([row["code"] for row in rows], batch_size=32, truncation=True)
    y_true = [row["label"] for row in rows]
    y_pred = [max(items, key=lambda item: item["score"])["label"] for items in scores]
    matrix = confusion_matrix(y_true, y_pred, labels=LABELS).tolist()
    report = classification_report(y_true, y_pred, labels=LABELS, output_dict=True, zero_division=0)
    macro_f1 = report["macro avg"]["f1-score"]

    latency = measure_latency(classify, rows) if args.latency else None
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({
        "adapter": spec.name,
        "adapter_kind": spec.kind,
        "base_model": spec.base_model,
        "dataset": args.data.name,
        "count": len(rows),
        "classification_report": report,
        "false_rates": error_rates(matrix),
        "confusion_matrix": {"labels": LABELS, "matrix": matrix},
        "promotion": {
            "threshold_macro_f1": args.promotion_threshold,
            "observed_macro_f1": macro_f1,
            "passed": macro_f1 >= args.promotion_threshold,
        },
        "latency": latency,
    }, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "adapter": spec.name,
        "macro_f1": macro_f1,
        "passed": macro_f1 >= args.promotion_threshold,
        "latency_ms": latency["avg_ms_per_snippet"] if latency else None,
    }, indent=2))


if __name__ == "__main__":
    main()
