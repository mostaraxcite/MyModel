"""Evaluate XSS-SLM v0.1 without exposing test labels to training."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from sklearn.metrics import classification_report, confusion_matrix
from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline


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


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", type=Path, default=root / "model")
    parser.add_argument("--data", type=Path, default=root / "data" / "test.jsonl")
    parser.add_argument("--output", type=Path, default=root / "evaluation" / "metrics.json")
    parser.add_argument("--promotion-threshold", type=float, default=0.90)
    args = parser.parse_args()

    rows = [json.loads(line) for line in args.data.read_text(encoding="utf-8").splitlines() if line]
    tokenizer = AutoTokenizer.from_pretrained(args.model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(args.model_dir)
    classifier = pipeline("text-classification", model=model, tokenizer=tokenizer, top_k=None, device=-1)
    predictions = classifier([row["code"] for row in rows], batch_size=64, truncation=True)
    y_true = [row["label"] for row in rows]
    y_pred = [max(scores, key=lambda item: item["score"])["label"] for scores in predictions]
    matrix = confusion_matrix(y_true, y_pred, labels=LABELS).tolist()
    report = classification_report(y_true, y_pred, labels=LABELS, output_dict=True, zero_division=0)
    macro_f1 = report["macro avg"]["f1-score"]
    result = {
        "count": len(rows),
        "classification_report": report,
        "false_rates": error_rates(matrix),
        "confusion_matrix": {"labels": LABELS, "matrix": matrix},
        "promotion": {
            "threshold_macro_f1": args.promotion_threshold,
            "observed_macro_f1": macro_f1,
            "passed": macro_f1 >= args.promotion_threshold,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
