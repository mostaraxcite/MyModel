"""Side-by-side evaluation on standard test + Hard Test v3 (locked)."""
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


def evaluate(rows: list[dict], classifier, batch_size: int = 64) -> dict:
    predictions = classifier([row["code"] for row in rows], batch_size=batch_size, truncation=True)
    y_true = [row["label"] for row in rows]
    y_pred = [max(scores, key=lambda item: item["score"])["label"] for scores in predictions]
    matrix = confusion_matrix(y_true, y_pred, labels=LABELS).tolist()
    report = classification_report(y_true, y_pred, labels=LABELS, output_dict=True, zero_division=0)
    macro_f1 = report["macro avg"]["f1-score"]
    return {
        "count": len(rows),
        "macro_f1": macro_f1,
        "report": report,
        "false_rates": error_rates(matrix),
        "confusion_matrix": {"labels": LABELS, "matrix": matrix},
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", type=Path, default=root / "model")
    parser.add_argument("--data-dir", type=Path, default=root / "data")
    parser.add_argument("--output", type=Path, default=root / "evaluation" / "round3_metrics.json")
    parser.add_argument("--promotion-threshold", type=float, default=0.90)
    args = parser.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(args.model_dir)
    classifier = pipeline("text-classification", model=model, tokenizer=tokenizer, top_k=None, device=-1)

    standard = [json.loads(line) for line in (args.data_dir / "test.jsonl").read_text(encoding="utf-8").splitlines() if line]
    hard = [json.loads(line) for line in (args.data_dir / "hard_test.jsonl").read_text(encoding="utf-8").splitlines() if line]

    standard_metrics = evaluate(standard, classifier)
    hard_metrics = evaluate(hard, classifier)

    summary = {
        "promotion_threshold": args.promotion_threshold,
        "standard_test": {
            "macro_f1": standard_metrics["macro_f1"],
            "passed": standard_metrics["macro_f1"] >= args.promotion_threshold,
            "per_label_f1": {
                label: standard_metrics["report"][label]["f1-score"] for label in LABELS
            },
            "xss_false_positive_rate": standard_metrics["false_rates"]["XSS"]["false_positive_rate"],
            "xss_false_negative_rate": standard_metrics["false_rates"]["XSS"]["false_negative_rate"],
            "confusion_matrix": standard_metrics["confusion_matrix"],
        },
        "hard_test_v4": {
            "macro_f1": hard_metrics["macro_f1"],
            "passed": hard_metrics["macro_f1"] >= args.promotion_threshold,
            "per_label_f1": {
                label: hard_metrics["report"][label]["f1-score"] for label in LABELS
            },
            "xss_false_positive_rate": hard_metrics["false_rates"]["XSS"]["false_positive_rate"],
            "xss_false_negative_rate": hard_metrics["false_rates"]["XSS"]["false_negative_rate"],
            "confusion_matrix": hard_metrics["confusion_matrix"],
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
