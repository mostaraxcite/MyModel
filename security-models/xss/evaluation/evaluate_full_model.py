"""Evaluate a fully fine-tuned sequence classifier on XSS datasets."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from sklearn.metrics import classification_report, confusion_matrix
from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline

THREE_LABELS = ["SAFE", "POSSIBLE_XSS", "XSS"]
BINARY_LABELS = ["SAFE", "XSS"]


def read_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def error_rates(matrix: list[list[int]], labels: list[str]) -> dict:
    total = sum(sum(row) for row in matrix)
    out = {}
    for i, label in enumerate(labels):
        tp = matrix[i][i]
        fp = sum(row[i] for row in matrix) - tp
        fn = sum(matrix[i]) - tp
        tn = total - tp - fp - fn
        out[label] = {
            "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
            "false_negative_rate": fn / (fn + tp) if fn + tp else 0.0,
        }
    return out


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--model-dir", type=Path, required=True)
    p.add_argument("--data", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--external-binary", action="store_true")
    p.add_argument("--calibration", type=Path, default=None)
    args = p.parse_args()

    rows = read_rows(args.data)
    tokenizer = AutoTokenizer.from_pretrained(args.model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(args.model_dir)
    classify = pipeline("text-classification", model=model, tokenizer=tokenizer, top_k=None, device=-1)
    scores = classify([r["code"] for r in rows], batch_size=32, truncation=True)
    calibration = json.loads(args.calibration.read_text()) if args.calibration else None

    def decide(items):
        by_label = {item["label"]: float(item["score"]) for item in items}
        raw = max(items, key=lambda item: item["score"])["label"]
        if calibration and raw == "XSS":
            px = by_label.get("XSS", 0.0)
            competitor = max(by_label.get("SAFE", 0.0), by_label.get("POSSIBLE_XSS", 0.0))
            if px < float(calibration["xss_threshold"]) or (px - competitor) < float(calibration["xss_margin"]):
                return "POSSIBLE_XSS"
        return raw

    preds = [decide(items) for items in scores]

    if args.external_binary:
        decided = [(r["label"], pred) for r, pred in zip(rows, preds) if pred in BINARY_LABELS]
        y_true, y_pred = zip(*decided) if decided else ([], [])
        matrix = confusion_matrix(y_true, y_pred, labels=BINARY_LABELS).tolist()
        report = classification_report(
            y_true, y_pred, labels=BINARY_LABELS, output_dict=True, zero_division=0
        )
        safe_total = sum(r["label"] == "SAFE" for r in rows)
        xss_total = sum(r["label"] == "XSS" for r in rows)
        fp = sum(r["label"] == "SAFE" and pred == "XSS" for r, pred in zip(rows, preds))
        fn = sum(r["label"] == "XSS" and pred == "SAFE" for r, pred in zip(rows, preds))
        result = {
            "dataset": args.data.name,
            "count": len(rows),
            "coverage": len(decided) / len(rows) if rows else 0.0,
            "abstention_rate": preds.count("POSSIBLE_XSS") / len(rows) if rows else 0.0,
            "decided_macro_f1": report["macro avg"]["f1-score"],
            "per_label": {label: report[label] for label in BINARY_LABELS},
            "xss_false_positive_rate_all": fp / safe_total if safe_total else 0.0,
            "xss_false_negative_rate_all": fn / xss_total if xss_total else 0.0,
            "confusion_decided": {"labels": BINARY_LABELS, "matrix": matrix},
            "promotion": {
                "passed": (
                    report["macro avg"]["f1-score"] >= 0.90
                    and (len(decided) / len(rows) if rows else 0.0) >= 0.90
                    and (fp / safe_total if safe_total else 0.0) <= 0.08
                    and (fn / xss_total if xss_total else 0.0) <= 0.08
                ),
                "requirements": {"macro_f1": 0.90, "coverage": 0.90, "max_fpr": 0.08, "max_fnr": 0.08},
            },
        }
    else:
        y_true = [r["label"] for r in rows]
        matrix = confusion_matrix(y_true, preds, labels=THREE_LABELS).tolist()
        report = classification_report(
            y_true, preds, labels=THREE_LABELS, output_dict=True, zero_division=0
        )
        result = {
            "dataset": args.data.name,
            "count": len(rows),
            "classification_report": report,
            "false_rates": error_rates(matrix, THREE_LABELS),
            "confusion_matrix": {"labels": THREE_LABELS, "matrix": matrix},
            "promotion": {
                "threshold_macro_f1": 0.90,
                "observed_macro_f1": report["macro avg"]["f1-score"],
                "passed": report["macro avg"]["f1-score"] >= 0.90,
            },
        }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
