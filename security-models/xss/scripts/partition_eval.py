"""Subset evaluation: split hard_test_v3 by provenance and report each."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from sklearn.metrics import classification_report, confusion_matrix
from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline


LABELS = ["SAFE", "POSSIBLE_XSS", "XSS"]
ROOT = Path(__file__).resolve().parents[1]


def evaluate(rows, classifier):
    if not rows:
        return None
    preds = classifier([r["code"] for r in rows], batch_size=64, truncation=True)
    y_true = [r["label"] for r in rows]
    y_pred = [max(s, key=lambda i: i["score"])["label"] for s in preds]
    report = classification_report(y_true, y_pred, labels=LABELS, output_dict=True, zero_division=0)
    matrix = confusion_matrix(y_true, y_pred, labels=LABELS).tolist()
    return {"count": len(rows), "macro_f1": report["macro avg"]["f1-score"], "report": report,
            "confusion_matrix": {"labels": LABELS, "matrix": matrix}}


def main():
    rows = [json.loads(line) for line in (ROOT / "data" / "hard_test.jsonl").read_text(encoding="utf-8").splitlines() if line]
    tokenizer = AutoTokenizer.from_pretrained(ROOT / "model")
    model = AutoModelForSequenceClassification.from_pretrained(ROOT / "model")
    clf = pipeline("text-classification", model=model, tokenizer=tokenizer, top_k=None, device=-1)

    buckets = defaultdict(list)
    for row in rows:
        origin = row["provenance"].get("origin", "unknown")
        buckets[origin].append(row)

    out = {}
    for origin, items in buckets.items():
        out[origin] = evaluate(items, clf)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
