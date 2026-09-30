"""Calibrate XSS confidence on development-only stress sets.

The calibrator NEVER reads locked Hard Test or External Test v5. It chooses a
minimum XSS probability and winner margin. Borderline XSS predictions are
downgraded to POSSIBLE_XSS rather than SAFE.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from sklearn.metrics import classification_report
from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline

LABELS = ["SAFE", "POSSIBLE_XSS", "XSS"]


def read_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def infer(classifier, rows: list[dict]) -> list[dict[str, float]]:
    outputs = classifier([r["code"] for r in rows], batch_size=32, truncation=True)
    return [{item["label"]: float(item["score"]) for item in items} for items in outputs]


def decide(score: dict[str, float], threshold: float, margin: float) -> str:
    raw = max(score, key=score.get)
    if raw == "XSS":
        px = score.get("XSS", 0.0)
        competitor = max(score.get("SAFE", 0.0), score.get("POSSIBLE_XSS", 0.0))
        if px < threshold or (px - competitor) < margin:
            return "POSSIBLE_XSS"
    return raw


def binary_metrics(rows: list[dict], scores: list[dict[str, float]], threshold: float, margin: float) -> dict:
    preds = [decide(s, threshold, margin) for s in scores]
    decided = [(r["label"], p) for r, p in zip(rows, preds) if p in ("SAFE", "XSS")]
    y_true = [x[0] for x in decided]
    y_pred = [x[1] for x in decided]
    report = classification_report(
        y_true, y_pred, labels=["SAFE", "XSS"], output_dict=True, zero_division=0
    ) if decided else {"macro avg": {"f1-score": 0.0}}

    safe_total = sum(r["label"] == "SAFE" for r in rows)
    xss_total = sum(r["label"] == "XSS" for r in rows)
    safe_as_xss = sum(r["label"] == "SAFE" and p == "XSS" for r, p in zip(rows, preds))
    xss_as_safe = sum(r["label"] == "XSS" and p == "SAFE" for r, p in zip(rows, preds))
    return {
        "coverage": len(decided) / len(rows) if rows else 0.0,
        "macro_f1": float(report["macro avg"]["f1-score"]),
        "safe_fpr": safe_as_xss / safe_total if safe_total else 0.0,
        "xss_to_safe_rate": xss_as_safe / xss_total if xss_total else 0.0,
        "abstention_rate": preds.count("POSSIBLE_XSS") / len(rows) if rows else 0.0,
    }


def three_way_metrics(rows: list[dict], scores: list[dict[str, float]], threshold: float, margin: float) -> dict:
    preds = [decide(s, threshold, margin) for s in scores]
    report = classification_report(
        [r["label"] for r in rows],
        preds,
        labels=LABELS,
        output_dict=True,
        zero_division=0,
    )
    return {
        "macro_f1": float(report["macro avg"]["f1-score"]),
        "safe_recall": float(report["SAFE"]["recall"]),
        "possible_recall": float(report["POSSIBLE_XSS"]["recall"]),
        "xss_recall": float(report["XSS"]["recall"]),
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--model-dir", type=Path, required=True)
    p.add_argument("--stress-data", type=Path, required=True)
    p.add_argument("--three-way-data", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(args.model_dir)
    classifier = pipeline("text-classification", model=model, tokenizer=tokenizer, top_k=None, device=-1)

    stress_rows = read_rows(args.stress_data)
    three_rows = read_rows(args.three_way_data)
    stress_scores = infer(classifier, stress_rows)
    three_scores = infer(classifier, three_rows)

    candidates = []
    thresholds = [round(x / 100, 2) for x in range(34, 96, 2)]
    margins = [round(x / 100, 2) for x in range(0, 41, 5)]
    for threshold in thresholds:
        for margin in margins:
            binary = binary_metrics(stress_rows, stress_scores, threshold, margin)
            three = three_way_metrics(three_rows, three_scores, threshold, margin)
            viable = (
                binary["safe_fpr"] <= 0.10
                and binary["xss_to_safe_rate"] <= 0.08
                and binary["coverage"] >= 0.90
                and binary["macro_f1"] >= 0.85
                and three["macro_f1"] >= 0.82
                and three["safe_recall"] >= 0.80
                and three["xss_recall"] >= 0.75
            )
            score = (
                0.35 * binary["macro_f1"]
                + 0.25 * binary["coverage"]
                + 0.25 * three["macro_f1"]
                + 0.15 * (1.0 - binary["safe_fpr"])
            )
            candidates.append({
                "xss_threshold": threshold,
                "xss_margin": margin,
                "stress": binary,
                "three_way": three,
                "viable": viable,
                "score": score,
            })

    viable = [c for c in candidates if c["viable"]]
    if viable:
        viable.sort(key=lambda c: (c["score"], -c["stress"]["safe_fpr"], c["stress"]["coverage"]), reverse=True)
        winner = viable[0]
    else:
        candidates.sort(key=lambda c: (c["score"], -c["stress"]["safe_fpr"], c["stress"]["coverage"]), reverse=True)
        winner = candidates[0]

    result = {
        "calibration_source": {
            "stress_data": str(args.stress_data),
            "three_way_data": str(args.three_way_data),
            "locked_tests_used": False,
        },
        "xss_threshold": winner["xss_threshold"],
        "xss_margin": winner["xss_margin"],
        "stress": winner["stress"],
        "three_way": winner["three_way"],
        "viable": winner["viable"],
        "score": winner["score"],
        "searched": len(candidates),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if not winner["viable"]:
        raise SystemExit("No calibration candidate passed development viability gates.")


if __name__ == "__main__":
    main()
