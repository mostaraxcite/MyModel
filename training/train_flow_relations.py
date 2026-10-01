"""Train a small offline relation advisor from independently reviewed spans.

This is a TF-IDF/logistic baseline, not an SLM or a final XSS classifier.
The locked external dataset is never accepted as a training argument.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from xss_specialist.flow_relations import LABELS, audit_relation_splits, load_rows, relation_text


class PreflightError(ValueError):
    pass


def fit_model(train: list[dict], dev: list[dict]) -> tuple[dict, dict]:
    """Numerical fitting only. Public train() adds review/disjointness/sample gates."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, recall_score
    from sklearn.pipeline import Pipeline

    pipeline = Pipeline([
        ("features", TfidfVectorizer(token_pattern=r"(?u)\b\w+\b", lowercase=False,
                                    ngram_range=(1, 2), sublinear_tf=True, max_features=12000)),
        ("relation", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=2027)),
    ])
    pipeline.fit([relation_text(r) for r in train], [r["label"] for r in train])
    predictions = pipeline.predict([relation_text(r) for r in dev])
    truth = [r["label"] for r in dev]
    features, model = pipeline["features"], pipeline["relation"]
    metrics = {
        "dev_accuracy": float(accuracy_score(truth, predictions)),
        "dev_macro_f1": float(f1_score(truth, predictions, labels=list(LABELS), average="macro", zero_division=0)),
        "dev_class_recall": dict(zip(LABELS, recall_score(truth, predictions, labels=list(LABELS), average=None, zero_division=0).tolist())),
        "dev_confusion_matrix": confusion_matrix(truth, predictions, labels=list(LABELS)).tolist(),
        "class_order": list(LABELS), "external_evaluated": False,
        "promotion_allowed": False,
    }
    artifact = {
        "schema": "xss-flow-relation-v1", "architecture": "tfidf-logistic-regression",
        "final_judge": False, "promoted": False,
        "classes": model.classes_.tolist(), "vocabulary": {k: int(v) for k, v in features.vocabulary_.items()},
        "idf": features.idf_.tolist(), "coefficients": model.coef_.tolist(),
        "intercept": model.intercept_.tolist(), "seed": 2027,
    }
    return artifact, metrics


def train(train_path: Path, dev_path: Path, output: Path) -> dict:
    if output.exists():
        raise PreflightError("output already exists; use a new candidate directory")
    try:
        train_rows, dev_rows = load_rows(train_path), load_rows(dev_path)
        audit = audit_relation_splits({"train": train_rows, "dev": dev_rows})
    except (ValueError, OSError) as error:
        raise PreflightError(str(error)) from error
    for split, minimum in (("train", 20), ("dev", 10)):
        if any(n < minimum for n in audit["class_counts"][split].values()):
            raise PreflightError(f"{split} requires at least {minimum} independently reviewed records per relation class")
    artifact, metrics = fit_model(train_rows, dev_rows)
    artifact["training_sha256"] = hashlib.sha256(train_path.read_bytes()).hexdigest()
    artifact["development_sha256"] = hashlib.sha256(dev_path.read_bytes()).hexdigest()
    report = {"status": "TRAINED_RESEARCH_CANDIDATE", "audit": audit, "metrics": metrics,
              "training_records": len(train_rows), "development_records": len(dev_rows),
              "model_role": "advisory flow-relation review only", "promotion_allowed": False}
    report["label_review"] = {
        "reviewers": sorted({r["verification"]["reviewer"] for r in train_rows + dev_rows}),
        "independent_expert_review": all(r["verification"].get("independent_expert_review") is True
                                         for r in train_rows + dev_rows),
    }
    output.mkdir(parents=True)
    (output / "model.json").write_text(json.dumps(artifact, indent=2))
    (output / "report.json").write_text(json.dumps(report, indent=2))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", required=True, type=Path)
    parser.add_argument("--dev", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--failure-report", type=Path)
    args = parser.parse_args()
    try:
        report = train(args.train, args.dev, args.output)
    except PreflightError as error:
        report = {"status": "BLOCKED_DATA_PREFLIGHT", "reason": str(error),
                  "training_started": False, "promotion_allowed": False,
                  "external_evaluated": False}
        if args.failure_report:
            args.failure_report.parent.mkdir(parents=True, exist_ok=True)
            args.failure_report.write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
        raise SystemExit(2)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
