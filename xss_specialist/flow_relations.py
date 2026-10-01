"""Small advisory relation model. No execution and no final XSS verdicts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

LABELS = ("CONNECTED", "DISCONNECTED", "UNKNOWN")
GROUPS = ("repository", "framework", "template", "generator")
FIELDS = ("source_expression", "sink_expression", "flow_excerpt")
MAX_EXCERPT = 4096


def relation_text(row: dict) -> str:
    if row.get("task") != "FLOW_RELATION":
        raise ValueError("expected task=FLOW_RELATION; whole-snippet classifier records are unsupported")
    parts = []
    for key in FIELDS:
        value = row.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > MAX_EXCERPT:
            raise ValueError(f"{key} must be a nonempty reviewed span of at most {MAX_EXCERPT} characters")
        parts.append(f"[{key}]\n{value}")
    return "\n".join(parts)


def audit_relation_splits(splits: dict[str, list[dict]]) -> dict:
    identities = {}
    counts = {}
    for name, rows in splits.items():
        if not rows:
            raise ValueError(f"empty split: {name}")
        identities[name] = {key: set() for key in (*GROUPS, "content", "id")}
        counts[name] = {label: 0 for label in LABELS}
        for row in rows:
            content = relation_text(row)
            label = row.get("label")
            if label not in LABELS:
                raise ValueError("relation label must be CONNECTED, DISCONNECTED or UNKNOWN")
            if not isinstance(row.get("id"), str) or not row["id"].strip():
                raise ValueError("relation id is required")
            review = row.get("verification", {})
            if review.get("status") != "REVIEWED" or any(
                not isinstance(review.get(k), str) or not review[k].strip()
                for k in ("reviewer", "rationale", "reference")
            ):
                raise ValueError("independent reviewed relation labels and evidence reference are required")
            provenance = row.get("provenance", {})
            for key in GROUPS:
                value = provenance.get(key)
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(f"missing provenance.{key}")
                identities[name][key].add(value.strip())
            digest = hashlib.sha256(content.encode()).hexdigest()
            if digest in identities[name]["content"] or row["id"] in identities[name]["id"]:
                raise ValueError(f"duplicate relation in {name}")
            identities[name]["content"].add(digest)
            identities[name]["id"].add(row["id"])
            counts[name][label] += 1
    names = list(splits)
    for i, left in enumerate(names):
        for right in names[i + 1:]:
            for key in identities[left]:
                if identities[left][key] & identities[right][key]:
                    raise ValueError(f"relation split overlap: {left}/{right} in {key}")
    return {"passed": True, "class_counts": counts, "groups": list(GROUPS),
            "note": "Metadata and review declarations are validated; authenticity requires corpus-owner review."}


def load_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


class FlowRelationAdvisor:
    """Read inert JSON weights; output priorities, never safety or confirmation."""
    def __init__(self, path: Path):
        import numpy as np
        from sklearn.feature_extraction.text import TfidfVectorizer

        artifact = json.loads(path.read_text())
        if artifact.get("schema") != "xss-flow-relation-v1" or artifact.get("final_judge") is not False:
            raise ValueError("unsupported or authoritative relation artifact")
        self.classes = artifact["classes"]
        if sorted(self.classes) != sorted(LABELS):
            raise ValueError("unexpected relation classes")
        self.vectorizer = TfidfVectorizer(vocabulary=artifact["vocabulary"],
                                         token_pattern=r"(?u)\b\w+\b", lowercase=False,
                                         ngram_range=(1, 2), sublinear_tf=True)
        self.vectorizer.idf_ = np.asarray(artifact["idf"], dtype=float)
        self.weights = np.asarray(artifact["coefficients"], dtype=float)
        self.intercept = np.asarray(artifact["intercept"], dtype=float)
        if self.weights.shape != (3, len(artifact["vocabulary"])) or self.intercept.shape != (3,):
            raise ValueError("invalid weight dimensions")
        if not all(np.isfinite(a).all() for a in (self.weights, self.intercept, self.vectorizer.idf_)):
            raise ValueError("nonfinite model weights")

    def predict(self, row: dict) -> dict:
        import numpy as np

        features = self.vectorizer.transform([relation_text(row)])
        logits = np.asarray(features @ self.weights.T).reshape(-1) + self.intercept
        values = np.exp(logits - logits.max())
        values /= values.sum()
        distribution = {k: float(v) for k, v in zip(self.classes, values)}
        return {"task": "FLOW_RELATION", "probabilities": distribution,
                "relation": max(distribution, key=distribution.get),
                "advisory_only": True, "confirmed": False, "requires_review": True}


def advise_review(result: dict, advice: dict) -> dict:
    """Add relation evidence to priority only; leave every authoritative field intact."""
    reviewed = {**result, "relation_advice": advice}
    if advice.get("relation") == "CONNECTED":
        reviewed["review_priority"] = "high"
    return reviewed
