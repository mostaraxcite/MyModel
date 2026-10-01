"""Build masked multi-task training data for the PyTorch XSS specialist.

Sources:
- benchmark XSSCase records: source/sink/defense supervision, structural train/holdout split.
- verified native flow-relation records: flow supervision only.

No whole-snippet SAFE/XSS target is emitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from benchmarks import cases
from xss_specialist.schema import Defense, Role
from xss_specialist.multitask import (
    DEFENSE_LABELS,
    FLOW_LABELS,
    IGNORE_INDEX,
    SINK_LABELS,
    SOURCE_LABELS,
)

ROOT = Path(__file__).resolve().parents[1]


def source_class(name: str) -> str:
    low = name.lower()
    if any(x in low for x in ("location.", "window.", "document.", "event.", "message.")):
        return "BROWSER"
    if any(x in low for x in ("req.", "request.", "$_get", "$_post")):
        return "SERVER"
    if any(x in low for x in ("props", "route.", "router.", "parammap")):
        return "FRAMEWORK"
    return "OTHER" if name.strip() else "NONE"


def sink_class(name: str) -> str:
    low = name.lower()
    if any(x in low for x in (
        "innerhtml", "outerhtml", "document.write", "$.html", ".html",
        "insertadjacenthtml", "dangerouslysetinnerhtml", "echo",
    )):
        return "DANGEROUS_HTML"
    if any(x in low for x in ("eval", "function(", "settimeout", "setinterval")):
        return "DANGEROUS_JS"
    if any(x in low for x in ("href", "src", "action", "templateurl")):
        return "DANGEROUS_URL"
    if any(x in low for x in (
        "textcontent", "innertext", "insertadjacenttext", ".text", "{child}",
        "htmlspecialchars", "scheme allow-list",
    )):
        return "SAFE_OUTPUT"
    return "OTHER" if name.strip() else "NONE"


def defense_class(defense: Defense) -> str:
    mapping = {
        Defense.NONE: "NONE",
        Defense.SANITIZATION: "SANITIZATION",
        Defense.CONTEXTUAL_ENCODING: "CONTEXTUAL_ENCODING",
        Defense.FRAMEWORK_ESCAPING: "FRAMEWORK_ESCAPING",
        Defense.SAFE_DOM_API: "SAFE_DOM_API",
        Defense.INPUT_CONSTRAINT: "INPUT_CONSTRAINT",
    }
    return mapping.get(defense, "OTHER")


def idx(labels: list[str], value: str) -> int:
    return labels.index(value)


def xss_rows(group: str, n_per_template: int, names: str) -> list[dict]:
    out = []
    for case in cases.generate(n_per_template=n_per_template, group=group, names=names):
        source = next((n.name for n in case.flow if n.role == Role.SOURCE), "")
        sink = next((n.name for n in reversed(case.flow) if n.role == Role.SINK), "")
        row = {
            "id": case.id,
            "text": case.code,
            "source_label": idx(SOURCE_LABELS, source_class(source)),
            "sink_label": idx(SINK_LABELS, sink_class(sink)),
            "defense_label": idx(DEFENSE_LABELS, defense_class(case.existing_defense)),
            "flow_label": IGNORE_INDEX,
            "metadata": {
                "origin": "xsscase-structural",
                "template": case.tags[-1] if case.tags else "",
                "language": case.language,
                "vulnerable": case.vulnerable,
                "context": case.context.value,
                "source": source,
                "sink": sink,
                "defense": case.existing_defense.value,
            },
        }
        out.append(row)
    return out


def relation_rows(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if item.get("task") != "FLOW_RELATION":
            continue
        text = (
            f"[SOURCE]\n{item['source_expression']}\n"
            f"[SINK]\n{item['sink_expression']}\n"
            f"[FLOW]\n{item['flow_excerpt']}"
        )
        rows.append({
            "id": item["id"],
            "text": text,
            "source_label": IGNORE_INDEX,
            "sink_label": IGNORE_INDEX,
            "defense_label": IGNORE_INDEX,
            "flow_label": idx(FLOW_LABELS, item["label"]),
            "metadata": {
                "origin": "verified-native-flow",
                "repository": item["provenance"]["repository"],
                "framework": item["provenance"]["framework"],
                "reference": item["verification"]["reference"],
            },
        })
    return rows


def digest(row: dict) -> str:
    return hashlib.sha256(row["text"].encode()).hexdigest()


def write(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))


def audit(train: list[dict], dev: list[dict]) -> dict:
    train_hash = {digest(r) for r in train}
    dev_hash = {digest(r) for r in dev}
    overlap = train_hash & dev_hash
    if overlap:
        raise SystemExit(f"multitask train/dev text overlap: {len(overlap)}")

    def counts(rows):
        result = {}
        for task, labels in (
            ("source", SOURCE_LABELS),
            ("sink", SINK_LABELS),
            ("defense", DEFENSE_LABELS),
            ("flow", FLOW_LABELS),
        ):
            c = {name: 0 for name in labels}
            masked = 0
            key = f"{task}_label"
            for row in rows:
                value = row[key]
                if value == IGNORE_INDEX:
                    masked += 1
                else:
                    c[labels[value]] += 1
            result[task] = {"classes": c, "masked": masked}
        return result

    return {
        "schema": "xss-multitask-data-v1",
        "train_rows": len(train),
        "dev_rows": len(dev),
        "exact_text_overlap": 0,
        "train": counts(train),
        "dev": counts(dev),
        "whole_snippet_xss_target": False,
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--train-per-template", type=int, default=160)
    p.add_argument("--dev-per-template", type=int, default=100)
    p.add_argument("--output-dir", type=Path, default=ROOT / "data" / "multitask-v1")
    args = p.parse_args()

    train = xss_rows("train", args.train_per_template, "train")
    dev = xss_rows("holdout", args.dev_per_template, "holdout")

    train += relation_rows(ROOT / "data" / "flow-relations-v1" / "train.jsonl")
    dev += relation_rows(ROOT / "data" / "flow-relations-v1" / "dev.jsonl")

    manifest = audit(train, dev)
    write(args.output_dir / "train.jsonl", train)
    write(args.output_dir / "dev.jsonl", dev)
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
