"""Reproduce reviewed relations from pinned, byte-identical upstream source.

No labels are inferred from the analyzer or from a model. Selections contain
single-agent static review; independent expert review remains a promotion step.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from xss_specialist.flow_relations import audit_relation_splits

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/flow-relations-v1"


def build(source_roots: dict[str, Path]) -> dict:
    selection_path = DATA / "reviewed_selections.json"
    selection = json.loads(selection_path.read_text())
    rows = {"train": [], "dev": []}
    copied = set()
    for item in selection["selections"]:
        framework = item["framework"]
        source_root = source_roots[framework]
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source_root, text=True).strip()
        if commit != item["commit"]:
            raise ValueError(f"{framework}: upstream commit does not match reviewed selection")
        source_path = source_root / item["source_file"]
        source = source_path.read_bytes()
        if hashlib.sha256(source).hexdigest() != item["source_sha256"]:
            raise ValueError("upstream source bytes changed")
        # Generated files are deliberately excluded from this native-code corpus.
        if b"automatically generated" in source[:2000].lower() or b"automatically generated" in source_path.name.encode():
            raise ValueError("generated code cannot use native-code exemptions")
        excerpt_span = item["excerpt_span"]
        excerpt = source[excerpt_span["start_byte"]:excerpt_span["end_byte"]].decode()
        for key in ("source", "sink"):
            span = item[key + "_span"]
            if source[span["start_byte"]:span["end_byte"]].decode() != item[key + "_expression"]:
                raise ValueError(f"{key} expression does not match pinned source bytes")
        snapshot = DATA / "sources" / framework / item["source_file"]
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, snapshot)
        copied.add(snapshot.relative_to(ROOT).as_posix())
        license_path = DATA / "sources" / framework / "LICENSE"
        shutil.copyfile(source_root / "LICENSE", license_path)
        split = "train" if framework == "express" else "dev"
        identity = f"{framework}:{item['source_file']}:{item['sink_span']['start_byte']}:{item['source_span']['start_byte']}"
        rows[split].append({
            "id": identity, "task": "FLOW_RELATION",
            "source_expression": item["source_expression"], "sink_expression": item["sink_expression"],
            "flow_excerpt": excerpt, "label": item["label"],
            "query_location": {"sink_span": item["sink_span"], "source_span": item["source_span"],
                               "statement_span": item["statement_span"], "line": item["line"]},
            "verification": {"status": "REVIEWED", "reviewer": item["reviewer"],
                "rationale": item["rationale"], "independent_expert_review": False,
                "reference": f"https://github.com/{item['repository']}/blob/{commit}/{item['source_file']}#L{item['line']}"},
            "provenance": {"repository": item["repository"], "framework": framework,
                "template": "not-applicable", "generator": "not-applicable", "code_origin": "repository",
                "commit": commit, "source_file": item["source_file"], "source_sha256": item["source_sha256"],
                "excerpt_span": excerpt_span, "source_snapshot": snapshot.relative_to(ROOT).as_posix(), "license": "MIT"},
        })
    audit = audit_relation_splits(rows)
    hashes = {}
    for split, records in rows.items():
        output = DATA / (split + ".jsonl")
        output.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in records))
        hashes[split] = hashlib.sha256(output.read_bytes()).hexdigest()
    manifest = {"schema": "native-flow-relations-v1", "audit": audit, "split_sha256": hashes,
                "selections_sha256": hashlib.sha256(selection_path.read_bytes()).hexdigest(),
                "snapshot_files": sorted(copied), "code_generated": False,
                "independent_expert_review": False, "locked_external_opened": False,
                "promotion_allowed": False,
                "limitations": ["90 deliberately selected local assignment queries from two repositories",
                                "Same implementer reviewed labels; no independent expert audit yet",
                                "Calls opaque by task definition; not ground truth for whole-program flow",
                                "Native code has no generator/template; structural template independence not claimed",
                                "Not an XSS detection benchmark"]}
    (DATA / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--express-source", required=True, type=Path)
    parser.add_argument("--fastify-source", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(build({"express": args.express_source, "fastify": args.fastify_source}), indent=2))


if __name__ == "__main__":
    main()
