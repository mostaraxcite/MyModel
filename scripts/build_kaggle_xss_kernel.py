"""Build a private Kaggle GPU training kernel from pinned public MyModel source.

No Kaggle credentials, GPU time, or network access are required to build it.
Publishing via Kaggle CLI is a separate explicit operator action.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "kaggle" / "spark_xss_train.py"
COMMIT_PLACEHOLDER = "__MYMODEL_SHA__"


def build(*, owner: str, sha: str, output_dir: Path,
          slug: str = "spark-xss-qlora-kaggle") -> dict:
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{1,39}", owner):
        raise ValueError("Invalid Kaggle username")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,60}", slug):
        raise ValueError("Invalid Kaggle kernel slug")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("MyModel SHA must be an immutable 40-character commit")
    code = TEMPLATE.read_text(encoding="utf-8")
    if code.count(COMMIT_PLACEHOLDER) != 1:
        # A single exact replacement in the template assignment.
        raise ValueError("Unexpected Kaggle script template; refusing unsafe substitution")
    code = code.replace(f'REPO_SHA = "{COMMIT_PLACEHOLDER}"', f'REPO_SHA = "{sha}"')
    if f'REPO_SHA = "{sha}"' not in code:
        raise ValueError("Unable to insert pinned repository SHA")
    # Cannot leave an unresolved placeholder except for its explanatory comment.
    output_dir.mkdir(parents=True, exist_ok=True)
    script = output_dir / "spark_xss_train.py"
    script.write_text(code, encoding="utf-8")
    metadata = {
        "id": f"{owner}/{slug}",
        "title": "Spark XSS QLoRA Kaggle",
        "code_file": script.name,
        "language": "python",
        "kernel_type": "script",
        "is_private": True,
        "enable_gpu": True,
        "enable_internet": True,
        "machine_shape": "NvidiaTeslaT4",
        "dataset_sources": [],
        "competition_sources": [],
        "kernel_sources": [],
        "model_sources": [],
    }
    (output_dir / "kernel-metadata.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )
    manifest = {
        "status": "PACKAGED_NOT_SUBMITTED",
        "github_sha": sha,
        "script_sha256": hashlib.sha256(script.read_bytes()).hexdigest(),
        "kernel_id": metadata["id"],
        "accelerator": "NvidiaTeslaT4",
        "private": True,
        "internet_enabled": True,
        "requires_kaggle_account": True,
        "training_started": False,
        "registered_or_deployed": False,
    }
    (output_dir / "packaging-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--owner", required=True, help="Your Kaggle username, not your GitHub login")
    p.add_argument("--sha", required=True, help="Current pinned 40-character MyModel commit")
    p.add_argument("--output-dir", type=Path, default=Path("kaggle-dist"))
    p.add_argument("--slug", default="spark-xss-qlora-kaggle")
    args = p.parse_args()
    print(json.dumps(
        build(owner=args.owner, sha=args.sha, output_dir=args.output_dir,
              slug=args.slug),
        indent=2,
    ))


if __name__ == "__main__":
    main()
