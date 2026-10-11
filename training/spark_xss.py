"""Opt-in Spark-X2.5 XSS LoRA dataset and LLaMA-Factory recipe builder.

This module NEVER trains, downloads model weights, scans targets, or promotes
a checkpoint unless a human separately runs the generated training command.
It consumes MyModel's existing curated SFT records, not locked benchmarks.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any

import yaml


DEFAULT_MODEL = "XHToken/Spark-X2.5-4B"
DEFAULT_INPUT = Path("data/training/sft_v3.jsonl")
DEFAULT_OUTPUT = Path("models/spark-x25-xss")
RESTRICTED_INPUT_PARTS = {"benchmarks", "frozen", "evaluation", "reports"}
RESTRICTED_TAGS = {"test", "locked", "benchmark", "frozen", "holdout"}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_is_training_data(path: Path) -> bool:
    """Never train from the repo's frozen benchmark/evaluation directories."""
    resolved = path.resolve()
    project = Path(__file__).resolve().parents[1]
    try:
        parts = set(resolved.relative_to(project).parts)
    except ValueError:
        return False
    return ("data" in parts and "training" in parts
            and not bool(parts & RESTRICTED_INPUT_PARTS))


def validate_record(row: dict[str, Any], line: int) -> tuple[str, dict, str]:
    """Return (group, alpaca record, class); refuse unverifiable examples."""
    if not isinstance(row, dict):
        raise ValueError(f"line {line}: expected object")
    origin = row.get("origin")
    if origin not in {"synthetic", "verified"}:
        raise ValueError(f"line {line}: origin must be synthetic or verified")
    if origin == "verified" and row.get("reviewed") is not True:
        raise ValueError(f"line {line}: verified examples require reviewed=true")
    tags = row.get("tags") or []
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        raise ValueError(f"line {line}: invalid tags")
    if set(t.lower() for t in tags) & RESTRICTED_TAGS:
        raise ValueError(f"line {line}: reserved/locked evaluation tag")
    case_id = row.get("case_id")
    if not isinstance(case_id, str) or not case_id.strip():
        raise ValueError(f"line {line}: missing case_id")
    messages = row.get("messages")
    if (
        not isinstance(messages, list) or len(messages) != 2
        or [x.get("role") for x in messages if isinstance(x, dict)]
           != ["user", "assistant"]
    ):
        raise ValueError(f"line {line}: expected one user and one assistant message")
    prompt, response = (m.get("content") for m in messages)
    if not isinstance(prompt, str) or not prompt.strip() or not isinstance(response, str) or not response.strip():
        raise ValueError(f"line {line}: empty/non-string message")
    if not isinstance(row.get("vulnerable"), bool):
        raise ValueError(f"line {line}: missing vulnerability training label")
    # Prefer stable generator/template family over per-row random train/eval.
    group = next((t for t in tags if t not in {"train", "synthetic", "verified"}), None)
    if group is None:
        group = re.sub(r"-(?:v|s)-\d+$", "", case_id)
    if not group.strip():
        raise ValueError(f"line {line}: missing grouping key")
    return group, {"instruction": prompt, "input": "", "output": response}, (
        "vulnerable" if row["vulnerable"] else "safe"
    )


def convert(source: Path, output_dir: Path, *, seed: int = 1337,
            valid_fraction: float = 0.2, model: str = DEFAULT_MODEL,
            revision: str | None = None, template: str | None = None,
            four_bit: bool = False) -> dict[str, Any]:
    if not source_is_training_data(source):
        raise ValueError("Only data/training inputs inside MyModel are allowed; frozen tests are excluded")
    if not source.is_file():
        raise FileNotFoundError(source)
    if output_dir.resolve().is_relative_to(source.resolve().parent):
        raise ValueError("Output must not live inside source data/training directory")
    if not 0.05 <= valid_fraction <= 0.45:
        raise ValueError("valid_fraction must be between 0.05 and 0.45")

    groups: dict[str, list[tuple[dict, str]]] = {}
    input_hashes: dict[str, str] = {}
    for line_number, text in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        if not text.strip():
            continue
        group, record, label = validate_record(json.loads(text), line_number)
        prompt_hash = sha256(record["instruction"].encode("utf-8"))
        known_group = input_hashes.setdefault(prompt_hash, group)
        if known_group != group:
            raise ValueError("Identical prompts occur in different groups; cannot guarantee split isolation")
        groups.setdefault(group, []).append((record, label))
    if len(groups) < 2:
        raise ValueError("At least two disjoint template groups are required")
    # All variants of each source/sink template stay in the same split.
    ordered = sorted(groups, key=lambda g: sha256(f"{seed}:{g}".encode()))
    count_valid = max(1, min(len(ordered) - 1, round(len(ordered) * valid_fraction)))
    valid_groups = set(ordered[:count_valid])
    train, valid = [], []
    distributions = {"train": Counter(), "eval": Counter()}
    for group, values in groups.items():
        name = "eval" if group in valid_groups else "train"
        target = valid if name == "eval" else train
        for record, label in values:
            target.append(record)
            distributions[name][label] += 1
    if not train or not valid:
        raise ValueError("Both train and validation must be nonempty")
    if any(distributions[part]["safe"] == 0 or distributions[part]["vulnerable"] == 0
           for part in ("train", "eval")):
        raise ValueError("Both splits must contain safe and vulnerable examples")

    output_dir.mkdir(parents=True, exist_ok=True)
    def write_json(name: str, value: Any) -> str:
        path = output_dir / name
        data = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        path.write_bytes(data)
        return sha256(data)

    train_sha = write_json("train.json", train)
    eval_sha = write_json("eval.json", valid)
    write_json("dataset_info.json", {
        "spark_xss_train": {
            "file_name": "train.json",
            "columns": {"prompt": "instruction", "query": "input", "response": "output"},
        },
        "spark_xss_eval": {
            "file_name": "eval.json",
            "columns": {"prompt": "instruction", "query": "input", "response": "output"},
        },
    })

    recipe = {
        "model_name_or_path": model,
        "trust_remote_code": True,
        "stage": "sft",
        "do_train": True,
        "do_eval": True,
        "finetuning_type": "lora",
        "lora_target": "all",
        "lora_rank": 16,
        "lora_alpha": 32,
        "lora_dropout": 0.05,
        "dataset_dir": str(output_dir.resolve()),
        "dataset": "spark_xss_train",
        "eval_dataset": "spark_xss_eval",
        "cutoff_len": 2048,
        "learning_rate": 1.0e-4,
        "num_train_epochs": 2.0,
        "per_device_train_batch_size": 1,
        "per_device_eval_batch_size": 1,
        "gradient_accumulation_steps": 8,
        "lr_scheduler_type": "cosine",
        "warmup_ratio": 0.05,
        "bf16": True,
        "eval_strategy": "steps",
        "eval_steps": 100,
        "save_strategy": "steps",
        "save_steps": 100,
        "save_total_limit": 2,
        "logging_steps": 10,
        "report_to": "none",
        "seed": seed,
        "output_dir": str((output_dir / "adapter").resolve()),
    }
    if revision:
        recipe["model_revision"] = revision
    if template:
        recipe["template"] = template
    if four_bit:
        recipe["quantization_bit"] = 4
        recipe["quantization_method"] = "bnb"
    (output_dir / "train.yaml").write_text(
        yaml.safe_dump(recipe, sort_keys=False, allow_unicode=True), encoding="utf-8"
    )

    manifest = {
        "status": "DATA_PREPARED_NOT_TRAINED",
        "base_model": model,
        "base_revision": revision,
        "dataset_origin": "curated_synthetic_or_reviewed_only",
        "source_sha256": sha256(source.read_bytes()),
        "train_sha256": train_sha,
        "eval_sha256": eval_sha,
        "train_records": len(train),
        "eval_records": len(valid),
        "train_template_groups": len(groups) - len(valid_groups),
        "eval_template_groups": len(valid_groups),
        "class_counts": {name: dict(counter) for name, counter in distributions.items()},
        "promotion": "NOT_EVALUATED",
        "browser_confirmation_required": True,
        "notes": "Synthetic code labels are not live vulnerability confirmation. "
                 "Evaluate on independent held-out suites before any model promotion.",
    }
    write_json("manifest.json", manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--model-revision", default=None)
    parser.add_argument("--template", default=None, help="Use a verified model-specific LLaMA-Factory template")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--valid-fraction", type=float, default=0.2)
    parser.add_argument("--four-bit", action="store_true", help="Experimental bitsandbytes QLoRA, GPU required")
    parser.add_argument("--launch-training", action="store_true",
                        help="Explicitly start training (requires pinned revision and installed LLaMA-Factory)")
    args = parser.parse_args()
    if args.launch_training:
        if not args.model_revision or not re.fullmatch(r"[0-9a-f]{40}", args.model_revision):
            parser.error("Launching training requires --model-revision with a pinned 40-hex commit hash")
        if not shutil.which("llamafactory-cli"):
            parser.error("llamafactory-cli is not installed; see docs/SPARK_XSS_TRAINING.md")
    manifest = convert(
        args.input, args.output_dir, seed=args.seed,
        valid_fraction=args.valid_fraction, model=args.model,
        revision=args.model_revision, template=args.template,
        four_bit=args.four_bit,
    )
    print(json.dumps(manifest, indent=2))
    if args.launch_training:
        # No shell, no service deployment; only requested GPU training.
        subprocess.run(["llamafactory-cli", "train", str(args.output_dir / "train.yaml")], check=True)


if __name__ == "__main__":
    main()
