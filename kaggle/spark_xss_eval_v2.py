"""Kaggle GPU entry point for frozen base-vs-XSS-LoRA benchmark.

Requires the private trained notebook as a kernel source. Does not train,
modify MyHunt, scan external sites, or approve/promote checkpoints.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import traceback

REPO = "https://github.com/mostaraxcite/MyModel.git"
REPO_SHA = "__MYMODEL_EVAL_SHA__"  # substituted only by GitHub workflow
FORK = "https://github.com/XHToken/LlamaFactory.git"
FORK_SHA = "f56888d47dc5681e15b83ddbea01adddf2050adf"
OUTPUT = Path("/kaggle/working/spark-xss-v2-regression-evaluation")
EXPECTED_TRAINING_SHA = "06069340505e535573230a81eb88c45560084df3"


def run(*args, cwd=None):
    print("Running:", " ".join(map(str, args)), flush=True)
    subprocess.run([str(x) for x in args], cwd=str(cwd) if cwd else None, check=True)


def checkout(url, sha, where):
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise RuntimeError("Unpinned source commit refused")
    if where.exists():
        raise RuntimeError("Refusing to reuse stale checkout")
    run("git", "init", where)
    run("git", "remote", "add", "origin", url, cwd=where)
    run("git", "fetch", "--depth", "1", "origin", sha, cwd=where)
    run("git", "checkout", "--detach", "FETCH_HEAD", cwd=where)
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"],
                                     cwd=str(where), text=True).strip()
    if actual != sha:
        raise RuntimeError("Pinned source commit verification failed")


def find_valid_adapter():
    """The training notebook's frozen output is attached through kernel_sources."""
    found = []
    for p in sorted(Path("/kaggle/input").rglob("adapter_config.json")):
        folder = p.parent
        if not (folder / "adapter_model.safetensors").is_file():
            continue
        status = folder.parent.parent / "run_status.json"
        if not status.is_file():
            continue
        run_state = json.loads(status.read_text())
        if (run_state.get("status") == "candidate_saved_not_evaluated"
                and run_state.get("training_variant") == "balanced_v2_hard_negatives"
                and run_state.get("dataset_records", 0) >= 480
                and run_state.get("my_model_sha") == EXPECTED_TRAINING_SHA
                and run_state.get("model_revision")
                  == "0bcb35678590218655dff3765b9e61c83b35e9c4"):
            found.append(folder)
    if len(found) != 1:
        raise RuntimeError(
            f"Expected one exact known trained adapter mounted in /kaggle/input, "
            f"found {len(found)}. Attach the successful private Kaggle notebook output."
        )
    print("Verified balanced v2 trained adapter:", found[0], flush=True)
    return found[0]


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    status_file = OUTPUT / "status.json"
    status = {
        "status": "started", "evaluated": False,
        "benchmark_type": "exposed_v1_48_case_regression_not_independent_heldout",
        "promotion": "NOT_APPROVED", "github_evaluation_sha": REPO_SHA
    }
    def save():
        status_file.write_text(json.dumps(status, indent=2) + "\n")
    save()
    try:
        os.environ["CUDA_VISIBLE_DEVICES"] = "0"
        os.environ["HF_HOME"] = "/kaggle/temp/spark-eval-hf-cache"
        os.environ["TRANSFORMERS_NO_ADVISORY_WARNINGS"] = "1"
        os.environ["TOKENIZERS_PARALLELISM"] = "false"
        import torch
        if not torch.cuda.is_available():
            raise RuntimeError("Evaluation requires a Kaggle Tesla T4 accelerator")
        print("GPU:", torch.cuda.get_device_name(0), flush=True)
        adapter = find_valid_adapter()
        repo = Path("/kaggle/working/spark-eval-source")
        checkout(REPO, REPO_SHA, repo)
        fork = Path("/kaggle/working/spark-eval-llamafactory")
        checkout(FORK, FORK_SHA, fork)
        run(sys.executable, "-m", "pip", "install", "-q", "-e", fork)
        run(sys.executable, "-m", "pip", "install", "-q",
            "transformers==4.57.1", "huggingface_hub>=0.34,<1",
            "bitsandbytes>=0.45", "peft>=0.18.0,<=0.18.1", "pyyaml>=6")
        import transformers
        if transformers.__version__ != "4.57.1":
            raise RuntimeError("Transformers version mismatch")
        sys.path.insert(0, str(repo))
        from evaluation.spark_xss_benchmark import run_evaluation
        report = run_evaluation(
            adapter,
            repo / "data/training/sft_v3.jsonl",
            OUTPUT / "report.json",
        )
        report["training_variant"] = "balanced_v2_hard_negatives"
        print("RESULT_SUMMARY:", json.dumps({
            "n": report["trained"]["n"],
            "baseline": report["baseline"], "trained": report["trained"],
            "paired_contrast_accuracy": report["paired_contrast_accuracy"],
            "promotion": report["promotion_recommendation"],
        }), flush=True)
        status.update(status="success", evaluated=True,
                      training_variant="balanced_v2_hard_negatives",
                      benchmark_cases=report["trained"]["n"])
        save()
    except BaseException as exc:
        status.update(status="failed", evaluated=False,
                      error=f"{type(exc).__name__}: {exc}")
        save()
        traceback.print_exc()
        raise


if __name__ == "__main__":
    main()
