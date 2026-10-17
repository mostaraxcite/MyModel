"""Kaggle GPU entry point for Spark evidence-only v3 QLoRA candidate.

Separate from v1/v2 checkpoint. Train ONLY advisory evidence fields, not a
binary XSS label. No production/model promotion or live site scanning.

Generated kernel contains a pinned MyModel commit; it fetches the exact
public source revision. It does not scan websites or publish models.
Running this script on Kaggle consumes the account's free GPU quota.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import traceback


REPO_URL = "https://github.com/mostaraxcite/MyModel.git"
REPO_SHA = "__MYMODEL_SHA__"  # replaced only by scripts/build_kaggle_xss_kernel.py
FORK_URL = "https://github.com/XHToken/LlamaFactory.git"
FORK_SHA = "f56888d47dc5681e15b83ddbea01adddf2050adf"
MODEL_ID = "XHToken/Spark-X2.5-4B"
# The Spark author training guide supports Transformers 4.57.1. In Kaggle v4,
# the fork resolved Transformers 5.8.0, which requires a dict for
# `_tied_weights_keys`, while Spark remote model code still supplies a list.
# Do not silently use Transformers 5.x for this experimental training path.
TRANSFORMERS_VERSION = "4.57.1"
KAGGLE_ROOT = Path("/kaggle/working")
RESULTS = KAGGLE_ROOT / "spark-schema-v15-result"


def run(*cmd: str, cwd: Path | None = None) -> None:
    print("Running:", " ".join(cmd), flush=True)
    subprocess.run(list(cmd), cwd=str(cwd) if cwd else None, check=True)


def prepare_checkout() -> Path:
    if not re.fullmatch(r"[0-9a-f]{40}", REPO_SHA):
        raise ValueError("Missing pinned MyModel commit. Run build_kaggle_xss_kernel.py first.")
    folder = KAGGLE_ROOT / "my-model-source"
    if folder.exists():
        raise FileExistsError("Refusing to reuse a stale MyModel checkout")
    run("git", "init", str(folder))
    run("git", "remote", "add", "origin", REPO_URL, cwd=folder)
    run("git", "fetch", "--depth", "1", "origin", REPO_SHA, cwd=folder)
    run("git", "checkout", "--detach", "FETCH_HEAD", cwd=folder)
    actual = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=folder, text=True
    ).strip()
    if actual != REPO_SHA:
        raise RuntimeError(f"Expected MyModel commit {REPO_SHA}, got {actual}")
    return folder


def check_gpu() -> dict:
    # Kaggle's T4x2 means two independent 16 GB cards, not one 32 GB device.
    os.environ["CUDA_VISIBLE_DEVICES"] = "0"
    os.environ["NPROC_PER_NODE"] = "1"
    import torch

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA GPU unavailable: enable Kaggle Accelerator > GPU T4 x2")
    name = torch.cuda.get_device_name(0)
    available_mb = torch.cuda.get_device_properties(0).total_memory // (1024 * 1024)
    capability = torch.cuda.get_device_capability(0)
    info = {"gpu": name, "vram_mib": available_mb,
            "cuda_capability": list(capability), "visible_gpus": 1}
    print("GPU:", json.dumps(info), flush=True)
    if available_mb < 14500 or capability[0] < 7:
        raise RuntimeError("Requires >= ~15 GiB VRAM and CUDA compute capability >=7.0")
    return info


def install_training_deps() -> None:
    # Install the model-author's confirmed Spark-aware training fork by commit.
    folder = KAGGLE_ROOT / "spark-llamafactory"
    run("git", "init", str(folder))
    run("git", "remote", "add", "origin", FORK_URL, cwd=folder)
    run("git", "fetch", "--depth", "1", "origin", FORK_SHA, cwd=folder)
    run("git", "checkout", "--detach", "FETCH_HEAD", cwd=folder)
    run(sys.executable, "-m", "pip", "install", "-q", "-e", str(folder))
    run(sys.executable, "-m", "pip", "install", "-q",
        f"transformers=={TRANSFORMERS_VERSION}",
        "bitsandbytes>=0.45", "huggingface_hub>=0.34,<1", "pyyaml>=6")
    # Fail before downloading a multi-GB model if Kaggle pip resolves 5.x again.
    import transformers
    print("Pinned Transformers version:", transformers.__version__, flush=True)
    if transformers.__version__ != TRANSFORMERS_VERSION:
        raise RuntimeError(
            f"Spark requires transformers=={TRANSFORMERS_VERSION}; "
            f"installed: {transformers.__version__}"
        )


def main() -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    state = {
        "status": "started",
        "training_started": False,
        "model_promoted": False,
        "my_model_sha": REPO_SHA,
        "framework_sha": FORK_SHA,
        "model_id": MODEL_ID,
        "training_variant": "schema_explicit_v15",
    }
    state_path = RESULTS / "run_status.json"

    def save_status() -> None:
        state_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")

    save_status()
    try:
        gpu = check_gpu()
        state["gpu_info"] = gpu
        save_status()
        repo = prepare_checkout()
        # The AST labeller must be available BEFORE data preparation.
        install_training_deps()
        run(sys.executable, "-m", "pip", "install", "-q",
            "tree-sitter>=0.24,<1", "tree-sitter-javascript>=0.23,<1")
        output = RESULTS / "training"
        cmd = [
            sys.executable, "-m", "training.spark_schema_v15",
            "--output-dir", str(output),
        ]
        run(*cmd, cwd=repo)
        manifest = json.loads((output / "manifest.json").read_text())
        if (manifest.get("train") != 220 or manifest.get("eval") != 120
                or manifest.get("training_target") != "ADVISORY_EVIDENCE_FIELDS_ONLY"
                or manifest.get("promotion") != "DO_NOT_PROMOTE"):
            raise RuntimeError("Evidence-only dataset integrity gate failed")
        state["train_sha256"] = manifest["train_sha256"]
        state["eval_sha256"] = manifest["eval_sha256"]
        state["training_rows"] = manifest["train"]
        state["eval_rows"] = manifest["eval"]
        state["model_has_final_authority"] = False
        save_status()
        from huggingface_hub import HfApi

        # Resolves and records a real, immutable model revision at runtime.
        revision = HfApi().model_info(MODEL_ID).sha
        if not re.fullmatch(r"[0-9a-f]{40}", revision or ""):
            raise RuntimeError("Could not resolve pinned Hugging Face Spark revision")
        state["model_revision"] = revision
        save_status()

        # v3 recipe already generated above. Check HF revision before launching
        # the separate adapter; never pick up a moving upstream model.
        if revision != "0bcb35678590218655dff3765b9e61c83b35e9c4":
            raise RuntimeError("Base Spark revision unexpectedly changed")
        # Optional explicit preflight mode: never trains.
        if os.environ.get("SPARK_XSS_PREPARE_ONLY", "").lower() in ("1", "true"):
            state["status"] = "prepared_not_trained"
        else:
            os.environ["DISABLE_VERSION_CHECK"] = "1"
            os.environ["TOKENIZERS_PARALLELISM"] = "false"
            os.environ["HF_HOME"] = "/kaggle/temp/spark-hf-cache"
            state["training_started"] = True
            state["status"] = "training"
            save_status()
            run(*cmd, "--launch-training", cwd=repo)
            adapter = output / "adapter"
            if not adapter.is_dir() or not (adapter / "adapter_config.json").is_file():
                raise RuntimeError("Training returned success but adapter_config.json was not produced")
            state["status"] = "candidate_saved_not_evaluated"
            state["adapter_path"] = str(adapter)

        state["promotion"] = "DO_NOT_PROMOTE"
        if state["training_started"]:
            sys.path.insert(0, str(repo))
            from evaluation.spark_schema_v15_eval import run_gpu
            report = run_gpu(output / "adapter", RESULTS / "evaluation.json")
            state["evaluation_complete"] = True
            state["status"] = "candidate_saved_evaluated_internal_only"
            print("V15_MODEL_REPORT=" + json.dumps(report, separators=(",", ":")), flush=True)
        state["browser_confirmation_required"] = True
        save_status()
    except Exception as exc:
        state["status"] = "failed"
        state["error"] = f"{type(exc).__name__}: {exc}"
        save_status()
        print(traceback.format_exc(), flush=True)
        raise


if __name__ == "__main__":
    main()

