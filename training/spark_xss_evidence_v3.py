"""Evidence-only Spark v3 SFT: four independent facts, no binary verdict.

Labels come exclusively from the bounded AST analyzer on training-only local
synthetic snippets. Unsupported flow is explicitly INCONCLUSIVE and never
relabeled to safe or vulnerable. No browser-execution claims are taught.
V1/v2 adapters, frozen benchmarks and previous validation reports are not
inputs. Group-held-out dev is a smoke test, not an external acceptance suite.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path

import yaml

from xss_specialist.evidence_pipeline import review_evidence

MODEL = "XHToken/Spark-X2.5-4B"
MODEL_REVISION = "0bcb35678590218655dff3765b9e61c83b35e9c4"
TRAINING_SOURCE = "training/spark_xss_evidence_v3.py"
OUT = Path("models/spark-x25-xss-evidence-v3")
FENCE = chr(96) * 3
SOURCES = (
    "location.hash",
    "location.search",
    "document.URL",
    "window.location.href",
    "req.query.q",
)
VARIABLES = ("incomingDraft", "untrustedLabel", "queryMarker", "externalValue")
# (group, body, expected grounded verdict, split)
# All variants of a template belong to the same split. No source/sink
# strings from the previously exposed 48-case evaluation are imported.
GROUPS = (
    ("html-inner", "pane.innerHTML = $V;", "CANDIDATE", "train"),
    ("html-adjacent", "pane.insertAdjacentHTML('afterbegin', $V);", "CANDIDATE", "train"),
    ("javascript-eval", "eval($V);", "CANDIDATE", "train"),
    ("handler-setattr", "pane.setAttribute('onfocus', $V);", "CANDIDATE", "train"),
    ("safe-text", "pane.textContent = $V;", "SAFE", "train"),
    ("safe-adjacent-text", "pane.insertAdjacentText('afterbegin', $V);", "SAFE", "train"),
    ("safe-aria", "pane.setAttribute('aria-label', $V);", "SAFE", "train"),
    ("safe-overwrite", "$V = 'static'; pane.innerHTML = $V;", "SAFE", "train"),
    ("unknown-call-return", "const html = unknownTransform($V); pane.innerHTML = html;", "INCONCLUSIVE", "train"),
    ("unknown-attribute", "pane.setAttribute(dynamicName, $V);", "INCONCLUSIVE", "train"),
    ("unknown-side-effects", "sideEffect($V); pane.innerHTML = $V;", "INCONCLUSIVE", "train"),
    ("html-outer", "pane.outerHTML = $V;", "CANDIDATE", "eval"),
    ("javascript-timeout", "setTimeout($V, 500);", "CANDIDATE", "eval"),
    ("safe-inner-text", "pane.innerText = $V;", "SAFE", "eval"),
    ("safe-constant-sink", "pane.innerHTML = 'static';", "SAFE", "eval"),
    ("unknown-sanitizer", "const clean = unverifiedFilter($V); pane.innerHTML = clean;", "INCONCLUSIVE", "eval"),
    ("unknown-no-sink", "opaqueConsumer($V);", "INCONCLUSIVE", "eval"),
)
EVIDENCE_KEYS = ("snippet_sha256", "source", "flow", "sink", "defense", "limitations")
INSTRUCTION = (
    "Task: XSS_EVIDENCE_FIELDS. You are an evidence extractor, NOT the final "
    "vulnerability judge. Return one JSON object with EXACTLY the following "
    "keys: snippet_sha256, source, flow, sink, defense, limitations. "
    "Trace only observed AST-grounded source-to-sink paths. Mark unresolved "
    "flows as UNKNOWN. A text-only DOM API is safe for that local output path. "
    "An unknown sanitizer name is NOT evidence of bypass or execution. "
    "Never output Classification, XSS, SAFE, a vulnerability verdict, or "
    "browser-confirmation assertions. Do not guess. "
)


def candidate_rows() -> list[dict]:
    out = []
    for family, body, expected, split in GROUPS:
        for source in SOURCES:
            for var in VARIABLES:
                # Stable simple synthetic JavaScript with one observable source;
                # branch/loop/fetch complexity is intentionally not pretended.
                declaration = f"let {var} = {source};"
                code = declaration + "\n" + body.replace("$V", var)
                report = review_evidence(code)
                if report["decision"]["status"] != expected:
                    raise ValueError(
                        f"Unsupported training label for {family}: "
                        f"expected {expected}, AST={report['decision']['status']}: {code}"
                    )
                evidence = {key: report[key] for key in EVIDENCE_KEYS}
                prompt = (
                    INSTRUCTION + "\nSnippet SHA256: " + evidence["snippet_sha256"]
                    + "\nJavaScript:\n" + FENCE + "javascript\n" + code
                    + "\n" + FENCE + "\nOutput evidence JSON only.\n"
                )
                response = json.dumps(evidence, sort_keys=True, ensure_ascii=False)
                out.append({
                    "case_id": f"evidence-v3-{family}-{source.replace('.', '_')}-{var}",
                    "family": family,
                    "split": split,
                    "task": "XSS_EVIDENCE_FIELDS",
                    "origin": "synthetic",
                    "label_provenance": "bounded_ast_analysis_and_manual_family_expectation",
                    "expected_static_status": expected,
                    "code": code,
                    "messages": [
                        {"role": "user", "content": prompt},
                        {"role": "assistant", "content": response},
                    ],
                })
    return out


def build(output_dir: Path = OUT) -> dict:
    if not output_dir.is_absolute():
        output_dir = output_dir.resolve()
    # Refuse the repository's frozen benchmark/evaluation tree as an output.
    root = Path(__file__).resolve().parents[1]
    restricted = (
        (root / "benchmarks").resolve(),
        (root / "evaluation").resolve(),
        (root / "data/training").resolve(),
    )
    if any(output_dir.is_relative_to(path) for path in restricted):
        raise ValueError("Output cannot overwrite frozen benchmarks or any input training corpus")

    records = candidate_rows()
    ids = [r["case_id"] for r in records]
    prompts = [r["messages"][0]["content"] for r in records]
    snippets = [r["code"] for r in records]
    if any(len(seq) != len(set(seq)) for seq in (ids, prompts, snippets)):
        raise ValueError("Duplicated training examples")
    trains = [r for r in records if r["split"] == "train"]
    devs = [r for r in records if r["split"] == "eval"]
    groups_a = {r["family"] for r in trains}
    groups_b = {r["family"] for r in devs}
    if groups_a & groups_b:
        raise ValueError("Train/dev template contamination")
    for subset in (trains, devs):
        groups = Counter(r["expected_static_status"] for r in subset)
        if set(groups) != {"CANDIDATE", "SAFE", "INCONCLUSIVE"}:
            raise ValueError("All three evidence statuses required in each split")

    # The model sees requested evidence fields, NOT a static verdict.
    def to_alpaca(row):
        return {
            "instruction": row["messages"][0]["content"],
            "input": "",
            "output": row["messages"][1]["content"],
        }
    output_dir.mkdir(parents=True, exist_ok=True)

    def write(filename, value):
        raw = json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
        file = output_dir / filename
        file.write_text(raw, encoding="utf-8")
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    train_sha = write("train.json", [to_alpaca(r) for r in trains])
    dev_sha = write("eval.json", [to_alpaca(r) for r in devs])
    write("dataset_info.json", {
        "spark_evidence_v3_train": {
            "file_name": "train.json",
            "columns": {"prompt": "instruction", "query": "input", "response": "output"},
        },
        "spark_evidence_v3_eval": {
            "file_name": "eval.json",
            "columns": {"prompt": "instruction", "query": "input", "response": "output"},
        },
    })
    recipe = {
        "model_name_or_path": MODEL,
        "model_revision": MODEL_REVISION,
        "trust_remote_code": True,
        "stage": "sft",
        "do_train": True, "do_eval": True, "finetuning_type": "lora",
        "lora_target": "all", "lora_rank": 8, "lora_alpha": 16, "lora_dropout": 0.05,
        "dataset_dir": str(output_dir),
        "dataset": "spark_evidence_v3_train",
        "eval_dataset": "spark_evidence_v3_eval",
        "template": "spark", "cutoff_len": 1024,
        "gradient_checkpointing": True, "learning_rate": 1.0e-5,
        "num_train_epochs": 1.0,
        "per_device_train_batch_size": 1, "per_device_eval_batch_size": 1,
        "gradient_accumulation_steps": 8,
        "lr_scheduler_type": "cosine", "warmup_ratio": 0.1,
        "bf16": False, "fp16": True, "eval_strategy": "epoch",
        "save_strategy": "epoch", "save_total_limit": 1,
        "logging_steps": 5, "report_to": "none", "seed": 1337,
        "quantization_bit": 4, "quantization_method": "bitsandbytes",
        "quantization_type": "nf4", "double_quantization": True,
        "output_dir": str(output_dir / "adapter"),
    }
    (output_dir / "train.yaml").write_text(
        yaml.safe_dump(recipe, sort_keys=False), encoding="utf-8"
    )
    manifest = {
        "status": "DATA_PREPARED_NOT_TRAINED",
        "candidate": "spark-evidence-first-v3",
        "train": len(trains), "eval": len(devs),
        "train_sha256": train_sha, "eval_sha256": dev_sha,
        "train_groups": sorted(groups_a), "eval_groups": sorted(groups_b),
        "per_split_status_counts": {
            split: dict(Counter(r["expected_static_status"] for r in rows))
            for split, rows in (("train", trains), ("eval", devs))
        },
        "training_target": "ADVISORY_EVIDENCE_FIELDS_ONLY",
        "model_has_final_authority": False,
        "browser_confirmation_required": True,
        "promotion": "DO_NOT_PROMOTE",
    }
    write("manifest.json", manifest)
    return manifest


def main():
    import argparse
    import shutil
    import subprocess
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=OUT)
    parser.add_argument("--launch-training", action="store_true",
                        help="GPU-required training; no model promotion")
    args = parser.parse_args()
    if args.launch_training and not shutil.which("llamafactory-cli"):
        parser.error("LLaMA-Factory model-author fork must be installed")
    manifest = build(args.output_dir)
    print(json.dumps(manifest, indent=2), flush=True)
    if args.launch_training:
        if __import__("os").environ.get("CUDA_VISIBLE_DEVICES") == "-1":
            parser.error("Explicitly disabled GPU; refusing SFT")
        subprocess.run(
            ["llamafactory-cli", "train", str(args.output_dir.resolve() / "train.yaml")],
            check=True,
        )


if __name__ == "__main__":
    main()
