"""Independent XSS benchmark: paired model inference and auditable metrics.

Runs only on an authorized GPU with the frozen Kaggle adapter mounted.
No target scanning, autonomous promotion, or training. Requires 4-bit CUDA.
The primary metric is a controlled first-label probability, not browser proof.
"""
from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
import re
from typing import Any

from evaluation.spark_xss_heldout import SYSTEM, assert_no_training_overlap, cases

GOLD = {"safe", "vulnerable"}
EXPECTED_BASE_REVISION = "0bcb35678590218655dff3765b9e61c83b35e9c4"
EXPECTED_TRAINING_SHA = "a112ec7c4db50e19c40de95f5f35a804d9fdf6fb"


def classification_metrics(golds: list[str], predictions: list[str]) -> dict[str, Any]:
    """Treat invalid/abstained prediction as incorrect; cannot game metrics."""
    if len(golds) != len(predictions) or not golds:
        raise ValueError("gold and prediction vectors must be same nonzero size")
    if any(g not in GOLD for g in golds):
        raise ValueError("Unknown ground truth")
    tp = tn = fp = fn = abstained = 0
    for gold, pred in zip(golds, predictions):
        if pred not in GOLD:
            abstained += 1
            if gold == "safe":
                fp += 1  # conservative: error on benign code counts against FPR
            else:
                fn += 1
        elif gold == "vulnerable" and pred == "vulnerable":
            tp += 1
        elif gold == "safe" and pred == "safe":
            tn += 1
        elif gold == "safe":
            fp += 1
        else:
            fn += 1
    divide = lambda num, den: num / den if den else 0.0
    precision = divide(tp, tp + fp)
    recall = divide(tp, tp + fn)
    return {
        "n": len(golds), "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "abstained": abstained,
        "accuracy": divide(tp + tn, len(golds)),
        "precision": precision, "recall": recall,
        "f1": divide(2 * precision * recall, precision + recall),
        "fpr": divide(fp, fp + tn), "fnr": divide(fn, fn + tp),
        "balanced_accuracy": (divide(tp, tp + fn) + divide(tn, tn + fp)) / 2,
    }


def score_report(items: list[dict], baseline: list[dict], tuned: list[dict]) -> dict:
    if len(items) != len(baseline) or len(items) != len(tuned):
        raise ValueError("Incomplete model comparison: report is invalid")
    ids = [item["id"] for item in items]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate case identifiers")
    for preds in (baseline, tuned):
        if [x["id"] for x in preds] != ids:
            raise ValueError("Predictions must align with frozen test case IDs")
    golds = [x["label"] for x in items]
    b = classification_metrics(golds, [x["prediction"] for x in baseline])
    t = classification_metrics(golds, [x["prediction"] for x in tuned])
    groups: dict[str, list[int]] = defaultdict(list)
    for i, item in enumerate(items):
        groups[item["family"]].append(i)
    family_metrics = {}
    for name, indexes in groups.items():
        family_metrics[name] = {
            "base": classification_metrics([golds[i] for i in indexes],
                                           [baseline[i]["prediction"] for i in indexes]),
            "trained": classification_metrics([golds[i] for i in indexes],
                                              [tuned[i]["prediction"] for i in indexes]),
        }
    pairs: dict[str, dict[str, dict]] = {}
    for item, guess in zip(items, tuned):
        stem = re.sub(r"-(?:unsafe|safe)$", "", item["id"])
        pairs.setdefault(stem, {})[item["label"]] = guess
    pair_pass = sum(
        "safe" in pair and "vulnerable" in pair
        and pair["safe"]["prediction"] == "safe"
        and pair["vulnerable"]["prediction"] == "vulnerable"
        for pair in pairs.values()
    )
    return {
        "benchmark_type": "frozen-synthetic-static-code-review-not-runtime-confirmed",
        "baseline": b, "trained": t,
        "family_metrics": family_metrics,
        "paired_contrast_accuracy": pair_pass / len(pairs) if pairs else 0.0,
        "paired_contrast_correct": pair_pass, "paired_contrast_total": len(pairs),
        "delta_fpr": t["fpr"] - b["fpr"],
        "delta_recall": t["recall"] - b["recall"],
        "promotion_recommendation": "DO_NOT_PROMOTE",
        "promotion_reason": "Static synthetic benchmark cannot establish real-world XSS or runtime-confirmed findings.",
        "cases": [
            {"id": case["id"], "family": case["family"], "gold": case["label"],
             "base": base["prediction"], "adapted": fine["prediction"],
             "base_prob_unsafe": base.get("p_vulnerable"),
             "adapted_prob_unsafe": fine.get("p_vulnerable")}
            for case, base, fine in zip(items, baseline, tuned)
        ],
    }


def spark_input(prompt: str) -> str:
    """Replicate the LLaMA-Factory Spark template visible in Kaggle training logs."""
    return (
        "<｜start▁of▁sentence｜><|System|>\n" + SYSTEM
        + "<｜end▁of▁sentence｜><｜start▁of▁sentence｜><|User|>"
        + prompt + "<｜end▁of▁sentence｜><｜start▁of▁sentence｜><|Bot|></think>Classification:"
    )


def predict_label(model, tokenizer, prompt: str) -> dict:
    """Controlled, reproducible label-first-token ranking (not free generation)."""
    import torch
    prefix = spark_input(prompt)
    encoded = tokenizer(prefix, return_tensors="pt", add_special_tokens=False)
    gpu = next(model.parameters()).device
    encoded = {k: v.to(gpu) for k, v in encoded.items()}
    variants = {
        label: tokenizer.encode(" " + label, add_special_tokens=False)
        for label in sorted(GOLD)
    }
    if not all(variants.values()):
        raise RuntimeError("Tokenizer failed to encode comparison labels")
    # Both labels are expected to be single tokens for Spark; if that changes,
    # evaluate complete candidate sequence log-likelihood rather than silently
    # comparing only a shared prefix or using a biased partial target.
    with torch.inference_mode():
        if all(len(ids) == 1 for ids in variants.values()):
            logits = model(**encoded, use_cache=False).logits[0, -1].float()
            pair = torch.stack((logits[variants["safe"][0]],
                                logits[variants["vulnerable"][0]]))
        else:
            scores = {}
            for label, ids in variants.items():
                prompt_ids = encoded["input_ids"]
                combined = torch.cat(
                    (prompt_ids, torch.tensor([ids[:-1]], device=gpu)), dim=1
                )
                outputs = model(input_ids=combined, use_cache=False).logits
                start = prompt_ids.size(1) - 1
                positions = outputs[0, start : start + len(ids)].float()
                targets = torch.tensor(ids, device=gpu)
                scores[label] = torch.log_softmax(positions, dim=-1).gather(
                    1, targets.unsqueeze(1)
                ).sum() / len(ids)
            pair = torch.stack((scores["safe"], scores["vulnerable"]))
        p = torch.softmax(pair, dim=0)
    return {
        "prediction": "vulnerable" if float(p[1]) >= 0.5 else "safe",
        "p_vulnerable": float(p[1]),
        "method": "forced-next-token-conditional-probability",
    }


def run_evaluation(adapter: Path, training_file: Path, destination: Path) -> dict:
    """Actual side-effecting CUDA evaluation invoked by Kaggle kernel only."""
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
    from peft import PeftModel

    if not torch.cuda.is_available():
        raise RuntimeError("Kaggle GPU required for true paired model comparison")
    if not (adapter / "adapter_config.json").is_file():
        raise FileNotFoundError("Trained adapter_config.json missing")
    if not (adapter / "adapter_model.safetensors").is_file():
        raise FileNotFoundError("Trained adapter_model.safetensors missing")
    manifest = assert_no_training_overlap(training_file)
    test = cases()
    cfg = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_use_double_quant=True,
                             bnb_4bit_compute_dtype=torch.float16)
    name = "XHToken/Spark-X2.5-4B"
    tok = AutoTokenizer.from_pretrained(name, revision=EXPECTED_BASE_REVISION,
                                        trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        name, revision=EXPECTED_BASE_REVISION, trust_remote_code=True,
        torch_dtype=torch.float16, quantization_config=cfg, device_map={"": 0},
    ).eval()
    baseline = []
    for i, item in enumerate(test, 1):
        pred = predict_label(model, tok, item["prompt"])
        baseline.append({"id": item["id"], **pred})
        print(f"BASE {i}/{len(test)} {item['id']} predicted={pred['prediction']}", flush=True)
    adapted = PeftModel.from_pretrained(model, str(adapter), is_trainable=False).eval()
    tuned = []
    for i, item in enumerate(test, 1):
        pred = predict_label(adapted, tok, item["prompt"])
        tuned.append({"id": item["id"], **pred})
        print(f"TUNED {i}/{len(test)} {item['id']} predicted={pred['prediction']}", flush=True)
    report = score_report(test, baseline, tuned)
    report["corpus_integrity"] = manifest
    report["adapter_source"] = str(adapter)
    report["base_revision"] = EXPECTED_BASE_REVISION
    report["expected_training_source_sha"] = EXPECTED_TRAINING_SHA
    report["scoring_method"] = "controlled next-token classification; not natural-language-generation or browser execution"
    report["actual_browser_confirmations"] = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    return report
