"""PEFT LoRA trainer for an encoder-based XSS classifier (v0.5+).

The base model is frozen; only LoRA adapters on q/k/v plus the 3-class
classification head are trained. This keeps the trainable parameter count small
enough to run on CPU while still adapting the encoder to the XSS classification
task. The resulting adapter is saved with `peft.save_pretrained` so it can be
loaded back via `adapter_registry` together with the base model name.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import numpy as np
import torch
from datasets import Dataset, concatenate_datasets
from peft import LoraConfig, TaskType, get_peft_model
from sklearn.metrics import f1_score, precision_recall_fscore_support
from sklearn.utils.class_weight import compute_class_weight
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
)


LABELS = ["SAFE", "POSSIBLE_XSS", "XSS"]
LABEL_TO_ID = {label: index for index, label in enumerate(LABELS)}
ID_TO_LABEL = {index: label for label, index in LABEL_TO_ID.items()}
DEFAULT_BASE_MODEL = "nreimers/MiniLM-L6-H384-uncased"


# MiniLM-L6 uses BERT-style attention. Keep targets deliberately precise:
# the suffix "dense" also matches feed-forward/output layers in BERT-family
# encoders, so using it would adapt more modules than intended.
DEFAULT_LORA_TARGETS = ["query", "key", "value"]


def parse_lora_targets(raw: str | None) -> list[str]:
    """Parse a comma-separated PEFT target list without mutating the default."""
    if raw is None:
        return list(DEFAULT_LORA_TARGETS)
    targets = [item.strip() for item in raw.split(",") if item.strip()]
    if not targets:
        raise ValueError("--target-modules must contain at least one module name")
    return targets


def _safe_load_jsonl(path: Path, limit: int | None = None) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        rows.append(json.loads(line))
        if limit and len(rows) >= limit:
            break
    return rows


def _filter_partition(rows: list[dict], partitions: set[str] | None) -> list[dict]:
    if not partitions:
        return rows
    return [row for row in rows if row.get("provenance", {}).get("partition") in partitions]


def load_classification_split(
    path: Path,
    partitions: set[str] | None = None,
    limit: int | None = None,
    sample_weight: float = 1.0,
) -> Dataset:
    rows = _filter_partition(_safe_load_jsonl(path, limit=limit), partitions)
    return Dataset.from_dict(
        {
            "text": [row["code"] for row in rows],
            "label": [LABEL_TO_ID[row["label"]] for row in rows],
            "sample_weight": [float(sample_weight)] * len(rows),
        }
    )


class WeightedLossTrainer(Trainer):
    """Trainer that reweights cross-entropy by inverse class frequency.

    Without this, MiniLM-L6 collapses to predicting the majority class
    (XSS, ~42% of train). POSSIBLE_XSS is the minority (~19%) and gets
    swallowed. The class weight vector normalises to mean=1 so the loss
    scale stays comparable.
    """

    def __init__(self, *args, class_weights: torch.Tensor | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self._class_weights = class_weights

    def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
        labels = inputs.pop("labels")
        sample_weight = inputs.pop("sample_weight", None)
        outputs = model(**inputs)
        logits = outputs.logits
        class_weight = self._class_weights.to(logits.device) if self._class_weights is not None else None
        per_item = torch.nn.functional.cross_entropy(
            logits, labels, weight=class_weight, reduction="none"
        )
        if sample_weight is not None:
            sw = sample_weight.to(logits.device, dtype=per_item.dtype)
            loss = (per_item * sw).sum() / sw.sum().clamp_min(1e-8)
        else:
            loss = per_item.mean()
        return (loss, outputs) if return_outputs else loss


def compute_class_weights(train_dataset: Dataset, mode: str = "balanced") -> torch.Tensor | None:
    """Return class weights with controllable strength.

    balanced = inverse-frequency weights (legacy behavior)
    sqrt     = square-root of inverse-frequency weights (gentler)
    none     = ordinary cross-entropy
    """
    if mode == "none":
        return None
    labels = np.array(train_dataset["label"], dtype=int)
    counts = np.bincount(labels, minlength=len(LABELS)).astype(float)
    present = counts > 0
    weights = np.ones(len(LABELS), dtype=float)
    if present.any():
        weights[present] = len(labels) / (present.sum() * counts[present])
        if mode == "sqrt":
            weights[present] = np.sqrt(weights[present])
        elif mode != "balanced":
            raise ValueError(f"unsupported class weight mode: {mode}")
        weights[present] /= weights[present].mean()
    return torch.tensor(weights, dtype=torch.float32)


def compute_metrics(eval_pred) -> dict:
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    macro_f1 = f1_score(labels, preds, average="macro", zero_division=0)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, labels=list(range(len(LABELS))), zero_division=0
    )
    per_class = {
        LABELS[index]: {
            "precision": float(precision[index]),
            "recall": float(recall[index]),
            "f1": float(f1[index]),
        }
        for index in range(len(LABELS))
    }
    return {
        "macro_f1": float(macro_f1),
        "safe_recall": float(recall[LABEL_TO_ID["SAFE"]]),
        "possible_xss_recall": float(recall[LABEL_TO_ID["POSSIBLE_XSS"]]),
        "xss_recall": float(recall[LABEL_TO_ID["XSS"]]),
        "min_class_recall": float(min(recall)),
        "per_class": per_class,
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-model", default=DEFAULT_BASE_MODEL)
    parser.add_argument("--train-data", type=Path, default=Path("security-models/xss/data/train.jsonl"))
    parser.add_argument("--validation-data", type=Path, default=Path("security-models/xss/data/validation.jsonl"))
    parser.add_argument("--output-dir", type=Path, default=Path("security-models/xss/adapters/xss-v06"))
    parser.add_argument("--epochs", type=float, default=2.0)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--seed", type=int, default=2027)
    parser.add_argument("--rank", type=int, default=8)
    parser.add_argument("--alpha", type=int, default=16)
    parser.add_argument("--dropout", type=float, default=0.05)
    parser.add_argument("--lr", type=float, default=2e-4)
    parser.add_argument("--train-limit", type=int, default=0, help="0 = use all rows")
    parser.add_argument("--validation-limit", type=int, default=0)
    parser.add_argument("--extra-train-data", type=Path, default=None)
    parser.add_argument("--extra-train-weight", type=float, default=1.0)
    parser.add_argument("--extra-train-copies", type=int, default=1)
    parser.add_argument("--extra-validation-data", type=Path, default=None)
    parser.add_argument("--extra-validation-copies", type=int, default=1)
    parser.add_argument(
        "--class-weight-mode",
        choices=("none", "sqrt", "balanced"),
        default="balanced",
        help="Strength of inverse-frequency class weighting.",
    )
    parser.add_argument("--adapter-name", default="xss-v06")
    parser.add_argument(
        "--target-modules",
        default=None,
        help="Comma-separated PEFT target module suffixes. Defaults to query,key,value.",
    )
    args = parser.parse_args()
    target_modules = parse_lora_targets(args.target_modules)

    torch.manual_seed(args.seed)

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    base = AutoModelForSequenceClassification.from_pretrained(
        args.base_model,
        num_labels=len(LABELS),
        id2label=ID_TO_LABEL,
        label2id=LABEL_TO_ID,
    )

    lora_config = LoraConfig(
        task_type=TaskType.SEQ_CLS,
        r=args.rank,
        lora_alpha=args.alpha,
        lora_dropout=args.dropout,
        bias="none",
        target_modules=target_modules,
        modules_to_save=["classifier"],  # keep classifier head fully trainable
    )

    model = get_peft_model(base, lora_config)
    model.print_trainable_parameters()

    train_set = load_classification_split(
        args.train_data,
        limit=args.train_limit or None,
    )
    validation_set = load_classification_split(
        args.validation_data,
        limit=args.validation_limit or None,
    )

    extra_train_rows = 0
    extra_validation_rows = 0
    if args.extra_train_data:
        extra = load_classification_split(
            args.extra_train_data,
            sample_weight=args.extra_train_weight,
        )
        extra_train_rows = len(extra)
        if args.extra_train_copies < 1:
            raise ValueError("--extra-train-copies must be >= 1")
        train_set = concatenate_datasets([train_set] + [extra] * args.extra_train_copies)

    if args.extra_validation_data:
        extra_val = load_classification_split(args.extra_validation_data)
        extra_validation_rows = len(extra_val)
        if args.extra_validation_copies < 1:
            raise ValueError("--extra-validation-copies must be >= 1")
        validation_set = concatenate_datasets(
            [validation_set] + [extra_val] * args.extra_validation_copies
        )

    def tokenize(batch: dict) -> dict:
        return tokenizer(batch["text"], truncation=True, max_length=args.max_length)

    train_set = train_set.map(tokenize, batched=True, remove_columns=["text"])
    validation_set = validation_set.map(tokenize, batched=True, remove_columns=["text"])

    class_weights = compute_class_weights(train_set, args.class_weight_mode)
    print(
        "class weight mode:",
        args.class_weight_mode,
        "weights:",
        class_weights.tolist() if class_weights is not None else None,
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    run = TrainingArguments(
        output_dir=str(args.output_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size * 2,
        learning_rate=args.lr,
        weight_decay=0.01,
        warmup_steps=int((len(train_set) * args.epochs / args.batch_size) * 0.1),
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="macro_f1",
        greater_is_better=True,
        report_to="none",
        seed=args.seed,
        dataloader_pin_memory=False,
        fp16=False,  # CPU only
        logging_steps=50,
    )

    started = time.time()
    trainer = WeightedLossTrainer(
        model=model,
        args=run,
        train_dataset=train_set,
        eval_dataset=validation_set,
        data_collator=DataCollatorWithPadding(tokenizer=tokenizer),
        compute_metrics=compute_metrics,
        class_weights=class_weights,
    )
    trainer.train()

    # Persist the LoRA adapter (NOT the base weights). The base is recovered by
    # name from the registry so the base stays replaceable.
    model.save_pretrained(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)

    record = {
        "adapter_name": args.adapter_name,
        "base_model": args.base_model,
        "task": "xss-3way-classification",
        "labels": LABELS,
        "lora": {
            "rank": args.rank,
            "alpha": args.alpha,
            "dropout": args.dropout,
            "target_modules": target_modules,
            "modules_to_save": ["classifier"],
        },
        "train_rows": len(train_set),
        "validation_rows": len(validation_set),
        "base_train_path": str(args.train_data),
        "base_validation_path": str(args.validation_data),
        "extra_train_data": str(args.extra_train_data) if args.extra_train_data else None,
        "extra_train_rows_unique": extra_train_rows,
        "extra_train_weight": args.extra_train_weight,
        "extra_train_copies": args.extra_train_copies,
        "extra_validation_data": str(args.extra_validation_data) if args.extra_validation_data else None,
        "extra_validation_rows_unique": extra_validation_rows,
        "extra_validation_copies": args.extra_validation_copies,
        "class_weight_mode": args.class_weight_mode,
        "class_weights": class_weights.tolist() if class_weights is not None else None,
        "training_sha256": _sha256(args.train_data),
        "validation_sha256": _sha256(args.validation_data),
        "external_test_v5_used_for_training": False,
        "seed": args.seed,
        "runtime_seconds": round(time.time() - started, 2),
        "trainer_history": trainer.state.log_history,
        "best_metric": trainer.state.best_metric,
    }
    (args.output_dir / "adapter_metadata.json").write_text(
        json.dumps(record, indent=2, default=str) + "\n", encoding="utf-8"
    )
    print(json.dumps({"adapter_metadata": str(args.output_dir / "adapter_metadata.json")}))
    print(json.dumps(record, indent=2, default=str))


if __name__ == "__main__":
    main()
