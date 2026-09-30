"""Full fine-tune a compact encoder for three-way XSS classification.

This is the controlled successor to the v0.4 training recipe. Unlike the
PEFT/LoRA path, the encoder is not frozen. It is intended for small encoders
where updating all parameters is still practical and gives the classifier
enough capacity to learn source/sink/sanitizer boundaries.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import numpy as np
from datasets import Dataset, concatenate_datasets
from sklearn.metrics import f1_score, precision_recall_fscore_support
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
)

LABELS = ["SAFE", "POSSIBLE_XSS", "XSS"]
LABEL_TO_ID = {label: i for i, label in enumerate(LABELS)}
ID_TO_LABEL = {i: label for label, i in LABEL_TO_ID.items()}


def read_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def load_split(path: Path) -> Dataset:
    rows = read_rows(path)
    return Dataset.from_dict({
        "text": [row["code"] for row in rows],
        "label": [LABEL_TO_ID[row["label"]] for row in rows],
    })


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def metrics(eval_pred) -> dict:
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    macro = f1_score(labels, preds, average="macro", zero_division=0)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, labels=list(range(len(LABELS))), zero_division=0
    )
    result = {"macro_f1": float(macro), "min_class_recall": float(min(recall))}
    for i, label in enumerate(LABELS):
        key = label.lower()
        result[f"{key}_precision"] = float(precision[i])
        result[f"{key}_recall"] = float(recall[i])
        result[f"{key}_f1"] = float(f1[i])
    return result


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--model", default="google/bert_uncased_L-4_H-256_A-4")
    p.add_argument("--train-data", type=Path, required=True)
    p.add_argument("--validation-data", type=Path, required=True)
    p.add_argument("--extra-train-data", type=Path, default=None)
    p.add_argument("--extra-validation-data", type=Path, default=None)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--run-name", default="xss-full-finetune")
    p.add_argument("--epochs", type=float, default=5)
    p.add_argument("--batch-size", type=int, default=32)
    p.add_argument("--max-length", type=int, default=128)
    p.add_argument("--lr", type=float, default=3e-5)
    p.add_argument("--weight-decay", type=float, default=0.01)
    p.add_argument("--seed", type=int, default=1337)
    args = p.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model,
        num_labels=len(LABELS),
        id2label=ID_TO_LABEL,
        label2id=LABEL_TO_ID,
    )

    train_set = load_split(args.train_data)
    validation_set = load_split(args.validation_data)
    extra_train_rows = 0
    extra_validation_rows = 0

    if args.extra_train_data:
        extra = load_split(args.extra_train_data)
        extra_train_rows = len(extra)
        train_set = concatenate_datasets([train_set, extra])

    if args.extra_validation_data:
        extra_val = load_split(args.extra_validation_data)
        extra_validation_rows = len(extra_val)
        validation_set = concatenate_datasets([validation_set, extra_val])

    def tokenize(batch: dict) -> dict:
        return tokenizer(batch["text"], truncation=True, max_length=args.max_length)

    train_set = train_set.map(tokenize, batched=True, remove_columns=["text"])
    validation_set = validation_set.map(tokenize, batched=True, remove_columns=["text"])

    args.output_dir.mkdir(parents=True, exist_ok=True)
    config = TrainingArguments(
        output_dir=str(args.output_dir),
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=args.lr,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size * 2,
        num_train_epochs=args.epochs,
        weight_decay=args.weight_decay,
        load_best_model_at_end=True,
        metric_for_best_model="macro_f1",
        greater_is_better=True,
        report_to="none",
        seed=args.seed,
        dataloader_pin_memory=False,
        logging_steps=50,
    )

    started = time.time()
    trainer = Trainer(
        model=model,
        args=config,
        train_dataset=train_set,
        eval_dataset=validation_set,
        data_collator=DataCollatorWithPadding(tokenizer=tokenizer),
        compute_metrics=metrics,
    )
    trainer.train()
    trainer.save_model(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)

    final_eval = trainer.evaluate()
    record = {
        "run_name": args.run_name,
        "training": "full_finetune",
        "base_model": args.model,
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "max_length": args.max_length,
        "learning_rate": args.lr,
        "weight_decay": args.weight_decay,
        "seed": args.seed,
        "train_rows": len(train_set),
        "validation_rows": len(validation_set),
        "extra_train_rows": extra_train_rows,
        "extra_validation_rows": extra_validation_rows,
        "train_sha256": sha256(args.train_data),
        "validation_sha256": sha256(args.validation_data),
        "runtime_seconds": round(time.time() - started, 2),
        "best_metric": trainer.state.best_metric,
        "final_eval": final_eval,
        "external_test_v5_used_for_training": False,
    }
    (args.output_dir / "training_metadata.json").write_text(
        json.dumps(record, indent=2, default=str) + "\n", encoding="utf-8"
    )
    print(json.dumps(record, indent=2, default=str))


if __name__ == "__main__":
    main()
