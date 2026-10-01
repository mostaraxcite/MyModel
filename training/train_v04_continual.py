"""Continual fine-tuning for the promoted v0.4 XSS checkpoint only.

This path deliberately does not reopen the retired whole-snippet training series.
It accepts a local v0.4-compatible BertForSequenceClassification checkpoint,
uses low-LR rehearsal, and can freeze lower encoder layers to reduce forgetting.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import numpy as np
from datasets import Dataset
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
EXPECTED_MODEL_TYPE = "bert"
EXPECTED_HIDDEN = 256
EXPECTED_LAYERS = 4


def read_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def load_split(path: Path) -> Dataset:
    rows = read_rows(path)
    return Dataset.from_dict({
        "text": [r["code"] for r in rows],
        "label": [LABEL_TO_ID[r["label"]] for r in rows],
    })


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_v04_checkpoint(model_dir: Path) -> dict:
    config_path = model_dir / "config.json"
    if not config_path.exists():
        raise SystemExit(f"v0.4 checkpoint missing config.json: {model_dir}")
    cfg = json.loads(config_path.read_text())
    if cfg.get("model_type") != EXPECTED_MODEL_TYPE:
        raise SystemExit(f"expected BERT v0.4 checkpoint, got {cfg.get('model_type')}")
    if int(cfg.get("hidden_size", -1)) != EXPECTED_HIDDEN:
        raise SystemExit(f"expected v0.4 hidden_size={EXPECTED_HIDDEN}")
    if int(cfg.get("num_hidden_layers", -1)) != EXPECTED_LAYERS:
        raise SystemExit(f"expected v0.4 num_hidden_layers={EXPECTED_LAYERS}")
    id2label = {int(k): v for k, v in cfg.get("id2label", {}).items()}
    if id2label and id2label != ID_TO_LABEL:
        raise SystemExit(f"unexpected label mapping: {id2label}")
    return cfg


def freeze_lower_layers(model, count: int) -> None:
    if count < 0 or count > EXPECTED_LAYERS:
        raise SystemExit(f"--freeze-layers must be in 0..{EXPECTED_LAYERS}")
    if count == 0:
        return
    if not hasattr(model, "bert"):
        raise SystemExit("v0.4 continual trainer only supports BertForSequenceClassification")
    for param in model.bert.embeddings.parameters():
        param.requires_grad = False
    for layer in model.bert.encoder.layer[:count]:
        for param in layer.parameters():
            param.requires_grad = False


def metrics(eval_pred) -> dict:
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    macro = f1_score(labels, preds, average="macro", zero_division=0)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, labels=list(range(len(LABELS))), zero_division=0
    )
    out = {"macro_f1": float(macro), "min_class_recall": float(min(recall))}
    for i, label in enumerate(LABELS):
        key = label.lower()
        out[f"{key}_precision"] = float(precision[i])
        out[f"{key}_recall"] = float(recall[i])
        out[f"{key}_f1"] = float(f1[i])
    return out


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--model-dir", type=Path, required=True)
    p.add_argument("--train-data", type=Path, required=True)
    p.add_argument("--validation-data", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--run-name", default="xss-v0.4.1-continual")
    p.add_argument("--epochs", type=float, default=1.0)
    p.add_argument("--batch-size", type=int, default=32)
    p.add_argument("--max-length", type=int, default=128)
    p.add_argument("--lr", type=float, default=5e-6)
    p.add_argument("--weight-decay", type=float, default=0.01)
    p.add_argument("--freeze-layers", type=int, default=2)
    p.add_argument("--seed", type=int, default=1337)
    args = p.parse_args()

    if args.max_length != 128:
        raise SystemExit("v0.4 continual path requires max_length=128 for distribution compatibility")
    validate_v04_checkpoint(args.model_dir)

    tokenizer = AutoTokenizer.from_pretrained(args.model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(args.model_dir)
    freeze_lower_layers(model, args.freeze_layers)

    train_set = load_split(args.train_data)
    validation_set = load_split(args.validation_data)

    def tokenize(batch: dict) -> dict:
        return tokenizer(batch["text"], truncation=True, max_length=128)

    train_set = train_set.map(tokenize, batched=True, remove_columns=["text"])
    validation_set = validation_set.map(tokenize, batched=True, remove_columns=["text"])

    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total = sum(p.numel() for p in model.parameters())

    args.output_dir.mkdir(parents=True, exist_ok=True)
    train_args = TrainingArguments(
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
        args=train_args,
        train_dataset=train_set,
        eval_dataset=validation_set,
        data_collator=DataCollatorWithPadding(tokenizer=tokenizer),
        compute_metrics=metrics,
    )
    trainer.train()
    trainer.save_model(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)
    final_eval = trainer.evaluate()

    metadata = {
        "run_name": args.run_name,
        "training": "v0.4_continual_finetune",
        "source_checkpoint": str(args.model_dir),
        "epochs": args.epochs,
        "learning_rate": args.lr,
        "freeze_layers": args.freeze_layers,
        "max_length": 128,
        "batch_size": args.batch_size,
        "seed": args.seed,
        "train_rows": len(train_set),
        "validation_rows": len(validation_set),
        "train_sha256": sha256(args.train_data),
        "validation_sha256": sha256(args.validation_data),
        "trainable_parameters": trainable,
        "total_parameters": total,
        "trainable_fraction": trainable / total if total else 0.0,
        "runtime_seconds": round(time.time() - started, 2),
        "best_metric": trainer.state.best_metric,
        "final_eval": final_eval,
        "locked_external_used_for_training": False,
    }
    (args.output_dir / "training_metadata.json").write_text(
        json.dumps(metadata, indent=2, default=str) + "\n", encoding="utf-8"
    )
    print(json.dumps(metadata, indent=2, default=str))


if __name__ == "__main__":
    main()
