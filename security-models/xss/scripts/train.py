"""Fine-tune a compact encoder for three-way XSS classification."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
from datasets import Dataset
from sklearn.metrics import f1_score
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


def load(path: Path) -> Dataset:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    return Dataset.from_dict({"text": [r["code"] for r in rows], "label": [LABEL_TO_ID[r["label"]] for r in rows]})


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=root / "data")
    parser.add_argument("--output-dir", type=Path, default=root / "model")
    parser.add_argument("--model", default="google/bert_uncased_L-4_H-256_A-4")
    parser.add_argument("--epochs", type=float, default=3)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model, num_labels=3, id2label=ID_TO_LABEL, label2id=LABEL_TO_ID
    )
    train_set, validation_set = load(args.data_dir / "train.jsonl"), load(args.data_dir / "validation.jsonl")

    def tokenize(batch: dict) -> dict:
        return tokenizer(batch["text"], truncation=True, max_length=128)

    train_set = train_set.map(tokenize, batched=True, remove_columns=["text"])
    validation_set = validation_set.map(tokenize, batched=True, remove_columns=["text"])

    def metrics(result) -> dict:
        predictions = np.argmax(result.predictions, axis=-1)
        return {"macro_f1": f1_score(result.label_ids, predictions, average="macro")}

    config = TrainingArguments(
        output_dir=str(args.output_dir),
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=3e-5,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size * 2,
        num_train_epochs=args.epochs,
        weight_decay=0.01,
        load_best_model_at_end=True,
        metric_for_best_model="macro_f1",
        report_to="none",
        seed=args.seed,
        dataloader_pin_memory=False,
    )
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


if __name__ == "__main__":
    main()
