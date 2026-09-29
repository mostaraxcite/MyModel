"""Experimental Qwen causal-LM trainer; not the official v0.5 training path."""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import AutoModelForCausalLM, AutoTokenizer, Trainer, TrainingArguments


DEFAULT_MODEL = "Qwen/Qwen3.5-0.8B-Base"


def load_rows(path: Path, limit: int | None = None) -> list[dict]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    return rows[:limit] if limit else rows


def render(rows: list[dict], tokenizer, max_length: int) -> Dataset:
    encoded = []
    for row in rows:
        text = tokenizer.apply_chat_template(row["messages"], tokenize=False, add_generation_prompt=False)
        item = tokenizer(text, truncation=True, max_length=max_length)
        item["labels"] = item["input_ids"].copy()
        encoded.append(item)
    return Dataset.from_list(encoded)


class CausalCollator:
    def __init__(self, tokenizer):
        self.tokenizer = tokenizer

    def __call__(self, features: list[dict]) -> dict:
        labels = [feature.pop("labels") for feature in features]
        batch = self.tokenizer.pad(features, padding=True, return_tensors="pt")
        width = batch["input_ids"].shape[1]
        batch["labels"] = torch.tensor(
            [label + [-100] * (width - len(label)) for label in labels], dtype=torch.long
        )
        return batch


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--train", type=Path, default=Path("data/training/sft.jsonl"))
    parser.add_argument("--validation", type=Path, default=Path("data/training/mlx/valid.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("models/adapters/xss-lora-v1"))
    parser.add_argument("--epochs", type=float, default=1.0)
    parser.add_argument("--max-length", type=int, default=384)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--rank", type=int, default=8)
    parser.add_argument("--use-4bit", action="store_true")
    args = parser.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    tokenizer.pad_token = tokenizer.pad_token or tokenizer.eos_token
    model_kwargs = {"dtype": torch.float16 if torch.cuda.is_available() else torch.float32}
    if args.use_4bit:
        from transformers import BitsAndBytesConfig
        model_kwargs["quantization_config"] = BitsAndBytesConfig(load_in_4bit=True)
        model_kwargs["device_map"] = "auto"
    model = AutoModelForCausalLM.from_pretrained(args.model, **model_kwargs)
    if args.use_4bit:
        model = prepare_model_for_kbit_training(model)
    model.gradient_checkpointing_enable()
    model.config.use_cache = False
    config = LoraConfig(
        r=args.rank,
        lora_alpha=args.rank * 2,
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    )
    model = get_peft_model(model, config)

    train_rows = load_rows(args.train, args.limit)
    valid_rows = load_rows(args.validation, max(2, (args.limit or 100) // 10))
    training = render(train_rows, tokenizer, args.max_length)
    validation = render(valid_rows, tokenizer, args.max_length)
    run = TrainingArguments(
        output_dir=str(args.output),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=1,
        per_device_eval_batch_size=1,
        gradient_accumulation_steps=16,
        learning_rate=2e-4,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        fp16=torch.cuda.is_available(),
        gradient_checkpointing=True,
        dataloader_pin_memory=False,
        report_to="none",
    )
    started = time.time()
    trainer = Trainer(
        model=model,
        args=run,
        train_dataset=training,
        eval_dataset=validation,
        data_collator=CausalCollator(tokenizer),
    )
    trainer.train()
    args.output.mkdir(parents=True, exist_ok=True)
    trainer.model.save_pretrained(args.output)
    tokenizer.save_pretrained(args.output)
    record = {
        "base_model": args.model,
        "adapter": "PEFT LoRA",
        "rank": args.rank,
        "train_rows": len(train_rows),
        "validation_rows": len(valid_rows),
        "external_test_v5_used_for_training": False,
        "runtime_seconds": round(time.time() - started, 2),
        "training_sha256": hashlib.sha256(args.train.read_bytes()).hexdigest(),
    }
    (args.output / "training_record.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
