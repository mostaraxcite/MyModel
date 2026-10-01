"""Train the direct-PyTorch XSS multi-task specialist.

This trainer starts from a v0.4-compatible checkpoint, discards the legacy
three-way classifier head, and learns independent structural heads. It never
uses a whole-snippet SAFE/XSS loss.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import time
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import f1_score, accuracy_score
from torch.utils.data import Dataset, DataLoader, WeightedRandomSampler
from transformers import AutoTokenizer, get_linear_schedule_with_warmup

from xss_specialist.multitask import (
    XSSMultiTaskModel,
    LABEL_SPACES,
    IGNORE_INDEX,
)


TASKS = tuple(LABEL_SPACES)


class JsonlDataset(Dataset):
    def __init__(self, path: Path):
        self.rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def __len__(self):
        return len(self.rows)

    def __getitem__(self, index):
        return self.rows[index]


class Collator:
    def __init__(self, tokenizer, max_length: int):
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __call__(self, rows):
        batch = self.tokenizer(
            [r["text"] for r in rows],
            padding=True,
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt",
        )
        for task in TASKS:
            batch[f"{task}_labels"] = torch.tensor(
                [int(r[f"{task}_label"]) for r in rows], dtype=torch.long
            )
        return batch


def evaluate(model, loader, device):
    model.eval()
    truth = {task: [] for task in TASKS}
    pred = {task: [] for task in TASKS}
    losses = []

    with torch.no_grad():
        for batch in loader:
            batch = {k: v.to(device) for k, v in batch.items()}
            out = model(**batch)
            if out.loss is not None:
                losses.append(float(out.loss.detach().cpu()))
            for task in TASKS:
                labels = batch[f"{task}_labels"]
                mask = labels.ne(IGNORE_INDEX)
                if not mask.any():
                    continue
                values = out.logits[task].argmax(dim=-1)
                truth[task].extend(labels[mask].cpu().tolist())
                pred[task].extend(values[mask].cpu().tolist())

    metrics = {"loss": float(np.mean(losses)) if losses else None, "tasks": {}}
    scores = []
    for task in TASKS:
        if not truth[task]:
            metrics["tasks"][task] = {"count": 0, "macro_f1": None, "accuracy": None}
            continue
        present_labels = sorted(set(truth[task]))
        present_f1 = f1_score(
            truth[task],
            pred[task],
            labels=present_labels,
            average="macro",
            zero_division=0,
        )
        full_space_f1 = f1_score(
            truth[task],
            pred[task],
            labels=list(range(len(LABEL_SPACES[task]))),
            average="macro",
            zero_division=0,
        )
        acc = accuracy_score(truth[task], pred[task])
        metrics["tasks"][task] = {
            "count": len(truth[task]),
            "present_labels": [LABEL_SPACES[task][i] for i in present_labels],
            "macro_f1": float(present_f1),
            "full_space_macro_f1": float(full_space_f1),
            "accuracy": float(acc),
        }
        scores.append(float(present_f1))

    # Flow matters most because it captures the relation the legacy classifier
    # could not reliably generalize. Keep a transparent weighted score.
    weights = {"source": 0.20, "sink": 0.20, "defense": 0.20, "flow": 0.40}
    available = [
        (task, metrics["tasks"][task]["macro_f1"])
        for task in TASKS
        if metrics["tasks"][task]["macro_f1"] is not None
    ]
    denom = sum(weights[t] for t, _ in available)
    metrics["weighted_macro_f1"] = (
        sum(weights[t] * value for t, value in available) / denom if denom else 0.0
    )
    return metrics


def freeze_backbone_layers(model: XSSMultiTaskModel, count: int) -> None:
    bert = getattr(model.backbone, "encoder", None)
    embeddings = getattr(model.backbone, "embeddings", None)
    if not hasattr(model.backbone, "encoder") or not hasattr(model.backbone.encoder, "layer"):
        if count:
            raise SystemExit("layer freezing currently supports BERT-like backbones only")
        return
    layers = model.backbone.encoder.layer
    if count < 0 or count > len(layers):
        raise SystemExit(f"--freeze-layers must be in 0..{len(layers)}")
    if count > 0 and embeddings is not None:
        for p in embeddings.parameters():
            p.requires_grad = False
    for layer in layers[:count]:
        for p in layer.parameters():
            p.requires_grad = False


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--backbone", type=Path, required=True,
                   help="v0.4-compatible checkpoint directory")
    p.add_argument("--train-data", type=Path, required=True)
    p.add_argument("--dev-data", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--epochs", type=int, default=5)
    p.add_argument("--batch-size", type=int, default=32)
    p.add_argument("--max-length", type=int, default=128)
    p.add_argument("--lr", type=float, default=1e-5)
    p.add_argument("--weight-decay", type=float, default=0.01)
    p.add_argument("--freeze-layers", type=int, default=1)
    p.add_argument("--flow-sample-weight", type=float, default=8.0)
    p.add_argument("--source-loss-weight", type=float, default=0.5)
    p.add_argument("--sink-loss-weight", type=float, default=2.0)
    p.add_argument("--defense-loss-weight", type=float, default=2.5)
    p.add_argument("--flow-loss-weight", type=float, default=1.5)
    p.add_argument("--class-balance-power", type=float, default=0.35)
    p.add_argument("--seed", type=int, default=4041)
    args = p.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)

    tokenizer = AutoTokenizer.from_pretrained(args.backbone)
    model = XSSMultiTaskModel(str(args.backbone))
    freeze_backbone_layers(model, args.freeze_layers)

    train = JsonlDataset(args.train_data)
    dev = JsonlDataset(args.dev_data)

    task_loss_weights = {
        "source": args.source_loss_weight,
        "sink": args.sink_loss_weight,
        "defense": args.defense_loss_weight,
        "flow": args.flow_loss_weight,
    }

    class_weights = {}
    class_weight_report = {}
    for task, labels in LABEL_SPACES.items():
        counts = np.zeros(len(labels), dtype=np.float64)
        key = f"{task}_label"
        for row in train.rows:
            value = int(row[key])
            if value != IGNORE_INDEX:
                counts[value] += 1.0

        weights_for_task = np.zeros(len(labels), dtype=np.float32)
        present = counts > 0
        if present.any():
            weights_for_task[present] = 1.0 / np.power(
                counts[present], args.class_balance_power
            )
            weights_for_task[present] /= weights_for_task[present].mean()
        class_weights[task] = torch.tensor(weights_for_task, dtype=torch.float32)
        class_weight_report[task] = {
            labels[i]: {
                "count": int(counts[i]),
                "weight": float(weights_for_task[i]),
            }
            for i in range(len(labels))
        }

    model.configure_losses(
        task_loss_weights=task_loss_weights,
        class_weights=class_weights,
    )

    weights = []
    for row in train.rows:
        weight = args.flow_sample_weight if int(row["flow_label"]) != IGNORE_INDEX else 1.0
        weights.append(weight)

    generator = torch.Generator()
    generator.manual_seed(args.seed)
    sampler = WeightedRandomSampler(
        weights=weights,
        num_samples=len(train),
        replacement=True,
        generator=generator,
    )

    collate = Collator(tokenizer, args.max_length)
    train_loader = DataLoader(
        train,
        batch_size=args.batch_size,
        sampler=sampler,
        collate_fn=collate,
    )
    dev_loader = DataLoader(
        dev,
        batch_size=args.batch_size * 2,
        shuffle=False,
        collate_fn=collate,
    )

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    trainable = [p for p in model.parameters() if p.requires_grad]
    optimizer = torch.optim.AdamW(trainable, lr=args.lr, weight_decay=args.weight_decay)
    steps = max(1, args.epochs * len(train_loader))
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=max(1, math.ceil(steps * 0.08)),
        num_training_steps=steps,
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    best = -1.0
    history = []
    started = time.time()

    for epoch in range(1, args.epochs + 1):
        model.train()
        epoch_losses = []
        for batch in train_loader:
            batch = {k: v.to(device) for k, v in batch.items()}
            optimizer.zero_grad(set_to_none=True)
            out = model(**batch)
            if out.loss is None:
                continue
            out.loss.backward()
            torch.nn.utils.clip_grad_norm_(trainable, 1.0)
            optimizer.step()
            scheduler.step()
            epoch_losses.append(float(out.loss.detach().cpu()))

        dev_metrics = evaluate(model, dev_loader, device)
        row = {
            "epoch": epoch,
            "train_loss": float(np.mean(epoch_losses)) if epoch_losses else None,
            "dev": dev_metrics,
        }
        history.append(row)
        print(json.dumps(row, indent=2))

        score = float(dev_metrics["weighted_macro_f1"])
        if score > best:
            best = score
            model.save(args.output_dir)
            tokenizer.save_pretrained(args.output_dir / "backbone")
            (args.output_dir / "best_metrics.json").write_text(
                json.dumps(row, indent=2) + "\n"
            )

    final = {
        "schema": "xss-multitask-training-v1",
        "architecture": "direct-pytorch-multitask",
        "backbone_source": str(args.backbone),
        "whole_snippet_classifier_loss": False,
        "tasks": LABEL_SPACES,
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "max_length": args.max_length,
        "learning_rate": args.lr,
        "freeze_layers": args.freeze_layers,
        "flow_sample_weight": args.flow_sample_weight,
        "task_loss_weights": task_loss_weights,
        "class_balance_power": args.class_balance_power,
        "class_weights": class_weight_report,
        "seed": args.seed,
        "train_rows": len(train),
        "dev_rows": len(dev),
        "best_weighted_macro_f1": best,
        "history": history,
        "runtime_seconds": round(time.time() - started, 2),
        "device": str(device),
        "promotion_allowed": False,
        "note": "Component model only; browser/deterministic evidence remains final authority.",
    }
    (args.output_dir / "training_report.json").write_text(json.dumps(final, indent=2) + "\n")
    print(json.dumps(final, indent=2))


if __name__ == "__main__":
    main()
