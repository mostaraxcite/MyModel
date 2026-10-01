"""Train the isolated dual-branch XSS structural model.

Semantic and flow branches are optimized with separate loaders, optimizers, and
schedulers. No flow gradient can update the semantic encoder and no semantic
gradient can update the flow encoder.
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
from sklearn.metrics import accuracy_score, f1_score
from torch.utils.data import Dataset, DataLoader, RandomSampler
from transformers import AutoTokenizer, get_linear_schedule_with_warmup

from xss_specialist.dual_branch import (
    XSSDualBranchModel,
    SEMANTIC_LABEL_SPACES,
    LABEL_SPACES,
)
from xss_specialist.multitask import IGNORE_INDEX


SEMANTIC_TASKS = tuple(SEMANTIC_LABEL_SPACES)
TASKS = tuple(LABEL_SPACES)


class RowsDataset(Dataset):
    def __init__(self, rows):
        self.rows = list(rows)

    def __len__(self):
        return len(self.rows)

    def __getitem__(self, index):
        return self.rows[index]


def read_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


class SemanticCollator:
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
        for task in SEMANTIC_TASKS:
            batch[f"{task}_labels"] = torch.tensor(
                [int(r[f"{task}_label"]) for r in rows],
                dtype=torch.long,
            )
        return batch


class FlowCollator:
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
        batch["flow_labels"] = torch.tensor(
            [int(r["flow_label"]) for r in rows],
            dtype=torch.long,
        )
        return batch


def class_weights(rows, task: str, power: float):
    labels = LABEL_SPACES[task]
    counts = np.zeros(len(labels), dtype=np.float64)
    key = f"{task}_label"
    for row in rows:
        value = int(row[key])
        if value != IGNORE_INDEX:
            counts[value] += 1.0

    weights = np.zeros(len(labels), dtype=np.float32)
    present = counts > 0
    if present.any():
        weights[present] = 1.0 / np.power(counts[present], power)
        weights[present] /= weights[present].mean()

    report = {
        labels[i]: {"count": int(counts[i]), "weight": float(weights[i])}
        for i in range(len(labels))
    }
    return torch.tensor(weights, dtype=torch.float32), report


def freeze_bert_layers(backbone, count: int):
    embeddings = getattr(backbone, "embeddings", None)
    encoder = getattr(backbone, "encoder", None)
    layers = getattr(encoder, "layer", None)
    if layers is None:
        if count:
            raise SystemExit("layer freezing supports BERT-like encoders only")
        return
    if count < 0 or count > len(layers):
        raise SystemExit(f"freeze count must be in 0..{len(layers)}")
    if count > 0 and embeddings is not None:
        for p in embeddings.parameters():
            p.requires_grad = False
    for layer in layers[:count]:
        for p in layer.parameters():
            p.requires_grad = False


def metric_block(truth, pred, task):
    present = sorted(set(truth))
    present_f1 = f1_score(
        truth, pred, labels=present, average="macro", zero_division=0
    )
    full_f1 = f1_score(
        truth,
        pred,
        labels=list(range(len(LABEL_SPACES[task]))),
        average="macro",
        zero_division=0,
    )
    return {
        "count": len(truth),
        "present_labels": [LABEL_SPACES[task][i] for i in present],
        "macro_f1": float(present_f1),
        "full_space_macro_f1": float(full_f1),
        "accuracy": float(accuracy_score(truth, pred)),
    }


def evaluate(model, semantic_loader, flow_loader, device):
    model.eval()
    truth = {task: [] for task in TASKS}
    pred = {task: [] for task in TASKS}
    sem_losses = []
    flow_losses = []

    with torch.no_grad():
        for batch in semantic_loader:
            batch = {k: v.to(device) for k, v in batch.items()}
            out = model.forward_semantic(**batch)
            if out.loss is not None:
                sem_losses.append(float(out.loss.detach().cpu()))
            for task in SEMANTIC_TASKS:
                labels = batch[f"{task}_labels"]
                mask = labels.ne(IGNORE_INDEX)
                if not mask.any():
                    continue
                values = out.logits[task].argmax(dim=-1)
                truth[task].extend(labels[mask].cpu().tolist())
                pred[task].extend(values[mask].cpu().tolist())

        for batch in flow_loader:
            batch = {k: v.to(device) for k, v in batch.items()}
            out = model.forward_flow(**batch)
            if out.loss is not None:
                flow_losses.append(float(out.loss.detach().cpu()))
            labels = batch["flow_labels"]
            mask = labels.ne(IGNORE_INDEX)
            values = out.logits["flow"].argmax(dim=-1)
            truth["flow"].extend(labels[mask].cpu().tolist())
            pred["flow"].extend(values[mask].cpu().tolist())

    tasks = {task: metric_block(truth[task], pred[task], task) for task in TASKS}
    weights = {"source": 0.20, "sink": 0.20, "defense": 0.20, "flow": 0.40}
    weighted = sum(weights[t] * tasks[t]["macro_f1"] for t in TASKS)
    return {
        "semantic_loss": float(np.mean(sem_losses)) if sem_losses else None,
        "flow_loss": float(np.mean(flow_losses)) if flow_losses else None,
        "tasks": tasks,
        "weighted_macro_f1": float(weighted),
    }


def make_scheduler(optimizer, epochs, loader_len):
    steps = max(1, epochs * loader_len)
    return get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=max(1, math.ceil(steps * 0.08)),
        num_training_steps=steps,
    )


def train_one_epoch(model, loader, optimizer, scheduler, params, device, branch):
    losses = []
    if branch == "semantic":
        model.semantic_backbone.train()
        model.semantic_heads.train()
        forward = model.forward_semantic
    else:
        model.flow_backbone.train()
        model.flow_head.train()
        forward = model.forward_flow

    for batch in loader:
        batch = {k: v.to(device) for k, v in batch.items()}
        optimizer.zero_grad(set_to_none=True)
        out = forward(**batch)
        if out.loss is None:
            continue
        out.loss.backward()
        torch.nn.utils.clip_grad_norm_(params, 1.0)
        optimizer.step()
        scheduler.step()
        losses.append(float(out.loss.detach().cpu()))
    return float(np.mean(losses)) if losses else None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--backbone", type=Path, required=True)
    p.add_argument("--train-data", type=Path, required=True)
    p.add_argument("--dev-data", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--epochs", type=int, default=8)
    p.add_argument("--batch-size", type=int, default=32)
    p.add_argument("--max-length", type=int, default=128)
    p.add_argument("--semantic-lr", type=float, default=2e-5)
    p.add_argument("--flow-lr", type=float, default=2e-5)
    p.add_argument("--semantic-freeze-layers", type=int, default=0)
    p.add_argument("--flow-freeze-layers", type=int, default=0)
    p.add_argument("--flow-repeat", type=int, default=16)
    p.add_argument("--source-loss-weight", type=float, default=0.5)
    p.add_argument("--sink-loss-weight", type=float, default=2.0)
    p.add_argument("--defense-loss-weight", type=float, default=2.5)
    p.add_argument("--semantic-class-power", type=float, default=0.35)
    p.add_argument("--flow-class-power", type=float, default=0.0)
    p.add_argument("--seed", type=int, default=5051)
    args = p.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)

    rows = read_jsonl(args.train_data)
    dev_rows = read_jsonl(args.dev_data)

    semantic_rows = [
        row for row in rows
        if any(int(row[f"{task}_label"]) != IGNORE_INDEX for task in SEMANTIC_TASKS)
    ]
    flow_rows = [
        row for row in rows if int(row["flow_label"]) != IGNORE_INDEX
    ]
    semantic_dev = [
        row for row in dev_rows
        if any(int(row[f"{task}_label"]) != IGNORE_INDEX for task in SEMANTIC_TASKS)
    ]
    flow_dev = [
        row for row in dev_rows if int(row["flow_label"]) != IGNORE_INDEX
    ]

    if not semantic_rows or not flow_rows or not semantic_dev or not flow_dev:
        raise SystemExit("dual-branch training requires semantic and flow train/dev rows")

    tokenizer = AutoTokenizer.from_pretrained(args.backbone)
    model = XSSDualBranchModel(str(args.backbone))

    freeze_bert_layers(model.semantic_backbone, args.semantic_freeze_layers)
    freeze_bert_layers(model.flow_backbone, args.flow_freeze_layers)

    class_weight_map = {}
    class_weight_report = {}
    for task in SEMANTIC_TASKS:
        tensor, report = class_weights(
            semantic_rows, task, args.semantic_class_power
        )
        class_weight_map[task] = tensor
        class_weight_report[task] = report
    flow_tensor, flow_report = class_weights(
        flow_rows, "flow", args.flow_class_power
    )
    class_weight_map["flow"] = flow_tensor
    class_weight_report["flow"] = flow_report

    semantic_task_weights = {
        "source": args.source_loss_weight,
        "sink": args.sink_loss_weight,
        "defense": args.defense_loss_weight,
    }
    model.configure_losses(
        semantic_task_weights=semantic_task_weights,
        class_weights=class_weight_map,
    )

    sem_collate = SemanticCollator(tokenizer, args.max_length)
    flow_collate = FlowCollator(tokenizer, args.max_length)

    generator = torch.Generator().manual_seed(args.seed)
    semantic_loader = DataLoader(
        RowsDataset(semantic_rows),
        batch_size=args.batch_size,
        shuffle=True,
        generator=generator,
        collate_fn=sem_collate,
    )

    # Flow data is intentionally repeated inside its isolated branch. Repetition
    # cannot steal semantic batches or alter semantic gradients.
    repeated_flow = flow_rows * max(1, args.flow_repeat)
    flow_loader = DataLoader(
        RowsDataset(repeated_flow),
        batch_size=args.batch_size,
        shuffle=True,
        generator=torch.Generator().manual_seed(args.seed + 1),
        collate_fn=flow_collate,
    )

    semantic_dev_loader = DataLoader(
        RowsDataset(semantic_dev),
        batch_size=args.batch_size * 2,
        shuffle=False,
        collate_fn=sem_collate,
    )
    flow_dev_loader = DataLoader(
        RowsDataset(flow_dev),
        batch_size=args.batch_size * 2,
        shuffle=False,
        collate_fn=flow_collate,
    )

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    semantic_params = [p for p in model.semantic_parameters() if p.requires_grad]
    flow_params = [p for p in model.flow_parameters() if p.requires_grad]

    semantic_optimizer = torch.optim.AdamW(
        semantic_params, lr=args.semantic_lr, weight_decay=0.01
    )
    flow_optimizer = torch.optim.AdamW(
        flow_params, lr=args.flow_lr, weight_decay=0.01
    )
    semantic_scheduler = make_scheduler(
        semantic_optimizer, args.epochs, len(semantic_loader)
    )
    flow_scheduler = make_scheduler(
        flow_optimizer, args.epochs, len(flow_loader)
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    best = -1.0
    history = []
    started = time.time()

    for epoch in range(1, args.epochs + 1):
        semantic_train_loss = train_one_epoch(
            model,
            semantic_loader,
            semantic_optimizer,
            semantic_scheduler,
            semantic_params,
            device,
            "semantic",
        )
        flow_train_loss = train_one_epoch(
            model,
            flow_loader,
            flow_optimizer,
            flow_scheduler,
            flow_params,
            device,
            "flow",
        )

        dev = evaluate(
            model, semantic_dev_loader, flow_dev_loader, device
        )
        row = {
            "epoch": epoch,
            "semantic_train_loss": semantic_train_loss,
            "flow_train_loss": flow_train_loss,
            "dev": dev,
        }
        history.append(row)
        print(json.dumps(row, indent=2))

        score = float(dev["weighted_macro_f1"])
        if score > best:
            best = score
            model.save(args.output_dir)
            tokenizer.save_pretrained(args.output_dir / "semantic_backbone")
            tokenizer.save_pretrained(args.output_dir / "flow_backbone")
            (args.output_dir / "best_metrics.json").write_text(
                json.dumps(row, indent=2) + "\n"
            )

    final = {
        "schema": "xss-dual-branch-training-v2",
        "architecture": "dual-encoder-isolated-branches",
        "backbone_source": str(args.backbone),
        "whole_snippet_classifier_loss": False,
        "branches_share_trainable_parameters": False,
        "semantic_tasks": list(SEMANTIC_TASKS),
        "flow_task": "flow",
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "max_length": args.max_length,
        "semantic_lr": args.semantic_lr,
        "flow_lr": args.flow_lr,
        "semantic_freeze_layers": args.semantic_freeze_layers,
        "flow_freeze_layers": args.flow_freeze_layers,
        "flow_repeat": args.flow_repeat,
        "semantic_task_weights": semantic_task_weights,
        "semantic_class_power": args.semantic_class_power,
        "flow_class_power": args.flow_class_power,
        "class_weights": class_weight_report,
        "semantic_train_rows": len(semantic_rows),
        "flow_train_rows": len(flow_rows),
        "semantic_dev_rows": len(semantic_dev),
        "flow_dev_rows": len(flow_dev),
        "best_weighted_macro_f1": best,
        "history": history,
        "runtime_seconds": round(time.time() - started, 2),
        "device": str(device),
        "promotion_allowed": False,
        "next_gate": "independent real XSS corpus plus deterministic/browser integration",
        "note": "Structural component only; deterministic/browser evidence remains final authority.",
    }
    (args.output_dir / "training_report.json").write_text(
        json.dumps(final, indent=2) + "\n"
    )
    print(json.dumps(final, indent=2))


if __name__ == "__main__":
    main()
