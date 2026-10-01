"""Train the standalone v0.4-initialized XSS flow branch on reviewed native relations."""
from __future__ import annotations

import argparse
import json
import math
import random
import time
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import accuracy_score, f1_score, precision_recall_fscore_support
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, get_linear_schedule_with_warmup

from xss_specialist.dual_branch import XSSFlowBranchModel
from xss_specialist.multitask import FLOW_LABELS


LABEL_TO_ID = {label: i for i, label in enumerate(FLOW_LABELS)}


def relation_text(row: dict) -> str:
    return (
        f"[SOURCE]\n{row['source_expression']}\n"
        f"[SINK]\n{row['sink_expression']}\n"
        f"[FLOW]\n{row['flow_excerpt']}"
    )


class RelationDataset(Dataset):
    def __init__(self, path: Path):
        self.rows = [
            json.loads(line)
            for line in path.read_text().splitlines()
            if line.strip()
        ]
        for row in self.rows:
            if row.get("task") != "FLOW_RELATION":
                raise ValueError("flow branch accepts FLOW_RELATION rows only")
            if row.get("label") not in LABEL_TO_ID:
                raise ValueError(f"unexpected flow label: {row.get('label')}")

    def __len__(self):
        return len(self.rows)

    def __getitem__(self, index):
        row = self.rows[index]
        return {
            "text": relation_text(row),
            "label": LABEL_TO_ID[row["label"]],
        }


class Collator:
    def __init__(self, tokenizer, max_length: int):
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __call__(self, rows):
        batch = self.tokenizer(
            [row["text"] for row in rows],
            padding=True,
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt",
        )
        batch["flow_labels"] = torch.tensor(
            [row["label"] for row in rows],
            dtype=torch.long,
        )
        return batch


def freeze_layers(backbone, count: int) -> None:
    embeddings = getattr(backbone, "embeddings", None)
    encoder = getattr(backbone, "encoder", None)
    layers = getattr(encoder, "layer", None)
    if layers is None:
        if count:
            raise SystemExit("freezing supports BERT-like backbones only")
        return
    if count < 0 or count > len(layers):
        raise SystemExit(f"--freeze-layers must be in 0..{len(layers)}")
    if count > 0 and embeddings is not None:
        for p in embeddings.parameters():
            p.requires_grad = False
    for layer in layers[:count]:
        for p in layer.parameters():
            p.requires_grad = False


def class_weights(dataset: RelationDataset, power: float) -> tuple[torch.Tensor, dict]:
    counts = np.zeros(len(FLOW_LABELS), dtype=np.float64)
    for row in dataset.rows:
        counts[LABEL_TO_ID[row["label"]]] += 1

    weights = np.ones(len(FLOW_LABELS), dtype=np.float32)
    present = counts > 0
    if power > 0 and present.any():
        weights[present] = 1.0 / np.power(counts[present], power)
        weights[present] /= weights[present].mean()

    report = {
        FLOW_LABELS[i]: {
            "count": int(counts[i]),
            "weight": float(weights[i]),
        }
        for i in range(len(FLOW_LABELS))
    }
    return torch.tensor(weights, dtype=torch.float32), report


def evaluate(model, loader, device):
    model.eval()
    truth, pred, losses = [], [], []

    with torch.no_grad():
        for batch in loader:
            batch = {k: v.to(device) for k, v in batch.items()}
            out = model(**batch)
            if out.loss is not None:
                losses.append(float(out.loss.detach().cpu()))
            values = out.logits["flow"].argmax(dim=-1)
            truth.extend(batch["flow_labels"].cpu().tolist())
            pred.extend(values.cpu().tolist())

    labels = list(range(len(FLOW_LABELS)))
    macro = f1_score(truth, pred, labels=labels, average="macro", zero_division=0)
    precision, recall, f1, support = precision_recall_fscore_support(
        truth,
        pred,
        labels=labels,
        zero_division=0,
    )
    return {
        "loss": float(np.mean(losses)) if losses else None,
        "macro_f1": float(macro),
        "accuracy": float(accuracy_score(truth, pred)),
        "per_class": {
            FLOW_LABELS[i]: {
                "precision": float(precision[i]),
                "recall": float(recall[i]),
                "f1": float(f1[i]),
                "support": int(support[i]),
            }
            for i in labels
        },
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--backbone", type=Path, required=True)
    p.add_argument("--train", type=Path, required=True)
    p.add_argument("--dev", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--epochs", type=int, default=8)
    p.add_argument("--batch-size", type=int, default=32)
    p.add_argument("--max-length", type=int, default=128)
    p.add_argument("--lr", type=float, default=2e-5)
    p.add_argument("--freeze-layers", type=int, default=0)
    p.add_argument("--class-balance-power", type=float, default=0.0)
    p.add_argument("--seed", type=int, default=6061)
    args = p.parse_args()

    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)

    train = RelationDataset(args.train)
    dev = RelationDataset(args.dev)
    tokenizer = AutoTokenizer.from_pretrained(args.backbone)
    model = XSSFlowBranchModel(str(args.backbone))
    freeze_layers(model.backbone, args.freeze_layers)

    weights, weight_report = class_weights(train, args.class_balance_power)
    model.configure_class_weights(weights)

    collate = Collator(tokenizer, args.max_length)
    train_loader = DataLoader(
        train,
        batch_size=args.batch_size,
        shuffle=True,
        generator=torch.Generator().manual_seed(args.seed),
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

    params = [p for p in model.parameters() if p.requires_grad]
    optimizer = torch.optim.AdamW(params, lr=args.lr, weight_decay=0.01)
    total_steps = max(1, args.epochs * len(train_loader))
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=max(1, math.ceil(total_steps * 0.08)),
        num_training_steps=total_steps,
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    best = -1.0
    history = []
    started = time.time()

    for epoch in range(1, args.epochs + 1):
        model.train()
        losses = []
        for batch in train_loader:
            batch = {k: v.to(device) for k, v in batch.items()}
            optimizer.zero_grad(set_to_none=True)
            out = model(**batch)
            if out.loss is None:
                continue
            out.loss.backward()
            torch.nn.utils.clip_grad_norm_(params, 1.0)
            optimizer.step()
            scheduler.step()
            losses.append(float(out.loss.detach().cpu()))

        dev_metrics = evaluate(model, dev_loader, device)
        row = {
            "epoch": epoch,
            "train_loss": float(np.mean(losses)) if losses else None,
            "dev": dev_metrics,
        }
        history.append(row)
        print(json.dumps(row, indent=2))

        if dev_metrics["macro_f1"] > best:
            best = float(dev_metrics["macro_f1"])
            model.save(args.output_dir)
            tokenizer.save_pretrained(args.output_dir / "flow_backbone")
            (args.output_dir / "best_metrics.json").write_text(
                json.dumps(row, indent=2) + "\n"
            )

    report = {
        "schema": "xss-flow-branch-training-v2",
        "architecture": "standalone-v04-flow-branch",
        "backbone_source": str(args.backbone),
        "labels": FLOW_LABELS,
        "train_rows": len(train),
        "dev_rows": len(dev),
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "max_length": args.max_length,
        "learning_rate": args.lr,
        "freeze_layers": args.freeze_layers,
        "class_balance_power": args.class_balance_power,
        "class_weights": weight_report,
        "seed": args.seed,
        "best_macro_f1": best,
        "history": history,
        "runtime_seconds": round(time.time() - started, 2),
        "device": str(device),
        "whole_snippet_classifier_loss": False,
        "locked_external_used": False,
        "final_judge": False,
        "promotion_allowed": False,
        "note": "Flow relation advisor only; static/browser authority is unchanged.",
    }
    (args.output_dir / "training_report.json").write_text(
        json.dumps(report, indent=2) + "\n"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
