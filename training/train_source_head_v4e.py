"""Fine-tune only the source head of the validated v4d checkpoint.

The semantic backbone and sink/defense heads are frozen. External v6 is sealed
and is never read by this training path.
"""
from __future__ import annotations
import argparse, json, math, random, time
from pathlib import Path

import numpy as np
import torch
from sklearn.metrics import accuracy_score, f1_score
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer, get_linear_schedule_with_warmup

from xss_specialist.dual_branch import XSSDualBranchModel, SEMANTIC_LABEL_SPACES
from xss_specialist.multitask import IGNORE_INDEX


class Rows(Dataset):
    def __init__(self,path:Path):
        self.rows=[json.loads(x) for x in path.read_text().splitlines() if x.strip()]
    def __len__(self): return len(self.rows)
    def __getitem__(self,i): return self.rows[i]


class Collator:
    def __init__(self,tok,max_length): self.tok,self.max_length=tok,max_length
    def __call__(self,rows):
        b=self.tok([r["text"] for r in rows],padding=True,truncation=True,
                   max_length=self.max_length,return_tensors="pt")
        for t in ("source","sink","defense"):
            b[f"{t}_labels"]=torch.tensor(
                [int(r[f"{t}_label"]) for r in rows],dtype=torch.long
            )
        return b


def only_source_rows(rows:Rows):
    return [r for r in rows.rows if int(r["source_label"]) != IGNORE_INDEX]


def metrics(model,loader,device):
    truth={t:[] for t in ("source","sink","defense")}
    pred={t:[] for t in ("source","sink","defense")}
    model.eval()
    with torch.no_grad():
        for batch in loader:
            batch={k:v.to(device) for k,v in batch.items()}
            out=model.forward_semantic(**batch)
            for t in truth:
                y=batch[f"{t}_labels"]; mask=y.ne(IGNORE_INDEX)
                if not mask.any(): continue
                p=out.logits[t].argmax(-1)
                truth[t].extend(y[mask].cpu().tolist())
                pred[t].extend(p[mask].cpu().tolist())
    result={}
    for t in truth:
        labels=SEMANTIC_LABEL_SPACES[t]
        ids=list(range(len(labels)))
        result[t]={
            "macro_f1":float(f1_score(truth[t],pred[t],labels=ids,average="macro",zero_division=0)),
            "accuracy":float(accuracy_score(truth[t],pred[t])),
            "per_class_f1":{
                labels[i]:float(f1_score(truth[t],pred[t],labels=[i],average="macro",zero_division=0))
                for i in ids
            },
        }
    result["mean_macro_f1"]=float(np.mean([result[t]["macro_f1"] for t in ("source","sink","defense")]))
    return result


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--checkpoint",type=Path,required=True)
    p.add_argument("--train",type=Path,required=True)
    p.add_argument("--dev",type=Path,required=True)
    p.add_argument("--output-dir",type=Path,required=True)
    p.add_argument("--epochs",type=int,default=8)
    p.add_argument("--batch-size",type=int,default=64)
    p.add_argument("--max-length",type=int,default=96)
    p.add_argument("--lr",type=float,default=2e-4)
    p.add_argument("--seed",type=int,default=10112)
    a=p.parse_args()

    random.seed(a.seed); np.random.seed(a.seed); torch.manual_seed(a.seed)
    base_train=Rows(a.train); dev=Rows(a.dev)
    source_train=only_source_rows(base_train)
    if not source_train: raise SystemExit("no source rows")

    tok=AutoTokenizer.from_pretrained(a.checkpoint/"semantic_backbone")
    model=XSSDualBranchModel.load(a.checkpoint)

    for param in model.parameters():
        param.requires_grad=False
    for param in model.semantic_heads["source"].parameters():
        param.requires_grad=True

    model.configure_losses(
        semantic_task_weights={"source":1.0,"sink":0.0,"defense":0.0},
        class_weights={"source":None,"sink":None,"defense":None,"flow":None},
    )

    coll=Collator(tok,a.max_length)
    train_ds=Rows.__new__(Rows); train_ds.rows=source_train
    train_loader=DataLoader(
        train_ds,batch_size=a.batch_size,shuffle=True,
        generator=torch.Generator().manual_seed(a.seed),collate_fn=coll
    )
    dev_loader=DataLoader(dev,batch_size=a.batch_size*2,shuffle=False,collate_fn=coll)

    device=torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    params=[p for p in model.semantic_heads["source"].parameters() if p.requires_grad]
    opt=torch.optim.AdamW(params,lr=a.lr,weight_decay=.01)
    steps=max(1,a.epochs*len(train_loader))
    sch=get_linear_schedule_with_warmup(
        opt,num_warmup_steps=max(1,math.ceil(steps*.05)),num_training_steps=steps
    )

    a.output_dir.mkdir(parents=True,exist_ok=True)
    baseline=metrics(model,dev_loader,device)
    best_source=baseline["source"]["macro_f1"]
    best_full=baseline
    model.save(a.output_dir)
    tok.save_pretrained(a.output_dir/"semantic_backbone")
    tok.save_pretrained(a.output_dir/"flow_backbone")
    (a.output_dir/"best_metrics.json").write_text(
        json.dumps({"epoch":0,"dev":baseline},indent=2)+"\n"
    )

    history=[{"epoch":0,"dev":baseline}]
    started=time.time()
    for epoch in range(1,a.epochs+1):
        model.semantic_heads["source"].train()
        losses=[]
        for batch in train_loader:
            batch={k:v.to(device) for k,v in batch.items()}
            batch["sink_labels"].fill_(IGNORE_INDEX)
            batch["defense_labels"].fill_(IGNORE_INDEX)
            opt.zero_grad(set_to_none=True)
            out=model.forward_semantic(**batch)
            if out.loss is None: continue
            out.loss.backward()
            torch.nn.utils.clip_grad_norm_(params,1.0)
            opt.step(); sch.step()
            losses.append(float(out.loss.detach().cpu()))

        ev=metrics(model,dev_loader,device)
        row={"epoch":epoch,"train_loss":float(np.mean(losses)) if losses else None,"dev":ev}
        history.append(row); print(json.dumps(row,indent=2))

        preserved=(
            ev["sink"]["macro_f1"] >= baseline["sink"]["macro_f1"] - 1e-9
            and ev["defense"]["macro_f1"] >= baseline["defense"]["macro_f1"] - 1e-9
        )
        if preserved and ev["source"]["macro_f1"] > best_source:
            best_source=ev["source"]["macro_f1"]; best_full=ev
            model.save(a.output_dir)
            tok.save_pretrained(a.output_dir/"semantic_backbone")
            tok.save_pretrained(a.output_dir/"flow_backbone")
            (a.output_dir/"best_metrics.json").write_text(
                json.dumps({"epoch":epoch,"dev":ev},indent=2)+"\n"
            )

    report={
        "schema":"xss-source-head-v4e-training",
        "checkpoint_source":str(a.checkpoint),
        "trainable_parameters":sum(p.numel() for p in params),
        "backbone_frozen":True,
        "sink_head_frozen":True,
        "defense_head_frozen":True,
        "source_head_only":True,
        "train_source_rows":len(source_train),
        "dev_rows":len(dev),
        "baseline":baseline,
        "best":best_full,
        "best_source_macro_f1":best_source,
        "history":history,
        "external_v6_used":False,
        "locked_hard_used":False,
        "promotion_allowed":False,
        "runtime_seconds":round(time.time()-started,2),
    }
    (a.output_dir/"training_report.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))


if __name__=="__main__": main()
