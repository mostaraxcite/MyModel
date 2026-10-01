"""Train the class-complete semantic Source/Sink/Defense branch only."""
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


TASKS=tuple(SEMANTIC_LABEL_SPACES)


class Rows(Dataset):
    def __init__(self,path:Path):
        self.rows=[json.loads(x) for x in path.read_text().splitlines() if x.strip()]
    def __len__(self): return len(self.rows)
    def __getitem__(self,i): return self.rows[i]


class Collator:
    def __init__(self,tok,max_length): self.tok,self.max_length=tok,max_length
    def __call__(self,rows):
        batch=self.tok([r["text"] for r in rows],padding=True,truncation=True,
                       max_length=self.max_length,return_tensors="pt")
        for task in TASKS:
            batch[f"{task}_labels"]=torch.tensor(
                [int(r[f"{task}_label"]) for r in rows],dtype=torch.long)
        return batch


def freeze(backbone,count):
    emb=getattr(backbone,"embeddings",None)
    layers=getattr(getattr(backbone,"encoder",None),"layer",None)
    if layers is None:
        if count: raise SystemExit("freeze supports BERT-like encoders only")
        return
    if count<0 or count>len(layers): raise SystemExit("invalid freeze count")
    if count and emb is not None:
        for p in emb.parameters(): p.requires_grad=False
    for layer in layers[:count]:
        for p in layer.parameters(): p.requires_grad=False


def weights(rows,task,power):
    labels=SEMANTIC_LABEL_SPACES[task]
    counts=np.zeros(len(labels),dtype=np.float64)
    for r in rows.rows:
        counts[int(r[f"{task}_label"])]+=1
    w=np.ones(len(labels),dtype=np.float32)
    if power>0:
        mask=counts>0
        w[mask]=1.0/np.power(counts[mask],power)
        w[mask]/=w[mask].mean()
    return torch.tensor(w,dtype=torch.float32),{
        labels[i]:{"count":int(counts[i]),"weight":float(w[i])}
        for i in range(len(labels))
    }


def evaluate(model,loader,device):
    truth={t:[] for t in TASKS}; pred={t:[] for t in TASKS}; losses=[]
    model.eval()
    with torch.no_grad():
        for batch in loader:
            batch={k:v.to(device) for k,v in batch.items()}
            out=model.forward_semantic(**batch)
            if out.loss is not None: losses.append(float(out.loss.detach().cpu()))
            for t in TASKS:
                y=batch[f"{t}_labels"]
                p=out.logits[t].argmax(-1)
                truth[t].extend(y.cpu().tolist()); pred[t].extend(p.cpu().tolist())
    tasks={}
    for t in TASKS:
        labels=list(range(len(SEMANTIC_LABEL_SPACES[t])))
        tasks[t]={
            "macro_f1":float(f1_score(truth[t],pred[t],labels=labels,average="macro",zero_division=0)),
            "accuracy":float(accuracy_score(truth[t],pred[t])),
            "per_class_f1":{
                SEMANTIC_LABEL_SPACES[t][i]:float(
                    f1_score(truth[t],pred[t],labels=[i],average="macro",zero_division=0)
                ) for i in labels
            },
        }
    macro=float(np.mean([tasks[t]["macro_f1"] for t in TASKS]))
    return {"loss":float(np.mean(losses)) if losses else None,
            "tasks":tasks,"mean_macro_f1":macro}


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--backbone",type=Path,required=True)
    p.add_argument("--train",type=Path,required=True)
    p.add_argument("--dev",type=Path,required=True)
    p.add_argument("--output-dir",type=Path,required=True)
    p.add_argument("--epochs",type=int,default=8)
    p.add_argument("--batch-size",type=int,default=32)
    p.add_argument("--max-length",type=int,default=128)
    p.add_argument("--lr",type=float,default=3e-5)
    p.add_argument("--freeze-layers",type=int,default=0)
    p.add_argument("--class-power",type=float,default=0.30)
    p.add_argument("--source-weight",type=float,default=1.0)
    p.add_argument("--sink-weight",type=float,default=1.5)
    p.add_argument("--defense-weight",type=float,default=1.5)
    p.add_argument("--seed",type=int,default=7072)
    a=p.parse_args()

    random.seed(a.seed); np.random.seed(a.seed); torch.manual_seed(a.seed)
    train=Rows(a.train); dev=Rows(a.dev)
    tok=AutoTokenizer.from_pretrained(a.backbone)
    model=XSSDualBranchModel(str(a.backbone))
    freeze(model.semantic_backbone,a.freeze_layers)

    class_map={}; report={}
    for t in TASKS:
        w,r=weights(train,t,a.class_power); class_map[t]=w; report[t]=r
    model.configure_losses(
        semantic_task_weights={
            "source":a.source_weight,"sink":a.sink_weight,"defense":a.defense_weight
        },
        class_weights=class_map,
    )

    coll=Collator(tok,a.max_length)
    tr=DataLoader(train,batch_size=a.batch_size,shuffle=True,
                  generator=torch.Generator().manual_seed(a.seed),collate_fn=coll)
    dv=DataLoader(dev,batch_size=a.batch_size*2,shuffle=False,collate_fn=coll)

    device=torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    params=[p for p in model.semantic_parameters() if p.requires_grad]
    opt=torch.optim.AdamW(params,lr=a.lr,weight_decay=0.01)
    steps=max(1,a.epochs*len(tr))
    sch=get_linear_schedule_with_warmup(
        opt,num_warmup_steps=max(1,math.ceil(steps*.08)),num_training_steps=steps)

    a.output_dir.mkdir(parents=True,exist_ok=True)
    best=-1.0; history=[]; started=time.time()
    for epoch in range(1,a.epochs+1):
        model.semantic_backbone.train(); model.semantic_heads.train()
        losses=[]
        for batch in tr:
            batch={k:v.to(device) for k,v in batch.items()}
            opt.zero_grad(set_to_none=True)
            out=model.forward_semantic(**batch)
            out.loss.backward()
            torch.nn.utils.clip_grad_norm_(params,1.0)
            opt.step(); sch.step()
            losses.append(float(out.loss.detach().cpu()))
        ev=evaluate(model,dv,device)
        row={"epoch":epoch,"train_loss":float(np.mean(losses)),"dev":ev}
        history.append(row); print(json.dumps(row,indent=2))
        if ev["mean_macro_f1"]>best:
            best=ev["mean_macro_f1"]
            model.save(a.output_dir)
            tok.save_pretrained(a.output_dir/"semantic_backbone")
            tok.save_pretrained(a.output_dir/"flow_backbone")
            (a.output_dir/"best_metrics.json").write_text(json.dumps(row,indent=2)+"\n")

    final={
        "schema":"xss-semantic-v3-training",
        "architecture":"v04-backbone-semantic-only",
        "train_rows":len(train),"dev_rows":len(dev),
        "epochs":a.epochs,"lr":a.lr,"freeze_layers":a.freeze_layers,
        "max_length":a.max_length,"class_power":a.class_power,
        "class_weights":report,"best_mean_macro_f1":best,"history":history,
        "runtime_seconds":round(time.time()-started,2),
        "whole_snippet_classifier_loss":False,
        "locked_hard_or_external_used":False,
        "final_judge":False,"promotion_allowed":False,
    }
    (a.output_dir/"training_report.json").write_text(json.dumps(final,indent=2)+"\n")
    print(json.dumps(final,indent=2))


if __name__=="__main__":
    main()
